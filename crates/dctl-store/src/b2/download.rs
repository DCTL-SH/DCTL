//! B2 downloads: full object, byte-range (streaming-seek), and streaming-to-file.

use std::path::Path;

use bytes::Bytes;

use crate::error::{Result, StoreError};
use crate::model::{ByteRange, ObjectKey};
use crate::streaming;

use super::name::encode_file_name;
use super::retry::{self, Attempt, Observed};
use crate::deadline::Answered;

use super::{B2Backend, constants, reqwest_err, stalled_attempt, transport_attempt};

/// HTTP 404 Not Found.
const HTTP_NOT_FOUND: u16 = 404;

pub(super) async fn get(b2: &B2Backend, key: &ObjectKey) -> Result<Bytes> {
    let resp = send_download(b2, key, None).await?;
    resp.bytes()
        .await
        .map_err(|expired| expired.into_store_error(super::B2_BACKEND_NAME))?
        .map_err(reqwest_err)
}

pub(super) async fn get_range(b2: &B2Backend, key: &ObjectKey, range: ByteRange) -> Result<Bytes> {
    let header = match range.length {
        Some(len) => format!("bytes={}-{}", range.offset, range.offset + len - 1),
        None => format!("bytes={}-", range.offset),
    };
    let resp = send_download(b2, key, Some(header)).await?;
    resp.bytes()
        .await
        .map_err(|expired| expired.into_store_error(super::B2_BACKEND_NAME))?
        .map_err(reqwest_err)
}

/// Streaming download (the B2 override of
/// [`Backend::get_to_path`](crate::backend::Backend::get_to_path)): copy the object body
/// straight to `dest` at constant memory (temp → fsync → atomic rename) without ever
/// holding the whole object in RAM. A missing object maps to `NotFound`, matching [`get`].
pub(super) async fn get_to_path(b2: &B2Backend, key: &ObjectKey, dest: &Path) -> Result<()> {
    let (watch, resp) = send_download(b2, key, None).await?.into_parts();
    // Verify the committed length against the object's declared Content-Length so a
    // short-but-clean body is not atomically committed as if whole.
    let expected_len = streaming::content_length(&resp);
    // The watch travels with the body. A 4 GiB restore is hours of body against
    // milliseconds of headers, so a deadline that ended when the status was
    // confirmed would be watching the part that never stalls.
    streaming::stream_to_file(resp, dest, expected_len, b2.meter.as_ref(), &watch).await
}

/// Send an authenticated download request (optionally ranged) and return the response
/// once its status is confirmed successful. Maps 404 to `NotFound`; other non-2xx to a
/// backend error carrying the body.
///
/// Retried on the statuses [`retry`] calls temporary, with the authorization
/// re-read each time so an expired token is replaced rather than resent. Only
/// the *headers* are retried: once the status is good the body is handed to the
/// caller and streamed, and a connection that drops mid-body is reported rather
/// than silently restarted — restarting a stream without rewinding the hash is
/// how a truncated object gets committed as a whole one.
async fn send_download(b2: &B2Backend, key: &ObjectKey, range: Option<String>) -> Result<Answered> {
    retry::run(constants::OP_DOWNLOAD, b2.deadlines.run, |_| async {
        let auth = b2.auth().await.map_err(Attempt::transport)?;
        let url = format!(
            "{}/{}/{}/{}",
            auth.download_url,
            constants::DOWNLOAD_SEGMENT,
            b2.bucket_name,
            encode_file_name(key.as_str())
        );

        tracing::debug!(has_range = range.is_some(), "b2 download");
        let mut request = b2
            .client
            .get(&url)
            .header(constants::H_AUTHORIZATION, &auth.auth_token);
        if let Some(range_header) = range.clone() {
            request = request.header(constants::H_RANGE, range_header);
        }

        let watch = b2.deadlines.watch();
        let response = watch
            .guard(request.send())
            .await
            .map_err(stalled_attempt)?
            .map_err(transport_attempt)?;
        b2.observe_expiry(classify_download(Answered { watch, response }, key).await)
            .await
    })
    .await
}

/// Turn a download response into either the response itself or one attempt's
/// failure, keeping the status, B2's error code and any `Retry-After`.
///
/// A `404` is [`StoreError::NotFound`] and is **never** retried, which the
/// classifier gets right for free: an absent object is an answer, and asking six
/// times does not make it present.
async fn classify_download(
    resp: Answered,
    key: &ObjectKey,
) -> std::result::Result<Answered, Attempt> {
    let status = resp.status();
    if status.as_u16() == HTTP_NOT_FOUND {
        return Err(Attempt {
            observed: Observed {
                status: Some(HTTP_NOT_FOUND),
                code: None,
                retry_after: None,
                settled: false,
            },
            error: StoreError::NotFound(key.to_string()),
        });
    }
    if status.is_success() {
        return Ok(resp);
    }
    let retry_after = super::retry_after_of(resp.headers());
    let bytes = resp
        .bytes()
        .await
        .map_err(stalled_attempt)?
        .map_err(transport_attempt)?;
    Err(Attempt {
        observed: Observed {
            status: Some(status.as_u16()),
            code: super::b2_error_code(&bytes),
            retry_after,
            settled: false,
        },
        error: StoreError::Backend(format!(
            "b2 download error {}: {}",
            status.as_u16(),
            String::from_utf8_lossy(&bytes)
        )),
    })
}
