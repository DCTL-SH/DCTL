//! B2 downloads: full object, byte-range (streaming-seek), and streaming-to-file.

use std::path::Path;

use bytes::Bytes;

use crate::error::{Result, StoreError};
use crate::model::{ByteRange, ObjectKey};
use crate::streaming;

use super::name::encode_file_name;
use super::{B2Backend, constants, reqwest_err};

/// HTTP 404 Not Found.
const HTTP_NOT_FOUND: u16 = 404;

pub(super) async fn get(b2: &B2Backend, key: &ObjectKey) -> Result<Bytes> {
    let resp = send_download(b2, key, None).await?;
    resp.bytes().await.map_err(reqwest_err)
}

pub(super) async fn get_range(b2: &B2Backend, key: &ObjectKey, range: ByteRange) -> Result<Bytes> {
    let header = match range.length {
        Some(len) => format!("bytes={}-{}", range.offset, range.offset + len - 1),
        None => format!("bytes={}-", range.offset),
    };
    let resp = send_download(b2, key, Some(header)).await?;
    resp.bytes().await.map_err(reqwest_err)
}

/// Streaming download (the B2 override of
/// [`Backend::get_to_path`](crate::backend::Backend::get_to_path)): copy the object body
/// straight to `dest` at constant memory (temp → fsync → atomic rename) without ever
/// holding the whole object in RAM. A missing object maps to `NotFound`, matching [`get`].
pub(super) async fn get_to_path(b2: &B2Backend, key: &ObjectKey, dest: &Path) -> Result<()> {
    let resp = send_download(b2, key, None).await?;
    // Verify the committed length against the object's declared Content-Length so a
    // short-but-clean body is not atomically committed as if whole.
    let expected_len = streaming::content_length(&resp);
    streaming::stream_to_file(resp, dest, expected_len).await
}

/// Send an authenticated download request (optionally ranged) and return the response
/// once its status is confirmed successful. Maps 404 to `NotFound`; other non-2xx to a
/// backend error carrying the body.
async fn send_download(
    b2: &B2Backend,
    key: &ObjectKey,
    range: Option<String>,
) -> Result<reqwest::Response> {
    let auth = b2.auth().await?;
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
    if let Some(range_header) = range {
        request = request.header(constants::H_RANGE, range_header);
    }

    let resp = request.send().await.map_err(reqwest_err)?;
    let status = resp.status();
    if status.as_u16() == HTTP_NOT_FOUND {
        return Err(StoreError::NotFound(key.to_string()));
    }
    if !status.is_success() {
        let bytes = resp.bytes().await.map_err(reqwest_err)?;
        return Err(StoreError::Backend(format!(
            "b2 download error {}: {}",
            status.as_u16(),
            String::from_utf8_lossy(&bytes)
        )));
    }
    Ok(resp)
}
