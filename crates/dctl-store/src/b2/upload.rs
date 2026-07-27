//! B2 uploads: SHA-1-verified single-file and large-file (multipart) paths, both
//! from an in-memory `Bytes` (`put`) and streamed from a file (`put_from_path`).

use std::path::Path;

use bytes::Bytes;

use crate::backend::UploadTicket;
use crate::checksum::{ContentHash, Hasher};
use crate::error::{Result, StoreError};
use crate::model::{ObjectKey, PutOutcome};
use crate::streaming;

use super::api::{
    AuthState, CancelLargeFileResponse, FinishLargeFileResponse, GetUploadPartUrlResponse,
    GetUploadUrlResponse, StartLargeFileResponse, UploadFileResponse, UploadPartResponse,
};
use super::name::encode_file_name;
use super::{B2Backend, constants, parse_json, reqwest_err};

pub(super) async fn put(
    b2: &B2Backend,
    key: &ObjectKey,
    data: Bytes,
    expected: &ContentHash,
) -> Result<PutOutcome> {
    // Guard: the caller's declared hash must match the bytes we're about to send.
    let caller = ContentHash::compute(expected.algo, &data);
    if !caller.matches(expected) {
        return Err(StoreError::ChecksumMismatch {
            expected: expected.hex(),
            actual: caller.hex(),
        });
    }

    // B2 verifies uploads by SHA-1; compute it once for the request headers.
    let sha1 = ContentHash::sha1(&data);
    let auth = b2.auth().await?;
    if data.len() as u64 <= constants::MULTIPART_THRESHOLD {
        upload_single(b2, &auth, key, &data, &sha1).await?;
    } else {
        upload_large(b2, &auth, key, &data).await?;
    }

    // B2 confirmed the SHA-1 of the exact bytes we sent, and those bytes matched
    // `expected` (guard above) — so the stored object matches `expected`.
    Ok(PutOutcome {
        size: data.len() as u64,
        verified: caller,
    })
}

async fn upload_single(
    b2: &B2Backend,
    auth: &AuthState,
    key: &ObjectKey,
    data: &[u8],
    sha1: &ContentHash,
) -> Result<()> {
    let upload: GetUploadUrlResponse = b2
        .post_json(
            auth,
            constants::EP_GET_UPLOAD_URL,
            serde_json::json!({ "bucketId": auth.bucket_id }),
        )
        .await?;

    let sha1_hex = sha1.hex();
    tracing::debug!(bytes = data.len(), "b2 upload (single-file)");
    let resp = b2
        .client
        .post(&upload.upload_url)
        .header(constants::H_AUTHORIZATION, &upload.authorization_token)
        .header(constants::H_FILE_NAME, encode_file_name(key.as_str()))
        .header(constants::H_CONTENT_TYPE, constants::CONTENT_TYPE_AUTO)
        .header(constants::H_CONTENT_SHA1, &sha1_hex)
        .header(constants::H_CONTENT_LENGTH, data.len().to_string())
        .body(data.to_vec())
        .send()
        .await
        .map_err(reqwest_err)?;

    let info: UploadFileResponse = parse_json(resp).await?;
    verify_sha1(&sha1_hex, &info.content_sha1)
}

/// In-memory large-file upload (the buffered `>threshold` path reachable via [`put`]).
/// Cancels the large file on any error so no unfinished large file lingers (consuming
/// storage and unfinished-file quota) — mirroring the streaming sibling
/// [`stream_large_from_path`].
async fn upload_large(
    b2: &B2Backend,
    auth: &AuthState,
    key: &ObjectKey,
    data: &[u8],
) -> Result<()> {
    let start: StartLargeFileResponse = b2
        .post_json(
            auth,
            constants::EP_START_LARGE_FILE,
            serde_json::json!({
                "bucketId": auth.bucket_id,
                "fileName": key.as_str(),
                "contentType": constants::CONTENT_TYPE_AUTO,
            }),
        )
        .await?;

    match upload_parts_and_finish(b2, auth, &start.file_id, data).await {
        Ok(()) => Ok(()),
        Err(e) => {
            // Cancel so no unfinished large file lingers. Keep the original error; a
            // failed cancel is ignored, not surfaced.
            let _ = cancel_large_file(b2, auth, &start.file_id).await;
            Err(e)
        }
    }
}

/// Upload every part of the in-memory `data` slice, then finish the large file. Any
/// error propagates to [`upload_large`], which cancels the large file.
async fn upload_parts_and_finish(
    b2: &B2Backend,
    auth: &AuthState,
    file_id: &str,
    data: &[u8],
) -> Result<()> {
    // Grow the part size for very large objects so the part count stays within B2's
    // 10,000-part cap; normal objects keep the recommended part size.
    let part_size = streaming::adaptive_part_size(
        data.len() as u64,
        auth.recommended_part_size,
        constants::MIN_PART_SIZE,
        constants::B2_MAX_PART_SIZE,
        streaming::MAX_PARTS,
    )?;
    let plan = streaming::plan_parts(data.len() as u64, part_size);
    tracing::debug!(bytes = data.len(), part_size, "b2 upload (multipart)");

    let mut part_sha1s: Vec<String> = Vec::with_capacity(plan.len());
    for span in &plan {
        let start = span.offset as usize;
        let end = start + span.len as usize;
        upload_one_part(
            b2,
            auth,
            file_id,
            span.number,
            &data[start..end],
            &mut part_sha1s,
        )
        .await?;
    }

    let _: FinishLargeFileResponse = b2
        .post_json(
            auth,
            constants::EP_FINISH_LARGE_FILE,
            serde_json::json!({ "fileId": file_id, "partSha1Array": part_sha1s }),
        )
        .await?;
    Ok(())
}

/// Confirm B2 echoed back the SHA-1 we sent (case-insensitive hex).
fn verify_sha1(sent: &str, got: &str) -> Result<()> {
    if sent.eq_ignore_ascii_case(got) {
        Ok(())
    } else {
        Err(StoreError::ChecksumMismatch {
            expected: sent.to_string(),
            actual: got.to_string(),
        })
    }
}

/// Streaming counterpart of [`put`]: store the file at `source` under `key`, verified,
/// without ever holding the whole file in memory.
///
/// Below B2's large-file threshold the (bounded) file is read and handed to the verified
/// single-shot [`put`], exactly matching the buffered path. Above it, the file is streamed
/// part-by-part through the native large-file API at `O(part_size)` memory. This mirrors
/// the live-verified buffered [`upload_large`] — same threshold, same part size, same
/// per-part SHA-1 verification — only fed from a file instead of an in-RAM slice.
pub(super) async fn put_from_path(
    b2: &B2Backend,
    key: &ObjectKey,
    source: &Path,
    expected: &ContentHash,
) -> Result<PutOutcome> {
    let size = tokio::fs::metadata(source).await?.len();

    // Below the large-file threshold: read the bounded file and use the verified
    // single-shot path, exactly like `put` (same in-memory guard + SHA-1 upload).
    if !streaming::use_multipart(size, constants::MULTIPART_THRESHOLD) {
        let data = tokio::fs::read(source).await?;
        return put(b2, key, Bytes::from(data), expected).await;
    }

    let auth = b2.auth().await?;
    stream_large_from_path(b2, &auth, key, source, expected).await
}

/// Stream a large file to B2, aborting the large-file upload on any error so nothing
/// partial is ever committed.
async fn stream_large_from_path(
    b2: &B2Backend,
    auth: &AuthState,
    key: &ObjectKey,
    source: &Path,
    expected: &ContentHash,
) -> Result<PutOutcome> {
    let start: StartLargeFileResponse = b2
        .post_json(
            auth,
            constants::EP_START_LARGE_FILE,
            serde_json::json!({
                "bucketId": auth.bucket_id,
                "fileName": key.as_str(),
                "contentType": constants::CONTENT_TYPE_AUTO,
            }),
        )
        .await?;

    match upload_and_finish(b2, auth, &start.file_id, source, expected).await {
        Ok(outcome) => Ok(outcome),
        Err(e) => {
            // Abort so nothing partial is committed and no unfinished large file lingers.
            let _ = cancel_large_file(b2, auth, &start.file_id).await;
            Err(e)
        }
    }
}

/// Upload every part streamed from `source`, verify the whole-file hash against
/// `expected`, then finish the large file. Any failure here propagates to the caller,
/// which cancels the large file.
async fn upload_and_finish(
    b2: &B2Backend,
    auth: &AuthState,
    file_id: &str,
    source: &Path,
    expected: &ContentHash,
) -> Result<PutOutcome> {
    let size = tokio::fs::metadata(source).await?.len();
    // Grow the part size for very large objects so the part count stays within B2's
    // 10,000-part cap; normal objects keep the recommended part size. Computed once from
    // the total and used for the whole upload.
    let part_size = streaming::adaptive_part_size(
        size,
        auth.recommended_part_size,
        constants::MIN_PART_SIZE,
        constants::B2_MAX_PART_SIZE,
        streaming::MAX_PARTS,
    )?;
    let plan = streaming::plan_parts(size, part_size);
    tracing::debug!(
        bytes = size,
        part_size,
        parts = plan.len(),
        "b2 stream (multipart)"
    );

    let mut file = tokio::fs::File::open(source).await?;
    // One reusable part buffer keeps peak memory at O(part_size).
    let mut buf = vec![0u8; part_size as usize];
    // Whole-file hash under the caller's algorithm, folded part-by-part, so the
    // verified-write contract holds without ever buffering the whole file.
    let mut whole = Hasher::new(expected.algo);
    let mut part_sha1s: Vec<String> = Vec::with_capacity(plan.len());

    for span in &plan {
        let want = span.len as usize;
        let n = streaming::fill_buf(&mut file, &mut buf[..want]).await?;
        if n != want {
            return Err(StoreError::Backend(
                "b2 stream: source file shorter than expected (changed under read)".into(),
            ));
        }
        let chunk = &buf[..want];
        whole.update(chunk);
        upload_one_part(b2, auth, file_id, span.number, chunk, &mut part_sha1s).await?;
    }

    // Verify the streamed bytes hash to `expected` BEFORE finishing (which commits).
    let verified = whole.finalize();
    if !verified.matches(expected) {
        return Err(StoreError::ChecksumMismatch {
            expected: expected.hex(),
            actual: verified.hex(),
        });
    }

    let _: FinishLargeFileResponse = b2
        .post_json(
            auth,
            constants::EP_FINISH_LARGE_FILE,
            serde_json::json!({ "fileId": file_id, "partSha1Array": part_sha1s }),
        )
        .await?;

    Ok(PutOutcome { size, verified })
}

/// Fetch a fresh upload-part URL, upload `chunk` as part `part_number` with its streamed
/// SHA-1, confirm B2 echoed that SHA-1, and record it for the finish call.
async fn upload_one_part(
    b2: &B2Backend,
    auth: &AuthState,
    file_id: &str,
    part_number: u32,
    chunk: &[u8],
    part_sha1s: &mut Vec<String>,
) -> Result<()> {
    let part_url: GetUploadPartUrlResponse = b2
        .post_json(
            auth,
            constants::EP_GET_UPLOAD_PART_URL,
            serde_json::json!({ "fileId": file_id }),
        )
        .await?;

    let sha1_hex = ContentHash::sha1(chunk).hex();
    let resp = b2
        .client
        .post(&part_url.upload_url)
        .header(constants::H_AUTHORIZATION, &part_url.authorization_token)
        .header(constants::H_PART_NUMBER, part_number.to_string())
        .header(constants::H_CONTENT_SHA1, &sha1_hex)
        .header(constants::H_CONTENT_LENGTH, chunk.len().to_string())
        .body(chunk.to_vec())
        .send()
        .await
        .map_err(reqwest_err)?;

    let part: UploadPartResponse = parse_json(resp).await?;
    verify_sha1(&sha1_hex, &part.content_sha1)?;
    part_sha1s.push(sha1_hex);
    Ok(())
}

/// Cancel an unfinished large file so nothing partial remains. Best-effort: callers
/// invoke it on the error path and keep the original error.
async fn cancel_large_file(b2: &B2Backend, auth: &AuthState, file_id: &str) -> Result<()> {
    let _: CancelLargeFileResponse = b2
        .post_json(
            auth,
            constants::EP_CANCEL_LARGE_FILE,
            serde_json::json!({ "fileId": file_id }),
        )
        .await?;
    Ok(())
}

// ---- delegated (token-scoped) upload -----------------------------------------

/// Issue a delegated upload ticket for `key` — the B2 implementation of
/// [`Backend::prepare_upload`](crate::backend::Backend::prepare_upload).
///
/// Authorizes (cached) and fetches a fresh `b2_get_upload_url`, then hands back the exact
/// `POST` the client must replay. B2 uploads are token-scoped, so `expires_unix` is `None`
/// (the ticket lives as long as the returned upload-auth token).
///
/// **SHA-1 note.** B2 verifies uploads by **SHA-1**, but `content_sha256` (when supplied)
/// is a SHA-256 — the two are not interconvertible, so we cannot present a matching
/// `X-Bz-Content-Sha1` here. We send the B2 sentinel `do_not_verify`; the sealed object's
/// integrity is instead checked when it is later **opened** (DSF1 verification), not at PUT
/// time. We deliberately do not attempt any conversion.
pub(super) async fn prepare_upload(
    b2: &B2Backend,
    key: &ObjectKey,
    content_len: u64,
    _content_sha256: Option<&[u8; 32]>,
) -> Result<UploadTicket> {
    let auth = b2.auth().await?;
    let upload: GetUploadUrlResponse = b2
        .post_json(
            &auth,
            constants::EP_GET_UPLOAD_URL,
            serde_json::json!({ "bucketId": auth.bucket_id }),
        )
        .await?;
    Ok(build_b2_ticket(
        upload.upload_url,
        upload.authorization_token,
        key,
        content_len,
    ))
}

/// Pure assembly of the B2 upload ticket from a fetched `upload_url` + `auth_token`. Split
/// from the network fetch so the header/URL shape is unit-testable without a live
/// `b2_get_upload_url`.
fn build_b2_ticket(
    upload_url: String,
    auth_token: String,
    key: &ObjectKey,
    content_len: u64,
) -> UploadTicket {
    UploadTicket {
        method: "POST".to_string(),
        url: upload_url,
        headers: vec![
            (constants::H_AUTHORIZATION.to_string(), auth_token),
            (
                constants::H_FILE_NAME.to_string(),
                encode_file_name(key.as_str()),
            ),
            (
                constants::H_CONTENT_TYPE.to_string(),
                constants::CONTENT_TYPE_AUTO.to_string(),
            ),
            // SHA-256 ≠ B2's SHA-1: cannot verify at PUT, so sentinel + verify-on-open.
            (
                constants::H_CONTENT_SHA1.to_string(),
                "do_not_verify".to_string(),
            ),
            (
                constants::H_CONTENT_LENGTH.to_string(),
                content_len.to_string(),
            ),
        ],
        expires_unix: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Offline B2 ticket assembly: correct method, verbatim URL, token-scoped (no signed
    /// expiry), url-encoded file name, `b2/x-auto`, the `do_not_verify` SHA-1 sentinel, and
    /// the declared length — all without a live `b2_get_upload_url`.
    #[test]
    fn b2_ticket_assembly() {
        let key = ObjectKey::new("photos/2020/a b.jpg");
        let ticket = build_b2_ticket(
            "https://pod-000.backblaze.com/b2api/v2/b2_upload_file/abc123".to_string(),
            "UPLOAD_AUTH_TOKEN".to_string(),
            &key,
            4096,
        );

        assert_eq!(ticket.method, "POST");
        assert_eq!(
            ticket.url,
            "https://pod-000.backblaze.com/b2api/v2/b2_upload_file/abc123"
        );
        assert_eq!(ticket.expires_unix, None);
        assert!(
            ticket
                .headers
                .contains(&("Authorization".to_string(), "UPLOAD_AUTH_TOKEN".to_string()))
        );
        assert!(ticket.headers.contains(&(
            "X-Bz-File-Name".to_string(),
            "photos/2020/a%20b.jpg".to_string()
        )));
        assert!(
            ticket
                .headers
                .contains(&("Content-Type".to_string(), "b2/x-auto".to_string()))
        );
        assert!(
            ticket
                .headers
                .contains(&("X-Bz-Content-Sha1".to_string(), "do_not_verify".to_string()))
        );
        assert!(
            ticket
                .headers
                .contains(&("Content-Length".to_string(), "4096".to_string()))
        );
    }
}
