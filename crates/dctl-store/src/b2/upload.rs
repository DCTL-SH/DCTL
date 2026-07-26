//! B2 uploads: SHA-1-verified single-file and large-file (multipart) paths.

use bytes::Bytes;

use crate::checksum::ContentHash;
use crate::error::{Result, StoreError};
use crate::model::{ObjectKey, PutOutcome};

use super::api::{
    AuthState, FinishLargeFileResponse, GetUploadPartUrlResponse, GetUploadUrlResponse,
    StartLargeFileResponse, UploadFileResponse, UploadPartResponse,
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

    let part_size = auth.recommended_part_size as usize;
    tracing::debug!(bytes = data.len(), part_size, "b2 upload (multipart)");
    let mut part_sha1s: Vec<String> = Vec::new();
    let mut offset = 0usize;
    let mut part_number = 1u32;

    while offset < data.len() {
        let end = (offset + part_size).min(data.len());
        let chunk = &data[offset..end];

        let part_url: GetUploadPartUrlResponse = b2
            .post_json(
                auth,
                constants::EP_GET_UPLOAD_PART_URL,
                serde_json::json!({ "fileId": start.file_id }),
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

        offset = end;
        part_number += 1;
    }

    let _: FinishLargeFileResponse = b2
        .post_json(
            auth,
            constants::EP_FINISH_LARGE_FILE,
            serde_json::json!({ "fileId": start.file_id, "partSha1Array": part_sha1s }),
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
