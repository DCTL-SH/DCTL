//! B2 downloads: full object and byte-range (streaming-seek).

use bytes::Bytes;

use crate::error::{Result, StoreError};
use crate::model::{ByteRange, ObjectKey};

use super::name::encode_file_name;
use super::{B2Backend, constants, reqwest_err};

/// HTTP 404 Not Found.
const HTTP_NOT_FOUND: u16 = 404;

pub(super) async fn get(b2: &B2Backend, key: &ObjectKey) -> Result<Bytes> {
    fetch(b2, key, None).await
}

pub(super) async fn get_range(b2: &B2Backend, key: &ObjectKey, range: ByteRange) -> Result<Bytes> {
    let header = match range.length {
        Some(len) => format!("bytes={}-{}", range.offset, range.offset + len - 1),
        None => format!("bytes={}-", range.offset),
    };
    fetch(b2, key, Some(header)).await
}

async fn fetch(b2: &B2Backend, key: &ObjectKey, range: Option<String>) -> Result<Bytes> {
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
    resp.bytes().await.map_err(reqwest_err)
}
