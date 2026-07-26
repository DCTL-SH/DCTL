//! B2 listing, metadata, existence, and version-aware delete.

use crate::error::{Result, StoreError};
use crate::model::{ObjectKey, ObjectMeta, Page};

use super::api::{DeleteFileVersionResponse, ListFileNamesResponse, ListFileVersionsResponse};
use super::{B2Backend, constants};

/// `maxFileCount` used when probing for a single exact file (head/exists).
const SINGLE: u32 = 1;

pub(super) async fn list_page(
    b2: &B2Backend,
    prefix: &str,
    cursor: Option<String>,
) -> Result<Page> {
    let auth = b2.auth().await?;
    let resp: ListFileNamesResponse = b2
        .post_json(
            &auth,
            constants::EP_LIST_FILE_NAMES,
            serde_json::json!({
                "bucketId": auth.bucket_id,
                "prefix": prefix,
                "startFileName": cursor,
                "maxFileCount": constants::LIST_PAGE_SIZE,
            }),
        )
        .await?;

    let items = resp
        .files
        .into_iter()
        .filter(|f| f.action == constants::ACTION_UPLOAD)
        .map(to_meta)
        .collect();
    Ok(Page {
        items,
        next_cursor: resp.next_file_name,
    })
}

pub(super) async fn head(b2: &B2Backend, key: &ObjectKey) -> Result<ObjectMeta> {
    let auth = b2.auth().await?;
    let resp: ListFileNamesResponse = b2
        .post_json(
            &auth,
            constants::EP_LIST_FILE_NAMES,
            serde_json::json!({
                "bucketId": auth.bucket_id,
                "prefix": key.as_str(),
                "startFileName": key.as_str(),
                "maxFileCount": SINGLE,
            }),
        )
        .await?;

    resp.files
        .into_iter()
        .find(|f| f.file_name == key.as_str() && f.action == constants::ACTION_UPLOAD)
        .map(to_meta)
        .ok_or_else(|| StoreError::NotFound(key.to_string()))
}

pub(super) async fn exists(b2: &B2Backend, key: &ObjectKey) -> Result<bool> {
    match head(b2, key).await {
        Ok(_) => Ok(true),
        Err(StoreError::NotFound(_)) => Ok(false),
        Err(e) => Err(e),
    }
}

pub(super) async fn delete(b2: &B2Backend, key: &ObjectKey) -> Result<()> {
    let auth = b2.auth().await?;
    // Delete every version of this exact file name (idempotent — none is fine).
    let resp: ListFileVersionsResponse = b2
        .post_json(
            &auth,
            constants::EP_LIST_FILE_VERSIONS,
            serde_json::json!({
                "bucketId": auth.bucket_id,
                "startFileName": key.as_str(),
                "prefix": key.as_str(),
                "maxFileCount": constants::LIST_PAGE_SIZE,
            }),
        )
        .await?;

    for version in resp
        .files
        .into_iter()
        .filter(|v| v.file_name == key.as_str())
    {
        let _: DeleteFileVersionResponse = b2
            .post_json(
                &auth,
                constants::EP_DELETE_FILE_VERSION,
                serde_json::json!({ "fileName": version.file_name, "fileId": version.file_id }),
            )
            .await?;
    }
    Ok(())
}

fn to_meta(f: super::api::FileItem) -> ObjectMeta {
    ObjectMeta {
        key: ObjectKey::new(f.file_name),
        size: f.content_length,
        modified_unix: Some(f.upload_timestamp / constants::MILLIS_PER_SECOND),
    }
}
