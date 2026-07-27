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

/// Delete **every** version of this exact file name.
///
/// Idempotent: a name with no versions is a successful no-op, which is the
/// contract [`crate::backend::Backend::delete`] states.
///
/// ## Why this is a loop
///
/// It was a single `b2_list_file_versions` with `maxFileCount: 1000`, and the
/// response's continuation tokens were not even parsed. So a name with more than
/// a thousand versions had its first page deleted and the call returned `Ok`:
///
/// ```text
/// $ dctl deletefile b2:probe/manyver/v.txt
/// removed             13 B  probe/manyver/v.txt
/// OK removed: 1 object(s), 13 B                       [exit=0]
/// $ dctl ls b2:probe/manyver
///       10 B v.txt                                    <- still there
/// $ dctl cat b2:probe/manyver/v.txt
/// version 2                                           <- still readable
/// ```
///
/// A customer invokes "delete my data". DCTL exits 0, the audit chain records
/// `delete success`, and the object is still listed and still readable. B2
/// returns versions **newest-first**, so the survivors are the *oldest* copies —
/// the original content, not a recent revision.
///
/// A thousand versions is not exotic on this provider. Every `copy` or `sync`
/// creates a new one, so an hourly job crosses the threshold in six weeks.
///
/// ## Both continuation tokens, or none
///
/// A version listing is keyed by `(fileName, fileId)`, because one name has many
/// versions. Resuming from `nextFileName` alone restarts at that name's newest
/// version, which is a loop that never terminates and never finishes deleting.
/// The two tokens are therefore sent together or not at all.
///
/// ## Deleting while listing
///
/// Each page is deleted before the next is requested, which is what keeps memory
/// flat over a name with a hundred thousand versions. It also means the cursor
/// points at versions that no longer exist — harmless, because B2's cursor is a
/// position in a name-ordered sequence rather than a handle to a row, and a
/// deleted version simply is not returned again. The loop ends when the server
/// stops offering a continuation, never on a page that happened to come back
/// short.
pub(super) async fn delete(b2: &B2Backend, key: &ObjectKey) -> Result<()> {
    let auth = b2.auth().await?;
    let mut start_name: Option<String> = Some(key.as_str().to_string());
    let mut start_id: Option<String> = None;

    loop {
        let resp: ListFileVersionsResponse = b2
            .post_json(
                &auth,
                constants::EP_LIST_FILE_VERSIONS,
                serde_json::json!({
                    "bucketId": auth.bucket_id,
                    "startFileName": start_name,
                    "startFileId": start_id,
                    "prefix": key.as_str(),
                    "maxFileCount": constants::LIST_PAGE_SIZE,
                }),
            )
            .await?;

        for version in resp.files.iter().filter(|v| v.file_name == key.as_str()) {
            let _: DeleteFileVersionResponse = b2
                .post_json(
                    &auth,
                    constants::EP_DELETE_FILE_VERSION,
                    serde_json::json!({
                        "fileName": version.file_name,
                        "fileId": version.file_id,
                    }),
                )
                .await?;
        }

        // The server decides when the listing is over. A short page is not the
        // end — B2 may return fewer rows than asked for at any point — and
        // stopping on one is how the original defect would come back wearing a
        // different shape.
        match resp.next_file_name {
            Some(next) => {
                start_name = Some(next);
                start_id = resp.next_file_id;
            }
            None => return Ok(()),
        }
    }
}

fn to_meta(f: super::api::FileItem) -> ObjectMeta {
    ObjectMeta {
        key: ObjectKey::new(f.file_name),
        size: f.content_length,
        modified_unix: Some(f.upload_timestamp / constants::MILLIS_PER_SECOND),
    }
}
