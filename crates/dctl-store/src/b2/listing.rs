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
        // No filesystem, no links. See `crate::links`.
        ..Page::default()
    })
}

pub(super) async fn head(b2: &B2Backend, key: &ObjectKey) -> Result<ObjectMeta> {
    let auth = b2.auth().await?;
    let resp: ListFileNamesResponse = b2
        .post_json(
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
    delete_every_version(
        &LiveVersions {
            b2,
            bucket_id: auth.bucket_id.clone(),
            key,
        },
        key.as_str(),
    )
    .await
}

/// The two calls the version-delete loop makes, behind a seam a test can drive.
///
/// The loop *is* the fix, and a loop written straight against
/// [`B2Backend::post_json`] cannot be exercised without a live bucket. That is
/// how the first attempt at this shipped with tests that only proved the
/// continuation tokens **deserialised**: deleting the loop and returning after
/// the first page left the whole workspace suite green — 2947 passed, 0 failed —
/// so the defect the commit was written for could walk straight back in.
///
/// One indirection buys a test that fails for the reason the defect exists.
#[async_trait::async_trait]
trait VersionPages {
    /// One page of versions, resumed from `(start_name, start_id)`.
    ///
    /// Both tokens together or neither: a version listing is keyed by
    /// `(fileName, fileId)`, so resuming from the name alone restarts at that
    /// name's newest version — a loop that never terminates and never finishes
    /// deleting.
    async fn page(
        &self,
        start_name: Option<String>,
        start_id: Option<String>,
    ) -> Result<ListFileVersionsResponse>;

    /// Remove one version, addressed by the pair that identifies it.
    async fn remove(&self, file_name: &str, file_id: &str) -> Result<()>;
}

/// Delete every version of `name`, following the server's continuations.
///
/// Each page is deleted before the next is requested, which keeps memory flat
/// over a name with a hundred thousand versions. The cursor then points at
/// versions that no longer exist — harmless, because B2's cursor is a position
/// in a name-ordered sequence rather than a handle to a row.
///
/// The loop ends when the server stops offering a continuation, **never** on a
/// page that happened to come back short: B2 may return fewer rows than asked
/// for at any point, and treating that as the end is how the original defect
/// would return wearing a different shape.
async fn delete_every_version(pages: &(impl VersionPages + Sync), name: &str) -> Result<()> {
    let mut start_name: Option<String> = Some(name.to_string());
    let mut start_id: Option<String> = None;

    loop {
        let resp = pages.page(start_name, start_id).await?;

        // The listing is by prefix, so a longer name sharing this one's opening
        // characters comes back in the same page and must be left alone.
        for version in resp.files.iter().filter(|v| v.file_name == name) {
            pages.remove(&version.file_name, &version.file_id).await?;
        }

        match resp.next_file_name {
            Some(next) => {
                start_name = Some(next);
                start_id = resp.next_file_id;
            }
            None => return Ok(()),
        }
    }
}

/// [`VersionPages`] against the real bucket.
struct LiveVersions<'a> {
    b2: &'a B2Backend,
    bucket_id: String,
    key: &'a ObjectKey,
}

#[async_trait::async_trait]
impl VersionPages for LiveVersions<'_> {
    async fn page(
        &self,
        start_name: Option<String>,
        start_id: Option<String>,
    ) -> Result<ListFileVersionsResponse> {
        self.b2
            .post_json(
                constants::EP_LIST_FILE_VERSIONS,
                serde_json::json!({
                    "bucketId": self.bucket_id,
                    "startFileName": start_name,
                    "startFileId": start_id,
                    "prefix": self.key.as_str(),
                    "maxFileCount": constants::LIST_PAGE_SIZE,
                }),
            )
            .await
    }

    async fn remove(&self, file_name: &str, file_id: &str) -> Result<()> {
        let _: DeleteFileVersionResponse = self
            .b2
            .post_json(
                constants::EP_DELETE_FILE_VERSION,
                serde_json::json!({ "fileName": file_name, "fileId": file_id }),
            )
            .await?;
        Ok(())
    }
}

/// Describe one listed file, preferring the source's own modification time.
///
/// ## The rule for objects written before DCTL sent a time
///
/// `src_last_modified_millis` is read when it is there and `uploadTimestamp` is
/// used when it is not. That is the whole migration story, and it needs no
/// version field because the two facts are distinguishable by presence alone:
/// an object carrying the key was written with a source time, and one without it
/// was written before DCTL sent one (or by a tool that never did).
///
/// The fallback is deliberately *not* "absent". An object with no recorded source
/// time still has a true, useful timestamp — when the provider accepted it — and
/// reporting nothing would make `--update` unable to protect it and `dctl lsl`
/// print a blank column for half a bucket. It does mean an object uploaded before
/// this change is compared against a source time it never recorded and is
/// transferred once more; after that one run it carries its own time and is never
/// sent again. Silently pretending the upload time *is* the source time is what
/// the old code did, and it is why every run was a full run.
fn to_meta(f: super::api::FileItem) -> ObjectMeta {
    let recorded = f
        .file_info
        .get(constants::FILE_INFO_SRC_MODIFIED)
        .and_then(|millis| millis.parse::<i64>().ok())
        // Floor division, so a pre-epoch millisecond value does not round
        // *towards* the epoch and land a file one second later than it is.
        .map(|millis| millis.div_euclid(constants::MILLIS_PER_SECOND));
    ObjectMeta {
        key: ObjectKey::new(f.file_name),
        size: f.content_length,
        modified_unix: Some(recorded.unwrap_or(f.upload_timestamp / constants::MILLIS_PER_SECOND)),
    }
}

#[cfg(test)]
mod meta_tests {
    use super::to_meta;
    use crate::b2::api::FileItem;

    fn item(body: serde_json::Value) -> FileItem {
        serde_json::from_value(body).expect("a listed file parses")
    }

    #[test]
    fn a_recorded_source_time_outranks_the_upload_timestamp() {
        // The whole point: the object was uploaded today and the file it holds
        // was last written in 2020. Reporting today is a true fact about a
        // different event, and it is what made every `sync` a full `sync`.
        let meta = to_meta(item(serde_json::json!({
            "fileName": "a.txt",
            "contentLength": 14,
            "uploadTimestamp": 1_784_000_000_000_i64,
            "action": "upload",
            "fileInfo": { "src_last_modified_millis": "1577836800000" },
        })));
        assert_eq!(meta.modified_unix, Some(1_577_836_800));
    }

    #[test]
    fn an_object_written_before_this_change_falls_back_to_its_upload_time() {
        // The migration rule, stated as a test: no key means no source time was
        // ever recorded, and the upload time is the only true timestamp there is.
        let meta = to_meta(item(serde_json::json!({
            "fileName": "old.txt",
            "contentLength": 3,
            "uploadTimestamp": 1_600_000_000_000_i64,
            "action": "upload",
        })));
        assert_eq!(meta.modified_unix, Some(1_600_000_000));
    }

    #[test]
    fn an_unparsable_source_time_falls_back_rather_than_failing_the_listing() {
        // Another tool may have written anything into that key. A whole bucket
        // must stay listable regardless.
        let meta = to_meta(item(serde_json::json!({
            "fileName": "odd.txt",
            "contentLength": 1,
            "uploadTimestamp": 1_600_000_000_000_i64,
            "action": "upload",
            "fileInfo": { "src_last_modified_millis": "not-a-number" },
        })));
        assert_eq!(meta.modified_unix, Some(1_600_000_000));
    }

    #[test]
    fn a_pre_epoch_source_time_rounds_away_from_the_epoch() {
        // Truncating division would turn -1500 ms into 1970-01-01T00:00:00 and
        // move the file *forwards* in time. Floor division keeps it before the
        // epoch, where it is.
        let meta = to_meta(item(serde_json::json!({
            "fileName": "ancient.txt",
            "contentLength": 1,
            "uploadTimestamp": 1_600_000_000_000_i64,
            "action": "upload",
            "fileInfo": { "src_last_modified_millis": "-1500" },
        })));
        assert_eq!(meta.modified_unix, Some(-2));
    }
}

#[cfg(test)]
mod delete_tests {
    use super::{VersionPages, delete_every_version};
    use crate::error::Result;
    use std::sync::Mutex;

    /// The object under test, and a longer name that shares its prefix.
    const NAME: &str = "probe/v.txt";
    const NEIGHBOUR: &str = "probe/v.txt.bak";

    /// One `(fileName, fileId)` row as B2 would return it.
    type Version = (&'static str, &'static str);

    /// One scripted page: its rows, then the two continuation tokens the server
    /// would offer with it. `None`/`None` is the end of the listing.
    type ScriptedPage = (Vec<Version>, Option<&'static str>, Option<&'static str>);

    /// A scripted bucket: pages handed out in order, deletions recorded.
    struct Scripted {
        /// Pages in the order B2 would send them.
        pages: Vec<ScriptedPage>,
        /// Every `(start_name, start_id)` the loop asked with.
        asked: Mutex<Vec<(Option<String>, Option<String>)>>,
        /// Every `fileId` the loop deleted.
        removed: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl VersionPages for Scripted {
        async fn page(
            &self,
            start_name: Option<String>,
            start_id: Option<String>,
        ) -> Result<super::ListFileVersionsResponse> {
            let mut asked = self.asked.lock().unwrap();
            let n = asked.len();
            asked.push((start_name, start_id));
            let (files, next_name, next_id) = self
                .pages
                .get(n)
                .cloned()
                .expect("the loop asked for a page the script does not have");
            let body = serde_json::json!({
                "files": files
                    .iter()
                    .map(|(name, id)| serde_json::json!({
                        "fileName": name, "fileId": id, "action": "upload"
                    }))
                    .collect::<Vec<_>>(),
                "nextFileName": next_name,
                "nextFileId": next_id,
            });
            Ok(serde_json::from_value(body).unwrap())
        }

        async fn remove(&self, _file_name: &str, file_id: &str) -> Result<()> {
            self.removed.lock().unwrap().push(file_id.to_string());
            Ok(())
        }
    }

    fn scripted(pages: Vec<ScriptedPage>) -> Scripted {
        Scripted {
            pages,
            asked: Mutex::new(Vec::new()),
            removed: Mutex::new(Vec::new()),
        }
    }

    #[tokio::test]
    async fn every_page_of_versions_is_deleted_not_only_the_first() {
        // The defect, exactly: one `b2_list_file_versions`, first page deleted,
        // `Ok` returned. `dctl deletefile` exited 0, the audit chain recorded
        // `delete success`, and `dctl ls` still listed the object while `dctl
        // cat` still read it back. B2 returns versions newest-first, so the
        // survivors were the *oldest* copies — the original content.
        let bucket = scripted(vec![
            (vec![(NAME, "id1"), (NAME, "id2")], Some(NAME), Some("id3")),
            (vec![(NAME, "id3"), (NAME, "id4")], Some(NAME), Some("id5")),
            (vec![(NAME, "id5")], None, None),
        ]);

        delete_every_version(&bucket, NAME).await.unwrap();

        assert_eq!(
            *bucket.removed.lock().unwrap(),
            ["id1", "id2", "id3", "id4", "id5"],
            "a version survived, so the object is still readable after a successful delete"
        );
    }

    #[tokio::test]
    async fn a_continuation_carries_the_file_id_and_not_only_the_name() {
        // Resuming from `nextFileName` alone restarts at that name's newest
        // version: the same page forever, and a delete that never completes.
        let bucket = scripted(vec![
            (vec![(NAME, "id1")], Some(NAME), Some("id2")),
            (vec![(NAME, "id2")], None, None),
        ]);

        delete_every_version(&bucket, NAME).await.unwrap();

        let asked = bucket.asked.lock().unwrap();
        assert_eq!(asked.len(), 2, "the second page was never requested");
        assert_eq!(
            asked[1],
            (Some(NAME.to_string()), Some("id2".to_string())),
            "the second request must resume from both tokens"
        );
    }

    #[tokio::test]
    async fn a_short_page_is_not_mistaken_for_the_end_of_the_listing() {
        // B2 may return fewer rows than `maxFileCount` at any point. Stopping on
        // a short page is the original defect wearing a different shape.
        let bucket = scripted(vec![
            (vec![(NAME, "id1")], Some(NAME), Some("id2")),
            (vec![(NAME, "id2")], None, None),
        ]);

        delete_every_version(&bucket, NAME).await.unwrap();

        assert_eq!(*bucket.removed.lock().unwrap(), ["id1", "id2"]);
    }

    #[tokio::test]
    async fn a_neighbour_sharing_the_prefix_is_left_alone() {
        // The listing is by prefix, so `probe/v.txt.bak` arrives in the same
        // page. Deleting it would turn one removal into two.
        let bucket = scripted(vec![(
            vec![(NAME, "id1"), (NEIGHBOUR, "other"), (NAME, "id2")],
            None,
            None,
        )]);

        delete_every_version(&bucket, NAME).await.unwrap();

        assert_eq!(*bucket.removed.lock().unwrap(), ["id1", "id2"]);
    }

    #[tokio::test]
    async fn a_name_with_no_versions_is_a_successful_no_op() {
        // The idempotence `Backend::delete` promises.
        let bucket = scripted(vec![(vec![], None, None)]);
        delete_every_version(&bucket, NAME).await.unwrap();
        assert!(bucket.removed.lock().unwrap().is_empty());
    }
}
