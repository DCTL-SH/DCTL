//! B2 API request/response DTOs and cached authorization state.

use serde::Deserialize;

/// Cached result of `b2_authorize_account` (+ resolved bucket id).
#[derive(Clone)]
pub(crate) struct AuthState {
    /// The account the key belongs to.
    ///
    /// Kept because `b2_list_buckets` needs it, and the store-identity probe has
    /// to call that again — fresh — on every check: the `bucket_id` below was
    /// resolved once when this run authorized, so comparing it against itself
    /// would answer "unchanged" for a bucket that had since been deleted.
    pub account_id: String,
    pub api_url: String,
    pub download_url: String,
    pub auth_token: String,
    pub bucket_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthorizeResponse {
    pub account_id: String,
    pub authorization_token: String,
    pub api_url: String,
    pub download_url: String,
    pub recommended_part_size: u64,
    pub allowed: Allowed,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Allowed {
    pub bucket_id: Option<String>,
    /// The name beside the id, when the key is bucket-restricted.
    ///
    /// Read so `authorize` can refuse a key whose restriction names a
    /// DIFFERENT bucket than the one configured — silently substituting the
    /// key's bucket for the configured one is how a stray half-initialised
    /// bucket appeared on a shared account.
    pub bucket_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListBucketsResponse {
    pub buckets: Vec<BucketItem>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BucketItem {
    pub bucket_id: String,
    pub bucket_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetUploadUrlResponse {
    pub upload_url: String,
    pub authorization_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UploadFileResponse {
    pub content_sha1: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StartLargeFileResponse {
    pub file_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetUploadPartUrlResponse {
    pub upload_url: String,
    pub authorization_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UploadPartResponse {
    pub content_sha1: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FinishLargeFileResponse {
    #[allow(dead_code)]
    pub file_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CancelLargeFileResponse {
    #[allow(dead_code)]
    pub file_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListFileNamesResponse {
    pub files: Vec<FileItem>,
    pub next_file_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FileItem {
    pub file_name: String,
    pub content_length: u64,
    /// The SHA-1 B2 computed over the bytes it accepted, as it reports it back.
    ///
    /// Kept as the provider's own string rather than a parsed digest, because
    /// three of its values are not digests: `"none"` on every large file, an
    /// `unverified:` prefix on an upload sent with `do_not_verify`, and — on an
    /// object written by some other tool through some other API — whatever that
    /// tool left. [`super::listing::stored_checksum`] is the one place that
    /// decides which of those is a value a re-read can be compared against.
    ///
    /// Optional and defaulted for the reason `file_info` is: an object whose
    /// listing omits the field is ordinary, not malformed, and refusing to
    /// parse the page it arrived in would make a whole bucket unlistable.
    #[serde(default)]
    pub content_sha1: Option<String>,
    pub upload_timestamp: i64,
    pub action: String,
    /// The `fileInfo` map B2 stores alongside the object.
    ///
    /// Only one key is read from it — `src_last_modified_millis`, the source's
    /// own modification time (`constants::FILE_INFO_SRC_MODIFIED`). It is
    /// defaulted rather than required because it is genuinely absent on every
    /// object written before DCTL sent it, and on every object any other tool
    /// wrote without one; an object with no `fileInfo` is ordinary, not
    /// malformed, and refusing to parse the page it arrived in would make a
    /// whole bucket unlistable.
    #[serde(default)]
    pub file_info: std::collections::HashMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListFileVersionsResponse {
    pub files: Vec<VersionItem>,
    /// Where the next page starts, or `None` at the end of the listing.
    ///
    /// **Both continuation fields are required together.** B2 keys a version
    /// listing by `(fileName, fileId)`, because one name has many versions, so
    /// resuming from `nextFileName` alone restarts at that name's *newest*
    /// version and loops forever over the first page. These two fields not
    /// existing on this struct at all is what made `delete` stop after one page
    /// and report success with the older versions still alive.
    pub next_file_name: Option<String>,
    /// See [`ListFileVersionsResponse::next_file_name`].
    pub next_file_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VersionItem {
    pub file_name: String,
    pub file_id: String,
}

/// `b2_list_unfinished_large_files` — the large files this account started and
/// never finished.
///
/// The parts of such a file are stored and billed and **no object listing shows
/// them**: `b2_list_file_names` returns objects, and an unfinished large file is
/// not one yet. This is the only call in the B2 API that can see them.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListUnfinishedResponse {
    pub files: Vec<UnfinishedItem>,
    /// Where the next page starts, or `None` at the end.
    ///
    /// Keyed by `fileId` rather than by name, because an unfinished large file
    /// has no committed name to key by and two of them may be aimed at the same
    /// one.
    pub next_file_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UnfinishedItem {
    pub file_id: String,
    pub file_name: String,
    /// When `b2_start_large_file` was called, in epoch milliseconds.
    ///
    /// Optional because it is what `--min-age` reads, and a reply that omitted it
    /// must produce "the age is unknown" — which the sweep holds on — rather than
    /// a parse failure that makes the whole page unreadable. B2 documents it as
    /// always present; the tolerance costs nothing and the alternative is a class
    /// that cannot be swept at all because one field moved.
    #[serde(default)]
    pub upload_timestamp: Option<i64>,
}

#[derive(Deserialize)]
pub(crate) struct DeleteFileVersionResponse {
    #[allow(dead_code)]
    #[serde(rename = "fileId")]
    pub file_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `b2_list_file_versions` reply with more to come, trimmed to the fields
    /// this crate reads. Both continuation tokens are present, because B2 keys a
    /// version listing by `(fileName, fileId)`.
    const CONTINUED: &str = r#"{
      "files": [
        {"fileName": "probe/v.txt", "fileId": "4_z50a_f100a", "action": "upload"},
        {"fileName": "probe/v.txt", "fileId": "4_z50a_f100b", "action": "upload"}
      ],
      "nextFileName": "probe/v.txt",
      "nextFileId": "4_z50a_f100c"
    }"#;

    /// The same reply at the end of the listing.
    const FINAL: &str = r#"{
      "files": [{"fileName": "probe/v.txt", "fileId": "4_z50a_f100z", "action": "upload"}],
      "nextFileName": null,
      "nextFileId": null
    }"#;

    #[test]
    fn a_version_listing_carries_both_continuation_tokens() {
        // The defect this pins was an *absence*: neither field existed on this
        // struct, so `delete` issued one request, deleted the first thousand
        // versions and returned `Ok`. `dctl deletefile` then exited 0 over an
        // object that `dctl ls` still listed and `dctl cat` still read back —
        // and because B2 returns versions newest-first, the survivors were the
        // *oldest* copies, which is the original content.
        //
        // Both tokens together, or neither: resuming from `nextFileName` alone
        // restarts at that name's newest version, which never terminates.
        let more: ListFileVersionsResponse =
            serde_json::from_str(CONTINUED).expect("a continued page parses");
        assert_eq!(more.files.len(), 2);
        assert_eq!(more.next_file_name.as_deref(), Some("probe/v.txt"));
        assert_eq!(more.next_file_id.as_deref(), Some("4_z50a_f100c"));

        let last: ListFileVersionsResponse =
            serde_json::from_str(FINAL).expect("a final page parses");
        assert_eq!(last.next_file_name, None);
        assert_eq!(last.next_file_id, None);
    }

    #[test]
    fn a_reply_with_no_continuation_keys_at_all_is_the_end_of_the_listing() {
        // An older or stricter server may omit the keys rather than send null.
        // Reading that as "there is more" would loop; reading it as an error
        // would refuse a perfectly good reply.
        let body = r#"{"files": []}"#;
        let page: ListFileVersionsResponse =
            serde_json::from_str(body).expect("an unadorned page parses");
        assert!(page.files.is_empty());
        assert_eq!(page.next_file_name, None);
    }
}
