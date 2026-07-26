//! B2 protocol constants — endpoint paths, header names, content types, limits.
//!
//! These are part of the Backblaze B2 native API (v2), not app configuration.
//! Centralized here so no protocol literal is duplicated across the module.

/// Global authorization endpoint (region-independent; returns region URLs).
pub(super) const AUTHORIZE_URL: &str = "https://api.backblazeb2.com/b2api/v2/b2_authorize_account";
/// Path prefix for API endpoints under the account's `apiUrl`.
pub(super) const API_PREFIX: &str = "b2api/v2";
/// Path segment for file downloads under the account's `downloadUrl`.
pub(super) const DOWNLOAD_SEGMENT: &str = "file";

// Endpoints (appended to `{apiUrl}/{API_PREFIX}/`).
pub(super) const EP_LIST_BUCKETS: &str = "b2_list_buckets";
pub(super) const EP_GET_UPLOAD_URL: &str = "b2_get_upload_url";
pub(super) const EP_START_LARGE_FILE: &str = "b2_start_large_file";
pub(super) const EP_GET_UPLOAD_PART_URL: &str = "b2_get_upload_part_url";
pub(super) const EP_FINISH_LARGE_FILE: &str = "b2_finish_large_file";
pub(super) const EP_LIST_FILE_NAMES: &str = "b2_list_file_names";
pub(super) const EP_LIST_FILE_VERSIONS: &str = "b2_list_file_versions";
pub(super) const EP_DELETE_FILE_VERSION: &str = "b2_delete_file_version";

// Header names.
pub(super) const H_AUTHORIZATION: &str = "Authorization";
pub(super) const H_FILE_NAME: &str = "X-Bz-File-Name";
pub(super) const H_CONTENT_SHA1: &str = "X-Bz-Content-Sha1";
pub(super) const H_PART_NUMBER: &str = "X-Bz-Part-Number";
pub(super) const H_CONTENT_TYPE: &str = "Content-Type";
pub(super) const H_CONTENT_LENGTH: &str = "Content-Length";
pub(super) const H_RANGE: &str = "Range";

/// Content type instructing B2 to auto-detect (`b2/x-auto`).
pub(super) const CONTENT_TYPE_AUTO: &str = "b2/x-auto";

/// B2's absolute minimum part size (bytes) for large files.
pub(super) const MIN_PART_SIZE: u64 = 5_000_000;
/// Objects larger than this use the large-file (multipart) API.
pub(super) const MULTIPART_THRESHOLD: u64 = 100 * 1024 * 1024;
/// Objects requested per listing page.
pub(super) const LIST_PAGE_SIZE: u32 = 1000;
/// The `action` value marking a real uploaded file (vs a hide marker).
pub(super) const ACTION_UPLOAD: &str = "upload";
/// B2 upload timestamps are epoch milliseconds; divide to get seconds.
pub(super) const MILLIS_PER_SECOND: i64 = 1000;
