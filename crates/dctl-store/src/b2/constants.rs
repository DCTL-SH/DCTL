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

/// Names for the two operations that are not `b2api/v2` endpoint calls, used in
/// the log line a retry emits so every retried operation is identifiable.
pub(super) const OP_DOWNLOAD: &str = "b2_download_file_by_name";
pub(super) const OP_UPLOAD_FILE: &str = "b2_upload_file";
pub(super) const OP_UPLOAD_PART: &str = "b2_upload_part";

/// Name of the authorization call in a log line. Not appended to `apiUrl` —
/// [`AUTHORIZE_URL`] is absolute — but a retried authorization has to be
/// identifiable in the log alongside every other retried operation.
pub(super) const EP_AUTHORIZE: &str = "b2_authorize_account";

// Endpoints (appended to `{apiUrl}/{API_PREFIX}/`).
pub(super) const EP_LIST_BUCKETS: &str = "b2_list_buckets";
pub(super) const EP_GET_UPLOAD_URL: &str = "b2_get_upload_url";
pub(super) const EP_START_LARGE_FILE: &str = "b2_start_large_file";
pub(super) const EP_GET_UPLOAD_PART_URL: &str = "b2_get_upload_part_url";
pub(super) const EP_FINISH_LARGE_FILE: &str = "b2_finish_large_file";
pub(super) const EP_CANCEL_LARGE_FILE: &str = "b2_cancel_large_file";
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
/// B2's documented maximum part size (bytes) for large files: 5 GB, in B2's decimal
/// byte convention (matching `MIN_PART_SIZE`'s 5 MB). This is the upper bound when
/// adaptively growing part size to keep a large file within B2's 10,000-part cap;
/// combined, a single large file is bounded at 5 GB * 10,000 = 50 TB.
/// See <https://www.backblaze.com/apidocs/b2-upload-part>.
pub(super) const B2_MAX_PART_SIZE: u64 = 5_000_000_000;
/// Objects larger than this use the large-file (multipart) API.
pub(super) const MULTIPART_THRESHOLD: u64 = 100 * 1024 * 1024;
/// Objects requested per listing page.
pub(super) const LIST_PAGE_SIZE: u32 = 1000;
/// The `action` value marking a real uploaded file (vs a hide marker).
pub(super) const ACTION_UPLOAD: &str = "upload";
/// B2 upload timestamps are epoch milliseconds; divide to get seconds.
pub(super) const MILLIS_PER_SECOND: i64 = 1000;

/// The header B2 sends to name how long a client should wait before asking
/// again. Sent with `429` and sometimes with `503`.
pub(super) const H_RETRY_AFTER: &str = "Retry-After";

// ── Retry schedule (see `super::retry`) ─────────────────────────────────────
//
// The numbers below bound one request's total patience. They are here rather
// than in the retry module for the same reason every other protocol constant is
// here: an operator asking "how long will `dctl` sit on a failing bucket?" gets
// the whole answer from one file.

/// How many attempts one B2 request gets, the first one included.
///
/// Five retries after the original. Enough to ride out the pod rotation behind a
/// `503 no tomes available` — which is what B2 answers when an upload URL's
/// storage pod is busy, and which took five of ten files out of the first live
/// restore drill — without turning a genuinely broken bucket into a run that
/// looks hung. With the backoff below the worst case is under sixteen seconds of
/// waiting per request.
pub(super) const RETRY_MAX_ATTEMPTS: u32 = 6;

/// The wait before the second attempt; every later wait doubles it.
///
/// Half a second, because the failures this schedule is for are decided by
/// another machine picking a different pod, not by anything healing. Retrying
/// instantly would spend the whole budget inside the window that made the first
/// attempt fail.
pub(super) const RETRY_FIRST_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);

/// The longest the schedule itself will wait between two attempts.
///
/// Eight seconds: past this the doubling stops buying resilience and starts
/// buying a run nobody can tell from a hang. A `Retry-After` the server actually
/// sent is honoured beyond this — the server knows something the schedule does
/// not — up to [`RETRY_AFTER_CAP`].
pub(super) const RETRY_MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(8);

/// The longest a server-sent `Retry-After` is obeyed.
///
/// A minute. B2 sends `Retry-After` with a rate limit, where obeying it is the
/// difference between being throttled and being blocked, so it wins over the
/// schedule. It does not win unboundedly: a header of `86400` on a nightly
/// backup would produce a process that sits silent for a day, and a failure an
/// operator can see beats a wait they cannot.
pub(super) const RETRY_AFTER_CAP: std::time::Duration = std::time::Duration::from_secs(60);
