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
pub(super) const EP_LIST_UNFINISHED: &str = "b2_list_unfinished_large_files";
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

/// The `fileInfo` key B2 reserves for the source's own last-modified time, in
/// epoch milliseconds.
///
/// Not a name invented here: it is the key Backblaze documents for exactly this
/// purpose and the one `rclone` reads and writes, so a bucket written by DCTL
/// keeps its timestamps when read by rclone and the other way round. Choosing a
/// private spelling would have made every object DCTL wrote look, to every other
/// tool, like a file last modified when it was uploaded.
///
/// See <https://www.backblaze.com/apidocs/b2-upload-file>.
pub(super) const FILE_INFO_SRC_MODIFIED: &str = "src_last_modified_millis";
/// [`FILE_INFO_SRC_MODIFIED`] as an upload header: B2 carries `fileInfo` on
/// `b2_upload_file` as `X-Bz-Info-<key>`.
pub(super) const H_SRC_MODIFIED: &str = "X-Bz-Info-src_last_modified_millis";

/// Content type instructing B2 to auto-detect (`b2/x-auto`).
pub(super) const CONTENT_TYPE_AUTO: &str = "b2/x-auto";

// ── The upload's memory contract ────────────────────────────────────────────
//
// An upload's peak resident memory is
//
//     peak ≈ part_size × UPLOAD_PARTS_IN_FLIGHT
//
// and **no term in it is a function of the object's size**. One part is read
// into one buffer, that buffer is handed to the request as an owned `Bytes`, and
// every attempt at that part re-sends the same allocation instead of a copy of
// it; the buffer is released before the next part's is taken. Parts go one at a
// time, so the multiplier is [`UPLOAD_PARTS_IN_FLIGHT`] = 1.
//
// It is written here rather than in `upload.rs` because both numbers it is made
// of are here, and because the previous shape of this backend — a reusable part
// buffer plus a fresh `to_vec()` of every attempt — cost *twice* the part size
// while its own doc comment claimed `O(part_size)`. A contract stated beside the
// code that implements it is a contract a reader checks.
//
// The one term that is not flat is forced by B2 and not chosen here:
// `b2_upload_part` accepts at most [`MAX_PARTS`](crate::streaming::MAX_PARTS)
// = 10,000 parts per large file, so an object larger than
// `part_size × 10,000` must be cut into bigger parts and the peak grows as
// `object / 10,000`. At the default part size that floor starts at 1 TiB. It is
// a documented slope rather than a surprise, and `adaptive_part_size` is where
// it happens.

/// Default multipart part size, and — because they are the same number — the
/// size above which an object stops being uploaded in one request.
///
/// This is a **memory** knob before it is a throughput one: it is the whole of
/// the peak above, so an operator who must run inside a small container lowers
/// it and pays in request count. It reaches here from a remote's `chunk_size`
/// setting through [`B2Backend::with_part_size`](super::B2Backend::with_part_size).
///
/// B2's `b2_authorize_account` answers with a `recommendedPartSize` — 100,000,000
/// bytes on the account this was measured against — and it is deliberately **not**
/// used as the default. It is advisory, it is per-account, and it arrives from the
/// network: taking it would make DCTL's peak memory whatever the provider said
/// that morning, which is not a contract anybody can hold the tool to. `rclone`
/// makes the same call — it parses `recommendedPartSize` into
/// `api.AuthorizeAccountResponse` (`backend/b2/api/types.go:150`) and never sizes
/// an upload with it, using its own `defaultChunkSize = 96 * fs.Mebi`
/// (`backend/b2/b2.go:67`) instead.
///
/// 100 MiB is the same number as the S3 client's own `DEFAULT_PART_SIZE`, so the
/// two object-store families state one memory figure rather than two, and it is
/// twenty times B2's five-megabyte floor — few enough requests on a large object
/// that the per-request cost stays invisible, small enough that a retried part is
/// not an expensive thing to lose.
pub(super) const DEFAULT_PART_SIZE: u64 = 100 * 1024 * 1024;

/// How many parts of one object are in flight at once.
///
/// One. It is a named constant rather than an unwritten property of a `for` loop
/// because it is the second factor in the contract above: uploading four parts
/// concurrently would quadruple the peak, and the change that did it would be a
/// change to a loop with no obvious connection to a memory figure recorded in
/// `HANDOVER.md`. The memory test in `tests/b2_upload_memory.rs` computes its
/// ceiling from this constant, so raising the concurrency without raising this
/// fails a test that names the reason.
pub(super) const UPLOAD_PARTS_IN_FLIGHT: u64 = 1;

/// B2's absolute minimum part size (bytes) for large files.
///
/// A provider limit, not a preference. A configured part size below it is raised
/// rather than refused: the alternative is an upload that is accepted, runs, and
/// is rejected at the second part, long after the operator stopped watching.
pub(super) const MIN_PART_SIZE: u64 = 5_000_000;
/// B2's documented maximum part size (bytes) for large files: 5 GB, in B2's decimal
/// byte convention (matching `MIN_PART_SIZE`'s 5 MB). This is the upper bound when
/// adaptively growing part size to keep a large file within B2's 10,000-part cap;
/// combined, a single large file is bounded at 5 GB * 10,000 = 50 TB.
/// See <https://www.backblaze.com/apidocs/b2-upload-part>.
pub(super) const B2_MAX_PART_SIZE: u64 = 5_000_000_000;
/// Objects requested per listing page.
pub(super) const LIST_PAGE_SIZE: u32 = 1000;
/// Unfinished large files requested per listing page.
///
/// **One hundred, not [`LIST_PAGE_SIZE`]'s thousand**, because B2 documents a
/// different ceiling for this endpoint: `b2_list_file_names` accepts up to
/// 10 000 and `b2_list_unfinished_large_files` accepts up to 100, and sending
/// the larger number is a `400 bad_request` — *"maxFileCount must be in the
/// range 1 - 100"* — rather than a value the server quietly clamps.
///
/// It has its own constant rather than sharing the listing's because the two
/// limits are set by two different endpoints and nothing about the code makes
/// them move together. Sharing one was the defect: the sweep worked against the
/// mock, passed the gate, and failed on the first real bucket it met.
///
/// See <https://www.backblaze.com/apidocs/b2-list-unfinished-large-files>.
pub(super) const UNFINISHED_PAGE_SIZE: u32 = 100;
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
