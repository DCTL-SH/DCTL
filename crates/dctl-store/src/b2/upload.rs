//! B2 uploads: SHA-1-verified single-file and large-file (multipart) paths, both
//! from an in-memory `Bytes` (`put`) and streamed from a file (`put_from_path`).
//!
//! ## Every body here is an owned `Bytes`, and that is the memory contract
//!
//! [`constants`] states it: peak ≈ `part_size × UPLOAD_PARTS_IN_FLIGHT`, with no
//! term in the object's size. What makes it true is that a part is materialised
//! **once** — read into one buffer, handed to the request as an owned `Bytes`,
//! and re-sent by cloning that handle on every attempt. Nothing here calls
//! `to_vec` or `copy_from_slice` on a body, and nothing should: those were the
//! two lines that made this backend cost twice its part size while the doc
//! comment above the buffer said `O(part_size)`. Measured on the release binary
//! under a 512 MiB cap, that was 213 MiB of RSS for every object from 128 MiB to
//! 4 GiB; the same runs afterwards are in `HANDOVER.md` §25.
//!
//! `rclone` reaches the same place from the other direction: it hands the part
//! upload an `io.ReadSeeker` over one pooled buffer and **rewinds** it for a
//! retry rather than buffering a second copy (`backend/b2/upload.go:251-259`),
//! and returns the buffer to a pool afterwards (`lib/multipart/multipart.go:74`,
//! `:80-83`). A `Bytes` clone is the same idea with the refcount doing the work.

use std::path::Path;

use bytes::Bytes;

use crate::backend::UploadTicket;
use crate::checksum::{ContentHash, Hasher};
use crate::deadline::Answered;
use crate::error::{Result, StoreError};
use crate::model::{ObjectKey, PutOutcome};
use crate::modified::SourceModified;
use crate::streaming;

use super::api::{
    AuthState, CancelLargeFileResponse, FinishLargeFileResponse, GetUploadPartUrlResponse,
    GetUploadUrlResponse, ListUnfinishedResponse, StartLargeFileResponse, UploadFileResponse,
    UploadPartResponse,
};
use super::name::encode_file_name;
use super::retry::{self, Attempt};
use super::{B2Backend, constants, read_json, stalled_attempt, transport_attempt};

/// The `fileInfo` B2 stores with an object, as the JSON body of
/// `b2_start_large_file` wants it.
///
/// Empty when the writer had no time to record — B2 then stamps only its own
/// `uploadTimestamp`, which is what [`listing::to_meta`](super::listing) falls
/// back to.
fn file_info(modified: SourceModified) -> serde_json::Value {
    match modified.millis() {
        Some(millis) => {
            serde_json::json!({ constants::FILE_INFO_SRC_MODIFIED: millis.to_string() })
        }
        None => serde_json::json!({}),
    }
}

/// The whole `b2_start_large_file` request body.
///
/// A value the two large-file paths *transmit* rather than a body each of them
/// assembles, and that is the point: the source's modification time is carried
/// in `fileInfo`, and while each call site built its own JSON the only thing
/// that could notice the field going missing was a live test against a real
/// bucket (`HANDOVER.md` §15.4). Deleting it from here fails
/// `cargo test --workspace`, which is the gate this project quotes.
fn start_large_file_body(
    bucket_id: &str,
    key: &ObjectKey,
    modified: SourceModified,
) -> serde_json::Value {
    serde_json::json!({
        "bucketId": bucket_id,
        "fileName": key.as_str(),
        "contentType": constants::CONTENT_TYPE_AUTO,
        "fileInfo": file_info(modified),
    })
}

/// Every header a single-file upload carries except the per-attempt
/// `Authorization`, which belongs to the upload URL and changes on each retry.
///
/// The same argument as [`start_large_file_body`], on the path that carries most
/// objects: the source's time travels with the bytes as
/// `X-Bz-Info-src_last_modified_millis`, and it used to be three lines inside a
/// retry closure that no offline test could reach. It travels with the bytes
/// rather than in a later call because B2 fixes `fileInfo` at upload — changing
/// it afterwards means copying the object onto itself, which is a second request
/// and a second *version* of every file on every run.
fn upload_headers(
    key: &ObjectKey,
    sha1_hex: &str,
    content_len: usize,
    modified: SourceModified,
) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        (constants::H_FILE_NAME, encode_file_name(key.as_str())),
        (
            constants::H_CONTENT_TYPE,
            constants::CONTENT_TYPE_AUTO.to_string(),
        ),
        (constants::H_CONTENT_SHA1, sha1_hex.to_string()),
        (constants::H_CONTENT_LENGTH, content_len.to_string()),
    ];
    if let Some(millis) = modified.millis() {
        headers.push((constants::H_SRC_MODIFIED, millis.to_string()));
    }
    headers
}

pub(super) async fn put(
    b2: &B2Backend,
    key: &ObjectKey,
    data: Bytes,
    expected: &ContentHash,
    modified: SourceModified,
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
    let size = data.len() as u64;
    if streaming::use_multipart(size, b2.part_size()) {
        upload_large(b2, &auth, key, &data, modified).await?;
    } else {
        upload_single(b2, &auth, key, data, &sha1, modified).await?;
    }

    // B2 confirmed the SHA-1 of the exact bytes we sent, and those bytes matched
    // `expected` (guard above) — so the stored object matches `expected`.
    Ok(PutOutcome {
        size,
        verified: caller,
    })
}

/// Upload the whole object in one request, fetching the upload URL that request
/// needs, and retrying both together.
///
/// The pairing is the point. B2 hands out an upload URL bound to one storage
/// pod, and answers `503 {"code":"service_unavailable","message":"no tomes
/// available"}` when that pod cannot take the write. Its documented remedy is to
/// call `b2_get_upload_url` **again** and send the bytes to whatever pod comes
/// back; replaying the same URL arrives at the same busy pod. So the retry has
/// to enclose the URL fetch, which is why this reaches for `post_json_once`
/// rather than the retrying `post_json` underneath it — one loop per logical
/// operation, not two nested ones whose combined budget nobody can state.
///
/// This is not hypothetical tidiness: the first live restore drill against a
/// real bucket lost five of ten files to exactly that `503`, reported
/// `Errors: 5` and exit 6, and left the backup half stored.
async fn upload_single(
    b2: &B2Backend,
    auth: &AuthState,
    key: &ObjectKey,
    data: Bytes,
    sha1: &ContentHash,
    modified: SourceModified,
) -> Result<()> {
    let sha1_hex = sha1.hex();
    // Assembled once, outside the retry, because it is the same request every
    // attempt: a header set rebuilt per attempt is a header set that can differ
    // between them.
    let headers = upload_headers(key, &sha1_hex, data.len(), modified);
    retry::run(constants::OP_UPLOAD_FILE, b2.deadlines.run, |_| async {
        let upload: GetUploadUrlResponse = b2
            .post_json_once(
                auth,
                constants::EP_GET_UPLOAD_URL,
                serde_json::json!({ "bucketId": auth.bucket_id }),
            )
            .await?;

        tracing::debug!(bytes = data.len(), "b2 upload (single-file)");
        let mut request = b2
            .client
            .post(&upload.upload_url)
            // Bound to the URL this attempt was handed, so it is the one header
            // that cannot come from the description above.
            .header(constants::H_AUTHORIZATION, &upload.authorization_token);
        for (name, value) in &headers {
            request = request.header(*name, value);
        }
        // The object's one buffer, re-sent rather than re-copied: `Bytes::clone`
        // moves a refcount, so a retried upload costs no memory beyond the
        // allocation the first attempt already had. Framing it for the deadline
        // costs nothing further: the frames are views of that same buffer.
        let watch = b2.deadlines.watch();
        let response = watch
            .guard(request.body(watch.body(data.clone())).send())
            .await
            .map_err(stalled_attempt)?
            .map_err(transport_attempt)?;

        let info: UploadFileResponse = b2
            .observe_expiry(read_json(Answered { watch, response }).await)
            .await?;
        // A SHA-1 B2 echoes back wrong is not a busy pod: B2 already checked the
        // body against the header it was sent, so a different digest in the
        // answer is what it holds. Settled, so it is reported as the mismatch it
        // is on the first attempt rather than after five more whole uploads.
        verify_sha1(&sha1_hex, &info.content_sha1).map_err(Attempt::settled)
    })
    .await
}

/// In-memory large-file upload (the buffered `>threshold` path reachable via [`put`]).
/// Cancels the large file on any error so no unfinished large file lingers (consuming
/// storage and unfinished-file quota) — mirroring the streaming sibling
/// [`stream_large_from_path`].
async fn upload_large(
    b2: &B2Backend,
    auth: &AuthState,
    key: &ObjectKey,
    data: &Bytes,
    modified: SourceModified,
) -> Result<()> {
    let start: StartLargeFileResponse = b2
        .post_json(
            constants::EP_START_LARGE_FILE,
            start_large_file_body(&auth.bucket_id, key, modified),
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

/// Upload every part of the in-memory `data`, then finish the large file. Any
/// error propagates to [`upload_large`], which cancels the large file.
async fn upload_parts_and_finish(
    b2: &B2Backend,
    auth: &AuthState,
    file_id: &str,
    data: &Bytes,
) -> Result<()> {
    // Grow the part size for very large objects so the part count stays within B2's
    // 10,000-part cap; normal objects keep the configured part size.
    let part_size = streaming::adaptive_part_size(
        data.len() as u64,
        b2.part_size(),
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
        // A view of the caller's buffer, not a copy of a piece of it: this arm is
        // already holding the whole object, and copying each part out of it would
        // add a part's worth of memory on top of an object's worth.
        upload_one_part(
            b2,
            auth,
            file_id,
            span.number,
            data.slice(start..end),
            &mut part_sha1s,
        )
        .await?;
    }

    let _: FinishLargeFileResponse = b2
        .post_json(
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
/// At or below the part size the (bounded) file is read and handed to the verified
/// single-shot [`put`], exactly matching the buffered path. Above it, the file is streamed
/// part-by-part through the native large-file API at `O(part_size)` memory. This mirrors
/// the live-verified buffered [`upload_large`] — same cutoff, same part size, same
/// per-part SHA-1 verification — only fed from a file instead of an in-RAM slice.
///
/// The two arms share one number, which is what keeps the memory contract to a
/// single figure: whichever arm runs, the most this holds is one part size. When
/// the cutoff was its own larger constant the *small* arm was the expensive one —
/// a 99 MiB object cost 203 MiB of anonymous memory and a 4 GiB object cost 197.
pub(super) async fn put_from_path(
    b2: &B2Backend,
    key: &ObjectKey,
    source: &Path,
    expected: &ContentHash,
    modified: SourceModified,
) -> Result<PutOutcome> {
    let size = tokio::fs::metadata(source).await?.len();

    // At or below one part: read the bounded file and use the verified single-shot
    // path, exactly like `put` (same in-memory guard + SHA-1 upload).
    if !streaming::use_multipart(size, b2.part_size()) {
        let data = tokio::fs::read(source).await?;
        return put(b2, key, Bytes::from(data), expected, modified).await;
    }

    let auth = b2.auth().await?;
    stream_large_from_path(b2, &auth, key, source, expected, modified).await
}

/// Stream a large file to B2, aborting the large-file upload on any error so nothing
/// partial is ever committed.
async fn stream_large_from_path(
    b2: &B2Backend,
    auth: &AuthState,
    key: &ObjectKey,
    source: &Path,
    expected: &ContentHash,
    modified: SourceModified,
) -> Result<PutOutcome> {
    let start: StartLargeFileResponse = b2
        .post_json(
            constants::EP_START_LARGE_FILE,
            start_large_file_body(&auth.bucket_id, key, modified),
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
    // 10,000-part cap; normal objects keep the configured part size. Computed once from
    // the total and used for the whole upload.
    //
    // This is the one place the peak stops being flat, and it is B2's rule rather
    // than a choice made here: past `part_size × MAX_PARTS` there is no way to
    // send the object without larger parts. See `constants`.
    let part_size = streaming::adaptive_part_size(
        size,
        b2.part_size(),
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
    // Whole-file hash under the caller's algorithm, folded part-by-part, so the
    // verified-write contract holds without ever buffering the whole file.
    let mut whole = Hasher::new(expected.algo);
    let mut part_sha1s: Vec<String> = Vec::with_capacity(plan.len());

    for span in &plan {
        let want = span.len as usize;
        // One allocation per part, given away to the request as an owned `Bytes`
        // so that the bytes on the wire are *this* buffer and not a copy of it.
        // The previous part's buffer is dropped when its upload returns, before
        // this one is taken, which is what makes the peak one part and not two —
        // the reusable buffer this replaces was live at the same time as the copy
        // the request needed, and cost exactly double.
        let mut part = vec![0u8; want];
        let n = streaming::fill_buf(&mut file, &mut part).await?;
        if n != want {
            return Err(StoreError::Backend(
                "b2 stream: source file shorter than expected (changed under read)".into(),
            ));
        }
        whole.update(&part);
        upload_one_part(
            b2,
            auth,
            file_id,
            span.number,
            Bytes::from(part),
            &mut part_sha1s,
        )
        .await?;
        // Charged once the part is acknowledged, so a retried part is charged
        // for every attempt — each one really did use the link.
        crate::meter::charge(b2.meter.as_ref(), want as u64).await;
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
            constants::EP_FINISH_LARGE_FILE,
            serde_json::json!({ "fileId": file_id, "partSha1Array": part_sha1s }),
        )
        .await?;

    Ok(PutOutcome { size, verified })
}

/// Fetch a fresh upload-part URL, upload `chunk` as part `part_number` with its streamed
/// SHA-1, confirm B2 echoed that SHA-1, and record it for the finish call.
///
/// Retried as one unit for the same reason [`upload_single`] is: a part URL is
/// bound to a pod, and the remedy for a busy one is a different URL. A part is
/// individually addressed by its number, so re-sending it is idempotent — B2
/// keeps the last body received for that number and the finish call names the
/// SHA-1 this function verified.
///
/// `chunk` is taken **by value** and cloned per attempt. `Bytes::clone` moves a
/// refcount, so however many times a busy pod makes this try again, the part
/// exists in memory exactly once. Taking a slice instead would force every caller
/// to own a second buffer for the body, which is what it used to do.
async fn upload_one_part(
    b2: &B2Backend,
    auth: &AuthState,
    file_id: &str,
    part_number: u32,
    chunk: Bytes,
    part_sha1s: &mut Vec<String>,
) -> Result<()> {
    let sha1_hex = ContentHash::sha1(&chunk).hex();
    retry::run(constants::OP_UPLOAD_PART, b2.deadlines.run, |_| async {
        let part_url: GetUploadPartUrlResponse = b2
            .post_json_once(
                auth,
                constants::EP_GET_UPLOAD_PART_URL,
                serde_json::json!({ "fileId": file_id }),
            )
            .await?;

        let watch = b2.deadlines.watch();
        let response = watch
            .guard(
                b2.client
                    .post(&part_url.upload_url)
                    .header(constants::H_AUTHORIZATION, &part_url.authorization_token)
                    .header(constants::H_PART_NUMBER, part_number.to_string())
                    .header(constants::H_CONTENT_SHA1, &sha1_hex)
                    .header(constants::H_CONTENT_LENGTH, chunk.len().to_string())
                    .body(watch.body(chunk.clone()))
                    .send(),
            )
            .await
            .map_err(stalled_attempt)?
            .map_err(transport_attempt)?;

        let part: UploadPartResponse = b2
            .observe_expiry(read_json(Answered { watch, response }).await)
            .await?;
        // Settled, exactly as on the single-shot path above — and it matters
        // more here, because the thing that would be re-sent is a whole part.
        verify_sha1(&sha1_hex, &part.content_sha1).map_err(Attempt::settled)
    })
    .await?;
    part_sha1s.push(sha1_hex);
    Ok(())
}

/// Store an object that does not exist yet, taking its bytes from `source` in
/// bounded windows.
///
/// Same two arms and the same one number as [`put_from_path`], because the arms
/// are what keeps the memory contract to a single figure: at or below the part
/// size the whole object is read into one bounded buffer and sent by the verified
/// single-shot path; above it, one part at a time goes through the native
/// large-file API. `source.len()` is what decides — declared before the first
/// window, which is why [`ObjectStream`](crate::ObjectStream) requires a length
/// and why the vault's sealer was split in two to be able to supply one.
///
/// The digest arrives at the other end from where [`put_from_path`]'s does; see
/// [`Backend::put_stream`](crate::Backend::put_stream). Nothing here is finished
/// — `b2_finish_large_file` is the commit — until
/// [`ObjectStream::agreed`](crate::ObjectStream::agreed) has returned.
pub(super) async fn put_stream(
    b2: &B2Backend,
    key: &ObjectKey,
    mut source: crate::incoming::ObjectStream,
    modified: SourceModified,
) -> Result<PutOutcome> {
    let size = source.len();

    // At or below one part: the object is bounded by the part size by definition,
    // so it is drained into one buffer and takes the same verified single-shot
    // path a buffered `put` takes.
    if !streaming::use_multipart(size, b2.part_size()) {
        // The buffer and both of the questions that have to be answered before it
        // may be committed — shared with S3's identical arm, and behind a seam,
        // because through an `ObjectStream` the two answers cannot disagree and
        // a check no input reaches is a check no test holds. See
        // `crate::incoming::whole`.
        let (whole, expected) = crate::incoming::drain_whole(&mut source, size).await?;
        let outcome = put(b2, key, whole, &expected, modified).await?;
        crate::meter::charge(b2.meter.as_ref(), size).await;
        return Ok(outcome);
    }

    let auth = b2.auth().await?;
    let start: StartLargeFileResponse = b2
        .post_json(
            constants::EP_START_LARGE_FILE,
            start_large_file_body(&auth.bucket_id, key, modified),
        )
        .await?;

    match stream_parts_and_finish(b2, &auth, &start.file_id, &mut source, size).await {
        Ok(outcome) => Ok(outcome),
        Err(e) => {
            // Cancel so nothing partial is committed and no unfinished large file
            // is left billing. Best-effort; the original error is what is reported.
            let _ = cancel_large_file(b2, &auth, &start.file_id).await;
            Err(e)
        }
    }
}

/// Send every part of a streamed object, then finish the large file.
///
/// One part buffer is live at a time and it is given away to the request as an
/// owned `Bytes`, exactly as on the from-a-file path — that is the whole of the
/// multipart term in the memory contract, and it is why nothing here calls
/// `to_vec` or `copy_from_slice` on a body.
async fn stream_parts_and_finish(
    b2: &B2Backend,
    auth: &AuthState,
    file_id: &str,
    source: &mut crate::incoming::ObjectStream,
    size: u64,
) -> Result<PutOutcome> {
    // The one place the peak stops being flat, and it is B2's rule rather than a
    // choice made here: past `part_size × MAX_PARTS` there is no way to send the
    // object without larger parts. See `constants`.
    let part_size = streaming::adaptive_part_size(
        size,
        b2.part_size(),
        constants::MIN_PART_SIZE,
        constants::B2_MAX_PART_SIZE,
        streaming::MAX_PARTS,
    )?;
    let plan = streaming::plan_parts(size, part_size);
    tracing::debug!(
        bytes = size,
        part_size,
        parts = plan.len(),
        "b2 stream (multipart, no spool)"
    );

    let mut part_sha1s: Vec<String> = Vec::with_capacity(plan.len());
    for span in &plan {
        let want = usize::try_from(span.len)
            .map_err(|_| StoreError::Backend("part larger than this machine's usize".into()))?;
        // One allocation per part, handed to the request as an owned `Bytes`, and
        // dropped when its upload returns before the next one is taken.
        let mut part = vec![0u8; want];
        let n = source.fill(&mut part).await?;
        if n != want {
            return Err(StoreError::ShortWrite {
                expected: size,
                actual: span.offset + n as u64,
            });
        }
        upload_one_part(
            b2,
            auth,
            file_id,
            span.number,
            Bytes::from(part),
            &mut part_sha1s,
        )
        .await?;
        crate::meter::charge(b2.meter.as_ref(), span.len).await;
    }

    // Both ends of the pipe agree about what the object was, it was as long as it
    // said, and the producer had nothing left over. Only now is anything
    // committed — `b2_finish_large_file` is the commit, and it is below this line
    // for the same reason the rename is below the read-back on `local:`.
    let verified = source.sealed().await?;

    let _: FinishLargeFileResponse = b2
        .post_json(
            constants::EP_FINISH_LARGE_FILE,
            serde_json::json!({ "fileId": file_id, "partSha1Array": part_sha1s }),
        )
        .await?;

    Ok(PutOutcome { size, verified })
}

/// One page of the large files this account started and never finished.
///
/// `b2_list_unfinished_large_files` is the only call in the B2 API that can see
/// them: their parts are stored and billed, and `b2_list_file_names` steps over
/// them because an unfinished large file is not an object yet.
///
/// `namePrefix` is passed through so a sweep scoped to a path costs one request
/// rather than a whole-bucket enumeration filtered afterwards, and `startFileId`
/// is the cursor — keyed by id, because two unfinished uploads may be aimed at
/// the same name.
pub(super) async fn list_unfinished(
    b2: &B2Backend,
    prefix: &str,
    cursor: Option<String>,
) -> Result<crate::multipart::IncompleteUploads> {
    let auth = b2.auth().await?;
    let mut body = serde_json::json!({
        "bucketId": auth.bucket_id,
        "maxFileCount": constants::UNFINISHED_PAGE_SIZE,
    });
    if !prefix.is_empty() {
        body["namePrefix"] = serde_json::Value::String(prefix.to_string());
    }
    if let Some(start) = cursor {
        body["startFileId"] = serde_json::Value::String(start);
    }

    let page: ListUnfinishedResponse = b2.post_json(constants::EP_LIST_UNFINISHED, body).await?;
    let items = page
        .files
        .into_iter()
        .map(|file| crate::multipart::IncompleteUpload {
            key: ObjectKey::new(file.file_name),
            id: file.file_id,
            // B2 dates a large file in epoch milliseconds; the sweep works in
            // whole seconds, which is the resolution every age in this tool uses.
            started_unix: file
                .upload_timestamp
                .map(|millis| millis / constants::MILLIS_PER_SECOND),
        })
        .collect();
    Ok(crate::multipart::IncompleteUploads::Page(
        crate::multipart::IncompletePage {
            items,
            next_cursor: page.next_file_id,
        },
    ))
}

/// Cancel one unfinished large file by the id the listing gave.
///
/// An upload that is already gone — finished by the process that owned it, or
/// swept by a concurrent run — is a **success**: the state the caller asked for is
/// the state that obtains, and failing a sweep because somebody else tidied first
/// would make two DCTLs on one bucket report errors at each other.
pub(super) async fn abort_unfinished(
    b2: &B2Backend,
    upload: &crate::multipart::IncompleteUpload,
) -> Result<()> {
    let auth = b2.auth().await?;
    match cancel_large_file(b2, &auth, &upload.id).await {
        Ok(()) => Ok(()),
        Err(StoreError::NotFound(_)) => Ok(()),
        // B2 answers a cancel of an id it does not hold with `400 bad_request`
        // rather than a 404, so the status alone cannot tell "already gone" from
        // "malformed request" — the code can, and it is the one B2 documents.
        Err(StoreError::Provider { code, .. }) if code == "file_not_present" => Ok(()),
        Err(other) => Err(other),
    }
}

/// Cancel an unfinished large file so nothing partial remains. Best-effort: callers
/// invoke it on the error path and keep the original error.
async fn cancel_large_file(b2: &B2Backend, _auth: &AuthState, file_id: &str) -> Result<()> {
    let _: CancelLargeFileResponse = b2
        .post_json(
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

    #[test]
    fn a_known_time_becomes_the_file_info_b2_documents() {
        // The key is `src_last_modified_millis` — Backblaze's own spelling, which
        // rclone also reads and writes. A private one would make every object
        // DCTL wrote look, to every other tool, like a file modified when it was
        // uploaded.
        assert_eq!(
            file_info(SourceModified::at(1_577_836_800)),
            serde_json::json!({ "src_last_modified_millis": "1577836800000" })
        );
    }

    #[test]
    fn an_unknown_time_sends_no_file_info_at_all() {
        // Not a zero and not the epoch: B2 stamps its own `uploadTimestamp`, and
        // the listing falls back to it. Sending `"0"` would date every such
        // object 1970 and invert `--update` over all of them.
        assert_eq!(file_info(SourceModified::unknown()), serde_json::json!({}));
    }

    /// The whole `b2_start_large_file` body, including the time.
    ///
    /// The two large-file paths used to assemble this inline, so deleting the
    /// `fileInfo` line from either left `cargo test --workspace` green and was
    /// caught only by `b2_stores_and_returns_the_source_modification_time` with
    /// live credentials (`HANDOVER.md` §15.4). Asserting the body as a whole is
    /// what closes that: there is one description, and this is a test of it.
    #[test]
    fn a_large_file_starts_with_the_source_time_in_its_file_info() {
        assert_eq!(
            start_large_file_body(
                "bucket-abc",
                &ObjectKey::new("photos/2020/a.jpg"),
                SourceModified::at(1_577_836_800)
            ),
            serde_json::json!({
                "bucketId": "bucket-abc",
                "fileName": "photos/2020/a.jpg",
                "contentType": "b2/x-auto",
                "fileInfo": { "src_last_modified_millis": "1577836800000" },
            })
        );
    }

    #[test]
    fn a_large_file_with_no_source_time_carries_an_empty_file_info() {
        let body = start_large_file_body(
            "bucket-abc",
            &ObjectKey::new("scratch.bin"),
            SourceModified::unknown(),
        );
        assert_eq!(body["fileInfo"], serde_json::json!({}));
    }

    /// The single-file path, which is what carries most objects.
    ///
    /// The header is B2's documented spelling — rclone's too, so the two tools
    /// read each other's buckets rather than each seeing the other's objects as
    /// modified when they were uploaded.
    #[test]
    fn a_single_file_upload_sends_the_source_time_with_the_bytes() {
        let headers = upload_headers(
            &ObjectKey::new("a b.jpg"),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            4096,
            SourceModified::at(1_577_836_800),
        );
        assert!(
            headers.contains(&(
                "X-Bz-Info-src_last_modified_millis",
                "1577836800000".to_string()
            )),
            "got {headers:?}"
        );
        // …alongside everything else the request needs, so a reader can see the
        // whole description in one place.
        assert!(headers.contains(&("X-Bz-File-Name", "a%20b.jpg".to_string())));
        assert!(headers.contains(&("Content-Type", "b2/x-auto".to_string())));
        assert!(headers.contains(&(
            "X-Bz-Content-Sha1",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string()
        )));
        assert!(headers.contains(&("Content-Length", "4096".to_string())));
    }

    #[test]
    fn a_single_file_upload_with_no_source_time_sends_no_such_header() {
        // Absent, not zero. B2 then stamps its own `uploadTimestamp` and the
        // listing falls back to it; a `"0"` would date the object 1970.
        let headers = upload_headers(
            &ObjectKey::new("scratch.bin"),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            1,
            SourceModified::unknown(),
        );
        assert!(
            !headers
                .iter()
                .any(|(name, _)| *name == constants::H_SRC_MODIFIED),
            "got {headers:?}"
        );
    }

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
