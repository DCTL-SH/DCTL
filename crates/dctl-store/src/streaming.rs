//! Shared, provider-neutral helpers for constant-memory streaming transfers.
//!
//! This backs the [`put_from_path`](crate::backend::Backend::put_from_path) and
//! [`get_to_path`](crate::backend::Backend::get_to_path) overrides for the networked
//! backends (B2, S3, R2): the **part-planning** math (pure, unit-tested here), a
//! bounded file-fill read, and a chunked response→file download. Everything works in
//! fixed-size buffers so peak memory is `O(part_size)` regardless of object size.

use std::path::{Path, PathBuf};

use crate::error::{Result, StoreError};

/// Working-buffer size for the streaming download copy.
const STREAM_BUF_LEN: usize = 128 * 1024;

/// The provider-wide cap on the number of parts in a single multipart/large-file
/// upload. Both S3 and B2 reject an upload with more than this many parts, so part
/// size must grow with the object to keep the count at or below this ceiling.
pub(crate) const MAX_PARTS: u64 = 10_000;

/// One part's placement within the source file, for a multipart upload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PartSpan {
    /// 1-based part number (as required by both the B2 and S3 multipart APIs).
    pub number: u32,
    /// Byte offset of this part from the start of the source.
    pub offset: u64,
    /// Length of this part in bytes.
    pub len: u64,
}

/// Whether a `total`-byte source should use the multipart path.
///
/// The single-shot threshold is **inclusive**: `total <= threshold` stays single-shot
/// (matching the buffered `put` of every backend, which uses `<=`), and only a strictly
/// larger source goes multipart.
#[must_use]
pub(crate) fn use_multipart(total: u64, threshold: u64) -> bool {
    total > threshold
}

/// Plan the part boundaries for a `total`-byte source split into `part_size` blocks.
///
/// Every part is exactly `part_size` bytes except the last, which carries the remainder
/// (`1..=part_size` bytes). Part numbers are 1-based and contiguous. A `total` of zero
/// yields no parts; `part_size` is clamped to at least 1 so the function is total.
#[must_use]
pub(crate) fn plan_parts(total: u64, part_size: u64) -> Vec<PartSpan> {
    let part_size = part_size.max(1);
    let mut parts = Vec::new();
    let mut offset = 0u64;
    let mut number = 1u32;
    while offset < total {
        let len = part_size.min(total - offset);
        parts.push(PartSpan {
            number,
            offset,
            len,
        });
        offset += len;
        number += 1;
    }
    parts
}

/// Choose a multipart part size that keeps the part count within `max_parts`.
///
/// Both S3 and B2 cap a single multipart/large-file upload at `max_parts` (10,000)
/// parts. With a fixed `base_part`, any object larger than `base_part * max_parts`
/// would produce more parts than allowed and be hard-rejected by the provider. This
/// grows the part size just enough to stay within the cap:
///
/// - `needed = total.div_ceil(max_parts)` — the smallest part size whose part count
///   is `<= max_parts`.
/// - `part = base_part.max(needed).max(min_part)` — never below the base (so normal
///   sizes are unaffected and keep the provider's recommended part size) and never
///   below the provider's minimum part size.
/// - If the required `part` exceeds `max_part` (the provider's per-part ceiling), the
///   object is larger than `max_part * max_parts` can ever hold as a single object, so
///   this returns a clear error instead of attempting an upload that must fail.
///
/// Below the growth threshold (`total <= base_part * max_parts`) this returns
/// `base_part` unchanged, preserving existing behavior for normal-sized objects.
pub(crate) fn adaptive_part_size(
    total: u64,
    base_part: u64,
    min_part: u64,
    max_part: u64,
    max_parts: u64,
) -> Result<u64> {
    // Smallest part size whose part count is `<= max_parts` (guard div-by-zero so the
    // function is total; callers always pass a non-zero cap).
    let needed = total.div_ceil(max_parts.max(1));
    // Grow from the base only when needed, and never below the provider minimum.
    let part = base_part.max(needed).max(min_part);
    if part > max_part {
        return Err(StoreError::Backend(format!(
            "object too large for backend: {total} bytes exceeds the single-object limit \
             of max_part ({max_part}) * max_parts ({max_parts}) = {}",
            max_part.saturating_mul(max_parts)
        )));
    }
    Ok(part)
}

/// The response's declared body length from the `Content-Length` header, if present
/// and parseable as a `u64`.
///
/// Returns `None` for chunked / unknown-length bodies (transfer-encoding), where the
/// streamed length cannot be verified against a declared size.
#[must_use]
pub(crate) fn content_length(resp: &reqwest::Response) -> Option<u64> {
    resp.headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
}

/// Read from `file` until `buf` is full or EOF, returning the number of bytes read.
///
/// A single `AsyncRead::read` may return fewer bytes than requested, so this loops to
/// fill the whole slice; a return value shorter than `buf.len()` means EOF was reached.
/// The blocking read runs on Tokio's blocking pool (via `tokio::fs`), off the executor.
pub(crate) async fn fill_buf(file: &mut tokio::fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    use tokio::io::AsyncReadExt as _;
    let mut filled = 0;
    while filled < buf.len() {
        let n = file.read(&mut buf[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// Stream an HTTP response body to `dest` with constant memory: temp file → fsync →
/// atomic rename.
///
/// The body is consumed chunk-by-chunk (`Response::chunk`, no whole-body buffering) into
/// a temp sibling of `dest`; only after the bytes are flushed and fsynced is the temp
/// atomically renamed into place, so a failure mid-transfer leaves no partial object at
/// `dest`. Parent directories are created as needed, matching the buffered default.
///
/// `expected_len` is the object's declared `Content-Length` (see
/// [`content_length`]) when the server sent one. If present, the number of bytes
/// actually committed must equal it exactly: a well-framed but short body (HTTP 200,
/// clean EOF, fewer bytes than the object) is otherwise indistinguishable from a whole
/// object and would be atomically committed as if complete. On a length mismatch the
/// temp is removed and an integrity error is returned (nothing is renamed into place).
/// When `expected_len` is `None` (chunked transfer, no declared size) the length cannot
/// be verified and the streamed bytes are kept as-is.
pub(crate) async fn stream_to_file(
    mut resp: reqwest::Response,
    dest: &Path,
    expected_len: Option<u64>,
) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;

    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let tmp = temp_sibling(dest);
    let file = tokio::fs::File::create(&tmp).await?;
    let mut writer = tokio::io::BufWriter::with_capacity(STREAM_BUF_LEN, file);

    let bytes_written = match copy_body(&mut resp, &mut writer).await {
        Ok(n) => n,
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }
    };
    // Length verification: a declared Content-Length must match the bytes committed,
    // or the "atomic" object at `dest` would be a silently truncated body.
    if let Some(expected) = expected_len {
        if bytes_written != expected {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(StoreError::Backend(format!(
                "streaming download truncated: expected {expected} bytes, wrote {bytes_written}"
            )));
        }
    }
    if let Err(e) = writer.flush().await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e.into());
    }
    let file = writer.into_inner();
    if let Err(e) = file.sync_all().await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e.into());
    }
    drop(file);
    if let Err(e) = tokio::fs::rename(&tmp, dest).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e.into());
    }
    Ok(())
}

/// Copy the response body into `writer`, one network chunk at a time, returning the
/// total number of bytes written (so the caller can verify it against a declared
/// `Content-Length`).
async fn copy_body(
    resp: &mut reqwest::Response,
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> Result<u64> {
    use tokio::io::AsyncWriteExt as _;
    let mut written = 0u64;
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                writer.write_all(&chunk).await?;
                written += chunk.len() as u64;
            }
            Ok(None) => break,
            Err(e) => return Err(StoreError::Backend(e.to_string())),
        }
    }
    Ok(written)
}

/// A unique sibling temp path in `dest`'s directory (same filesystem, so the final
/// rename is atomic).
fn temp_sibling(dest: &Path) -> PathBuf {
    crate::staging::staging_sibling(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_or_at_threshold_stays_single_shot() {
        assert!(!use_multipart(0, 100));
        assert!(!use_multipart(50, 100));
        // Boundary is inclusive: exactly the threshold is still single-shot.
        assert!(!use_multipart(100, 100));
    }

    #[test]
    fn above_threshold_goes_multipart() {
        assert!(use_multipart(101, 100));
        assert!(use_multipart(u64::MAX, 100));
    }

    #[test]
    fn exact_multiple_splits_into_equal_parts() {
        let parts = plan_parts(300, 100);
        assert_eq!(
            parts,
            vec![
                PartSpan {
                    number: 1,
                    offset: 0,
                    len: 100
                },
                PartSpan {
                    number: 2,
                    offset: 100,
                    len: 100
                },
                PartSpan {
                    number: 3,
                    offset: 200,
                    len: 100
                },
            ]
        );
    }

    #[test]
    fn remainder_becomes_a_short_last_part() {
        let parts = plan_parts(250, 100);
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len, 100);
        assert_eq!(parts[1].len, 100);
        // Last part carries the remainder only.
        assert_eq!(parts[2].len, 50);
        assert_eq!(parts[2].offset, 200);
        // Spans are contiguous and cover the whole source exactly.
        assert_eq!(parts.iter().map(|p| p.len).sum::<u64>(), 250);
        // Part numbers are 1-based and contiguous.
        assert_eq!(
            parts.iter().map(|p| p.number).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn smaller_than_one_part_is_a_single_part() {
        let parts = plan_parts(40, 100);
        assert_eq!(
            parts,
            vec![PartSpan {
                number: 1,
                offset: 0,
                len: 40
            }]
        );
    }

    #[test]
    fn one_byte_over_a_part_yields_two_parts() {
        let parts = plan_parts(101, 100);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1].len, 1);
        assert_eq!(parts[1].offset, 100);
    }

    #[test]
    fn zero_length_source_has_no_parts() {
        assert!(plan_parts(0, 100).is_empty());
    }

    #[test]
    fn zero_part_size_is_clamped_not_infinite() {
        // Degenerate input must terminate: part_size is clamped to 1.
        let parts = plan_parts(3, 0);
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|p| p.len == 1));
    }

    // S3's part-size envelope, used to exercise `adaptive_part_size` (B2's is the same
    // shape with different numbers).
    const S3_BASE: u64 = 100 * 1024 * 1024; // 100 MiB recommended part
    const S3_MIN: u64 = 5 * 1024 * 1024; // 5 MiB minimum part
    const S3_MAX: u64 = 5 * 1024 * 1024 * 1024; // 5 GiB maximum part

    #[test]
    fn adaptive_below_threshold_returns_base() {
        // Normal-sized objects need no growth: the base part size is returned unchanged,
        // so existing behavior (and the plan_parts tests above) is preserved.
        assert_eq!(
            adaptive_part_size(1, S3_BASE, S3_MIN, S3_MAX, MAX_PARTS).unwrap(),
            S3_BASE
        );
        assert_eq!(
            adaptive_part_size(500 * 1024 * 1024, S3_BASE, S3_MIN, S3_MAX, MAX_PARTS).unwrap(),
            S3_BASE
        );
        // The largest object that still fits in base * MAX_PARTS parts keeps the base.
        let at_base_cap = S3_BASE * MAX_PARTS;
        assert_eq!(
            adaptive_part_size(at_base_cap, S3_BASE, S3_MIN, S3_MAX, MAX_PARTS).unwrap(),
            S3_BASE
        );
        // ...and that ceiling really is exactly MAX_PARTS parts at the base size.
        assert_eq!(plan_parts(at_base_cap, S3_BASE).len() as u64, MAX_PARTS);
    }

    #[test]
    fn adaptive_grows_a_2tib_object_within_the_part_cap() {
        let two_tib = 2 * 1024u64.pow(4);
        let part = adaptive_part_size(two_tib, S3_BASE, S3_MIN, S3_MAX, MAX_PARTS).unwrap();
        // It grew past the base (a fixed base would have produced > 10,000 parts).
        assert!(part > S3_BASE);
        // And the resulting plan is within the provider's 10,000-part hard cap.
        assert!(
            plan_parts(two_tib, part).len() as u64 <= MAX_PARTS,
            "2 TiB planned into more than {MAX_PARTS} parts"
        );
    }

    #[test]
    fn adaptive_at_ceiling_is_ok_and_one_byte_over_errors() {
        // The absolute single-object ceiling is max_part * max_parts.
        let ceiling = S3_MAX * MAX_PARTS;
        // Exactly at the ceiling: the max part size is used and the upload is accepted.
        assert_eq!(
            adaptive_part_size(ceiling, S3_BASE, S3_MIN, S3_MAX, MAX_PARTS).unwrap(),
            S3_MAX
        );
        // One byte over: it would need a part larger than max_part, so it errors clearly.
        assert!(adaptive_part_size(ceiling + 1, S3_BASE, S3_MIN, S3_MAX, MAX_PARTS).is_err());
    }

    #[test]
    fn adaptive_result_always_within_min_and_max_bounds() {
        // A tiny base still never drops below the provider's minimum part size.
        assert!(adaptive_part_size(1, S3_MIN, S3_MIN, S3_MAX, MAX_PARTS).unwrap() >= S3_MIN);
        // Every Ok result across a wide range of sizes stays within [min, max].
        for total in [
            1u64,
            S3_BASE,
            S3_BASE * MAX_PARTS,
            2 * 1024u64.pow(4),
            S3_MAX * MAX_PARTS,
        ] {
            let part = adaptive_part_size(total, S3_BASE, S3_MIN, S3_MAX, MAX_PARTS).unwrap();
            assert!(
                (S3_MIN..=S3_MAX).contains(&part),
                "part {part} out of [{S3_MIN}, {S3_MAX}] for total {total}"
            );
        }
    }
}
