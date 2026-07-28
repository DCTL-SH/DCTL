//! The numbers the S3 protocol client is built around, and why each is what it is.
//!
//! Gathered here rather than left at the top of `client.rs` for the reason every
//! other crate keeps a `constants.rs`: a tunable buried beside the code that
//! uses it is a tunable nobody finds when a provider turns out to disagree with
//! it, and three of the five below are provider *limits* rather than DCTL's
//! choices — getting one wrong is a rejected upload at the ten-thousandth part,
//! which is the worst possible moment to discover it.

/// Default multipart part size, and — because they are the same number — the
/// size above which an object stops being uploaded in one request.
///
/// One knob rather than rclone's two (`--s3-chunk-size` and
/// `--s3-upload-cutoff`) because DCTL has only ever had one: the buffered and
/// streaming paths both compared against this exact value and both cut parts at
/// it, so splitting it now would change behaviour without being asked to. What
/// changed is that it is a **default** rather than a constant — see
/// [`S3Config::part_size`](super::config::S3Config::part_size) — because a
/// remote's `chunk_size` setting existed in the configuration file, was
/// documented, and reached nothing.
///
/// 100 MiB is twenty times S3's five-mebibyte minimum, which keeps the request
/// count low on a large object without making a retry of one part expensive.
pub(crate) const DEFAULT_PART_SIZE: u64 = 100 * 1024 * 1024;

/// S3's minimum part size: 5 MiB. Every part but the last must be at least this.
///
/// A provider limit, not a preference. A configured `chunk_size` below it is
/// raised rather than refused — the alternative is an upload that fails at the
/// second part with `EntityTooSmall`, long after the operator has stopped
/// watching.
pub(crate) const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;

/// S3's maximum part size: 5 GiB.
///
/// With [`MAX_PARTS`](crate::streaming::MAX_PARTS) this bounds a single
/// multipart object at 5 GiB × 10,000 ≈ 48.8 TiB, which is the limit
/// `adaptive_part_size` reports by name when an object exceeds it.
pub(crate) const MAX_PART_SIZE: u64 = 5 * 1024 * 1024 * 1024;

/// Objects returned per `ListObjectsV2` page.
///
/// S3's own maximum. Asking for fewer would multiply the request count — and the
/// per-request charge — for no benefit, because a page is streamed and never
/// held whole.
pub(crate) const LIST_PAGE_SIZE: u32 = 1000;

/// Lifetime of a delegated (presigned) upload authorization: 15 minutes.
///
/// Long enough for a client to start a background upload, short enough to bound
/// the delegation if the URL leaks. S3's own ceiling for a SigV4 presign is
/// seven days; nothing DCTL delegates needs anything like that.
pub(crate) const PRESIGN_TTL_SECS: u64 = 15 * 60;

/// The user-metadata header carrying the source's own last-modified time.
///
/// `rclone`'s spelling, not one invented here (`backend/s3/s3.go`, `metaMtime`),
/// so the two tools read each other's buckets rather than each seeing the other's
/// objects as modified when they were uploaded.
pub(crate) const H_SRC_MODIFIED: &str = "x-amz-meta-mtime";

/// The S3 storage service name used in the SigV4 credential scope.
pub(crate) const S3_SERVICE: &str = "s3";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_part_size_envelope_is_the_one_s3_publishes() {
        // Getting any of these wrong is an upload that fails partway through a
        // large object, which is the most expensive place to find out.
        assert_eq!(MIN_PART_SIZE, 5 * 1024 * 1024, "S3's documented minimum");
        assert_eq!(MAX_PART_SIZE, 5 * 1024 * 1024 * 1024, "S3's maximum");
        const {
            assert!(DEFAULT_PART_SIZE >= MIN_PART_SIZE);
            assert!(DEFAULT_PART_SIZE <= MAX_PART_SIZE);
        }
    }

    #[test]
    fn the_default_part_size_covers_a_large_object_without_growing() {
        // 100 MiB × 10,000 parts is just under a tebibyte, so the adaptive
        // growth path is reached only by genuinely enormous objects and the
        // ordinary case keeps a predictable part count.
        assert_eq!(
            DEFAULT_PART_SIZE * crate::streaming::MAX_PARTS,
            1_048_576_000_000_u64,
            "100 MiB * 10,000 parts is just under a tebibyte"
        );
    }

    #[test]
    fn a_listing_page_is_the_largest_s3_will_return() {
        assert_eq!(LIST_PAGE_SIZE, 1000);
    }
}
