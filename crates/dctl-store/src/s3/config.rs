//! S3 endpoint + credentials configuration.
//!
//! Each S3-family provider (generic S3, Cloudflare R2, Wasabi, MinIO, B2's S3 API)
//! constructs one of these with its own endpoint/region rules, then reuses the
//! shared S3 protocol. Not `Debug` — the secret key must never be logged.

use super::constants::{DEFAULT_PART_SIZE, MAX_PART_SIZE, MIN_PART_SIZE};

/// Connection + credential settings for an S3-compatible endpoint.
#[derive(Clone)]
pub struct S3Config {
    /// Base endpoint, e.g. `https://s3.eu-central-003.backblazeb2.com`.
    pub endpoint: String,
    /// SigV4 region, e.g. `eu-central-003`, `us-east-1`, or `auto` (R2).
    pub region: String,
    /// Bucket name.
    pub bucket: String,
    pub(crate) access_key: String,
    pub(crate) secret_key: String,
    /// `true` = path-style (`{endpoint}/{bucket}/{key}`); most compatible.
    pub path_style: bool,
    /// Multipart part size, and the size above which an upload stops being a
    /// single request. See [`S3Config::part_size`].
    part_size: u64,
}

impl S3Config {
    /// Path-style config (works with R2, B2-S3, Wasabi, MinIO, and AWS legacy buckets).
    #[must_use]
    pub fn new(
        endpoint: impl Into<String>,
        region: impl Into<String>,
        bucket: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            region: region.into(),
            bucket: bucket.into(),
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            path_style: true,
            part_size: DEFAULT_PART_SIZE,
        }
    }

    /// Set the multipart part size, clamped into the envelope S3 publishes.
    ///
    /// `None` keeps [`DEFAULT_PART_SIZE`]. A value outside
    /// [`MIN_PART_SIZE`]..=[`MAX_PART_SIZE`] is **clamped rather than refused**,
    /// and that is a deliberate asymmetry with how DCTL treats most bad input:
    /// the failure a refusal would prevent is a config file that will not load,
    /// while the failure clamping prevents is an upload that is accepted, runs
    /// for an hour, and is rejected at the second part with `EntityTooSmall`.
    /// The clamped value is what the object is actually cut at, and
    /// [`S3Config::part_size`] reports it, so nothing downstream believes the
    /// number that was asked for.
    #[must_use]
    pub fn with_part_size(mut self, part_size: Option<u64>) -> Self {
        if let Some(size) = part_size {
            self.part_size = size.clamp(MIN_PART_SIZE, MAX_PART_SIZE);
        }
        self
    }

    /// The multipart part size in force.
    ///
    /// Also the single-shot cutoff: an object of exactly this many bytes is one
    /// `PutObject`, and one byte more is a multipart upload. They are the same
    /// number because they have always been the same number here — rclone splits
    /// them into `--s3-chunk-size` and `--s3-upload-cutoff`, and separating them
    /// now would change what an existing configuration does without being asked.
    #[must_use]
    pub const fn part_size(&self) -> u64 {
        self.part_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> S3Config {
        S3Config::new("https://example.invalid", "us-east-1", "b", "k", "s")
    }

    #[test]
    fn the_default_part_size_is_the_one_the_client_always_used() {
        assert_eq!(config().part_size(), DEFAULT_PART_SIZE);
        assert_eq!(config().with_part_size(None).part_size(), DEFAULT_PART_SIZE);
    }

    #[test]
    fn a_configured_part_size_is_clamped_into_the_providers_envelope() {
        // The failure this prevents is not a bad config file; it is an upload
        // that starts, runs, and is rejected at the second part because the
        // operator wrote `chunk_size = 1048576` and S3's floor is five times
        // that. Clamping is visible through `part_size()`, so the plan and the
        // logs quote what will actually be sent.
        assert_eq!(
            config().with_part_size(Some(1024)).part_size(),
            MIN_PART_SIZE
        );
        assert_eq!(
            config().with_part_size(Some(u64::MAX)).part_size(),
            MAX_PART_SIZE
        );
        // Anything inside the envelope is taken as written.
        assert_eq!(
            config().with_part_size(Some(8 * 1024 * 1024)).part_size(),
            8 * 1024 * 1024
        );
    }
}
