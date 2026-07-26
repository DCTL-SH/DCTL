//! S3 endpoint + credentials configuration.
//!
//! Each S3-family provider (generic S3, Cloudflare R2, Wasabi, MinIO, B2's S3 API)
//! constructs one of these with its own endpoint/region rules, then reuses the
//! shared S3 protocol. Not `Debug` — the secret key must never be logged.

/// The S3 storage service name used in SigV4 scope.
pub(crate) const S3_SERVICE: &str = "s3";

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
        }
    }
}
