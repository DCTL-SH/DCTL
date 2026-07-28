//! Cloudflare R2 backend.
//!
//! R2 speaks the S3 protocol, so it reuses the shared [`S3Client`](crate::s3), but
//! it is its own provider type with R2's own rules: the endpoint is derived from
//! the account id and the SigV4 region is always `auto`. Keeping it a distinct
//! type leaves room for R2-specific behaviour without touching the generic S3 path.

use async_trait::async_trait;
use bytes::Bytes;

use crate::backend::{Backend, UploadTicket};
use crate::checksum::ContentHash;
use crate::error::Result;
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};
use crate::modified::SourceModified;
use crate::s3::{S3Client, S3Config};

/// R2's fixed SigV4 region.
///
/// Not a placeholder and not a default that could be overridden: R2 has no
/// regions, and Cloudflare's documentation requires requests to be signed for
/// the literal string `auto`. Signing for `us-east-1` — the value an operator
/// migrating an S3 config would carry over — is rejected with
/// `SignatureDoesNotMatch`, which is why the R2 backend is a distinct type that
/// sets this itself rather than an `S3Backend` with a different endpoint.
const R2_REGION: &str = "auto";

/// The endpoint template every R2 account is reached through.
const R2_ENDPOINT_TEMPLATE: &str = "https://{account}.r2.cloudflarestorage.com";

/// A `Backend` over a Cloudflare R2 bucket.
pub struct R2Backend {
    client: S3Client,
}

impl R2Backend {
    /// The S3 settings an R2 account resolves to: the derived endpoint, the
    /// fixed `auto` region, and the caller's bucket and credentials.
    ///
    /// Public and separate from [`R2Backend::new`] because the two decisions R2
    /// makes on the operator's behalf — the endpoint hostname and the signing
    /// region — are the two most expensive things to get wrong and are otherwise
    /// unobservable without a Cloudflare account. This is the seam a test drives
    /// them through, and it is also how an operator points the same code path at
    /// a jurisdiction-specific endpoint or a local S3 implementation.
    #[must_use]
    pub fn config(
        account_id: &str,
        bucket: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> S3Config {
        let endpoint = R2_ENDPOINT_TEMPLATE.replace("{account}", account_id);
        S3Config::new(endpoint, R2_REGION, bucket, access_key, secret_key)
    }

    /// Create an R2 backend. The endpoint is `https://<account_id>.r2.cloudflarestorage.com`.
    ///
    /// # Errors
    /// Whatever building the TLS client reported.
    pub fn new(
        account_id: &str,
        bucket: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> Result<Self> {
        Self::from_config(Self::config(account_id, bucket, access_key, secret_key))
    }

    /// Create an R2 backend from settings [`R2Backend::config`] produced.
    ///
    /// # Errors
    /// Whatever building the TLS client reported.
    pub fn from_config(config: S3Config) -> Result<Self> {
        Ok(Self {
            client: S3Client::new(config)?,
        })
    }

    /// The same backend, declaring every part and body chunk it moves to
    /// `meter`. A builder, for the reason [`crate::LocalFs::with_meter`] gives.
    #[must_use]
    pub fn with_meter(mut self, meter: std::sync::Arc<dyn crate::meter::Meter>) -> Self {
        self.client = self.client.with_meter(meter);
        self
    }
}

#[async_trait]
impl Backend for R2Backend {
    fn name(&self) -> &'static str {
        "r2"
    }
    async fn put(
        &self,
        key: &ObjectKey,
        data: Bytes,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        self.client.put(key, data, expected, modified).await
    }
    async fn put_from_path(
        &self,
        key: &ObjectKey,
        source: &std::path::Path,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        self.client
            .put_from_path(key, source, expected, modified)
            .await
    }
    async fn get(&self, key: &ObjectKey) -> Result<Bytes> {
        self.client.get(key).await
    }
    async fn get_to_path(&self, key: &ObjectKey, dest: &std::path::Path) -> Result<()> {
        self.client.get_to_path(key, dest).await
    }
    async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> Result<Bytes> {
        self.client.get_range(key, range).await
    }
    async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta> {
        self.client.head(key).await
    }
    async fn exists(&self, key: &ObjectKey) -> Result<bool> {
        self.client.exists(key).await
    }
    async fn delete(&self, key: &ObjectKey) -> Result<()> {
        self.client.delete(key).await
    }
    async fn list_page(&self, prefix: &str, cursor: Option<String>) -> Result<Page> {
        self.client.list_page(prefix, cursor).await
    }
    async fn prepare_upload(
        &self,
        key: &ObjectKey,
        content_len: u64,
        content_sha256: Option<&[u8; 32]>,
    ) -> Result<UploadTicket> {
        self.client.prepare_upload(key, content_len, content_sha256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_endpoint_is_derived_from_the_account_and_nothing_else() {
        // The one piece of R2-specific addressing, and it is unobservable
        // without an account — so it is asserted here rather than assumed.
        let config = R2Backend::config("abc123", "vault", "k", "s");
        assert_eq!(
            config.endpoint, "https://abc123.r2.cloudflarestorage.com",
            "an R2 account id is a hostname label, not a path component"
        );
        assert_eq!(config.bucket, "vault");
        // Path-style, which is what R2 serves: the bucket is the first path
        // segment, never a hostname prefix.
        assert!(config.path_style);
    }

    #[test]
    fn the_signing_region_is_auto_and_is_not_a_default_to_be_overridden() {
        // Signing for `us-east-1` — the value an operator migrating an S3 config
        // brings with them — is rejected by R2 with SignatureDoesNotMatch. The
        // region is therefore set by this constructor and not read from any
        // setting, and this is the assertion that keeps it that way.
        assert_eq!(R2Backend::config("abc123", "b", "k", "s").region, "auto");
    }

    #[test]
    fn the_part_size_default_survives_the_r2_constructor() {
        // R2 goes through the same client, so the multipart envelope has to be
        // the same one — a smaller default here would silently change how an R2
        // upload is cut without anything saying so.
        assert_eq!(
            R2Backend::config("a", "b", "k", "s").part_size(),
            crate::s3::S3Config::new("https://x", "auto", "b", "k", "s").part_size()
        );
        assert_eq!(
            R2Backend::config("a", "b", "k", "s")
                .with_part_size(Some(8 * 1024 * 1024))
                .part_size(),
            8 * 1024 * 1024
        );
    }
}
