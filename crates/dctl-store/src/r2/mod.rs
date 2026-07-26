//! Cloudflare R2 backend.
//!
//! R2 speaks the S3 protocol, so it reuses the shared [`S3Client`](crate::s3), but
//! it is its own provider type with R2's own rules: the endpoint is derived from
//! the account id and the SigV4 region is always `auto`. Keeping it a distinct
//! type leaves room for R2-specific behaviour without touching the generic S3 path.

use async_trait::async_trait;
use bytes::Bytes;

use crate::backend::Backend;
use crate::checksum::ContentHash;
use crate::error::Result;
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};
use crate::s3::{S3Client, S3Config};

/// R2's fixed SigV4 region.
const R2_REGION: &str = "auto";

/// A `Backend` over a Cloudflare R2 bucket.
pub struct R2Backend {
    client: S3Client,
}

impl R2Backend {
    /// Create an R2 backend. The endpoint is `https://<account_id>.r2.cloudflarestorage.com`.
    pub fn new(
        account_id: &str,
        bucket: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> Result<Self> {
        let endpoint = format!("https://{account_id}.r2.cloudflarestorage.com");
        let config = S3Config::new(endpoint, R2_REGION, bucket, access_key, secret_key);
        Ok(Self {
            client: S3Client::new(config)?,
        })
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
    ) -> Result<PutOutcome> {
        self.client.put(key, data, expected).await
    }
    async fn get(&self, key: &ObjectKey) -> Result<Bytes> {
        self.client.get(key).await
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
}
