//! Generic S3-compatible backend + the shared S3 protocol (SigV4, XML parsing).
//!
//! `S3Backend` works against any S3 endpoint (AWS S3, MinIO, Wasabi, Backblaze's
//! S3 API). Provider-specific backends that speak S3 — e.g. Cloudflare R2 — live
//! in their own modules and reuse [`client::S3Client`] with their own config and
//! quirks, so each provider stays a distinct type.

mod client;
mod config;
mod sigv4;
mod xml;

pub use config::S3Config;

use async_trait::async_trait;
use bytes::Bytes;

use crate::backend::{Backend, UploadTicket};
use crate::checksum::ContentHash;
use crate::error::Result;
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};

pub(crate) use client::S3Client;

/// A `Backend` over a generic S3-compatible endpoint.
pub struct S3Backend {
    client: S3Client,
}

impl S3Backend {
    /// Create a backend from an [`S3Config`], with hybrid post-quantum TLS.
    pub fn new(config: S3Config) -> Result<Self> {
        Ok(Self {
            client: S3Client::new(config)?,
        })
    }
}

#[async_trait]
impl Backend for S3Backend {
    fn name(&self) -> &'static str {
        "s3"
    }
    async fn put(
        &self,
        key: &ObjectKey,
        data: Bytes,
        expected: &ContentHash,
    ) -> Result<PutOutcome> {
        self.client.put(key, data, expected).await
    }
    async fn put_from_path(
        &self,
        key: &ObjectKey,
        source: &std::path::Path,
        expected: &ContentHash,
    ) -> Result<PutOutcome> {
        self.client.put_from_path(key, source, expected).await
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
