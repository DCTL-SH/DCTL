//! Generic S3-compatible backend + the shared S3 protocol (SigV4, XML parsing).
//!
//! `S3Backend` works against any S3 endpoint (AWS S3, MinIO, Wasabi, Backblaze's
//! S3 API). Provider-specific backends that speak S3 — e.g. Cloudflare R2 — live
//! in their own modules and reuse [`client::S3Client`] with their own config and
//! quirks, so each provider stays a distinct type.

mod client;
mod config;
mod constants;
mod instant;
mod sigv4;
mod xml;

pub use config::S3Config;

use async_trait::async_trait;
use bytes::Bytes;

use crate::backend::{Backend, UploadTicket};
use crate::checksum::ContentHash;
use crate::deadline::Deadlines;
use crate::error::Result;
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};
use crate::modified::SourceModified;

pub(crate) use client::S3Client;

/// A `Backend` over a generic S3-compatible endpoint.
pub struct S3Backend {
    client: S3Client,
}

impl S3Backend {
    /// Create a backend from an [`S3Config`], with hybrid post-quantum TLS and
    /// the run's `--timeout` / `--contimeout`.
    ///
    /// `deadlines` is a required argument rather than a builder, and the
    /// difference is the point. A builder can be forgotten, and this crate has
    /// already paid for that once: `crate::meter` was written into each arm of
    /// the CLI's construction match and four of the five arms dropped it, so
    /// `--bwlimit` was inert on every cloud provider with nothing to indicate
    /// it. A positional argument cannot be dropped — the compiler will not
    /// accept the call without it.
    pub fn new(config: S3Config, deadlines: Deadlines) -> Result<Self> {
        Ok(Self {
            client: S3Client::new(config, deadlines)?,
        })
    }

    /// The multipart part size this backend will cut at, after a remote's
    /// `chunk_size` — or the compiled default — has been applied.
    ///
    /// Public for the reason
    /// [`B2Backend::upload_peak_bytes`](crate::b2::B2Backend::upload_peak_bytes)
    /// is: a setting that travels four layers — configuration file, resolver,
    /// `Target`, constructor — needs something observable at the far end, or the
    /// last step of the journey is a line no test can check. It was exactly that
    /// line on B2 that proved deletable with the whole gate staying green.
    #[must_use]
    pub const fn part_size(&self) -> u64 {
        self.client.part_size()
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
impl Backend for S3Backend {
    fn name(&self) -> &'static str {
        "s3"
    }

    /// `HEAD` on the bucket: existence, and nothing stronger.
    ///
    /// S3 gives a bucket **no identifier**. A bucket deleted and re-created
    /// under the same name is a different bucket and this protocol offers
    /// nothing that says so, which is why the answer is
    /// [`StoreIdentity::existence_only`] rather than a token that would look
    /// like a comparison and never be one.
    async fn store_identity(&self) -> Result<Option<crate::guard::StoreIdentity>> {
        self.client.bucket_identity().await
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
    /// The same two arms as [`put_from_path`](Backend::put_from_path), fed by a
    /// producer instead of by a file — so a sealed object reaches the bucket
    /// without ever being written to local disk.
    async fn put_stream(
        &self,
        key: &ObjectKey,
        source: crate::incoming::ObjectStream,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        self.client.put_stream(key, source, modified).await
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

    /// Nothing comparable, and the reason is DCTL's write path rather than the
    /// protocol: see [`crate::recorded::NO_COMPARABLE_CHECKSUM_S3`].
    fn checksum_support(&self) -> crate::recorded::ChecksumSupport {
        crate::recorded::ChecksumSupport::None(crate::recorded::NO_COMPARABLE_CHECKSUM_S3)
    }

    /// Absent for every key, without a request: see
    /// [`checksum_support`](Backend::checksum_support).
    async fn stored_checksum(&self, _key: &ObjectKey) -> Result<crate::recorded::StoredChecksum> {
        Ok(crate::recorded::StoredChecksum::Absent(
            crate::recorded::NO_COMPARABLE_CHECKSUM_S3.to_string(),
        ))
    }
    async fn exists(&self, key: &ObjectKey) -> Result<bool> {
        self.client.exists(key).await
    }
    async fn delete(&self, key: &ObjectKey) -> Result<()> {
        self.client.delete(key).await
    }
    /// Nothing is ever written under a temporary key here, so nothing can be
    /// abandoned under one.
    ///
    /// Measured rather than assumed: a `SIGKILL` three seconds into a copy to a
    /// live B2 bucket leaves the bucket holding `system/envelope.bin` and
    /// nothing else. The upload goes straight to the final key with a checksum
    /// the provider verifies, so there is no staging namespace to sweep.
    ///
    /// What an interrupted *large* upload leaves is an unfinished multipart
    /// upload, which is billed and which no object listing shows — a different
    /// class, asked for separately, and now answered:
    /// [`list_incomplete_uploads`](Backend::list_incomplete_uploads).
    async fn list_staging(
        &self,
        _prefix: &str,
        _cursor: Option<String>,
    ) -> Result<crate::staging::StagingListing> {
        Ok(crate::staging::StagingListing::NotStaged(
            crate::staging::NOT_STAGED_REASON,
        ))
    }

    /// The uploads this bucket is still holding open, through
    /// `ListMultipartUploads` — the only call in the API that can see them.
    async fn list_incomplete_uploads(
        &self,
        prefix: &str,
        cursor: Option<String>,
    ) -> Result<crate::multipart::IncompleteUploads> {
        self.client.list_incomplete_uploads(prefix, cursor).await
    }

    /// `AbortMultipartUpload`, which releases every part the upload is holding.
    async fn abort_incomplete_upload(
        &self,
        upload: &crate::multipart::IncompleteUpload,
    ) -> Result<()> {
        self.client.abort_incomplete_upload(upload).await
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
