//! The provider-neutral storage `Backend` trait.

use async_trait::async_trait;
use bytes::Bytes;

use crate::checksum::ContentHash;
use crate::error::{Result, StoreError};
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};
use crate::modified::SourceModified;

/// A delegated (presigned) authorization to upload exactly ONE object key.
///
/// The bytes uploaded are an already-sealed DSF1 object; this delegates only
/// **transport** — the issuer hands a client (e.g. an iOS `URLSession` background
/// upload) the exact request it must replay, and never sees plaintext / DEK / KW.
///
/// Not `Debug`: `url` (S3/R2) embeds a SigV4 signature and `headers` (B2) carry a
/// short-lived upload-auth token — short-lived transport credentials that must not be
/// logged, mirroring [`S3Config`](crate::s3::S3Config) / `B2Credentials`.
pub struct UploadTicket {
    /// HTTP method the client must use: `"PUT"` for S3/R2, `"POST"` for B2.
    pub method: String,
    /// The presigned URL (S3/R2) or the B2 `uploadUrl`.
    pub url: String,
    /// Headers the client MUST send verbatim (order preserved).
    pub headers: Vec<(String, String)>,
    /// SigV4 absolute expiry as a unix timestamp (S3/R2); `None` when the ticket is
    /// scoped by an opaque token's own lifetime instead (B2).
    pub expires_unix: Option<u64>,
}

/// A storage backend: moves opaque objects to/from a provider.
///
/// Three invariants every implementation must uphold:
/// - **Verified write:** [`put`](Backend::put) must not report success unless the
///   stored bytes match `expected`. On mismatch it must leave nothing committed.
/// - **Range read:** [`get_range`](Backend::get_range) must return exactly the
///   requested bytes without transferring the whole object (streaming-seek).
/// - **The writer's time comes back:** a `put` carrying a known
///   [`SourceModified`] must be readable back through [`head`](Backend::head) and
///   [`list_page`](Backend::list_page) as that same whole second — or the
///   implementation must document, in its own module, exactly why its protocol
///   cannot. This is the property `sync` is incremental *because of*, and the one
///   whose absence made every run a full run.
#[async_trait]
pub trait Backend: Send + Sync {
    /// Short, stable backend identifier (e.g. `"local"`, `"b2"`).
    fn name(&self) -> &'static str;

    /// Atomically store `data` under `key`, verifying it matches `expected`, and
    /// record `modified` as the object's last-modified time.
    ///
    /// `modified` describes the **content**, not this call — see
    /// [`SourceModified`]. [`SourceModified::unknown`] leaves the provider's own
    /// timestamp standing, which is what DCTL's internal bookkeeping objects want
    /// and what a copy from a source that reports no time has always defaulted to.
    async fn put(
        &self,
        key: &ObjectKey,
        data: Bytes,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> Result<PutOutcome>;

    /// Store the file at `source` under `key`, verifying it matches `expected`.
    ///
    /// This is the streaming counterpart of [`put`](Backend::put): it exists so a huge
    /// file can be stored without ever holding its whole body in memory. The **provided
    /// default** simply reads `source` into memory and delegates to [`put`], preserving
    /// the verified-write contract for every backend unchanged — backends that can stream
    /// straight from a path (e.g. [`LocalFs`](crate::local::LocalFs)) override this to run
    /// at `O(buffer)` memory. (True multipart-from-file for B2/S3/R2 is a follow-up.)
    async fn put_from_path(
        &self,
        key: &ObjectKey,
        source: &std::path::Path,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        let data = tokio::fs::read(source).await?;
        self.put(key, Bytes::from(data), expected, modified).await
    }

    /// Fetch the entire object.
    async fn get(&self, key: &ObjectKey) -> Result<Bytes>;

    /// Download the object at `key` to the local file `dest`, streaming.
    ///
    /// This is the streaming counterpart of [`get`](Backend::get): it exists so a huge
    /// object can be read to disk without ever holding its whole body in memory. The
    /// **provided default** simply calls [`get`] and writes the returned bytes to `dest`,
    /// so every backend has a correct implementation unchanged — backends that can stream
    /// straight to a path (e.g. [`LocalFs`](crate::local::LocalFs)) override this to run at
    /// `O(buffer)` memory. (True streaming download for B2/S3/R2 is a follow-up; they keep
    /// the buffered default for now.)
    async fn get_to_path(&self, key: &ObjectKey, dest: &std::path::Path) -> Result<()> {
        let bytes = self.get(key).await?;
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(dest, &bytes).await?;
        Ok(())
    }

    /// Fetch a byte range (streaming-seek primitive). Length past EOF is clamped.
    async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> Result<Bytes>;

    /// Object metadata without transferring the body.
    async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta>;

    /// Whether the object exists.
    async fn exists(&self, key: &ObjectKey) -> Result<bool>;

    /// Delete the object. Idempotent: deleting a missing object succeeds.
    async fn delete(&self, key: &ObjectKey) -> Result<()>;

    /// One page of a prefix listing. Pass the previous page's `next_cursor` to
    /// continue; `None` starts from the beginning. Keeps memory constant.
    async fn list_page(&self, prefix: &str, cursor: Option<String>) -> Result<Page>;

    /// Issue a delegated authorization for a client to upload the single object `key`
    /// **directly** to the backend (see [`UploadTicket`]).
    ///
    /// `content_len` is the exact byte length the client will send. `content_sha256`,
    /// when supplied, is the SHA-256 of those (already-sealed) bytes; backends that can
    /// bind it into the authorization do so (S3/R2 sign it), tightening the delegation to
    /// exactly those bytes. The bytes are opaque ciphertext — issuing a ticket never
    /// exposes plaintext or key material.
    ///
    /// The **provided default** returns a clear error: most backends (e.g.
    /// [`LocalFs`](crate::local::LocalFs)) have no notion of delegated upload. Backends
    /// that support it (S3, R2, B2) override this.
    async fn prepare_upload(
        &self,
        key: &ObjectKey,
        content_len: u64,
        content_sha256: Option<&[u8; 32]>,
    ) -> Result<UploadTicket> {
        let _ = (key, content_len, content_sha256);
        Err(StoreError::Backend(format!(
            "delegated upload unsupported by this backend: {}",
            self.name()
        )))
    }
}
