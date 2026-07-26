//! The provider-neutral storage `Backend` trait.

use async_trait::async_trait;
use bytes::Bytes;

use crate::checksum::ContentHash;
use crate::error::Result;
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};

/// A storage backend: moves opaque objects to/from a provider.
///
/// Two invariants every implementation must uphold:
/// - **Verified write:** [`put`](Backend::put) must not report success unless the
///   stored bytes match `expected`. On mismatch it must leave nothing committed.
/// - **Range read:** [`get_range`](Backend::get_range) must return exactly the
///   requested bytes without transferring the whole object (streaming-seek).
#[async_trait]
pub trait Backend: Send + Sync {
    /// Short, stable backend identifier (e.g. `"local"`, `"b2"`).
    fn name(&self) -> &'static str;

    /// Atomically store `data` under `key`, verifying it matches `expected`.
    async fn put(&self, key: &ObjectKey, data: Bytes, expected: &ContentHash)
    -> Result<PutOutcome>;

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
    ) -> Result<PutOutcome> {
        let data = tokio::fs::read(source).await?;
        self.put(key, Bytes::from(data), expected).await
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
}
