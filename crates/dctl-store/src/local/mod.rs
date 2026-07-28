//! Local filesystem backend — a fully-featured, verified-write `Backend` over a
//! directory tree.
//!
//! Primary use is development/testing and local storage targets. Its listing
//! walks the tree (appropriate at that scale); networked backends (B2) will map
//! `list_page` onto native provider pagination.

mod key_path;
mod read;
mod remove;
pub(crate) mod root;
mod verified_write;
mod walk;

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;

use crate::backend::Backend;
use crate::checksum::ContentHash;
use crate::error::Result;
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};
use crate::modified::SourceModified;

/// A [`Backend`] backed by a local directory tree rooted at `root`.
#[derive(Clone, Debug)]
pub struct LocalFs {
    root: PathBuf,
    /// What `root` was when this backend was built, or [`None`] if there was
    /// nothing there yet.
    ///
    /// Recorded once, at construction, because that is the moment the caller
    /// decided this directory *is* the store — for a vault it is the moment its
    /// `system/envelope.bin` was read out of it. Every write then checks that it
    /// is still writing into the same directory; see [`root`] for the run that
    /// reported `Files: 25 / 25, Errors: 0` into a replacement.
    opened_as: Option<root::RootId>,
}

impl LocalFs {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let opened_as = root::identify(&root);
        Self { root, opened_as }
    }

    /// Refuse a write whose store root is no longer the one this backend opened.
    ///
    /// # Errors
    /// [`StoreError::RootChanged`] when the recorded root has been removed or
    /// replaced.
    pub(crate) fn require_same_root(&self) -> Result<()> {
        root::check(&self.root, self.opened_as)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve an object key to a safe absolute path under `root`.
    pub(crate) fn resolve(&self, key: &ObjectKey) -> Result<PathBuf> {
        key_path::resolve(&self.root, key)
    }
}

#[async_trait]
impl Backend for LocalFs {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn put(
        &self,
        key: &ObjectKey,
        data: Bytes,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        verified_write::put(self, key, data, expected, modified).await
    }

    async fn put_from_path(
        &self,
        key: &ObjectKey,
        source: &Path,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        verified_write::put_from_path(self, key, source, expected, modified).await
    }

    async fn get(&self, key: &ObjectKey) -> Result<Bytes> {
        read::get(self, key).await
    }

    async fn get_to_path(&self, key: &ObjectKey, dest: &Path) -> Result<()> {
        read::get_to_path(self, key, dest).await
    }

    async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> Result<Bytes> {
        read::get_range(self, key, range).await
    }

    async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta> {
        walk::head(self, key).await
    }

    async fn exists(&self, key: &ObjectKey) -> Result<bool> {
        walk::exists(self, key).await
    }

    async fn delete(&self, key: &ObjectKey) -> Result<()> {
        remove::delete(self, key).await
    }

    async fn list_page(&self, prefix: &str, cursor: Option<String>) -> Result<Page> {
        walk::list_page(self, prefix, cursor).await
    }
}
