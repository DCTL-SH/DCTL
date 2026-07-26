//! Local filesystem backend — a fully-featured, verified-write `Backend` over a
//! directory tree.
//!
//! Primary use is development/testing and local storage targets. Its listing
//! walks the tree (appropriate at that scale); networked backends (B2) will map
//! `list_page` onto native provider pagination.

mod key_path;
mod read;
mod remove;
mod verified_write;
mod walk;

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;

use crate::backend::Backend;
use crate::checksum::ContentHash;
use crate::error::Result;
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};

/// A [`Backend`] backed by a local directory tree rooted at `root`.
#[derive(Clone, Debug)]
pub struct LocalFs {
    root: PathBuf,
}

impl LocalFs {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
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
    ) -> Result<PutOutcome> {
        verified_write::put(self, key, data, expected).await
    }

    async fn put_from_path(
        &self,
        key: &ObjectKey,
        source: &Path,
        expected: &ContentHash,
    ) -> Result<PutOutcome> {
        verified_write::put_from_path(self, key, source, expected).await
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
