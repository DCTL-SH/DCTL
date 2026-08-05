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
mod tree;
mod verified_write;
mod walk;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;

use crate::backend::Backend;
use crate::checksum::ContentHash;
use crate::error::Result;
use crate::links::LinkPolicy;
use crate::meter::{self, Meter};
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};
use crate::modified::SourceModified;
use crate::staging::Want;

/// A [`Backend`] backed by a local directory tree rooted at `root`.
#[derive(Clone, Debug)]
pub struct LocalFs {
    root: PathBuf,
    /// What the tree walk does with the symbolic links it finds.
    ///
    /// Held on the backend rather than passed to
    /// [`list_page`](Backend::list_page), because it is a property of the run
    /// and not of one request: a paged listing whose second page followed links
    /// its first page had skipped would produce a listing no walk ever saw. See
    /// [`crate::links`] for the policy itself and for why the default is to skip
    /// and say so.
    links: LinkPolicy,
    /// What `root` was when this backend was built, or [`None`] if there was
    /// nothing there yet.
    ///
    /// Recorded once, at construction, because that is the moment the caller
    /// decided this directory *is* the store — for a vault it is the moment its
    /// `system/envelope.bin` was read out of it. Every write then checks that it
    /// is still writing into the same directory; see [`root`] for the run that
    /// reported `Files: 25 / 25, Errors: 0` into a replacement.
    opened_as: Option<crate::guard::StoreIdentity>,
    /// Who is told about bytes as they move, window by window.
    ///
    /// See [`crate::meter`]. Held on the backend rather than passed per call
    /// because pacing is a property of the *run* — one `--bwlimit` covers every
    /// object a command touches — and a per-call argument is one a new call site
    /// can omit, which is a window that silently escapes the cap.
    meter: Arc<dyn Meter>,
    /// The key list one paged listing is walking, held between its pages.
    ///
    /// This backend has no server to page for it, so a listing is a tree walk
    /// sliced into pages — and each page used to re-walk and re-sort the whole
    /// tree. With `PAGE_SIZE` at 1000, a store of 200,001 objects walked it 201
    /// times, which is quadratic and was measured as such: `dctl check` took
    /// 252 ms over 1,000 files, 885 ms over 10,000 and **30.1 s** over 100,000,
    /// roughly 34× for each 10× of files.
    ///
    /// Holding the walk turns a paged listing back into one walk. It also makes
    /// the listing *more* truthful, which was the surprise: re-walking between
    /// pages meant a tree that changed mid-listing could hand back a page
    /// sequence no single walk ever saw, silently skipping or repeating keys.
    /// A snapshot cannot.
    ///
    /// Only continuations read it — a listing that starts (`cursor: None`)
    /// always walks afresh — so this is never a stale answer to a new question.
    /// Two interleaved listings of different prefixes simply evict each other
    /// and fall back to walking, which is what every page did before.
    listing: Arc<Mutex<Option<WalkSnapshot>>>,
}

/// The sorted, prefix-filtered keys of one paged listing.
#[derive(Debug)]
struct WalkSnapshot {
    /// What the caller asked for, so a continuation of a *different* listing
    /// cannot be served this one's keys.
    prefix: String,
    /// Objects or staging debris — the two listings walk the same tree with
    /// opposite predicates and must not be confused for one another.
    want: Want,
    /// Every matching key, sorted, as the first page found them.
    keys: Vec<String>,
}

impl LocalFs {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let opened_as = root::identify(&root);
        Self {
            root,
            links: LinkPolicy::default(),
            opened_as,
            meter: meter::unmetered(),
            listing: Arc::new(Mutex::new(None)),
        }
    }

    /// The keys this page should slice, walking only when a listing begins.
    ///
    /// # Errors
    /// Whatever the tree walk reported.
    pub(crate) async fn listing_keys(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        want: Want,
        links: LinkPolicy,
    ) -> Result<(Vec<String>, Option<crate::local::tree::Walked>)> {
        // A poisoned lock is not a reason to fail a listing: the snapshot is an
        // optimisation, and walking again is exactly what this code did before
        // it existed. Falling through is the honest answer, and it is also the
        // correct one.
        if cursor.is_some() {
            if let Ok(held) = self.listing.lock() {
                if let Some(snapshot) = held.as_ref() {
                    if snapshot.prefix == prefix && snapshot.want == want {
                        return Ok((snapshot.keys.clone(), None));
                    }
                }
            }
        }

        let walked = tree::collect(self.root(), links, want).await?;
        let mut keys: Vec<String> = walked
            .keys
            .iter()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect();
        keys.sort();

        if let Ok(mut held) = self.listing.lock() {
            *held = Some(WalkSnapshot {
                prefix: prefix.to_string(),
                want,
                keys: keys.clone(),
            });
        }
        Ok((keys, Some(walked)))
    }

    /// The same backend, declaring every window it moves to `meter`.
    ///
    /// A builder for the reason [`LocalFs::with_links`] gives: almost every
    /// construction of a backend in this workspace is an internal bookkeeping
    /// read that nobody is pacing, and only the CLI — which holds the run's
    /// `--bwlimit` — has anything to install.
    #[must_use]
    pub fn with_meter(mut self, meter: Arc<dyn Meter>) -> Self {
        self.meter = meter;
        self
    }

    /// Who is told about this backend's bytes.
    pub(crate) fn meter(&self) -> Arc<dyn Meter> {
        Arc::clone(&self.meter)
    }

    /// The same backend, walking symbolic links under `policy`.
    ///
    /// A builder rather than a second constructor: the root is what makes a
    /// backend, the link policy is what a run asks of it, and every one of the
    /// sixty-odd places that build a `LocalFs` for a test or an internal
    /// bookkeeping read wants the default. Only the CLI, which has the flag,
    /// says otherwise.
    #[must_use]
    pub fn with_links(mut self, policy: LinkPolicy) -> Self {
        self.links = policy;
        self
    }

    /// What this backend's listing does with symbolic links.
    #[must_use]
    pub const fn links(&self) -> LinkPolicy {
        self.links
    }

    /// Refuse a write whose store root is no longer the one this backend opened.
    ///
    /// # Errors
    /// [`StoreError::RootChanged`] when the recorded root has been removed or
    /// replaced.
    pub(crate) fn require_same_root(&self) -> Result<()> {
        root::check(&self.root, self.opened_as.as_ref())
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

    /// The root's `(st_dev, st_ino)` pair — a renamed directory keeps its
    /// inode, so the store moved away is distinguishable from the fresh one
    /// created in its place. See [`root`] for the run this exists to stop
    /// reporting as a success.
    async fn store_identity(&self) -> Result<Option<crate::guard::StoreIdentity>> {
        Ok(root::identify(&self.root))
    }

    async fn put(
        &self,
        key: &ObjectKey,
        data: Bytes,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        let moved = data.len() as u64;
        let outcome = verified_write::put(self, key, data, expected, modified).await?;
        // One window, because the whole object *was* one window: the buffered
        // put is the path a small object takes, and charging it here is what
        // keeps a run of ten thousand small files paced now that the pipeline no
        // longer charges per file.
        meter::charge(self.meter.as_ref(), moved).await;
        Ok(outcome)
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

    /// A local write is a write: the windows go straight into the staging file.
    ///
    /// There is no protocol here to be adapted to — no parts, no lengths declared
    /// in a header, no request that has to know its own size — so this is the one
    /// backend where the streaming path is simply the buffered path with its
    /// source replaced. What it keeps is the read-back: the staging file is
    /// re-read and hashed before the rename, so "the bytes durably on disk match"
    /// still means the disk and not the pipe.
    async fn put_stream(
        &self,
        key: &ObjectKey,
        source: crate::incoming::ObjectStream,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        verified_write::put_stream(self, key, source, modified).await
    }

    async fn get(&self, key: &ObjectKey) -> Result<Bytes> {
        let bytes = read::get(self, key).await?;
        meter::charge(self.meter.as_ref(), bytes.len() as u64).await;
        Ok(bytes)
    }

    async fn get_to_path(&self, key: &ObjectKey, dest: &Path) -> Result<()> {
        read::get_to_path(self, key, dest).await
    }

    async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> Result<Bytes> {
        let bytes = read::get_range(self, key, range).await?;
        // The window a caller asked for is the window that moved. This is the
        // call a streaming read makes once per chunk, so it is the finest grain
        // the read side has, and pacing it is what stops `--bwlimit` being inert
        // on a `cat` of one enormous object.
        meter::charge(self.meter.as_ref(), bytes.len() as u64).await;
        Ok(bytes)
    }

    async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta> {
        walk::head(self, key).await
    }

    /// Nothing. A filesystem holds bytes and a length, and neither survives a
    /// change to the other in a way anything could compare against later.
    ///
    /// This is the answer that makes `dctl verify` refuse rather than print
    /// `ok` over a store where a flipped byte reads back perfectly — which it
    /// did, measured, at exit 0. See [`crate::recorded`].
    fn checksum_support(&self) -> crate::recorded::ChecksumSupport {
        crate::recorded::ChecksumSupport::None(crate::recorded::NO_RECORDED_CHECKSUM_FILESYSTEM)
    }

    /// Absent for every key, without a request: see
    /// [`checksum_support`](Backend::checksum_support).
    async fn stored_checksum(&self, _key: &ObjectKey) -> Result<crate::recorded::StoredChecksum> {
        Ok(crate::recorded::StoredChecksum::Absent(
            crate::recorded::NO_RECORDED_CHECKSUM_FILESYSTEM.to_string(),
        ))
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

    /// This backend stages, so it has debris to enumerate and does.
    ///
    /// `rename` is what makes a local write atomic and a staging sibling is what
    /// there is to rename, so every interrupted `put` leaves exactly one of
    /// these — and until this method existed the sweep that exists to reclaim
    /// them looked in the object listing, which omits them on purpose, and
    /// reported that there were none.
    async fn list_staging(
        &self,
        prefix: &str,
        cursor: Option<String>,
    ) -> Result<crate::staging::StagingListing> {
        walk::list_staging_page(self, prefix, cursor).await
    }

    /// A local write is one stream to one staging file, so there is no such thing
    /// as half an upload here — what an interruption leaves is staging debris,
    /// which [`list_staging`](Backend::list_staging) enumerates and `cleanup`
    /// already reclaims.
    async fn list_incomplete_uploads(
        &self,
        _prefix: &str,
        _cursor: Option<String>,
    ) -> Result<crate::multipart::IncompleteUploads> {
        Ok(crate::multipart::IncompleteUploads::NotMultipart(
            crate::multipart::NOT_MULTIPART_REASON,
        ))
    }

    /// Unreachable by construction: this backend never returns an upload to
    /// cancel, so nothing can hand one back. It refuses rather than succeeding
    /// quietly, because a caller that got here has an upload from somewhere else.
    async fn abort_incomplete_upload(
        &self,
        upload: &crate::multipart::IncompleteUpload,
    ) -> Result<()> {
        Err(crate::error::StoreError::Backend(format!(
            "local: asked to cancel upload '{}', but this backend starts none",
            upload.id
        )))
    }
}
