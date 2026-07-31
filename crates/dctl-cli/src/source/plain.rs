//! The plain source: an object store, read as it stands.
//!
//! No decryption, no index, no translation — the keys a provider reports are the
//! paths this hands back, and the bytes it stores are the bytes it returns. That
//! is what `dctl ls ./photos` and `dctl ls archive-store:` both need: one is a
//! directory of ordinary files, the other is a directory of a vault's opaque
//! objects, and in neither case is there anything to unseal.
//!
//! ## Pagination is the whole design
//!
//! [`Backend::list_page`] exists because `PLAN.md` §16.2 requires listings to
//! cost O(page) and not O(objects): a bucket with ten million keys must list on a
//! laptop. This implementation therefore walks cursors and holds **one provider
//! page** — one round trip's worth of metadata — no matter how large the store
//! is. Collecting the pages into a `Vec` first would be one line shorter and
//! would put the memory ceiling back where the tool cannot ship with it.
//!
//! Unlike the sealed source, this side has no excuse available to it: the
//! streaming primitive already exists at the layer below, so using anything else
//! would be a choice.
//!
//! ## What is not known here
//!
//! A plain store reports a key, a size and usually a modification time. Its
//! *listing* carries no digest, so [`Entry::content_hash`] stays [`None`] there
//! — a provider's own checksum is a statement about the bytes it happens to be
//! holding, which is a different claim from "this is the hash of the file that
//! was written", and rendering one where the other is expected would make
//! `dctl hashsum` quietly wrong.
//!
//! What this side *can* answer, and now does, is [`Source::content_hash`]: a
//! plain store holds the plaintext, so reading an object and hashing it produces
//! exactly the digest a vault would have recorded for the same file. It costs a
//! read, which is why it is a method a caller asks for rather than a field every
//! listing pays for.

use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use dctl_store::Deadlines;
use dctl_store::{
    Backend, ByteRange, ChecksumSupport, Hasher, LinkPolicy, LinkReport, ObjectKey, ObjectMeta,
    SpecialReport, StoreError, StoredChecksum,
};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::constants::{INTEGRITY_FAILURE_HINT, READ_BACK_WINDOW_BYTES};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::platform::path;
use crate::remote::RemoteSpec;

use super::entry::Entry;
use super::{Assurance, Entries, Sizes, Source};

/// An object store, read without interpretation.
pub struct PlainSource {
    backend: Arc<dyn Backend>,
}

impl PlainSource {
    /// Build the backend `spec` names and read it directly.
    ///
    /// Takes the already-loaded configuration rather than reading one, so that
    /// [`super::open`] resolves the file exactly once per run. Two loads would
    /// be two chances to disagree about which remotes exist — and on a run where
    /// the file changed underneath, two different answers to the same question.
    ///
    /// # Errors
    /// [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError) for a remote
    /// the configuration and the provider shorthands both fail to explain, or
    /// for one whose settings are incomplete.
    pub fn open(
        config: &Config,
        spec: &RemoteSpec,
        links: LinkPolicy,
        deadlines: Deadlines,
    ) -> Result<Self> {
        let resolved = crate::remote::resolve::resolve(spec, config)?;
        // Unmetered: this is the *listing and reading* view, reached by `ls`,
        // `size`, `tree` and `cat`. `cat` is the only one of those that moves a
        // body, and it is opened through `crate::source::open`, which installs
        // the run's meter — see there. A listing moves metadata, and pacing a
        // listing against a bandwidth cap set for file transfers would make
        // `dctl ls` mysteriously slow.
        Ok(Self::new(crate::remote::registry::build(
            &resolved,
            links,
            dctl_store::unmetered(),
            deadlines,
        )?))
    }

    /// Read an already-built backend.
    ///
    /// The seam a test drives: a `LocalFs` over a temporary directory is a real
    /// backend, so the tests below exercise the same code a `local:` remote runs
    /// without needing a configuration file to point at it.
    #[must_use]
    pub const fn new(backend: Arc<dyn Backend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl Source for PlainSource {
    async fn enumerate(&self, prefix: &str) -> Result<Box<dyn Entries>> {
        Ok(Box::new(Paged {
            backend: Arc::clone(&self.backend),
            prefix: prefix.to_string(),
            cursor: None,
            exhausted: false,
            page: VecDeque::new(),
            links: LinkReport::default(),
            specials: SpecialReport::default(),
        }))
    }

    fn sizes(&self) -> Sizes {
        // Whatever the provider reported for the object, unaltered — which for
        // a vault's store remote means the *sealed* length, overhead included.
        // That is the honest answer for this view: nothing here decrypts, so
        // nothing here knows a plaintext length to report instead.
        Sizes::Stored
    }

    async fn read(&self, path: &str) -> Result<Zeroizing<Vec<u8>>> {
        let bytes = self.backend.get(&ObjectKey::new(path)).await?;
        Ok(Zeroizing::new(bytes.to_vec()))
    }

    async fn stream_to(
        &self,
        path: &str,
        out: &mut (dyn tokio::io::AsyncWrite + Unpin + Send),
    ) -> Result<u64> {
        use tokio::io::AsyncWriteExt as _;

        let key = ObjectKey::new(path.to_string());
        let size = self.backend.head(&key).await?.size;

        let mut at = 0_u64;
        while at < size {
            let want = READ_BACK_WINDOW_BYTES.min(size - at);
            let window = self
                .backend
                .get_range(&key, ByteRange::new(at, Some(want)))
                .await?;
            if window.is_empty() {
                // The object declared a length and stopped serving before it.
                // Returning what arrived would report a truncated object as a
                // complete read, which is the misreport `PLAN.md` §6 forbids.
                return Err(CliError::new(
                    ExitCode::IntegrityFailure,
                    format!("'{path}' stopped serving bytes at {at} of the {size} it declares"),
                ));
            }
            out.write_all(&window).await?;
            at += window.len() as u64;
        }
        out.flush().await?;
        Ok(at)
    }

    async fn read_range(
        &self,
        path: &str,
        offset: u64,
        length: Option<u64>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let range = ByteRange::new(offset, length);
        match self.backend.get_range(&ObjectKey::new(path), range).await {
            Ok(bytes) => Ok(Zeroizing::new(bytes.to_vec())),
            // The trait promises a short read past the end rather than a
            // failure, so that a window resolved against a size the object no
            // longer has behaves the way a `seek` on a local file does. The
            // backend is stricter; the softening belongs here, at the boundary
            // that made the promise, and not in every caller.
            Err(StoreError::RangeOutOfBounds { .. }) => Ok(Zeroizing::new(Vec::new())),
            Err(error) => Err(error.into()),
        }
    }

    async fn prefetch(&self, _path: &str, _offset: u64, _length: u64) {
        // Nothing to warm, and that is a property of this view rather than an
        // omission. A plain read is one `Backend::get_range` straight to the
        // caller's buffer — there is no cache between the two for a fetch to land
        // in, so "fetch it early" would mean holding a speculative copy of bytes
        // nobody has asked for, at a cost that is not this layer's to decide.
        //
        // The sealed source has one because it *must*: a vault cannot serve a
        // 4 KiB read without decrypting the whole megabyte chunk around it, so the
        // chunks exist as a cache whether anybody prefetches or not, and warming
        // them costs no memory that a read would not have spent anyway. That
        // asymmetry is the reason this method is on the trait rather than folded
        // into one implementation.
    }

    async fn stat(&self, path: &str) -> Result<Option<Entry>> {
        match self.backend.head(&ObjectKey::new(path)).await {
            Ok(meta) => Ok(Some(from_meta(meta))),
            // "Not there" is the ordinary negative answer to this question, so
            // it travels as `Ok(None)`; the error channel stays reserved for a
            // failure to *look*, which is the case a caller must not confuse
            // with an absent object.
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Read the object and hash it, one window at a time.
    ///
    /// A plain store holds the plaintext, so the BLAKE3 of what it is holding is
    /// the BLAKE3 a vault would have recorded for the same file — which is what
    /// makes the two sides of `--checksum` comparable at all.
    ///
    /// Windowed for the reason [`Source::verify`] is windowed: the point is to
    /// touch every byte, and a whole-object `get` would buffer a fifty-gigabyte
    /// file to do it. `PLAN.md` §16.2 caps memory at O(concurrency), and a
    /// `--checksum` that materialised a huge file *in order to decide whether to
    /// copy it* would be the most absurd possible way to break that rule.
    async fn content_hash(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let key = ObjectKey::new(path);
        let meta = match self.backend.head(&key).await {
            Ok(meta) => meta,
            Err(StoreError::NotFound(_)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };

        let mut hasher = blake3::Hasher::new();
        let mut offset = 0;
        while offset < meta.size {
            let window = READ_BACK_WINDOW_BYTES.min(meta.size - offset);
            let bytes = self
                .backend
                .get_range(&key, ByteRange::new(offset, Some(window)))
                .await?;

            // The same disagreement `verify` refuses to paper over: a store that
            // hands back nothing while claiming there is more has contradicted
            // its own `head`. Believing the loop condition would spin forever;
            // believing the provider would hash a prefix and call it the file.
            if bytes.is_empty() {
                return Err(CliError::new(
                    ExitCode::IntegrityFailure,
                    format!(
                        "'{path}' ended after {offset} bytes but the remote reports \
                         {} — the object is truncated",
                        meta.size
                    ),
                )
                .with_hint(
                    "The remote's own metadata disagrees with what it will serve. \
                     Restore this object from another copy.",
                ));
            }
            hasher.update(&bytes);
            offset += bytes.len() as u64;
        }

        Ok(Some(hasher.finalize().as_bytes().to_vec()))
    }

    /// Read every byte back and, where the provider recorded a digest, compare
    /// what came back against it.
    ///
    /// **Both halves are needed and neither substitutes for the other.** The
    /// read-back is what notices a replica quietly losing objects and a store
    /// that stops serving part-way. The comparison is the only thing here
    /// capable of noticing that the bytes *changed*, because the digest was
    /// written down at write time and kept in the provider's metadata rather
    /// than in the object: rot moves one and leaves the other.
    ///
    /// A read-back on its own was the whole of this method, and it is the defect
    /// [`dctl_store::recorded`] records. Measured on the shipped binary: a byte
    /// flipped in place, and a 4 KiB object truncated to 100 bytes, on a plain
    /// `local:` and a plain `sftp:` remote — `ok` in the table and **exit 0** on
    /// all four. A truncation is invisible to a read-back by construction:
    /// shortening a file moves its length too, so `head` and the bytes agree and
    /// every byte the object claims does come back.
    ///
    /// The order is read-then-ask rather than ask-then-read, so that an object
    /// the provider has no digest for is still *proved retrievable* before it is
    /// reported unverifiable. The finding is then additional information rather
    /// than a substitute for the check that could be made.
    async fn verify(&self, path: &str) -> Result<()> {
        let key = ObjectKey::new(path);
        // `head` first, so an object that is simply gone is reported as
        // *missing* rather than as a failed read — those are different findings
        // and they send an operator to different places.
        let meta = self.backend.head(&key).await?;

        // Decided before a byte moves. A caller that folded a digest only when
        // it turned out to have something to compare it with would have to
        // either read twice or buffer the object, and the second is the memory
        // ceiling this whole method is windowed to avoid.
        let mut folding = self.backend.checksum_support().algo().map(Hasher::new);

        // Ranged reads rather than one `get`, because the point of a read-back
        // is to touch every byte and a `get` would buffer them all to do it.
        // A scrub of a store holding fifty-gigabyte sealed objects has to cost
        // one window of memory, not one object.
        let mut offset = 0;
        while offset < meta.size {
            let window = READ_BACK_WINDOW_BYTES.min(meta.size - offset);
            let bytes = self
                .backend
                .get_range(&key, ByteRange::new(offset, Some(window)))
                .await?;

            // A store that hands back nothing while claiming there is more has
            // contradicted its own `head`, and the object is shorter than the
            // provider says it is. Believing the loop condition instead would
            // spin forever; believing the provider would report an object as
            // healthy after reading a prefix of it. Neither is acceptable, so
            // the disagreement itself is the finding.
            if bytes.is_empty() {
                return Err(CliError::new(
                    ExitCode::IntegrityFailure,
                    format!(
                        "'{path}' ended after {offset} bytes but the remote reports \
                         {} — the object is truncated",
                        meta.size
                    ),
                )
                .with_hint(
                    "The remote's own metadata disagrees with what it will serve. \
                     Restore this object from another copy.",
                ));
            }
            if let Some(hasher) = folding.as_mut() {
                hasher.update(&bytes);
            }
            offset += bytes.len() as u64;
        }

        let Some(hasher) = folding else {
            // Nothing was recorded here, so the read-back is the whole of the
            // claim and it has been made. What that is worth is published by
            // [`Source::assurance`] and refused at the door by
            // `commands::integrity::assurance`, rather than being decided per
            // object in a place the operator's flag is not in scope.
            return Ok(());
        };

        match self.backend.stored_checksum(&key).await? {
            StoredChecksum::Recorded(recorded) => {
                let read = hasher.finalize();
                if read.matches(&recorded) {
                    return Ok(());
                }
                Err(CliError::new(
                    ExitCode::IntegrityFailure,
                    format!(
                        "'{path}' does not match the digest recorded when it was written: \
                         the remote recorded {} and the {} bytes it served now hash to {}",
                        recorded.hex(),
                        meta.size,
                        read.hex(),
                    ),
                )
                .with_hint(INTEGRITY_FAILURE_HINT))
            }
            // The object is there, every byte of it came back, and there is
            // nothing recorded anywhere that could say whether those are the
            // bytes that were written. That is not `ok`: `ok` is the word an
            // operator reads as *checked*.
            StoredChecksum::Absent(reason) => Err(CliError::new(
                ExitCode::VerificationNotPossible,
                format!("'{path}' came back whole and could not be checked — {reason}"),
            )),
        }
    }

    /// What a clean [`Source::verify`] here proves, read off the backend rather
    /// than asserted.
    ///
    /// It was the flat constant [`Assurance::ReadBack`], which was true of
    /// `local:` and `sftp:` and false of B2 — and a report cannot state a claim
    /// its source will not make. The backend answers, because what a provider
    /// records is the provider's property and not this layer's.
    fn assurance(&self) -> Assurance {
        match self.backend.checksum_support() {
            // The digest is the provider's rather than DCTL's, and it is not
            // keyed — so this is not a vault's claim and does not borrow its
            // word. It is exactly the claim a rot check needs.
            ChecksumSupport::Recorded(_) => Assurance::ProviderChecksum,
            // Nothing here recorded a hash of what was written, so nothing here
            // can compare against one. A clean read-back proves the object is
            // still retrievable in full; it does not prove the bytes are
            // unchanged, and reporting otherwise would be inventing a guarantee.
            ChecksumSupport::None(_) => Assurance::ReadBack,
        }
    }
}

/// A cursor that pulls one provider page at a time.
struct Paged {
    backend: Arc<dyn Backend>,
    /// The prefix the listing was opened at, re-sent with every page because a
    /// cursor is only meaningful together with the query that produced it.
    prefix: String,
    /// Where the next page resumes; [`None`] before the first request.
    cursor: Option<String>,
    /// Set once the provider reports no continuation, so an exhausted cursor
    /// answers `None` without issuing further requests.
    exhausted: bool,
    /// The current page, drained from the front. This — and nothing larger — is
    /// the memory a listing of any store costs.
    page: VecDeque<Entry>,
    /// What every page fetched so far said about the symbolic links its walk
    /// met. Merged rather than replaced, because a backend is free to report
    /// per page; both of the two that report anything put the whole walk on the
    /// first page and leave the continuations empty, and merging an empty report
    /// changes nothing.
    links: LinkReport,
    /// What every page fetched so far said about the fifos, sockets and device
    /// nodes its walk met. Merged for the reason `links` is merged, and beside
    /// it because they are one promise about two kinds of entry.
    specials: SpecialReport,
}

impl Paged {
    /// Fetch the next page and load whatever survives the prefix check.
    ///
    /// A page can legitimately produce nothing: the provider matches prefixes by
    /// bytes, so an entire page may consist of `photos-backup/...` keys during a
    /// listing of `photos`. The caller's loop therefore re-enters rather than
    /// concluding the listing is over.
    async fn fetch(&mut self) -> Result<()> {
        let page = self
            .backend
            .list_page(&self.prefix, self.cursor.clone())
            .await?;

        // A provider that returns no items and repeats the cursor it was given
        // has nothing further to say. Believing it would spin forever, and a
        // command that hangs is harder to diagnose than one that stops early —
        // so the listing ends here rather than looping on a broken pager.
        let stalled = page.items.is_empty() && page.next_cursor == self.cursor;

        self.links.merge(&page.links);
        self.specials.merge(&page.specials);

        self.page = page
            .items
            .into_iter()
            // Whole-component containment, for the same reason the sealed source
            // applies it: `photos` is not the parent of `photos-backup`, and a
            // byte-wise match would report a neighbouring tree as though the
            // user had asked for it.
            .filter(|meta| path::is_under(&self.prefix, meta.key.as_str()))
            .map(from_meta)
            .collect();

        self.exhausted = stalled || page.next_cursor.is_none();
        self.cursor = page.next_cursor;
        Ok(())
    }
}

#[async_trait]
impl Entries for Paged {
    async fn next(&mut self) -> Result<Option<Entry>> {
        loop {
            if let Some(entry) = self.page.pop_front() {
                return Ok(Some(entry));
            }
            if self.exhausted {
                return Ok(None);
            }
            self.fetch().await?;
        }
    }

    fn links(&self) -> LinkReport {
        self.links.clone()
    }

    fn specials(&self) -> SpecialReport {
        self.specials.clone()
    }
}

/// Translate provider metadata into the provider-neutral entry.
fn from_meta(meta: ObjectMeta) -> Entry {
    // No `with_content_hash`: see the module documentation on why a provider's
    // checksum is not the plaintext hash a vault records.
    Entry::new(meta.key.as_str(), meta.size).with_modified(meta.modified_unix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dctl_store::LocalFs;
    use std::path::Path;
    use tempfile::TempDir;

    /// A provider whose `head` claims more bytes than it will serve.
    ///
    /// The one condition every guard in this module exists for, and the one no
    /// real backend in the workspace can be made to produce: `LocalFs` reads a
    /// real file, so its `head` and its `get_range` can never disagree. A store
    /// that answers a range past what it holds with *nothing* — an object
    /// truncated under it, a proxy that stopped mid-stream, a bucket restored
    /// from a partial copy — is what turns a `--checksum`, a `verify` and a `cat`
    /// into confident wrong answers, so it is driven from here.
    ///
    /// Deliberately not an error: an error would be caught by any code path at
    /// all. Serving a short read and then an empty one is the *plausible*
    /// failure, because every byte it does hand over is genuinely that object's.
    struct ShortServing {
        /// What `head` and every listing report.
        declared: u64,
        /// How many bytes actually exist. Ranges beyond this are empty.
        served: u64,
    }

    impl ShortServing {
        /// The object's real bytes: a repeating pattern, so a hash over a prefix
        /// differs from a hash over the whole thing.
        fn body(&self) -> Vec<u8> {
            (0..self.served).map(|n| (n % 251) as u8).collect()
        }
    }

    #[async_trait]
    impl Backend for ShortServing {
        fn name(&self) -> &'static str {
            "short-serving"
        }

        async fn store_identity(&self) -> dctl_store::Result<Option<dctl_store::StoreIdentity>> {
            Ok(Some(dctl_store::StoreIdentity::distinguishing("short")))
        }

        /// Nothing recorded, which is the case this fake is used to drive: the
        /// disagreement it induces is between `head` and what is served, and it
        /// must be caught without a digest to compare against.
        fn checksum_support(&self) -> dctl_store::ChecksumSupport {
            dctl_store::ChecksumSupport::None("this fake records no digests")
        }

        async fn stored_checksum(
            &self,
            _key: &ObjectKey,
        ) -> dctl_store::Result<dctl_store::StoredChecksum> {
            Ok(dctl_store::StoredChecksum::Absent(
                "this fake records no digests".to_string(),
            ))
        }

        async fn put(
            &self,
            _key: &ObjectKey,
            _data: bytes::Bytes,
            _expected: &dctl_store::ContentHash,
            _modified: dctl_store::SourceModified,
        ) -> dctl_store::Result<dctl_store::PutOutcome> {
            Err(StoreError::Backend("this fake is read-only".into()))
        }

        async fn get(&self, _key: &ObjectKey) -> dctl_store::Result<bytes::Bytes> {
            Ok(bytes::Bytes::from(self.body()))
        }

        async fn get_range(
            &self,
            _key: &ObjectKey,
            range: ByteRange,
        ) -> dctl_store::Result<bytes::Bytes> {
            let body = self.body();
            let start = usize::try_from(range.offset)
                .unwrap_or(usize::MAX)
                .min(body.len());
            let end = match range.length {
                Some(length) => start
                    .saturating_add(usize::try_from(length).unwrap_or(usize::MAX))
                    .min(body.len()),
                None => body.len(),
            };
            Ok(bytes::Bytes::copy_from_slice(&body[start..end]))
        }

        async fn head(&self, key: &ObjectKey) -> dctl_store::Result<ObjectMeta> {
            Ok(ObjectMeta {
                key: key.clone(),
                size: self.declared,
                modified_unix: None,
            })
        }

        async fn exists(&self, _key: &ObjectKey) -> dctl_store::Result<bool> {
            Ok(true)
        }

        async fn delete(&self, _key: &ObjectKey) -> dctl_store::Result<()> {
            Ok(())
        }

        async fn list_page(
            &self,
            _prefix: &str,
            _cursor: Option<String>,
        ) -> dctl_store::Result<dctl_store::Page> {
            Ok(dctl_store::Page::default())
        }

        async fn list_staging(
            &self,
            _prefix: &str,
            _cursor: Option<String>,
        ) -> dctl_store::Result<dctl_store::StagingListing> {
            Ok(dctl_store::StagingListing::NotStaged("a fake"))
        }

        async fn put_stream(
            &self,
            _key: &ObjectKey,
            _source: dctl_store::ObjectStream,
            _modified: dctl_store::SourceModified,
        ) -> dctl_store::Result<dctl_store::PutOutcome> {
            Err(StoreError::Backend("this fake is read-only".into()))
        }

        async fn list_incomplete_uploads(
            &self,
            _prefix: &str,
            _cursor: Option<String>,
        ) -> dctl_store::Result<dctl_store::IncompleteUploads> {
            Ok(dctl_store::IncompleteUploads::NotMultipart("a fake"))
        }

        async fn abort_incomplete_upload(
            &self,
            _upload: &dctl_store::IncompleteUpload,
        ) -> dctl_store::Result<()> {
            Err(StoreError::Backend("this fake is read-only".into()))
        }
    }

    /// A source over a store that declares `declared` bytes and holds `served`.
    fn short_serving(declared: u64, served: u64) -> PlainSource {
        PlainSource::new(Arc::new(ShortServing { declared, served }))
    }

    /// A backend shaped like B2: it writes the bytes to a real directory and
    /// keeps a digest of them **somewhere else**.
    ///
    /// That separation is the whole mechanism under test and the reason a fake
    /// is the right instrument here rather than a wrapper over `LocalFs` alone:
    /// rot moves the bytes and leaves the recorded digest where it was, so a
    /// test has to be able to move one without the other. Damaging the file on
    /// disk is exactly what the live proof does to a B2 object it uploaded.
    struct Recording {
        inner: LocalFs,
        /// Key to the digest recorded when the object was written — the
        /// provider's metadata, kept out of the bytes.
        recorded: std::sync::Mutex<std::collections::HashMap<String, dctl_store::ContentHash>>,
    }

    impl Recording {
        fn over(root: &Path) -> Self {
            Self {
                inner: LocalFs::new(root),
                recorded: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }

        /// Record `bytes` under `key` the way a provider does on a verified
        /// write: the object, and beside it the digest of what was accepted.
        fn accept(&self, key: &str, bytes: &[u8]) {
            self.recorded
                .lock()
                .expect("the fixture's map is not poisoned")
                .insert(key.to_string(), dctl_store::ContentHash::sha1(bytes));
        }

        /// Forget the digest for `key`, leaving the object — a B2 large file,
        /// whose `contentSha1` is the literal string `none`.
        fn forget(&self, key: &str) {
            self.recorded
                .lock()
                .expect("the fixture's map is not poisoned")
                .remove(key);
        }
    }

    #[async_trait]
    impl Backend for Recording {
        fn name(&self) -> &'static str {
            "recording"
        }

        fn checksum_support(&self) -> dctl_store::ChecksumSupport {
            dctl_store::ChecksumSupport::Recorded(dctl_store::HashAlgo::Sha1)
        }

        async fn stored_checksum(
            &self,
            key: &ObjectKey,
        ) -> dctl_store::Result<dctl_store::StoredChecksum> {
            Ok(
                match self
                    .recorded
                    .lock()
                    .expect("the fixture's map is not poisoned")
                    .get(key.as_str())
                {
                    Some(digest) => dctl_store::StoredChecksum::Recorded(digest.clone()),
                    None => dctl_store::StoredChecksum::Absent(format!(
                        "nothing was recorded for '{}'",
                        key.as_str()
                    )),
                },
            )
        }

        async fn store_identity(&self) -> dctl_store::Result<Option<dctl_store::StoreIdentity>> {
            self.inner.store_identity().await
        }
        async fn put(
            &self,
            key: &ObjectKey,
            data: bytes::Bytes,
            expected: &dctl_store::ContentHash,
            modified: dctl_store::SourceModified,
        ) -> dctl_store::Result<dctl_store::PutOutcome> {
            self.accept(key.as_str(), &data);
            self.inner.put(key, data, expected, modified).await
        }
        async fn put_stream(
            &self,
            key: &ObjectKey,
            source: dctl_store::ObjectStream,
            modified: dctl_store::SourceModified,
        ) -> dctl_store::Result<dctl_store::PutOutcome> {
            self.inner.put_stream(key, source, modified).await
        }
        async fn get(&self, key: &ObjectKey) -> dctl_store::Result<bytes::Bytes> {
            self.inner.get(key).await
        }
        async fn get_range(
            &self,
            key: &ObjectKey,
            range: ByteRange,
        ) -> dctl_store::Result<bytes::Bytes> {
            self.inner.get_range(key, range).await
        }
        async fn head(&self, key: &ObjectKey) -> dctl_store::Result<ObjectMeta> {
            self.inner.head(key).await
        }
        async fn exists(&self, key: &ObjectKey) -> dctl_store::Result<bool> {
            self.inner.exists(key).await
        }
        async fn delete(&self, key: &ObjectKey) -> dctl_store::Result<()> {
            self.inner.delete(key).await
        }
        async fn list_page(
            &self,
            prefix: &str,
            cursor: Option<String>,
        ) -> dctl_store::Result<dctl_store::Page> {
            self.inner.list_page(prefix, cursor).await
        }
        async fn list_staging(
            &self,
            prefix: &str,
            cursor: Option<String>,
        ) -> dctl_store::Result<dctl_store::StagingListing> {
            self.inner.list_staging(prefix, cursor).await
        }
        async fn list_incomplete_uploads(
            &self,
            prefix: &str,
            cursor: Option<String>,
        ) -> dctl_store::Result<dctl_store::IncompleteUploads> {
            self.inner.list_incomplete_uploads(prefix, cursor).await
        }
        async fn abort_incomplete_upload(
            &self,
            upload: &dctl_store::IncompleteUpload,
        ) -> dctl_store::Result<()> {
            self.inner.abort_incomplete_upload(upload).await
        }
    }

    /// A real file on disk with a real digest recorded beside it, and a handle
    /// on both so a test can move one without the other.
    struct Recorded {
        _root: TempDir,
        path: std::path::PathBuf,
        backend: Arc<Recording>,
        source: PlainSource,
    }

    fn recorded_object(name: &str, bytes: &[u8]) -> Recorded {
        let root = TempDir::new().expect("a temporary directory");
        let path = root.path().join(name);
        std::fs::write(&path, bytes).expect("the fixture file is written");
        let backend = Arc::new(Recording::over(root.path()));
        backend.accept(name, bytes);
        let source = PlainSource::new(Arc::clone(&backend) as Arc<dyn Backend>);
        Recorded {
            _root: root,
            path,
            backend,
            source,
        }
    }

    #[tokio::test]
    async fn a_flipped_byte_is_caught_where_the_provider_recorded_a_digest() {
        // The defect this whole capability exists to close, measured on the
        // shipped binary before it did: one byte flipped in place on a plain
        // remote produced `ok` and exit 0.
        let fixture = recorded_object(
            "a.bin",
            &(0..4096).map(|n| (n % 251) as u8).collect::<Vec<_>>(),
        );
        fixture.source.verify("a.bin").await.expect("intact first");

        let mut bytes = std::fs::read(&fixture.path).expect("readable");
        bytes[1000] ^= 0xFF;
        std::fs::write(&fixture.path, &bytes).expect("rewritten");

        let error = fixture
            .source
            .verify("a.bin")
            .await
            .expect_err("a changed byte must be caught");
        assert_eq!(error.code(), ExitCode::IntegrityFailure);
        assert!(
            error.message().contains("a.bin"),
            "the object must be named: {}",
            error.message()
        );
    }

    #[tokio::test]
    async fn a_truncation_is_caught_where_the_provider_recorded_a_digest() {
        // The other half, and the one a read-back can never see on a filesystem:
        // truncating a file moves its length too, so `head` and the bytes agree
        // and every byte the object claims comes back.
        let fixture = recorded_object(
            "b.bin",
            &(0..4096).map(|n| (n % 251) as u8).collect::<Vec<_>>(),
        );
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&fixture.path)
            .expect("the object opens for writing");
        file.set_len(100).expect("the object is truncated");
        drop(file);
        assert_eq!(
            std::fs::metadata(&fixture.path).expect("stat").len(),
            100,
            "the fixture must really be shorter"
        );

        let error = fixture
            .source
            .verify("b.bin")
            .await
            .expect_err("a truncation must be caught");
        assert_eq!(error.code(), ExitCode::IntegrityFailure);
    }

    #[tokio::test]
    async fn an_intact_object_still_passes_where_the_provider_recorded_a_digest() {
        // The control that makes the two above mean anything: a comparison that
        // failed on everything would be a check nobody could use.
        let fixture = recorded_object("c.bin", b"unchanged bytes");
        fixture
            .source
            .verify("c.bin")
            .await
            .expect("an untouched object verifies");
        assert_eq!(fixture.source.assurance(), Assurance::ProviderChecksum);
    }

    #[tokio::test]
    async fn an_object_the_provider_has_no_digest_for_is_not_reported_ok() {
        // A B2 large file carries `contentSha1: "none"`. The object is fine, the
        // read is fine, and there is nothing to compare — which is a different
        // answer from `ok` and must not be spelled the same way.
        let fixture = recorded_object("d.bin", b"perfectly readable");
        fixture.backend.forget("d.bin");

        let error = fixture
            .source
            .verify("d.bin")
            .await
            .expect_err("an object with nothing recorded must not pass");
        assert_eq!(error.code(), ExitCode::VerificationNotPossible);
        assert_eq!(
            crate::commands::integrity::failure::classify(&error),
            crate::commands::integrity::failure::Verdict::Unverifiable,
            "and it must not be classified as damage"
        );
    }

    #[tokio::test]
    async fn a_remote_that_records_nothing_cannot_certify_and_says_so() {
        // `local:` and `sftp:` are this case. The read-back still happens — it
        // is how a replica quietly losing objects is caught — and the claim it
        // supports is the weaker one, published rather than assumed.
        let fixture = tree_with(&[("a.txt", b"one")]);
        assert_eq!(fixture.source.assurance(), Assurance::ReadBack);
        assert!(!fixture.source.assurance().detects_corruption());
        fixture
            .source
            .verify("a.txt")
            .await
            .expect("the retrievability check still runs");
    }

    /// A real directory tree behind a real `LocalFs`, with `files` written into
    /// it. The same backend a `local:` remote builds.
    struct Fixture {
        _root: TempDir,
        source: PlainSource,
    }

    fn tree_with(files: &[(&str, &[u8])]) -> Fixture {
        let root = TempDir::new().expect("a temporary directory");
        for (relative, bytes) in files {
            let path = root.path().join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("the parent directory is created");
            }
            std::fs::write(&path, bytes).expect("the fixture file is written");
        }
        let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(root.path()));
        Fixture {
            _root: root,
            source: PlainSource::new(backend),
        }
    }

    /// A fixture with more objects than one provider page holds, so the paging
    /// loop is genuinely exercised rather than being a code path a small test
    /// never enters.
    fn wide_tree(count: usize) -> (TempDir, PlainSource) {
        let root = TempDir::new().expect("a temporary directory");
        for n in 0..count {
            std::fs::write(root.path().join(format!("f{n:05}.bin")), b"x")
                .expect("the fixture file is written");
        }
        let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(root.path()));
        (root, PlainSource::new(backend))
    }

    async fn paths(source: &PlainSource, prefix: &str) -> Vec<String> {
        let mut cursor = source.enumerate(prefix).await.expect("a listing opens");
        let mut out = Vec::new();
        while let Some(entry) = cursor.next().await.expect("a page cannot fail") {
            out.push(entry.path);
        }
        out
    }

    #[tokio::test]
    async fn every_file_is_enumerated_once_in_path_order() {
        let fixture = tree_with(&[
            ("b/second.txt", b"22"),
            ("a.txt", b"1"),
            ("b/first.txt", b"333"),
        ]);
        assert_eq!(
            paths(&fixture.source, "").await,
            ["a.txt", "b/first.txt", "b/second.txt"]
        );
    }

    #[tokio::test]
    async fn a_prefix_scopes_the_listing_to_whole_components() {
        let fixture = tree_with(&[
            ("photos/a.jpg", b"a"),
            ("photos-backup/b.jpg", b"b"),
            ("other/c.jpg", b"c"),
        ]);
        assert_eq!(paths(&fixture.source, "photos").await, ["photos/a.jpg"]);
    }

    #[tokio::test]
    async fn an_empty_directory_enumerates_to_nothing_without_failing() {
        let fixture = tree_with(&[]);
        let mut cursor = fixture
            .source
            .enumerate("")
            .await
            .expect("an empty listing still opens");
        assert!(cursor.next().await.expect("no failure").is_none());
        assert!(cursor.next().await.expect("no failure").is_none());
    }

    #[tokio::test]
    async fn a_prefix_that_matches_nothing_is_empty_rather_than_everything() {
        let fixture = tree_with(&[("a.txt", b"1")]);
        assert!(paths(&fixture.source, "nowhere").await.is_empty());
    }

    #[tokio::test]
    async fn a_listing_crosses_page_boundaries_without_losing_or_repeating_an_object() {
        // The property the cursor exists for. `LocalFs` pages at a thousand
        // keys, so this spans three pages and would silently truncate if the
        // continuation were dropped.
        let (_root, source) = wide_tree(2_500);
        let listed = paths(&source, "").await;

        assert_eq!(listed.len(), 2_500, "every object must be reported once");
        let mut sorted = listed.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), listed.len(), "no object may repeat");
        assert_eq!(sorted, listed, "entries must arrive in path order");
    }

    #[tokio::test]
    async fn a_read_returns_the_stored_bytes() {
        let fixture = tree_with(&[("notes/today.md", b"as stored")]);
        let bytes = fixture
            .source
            .read("notes/today.md")
            .await
            .expect("the object reads back");
        assert_eq!(bytes.as_slice(), b"as stored");
    }

    #[tokio::test]
    async fn a_missing_path_is_reported_rather_than_read_as_empty() {
        let fixture = tree_with(&[("a.txt", b"1")]);
        let error = fixture
            .source
            .read("nope.txt")
            .await
            .expect_err("a missing object must fail");
        assert_eq!(error.code(), crate::exit::ExitCode::FileNotFound);
        assert!(error.hint().is_some(), "a refusal must say what to do next");
    }

    #[tokio::test]
    async fn a_range_read_returns_exactly_its_window() {
        let fixture = tree_with(&[("a.bin", b"0123456789")]);
        let source = &fixture.source;

        assert_eq!(
            source
                .read_range("a.bin", 4, Some(3))
                .await
                .unwrap()
                .as_slice(),
            b"456"
        );
        assert_eq!(
            source
                .read_range("a.bin", 7, None)
                .await
                .unwrap()
                .as_slice(),
            b"789"
        );
        assert_eq!(
            source
                .read_range("a.bin", 8, Some(999))
                .await
                .unwrap()
                .as_slice(),
            b"89"
        );
        // Past the end is a short read, matching what the trait promises and
        // what a seek on a local file does — the backend's own refusal is
        // softened here rather than in each caller.
        assert!(
            source
                .read_range("a.bin", 10, Some(5))
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            source
                .read_range("a.bin", 4_000, None)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn stat_describes_an_object_and_answers_none_for_a_missing_one() {
        let fixture = tree_with(&[("photos/a.jpg", b"12345")]);

        let found = fixture
            .source
            .stat("photos/a.jpg")
            .await
            .expect("the lookup succeeds")
            .expect("the object is there");
        assert_eq!(found.path, "photos/a.jpg");
        assert_eq!(found.size, Some(5));
        // A plain store cannot claim a plaintext hash it never recorded.
        assert_eq!(found.content_hash, None);

        assert!(
            fixture
                .source
                .stat("photos/missing.jpg")
                .await
                .expect("the lookup still succeeds")
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_directory_is_not_an_object() {
        // `stat` answers about objects. A directory is not one, and reporting it
        // as a zero-byte object would make `dctl cat` on it look survivable.
        let fixture = tree_with(&[("photos/a.jpg", b"1")]);
        assert!(
            fixture
                .source
                .stat("photos")
                .await
                .expect("the lookup succeeds")
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_read_back_touches_every_byte_and_says_what_that_proves() {
        // The window is larger than these objects, so this exercises the loop's
        // ordinary exit; the point being asserted is that a present object
        // passes and a missing one is reported as missing rather than as damage.
        let fixture = tree_with(&[("a.bin", b"0123456789"), ("empty.bin", b"")]);
        let source = &fixture.source;

        source.verify("a.bin").await.expect("an intact object");
        // A zero-length object is still an object: `head` proves it is there,
        // and there are no bytes to disagree about.
        source.verify("empty.bin").await.expect("an empty object");

        let error = source
            .verify("gone.bin")
            .await
            .expect_err("a missing object cannot be verified");
        assert_eq!(error.code(), crate::exit::ExitCode::FileNotFound);

        // And the claim a pass supports is stated, not assumed: nothing here
        // recorded a hash, so a clean read proves retrievability and no more.
        assert_eq!(source.assurance(), Assurance::ReadBack);
        assert!(!source.assurance().detects_corruption());
    }

    #[tokio::test]
    async fn an_object_larger_than_one_window_is_read_back_in_full() {
        // The loop, genuinely entered more than once. A read-back that stopped
        // after the first window would report a truncated object as healthy.
        let size = usize::try_from(READ_BACK_WINDOW_BYTES).unwrap() + 1024;
        let root = TempDir::new().unwrap();
        std::fs::write(root.path().join("big.bin"), vec![7u8; size]).unwrap();
        let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(root.path()));

        PlainSource::new(backend)
            .verify("big.bin")
            .await
            .expect("a multi-window object reads back");
    }

    #[tokio::test]
    async fn a_store_that_serves_a_prefix_is_not_hashed_as_the_file() {
        // The guard this product is sold on. A truncated object hashed to its
        // prefix produces a digest that is internally consistent and wrong:
        // `--checksum` compares it against the vault's recorded hash, finds a
        // difference, and re-transfers — or, worse, the *destination* is the
        // truncated side and a `check` blesses whatever the two happen to agree
        // on. Either way the number came from bytes nobody has all of.
        //
        // Ten bytes declared, four served. The first window is a legitimate
        // short read; the second is empty, and empty while `head` still claims
        // six bytes to go is the store contradicting itself.
        let source = short_serving(10, 4);

        let error = source
            .content_hash("truncated.bin")
            .await
            .expect_err("a prefix must never be reported as the object's hash");

        assert_eq!(error.code(), ExitCode::IntegrityFailure);
        assert!(
            error.message().contains("truncated") && error.message().contains("4"),
            "the refusal must say where it stopped and what was claimed: {}",
            error.message()
        );
        assert!(
            error.hint().is_some(),
            "a refusal must say what to do next: restore from another copy"
        );
    }

    #[tokio::test]
    async fn the_prefix_hash_is_a_real_digest_which_is_exactly_why_it_is_refused() {
        // The other half, and the reason the test above cannot be satisfied by
        // any old failure: the hash of the four bytes that *were* served is a
        // perfectly good BLAKE3. Nothing downstream could tell it from the
        // right answer — it is not short, not zero, not malformed. The only
        // thing wrong with it is that the object is ten bytes long.
        //
        // So the same fake, serving everything it declares, must produce that
        // full-length digest and no error at all. Without this row a guard that
        // simply refused every object would pass the truncation test.
        let whole = short_serving(10, 10);
        let hash = whole
            .content_hash("intact.bin")
            .await
            .expect("an object served in full hashes")
            .expect("and yields a digest");

        let ten: Vec<u8> = (0..10u8).map(|n| n % 251).collect();
        assert_eq!(hash, blake3::hash(&ten).as_bytes().to_vec());
        // …and it is not the prefix's, which is what a dropped guard returns.
        assert_ne!(hash, blake3::hash(&ten[..4]).as_bytes().to_vec());
    }

    #[tokio::test]
    async fn verify_refuses_a_short_object_rather_than_reporting_it_healthy() {
        // `dctl verify` and `dctl check` are the commands an operator runs to be
        // told the archive is intact. A read-back that stopped at the first
        // empty window and returned `Ok` would report exactly this object —
        // present, addressable, and missing six of its ten bytes — as healthy.
        let source = short_serving(10, 4);

        let error = source
            .verify("truncated.bin")
            .await
            .expect_err("a short object cannot pass a read-back");

        assert_eq!(error.code(), ExitCode::IntegrityFailure);
        assert!(error.message().contains("truncated"), "{}", error.message());
        // And the same object served in full passes, so the refusal is about the
        // shortfall and not about the fake.
        short_serving(10, 10)
            .verify("intact.bin")
            .await
            .expect("an object served in full verifies");
    }

    #[tokio::test]
    async fn cat_fails_on_a_short_object_rather_than_writing_a_partial_file() {
        // The third copy of the same guard, on the path that hands bytes to a
        // user: `dctl cat archive:big.iso > big.iso`. Writing four bytes and
        // exiting 0 would put a truncated file on the operator's disk under the
        // name of the whole one — a restore that reports success and loses the
        // file, which is `PLAN.md` §6's forbidden outcome.
        let source = short_serving(10, 4);
        let mut sink: Vec<u8> = Vec::new();

        let error = source
            .stream_to("truncated.bin", &mut sink)
            .await
            .expect_err("a short object must fail the stream");

        assert_eq!(error.code(), ExitCode::IntegrityFailure);
        assert!(
            error.message().contains("stopped serving bytes at 4"),
            "the refusal must name the byte it stopped at: {}",
            error.message()
        );
        // The bytes that did arrive are the object's own — which is why the
        // failure has to be reported rather than inferred from the output.
        assert_eq!(sink.len(), 4);

        let mut whole: Vec<u8> = Vec::new();
        assert_eq!(
            short_serving(10, 10)
                .stream_to("intact.bin", &mut whole)
                .await
                .expect("an object served in full streams"),
            10
        );
    }

    #[test]
    fn a_local_spec_needs_no_configuration_to_resolve() {
        // The headless case `PLAN.md` §14 requires: a bare path is a legitimate
        // source with no config file anywhere in sight.
        let root = TempDir::new().unwrap();
        let spec = RemoteSpec::Local(root.path().to_path_buf());
        assert!(
            PlainSource::open(
                &Config::default(),
                &spec,
                LinkPolicy::default(),
                Deadlines::default()
            )
            .is_ok()
        );
        let _: &Path = root.path();
    }

    #[test]
    fn an_unknown_remote_is_named_rather_than_guessed_at() {
        let spec = RemoteSpec::Named {
            remote: "nosuchremote".into(),
            path: String::new(),
        };
        let error = PlainSource::open(
            &Config::default(),
            &spec,
            LinkPolicy::default(),
            Deadlines::default(),
        )
        .err()
        .expect("an unconfigured remote cannot be built");
        assert_eq!(error.code(), crate::exit::ExitCode::FatalError);
        assert!(
            error.message().contains("nosuchremote"),
            "the refusal must name the remote: {}",
            error.message()
        );
    }
}
