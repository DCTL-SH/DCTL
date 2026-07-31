//! The sealed source: a vault, read through its encrypted index.
//!
//! Everything here goes through [`dctl_core::Vault`], which means every read is
//! authenticated before it is returned and a listing shows *plaintext* paths and
//! *plaintext* sizes rather than the opaque object keys those files are actually
//! stored under. That translation is the whole reason `dctl ls archive:` and
//! `dctl ls archive-store:` show two completely different things about one
//! directory of bytes, and it is why the sealed view has to be a source of its
//! own rather than a filter over the plain one.
//!
//! ## The buffering here is the core's, and this is where it will disappear
//!
//! `PLAN.md` §16.2 forbids materialising a full file list, and this
//! implementation does exactly that — once, in [`VaultSource::enumerate`],
//! because [`Vault::list`](dctl_core::Vault::list) returns a `Vec<Record>`. Its
//! own documentation is candid about it: it enumerates the index in constant
//! memory internally and then materialises the result "for caller convenience".
//! So the records are built, sorted and handed over in full before this file
//! sees any of them, and nothing that can be written on this side of the crate
//! boundary changes that.
//!
//! What *is* in this file's gift is refusing to spread the problem. The cursor
//! below hands out one [`Entry`] at a time and is the only thing any caller
//! ever holds, so every listing verb in the binary is already written against a
//! stream. The fix, when it comes, is one function: `dctl-core` grows a
//! `Vault::for_each`-shaped or range-cursor API over
//! [`dctl_index::Index::for_each`] — which already streams — and
//! [`Buffered`] is replaced by a cursor that pulls from it. No call site
//! changes. Structuring it the other way round, with the renderers over a slice
//! and "we will stream it later", is how a tool ends up unable to list its own
//! dataset.
//!
//! ## A window costs the window, not the object
//!
//! [`Vault::get_file`](dctl_core::Vault::get_file) decrypts and authenticates an
//! entire object and hands back the plaintext. Serving a byte window through it
//! is what this file used to do, and the cost was not subtle: an audit measured
//! **+97 MB of resident memory and a 95 MiB transfer to return a 10-byte
//! window** of a 95 MiB object. Mounted, a player seeking through a 40 GB film
//! would have re-downloaded 40 GB on every seek.
//!
//! `docs/FORMAT.md` §3 specifies the alternative, and it is the reason the format
//! is chunked at all: chunk `i`'s ciphertext starts at
//! `payload_start + i·(chunk_size + 16)`, so the chunks covering a window are
//! arithmetic rather than a search, and `Backend::get_range` — which every
//! backend implements — fetches exactly those. [`VaultSource::read_range`] now
//! goes through [`dctl_core::range`], so a window costs **one ranged request for
//! its covering chunks** and nothing else.
//!
//! Measured, not assumed. A ten-byte window of a **96 MiB** sealed object costs
//! **+1.9 MiB of peak resident memory above the unlock baseline**; the
//! whole-object read it replaced costs **+97.6 MiB** — the figure the audit
//! reported. Against a **512 MiB** object the window costs **+2.1 MiB**, which is
//! the same number, while the whole-object read costs **+1025 MiB**. The windowed
//! figure is set by the chunk size and does not move when the object grows, and
//! that is the whole difference between a cost that scales with the file and one
//! that scales with the read. The `cat` pre-flight warning that used to announce
//! the old cost is gone with the cost; see `commands::cat::source`, which is
//! where it was printed.
//!
//! Repeated windows cost even less than that. A kernel reads a file 4 KiB at a
//! time and a chunk is 1 MiB, so the chunks are cached, bounded, between reads —
//! see [`chunk_cache`](super::chunk_cache), which is where that cost argument
//! lives.
//!
//! ### What a windowed read proves, and what it cannot
//!
//! Every returned byte is authenticated by its chunk's own Poly1305 tag, over an
//! AAD binding the object's authenticated head and the chunk's index — so
//! substitution, reordering, splicing from another object and truncation are all
//! caught, exactly as §3 intends. The two **whole-object** checks are a different
//! matter: the trailing footer BLAKE3 and the metadata's `content_blake3` each
//! cover the entire object, and no partial read can compute either. They are not
//! evaluated here and they are not faked. [`Source::verify`] — behind
//! `dctl verify` and `dctl scrub` — streams the object end to end and remains the
//! read that makes the whole-object statement.
//!
//! [`Source::read`] is unchanged and still whole-object, because a caller that
//! genuinely wants everything should get the stronger guarantee:
//! `Vault::get_file` re-hashes the plaintext it decrypted and compares it against
//! the object's own recorded `content_blake3`.

use std::collections::VecDeque;

use async_trait::async_trait;
use dctl_core::Record;
use zeroize::Zeroizing;

use crate::ctx::Ctx;
use crate::error::Result;
use crate::platform::path;
use crate::remote::RemoteSpec;
use crate::session::{self, Session};

use super::chunk_cache::ChunkCache;
use super::entry::Entry;
use super::{Assurance, Entries, Inventory, Sizes, Source};

/// A vault, unlocked, presented as a readable source.
pub struct VaultSource {
    /// The unlocked vault plus the context that identified it.
    ///
    /// Held whole rather than reduced to its `vault` field: the session also
    /// carries the remote name and the index path, which are what an error
    /// raised from here has to quote for an operator to know *which* vault
    /// refused them.
    session: Session,

    /// Open readers and decrypted chunks, bounded, for the life of this source.
    ///
    /// Lives here rather than inside `dctl_core` because what to keep resident is
    /// a policy decision belonging to the process doing the reading — a mount
    /// wants a working set, a one-shot `dctl cat` wants nothing — and because
    /// the core deliberately holds no mutable state keyed by logical path. Wiped
    /// when this source drops; never written to disk.
    chunks: ChunkCache,
}

impl VaultSource {
    /// Unlock the vault `spec` addresses.
    ///
    /// Delegates to [`session::open`], which is the one place that follows a
    /// vault chain to the remote actually holding bytes, acquires the password
    /// through the full fallback ladder, and refuses a second factor this build
    /// cannot apply. None of that is re-implemented here, and that is the point:
    /// a second copy of the unlock sequence is a second copy that can forget
    /// `--no-ask-password` and hang an unattended backup on an invisible prompt.
    ///
    /// # Errors
    /// Whatever [`session::open`] reported — an unresolvable remote, a missing
    /// password, or an envelope that will not unwrap.
    pub async fn open(ctx: &Ctx, spec: &RemoteSpec) -> Result<Self> {
        Ok(Self::new(session::open(ctx, spec).await?))
    }

    /// Wrap an already-unlocked session.
    ///
    /// Separate from [`VaultSource::open`] so a test can drive a real vault over
    /// a temporary directory without a config file, a password prompt or an
    /// environment variable — and so a future command that already holds a
    /// session does not unlock a second time to read from it.
    #[must_use]
    pub fn new(session: Session) -> Self {
        Self {
            session,
            chunks: ChunkCache::new(),
        }
    }

    /// The plaintext of one object, whole.
    ///
    /// The deliberately *stronger* read: `Vault::get_file` decrypts every chunk
    /// and then re-hashes the assembled plaintext against the object's own
    /// DEK-authenticated `content_blake3`, which is a statement about the whole
    /// object that no windowed read can make. Used by [`Source::read`], and by
    /// [`Source::read_range`] only when the window is "everything".
    async fn whole(&self, path: &str) -> Result<Zeroizing<Vec<u8>>> {
        Ok(self.session.vault.get_file(path).await?)
    }
}

#[async_trait]
impl Source for VaultSource {
    async fn enumerate(&self, prefix: &str) -> Result<Box<dyn Entries>> {
        // Sorted ascending by path by the core, which is the ordering contract
        // on `Entries` — restated here because a change in `Vault::list` that
        // dropped the sort would break `lsd` and `tree` silently rather than
        // loudly.
        let records = self.session.vault.list(prefix)?;

        let entries = records
            .into_iter()
            // The index matches a prefix by bytes, so listing `photos` also
            // sees `photos-backup`. Comparing whole components is what stops
            // `dctl ls archive:photos` from reporting a neighbouring tree as if
            // it were inside the one that was named.
            .filter(|record| path::is_under(prefix, &record.path))
            .map(from_record)
            .collect();

        Ok(Box::new(Buffered { entries }))
    }

    fn sizes(&self) -> Sizes {
        // `Record::size` is the length of the file that was sealed, never of the
        // object holding it: the index is written from the plaintext, and the
        // ciphertext length would have to be asked of the provider one object at
        // a time. Saying so is what keeps `dctl size archive:` from being read
        // as a storage bill.
        Sizes::Plaintext
    }

    async fn read(&self, path: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.whole(path).await
    }

    async fn stream_to(
        &self,
        path: &str,
        out: &mut (dyn tokio::io::AsyncWrite + Unpin + Send),
    ) -> Result<u64> {
        // The core's window walk: one ranged request per window of chunks, each
        // authenticated before a byte of it is written, and the assembled
        // plaintext checked against the object's own recorded hash at the end.
        // Same statement as `whole`, without the buffer that made it cost the
        // file.
        Ok(self
            .session
            .vault
            .stream_file_to(path, &mut *out)
            .await?
            .bytes)
    }

    async fn read_range(
        &self,
        path: &str,
        offset: u64,
        length: Option<u64>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        // "From the start, to the end" is not a window — it is the whole object
        // spelled with range arguments, and it is what a caller that does not
        // know the size writes. Serving it through the ranged path would trade
        // the whole-object `content_blake3` check for per-chunk tags and gain
        // nothing, since every chunk is fetched either way.
        if offset == 0 && length.is_none() {
            return self.whole(path).await;
        }
        self.chunks
            .read_range(&self.session.vault, path, offset, length)
            .await
    }

    async fn prefetch(&self, path: &str, offset: u64, length: u64) {
        // Straight through to the cache the next read will consult. Nothing is
        // assembled and nothing is returned: what a sealed source can usefully
        // warm is exactly the decrypted, authenticated chunks — see
        // [`ChunkCache::warm`](super::chunk_cache::ChunkCache::warm) for why that
        // is not the same call as a `read_range` whose result is dropped.
        self.chunks
            .warm(&self.session.vault, path, offset, length)
            .await;
    }

    async fn stat(&self, path: &str) -> Result<Option<Entry>> {
        // Answered from the local index, which is the only thing that can answer
        // it without reading the object: a vault's sizes live in its index, and
        // the object header would have to be fetched and decrypted to learn them
        // any other way.
        //
        // A path the index has never seen therefore reports `None` even when the
        // backend holds it — the cross-device case, where `Vault::get_file`
        // still succeeds by way of the authoritative §5 name record. That is a
        // real gap, and the honest place to fix it is `dctl-core`, with a `stat`
        // that consults the same name record. Callers are told to reach for
        // `dctl index rebuild`, which populates the index from the backend and
        // makes this answer true again.
        let query = path::normalize_unicode(path);
        let records = self.session.vault.list(&query)?;
        let Some(entry) = records
            .into_iter()
            .find(|record| record.path == query)
            .map(from_record)
        else {
            return Ok(None);
        };

        if entry.size.is_some() {
            return Ok(Some(entry));
        }

        // A rebuilt row: real, and carrying a size nobody has ever measured.
        // Returning its zero would make `dctl cat` write no bytes and exit 0 for
        // a file that is plainly there, which is the one failure this project
        // may not have. So the size is *established* rather than guessed — see
        // [`unmeasured`] for why this case is distinguishable and why it cannot
        // fire for a genuinely empty file.
        //
        // Establishing it used to cost a whole-object read. It no longer does:
        // both the length and the plaintext hash are fields of the object's own
        // header, sealed under its DEK and cross-checked against the head, so a
        // bounded header read answers the question outright. That matters more
        // than it looks — a mount stats constantly, and a `getattr` that pulled
        // a 40 GB film to learn its size is a filesystem nobody can use.
        let (size, content_hash) = self
            .chunks
            .measure(&self.session.vault, &entry.path)
            .await?;
        let described = Entry::new(entry.path, size).with_modified(entry.modified_unix);
        Ok(Some(match content_hash {
            // The writer's own record of the whole plaintext, authenticated
            // under the object's DEK. Absent only for a metadata schema this
            // build does not parse (`FORMAT.md` §8), in which case the honest
            // answer is that nobody here knows the hash.
            Some(hash) => described.with_content_hash(hash.to_vec()),
            None => described,
        }))
    }

    /// The digest the index already holds, for free.
    ///
    /// A vault recorded the plaintext BLAKE3 at write time, under the same
    /// verified-write contract that refused to commit unless the stored bytes
    /// matched. Nothing is read to obtain it — which is exactly the asymmetry
    /// [`Source::content_hash`] exists to make explicit, because the plain side
    /// pays a full read for the same answer.
    ///
    /// A rebuilt index row carries an *empty* digest, which
    /// [`Entry::with_content_hash`](super::entry::Entry::with_content_hash) maps
    /// to [`None`]. That absence travels: the comparison then refuses rather
    /// than treating "nobody has read this object yet" as a hash, and the remedy
    /// is a read that fills the row in.
    async fn content_hash(&self, path: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.stat(path).await?.and_then(|entry| entry.content_hash))
    }

    async fn verify(&self, path: &str) -> Result<()> {
        // The read that makes the *whole-object* statement, which is exactly what
        // a windowed read cannot: `Vault::verify_file` stream-decrypts into a
        // sink, so every chunk tag **and the footer BLAKE3 over the entire
        // object** are checked, at O(chunk) plaintext memory. That is what makes
        // a scrub of a vault full of multi-gigabyte videos possible at all, and
        // it is why this method exists instead of `read`-and-discard.
        Ok(self.session.vault.verify_file(path).await?)
    }

    fn assurance(&self) -> Assurance {
        // The vault recorded a plaintext BLAKE3 under the object's own DEK at
        // write time, and every chunk carries an authentication tag. A pass here
        // is a statement about the bytes that were written, not merely about the
        // bytes that came back.
        Assurance::Authenticated
    }

    fn inventory(&self) -> Inventory {
        // Every object written through the vault got an index row, and this
        // source enumerates that index rather than the backend — so the two
        // sides of a `verify` are a record and a remote, not one remote twice.
        // An object the backend no longer has is a row with nothing behind it,
        // which is why a deleted object here exits 4 and the same deletion on
        // the plain view of the same bytes exits 0.
        //
        // The record survives the machine that holds it: `index rebuild`
        // reconstructs it from the backend alone, because every sealed object
        // carries an authenticated header naming the path inside it, and the
        // recovery phrase reconstructs the key that reads those headers. That
        // is the property a plain remote has no equivalent of and cannot be
        // given one — see [`super::inventory`].
        Inventory::Recorded
    }
}

/// A cursor over records the core already materialised.
///
/// Named for what it is. See the module documentation for why the buffer is
/// here, whose limitation it is, and what replacing it looks like.
struct Buffered {
    /// Remaining entries in path order. A [`VecDeque`] so that taking the front
    /// is O(1) rather than an O(n) shift out of a `Vec` on every single entry.
    entries: VecDeque<Entry>,
}

#[async_trait]
impl Entries for Buffered {
    async fn next(&mut self) -> Result<Option<Entry>> {
        Ok(self.entries.pop_front())
    }
}

/// Translate one index record into the provider-neutral entry.
///
/// Public because it is the binary's **only** translation of a `dctl_core`
/// record into an [`Entry`], and a second spelling of it is a second place that
/// can forget the unmeasured case. `commands::removal::medium` had exactly such
/// a copy, and it went on rendering `0 B` for rebuilt rows after this one
/// stopped — which is how `dctl delete --dry-run` came to report freeing nothing
/// while naming three real files.
///
/// Deliberately drops `object_key`. It is the opaque name the ciphertext is
/// stored under, and printing it beside the plaintext path — which is what a
/// listing does — would hand an observer exactly the mapping the metadata-
/// privacy design exists to withhold (`PLAN.md` §2, §7). A type that cannot
/// carry it is a type no renderer can leak it through.
pub fn from_record(record: Record) -> Entry {
    // The whole point of the branch: a row that was never measured must not
    // hand its zero on as though somebody had weighed the file. See
    // [`unmeasured`] for why the two conditions together identify the case, and
    // [`Entry::size`](super::entry::Entry::size) for what believing the zero
    // cost — a rebuilt vault reporting nought bytes to a capacity monitor and to
    // a scrub's audit trail.
    let entry = if unmeasured(&record) {
        Entry::unmeasured(record.path)
    } else {
        Entry::new(record.path, record.size)
    };
    entry
        .with_modified(record.modified_unix)
        .with_content_hash(record.content_hash)
}

/// Whether this record's size was never measured.
///
/// A rebuilt index used to be entirely made of these rows.
/// [`Vault::rebuild_index`](dctl_core::Vault::rebuild_index) recovers a machine
/// from the backend alone, and it was a **list-only pass**: it decrypted the §5
/// name records and wrote `size: 0` with an *empty* content hash, and nothing
/// ever filled them in. `Vault::get_file` resolves the object key, decrypts and
/// returns, writing nothing back, so `cat`, `hashsum` and a whole `scrub` all
/// left the row as unmeasured as they found it — checked by running each of them
/// against a rebuilt index. On a restored machine the state was permanent until
/// the next backup ran.
///
/// The rebuild now describes each object from its own header, so this is no
/// longer the ordinary state of a recovered index. It is still reachable — an
/// object the rebuild could not read back leaves exactly this row, and the
/// rebuild reports how many — which is why the absence still has to survive all
/// the way to the renderers rather than being treated as impossible.
///
/// The two conditions together are what make the case identifiable. A file
/// written through the ordinary path always has a 32-byte BLAKE3 recorded, and
/// that is true of a genuinely empty file too: `blake3::hash(b"")` is a full
/// digest, not nothing. So `size == 0` with *no* hash cannot be an empty file
/// that was written here; it can only be a row nobody has measured yet.
///
/// Distinguishing them matters because the alternative is silent: a caller that
/// believed the zero would read no bytes and report success.
///
/// Asked of the **record** rather than of the [`Entry`] built from it, because
/// the entry no longer carries a zero to inspect: [`from_record`] is the one
/// place that decides, and it decides from the only data that can tell the two
/// apart.
fn unmeasured(record: &Record) -> bool {
    record.size == 0 && record.content_hash.is_empty()
}

// The window arithmetic that used to live here — slice a buffer the caller had
// already paid to download whole — is gone with the read that needed it. Clamping
// now happens where the bytes are chosen rather than after they arrive: see
// [`RangeHeader::span`](dctl_crypto::object::RangeHeader::span) for the covering
// chunks and [`chunk_cache`](super::chunk_cache) for the copy out of them.

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use async_trait::async_trait;
    use bytes::Bytes;
    use dctl_core::Vault;
    use dctl_store::{
        Backend, ByteRange, ContentHash, LocalFs, ObjectKey, ObjectMeta, Page, PutOutcome,
    };
    use tempfile::TempDir;

    /// A real vault over two temporary directories, with `files` written into
    /// it. Nothing is mocked: the objects are sealed, stored and indexed exactly
    /// as `dctl copy` would have stored them.
    struct Fixture {
        /// The directory the objects live in. Reached into by the tests that
        /// corrupt or remove an object — including the only way left to produce
        /// an unmeasured index row, which is an object that is not there to
        /// describe.
        store: TempDir,
        _index: TempDir,
        source: VaultSource,
        /// The meter under the vault — how many bytes of object storage this
        /// fixture has actually moved. See [`Metered`].
        meter: Arc<Metered>,
    }

    /// A [`Backend`] that counts the bytes it hands back, wrapping a real one.
    ///
    /// The claim this file makes about a windowed read is a claim about *egress*,
    /// and egress is the one thing an assertion on the returned plaintext cannot
    /// see: the old whole-object implementation returned exactly the same ten
    /// bytes while transferring ninety-five megabytes to do it. So the transfer
    /// is measured rather than argued about — a wrapper here counts every byte
    /// that leaves storage, and the tests assert on that number.
    ///
    /// Every method delegates. Nothing is simulated, faked or short-circuited:
    /// the objects underneath are the ones `dctl copy` wrote, read back through
    /// the ordinary `LocalFs`.
    struct Metered {
        inner: LocalFs,
        /// Bytes returned by `get` and `get_range` since the last reset.
        fetched: AtomicU64,
        /// Calls to `get_range` since the last reset — a window that costs one
        /// request and a window that costs a hundred move very different amounts
        /// of a provider's rate limit even when the byte totals agree.
        requests: AtomicU64,
    }

    impl Metered {
        fn new(root: &Path) -> Self {
            Self {
                inner: LocalFs::new(root),
                fetched: AtomicU64::new(0),
                requests: AtomicU64::new(0),
            }
        }

        /// Bytes fetched and ranged requests issued, then zeroed — so a test can
        /// measure one operation without the setup that preceded it.
        fn take(&self) -> (u64, u64) {
            (
                self.fetched.swap(0, Ordering::Relaxed),
                self.requests.swap(0, Ordering::Relaxed),
            )
        }

        fn count(&self, bytes: &Bytes) {
            self.fetched
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        }
    }

    #[async_trait]
    impl Backend for Metered {
        fn name(&self) -> &'static str {
            self.inner.name()
        }
        async fn store_identity(&self) -> dctl_store::Result<Option<dctl_store::StoreIdentity>> {
            self.inner.store_identity().await
        }

        /// Forwarded: this double measures traffic, and traffic is not what a
        /// provider records about an object.
        fn checksum_support(&self) -> dctl_store::ChecksumSupport {
            self.inner.checksum_support()
        }

        async fn stored_checksum(
            &self,
            key: &ObjectKey,
        ) -> dctl_store::Result<dctl_store::StoredChecksum> {
            self.inner.stored_checksum(key).await
        }
        async fn put(
            &self,
            key: &ObjectKey,
            data: Bytes,
            expected: &ContentHash,
            modified: dctl_store::SourceModified,
        ) -> dctl_store::Result<PutOutcome> {
            self.inner.put(key, data, expected, modified).await
        }
        async fn put_from_path(
            &self,
            key: &ObjectKey,
            source: &Path,
            expected: &ContentHash,
            modified: dctl_store::SourceModified,
        ) -> dctl_store::Result<PutOutcome> {
            self.inner
                .put_from_path(key, source, expected, modified)
                .await
        }
        async fn get(&self, key: &ObjectKey) -> dctl_store::Result<Bytes> {
            let bytes = self.inner.get(key).await?;
            self.count(&bytes);
            Ok(bytes)
        }
        async fn get_to_path(&self, key: &ObjectKey, dest: &Path) -> dctl_store::Result<()> {
            self.inner.get_to_path(key, dest).await
        }
        async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> dctl_store::Result<Bytes> {
            self.requests.fetch_add(1, Ordering::Relaxed);
            let bytes = self.inner.get_range(key, range).await?;
            self.count(&bytes);
            Ok(bytes)
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
        ) -> dctl_store::Result<Page> {
            self.inner.list_page(prefix, cursor).await
        }

        async fn list_staging(
            &self,
            prefix: &str,
            cursor: Option<String>,
        ) -> dctl_store::Result<dctl_store::StagingListing> {
            self.inner.list_staging(prefix, cursor).await
        }

        async fn put_stream(
            &self,
            key: &ObjectKey,
            source: dctl_store::ObjectStream,
            modified: dctl_store::SourceModified,
        ) -> dctl_store::Result<PutOutcome> {
            self.inner.put_stream(key, source, modified).await
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

    async fn vault_with(files: &[(&str, &[u8])]) -> Fixture {
        let store = TempDir::new().expect("a temporary store");
        let index = TempDir::new().expect("a temporary index");
        let meter = Arc::new(Metered::new(store.path()));
        let backend: Arc<dyn Backend> = Arc::clone(&meter) as Arc<dyn Backend>;
        let index_path: PathBuf = index.path().join("index.redb");

        let vault = Vault::init(Arc::clone(&backend), &index_path, "pw")
            .await
            .expect("a fresh vault initialises")
            .vault;
        for (path, bytes) in files {
            vault
                .put_file(path, bytes, dctl_core::Modified::Now)
                .await
                .expect("a verified write");
        }

        let session = Session {
            vault,
            remote: "archive:".to_string(),
            index: index_path,
        };
        Fixture {
            store,
            _index: index,
            source: VaultSource::new(session),
            meter,
        }
    }

    async fn paths(source: &VaultSource, prefix: &str) -> Vec<String> {
        let mut cursor = source.enumerate(prefix).await.expect("a listing opens");
        let mut out = Vec::new();
        while let Some(entry) = cursor.next().await.expect("a page cannot fail") {
            out.push(entry.path);
        }
        out
    }

    #[tokio::test]
    async fn every_stored_file_is_enumerated_once_in_path_order() {
        let fixture = vault_with(&[
            ("b/second.txt", b"22"),
            ("a.txt", b"1"),
            ("b/first.txt", b"333"),
        ])
        .await;

        assert_eq!(
            paths(&fixture.source, "").await,
            ["a.txt", "b/first.txt", "b/second.txt"]
        );
    }

    #[tokio::test]
    async fn a_prefix_scopes_the_listing_to_whole_components() {
        // `photos` is not the parent of `photos-backup`. The index matches
        // prefixes by bytes and would report both.
        let fixture = vault_with(&[
            ("photos/a.jpg", b"a"),
            ("photos-backup/b.jpg", b"b"),
            ("other/c.jpg", b"c"),
        ])
        .await;

        assert_eq!(paths(&fixture.source, "photos").await, ["photos/a.jpg"]);
    }

    #[tokio::test]
    async fn an_empty_vault_enumerates_to_nothing_without_failing() {
        // "There is nothing here" is an answer, not an error — and an exhausted
        // cursor keeps saying so rather than looping.
        let fixture = vault_with(&[]).await;
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
        // The failure mode worth guarding: a prefix filter that silently fell
        // through would list the whole vault for `dctl ls archive:nowhere`.
        let fixture = vault_with(&[("a.txt", b"1")]).await;
        assert!(paths(&fixture.source, "nowhere").await.is_empty());
    }

    #[tokio::test]
    async fn an_entry_carries_the_plaintext_size_and_hash() {
        let fixture = vault_with(&[("a.txt", b"hello")]).await;
        let mut cursor = fixture.source.enumerate("").await.expect("a listing");
        let entry = cursor.next().await.expect("no failure").expect("one entry");

        // The plaintext length, not the sealed object's — otherwise `ls` and
        // `cat | wc -c` disagree about the same file.
        assert_eq!(entry.size, Some(5));
        assert_eq!(
            entry.content_hash.as_deref(),
            Some(blake3::hash(b"hello").as_bytes().as_slice()),
            "the recorded hash must be of the plaintext"
        );
    }

    #[tokio::test]
    async fn a_read_returns_the_plaintext() {
        let fixture = vault_with(&[("notes/today.md", b"sealed and returned")]).await;
        let bytes = fixture
            .source
            .read("notes/today.md")
            .await
            .expect("the object reads back");
        assert_eq!(bytes.as_slice(), b"sealed and returned");
    }

    #[tokio::test]
    async fn a_missing_path_is_reported_rather_than_read_as_empty() {
        // Returning zero bytes for an object that is not there is the misreport
        // `PLAN.md` §6 forbids: a redirected `dctl cat` would leave a file that
        // looks like a successful, empty download.
        let fixture = vault_with(&[("a.txt", b"1")]).await;
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
        let fixture = vault_with(&[("a.bin", b"0123456789")]).await;
        let source = &fixture.source;

        assert_eq!(
            source
                .read_range("a.bin", 4, Some(3))
                .await
                .unwrap()
                .as_slice(),
            b"456"
        );
        // No length means "to the end".
        assert_eq!(
            source
                .read_range("a.bin", 7, None)
                .await
                .unwrap()
                .as_slice(),
            b"789"
        );
        // A window longer than what is left is clamped, not refused.
        assert_eq!(
            source
                .read_range("a.bin", 8, Some(999))
                .await
                .unwrap()
                .as_slice(),
            b"89"
        );
        // An offset at or past the end yields nothing, exactly as a seek would.
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
        // "From the start, to the end" is the whole object spelled as a range,
        // and it takes the whole-object path — which must return the same bytes
        // `read` does, or the two spellings of one request disagree.
        assert_eq!(
            source
                .read_range("a.bin", 0, None)
                .await
                .unwrap()
                .as_slice(),
            source.read("a.bin").await.unwrap().as_slice()
        );
    }

    #[tokio::test]
    async fn stat_describes_a_stored_object_and_answers_none_for_a_missing_one() {
        let fixture = vault_with(&[("photos/a.jpg", b"12345")]).await;

        let found = fixture
            .source
            .stat("photos/a.jpg")
            .await
            .expect("the lookup succeeds")
            .expect("the object is there");
        assert_eq!(found.path, "photos/a.jpg");
        assert_eq!(found.size, Some(5));

        // Absent is an answer, not a failure — the caller distinguishes "not
        // there" from "could not look" by which channel it arrived on.
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
    async fn stat_does_not_mistake_a_sibling_for_the_object_asked_for() {
        // `vault.list` is a byte-wise prefix scan, so a naive "first record"
        // would answer `a.jpg.bak` for a query about `a.jpg`.
        let fixture = vault_with(&[("a.jpg.bak", b"old"), ("a.jpg", b"new")]).await;
        let found = fixture
            .source
            .stat("a.jpg")
            .await
            .expect("the lookup succeeds")
            .expect("the object is there");
        assert_eq!(found.path, "a.jpg");
        assert_eq!(found.size, Some(3));
    }

    #[tokio::test]
    async fn a_rebuild_records_what_the_object_declares_rather_than_nothing() {
        // The failure this guards, seen for real: `dctl index rebuild` wrote rows
        // with no size, and a `stat` that believed the zero made
        // `dctl cat archive:a.txt` print nothing and exit 0 for a file that was
        // plainly there. `stat` was taught to measure round it — but `check`,
        // `size` and `sync` read the row, and the row said nothing.
        let fixture = vault_with(&[("a.txt", b"hello world")]).await;
        let rebuilt = fixture
            .source
            .session
            .vault
            .rebuild_index()
            .await
            .expect("the index rebuilds from the backend");
        assert_eq!(
            (rebuilt.files, rebuilt.measured, rebuilt.unmeasured),
            (1, 1, 0)
        );

        // The listing reads the index directly, so it is where a degraded row
        // shows. Both facts are the object's own, sealed under its DEK.
        let mut cursor = fixture.source.enumerate("").await.unwrap();
        let listed = cursor.next().await.unwrap().expect("the row is there");
        assert_eq!(
            listed.size,
            Some(11),
            "the rebuilt row carries the size the object declares"
        );
        assert_eq!(
            listed.content_hash.as_deref(),
            Some(blake3::hash(b"hello world").as_bytes().as_slice()),
            "and the content hash, without which `dctl check` cannot compare"
        );

        // And `stat` agrees, from the row rather than from a second read.
        let found = fixture
            .source
            .stat("a.txt")
            .await
            .unwrap()
            .expect("the object is there");
        assert_eq!(found.size, Some(11));
    }

    #[tokio::test]
    async fn an_object_the_rebuild_cannot_read_leaves_a_row_that_claims_nothing() {
        // The one case that still produces an unmeasured row, and the reason the
        // absence has to survive to the renderers: the name record maps the path,
        // the object it points at is gone, and the row must not answer zero for a
        // file whose size nobody knows.
        let fixture = vault_with(&[("a.txt", b"hello world")]).await;
        std::fs::remove_dir_all(fixture.store.path().join("o"))
            .expect("the object tree is removable");

        let rebuilt = fixture
            .source
            .session
            .vault
            .rebuild_index()
            .await
            .expect("a rebuild over a missing object still maps the path");
        assert_eq!(
            (rebuilt.files, rebuilt.measured, rebuilt.unmeasured),
            (1, 0, 1)
        );

        let mut cursor = fixture.source.enumerate("").await.unwrap();
        let listed = cursor.next().await.unwrap().expect("the row is there");
        assert_eq!(
            listed.size, None,
            "an unmeasured row reports no size rather than answering zero"
        );
    }

    #[tokio::test]
    async fn a_genuinely_empty_file_is_not_mistaken_for_an_unmeasured_row() {
        // `blake3::hash(b"")` is a full digest, so a file written here always
        // has one — which is exactly what keeps the two cases apart.
        let fixture = vault_with(&[("empty.txt", b"")]).await;
        let found = fixture
            .source
            .stat("empty.txt")
            .await
            .unwrap()
            .expect("an empty object is still an object");
        assert_eq!(found.size, Some(0));
        assert!(found.content_hash.is_some());
    }

    #[tokio::test]
    async fn a_verify_authenticates_the_stored_bytes_and_notices_when_they_change() {
        // The claim this source is allowed to make, proved: the object is
        // overwritten behind DCTL's back and the check catches it.
        let fixture = vault_with(&[("a.txt", b"sealed")]).await;
        fixture
            .source
            .verify("a.txt")
            .await
            .expect("an intact object authenticates");

        let objects = fixture.store.path().join("o");
        for entry in std::fs::read_dir(&objects).expect("the object directory exists") {
            let path = entry.expect("a directory entry").path();
            let length = std::fs::metadata(&path).expect("readable").len();
            std::fs::write(&path, vec![0xA5; length as usize]).expect("overwritten");
        }

        let error = fixture
            .source
            .verify("a.txt")
            .await
            .expect_err("altered bytes must not pass");
        assert_eq!(error.code(), crate::exit::ExitCode::IntegrityFailure);

        // And the claim itself, which is what separates this source from a
        // plain store that would have read the same garbage back happily.
        assert_eq!(fixture.source.assurance(), Assurance::Authenticated);
        assert!(fixture.source.assurance().detects_corruption());
    }

    #[tokio::test]
    async fn a_verify_of_a_missing_object_is_reported_as_missing() {
        let fixture = vault_with(&[("a.txt", b"1")]).await;
        let error = fixture
            .source
            .verify("nope.txt")
            .await
            .expect_err("a missing object cannot be verified");
        assert_eq!(error.code(), crate::exit::ExitCode::FileNotFound);
    }

    #[tokio::test]
    async fn a_window_never_reads_outside_the_object() {
        // The values a `u64` flag can hold that a `usize` index cannot, against a
        // real sealed object rather than a buffer — the clamp now happens while
        // choosing chunks, so this is the level it has to be proved at.
        // One fixture for both files: initialising a vault runs Argon2id at its
        // real cost, so a second one here would buy nothing but seconds.
        let fixture = vault_with(&[("a.bin", b"abcdef"), ("nothing.bin", b"")]).await;
        let source = &fixture.source;
        assert!(
            source
                .read_range("a.bin", u64::MAX, None)
                .await
                .expect("an absurd offset clamps rather than wrapping")
                .is_empty()
        );
        assert_eq!(
            source
                .read_range("a.bin", 1, Some(u64::MAX))
                .await
                .expect("an absurd length clamps to what is there")
                .as_slice(),
            b"bcdef"
        );
        // A zero-length object has no chunks at all, so the covering-chunk
        // arithmetic must produce an empty span rather than reach for chunk 0.
        assert!(
            source
                .read_range("nothing.bin", 0, Some(4))
                .await
                .expect("an empty object has no window to serve")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_window_of_a_multi_chunk_object_matches_every_offset() {
        // The whole point of the ranged path, end to end through a real vault: an
        // object several chunks long, read at every offset and length that crosses
        // a boundary. A one-off in the covering-chunk arithmetic, or a chunk
        // served from the cache at the wrong position, shows up here.
        let size = 300 * 1024;
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let fixture = vault_with(&[("big.bin", &plaintext)]).await;

        for offset in [0u64, 1, 1023, 65_535, 65_536, 131_072, 262_143, 307_199] {
            for length in [1u64, 2, 4096, 65_537, 300 * 1024] {
                let window = fixture
                    .source
                    .read_range("big.bin", offset, Some(length))
                    .await
                    .expect("a window of a stored object reads back");
                let start = offset as usize;
                let end = (start + length as usize).min(plaintext.len());
                assert_eq!(
                    window.as_slice(),
                    &plaintext[start..end],
                    "offset {offset} length {length}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_repeated_window_is_served_from_the_cache_without_the_backend() {
        // The property the cache exists for, proved by removing the backend from
        // under it: once a chunk has been fetched and authenticated, a later read
        // inside it must not touch storage. Without this, a mount would re-fetch
        // the same megabyte for every 4 KiB the kernel asks for.
        let plaintext: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let fixture = vault_with(&[("big.bin", &plaintext)]).await;

        let first = fixture
            .source
            .read_range("big.bin", 4096, Some(4096))
            .await
            .expect("the first window fetches its chunk");
        assert_eq!(first.as_slice(), &plaintext[4096..8192]);

        // Delete every stored object. A read that still answers correctly can only
        // have come from memory.
        let objects = fixture.store.path().join("o");
        for entry in std::fs::read_dir(&objects).expect("the object directory exists") {
            std::fs::remove_file(entry.expect("a directory entry").path()).expect("removed");
        }

        let again = fixture
            .source
            .read_range("big.bin", 5000, Some(1000))
            .await
            .expect("a second window inside the same chunk needs no request");
        assert_eq!(again.as_slice(), &plaintext[5000..6000]);
    }

    #[tokio::test]
    async fn a_small_window_of_a_large_object_transfers_the_window_not_the_object() {
        // The measurement this whole change exists for, taken rather than argued.
        // An audit found a 10-byte window of a 95 MiB object costing a 95 MiB
        // transfer and ~97 MB of resident memory, because the only read available
        // was whole-object. The bytes returned were correct then too — which is
        // exactly why the assertion has to be on the *transfer*.
        //
        // 8 MiB is small enough to seal quickly in a unit test and large enough
        // that the ratio cannot be a rounding artefact: the covering chunk is a
        // few per cent of it, not most of it.
        let size = 8 * 1024 * 1024;
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let fixture = vault_with(&[("big.bin", &plaintext)]).await;
        let object = std::fs::read_dir(fixture.store.path().join("o"))
            .expect("the object directory exists")
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.metadata().map_or(0, |meta| meta.len()))
            .sum::<u64>();
        assert!(object >= size as u64, "the sealed object holds the file");

        // ── The new path: ten bytes from the middle. ──
        fixture.meter.take();
        let offset = size as u64 / 2 + 7;
        let window = fixture
            .source
            .read_range("big.bin", offset, Some(10))
            .await
            .expect("a window reads back");
        let (windowed_bytes, windowed_requests) = fixture.meter.take();
        assert_eq!(
            window.as_slice(),
            &plaintext[offset as usize..offset as usize + 10]
        );

        // ── The old path, still reachable and still correct: everything. This is
        //    byte-for-byte what the previous `read_range` did before slicing. ──
        let whole = fixture.source.read("big.bin").await.expect("a whole read");
        let (whole_bytes, _) = fixture.meter.take();
        assert_eq!(whole.len(), size);

        // The window must cost one header probe plus the one chunk it lives in,
        // and nothing that scales with the object. Two mebibytes is that bound
        // with room to spare at the format's 1 MiB default chunk size (spelled
        // out rather than imported: this crate depends on `dctl-core`, not on
        // `dctl-crypto`, and reaching past a layer for a test constant is how
        // layering stops meaning anything).
        assert!(
            windowed_bytes <= 2 * 1024 * 1024,
            "a 10-byte window moved {windowed_bytes} bytes; one covering chunk \
             plus a header probe is under 2 MiB"
        );
        assert!(
            windowed_bytes * 4 < whole_bytes,
            "a 10-byte window moved {windowed_bytes} bytes against {whole_bytes} \
             for the whole object — the ranged read is not saving anything"
        );
        // Two requests on a cold open: the bounded header probe, then the chunks.
        // Anything more means the header is being re-read per window.
        assert_eq!(
            windowed_requests, 2,
            "a cold window costs one header probe and one payload range"
        );
    }

    #[tokio::test]
    async fn reading_an_object_end_to_end_fetches_each_chunk_once() {
        // The cache's reason to exist, measured. A kernel reads a file in small
        // steps; without a cache each step re-fetches and re-decrypts the whole
        // chunk it lands in, so a 4 MiB file read in 64 KiB windows would move
        // 64 MiB. The transfer must track the file, not the number of reads.
        let size = 4 * 1024 * 1024;
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let fixture = vault_with(&[("big.bin", &plaintext)]).await;

        fixture.meter.take();
        let step = 64 * 1024;
        let mut assembled = Vec::with_capacity(size);
        let mut at = 0u64;
        while (at as usize) < size {
            let part = fixture
                .source
                .read_range("big.bin", at, Some(step))
                .await
                .expect("each step reads back");
            assert!(
                !part.is_empty(),
                "a step inside the object must yield bytes"
            );
            assembled.extend_from_slice(&part);
            at += part.len() as u64;
        }
        let (bytes, requests) = fixture.meter.take();

        assert_eq!(
            assembled, plaintext,
            "a stepped read must reassemble exactly"
        );
        // Sixty-four reads of a four-chunk object. Uncached that is 64 chunk
        // fetches; cached it is four, plus the one header probe.
        assert!(
            requests <= 8,
            "{} reads of a 4-chunk object issued {requests} requests — the cache \
             is not holding chunks between reads",
            size / step as usize
        );
        assert!(
            bytes < (size as u64) * 2,
            "reading {size} bytes moved {bytes} — the cache is not holding chunks"
        );
    }

    #[tokio::test]
    async fn a_stat_of_an_unmeasured_row_costs_a_header_read_rather_than_the_object() {
        // A rebuilt index carries no sizes, and `stat` must still answer with a
        // real one — it used to establish that by reading the whole object, which
        // is a `getattr` that downloads a film. The length and the plaintext hash
        // are both fields of the object's own DEK-authenticated header, so the
        // answer is now bounded.
        let size = 4 * 1024 * 1024;
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let fixture = vault_with(&[("big.bin", &plaintext)]).await;
        fixture
            .source
            .session
            .vault
            .rebuild_index()
            .await
            .expect("the index rebuilds from the backend");

        fixture.meter.take();
        let found = fixture
            .source
            .stat("big.bin")
            .await
            .expect("the lookup succeeds")
            .expect("the object is there");
        let (bytes, _) = fixture.meter.take();

        assert_eq!(found.size, Some(size as u64));
        assert_eq!(
            found.content_hash.as_deref(),
            Some(blake3::hash(&plaintext).as_bytes().as_slice()),
            "the recorded hash must be of the plaintext"
        );
        assert!(
            bytes < 64 * 1024,
            "a stat of a {size}-byte object moved {bytes} bytes"
        );
    }

    #[tokio::test]
    async fn a_windowed_read_refuses_a_tampered_chunk() {
        // The guarantee the ranged path is allowed to make. The footer and the
        // whole-plaintext hash cannot be checked on a partial read; the per-chunk
        // Poly1305 tag can, and it must be what stops corrupt bytes here.
        let plaintext: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let fixture = vault_with(&[("big.bin", &plaintext)]).await;

        let objects = fixture.store.path().join("o");
        for entry in std::fs::read_dir(&objects).expect("the object directory exists") {
            let path = entry.expect("a directory entry").path();
            let mut bytes = std::fs::read(&path).expect("readable");
            // Deep inside the payload, well past the header, so the header still
            // opens and only a chunk's ciphertext is disturbed.
            let at = bytes.len() / 2;
            bytes[at] ^= 0x80;
            std::fs::write(&path, &bytes).expect("overwritten");
        }

        let error = fixture
            .source
            .read_range("big.bin", 100_000, Some(64))
            .await
            .expect_err("a flipped ciphertext byte must not be served");
        assert_eq!(error.code(), crate::exit::ExitCode::IntegrityFailure);

        // And an object that stops inside its own header — a half-finished upload,
        // or a provider serving a truncated body — is refused rather than probed
        // in a loop or read as an empty file. The reader asks for a bounded prefix
        // and gets less than the object claims to need, which is only possible if
        // there is no more object.
        for entry in std::fs::read_dir(&objects).expect("the object directory exists") {
            let path = entry.expect("a directory entry").path();
            let bytes = std::fs::read(&path).expect("readable");
            std::fs::write(&path, &bytes[..40]).expect("truncated to inside the head");
        }
        let stump = VaultSource::new(Session {
            vault: fixture.source.session.vault,
            remote: fixture.source.session.remote,
            index: fixture.source.session.index,
        });
        let error = stump
            .read_range("big.bin", 0, Some(8))
            .await
            .expect_err("an object truncated inside its header must not be served");
        assert_eq!(error.code(), crate::exit::ExitCode::IntegrityFailure);
    }
}
