//! Everything a mount knows, and every operation it can perform.
//!
//! The filesystem callbacks in [`super::fs`] are a translation layer and nothing
//! more: they take fuser's types, call one method here, and turn the answer into
//! a reply. All of the actual work — resolving an inode, deciding whether a
//! listing is still fresh, mapping a byte window onto a ranged read — is in this
//! module, where it can be tested without a kernel.
//!
//! ## One lock, never held across an await
//!
//! The inode table, the directory cache and the handle table are three maps that
//! have to agree with each other: a `lookup` allocates an inode from a listing it
//! just read, and a concurrent `forget` must not drop that number between the
//! allocation and the reply. So they sit behind one `std::sync::Mutex`, and every
//! critical section is a map operation measured in nanoseconds.
//!
//! Nothing is awaited while it is held — the pattern throughout is *take the
//! lock, decide, drop it, do the I/O, take it again to record the result*. That
//! is what allows a `read` of a fifty-gigabyte film to be in flight while a
//! `readdir` of another directory completes, and it is why a synchronous mutex is
//! the right one: an async mutex would add a task-wakeup path to protect against
//! contention that cannot occur.
//!
//! Two callers racing on the same cold directory will both list it, and the
//! second store wins. That costs one redundant listing and is otherwise harmless
//! — both read the same prefix — where holding the lock across the listing would
//! serialise every first `ls` in the mount behind one provider round trip.
//!
//! ## A missing thing is `None`, never an error
//!
//! Every lookup-shaped method here answers `Ok(None)` for "there is no such
//! entry" and reserves the error channel for a failure to *look*. That is the
//! same split [`Source::stat`] makes, and it matters more here: `ENOENT` is a
//! normal, expected answer that every program handles, and reporting it as `EIO`
//! turns a `ls` of a file deleted on another machine into an apparent hardware
//! fault.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use fuser::{FileAttr, FileHandle, INodeNo};
use zeroize::Zeroizing;

use crate::constants::{MOUNT_DIR_CACHE_MAX, MOUNT_READDIR_BATCH};
use crate::error::Result;
use crate::source::Source;

use super::attr::{self, Identity};
use super::config::MountConfig;
use super::handle::HandleTable;
use super::inode::{InodeTable, Kind};
use super::tree::{self, Listing};

/// One directory listing plus when it was read.
struct Cached {
    listing: Arc<Listing>,
    /// Monotonic, so a clock adjustment mid-mount cannot make a listing look
    /// fresh forever — or expire everything at once.
    read_at: Instant,
    /// Recency for eviction, stamped on use. Separate from `read_at`, which ages
    /// the *content*: a listing that is read constantly still has to be re-read
    /// when it goes stale.
    used: u64,
}

/// The maps that have to agree with each other, behind one lock.
struct Interior {
    inodes: InodeTable,
    handles: HandleTable,
    directories: HashMap<String, Cached>,
    /// Monotonic recency counter for directory eviction.
    tick: u64,
}

/// A mounted vault: what it is serving, and what it currently remembers.
pub struct MountState {
    /// The unlocked source every read goes through.
    ///
    /// `Arc<dyn Source>` rather than a concrete type for the reason
    /// [`crate::source`] exists: the mount cannot tell a sealed vault from a
    /// plain object store, and therefore cannot become the place where the two
    /// behave differently.
    source: Arc<dyn Source>,
    config: MountConfig,
    identity: Identity,
    interior: Mutex<Interior>,
}

impl MountState {
    /// Build the state for a mount of `config.root` through `source`.
    #[must_use]
    pub fn new(source: Arc<dyn Source>, config: MountConfig, identity: Identity) -> Self {
        let root = config.root.clone();
        Self {
            source,
            config,
            identity,
            interior: Mutex::new(Interior {
                inodes: InodeTable::new(root),
                handles: HandleTable::new(),
                directories: HashMap::new(),
                tick: 0,
            }),
        }
    }

    /// The resolved settings, for the callbacks that need a TTL to reply with.
    #[must_use]
    pub const fn config(&self) -> &MountConfig {
        &self.config
    }

    /// Resolve `name` inside the directory `parent`, taking a kernel reference to
    /// whatever is found.
    ///
    /// The reference is taken here rather than by the caller because the protocol
    /// ties it to the *reply*: every successful `lookup` increments the kernel's
    /// count, and a mount that allocated an inode without counting it could evict
    /// a number the kernel is still using. Returning the attributes and the count
    /// from one place is what keeps the two in step.
    ///
    /// # Errors
    /// Whatever listing the parent reported.
    pub async fn lookup(&self, parent: INodeNo, name: &str) -> Result<Option<FileAttr>> {
        let Some((path, Kind::Directory)) = self.resolve(parent) else {
            // The parent is not a directory, or is not remembered at all. Either
            // way there is nothing under it.
            return Ok(None);
        };

        let listing = self.listing(&path).await?;
        let Some(child) = listing.child(name) else {
            return Ok(None);
        };

        let size = self.size_of(child.kind, &child.path, child.size).await?;
        let mut interior = self.interior();
        let ino = interior.inodes.intern(&child.path, child.kind);
        interior.inodes.remember(ino);
        Ok(Some(attr::of(
            ino,
            child.kind,
            size,
            child.modified_unix,
            &self.identity,
        )))
    }

    /// The attributes of `ino`.
    ///
    /// The mount root is answered without any I/O — it is a directory by
    /// definition and its attributes are constants. Everything else is answered
    /// from its **parent's** listing, which is the only place a directory's
    /// existence is recorded at all: nothing stores `photos`, so `stat`ing it
    /// through the source would report that it is not there.
    ///
    /// # Errors
    /// Whatever listing the parent reported.
    pub async fn getattr(&self, ino: INodeNo) -> Result<Option<FileAttr>> {
        let Some((path, kind)) = self.resolve(ino) else {
            return Ok(None);
        };
        if ino == INodeNo::ROOT {
            return Ok(Some(attr::directory(ino, &self.identity)));
        }

        let parent = crate::platform::path::parent(&path).to_string();
        let listing = self.listing(&parent).await?;
        let name = crate::platform::path::file_name(&path);
        let Some(child) = listing.child(name) else {
            // The entry has gone since it was interned. `None` becomes ENOENT,
            // which is exactly what has happened.
            return Ok(None);
        };

        let size = self.size_of(kind, &child.path, child.size).await?;
        Ok(Some(attr::of(
            ino,
            child.kind,
            size,
            child.modified_unix,
            &self.identity,
        )))
    }

    /// Open `ino` for reading, returning the handle the kernel should quote back.
    ///
    /// Nothing is fetched: opening a file in this mount costs one map insertion,
    /// which is what makes a media player's habit of opening a file to read its
    /// header and closing it again free. The first `read` is where a provider is
    /// contacted.
    ///
    /// # Errors
    /// Never fails on I/O — it performs none. `Ok(None)` means the inode is not a
    /// file this mount can open, which the caller reports as `ENOENT` for an
    /// unknown inode or `EISDIR` for a directory.
    pub fn open(&self, ino: INodeNo) -> Option<(FileHandle, Kind)> {
        let (path, kind) = self.resolve(ino)?;
        if kind != Kind::File {
            return Some((FileHandle(0), kind));
        }
        let handle = self.interior().handles.open_file(path);
        Some((handle, Kind::File))
    }

    /// Read the byte window `[offset, offset + size)` of the file `handle` is
    /// open on.
    ///
    /// **This is the call the format exists for.** It goes straight to
    /// [`Source::read_range`], which fetches only the chunks covering the window
    /// (`docs/FORMAT.md` §3) — so a player seeking to 45:00 in a fifty-gigabyte
    /// film transfers the covering chunks and nothing else. There is no
    /// whole-object path behind it, at any size.
    ///
    /// A window past the end of the file returns fewer bytes than asked for
    /// rather than failing, which is what `read(2)` does and what the kernel
    /// expects: it is how end-of-file is signalled.
    ///
    /// # Errors
    /// Whatever the source reported. An authentication failure returns the error
    /// and **no bytes** — there is no mode in which this hands a program data
    /// that did not verify.
    pub async fn read(
        &self,
        handle: FileHandle,
        offset: u64,
        size: u32,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let Some(path) = self.interior().handles.path_of(handle).map(str::to_owned) else {
            return Ok(None);
        };

        let bytes = self
            .source
            .read_range(&path, offset, Some(u64::from(size)))
            .await?;

        self.schedule_read_ahead(handle, &path, offset, u64::from(size));
        Ok(Some(bytes))
    }

    /// Open `ino` as a directory, snapshotting its contents.
    ///
    /// The snapshot is what makes `readdir` resumable: the kernel reads a
    /// directory in several calls and expects the sequence not to shift between
    /// them, which a filesystem that re-listed on each call cannot promise.
    ///
    /// # Errors
    /// Whatever listing the directory reported.
    pub async fn opendir(&self, ino: INodeNo) -> Result<Option<(FileHandle, Kind)>> {
        let Some((path, kind)) = self.resolve(ino) else {
            return Ok(None);
        };
        if kind != Kind::Directory {
            return Ok(Some((FileHandle(0), kind)));
        }

        let listing = self.listing(&path).await?;
        let handle = self.interior().handles.open_directory(listing);
        Ok(Some((handle, Kind::Directory)))
    }

    /// One batch of an open directory's entries, starting at `offset`.
    ///
    /// The offset is the *count already delivered*, which is the simplest
    /// resumption cookie that satisfies the protocol: the kernel hands back the
    /// offset of the last entry it accepted, and the filesystem continues after
    /// it. It is meaningful only against the snapshot the handle was opened on,
    /// which is exactly the guarantee [`MountState::opendir`] makes.
    ///
    /// At most [`MOUNT_READDIR_BATCH`] entries, because the kernel's reply buffer
    /// is bounded and materialising a million-entry directory to fill four
    /// kilobytes of it would be a million allocations thrown away. A short batch
    /// is legal and expected: the kernel simply asks again from the next offset,
    /// and the listing it is served from is already cached.
    ///
    /// [`None`] means the handle is not an open directory, which is `EBADF`.
    #[must_use]
    pub fn readdir(&self, ino: INodeNo, handle: FileHandle, offset: u64) -> Option<Vec<DirEntry>> {
        let listing = self.interior().handles.listing_of(handle)?;

        let mut interior = self.interior();
        let parent = interior
            .inodes
            .resolve(ino)
            .map(|(path, _)| crate::platform::path::parent(&path).to_string());

        let mut entries = Vec::new();
        // `.` and `..` are the filesystem's to supply — the kernel does not
        // synthesise them, and a directory without them is one that `cd ..`
        // cannot leave. They occupy offsets 0 and 1, so the real children start
        // at 2 and the arithmetic below has to account for it.
        let dotdot = parent
            .as_deref()
            .map_or(INodeNo::ROOT, |path| self.number_of(&mut interior, path));
        let synthetic: [(INodeNo, &str); 2] = [(ino, "."), (dotdot, "..")];
        let leading = u64::try_from(synthetic.len()).unwrap_or(u64::MAX);

        for (index, (number, name)) in synthetic.into_iter().enumerate() {
            let position = u64::try_from(index).unwrap_or(u64::MAX);
            if position < offset {
                continue;
            }
            entries.push(DirEntry {
                ino: number,
                kind: Kind::Directory,
                name: name.to_string(),
                // The offset the kernel should ask for next: one past this entry.
                next_offset: position.saturating_add(1),
            });
        }

        // Resumption seeks rather than scans. Offsets are contiguous and the two
        // synthetic entries occupy the first of them, so the first child the
        // kernel has not seen is at exactly this index — where walking from the
        // start and skipping would make reading a hundred-thousand-entry
        // directory quadratic in the number of calls it takes.
        let first = usize::try_from(offset.saturating_sub(leading)).unwrap_or(usize::MAX);
        for (index, child) in listing.children.iter().enumerate().skip(first) {
            if entries.len() >= MOUNT_READDIR_BATCH {
                break;
            }
            // The two synthetic entries come first, so a child's own position is
            // its index plus two.
            let position = u64::try_from(index)
                .unwrap_or(u64::MAX)
                .saturating_add(leading);
            let number = interior.inodes.intern(&child.path, child.kind);
            entries.push(DirEntry {
                ino: number,
                kind: child.kind,
                name: child.name.clone(),
                next_offset: position.saturating_add(1),
            });
        }

        Some(entries)
    }

    /// Forget a handle from `release` or `releasedir`.
    ///
    /// Answers whether it was a handle this mount had issued, so a caller can
    /// tell the kernel `EBADF` for one it never gave out rather than reporting
    /// success for a release that released nothing.
    pub fn release(&self, handle: FileHandle) -> bool {
        self.interior().handles.release(handle)
    }

    /// Drop `count` of the kernel's references to `ino`.
    pub fn forget(&self, ino: INodeNo, count: u64) {
        self.interior().inodes.forget(ino, count);
    }

    /// The whole-mount totals a `statfs` reports.
    ///
    /// Read from the mount root's listing, which is where the aggregation the
    /// mount already performs lands ([`super::tree`]). That listing is the
    /// expensive one — it walks the whole index — so this deliberately goes
    /// through the same TTL cache as `readdir`, and a `df` right after an `ls`
    /// costs nothing.
    ///
    /// # Errors
    /// Whatever listing the root reported.
    pub async fn statfs(&self) -> Result<Totals> {
        let listing = self.listing(&self.config.root).await?;
        Ok(Totals {
            bytes: listing.subtree_bytes,
            objects: listing.subtree_objects,
        })
    }

    /// Drop everything cached. Called from `destroy`, when the session ends.
    ///
    /// The decrypted chunks are not here — they belong to the source, and go when
    /// it does — but the listings are, and they hold plaintext filenames. Clearing
    /// them at the end of the session rather than waiting for the process to exit
    /// keeps the window in which a name is resident as short as the mount.
    ///
    /// What was still held is logged on the way out. An inode count is how a
    /// "why did this mount use so much memory" question is answered, and a
    /// non-zero handle count says the kernel was still holding files open when
    /// the session ended — which is ordinary at unmount and is a leak if it grows
    /// across mounts.
    pub fn clear(&self) {
        let mut interior = self.interior();
        tracing::debug!(
            inodes = interior.inodes.len(),
            open_handles = interior.handles.len(),
            directories = interior.directories.len(),
            "dropping what the mount had cached"
        );
        interior.directories.clear();
    }

    /// The inode number for a `..` target.
    ///
    /// A `..` that would point above the mount root resolves to the root itself,
    /// because nothing above the root is addressable through this filesystem —
    /// that is what a mount boundary means, and the kernel expects exactly this
    /// answer for the top of any mount. Anything inside gets its ordinary
    /// number.
    fn number_of(&self, interior: &mut MutexGuard<'_, Interior>, path: &str) -> INodeNo {
        if path != self.config.root && !crate::platform::path::is_under(&self.config.root, path) {
            return INodeNo::ROOT;
        }
        interior.inodes.intern(path, Kind::Directory)
    }

    /// The listing of `directory`, from the cache when it is still fresh.
    ///
    /// Freshness is `--dir-cache-time`. Beyond it the listing is read again,
    /// which is how a file another machine added appears without a remount — and
    /// why the flag's default is five minutes rather than the life of the mount.
    async fn listing(&self, directory: &str) -> Result<Arc<Listing>> {
        if let Some(cached) = self.cached_listing(directory) {
            return Ok(cached);
        }

        // The lock is *not* held across this. A cold listing of a large vault is
        // a provider round trip and an index walk; serialising every other
        // operation behind it would make one slow `ls` stall the whole mount.
        let listing = Arc::new(tree::list(self.source.as_ref(), directory).await?);
        self.store_listing(directory.to_string(), Arc::clone(&listing));
        Ok(listing)
    }

    /// A cached listing, if there is one and it has not aged out.
    fn cached_listing(&self, directory: &str) -> Option<Arc<Listing>> {
        let mut interior = self.interior();
        let tick = interior.tick.wrapping_add(1);
        interior.tick = tick;

        let cached = interior.directories.get_mut(directory)?;
        // `elapsed` on a monotonic instant, never a wall clock: a clock
        // adjustment mid-mount must not make every listing immortal.
        if cached.read_at.elapsed() > self.config.dir_ttl {
            return None;
        }
        cached.used = tick;
        Some(Arc::clone(&cached.listing))
    }

    /// Store a listing, evicting the least recently used ones over the bound.
    fn store_listing(&self, directory: String, listing: Arc<Listing>) {
        let mut interior = self.interior();
        let tick = interior.tick.wrapping_add(1);
        interior.tick = tick;
        interior.directories.insert(
            directory,
            Cached {
                listing,
                read_at: Instant::now(),
                used: tick,
            },
        );

        while interior.directories.len() > MOUNT_DIR_CACHE_MAX {
            let Some(oldest) = interior
                .directories
                .iter()
                .min_by_key(|(_, cached)| cached.used)
                .map(|(path, _)| path.clone())
            else {
                break;
            };
            interior.directories.remove(&oldest);
        }
    }

    /// The size to report for a child, establishing it if nobody has measured it.
    ///
    /// A directory has a constant apparent size and never reaches the source. A
    /// file whose index row carries no size — once the state
    /// [`Vault::rebuild_index`](dctl_core::Vault::rebuild_index) left every row
    /// in, and now only what it leaves for an object it could not read back — is
    /// measured from the object's own authenticated header, which is a bounded
    /// read and not a transfer of the file. Reporting the absent size as zero
    /// instead would make every reader see an empty file and exit successfully,
    /// which is `PLAN.md` §6's misreport with a filesystem's authority behind
    /// it.
    async fn size_of(&self, kind: Kind, path: &str, recorded: Option<u64>) -> Result<u64> {
        match (kind, recorded) {
            (Kind::Directory, _) => Ok(0),
            (Kind::File, Some(size)) => Ok(size),
            (Kind::File, None) => Ok(self
                .source
                .stat(path)
                .await?
                .and_then(|entry| entry.size)
                // The object is gone between the listing and now. Zero is the
                // honest length of something that is not there, and the read
                // that follows reports `ENOENT` rather than a short file.
                .unwrap_or(0)),
        }
    }

    /// Warm the chunks after a read, if this handle has not already covered them.
    ///
    /// `PLAN.md` §15's latency hiding: serve chunk *k* while fetching *k+1…k+P*,
    /// with *P* set by `--buffer-size`. Spawned rather than awaited — the read
    /// that triggered it is already answerable, and making a reader wait for
    /// somebody else's bytes would turn read-ahead into read-behind.
    fn schedule_read_ahead(&self, handle: FileHandle, path: &str, offset: u64, size: u64) {
        let window = self.config.read_ahead;
        if window == 0 {
            return;
        }
        let from = offset.saturating_add(size);
        if !self
            .interior()
            .handles
            .claim_read_ahead(handle, from, window)
        {
            return;
        }

        let source = Arc::clone(&self.source);
        let path = path.to_string();
        tokio::spawn(async move {
            source.prefetch(&path, from, window).await;
        });
    }

    /// Resolve an inode to its path and kind.
    fn resolve(&self, ino: INodeNo) -> Option<(String, Kind)> {
        self.interior().inodes.resolve(ino)
    }

    /// Lock the interior, recovering from a poisoned mutex rather than failing.
    ///
    /// Poisoning means a thread panicked while holding the lock. Nothing in a
    /// critical section here can panic — they are map operations on
    /// already-validated values — but if one somehow did, refusing every
    /// subsequent operation would turn that into a wedged mount, which is
    /// precisely the failure this module's no-panic rule exists to prevent. The
    /// worst a recovered lock can carry is a stale recency counter in a cache.
    fn interior(&self) -> MutexGuard<'_, Interior> {
        self.interior.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One entry a `readdir` reports.
///
/// A plain struct rather than fuser's types so [`MountState`] can be tested
/// without a kernel, and so the offset arithmetic — the part that is easy to get
/// wrong and impossible to notice — is visible to a test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// Inode number for this entry.
    pub ino: INodeNo,
    /// Whether it is a file or a directory.
    pub kind: Kind,
    /// The name inside its parent.
    pub name: String,
    /// The offset the kernel should ask for to continue after this entry.
    pub next_offset: u64,
}

/// What a `statfs` has to answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Totals {
    /// Total plaintext bytes under the mount root, or [`None`] when any object
    /// beneath it has never been measured.
    ///
    /// [`None`] is reported to `df` as a zero-block filesystem rather than as the
    /// sum of the measured part. A partial total presented as a total is the same
    /// misreport a zero would be — and worse, because it is plausible. A zero is
    /// visibly not a real number, which is the correct impression to leave when
    /// the number is not knowable.
    pub bytes: Option<u64>,
    /// Objects under the mount root. Always exact: a listing counts every entry
    /// whether or not anything measured it.
    pub objects: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{Assurance, Entries, Entry, Inventory, Sizes};
    use async_trait::async_trait;
    use fuser::SessionACL;
    use std::collections::VecDeque;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// A source over a fixed set of paths, counting what is asked of it.
    struct Fixture {
        entries: Vec<Entry>,
        listings: AtomicUsize,
        reads: AtomicUsize,
        prefetches: AtomicUsize,
    }

    impl Fixture {
        fn new(paths: &[(&str, Option<u64>)]) -> Arc<Self> {
            let mut entries: Vec<Entry> = paths
                .iter()
                .map(|(path, size)| match size {
                    Some(size) => Entry::new(*path, *size).with_modified(Some(1_700_000_000)),
                    None => Entry::unmeasured(*path),
                })
                .collect();
            entries.sort_by(|left, right| left.path.cmp(&right.path));
            Arc::new(Self {
                entries,
                listings: AtomicUsize::new(0),
                reads: AtomicUsize::new(0),
                prefetches: AtomicUsize::new(0),
            })
        }

        /// Deterministic content for a path, so a read can be checked.
        fn content(path: &str, size: u64) -> Vec<u8> {
            path.bytes()
                .cycle()
                .take(usize::try_from(size).unwrap_or(0))
                .collect()
        }
    }

    struct Cursor {
        entries: VecDeque<Entry>,
    }

    #[async_trait]
    impl Entries for Cursor {
        async fn next(&mut self) -> Result<Option<Entry>> {
            Ok(self.entries.pop_front())
        }
    }

    #[async_trait]
    impl Source for Fixture {
        /// The fixture stores plaintext, so hashing what it holds is the same
        /// answer a plain store gives — which is the point of the method.
        async fn content_hash(&self, path: &str) -> Result<Option<Vec<u8>>> {
            match self.read(path).await {
                Ok(bytes) => Ok(Some(blake3::hash(&bytes).as_bytes().to_vec())),
                Err(_) => Ok(None),
            }
        }

        async fn stream_to(
            &self,
            path: &str,
            out: &mut (dyn tokio::io::AsyncWrite + Unpin + Send),
        ) -> Result<u64> {
            use tokio::io::AsyncWriteExt as _;
            let bytes = self.read(path).await?;
            out.write_all(&bytes).await?;
            Ok(bytes.len() as u64)
        }

        async fn enumerate(&self, prefix: &str) -> Result<Box<dyn Entries>> {
            self.listings.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(Cursor {
                entries: self
                    .entries
                    .iter()
                    .filter(|entry| crate::platform::path::is_under(prefix, &entry.path))
                    .cloned()
                    .collect(),
            }))
        }

        fn sizes(&self) -> Sizes {
            Sizes::Plaintext
        }

        async fn read(&self, path: &str) -> Result<Zeroizing<Vec<u8>>> {
            self.read_range(path, 0, None).await
        }

        async fn read_range(
            &self,
            path: &str,
            offset: u64,
            length: Option<u64>,
        ) -> Result<Zeroizing<Vec<u8>>> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            let Some(entry) = self.entries.iter().find(|entry| entry.path == path) else {
                return Err(crate::error::CliError::new(
                    crate::exit::ExitCode::FileNotFound,
                    format!("{path}: no such object"),
                ));
            };
            let size = entry.size.unwrap_or(0);
            let content = Self::content(path, size);
            let start = usize::try_from(offset)
                .unwrap_or(usize::MAX)
                .min(content.len());
            let end = length
                .map_or(content.len(), |len| {
                    start.saturating_add(usize::try_from(len).unwrap_or(usize::MAX))
                })
                .min(content.len());
            Ok(Zeroizing::new(content[start..end].to_vec()))
        }

        async fn prefetch(&self, _path: &str, _offset: u64, _length: u64) {
            self.prefetches.fetch_add(1, Ordering::Relaxed);
        }

        async fn stat(&self, path: &str) -> Result<Option<Entry>> {
            Ok(self
                .entries
                .iter()
                .find(|entry| entry.path == path)
                // An unmeasured row is measured from the object's header; the
                // fixture stands in for that with a known length.
                .map(|entry| match entry.size {
                    Some(_) => entry.clone(),
                    None => Entry::new(entry.path.clone(), 4_242),
                }))
        }

        async fn verify(&self, _path: &str) -> Result<()> {
            Ok(())
        }

        fn assurance(&self) -> Assurance {
            Assurance::Authenticated
        }

        fn inventory(&self) -> Inventory {
            // A mount is served out of a vault, and this fixture stands in for
            // one: the file list is a record rather than the backend's own
            // listing. Stated rather than defaulted, for the reason the trait
            // gives no default.
            Inventory::Recorded
        }
    }

    fn config(root: &str, read_ahead: u64) -> MountConfig {
        MountConfig {
            root: root.to_string(),
            attr_ttl: Duration::from_secs(1),
            dir_ttl: Duration::from_secs(300),
            read_ahead,
            acl: SessionACL::Owner,
            volume_name: None,
            no_modtime: false,
        }
    }

    fn state(source: Arc<Fixture>, root: &str, read_ahead: u64) -> MountState {
        MountState::new(
            source,
            config(root, read_ahead),
            Identity::capture(Path::new("."), false),
        )
    }

    fn mounted(paths: &[(&str, Option<u64>)]) -> (Arc<Fixture>, MountState) {
        let source = Fixture::new(paths);
        let state = state(Arc::clone(&source), "", 0);
        (source, state)
    }

    #[tokio::test]
    async fn the_root_is_a_directory_without_touching_the_source() {
        // A `getattr` of the mount root must be free: the kernel asks for it
        // constantly and nothing about it can change.
        let (source, state) = mounted(&[("a.txt", Some(3))]);
        let attr = state.getattr(INodeNo::ROOT).await.unwrap().unwrap();
        assert_eq!(attr.kind, fuser::FileType::Directory);
        assert_eq!(source.listings.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn a_name_that_exists_looks_up_to_a_file() {
        let (_, state) = mounted(&[("a.txt", Some(3))]);
        let attr = state.lookup(INodeNo::ROOT, "a.txt").await.unwrap().unwrap();
        assert_eq!(attr.kind, fuser::FileType::RegularFile);
        assert_eq!(attr.size, 3);
    }

    #[tokio::test]
    async fn a_name_that_does_not_exist_is_absent_rather_than_an_error() {
        // ENOENT is a normal answer every program handles; reporting it as a
        // failure would make a missing file look like broken hardware.
        let (_, state) = mounted(&[("a.txt", Some(3))]);
        assert!(
            state
                .lookup(INodeNo::ROOT, "b.txt")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_lookup_under_something_that_is_not_a_directory_finds_nothing() {
        let (_, state) = mounted(&[("a.txt", Some(3))]);
        let file = state.lookup(INodeNo::ROOT, "a.txt").await.unwrap().unwrap();
        assert!(state.lookup(file.ino, "anything").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_inferred_directory_looks_up_and_can_be_descended() {
        // Nothing stores `photos`; it exists because `photos/a.jpg` does, and the
        // mount has to be able to walk into it.
        let (_, state) = mounted(&[("photos/a.jpg", Some(9))]);
        let dir = state
            .lookup(INodeNo::ROOT, "photos")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dir.kind, fuser::FileType::Directory);
        let file = state.lookup(dir.ino, "a.jpg").await.unwrap().unwrap();
        assert_eq!(file.size, 9);
    }

    #[tokio::test]
    async fn getattr_of_a_directory_is_answered_from_its_parent() {
        // The only place a directory's existence is recorded: `stat`ing it
        // through the source would report that it is not there.
        let (_, state) = mounted(&[("photos/a.jpg", Some(9))]);
        let dir = state
            .lookup(INodeNo::ROOT, "photos")
            .await
            .unwrap()
            .unwrap();
        let again = state.getattr(dir.ino).await.unwrap().unwrap();
        assert_eq!(again.kind, fuser::FileType::Directory);
        assert_eq!(again.ino, dir.ino);
    }

    #[tokio::test]
    async fn an_unknown_inode_has_no_attributes() {
        let (_, state) = mounted(&[("a.txt", Some(1))]);
        assert!(state.getattr(INodeNo(99_999)).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_unmeasured_file_reports_its_real_size_not_a_zero() {
        // A rebuilt index row carries no size. Reporting zero would make every
        // reader see an empty file and succeed, which is the misreport with a
        // filesystem's authority behind it.
        let (_, state) = mounted(&[("rebuilt.bin", None)]);
        let attr = state
            .lookup(INodeNo::ROOT, "rebuilt.bin")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(attr.size, 4_242);
    }

    #[tokio::test]
    async fn a_read_asks_the_source_for_exactly_the_window() {
        // The call the whole format exists for: no whole-object path behind it.
        let (_, state) = mounted(&[("film.mkv", Some(1_000))]);
        let attr = state
            .lookup(INodeNo::ROOT, "film.mkv")
            .await
            .unwrap()
            .unwrap();
        let (handle, kind) = state.open(attr.ino).unwrap();
        assert_eq!(kind, Kind::File);

        let bytes = state.read(handle, 100, 16).await.unwrap().unwrap();
        let expected = Fixture::content("film.mkv", 1_000);
        assert_eq!(bytes.as_slice(), &expected[100..116]);
    }

    #[tokio::test]
    async fn a_read_past_the_end_is_short_rather_than_an_error() {
        // How end-of-file is signalled; failing here would make every reader
        // report an error at the end of every file.
        let (_, state) = mounted(&[("a.txt", Some(4))]);
        let attr = state.lookup(INodeNo::ROOT, "a.txt").await.unwrap().unwrap();
        let (handle, _) = state.open(attr.ino).unwrap();
        assert_eq!(state.read(handle, 2, 100).await.unwrap().unwrap().len(), 2);
        assert!(
            state
                .read(handle, 400, 100)
                .await
                .unwrap()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_read_on_a_handle_that_was_never_issued_finds_no_file() {
        let (_, state) = mounted(&[("a.txt", Some(4))]);
        assert!(state.read(FileHandle(77), 0, 4).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_released_handle_cannot_be_read_through() {
        let (_, state) = mounted(&[("a.txt", Some(4))]);
        let attr = state.lookup(INodeNo::ROOT, "a.txt").await.unwrap().unwrap();
        let (handle, _) = state.open(attr.ino).unwrap();
        assert!(state.release(handle));
        assert!(state.read(handle, 0, 4).await.unwrap().is_none());
        assert!(!state.release(handle), "a second release released nothing");
    }

    #[tokio::test]
    async fn opening_a_file_costs_no_provider_request() {
        // A media player opens a file to read its header and closes it again;
        // that must not be a round trip on its own.
        let (source, state) = mounted(&[("a.txt", Some(4))]);
        let attr = state.lookup(INodeNo::ROOT, "a.txt").await.unwrap().unwrap();
        let before = source.reads.load(Ordering::Relaxed);
        state.open(attr.ino).unwrap();
        assert_eq!(source.reads.load(Ordering::Relaxed), before);
    }

    #[tokio::test]
    async fn a_directory_listing_starts_with_dot_and_dotdot() {
        // The kernel does not synthesise them, and a directory without `..` is
        // one that `cd ..` cannot leave.
        let (_, state) = mounted(&[("a.txt", Some(1))]);
        let (handle, _) = state.opendir(INodeNo::ROOT).await.unwrap().unwrap();
        let entries = state.readdir(INodeNo::ROOT, handle, 0).unwrap();
        assert_eq!(entries[0].name, ".");
        assert_eq!(entries[1].name, "..");
        assert_eq!(entries[2].name, "a.txt");
    }

    #[tokio::test]
    async fn dotdot_of_the_mount_root_is_the_root_itself() {
        // A mount is its own top; nothing above it is addressable here.
        let (_, state) = mounted(&[("a.txt", Some(1))]);
        let (handle, _) = state.opendir(INodeNo::ROOT).await.unwrap().unwrap();
        let entries = state.readdir(INodeNo::ROOT, handle, 0).unwrap();
        assert_eq!(entries[1].ino, INodeNo::ROOT);
    }

    #[tokio::test]
    async fn readdir_resumes_from_an_offset_without_repeating_or_skipping() {
        // The property `opendir`'s snapshot exists for. A duplicate shows up as
        // `ls` printing a name twice; a skip shows up as a file that is not there.
        let (_, state) = mounted(&[("a.txt", Some(1)), ("b.txt", Some(1)), ("c.txt", Some(1))]);
        let (handle, _) = state.opendir(INodeNo::ROOT).await.unwrap().unwrap();

        let mut names = Vec::new();
        let mut offset = 0;
        loop {
            let batch = state.readdir(INodeNo::ROOT, handle, offset).unwrap();
            let Some(last) = batch.last() else { break };
            offset = last.next_offset;
            names.extend(batch.into_iter().map(|entry| entry.name));
        }
        assert_eq!(names, vec![".", "..", "a.txt", "b.txt", "c.txt"]);
    }

    #[tokio::test]
    async fn readdir_one_entry_at_a_time_yields_the_same_sequence() {
        // What a kernel with a small reply buffer does. Every offset has to be a
        // valid resumption point, not just the ones a full batch produced.
        let (_, state) = mounted(&[("a.txt", Some(1)), ("b.txt", Some(1))]);
        let (handle, _) = state.opendir(INodeNo::ROOT).await.unwrap().unwrap();

        let mut names = Vec::new();
        for offset in 0..4 {
            let batch = state.readdir(INodeNo::ROOT, handle, offset).unwrap();
            names.push(batch.first().map(|entry| entry.name.clone()));
        }
        assert_eq!(
            names,
            vec![
                Some(".".into()),
                Some("..".into()),
                Some("a.txt".into()),
                Some("b.txt".into())
            ]
        );
        // Past the end: an empty batch, which is how the kernel learns to stop.
        assert!(state.readdir(INodeNo::ROOT, handle, 4).unwrap().is_empty());
    }

    #[tokio::test]
    async fn readdir_on_a_handle_that_is_not_a_directory_finds_nothing() {
        let (_, state) = mounted(&[("a.txt", Some(1))]);
        let attr = state.lookup(INodeNo::ROOT, "a.txt").await.unwrap().unwrap();
        let (file, _) = state.open(attr.ino).unwrap();
        assert!(state.readdir(INodeNo::ROOT, file, 0).is_none());
    }

    #[tokio::test]
    async fn opening_a_file_as_a_directory_reports_what_it_really_is() {
        // The caller turns this into EISDIR/ENOTDIR; the state's job is to say
        // which, rather than to invent a handle.
        let (_, state) = mounted(&[("a.txt", Some(1))]);
        let attr = state.lookup(INodeNo::ROOT, "a.txt").await.unwrap().unwrap();
        let (_, kind) = state.opendir(attr.ino).await.unwrap().unwrap();
        assert_eq!(kind, Kind::File);
    }

    #[tokio::test]
    async fn a_directory_listing_is_served_from_cache_within_its_ttl() {
        // What `--dir-cache-time` buys: browsing does not re-walk the index.
        let (source, state) = mounted(&[("a.txt", Some(1))]);
        state.lookup(INodeNo::ROOT, "a.txt").await.unwrap();
        let after_first = source.listings.load(Ordering::Relaxed);
        assert_eq!(after_first, 1);

        state.lookup(INodeNo::ROOT, "a.txt").await.unwrap();
        state.opendir(INodeNo::ROOT).await.unwrap();
        assert_eq!(source.listings.load(Ordering::Relaxed), after_first);
    }

    #[tokio::test]
    async fn an_expired_listing_is_read_again() {
        // The other half of the same flag: a file another machine added has to
        // appear without a remount.
        let source = Fixture::new(&[("a.txt", Some(1))]);
        let mut config = config("", 0);
        config.dir_ttl = Duration::ZERO;
        let state = MountState::new(
            Arc::clone(&source) as Arc<dyn Source>,
            config,
            Identity::capture(Path::new("."), false),
        );

        state.lookup(INodeNo::ROOT, "a.txt").await.unwrap();
        state.lookup(INodeNo::ROOT, "a.txt").await.unwrap();
        assert_eq!(source.listings.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn statfs_totals_the_whole_mounted_subtree() {
        let (_, state) = mounted(&[
            ("docs/a.txt", Some(10)),
            ("photos/2024/a.jpg", Some(100)),
            ("top.bin", Some(1)),
        ]);
        let totals = state.statfs().await.unwrap();
        assert_eq!(totals.bytes, Some(111));
        assert_eq!(totals.objects, 3);
    }

    #[tokio::test]
    async fn statfs_reports_an_unknown_total_as_unknown() {
        // Not as the sum of the measured part: a plausible wrong number is worse
        // than an obviously absent one.
        let (_, state) = mounted(&[("a.txt", Some(10)), ("b.bin", None)]);
        let totals = state.statfs().await.unwrap();
        assert_eq!(totals.bytes, None);
        assert_eq!(totals.objects, 2);
    }

    #[tokio::test]
    async fn a_subtree_mount_cannot_address_anything_above_its_root() {
        // Not because a check refuses it — because no path outside the prefix can
        // be built from what the kernel supplies.
        let source = Fixture::new(&[("photos/2024/a.jpg", Some(1)), ("secret.txt", Some(1))]);
        let state = state(Arc::clone(&source), "photos", 0);

        let (handle, _) = state.opendir(INodeNo::ROOT).await.unwrap().unwrap();
        let names: Vec<String> = state
            .readdir(INodeNo::ROOT, handle, 0)
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert_eq!(names, vec![".", "..", "2024"]);
        assert!(
            state
                .lookup(INodeNo::ROOT, "secret.txt")
                .await
                .unwrap()
                .is_none(),
            "a file outside the mounted subtree was reachable"
        );
    }

    #[tokio::test]
    async fn read_ahead_is_scheduled_once_per_window_not_once_per_read() {
        // The watermark's whole purpose: a 4 KiB-stepping reader must not
        // schedule a read-ahead 256 times for the same megabyte.
        let source = Fixture::new(&[("film.mkv", Some(100_000))]);
        let state = state(Arc::clone(&source), "", 10_000);
        let attr = state
            .lookup(INodeNo::ROOT, "film.mkv")
            .await
            .unwrap()
            .unwrap();
        let (handle, _) = state.open(attr.ino).unwrap();

        for offset in (0..8_000).step_by(1_000) {
            state.read(handle, offset, 1_000).await.unwrap();
        }
        // Spawned, so let the runtime run them.
        tokio::task::yield_now().await;
        let scheduled = source.prefetches.load(Ordering::Relaxed);
        assert!(
            scheduled <= 2,
            "eight reads inside one read-ahead window scheduled {scheduled} fetches"
        );
        assert!(scheduled >= 1, "no read-ahead was scheduled at all");
    }

    #[tokio::test]
    async fn read_ahead_is_off_when_the_buffer_is_disabled() {
        // `--buffer-size 0` means allocate nothing, and must therefore fetch
        // nothing speculatively.
        let source = Fixture::new(&[("film.mkv", Some(100_000))]);
        let state = state(Arc::clone(&source), "", 0);
        let attr = state
            .lookup(INodeNo::ROOT, "film.mkv")
            .await
            .unwrap()
            .unwrap();
        let (handle, _) = state.open(attr.ino).unwrap();
        state.read(handle, 0, 1_000).await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(source.prefetches.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn clearing_the_state_drops_the_cached_listings() {
        // Listings hold plaintext filenames; the window in which they are
        // resident should be the mount's, not the process's.
        let (source, state) = mounted(&[("a.txt", Some(1))]);
        state.lookup(INodeNo::ROOT, "a.txt").await.unwrap();
        state.clear();
        state.lookup(INodeNo::ROOT, "a.txt").await.unwrap();
        assert_eq!(source.listings.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn forgetting_an_inode_does_not_break_a_later_lookup() {
        // The kernel is free to forget anything at any time; the mount has to be
        // able to hand the path back afterwards.
        let (_, state) = mounted(&[("a.txt", Some(1))]);
        let attr = state.lookup(INodeNo::ROOT, "a.txt").await.unwrap().unwrap();
        state.forget(attr.ino, 1);
        let again = state.lookup(INodeNo::ROOT, "a.txt").await.unwrap().unwrap();
        assert_eq!(again.ino, attr.ino);
    }

    /// The same operations against a **real** source over a **real** backend.
    ///
    /// The fixture above is a stand-in for the parts of a source the mount does
    /// not care which it got, and it is the right tool for the offset arithmetic
    /// and the cache behaviour — but it is written by the same hand as the code
    /// it checks, and a shared misunderstanding would pass both. These drive
    /// [`PlainSource`](crate::source::plain::PlainSource) over
    /// [`LocalFs`](dctl_store::LocalFs), which is the implementation `dctl ls`
    /// and `dctl cat` use for a `local:` remote: real directory paging, real
    /// ranged reads, real `stat`.
    ///
    /// The sealed source is not driven here because it is already driven end to
    /// end, against a real vault with a metered backend, in
    /// [`crate::source::vault`] — including the property this mount depends on
    /// most, that a window transfers the window and not the object.
    mod over_a_real_backend {
        use super::*;
        use crate::source::plain::PlainSource;
        use dctl_store::{Backend, LocalFs};
        use tempfile::TempDir;

        /// A directory of real files, served through the real plain source.
        fn served(files: &[(&str, &[u8])]) -> (TempDir, MountState) {
            let root = TempDir::new().expect("a temporary directory");
            for (path, bytes) in files {
                let full = root.path().join(path);
                if let Some(parent) = full.parent() {
                    std::fs::create_dir_all(parent).expect("a parent directory");
                }
                std::fs::write(&full, bytes).expect("a file");
            }
            let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(root.path()));
            let source: Arc<dyn Source> = Arc::new(PlainSource::new(backend));
            let state = MountState::new(
                source,
                config("", 0),
                Identity::capture(Path::new("."), false),
            );
            (root, state)
        }

        #[tokio::test]
        async fn a_tree_of_real_files_is_walked_the_way_a_shell_walks_it() {
            // The whole read path in one test: opendir, readdir, lookup into a
            // subdirectory, and a read of what is found there.
            let (_root, state) = served(&[
                ("top.txt", b"top"),
                ("photos/2024/note.txt", b"hello from the vault"),
                ("photos/big.bin", &[7u8; 4096]),
            ]);

            let (root_dir, _) = state.opendir(INodeNo::ROOT).await.unwrap().unwrap();
            let names: Vec<String> = state
                .readdir(INodeNo::ROOT, root_dir, 0)
                .unwrap()
                .into_iter()
                .map(|entry| entry.name)
                .collect();
            assert_eq!(names, vec![".", "..", "photos", "top.txt"]);

            let photos = state
                .lookup(INodeNo::ROOT, "photos")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(photos.kind, fuser::FileType::Directory);

            let year = state.lookup(photos.ino, "2024").await.unwrap().unwrap();
            let note = state.lookup(year.ino, "note.txt").await.unwrap().unwrap();
            assert_eq!(note.size, 20);

            let (handle, kind) = state.open(note.ino).unwrap();
            assert_eq!(kind, Kind::File);
            let bytes = state.read(handle, 0, 64).await.unwrap().unwrap();
            assert_eq!(bytes.as_slice(), b"hello from the vault");
            assert!(state.release(handle));
        }

        #[tokio::test]
        async fn a_window_of_a_real_file_is_exactly_the_window() {
            // What a player seeking into a film asks for, against bytes that are
            // really on disk rather than a fixture's arithmetic.
            let content: Vec<u8> = (0..4096u32).map(|byte| byte as u8).collect();
            let (_root, state) = served(&[("film.bin", &content)]);

            let attr = state
                .lookup(INodeNo::ROOT, "film.bin")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(attr.size, 4096);
            let (handle, _) = state.open(attr.ino).unwrap();

            for (offset, size) in [(0u64, 16u32), (1_000, 100), (4_090, 6)] {
                let window = state.read(handle, offset, size).await.unwrap().unwrap();
                let from = usize::try_from(offset).unwrap();
                let to = from + usize::try_from(size).unwrap();
                assert_eq!(
                    window.as_slice(),
                    &content[from..to],
                    "window at {offset}+{size}"
                );
            }

            // Past the end is short rather than an error — how EOF is signalled.
            assert!(
                state
                    .read(handle, 5_000, 16)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_empty()
            );
        }

        #[tokio::test]
        async fn statfs_counts_what_is_really_there() {
            let (_root, state) = served(&[("a.bin", &[0u8; 100]), ("d/b.bin", &[0u8; 200])]);
            let totals = state.statfs().await.unwrap();
            assert_eq!(totals.bytes, Some(300));
            assert_eq!(totals.objects, 2);
        }

        #[tokio::test]
        async fn a_name_that_is_not_there_is_absent_and_not_an_error() {
            let (_root, state) = served(&[("a.bin", b"x")]);
            assert!(
                state
                    .lookup(INodeNo::ROOT, "b.bin")
                    .await
                    .unwrap()
                    .is_none()
            );
        }

        #[tokio::test]
        async fn an_empty_directory_does_not_exist_because_nothing_implies_it() {
            // The consequence of inferring directories from paths, visible
            // through the mount: `mkdir` on a store makes nothing, so a
            // directory with no objects under it is not there to be found.
            let (root, state) = served(&[("a.bin", b"x")]);
            std::fs::create_dir(root.path().join("empty")).expect("a real directory");

            let (handle, _) = state.opendir(INodeNo::ROOT).await.unwrap().unwrap();
            let names: Vec<String> = state
                .readdir(INodeNo::ROOT, handle, 0)
                .unwrap()
                .into_iter()
                .map(|entry| entry.name)
                .collect();
            assert_eq!(names, vec![".", "..", "a.bin"]);
        }
    }
}
