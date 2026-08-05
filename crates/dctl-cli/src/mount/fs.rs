//! The kernel-facing half: `fuser`'s callbacks, and nothing else.
//!
//! Every method here does the same three things — translate fuser's types into
//! DCTL's, call one method on [`MountState`], turn the answer into a reply — and
//! that thinness is the design. The interesting decisions (what a directory is,
//! which chunks a window covers, when a listing is stale) live in [`super::state`]
//! and [`super::tree`], where they can be tested without a kernel. What is left
//! here is the part that cannot be tested without one, and the less of it there
//! is the better.
//!
//! ## Nothing blocks the session loop
//!
//! `fuser` reads requests on one thread and dispatches them there. Every callback
//! that can touch a provider therefore hands its work — *and its reply* — to the
//! Tokio runtime and returns immediately, so the loop is free to accept the next
//! request. That is what lets a directory listing complete while a
//! fifty-gigabyte read is in flight, and it is the concurrency `PLAN.md` §15 asks
//! for ("multithreaded so parallel opens/seeks don't serialize") on a session
//! loop that is single-threaded on macOS by `fuser`'s own constraint.
//!
//! A reply is `Send` precisely so it can be moved like this, and a reply dropped
//! without being sent answers `EIO` — so even a task that ended unexpectedly
//! cannot leave a caller blocked forever.
//!
//! ## Every path out of a callback is a reply
//!
//! There is no `?` in this file and no early return that does not send something.
//! A callback that returned without replying would hang the calling process
//! rather than failing it, and on macOS a hung process holding a mount takes
//! Finder with it. The shape that enforces it is the same everywhere: match, and
//! reply on both arms.

use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use fuser::{
    AccessFlags, BsdFileFlags, CopyFileRangeFlags, Errno, FileHandle, Filesystem, FopenFlags,
    Generation, INodeNo, KernelConfig, LockOwner, OpenAccMode, OpenFlags, RenameFlags, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs,
    ReplyWrite, ReplyXattr, Request, TimeOrNow, WriteFlags,
};

use crate::constants::{MOUNT_BLOCK_SIZE, MOUNT_MAX_NAME_LEN};
use crate::platform::path;
use crate::source::Source;

use super::attr::{self, Identity};
use super::config::MountConfig;
use super::errno;
use super::inode::Kind;
use super::refuse;
use super::state::MountState;

/// Generation number reported with every inode.
///
/// Zero, and it stays zero because inode numbers are never recycled
/// ([`super::inode`]). A generation exists so that a filesystem which *does*
/// recycle a number can tell an NFS client that the thing behind it has changed;
/// a filesystem that allocates monotonically has nothing to distinguish and
/// would be inventing a value.
const GENERATION: Generation = Generation(0);

/// A vault, presented to the kernel.
pub struct VaultFs {
    state: Arc<MountState>,
    /// Where the asynchronous work runs.
    ///
    /// A handle rather than a runtime: the process already has one, built in
    /// `main`, and a second would mean a second thread pool and a second set of
    /// provider connection pools serving the same vault.
    runtime: tokio::runtime::Handle,
}

impl VaultFs {
    /// Build the filesystem for `source`, mounted per `config`.
    ///
    /// `mountpoint` is used only to establish who the mount's files belong to —
    /// see [`Identity::capture`] — and is not retained.
    #[must_use]
    pub fn new(
        source: Arc<dyn Source>,
        config: MountConfig,
        mountpoint: &Path,
        runtime: tokio::runtime::Handle,
        audit: Arc<super::audit::MountAudit>,
    ) -> Self {
        let identity = Identity::capture(mountpoint, config.no_modtime);
        Self {
            state: Arc::new(MountState::new(source, config, identity, audit)),
            runtime,
        }
    }

    /// Run `work` on the runtime, with its own handle to the mount's state.
    ///
    /// The one place a callback becomes asynchronous. Written as a closure over a
    /// cloned `Arc` rather than as a borrow because the task outlives the
    /// callback by design — that is the whole point of not blocking the session
    /// loop.
    fn spawn<F, Fut>(&self, work: F)
    where
        F: FnOnce(Arc<MountState>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let state = Arc::clone(&self.state);
        self.runtime.spawn(async move { work(state).await });
    }
}

impl Filesystem for VaultFs {
    /// Negotiate with the kernel before the first request.
    ///
    /// The only thing tuned here is read-ahead, and it is tuned from
    /// `--buffer-size` because that is what the flag means on the kernel's side
    /// of the boundary: how much the kernel may ask for beyond what a program
    /// requested. `PLAN.md` §15 names it as one of the per-platform knobs, and it
    /// composes with — rather than replaces — the mount's own read-ahead into the
    /// decrypted-chunk cache: the kernel asking for more per request means fewer,
    /// larger reads, and the chunk warming means the ones it does make are
    /// already covered.
    ///
    /// A kernel that will not grant the requested window answers with the largest
    /// it will take, which is used instead. Refusing to mount over it would be
    /// absurd — the mount works either way, only less eagerly — but silently
    /// asking for something else would leave a user tuning a dial that is not
    /// connected, so the granted value is logged.
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> std::io::Result<()> {
        let wanted = u32::try_from(self.state.config().read_ahead).unwrap_or(u32::MAX);
        if wanted > 0 {
            let granted = match config.set_max_readahead(wanted) {
                Ok(_) => wanted,
                // The error carries the nearest value that would succeed. Asking
                // for exactly that cannot fail for the same reason.
                Err(nearest) => {
                    let _ = config.set_max_readahead(nearest);
                    nearest
                }
            };
            if granted != wanted {
                tracing::debug!(
                    requested = wanted,
                    granted,
                    "the kernel capped the read-ahead window"
                );
            }
        }

        tracing::debug!(
            abi = %config.kernel_abi(),
            read_ahead = self.state.config().read_ahead,
            "filesystem initialised"
        );
        // Once per mount, so an operator can see what this filesystem will refuse
        // before anything tries — rather than working it out from a stream of
        // EROFS records after a backup tool has been pointed at the mountpoint.
        tracing::debug!(
            refused = ?refuse::REFUSED,
            errno = refuse::READ_ONLY.code(),
            "read-only: every operation that would change something is refused"
        );
        Ok(())
    }

    /// The session has ended. Drop what was cached.
    ///
    /// The decrypted chunks and the vault's keys are not here — they belong to
    /// the source and go when the process's last reference to it does — but the
    /// directory listings are, and they hold plaintext filenames. Clearing them
    /// when the mount ends rather than when the process exits keeps the window in
    /// which a name is resident as short as the mount itself.
    fn destroy(&mut self) {
        self.state.clear();
        tracing::debug!("filesystem destroyed; cached listings dropped");
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Some(name) = logical_name(name) else {
            // A vault path is NFC UTF-8 (`docs/FORMAT.md` §5), so a name that is
            // not representable as one cannot name anything stored. ENOENT is
            // the truth: there is no such entry.
            reply.error(Errno::ENOENT);
            return;
        };

        let attr_ttl = self.state.config().attr_ttl;
        self.spawn(move |state| async move {
            match state.lookup(parent, &name).await {
                Ok(Some(attr)) => reply.entry(&attr_ttl, &attr, GENERATION),
                Ok(None) => reply.error(Errno::ENOENT),
                Err(error) => reply.error(errno::from_error("lookup", &name, &error)),
            }
        });
    }

    /// Release `count` of the kernel's references to an inode.
    ///
    /// Implemented rather than ignored, which is the difference between a mount
    /// whose memory is bounded by what is *in use* and one bounded by what has
    /// ever been *walked past*. A `find` over a ten-million-object vault sends
    /// ten million of these, and a filesystem that dropped them on the floor
    /// would retain every path for the life of the mount.
    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        self.state.forget(ino, nlookup);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let attr_ttl = self.state.config().attr_ttl;
        self.spawn(move |state| async move {
            match state.getattr(ino).await {
                Ok(Some(attr)) => reply.attr(&attr_ttl, &attr),
                Ok(None) => reply.error(Errno::ENOENT),
                Err(error) => reply.error(errno::from_error("getattr", "", &error)),
            }
        });
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        // Refused here rather than at the first `write`, because this is where a
        // program can still act on it: an editor told "read-only file system" at
        // open offers to save elsewhere, while one allowed to open the file
        // buffers the user's work and finds out at save time.
        if flags.acc_mode() != OpenAccMode::O_RDONLY {
            refuse::open_for_write(reply);
            return;
        }

        match self.state.open(ino) {
            Some((handle, Kind::File)) => {
                // No `FOPEN_KEEP_CACHE`: the kernel is left free to drop this
                // file's cached pages when it is next opened, which is what
                // makes a file rewritten from another machine readable without a
                // remount. Keeping the cache would be faster and would serve
                // stale bytes.
                reply.opened(handle, FopenFlags::empty());
            }
            // A directory opened as a file. EISDIR is what a local filesystem
            // answers, and what every caller expects.
            Some((_, Kind::Directory)) => reply.error(Errno::EISDIR),
            None => reply.error(Errno::ENOENT),
        }
    }

    /// Read a byte window.
    ///
    /// **The call this filesystem exists to make fast.** It goes to
    /// [`MountState::read`] and from there to the ranged read: only the chunks
    /// covering `[offset, offset + size)` are fetched and authenticated
    /// (`docs/FORMAT.md` §3), so seeking to 45:00 in a fifty-gigabyte film costs
    /// the covering chunks and nothing else. There is no whole-object path behind
    /// this at any size.
    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        self.spawn(move |state| async move {
            match state.read(fh, offset, size).await {
                // Fewer bytes than asked for is how end-of-file is reported, and
                // is not an error: the kernel treats a short reply as EOF.
                Ok(Some(bytes)) => reply.data(&bytes),
                // A handle this mount never issued, or one already released.
                Ok(None) => reply.error(Errno::EBADF),
                // Includes authentication failure, which returns *no bytes*.
                // There is no mode in which this hands a program data that did
                // not verify.
                Err(error) => reply.error(errno::from_error("read", "", &error)),
            }
        });
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        if self.state.release(fh) {
            reply.ok();
        } else {
            // Reporting success for a release that released nothing would hide a
            // handle leak, and a leak in this table is the one that eventually
            // matters.
            reply.error(Errno::EBADF);
        }
    }

    /// Open a directory, snapshotting its contents for the `readdir` calls that
    /// follow.
    ///
    /// The snapshot is what makes `readdir` resumable: the kernel reads a
    /// directory in several calls and expects the sequence not to shift between
    /// them, which a filesystem that re-listed on every call cannot promise.
    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        self.spawn(move |state| async move {
            match state.opendir(ino).await {
                Ok(Some((handle, Kind::Directory))) => {
                    reply.opened(handle, FopenFlags::empty());
                }
                // A file opened as a directory, which is what `cd` into one does.
                Ok(Some((_, Kind::File))) => reply.error(Errno::ENOTDIR),
                Ok(None) => reply.error(Errno::ENOENT),
                Err(error) => reply.error(errno::from_error("opendir", "", &error)),
            }
        });
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let Some(entries) = self.state.readdir(ino, fh, offset) else {
            reply.error(Errno::EBADF);
            return;
        };

        for entry in entries {
            // `add` answers true when the kernel's buffer is full. Everything
            // after that has to be dropped, not truncated silently — the kernel
            // asks again from `next_offset` and receives it then.
            if reply.add(
                entry.ino,
                entry.next_offset,
                attr::file_type(entry.kind),
                &entry.name,
            ) {
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        if self.state.release(fh) {
            reply.ok();
        } else {
            reply.error(Errno::EBADF);
        }
    }

    /// Filesystem statistics, as `df` reads them.
    ///
    /// `bfree` and `bavail` are zero, and that is the one number here that is
    /// certainly right: nothing can be written to this filesystem, so there is no
    /// space available on it. The total is the size of what is under the mount
    /// root, which the mount computes for its own listings anyway — and is
    /// reported as zero when any object beneath the root has never been measured,
    /// because a partial total presented as a total is a plausible wrong number
    /// and a zero is a visible absent one.
    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        self.spawn(move |state| async move {
            match state.statfs().await {
                Ok(totals) => {
                    let block = u64::from(MOUNT_BLOCK_SIZE);
                    let blocks = totals
                        .bytes
                        .map_or(0, |bytes| bytes.saturating_add(block - 1) / block);
                    reply.statfs(
                        blocks,
                        // Free, and available to an unprivileged caller. Both
                        // zero: a read-only filesystem has no space in any sense
                        // a caller can use.
                        0,
                        0,
                        totals.objects,
                        // Free inodes: none, for the same reason.
                        0,
                        MOUNT_BLOCK_SIZE,
                        MOUNT_MAX_NAME_LEN,
                        MOUNT_BLOCK_SIZE,
                    );
                }
                Err(error) => reply.error(errno::from_error("statfs", "", &error)),
            }
        });
    }

    /// Answer `access(2)`.
    ///
    /// Implemented rather than left to the default, and the reason is the write
    /// bit. The default replies `ENOSYS`, which tells the kernel to decide for
    /// itself — and without `default_permissions` it decides *yes*. A program
    /// that asks `access(path, W_OK)` before writing would be told it may, and
    /// would then meet `EROFS` at the write. Answering here means the refusal
    /// arrives where the program asked the question.
    fn access(&self, _req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        if mask.contains(AccessFlags::W_OK) {
            refuse::empty("access(write)", "", reply);
            return;
        }
        // Execute is refused for files and granted for directories, where the bit
        // means *search* rather than *run*: without it nothing could traverse the
        // mount at all. It matches the permissions reported by `getattr`, which is
        // the property that matters — an `access` that disagreed with the mode
        // bits would make a shell and a `stat` reach different conclusions about
        // the same file.
        self.spawn(move |state| async move {
            match state.getattr(ino).await {
                Ok(Some(attr)) => {
                    let executable = attr.kind == fuser::FileType::Directory;
                    if mask.contains(AccessFlags::X_OK) && !executable {
                        reply.error(Errno::EACCES);
                    } else {
                        reply.ok();
                    }
                }
                Ok(None) => reply.error(Errno::ENOENT),
                Err(error) => reply.error(errno::from_error("access", "", &error)),
            }
        });
    }

    /// Extended attributes: there are none, and saying so is not the same as
    /// saying the operation is unsupported.
    ///
    /// A vault records no extended attributes, so every name is absent. Replying
    /// with the platform's "no such attribute" errno is the accurate answer and
    /// the one every caller handles; `ENOSYS` would instead tell the kernel this
    /// filesystem has no xattr support at all, which on macOS — where Finder and
    /// Spotlight query attributes on everything they see — produces a stream of
    /// confusing failures rather than a clean "not set".
    fn getxattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _name: &OsStr,
        _size: u32,
        reply: ReplyXattr,
    ) {
        reply.error(Errno::NO_XATTR);
    }

    /// List extended attributes: an empty list, which is the truth.
    fn listxattr(&self, _req: &Request, _ino: INodeNo, size: u32, reply: ReplyXattr) {
        if size == 0 {
            reply.size(0);
        } else {
            reply.data(&[]);
        }
    }

    // ─── The read-only wall ─────────────────────────────────────────────────
    //
    // Every operation below would change something. Each is refused with EROFS,
    // individually and every time it is attempted — see `super::refuse` for why
    // that errno, and why a filesystem that accepted a write and dropped it would
    // be the worst failure this mount could have. The kernel's own `ro` flag
    // catches most of these first; these are what catches the rest.

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _offset: u64,
        _data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        refuse::write(reply);
    }

    /// `chmod`, `chown`, `utimes` — and `truncate`, which is how a program
    /// empties a file before rewriting it.
    fn setattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        _size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        refuse::attr("setattr", reply);
    }

    fn create(
        &self,
        _req: &Request,
        _parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        refuse::create(name, reply);
    }

    fn mknod(
        &self,
        _req: &Request,
        _parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        refuse::entry("mknod", name, reply);
    }

    /// A vault cannot store an empty directory — nothing implies one — so this
    /// would be refused even if the mount were writable.
    fn mkdir(
        &self,
        _req: &Request,
        _parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        refuse::entry("mkdir", name, reply);
    }

    fn unlink(&self, _req: &Request, _parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        refuse::empty("unlink", &name.to_string_lossy(), reply);
    }

    fn rmdir(&self, _req: &Request, _parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        refuse::empty("rmdir", &name.to_string_lossy(), reply);
    }

    fn symlink(
        &self,
        _req: &Request,
        _parent: INodeNo,
        link_name: &OsStr,
        _target: &Path,
        reply: ReplyEntry,
    ) {
        refuse::entry("symlink", link_name, reply);
    }

    fn link(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        refuse::entry("link", newname, reply);
    }

    fn rename(
        &self,
        _req: &Request,
        _parent: INodeNo,
        name: &OsStr,
        _newparent: INodeNo,
        _newname: &OsStr,
        _flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        refuse::empty("rename", &name.to_string_lossy(), reply);
    }

    fn setxattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        name: &OsStr,
        _value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        refuse::empty("setxattr", &name.to_string_lossy(), reply);
    }

    fn removexattr(&self, _req: &Request, _ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        refuse::empty("removexattr", &name.to_string_lossy(), reply);
    }

    fn fallocate(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _offset: u64,
        _length: u64,
        _mode: i32,
        reply: ReplyEmpty,
    ) {
        refuse::empty("fallocate", "", reply);
    }

    /// Nothing is buffered, so there is nothing to flush — but this is on the
    /// wall rather than answering `ok` because a successful `fsync` is a promise
    /// that written data is durable, and no data was written. Refusing keeps the
    /// promise honest for a caller that reached here after a refused `write`.
    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        refuse::empty("fsync", "", reply);
    }

    fn fsyncdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        refuse::empty("fsyncdir", "", reply);
    }

    /// `copy_file_range(2)`: a server-side copy, which writes to a destination.
    ///
    /// Easy to miss because it reads like a read — the interesting half of it is
    /// the *out* file, and that is a write. The default would answer `ENOSYS`,
    /// which makes the kernel fall back to read-then-write; the read half would
    /// then succeed against this mount and the write half would fail somewhere
    /// else, which is a worse story than refusing here.
    fn copy_file_range(
        &self,
        _req: &Request,
        _ino_in: INodeNo,
        _fh_in: FileHandle,
        _offset_in: u64,
        _ino_out: INodeNo,
        _fh_out: FileHandle,
        _offset_out: u64,
        _len: u64,
        _flags: CopyFileRangeFlags,
        reply: ReplyWrite,
    ) {
        refuse::write_range(reply);
    }

    /// macOS only: rename the volume.
    ///
    /// On the wall because it changes what the filesystem presents, and because
    /// `--volname` is where a volume name is decided — a mount whose name could
    /// be changed from Finder would have two sources for one setting, and the
    /// flag would silently stop describing the mount.
    #[cfg(target_os = "macos")]
    fn setvolname(&self, _req: &Request, name: &OsStr, reply: ReplyEmpty) {
        refuse::empty("setvolname", &name.to_string_lossy(), reply);
    }

    /// macOS only: `exchangedata(2)`, which swaps the contents of two files.
    ///
    /// A mutation of both, and one that predates `rename` on HFS+ — still used by
    /// some macOS applications to save a document atomically, which is exactly the
    /// path that must meet a refusal rather than a partial success.
    #[cfg(target_os = "macos")]
    fn exchange(
        &self,
        _req: &Request,
        _parent: INodeNo,
        name: &OsStr,
        _newparent: INodeNo,
        _newname: &OsStr,
        _options: u64,
        reply: ReplyEmpty,
    ) {
        refuse::empty("exchange", &name.to_string_lossy(), reply);
    }

    /// `close(2)` on a descriptor, which happens on every open file whether it
    /// was written or not.
    ///
    /// The one member of this family that answers `ok`. It is not a mutation: it
    /// is the kernel's opportunity for a filesystem to report a deferred write
    /// error, and there are no deferred writes here. Refusing would make every
    /// `close` of a file read through this mount fail, which would break every
    /// program that checks the return value of `close` — the default `ENOSYS`
    /// would do the same.
    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }
}

/// The vault-shaped spelling of a name the kernel supplied.
///
/// Two conversions, both necessary. A vault path is UTF-8, so a name that is not
/// is not a name anything stored can have — and the caller reports that as
/// `ENOENT`, which is the truth rather than an error. It is also **NFC**
/// (`docs/FORMAT.md` §5), and macOS is the reason that matters: the same
/// filename typed into a terminal and produced by Finder can differ by
/// normalisation alone, and comparing the two byte-wise would make a file
/// visible in a listing and unopenable by name.
fn logical_name(name: &OsStr) -> Option<String> {
    Some(path::normalize_unicode(name.to_str()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_the_kernel_supplies_is_normalised_before_it_is_looked_up() {
        // macOS is the reason: the same name typed into a terminal and produced
        // by Finder can differ by normalisation alone, and a byte comparison
        // would make a file visible in a listing and unopenable by name.
        let decomposed = OsStr::new("cafe\u{301}.txt");
        let composed = OsStr::new("caf\u{e9}.txt");
        assert_eq!(logical_name(decomposed), logical_name(composed));
        assert_eq!(logical_name(composed).as_deref(), Some("caf\u{e9}.txt"));
    }

    #[test]
    fn a_name_that_is_not_utf8_names_nothing() {
        // A vault path is UTF-8, so such a name cannot address anything stored;
        // the caller reports ENOENT, which is the truth.
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(logical_name(OsStr::from_bytes(&[0xff, 0xfe])), None);
    }

    #[test]
    fn the_generation_number_is_fixed_because_inodes_are_never_recycled() {
        // A generation distinguishes two lives of one inode number. Numbers here
        // are allocated monotonically, so there is only ever one life.
        assert_eq!(GENERATION, Generation(0));
    }
}
