//! The `stat` a program sees when it looks at something in the mount.
//!
//! A vault records three things about a file: its plaintext length, its
//! modification time and its content hash. A POSIX `struct stat` has fifteen
//! fields. Every one of the twelve the vault has nothing to say about is filled
//! in here, once, and the value chosen for each is a decision with consequences —
//! a permission bit invites an editor to open a file for writing, a link count
//! changes how `find` walks a tree, a block count is what `du` adds up.
//!
//! So the fabricated fields are constants in [`crate::constants`] with the
//! reasoning attached, and this module is the single place they are assembled.
//! The alternative — a `FileAttr` literal at each of the three callbacks that
//! needs one — is how a mount comes to report one permission set through
//! `getattr` and another through `lookup`, which is a real and very confusing
//! bug.
//!
//! ## Ownership is the process's, not the vault's
//!
//! Every file in the mount is owned by the user running it. A vault stores no
//! uid or gid — deliberately, since a uid is metadata about a machine and
//! [the plan](https://doc.dctl.sh/project/plan) §2 keeps that out of the stored
//! form — so there is nothing to report but the truth about who can read this
//! mount. That truth is also the
//! useful one: with the default `SessionACL::Owner` nobody else can talk to the
//! filesystem at all.
//!
//! ## Times, and the one flag that changes them
//!
//! `mtime` is the vault's recorded modification time where there is one. Where
//! there is not — a record written before times were captured — the mount time
//! is used, because a filesystem cannot decline to answer and the epoch would
//! tell a `sync` that every file was last modified in 1970. `--no-modtime` makes
//! the mount time the answer for everything, which is what a user asking not to
//! leak timestamps through the mount wants.
//!
//! `atime` follows `mtime` rather than tracking reads: the mount is read-only,
//! so an access time it updated could never be stored. `ctime` and `crtime`
//! likewise — a vault records no inode-change time and no birth time, and
//! inventing distinct values would be inventing history.

use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{FileAttr, FileType, INodeNo};

use crate::constants::{
    MOUNT_BLOCK_SIZE, MOUNT_DIRECTORY_APPARENT_SIZE, MOUNT_DIRECTORY_LINK_COUNT,
    MOUNT_DIRECTORY_MODE, MOUNT_FILE_LINK_COUNT, MOUNT_FILE_MODE, MOUNT_STAT_BLOCK_SIZE,
};

use super::inode::Kind;

/// The parts of a `stat` that are the same for every file in one mount.
///
/// Resolved once when the filesystem is built, so a callback does not call
/// `getuid` and read the clock on a path the kernel takes thousands of times a
/// second.
#[derive(Clone, Copy, Debug)]
pub struct Identity {
    /// User the mount's files are attributed to.
    uid: u32,
    /// Group the mount's files are attributed to.
    gid: u32,
    /// When the mount was attached — the fallback timestamp, and the only
    /// timestamp under `--no-modtime`.
    mounted_at: SystemTime,
    /// Whether recorded modification times are suppressed.
    no_modtime: bool,
}

impl Identity {
    /// Capture who this mount's files belong to, and when it was attached.
    ///
    /// The identity is **probed rather than asked for**, and that is a
    /// consequence of the crate being `#![forbid(unsafe_code)]`: `geteuid` is a
    /// C function and there is no safe binding for it in this dependency set. The
    /// probe answers a slightly different question — *what does a file this
    /// process creates belong to* — and it is the better question, because it is
    /// the one `ls -l` inside the mount is really asking. A `geteuid` that
    /// disagreed with the filesystem (in a container with a uid map, say) would
    /// be the wrong answer confidently stated.
    ///
    /// `mountpoint` is the fallback: if no temporary file can be created at all,
    /// the directory the filesystem is being attached to has an owner, and it has
    /// already been checked to exist and be readable. Its owner is a real
    /// answer where a hard-coded zero would be a claim that everything in the
    /// vault belongs to root.
    #[must_use]
    pub fn capture(mountpoint: &Path, no_modtime: bool) -> Self {
        let (uid, gid) = probe_ownership()
            .or_else(|| owner_of(mountpoint))
            .unwrap_or_default();
        Self {
            uid,
            gid,
            mounted_at: SystemTime::now(),
            no_modtime,
        }
    }

    /// The time reported for a file with `modified_unix` recorded against it.
    ///
    /// Public so `readdirplus`-shaped callers and the tests can ask the same
    /// question the attribute builders do, rather than re-deriving the rule.
    #[must_use]
    pub fn time_for(&self, modified_unix: Option<i64>) -> SystemTime {
        if self.no_modtime {
            return self.mounted_at;
        }
        modified_unix.map_or(self.mounted_at, from_unix)
    }
}

/// The `stat` of one stored object.
///
/// `size` is the **plaintext** length: what a `read` of the whole file returns,
/// not what the sealed object occupies. Reporting the stored length would make
/// `ls -l` and `wc -c` disagree about the same file through the same mount, and
/// would make every `cp` out of the mount look like a short read.
#[must_use]
pub fn file(ino: INodeNo, size: u64, modified_unix: Option<i64>, identity: &Identity) -> FileAttr {
    let time = identity.time_for(modified_unix);
    FileAttr {
        ino,
        size,
        blocks: blocks(size),
        atime: time,
        mtime: time,
        ctime: time,
        crtime: time,
        kind: FileType::RegularFile,
        perm: MOUNT_FILE_MODE,
        nlink: MOUNT_FILE_LINK_COUNT,
        uid: identity.uid,
        gid: identity.gid,
        // No device number: nothing in a vault is a device, and `rdev` is only
        // read for the two file types this mount never reports.
        rdev: 0,
        blksize: MOUNT_BLOCK_SIZE,
        // BSD file flags (`chflags`): none. A vault records no such flags, and
        // claiming one — `UF_IMMUTABLE`, say — would be a statement about
        // enforcement this layer does not perform.
        flags: 0,
    }
}

/// The `stat` of an inferred directory.
///
/// Nothing stores it, so every field is either a constant or the mount's own.
/// The apparent size in particular is *not* the recursive total beneath it —
/// see [`MOUNT_DIRECTORY_APPARENT_SIZE`] for why summing a POSIX size field
/// across a tree answers the wrong question.
#[must_use]
pub fn directory(ino: INodeNo, identity: &Identity) -> FileAttr {
    // A directory has no recorded modification time to report: it is not stored,
    // so nothing ever modified it. The mount time is the honest answer, and is
    // what `time_for` yields for an absent timestamp.
    let time = identity.time_for(None);
    FileAttr {
        ino,
        size: MOUNT_DIRECTORY_APPARENT_SIZE,
        blocks: blocks(MOUNT_DIRECTORY_APPARENT_SIZE),
        atime: time,
        mtime: time,
        ctime: time,
        crtime: time,
        kind: FileType::Directory,
        perm: MOUNT_DIRECTORY_MODE,
        nlink: MOUNT_DIRECTORY_LINK_COUNT,
        uid: identity.uid,
        gid: identity.gid,
        rdev: 0,
        blksize: MOUNT_BLOCK_SIZE,
        flags: 0,
    }
}

/// The `stat` for either kind, given a size that only matters for files.
///
/// The shape the callbacks want: they hold a [`Kind`] and a size and should not
/// each contain the branch.
#[must_use]
pub fn of(
    ino: INodeNo,
    kind: Kind,
    size: u64,
    modified_unix: Option<i64>,
    identity: &Identity,
) -> FileAttr {
    match kind {
        Kind::File => file(ino, size, modified_unix, identity),
        Kind::Directory => directory(ino, identity),
    }
}

/// The FUSE file type for a [`Kind`].
///
/// `readdir` reports a type per entry without building a whole `FileAttr`, so
/// the mapping is needed on its own as well as inside the builders above.
#[must_use]
pub const fn file_type(kind: Kind) -> FileType {
    match kind {
        Kind::File => FileType::RegularFile,
        Kind::Directory => FileType::Directory,
    }
}

/// 512-byte blocks a file of `size` bytes occupies, rounded up.
///
/// This is what `du` adds up, so it has to round *up*: a one-byte file occupies
/// a block, and reporting zero would make `du` say a vault full of small files
/// takes no space. Ceiling division written as a saturating add rather than as
/// `(size + 511) / 512`, because the naive form overflows for a size within 511
/// bytes of `u64::MAX` — unreachable through a real vault, and a panic in a
/// filesystem callback is not a thing to leave one arithmetic edge away.
#[must_use]
fn blocks(size: u64) -> u64 {
    size.saturating_add(MOUNT_STAT_BLOCK_SIZE.saturating_sub(1)) / MOUNT_STAT_BLOCK_SIZE
}

/// What a file created by this process belongs to, by creating one.
///
/// The direct question, asked directly. A temporary file inherits the process's
/// effective user, so its owner *is* the answer the mount should report — and
/// unlike `geteuid` it stays correct where a uid namespace or a container mapping
/// makes the process's number and the filesystem's number differ.
///
/// [`None`] if no temporary file can be created, which on a machine that is about
/// to run a filesystem is unusual enough to be worth falling back rather than
/// failing over: the caller has a second source.
fn probe_ownership() -> Option<(u32, u32)> {
    let probe = tempfile::NamedTempFile::new().ok()?;
    let metadata = probe.as_file().metadata().ok()?;
    Some((metadata.uid(), metadata.gid()))
}

/// The owner of an existing path.
///
/// The fallback, and a real answer rather than a default: the mountpoint has
/// already been checked to exist and be a readable directory, so its owner is
/// known and is very often the same user. A hard-coded zero in its place would
/// claim every file in the vault belongs to root.
fn owner_of(path: &Path) -> Option<(u32, u32)> {
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.uid(), metadata.gid()))
}

/// A unix timestamp as a [`SystemTime`], clamped rather than panicking.
///
/// A negative timestamp is a time before 1970, which an index should never hold
/// but which a corrupted or hand-edited record could. `checked_sub`/`checked_add`
/// keep the conversion total: an unrepresentable time reports as the epoch, which
/// is visibly wrong to a human and harmless to a program, where the alternative
/// is an overflow panic inside `getattr`.
fn from_unix(seconds: i64) -> SystemTime {
    if seconds >= 0 {
        seconds
            .try_into()
            .ok()
            .and_then(|secs: u64| UNIX_EPOCH.checked_add(Duration::from_secs(secs)))
            .unwrap_or(UNIX_EPOCH)
    } else {
        seconds
            .checked_neg()
            .and_then(|secs| u64::try_from(secs).ok())
            .and_then(|secs| UNIX_EPOCH.checked_sub(Duration::from_secs(secs)))
            .unwrap_or(UNIX_EPOCH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity::capture(Path::new("."), false)
    }

    #[test]
    fn a_file_is_readable_by_everyone_and_writable_by_nobody() {
        // The mount is read-only. Permissions that said otherwise would invite an
        // editor to buffer a user's work and meet EROFS at save time.
        let attr = file(INodeNo(2), 1024, Some(0), &identity());
        assert_eq!(attr.perm, 0o444);
        assert_eq!(attr.perm & 0o222, 0, "no write bit anywhere");
        assert_eq!(attr.perm & 0o111, 0, "a vault records no execute bit");
        assert_eq!(attr.kind, FileType::RegularFile);
        assert_eq!(attr.nlink, 1);
    }

    #[test]
    fn a_directory_keeps_its_search_bit() {
        // Without execute on a directory nothing can traverse into it, so the
        // mount would be unusable — the one place the "no execute" rule inverts.
        let attr = directory(INodeNo(1), &identity());
        assert_eq!(attr.perm, 0o555);
        assert_ne!(attr.perm & 0o111, 0, "search permission is required");
        assert_eq!(attr.perm & 0o222, 0);
        assert_eq!(attr.kind, FileType::Directory);
    }

    #[test]
    fn a_file_reports_its_plaintext_size() {
        // Not the sealed length: `ls -l` and `wc -c` have to agree about the same
        // file read through the same mount.
        let attr = file(INodeNo(2), 4096, None, &identity());
        assert_eq!(attr.size, 4096);
    }

    #[test]
    fn block_counts_round_up_so_du_never_reports_nothing() {
        assert_eq!(blocks(0), 0);
        assert_eq!(blocks(1), 1);
        assert_eq!(blocks(511), 1);
        assert_eq!(blocks(512), 1);
        assert_eq!(blocks(513), 2);
        assert_eq!(blocks(4096), 8);
    }

    #[test]
    fn an_enormous_size_does_not_overflow_the_block_count() {
        // The arithmetic edge the saturating form exists for. A panic here is a
        // panic inside `getattr`, which wedges the mount.
        assert!(blocks(u64::MAX) > 0);
    }

    #[test]
    fn a_recorded_modification_time_is_reported() {
        let identity = identity();
        let attr = file(INodeNo(2), 0, Some(1_700_000_000), &identity);
        assert_eq!(attr.mtime, UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        // Read-only, so access time cannot be tracked and follows modification.
        assert_eq!(attr.atime, attr.mtime);
    }

    #[test]
    fn a_file_with_no_recorded_time_reports_the_mount_time_not_the_epoch() {
        // The epoch would tell a timestamp-comparing tool that every file in the
        // vault was last modified in 1970, and it would rewrite all of them.
        let identity = identity();
        let attr = file(INodeNo(2), 0, None, &identity);
        assert_ne!(attr.mtime, UNIX_EPOCH);
        assert_eq!(attr.mtime, identity.mounted_at);
    }

    #[test]
    fn no_modtime_suppresses_a_recorded_time() {
        // The half of the flag that is a real request: do not leak timestamps
        // through the mount to a tool that compares them.
        let identity = Identity::capture(Path::new("."), true);
        let attr = file(INodeNo(2), 0, Some(1_700_000_000), &identity);
        assert_eq!(attr.mtime, identity.mounted_at);
        assert_ne!(attr.mtime, UNIX_EPOCH + Duration::from_secs(1_700_000_000));
    }

    #[test]
    fn a_timestamp_before_the_epoch_converts_rather_than_panicking() {
        // Should never be in an index; a corrupted record could hold one, and a
        // panic in `getattr` takes the mount with it.
        assert_eq!(from_unix(0), UNIX_EPOCH);
        assert!(from_unix(-1) < UNIX_EPOCH);
        assert!(from_unix(i64::MIN) <= UNIX_EPOCH);
        assert!(from_unix(i64::MAX) >= UNIX_EPOCH);
    }

    #[test]
    fn every_file_is_owned_by_the_user_running_the_mount() {
        // A vault stores no uid, and the useful truth is who may read this mount.
        let identity = identity();
        let attr = file(INodeNo(2), 0, None, &identity);
        let dir = directory(INodeNo(1), &identity);
        assert_eq!(attr.uid, identity.uid);
        assert_eq!(dir.uid, identity.uid);
        assert_eq!(attr.gid, identity.gid);
    }

    #[test]
    fn the_kind_selects_the_builder() {
        let identity = identity();
        assert_eq!(
            of(INodeNo(2), Kind::File, 99, None, &identity).kind,
            FileType::RegularFile
        );
        assert_eq!(of(INodeNo(2), Kind::File, 99, None, &identity).size, 99);
        // A directory's apparent size is a constant, whatever size is passed.
        assert_eq!(
            of(INodeNo(1), Kind::Directory, 99, None, &identity).size,
            MOUNT_DIRECTORY_APPARENT_SIZE
        );
    }

    #[test]
    fn the_reported_file_types_match_the_attributes() {
        // `readdir` reports a type without building a whole attribute; the two
        // answers must be the same answer.
        let identity = identity();
        assert_eq!(
            file_type(Kind::File),
            file(INodeNo(2), 0, None, &identity).kind
        );
        assert_eq!(
            file_type(Kind::Directory),
            directory(INodeNo(1), &identity).kind
        );
    }
}
