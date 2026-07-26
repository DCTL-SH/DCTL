//! One transferable thing, as both sides of a transfer describe it.
//!
//! An entry is deliberately *thin*: a logical path, a size, a modification time,
//! and — when the side can supply one cheaply — a content hash. That is exactly
//! the information [`super::compare`] needs and nothing more, which is what lets
//! a local directory walk and a vault index listing produce the same type.
//!
//! The path is always **logical** (`/`-separated, NFC, relative to the transfer
//! root) even when it came from the local filesystem, because pairing the two
//! sides is a string comparison and the two sides may have been written by
//! different operating systems. `caf\u{e9}/a.jpg` from Linux and
//! `cafe\u{301}/a.jpg` from macOS are the same file, and only normalisation
//! makes them compare equal — see [`crate::platform::path`].

use std::time::SystemTime;

/// What kind of thing an entry describes.
///
/// Only two variants, because only two survive the trip through a vault. Files
/// are objects; directories exist solely as prefixes of object paths and so are
/// implicit — *except* an empty one, which has no objects under it and would
/// therefore vanish. `--create-empty-src-dirs` exists to keep those, so they
/// have to be representable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An object with content.
    File,
    /// A directory containing no files at any depth beneath it.
    EmptyDir,
}

/// One file (or empty directory) on one side of a transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Logical path relative to the transfer root.
    pub path: String,
    /// Size in bytes. Always zero for [`Kind::EmptyDir`].
    pub size: u64,
    /// Modification time, when the side can report one.
    ///
    /// Optional rather than defaulted, because "unknown" and "the epoch" must
    /// not compare equal: a backend that reports no timestamp would otherwise
    /// make every file look older than every local file and invert `--update`.
    pub modified: Option<SystemTime>,
    /// Content hash, when the side already knows it.
    ///
    /// Never computed speculatively. Hashing a local tree costs a full read of
    /// every file, which is the entire cost of the transfer itself — so it
    /// happens only when `--checksum` asks for it, and only through the engine
    /// that is reading the bytes anyway.
    pub hash: Option<String>,
    /// Whether this is a file or an empty directory.
    pub kind: Kind,
}

impl Entry {
    /// A file entry with no timestamp and no hash.
    #[must_use]
    pub fn file(path: impl Into<String>, size: u64) -> Self {
        Self {
            path: path.into(),
            size,
            modified: None,
            hash: None,
            kind: Kind::File,
        }
    }

    /// An empty-directory entry.
    #[must_use]
    pub fn empty_dir(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            size: 0,
            modified: None,
            hash: None,
            kind: Kind::EmptyDir,
        }
    }

    /// Attach a modification time.
    #[must_use]
    pub const fn with_modified(mut self, modified: SystemTime) -> Self {
        self.modified = Some(modified);
        self
    }

    /// Whether this entry carries content.
    #[must_use]
    pub const fn is_file(&self) -> bool {
        matches!(self.kind, Kind::File)
    }

    /// Whether this entry is newer than `other` by more than `window`.
    ///
    /// Returns `false` whenever either timestamp is unknown. That is the safe
    /// direction for `--update`, whose contract is "do not overwrite something
    /// newer": without both timestamps we cannot prove the destination is newer,
    /// so we do not claim it — the transfer proceeds and the verified-write
    /// pipeline decides, rather than a guess silently skipping a file.
    #[must_use]
    pub fn is_newer_than(&self, other: &Self, window: std::time::Duration) -> bool {
        let (Some(mine), Some(theirs)) = (self.modified, other.modified) else {
            return false;
        };
        mine.duration_since(theirs)
            .is_ok_and(|delta| delta > window)
    }

    /// Whether two timestamps agree to within `window`.
    ///
    /// Unknown on either side means "cannot tell", which is reported as *not*
    /// equal so the caller falls back to a stronger comparison instead of
    /// assuming a match it never established.
    #[must_use]
    pub fn modified_matches(&self, other: &Self, window: std::time::Duration) -> bool {
        let (Some(mine), Some(theirs)) = (self.modified, other.modified) else {
            return false;
        };
        let delta = mine
            .duration_since(theirs)
            .or_else(|_| theirs.duration_since(mine));
        delta.is_ok_and(|delta| delta <= window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const WINDOW: Duration = Duration::from_secs(1);

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn a_file_entry_carries_its_size_and_nothing_else() {
        let entry = Entry::file("a/b.txt", 42);
        assert!(entry.is_file());
        assert_eq!(entry.size, 42);
        assert!(entry.modified.is_none());
        assert!(entry.hash.is_none());
    }

    #[test]
    fn an_empty_directory_has_no_size() {
        let entry = Entry::empty_dir("a/empty");
        assert!(!entry.is_file());
        assert_eq!(entry.size, 0);
        assert_eq!(entry.kind, Kind::EmptyDir);
    }

    #[test]
    fn timestamps_compare_within_the_modify_window() {
        let older = Entry::file("a", 1).with_modified(at(1000));
        let same = Entry::file("a", 1).with_modified(at(1001));
        let newer = Entry::file("a", 1).with_modified(at(1010));

        // One second of drift is what a whole-second provider timestamp costs.
        assert!(older.modified_matches(&same, WINDOW));
        assert!(same.modified_matches(&older, WINDOW));
        assert!(!older.modified_matches(&newer, WINDOW));

        assert!(newer.is_newer_than(&older, WINDOW));
        assert!(!older.is_newer_than(&newer, WINDOW));
        assert!(!same.is_newer_than(&older, WINDOW), "inside the window");
    }

    #[test]
    fn an_unknown_timestamp_never_claims_a_match() {
        // A backend that reports no mtime must not be able to make a file look
        // identical, or `sync` would skip files it has never compared.
        let known = Entry::file("a", 1).with_modified(at(1000));
        let unknown = Entry::file("a", 1);
        assert!(!known.modified_matches(&unknown, WINDOW));
        assert!(!unknown.modified_matches(&known, WINDOW));
    }

    #[test]
    fn an_unknown_timestamp_never_claims_to_be_newer() {
        // The `--update` direction: without proof the destination is newer, the
        // file is transferred rather than silently skipped.
        let known = Entry::file("a", 1).with_modified(at(9_999));
        let unknown = Entry::file("a", 1);
        assert!(!unknown.is_newer_than(&known, WINDOW));
        assert!(!known.is_newer_than(&unknown, WINDOW));
    }

    #[test]
    fn a_hash_is_absent_until_a_side_supplies_one() {
        // Never computed speculatively: hashing a local tree costs a full read
        // of every file, which is the entire cost of the transfer itself.
        assert!(Entry::file("a", 1).hash.is_none());
    }
}
