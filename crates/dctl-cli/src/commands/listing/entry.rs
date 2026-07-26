//! One thing a listing can print.
//!
//! An [`Entry`] is the listing family's own view of a
//! [`source::Entry`](crate::source::Entry), narrowed to what the six renderers
//! actually read and widened by the two things only a listing needs: where the
//! listing root ended inside the path, and whether the row stands for a
//! directory that no store actually holds.
//!
//! The narrowing already happened one layer down. A source entry carries no
//! wrapped DEK and no opaque object key, because a type that cannot hold them is
//! a type no renderer can leak them through — an object key printed next to a
//! plaintext path in an `lsjson` dump hands an observer exactly the mapping the
//! design exists to hide (`PLAN.md` §2, §7).
//!
//! ## Paths are stored whole, depth is derived
//!
//! An entry keeps its full logical path and remembers where the listing root
//! ended inside it, rather than keeping a second, relative copy. Filters,
//! depth limits and `--include` patterns all work in root-relative terms while
//! `Path` in the JSON output and the argument to `dctl cat` are absolute within
//! the vault, and holding both spellings for ten million entries would double
//! the only allocation on the hot path to save an integer.

use crate::constants::PATH_SEPARATOR;
use crate::output::hex;
use crate::platform::path;
use crate::source;

/// One object, or one directory synthesised from the objects beneath it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Full logical path within the vault, never with a leading separator.
    path: String,
    /// Byte offset in `path` at which the root-relative portion starts.
    root_len: usize,
    /// Plaintext size in bytes. For a directory, the total beneath it.
    size: u64,
    /// Last-modified time in unix seconds, when the index recorded one.
    modified_unix: Option<i64>,
    /// Hex-encoded plaintext content hash. Never present on a directory.
    content_hash: Option<String>,
    /// Whether this entry stands for a directory rather than an object.
    is_dir: bool,
}

impl Entry {
    /// Build an entry from what a source reported, rooted at `root`.
    ///
    /// `root` is the logical prefix the listing was opened at; everything after
    /// it is what filters and depth limits see. Callers are expected to have
    /// already established that the entry really is under the root —
    /// [`crate::source::Source::enumerate`] guarantees it, because that is also
    /// where a loose byte-wise prefix match from an index or a provider gets
    /// corrected.
    ///
    /// A missing content hash stays missing. A plain object store does not know
    /// the plaintext BLAKE3 of what it holds, and rendering `""` in a checksum
    /// column would tell an operator the object hashes to nothing.
    #[must_use]
    pub fn from_source(entry: source::Entry, root: &str) -> Self {
        let root_len = relative_offset(&entry.path, root);
        Self {
            root_len,
            size: entry.size,
            modified_unix: entry.modified_unix,
            content_hash: entry.content_hash.as_deref().map(hex::encode),
            is_dir: false,
            path: entry.path,
        }
    }

    /// Build a directory entry: a path with an aggregate size behind it.
    ///
    /// Directories are never stored — an object store has no such thing — so
    /// every one a listing shows is inferred from the paths of the objects
    /// beneath it. `size` is the total of those objects, which is the only
    /// figure a directory can honestly report.
    #[must_use]
    pub fn directory(path: String, root: &str, size: u64) -> Self {
        Self {
            root_len: relative_offset(&path, root),
            path,
            size,
            modified_unix: None,
            content_hash: None,
            is_dir: true,
        }
    }

    /// Full logical path within the vault.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The path relative to the listing root, which is what filters match and
    /// what depth counts.
    #[must_use]
    pub fn relative(&self) -> &str {
        self.path.get(self.root_len..).unwrap_or(&self.path)
    }

    /// Final path component.
    #[must_use]
    pub fn name(&self) -> &str {
        path::file_name(&self.path)
    }

    /// Plaintext size in bytes; for a directory, the total beneath it.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Last-modified time in unix seconds, if the index recorded one.
    #[must_use]
    pub const fn modified_unix(&self) -> Option<i64> {
        self.modified_unix
    }

    /// Hex-encoded plaintext content hash, absent on a directory.
    #[must_use]
    pub fn content_hash(&self) -> Option<&str> {
        self.content_hash.as_deref()
    }

    /// Whether this entry stands for a directory.
    #[must_use]
    pub const fn is_dir(&self) -> bool {
        self.is_dir
    }

    /// Depth below the listing root: a file directly in the root is at 1.
    ///
    /// One-based rather than zero-based so that it reads the same way
    /// `--max-depth` does, and so that `--max-depth 1` means "the top level"
    /// exactly as it does in rclone.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.relative()
            .split(PATH_SEPARATOR)
            .filter(|part| !part.is_empty())
            .count()
    }

    /// The root-relative directory components, without the final name.
    ///
    /// What [`super::dirs`] walks to decide which directories an object
    /// implies. Returned as borrowed slices: this runs once per object on a
    /// ten-million-object listing, and the caller only needs them for the length
    /// of one comparison.
    #[must_use]
    pub fn parent_components(&self) -> Vec<&str> {
        let mut parts: Vec<&str> = self
            .relative()
            .split(PATH_SEPARATOR)
            .filter(|part| !part.is_empty())
            .collect();
        // A directory entry *is* its own last component; a file's last component
        // is its name and implies no directory.
        if !self.is_dir {
            parts.pop();
        }
        parts
    }
}

/// Byte offset in `full` at which the portion below `root` begins.
///
/// Tolerates a root that does not actually prefix the path by falling back to
/// zero: an entry that is mislabelled is still better rendered whole than
/// rendered as a slice taken from the middle of a UTF-8 sequence.
fn relative_offset(full: &str, root: &str) -> usize {
    let root = root.trim_end_matches(PATH_SEPARATOR);
    if root.is_empty() || !path::is_under(root, full) {
        return 0;
    }
    // Step past the root and the separator that follows it. The root may equal
    // the whole path, in which case there is nothing after it.
    let after = root.len() + PATH_SEPARATOR.len_utf8();
    if after <= full.len() {
        after
    } else {
        full.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::listing::tests_support::listed;

    #[test]
    fn an_entry_keeps_the_full_path_and_derives_the_relative_one() {
        let entry = Entry::from_source(listed("photos/2024/a.jpg", 12, Some(0)), "photos");
        assert_eq!(entry.path(), "photos/2024/a.jpg");
        assert_eq!(entry.relative(), "2024/a.jpg");
        assert_eq!(entry.name(), "a.jpg");
        assert_eq!(entry.depth(), 2);
    }

    #[test]
    fn a_root_less_listing_is_relative_to_the_vault() {
        let entry = Entry::from_source(listed("a/b.txt", 1, None), "");
        assert_eq!(entry.relative(), "a/b.txt");
        assert_eq!(entry.depth(), 2);
    }

    #[test]
    fn a_trailing_separator_on_the_root_changes_nothing() {
        let with = Entry::from_source(listed("photos/a.jpg", 1, None), "photos/");
        let without = Entry::from_source(listed("photos/a.jpg", 1, None), "photos");
        assert_eq!(with.relative(), without.relative());
        assert_eq!(with.relative(), "a.jpg");
    }

    #[test]
    fn a_root_that_is_the_whole_path_leaves_nothing_relative() {
        // `dctl ls vault:photos/a.jpg` addresses one object; slicing past the
        // end of the string would be the obvious way to make that panic.
        let entry = Entry::from_source(listed("photos/a.jpg", 1, None), "photos/a.jpg");
        assert_eq!(entry.relative(), "");
        assert_eq!(entry.depth(), 0);
    }

    #[test]
    fn a_root_that_only_looks_like_a_prefix_is_not_stripped() {
        // `photos` is not a parent of `photos-backup`, and a byte-wise strip
        // would silently produce the relative path "-backup/a.jpg".
        let entry = Entry::from_source(listed("photos-backup/a.jpg", 1, None), "photos");
        assert_eq!(entry.relative(), "photos-backup/a.jpg");
    }

    #[test]
    fn a_multibyte_root_is_stripped_on_a_character_boundary() {
        let entry = Entry::from_source(listed("caf\u{e9}/a.jpg", 1, None), "caf\u{e9}");
        assert_eq!(entry.relative(), "a.jpg");
    }

    #[test]
    fn key_material_never_reaches_an_entry() {
        // The record carries a wrapped DEK and an object key; neither has an
        // accessor here, which is what keeps them out of every renderer.
        let entry = Entry::from_source(listed("a.txt", 1, None), "");
        let debug = format!("{entry:?}");
        assert!(!debug.contains("wrapped_dek"));
        assert!(!debug.contains("object_key"));
    }

    #[test]
    fn parent_components_stop_before_the_file_name() {
        let file = Entry::from_source(listed("a/b/c.txt", 1, None), "");
        assert_eq!(file.parent_components(), vec!["a", "b"]);
        // A file in the root implies no directory at all.
        let top = Entry::from_source(listed("c.txt", 1, None), "");
        assert!(top.parent_components().is_empty());
    }

    #[test]
    fn a_directory_owns_its_own_last_component() {
        let dir = Entry::directory("a/b".into(), "", 99);
        assert!(dir.is_dir());
        assert_eq!(dir.parent_components(), vec!["a", "b"]);
        assert_eq!(dir.size(), 99);
        assert_eq!(dir.content_hash(), None);
        assert_eq!(dir.modified_unix(), None);
    }

    #[test]
    fn content_hashes_render_as_lower_case_hex() {
        let entry = Entry::from_source(listed("a.txt", 1, None), "");
        assert_eq!(entry.content_hash(), Some("abcd"));
    }
}
