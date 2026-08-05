//! Deterministic, privacy-preserving keying for index entries.
//!
//! The database key for a path is a *keyed* BLAKE3 hash of the path — equal paths
//! map to equal keys (point lookups work), but the on-disk database never reveals
//! the plaintext paths. Record values are AEAD-encrypted and bound (via AAD) to
//! their key, so the at-rest database leaks neither paths nor metadata.
//!
//! ## Why a directory needs a key of its own
//!
//! A keyed hash destroys order: `BLAKE3(k, "a/b")` and `BLAKE3(k, "a/c")` are as
//! far apart as any two digests, so rows stream in an order unrelated to the
//! paths they came from. That is the privacy property — the database cannot be
//! sorted back into a directory tree — and it is also why a listing could not
//! seek to a prefix or stop early, and had to decrypt *every* row in the index
//! to answer any question about any directory.
//!
//! Measured on a 100,000-file vault, that cost 413 ms per `readdir`, and since a
//! walk performs one per directory the whole traversal was quadratic: 47 ms at
//! 1,000 files, 4.0 s at 10,000, **417 s at 100,000**. A listing matching *no*
//! files cost 755 ms — the same as one matching all of them — which is the
//! clearest statement of the problem: the prefix never narrowed the work.
//!
//! So each row also carries the keyed hash of the directory that holds it, and
//! that column is indexed. `readdir` becomes one indexed lookup returning only
//! the rows it will show. What this leaks is that some set of rows share a
//! parent, and the shape of the tree — how many directories, how wide each is —
//! but never a name, a path, or an order. Order-preserving keys would have
//! leaked all three, which is the alternative this deliberately does not take.
//!
//! The functions below are the path arithmetic deciding what "the directory that
//! holds it" means. They are pure and take no key, so they can be reasoned about
//! — and tested — without the cryptography.

/// The separator between logical path components.
///
/// Logical paths are always `/`-separated whatever platform produced them; the
/// conversion happens above this crate, where a native path becomes a vault path.
pub(crate) const SEPARATOR: char = '/';

/// 32-byte database key for `path` under the keying key.
///
/// Also the key of a *directory* row, whose "path" is the directory's own
/// logical path. One function for both, so a directory and a file at the same
/// path could never hash apart.
pub(crate) fn index_key(keying_key: &[u8; 32], path: &str) -> [u8; 32] {
    *blake3::keyed_hash(keying_key, path.as_bytes()).as_bytes()
}

/// The directory holding `path`, or the empty string when it sits at the root.
///
/// The root is the empty string rather than `/` or `.` because that is what the
/// rest of the tool already calls it: a whole-vault mount's root prefix is `""`
/// and `Vault::list("")` means everything. A second spelling here would put two
/// different keys on one directory.
pub(crate) fn parent_of(path: &str) -> &str {
    match path.rfind(SEPARATOR) {
        Some(at) => &path[..at],
        None => "",
    }
}

/// Every directory `path` lies beneath, outermost first, excluding the root.
///
/// `a/b/c.txt` yields `["a", "a/b"]`. This is what maintains the directory rows:
/// a file's arrival implies each of these exists, and its removal is what can
/// make them stop existing, so both operations walk exactly this list.
///
/// The root is excluded deliberately — it exists whether or not anything is in
/// it, so giving it a reference count would mean an empty vault still held a
/// directory row for a directory nobody created.
pub(crate) fn ancestors_of(path: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(offset) = path[at..].find(SEPARATOR) {
        let end = at + offset;
        // A leading or doubled separator yields an empty component, which is the
        // root's own name — skip it rather than mint a second key for the root.
        if end > 0 {
            out.push(&path[..end]);
        }
        at = end + SEPARATOR.len_utf8();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_at_the_root_is_held_by_the_root() {
        assert_eq!(parent_of("top.txt"), "");
        assert!(ancestors_of("top.txt").is_empty());
    }

    #[test]
    fn a_nested_file_names_each_directory_above_it_outermost_first() {
        assert_eq!(parent_of("a/b/c.txt"), "a/b");
        assert_eq!(ancestors_of("a/b/c.txt"), vec!["a", "a/b"]);
    }

    #[test]
    fn a_sibling_sharing_a_name_prefix_has_a_different_parent() {
        // `photos` and `photos-backup` sort adjacently and share bytes. A parent
        // computed by byte prefix rather than by component would list one tree's
        // files inside the other's.
        assert_eq!(parent_of("photos/a.jpg"), "photos");
        assert_eq!(parent_of("photos-backup/a.jpg"), "photos-backup");
        assert_ne!(parent_of("photos/a.jpg"), parent_of("photos-backup/a.jpg"));
    }

    #[test]
    fn the_root_never_becomes_an_ancestor_of_its_own() {
        // A leading separator would otherwise push `""` — a directory row for the
        // root, which exists without one and would never be collected.
        assert!(ancestors_of("/leading.txt").is_empty());
        assert_eq!(ancestors_of("/a/b.txt"), vec!["/a"]);
    }

    #[test]
    fn a_directory_and_the_file_beside_it_do_not_share_a_key() {
        // `photos` the directory and `photos.txt` the file both begin `photos`.
        // Different rows must be different keys, or a listing would find one when
        // it asked for the other.
        let key = [7u8; 32];
        assert_ne!(index_key(&key, "photos"), index_key(&key, "photos.txt"));
    }

    #[test]
    fn one_path_always_hashes_to_one_key() {
        let key = [3u8; 32];
        assert_eq!(index_key(&key, "a/b.txt"), index_key(&key, "a/b.txt"));
        // …and a different keying key gives a different database entirely.
        assert_ne!(index_key(&key, "a/b.txt"), index_key(&[4u8; 32], "a/b.txt"));
    }
}
