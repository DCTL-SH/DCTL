//! What "empty directory" means when there are no directories.
//!
//! An object store holds one flat namespace of keys with slashes in them.
//! `photos/2024/a.jpg` is a key, not a file inside two containers, and a
//! directory that holds no objects **does not exist at all** — there is nothing
//! anywhere that records it. A vault inherits that exactly: its index maps
//! plaintext paths to objects, and a path prefix nothing is stored under is
//! simply a prefix nothing is stored under.
//!
//! `mkdir` is what makes an empty directory expressible: it writes a zero-byte
//! object at `<dir>/`[`DIRECTORY_MARKER_NAME`], and that marker is the only
//! evidence an empty directory was ever intended. So the whole vocabulary of
//! this module is derived from a set of logical paths, and only from that:
//!
//! * A directory **exists** if some object's path lies under it — including its
//!   own marker.
//! * A directory is **empty** if the only objects under it, at any depth, are
//!   directory markers.
//! * Removing a directory therefore means removing its marker. Where there is no
//!   marker there is nothing to remove, and the directory stops existing the
//!   moment its last object does.
//!
//! ## Why this is not the same promise a filesystem makes, and why it still
//! means what a user expects
//!
//! `rmdir` on a POSIX filesystem fails with `ENOTEMPTY` if the directory holds
//! *anything*, including a subdirectory. That is the promise a script relies on,
//! and it is preserved here in full: a directory holding an object is refused,
//! and so is one holding a subdirectory — [`Directories::subdirectories`] finds
//! the markers below it and the refusal names them. The difference is in the
//! other direction, and it is unavoidable rather than chosen:
//!
//! * `rmdir` of a directory with **no marker and no objects** cannot succeed,
//!   because the directory was never there. It is reported as missing, which is
//!   what `rmdir` on a filesystem does for a path that does not exist.
//! * `rmdirs` sweeping a tree can only remove the directories somebody declared
//!   with `mkdir`. A directory that existed *only* because a file was stored in
//!   it has already ceased to exist by the time the file is gone, and reporting
//!   that as a removal would be counting a thing that never happened.
//!
//! Both of those are stated in the report rather than smoothed over, because the
//! alternative — inventing a directory removal so the numbers look like a
//! filesystem's — is precisely the misreport `PLAN.md` §6 forbids.

use std::collections::BTreeSet;

use crate::constants::{DIRECTORY_MARKER_NAME, PATH_SEPARATOR};
use crate::platform::path as logical;

/// The directory structure implied by one set of logical paths.
///
/// Built once per removal from the listing the command already had to perform,
/// so that emptiness, subdirectory containment and marker location are all
/// answered from the same snapshot. Two walks of the same tree could disagree
/// with each other if anything wrote in between, and "disagreed with itself" is
/// not an acceptable state for a command that deletes.
#[derive(Debug, Default)]
pub struct Directories {
    /// Every path that is *not* a directory marker, sorted.
    ///
    /// A [`BTreeSet`] because emptiness is asked once per candidate directory
    /// and answered by a range scan that stops at the first hit — linear per
    /// question over a ten-million-path set would make a `rmdirs` quadratic.
    objects: BTreeSet<String>,
    /// Every directory that has a marker object, sorted.
    markers: BTreeSet<String>,
}

impl Directories {
    /// Derive the structure from the paths a listing produced.
    #[must_use]
    pub fn from_paths<I, S>(paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut structure = Self::default();
        for path in paths {
            let path = path.as_ref();
            match directory_of_marker(path) {
                Some(directory) => {
                    structure.markers.insert(directory.to_string());
                }
                None => {
                    structure.objects.insert(path.to_string());
                }
            }
        }
        structure
    }

    /// Whether anything at all — object or marker — lies at or under `directory`.
    ///
    /// The existence question, asked before the emptiness one: `rmdir` of a path
    /// nothing is stored under is a missing directory, not an empty one, and
    /// answering it as "already empty, nothing to do" would report a success for
    /// a typo.
    #[must_use]
    pub fn exists(&self, directory: &str) -> bool {
        self.markers.contains(directory)
            || self
                .markers
                .iter()
                .any(|dir| logical::is_under(directory, dir))
            || self.holds_object(directory)
    }

    /// Whether `directory` holds any object other than a directory marker, at
    /// any depth.
    #[must_use]
    pub fn holds_object(&self, directory: &str) -> bool {
        self.first_object_under(directory).is_some()
    }

    /// Whether `directory` is empty: nothing under it but markers.
    #[must_use]
    pub fn is_empty(&self, directory: &str) -> bool {
        !self.holds_object(directory)
    }

    /// One object under `directory`, for a refusal that names an example.
    ///
    /// A message that says "not empty" and stops leaves the user running a
    /// listing to find out why. Naming one survivor is the difference between a
    /// refusal and an obstruction.
    #[must_use]
    pub fn first_object_under(&self, directory: &str) -> Option<&str> {
        if directory.is_empty() {
            return self.objects.first().map(String::as_str);
        }
        // Range from the directory's own prefix and stop at the first key that
        // leaves it, so the scan costs one comparison on a set of any size.
        let prefix = format!("{directory}{PATH_SEPARATOR}");
        self.objects
            .range(prefix.clone()..)
            .next()
            .filter(|candidate| candidate.starts_with(&prefix))
            .map(String::as_str)
    }

    /// The declared directories strictly below `directory`, deepest first.
    ///
    /// "Declared" is the load-bearing word: these are the ones with markers, and
    /// they are the ones a `rmdir` must refuse to remove out from under. A
    /// directory that exists only because a file sits in it is already covered by
    /// [`Directories::holds_object`].
    #[must_use]
    pub fn subdirectories(&self, directory: &str) -> Vec<&str> {
        let mut found: Vec<&str> = self
            .markers
            .iter()
            .map(String::as_str)
            .filter(|candidate| *candidate != directory && logical::is_under(directory, candidate))
            .collect();
        sort_deepest_first(&mut found);
        found
    }

    /// Every declared directory at or below `directory`, deepest first.
    ///
    /// Deepest first is not a preference. Removing `a/b` can be what makes `a`
    /// empty, so a sweep that visited parents first would leave half the litter
    /// standing and report success — and, worse, a crash part-way through a
    /// parents-first sweep would leave a directory marked as removed while its
    /// children were still there.
    #[must_use]
    pub fn declared_at_or_below(&self, directory: &str) -> Vec<&str> {
        let mut found: Vec<&str> = self
            .markers
            .iter()
            .map(String::as_str)
            .filter(|candidate| logical::is_under(directory, candidate))
            .collect();
        sort_deepest_first(&mut found);
        found
    }

    /// Whether `directory` has a marker object of its own.
    #[must_use]
    pub fn is_declared(&self, directory: &str) -> bool {
        self.markers.contains(directory)
    }
}

/// The logical path of the marker object that declares `directory`.
#[must_use]
pub fn marker_path(directory: &str) -> String {
    if directory.is_empty() {
        return DIRECTORY_MARKER_NAME.to_string();
    }
    format!("{directory}{PATH_SEPARATOR}{DIRECTORY_MARKER_NAME}")
}

/// Whether a logical path is a directory marker.
#[must_use]
pub fn is_marker(path: &str) -> bool {
    logical::file_name(path) == DIRECTORY_MARKER_NAME
}

/// The directory a marker path declares, or [`None`] for an ordinary object.
fn directory_of_marker(path: &str) -> Option<&str> {
    is_marker(path).then(|| logical::parent(path))
}

/// Order paths so that a child always precedes its parent.
///
/// By component count first, so `a/b/c` precedes `a/b`, and by path within a
/// depth so the order is deterministic — a report whose lines move between two
/// runs over the same tree is a report nobody can diff.
fn sort_deepest_first(paths: &mut [&str]) {
    paths.sort_by(|left, right| depth(right).cmp(&depth(left)).then_with(|| left.cmp(right)));
}

/// Number of components in a logical path.
fn depth(path: &str) -> usize {
    path.split(PATH_SEPARATOR)
        .filter(|part| !part.is_empty())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn structure(paths: &[&str]) -> Directories {
        Directories::from_paths(paths.iter().copied())
    }

    #[test]
    fn a_marker_declares_its_directory_and_is_not_an_object_in_it() {
        // The distinction the whole module rests on: if a marker counted as an
        // object, no directory created by `mkdir` would ever be empty.
        let dirs = structure(&[&marker_path("photos/2024")]);
        assert!(dirs.is_declared("photos/2024"));
        assert!(dirs.is_empty("photos/2024"));
        assert!(dirs.exists("photos/2024"));
    }

    #[test]
    fn a_directory_holding_a_file_is_not_empty_at_any_depth() {
        let dirs = structure(&["photos/2024/raw/a.dng"]);
        assert!(!dirs.is_empty("photos"));
        assert!(!dirs.is_empty("photos/2024"));
        assert!(!dirs.is_empty("photos/2024/raw"));
        assert_eq!(
            dirs.first_object_under("photos"),
            Some("photos/2024/raw/a.dng")
        );
    }

    #[test]
    fn emptiness_compares_whole_components() {
        // `photos` is not the parent of `photos-backup`. A byte-wise prefix
        // check here would report `photos` non-empty because of a neighbour, and
        // refuse a `rmdir` that should have succeeded.
        let dirs = structure(&[&marker_path("photos"), "photos-backup/a.jpg"]);
        assert!(dirs.is_empty("photos"));
        assert!(!dirs.is_empty("photos-backup"));
    }

    #[test]
    fn a_path_nothing_is_stored_under_does_not_exist() {
        // The honest answer for a vault: an empty directory and a directory that
        // was never created are the same absence unless somebody ran `mkdir`.
        let dirs = structure(&["photos/a.jpg"]);
        assert!(!dirs.exists("holidays"));
        assert!(dirs.exists("photos"));
        // …and "does not exist" must not be confused with "is empty".
        assert!(dirs.is_empty("holidays"));
    }

    #[test]
    fn a_declared_directory_exists_even_with_nothing_but_the_marker() {
        let dirs = structure(&[&marker_path("empty")]);
        assert!(dirs.exists("empty"));
        assert!(!dirs.exists("never-made"));
    }

    #[test]
    fn a_parent_exists_because_of_a_declared_child() {
        // `mkdir -p a/b` writes one marker at `a/b`. `a` is still a real
        // directory and `rmdir a` must refuse it, not report it missing.
        let dirs = structure(&[&marker_path("a/b")]);
        assert!(dirs.exists("a"));
        assert_eq!(dirs.subdirectories("a"), vec!["a/b"]);
    }

    #[test]
    fn subdirectories_exclude_the_directory_itself() {
        let dirs = structure(&[&marker_path("a"), &marker_path("a/b")]);
        assert_eq!(dirs.subdirectories("a"), vec!["a/b"]);
        assert!(dirs.subdirectories("a/b").is_empty());
    }

    #[test]
    fn declared_directories_come_back_deepest_first() {
        // Removing `a/b/c` is what makes `a/b` removable, so a sweep that saw
        // the parent first would leave the child behind.
        let dirs = structure(&[
            &marker_path("a"),
            &marker_path("a/b"),
            &marker_path("a/b/c"),
        ]);
        assert_eq!(dirs.declared_at_or_below("a"), vec!["a/b/c", "a/b", "a"]);
    }

    #[test]
    fn ordering_within_a_depth_is_deterministic() {
        // Two runs over one tree must produce byte-identical reports.
        let dirs = structure(&[&marker_path("z/b"), &marker_path("a/b")]);
        assert_eq!(dirs.declared_at_or_below(""), vec!["a/b", "z/b"]);
    }

    #[test]
    fn the_root_is_addressable_as_a_directory() {
        let dirs = structure(&["a.txt", &marker_path("d")]);
        assert!(dirs.exists(""));
        assert!(!dirs.is_empty(""));
        assert_eq!(dirs.first_object_under(""), Some("a.txt"));
        assert_eq!(dirs.declared_at_or_below(""), vec!["d"]);
    }

    #[test]
    fn a_marker_path_round_trips_through_its_directory() {
        assert_eq!(marker_path("a/b"), format!("a/b/{DIRECTORY_MARKER_NAME}"));
        assert_eq!(marker_path(""), DIRECTORY_MARKER_NAME);
        assert_eq!(directory_of_marker(&marker_path("a/b")), Some("a/b"));
        assert_eq!(directory_of_marker(&marker_path("")), Some(""));
        assert_eq!(directory_of_marker("a/b/photo.jpg"), None);
    }

    #[test]
    fn a_file_merely_named_like_a_marker_is_still_a_marker() {
        // There is no way to tell them apart, and the constant's own docs say
        // the name is brand-specific precisely so that nobody has one by
        // accident. Stating the rule here is what stops it being rediscovered.
        assert!(is_marker(&format!("a/{DIRECTORY_MARKER_NAME}")));
        assert!(!is_marker("a/.dctl-dir.bak"));
    }

    #[test]
    fn an_empty_structure_answers_everything_without_failing() {
        let dirs = Directories::default();
        assert!(!dirs.exists("anything"));
        assert!(dirs.is_empty("anything"));
        assert!(dirs.subdirectories("").is_empty());
        assert_eq!(dirs.first_object_under(""), None);
    }
}
