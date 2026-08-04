//! One directory's contents, inferred from the paths of the objects beneath it.
//!
//! A vault stores no directories — see [`super`] — so every directory the mount
//! shows is a *grouping of logical paths by their leading components*. That
//! inference already exists: it is what `dctl lsd` and `dctl tree` are built on,
//! and it lives in [`crate::commands::listing::dirs`]. This module reuses it
//! rather than restating it, and the reason is not tidiness. Two definitions of
//! "what is a directory here" would disagree eventually, and the disagreement
//! would be silent: `dctl lsd archive:` would show a directory the mount does not
//! have, or the mount would show one `dctl lsd` denies, and neither would produce
//! an error.
//!
//! So a directory listing is one pass of [`Aggregator`] over the entries under
//! that prefix, at depth one. What the aggregator closes is a subdirectory; an
//! entry whose root-relative path has no separator left in it — which
//! [`Entry::parent_components`] answers, and which is the same function
//! [`Aggregator`] itself consults — is a file sitting directly here.
//!
//! ## Why the totals are kept
//!
//! [`Aggregator`] computes each subdirectory's recursive byte count and object
//! count on the pass it was making anyway, and the mount needs them for exactly
//! one thing: `statfs`. A filesystem has to be able to say how large it is, and
//! for a mounted vault the only true answer is the total of what is under the
//! mount root — which is this listing's totals, at the root. Nothing else reads
//! them, and in particular a directory's own `st_size` does *not*: see
//! [`MOUNT_DIRECTORY_APPARENT_SIZE`](crate::constants::MOUNT_DIRECTORY_APPARENT_SIZE)
//! for why summing a POSIX size field across a tree is a different, wrong
//! question.
//!
//! ## The cost, stated rather than hidden
//!
//! Listing a subdirectory costs the subtree under it, because
//! [`Vault::list`](dctl_core::Vault::list) matches an index prefix. Listing the
//! **mount root** therefore costs the whole vault: every record is materialised,
//! grouped and dropped, and only the top level is kept. That is the core's
//! buffering, documented in [`crate::source::vault`], and the mount inherits it
//! rather than working around it — a `readdir` of the top of a ten-million-object
//! vault is a ten-million-record read. `--dir-cache-time` is the dial that
//! decides how often it is paid; [`super::state`] is where the caching lives.

use crate::commands::listing::Entry as ListEntry;
use crate::commands::listing::dirs::{Aggregator, Directory};
use crate::error::Result;
use crate::platform::path;
use crate::source::Source;

use super::inode::Kind;

/// Depth the aggregator is run at: one level, which is a directory's children.
///
/// Not a tunable — it is what "the contents of this directory" means — so it is
/// a private constant here rather than a knob in `constants.rs`. A mount that
/// grouped two levels at once would be answering a question `readdir` did not
/// ask and holding the second level's listings nobody requested.
const IMMEDIATE_CHILDREN: usize = 1;

/// One entry in a directory: a stored object, or a prefix that implies one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Child {
    /// Final path component — the name the kernel asked for, or will.
    pub name: String,
    /// Full logical path within the vault, including the mount's root prefix.
    pub path: String,
    /// Whether this is an object or an inferred directory.
    pub kind: Kind,
    /// Plaintext size, when the index recorded one.
    ///
    /// [`None`] means *nobody has ever measured this object* — the state an
    /// index rebuilt from the backend leaves every row in, because a rebuild is
    /// a list-only pass. It is deliberately not zero: reporting a rebuilt row as
    /// a zero-byte file through a filesystem would make every reader see an empty
    /// file and exit successfully. [`super::state`] establishes the real size
    /// from the object's authenticated header when a `getattr` needs it.
    ///
    /// Always [`None`] for a directory, whose apparent size is a constant.
    pub size: Option<u64>,
    /// Last-modified time in unix seconds, when the index recorded one.
    pub modified_unix: Option<i64>,
}

/// The contents of one directory, as of the moment it was read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Listing {
    /// Children in ascending name order, which is the order `readdir` reports
    /// and the order a `find` walks.
    pub children: Vec<Child>,
    /// Total plaintext bytes under this directory at every depth, or [`None`]
    /// when any object beneath it has never been measured.
    ///
    /// Absorbing rather than skipping, exactly as `dctl lsd`'s column is: a
    /// subtree holding one unmeasured object has no known total, and reporting
    /// the sum of the rest as though it were the whole is the same misreport a
    /// zero would be — just harder to notice.
    pub subtree_bytes: Option<u64>,
    /// Objects under this directory at every depth.
    pub subtree_objects: u64,
}

impl Listing {
    /// The child called `name`, if this directory has one.
    ///
    /// A linear scan. A directory listing is bounded by its own width, the
    /// comparison is a string equality on a short slice, and a map would need
    /// building on every listing to save a scan that only `lookup` performs —
    /// which the kernel then caches for `--attr-timeout`.
    #[must_use]
    pub fn child(&self, name: &str) -> Option<&Child> {
        self.children.iter().find(|child| child.name == name)
    }
}

/// Read one directory.
///
/// `dir` is the full logical path of the directory within the vault; the mount
/// root is the empty string for a whole-vault mount and the subtree prefix
/// otherwise.
///
/// # Errors
/// Whatever the index or the provider reported. A failure part-way through is an
/// error and never a short listing — a directory that silently lost half its
/// entries is how a mount tells a backup tool that files were deleted.
pub async fn list(source: &dyn Source, dir: &str) -> Result<Listing> {
    let mut cursor = source.enumerate(dir).await?;

    let mut children: Vec<Child> = Vec::new();
    let mut aggregator = Aggregator::new(dir, Some(IMMEDIATE_CHILDREN));
    let mut directories: Vec<Directory> = Vec::new();

    // Totals start at a *known* zero: an empty directory genuinely holds zero
    // bytes. They become unknown the moment an unmeasured object lands in them.
    let mut bytes: Option<u64> = Some(0);
    let mut objects: u64 = 0;

    while let Some(entry) = cursor.next().await? {
        let entry = ListEntry::from_source(entry, dir);

        // No parent components left below this directory means the object sits
        // directly in it. The same question the aggregator asks to decide which
        // directories a path implies, so the two cannot disagree about where the
        // boundary is.
        if entry.parent_components().is_empty() {
            bytes = bytes
                .zip(entry.size())
                .map(|(total, size)| total.saturating_add(size));
            objects = objects.saturating_add(1);
            children.push(Child {
                name: entry.name().to_string(),
                path: entry.path().to_string(),
                kind: Kind::File,
                size: entry.size(),
                modified_unix: entry.modified_unix(),
            });
        }

        aggregator.push(&entry, &mut |directory| {
            directories.push(directory.clone());
            Ok(())
        })?;
    }
    aggregator.finish(&mut |directory| {
        directories.push(directory.clone());
        Ok(())
    })?;

    for directory in directories {
        bytes = bytes
            .zip(directory.bytes())
            .map(|(total, size)| total.saturating_add(size));
        objects = objects.saturating_add(directory.objects());

        let full = directory.to_entry().path().to_string();
        children.push(Child {
            name: path::file_name(&full).to_string(),
            path: full,
            kind: Kind::Directory,
            size: None,
            modified_unix: None,
        });
    }

    // Files arrive in path order and directories in path order, but the two
    // sequences are interleaved by name in the answer `readdir` owes. Sorting
    // once here is what makes a listing deterministic between mounts, which a
    // test — and a user comparing two `ls` runs — is entitled to.
    children.sort_by(|left, right| left.name.cmp(&right.name));

    Ok(Listing {
        children,
        subtree_bytes: bytes,
        subtree_objects: objects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{Assurance, Entries, Entry, Inventory, Sizes};
    use async_trait::async_trait;
    use std::collections::VecDeque;
    use zeroize::Zeroizing;

    /// A source over a fixed, sorted set of paths.
    ///
    /// The grouping is pure path arithmetic, so a real vault would only slow the
    /// test down; what has to be exercised is that this module and `dctl lsd`
    /// agree, and both read the same [`Entry`] stream.
    struct Fixture {
        entries: Vec<Entry>,
    }

    impl Fixture {
        fn new(paths: &[(&str, Option<u64>)]) -> Self {
            let mut entries: Vec<Entry> = paths
                .iter()
                .map(|(path, size)| match size {
                    Some(size) => Entry::new(*path, *size).with_modified(Some(1_700_000_000)),
                    None => Entry::unmeasured(*path),
                })
                .collect();
            entries.sort_by(|left, right| left.path.cmp(&right.path));
            Self { entries }
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
            Ok(Box::new(Cursor {
                entries: self
                    .entries
                    .iter()
                    .filter(|entry| path::is_under(prefix, &entry.path))
                    .cloned()
                    .collect(),
            }))
        }

        fn sizes(&self) -> Sizes {
            Sizes::Plaintext
        }

        async fn read(&self, _path: &str) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(Vec::new()))
        }

        async fn read_range(
            &self,
            _path: &str,
            _offset: u64,
            _length: Option<u64>,
        ) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(Vec::new()))
        }

        async fn prefetch(&self, _path: &str, _offset: u64, _length: u64) {}

        fn tune_cache(&self, _bytes: usize, _max_chunks: usize) {}

        async fn stat(&self, path: &str) -> Result<Option<Entry>> {
            Ok(self.entries.iter().find(|e| e.path == path).cloned())
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

    fn names(listing: &Listing) -> Vec<(&str, Kind)> {
        listing
            .children
            .iter()
            .map(|child| (child.name.as_str(), child.kind))
            .collect()
    }

    #[tokio::test]
    async fn a_prefix_with_objects_beneath_it_is_a_directory() {
        // The whole inference: nothing stores `photos`, and it exists because
        // `photos/a.jpg` does.
        let source = Fixture::new(&[("photos/a.jpg", Some(10)), ("top.txt", Some(1))]);
        let listing = list(&source, "").await.unwrap();
        assert_eq!(
            names(&listing),
            vec![("photos", Kind::Directory), ("top.txt", Kind::File)]
        );
    }

    #[tokio::test]
    async fn only_immediate_children_are_reported() {
        // `readdir` asks for one level. A deep object implies the top-level
        // directory and nothing else at this level.
        let source = Fixture::new(&[("a/b/c/deep.bin", Some(4096))]);
        let listing = list(&source, "").await.unwrap();
        assert_eq!(names(&listing), vec![("a", Kind::Directory)]);

        let inner = list(&source, "a").await.unwrap();
        assert_eq!(names(&inner), vec![("b", Kind::Directory)]);
        assert_eq!(inner.children[0].path, "a/b");
    }

    #[tokio::test]
    async fn a_sibling_that_shares_a_name_prefix_is_a_different_directory() {
        // `photos` and `photos-backup` sort adjacently; a byte-wise prefix match
        // would merge them, and the mount would show one tree's files inside
        // another's.
        let source = Fixture::new(&[("photos-backup/a.jpg", Some(2)), ("photos/a.jpg", Some(1))]);
        let listing = list(&source, "photos").await.unwrap();
        assert_eq!(names(&listing), vec![("a.jpg", Kind::File)]);
        assert_eq!(listing.subtree_objects, 1);
    }

    #[tokio::test]
    async fn the_totals_cover_the_whole_subtree() {
        // What `statfs` reports for the mount: everything under the root, not
        // just what is directly in it.
        let source = Fixture::new(&[
            ("docs/a.txt", Some(10)),
            ("photos/2024/a.jpg", Some(100)),
            ("photos/b.jpg", Some(200)),
            ("top.txt", Some(1)),
        ]);
        let listing = list(&source, "").await.unwrap();
        assert_eq!(listing.subtree_bytes, Some(311));
        assert_eq!(listing.subtree_objects, 4);
    }

    #[tokio::test]
    async fn one_unmeasured_object_makes_the_total_unknown_rather_than_smaller() {
        // A partial total presented as a total is the same misreport a zero
        // would be, and harder to spot.
        let source = Fixture::new(&[("a.txt", Some(10)), ("b.txt", None)]);
        let listing = list(&source, "").await.unwrap();
        assert_eq!(listing.subtree_bytes, None);
        // …and the object is still counted, so the row says something is there.
        assert_eq!(listing.subtree_objects, 2);
    }

    #[tokio::test]
    async fn an_unmeasured_object_keeps_its_absent_size_rather_than_a_zero() {
        // The size a `getattr` then establishes from the object's own header.
        // A zero here would make every reader see an empty file and succeed.
        let source = Fixture::new(&[("a.txt", None)]);
        let listing = list(&source, "").await.unwrap();
        assert_eq!(listing.child("a.txt").and_then(|child| child.size), None);
    }

    #[tokio::test]
    async fn an_unmeasured_object_inside_a_subtree_only_clouds_the_total() {
        // The absorbing rule has to survive the aggregator's own totals, which
        // is where the two halves of this function meet.
        let source = Fixture::new(&[("photos/a.jpg", None), ("top.txt", Some(5))]);
        let listing = list(&source, "").await.unwrap();
        assert_eq!(listing.subtree_bytes, None);
        assert_eq!(listing.subtree_objects, 2);
        assert_eq!(names(&listing).len(), 2);
    }

    #[tokio::test]
    async fn children_are_reported_in_name_order() {
        // Files and directories arrive as two sorted sequences and have to come
        // out as one, or two `ls` runs of the same vault disagree.
        let source = Fixture::new(&[
            ("z.txt", Some(1)),
            ("a/one.bin", Some(1)),
            ("m.txt", Some(1)),
            ("b/two.bin", Some(1)),
        ]);
        let listing = list(&source, "").await.unwrap();
        assert_eq!(
            names(&listing),
            vec![
                ("a", Kind::Directory),
                ("b", Kind::Directory),
                ("m.txt", Kind::File),
                ("z.txt", Kind::File)
            ]
        );
    }

    #[tokio::test]
    async fn an_empty_vault_lists_nothing_and_totals_a_known_zero() {
        // Known zero, not unknown: there is nothing unmeasured in an empty tree.
        let source = Fixture::new(&[]);
        let listing = list(&source, "").await.unwrap();
        assert!(listing.children.is_empty());
        assert_eq!(listing.subtree_bytes, Some(0));
        assert_eq!(listing.subtree_objects, 0);
    }

    #[tokio::test]
    async fn a_child_carries_the_full_vault_path_not_just_its_name() {
        // What the mount opens objects by. A name alone would address the wrong
        // file the moment two directories held one.
        let source = Fixture::new(&[("photos/2024/a.jpg", Some(3))]);
        let listing = list(&source, "photos/2024").await.unwrap();
        let child = listing.child("a.jpg").unwrap();
        assert_eq!(child.path, "photos/2024/a.jpg");
        assert_eq!(child.size, Some(3));
        assert_eq!(child.modified_unix, Some(1_700_000_000));
    }

    #[tokio::test]
    async fn a_name_that_is_not_there_is_absent_rather_than_an_error() {
        let source = Fixture::new(&[("a.txt", Some(1))]);
        let listing = list(&source, "").await.unwrap();
        assert!(listing.child("b.txt").is_none());
    }

    #[tokio::test]
    async fn a_directory_and_a_file_may_share_a_parent_without_merging() {
        // `photos` the directory and `photos.txt` the file both start with
        // `photos`; grouping by bytes rather than components would fold them.
        let source = Fixture::new(&[("photos/a.jpg", Some(1)), ("photos.txt", Some(2))]);
        let listing = list(&source, "").await.unwrap();
        assert_eq!(
            names(&listing),
            vec![("photos", Kind::Directory), ("photos.txt", Kind::File)]
        );
    }
}
