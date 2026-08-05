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
//! ## Where the totals went
//!
//! This module used to compute each subdirectory's recursive byte and object
//! count on the same pass, for exactly one caller: `statfs`. A filesystem has to
//! say how large it is, and for a mounted vault the only true answer is the total
//! under the mount root.
//!
//! Computing it *here* meant a listing could not be answered without visiting
//! everything beneath it — so `readdir` of the mount root read the whole vault,
//! and every `df` did it again. The totals are now maintained by the index as
//! files arrive and leave and read through
//! [`Source::totals`](crate::source::Source::totals), which costs one row.
//! A directory's own `st_size` never read them and still does not: see
//! [`MOUNT_DIRECTORY_APPARENT_SIZE`](crate::constants::MOUNT_DIRECTORY_APPARENT_SIZE)
//! for why summing a POSIX size field across a tree is a different, wrong
//! question.
//!
//! ## The cost, stated rather than hidden
//!
//! A listing costs the directory it names. That is new, and it is the reason
//! this module was rewritten: [`Vault::list`](dctl_core::Vault::list) matches an
//! index prefix, and because the index keys rows by a *keyed hash* of the path,
//! matching a prefix means decrypting every row in the index — whatever the
//! prefix is. Measured on a 100,000-file vault, a listing matching no files cost
//! 755 ms, the same as one matching all of them, and a full `find` over the
//! mount took **417 seconds** against 4 seconds at 10,000 files: quadratic,
//! because a walk performs one `readdir` per directory.
//!
//! [`Source::children`](crate::source::Source::children) is the direct question,
//! answered by the index's parent column, and a source that cannot answer it
//! falls back to [`group`], which is the old grouping pass and still costs the
//! subtree. `--dir-cache-time` decides how often either is paid;
//! [`super::state`] is where the caching lives.

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
///
/// Deliberately *only* the children. This used to carry the recursive byte and
/// object totals of the subtree as well, computed on the same pass, and exactly
/// one caller read them: `statfs`, at the mount root. That made every `df` a
/// whole-vault walk — and, worse, it meant a directory listing could not be
/// answered without visiting everything beneath it, which is the cost that made
/// a tree walk quadratic. The totals now come from
/// [`Source::totals`](crate::source::Source::totals), which the vault maintains
/// as files arrive and leave.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Listing {
    /// Children in ascending name order, which is the order `readdir` reports
    /// and the order a `find` walks.
    pub children: Vec<Child>,
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
    // The direct answer, when the source has one. A vault does: its index keys
    // every row by the directory holding it, so this is two indexed lookups
    // rather than a pass over everything stored.
    if let Some(children) = source.children(dir).await? {
        return Ok(assemble(children));
    }
    group(source, dir).await
}

/// Turn a source's own answer into a listing.
fn assemble(children: crate::source::Children) -> Listing {
    let mut out: Vec<Child> = Vec::with_capacity(children.files.len() + children.dirs.len());
    for entry in children.files {
        out.push(Child {
            name: path::file_name(&entry.path).to_string(),
            size: entry.size,
            modified_unix: entry.modified_unix,
            path: entry.path,
            kind: Kind::File,
        });
    }
    for directory in children.dirs {
        out.push(Child {
            name: path::file_name(&directory).to_string(),
            path: directory,
            kind: Kind::Directory,
            size: None,
            modified_unix: None,
        });
    }
    // Files and directories arrive as two sequences and have to come out as one,
    // or two `ls` runs of the same vault disagree.
    out.sort_by(|left, right| left.name.cmp(&right.name));
    Listing { children: out }
}

/// Infer one directory by grouping every path beneath it.
///
/// The fallback for a source that cannot answer directly — a plain object store
/// has no directories and no question cheaper than "every key under this
/// prefix". It costs the subtree, which is why a source that can do better
/// should, and [`Source::children`](crate::source::Source::children) is how.
async fn group(source: &dyn Source, dir: &str) -> Result<Listing> {
    let mut cursor = source.enumerate(dir).await?;

    let mut children: Vec<Child> = Vec::new();
    let mut aggregator = Aggregator::new(dir, Some(IMMEDIATE_CHILDREN));
    let mut directories: Vec<Directory> = Vec::new();

    while let Some(entry) = cursor.next().await? {
        let entry = ListEntry::from_source(entry, dir);

        // No parent components left below this directory means the object sits
        // directly in it. The same question the aggregator asks to decide which
        // directories a path implies, so the two cannot disagree about where the
        // boundary is.
        if entry.parent_components().is_empty() {
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

    Ok(Listing { children })
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

        async fn exists(&self, path: &str) -> Result<bool> {
            Ok(self.entries.iter().any(|entry| entry.path == path))
        }

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
    }

    #[tokio::test]
    async fn a_listing_reports_one_level_of_a_deep_tree() {
        // What `readdir` owes: the top level, whatever is stacked beneath it.
        // The recursive byte and object totals this used to assert have moved to
        // `Source::totals`, which the vault maintains rather than walking for —
        // computing them here is what made a listing cost its whole subtree.
        let source = Fixture::new(&[
            ("docs/a.txt", Some(10)),
            ("photos/2024/a.jpg", Some(100)),
            ("photos/b.jpg", Some(200)),
            ("top.txt", Some(1)),
        ]);
        let listing = list(&source, "").await.unwrap();
        assert_eq!(
            names(&listing),
            vec![
                ("docs", Kind::Directory),
                ("photos", Kind::Directory),
                ("top.txt", Kind::File)
            ]
        );
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
    async fn an_unmeasured_object_still_appears_in_the_listing() {
        // Whether anyone has measured a file has nothing to do with whether it
        // is there, and a `readdir` that hid it would be the worse error.
        let source = Fixture::new(&[("photos/a.jpg", None), ("top.txt", Some(5))]);
        let listing = list(&source, "").await.unwrap();
        assert_eq!(
            names(&listing),
            vec![("photos", Kind::Directory), ("top.txt", Kind::File)]
        );
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
    async fn an_empty_vault_lists_nothing() {
        let source = Fixture::new(&[]);
        let listing = list(&source, "").await.unwrap();
        assert!(listing.children.is_empty());
    }

    /// A source that answers `children` directly and counts every time anyone
    /// falls back to walking it instead.
    ///
    /// The count is the whole point. A `readdir` served by grouping a subtree
    /// scan looks identical from the outside to one served by an indexed lookup
    /// — same names, same order, same everything — and differs only in costing
    /// the vault rather than the directory. Nothing but the call itself can tell
    /// them apart, so this asserts on the call.
    struct Direct {
        inner: Fixture,
        walked: std::sync::atomic::AtomicUsize,
    }

    impl Direct {
        fn new(paths: &[(&str, Option<u64>)]) -> Self {
            Self {
                inner: Fixture::new(paths),
                walked: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn walks(&self) -> usize {
            self.walked.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Source for Direct {
        async fn enumerate(&self, prefix: &str) -> Result<Box<dyn Entries>> {
            self.walked
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.enumerate(prefix).await
        }

        async fn children(&self, dir: &str) -> Result<Option<crate::source::Children>> {
            // What the vault's index answers: the files whose parent is this
            // directory, and the directories whose parent is this directory.
            let mut files = Vec::new();
            let mut dirs = std::collections::BTreeSet::new();
            for entry in &self.inner.entries {
                if !path::is_under(dir, &entry.path) {
                    continue;
                }
                let rest = entry.path[if dir.is_empty() { 0 } else { dir.len() + 1 }..].to_string();
                match rest.split_once('/') {
                    None => files.push(entry.clone()),
                    Some((head, _)) => {
                        dirs.insert(if dir.is_empty() {
                            head.to_string()
                        } else {
                            format!("{dir}/{head}")
                        });
                    }
                }
            }
            Ok(Some(crate::source::Children {
                files,
                dirs: dirs.into_iter().collect(),
            }))
        }

        async fn content_hash(&self, path: &str) -> Result<Option<Vec<u8>>> {
            self.inner.content_hash(path).await
        }
        async fn stream_to(
            &self,
            path: &str,
            out: &mut (dyn tokio::io::AsyncWrite + Unpin + Send),
        ) -> Result<u64> {
            self.inner.stream_to(path, out).await
        }
        fn sizes(&self) -> Sizes {
            self.inner.sizes()
        }
        async fn read(&self, path: &str) -> Result<Zeroizing<Vec<u8>>> {
            self.inner.read(path).await
        }
        async fn read_range(
            &self,
            path: &str,
            offset: u64,
            length: Option<u64>,
        ) -> Result<Zeroizing<Vec<u8>>> {
            self.inner.read_range(path, offset, length).await
        }
        async fn prefetch(&self, path: &str, offset: u64, length: u64) {
            self.inner.prefetch(path, offset, length).await;
        }
        fn tune_cache(&self, bytes: usize, max_chunks: usize) {
            self.inner.tune_cache(bytes, max_chunks);
        }
        async fn exists(&self, path: &str) -> Result<bool> {
            self.inner.exists(path).await
        }
        async fn stat(&self, path: &str) -> Result<Option<Entry>> {
            self.inner.stat(path).await
        }
        async fn verify(&self, path: &str) -> Result<()> {
            self.inner.verify(path).await
        }
        fn assurance(&self) -> Assurance {
            self.inner.assurance()
        }
        fn inventory(&self) -> Inventory {
            self.inner.inventory()
        }
    }

    #[tokio::test]
    async fn a_source_that_can_answer_directly_is_never_walked() {
        // The guard on the whole optimisation. Grouping a subtree scan produces
        // the same listing, so only the absence of the scan distinguishes a
        // `readdir` that costs its directory from one that costs the vault —
        // and it was the vault: 417 seconds to walk 100,000 files, against 4
        // seconds for 10,000.
        let source = Direct::new(&[
            ("photos/2024/a.jpg", Some(1)),
            ("photos/b.jpg", Some(2)),
            ("top.txt", Some(3)),
        ]);

        let root = list(&source, "").await.unwrap();
        assert_eq!(
            names(&root),
            vec![("photos", Kind::Directory), ("top.txt", Kind::File)]
        );

        let inner = list(&source, "photos").await.unwrap();
        assert_eq!(
            names(&inner),
            vec![("2024", Kind::Directory), ("b.jpg", Kind::File)]
        );

        assert_eq!(
            source.walks(),
            0,
            "a listing must not fall back to enumerating the subtree"
        );
    }

    #[tokio::test]
    async fn a_source_that_cannot_answer_directly_is_still_served() {
        // The default is `None`, and a plain object store means it: it has no
        // directories and no question cheaper than every key under a prefix.
        // That path has to keep working, or the fast path would be the only one.
        let source = Fixture::new(&[("photos/a.jpg", Some(1)), ("top.txt", Some(2))]);
        assert!(
            source.children("").await.unwrap().is_none(),
            "the fixture takes the trait's default"
        );
        let listing = list(&source, "").await.unwrap();
        assert_eq!(
            names(&listing),
            vec![("photos", Kind::Directory), ("top.txt", Kind::File)]
        );
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
