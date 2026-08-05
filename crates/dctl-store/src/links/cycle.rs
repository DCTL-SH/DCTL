//! Why a walk that follows links still finishes.
//!
//! A link pointing at one of its own ancestors is the oldest way to make a
//! backup tool run until the disk fills. Loop protection is precisely why the
//! symlink fix had gone unattempted for so long, so it is not an afterthought
//! here: nothing in this crate follows a link without it.
//!
//! # Why the ancestors and not everywhere the walk has been
//!
//! The obvious implementation keeps one global set of every directory the walk
//! has entered and refuses a second visit. It terminates, and it is wrong in a
//! way that would have re-created the defect this work exists to remove.
//!
//! ```text
//!   photos/current -> /mnt/big/2026
//!   photos/latest  -> /mnt/big/2026
//! ```
//!
//! Two links, one directory, two legitimate names for it. A global set walks
//! `/mnt/big/2026` under `current` and then **silently drops** everything under
//! `latest` — a directory the operator named, absent from the listing, with
//! nothing said. That is the same shape of loss, arrived at from the other
//! direction.
//!
//! A cycle is not "a directory seen twice". It is a directory that is **its own
//! ancestor**: following it re-enters a path the walk is already inside. So what
//! is tracked is the chain from the root to the directory being walked, and a
//! link is refused only when its target is already somewhere on that chain. Two
//! links to one tree copy it twice — a cost the operator sees in the report and
//! in the byte count, not a loss they discover on restore day. rclone reaches the
//! same outcome by a cheaper route, letting the kernel's `ELOOP` stop the
//! descent; that stops at the forty-link limit rather than at the first
//! repetition, and says nothing about which link did it.
//!
//! # What identifies a directory
//!
//! On Unix, `(st_dev, st_ino)` — the same measurement
//! [`crate::local::root`] uses to tell a renamed store from a replacement, and
//! the only one that sees through a bind mount, where two canonical paths name
//! one directory. Where that pair is not available — every non-Unix target, and
//! SFTP, whose version-3 attribute set carries no inode — the canonical path
//! stands in. That is weaker against bind mounts and exact against everything
//! else, and it is stated rather than implied.
//!
//! # Cost
//!
//! One `Arc` per stack entry and one chain node per directory of depth, shared
//! between siblings. The chain is walked to answer a membership question, which
//! is O(depth) — tens of comparisons on any real tree, and paid only for links,
//! only when a policy that follows is in force. A walk that follows nothing
//! builds no chain at all.

use std::path::Path;
use std::sync::Arc;

/// What a directory is, as far as the backend can tell one from another.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DirId {
    /// A Unix `(st_dev, st_ino)` pair, packed. Exact: survives renames, sees
    /// through bind mounts, and is not reused while the directory exists.
    Inode(u128),
    /// A canonical path, for the targets that expose no inode. Exact except
    /// where two paths are made to name one directory by the mount table.
    Path(String),
}

/// The identity of a local directory, however well this platform can express it.
///
/// Takes metadata the caller already has rather than fetching its own, for two
/// reasons. It keeps this module free of I/O, so the rule is assertable without
/// a filesystem; and it keeps the walk's `stat` count at one per directory
/// instead of two, on the path where every extra syscall is multiplied by the
/// size of the tree.
///
/// That metadata must come from a call that **follows** links — `metadata`, not
/// `symlink_metadata`. The question is what the link leads to, and a link's own
/// inode would make every link look like a different place from the directory it
/// names, which is exactly the comparison that has to succeed for a cycle to be
/// caught.
#[must_use]
pub fn local_dir_id(meta: &std::fs::Metadata, path: &Path) -> DirId {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let _ = path;
        DirId::Inode((u128::from(meta.dev()) << 64) | u128::from(meta.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        DirId::Path(
            std::fs::canonicalize(path)
                .unwrap_or_else(|_| path.to_path_buf())
                .to_string_lossy()
                .into_owned(),
        )
    }
}

/// The chain of directories from the walk root down to the one being read.
///
/// Immutable and shared: a directory with four hundred subdirectories pushes
/// four hundred stack entries that all point at one chain node, so the memory is
/// O(depth) and not O(entries).
#[derive(Debug)]
pub struct Ancestors {
    id: DirId,
    parent: Option<Arc<Self>>,
}

impl Ancestors {
    /// The chain holding only the walk root.
    #[must_use]
    pub fn root(id: DirId) -> Arc<Self> {
        Arc::new(Self { id, parent: None })
    }

    /// This chain extended by one directory.
    #[must_use]
    pub fn child(self: &Arc<Self>, id: DirId) -> Arc<Self> {
        Arc::new(Self {
            id,
            parent: Some(Arc::clone(self)),
        })
    }

    /// What this node stands for.
    ///
    /// Exposed because a backend whose identities are canonical paths builds the
    /// next one from the last: an ordinary subdirectory's path is its parent's
    /// plus its own name, which saves a `realpath` round trip per directory on a
    /// walk that already makes too many of them.
    #[must_use]
    pub const fn id(&self) -> &DirId {
        &self.id
    }

    /// Whether `id` is already on the path from the root to here.
    ///
    /// `true` is the answer that stops a walk: descending would re-enter a
    /// directory it has not yet left.
    #[must_use]
    pub fn contains(&self, id: &DirId) -> bool {
        let mut here = Some(self);
        while let Some(node) = here {
            if node.id == *id {
                return true;
            }
            here = node.parent.as_deref();
        }
        false
    }

    /// How many directories deep this chain is, counting the root as one.
    #[must_use]
    pub fn depth(&self) -> usize {
        let mut depth = 0;
        let mut here = Some(self);
        while let Some(node) = here {
            depth += 1;
            here = node.parent.as_deref();
        }
        depth
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u128) -> DirId {
        DirId::Inode(n)
    }

    #[test]
    fn a_chain_contains_every_directory_above_it() {
        let root = Ancestors::root(id(1));
        let mid = root.child(id(2));
        let leaf = mid.child(id(3));

        for known in [1, 2, 3] {
            assert!(leaf.contains(&id(known)), "{known} is an ancestor");
        }
        assert_eq!(leaf.depth(), 3);
    }

    #[test]
    fn a_sibling_is_not_an_ancestor() {
        // The property the global-set implementation gets wrong: two branches
        // of one tree are unrelated, and a link from one into the other is not
        // a cycle. Refusing it would drop a directory the operator named.
        let root = Ancestors::root(id(1));
        let left = root.child(id(2));
        let right = root.child(id(3));

        assert!(!left.contains(&id(3)));
        assert!(!right.contains(&id(2)));
    }

    #[test]
    fn a_directory_that_is_its_own_ancestor_is_caught() {
        // `inner/loop -> .` — the walk is inside the very directory the link
        // names, so following it would never finish.
        let root = Ancestors::root(id(1));
        let inner = root.child(id(2));
        assert!(inner.contains(&id(1)));
    }

    #[test]
    fn two_paths_that_are_one_directory_compare_equal() {
        // Identity, not spelling: `DirId` is what makes `/srv/data` and
        // `/mnt/bigdisk/data` the same place when one is a link to the other.
        assert_eq!(id(7), id(7));
        assert_ne!(id(7), id(8));
        assert_ne!(id(7), DirId::Path("/srv".into()));
    }

    #[test]
    fn a_real_directory_and_a_link_to_it_have_one_identity() {
        // The measurement itself, which the pure tests above cannot check: a
        // link and its target must resolve to the same `DirId` or no cycle is
        // ever detected.
        let temp = tempfile::TempDir::new().unwrap();
        let real = temp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = temp.path().join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        #[cfg(not(unix))]
        std::os::windows::fs::symlink_dir(&real, &link).unwrap();

        let of = |path: &Path| local_dir_id(&std::fs::metadata(path).unwrap(), path);
        assert_eq!(of(&real), of(&link));

        let other = temp.path().join("other");
        std::fs::create_dir(&other).unwrap();
        assert_ne!(of(&real), of(&other));
    }
}
