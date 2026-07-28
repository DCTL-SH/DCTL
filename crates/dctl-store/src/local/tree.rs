//! Walking a local directory tree into object keys, and saying what was passed
//! over on the way.
//!
//! Iterative rather than recursive — an explicit stack, so a deeply nested tree
//! is an input and not a stack overflow, and so no `async fn` has to box itself
//! to call itself.
//!
//! # The entry that used to disappear
//!
//! The walk this replaced asked [`tokio::fs::DirEntry::file_type`] for each
//! child and matched on *is a directory* then *is a file*. That call does not
//! traverse links, so a symlink is neither, fell past both arms, and was
//! dropped without a word — the defect [`crate::links`] documents in full.
//! Every branch below therefore ends in either a key or a
//! [`LinkVerdict`](crate::links::LinkVerdict); nothing leaves this function
//! unaccounted for.
//!
//! # What the walk costs under the default
//!
//! Nothing extra. [`LinkPolicy::Skip`] never resolves a target, never
//! canonicalises a path and never builds an ancestor chain, so a tree with no
//! links is read with exactly the syscalls it was read with before. The `stat`
//! per link, the `realpath` per link under `in-tree`, and the chain node per
//! directory are all paid only by a run that asked to follow.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::Result;
use crate::links::{
    Ancestors, LinkPolicy, LinkReport, LinkTarget, LinkVerdict, decide, local_dir_id,
};

/// One walk's findings: the keys it produced, and what it did about the links.
#[derive(Debug, Default)]
pub(super) struct Walked {
    /// Forward-slash-relative keys of every regular file the walk reached.
    pub keys: Vec<String>,
    /// Every symbolic link met, counted, with a bounded sample named.
    pub links: LinkReport,
}

/// A directory waiting to be read, with the chain of directories above it.
///
/// The chain is [`None`] whenever the policy follows nothing: with no link to
/// follow there is no cycle to close, and building it would be memory spent to
/// answer a question that cannot be asked.
struct Pending {
    path: PathBuf,
    ancestors: Option<Arc<Ancestors>>,
}

/// Walk `root` under `policy`, returning its object keys and its link report.
///
/// # Errors
/// An unreadable directory *other than a missing one* fails the walk: a listing
/// that quietly omitted a subtree it could not open would be the same misreport
/// this module exists to remove. A missing directory is an empty listing, which
/// is the ordinary answer for a prefix that holds no objects yet.
pub(super) async fn collect(root: &Path, policy: LinkPolicy) -> Result<Walked> {
    let mut walked = Walked::default();

    // Resolved once. Only `in-tree` asks where a link led, so only `in-tree`
    // pays for the answer.
    let confine = if policy.confined() {
        tokio::fs::canonicalize(root).await.ok()
    } else {
        None
    };

    let ancestors = if policy.follows() {
        match tokio::fs::metadata(root).await {
            Ok(meta) => Some(Ancestors::root(local_dir_id(&meta, root))),
            // Nothing at the root is an empty listing, handled again per
            // directory below for the subtree that vanishes mid-walk.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(walked),
            Err(error) => return Err(error.into()),
        }
    } else {
        None
    };

    let mut stack = vec![Pending {
        path: root.to_path_buf(),
        ancestors,
    }];

    while let Some(Pending {
        path: dir,
        ancestors,
    }) = stack.pop()
    {
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let Some(key) = relative_key(root, &path) else {
                continue;
            };
            // Not traversed, deliberately: this is the call that decides whether
            // an entry *is* a link, and the whole policy hangs off the answer.
            let file_type = entry.file_type().await?;

            if file_type.is_symlink() {
                follow(
                    &mut walked,
                    &mut stack,
                    policy,
                    confine.as_deref(),
                    &ancestors,
                    path,
                    key,
                )
                .await?;
            } else if file_type.is_dir() {
                stack.push(Pending {
                    ancestors: descend(&ancestors, &path).await,
                    path,
                });
            } else if file_type.is_file() {
                emit(&mut walked, key);
            }
            // Anything else — a socket, fifo or device — has no bytes a
            // transfer carries. Passing over those is rclone's behaviour too
            // (`backend/local/local.go:1298`, "Can't transfer non file/directory"),
            // and unlike a link it is not a door to a whole tree.
        }
    }

    Ok(walked)
}

/// Decide one symbolic link and act on the decision.
///
/// Split out because it is where the policy actually bites, and a reader
/// checking that every path ends in a verdict should be able to see all of them
/// at once.
async fn follow(
    walked: &mut Walked,
    stack: &mut Vec<Pending>,
    policy: LinkPolicy,
    confine: Option<&Path>,
    ancestors: &Option<Arc<Ancestors>>,
    path: PathBuf,
    key: String,
) -> Result<()> {
    if !policy.follows() {
        walked
            .links
            .observe(key, decide(policy, LinkTarget::Unread));
        return Ok(());
    }

    // `metadata` traverses, which is the point: this is the first and only look
    // behind the link, and it answers both "is there anything there" and "is it
    // a directory".
    let Ok(target) = tokio::fs::metadata(&path).await else {
        // Includes `ELOOP` from a link that points at itself, which the
        // filesystem refuses to resolve before this walk ever gets the chance.
        walked
            .links
            .observe(key, decide(policy, LinkTarget::Missing));
        return Ok(());
    };

    let landed = match confine {
        None => LinkTarget::Inside,
        Some(base) => match tokio::fs::canonicalize(&path).await {
            Ok(resolved) if resolved.starts_with(base) => LinkTarget::Inside,
            Ok(_) => LinkTarget::Outside,
            Err(_) => LinkTarget::Missing,
        },
    };

    let verdict = decide(policy, landed);
    if !verdict.followed() {
        walked.links.observe(key, verdict);
        return Ok(());
    }

    if target.is_dir() {
        let id = local_dir_id(&target, &path);
        if ancestors.as_ref().is_some_and(|chain| chain.contains(&id)) {
            // Following would re-enter a directory the walk has not left. See
            // `links::cycle` for why this is the ancestor chain and not every
            // directory the walk has ever seen.
            walked.links.observe(key, LinkVerdict::Cycle);
            return Ok(());
        }
        walked.links.observe(key, LinkVerdict::Followed);
        stack.push(Pending {
            ancestors: ancestors.as_ref().map(|chain| chain.child(id)),
            path,
        });
    } else if target.is_file() {
        walked.links.observe(key.clone(), LinkVerdict::Followed);
        emit(walked, key);
    } else {
        walked.links.observe(key, LinkVerdict::NotStorable);
    }
    Ok(())
}

/// The ancestor chain for a subdirectory, or [`None`] when none is being kept.
///
/// A directory that cannot be stat'd keeps its parent's chain rather than
/// dropping out of it: the cycle guard's failure mode has to be walking a
/// directory once too often, never refusing one that is genuinely new.
async fn descend(ancestors: &Option<Arc<Ancestors>>, path: &Path) -> Option<Arc<Ancestors>> {
    let chain = ancestors.as_ref()?;
    match tokio::fs::metadata(path).await {
        Ok(meta) => Some(chain.child(local_dir_id(&meta, path))),
        Err(_) => Some(Arc::clone(chain)),
    }
}

/// Add one file's key, unless it is an uncommitted write.
///
/// One rule, one implementation, in [`crate::staging`]: a prefix test on the
/// file's own name. It is applied here and not at each of the three call sites,
/// so a followed link and an ordinary file cannot come to disagree about what a
/// staging file is — the substring test this replaced hid `report.tmp.2024.csv`
/// from every listing, and `copy` said `Files: 5 / 5, Errors: 0` and left it
/// behind.
fn emit(walked: &mut Walked, key: String) {
    if let Some(name) = key.rsplit('/').next()
        && crate::staging::is_staging_name(name)
    {
        return;
    }
    walked.keys.push(key);
}

/// A path's key relative to the walk root: forward slashes, no leading
/// separator. [`None`] for a path that is not under the root at all, which
/// nothing here can produce and which is refused rather than guessed at.
fn relative_key(root: &Path, path: &Path) -> Option<String> {
    Some(
        path.strip_prefix(root)
            .ok()?
            .to_string_lossy()
            .replace('\\', "/"),
    )
}

// Every case below arranges a symbolic link, and `std::os::unix::fs::symlink`
// is the only spelling that creates one without asking whether the target is a
// file or a directory. The rules themselves are platform-neutral and are
// asserted as such in `crate::links`; what is proved here is that this walk
// applies them to a real filesystem.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// `/srv` with the data on another volume, linked into place — the layout
    /// the whole feature exists for.
    fn canonical_layout() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::TempDir::new().unwrap();
        let bigdisk = temp.path().join("mnt/bigdisk/data");
        std::fs::create_dir_all(bigdisk.join("nested")).unwrap();
        std::fs::write(bigdisk.join("report.csv"), b"rows").unwrap();
        std::fs::write(bigdisk.join("nested/deep.txt"), b"deep").unwrap();

        let srv = temp.path().join("srv");
        std::fs::create_dir_all(&srv).unwrap();
        std::fs::write(srv.join("readme.txt"), b"local").unwrap();
        std::os::unix::fs::symlink(&bigdisk, srv.join("data")).unwrap();
        (temp, srv)
    }

    async fn walk(root: &Path, policy: LinkPolicy) -> Walked {
        let mut walked = collect(root, policy).await.unwrap();
        walked.keys.sort();
        walked
    }

    #[tokio::test]
    async fn the_canonical_layout_is_named_rather_than_dropped() {
        // The defect itself: `/srv/data -> /mnt/bigdisk/data` used to vanish
        // from the listing with nothing said, so `copy` stored `readme.txt`
        // alone and exited 0.
        let (_temp, srv) = canonical_layout();
        let walked = walk(&srv, LinkPolicy::Skip).await;

        assert_eq!(walked.keys, ["readme.txt"]);
        assert_eq!(walked.links.skipped(), 1);
        assert_eq!(walked.links.notes()[0].path, "data");
        assert_eq!(walked.links.notes()[0].verdict, LinkVerdict::NotFollowed);
    }

    #[tokio::test]
    async fn the_canonical_layout_is_stored_when_asked_for() {
        let (_temp, srv) = canonical_layout();
        let walked = walk(&srv, LinkPolicy::Follow).await;

        assert_eq!(
            walked.keys,
            ["data/nested/deep.txt", "data/report.csv", "readme.txt"]
        );
        assert_eq!(walked.links.followed(), 1);
        assert_eq!(walked.links.skipped(), 0);
    }

    #[tokio::test]
    async fn a_tree_with_no_links_reports_nothing_about_them() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::write(temp.path().join("a.txt"), b"a").unwrap();
        for policy in [LinkPolicy::Skip, LinkPolicy::Follow, LinkPolicy::InTree] {
            let walked = walk(temp.path(), policy).await;
            assert_eq!(walked.keys, ["a.txt"]);
            assert!(walked.links.is_empty(), "{policy} invented a link");
        }
    }

    #[tokio::test]
    async fn a_link_to_a_file_is_stored_under_the_links_own_name() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::write(temp.path().join("real.txt"), b"bytes").unwrap();
        std::os::unix::fs::symlink(temp.path().join("real.txt"), temp.path().join("alias.txt"))
            .unwrap();

        let walked = walk(temp.path(), LinkPolicy::Follow).await;
        assert_eq!(walked.keys, ["alias.txt", "real.txt"]);
        assert_eq!(walked.links.followed(), 1);
    }

    #[tokio::test]
    async fn a_cycle_terminates_and_names_the_link_that_closed_it() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        std::fs::create_dir(root.join("inner")).unwrap();
        std::fs::write(root.join("inner/a.txt"), b"a").unwrap();
        std::os::unix::fs::symlink(root, root.join("inner/loop")).unwrap();

        let walked = walk(root, LinkPolicy::Follow).await;
        assert_eq!(walked.keys, ["inner/a.txt"]);
        assert_eq!(walked.links.skipped(), 1);
        assert_eq!(walked.links.notes()[0].verdict, LinkVerdict::Cycle);
        assert_eq!(walked.links.notes()[0].path, "inner/loop");
    }

    #[tokio::test]
    async fn a_link_to_itself_is_broken_rather_than_a_hang() {
        // The kernel refuses to resolve it (`ELOOP`) before the walk can, so it
        // arrives as an unreadable target and must be reported as one.
        let temp = tempfile::TempDir::new().unwrap();
        std::os::unix::fs::symlink(temp.path().join("ouroboros"), temp.path().join("ouroboros"))
            .unwrap();

        let walked = walk(temp.path(), LinkPolicy::Follow).await;
        assert!(walked.keys.is_empty());
        assert_eq!(walked.links.broken(), 1);
    }

    #[tokio::test]
    async fn two_links_to_one_tree_are_both_walked() {
        // Not a cycle: two legitimate names for one directory. A global visited
        // set would drop the second, which is the silent loss all of this
        // exists to remove.
        let temp = tempfile::TempDir::new().unwrap();
        let shared = temp.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::write(shared.join("x.txt"), b"x").unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::os::unix::fs::symlink(&shared, root.join("current")).unwrap();
        std::os::unix::fs::symlink(&shared, root.join("latest")).unwrap();

        let walked = walk(&root, LinkPolicy::Follow).await;
        assert_eq!(walked.keys, ["current/x.txt", "latest/x.txt"]);
        assert_eq!(walked.links.followed(), 2);
    }

    #[tokio::test]
    async fn a_broken_link_is_counted_and_named_rather_than_stopping_the_walk() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::write(temp.path().join("good.txt"), b"g").unwrap();
        std::os::unix::fs::symlink(temp.path().join("gone.txt"), temp.path().join("stale.txt"))
            .unwrap();

        let walked = walk(temp.path(), LinkPolicy::Follow).await;
        assert_eq!(walked.keys, ["good.txt"], "the other files still arrive");
        assert_eq!(walked.links.broken(), 1);
        assert_eq!(walked.links.notes()[0].path, "stale.txt");
        assert_eq!(walked.links.notes()[0].verdict, LinkVerdict::Broken);
    }

    #[tokio::test]
    async fn a_link_out_of_the_tree_is_followed_or_refused_by_policy() {
        let temp = tempfile::TempDir::new().unwrap();
        let outside = temp.path().join("etc");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("passwd"), b"root:x").unwrap();
        let root = temp.path().join("srv");
        std::fs::create_dir(&root).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("etc")).unwrap();

        let followed = walk(&root, LinkPolicy::Follow).await;
        assert_eq!(followed.keys, ["etc/passwd"]);
        assert_eq!(followed.links.followed(), 1);

        let confined = walk(&root, LinkPolicy::InTree).await;
        assert!(confined.keys.is_empty());
        assert_eq!(confined.links.notes()[0].verdict, LinkVerdict::OutOfTree);
    }

    #[tokio::test]
    async fn a_link_inside_the_tree_is_followed_under_in_tree() {
        // The other half: `in-tree` is a confinement, not a refusal to follow.
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        std::fs::create_dir(root.join("real")).unwrap();
        std::fs::write(root.join("real/a.txt"), b"a").unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("alias")).unwrap();

        let walked = walk(root, LinkPolicy::InTree).await;
        assert_eq!(walked.keys, ["alias/a.txt", "real/a.txt"]);
        assert_eq!(walked.links.followed(), 1);
    }

    #[tokio::test]
    async fn nested_links_resolve_through_each_other() {
        // A link to a directory that itself holds a link to a file elsewhere.
        let temp = tempfile::TempDir::new().unwrap();
        let store = temp.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join("payload.bin"), b"p").unwrap();

        let middle = temp.path().join("middle");
        std::fs::create_dir(&middle).unwrap();
        std::os::unix::fs::symlink(store.join("payload.bin"), middle.join("payload.bin")).unwrap();

        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::os::unix::fs::symlink(&middle, root.join("via")).unwrap();

        let walked = walk(&root, LinkPolicy::Follow).await;
        assert_eq!(walked.keys, ["via/payload.bin"]);
        assert_eq!(walked.links.followed(), 2, "both links were resolved");
    }

    #[tokio::test]
    async fn a_link_to_a_socket_is_reported_as_unstorable_rather_than_dropped() {
        // Nothing to carry, and nothing hidden either.
        let temp = tempfile::TempDir::new().unwrap();
        let fifo = temp.path().join("pipe");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if !made {
            return; // no mkfifo on this host; the pure decision is covered above
        }
        std::os::unix::fs::symlink(&fifo, temp.path().join("alias")).unwrap();

        let walked = walk(temp.path(), LinkPolicy::Follow).await;
        assert!(walked.keys.is_empty());
        assert_eq!(walked.links.skipped(), 1);
        assert_eq!(
            walked
                .links
                .notes()
                .iter()
                .find(|note| note.path == "alias")
                .map(|note| note.verdict),
            Some(LinkVerdict::NotStorable)
        );
    }

    #[tokio::test]
    async fn a_missing_root_lists_empty_under_every_policy() {
        let temp = tempfile::TempDir::new().unwrap();
        let missing = temp.path().join("never-made");
        for policy in [LinkPolicy::Skip, LinkPolicy::Follow, LinkPolicy::InTree] {
            let walked = walk(&missing, policy).await;
            assert!(walked.keys.is_empty(), "{policy}");
            assert!(walked.links.is_empty(), "{policy}");
        }
    }

    #[tokio::test]
    async fn an_in_flight_write_is_never_a_key_however_it_is_reached() {
        // One staging rule for a plain file and for a link that resolves to one.
        let temp = tempfile::TempDir::new().unwrap();
        let staging = format!("{}999.1", crate::staging::STAGING_NAME_PREFIX);
        std::fs::write(temp.path().join(&staging), b"half").unwrap();
        std::fs::write(temp.path().join("real.txt"), b"whole").unwrap();
        std::os::unix::fs::symlink(
            temp.path().join("real.txt"),
            temp.path().join(format!("{staging}.link")),
        )
        .unwrap();

        let walked = walk(temp.path(), LinkPolicy::Follow).await;
        assert_eq!(walked.keys, ["real.txt"]);
    }
}
