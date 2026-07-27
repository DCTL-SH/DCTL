//! Resolving a path the user typed to the place it actually names.
//!
//! [`crate::platform::path`] answers "what is this file called inside a vault".
//! This module answers a different question that the addressing rule depends on
//! entirely: **two spellings, one directory — are these the same place?**
//!
//! `std::fs::canonicalize` is the obvious answer and is not sufficient, because
//! it fails outright on a path that does not exist yet — and the destination of
//! a write very often does not. `dctl copy ./src staging/../vault` names the
//! vault directory; `canonicalize` refuses the whole path because `staging` is
//! missing, the addressing check then compared the raw string against the
//! configured one, missed, and wrote plaintext into a configured vault's object
//! store. One spelling refused, another permitted, same command, same
//! configuration. That is precisely the state-dependence invariant I4 forbids,
//! arriving through path syntax rather than through directory contents.
//!
//! So resolution here is **best-effort and total**: it always produces an
//! answer, resolving as much as the filesystem can confirm and normalising the
//! rest lexically.
//!
//! ## Why `..` is resolved against the filesystem, not the string
//!
//! `a/link/..` is `a` only when `link` is a real directory. When it is a symlink
//! the kernel resolves the link first, so the parent is the *target's* parent
//! and may be nowhere near `a`. A purely lexical normaliser gets that wrong in
//! the one direction that matters — it would claim a destination is outside a
//! vault when the kernel is about to put it inside one.
//!
//! Hence the walk below resolves the accumulated prefix after **every** existing
//! component, not merely once at the end. Resolving only the whole path is what
//! `canonicalize` already does, and it gives up entirely the moment any
//! component is missing — so `vault-link/newdir` would keep the link unresolved
//! and answer that it is nowhere near the vault it is a link to. Components that
//! do not exist yet cannot be symlinks, so normalising those lexically is not an
//! approximation: it is the same answer the kernel will give once they are
//! created.
//!
//! ## What it deliberately is not
//!
//! Not a security boundary and not a TOCTOU-free operation: a symlink can be
//! swapped between this call and the write it guards. It is a *naming* function.
//! The guarantee it underwrites is that DCTL's answer does not depend on which
//! of several equivalent spellings an operator typed — not that a hostile local
//! user cannot move a directory mid-command, which no userspace check can
//! promise.

use std::path::{Component, Path, PathBuf};

use crate::constants::PATH_SYMLINK_RESOLUTION_LIMIT;

/// The place `path` names, resolved as far as the filesystem can confirm.
///
/// `None` only for the empty path, which is how the transfer engine spells "this
/// direction has no local side": it must not be stat'ed and must not silently
/// become the process's working directory.
///
/// A relative path is taken against the current directory, because that is what
/// the command that typed it meant. If the current directory cannot be read the
/// path is resolved as far as it can be and returned relative, which degrades to
/// exactly the old string comparison rather than to a wrong answer.
#[must_use]
pub fn real_path(path: &Path) -> Option<PathBuf> {
    if path.as_os_str().is_empty() {
        return None;
    }
    Some(walk(path, PATH_SYMLINK_RESOLUTION_LIMIT))
}

/// One pass over `path`'s components, with `budget` symlink hops left to spend.
fn walk(path: &Path, budget: usize) -> PathBuf {
    let mut real = if path.is_absolute() {
        PathBuf::new()
    } else {
        // Canonicalised, because `getcwd` on macOS can hand back a path through
        // `/tmp`, which is a symlink to `/private/tmp`. Comparing a destination
        // resolved through one against a configured remote resolved through the
        // other would make the two disagree about a single directory.
        std::env::current_dir()
            .map(|cwd| cwd.canonicalize().unwrap_or(cwd))
            .unwrap_or_default()
    };

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => real.push(prefix.as_os_str()),
            Component::RootDir => real.push(Component::RootDir.as_os_str()),
            // `.` names the directory it sits in, so it contributes nothing.
            Component::CurDir => {}
            Component::ParentDir => {
                // Resolved before popping: see the module docs on why a lexical
                // pop is the wrong answer after a symlink.
                resolve_in_place(&mut real, budget);
                // `pop` on a root is a no-op, which is the right reading of
                // `/..` and stops the walk climbing out of the filesystem.
                real.pop();
            }
            Component::Normal(name) => {
                real.push(name);
                // Every component, because a link partway along a path is
                // exactly as much a link as one at its end.
                resolve_in_place(&mut real, budget);
            }
        }
    }

    real
}

/// Replace `path` with what the filesystem says it really is, if it can say.
///
/// A failure is the ordinary case rather than an error: the tail of a
/// destination usually does not exist yet, and leaving those components as
/// spelled is the correct prediction of where they will be created.
///
/// The second attempt is what makes this total. `canonicalize` fails on a
/// **dangling** symlink — one whose target has not been created, or has been
/// removed — and returning the link's own path there would be the one wrong
/// answer available: the kernel is about to create the *target*, so a
/// destination that resolves nowhere near a vault would be written straight into
/// one. `read_link` still works on a dangling link, so the target is followed by
/// hand, within [`PATH_SYMLINK_RESOLUTION_LIMIT`] hops so a cycle terminates.
fn resolve_in_place(path: &mut PathBuf, budget: usize) {
    if let Ok(real) = path.canonicalize() {
        *path = real;
        return;
    }

    let Some(remaining) = budget.checked_sub(1) else {
        // Out of hops. Whatever this is, the kernel would refuse it too.
        return;
    };

    let Ok(target) = std::fs::read_link(&*path) else {
        // Not a link at all: a component that simply does not exist yet, which
        // is the ordinary case for the tail of a destination.
        return;
    };

    // A relative link target is relative to the directory holding the link, not
    // to the process's working directory — and that directory is already
    // resolved, because this walk resolves as it goes.
    let followed = if target.is_absolute() {
        target
    } else {
        path.parent().unwrap_or(Path::new("")).join(target)
    };

    // Re-walked rather than pushed, because a link's target has components of
    // its own: `.`, `..`, and further links.
    *path = walk(&followed, remaining);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory tree with a real subdirectory and a symlink to it.
    fn tree() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        // The temporary directory itself may be reached through a symlink
        // (`/tmp` on macOS), so every expectation is stated against its own
        // resolved form rather than against the path `tempfile` handed back.
        let root = dir.path().canonicalize().expect("a resolvable root");
        std::fs::create_dir_all(root.join("vault/system")).expect("vault dirs");
        (dir, root)
    }

    #[test]
    fn an_empty_path_resolves_to_nothing() {
        // Not to the working directory, which is the failure this guards: a
        // direction with no local side would otherwise claim the place the
        // operator happens to be standing in.
        assert_eq!(real_path(Path::new("")), None);
    }

    #[test]
    fn a_path_that_exists_resolves_to_itself() {
        let (_dir, root) = tree();
        assert_eq!(
            real_path(&root.join("vault")).as_deref(),
            Some(root.join("vault").as_path())
        );
    }

    #[test]
    fn a_dot_dot_that_walks_through_a_real_directory_is_resolved() {
        // The spelling that defeated the old check. `staging` does not exist, so
        // `canonicalize` fails on the whole path and the raw string never
        // compared equal to the configured one — while the write itself landed
        // inside the vault.
        let (_dir, root) = tree();
        let typed = root.join("staging/../vault");
        assert_eq!(
            real_path(&typed).as_deref(),
            Some(root.join("vault").as_path()),
            "a path that does not exist yet still names a definite place"
        );
    }

    #[test]
    fn a_leading_dot_is_not_part_of_the_place() {
        let (_dir, root) = tree();
        let typed = root.join("./vault/./system");
        assert_eq!(
            real_path(&typed).as_deref(),
            Some(root.join("vault/system").as_path())
        );
    }

    #[test]
    fn components_that_do_not_exist_yet_are_kept() {
        // A destination is usually created by the command being guarded, so
        // resolution must describe where it *will* be rather than give up.
        let (_dir, root) = tree();
        let typed = root.join("vault/photos/2024/raw");
        assert_eq!(
            real_path(&typed).as_deref(),
            Some(root.join("vault/photos/2024/raw").as_path())
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_resolves_to_its_target() {
        let (_dir, root) = tree();
        std::os::unix::fs::symlink(root.join("vault"), root.join("link")).expect("a symlink");
        assert_eq!(
            real_path(&root.join("link")).as_deref(),
            Some(root.join("vault").as_path()),
            "the link and its target are one place"
        );
        assert_eq!(
            real_path(&root.join("link/photos")).as_deref(),
            Some(root.join("vault/photos").as_path())
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_resolves_to_the_target_that_is_about_to_exist() {
        // The case `canonicalize` cannot answer at all, and the one where being
        // wrong is worst: the store directory has been deleted and a link to it
        // remains, so a write through the link re-creates the store — inside a
        // vault's namespace — while a resolver that gave up would report the
        // destination as an ordinary place.
        let (_dir, root) = tree();
        std::os::unix::fs::symlink(root.join("vault"), root.join("link")).expect("a symlink");
        std::fs::remove_dir_all(root.join("vault")).expect("remove the target");

        assert_eq!(
            real_path(&root.join("link")).as_deref(),
            Some(root.join("vault").as_path())
        );
        assert_eq!(
            real_path(&root.join("link/photos")).as_deref(),
            Some(root.join("vault/photos").as_path())
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_relative_link_target_is_taken_from_the_links_own_directory() {
        // Not from the process's working directory, which is the classic way to
        // get this wrong and would resolve a link to somewhere entirely
        // unrelated depending on where the operator happened to be standing.
        let (_dir, root) = tree();
        std::fs::create_dir_all(root.join("holder")).expect("holder");
        std::os::unix::fs::symlink("../vault", root.join("holder/link")).expect("a symlink");

        assert_eq!(
            real_path(&root.join("holder/link")).as_deref(),
            Some(root.join("vault").as_path())
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_cycle_terminates_instead_of_hanging() {
        // A cycle is representable on every filesystem, so a hand-rolled
        // follower that did not bound itself would hang the command it was
        // guarding. Any answer is acceptable here; not returning is not.
        let (_dir, root) = tree();
        std::os::unix::fs::symlink(root.join("b"), root.join("a")).expect("a -> b");
        std::os::unix::fs::symlink(root.join("a"), root.join("b")).expect("b -> a");

        assert!(real_path(&root.join("a")).is_some());
    }

    #[cfg(unix)]
    #[test]
    fn dot_dot_after_a_symlink_follows_the_target_not_the_spelling() {
        // The reason `..` is not resolved lexically. `link/..` is the *target's*
        // parent — a lexical normaliser would answer `root`, and would be wrong
        // about which directory the kernel is going to write into.
        let (_dir, root) = tree();
        std::fs::create_dir_all(root.join("outer/inner")).expect("outer dirs");
        std::os::unix::fs::symlink(root.join("outer/inner"), root.join("link")).expect("a symlink");

        assert_eq!(
            real_path(&root.join("link/..")).as_deref(),
            Some(root.join("outer").as_path())
        );
    }

    #[test]
    fn a_relative_path_is_taken_against_the_working_directory() {
        // Absolute, because a comparison against a configured absolute path is
        // the whole use: a relative answer could never match one.
        let resolved = real_path(Path::new("relative/place")).expect("a place");
        assert!(
            resolved.is_absolute(),
            "got {} — a relative answer can match no configured remote",
            resolved.display()
        );
        assert!(resolved.ends_with("relative/place"));
    }

    #[test]
    fn the_walk_never_climbs_above_the_root() {
        // `/..` is `/` to the kernel, and a resolver that popped past it would
        // produce an empty path that compares equal to nothing at all.
        let resolved = real_path(Path::new("/../../..")).expect("a place");
        assert_eq!(resolved, PathBuf::from("/"));
    }
}
