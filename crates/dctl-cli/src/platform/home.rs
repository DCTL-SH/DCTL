//! Creating directories under DCTL's home, closed to everyone but their owner.
//!
//! `~/.dctl` is the whole of what DCTL writes on a client machine — the
//! configuration, the encrypted indexes, the audit chain, the logs — and
//! `dctl_meta::paths::HOME_DIR_MODE` declares it owner-only. It was not:
//! measured on a real machine, `~/.dctl` and `~/.dctl/index` were both `0755`,
//! world-readable.
//!
//! The reason is an ordering one, and it is why this module exists rather than
//! a `set_permissions` call at each site. Two writers already hardened what
//! they created — the configuration saver and the audit writer — but on a
//! fresh machine neither of them gets there first. The *index* does:
//! `dctl init` opens a database before it writes a config, and the index's
//! directory creation was a bare `create_dir_all`, which takes the process
//! umask. So the home directory was made by the one writer that did not close
//! it, and every writer after it found it already existing and left it alone.
//!
//! What is protected by the mode is not the file contents — the index is
//! encrypted and the audit chain is public-by-design — but the **names**: which
//! remotes exist, which buckets they point at, which vaults this machine can
//! reach. `dctl_meta::paths` says exactly that where it declares the mode.
//!
//! ## Only what we create
//!
//! Both existing writers harden a directory only when they are the ones who
//! brought it into existence, and this keeps that rule. An operator who points
//! `--index /srv/shared/dctl.redb` at a directory they already had should not
//! find it chmodded to `0700` as a side effect of opening a database. So the
//! missing ancestors are collected *before* the create and only those are
//! closed.

use std::path::{Path, PathBuf};

use crate::error::Result;

/// The directories on `path`'s chain that do not exist yet, outermost first.
///
/// Sampled before a `create_dir_all` so the caller can tell which directories
/// it is about to bring into existence — and therefore which it may harden.
/// A path whose ancestors all exist yields an empty list, which is the common
/// case on every run after the first.
#[must_use]
pub fn missing_ancestors(path: &Path) -> Vec<PathBuf> {
    let mut missing = Vec::new();
    let mut at = Some(path);
    while let Some(dir) = at {
        if dir.as_os_str().is_empty() || dir.exists() {
            break;
        }
        missing.push(dir.to_path_buf());
        at = dir.parent();
    }
    // Collected innermost-first by the walk up; hardening outermost-first keeps
    // a failure from leaving an inner directory closed under an open one.
    missing.reverse();
    missing
}

/// Close each of `directories` to everyone but its owner.
///
/// # Errors
/// Any failure to set the mode, with the path named. Deliberately not
/// swallowed: a directory that was meant to be owner-only and silently is not
/// is precisely the state this module exists to end.
pub fn harden_all(directories: &[PathBuf]) -> Result<()> {
    for directory in directories {
        harden(directory)?;
    }
    Ok(())
}

/// Enforce [`dctl_meta::paths::HOME_DIR_MODE`] on one directory.
///
/// A no-op on Windows, where access is an ACL rather than a mode and the
/// profile directory this lives under is already owner-only — the same
/// position the configuration saver and the audit writer take.
#[cfg(unix)]
pub fn harden(directory: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(
        directory,
        std::fs::Permissions::from_mode(dctl_meta::paths::HOME_DIR_MODE),
    )?;
    Ok(())
}

/// See the Unix definition.
#[cfg(not(unix))]
pub fn harden(_directory: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_directories_that_did_not_exist_are_reported() {
        let root = tempfile::tempdir().expect("a temporary root");
        let existing = root.path().join("already");
        std::fs::create_dir_all(&existing).expect("the existing directory");

        let target = existing.join("new/deeper");
        let missing = missing_ancestors(&target);

        assert_eq!(
            missing,
            vec![existing.join("new"), target],
            "outermost first, and never a directory the operator already had"
        );
        assert!(
            missing_ancestors(&existing).is_empty(),
            "a directory that exists is not ours to harden"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_created_home_is_closed_to_everyone_but_its_owner() {
        // The measured defect: `~/.dctl` and `~/.dctl/index` were both 0755,
        // because the index opened its database before anything wrote a config
        // and created the home with a bare `create_dir_all`.
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("a temporary root");
        let index_dir = root.path().join(".dctl/index");

        let created = missing_ancestors(&index_dir);
        std::fs::create_dir_all(&index_dir).expect("the directories");
        harden_all(&created).expect("hardening succeeds");

        for dir in [root.path().join(".dctl"), index_dir] {
            let mode = std::fs::metadata(&dir)
                .expect("the directory exists")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode,
                dctl_meta::paths::HOME_DIR_MODE,
                "{} is {mode:o}, not owner-only",
                dir.display()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_the_operator_already_had_is_left_alone() {
        // `--index /srv/shared/dctl.redb` must not chmod somebody's shared
        // directory as a side effect of opening a database.
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("a temporary root");
        let shared = root.path().join("shared");
        std::fs::create_dir_all(&shared).expect("the shared directory");
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755))
            .expect("the operator's own mode");

        let created = missing_ancestors(&shared);
        std::fs::create_dir_all(&shared).expect("already there");
        harden_all(&created).expect("nothing to harden");

        let mode = std::fs::metadata(&shared)
            .expect("still there")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755, "an existing directory keeps the mode it had");
    }
}
