//! Recognising a vault's object store on disk, without opening it.
//!
//! One question: *is there a vault at this path, or above it?* — answered from
//! the bytes that are really there, with no configuration and no key.
//!
//! It is **not** the rule that decides whether a command may write here. That is
//! [`crate::addressing`], which asks the configuration first, because what a
//! command encrypts may not depend on what a destination happens to contain.
//! This module is the *fallback* that module falls back to: for a location no
//! configured remote describes, the envelope on disk is the only evidence there
//! is, and refusing on it is better than writing plaintext into somebody's vault
//! because their config lives on another machine.
//!
//! ## The one thing an answer from here may cause
//!
//! A refusal. Nothing else. This is the only place in DCTL where a destination's
//! contents are read before a write, so it is the only place invariant I4 could
//! be broken, and the bound is what keeps it intact: a `Some` here can stop a
//! command and can never re-route one. It must never grow a caller that reads it
//! as "so seal instead" — that would be auto-detection, and would mean a user
//! who asked for a plain write got an encrypted one because of state they never
//! named. `Option<&Path>` rather than a mode is the shape that makes the wrong
//! use awkward to write.
//!
//! Deliberately cheap and key-free: it runs before any password is requested, so
//! it must answer without unlocking anything. It also expects an **already
//! resolved** path — [`crate::addressing`] resolves the destination before
//! calling, because `staging/../vault/system/envelope.bin` does not `stat` when
//! `staging` does not exist, and evidence that a spelling can hide is evidence
//! this module would report as absent.

use std::path::Path;

use crate::constants::VAULT_ENVELOPE_OBJECT_KEY;
use crate::platform::path as logical;

/// The vault directory `location` sits inside, if any.
///
/// Returned so a refusal can name the actual vault root rather than the path the
/// user happened to type — `'/srv/vault' contains a vault` is far more useful
/// than `'/srv/vault/photos/2024/raw' contains a vault` when the user is trying
/// to work out what they hit.
///
/// Walking ancestors is essential rather than thorough. Checking only the exact
/// path meant the refusal was defeated by naming any subdirectory:
/// `copy ./src ./vault` was blocked while `copy ./src ./vault/photos` wrote
/// plaintext into the vault and reported success. A guard that one extra path
/// component disables is worse than none, because it reads as protection.
#[must_use]
pub fn enclosing_vault(location: &Path) -> Option<&Path> {
    if location.as_os_str().is_empty() {
        return None;
    }
    location
        .ancestors()
        .find(|dir| logical::from_logical(dir, VAULT_ENVELOPE_OBJECT_KEY).exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory containing an envelope, plus a nested path inside it.
    fn vault_with_subdir() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let system = dir.path().join("system");
        std::fs::create_dir_all(&system).expect("system dir");
        std::fs::write(system.join("envelope.bin"), b"DKE1").expect("envelope");

        let nested = dir.path().join("photos").join("2024");
        std::fs::create_dir_all(&nested).expect("nested dirs");
        (dir, nested)
    }

    #[test]
    fn an_ordinary_directory_is_not_a_vault_store() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(enclosing_vault(dir.path()), None);
    }

    #[test]
    fn a_vault_root_is_recognised() {
        let (dir, _) = vault_with_subdir();
        assert_eq!(enclosing_vault(dir.path()), Some(dir.path()));
    }

    #[test]
    fn a_path_at_any_depth_inside_a_vault_is_recognised() {
        // The bypass this exists to close.
        let (dir, nested) = vault_with_subdir();
        assert!(enclosing_vault(&nested).is_some());
        assert!(enclosing_vault(&dir.path().join("photos")).is_some());
    }

    #[test]
    fn the_reported_vault_is_the_root_not_the_typed_path() {
        let (dir, nested) = vault_with_subdir();
        let found = enclosing_vault(&nested).expect("a vault above");
        assert_eq!(found, dir.path());
    }

    #[test]
    fn a_sibling_of_a_vault_is_untouched() {
        // The guard must not spread to directories that merely share a parent.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("vault/system")).unwrap();
        std::fs::write(dir.path().join("vault/system/envelope.bin"), b"DKE1").unwrap();
        let sibling = dir.path().join("ordinary");
        std::fs::create_dir_all(&sibling).unwrap();

        assert_eq!(enclosing_vault(&sibling), None);
    }

    #[test]
    fn an_empty_path_is_never_a_vault_store() {
        // Directions with no local side pass an empty root; it must not be
        // stat'ed, and must not resolve to the process's working directory.
        assert_eq!(enclosing_vault(Path::new("")), None);
    }
}
