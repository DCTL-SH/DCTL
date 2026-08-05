//! Whether the directory a write is about to land in is still the directory
//! this backend was opened on.
//!
//! # The defect this exists to make impossible
//!
//! A `dctl copy` of 25 files into a vault, with the vault's object store
//! renamed away three seconds in:
//!
//! ```text
//!  Transferred: 9.54 MiB / 9.54 MiB, 100%, 2.71 MiB/s
//!     Verified: 9.54 MiB checksum-matched
//!        Files: 25 / 25
//!       Errors: 0
//! ```
//!
//! Exit 0. Every object was reported stored, verified and committed — into a
//! *new, empty directory* that [`std::fs::create_dir_all`] had helpfully created
//! at the old path, holding no `system/envelope.bin` and belonging to no vault.
//! The post-write read-back passed because it re-read the same wrong directory.
//! The next command exited 7 with "no vault at this location".
//!
//! That is the forbidden class of [the plan](https://doc.dctl.sh/project/plan) §6 in its purest form: work reported
//! as done that did not happen. It is the write-side twin of the read-side
//! defect — an unmounted volume listing as an empty backup — which
//! [`crate::local::LocalFs`]'s caller guards with
//! `Place::require_readable_tree`. Nothing guarded the write.
//!
//! # Why identity, and not existence
//!
//! Checking only that *a* directory is there would pass in exactly the case that
//! matters: `create_dir_all` puts one back. What has to be compared is whether it
//! is the **same** directory, which on Unix is the `(st_dev, st_ino)` pair —
//! renaming a directory keeps its inode, so the store moved away is
//! distinguishable from the fresh one created in its place. It is the same
//! measurement `dctl_cli::mount::detached` makes to earn the word "unmounted".
//!
//! # Why a root that was absent at construction is not an error
//!
//! `dctl config create backup local path=/srv/new` names a directory that may
//! not exist yet, and the first `copy` through it legitimately creates one. So an
//! *unrecorded* identity — nothing was there when the backend was built — admits
//! the write. Only a root that existed and has since been removed or replaced is
//! a failure. That rule has no false positives: it never refuses a write the old
//! code would have performed correctly.
//!
//! # What this does not claim
//!
//! It is a check per write, not a lock. A root that vanishes between this
//! observation and the `rename` that publishes the object is still a race the
//! filesystem owns. What it removes is the *silent* case — a whole run's worth of
//! objects written into a replacement directory and reported as success — and it
//! is `local:` only. The equivalent for a deleted bucket or a removed SFTP base
//! is the remote backends' business, not this module's.

use std::path::Path;

use crate::error::StoreError;
use crate::guard::StoreIdentity;
use crate::guard::identity::{Verdict, refuse, verdict};

/// The identity of `root` now, or [`None`] if there is nothing there.
///
/// On Unix this is the device and inode pair, which survives a rename and is
/// not reused by a directory created in the same place — so it is
/// [`StoreIdentity::distinguishing`]. Elsewhere it degrades to "something is
/// there", which still catches the removal half of the defect and is *stated*
/// rather than implied: a silent partial answer here would be the same shape of
/// problem the module exists to remove, which is why the weaker answer is
/// spelled [`StoreIdentity::existence_only`] and travels with its own strength.
#[must_use]
pub(crate) fn identify(root: &Path) -> Option<StoreIdentity> {
    let meta = std::fs::metadata(root).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Some(StoreIdentity::distinguishing(format!(
            "{}:{}",
            meta.dev(),
            meta.ino()
        )))
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        Some(StoreIdentity::existence_only())
    }
}

/// Refuse the write if `root` is no longer the directory it was.
///
/// The comparison itself is [`crate::guard::identity::verdict`], shared with the
/// backend-agnostic guard. One rule, two call sites: this one sits immediately
/// in front of each local write, and `guard::Guarded` covers every provider —
/// including this one — from above.
pub(super) fn check(root: &Path, recorded: Option<&StoreIdentity>) -> Result<(), StoreError> {
    match verdict(recorded, identify(root).as_ref()) {
        Verdict::Proceed => Ok(()),
        other => Err(refuse(&root.display().to_string(), other)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn a_real_directory_identifies_as_itself_and_a_replacement_does_not() {
        // The half a pure test cannot answer: that `identify` really
        // distinguishes a renamed directory from one created in its place.
        // Without this the rule's own tests in `guard::identity` would pass over
        // a function that returned a constant.
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("store");
        std::fs::create_dir(&root).unwrap();

        let recorded = identify(&root);
        assert!(recorded.is_some());
        assert!(check(&root, recorded.as_ref()).is_ok());

        // Renamed away: nothing is there.
        std::fs::rename(&root, temp.path().join("store-moved")).unwrap();
        assert!(identify(&root).is_none());
        assert!(check(&root, recorded.as_ref()).is_err());

        // …and the directory that `create_dir_all` would put back is a
        // different one, which is the case a bare existence check would miss.
        std::fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            assert!(identify(&root).is_some());
            let error = check(&root, recorded.as_ref()).unwrap_err();
            assert!(error.to_string().contains("replaced"), "{error}");
        }
    }

    #[test]
    fn a_root_that_never_existed_admits_the_write_that_creates_it() {
        let temp = tempfile::TempDir::new().unwrap();
        let missing = temp.path().join("not-yet");
        assert!(identify(&missing).is_none());
        assert!(check(&missing, None).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn the_local_identity_is_the_strong_kind() {
        // What `guard` reports in its log line, and what decides whether an
        // operator can trust the guard to have seen a replacement on this
        // provider.
        let temp = tempfile::TempDir::new().unwrap();
        assert_eq!(
            identify(temp.path()).map(|id| id.strength()),
            Some(crate::guard::Strength::Distinguishing)
        );
    }
}
