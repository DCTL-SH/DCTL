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
//! That is the forbidden class of `PLAN.md` §6 in its purest form: work reported
//! as done that did not happen. It is the write-side twin of the read-side
//! defect `HANDOVER.md` §11.2 records — an unmounted volume listing as an empty
//! backup — which [`crate::local::LocalFs`]'s caller guards with
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
//! is `HANDOVER.md` §11.3's business, not this module's.

use std::path::Path;

use crate::error::StoreError;

/// What a directory is, as far as this platform can tell one from another.
///
/// Opaque on purpose: nothing outside this module should read the number, only
/// compare two of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RootId(u128);

/// The identity of `root` now, or [`None`] if there is nothing there.
///
/// On Unix this is the device and inode pair, which survives a rename and is not
/// reused by a directory created in the same place. Elsewhere it degrades to
/// "something is there", which still catches the removal half of the defect and
/// is stated rather than implied — a silent partial answer here would be the
/// same shape of problem the module exists to remove.
pub(super) fn identify(root: &Path) -> Option<RootId> {
    let meta = std::fs::metadata(root).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Some(RootId(
            (u128::from(meta.dev()) << 64) | u128::from(meta.ino()),
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        Some(RootId(0))
    }
}

/// What became of the root between construction and now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Write. Either the root is the one this backend opened, or there was none
    /// to open and creating it is the caller's ordinary first write.
    Proceed,
    /// The root existed and is gone.
    Gone,
    /// The root existed and a *different* directory now stands in its place.
    Replaced,
}

/// Compare a recorded identity with a current one.
///
/// Pure, and that is what makes the rule assertable without arranging a
/// filesystem for every case: the three outcomes are a function of two
/// `Option<RootId>`s and nothing else.
pub(super) const fn verdict(recorded: Option<RootId>, now: Option<RootId>) -> Verdict {
    match (recorded, now) {
        // Nothing was there to be lost. A first write creates the root.
        (None, _) => Verdict::Proceed,
        (Some(_), None) => Verdict::Gone,
        (Some(before), Some(after)) => {
            if before.0 == after.0 {
                Verdict::Proceed
            } else {
                Verdict::Replaced
            }
        }
    }
}

/// The error a caller reports, naming the root and what happened to it.
///
/// Says what the run must not be allowed to believe — that the objects are
/// where they were asked to go — rather than only what the filesystem returned.
pub(super) fn refuse(root: &Path, verdict: Verdict) -> StoreError {
    let what = match verdict {
        Verdict::Gone => "has been removed",
        Verdict::Replaced => "has been replaced by a different directory",
        // Never constructed: `check` only calls this on a refusal.
        Verdict::Proceed => "changed",
    };
    StoreError::RootChanged {
        root: root.display().to_string(),
        detail: what,
    }
}

/// Refuse the write if `root` is no longer the directory it was.
pub(super) fn check(root: &Path, recorded: Option<RootId>) -> Result<(), StoreError> {
    match verdict(recorded, identify(root)) {
        Verdict::Proceed => Ok(()),
        other => Err(refuse(root, other)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn a_root_that_never_existed_admits_the_write_that_creates_it() {
        // `dctl config create backup local path=/srv/new` names a directory that
        // does not exist yet, and the first copy through it must still work. A
        // guard that refused here would break the ordinary case to catch the
        // rare one.
        assert_eq!(verdict(None, None), Verdict::Proceed);
        assert_eq!(verdict(None, Some(RootId(7))), Verdict::Proceed);
    }

    #[test]
    fn the_same_root_admits_the_write() {
        assert_eq!(verdict(Some(RootId(7)), Some(RootId(7))), Verdict::Proceed);
    }

    #[test]
    fn a_root_that_was_there_and_is_not_is_refused() {
        assert_eq!(verdict(Some(RootId(7)), None), Verdict::Gone);
    }

    #[test]
    fn a_root_replaced_by_a_different_directory_is_refused() {
        // The case `create_dir_all` creates and the reason existence is not
        // enough: something *is* at the path, and it is not the store.
        assert_eq!(verdict(Some(RootId(7)), Some(RootId(8))), Verdict::Replaced);
    }

    #[test]
    fn the_refusal_names_the_root_and_says_which_of_the_two_happened() {
        let gone = refuse(Path::new("/srv/vault"), Verdict::Gone);
        let text = gone.to_string();
        assert!(text.contains("/srv/vault"), "{text}");
        assert!(text.contains("removed"), "{text}");

        let replaced = refuse(Path::new("/srv/vault"), Verdict::Replaced);
        assert!(replaced.to_string().contains("replaced"));
    }

    #[test]
    fn a_real_directory_identifies_as_itself_and_a_replacement_does_not() {
        // The half `verdict` cannot answer: that `identify` really distinguishes
        // a renamed directory from one created in its place. Without this the
        // pure tests above would pass over a function that returned a constant.
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("store");
        std::fs::create_dir(&root).unwrap();

        let recorded = identify(&root);
        assert!(recorded.is_some());
        assert!(check(&root, recorded).is_ok());

        // Renamed away: nothing is there.
        std::fs::rename(&root, temp.path().join("store-moved")).unwrap();
        assert_eq!(verdict(recorded, identify(&root)), Verdict::Gone);

        // …and the directory that `create_dir_all` would put back is a
        // different one, which is the case a bare existence check would miss.
        std::fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        assert_eq!(verdict(recorded, identify(&root)), Verdict::Replaced);
        #[cfg(unix)]
        assert!(check(&root, recorded).is_err());
    }
}
