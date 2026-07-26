//! Checking the directory a mount would be attached to.
//!
//! These checks run *now*, in a build that cannot mount anything, and that is
//! deliberate. Every one of them is a problem the user has to fix before phase 2
//! is of any use to them, and finding out today costs a command; finding out on
//! the day the feature lands costs a support conversation.
//!
//! Three rules, and the reasoning for each:
//!
//! * **The mountpoint must exist.** FUSE, FSKit and WinFSP all attach to an
//!   existing directory; none of them creates one. DCTL does not create it
//!   either — a typo in a path would otherwise leave a stray directory behind
//!   and mount an encrypted vault somewhere nobody meant.
//! * **It must be a directory.** Attaching to a file is not a thing any of the
//!   three can do.
//! * **It must be empty.** A mount *hides* whatever is underneath it: the files
//!   are not deleted, but they are invisible and unreachable until the
//!   filesystem is detached, and a backup that runs while a mount is up would
//!   see them as missing. Linux FUSE refuses this outright without `nonempty`,
//!   and DCTL refuses it everywhere so the rule does not change with the
//!   platform.
//!
//! Windows gets one exception, because it has a mount idiom the others do not:
//! WinFSP can attach a filesystem to an unused **drive letter** (`X:`), which by
//! definition does not exist as a directory. A drive-letter mountpoint therefore
//! skips the checks above, on Windows only.

use std::path::Path;

use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::platform::path;

/// Check that `mountpoint` could carry a filesystem.
///
/// # Errors
/// [`ExitCode::DirNotFound`] when it does not exist, and [`ExitCode::Usage`]
/// when it exists but is a file or is not empty. Both carry a hint naming the
/// fix.
pub fn validate(mountpoint: &Path) -> Result<()> {
    if is_drive_letter(mountpoint) {
        // A free drive letter is a valid WinFSP mountpoint and has no directory
        // to inspect. Elsewhere `X:` is a remote spec that reached the wrong
        // argument, which the caller has already ruled out.
        return Ok(());
    }

    let display = mountpoint.display();
    let metadata = std::fs::metadata(mountpoint).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => {
            CliError::new(ExitCode::DirNotFound, format!("'{display}' does not exist"))
                .with_hint("A mount attaches to an existing empty directory. Create it first.")
        }
        std::io::ErrorKind::PermissionDenied => CliError::new(
            ExitCode::FatalError,
            format!("'{display}' cannot be read: {error}"),
        )
        .with_hint("The mountpoint must be readable by the user running the mount."),
        _ => CliError::new(
            ExitCode::Uncategorised,
            format!("'{display}' cannot be inspected: {error}"),
        ),
    })?;

    if !metadata.is_dir() {
        return Err(CliError::usage(format!("'{display}' is not a directory"))
            .with_hint("A filesystem attaches to a directory. Name an empty one, or create it."));
    }

    let entries = std::fs::read_dir(mountpoint)
        .map_err(|error| {
            CliError::new(
                ExitCode::Uncategorised,
                format!("'{display}' cannot be listed: {error}"),
            )
        })?
        .filter_map(std::result::Result::ok)
        .count();

    if entries > 0 {
        return Err(
            CliError::usage(format!("'{display}' is not empty ({entries} entries)")).with_hint(
                "A mount hides whatever is already in the directory until it is \
                 unmounted — the files are not lost, but nothing can reach them, \
                 including a backup run while the mount is up. Use an empty \
                 directory.",
            ),
        );
    }

    Ok(())
}

/// Whether this mountpoint is a bare Windows drive letter such as `X:`.
///
/// True only on Windows: the same string on Linux or macOS is a relative path
/// with a colon in it, not a drive, and treating it as one would skip the checks
/// on a platform that needs them.
#[must_use]
fn is_drive_letter(mountpoint: &Path) -> bool {
    cfg!(target_os = "windows")
        && mountpoint
            .to_str()
            .is_some_and(path::looks_like_windows_drive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn an_empty_directory_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        assert!(validate(dir.path()).is_ok());
    }

    #[test]
    fn a_missing_mountpoint_is_reported_as_a_missing_directory() {
        // Its own exit code, not the generic one: a script that creates the
        // mountpoint on demand branches on exactly this.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("not-there");
        let error = validate(&missing).unwrap_err();
        assert_eq!(error.code(), ExitCode::DirNotFound);
        assert!(error.hint().is_some());
    }

    #[test]
    fn a_file_is_not_a_mountpoint() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        fs::write(&file, b"x").unwrap();
        let error = validate(&file).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[test]
    fn a_non_empty_directory_is_refused_with_a_count() {
        // The refusal has to explain itself: "not empty" alone reads as
        // pedantry until you know the mount would hide those files.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"x").unwrap();
        fs::write(dir.path().join("b.txt"), b"x").unwrap();
        let error = validate(dir.path()).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains('2'), "{}", error.message());
        assert!(error.hint().is_some_and(|hint| hint.contains("hides")));
    }

    #[test]
    fn a_hidden_file_still_counts_as_content() {
        // macOS drops .DS_Store into directories a user has merely looked at,
        // and a mount would hide it just the same. Reporting it is honest; the
        // user can then decide to remove it.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".DS_Store"), b"x").unwrap();
        assert!(validate(dir.path()).is_err());
    }

    #[test]
    fn drive_letters_are_a_windows_only_idiom() {
        // On Windows `X:` is a legitimate WinFSP mountpoint with no directory to
        // check; everywhere else it is just a path, and skipping the checks
        // would let a bad mountpoint through on the platforms that enforce them.
        let is_windows = cfg!(target_os = "windows");
        assert_eq!(is_drive_letter(Path::new("X:")), is_windows);
        assert_eq!(is_drive_letter(Path::new(r"X:\")), is_windows);
        // Never a drive letter on any platform.
        assert!(!is_drive_letter(Path::new("/mnt/vault")));
        assert!(!is_drive_letter(Path::new("vault:")));
    }
}
