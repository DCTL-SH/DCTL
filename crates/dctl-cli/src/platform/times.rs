//! Giving a written file the modification time of whatever it was made from.
//!
//! One function, in one place, because two spellings of it would eventually
//! disagree — and the way they would disagree is that one verb preserves a
//! timestamp and another silently does not, which is invisible until an
//! incremental run re-transfers a tree nobody changed.
//!
//! ## Why the modification time and nothing else
//!
//! `touch(1)` sets the access time too, and [`crate::commands::touch`] does the
//! same because that is what it was asked for. A transfer is not: a file this
//! run has just written genuinely *was* accessed now, so claiming otherwise
//! would be a fabrication, and no comparison in the tool reads an access time.
//!
//! ## Why an unknown time is a no-op rather than an error
//!
//! [`Modified::Unknown`] means the source could not say when it last changed —
//! a plain object store reports only when the provider accepted the upload, and
//! some filesystems record nothing at all. The written file then keeps the
//! moment it was written, which is what a copy has always defaulted to and is
//! honest about being the only fact available. Every later comparison reads two
//! incomparable timestamps as "not comparable" and transfers the file again,
//! which costs bandwidth; substituting a number would cost correctness.

use std::path::Path;

use dctl_core::Modified;

use crate::error::{CliError, Result};

/// Stamp `path` with `modified`, if there is a time to stamp it with.
///
/// # Errors
/// Whatever the platform reported. A failure is a real failure rather than a
/// shrug: the caller has just written the file's contents, and a timestamp that
/// silently did not take means the next run compares it, finds it different, and
/// transfers it again — forever, with nothing on stderr to explain why.
pub async fn stamp(path: &Path, modified: Modified) -> Result<()> {
    let Some(when) = modified.resolve().and_then(system_time) else {
        return Ok(());
    };

    let file = tokio::fs::File::options()
        .write(true)
        .open(path)
        .await
        .map_err(|error| at(path, error))?;

    set_modified(file, when)
        .await
        .map_err(|error| at(path, error))?;
    Ok(())
}

/// Stamp an already-open file, without reopening it by name.
///
/// The form a durable write wants: it holds the staging file, and stamping the
/// handle rather than the path means the time lands on the inode that is about
/// to be published — never on whatever a second lookup of that name would find.
///
/// # Errors
/// Whatever the platform reported, plus a failure of the blocking task itself.
pub async fn stamp_open(file: tokio::fs::File, modified: Modified) -> Result<tokio::fs::File> {
    let Some(when) = modified.resolve().and_then(system_time) else {
        return Ok(file);
    };
    let file = set_modified(file, when).await.map_err(|error| {
        CliError::from(error).with_hint("The destination's modification time could not be set.")
    })?;
    Ok(file)
}

/// The one call that actually moves a timestamp.
///
/// On the blocking pool because Tokio wraps neither timestamp call — its
/// `File` offers `set_len` and `set_permissions` and no `set_times` — so a std
/// handle has to be reached for, and a synchronous `utimensat` on the async
/// runtime would stall every other transfer sharing that thread.
///
/// The handle is passed through rather than dropped so a caller can go on to
/// `sync_all` the same file, which is what keeps the ordering right: the time is
/// set before the sync, so the metadata the sync flushes is the metadata the
/// file is published with.
async fn set_modified(
    file: tokio::fs::File,
    when: std::time::SystemTime,
) -> std::io::Result<tokio::fs::File> {
    let file = file.into_std().await;
    let file = tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
        file.set_times(std::fs::FileTimes::new().set_modified(when))?;
        Ok(file)
    })
    .await
    .map_err(std::io::Error::other)??;
    Ok(tokio::fs::File::from_std(file))
}

/// A whole-second unix timestamp as a [`SystemTime`], including before 1970.
///
/// [`None`] for a value this platform's clock cannot represent, which keeps
/// "unrepresentable" distinguishable from "the epoch": stamping a file with 1970
/// because its real time did not fit would be an invented answer, and a file
/// dated 1970 looks older than everything and inverts `--update`. Times *before*
/// the epoch are ordinary rather than exceptional — a restored archive
/// legitimately holds them — so the negative side is a subtraction and not a
/// failure.
fn system_time(seconds: i64) -> Option<std::time::SystemTime> {
    let magnitude = std::time::Duration::from_secs(seconds.unsigned_abs());
    if seconds >= 0 {
        std::time::SystemTime::UNIX_EPOCH.checked_add(magnitude)
    } else {
        std::time::SystemTime::UNIX_EPOCH.checked_sub(magnitude)
    }
}

/// Attach the offending path to a platform failure.
fn at(path: &Path, error: std::io::Error) -> CliError {
    CliError::from(error).with_hint(format!(
        "setting the modification time of {}",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The modification time of `path`, in whole seconds since the epoch.
    fn modified(path: &Path) -> i64 {
        let time = std::fs::metadata(path)
            .expect("the file exists")
            .modified()
            .expect("this platform reports modification times");
        match time.duration_since(std::time::UNIX_EPOCH) {
            Ok(delta) => i64::try_from(delta.as_secs()).expect("a representable time"),
            Err(before) => -i64::try_from(before.duration().as_secs()).expect("representable"),
        }
    }

    fn written(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("out.bin");
        std::fs::write(&path, bytes).expect("the fixture");
        (dir, path)
    }

    #[tokio::test]
    async fn a_source_time_lands_on_the_file() {
        let (_dir, path) = written(b"contents");
        stamp(&path, Modified::At(1_500_000_000))
            .await
            .expect("the time is set");
        assert_eq!(modified(&path), 1_500_000_000);
    }

    #[tokio::test]
    async fn a_pre_epoch_time_is_ordinary_rather_than_an_error() {
        // A restored archive legitimately holds them, and clamping one to zero
        // would silently rewrite the fact the record exists to state.
        let (_dir, path) = written(b"old");
        stamp(&path, Modified::At(-86_400))
            .await
            .expect("a pre-epoch time is storable");
        assert_eq!(modified(&path), -86_400);
    }

    #[tokio::test]
    async fn an_unknown_time_leaves_the_file_alone_and_does_not_fail() {
        // The honest fallback: the file keeps the moment it was written, which
        // is the only fact available. Asserted as "unchanged" rather than as
        // "not an error", because a version that quietly stamped the epoch would
        // also return `Ok`.
        let (_dir, path) = written(b"unknown");
        let before = modified(&path);
        stamp(&path, Modified::Unknown)
            .await
            .expect("nothing to do is not a failure");
        assert_eq!(modified(&path), before);
    }

    #[tokio::test]
    async fn the_contents_are_never_touched() {
        // This sets a metadata field. A version that opened with `create(true)`
        // instead of `write(true)` would truncate the file it was asked to
        // stamp, which is data loss caused by a timestamp.
        let (_dir, path) = written(b"every byte of this must survive");
        stamp(&path, Modified::At(1))
            .await
            .expect("the time is set");
        assert_eq!(
            std::fs::read(&path).expect("the file"),
            b"every byte of this must survive"
        );
    }

    #[tokio::test]
    async fn a_missing_file_is_reported_rather_than_ignored() {
        // A stamp that could not be applied must not look like one that was: the
        // next run would compare a timestamp nobody set.
        let dir = tempfile::tempdir().expect("a temporary directory");
        assert!(
            stamp(&dir.path().join("absent"), Modified::At(1))
                .await
                .is_err()
        );
    }
}
