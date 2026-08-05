//! Durable local writes for `rcat`.
//!
//! `PLAN.md` §6 puts local destinations under the same discipline as the index:
//! *fsync the file **and** its directory before reporting success*. A stream is
//! the hardest case for that promise, because its length is unknown until it
//! ends — there is no point at which a partially written file can be told apart
//! from a complete one by looking at it.
//!
//! So nothing is ever written to the destination name. The bytes go to a hidden
//! staging file beside it, and only after the data is on stable storage is the
//! staging file renamed into place. `rename(2)` is atomic within a directory, so
//! a reader sees either the previous object or the complete new one, never a
//! half-written mixture. If anything fails — a full disk, a broken producer, a
//! Ctrl-C — the staging file is removed and the destination is untouched.
//!
//! That is the local expression of the same rule the cloud path obeys: the commit
//! is the last step, and until it happens nothing has been stored.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::commands::pipeline::at_path;
use crate::constants::STREAM_CHUNK_BYTES;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};

use super::stream;

/// Stream `reader` into `destination`, durably.
///
/// Returns the number of bytes stored, which is knowable only once the stream has
/// ended.
///
/// # Errors
/// Any failure to create, write, sync or rename. In every case the destination is
/// left exactly as it was.
pub fn store(ctx: &Ctx, destination: &Path, reader: &mut impl Read) -> Result<u64> {
    let mut staging = Staging::create(destination)?;
    let mut buffer = vec![0_u8; STREAM_CHUNK_BYTES];

    let bytes = stream::pump(ctx, reader, &mut staging.file, &mut buffer)?;
    staging.commit()?;

    Ok(bytes)
}

/// A staging file that removes itself unless it is committed.
///
/// The guard is the point: every early return between `create` and `commit` —
/// including a panic in a test build — takes the partial file with it, so a
/// failed run cannot leave litter that a later run might mistake for data.
struct Staging {
    destination: PathBuf,
    path: PathBuf,
    file: File,
    committed: bool,
}

impl Staging {
    /// Create the staging file beside its destination.
    ///
    /// Beside, rather than in the system temporary directory, for two reasons:
    /// the final step must be a rename *within one filesystem* (a cross-device
    /// rename is a copy, which is neither atomic nor free), and the destination's
    /// own directory is the one place already known to be writable if the
    /// operation is to succeed at all.
    fn create(destination: &Path) -> Result<Self> {
        let Some(_name) = destination.file_name().and_then(|name| name.to_str()) else {
            return Err(CliError::usage(format!(
                "'{}' does not name a file",
                destination.display()
            ))
            .with_hint("rcat needs a destination file name, not a directory path."));
        };

        // An existing directory or device at the destination is refused rather
        // than replaced: renaming over one would destroy something that is not an
        // object DCTL put there.
        if let Ok(metadata) = fs::metadata(destination) {
            if !metadata.is_file() {
                return Err(CliError::usage(format!(
                    "'{}' exists and is not a regular file",
                    destination.display()
                ))
                .with_hint("Choose a destination file name that rcat may create or replace."));
            }
        }

        // The directory the caller named, before anything is created inside it.
        //
        // This was missing, and it made `rcat` the one write in the workspace
        // that could not create its own destination: `printf x | dctl rcat
        // backup:2026-07-30/db.sql` exited 4 with
        // `.../2026-07-30/.dctl-staging.NNN.0: No such file or directory`, while
        // `dctl copyto file backup:2026-07-30/db.sql` — same destination, same
        // backend, same staging rule — made the tree and succeeded. Every entry
        // point in `dctl_store::local::verified_write` calls `create_dir_all`
        // first; this one reached straight for the staging sibling.
        //
        // Creating it is also what rclone does on every write rather than a
        // convenience invented here: its local backend makes the parent
        // directory before it opens the object, and `rclone rcat` goes through
        // that path.
        //
        // The shape that met the defect is the ordinary one — a nightly dump
        // piped into a dated directory — so it failed on the first night of
        // every month and left no backup.
        if let Some(parent) = destination.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| at_path(parent, error))?;
            }
        }

        // The staging name comes from `dctl_store::staging`, shared with every
        // other verified write in the workspace. A destination directory can
        // also be a configured `local:` remote, and a staging spelling the
        // backend's listing did not recognise would be enumerated as an object.
        let staging = dctl_store::staging::staging_sibling(destination);

        let file = File::create(&staging).map_err(|error| at_path(&staging, error))?;

        Ok(Self {
            destination: destination.to_path_buf(),
            path: staging,
            file,
            committed: false,
        })
    }

    /// Flush to stable storage, then publish atomically.
    fn commit(&mut self) -> Result<()> {
        // Order matters and is not negotiable: the data must be on the platter
        // before the name that promises it exists, or a crash between the two
        // leaves a complete-looking file full of nothing.
        self.file
            .sync_all()
            .map_err(|error| at_path(&self.path, error))?;

        fs::rename(&self.path, &self.destination)
            .map_err(|error| at_path(&self.destination, error))?;

        // The rename itself is a directory modification, and on POSIX it is not
        // durable until the directory is synced too.
        sync_directory(&parent_of(&self.destination))?;

        self.committed = true;
        Ok(())
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if !self.committed {
            // Best effort by necessity — a destructor has nowhere to report to.
            // Leaving the file behind would be untidy; failing to remove it can
            // never make the destination wrong, because the destination was never
            // touched.
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// The directory containing `path`, as a path that can be opened.
///
/// A bare file name has an empty parent, which is not openable; the current
/// directory is what an empty parent means.
fn parent_of(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Flush a directory entry to stable storage.
///
/// POSIX makes the rename durable only once the containing directory is synced;
/// without this a crash can lose the new name even though the data survived.
#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<()> {
    let handle = File::open(directory).map_err(|error| at_path(directory, error))?;
    handle.sync_all().map_err(|error| at_path(directory, error))
}

/// Windows has no equivalent: a directory cannot be opened as a file, and NTFS
/// makes the metadata change durable through the file handle already flushed
/// above. The function exists so the call site reads the same on every platform.
#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use clap::Parser;
    use std::io;
    use tempfile::tempdir;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx() -> Ctx {
        Ctx::new(Harness::parse_from(["dctl"]).globals)
    }

    #[test]
    fn a_stream_lands_at_the_destination() {
        let dir = tempdir().unwrap();
        let destination = dir.path().join("out.bin");
        let payload: Vec<u8> = (0..=255_u8).cycle().take(4096).collect();

        let bytes = store(&ctx(), &destination, &mut payload.as_slice()).unwrap();

        assert_eq!(bytes, 4096);
        assert_eq!(fs::read(&destination).unwrap(), payload);
    }

    #[test]
    fn an_empty_stream_creates_an_empty_object() {
        let dir = tempdir().unwrap();
        let destination = dir.path().join("empty.bin");
        assert_eq!(store(&ctx(), &destination, &mut io::empty()).unwrap(), 0);
        assert!(destination.exists());
        assert_eq!(fs::metadata(&destination).unwrap().len(), 0);
    }

    #[test]
    fn nothing_is_left_behind_after_a_successful_run() {
        // The staging file must not survive the commit, or the next `ls` shows
        // a hidden file nobody asked for.
        let dir = tempdir().unwrap();
        let destination = dir.path().join("out.bin");
        store(&ctx(), &destination, &mut b"data".as_slice()).unwrap();

        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|entry| dctl_store::is_staging_name(&entry.file_name().to_string_lossy()))
            .collect();
        assert!(leftovers.is_empty(), "staging file survived the commit");
    }

    #[test]
    fn a_failed_stream_leaves_the_destination_untouched() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::ConnectionAborted))
            }
        }

        let dir = tempdir().unwrap();
        let destination = dir.path().join("out.bin");
        fs::write(&destination, b"original").unwrap();

        assert!(store(&ctx(), &destination, &mut Broken).is_err());

        // The pre-existing object must survive a failed replacement intact —
        // this is the local case of "a failed write commits nothing".
        assert_eq!(fs::read(&destination).unwrap(), b"original");
        // And the staging file must be gone.
        let leftovers = fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(leftovers, 1, "only the original object may remain");
    }

    #[test]
    fn an_existing_object_is_replaced_atomically() {
        let dir = tempdir().unwrap();
        let destination = dir.path().join("out.bin");
        fs::write(&destination, b"old contents, longer").unwrap();

        store(&ctx(), &destination, &mut b"new".as_slice()).unwrap();

        // A truncate-in-place write would leave the tail of the old contents.
        assert_eq!(fs::read(&destination).unwrap(), b"new");
    }

    #[test]
    fn a_directory_destination_is_refused() {
        let dir = tempdir().unwrap();
        let error = store(&ctx(), dir.path(), &mut b"x".as_slice()).unwrap_err();
        assert_eq!(error.code(), crate::exit::ExitCode::Usage);
    }

    #[test]
    fn a_bare_file_name_resolves_to_the_current_directory() {
        assert_eq!(parent_of(Path::new("out.bin")), PathBuf::from("."));
        assert_eq!(parent_of(Path::new("a/b/out.bin")), PathBuf::from("a/b"));
        assert_eq!(parent_of(Path::new("/out.bin")), PathBuf::from("/"));
    }
}
