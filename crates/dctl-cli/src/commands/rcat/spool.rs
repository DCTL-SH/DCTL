//! Getting a stream of unknown length into a vault.
//!
//! `Vault::put_file` takes a whole buffer. `Vault::put_file_from_path` takes a
//! path and seals it straight from disk in `O(chunk_size)` memory. A pipe is
//! neither, so one of the two has to be manufactured, and the choice decides
//! what `pg_dump | dctl rcat archive:db.sql` can do:
//!
//! * **Buffer in memory** and refuse past a fixed ceiling, the way the transfer
//!   engine did before it learned to stream. Simple, and it puts a hard ceiling on the
//!   one command whose whole purpose is a stream nobody measured. An operator
//!   would have to know their dump's size in advance — which is exactly what a
//!   pipe cannot tell them — and would discover the limit after the producer had
//!   already run.
//! * **Spool to a temporary file** and hand that to `put_file_from_path`. Peak
//!   memory is one chunk however large the stream is, the size limit disappears,
//!   and the ceiling becomes free space in the temporary directory — a resource
//!   an operator can see, measure and change.
//!
//! This module is the second. The cost is stated rather than buried: **the
//! plaintext touches the local disk before it is sealed.**
//!
//! ## What that costs, and what is done about it
//!
//! The spool file is created by `tempfile` with owner-only permissions and no
//! name any other process can guess or pre-create, and it is unlinked when the
//! command ends — including on the error paths, because the handle owns the file
//! and its `Drop` does the removal. Its location follows `TMPDIR` (`TEMP` on
//! Windows), so an operator who needs the plaintext to stay on a particular
//! volume — an encrypted one, a ramdisk — sets that and this follows.
//!
//! It is not a *new* class of exposure: `Vault::put_file_from_path` already
//! seals into a temporary file of its own in the same directory, so a machine
//! where the temporary directory is unacceptable was already unsuitable for
//! storing large files. What is new is that the *plaintext* is there too, for
//! the duration of the run. On a filesystem that reallocates blocks — every
//! journalling and copy-on-write filesystem — an unlink does not erase the
//! bytes, and this module does not pretend otherwise: there is no scrubbing pass
//! here, because a scrubbing pass over a modern filesystem is theatre.
//!
//! ## Nothing is stored until the stream ends
//!
//! The spool is filled first and sealed second, so a producer that dies halfway
//! leaves a partial temporary file and **no object at all**. That is the
//! `PLAN.md` §6 ordering a stream can actually keep: the length is unknown until
//! EOF, so there is no earlier moment at which a complete object could be
//! committed.

use std::io::Read;

use tempfile::NamedTempFile;

use crate::constants::{RCAT_SPOOL_PREFIX, STREAM_CHUNK_BYTES};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};

use super::stream;

/// A stream captured on disk, ready to be sealed from its path.
///
/// Holds the [`NamedTempFile`] rather than just its path: dropping the handle is
/// what removes the file, so a caller that kept only the path would leave the
/// user's plaintext behind on every early return.
pub struct Spooled {
    file: NamedTempFile,
    bytes: u64,
}

impl Spooled {
    /// Where the sealed write should read from.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        self.file.path()
    }

    /// How many bytes the stream turned out to hold.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// Read `reader` to EOF into a temporary file.
///
/// The counters move as the bytes do, so `--progress` shows a live figure during
/// a long stream; they report bytes *read*, never bytes stored, because nothing
/// is stored until the caller seals the result.
///
/// # Errors
/// [`ExitCode::Uncategorised`](crate::exit::ExitCode::Uncategorised) when the
/// temporary directory cannot be written — with the directory named, because
/// "permission denied" without a path sends an operator looking at the vault.
/// Any read failure propagates: a truncated stream must never become a complete
/// object.
pub fn capture(ctx: &Ctx, reader: &mut impl Read) -> Result<Spooled> {
    let mut file = NamedTempFile::with_prefix(RCAT_SPOOL_PREFIX).map_err(|error| {
        CliError::from(error).with_hint(format!(
            "spooling standard input into {}. Set TMPDIR to a writable \
             location with room for the stream.",
            std::env::temp_dir().display()
        ))
    })?;

    let mut buffer = vec![0_u8; STREAM_CHUNK_BYTES];
    let bytes = stream::pump(ctx, reader, file.as_file_mut(), &mut buffer)?;

    Ok(Spooled { file, bytes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx() -> Ctx {
        Ctx::new(Harness::parse_from(["dctl", "--quiet"]).globals)
    }

    #[test]
    fn a_stream_of_unknown_length_lands_on_disk_byte_for_byte() {
        let payload: Vec<u8> = (0..=255_u8).cycle().take(300_000).collect();
        let context = ctx();

        let spooled = capture(&context, &mut payload.as_slice()).expect("the spool is written");

        assert_eq!(spooled.bytes(), 300_000);
        assert_eq!(
            std::fs::read(spooled.path()).expect("the spool is readable"),
            payload,
            "the bytes must survive the chunking exactly"
        );
        assert_eq!(context.stats.snapshot().bytes_transferred, 300_000);
    }

    #[test]
    fn an_empty_stream_is_a_legitimate_empty_object() {
        let spooled = capture(&ctx(), &mut std::io::empty()).expect("nothing is still something");
        assert_eq!(spooled.bytes(), 0);
        assert_eq!(std::fs::metadata(spooled.path()).unwrap().len(), 0);
    }

    #[test]
    fn the_plaintext_is_removed_when_the_handle_is_dropped() {
        // The property the type exists for: the user's plaintext must not
        // outlive the command, on any path out of it.
        let path = {
            let spooled = capture(&ctx(), &mut b"secret".as_slice()).expect("the spool");
            spooled.path().to_path_buf()
        };
        assert!(!path.exists(), "the spool survived its handle");
    }

    #[test]
    fn a_failed_read_leaves_nothing_behind() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted))
            }
        }
        assert!(capture(&ctx(), &mut Broken).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn the_spool_is_readable_only_by_its_owner() {
        // Plaintext on a shared machine's temporary directory is exactly the
        // exposure this command's documentation promises not to create.
        use std::os::unix::fs::PermissionsExt as _;

        let spooled = capture(&ctx(), &mut b"secret".as_slice()).expect("the spool");
        let mode = std::fs::metadata(spooled.path())
            .expect("the spool is there")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "group or other can read the plaintext");
    }
}
