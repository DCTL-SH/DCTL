//! The stdin pump: copy a stream of unknown length into a writer.
//!
//! `rcat`'s defining constraint is that **the length is not knowable in
//! advance**. `pg_dump | dctl rcat vault:db.sql` cannot be asked how big the dump
//! will be, and buffering it to find out would put an arbitrary amount of the
//! user's data in memory. So this loop never asks: it reads a fixed-size chunk,
//! writes it, and stops at EOF.
//!
//! This is deliberately *not* [`crate::commands::cat::sink`]'s copy loop, and the
//! difference is a data-safety one rather than a stylistic one. `cat` writes to a
//! consumer that is allowed to walk away, so a broken pipe there ends the stream
//! successfully. `rcat` writes to storage, where every write failure — a full
//! disk, a closed handle — means the object is incomplete. Nothing is tolerated
//! here; a failed write aborts the run and the staged object is discarded, so the
//! destination never gains a truncated file that looks whole.

use std::io::{self, Read, Write};

use crate::ctx::Ctx;
use crate::error::{CliError, Result};

/// Copy `reader` into `writer` until EOF, returning the byte count.
///
/// Counters are updated as the bytes move rather than at the end, so `--progress`
/// and `--stats` show a live figure during a long stream. They report bytes
/// *transferred*, never bytes verified: nothing is durable until the caller
/// commits, which is the distinction `PLAN.md` §6 draws and the summary shows.
///
/// # Errors
/// Any read failure, and any write failure whatsoever.
pub fn pump(
    ctx: &Ctx,
    reader: &mut impl Read,
    writer: &mut impl Write,
    buffer: &mut [u8],
) -> Result<u64> {
    let mut total = 0_u64;

    loop {
        let read = match reader.read(buffer) {
            Ok(0) => break,
            Ok(read) => read,
            // A signal interrupted the read; the bytes are still queued.
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(CliError::from(error)),
        };

        writer.write_all(&buffer[..read]).map_err(CliError::from)?;

        total += read as u64;
        ctx.stats.add_bytes(read as u64);
    }

    writer.flush().map_err(CliError::from)?;
    Ok(total)
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
        Ctx::new(Harness::parse_from(["dctl"]).globals)
    }

    #[test]
    fn a_stream_of_unknown_length_is_copied_whole() {
        let payload: Vec<u8> = (0..=255_u8).cycle().take(5000).collect();
        let mut written = Vec::new();
        let mut buffer = [0_u8; 64];

        let ctx = ctx();
        let bytes = pump(&ctx, &mut payload.as_slice(), &mut written, &mut buffer).unwrap();

        assert_eq!(bytes, 5000);
        assert_eq!(written, payload, "bytes must survive the chunking exactly");
        assert_eq!(ctx.stats.snapshot().bytes_transferred, 5000);
    }

    #[test]
    fn an_empty_stream_stores_zero_bytes() {
        // A producer that emits nothing is not an error: an empty object is a
        // legitimate thing to create, and it must be reported as empty.
        let mut written = Vec::new();
        let mut buffer = [0_u8; 16];
        assert_eq!(
            pump(&ctx(), &mut io::empty(), &mut written, &mut buffer).unwrap(),
            0
        );
        assert!(written.is_empty());
    }

    #[test]
    fn a_write_failure_aborts_rather_than_truncating() {
        /// Accepts the first chunk, then fails as a full disk would.
        struct FullDisk {
            accepted: bool,
        }
        impl Write for FullDisk {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                if self.accepted {
                    return Err(io::Error::from(io::ErrorKind::WriteZero));
                }
                self.accepted = true;
                Ok(buffer.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let payload = vec![0_u8; 1000];
        let mut buffer = [0_u8; 100];
        let error = pump(
            &ctx(),
            &mut payload.as_slice(),
            &mut FullDisk { accepted: false },
            &mut buffer,
        )
        .unwrap_err();

        // Unlike `cat`, nothing about a failed write here is survivable: the
        // object would be short, and a short object must never be committed.
        assert_ne!(error.code(), crate::exit::ExitCode::Success);
    }

    #[test]
    fn a_read_failure_propagates() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::ConnectionAborted))
            }
        }
        let mut written = Vec::new();
        let mut buffer = [0_u8; 16];
        assert!(pump(&ctx(), &mut Broken, &mut written, &mut buffer).is_err());
    }

    #[test]
    fn an_interrupted_read_is_retried() {
        /// Fails once with `Interrupted`, then delivers its payload.
        struct Flaky {
            interrupted: bool,
            remaining: usize,
        }
        impl Read for Flaky {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                if self.remaining == 0 || buffer.is_empty() {
                    return Ok(0);
                }
                let written = buffer.len().min(self.remaining);
                buffer[..written].fill(b'z');
                self.remaining -= written;
                Ok(written)
            }
        }

        let mut written = Vec::new();
        let mut buffer = [0_u8; 8];
        let bytes = pump(
            &ctx(),
            &mut Flaky {
                interrupted: false,
                remaining: 20,
            },
            &mut written,
            &mut buffer,
        )
        .unwrap();

        assert_eq!(bytes, 20);
        assert_eq!(written.len(), 20);
    }
}
