//! The raw-byte writer for `dctl cat`.
//!
//! Object contents never go through [`crate::output::Out`]. That sink is for
//! *text*: it appends a newline, and it runs what it is given through the colour
//! auto-detector. A film, a database dump or a tarball must arrive byte for byte,
//! so the bytes are written straight to a locked `stdout` instead.
//!
//! **A closed pipe is success.** `dctl cat film.mkv | head -c 1M` closes the read
//! end of the pipe after a megabyte. Rust ignores `SIGPIPE`, so instead of dying
//! the process gets `EPIPE` back from `write`, and treating that as a failure
//! would make every `| head` in every script exit non-zero. A broken pipe
//! therefore stops the stream and reports [`Flow::Stop`]; the command returns
//! `Ok` and the process exits 0. Every *other* write error propagates — a full
//! disk on a redirected stdout is a real failure and must be reported as one.
//!
//! The sink is generic over its writer so the discard path can hand it
//! [`std::io::sink`] and the tests can hand it a `Vec<u8>`. There is exactly one
//! copy loop, and every mode exercises it.

use std::io::{self, Read, Write};

use crate::error::{CliError, Result};

/// Whether the consumer is still listening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    /// Keep going.
    Continue,
    /// The far end closed the pipe. Stop cleanly — this is not an error.
    Stop,
}

/// A byte sink that counts what it writes and tolerates a closed pipe.
pub struct Sink<W: Write> {
    writer: W,
    written: u64,
    /// Cleared by a broken pipe, so later writes are dropped instead of
    /// re-issuing a syscall that can only fail the same way.
    open: bool,
}

impl<W: Write> Sink<W> {
    /// Wrap a writer.
    pub const fn writing(writer: W) -> Self {
        Self {
            writer,
            written: 0,
            open: true,
        }
    }

    /// Bytes accepted so far, across every object.
    #[must_use]
    pub const fn written(&self) -> u64 {
        self.written
    }

    /// Write one chunk.
    ///
    /// # Errors
    /// Any write failure other than a broken pipe.
    pub fn write(&mut self, chunk: &[u8]) -> Result<Flow> {
        if !self.open {
            return Ok(Flow::Stop);
        }
        match self.writer.write_all(chunk) {
            Ok(()) => {
                self.written += chunk.len() as u64;
                Ok(Flow::Continue)
            }
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                self.open = false;
                Ok(Flow::Stop)
            }
            Err(error) => Err(CliError::from(error)),
        }
    }

    /// Copy everything `reader` yields into the sink, reusing `buffer`.
    ///
    /// The buffer is borrowed rather than owned so one allocation serves every
    /// object in the invocation: memory stays O(1), not O(objects) and never
    /// O(file size).
    ///
    /// # Errors
    /// A read failure, or a write failure other than a broken pipe.
    pub fn drain(&mut self, reader: &mut impl Read, buffer: &mut [u8]) -> Result<Flow> {
        loop {
            let read = match reader.read(buffer) {
                Ok(0) => return Ok(Flow::Continue),
                Ok(read) => read,
                // A signal interrupted the read; the bytes are still there.
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(CliError::from(error)),
            };

            if self.write(&buffer[..read])? == Flow::Stop {
                return Ok(Flow::Stop);
            }
        }
    }

    /// Flush and report the total.
    ///
    /// # Errors
    /// A flush failure other than a broken pipe.
    pub fn finish(&mut self) -> Result<u64> {
        if self.open {
            match self.writer.flush() {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::BrokenPipe => self.open = false,
                Err(error) => return Err(CliError::from(error)),
            }
        }
        Ok(self.written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::ExitCode;

    /// A writer that fails every write with a chosen error kind.
    struct Failing(io::ErrorKind);

    impl Write for Failing {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(self.0, "test"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(self.0, "test"))
        }
    }

    #[test]
    fn bytes_pass_through_unchanged() {
        // Byte-for-byte fidelity is the whole contract: no newline, no escape,
        // no re-encoding. Binary content must survive exactly.
        let payload: Vec<u8> = (0..=255_u8).collect();
        let mut sink = Sink::writing(Vec::new());
        let mut buffer = [0_u8; 7];
        assert_eq!(
            sink.drain(&mut payload.as_slice(), &mut buffer).unwrap(),
            Flow::Continue
        );
        assert_eq!(sink.finish().unwrap(), 256);
        assert_eq!(sink.writer, payload);
    }

    #[test]
    fn a_broken_pipe_stops_the_stream_without_failing() {
        // `dctl cat big.mkv | head -c 1M`: the consumer goes away and the run is
        // still a success.
        let mut sink = Sink::writing(Failing(io::ErrorKind::BrokenPipe));
        assert_eq!(sink.write(b"hello").unwrap(), Flow::Stop);
        // Later writes are dropped rather than retried.
        assert_eq!(sink.write(b"more").unwrap(), Flow::Stop);
        assert_eq!(sink.finish().unwrap(), 0);
    }

    #[test]
    fn a_broken_pipe_mid_object_ends_the_drain() {
        let payload = vec![0_u8; 4096];
        let mut sink = Sink::writing(Failing(io::ErrorKind::BrokenPipe));
        let mut buffer = [0_u8; 64];
        assert_eq!(
            sink.drain(&mut payload.as_slice(), &mut buffer).unwrap(),
            Flow::Stop
        );
    }

    #[test]
    fn any_other_write_failure_is_a_real_error() {
        // A full disk on a redirected stdout must not be mistaken for `head`.
        let mut sink = Sink::writing(Failing(io::ErrorKind::WriteZero));
        let error = sink.write(b"hello").unwrap_err();
        assert_ne!(error.code(), ExitCode::Success);
    }

    #[test]
    fn a_read_failure_propagates() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            }
        }
        let mut sink = Sink::writing(Vec::new());
        let mut buffer = [0_u8; 16];
        assert!(sink.drain(&mut Broken, &mut buffer).is_err());
    }

    #[test]
    fn an_interrupted_read_is_retried_not_reported() {
        /// Fails once with `Interrupted`, then yields its payload.
        struct Flaky {
            interrupted: bool,
        }
        impl Read for Flaky {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                if buffer.is_empty() {
                    return Ok(0);
                }
                buffer[0] = b'x';
                Ok(1)
            }
        }

        let mut sink = Sink::writing(Vec::new());
        let mut buffer = [0_u8; 0];
        // An empty buffer terminates the loop after the retry, which is enough
        // to prove the Interrupted arm did not surface as an error.
        assert_eq!(
            sink.drain(&mut Flaky { interrupted: false }, &mut buffer)
                .unwrap(),
            Flow::Continue
        );
    }

    #[test]
    fn the_byte_count_accumulates_across_objects() {
        let mut sink = Sink::writing(Vec::new());
        let mut buffer = [0_u8; 8];
        sink.drain(&mut b"one".as_slice(), &mut buffer).unwrap();
        assert_eq!(sink.written(), 3);
        sink.drain(&mut b"two!".as_slice(), &mut buffer).unwrap();
        assert_eq!(sink.written(), 7);
        assert_eq!(sink.finish().unwrap(), 7);
    }

    #[test]
    fn discarding_still_counts_what_it_read() {
        // `--discard` proves an object can be read end to end; the byte count is
        // the only evidence the run produces, so it must be exact.
        let mut sink = Sink::writing(io::sink());
        let mut buffer = [0_u8; 16];
        sink.drain(&mut vec![7_u8; 100].as_slice(), &mut buffer)
            .unwrap();
        assert_eq!(sink.finish().unwrap(), 100);
    }
}
