//! Resolving one `cat` argument into a byte source.
//!
//! Every argument is *pre-flighted* before a single byte reaches stdout: the
//! object is located, its size is read, and the requested span is resolved
//! against that size. Only when every argument has survived does the command
//! start writing. That ordering is deliberate — `dctl cat a.bin vault:b.bin >
//! out` must not emit half a stream and then fail, because a truncated file that
//! *looks* complete is exactly the false success `PLAN.md` §6 exists to prevent.
//!
//! Pre-flight is also where the engine boundary sits. A **local** path is fully
//! implemented: the file is seekable, so `--offset` is a real `seek` and
//! `--count` a real limit, and no bytes outside the range are ever read. A
//! **remote** object needs an unlocked vault and a ranged read of the stored
//! chunks that cover the slice; that call does not exist yet, so pre-flight fails
//! with [`CliError::unimplemented`] before anything is written, printed or
//! promised.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

use crate::commands::pipeline::{ObjectSpec, at_path, command_name};
use crate::constants::{RANGE_READ_FEATURE, RANGE_READ_HINT};
use crate::error::{CliError, Result};

use super::range::{Slice, Span};

/// A located object plus the slice of it the caller asked for.
#[derive(Debug)]
pub struct Source {
    spec: ObjectSpec,
    size: u64,
    slice: Slice,
}

impl Source {
    /// Locate the object, read its size, and resolve `span` against it.
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::FileNotFound`] when a local path does not exist,
    /// [`crate::exit::ExitCode::Usage`] when it is a directory or names no
    /// object, and [`crate::exit::ExitCode::FatalError`] for a remote object,
    /// whose ranged read the engine cannot yet perform.
    pub fn preflight(spec: ObjectSpec, span: Span) -> Result<Self> {
        if spec.is_bare_remote() {
            return Err(
                CliError::usage(format!("'{spec}' names a remote but no object"))
                    .with_hint("Name the object to write, for example 'vault:notes/today.md'."),
            );
        }

        if !spec.is_local() {
            return Err(CliError::unimplemented(format!(
                "{RANGE_READ_FEATURE} ({})",
                command_name("cat")
            ))
            .with_hint(RANGE_READ_HINT));
        }

        let size = local_size(&spec)?;
        Ok(Self {
            slice: span.resolve(size),
            spec,
            size,
        })
    }

    /// Open a reader positioned at the start of the slice and limited to its
    /// length.
    ///
    /// # Errors
    /// Any failure to open or seek the underlying file.
    pub fn open(&self) -> Result<Reader> {
        // Unreachable while `preflight` refuses remotes, but written as a refusal
        // rather than an assertion: a future engine wires the remote arm in here,
        // and until it does the honest answer is still an error.
        if !self.spec.is_local() {
            return Err(CliError::unimplemented(format!(
                "{RANGE_READ_FEATURE} ({})",
                command_name("cat")
            ))
            .with_hint(RANGE_READ_HINT));
        }

        let path = self.spec.local_path();
        let mut file = File::open(&path).map_err(|error| at_path(&path, error))?;

        // Skipped at offset zero, which is the overwhelmingly common case and
        // the one where the syscall would buy nothing.
        if self.slice.start > 0 {
            file.seek(SeekFrom::Start(self.slice.start))
                .map_err(|error| at_path(&path, error))?;
        }

        Ok(Reader {
            inner: file.take(self.slice.length),
        })
    }

    /// The specification this source came from.
    #[must_use]
    pub const fn spec(&self) -> &ObjectSpec {
        &self.spec
    }

    /// The object's total size in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// The byte range that will be read.
    #[must_use]
    pub const fn slice(&self) -> Slice {
        self.slice
    }
}

/// A bounded reader over one object's slice.
///
/// A newtype rather than a bare [`std::io::Take`] so that adding the remote arm
/// changes this one type and nothing else: the copy loop consuming it only ever
/// sees a [`Read`].
pub struct Reader {
    inner: io::Take<File>,
}

impl Read for Reader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buffer)
    }
}

/// Stat a local object, refusing anything that is not a regular file.
///
/// The refusal is not fussiness. Every range flag is resolved against the size
/// reported here, and a FIFO, socket or character device reports zero — so
/// `--tail 1M` on one would silently select nothing and `cat` would appear to
/// succeed while writing no bytes at all. Refusing says what happened instead.
fn local_size(spec: &ObjectSpec) -> Result<u64> {
    let path = spec.local_path();
    let metadata = std::fs::metadata(&path).map_err(|error| at_path(&path, error))?;

    if metadata.is_dir() {
        return Err(
            CliError::usage(format!("'{spec}' is a directory")).with_hint(
                "cat writes the contents of one object. Name a file, or list the \
                 directory with `dctl ls`.",
            ),
        );
    }

    if !metadata.is_file() {
        return Err(
            CliError::usage(format!("'{spec}' is not a regular file")).with_hint(
                "cat writes stored objects. A device, socket or FIFO has no size to \
                 range over — read it with your shell instead.",
            ),
        );
    }

    Ok(metadata.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::ExitCode;
    use std::io::Write;
    use std::path::Path;
    use tempfile::tempdir;

    fn spec(text: &str) -> ObjectSpec {
        ObjectSpec::parse(text).unwrap()
    }

    fn file_with(dir: &Path, name: &str, bytes: &[u8]) -> String {
        let path = dir.join(name);
        let mut file = File::create(&path).unwrap();
        file.write_all(bytes).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn a_local_file_is_measured_and_sliced() {
        let dir = tempdir().unwrap();
        let path = file_with(dir.path(), "a.bin", b"0123456789");

        let source = Source::preflight(spec(&path), Span::WHOLE).unwrap();
        assert_eq!(source.size(), 10);
        assert_eq!(source.slice().length, 10);
    }

    #[test]
    fn a_slice_reads_only_the_bytes_it_covers() {
        let dir = tempdir().unwrap();
        let path = file_with(dir.path(), "a.bin", b"0123456789");
        let span = Span::from_flags(None, Some(4), None, None).unwrap();

        let source = Source::preflight(spec(&path), span).unwrap();
        assert_eq!(
            source.slice(),
            Slice {
                start: 6,
                length: 4
            }
        );

        let mut read = Vec::new();
        source.open().unwrap().read_to_end(&mut read).unwrap();
        assert_eq!(read, b"6789", "the seek and the limit must both apply");
    }

    #[test]
    fn an_empty_slice_reads_nothing() {
        let dir = tempdir().unwrap();
        let path = file_with(dir.path(), "a.bin", b"0123456789");
        let span = Span::from_flags(Some(0), None, None, None).unwrap();

        let source = Source::preflight(spec(&path), span).unwrap();
        assert!(source.slice().is_empty());

        let mut read = Vec::new();
        source.open().unwrap().read_to_end(&mut read).unwrap();
        assert!(read.is_empty());
    }

    #[test]
    fn a_missing_file_is_file_not_found_with_its_path_quoted() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("nope.bin");
        let error = Source::preflight(spec(&missing.to_string_lossy()), Span::WHOLE).unwrap_err();

        assert_eq!(error.code(), ExitCode::FileNotFound);
        assert!(
            error.message().contains("nope.bin"),
            "the message must name the file: {}",
            error.message()
        );
        assert!(error.hint().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn a_device_is_refused_rather_than_read_as_empty() {
        // /dev/null stats as zero bytes, so every range flag would resolve to
        // "nothing" and the command would look like it succeeded.
        let error = Source::preflight(spec("/dev/null"), Span::WHOLE).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some());
    }

    #[test]
    fn a_directory_is_a_usage_error() {
        let dir = tempdir().unwrap();
        let error =
            Source::preflight(spec(&dir.path().to_string_lossy()), Span::WHOLE).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[test]
    fn a_remote_object_fails_loudly_rather_than_silently() {
        // The engine cannot range-read a vault yet. That must surface as an
        // error with a real exit code, never as an empty successful stream.
        let error = Source::preflight(spec("vault:film.mkv"), Span::WHOLE).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert_ne!(error.code(), ExitCode::Success);
        assert!(
            error.hint().is_some(),
            "a refusal must say what works today"
        );
    }

    #[test]
    fn a_bare_remote_names_no_object_to_write() {
        let error = Source::preflight(spec("vault:"), Span::WHOLE).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }
}
