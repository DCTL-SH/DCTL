//! Resolving one `cat` argument into a byte source.
//!
//! Every argument is *pre-flighted* before a single byte reaches stdout: the
//! object is located, its size is read, and the requested span is resolved
//! against that size. Only when every argument has survived does the command
//! start writing. That ordering is deliberate — `dctl cat a.bin archive:b.bin >
//! out` must not emit half a stream and then fail, because a truncated file that
//! *looks* complete is exactly the false success `PLAN.md` §6 exists to prevent.
//!
//! ## Two origins, one pre-flight
//!
//! A **local** path is measured with `stat` and read with a `seek` plus a
//! bounded read: memory is one buffer, and `--offset 40G` on a film costs one
//! syscall.
//!
//! A **remote** object is measured with [`ReadSource::stat`] and read with
//! [`ReadSource::read`] or [`ReadSource::read_range`] on the binary's one read
//! abstraction, which is what makes `dctl cat archive:film.mkv` and
//! `dctl cat archive-store:<key>` both work without this file knowing which is
//! which. (Spelled `ReadSource` throughout this module's documentation because
//! the local [`Source`] is this file's own pre-flighted argument, and an
//! unqualified `Source` here would link to that.)
//!
//! ## What a remote read costs, stated plainly
//!
//! [`ReadSource::read`] and [`ReadSource::read_range`] hand back bytes, not a
//! reader, so the requested window is held in memory while it is written. That is the whole
//! cost now: `dctl cat archive:film.mkv --head 1M` needs room for a megabyte,
//! whichever kind of remote it names.
//!
//! It used to be much worse against a sealed vault, and this is where the
//! difference showed. `dctl-core` exposed only a whole-object read, so a vault
//! served `--count 4` against a 40 GB film by moving 40 GB — a transfer that
//! returned four bytes, exited 0, and appeared on a bill with nothing linking it
//! back to the command. This file warned about it at pre-flight because that was
//! the only honest thing available. It no longer needs to: a vault computes the
//! chunks covering a window and fetches exactly those (`docs/FORMAT.md` §3), so
//! both sources are O(window) and the warning is gone rather than dormant.
//!
//! `dctl cat archive:film.mkv` with no range flags still needs room for the film,
//! because that asks for the film. [`Reader`] gains a streaming variant the day
//! stdout is written chunk-by-chunk instead of from a buffer; nothing above it
//! changes when it does.
//!
//! Buffering is *not* how the range flags are honoured. `--offset` and `--count`
//! resolve to a window that is passed down as a window, so both a plain store and
//! a vault serve it with a genuine ranged request rather than reading and
//! discarding.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::commands::pipeline::{ObjectSpec, at_path};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::source::Source as ReadSource;

use super::opened::Opened;
use super::range::{Slice, Span};

/// A located object plus the slice of it the caller asked for.
pub struct Source {
    spec: ObjectSpec,
    size: u64,
    slice: Slice,
    /// The source to read a remote object through, or `None` for a local path.
    ///
    /// Held per argument rather than looked up again at read time so that the
    /// handle proven to work during pre-flight is the handle that is used —
    /// re-resolving between the check and the read is how a command ends up
    /// having validated something it did not go on to read.
    origin: Option<Arc<dyn ReadSource>>,
    /// The object's key **inside** [`Source::origin`], which is not the spec's
    /// path whenever resolution consumed part of it.
    ///
    /// `b2:DCTL001/a.txt` names the bucket `DCTL001` and the object `a.txt`, so
    /// a read of the spec's path asks that bucket for `DCTL001/a.txt`. Empty and
    /// unused for a local argument, whose bytes are opened through its own path.
    key: String,
}

impl Source {
    /// Locate the object, read its size, and resolve `span` against it.
    ///
    /// # Errors
    /// [`ExitCode::FileNotFound`] when a local path or a remote object does not
    /// exist, [`ExitCode::Usage`] when the argument is a directory or names a
    /// remote but no object, and whatever opening the remote reported.
    pub async fn preflight(spec: ObjectSpec, span: Span, opened: &mut Opened<'_>) -> Result<Self> {
        if spec.is_bare_remote() {
            return Err(
                CliError::usage(format!("'{spec}' names a remote but no object"))
                    .with_hint("Name the object to write, for example 'archive:notes/today.md'."),
            );
        }

        if spec.remote().is_none() {
            let size = local_size(&spec)?;
            return Ok(Self {
                slice: span.resolve(size),
                spec,
                size,
                origin: None,
                key: String::new(),
            });
        }

        let located = opened.get(&spec).await?;
        let source = located.source;
        let key = located.key;
        let size = remote_size(&spec, &key, source.as_ref()).await?;
        let slice = span.resolve(size);

        // There used to be a warning here, because a vault served a byte window
        // by moving the whole object and `--count 4` against a 40 GB film was a
        // 40 GB transfer nothing tied back to the command. Both sources now serve
        // a genuine window — see `crate::source::vault` — so the announcement has
        // nothing left to announce, and a warning that fires on a cost that is no
        // longer paid is worse than none: it is the one an operator learns to
        // filter out before the run that mattered.
        Ok(Self {
            slice,
            spec,
            size,
            origin: Some(source),
            key,
        })
    }

    /// Open a reader over exactly the slice this source resolved to.
    ///
    /// # Errors
    /// Any failure to open, seek or read the underlying object — including a
    /// vault object whose bytes fail authentication, which is reported and
    /// **not** returned.
    pub async fn open(&self) -> Result<Reader> {
        let Some(source) = &self.origin else {
            let path = self.spec.local_path();
            let mut file = File::open(&path).map_err(|error| at_path(&path, error))?;

            // Skipped at offset zero, which is the overwhelmingly common case
            // and the one where the syscall would buy nothing.
            if self.slice.start > 0 {
                file.seek(SeekFrom::Start(self.slice.start))
                    .map_err(|error| at_path(&path, error))?;
            }

            return Ok(Reader::Local(file.take(self.slice.length)));
        };

        // Only a *window* arrives here. A whole-object read never opens a
        // reader at all — it is streamed straight into the sink by
        // [`Source::stream_to`](crate::source::Source::stream_to), which makes
        // the same whole-object integrity statement without the buffer that
        // statement used to cost. See `whole_object_source`.
        //
        // A window is materialised, and that is not the same defect: its size is
        // what the operator asked for on the command line, so it is bounded by
        // the request rather than by the object.
        let bytes = source
            .read_range(&self.key, self.slice.start, Some(self.slice.length))
            .await?;

        Ok(Reader::Buffered { bytes, position: 0 })
    }

    /// The remote to stream through when this source's slice *is* the whole
    /// object, and [`None`] otherwise.
    ///
    /// The condition is the same one [`Source::open`] uses to choose the
    /// stronger read, and it is asked here rather than there because the two
    /// answers now have different shapes: a whole-object read is streamed into
    /// the sink and a windowed one is materialised, so the choice has to be made
    /// where the writing happens. A local path answers [`None`] — the file is
    /// already on this machine and reading it through a `File` costs a buffer,
    /// not a copy of the file.
    #[must_use]
    pub fn whole_object_source(&self) -> Option<&Arc<dyn ReadSource>> {
        if self.slice.start != 0 || self.slice.length != self.size {
            return None;
        }
        self.origin.as_ref()
    }

    /// The specification this source came from.
    #[must_use]
    pub const fn spec(&self) -> &ObjectSpec {
        &self.spec
    }

    /// The object's key inside its source.
    ///
    /// Every read of a remote object goes through this rather than through
    /// [`Source::spec`]'s path, because the two differ by whatever resolution
    /// consumed — a bucket, on any provider shorthand. Kept as an accessor
    /// rather than left to each caller to derive, so a third read path cannot
    /// quietly go back to the spec.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
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
/// An enum rather than a trait object because the two arms have genuinely
/// different lifetimes — one owns a file handle, the other owns bytes that must
/// be wiped when it dies — and the copy loop consuming it only ever sees a
/// [`Read`].
pub enum Reader {
    /// A seekable file, read straight through at O(buffer) memory.
    Local(io::Take<File>),

    /// Bytes already fetched. See the module documentation for what this costs
    /// and why the alternative does not exist yet.
    ///
    /// [`Zeroizing`] because these may be a vault's plaintext, and `PLAN.md` §7
    /// wants it gone from memory when the reader dies rather than left in a
    /// freed page.
    Buffered {
        bytes: Zeroizing<Vec<u8>>,
        position: usize,
    },
}

impl Read for Reader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Local(file) => file.read(buffer),
            Self::Buffered { bytes, position } => {
                let remaining = bytes.get(*position..).unwrap_or(&[]);
                let taken = remaining.len().min(buffer.len());
                buffer
                    .get_mut(..taken)
                    .unwrap_or(&mut [])
                    .copy_from_slice(remaining.get(..taken).unwrap_or(&[]));
                *position += taken;
                Ok(taken)
            }
        }
    }
}

/// Stat a remote object, refusing one the source cannot describe.
///
/// A vault answers this from its index, so an object written on another machine
/// and never listed here reports absent even though a read would succeed through
/// the authoritative name record. The hint names the remedy for that case
/// explicitly, because "not found" for a file the user knows they stored is the
/// most alarming message this command can produce.
async fn remote_size(spec: &ObjectSpec, key: &str, source: &dyn ReadSource) -> Result<u64> {
    match source.stat(key).await? {
        // `Source::stat` promises a measured size — the sealed source pays a
        // read rather than pass an unmeasured index row on, precisely so that
        // `--offset` and `--tail` are resolved against a real length. The `None`
        // arm is therefore unreachable through either implementation today, and
        // it is still written out rather than unwrapped: every range flag is
        // resolved against this number, so an implementation that one day
        // forgot the promise must produce a refusal naming what is missing, not
        // a `cat` that writes no bytes and exits 0.
        Some(entry) => entry.size.ok_or_else(|| {
            CliError::new(
                ExitCode::Uncategorised,
                format!("'{spec}' has no recorded size, so a range cannot be resolved against it"),
            )
            .with_hint(
                "This should not happen: a `stat` is required to establish a \
                 size even when the index holds none. Please report it.",
            )
        }),
        None => Err(
            CliError::new(ExitCode::FileNotFound, format!("'{spec}' is not there")).with_hint(
                "Check the path with `dctl ls`. If the object was written from \
                 another machine, this machine's index has not seen it yet — \
                 `dctl index rebuild` rescans the store.",
            ),
        ),
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
    use crate::cli::GlobalArgs;
    use crate::ctx::Ctx;
    use clap::Parser;
    use std::io::Write;
    use std::path::Path;
    use tempfile::tempdir;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx() -> Ctx {
        Ctx::new(Harness::parse_from(["dctl", "--no-ask-password"]).globals)
    }

    fn spec(text: &str) -> ObjectSpec {
        ObjectSpec::parse(text).unwrap()
    }

    fn file_with(dir: &Path, name: &str, bytes: &[u8]) -> String {
        let path = dir.join(name);
        let mut file = File::create(&path).unwrap();
        file.write_all(bytes).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// Pre-flight one argument with a cache nothing else has touched.
    async fn preflight(context: &Ctx, text: &str, span: Span) -> Result<Source> {
        let mut opened = Opened::new(context);
        Source::preflight(spec(text), span, &mut opened).await
    }

    #[tokio::test]
    async fn a_local_file_is_measured_and_sliced() {
        let dir = tempdir().unwrap();
        let path = file_with(dir.path(), "a.bin", b"0123456789");

        let source = preflight(&ctx(), &path, Span::WHOLE).await.unwrap();
        assert_eq!(source.size(), 10);
        assert_eq!(source.slice().length, 10);
    }

    #[tokio::test]
    async fn a_slice_reads_only_the_bytes_it_covers() {
        let dir = tempdir().unwrap();
        let path = file_with(dir.path(), "a.bin", b"0123456789");
        let span = Span::from_flags(None, Some(4), None, None).unwrap();

        let source = preflight(&ctx(), &path, span).await.unwrap();
        assert_eq!(
            source.slice(),
            Slice {
                start: 6,
                length: 4
            }
        );

        let mut read = Vec::new();
        source.open().await.unwrap().read_to_end(&mut read).unwrap();
        assert_eq!(read, b"6789", "the seek and the limit must both apply");
    }

    #[tokio::test]
    async fn an_empty_slice_reads_nothing() {
        let dir = tempdir().unwrap();
        let path = file_with(dir.path(), "a.bin", b"0123456789");
        let span = Span::from_flags(Some(0), None, None, None).unwrap();

        let source = preflight(&ctx(), &path, span).await.unwrap();
        assert!(source.slice().is_empty());

        let mut read = Vec::new();
        source.open().await.unwrap().read_to_end(&mut read).unwrap();
        assert!(read.is_empty());
    }

    #[tokio::test]
    async fn a_missing_file_is_file_not_found_with_its_path_quoted() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("nope.bin");
        let error = preflight(&ctx(), &missing.to_string_lossy(), Span::WHOLE)
            .await
            .err()
            .expect("a missing file must fail");

        assert_eq!(error.code(), ExitCode::FileNotFound);
        assert!(
            error.message().contains("nope.bin"),
            "the message must name the file: {}",
            error.message()
        );
        assert!(error.hint().is_some());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_device_is_refused_rather_than_read_as_empty() {
        // /dev/null stats as zero bytes, so every range flag would resolve to
        // "nothing" and the command would look like it succeeded.
        let error = preflight(&ctx(), "/dev/null", Span::WHOLE)
            .await
            .err()
            .expect("a device must be refused");
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some());
    }

    #[tokio::test]
    async fn a_directory_is_a_usage_error() {
        let dir = tempdir().unwrap();
        let error = preflight(&ctx(), &dir.path().to_string_lossy(), Span::WHOLE)
            .await
            .err()
            .expect("a directory must be refused");
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn an_unconfigured_remote_fails_loudly_rather_than_silently() {
        // It must surface as an error with a real exit code, never as an empty
        // successful stream.
        let error = preflight(&ctx(), "nosuchremote:film.mkv", Span::WHOLE)
            .await
            .err()
            .expect("an unconfigured remote cannot be read");
        assert_eq!(error.code(), ExitCode::FatalError);
        assert_ne!(error.code(), ExitCode::Success);
        assert!(
            error.hint().is_some(),
            "a refusal must say what works today"
        );
    }

    #[tokio::test]
    async fn a_bare_remote_names_no_object_to_write() {
        let error = preflight(&ctx(), "archive:", Span::WHOLE)
            .await
            .err()
            .expect("a bare remote names no object");
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[test]
    fn a_buffered_reader_hands_back_every_byte_once() {
        // The remote arm's reader, exercised without a remote: a short output
        // buffer must not lose, repeat or overrun.
        let mut reader = Reader::Buffered {
            bytes: Zeroizing::new(b"0123456789".to_vec()),
            position: 0,
        };
        let mut out = Vec::new();
        let mut window = [0_u8; 3];
        loop {
            let taken = reader.read(&mut window).unwrap();
            if taken == 0 {
                break;
            }
            out.extend_from_slice(&window[..taken]);
        }
        assert_eq!(out, b"0123456789");

        // An exhausted reader keeps reporting end-of-stream.
        assert_eq!(reader.read(&mut window).unwrap(), 0);
    }

    #[test]
    fn an_empty_buffered_reader_is_immediately_at_the_end() {
        let mut reader = Reader::Buffered {
            bytes: Zeroizing::new(Vec::new()),
            position: 0,
        };
        assert_eq!(reader.read(&mut [0_u8; 4]).unwrap(), 0);
    }
}
