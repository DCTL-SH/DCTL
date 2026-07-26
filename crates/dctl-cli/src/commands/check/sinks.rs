//! The files `check` writes its verdicts to.
//!
//! A comparison of two large trees is not something anyone reads off a terminal;
//! it is something a script consumes. The `--combined`/`--differ`/`--match`/
//! `--missing-on-*` flags exist so the run produces exactly the artefacts the
//! next step needs — most often a `--missing-on-dst` list piped straight back
//! into `dctl copy --files-from`.
//!
//! Two rules shape this module:
//!
//! * **Nothing is created until there is something to write.** [`Destinations`]
//!   can be checked for obvious problems — a path that is a directory, a parent
//!   that does not exist, two flags aimed at one file — *without* touching the
//!   filesystem, so a run that fails before it compares anything leaves no
//!   confusing empty files behind, and `--dry-run` genuinely writes nothing.
//! * **Two verdict streams never share a file.** Pointing `--differ` and
//!   `--match` at the same path would interleave two lists into one file with no
//!   way to tell them apart, which is worse than either list alone; it is
//!   rejected up front.

// Some of what follows is not reachable from this build's `run` body: the engine
// has no entry point yet for the step that would call it (see the command's
// module documentation). It is written and unit-tested now, with the tests that
// pin its contract, rather than left until the engine lands — a machine-readable
// output format that first appears on the day it is needed is a format nobody
// reviewed.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::constants::COMBINED_MARK_SEPARATOR;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

use super::difference::Difference;

/// The flag spellings, mirroring the long names clap derives from the argument
/// fields. Named here so an error can point at the flag the user actually typed
/// rather than at an internal field name.
const FLAG_COMBINED: &str = "--combined";
/// See [`FLAG_COMBINED`].
const FLAG_MISSING_ON_SRC: &str = "--missing-on-src";
/// See [`FLAG_COMBINED`].
const FLAG_MISSING_ON_DST: &str = "--missing-on-dst";
/// See [`FLAG_COMBINED`].
const FLAG_DIFFER: &str = "--differ";
/// See [`FLAG_COMBINED`].
const FLAG_MATCH: &str = "--match";

/// Where each verdict stream should be written, if anywhere.
#[derive(Clone, Debug, Default)]
pub struct Destinations {
    /// Every path with its one-character verdict mark.
    pub combined: Option<PathBuf>,
    /// Paths present only at the destination.
    pub missing_on_src: Option<PathBuf>,
    /// Paths present only at the source.
    pub missing_on_dst: Option<PathBuf>,
    /// Paths present on both sides but different.
    pub differ: Option<PathBuf>,
    /// Paths that matched.
    pub matched: Option<PathBuf>,
}

impl Destinations {
    /// Whether the run was asked to write any files at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.combined.is_none()
            && self.missing_on_src.is_none()
            && self.missing_on_dst.is_none()
            && self.differ.is_none()
            && self.matched.is_none()
    }

    /// Every requested destination, paired with the flag that requested it.
    fn requested(&self) -> Vec<(&'static str, &Path)> {
        [
            (FLAG_COMBINED, self.combined.as_deref()),
            (FLAG_MISSING_ON_SRC, self.missing_on_src.as_deref()),
            (FLAG_MISSING_ON_DST, self.missing_on_dst.as_deref()),
            (FLAG_DIFFER, self.differ.as_deref()),
            (FLAG_MATCH, self.matched.as_deref()),
        ]
        .into_iter()
        .filter_map(|(flag, path)| path.map(|path| (flag, path)))
        .collect()
    }

    /// Check every destination without creating anything.
    ///
    /// # Errors
    /// [`CliError::usage`] when two flags name one file or a destination is a
    /// directory; an error carrying [`ExitCode::DirNotFound`] when the parent
    /// directory does not exist.
    pub fn validate(&self) -> Result<()> {
        let mut seen: BTreeMap<&Path, &'static str> = BTreeMap::new();

        for (flag, path) in self.requested() {
            if let Some(previous) = seen.insert(path, flag) {
                return Err(CliError::usage(format!(
                    "{previous} and {flag} both write to '{}'",
                    path.display()
                ))
                .with_hint(
                    "Two verdict streams in one file cannot be told apart afterwards. \
                     Give each flag its own path, or use --combined, whose marks \
                     distinguish them.",
                ));
            }

            if path.is_dir() {
                return Err(CliError::usage(format!(
                    "{flag} '{}' is a directory",
                    path.display()
                )));
            }

            // An absent parent is the common typo, and reporting it now — before
            // a comparison that may take hours — is the whole point of checking
            // ahead of time.
            // An empty parent means a bare filename, which is the working
            // directory and always exists.
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty() && !parent.is_dir())
            {
                return Err(CliError::new(
                    ExitCode::DirNotFound,
                    format!(
                        "{flag} '{}': the directory '{}' does not exist",
                        path.display(),
                        parent.display()
                    ),
                )
                .with_hint("Create the directory first, or write to an existing one."));
            }
        }
        Ok(())
    }
}

/// One open output file.
struct Sink {
    path: PathBuf,
    writer: BufWriter<File>,
}

impl Sink {
    fn create(path: &Path) -> Result<Self> {
        let file = File::create(path).map_err(|error| io_failure(path, &error))?;
        Ok(Self {
            path: path.to_path_buf(),
            writer: BufWriter::new(file),
        })
    }

    fn line(&mut self, text: &str) -> Result<()> {
        writeln!(self.writer, "{text}").map_err(|error| io_failure(&self.path, &error))
    }

    fn flush(&mut self) -> Result<()> {
        self.writer
            .flush()
            .map_err(|error| io_failure(&self.path, &error))
    }
}

/// The open verdict files for one run.
pub struct Sinks {
    combined: Option<Sink>,
    missing_on_src: Option<Sink>,
    missing_on_dst: Option<Sink>,
    differ: Option<Sink>,
    matched: Option<Sink>,
}

impl Sinks {
    /// Create every requested file, truncating any that already exist.
    ///
    /// Call only once the run is committed to producing results — and never
    /// under `--dry-run`, which must leave the filesystem untouched.
    ///
    /// # Errors
    /// Any failure to create one of the files, named so the user knows which.
    pub fn create(destinations: &Destinations) -> Result<Self> {
        Ok(Self {
            combined: open(destinations.combined.as_deref())?,
            missing_on_src: open(destinations.missing_on_src.as_deref())?,
            missing_on_dst: open(destinations.missing_on_dst.as_deref())?,
            differ: open(destinations.differ.as_deref())?,
            matched: open(destinations.matched.as_deref())?,
        })
    }

    /// Record one verdict.
    ///
    /// The combined file gets `<mark> <path>`; a per-verdict file gets the bare
    /// path, because that form feeds straight into `--files-from` with no
    /// post-processing.
    ///
    /// # Errors
    /// Any write failure, named with the file it happened on.
    pub fn record(&mut self, difference: Difference, path: &str) -> Result<()> {
        if let Some(sink) = self.combined.as_mut() {
            sink.line(&format!(
                "{}{COMBINED_MARK_SEPARATOR}{path}",
                difference.mark()
            ))?;
        }

        let stream = match difference {
            Difference::Match => self.matched.as_mut(),
            Difference::Differ => self.differ.as_mut(),
            Difference::MissingOnSrc => self.missing_on_src.as_mut(),
            Difference::MissingOnDst => self.missing_on_dst.as_mut(),
            // An unclassifiable path belongs in no verdict list; the combined
            // file's `!` mark is the only place it is honest to put it.
            Difference::Error => None,
        };
        if let Some(sink) = stream {
            sink.line(path)?;
        }
        Ok(())
    }

    /// Flush every file.
    ///
    /// Explicit rather than left to `Drop`, because a buffered write that fails
    /// while the value is being dropped has nowhere to report the failure — and
    /// a truncated verdict file that nobody was told about is precisely the
    /// silent partial success `PLAN.md` §6 forbids.
    ///
    /// # Errors
    /// Any flush failure, named with the file it happened on.
    pub fn finish(&mut self) -> Result<()> {
        for sink in [
            self.combined.as_mut(),
            self.missing_on_src.as_mut(),
            self.missing_on_dst.as_mut(),
            self.differ.as_mut(),
            self.matched.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            sink.flush()?;
        }
        Ok(())
    }
}

/// Create a sink for an optional path.
fn open(path: Option<&Path>) -> Result<Option<Sink>> {
    path.map(Sink::create).transpose()
}

/// Classify a filesystem failure, naming the file it happened on.
fn io_failure(path: &Path, error: &std::io::Error) -> CliError {
    let code = match error.kind() {
        std::io::ErrorKind::NotFound => ExitCode::DirNotFound,
        std::io::ErrorKind::PermissionDenied => ExitCode::FatalError,
        _ => ExitCode::Uncategorised,
    };
    CliError::new(code, format!("cannot write '{}': {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    #[test]
    fn no_flags_means_no_files() {
        let destinations = Destinations::default();
        assert!(destinations.is_empty());
        assert!(destinations.validate().is_ok());
    }

    #[test]
    fn validation_creates_nothing() {
        // The whole reason validation is separate from creation: a run that
        // fails before comparing anything must leave no empty artefacts, and
        // --dry-run must be able to check the arguments without writing.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("differ.txt");
        let destinations = Destinations {
            differ: Some(path.clone()),
            ..Destinations::default()
        };
        destinations.validate().unwrap();
        assert!(!path.exists(), "validation must not touch the filesystem");
    }

    #[test]
    fn two_flags_may_not_share_one_file() {
        // Interleaved verdicts cannot be separated afterwards, so this is
        // rejected rather than silently producing a useless file.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        let destinations = Destinations {
            differ: Some(path.clone()),
            matched: Some(path),
            ..Destinations::default()
        };
        let error = destinations.validate().unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some());
    }

    #[test]
    fn a_missing_parent_directory_is_reported_before_the_comparison() {
        let dir = tempfile::tempdir().unwrap();
        let destinations = Destinations {
            combined: Some(dir.path().join("nope").join("out.txt")),
            ..Destinations::default()
        };
        let error = destinations.validate().unwrap_err();
        assert_eq!(error.code(), ExitCode::DirNotFound);
    }

    #[test]
    fn a_directory_destination_is_a_usage_error() {
        let dir = tempfile::tempdir().unwrap();
        let destinations = Destinations {
            matched: Some(dir.path().to_path_buf()),
            ..Destinations::default()
        };
        assert_eq!(destinations.validate().unwrap_err().code(), ExitCode::Usage);
    }

    #[test]
    fn a_bare_filename_validates_against_the_working_directory() {
        // `--combined out.txt` has an empty parent, which must not be mistaken
        // for a missing directory.
        let destinations = Destinations {
            combined: Some(PathBuf::from("out.txt")),
            ..Destinations::default()
        };
        assert!(destinations.validate().is_ok());
    }

    #[test]
    fn the_combined_file_carries_rclone_marks_and_the_streams_carry_bare_paths() {
        let dir = tempfile::tempdir().unwrap();
        let combined = dir.path().join("combined.txt");
        let differ = dir.path().join("differ.txt");
        let missing_on_dst = dir.path().join("missing.txt");

        let destinations = Destinations {
            combined: Some(combined.clone()),
            differ: Some(differ.clone()),
            missing_on_dst: Some(missing_on_dst.clone()),
            ..Destinations::default()
        };
        destinations.validate().unwrap();

        let mut sinks = Sinks::create(&destinations).unwrap();
        sinks.record(Difference::Match, "same.txt").unwrap();
        sinks.record(Difference::Differ, "changed.txt").unwrap();
        sinks.record(Difference::MissingOnDst, "new.txt").unwrap();
        sinks.record(Difference::Error, "unreadable.txt").unwrap();
        sinks.finish().unwrap();

        assert_eq!(
            read(&combined),
            "= same.txt\n* changed.txt\n+ new.txt\n! unreadable.txt\n"
        );
        // A per-verdict file is a `--files-from` list, so it carries paths only.
        assert_eq!(read(&differ), "changed.txt\n");
        assert_eq!(read(&missing_on_dst), "new.txt\n");
    }

    #[test]
    fn an_unclassifiable_path_lands_only_in_the_combined_file() {
        // It is not a match, not a difference, and not missing anywhere — no
        // verdict list can honestly claim it.
        let dir = tempfile::tempdir().unwrap();
        let matched = dir.path().join("match.txt");
        let destinations = Destinations {
            matched: Some(matched.clone()),
            ..Destinations::default()
        };
        let mut sinks = Sinks::create(&destinations).unwrap();
        sinks.record(Difference::Error, "unreadable.txt").unwrap();
        sinks.finish().unwrap();
        assert_eq!(read(&matched), "");
    }

    #[test]
    fn creating_a_sink_truncates_a_previous_run() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("differ.txt");
        std::fs::write(&path, "stale content from an older run\n").unwrap();

        let destinations = Destinations {
            differ: Some(path.clone()),
            ..Destinations::default()
        };
        let mut sinks = Sinks::create(&destinations).unwrap();
        sinks.record(Difference::Differ, "a.txt").unwrap();
        sinks.finish().unwrap();
        assert_eq!(read(&path), "a.txt\n");
    }
}
