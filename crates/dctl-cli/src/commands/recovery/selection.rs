//! Which files a backup or a restore considers, resolved and validated up front.
//!
//! Two rules govern this file, and both are about not lying.
//!
//! **A filter that cannot be honoured is an error, never a silence.** If
//! `--exclude '*.iso'` were quietly ignored, a backup would upload the archive
//! the rule existed to keep out, and its operator would have no way to know. The
//! glob matcher is not in this build yet, so asking for one fails loudly
//! (`GLOB_FILTER_FEATURE`).
//!
//! **`--files-from` is different, and is honoured.** An exact list of logical
//! paths needs no matcher — it is a set membership test — and it is what makes
//! the restore pre-flight (`PLAN.md` §13.6) usable today: an operator can hand
//! `restore` the manifest of what they intend to pull back and get every
//! unwritable name reported before a single byte lands.
//!
//! Validation happens before anything else a command does, deliberately. A
//! `--max-size` that does not parse is a typo, and a typo in a size limit is
//! exactly the kind of mistake that quietly backs up a third of a dataset.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::Serialize;

use crate::cli::globals::GlobalArgs;
use crate::constants::{
    GLOB_FILTER_FEATURE, MAX_DEPTH_UNLIMITED, PATTERN_FILTER_HINT, SIZE_PARSE_EXAMPLES,
};
use crate::error::{CliError, Result};
use crate::output::size;
use crate::platform::path as logical;

/// Comment marker in a `--files-from` list.
///
/// `#` at the start of a line, matching every other list file a sysadmin edits
/// (`hosts`, `crontab`, `.gitignore`). A manifest people annotate is a manifest
/// people keep up to date.
const FILES_FROM_COMMENT: char = '#';

/// The two size flags, spelled as the user typed them.
///
/// Named once because they appear both in the "which flag did you mistype"
/// message and in the crossed-bounds message; a rename that updated one and not
/// the other would send someone to the wrong flag.
const FLAG_MIN_SIZE: &str = "--min-size";
/// See [`FLAG_MIN_SIZE`].
const FLAG_MAX_SIZE: &str = "--max-size";

/// The resolved selection rules for one recovery.
///
/// Every field is omitted from the JSON when unset, so a machine consumer can
/// tell "no size limit" from "a limit of zero" without a sentinel value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Selection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
    /// Recursion limit, or `None` for unlimited. Never carries the `-1`
    /// sentinel: "no limit" is the absence of a value, not a negative one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<i32>,
    /// The exact logical paths named by `--files-from`, or `None` when the run
    /// considers everything it can reach.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only: Option<BTreeSet<String>>,
}

impl Selection {
    /// Read and validate the global filter flags.
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::Usage`] when a size does not parse, when the two
    /// size bounds cross (nothing could ever match, so the run would silently do
    /// nothing), or when `--max-depth` is negative without being the documented
    /// "unlimited" sentinel. [`crate::exit::ExitCode::FatalError`] when a glob
    /// filter is requested, since honouring it is not yet possible and ignoring
    /// it would be worse.
    pub fn resolve(globals: &GlobalArgs) -> Result<Self> {
        if !globals.include.is_empty()
            || !globals.exclude.is_empty()
            || !globals.filter_from.is_empty()
        {
            return Err(CliError::unimplemented(GLOB_FILTER_FEATURE).with_hint(PATTERN_FILTER_HINT));
        }

        let min_size = parse_bound(globals.min_size.as_deref(), FLAG_MIN_SIZE)?;
        let max_size = parse_bound(globals.max_size.as_deref(), FLAG_MAX_SIZE)?;
        match (min_size, max_size) {
            (Some(min), Some(max)) if min > max => {
                return Err(CliError::usage(format!(
                    "{FLAG_MIN_SIZE} ({min}) is larger than {FLAG_MAX_SIZE} ({max})"
                ))
                .with_hint(
                    "No file can satisfy both bounds, so the run would move nothing. \
                     Swap them, or drop one.",
                ));
            }
            _ => {}
        }

        let max_depth = match globals.max_depth {
            MAX_DEPTH_UNLIMITED => None,
            depth if depth < MAX_DEPTH_UNLIMITED => {
                return Err(
                    CliError::usage(format!("--max-depth {depth} is not a depth")).with_hint(
                        format!("Use a depth of 0 or more, or {MAX_DEPTH_UNLIMITED} for no limit."),
                    ),
                );
            }
            depth => Some(depth),
        };

        let only = if globals.files_from.is_empty() {
            None
        } else {
            Some(read_files_from(&globals.files_from)?)
        };

        Ok(Self {
            min_size,
            max_size,
            max_depth,
            only,
        })
    }

    /// Whether a file of this size is inside the size bounds.
    #[must_use]
    pub fn admits_size(&self, size: u64) -> bool {
        self.min_size.is_none_or(|min| size >= min) && self.max_size.is_none_or(|max| size <= max)
    }

    /// Whether this logical path is one the run was asked for.
    ///
    /// Always true when no `--files-from` was given: the absence of a list means
    /// "everything in scope", not "nothing".
    #[must_use]
    pub fn admits_path(&self, path: &str) -> bool {
        self.only.as_ref().is_none_or(|only| only.contains(path))
    }

    /// Whether a directory at this depth may still be descended into.
    ///
    /// Depth 1 is a file directly inside the transfer root, matching rclone's
    /// reading of `--max-depth 1` as "the top level only".
    #[must_use]
    pub fn admits_depth(&self, depth: i32) -> bool {
        self.max_depth.is_none_or(|max| depth <= max)
    }

    /// The explicit path list, if one was given.
    #[must_use]
    pub fn explicit_paths(&self) -> Option<&BTreeSet<String>> {
        self.only.as_ref()
    }
}

/// Parse one size bound, naming the flag in the error so the user knows which of
/// the two they mistyped.
fn parse_bound(value: Option<&str>, flag: &str) -> Result<Option<u64>> {
    match value {
        None => Ok(None),
        Some(raw) => size::parse_size(raw).map_err(|message| {
            CliError::usage(format!("{flag}: {message}"))
                .with_hint(format!("Sizes are written as {SIZE_PARSE_EXAMPLES}."))
        }),
    }
}

/// Read every `--files-from` list into one canonical set of logical paths.
///
/// Blank lines and `#` comments are skipped. Each surviving line goes through
/// [`logical::clean_logical`], so a list written on Windows with backslashes, or
/// on a Mac with decomposed accents, selects the same objects as one written on
/// Linux — the same normalisation the index key itself uses.
fn read_files_from(sources: &[PathBuf]) -> Result<BTreeSet<String>> {
    let mut paths = BTreeSet::new();

    for source in sources {
        let text = std::fs::read_to_string(source).map_err(|error| {
            CliError::from(error)
                .with_hint(format!("--files-from could not read {}.", source.display()))
        })?;

        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(FILES_FROM_COMMENT) {
                continue;
            }
            let Some(cleaned) = logical::clean_logical(line) else {
                return Err(CliError::usage(format!(
                    "{}:{}: '{line}' escapes the transfer root with '..'",
                    source.display(),
                    number + 1
                ))
                .with_hint(
                    "Paths in a --files-from list are relative to the transfer root \
                     and may not contain '..' components.",
                ));
            };
            if !cleaned.is_empty() {
                paths.insert(cleaned);
            }
        }
    }

    Ok(paths)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::exit::ExitCode;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn globals(args: &[&str]) -> GlobalArgs {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals
    }

    fn resolve(args: &[&str]) -> Result<Selection> {
        Selection::resolve(&globals(args))
    }

    #[test]
    fn an_unfiltered_run_admits_everything() {
        let selection = resolve(&[]).unwrap();
        assert!(selection.admits_size(0));
        assert!(selection.admits_size(u64::MAX));
        assert!(selection.admits_path("anything"));
        assert!(selection.admits_depth(i32::MAX));
        assert!(selection.explicit_paths().is_none());
    }

    #[test]
    fn size_bounds_are_inclusive_on_both_ends() {
        let selection = resolve(&["--min-size", "1k", "--max-size", "2k"]).unwrap();
        assert_eq!(selection.min_size, Some(1024));
        assert_eq!(selection.max_size, Some(2048));
        assert!(!selection.admits_size(1023));
        assert!(selection.admits_size(1024));
        assert!(selection.admits_size(2048));
        assert!(!selection.admits_size(2049));
    }

    #[test]
    fn crossed_size_bounds_are_a_usage_error() {
        // Silently matching nothing is the failure mode this prevents: the run
        // would report a clean success having moved not one file.
        let error = resolve(&["--min-size", "10G", "--max-size", "1M"]).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some());
    }

    #[test]
    fn an_unparseable_size_names_the_flag_that_carried_it() {
        let error = resolve(&["--max-size", "banana"]).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("--max-size"));
    }

    #[test]
    fn the_unlimited_sentinel_becomes_an_absent_depth() {
        assert_eq!(resolve(&[]).unwrap().max_depth, None);
        assert_eq!(resolve(&["--max-depth", "2"]).unwrap().max_depth, Some(2));
        // Written with `=` because a bare `-4` is a flag as far as the parser
        // is concerned; the value still has to be validated, not trusted.
        assert_eq!(
            resolve(&["--max-depth=-4"]).unwrap_err().code(),
            ExitCode::Usage
        );
    }

    #[test]
    fn depth_one_is_the_top_level_only() {
        let selection = resolve(&["--max-depth", "1"]).unwrap();
        assert!(selection.admits_depth(1));
        assert!(!selection.admits_depth(2));
    }

    #[test]
    fn a_glob_filter_is_refused_rather_than_ignored() {
        // The whole point: an ignored --exclude backs up the file the rule was
        // written to keep out, and nobody finds out until the bill arrives.
        for args in [
            vec!["--include", "*.raw"],
            vec!["--exclude", "*.iso"],
            vec!["--filter-from", "rules.txt"],
        ] {
            let error = resolve(&args).unwrap_err();
            assert_ne!(error.code(), ExitCode::Success);
            assert!(error.message().contains("glob filtering"));
        }
    }

    #[test]
    fn an_exact_path_list_is_honoured() {
        let dir = tempfile::tempdir().unwrap();
        let list = dir.path().join("paths.txt");
        std::fs::write(
            &list,
            "# a manifest\n\nphotos/2024/a.jpg\r\n./photos//2024/b.jpg\n",
        )
        .unwrap();

        let list_arg = list.display().to_string();
        let selection = resolve(&["--files-from", list_arg.as_str()]).unwrap();
        let paths = selection.explicit_paths().unwrap();
        assert_eq!(paths.len(), 2);
        assert!(selection.admits_path("photos/2024/a.jpg"));
        // Noise in the spelling must not produce a path that matches nothing.
        assert!(selection.admits_path("photos/2024/b.jpg"));
        assert!(!selection.admits_path("photos/2024/c.jpg"));
    }

    #[test]
    fn a_path_list_that_escapes_its_root_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let list = dir.path().join("paths.txt");
        std::fs::write(&list, "../../etc/shadow\n").unwrap();

        let list_arg = list.display().to_string();
        let error = resolve(&["--files-from", list_arg.as_str()]).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("escapes"));
    }

    #[test]
    fn a_missing_path_list_is_reported_as_missing() {
        let error = resolve(&["--files-from", "/nonexistent/list.txt"]).unwrap_err();
        assert_eq!(error.code(), ExitCode::FileNotFound);
        assert!(error.hint().is_some());
    }

    #[test]
    fn unicode_spellings_in_a_list_converge_with_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let list = dir.path().join("paths.txt");
        // Written on a Mac: decomposed.
        std::fs::write(&list, "cafe\u{301}/a.jpg\n").unwrap();

        let list_arg = list.display().to_string();
        let selection = resolve(&["--files-from", list_arg.as_str()]).unwrap();
        // Addressed from Linux: composed. Both must be the same object.
        assert!(selection.admits_path("caf\u{e9}/a.jpg"));
    }
}
