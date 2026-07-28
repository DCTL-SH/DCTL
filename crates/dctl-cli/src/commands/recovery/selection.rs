//! Which files a backup or a restore considers, resolved and validated up front.
//!
//! One rule governs this file: **a filter that cannot be honoured is an error,
//! never a silence.** If `--exclude '*.iso'` were quietly ignored, a backup would
//! upload the archive the rule existed to keep out and its operator would have
//! no way to know; on the restore side the same silence writes files somebody
//! deliberately left out of the run.
//!
//! Honouring them is now the ordinary case. [`crate::filter::FilterSet`] is the
//! single engine every command consults — the transfer family, the listing
//! family and this one — so `--include`, `--exclude`, `--filter-from`,
//! `--files-from`, `--min-size`, `--max-size` and `--max-depth` mean exactly the
//! same thing to `dctl backup` as they do to `dctl copy`. Three implementations
//! of one flag would eventually disagree, and the way they disagree is that a
//! listing shows a file the backup then omits.
//!
//! What remains an error is a filter that will not *compile*: a malformed
//! pattern, a rule file that cannot be read, a size that does not parse. Those
//! are refused before anything is walked, because a run that proceeds with a
//! rule the operator believes is in force is the data-loss case this whole file
//! exists to prevent.
//!
//! Validation happens before anything else a command does, deliberately. A
//! `--max-size` that does not parse is a typo, and a typo in a size limit is
//! exactly the kind of mistake that quietly backs up a third of a dataset.
//!
//! ## Why this type still exists on top of the engine
//!
//! [`Selection`] is what a recovery *reports*: it is serialised into the plan
//! document, so `dctl backup --dry-run --json` states the rules the run applied
//! rather than leaving a reader to re-derive them from the command line. The
//! engine answers questions; this answers "what was asked for", and the two are
//! different jobs even though one is built from the other.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::cli::globals::GlobalArgs;
use crate::error::Result;
use crate::filter::{FilterSet, SizeBounds};

/// The resolved selection rules for one recovery.
///
/// Every field is omitted from the JSON when unset, so a machine consumer can
/// tell "no size limit" from "a limit of zero" without a sentinel value.
#[derive(Clone, Debug, Serialize)]
pub struct Selection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
    /// Recursion limit, or `None` for unlimited. Never carries the `-1`
    /// sentinel: "no limit" is the absence of a value, not a negative one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<usize>,
    /// The exact logical paths named by `--files-from`, or `None` when the run
    /// considers everything it can reach.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only: Option<BTreeSet<String>>,
    /// How many pattern rules are in force, so a plan document says whether any
    /// were. The rules themselves are not serialised: `--dump filters` is where
    /// a reader asks which one dropped a file, and duplicating them into every
    /// plan would bury the plan.
    pub rules: usize,

    /// The compiled engine. Skipped in the JSON — it is the *implementation* of
    /// the fields above, and serialising a matcher would say nothing a consumer
    /// could act on.
    #[serde(skip)]
    filter: FilterSet,
}

impl Default for Selection {
    fn default() -> Self {
        Self::from_filter(FilterSet::everything())
    }
}

impl PartialEq for Selection {
    /// Compares what was *asked for*, not the compiled program.
    ///
    /// The engine holds an NFA per rule and has no meaningful equality; the four
    /// reported fields plus the rule count are what a test is ever actually
    /// asserting about two selections.
    fn eq(&self, other: &Self) -> bool {
        self.min_size == other.min_size
            && self.max_size == other.max_size
            && self.max_depth == other.max_depth
            && self.only == other.only
            && self.rules == other.rules
    }
}

impl Eq for Selection {}

impl Selection {
    /// Read and validate the global filter flags.
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::Usage`] when a pattern will not compile, when a
    /// size does not parse, when the two size bounds cross (nothing could ever
    /// match, so the run would silently do nothing), when `--max-depth` is
    /// negative without being the documented "unlimited" sentinel, or when a
    /// `--filter-from`/`--files-from` file cannot be read or understood.
    pub fn resolve(globals: &GlobalArgs) -> Result<Self> {
        Ok(Self::from_filter(FilterSet::from_globals(globals)?))
    }

    /// Describe an already-compiled filter.
    ///
    /// The reported fields are read back out of the engine rather than captured
    /// alongside it, so a plan document cannot claim a bound the matcher is not
    /// actually applying.
    #[must_use]
    pub fn from_filter(filter: FilterSet) -> Self {
        let sizes: SizeBounds = filter.sizes();
        Self {
            min_size: sizes.min(),
            max_size: sizes.max(),
            max_depth: filter.depth().limit(),
            only: filter.explicit_paths().cloned(),
            rules: filter.rules().len(),
            filter,
        }
    }

    /// Whether a file at this path, size and modification time survives every
    /// rule.
    ///
    /// The single question a walk should ask, because the pattern rules, the
    /// path list, the size bounds and the age window are one decision: asking
    /// them separately is how a caller applies one and forgets another.
    ///
    /// `modified` is unix seconds, and [`None`] where the side genuinely does
    /// not know — a vault index row written by a rebuild, or a filesystem that
    /// records no times. It is a parameter rather than an option the filter
    /// carries because only the caller has the value, and that is what makes
    /// `--max-age` doing nothing here a compile error rather than a silence.
    #[must_use]
    pub fn admits_file(&self, path: &str, size: u64, modified: Option<i64>) -> bool {
        self.filter
            .admits(&crate::filter::Candidate::file(path, size).at(modified))
    }

    /// Whether a walk may descend into this directory.
    ///
    /// Deliberately not [`Selection::admits_file`]: a directory that is itself
    /// out of scope must still be entered when the rule that refused it says
    /// nothing about the tree below it. See [`FilterSet::may_descend`].
    #[must_use]
    pub fn may_descend(&self, path: &str) -> bool {
        self.filter.may_descend(path)
    }

    /// Whether any restriction at all is in force.
    ///
    /// Lets a command word an empty result honestly: "nothing here" and "nothing
    /// survived your filters" are different answers, and reporting the first
    /// when the second is true sends the operator looking for data that was
    /// never missing.
    #[must_use]
    pub fn is_restricting(&self) -> bool {
        self.filter.is_restricting()
    }
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
        assert!(selection.admits_file("anything", 0, None));
        assert!(selection.admits_file("anything", u64::MAX, None));
        assert!(selection.may_descend("anything/at/all"));
        assert!(!selection.is_restricting());
    }

    #[test]
    fn size_bounds_are_inclusive_on_both_ends() {
        let selection = resolve(&["--min-size", "1k", "--max-size", "2k"]).unwrap();
        assert_eq!(selection.min_size, Some(1024));
        assert_eq!(selection.max_size, Some(2048));
        assert!(!selection.admits_file("a", 1023, None));
        assert!(selection.admits_file("a", 1024, None));
        assert!(selection.admits_file("a", 2048, None));
        assert!(!selection.admits_file("a", 2049, None));
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
        assert!(selection.admits_file("a.txt", 1, None));
        assert!(!selection.admits_file("sub/a.txt", 1, None));
        // A directory *at* the limit is still entered — the limit applies to
        // what is inside it, not to the act of opening it.
        assert!(selection.may_descend(""));
        assert!(!selection.may_descend("sub"));
    }

    #[test]
    fn a_glob_filter_is_evaluated_rather_than_refused() {
        // The whole point of wiring the engine in: an `--exclude` used to stop
        // the command, which meant `dctl backup --exclude '*.iso'` could not run
        // at all. Now it removes exactly the files it names.
        let selection = resolve(&["--exclude", "*.iso"]).unwrap();
        assert_eq!(selection.rules, 1);
        assert!(selection.is_restricting());
        assert!(selection.admits_file("photo.jpg", 10, None));
        assert!(!selection.admits_file("ubuntu.iso", 10, None));
    }

    #[test]
    fn an_include_drops_everything_it_did_not_name() {
        // rclone's asymmetry, honoured here as it is in the transfer family.
        let selection = resolve(&["--include", "*.jpg"]).unwrap();
        assert!(selection.admits_file("photo.jpg", 10, None));
        assert!(!selection.admits_file("notes.txt", 10, None));
    }

    #[test]
    fn a_rule_file_is_read_and_applied_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("rules.txt");
        std::fs::write(&rules, "- *.tmp\n+ **\n").unwrap();
        let arg = rules.display().to_string();

        let selection = resolve(&["--filter-from", arg.as_str()]).unwrap();
        assert!(!selection.admits_file("build/out.tmp", 1, None));
        assert!(selection.admits_file("build/out.o", 1, None));
    }

    #[test]
    fn a_malformed_pattern_is_refused_rather_than_partially_applied() {
        // A rule that will not compile cannot be honoured, and proceeding with
        // an operator believing it is in force is the data-loss case.
        let error = resolve(&["--exclude", "a{b"]).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
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
        assert_eq!(selection.only.as_ref().map(BTreeSet::len), Some(2));
        assert!(selection.admits_file("photos/2024/a.jpg", 1, None));
        // Noise in the spelling must not produce a path that matches nothing.
        assert!(selection.admits_file("photos/2024/b.jpg", 1, None));
        assert!(!selection.admits_file("photos/2024/c.jpg", 1, None));
    }

    #[test]
    fn a_path_list_that_escapes_its_root_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let list = dir.path().join("paths.txt");
        std::fs::write(&list, "../../etc/shadow\n").unwrap();

        let list_arg = list.display().to_string();
        let error = resolve(&["--files-from", list_arg.as_str()]).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[test]
    fn a_missing_path_list_is_reported_as_missing() {
        let error = resolve(&["--files-from", "/nonexistent/list.txt"]).unwrap_err();
        assert_ne!(error.code(), ExitCode::Success);
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
        assert!(selection.admits_file("caf\u{e9}/a.jpg", 1, None));
    }

    #[test]
    fn a_walk_still_enters_a_directory_whose_children_were_named() {
        // The bug this guards: pruning `photos/` because the *directory* is not
        // in the `--files-from` list would report the tree as empty.
        let dir = tempfile::tempdir().unwrap();
        let list = dir.path().join("paths.txt");
        std::fs::write(&list, "photos/2024/a.jpg\n").unwrap();
        let list_arg = list.display().to_string();

        let selection = resolve(&["--files-from", list_arg.as_str()]).unwrap();
        assert!(selection.may_descend("photos"));
        assert!(selection.may_descend("photos/2024"));
        assert!(!selection.may_descend("documents"));
    }

    #[test]
    fn the_reported_rules_describe_the_engine_that_is_actually_applied() {
        // A plan document states the rules the run used, so the two must be read
        // out of the same value rather than captured separately.
        let selection = resolve(&["--exclude", "*.iso", "--min-size", "1k"]).unwrap();
        assert_eq!(selection.rules, 1);
        assert_eq!(selection.min_size, Some(1024));
        assert!(!selection.admits_file("ubuntu.iso", 4096, None));
        assert!(
            !selection.admits_file("tiny.txt", 10, None),
            "below --min-size"
        );
    }
}
