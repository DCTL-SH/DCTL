//! The vocabulary of a comparison: what two sides can disagree about, and how
//! "the same" is decided.
//!
//! `check` exists because [the plan](https://doc.dctl.sh/project/plan) §13.6
//! makes a tested restore a first-class requirement — a backup nobody ever
//! compared against its source is a hope, not a backup. The comparison
//! therefore has to be honest about *what* it proved, and that is entirely a
//! question of which fields it looked at:
//!
//! * size and modification time (the default) is cheap and catches the overwhelming
//!   majority of real differences, but two files can share both and differ;
//! * `--size-only` is cheaper still and deliberately ignores time, for
//!   destinations whose clocks or metadata cannot be trusted;
//! * `--checksum` is the only mode that actually proves the contents match.
//!
//! When the fields a mode needs are not available on both sides, the answer is
//! [`Difference::Error`] — never a silent fallback to a weaker comparison, and
//! never [`Difference::Match`]. A comparison that quietly downgrades itself is
//! worse than one that fails, because it reports a guarantee it did not check.

use serde::Serialize;

use crate::cli::GlobalArgs;
use crate::constants::{
    COMBINED_MARK_DIFFER, COMBINED_MARK_ERROR, COMBINED_MARK_MATCH, COMBINED_MARK_MISSING_ON_DST,
    COMBINED_MARK_MISSING_ON_SRC, DEFAULT_MODIFY_WINDOW_SECS, DIFFERENCE_DIFFER, DIFFERENCE_ERROR,
    DIFFERENCE_MATCH, DIFFERENCE_MISSING_ON_DST, DIFFERENCE_MISSING_ON_SRC,
};
use crate::error::Result;

/// One object as either side described it.
///
/// Everything except `path` and `size` is optional because the two sides are not
/// symmetrical: a vault always knows a plaintext hash, a local filesystem never
/// does until something reads the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Logical path, identical on both sides by construction.
    pub path: String,
    /// Size in bytes, when the side recorded one.
    ///
    /// A vault index rebuilt from object headers holds no sizes (see
    /// [`crate::source::Entry::size`]), and a `check` is the command whose whole
    /// job is to answer "are these the same". Absent rather than zero, so a
    /// size comparison against an unmeasured object returns "cannot tell"
    /// through the [`Comparison::same`] channel that already exists for it —
    /// rather than reporting a match between a real file and a fiction.
    pub size: Option<u64>,
    /// Last-modified time in unix seconds, when the side records one.
    pub modified_unix: Option<i64>,
    /// Content hash, when the side has one without reading the object.
    pub hash: Option<String>,
}

impl Entry {
    /// An entry with only the fields every side can supply.
    #[must_use]
    pub fn new(path: impl Into<String>, size: Option<u64>) -> Self {
        Self {
            path: path.into(),
            size,
            modified_unix: None,
            hash: None,
        }
    }

    /// Attach a modification time.
    #[must_use]
    pub const fn modified(mut self, unix_seconds: i64) -> Self {
        self.modified_unix = Some(unix_seconds);
        self
    }

    /// Attach a content hash.
    #[must_use]
    pub fn hashed(mut self, hash: impl Into<String>) -> Self {
        self.hash = Some(hash.into());
        self
    }
}

/// Which fields decide whether two entries are the same object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Comparison {
    /// Size and modification time, to within `window_secs`. The default.
    SizeAndModTime {
        /// Tolerance in whole seconds — [`crate::cli::window`] decides it, and
        /// the transfer family reads it from the same place.
        ///
        /// Carried in the value rather than read from a constant here, because
        /// this comparison and
        /// [`ComparePolicy`](crate::commands::transfer::ComparePolicy)'s must be
        /// the *same* tolerance. They were not: `check` demanded exact equality
        /// while `sync` allowed a second, so `check` reported files that `sync`
        /// had just written from their source, with the source's own time, as
        /// differing from it.
        window_secs: u64,
    },
    /// Size alone (`--size-only`).
    SizeOnly,
    /// Content hash (`--checksum`). The only mode that proves equality.
    Checksum,
}

impl Default for Comparison {
    /// Size and time at the default tolerance.
    ///
    /// Hand-written because the default variant carries a field, and the field's
    /// value is a decision — see [`crate::constants::DEFAULT_MODIFY_WINDOW_SECS`].
    fn default() -> Self {
        Self::SizeAndModTime {
            window_secs: DEFAULT_MODIFY_WINDOW_SECS,
        }
    }
}

impl Comparison {
    /// The comparison the global flags select.
    ///
    /// `--checksum` and `--size-only` are declared mutually exclusive by clap, so
    /// there is no precedence question to get wrong here.
    ///
    /// # Errors
    /// [`ExitCode::Usage`](crate::exit::ExitCode::Usage) for a `--modify-window`
    /// narrower than the resolution DCTL records — the same refusal a transfer
    /// gives, from the same function.
    pub fn from_globals(globals: &GlobalArgs) -> Result<Self> {
        if globals.checksum {
            return Ok(Self::Checksum);
        }
        if globals.size_only {
            return Ok(Self::SizeOnly);
        }
        Ok(Self::SizeAndModTime {
            window_secs: crate::cli::window::resolve(globals)?.as_secs(),
        })
    }

    /// Whether two entries are the same under this comparison.
    ///
    /// `None` means "cannot tell": the fields this mode needs are missing on at
    /// least one side. Callers turn that into [`Difference::Error`] rather than
    /// guessing.
    #[must_use]
    pub fn same(self, source: &Entry, dest: &Entry) -> Option<bool> {
        match self {
            // `zip` rather than `==` on the options: two absent sizes are two
            // unknowns, not a match. `Some(None) == Some(None)` would report a
            // rebuilt vault as identical to any other rebuilt vault without
            // either side having been measured.
            Self::SizeOnly => source
                .size
                .zip(dest.size)
                .map(|(left, right)| left == right),
            Self::SizeAndModTime { window_secs } => {
                match source.size.zip(dest.size) {
                    Some((left, right)) if left != right => return Some(false),
                    Some(_) => {}
                    // One side has no size, so this mode cannot answer at all —
                    // the same "cannot tell" a missing clock produces below.
                    None => return None,
                }
                match (source.modified_unix, dest.modified_unix) {
                    // Within the window, not exactly equal. Two sides can record
                    // the same instant differently and still both be right — a
                    // whole-second store against a nanosecond filesystem, a
                    // FAT destination rounding to two — and demanding equality
                    // reports a difference that exists only in digits neither
                    // side kept. See [`crate::cli::window`].
                    // `abs_diff` rather than a subtraction: two times far apart in
                    // opposite directions overflow an `i64` difference, and a
                    // wrapped one compares as "close".
                    (Some(left), Some(right)) => Some(left.abs_diff(right) <= window_secs),
                    // A side with no clock cannot be compared by time. Falling
                    // back to size alone would silently answer a weaker question.
                    _ => None,
                }
            }
            Self::Checksum => match (source.hash.as_deref(), dest.hash.as_deref()) {
                (Some(left), Some(right)) => Some(left.eq_ignore_ascii_case(right)),
                _ => None,
            },
        }
    }

    /// Whether this comparison proves the contents are identical.
    ///
    /// Only [`Comparison::Checksum`] does. The report says so, because "0
    /// differences" under a metadata comparison is a much weaker statement than
    /// under a checksum one.
    #[must_use]
    pub const fn proves_contents(self) -> bool {
        matches!(self, Self::Checksum)
    }
}

/// How one path differed between the two sides.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Difference {
    /// Present on both sides and the same under the active comparison.
    #[default]
    Match,
    /// Present on both sides, contents disagree.
    Differ,
    /// Present only at the destination.
    MissingOnSrc,
    /// Present only at the source.
    MissingOnDst,
    /// Neither the same nor different: a side could not be read, or the
    /// comparison needed a field that side did not have.
    Error,
}

impl Difference {
    /// The stable slug used in `--json` output and in the per-verdict files.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Match => DIFFERENCE_MATCH,
            Self::Differ => DIFFERENCE_DIFFER,
            Self::MissingOnSrc => DIFFERENCE_MISSING_ON_SRC,
            Self::MissingOnDst => DIFFERENCE_MISSING_ON_DST,
            Self::Error => DIFFERENCE_ERROR,
        }
    }

    /// The one-character mark `--combined` writes before the path.
    #[must_use]
    pub const fn mark(self) -> char {
        match self {
            Self::Match => COMBINED_MARK_MATCH,
            Self::Differ => COMBINED_MARK_DIFFER,
            Self::MissingOnSrc => COMBINED_MARK_MISSING_ON_SRC,
            Self::MissingOnDst => COMBINED_MARK_MISSING_ON_DST,
            Self::Error => COMBINED_MARK_ERROR,
        }
    }

    /// Whether this counts against the run: anything but a match.
    #[must_use]
    pub const fn is_difference(self) -> bool {
        !matches!(self, Self::Match)
    }

    /// Whether `--one-way` suppresses this verdict.
    ///
    /// Only "present at the destination but not the source". A one-way check
    /// asks "is everything from the source present and correct at the
    /// destination?", to which extra files at the destination are simply not an
    /// answer — that is the state a `copy` leaves behind by design.
    #[must_use]
    pub const fn suppressed_by_one_way(self) -> bool {
        matches!(self, Self::MissingOnSrc)
    }
}

impl Serialize for Difference {
    /// Fully qualified: this module imports `crate::error::Result`, which takes
    /// one type parameter, and `serde`'s signature needs the two-parameter one.
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.slug())
    }
}

/// Compare one path's presence and contents on both sides.
///
/// Takes `Option`s because absence is one of the answers: the caller walks the
/// union of both listings and hands over whatever each side had.
#[must_use]
pub fn classify(
    source: Option<&Entry>,
    dest: Option<&Entry>,
    comparison: Comparison,
) -> Difference {
    match (source, dest) {
        (Some(source), Some(dest)) => match comparison.same(source, dest) {
            Some(true) => Difference::Match,
            Some(false) => Difference::Differ,
            None => Difference::Error,
        },
        (Some(_), None) => Difference::MissingOnDst,
        (None, Some(_)) => Difference::MissingOnSrc,
        // The caller only asks about paths at least one side listed, so this is
        // unreachable in practice — classified as an error rather than a match
        // because "neither side has it" is not evidence that they agree.
        (None, None) => Difference::Error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn globals(args: &[&str]) -> GlobalArgs {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals
    }

    fn entry() -> Entry {
        Entry::new("a.txt", Some(100))
            .modified(1_700_000_000)
            .hashed("AA")
    }

    #[test]
    fn presence_on_one_side_only_is_named_from_the_missing_side() {
        // The flag names must read the same way as the verdicts, or a user
        // writing `--missing-on-dst` gets the opposite file.
        let entry = entry();
        assert_eq!(
            classify(Some(&entry), None, Comparison::SizeOnly),
            Difference::MissingOnDst
        );
        assert_eq!(
            classify(None, Some(&entry), Comparison::SizeOnly),
            Difference::MissingOnSrc
        );
    }

    #[test]
    fn size_only_ignores_time_and_hash() {
        let source = Entry::new("a.txt", Some(100)).modified(1).hashed("aa");
        let dest = Entry::new("a.txt", Some(100)).modified(2).hashed("bb");
        assert_eq!(
            classify(Some(&source), Some(&dest), Comparison::SizeOnly),
            Difference::Match
        );
    }

    #[test]
    fn the_default_comparison_notices_a_changed_time() {
        // Outside the window, so genuinely different rather than merely
        // differently recorded.
        let source = Entry::new("a.txt", Some(100)).modified(1);
        let dest = Entry::new("a.txt", Some(100)).modified(60);
        assert_eq!(
            classify(Some(&source), Some(&dest), Comparison::default()),
            Difference::Differ
        );
    }

    #[test]
    fn two_times_inside_the_window_are_a_match_not_a_difference() {
        // The half of the incremental-sync defect that lived here. `check`
        // demanded exact equality while `sync` allowed a second, so a tree
        // `sync` had just written — with the source's own time — came back as
        // `3 of 3 paths differ`. The two verbs now read the same tolerance from
        // `crate::cli::window`, and this is the assertion that fails first if
        // they ever stop.
        let source = Entry::new("a.txt", Some(100)).modified(1_700_000_000);
        let dest = Entry::new("a.txt", Some(100)).modified(1_700_000_001);
        assert_eq!(
            classify(Some(&source), Some(&dest), Comparison::default()),
            Difference::Match
        );
        // Symmetric: neither argument is privileged.
        assert_eq!(
            classify(Some(&dest), Some(&source), Comparison::default()),
            Difference::Match
        );
    }

    #[test]
    fn a_wider_window_is_the_value_that_is_used() {
        // A field that was carried and then ignored would look exactly like a
        // working one against the default. Two seconds apart: outside the
        // default window, inside a two-second one.
        let source = Entry::new("a.txt", Some(100)).modified(1_700_000_000);
        let dest = Entry::new("a.txt", Some(100)).modified(1_700_000_002);
        assert_eq!(
            classify(Some(&source), Some(&dest), Comparison::default()),
            Difference::Differ
        );
        assert_eq!(
            classify(
                Some(&source),
                Some(&dest),
                Comparison::SizeAndModTime { window_secs: 2 }
            ),
            Difference::Match
        );
    }

    #[test]
    fn a_size_difference_still_wins_inside_the_window() {
        // The window is a tolerance on *time*, not on content. A file whose
        // length changed within the same second must not be waved through.
        let source = Entry::new("a.txt", Some(100)).modified(1_700_000_000);
        let dest = Entry::new("a.txt", Some(101)).modified(1_700_000_000);
        assert_eq!(
            classify(Some(&source), Some(&dest), Comparison::default()),
            Difference::Differ
        );
    }

    #[test]
    fn times_far_apart_in_opposite_directions_do_not_wrap_into_a_match() {
        // A plain subtraction of two `i64` timestamps overflows here, and a
        // wrapped difference compares as "close" — a match between a file dated
        // before the epoch and one dated after the end of time.
        let source = Entry::new("a.txt", Some(1)).modified(i64::MIN);
        let dest = Entry::new("a.txt", Some(1)).modified(i64::MAX);
        assert_eq!(
            classify(Some(&source), Some(&dest), Comparison::default()),
            Difference::Differ
        );
    }

    #[test]
    fn a_missing_field_is_an_error_never_a_silent_downgrade() {
        // A destination with no clock must not be reported as matching just
        // because its size agrees: that answers a weaker question than the one
        // the user asked.
        let source = Entry::new("a.txt", Some(100)).modified(1);
        let dest = Entry::new("a.txt", Some(100));
        assert_eq!(
            classify(Some(&source), Some(&dest), Comparison::default()),
            Difference::Error
        );

        let source = Entry::new("a.txt", Some(100)).hashed("aa");
        let dest = Entry::new("a.txt", Some(100));
        assert_eq!(
            classify(Some(&source), Some(&dest), Comparison::Checksum),
            Difference::Error
        );
    }

    #[test]
    fn checksums_compare_case_insensitively_but_still_differ_on_content() {
        let source = Entry::new("a.txt", Some(100)).hashed("ABCD");
        let same = Entry::new("a.txt", Some(1)).hashed("abcd");
        let other = Entry::new("a.txt", Some(100)).hashed("beef");
        // Size is irrelevant under --checksum: the hash is the answer.
        assert_eq!(
            classify(Some(&source), Some(&same), Comparison::Checksum),
            Difference::Match
        );
        assert_eq!(
            classify(Some(&source), Some(&other), Comparison::Checksum),
            Difference::Differ
        );
    }

    #[test]
    fn only_a_checksum_comparison_claims_to_prove_contents() {
        assert!(Comparison::Checksum.proves_contents());
        assert!(!Comparison::default().proves_contents());
        assert!(!Comparison::SizeOnly.proves_contents());
    }

    #[test]
    fn the_global_flags_select_the_comparison() {
        assert_eq!(
            Comparison::from_globals(&globals(&[])).unwrap(),
            Comparison::default()
        );
        assert_eq!(
            Comparison::from_globals(&globals(&["--checksum"])).unwrap(),
            Comparison::Checksum
        );
        assert_eq!(
            Comparison::from_globals(&globals(&["--size-only"])).unwrap(),
            Comparison::SizeOnly
        );
        // The flag reaches this comparison too, not only the transfer family's.
        assert_eq!(
            Comparison::from_globals(&globals(&["--modify-window", "5"])).unwrap(),
            Comparison::SizeAndModTime { window_secs: 5 }
        );
        // And the refusal is the same one, from the same place.
        assert!(Comparison::from_globals(&globals(&["--modify-window", "0"])).is_err());
    }

    #[test]
    fn one_way_suppresses_only_extra_files_at_the_destination() {
        assert!(Difference::MissingOnSrc.suppressed_by_one_way());
        for difference in [
            Difference::Match,
            Difference::Differ,
            Difference::MissingOnDst,
            Difference::Error,
        ] {
            assert!(!difference.suppressed_by_one_way());
        }
    }

    #[test]
    fn only_a_match_is_not_a_difference() {
        assert!(!Difference::Match.is_difference());
        for difference in [
            Difference::Differ,
            Difference::MissingOnSrc,
            Difference::MissingOnDst,
            Difference::Error,
        ] {
            assert!(difference.is_difference());
        }
    }

    #[test]
    fn marks_and_slugs_are_unique_across_the_verdicts() {
        let all = [
            Difference::Match,
            Difference::Differ,
            Difference::MissingOnSrc,
            Difference::MissingOnDst,
            Difference::Error,
        ];
        for (index, difference) in all.iter().enumerate() {
            for other in &all[index + 1..] {
                assert_ne!(difference.mark(), other.mark());
                assert_ne!(difference.slug(), other.slug());
            }
        }
    }

    #[test]
    fn differences_serialise_as_their_slugs() {
        let json = serde_json::to_string(&Difference::MissingOnDst).unwrap();
        assert_eq!(json, "\"missing-on-dst\"");
    }
}
