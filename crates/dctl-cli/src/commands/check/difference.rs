//! The vocabulary of a comparison: what two sides can disagree about, and how
//! "the same" is decided.
//!
//! `check` exists because `PLAN.md` §13.6 makes a tested restore a first-class
//! requirement — a backup nobody ever compared against its source is a hope, not
//! a backup. The comparison therefore has to be honest about *what* it proved,
//! and that is entirely a question of which fields it looked at:
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
    COMBINED_MARK_MISSING_ON_SRC, DIFFERENCE_DIFFER, DIFFERENCE_ERROR, DIFFERENCE_MATCH,
    DIFFERENCE_MISSING_ON_DST, DIFFERENCE_MISSING_ON_SRC,
};

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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Comparison {
    /// Size and modification time. The default.
    #[default]
    SizeAndModTime,
    /// Size alone (`--size-only`).
    SizeOnly,
    /// Content hash (`--checksum`). The only mode that proves equality.
    Checksum,
}

impl Comparison {
    /// The comparison the global flags select.
    ///
    /// `--checksum` and `--size-only` are declared mutually exclusive by clap, so
    /// there is no precedence question to get wrong here.
    #[must_use]
    pub const fn from_globals(globals: &GlobalArgs) -> Self {
        if globals.checksum {
            Self::Checksum
        } else if globals.size_only {
            Self::SizeOnly
        } else {
            Self::SizeAndModTime
        }
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
            Self::SizeAndModTime => {
                match source.size.zip(dest.size) {
                    Some((left, right)) if left != right => return Some(false),
                    Some(_) => {}
                    // One side has no size, so this mode cannot answer at all —
                    // the same "cannot tell" a missing clock produces below.
                    None => return None,
                }
                match (source.modified_unix, dest.modified_unix) {
                    (Some(left), Some(right)) => Some(left == right),
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
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
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
        let source = Entry::new("a.txt", Some(100)).modified(1);
        let dest = Entry::new("a.txt", Some(100)).modified(2);
        assert_eq!(
            classify(Some(&source), Some(&dest), Comparison::SizeAndModTime),
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
            classify(Some(&source), Some(&dest), Comparison::SizeAndModTime),
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
        assert!(!Comparison::SizeAndModTime.proves_contents());
        assert!(!Comparison::SizeOnly.proves_contents());
    }

    #[test]
    fn the_global_flags_select_the_comparison() {
        assert_eq!(
            Comparison::from_globals(&globals(&[])),
            Comparison::SizeAndModTime
        );
        assert_eq!(
            Comparison::from_globals(&globals(&["--checksum"])),
            Comparison::Checksum
        );
        assert_eq!(
            Comparison::from_globals(&globals(&["--size-only"])),
            Comparison::SizeOnly
        );
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
