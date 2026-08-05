//! `--min-size` and `--max-size` as one predicate.
//!
//! Both bounds are **inclusive**, which is the only reading that makes
//! `--min-size 1K --max-size 1K` select the file that is exactly a kibibyte
//! rather than nothing. Exclusive bounds would also make the two flags disagree
//! with the sizes a listing prints: a file shown as `1.00 KiB` that
//! `--max-size 1K` refused would look like a bug in the listing.
//!
//! The pair is validated together rather than one flag at a time, because the
//! interesting mistake is not a bad number — it is two good numbers the wrong
//! way round. `--min-size 10G --max-size 1G` parses perfectly and can never
//! match anything, so a run using it would report success having moved nothing.
//! That is precisely the "reported work that did not happen" outcome
//! [the plan](https://doc.dctl.sh/project/plan) §6 forbids, so the crossed pair is a usage error instead.
//!
//! Sizes are parsed by [`crate::output::size::parse_size`], not here: the
//! spellings DCTL *accepts* and the spellings it *prints* are one contract, and
//! a second parser would be free to drift from it.
//!
//! ## A number with no unit is refused, and that is deliberate
//!
//! This is the one place these flags **refuse** an input rclone accepts, and it
//! exists because the two tools disagree about what the input means by a factor
//! of 1024. rclone gives a bare number the *kibibyte* multiplier —
//! `--max-size 1024` there is one mebibyte — while [`parse_size`] reads it as
//! bytes, which is what every other size in DCTL's own output means.
//!
//! Either reading is defensible; silently applying one to a command line written
//! for the other is not. `--max-size 100` would carry files up to 100 KiB for an
//! rclone user and up to 100 bytes here, and on `sync` the files in between are
//! not merely absent from the copy — they are candidates for deletion at the
//! destination. So a unitless bound is a usage error naming both readings, and
//! `--max-size 100B` and `--max-size 100K` are the two unambiguous ways to say
//! what was meant. `off` still needs no unit, because it is not a quantity.

use std::fmt;

use crate::constants::{
    FILTER_FLAG_MAX_SIZE, FILTER_FLAG_MIN_SIZE, SIZE_LIMIT_OFF, SIZE_PARSE_EXAMPLES,
};
use crate::output::size::parse_size;

/// Why a pair of size bounds was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SizeProblem {
    /// One of the two values is not a size.
    Unreadable { flag: &'static str, detail: String },
    /// A quantity with no unit, which DCTL and rclone read 1024 apart.
    Unitless { flag: &'static str, value: String },
    /// The bounds cross, so nothing can satisfy both.
    Crossed { min: u64, max: u64 },
}

impl SizeProblem {
    /// Advice for the reader.
    pub fn hint(&self) -> String {
        match self {
            Self::Unreadable { .. } => {
                format!(
                    "Sizes are written as {SIZE_PARSE_EXAMPLES}; '{SIZE_LIMIT_OFF}' removes a limit."
                )
            }
            Self::Unitless { value, .. } => format!(
                "Write '{value}B' for {value} bytes or '{value}K' for {value} kibibytes. \
                 rclone reads a bare number as kibibytes and every size DCTL prints is \
                 in bytes, so the two disagree by 1024 — on a sync that difference is \
                 not files missing from a copy, it is files deleted at the destination."
            ),
            Self::Crossed { .. } => {
                "No file can satisfy both bounds, so the run would move nothing \
                 and still report success. Swap them, or drop one."
                    .to_string()
            }
        }
    }
}

impl fmt::Display for SizeProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { flag, detail } => write!(f, "{flag}: {detail}"),
            Self::Unitless { flag, value } => write!(
                f,
                "{flag}: '{value}' has no unit, and a bare number means different \
                 things to different tools"
            ),
            Self::Crossed { min, max } => write!(
                f,
                "{FILTER_FLAG_MIN_SIZE} ({min} bytes) is larger than \
                 {FILTER_FLAG_MAX_SIZE} ({max} bytes)"
            ),
        }
    }
}

impl std::error::Error for SizeProblem {}

/// The size window a file has to fall inside.
///
/// `None` on either side is "no limit", never a sentinel number — so a caller
/// cannot confuse "unlimited" with "a limit of zero", which is the mistake that
/// turns `--max-size off` into a filter that admits nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SizeBounds {
    min: Option<u64>,
    max: Option<u64>,
}

impl SizeBounds {
    /// Both ends open. The starting point for a filter with no size flags, and
    /// `const` so an unrestricted [`super::FilterSet`] can be built in one.
    pub const fn open() -> Self {
        Self {
            min: None,
            max: None,
        }
    }

    /// Build a validated pair from two already-parsed values.
    ///
    /// # Errors
    /// [`SizeProblem::Crossed`] when the bounds cannot both be satisfied.
    pub fn new(min: Option<u64>, max: Option<u64>) -> Result<Self, SizeProblem> {
        if let (Some(low), Some(high)) = (min, max) {
            if low > high {
                return Err(SizeProblem::Crossed {
                    min: low,
                    max: high,
                });
            }
        }
        Ok(Self { min, max })
    }

    /// Parse and validate the two flags as the user typed them.
    ///
    /// # Errors
    /// [`SizeProblem::Unreadable`] naming which of the two flags was mistyped —
    /// the pair is easy to transpose, and an error that named neither would send
    /// the reader to the wrong one. [`SizeProblem::Crossed`] for a pair that
    /// cannot match.
    pub fn parse(min: Option<&str>, max: Option<&str>) -> Result<Self, SizeProblem> {
        Self::new(
            parse_one(min, FILTER_FLAG_MIN_SIZE)?,
            parse_one(max, FILTER_FLAG_MAX_SIZE)?,
        )
    }

    /// Whether a file of this size is inside the window. Both ends inclusive.
    pub fn admits(&self, size: u64) -> bool {
        self.min.is_none_or(|min| size >= min) && self.max.is_none_or(|max| size <= max)
    }

    /// Whether either bound is set.
    pub const fn is_limited(&self) -> bool {
        self.min.is_some() || self.max.is_some()
    }

    /// The lower bound, if any.
    pub const fn min(&self) -> Option<u64> {
        self.min
    }

    /// The upper bound, if any.
    pub const fn max(&self) -> Option<u64> {
        self.max
    }
}

/// Parse one bound, attributing any failure to the flag it came from.
fn parse_one(value: Option<&str>, flag: &'static str) -> Result<Option<u64>, SizeProblem> {
    let Some(text) = value else {
        return Ok(None);
    };
    if is_unitless(text) {
        return Err(SizeProblem::Unitless {
            flag,
            value: text.trim().to_string(),
        });
    }
    parse_size(text).map_err(|detail| SizeProblem::Unreadable { flag, detail })
}

/// Whether `text` is a quantity with no unit letter after it.
///
/// A shape test, not a parse: anything containing an ASCII letter carries a unit
/// (or is unparseable, which [`parse_size`] will say better). `off` therefore
/// passes straight through, and so does a malformed `10X`, whose real problem is
/// the suffix rather than the absence of one.
fn is_unitless(text: &str) -> bool {
    let trimmed = text.trim();
    !trimmed.is_empty() && !trimmed.contains(|c: char| c.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds(min: Option<&str>, max: Option<&str>) -> SizeBounds {
        SizeBounds::parse(min, max).expect("bounds should parse")
    }

    #[test]
    fn an_unset_pair_admits_everything() {
        let open = SizeBounds::default();
        assert_eq!(open, SizeBounds::open());
        assert!(!open.is_limited());
        assert!(open.admits(0));
        assert!(open.admits(u64::MAX));
    }

    #[test]
    fn both_bounds_are_inclusive_at_the_boundary() {
        // The whole point of this test: a file that is *exactly* the limit is
        // inside it, or `--min-size 1K --max-size 1K` would select nothing.
        let window = bounds(Some("1K"), Some("10K"));
        assert!(!window.admits(1023));
        assert!(window.admits(1024), "the lower bound is inclusive");
        assert!(window.admits(10 * 1024), "the upper bound is inclusive");
        assert!(!window.admits(10 * 1024 + 1));
    }

    #[test]
    fn a_single_size_window_admits_exactly_that_size() {
        let exact = bounds(Some("1K"), Some("1K"));
        assert!(exact.admits(1024));
        assert!(!exact.admits(1023));
        assert!(!exact.admits(1025));
    }

    #[test]
    fn one_sided_windows_leave_the_other_end_open() {
        let floor = bounds(Some("1M"), None);
        assert!(floor.admits(u64::MAX));
        assert!(!floor.admits(1));

        let ceiling = bounds(None, Some("1M"));
        assert!(ceiling.admits(0));
        assert!(!ceiling.admits(u64::MAX));
    }

    #[test]
    fn off_removes_a_limit_rather_than_setting_it_to_zero() {
        let window = bounds(None, Some(SIZE_LIMIT_OFF));
        assert!(!window.is_limited());
        assert!(window.admits(u64::MAX));
    }

    #[test]
    fn a_bare_number_is_refused_because_rclone_and_dctl_read_it_1024_apart() {
        // The silent divergence this closes. rclone gives a unitless value the
        // kibibyte multiplier, so `--max-size 100` selects files up to 100 KiB
        // there and would have selected files up to 100 bytes here. On a sync
        // the files in between are deletion candidates at the destination, not
        // merely absent.
        for flag in [FILTER_FLAG_MIN_SIZE, FILTER_FLAG_MAX_SIZE] {
            let error = if flag == FILTER_FLAG_MIN_SIZE {
                SizeBounds::parse(Some("100"), None)
            } else {
                SizeBounds::parse(None, Some("100"))
            }
            .expect_err("a unitless bound must be refused");
            match &error {
                SizeProblem::Unitless { flag: named, value } => {
                    assert_eq!(*named, flag);
                    assert_eq!(value, "100");
                }
                other => panic!("expected a unitless refusal, got {other}"),
            }
            // The remediation has to spell both readings, or the reader has to
            // guess which one DCTL meant.
            let hint = error.hint();
            assert!(hint.contains("100B"), "{hint}");
            assert!(hint.contains("100K"), "{hint}");
        }
        // A decimal with no unit is the same mistake and gets the same answer.
        assert!(matches!(
            SizeBounds::parse(Some("1.5"), None),
            Err(SizeProblem::Unitless { .. })
        ));
        // Both unambiguous spellings work, and mean what they say.
        assert_eq!(bounds(Some("100B"), None).min(), Some(100));
        assert_eq!(bounds(Some("100K"), None).min(), Some(100 * 1024));
        // `off` is not a quantity, so it needs no unit.
        assert!(SizeBounds::parse(None, Some(SIZE_LIMIT_OFF)).is_ok());
        // And a bad *suffix* is still reported as a bad suffix, not as a
        // missing one — that would send the reader to the wrong half.
        assert!(matches!(
            SizeBounds::parse(None, Some("10X")),
            Err(SizeProblem::Unreadable { .. })
        ));
    }

    #[test]
    fn a_zero_with_a_unit_is_a_real_limit() {
        // `--max-size 0K` asked for a size and must come back as one, or
        // "match nothing" silently becomes "match everything". A bare `0` is
        // refused with everything else that carries no unit, so the one
        // spelling that used to mean "unlimited" can no longer be typed by
        // accident where a limit was meant.
        assert!(matches!(
            SizeBounds::parse(None, Some("0")),
            Err(SizeProblem::Unitless { .. })
        ));
        let window = bounds(None, Some("0K"));
        assert!(window.is_limited());
        assert!(window.admits(0));
        assert!(!window.admits(1));
    }

    #[test]
    fn crossed_bounds_are_refused_rather_than_matching_nothing() {
        let error = SizeBounds::parse(Some("10G"), Some("1G")).expect_err("crossed bounds");
        assert!(matches!(error, SizeProblem::Crossed { .. }));
        assert!(error.to_string().contains(FILTER_FLAG_MIN_SIZE));
        assert!(error.to_string().contains(FILTER_FLAG_MAX_SIZE));
        assert!(error.hint().contains("nothing"));
        // Equal bounds are not crossed.
        assert!(SizeBounds::parse(Some("1G"), Some("1G")).is_ok());
    }

    #[test]
    fn an_unreadable_size_names_the_flag_it_came_from() {
        // The pair is easy to transpose; an error naming neither would send the
        // reader to the wrong flag.
        let error = SizeBounds::parse(Some("banana"), None).expect_err("bad min");
        assert!(error.to_string().contains(FILTER_FLAG_MIN_SIZE));
        assert!(!error.hint().is_empty());

        let error = SizeBounds::parse(None, Some("10X")).expect_err("bad max");
        assert!(error.to_string().contains(FILTER_FLAG_MAX_SIZE));
    }

    #[test]
    fn the_parsed_bounds_are_readable_back() {
        // The engine reports what it applied; a filter nobody can inspect is a
        // filter nobody can debug.
        let window = bounds(Some("1K"), Some("2K"));
        assert_eq!(window.min(), Some(1024));
        assert_eq!(window.max(), Some(2048));
    }
}
