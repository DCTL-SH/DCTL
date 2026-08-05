//! `--min-age` and `--max-age` as one predicate.
//!
//! The two flags a migrating rclone user reaches for after `--exclude`, and the
//! pair whose direction is easiest to get backwards. rclone's reading, kept
//! exactly:
//!
//! * **`--min-age 7d`** keeps files that are *at least* seven days old. It is a
//!   floor on **age**, which is a ceiling on modification time: rclone takes
//!   `now - 7d` as the ceiling and drops anything modified after it.
//! * **`--max-age 7d`** keeps files modified within the last seven days. A
//!   ceiling on age, a floor on modification time.
//!
//! Both ends are **inclusive**, because rclone's comparisons are strict and a
//! file sitting exactly on the boundary therefore survives. That also matches
//! [`super::size::SizeBounds`], so the two pairs of flags cannot disagree about
//! what "the limit" means.
//!
//! ## The window is fixed once, not re-read per file
//!
//! `now` is captured when the filter is built, so a run that takes an hour
//! selects the same set at the end as at the beginning. Re-reading the clock per
//! candidate would make `--max-age 1h` mean something different for the first
//! file than for the last, and a `sync` whose two sides were enumerated minutes
//! apart would see a different window on each side and delete the difference.
//! rclone fixes the window when it builds the filter, for the same reason.
//!
//! ## A file whose time nobody knows
//!
//! [`AgeBounds::admits`] takes an [`Option`] and admits `None` — the same
//! decision [`super::Candidate::unmeasured_file`] documents for sizes, for the
//! same reason: a vault index rebuilt from object headers records no time, and
//! both ways of guessing are wrong in a direction the user cannot see.
//! Substituting "now" would make `--min-age 30d` hide every recovered object;
//! substituting the epoch would make `--max-age 30d` hide them instead. Showing
//! the row and letting the time column say `-` puts the uncertainty where it can
//! be read.
//!
//! **rclone does not do this.** A zero modification time sorts before every
//! floor, so `--max-age` there drops an object whose time is merely unknown. The
//! difference is deliberate and is one of the few places DCTL declines to copy
//! rclone's behaviour; it is written down here rather than left to be
//! discovered.

use std::fmt;

use crate::constants::{
    AGE_LIMIT_OFF, AGE_PARSE_EXAMPLES, AGE_SUFFIX_SECONDS, FILTER_FLAG_MAX_AGE, FILTER_FLAG_MIN_AGE,
};

/// Why a pair of age bounds was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgeProblem {
    /// One of the two values is not an age.
    Unreadable { flag: &'static str, detail: String },
    /// The bounds cross, so nothing can satisfy both.
    ///
    /// `--min-age 30d --max-age 7d` asks for files both older than a month and
    /// younger than a week. rclone refuses the same pair, and for the reason
    /// `PLAN.md` §6 cares about: a run that can only ever move nothing must not
    /// report success.
    Crossed { min: i64, max: i64 },
}

impl AgeProblem {
    /// Advice for the reader.
    pub fn hint(&self) -> String {
        match self {
            Self::Unreadable { .. } => {
                format!(
                    "Ages are written as {AGE_PARSE_EXAMPLES}; '{AGE_LIMIT_OFF}' removes a limit."
                )
            }
            Self::Crossed { .. } => format!(
                "{FILTER_FLAG_MIN_AGE} is a floor on how old a file must be and \
                 {FILTER_FLAG_MAX_AGE} is a ceiling, so the minimum has to be the \
                 smaller of the two. As written no file can satisfy both, and the \
                 run would move nothing and still report success."
            ),
        }
    }
}

impl fmt::Display for AgeProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { flag, detail } => write!(f, "{flag}: {detail}"),
            Self::Crossed { min, max } => write!(
                f,
                "{FILTER_FLAG_MIN_AGE} ({min} seconds) is longer than \
                 {FILTER_FLAG_MAX_AGE} ({max} seconds)"
            ),
        }
    }
}

impl std::error::Error for AgeProblem {}

/// The modification-time window a file has to fall inside.
///
/// Stored as absolute unix seconds rather than as the two durations, because
/// that is the form the comparison needs and it is what fixes the window for the
/// whole run. `from` comes from `--max-age` and `to` from `--min-age`: the
/// crossing of names is inherent to the flags and is exactly why they are
/// converted once, here, rather than at each comparison.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AgeBounds {
    /// Earliest modification time admitted, from `--max-age`.
    from: Option<i64>,
    /// Latest modification time admitted, from `--min-age`.
    to: Option<i64>,
}

impl AgeBounds {
    /// Both ends open.
    pub const fn open() -> Self {
        Self {
            from: None,
            to: None,
        }
    }

    /// Build a window from two ages in seconds, relative to `now`.
    ///
    /// # Errors
    /// [`AgeProblem::Crossed`] when the pair cannot both be satisfied.
    pub fn new(min_age: Option<i64>, max_age: Option<i64>, now: i64) -> Result<Self, AgeProblem> {
        if let (Some(min), Some(max)) = (min_age, max_age)
            && min > max
        {
            return Err(AgeProblem::Crossed { min, max });
        }
        Ok(Self {
            from: max_age.map(|age| now.saturating_sub(age)),
            to: min_age.map(|age| now.saturating_sub(age)),
        })
    }

    /// Parse and validate the two flags as the user typed them.
    ///
    /// # Errors
    /// [`AgeProblem::Unreadable`] naming which flag was mistyped, or
    /// [`AgeProblem::Crossed`] for a pair that can never match.
    pub fn parse(min: Option<&str>, max: Option<&str>, now: i64) -> Result<Self, AgeProblem> {
        Self::new(
            parse_one(min, FILTER_FLAG_MIN_AGE)?,
            parse_one(max, FILTER_FLAG_MAX_AGE)?,
            now,
        )
    }

    /// Whether a file last modified at `modified` is inside the window.
    ///
    /// `None` is admitted. See the module documentation for why an unknown time
    /// is not guessed at.
    pub fn admits(&self, modified: Option<i64>) -> bool {
        let Some(modified) = modified else {
            return true;
        };
        self.from.is_none_or(|from| modified >= from) && self.to.is_none_or(|to| modified <= to)
    }

    /// Whether either bound is set.
    pub const fn is_limited(&self) -> bool {
        self.from.is_some() || self.to.is_some()
    }

    /// The earliest modification time admitted, if any.
    pub const fn from(&self) -> Option<i64> {
        self.from
    }

    /// The latest modification time admitted, if any.
    pub const fn to(&self) -> Option<i64> {
        self.to
    }
}

/// Parse one age, attributing any failure to the flag it came from.
fn parse_one(value: Option<&str>, flag: &'static str) -> Result<Option<i64>, AgeProblem> {
    match value {
        None => Ok(None),
        Some(text) => parse_age(text).map_err(|detail| AgeProblem::Unreadable { flag, detail }),
    }
}

/// Turn `30s`, `90m`, `7d`, `1y` or a bare number of seconds into **whole
/// seconds**, for the flags whose grain is a second.
///
/// rclone's suffix table and its default unit ([`AGE_SUFFIX_SECONDS`]), so a
/// script that moved across keeps selecting the same files. `off` and an
/// explicit zero both mean "no limit" and return [`None`] — distinct from
/// `Some(0)`, which would be an age bound of zero seconds and, as `--min-age`,
/// would admit only files modified in the future.
///
/// **A span shorter than a second truncates to `Some(0)` here**, which is what
/// it has always done and is right for what this feeds: `--min-age` and
/// `--max-age` compare against a modification time recorded in whole seconds,
/// so `--min-age 500ms` cannot select anything a second boundary does not
/// already select. A caller that needs the finer answer asks [`parse_span`]
/// instead — `--max-duration 500ms` is a real half-second, and truncating
/// *that* one would leave the run unbounded, which is the opposite of what was
/// asked for.
///
/// # Errors
/// A message naming the input and the accepted spellings.
pub fn parse_age(input: &str) -> Result<Option<i64>, String> {
    // Derived from `parse_span` rather than parsing again, so the two can never
    // disagree about what `6M` is worth. One dialect, two grains.
    Ok(parse_span(input)?.map(|span| i64::try_from(span.as_secs()).unwrap_or(i64::MAX)))
}

/// The same dialect, at full precision.
///
/// [`parse_age`] is this with the sub-second part discarded, because the flags
/// it feeds compare against whole-second timestamps. Everything that is a real
/// length of time — `--max-duration` — reads it here, because `500ms`
/// truncated to zero seconds would mean *unbounded*, and a run silently left
/// unbounded by a value the parser accepted is the exact class of failure this
/// project keeps finding in itself.
///
/// # Errors
/// A message naming the input and the accepted spellings.
pub fn parse_span(input: &str) -> Result<Option<std::time::Duration>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(format!("an age is required (try {AGE_PARSE_EXAMPLES})"));
    }
    if trimmed.eq_ignore_ascii_case(AGE_LIMIT_OFF) {
        return Ok(None);
    }

    // Longest suffix first, and case-sensitively, or `ms` reads as `m` and 500
    // milliseconds silently becomes eight hours. The table is ordered for this;
    // see AGE_SUFFIX_SECONDS.
    let (number, seconds_per_unit) = AGE_SUFFIX_SECONDS
        .iter()
        .find_map(|(suffix, seconds)| {
            trimmed
                .strip_suffix(suffix)
                .filter(|rest| !rest.is_empty())
                .map(|rest| (rest, *seconds))
        })
        .ok_or_else(|| format!("'{input}' is not a valid age (try {AGE_PARSE_EXAMPLES})"))?;

    let value: f64 = number
        .trim()
        .parse()
        .map_err(|_| format!("'{input}' is not a valid age (try {AGE_PARSE_EXAMPLES})"))?;
    if value < 0.0 {
        return Err(format!("'{input}' is negative"));
    }
    if value == 0.0 {
        return Ok(None);
    }

    // Saturating rather than wrapping: an absurd age is a limit that admits
    // everything, which is what the user meant, rather than a negative one that
    // admits nothing.
    let seconds = value * seconds_per_unit;
    if !seconds.is_finite() || seconds >= i64::MAX as f64 {
        return Ok(None);
    }
    // `try_from_secs_f64` refuses a negative, a NaN and an overflow; the first
    // two are already refused above and the third is what the guard on the line
    // before covers, so a failure here is a value nobody can act on and "no
    // limit" is the same answer the guard gives.
    Ok(std::time::Duration::try_from_secs_f64(seconds).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed "now" so every assertion below is about the arithmetic and never
    /// about when the suite happened to run.
    const NOW: i64 = 1_700_000_000;
    const DAY: i64 = 86_400;

    fn window(min: Option<&str>, max: Option<&str>) -> AgeBounds {
        AgeBounds::parse(min, max, NOW).expect("bounds should parse")
    }

    #[test]
    fn every_suffix_rclone_accepts_is_worth_what_rclone_says() {
        // rclone's suffix table, kept whole. A table that disagreed by a factor
        // would make `--max-age 30d` select a year.
        for (written, seconds) in [
            ("1s", 1_i64),
            ("90s", 90),
            ("1m", 60),
            ("2h", 7_200),
            ("7d", 7 * DAY),
            ("1w", 7 * DAY),
            ("1M", 30 * DAY),
            ("1y", 365 * DAY),
            // A bare number is seconds, which is rclone's default unit.
            ("3600", 3_600),
            // Fractional ages are legal in rclone and truncate towards zero
            // here.
            ("1.5d", 36 * 3_600),
        ] {
            assert_eq!(
                parse_age(written),
                Ok(Some(seconds)),
                "'{written}' did not parse as {seconds} seconds"
            );
        }
        // Every suffix in the table is reachable, so a row added with the wrong
        // ordering cannot sit there unmatched.
        for (suffix, per_unit) in AGE_SUFFIX_SECONDS {
            let written = format!("2{suffix}");
            assert_eq!(
                parse_age(&written),
                Ok(Some((2.0 * per_unit) as i64)),
                "'{written}' did not resolve to its own multiplier"
            );
        }
    }

    #[test]
    fn a_minute_and_a_month_are_told_apart_by_case() {
        // The single most expensive typo in this table: `1M` is thirty days and
        // `1m` is sixty seconds, a factor of 43,200. Matching case-insensitively
        // would make `--max-age 6M` select the last six minutes of work.
        assert_eq!(parse_age("1m"), Ok(Some(60)));
        assert_eq!(parse_age("1M"), Ok(Some(30 * DAY)));
        // And `ms` must win over `s` and `m`, or 500ms becomes 500 minutes.
        assert_eq!(parse_age("500ms"), Ok(Some(0)));
        assert_eq!(parse_age("5000ms"), Ok(Some(5)));
    }

    #[test]
    fn off_and_zero_remove_a_limit_rather_than_setting_one() {
        for written in ["off", "OFF", "0", "0d"] {
            assert_eq!(parse_age(written), Ok(None), "'{written}'");
        }
        assert!(!window(Some("off"), Some("off")).is_limited());
    }

    #[test]
    fn a_bad_age_names_the_flag_it_came_from() {
        let error = AgeBounds::parse(Some("yesterday"), None, NOW).expect_err("bad min");
        assert!(error.to_string().contains(FILTER_FLAG_MIN_AGE));
        assert!(!error.hint().is_empty());

        let error = AgeBounds::parse(None, Some("7q"), NOW).expect_err("bad max");
        assert!(error.to_string().contains(FILTER_FLAG_MAX_AGE));

        assert!(parse_age("-5d").is_err());
        assert!(
            parse_age("d").is_err(),
            "a suffix with no number is not an age"
        );
        assert!(parse_age("").is_err());
    }

    #[test]
    fn min_age_keeps_the_old_and_max_age_keeps_the_new() {
        // The direction, which is the thing worth pinning: `--min-age` is a
        // floor on *age*, so it is a ceiling on modification time.
        let old_only = window(Some("7d"), None);
        assert!(old_only.admits(Some(NOW - 8 * DAY)), "eight days old");
        assert!(!old_only.admits(Some(NOW - DAY)), "one day old");

        let new_only = window(None, Some("7d"));
        assert!(new_only.admits(Some(NOW - DAY)));
        assert!(!new_only.admits(Some(NOW - 8 * DAY)));
    }

    #[test]
    fn both_ends_are_inclusive_at_the_boundary() {
        // rclone compares strictly, so a file exactly on the edge survives —
        // and the same convention as SizeBounds, so the two pairs of flags
        // cannot mean different things by "the limit".
        let exact = window(Some("7d"), Some("7d"));
        assert!(exact.admits(Some(NOW - 7 * DAY)));
        assert!(!exact.admits(Some(NOW - 7 * DAY - 1)));
        assert!(!exact.admits(Some(NOW - 7 * DAY + 1)));
    }

    #[test]
    fn a_window_selects_a_band_in_the_middle() {
        let band = window(Some("7d"), Some("30d"));
        assert!(!band.admits(Some(NOW - DAY)), "too new");
        assert!(band.admits(Some(NOW - 14 * DAY)), "inside the band");
        assert!(!band.admits(Some(NOW - 60 * DAY)), "too old");
    }

    #[test]
    fn crossed_bounds_are_refused_rather_than_matching_nothing() {
        let error = AgeBounds::parse(Some("30d"), Some("7d"), NOW).expect_err("crossed");
        assert!(matches!(error, AgeProblem::Crossed { .. }));
        assert!(error.to_string().contains(FILTER_FLAG_MIN_AGE));
        assert!(error.to_string().contains(FILTER_FLAG_MAX_AGE));
        assert!(error.hint().contains("nothing"));
        // Equal is not crossed: it selects exactly one instant, which is a
        // strange thing to ask for but not an impossible one.
        assert!(AgeBounds::parse(Some("7d"), Some("7d"), NOW).is_ok());
    }

    #[test]
    fn a_file_whose_time_nobody_knows_is_admitted_rather_than_guessed_at() {
        // The documented departure from rclone, which treats a zero time as
        // older than every floor and silently drops the row. A rebuilt vault
        // index has no times at all, so that rule would hide the whole vault
        // from `--max-age` — including objects that plainly qualify.
        let band = window(Some("7d"), Some("30d"));
        assert!(band.admits(None));
        assert!(AgeBounds::open().admits(None));
    }

    #[test]
    fn an_unlimited_window_admits_every_instant() {
        let open = AgeBounds::default();
        assert_eq!(open, AgeBounds::open());
        assert!(!open.is_limited());
        assert!(open.admits(Some(i64::MIN)));
        assert!(open.admits(Some(i64::MAX)));
    }

    #[test]
    fn the_window_is_readable_back_for_the_report() {
        // A filter nobody can inspect is a filter nobody can debug, and the two
        // ends are easy to transpose in the reading as well as in the writing.
        let band = window(Some("7d"), Some("30d"));
        assert_eq!(band.to(), Some(NOW - 7 * DAY));
        assert_eq!(band.from(), Some(NOW - 30 * DAY));
    }
}
