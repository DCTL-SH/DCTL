//! A length of time typed on the command line, with `off` for "no limit".
//!
//! `--max-duration 4h` takes one, and it is a **cost control** in the same sense
//! [`super::quantity::ByteLimit`] is: it is what an operator sets so that a job
//! which goes wrong cannot run past the window it was given. That is why it is
//! parsed here, by clap, rather than in a command body — a `--max-duration` that
//! failed to parse and was then *ignored* would be a backup window silently
//! removed, which is the exact shape of failure this whole family of types
//! exists to prevent.
//!
//! # The dialect is the one this binary already speaks
//!
//! `--min-age` and `--max-age` read `30s`, `90m`, `2h`, `7d`, `1w`, `6M`, `1y`
//! and a bare number of seconds (`crate::constants::AGE_SUFFIX_SECONDS`, which
//! is rclone's table verbatim), and `off` removes the limit. This reuses that
//! parser rather than adding a second one, because two duration dialects inside
//! one binary is how `--min-age 30m` and `--max-duration 30m` come to mean
//! different lengths of time — and the project has already paid once for a flag
//! that had two parsers (`crate::constants`, the note above
//! `AGE_SUFFIX_SECONDS`).
//!
//! rclone's own `--max-duration` takes a Go duration, so `1h30m` is legal there
//! and is **not** legal here; `90m` is. That difference is a refusal rather than
//! a silent misreading — the parser rejects what it cannot read — which is the
//! direction this project errs in everywhere else.
//!
//! # `off` and `0` are one meaning
//!
//! No limit, represented as [`None`] rather than as `Some(0)`, so "unbounded"
//! can never be confused with "a window of zero seconds" — which would mean a
//! run that must be over before it starts. rclone reads a zero `--max-duration`
//! the same way, arming the deadline only when the value is positive.

use std::str::FromStr;
use std::time::Duration;

use crate::filter::age::parse_span;

/// A window of time, or none at all.
///
/// A newtype rather than a bare `Option<Duration>` so the `off` spelling has
/// exactly one implementation, and so a function taking a run's window cannot be
/// handed some other duration by mistake.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimeLimit(Option<Duration>);

impl TimeLimit {
    /// No limit — what `off`, `0` and an absent flag all mean.
    #[must_use]
    pub const fn none() -> Self {
        Self(None)
    }

    /// A window of exactly this long.
    ///
    /// Zero is normalised to [`TimeLimit::none`] rather than kept, because the
    /// two spellings a user has for "unbounded" must not produce two different
    /// values downstream.
    #[must_use]
    pub const fn of(value: Duration) -> Self {
        if value.is_zero() {
            Self(None)
        } else {
            Self(Some(value))
        }
    }

    /// The window, or [`None`] when there is none.
    #[must_use]
    pub const fn get(self) -> Option<Duration> {
        self.0
    }
}

impl FromStr for TimeLimit {
    /// A message, because that is what clap renders for a bad value.
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        // `parse_span`, not `parse_age`, and the difference is a bound that
        // exists rather than one that does not: the age filters compare against
        // whole-second timestamps and discard anything shorter, so
        // `--max-duration 500ms` read through them would truncate to zero — and
        // zero means *unbounded*. A value the parser accepted and then silently
        // dropped is the failure this whole type exists to prevent.
        parse_span(input).map(|parsed| parsed.map_or_else(Self::none, Self::of))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_off_spellings_all_mean_no_limit() {
        for spelling in ["off", "OFF", "0"] {
            assert_eq!(
                spelling.parse::<TimeLimit>().unwrap().get(),
                None,
                "'{spelling}' must mean unbounded"
            );
        }
    }

    #[test]
    fn a_window_parses_in_the_dialect_the_age_filters_use() {
        // One dialect per binary. If these ever diverge from `--min-age`, an
        // operator who has learned one of the two has learned the wrong one.
        assert_eq!(
            "30s".parse::<TimeLimit>().unwrap().get(),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            "90m".parse::<TimeLimit>().unwrap().get(),
            Some(Duration::from_secs(90 * 60))
        );
        assert_eq!(
            "4h".parse::<TimeLimit>().unwrap().get(),
            Some(Duration::from_secs(4 * 3600))
        );
        // A bare number is seconds, matching rclone and the age filters.
        assert_eq!(
            "3600".parse::<TimeLimit>().unwrap().get(),
            Some(Duration::from_secs(3600))
        );
    }

    #[test]
    fn a_malformed_window_is_a_message_and_not_a_silently_unbounded_run() {
        // The failure this type exists to prevent: `--max-duration 4hrs`
        // accepted, parsed to nothing, and the run never bounded at all.
        let error = "4hrs".parse::<TimeLimit>().unwrap_err();
        assert!(error.contains("4hrs"), "{error}");
        assert!("-5m".parse::<TimeLimit>().is_err());
        assert!("nonsense".parse::<TimeLimit>().is_err());
        assert!("".parse::<TimeLimit>().is_err());
    }

    #[test]
    fn a_window_shorter_than_a_second_is_a_real_window() {
        // The trap this type was written into and had to be pulled out of. The
        // age filters read the same dialect at whole-second grain, where a
        // sub-second value is correctly "no limit"; here that truncation would
        // mean an operator who wrote `500ms` got a run nothing bounded, which is
        // the opposite of what they asked for and is invisible.
        assert_eq!(
            "500ms".parse::<TimeLimit>().unwrap().get(),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            "1ms".parse::<TimeLimit>().unwrap().get(),
            Some(Duration::from_millis(1))
        );
        assert_eq!(
            "1.5s".parse::<TimeLimit>().unwrap().get(),
            Some(Duration::from_millis(1500))
        );
    }

    #[test]
    fn a_window_of_zero_is_unbounded_rather_than_impassable() {
        // The one reading that must not happen: a run required to be over
        // before it starts. rclone arms the deadline only when the value is
        // positive, and so does this.
        assert_eq!(TimeLimit::of(Duration::ZERO), TimeLimit::none());
        assert_eq!(
            TimeLimit::of(Duration::from_secs(1)).get(),
            Some(Duration::from_secs(1))
        );
    }
}
