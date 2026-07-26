//! Parsing the ages `cleanup` reasons about (`24h`, `7d`, `90m`).
//!
//! An age is the safety margin on a sweep: an incomplete multipart upload is
//! only *abandoned* once it is old enough that no live run could still be
//! finishing it. Getting that wrong deletes another process's in-flight work,
//! so the value is a flag rather than a hidden constant — and it is parsed
//! before the destructive gate, like every other removal input.
//!
//! The accepted spellings are exactly the suffixes
//! [`crate::output::size::duration`] prints, and the arithmetic reuses the same
//! `SECONDS_PER_*` constants. That symmetry is the point: what DCTL shows back
//! to the user is always something DCTL would accept.

use std::time::Duration;

use crate::constants::{
    CLEANUP_AGE_PARSE_EXAMPLES, DURATION_DAY_SUFFIX, DURATION_HOUR_SUFFIX, DURATION_MINUTE_SUFFIX,
    DURATION_SECOND_SUFFIX, SECONDS_PER_DAY, SECONDS_PER_HOUR, SECONDS_PER_MINUTE,
};
use crate::error::{CliError, Result};

/// Parse an age such as `24h`, `7d`, `90m`, `30s`, or a bare count of seconds.
///
/// # Errors
/// [`crate::exit::ExitCode::Usage`] when the number or the suffix is not
/// recognised, or when the value overflows a duration in seconds.
pub fn parse_age(input: &str) -> Result<Duration> {
    let trimmed = input.trim();
    let (number, suffix) = match trimmed.char_indices().last() {
        Some((index, last)) if last.is_ascii_alphabetic() => (&trimmed[..index], Some(last)),
        _ => (trimmed, None),
    };

    let value: u64 = number.trim().parse().map_err(|_| invalid(input))?;

    let seconds_per_unit = match suffix.map(|c| c.to_ascii_lowercase()) {
        None | Some(DURATION_SECOND_SUFFIX) => 1,
        Some(DURATION_MINUTE_SUFFIX) => SECONDS_PER_MINUTE,
        Some(DURATION_HOUR_SUFFIX) => SECONDS_PER_HOUR,
        Some(DURATION_DAY_SUFFIX) => SECONDS_PER_DAY,
        Some(_) => return Err(invalid(input)),
    };

    value
        .checked_mul(seconds_per_unit)
        .map(Duration::from_secs)
        .ok_or_else(|| invalid(input))
}

/// One message for every failure mode, so the hint always shows the spellings.
fn invalid(input: &str) -> CliError {
    CliError::usage(format!("'{input}' is not a valid age"))
        .with_hint(format!("Ages are written as {CLEANUP_AGE_PARSE_EXAMPLES}."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::CLEANUP_DEFAULT_MIN_AGE;
    use crate::exit::ExitCode;

    #[test]
    fn every_printed_suffix_is_also_an_accepted_one() {
        // The symmetry this module exists for: what `duration()` prints back
        // must parse again.
        assert_eq!(parse_age("30s").unwrap().as_secs(), 30);
        assert_eq!(parse_age("90m").unwrap().as_secs(), 90 * SECONDS_PER_MINUTE);
        assert_eq!(parse_age("24h").unwrap().as_secs(), SECONDS_PER_DAY);
        assert_eq!(parse_age("7d").unwrap().as_secs(), 7 * SECONDS_PER_DAY);
    }

    #[test]
    fn a_bare_number_is_seconds() {
        assert_eq!(parse_age("45").unwrap().as_secs(), 45);
    }

    #[test]
    fn suffixes_are_case_insensitive_and_surrounding_space_is_ignored() {
        assert_eq!(parse_age(" 2H ").unwrap().as_secs(), 2 * SECONDS_PER_HOUR);
    }

    #[test]
    fn zero_is_a_legal_age_meaning_no_margin() {
        // Legal but drastic: it sweeps uploads that may still be in flight.
        assert_eq!(parse_age("0h").unwrap(), Duration::ZERO);
    }

    #[test]
    fn nonsense_is_refused_with_advice() {
        for input in ["", "banana", "7w", "-1h", "1.5h", "h"] {
            let error = parse_age(input).unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "accepted '{input}'");
            assert!(error.hint().is_some(), "'{input}' failed without advice");
        }
    }

    #[test]
    fn an_overflowing_age_fails_instead_of_wrapping() {
        // Wrapping would turn "impossibly far in the past" into "right now",
        // which on a cleanup means sweeping live uploads.
        let error = parse_age(&format!("{}d", u64::MAX)).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[test]
    fn the_shipped_default_parses() {
        // Guards the constant against drifting into a spelling this rejects.
        assert!(parse_age(CLEANUP_DEFAULT_MIN_AGE).is_ok());
    }
}
