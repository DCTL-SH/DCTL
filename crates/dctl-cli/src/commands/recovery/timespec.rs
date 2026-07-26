//! Point-in-time arguments: `restore --at`, `audit --since`, `audit --until`.
//!
//! Four spellings are accepted, because the three audiences that type them want
//! different things: a person reaching for yesterday writes `2d`, a person
//! quoting an incident report writes `2026-07-26T14:30:00Z`, a script that has
//! already done arithmetic writes `@1753574400`, and a default writes `now`.
//! All four resolve to the same thing — Unix seconds, UTC.
//!
//! **UTC, always.** A local-time interpretation would make `--at 2026-07-26`
//! select a different set of objects on a laptop in Berlin than on a build agent
//! in UTC, and would be ambiguous for one hour every autumn when the local clock
//! repeats itself. A restore that quietly picks a different point in time
//! depending on where it runs is not a restore anybody can test (`PLAN.md`
//! §13.6), so the timezone is not a variable here.
//!
//! The Gregorian arithmetic below is **not** in [`crate::constants`] on purpose.
//! A tunable is something an operator might reasonably change; the number of
//! days in a 400-year era is not. Putting it beside the algorithm that uses it
//! keeps the constants module honest about what it holds.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::constants::{
    RFC3339_DATE_SEPARATOR, RFC3339_TIME_SEPARATOR, SECONDS_PER_HOUR, SECONDS_PER_MINUTE,
    TIME_DATE_TIME_SEPARATORS, TIME_MAX_YEAR, TIME_MIN_YEAR, TIME_NOW_KEYWORD, TIME_OFFSET_SIGNS,
    TIME_PARSE_EXAMPLES, TIME_RELATIVE_SUFFIXES, TIME_UNIX_PREFIX, TIME_UTC_DESIGNATORS,
};
use crate::error::{CliError, Result};

/// An instant, as seconds since 1970-01-01T00:00:00Z.
pub type UnixSeconds = i64;

/// Seconds in a day, as the calendar arithmetic below counts them.
///
/// Deliberately re-derived here rather than imported: this is the *civil* day
/// used to convert a date into an instant, and it is 86 400 seconds by
/// definition of the conversion, not by policy.
const SECONDS_PER_CIVIL_DAY: i64 = 86_400;

/// Days in a 400-year Gregorian era, and the offset that moves the era's origin
/// (0000-03-01) to the Unix epoch (1970-01-01).
///
/// These are Howard Hinnant's `days_from_civil` constants: fixed properties of
/// the Gregorian calendar, exact for every date the calendar defines.
const DAYS_PER_ERA: i64 = 146_097;
/// See [`DAYS_PER_ERA`].
const ERA_TO_EPOCH_DAYS: i64 = 719_468;

/// Days in each month of a non-leap year, January first.
const DAYS_IN_MONTH: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Read the wall clock.
///
/// A clock set before the epoch yields a negative value rather than an error:
/// the caller wants a number to compare against, and refusing to run because a
/// machine's RTC is wrong would be a worse failure than reporting the time it
/// actually claims.
#[must_use]
pub fn now() -> UnixSeconds {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(since) => since.as_secs() as i64,
        Err(before) => -(before.duration().as_secs() as i64),
    }
}

/// Parse a point in time, resolving relative spellings against `reference`.
///
/// `reference` is passed in rather than read from the clock so a test can pin
/// it, and so every `--at`/`--since`/`--until` in one invocation resolves
/// against the same instant instead of drifting by however long the parse took.
///
/// # Errors
/// [`crate::exit::ExitCode::Usage`] when the value matches none of the accepted
/// spellings, names an impossible date such as `2026-02-30`, or overflows.
pub fn parse(input: &str, reference: UnixSeconds) -> Result<UnixSeconds> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(unparseable(input));
    }

    if trimmed.eq_ignore_ascii_case(TIME_NOW_KEYWORD) {
        return Ok(reference);
    }

    if let Some(rest) = trimmed.strip_prefix(TIME_UNIX_PREFIX) {
        return rest.trim().parse::<i64>().map_err(|_| unparseable(input));
    }

    if let Some(seconds) = parse_relative(trimmed) {
        return reference.checked_sub(seconds).ok_or_else(|| {
            CliError::usage(format!("'{input}' is further back than time goes"))
                .with_hint("Name an absolute instant instead, for example 1970-01-01.")
        });
    }

    parse_calendar(trimmed).ok_or_else(|| unparseable(input))
}

/// The error every unrecognised spelling produces.
///
/// One constructor so the hint cannot drift between the four call sites: a user
/// who mistyped a date needs the list of shapes, not four different phrasings of
/// "no".
fn unparseable(input: &str) -> CliError {
    CliError::usage(format!("'{input}' is not a time")).with_hint(format!(
        "Accepted spellings: {TIME_PARSE_EXAMPLES}. Times are UTC."
    ))
}

/// Parse `<count><unit>` as a number of seconds *ago*, or `None` if it is not
/// that shape.
fn parse_relative(input: &str) -> Option<i64> {
    let unit = input.chars().last()?;
    let (_, multiplier) = TIME_RELATIVE_SUFFIXES
        .iter()
        .find(|(suffix, _)| *suffix == unit)?;

    let count: i64 = input[..input.len() - unit.len_utf8()].parse().ok()?;
    if count < 0 {
        // A negative offset would name the future, which no backup contains.
        return None;
    }
    count.checked_mul(*multiplier as i64)
}

/// Parse a calendar spelling: `YYYY-MM-DD`, optionally followed by a time of day
/// and a zone.
fn parse_calendar(input: &str) -> Option<UnixSeconds> {
    let (date, clock) = match input.find(TIME_DATE_TIME_SEPARATORS) {
        // Every accepted separator is one ASCII byte, so the split is always on
        // a character boundary.
        Some(index) => (&input[..index], Some(&input[index + 1..])),
        None => (input, None),
    };

    let (year, month, day) = parse_date(date)?;
    let (seconds_of_day, offset) = match clock {
        Some(clock) => parse_clock(clock)?,
        None => (0, 0),
    };

    let days = days_from_civil(year, month, day);
    days.checked_mul(SECONDS_PER_CIVIL_DAY)?
        .checked_add(seconds_of_day)?
        .checked_sub(offset)
}

/// Parse `YYYY-MM-DD`, rejecting a day the month does not have.
fn parse_date(date: &str) -> Option<(i64, i64, i64)> {
    let mut fields = date.split(RFC3339_DATE_SEPARATOR);
    let year = digits(fields.next()?)?;
    let month = digits(fields.next()?)?;
    let day = digits(fields.next()?)?;
    if fields.next().is_some() {
        return None;
    }

    if !(TIME_MIN_YEAR..=TIME_MAX_YEAR).contains(&year) || !(1..=12).contains(&month) {
        return None;
    }
    if day < 1 || day > days_in_month(year, month) {
        return None;
    }
    Some((year, month, day))
}

/// Parse `HH:MM[:SS][.frac][Z|±HH:MM]` into (seconds into the day, UTC offset).
fn parse_clock(clock: &str) -> Option<(i64, i64)> {
    let (clock, offset) = split_zone(clock)?;

    let mut fields = clock.split(RFC3339_TIME_SEPARATOR);
    let hour = digits(fields.next()?)?;
    let minute = digits(fields.next()?)?;
    // Fractional seconds are accepted and discarded: DCTL's resolution is one
    // second, and refusing a timestamp copied from a log because it carried
    // milliseconds would be pedantry, not safety.
    let second = match fields.next() {
        Some(field) => digits(field.split_once('.').map_or(field, |(whole, _)| whole))?,
        None => 0,
    };
    if fields.next().is_some() {
        return None;
    }

    // A leap second is spelled `:60`. Accepting it rolls into the next minute,
    // which is what every system without a leap-second table does anyway.
    if !(0..=23).contains(&hour) || !(0..=59).contains(&minute) || !(0..=60).contains(&second) {
        return None;
    }

    Some((
        hour * SECONDS_PER_HOUR as i64 + minute * SECONDS_PER_MINUTE as i64 + second,
        offset,
    ))
}

/// Split a trailing zone designator off a clock, returning the offset in
/// seconds east of UTC.
///
/// A bare clock with no zone is read as UTC — see the module docs for why that
/// is a decision and not an oversight.
fn split_zone(clock: &str) -> Option<(&str, i64)> {
    if let Some(stripped) = clock.strip_suffix(TIME_UTC_DESIGNATORS) {
        return Some((stripped, 0));
    }

    let Some(index) = clock.rfind(TIME_OFFSET_SIGNS) else {
        return Some((clock, 0));
    };
    let (head, zone) = clock.split_at(index);
    let sign = if zone.starts_with('-') { -1 } else { 1 };

    // `+02:00`, `+0200` and `+02` are all in the wild.
    let digits_only: String = zone[1..].chars().filter(|c| *c != ':').collect();
    let (hours, minutes) = match digits_only.len() {
        2 => (digits(&digits_only)?, 0),
        4 => (digits(&digits_only[..2])?, digits(&digits_only[2..])?),
        _ => return None,
    };
    if !(0..=23).contains(&hours) || !(0..=59).contains(&minutes) {
        return None;
    }

    Some((
        head,
        sign * (hours * SECONDS_PER_HOUR as i64 + minutes * SECONDS_PER_MINUTE as i64),
    ))
}

/// Parse a run of ASCII digits, rejecting signs, spaces and emptiness.
///
/// `str::parse` would accept `+7` and ` 7`, which would let `2026-+7-01` through
/// as a valid date. A timestamp filter that silently accepts a malformed date is
/// how a `--since` ends up matching nothing while looking like it worked.
///
/// Width is *not* checked. Zero padding is what DCTL writes; `2026-7-26` has one
/// possible reading, and refusing it would be strictness with no safety behind
/// it. The year is bounded by [`TIME_MIN_YEAR`]/[`TIME_MAX_YEAR`] instead, which
/// is the check that actually catches a typo.
fn digits(field: &str) -> Option<i64> {
    if field.is_empty() || !field.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    field.parse().ok()
}

/// Whether `year` is a Gregorian leap year.
const fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Days in `month` (1-based) of `year`.
fn days_in_month(year: i64, month: i64) -> i64 {
    let index = (month - 1) as usize;
    match DAYS_IN_MONTH.get(index) {
        Some(days) if month == 2 && is_leap_year(year) => days + 1,
        Some(days) => *days,
        None => 0,
    }
}

/// Days from the Unix epoch to `year-month-day`, by Howard Hinnant's
/// `days_from_civil`.
///
/// Chosen over pulling in a date crate for the same reason `dctl-decode` is a
/// single C file: this is fifteen lines of exact integer arithmetic with no
/// dependency, no timezone database to go stale, and no ambiguity. It is valid
/// for every date the Gregorian calendar defines, which is far more than the
/// [`TIME_MIN_YEAR`]–[`TIME_MAX_YEAR`] window the parser admits.
const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    // Shift the year so it starts on 1 March, which puts the leap day last and
    // removes February from the middle of the arithmetic.
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_shifted = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * DAYS_PER_ERA + day_of_era - ERA_TO_EPOCH_DAYS
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::exit::ExitCode;

    /// A fixed reference instant: 2026-07-26T00:00:00Z.
    ///
    /// Cross-checked against `date -u -r 1785024000`, deliberately using a tool
    /// that shares no code with the conversion under test.
    const REFERENCE: UnixSeconds = 1_785_024_000;

    fn at(input: &str) -> UnixSeconds {
        parse(input, REFERENCE).unwrap()
    }

    #[test]
    fn the_epoch_and_a_known_date_convert_exactly() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(at("1970-01-01"), 0);
        // Cross-checked against `date -u -d 2026-07-26 +%s`.
        assert_eq!(at("2026-07-26"), REFERENCE);
    }

    #[test]
    fn a_time_of_day_is_added_to_the_date() {
        assert_eq!(at("2026-07-26T00:00:00Z"), REFERENCE);
        assert_eq!(at("2026-07-26T01:02:03Z"), REFERENCE + 3723);
        // The separator may be a space or a lower-case t, and the seconds and
        // the zone are both optional.
        assert_eq!(at("2026-07-26 01:02"), REFERENCE + 3720);
        assert_eq!(at("2026-07-26t01:02:03"), REFERENCE + 3723);
    }

    #[test]
    fn a_numeric_offset_is_converted_to_utc() {
        // 01:00+02:00 is 23:00 the previous day in UTC.
        assert_eq!(
            at("2026-07-26T01:00:00+02:00"),
            REFERENCE - SECONDS_PER_HOUR as i64
        );
        assert_eq!(
            at("2026-07-26T01:00:00-0200"),
            REFERENCE + 3 * SECONDS_PER_HOUR as i64
        );
        assert_eq!(
            at("2026-07-26T01:00:00+02"),
            REFERENCE - SECONDS_PER_HOUR as i64
        );
    }

    #[test]
    fn fractional_seconds_are_accepted_and_truncated() {
        // Timestamps get copied out of logs; refusing milliseconds would only
        // make people edit the string by hand.
        assert_eq!(at("2026-07-26T00:00:01.250Z"), REFERENCE + 1);
    }

    #[test]
    fn relative_spellings_count_backwards_from_the_reference() {
        assert_eq!(at("0s"), REFERENCE);
        assert_eq!(at("90s"), REFERENCE - 90);
        assert_eq!(at("2d"), REFERENCE - 2 * 86_400);
        assert_eq!(at("1w"), REFERENCE - 7 * 86_400);
        // Minutes, never months.
        assert_eq!(at("1m"), REFERENCE - 60);
    }

    #[test]
    fn now_and_an_explicit_epoch_second_both_resolve() {
        assert_eq!(at("now"), REFERENCE);
        assert_eq!(at("NOW"), REFERENCE);
        assert_eq!(at("@1753574400"), 1_753_574_400);
        assert_eq!(at("@0"), 0);
    }

    #[test]
    fn leap_years_are_handled_by_the_calendar_not_by_luck() {
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(2023));
        assert!(
            !is_leap_year(1900),
            "a century is not automatically a leap year"
        );
        assert!(is_leap_year(2000), "but a 400-year one is");
        assert_eq!(days_in_month(2024, 2), 29);
        assert_eq!(days_in_month(2023, 2), 28);
        // 2024-02-29 exists; 2023-02-29 does not.
        assert!(parse("2024-02-29", REFERENCE).is_ok());
        assert!(parse("2023-02-29", REFERENCE).is_err());
    }

    #[test]
    fn an_impossible_date_is_refused_rather_than_rolled_over() {
        // The failure this prevents: `--at 2026-02-30` silently becoming
        // 2026-03-02 and restoring two days of changes nobody asked for.
        for input in [
            "2026-02-30",
            "2026-13-01",
            "2026-00-01",
            "2026-01-00",
            "2026-01-32",
        ] {
            let error = parse(input, REFERENCE).unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "{input} should be refused");
        }
    }

    #[test]
    fn malformed_spellings_are_refused_with_a_hint() {
        for input in [
            "",
            "   ",
            "yesterday",
            "2026-+7-26", // a sign is not a digit
            "2026-07-26T25:00:00Z",
            "2026-07-26T00:61:00Z",
            "2026-07-26T00:00:00+99:00",
            "@notanumber",
            "-2d",  // the future holds no backups
            "2026", // a year alone is not an instant
        ] {
            let error = parse(input, REFERENCE).unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "{input} should be refused");
            assert!(error.hint().is_some(), "{input} should explain itself");
        }
    }

    #[test]
    fn an_unpadded_field_is_accepted() {
        // Zero padding is what DCTL *writes*; refusing what a person types
        // would be strictness with no safety behind it, since `2026-7-26` has
        // exactly one reading.
        assert_eq!(at("2026-7-26"), REFERENCE);
        assert_eq!(at("2026-07-26T1:2:3"), REFERENCE + 3723);
    }

    #[test]
    fn years_outside_the_admitted_window_are_refused() {
        // A typo in the year is the one mistake that silently matches nothing.
        assert!(parse("1969-12-31", REFERENCE).is_err());
        assert!(parse("20265-01-01", REFERENCE).is_err());
        assert!(parse("9999-12-31", REFERENCE).is_ok());
    }

    #[test]
    fn the_reference_is_the_callers_not_the_clocks() {
        // Two parses in one invocation must resolve against the same instant, or
        // `--since now --until now` could describe a non-empty window.
        assert_eq!(parse("now", 42).unwrap(), 42);
        assert_eq!(parse("now", 0).unwrap(), 0);
    }

    #[test]
    fn the_clock_reader_returns_a_plausible_instant() {
        // Sanity only: the value must be past the epoch and not absurdly far
        // into the future, which catches a units mix-up (ms for s).
        let seconds = now();
        assert!(seconds > 1_700_000_000, "clock reads before 2023");
        assert!(seconds < 32_500_000_000, "clock reads past the year 3000");
    }
}
