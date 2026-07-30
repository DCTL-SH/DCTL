//! The one timestamp S3 sends that DCTL has to *read*, turned into unix seconds.
//!
//! `ListMultipartUploads` dates every open upload with `<Initiated>`, an ISO 8601
//! instant in UTC — `2010-11-10T20:48:33.000Z`. It is the only field in the reply
//! that lets a sweep tell an upload somebody abandoned last month from one another
//! process started four seconds ago, so `--min-age` cannot protect concurrent work
//! without it. Everything else this crate reads is already an integer.
//!
//! ## Why not a date crate
//!
//! The same answer `dctl-cli`'s renderer gives, from the other direction:
//! `chrono` and `time` are both excellent and both would bring a dependency, a
//! leap-second policy and a parser this crate would never call, in exchange for
//! thirty lines of arithmetic that has been settled since 1582. What is below is
//! Howard Hinnant's `days_from_civil` — the exact inverse of the `civil_from_days`
//! the CLI already uses to print times — plus a fixed-shape scan of the digits.
//!
//! ## What it refuses
//!
//! Anything that is not the shape S3 documents. A lenient parser here would be
//! worse than a strict one: the value decides whether a sweep may delete, and a
//! misread date is the difference between reclaiming abandoned parts and
//! cancelling an upload another process is half way through. Unparseable means
//! [`None`], [`None`] means the age is unknown, and unknown is not old — so a
//! reply this cannot read costs a sweep that reclaims nothing, never one that
//! reclaims the wrong thing.

/// Days from 0000-03-01 to 1970-01-01. Shifting the epoch to the first of March
/// puts the leap day at the end of the shifted year, so February's variable
/// length stops being a special case anywhere else.
const DAYS_BEFORE_EPOCH: i64 = 719_468;
/// Days in a 400-year era — the period over which the Gregorian leap rule repeats.
const DAYS_PER_ERA: i64 = 146_097;
/// Years in an era.
const YEARS_PER_ERA: i64 = 400;
/// Days in a non-leap year, before the leap-rule corrections below are applied.
const DAYS_PER_COMMON_YEAR: i64 = 365;

const SECONDS_PER_MINUTE: i64 = 60;
const SECONDS_PER_HOUR: i64 = 3_600;
const SECONDS_PER_DAY: i64 = 86_400;

/// The fixed prefix every value must have: `YYYY-MM-DDTHH:MM:SS`.
const FIXED_LEN: usize = 19;

/// Whole unix seconds for an S3 `<Initiated>` value, or [`None`] if it is not the
/// shape S3 documents.
///
/// Fractional seconds are accepted and **truncated**: the sweep works in whole
/// seconds and a millisecond either way cannot change whether something is a day
/// old. A trailing `Z` is accepted and required — S3 sends UTC and nothing else,
/// and an offset this did not apply would move an upload's age by hours.
#[must_use]
pub(super) fn parse_iso8601_utc(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() < FIXED_LEN {
        return None;
    }
    // Positional, because the format is fixed-width. A split-on-separators parse
    // would accept `2010-1-1T0:0:0Z`, which S3 does not send and which would make
    // the offsets below wrong for the next reader.
    for (index, expected) in [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')] {
        if bytes[index] != expected {
            return None;
        }
    }
    let year: i64 = value.get(0..4)?.parse().ok()?;
    let month: i64 = value.get(5..7)?.parse().ok()?;
    let day: i64 = value.get(8..10)?.parse().ok()?;
    let hour: i64 = value.get(11..13)?.parse().ok()?;
    let minute: i64 = value.get(14..16)?.parse().ok()?;
    let second: i64 = value.get(17..19)?.parse().ok()?;

    // The tail is either nothing but `Z`, or a fractional part and then `Z`.
    let tail = value.get(FIXED_LEN..)?;
    let tail = match tail.strip_prefix('.') {
        Some(rest) => {
            // Consume the fraction from the *front*: what follows it is the zone
            // designator, and trimming from the back would leave the digits in
            // place and reject every value S3 actually sends.
            let after = rest.trim_start_matches(|c: char| c.is_ascii_digit());
            if after.len() == rest.len() {
                return None; // a '.' with no digits after it
            }
            after
        }
        None => tail,
    };
    if tail != "Z" {
        return None;
    }

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // A leap second (`:60`) is admitted and lands on the following minute, which
    // is what every unix timestamp does with one.
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let days = days_from_civil(year, month, day);
    days.checked_mul(SECONDS_PER_DAY)?
        .checked_add(hour * SECONDS_PER_HOUR)?
        .checked_add(minute * SECONDS_PER_MINUTE)?
        .checked_add(second)
}

/// Days since 1970-01-01 for a proleptic Gregorian date — Howard Hinnant's
/// `days_from_civil`, exact over the whole `i64` range and allocating nothing.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    // Shift the year so it begins in March; February's leap day then falls at the
    // end of it and needs no special case.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - (YEARS_PER_ERA - 1) } / YEARS_PER_ERA;
    let year_of_era = y - era * YEARS_PER_ERA; // [0, 399]
    let month_shifted = if month > 2 { month - 3 } else { month + 9 }; // [0, 11]
    let day_of_year = (153 * month_shifted + 2) / 5 + day - 1; // [0, 365]
    let day_of_era =
        year_of_era * DAYS_PER_COMMON_YEAR + year_of_era / 4 - year_of_era / 100 + day_of_year; // [0, 146096]
    era * DAYS_PER_ERA + day_of_era - DAYS_BEFORE_EPOCH
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known instants, including the ones a leap-rule mistake gets wrong.
    #[test]
    fn known_instants_convert_exactly() {
        assert_eq!(parse_iso8601_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_iso8601_utc("1970-01-01T00:00:01Z"), Some(1));
        assert_eq!(
            parse_iso8601_utc("2001-09-09T01:46:40Z"),
            Some(1_000_000_000)
        );
        assert_eq!(
            parse_iso8601_utc("2010-11-10T20:48:33.000Z"),
            Some(1_289_422_113),
            "the instant AWS uses in its own ListMultipartUploads example"
        );
        // 2000 is a leap year (divisible by 400) and 1900 is not (divisible by
        // 100 but not 400) — the two cases a naive `year % 4` gets wrong.
        assert_eq!(parse_iso8601_utc("2000-03-01T00:00:00Z"), Some(951_868_800));
        assert_eq!(
            parse_iso8601_utc("1900-03-01T00:00:00Z"),
            Some(-2_203_891_200)
        );
        // Before the epoch, which a `u64` intermediate would have wrapped.
        assert_eq!(parse_iso8601_utc("1969-12-31T23:59:59Z"), Some(-1));
    }

    /// Fractional seconds are truncated rather than rejected or rounded: S3 sends
    /// them, the sweep works in whole seconds, and a millisecond cannot change
    /// whether an upload is a day old.
    #[test]
    fn a_fractional_second_is_truncated() {
        assert_eq!(
            parse_iso8601_utc("2010-11-10T20:48:33.999999999Z"),
            parse_iso8601_utc("2010-11-10T20:48:33Z")
        );
    }

    /// Everything that is not the documented shape answers `None`, which the
    /// sweep reads as "the age is unknown" and holds on.
    #[test]
    fn anything_that_is_not_the_documented_shape_is_unknown_rather_than_guessed() {
        for bad in [
            "",
            "not a date",
            "2010-11-10T20:48:33",       // no zone: could be anything
            "2010-11-10T20:48:33+01:00", // an offset this does not apply
            "2010-11-10 20:48:33Z",      // no 'T'
            "2010-1-1T0:0:0Z",           // not fixed-width
            "2010-11-10T20:48:33.Z",     // a '.' with no digits
            "2010-13-10T20:48:33Z",      // month 13
            "2010-11-10T24:48:33Z",      // hour 24
            "2010-11-10T20:60:33Z",      // minute 60
            "20101110T204833Z",          // basic format
        ] {
            assert_eq!(parse_iso8601_utc(bad), None, "{bad:?} was accepted");
        }
    }

    /// The conversion is monotonic over a long run of consecutive days — the
    /// property a misplaced leap-rule term breaks without breaking any single
    /// spot check.
    #[test]
    fn consecutive_days_are_exactly_one_day_apart_across_a_century() {
        let mut previous = days_from_civil(1950, 1, 1);
        for year in 1950..2050 {
            for (month, days) in [
                (1, 31),
                (2, if leap(year) { 29 } else { 28 }),
                (3, 31),
                (4, 30),
                (5, 31),
                (6, 30),
                (7, 31),
                (8, 31),
                (9, 30),
                (10, 31),
                (11, 30),
                (12, 31),
            ] {
                for day in 1..=days {
                    let now = days_from_civil(year, month, day);
                    if !(year == 1950 && month == 1 && day == 1) {
                        assert_eq!(now, previous + 1, "{year}-{month}-{day}");
                    }
                    previous = now;
                }
            }
        }
    }

    const fn leap(year: i64) -> bool {
        year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
    }
}
