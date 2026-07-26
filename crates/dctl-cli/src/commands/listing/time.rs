//! Unix seconds rendered as an RFC 3339 timestamp.
//!
//! ## Why UTC, always
//!
//! The index stores whole unix seconds and nothing else — no offset, no zone
//! name — so any local rendering would be this machine's guess, not the file's
//! truth. Printing that guess would make the same vault produce different bytes
//! on a laptop in Berlin and on a build agent in UTC, which destroys the one
//! thing machine-readable output is for: comparing two runs. `lsjson` output is
//! diffed, hashed and piped into `jq`; a timestamp that moves with the reader is
//! worse than no timestamp at all.
//!
//! ## Why not a date crate
//!
//! `chrono` and `time` are both excellent, and both would bring a dependency, a
//! leap-second policy and a parser this crate would never call, in exchange for
//! forty lines of arithmetic that has been settled since 1582. The conversion
//! below is Howard Hinnant's `civil_from_days`, which is exact over the whole
//! `i64` range and allocates nothing.

use crate::constants::{
    RFC3339_DATE_SEPARATOR, RFC3339_DATE_TIME_SEPARATOR, RFC3339_FIELD_WIDTH,
    RFC3339_TIME_SEPARATOR, RFC3339_UTC_DESIGNATOR, RFC3339_YEAR_WIDTH, SECONDS_PER_DAY,
    SECONDS_PER_HOUR, SECONDS_PER_MINUTE,
};

// ── Calendar invariants ──────────────────────────────────────────────────────
//
// These are not tunables and do not belong in `constants`: they are fixed
// properties of the proleptic Gregorian calendar, and changing one does not
// adjust a policy, it produces wrong dates. They are named rather than inlined
// so the algorithm reads as the published one.

/// Days from 0000-03-01 to 1970-01-01.
///
/// Shifting the epoch to the *first of March* is the trick the whole conversion
/// rests on: the leap day then falls at the end of the shifted year, so
/// February's variable length stops being a special case anywhere else.
const DAYS_BEFORE_EPOCH: i64 = 719_468;

/// Days in a 400-year era — the period over which the Gregorian leap rule
/// repeats exactly.
const DAYS_PER_ERA: i64 = 146_097;

/// Index of the last day of an era, i.e. [`DAYS_PER_ERA`] − 1. Used both to
/// floor a negative era and as the 400-year term of the leap-rule correction.
const LAST_DAY_OF_ERA: i64 = 146_096;

/// Years in an era.
const YEARS_PER_ERA: i64 = 400;

/// Days in a non-leap year.
const DAYS_PER_COMMON_YEAR: i64 = 365;

/// Days in four years, one of which is a leap year.
const DAYS_PER_4_YEARS: i64 = 1_460;

/// Days in a century, whose final year is not a leap year.
const DAYS_PER_100_YEARS: i64 = 36_524;

/// The leap-rule periods, in years.
const LEAP_CYCLE_YEARS: i64 = 4;
const CENTURY_YEARS: i64 = 100;

/// March..February month lengths repeat as 153 days per 5 months, which is what
/// turns a day-of-year into a month number without a lookup table.
const MONTH_LENGTH_NUMERATOR: i64 = 153;
const MONTH_LENGTH_STEP: i64 = 5;
const MONTH_LENGTH_OFFSET: i64 = 2;

/// March, where the shifted year begins.
const MARCH: i64 = 3;

/// Months per year, for folding a shifted month back into a calendar one.
const MONTHS_PER_YEAR: i64 = 12;

/// Shifted months 0..9 are March..December; 10 and 11 are January and February,
/// which belong to the *next* calendar year.
const SHIFTED_MONTHS_BEFORE_JANUARY: i64 = 10;

/// January and February — the two months the shift borrows from the next year.
const MONTHS_BORROWED_FROM_NEXT_YEAR: i64 = 2;

/// Format `seconds` since the unix epoch as an RFC 3339 timestamp in UTC.
///
/// Whole-second resolution, which is all the index records and all any provider
/// returns. For every year in `1000..=9999` the result is exactly
/// [`LISTING_MODTIME_COLUMN_WIDTH`] characters wide, which is what lets the
/// listing commands treat it as a fixed column.
///
/// [`LISTING_MODTIME_COLUMN_WIDTH`]: crate::constants::LISTING_MODTIME_COLUMN_WIDTH
#[must_use]
pub fn rfc3339(seconds: i64) -> String {
    let per_day = signed(SECONDS_PER_DAY);
    let per_hour = signed(SECONDS_PER_HOUR);
    let per_minute = signed(SECONDS_PER_MINUTE);

    // Euclidean division so a pre-1970 timestamp floors into the previous day
    // rather than truncating towards zero and landing hours in the future.
    let (year, month, day) = civil_from_days(seconds.div_euclid(per_day));
    let remainder = seconds.rem_euclid(per_day);

    let hour = remainder / per_hour;
    let minute = remainder % per_hour / per_minute;
    let second = remainder % per_minute;

    let y = RFC3339_YEAR_WIDTH;
    let f = RFC3339_FIELD_WIDTH;
    format!(
        "{year:0y$}{RFC3339_DATE_SEPARATOR}{month:0f$}{RFC3339_DATE_SEPARATOR}{day:0f$}\
         {RFC3339_DATE_TIME_SEPARATOR}\
         {hour:0f$}{RFC3339_TIME_SEPARATOR}{minute:0f$}{RFC3339_TIME_SEPARATOR}{second:0f$}\
         {RFC3339_UTC_DESIGNATOR}"
    )
}

/// A duration constant as a signed count.
///
/// Saturating rather than wrapping: the constants are all under a day's worth of
/// seconds, so the fallback is unreachable, and reaching for it would still be
/// preferable to a panic in the middle of a listing.
fn signed(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Convert days since the unix epoch into a civil year, month and day.
///
/// Howard Hinnant, *`chrono`-Compatible Low-Level Date Algorithms*.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + DAYS_BEFORE_EPOCH;

    // Floor rather than truncate, so a day before 0000-03-01 lands in the era
    // that contains it instead of the one after it.
    let era = if shifted >= 0 {
        shifted / DAYS_PER_ERA
    } else {
        (shifted - LAST_DAY_OF_ERA) / DAYS_PER_ERA
    };

    let day_of_era = shifted - era * DAYS_PER_ERA; // 0..=146096
    let year_of_era = (day_of_era - day_of_era / DAYS_PER_4_YEARS
        + day_of_era / DAYS_PER_100_YEARS
        - day_of_era / LAST_DAY_OF_ERA)
        / DAYS_PER_COMMON_YEAR; // 0..=399

    let shifted_year = year_of_era + era * YEARS_PER_ERA;

    let day_of_year = day_of_era
        - (DAYS_PER_COMMON_YEAR * year_of_era + year_of_era / LEAP_CYCLE_YEARS
            - year_of_era / CENTURY_YEARS); // 0..=365

    let shifted_month =
        (MONTH_LENGTH_STEP * day_of_year + MONTH_LENGTH_OFFSET) / MONTH_LENGTH_NUMERATOR; // 0..=11

    let day = day_of_year
        - (MONTH_LENGTH_NUMERATOR * shifted_month + MONTH_LENGTH_OFFSET) / MONTH_LENGTH_STEP
        + 1; // 1..=31

    let month = if shifted_month < SHIFTED_MONTHS_BEFORE_JANUARY {
        shifted_month + MARCH
    } else {
        shifted_month + MARCH - MONTHS_PER_YEAR
    };

    // January and February were borrowed from the following calendar year.
    let year = if month <= MONTHS_BORROWED_FROM_NEXT_YEAR {
        shifted_year + 1
    } else {
        shifted_year
    };

    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::LISTING_MODTIME_COLUMN_WIDTH;

    #[test]
    fn the_epoch_renders_as_itself() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_timestamps_match_published_values() {
        assert_eq!(rfc3339(1_234_567_890), "2009-02-13T23:31:30Z");
        assert_eq!(rfc3339(1_704_067_200), "2024-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_704_067_199), "2023-12-31T23:59:59Z");
        assert_eq!(rfc3339(1_000_000_000), "2001-09-09T01:46:40Z");
    }

    #[test]
    fn the_century_leap_rules_are_applied() {
        // The part a hand-rolled conversion gets wrong: 2000 is a leap year and
        // 1900 is not.
        assert_eq!(rfc3339(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(-2_203_891_200), "1900-03-01T00:00:00Z");
        assert_eq!(rfc3339(-2_203_977_600), "1900-02-28T00:00:00Z");
    }

    #[test]
    fn timestamps_before_the_epoch_floor_correctly() {
        // Truncating division would put this one second *after* the epoch.
        assert_eq!(rfc3339(-1), "1969-12-31T23:59:59Z");
        assert_eq!(rfc3339(-86_400), "1969-12-31T00:00:00Z");
    }

    #[test]
    fn the_end_of_a_day_is_not_the_start_of_the_next() {
        assert_eq!(rfc3339(86_399), "1970-01-01T23:59:59Z");
        assert_eq!(rfc3339(86_400), "1970-01-02T00:00:00Z");
    }

    #[test]
    fn the_width_is_fixed_across_four_centuries() {
        // A time column that changed width mid-listing would misalign every row
        // after it, so `lsl` reserves exactly this many characters.
        for seconds in [0, 1, 2_000_000_000, 4_000_000_000, -1, -2_000_000_000] {
            assert_eq!(
                rfc3339(seconds).chars().count(),
                LISTING_MODTIME_COLUMN_WIDTH,
                "{seconds}"
            );
        }
    }

    #[test]
    fn the_rendering_sorts_as_text_in_time_order() {
        // The reason a fixed-width RFC 3339 is worth the arithmetic: `sort` over
        // an `lsl` listing orders by time without parsing anything.
        let mut by_seconds = [-1i64, 0, 1_000_000_000, 2_000_000_000];
        by_seconds.sort_unstable();
        let rendered: Vec<String> = by_seconds.iter().map(|s| rfc3339(*s)).collect();
        let mut sorted = rendered.clone();
        sorted.sort();
        assert_eq!(rendered, sorted);
    }

    #[test]
    fn consecutive_days_never_repeat_or_skip() {
        // Walks eleven years, crossing three leap days and every month end.
        let mut previous = civil_from_days(0);
        for day in 1..4_000i64 {
            let current = civil_from_days(day);
            assert_ne!(current, previous, "day {day} repeated");
            assert!((1..=MONTHS_PER_YEAR).contains(&current.1), "month at {day}");
            assert!((1..=31).contains(&current.2), "day at {day}");
            previous = current;
        }
    }

    #[test]
    fn the_conversion_is_exact_at_an_era_boundary() {
        // 0000-03-01 is day zero of the shifted calendar; the era arithmetic
        // either side of it is where a truncating division shows up.
        assert_eq!(civil_from_days(-DAYS_BEFORE_EPOCH), (0, 3, 1));
        assert_eq!(civil_from_days(-DAYS_BEFORE_EPOCH - 1), (0, 2, 29));
    }
}
