//! Reading and writing the timestamps `dctl touch` accepts.
//!
//! DCTL converts calendar dates itself rather than taking a datetime dependency.
//! The reason is [the plan](https://doc.dctl.sh/project/plan) §13.1: a 20-year
//! restorability promise is a promise about the *smallest possible* dependency
//! surface, and a proleptic Gregorian
//! calendar has not changed since 1582 and will not change again. Sixty lines of
//! arithmetic that a reader can check against a wall calendar are a better bet
//! than a crate that may not build on a compiler released in 2045.
//!
//! Two rules are deliberate and are enforced here rather than left to the
//! caller:
//!
//! * **Everything is UTC.** A time with no zone is read as UTC, and an explicit
//!   offset is *refused* rather than converted. A laptop that crossed a timezone
//!   between two backups must not write two different modification times for the
//!   same content, and "which zone was this machine in that night?" is not a
//!   question a restore should have to answer.
//! * **Whole seconds.** [`dctl_index::Record::modified_unix`] stores whole
//!   seconds, so a fractional part is parsed and then discarded rather than
//!   rejected — a timestamp pasted from another tool's RFC 3339 output should
//!   just work, and rounding it would move the file's time by up to a second
//!   without saying so.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::constants::{
    DAYS_PER_COMMON_YEAR, LEAP_CENTURY_KEEP, LEAP_CENTURY_SKIP, LEAP_DAY_COUNT, LEAP_DAY_MONTH,
    LEAP_YEAR_CYCLE, MAX_HOUR, MAX_MINUTE, MAX_SECOND, MONTH_LENGTHS, MONTHS_PER_YEAR,
    SECONDS_PER_DAY, SECONDS_PER_HOUR, SECONDS_PER_MINUTE, TIMESTAMP_DATE_FIELDS,
    TIMESTAMP_DATE_SEPARATOR, TIMESTAMP_DATE_TIME_MARKER, TIMESTAMP_DATE_TIME_SEPARATORS,
    TIMESTAMP_EPOCH_PREFIX, TIMESTAMP_EXAMPLES, TIMESTAMP_FIELD_WIDTH,
    TIMESTAMP_FRACTION_SEPARATOR, TIMESTAMP_MAX_YEAR, TIMESTAMP_MIN_YEAR, TIMESTAMP_OFFSET_MARKERS,
    TIMESTAMP_TIME_FIELDS_MAX, TIMESTAMP_TIME_FIELDS_MIN, TIMESTAMP_TIME_SEPARATOR,
    TIMESTAMP_UTC_MARKER, TIMESTAMP_UTC_SUFFIXES, TIMESTAMP_YEAR_WIDTH, UNIX_EPOCH_YEAR,
};

/// The day, hour and minute lengths as the signed type the calendar walk uses.
///
/// Derived from the shared constants rather than restated, so a change there
/// cannot leave this file computing with a different length of day.
const SECONDS_PER_DAY_SIGNED: i64 = SECONDS_PER_DAY as i64;
/// See [`SECONDS_PER_DAY_SIGNED`].
const SECONDS_PER_HOUR_SIGNED: i64 = SECONDS_PER_HOUR as i64;
/// See [`SECONDS_PER_DAY_SIGNED`].
const SECONDS_PER_MINUTE_SIGNED: i64 = SECONDS_PER_MINUTE as i64;

/// A point in time, to the second, in UTC.
///
/// Stored as seconds since the Unix epoch because that is what the index stores;
/// keeping the CLI's representation identical to the record's means there is no
/// conversion left to get wrong at the boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    seconds: i64,
}

impl Timestamp {
    /// The current time.
    ///
    /// A clock set before 1970 yields a negative value rather than an error: a
    /// broken clock is the user's problem to notice, and refusing to run would
    /// be a strange way to tell them.
    #[must_use]
    pub fn now() -> Self {
        let seconds = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
            Err(error) => -i64::try_from(error.duration().as_secs()).unwrap_or(i64::MAX),
        };
        Self { seconds }
    }

    /// Seconds since the Unix epoch — the value the index records.
    #[must_use]
    pub const fn unix_seconds(self) -> i64 {
        self.seconds
    }

    /// The instant a stored record carries.
    ///
    /// The inverse of [`Timestamp::unix_seconds`], and the reason both exist:
    /// when `touch` reports the time an object *already* has, that number comes
    /// out of `dctl_index::Record::modified_unix` and has to be rendered by the
    /// same code that renders the time a run would have written. Two renderings
    /// of one instant is how a report comes to disagree with itself.
    #[must_use]
    pub const fn from_unix(seconds: i64) -> Self {
        Self { seconds }
    }

    /// Parse one of the accepted spellings (see [`TIMESTAMP_EXAMPLES`]).
    ///
    /// Used as a clap `value_parser`, so a malformed `--timestamp` is a usage
    /// error reported before the command body runs — the argument is checked
    /// once, at the edge, and every later stage can trust it.
    ///
    /// # Errors
    /// A message naming the input and the accepted spellings, which clap renders
    /// as the argument's validation failure.
    pub fn parse(input: &str) -> Result<Self, String> {
        let text = input.trim();
        if text.is_empty() {
            return Err(malformed(input));
        }

        // The epoch form is checked first: nothing else in the grammar starts
        // with '@', so it can never be confused with a date.
        if let Some(rest) = text.strip_prefix(TIMESTAMP_EPOCH_PREFIX) {
            let seconds: i64 = rest.trim().parse().map_err(|_| {
                format!(
                    "'{input}' is not a whole number of seconds since the Unix epoch \
                     (try {TIMESTAMP_EXAMPLES})"
                )
            })?;
            return Ok(Self { seconds });
        }

        // Everything DCTL accepts is UTC, so an explicit marker is redundant
        // rather than informative — strip it and carry on.
        let body = text.trim_end_matches(TIMESTAMP_UTC_SUFFIXES);

        let (date, time) = match body.find(TIMESTAMP_DATE_TIME_SEPARATORS) {
            // Every separator is one byte wide, so the split is safe.
            Some(index) => (&body[..index], body[index + 1..].trim()),
            None => (body, ""),
        };

        let (year, month, day) = parse_date(date, input)?;
        let (hour, minute, second) = if time.is_empty() {
            (0, 0, 0)
        } else {
            parse_time(time, input)?
        };

        let days = days_from_civil(year, month, day).ok_or_else(|| out_of_range(input))?;
        Ok(Self {
            seconds: days * SECONDS_PER_DAY_SIGNED
                + i64::from(hour) * SECONDS_PER_HOUR_SIGNED
                + i64::from(minute) * SECONDS_PER_MINUTE_SIGNED
                + i64::from(second),
        })
    }

    /// Render as RFC 3339 in UTC — `2024-05-01T12:00:00Z`.
    ///
    /// One canonical spelling whatever the input was, so the plan a user reads
    /// and the JSON a script parses agree with each other and with what any
    /// other tool would print for the same instant.
    ///
    /// A value too far out for a four-digit year falls back to the `@seconds`
    /// spelling rather than printing a wrong date: it is unreachable from the
    /// parser, which range-checks, but reachable from a clock that has lost its
    /// mind, and a wrong date is worse than an unusual one.
    #[must_use]
    pub fn to_rfc3339(self) -> String {
        let days = self.seconds.div_euclid(SECONDS_PER_DAY_SIGNED);
        let rest = self.seconds.rem_euclid(SECONDS_PER_DAY_SIGNED);

        let Some((year, month, day)) = civil_from_days(days) else {
            return format!("{TIMESTAMP_EPOCH_PREFIX}{}", self.seconds);
        };

        let hour = rest / SECONDS_PER_HOUR_SIGNED;
        let minute = (rest % SECONDS_PER_HOUR_SIGNED) / SECONDS_PER_MINUTE_SIGNED;
        let second = rest % SECONDS_PER_MINUTE_SIGNED;

        let years = TIMESTAMP_YEAR_WIDTH;
        let width = TIMESTAMP_FIELD_WIDTH;
        format!(
            "{year:0years$}{TIMESTAMP_DATE_SEPARATOR}{month:0width$}\
             {TIMESTAMP_DATE_SEPARATOR}{day:0width$}{TIMESTAMP_DATE_TIME_MARKER}\
             {hour:0width$}{TIMESTAMP_TIME_SEPARATOR}{minute:0width$}\
             {TIMESTAMP_TIME_SEPARATOR}{second:0width$}{TIMESTAMP_UTC_MARKER}"
        )
    }
}

/// Parse `YYYY-MM-DD`.
fn parse_date(text: &str, input: &str) -> Result<(i64, u32, u32), String> {
    let fields: Vec<&str> = text.split(TIMESTAMP_DATE_SEPARATOR).collect();
    if fields.len() != TIMESTAMP_DATE_FIELDS {
        return Err(malformed(input));
    }
    let year: i64 = digits(fields[0], input)?;
    let month: u32 = digits(fields[1], input)?;
    let day: u32 = digits(fields[2], input)?;
    Ok((year, month, day))
}

/// Parse `HH:MM` or `HH:MM:SS`, with an optional fractional part on the seconds.
fn parse_time(text: &str, input: &str) -> Result<(u32, u32, u32), String> {
    if text.contains(TIMESTAMP_OFFSET_MARKERS) {
        return Err(format!(
            "'{input}' carries a zone offset. DCTL timestamps are UTC: convert the \
             time first, or append Z if it already is."
        ));
    }

    let fields: Vec<&str> = text.split(TIMESTAMP_TIME_SEPARATOR).collect();
    if fields.len() < TIMESTAMP_TIME_FIELDS_MIN || fields.len() > TIMESTAMP_TIME_FIELDS_MAX {
        return Err(malformed(input));
    }

    let hour: u32 = digits(fields[0], input)?;
    let minute: u32 = digits(fields[1], input)?;
    // Seconds are the one optional field, so they sit at exactly the index the
    // minimum field count names.
    let second: u32 = match fields.get(TIMESTAMP_TIME_FIELDS_MIN).copied() {
        Some(field) => {
            // Sub-second precision is accepted and dropped: the index keeps
            // whole seconds, and rounding would move the time silently.
            let (whole, fraction) = field
                .split_once(TIMESTAMP_FRACTION_SEPARATOR)
                .unwrap_or((field, ""));
            if !fraction.is_empty() {
                let _: u64 = digits(fraction, input)?;
            }
            digits(whole, input)?
        }
        None => 0,
    };

    if hour > MAX_HOUR || minute > MAX_MINUTE || second > MAX_SECOND {
        return Err(format!(
            "'{input}' has a time field out of range (hours 0-{MAX_HOUR}, minutes \
             0-{MAX_MINUTE}, seconds 0-{MAX_SECOND})"
        ));
    }

    Ok((hour, minute, second))
}

/// Parse a run of ASCII digits.
///
/// Stricter than [`str::parse`] on purpose: `+5`, `-5` and ` 5` all parse as
/// numbers and none of them is a valid field of a timestamp, so accepting them
/// would let a malformed input through with a plausible-looking value.
fn digits<T: std::str::FromStr>(text: &str, input: &str) -> Result<T, String> {
    if text.is_empty() || !text.chars().all(|c| c.is_ascii_digit()) {
        return Err(malformed(input));
    }
    text.parse().map_err(|_| malformed(input))
}

/// Whether `year` is a leap year in the proleptic Gregorian calendar.
const fn is_leap_year(year: i64) -> bool {
    year % LEAP_YEAR_CYCLE == 0 && (year % LEAP_CENTURY_SKIP != 0 || year % LEAP_CENTURY_KEEP == 0)
}

/// Days in `year`.
const fn year_length(year: i64) -> i64 {
    if is_leap_year(year) {
        DAYS_PER_COMMON_YEAR + LEAP_DAY_COUNT
    } else {
        DAYS_PER_COMMON_YEAR
    }
}

/// Days in `month` of `year`, or `None` if the month number is not one.
fn month_length(year: i64, month: u32) -> Option<i64> {
    let index = usize::try_from(month).ok()?.checked_sub(1)?;
    let base = i64::from(*MONTH_LENGTHS.get(index)?);
    Some(if month == LEAP_DAY_MONTH && is_leap_year(year) {
        base + LEAP_DAY_COUNT
    } else {
        base
    })
}

/// Days from the Unix epoch to a calendar date, negative before 1970.
///
/// Walks a year at a time rather than using a closed-form era formula. Both are
/// correct; this one is checkable by eye, and the loop is bounded by
/// [`TIMESTAMP_MIN_YEAR`]/[`TIMESTAMP_MAX_YEAR`] at a few thousand iterations of
/// integer addition — far below the cost of the syscall that follows it.
///
/// Returns `None` for any date that does not exist, which is what makes
/// `2023-02-29` an error instead of `2023-03-01`.
fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    if !(TIMESTAMP_MIN_YEAR..=TIMESTAMP_MAX_YEAR).contains(&year) {
        return None;
    }
    if month == 0 || month > MONTHS_PER_YEAR {
        return None;
    }
    let length = month_length(year, month)?;
    if day == 0 || i64::from(day) > length {
        return None;
    }

    let mut days = 0;
    if year >= UNIX_EPOCH_YEAR {
        for walked in UNIX_EPOCH_YEAR..year {
            days += year_length(walked);
        }
    } else {
        for walked in year..UNIX_EPOCH_YEAR {
            days -= year_length(walked);
        }
    }
    for walked in 1..month {
        days += month_length(year, walked)?;
    }
    Some(days + i64::from(day - 1))
}

/// The inverse of [`days_from_civil`].
///
/// `None` once the walk leaves the supported year range, which is the only way a
/// four-digit year can fail to represent the value.
fn civil_from_days(days: i64) -> Option<(i64, u32, u32)> {
    let mut remaining = days;
    let mut year = UNIX_EPOCH_YEAR;

    while remaining < 0 {
        year -= 1;
        if year < TIMESTAMP_MIN_YEAR {
            return None;
        }
        remaining += year_length(year);
    }
    while remaining >= year_length(year) {
        remaining -= year_length(year);
        year += 1;
        if year > TIMESTAMP_MAX_YEAR {
            return None;
        }
    }

    let mut month = 1;
    loop {
        let length = month_length(year, month)?;
        if remaining < length {
            break;
        }
        remaining -= length;
        month += 1;
    }

    let day = u32::try_from(remaining).ok()? + 1;
    Some((year, month, day))
}

/// The failure every malformed spelling shares.
fn malformed(input: &str) -> String {
    format!("'{input}' is not a timestamp DCTL understands (try {TIMESTAMP_EXAMPLES})")
}

/// The failure for a date that parses but cannot be represented.
fn out_of_range(input: &str) -> String {
    format!(
        "'{input}' is not a date DCTL can represent (years {TIMESTAMP_MIN_YEAR} to \
         {TIMESTAMP_MAX_YEAR}, and the day must exist in its month)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seconds(input: &str) -> i64 {
        Timestamp::parse(input).unwrap().unix_seconds()
    }

    #[test]
    fn the_epoch_is_the_fixed_point_of_every_spelling() {
        for input in [
            "@0",
            "1970-01-01",
            "1970-01-01T00:00:00Z",
            "1970-01-01 00:00",
        ] {
            assert_eq!(seconds(input), 0, "for '{input}'");
        }
    }

    #[test]
    fn a_known_instant_matches_its_known_epoch_value() {
        // 2024-05-01T12:00:00Z, checked against an independent conversion.
        assert_eq!(seconds("2024-05-01T12:00:00Z"), 1_714_564_800);
        assert_eq!(seconds("2024-05-01"), 1_714_521_600);
        assert_eq!(seconds("@1714564800"), 1_714_564_800);
    }

    #[test]
    fn all_three_date_time_separators_are_accepted() {
        let expected = seconds("2024-05-01T09:30:00Z");
        assert_eq!(seconds("2024-05-01t09:30:00Z"), expected);
        assert_eq!(seconds("2024-05-01 09:30:00"), expected);
        // Seconds are optional; the zone marker is redundant either way.
        assert_eq!(seconds("2024-05-01T09:30"), expected);
    }

    #[test]
    fn times_before_the_epoch_are_negative_not_an_error() {
        assert_eq!(seconds("1969-12-31T23:59:59Z"), -1);
        assert_eq!(seconds("1969-12-31"), -86_400);
        assert_eq!(seconds("@-1"), -1);
    }

    #[test]
    fn sub_second_precision_is_dropped_rather_than_rounded() {
        // The index stores whole seconds. Rounding would move the file's time
        // without telling anyone.
        assert_eq!(
            seconds("2024-05-01T12:00:00.999999Z"),
            seconds("2024-05-01T12:00:00Z")
        );
    }

    #[test]
    fn a_zone_offset_is_refused_rather_than_converted() {
        // Converting would make the same command mean different things on two
        // machines, which is exactly what a backup must never do.
        let error = Timestamp::parse("2024-05-01T12:00:00+02:00").unwrap_err();
        assert!(error.contains("UTC"), "{error}");
    }

    #[test]
    fn the_leap_year_rule_is_the_gregorian_one() {
        assert!(
            Timestamp::parse("2024-02-29").is_ok(),
            "2024 is a leap year"
        );
        assert!(
            Timestamp::parse("2000-02-29").is_ok(),
            "2000: /400 keeps it"
        );
        assert!(
            Timestamp::parse("1900-02-29").is_err(),
            "1900: /100 skips it"
        );
        assert!(Timestamp::parse("2023-02-29").is_err(), "2023 is common");
    }

    #[test]
    fn a_day_that_does_not_exist_is_an_error_not_the_next_month() {
        // The whole reason the day is range-checked against its own month.
        for input in ["2024-04-31", "2024-13-01", "2024-00-10", "2024-01-00"] {
            assert!(Timestamp::parse(input).is_err(), "accepted '{input}'");
        }
    }

    #[test]
    fn out_of_range_time_fields_are_refused() {
        // Second 60 is RFC 3339's leap second; clamping it would silently
        // rewrite the value, so it is refused instead.
        for input in [
            "2024-05-01T24:00:00",
            "2024-05-01T12:60:00",
            "2024-05-01T12:00:60",
        ] {
            assert!(Timestamp::parse(input).is_err(), "accepted '{input}'");
        }
    }

    #[test]
    fn malformed_spellings_name_the_accepted_ones() {
        for input in [
            "",
            "   ",
            "yesterday",
            "2024/05/01",
            "20240501",
            "@banana",
            "2024-05",
        ] {
            let error = Timestamp::parse(input).unwrap_err();
            assert!(!error.is_empty(), "silent failure for '{input}'");
        }
        assert!(Timestamp::parse("nonsense").unwrap_err().contains("@"));
    }

    #[test]
    fn signed_and_padded_fields_are_not_numbers() {
        // `str::parse` would accept all of these; a timestamp field must not.
        for input in ["2024-+5-01", "2024-05- 1", "2024-5e2-01"] {
            assert!(Timestamp::parse(input).is_err(), "accepted '{input}'");
        }
    }

    #[test]
    fn rendering_is_canonical_whatever_the_input_looked_like() {
        for input in [
            "2024-05-01T12:00:00Z",
            "2024-05-01t12:00:00z",
            "2024-05-01 12:00:00",
            "@1714564800",
        ] {
            assert_eq!(
                Timestamp::parse(input).unwrap().to_rfc3339(),
                "2024-05-01T12:00:00Z",
                "for '{input}'"
            );
        }
    }

    #[test]
    fn rendering_pads_every_field_to_a_fixed_width() {
        // A column that changes width between records is unreadable in a log.
        assert_eq!(
            Timestamp::parse("0001-02-03T04:05:06")
                .unwrap()
                .to_rfc3339(),
            "0001-02-03T04:05:06Z"
        );
    }

    #[test]
    fn parsing_and_rendering_are_inverses_across_the_calendar() {
        // Walks four leap cycles a day at a time, which catches an off-by-one in
        // either direction that a handful of spot checks would miss.
        let start = Timestamp::parse("1968-01-01").unwrap().unix_seconds();
        let mut day = 0;
        while day < 366 * 20 {
            let stamp = Timestamp {
                seconds: start + day * SECONDS_PER_DAY_SIGNED,
            };
            let rendered = stamp.to_rfc3339();
            assert_eq!(
                Timestamp::parse(&rendered).unwrap(),
                stamp,
                "round trip failed at {rendered}"
            );
            day += 1;
        }
    }

    #[test]
    fn the_month_table_describes_a_common_year() {
        // If the table ever gained February's leap day the rule would apply it
        // twice, and every date after February would be a day late.
        let total: i64 = MONTH_LENGTHS.iter().map(|days| i64::from(*days)).sum();
        assert_eq!(total, DAYS_PER_COMMON_YEAR);
        assert_eq!(MONTH_LENGTHS.len(), MONTHS_PER_YEAR as usize);
    }

    #[test]
    fn now_is_after_the_tool_was_written_and_before_it_is_obsolete() {
        // A clock read through the wrong unit (millis, nanos) fails this.
        let now = Timestamp::now().unix_seconds();
        assert!(now > 1_700_000_000, "clock reads before 2023: {now}");
        assert!(now < 4_102_444_800, "clock reads after 2100: {now}");
    }

    #[test]
    fn an_unrepresentable_instant_falls_back_to_the_epoch_spelling() {
        // Unreachable from the parser, reachable from a broken clock. A wrong
        // date would be worse than an unusual one.
        let far_future = Timestamp {
            seconds: i64::MAX / 2,
        };
        assert!(far_future.to_rfc3339().starts_with(TIMESTAMP_EPOCH_PREFIX));
    }
}
