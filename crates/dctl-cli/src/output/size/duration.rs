//! Elapsed times and estimates of time remaining.
//!
//! Only ever two fields wide. A backup that has been running for a day and a
//! half is `1d12h`; the minutes it also has are noise next to the hours, and
//! spending columns on them would push the ETA off a narrow terminal.

use crate::constants::{
    DURATION_DAY_SUFFIX, DURATION_FIELD_WIDTH, DURATION_HOUR_SUFFIX, DURATION_MINUTE_SUFFIX,
    DURATION_SECOND_SUFFIX, SECONDS_PER_DAY, SECONDS_PER_HOUR, SECONDS_PER_MINUTE, UNKNOWN_VALUE,
};

/// Format a duration compactly: `4s`, `1m20s`, `2h05m`, `3d04h`.
///
/// The trailing field is zero-padded to [`DURATION_FIELD_WIDTH`] so the string
/// keeps a constant width as it counts down — an ETA that shrinks from `2h10m`
/// to `2h9m` would shift every column after it on each redraw.
#[must_use]
pub fn duration(seconds: u64) -> String {
    let width = DURATION_FIELD_WIDTH;

    if seconds < SECONDS_PER_MINUTE {
        format!("{seconds}{DURATION_SECOND_SUFFIX}")
    } else if seconds < SECONDS_PER_HOUR {
        format!(
            "{}{DURATION_MINUTE_SUFFIX}{:0width$}{DURATION_SECOND_SUFFIX}",
            seconds / SECONDS_PER_MINUTE,
            seconds % SECONDS_PER_MINUTE,
        )
    } else if seconds < SECONDS_PER_DAY {
        format!(
            "{}{DURATION_HOUR_SUFFIX}{:0width$}{DURATION_MINUTE_SUFFIX}",
            seconds / SECONDS_PER_HOUR,
            (seconds % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE,
        )
    } else {
        format!(
            "{}{DURATION_DAY_SUFFIX}{:0width$}{DURATION_HOUR_SUFFIX}",
            seconds / SECONDS_PER_DAY,
            (seconds % SECONDS_PER_DAY) / SECONDS_PER_HOUR,
        )
    }
}

/// Format an estimated time remaining, or [`UNKNOWN_VALUE`] when it cannot be
/// estimated.
///
/// A stalled or not-yet-started transfer has no rate to divide by, and inventing
/// one would put a confident wrong number in front of the user. The estimate
/// rounds *up*, so an ETA never reaches zero while bytes are still outstanding.
#[must_use]
pub fn eta(remaining_bytes: u64, bytes_per_second: f64) -> String {
    if bytes_per_second <= 0.0 || !bytes_per_second.is_finite() {
        return UNKNOWN_VALUE.to_string();
    }
    duration((remaining_bytes as f64 / bytes_per_second).ceil() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_are_compact() {
        assert_eq!(duration(0), "0s");
        assert_eq!(duration(45), "45s");
        assert_eq!(duration(80), "1m20s");
        assert_eq!(duration(3725), "1h02m");
        assert_eq!(duration(90_000), "1d01h");
    }

    #[test]
    fn every_unit_boundary_rolls_over_cleanly() {
        assert_eq!(duration(SECONDS_PER_MINUTE - 1), "59s");
        assert_eq!(duration(SECONDS_PER_MINUTE), "1m00s");
        assert_eq!(duration(SECONDS_PER_HOUR - 1), "59m59s");
        assert_eq!(duration(SECONDS_PER_HOUR), "1h00m");
        assert_eq!(duration(SECONDS_PER_DAY - 1), "23h59m");
        assert_eq!(duration(SECONDS_PER_DAY), "1d00h");
    }

    #[test]
    fn the_trailing_field_keeps_a_fixed_width() {
        // The reason for the zero padding: a countdown must not jitter.
        assert_eq!(
            duration(3600 + 9 * 60).len(),
            duration(3600 + 59 * 60).len()
        );
        assert_eq!(duration(60 + 9).len(), duration(60 + 59).len());
    }

    #[test]
    fn very_long_runs_stay_readable() {
        // Days are the top unit; a year-long figure grows the leading field
        // rather than gaining a new one.
        assert_eq!(duration(365 * SECONDS_PER_DAY), "365d00h");
    }

    #[test]
    fn eta_handles_a_stalled_transfer() {
        assert_eq!(eta(1000, 0.0), "-");
        assert_eq!(eta(1000, f64::NAN), "-");
        assert_eq!(eta(1000, 100.0), "10s");
    }

    #[test]
    fn eta_rounds_up_so_it_never_reads_zero_early() {
        // One byte left at 1000 B/s is 0.001s of work — reporting `0s` would
        // claim the transfer is finished when it is not.
        assert_eq!(eta(1, 1000.0), "1s");
        assert_eq!(eta(0, 1000.0), "0s");
    }

    #[test]
    fn eta_rejects_an_infinite_rate() {
        assert_eq!(eta(1000, f64::INFINITY), UNKNOWN_VALUE);
        assert_eq!(eta(1000, -5.0), UNKNOWN_VALUE);
    }
}
