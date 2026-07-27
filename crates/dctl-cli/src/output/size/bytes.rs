//! Byte counts and transfer rates.
//!
//! Both live here because a rate *is* a byte count with a time unit stapled on:
//! they must round identically, or the same transfer would appear to move
//! `1.00 GiB` at `1024.0 MiB/s`.

use crate::constants::{
    RATE_SUFFIX, SIZE_DECIMALS_ABOVE_CUTOFF, SIZE_DECIMALS_BELOW_CUTOFF,
    SIZE_HIGH_PRECISION_CUTOFF, UNKNOWN_VALUE,
};

use super::Units;

/// Format a byte count, e.g. `1.44 GiB`.
///
/// Precision shrinks as magnitude grows: bytes are exact, and larger units get
/// two significant decimals below [`SIZE_HIGH_PRECISION_CUTOFF`] and one above,
/// so columns stay narrow without becoming useless.
#[must_use]
pub fn bytes(count: u64, units: Units) -> String {
    let divisor = units.divisor();
    let suffixes = units.suffixes();
    // An empty table cannot happen — both are compile-time constants — but the
    // crate forbids `unwrap`, so the impossible case degrades to a bare number
    // rather than to a panic in the middle of a listing.
    let base = suffixes.first().copied().unwrap_or_default();

    // Sub-divisor counts are printed exactly: a file is 1023 bytes, not 1.00 KiB.
    if count < divisor as u64 {
        return format!("{count} {base}");
    }

    let mut value = count as f64;
    let mut index = 0usize;
    while value >= divisor && index + 1 < suffixes.len() {
        value /= divisor;
        index += 1;
    }

    let decimals = if value < SIZE_HIGH_PRECISION_CUTOFF {
        SIZE_DECIMALS_BELOW_CUTOFF
    } else {
        SIZE_DECIMALS_ABOVE_CUTOFF
    };
    let suffix = suffixes.get(index).copied().unwrap_or(base);
    format!("{value:.decimals$} {suffix}")
}

/// Format a byte count that may never have been measured.
///
/// The one place the absence is turned into text, so that `ls`, `lsl`, `lsd`,
/// `tree`, `size`, `scrub` and `verify` all spell it the same way and a reader
/// moving between them does not have to learn a second vocabulary. It is
/// [`UNKNOWN_VALUE`] — the placeholder this crate already uses for a value it
/// could not compute — and not `0 B`, because a rebuilt vault index really does
/// hold rows nobody has measured and rendering those as a number is the
/// misreport `PLAN.md` §6 forbids.
#[must_use]
pub fn bytes_or_unknown(count: Option<u64>, units: Units) -> String {
    count.map_or_else(|| UNKNOWN_VALUE.to_string(), |value| bytes(value, units))
}

/// Format a transfer rate, e.g. `12.4 MiB/s`.
///
/// A non-finite or non-positive rate renders as [`UNKNOWN_VALUE`] rather than as
/// `0 B/s`: before the first sample there is no measurement, and printing a zero
/// would claim a stall that has not been observed.
#[must_use]
pub fn rate(bytes_per_second: f64, units: Units) -> String {
    if !bytes_per_second.is_finite() || bytes_per_second <= 0.0 {
        return UNKNOWN_VALUE.to_string();
    }
    format!("{}{RATE_SUFFIX}", bytes(bytes_per_second as u64, units))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_counts_stay_exact() {
        assert_eq!(bytes(0, Units::Binary), "0 B");
        assert_eq!(bytes(512, Units::Binary), "512 B");
        assert_eq!(bytes(1023, Units::Binary), "1023 B");
    }

    #[test]
    fn binary_and_decimal_differ_as_expected() {
        assert_eq!(bytes(1024, Units::Binary), "1.00 KiB");
        assert_eq!(bytes(1000, Units::Decimal), "1.00 kB");
        // The classic "why does my 1 TB drive show as 931 GB" discrepancy. One
        // decimal, not two: 931 is above SIZE_HIGH_PRECISION_CUTOFF, so the
        // mantissa has already spent its significant figures.
        assert_eq!(bytes(1_000_000_000_000, Units::Binary), "931.3 GiB");
        assert_eq!(bytes(1_000_000_000_000, Units::Decimal), "1.00 TB");
    }

    #[test]
    fn precision_narrows_as_magnitude_grows() {
        assert_eq!(bytes(1024 * 5, Units::Binary), "5.00 KiB");
        assert_eq!(bytes(1024 * 50, Units::Binary), "50.0 KiB");
    }

    #[test]
    fn rate_handles_no_progress() {
        assert_eq!(rate(0.0, Units::Binary), "-");
        assert_eq!(rate(1024.0, Units::Binary), "1.00 KiB/s");
    }

    #[test]
    fn rate_rejects_every_unmeasurable_input() {
        // A rate is a division; all three of these are what that division
        // produces before the first byte or after a divide-by-zero elapsed time.
        for unmeasurable in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert_eq!(rate(unmeasurable, Units::Binary), UNKNOWN_VALUE);
        }
    }

    #[test]
    fn the_largest_unit_absorbs_everything_above_it() {
        // The suffix table ends at exbibytes; u64::MAX must not walk off it.
        let rendered = bytes(u64::MAX, Units::Binary);
        assert!(rendered.ends_with(" EiB"), "got {rendered}");
        assert!(bytes(u64::MAX, Units::Decimal).ends_with(" EB"));
    }

    #[test]
    fn the_divisor_boundary_switches_units_exactly_once() {
        assert_eq!(bytes(1023, Units::Binary), "1023 B");
        assert_eq!(bytes(1024, Units::Binary), "1.00 KiB");
        assert_eq!(bytes(999, Units::Decimal), "999 B");
        assert_eq!(bytes(1000, Units::Decimal), "1.00 kB");
    }

    #[test]
    fn a_rate_rounds_like_the_size_it_is_built_from() {
        // The invariant that keeps a summary self-consistent.
        let value = 1_536_000.0;
        assert_eq!(
            rate(value, Units::Binary),
            format!("{}/s", bytes(value as u64, Units::Binary))
        );
    }
}
