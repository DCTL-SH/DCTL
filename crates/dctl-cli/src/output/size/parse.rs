//! The inverse of [`super::bytes()`]: turning what a user types into a count.
//!
//! Kept in the presentation layer rather than in the argument parser because the
//! accepted spellings and the printed ones are one contract — `--max-size 10G`
//! must mean the same "10 GiB" that a listing shows.

use crate::constants::{
    SIZE_LIMIT_OFF, SIZE_LIMIT_ZERO, SIZE_PARSE_EXAMPLES, SIZE_SUFFIX_MULTIPLIERS,
};

/// Parse a human-written size such as `10G`, `1.5MiB`, `900k`, or `off`.
///
/// Accepts both conventions: a bare or `B`-suffixed unit letter is binary
/// (`10G` = 10 GiB, matching rclone), while an explicit SI suffix such as `10GB`
/// is decimal. `off` and `0` both mean "no limit" and return `None` — a distinct
/// value from `Some(0)`, so a caller can never confuse "unlimited" with "nothing
/// qualifies".
///
/// # Errors
/// Returns a message suitable for a clap validation failure.
pub fn parse_size(input: &str) -> Result<Option<u64>, String> {
    let trimmed = input.trim();
    if trimmed.eq_ignore_ascii_case(SIZE_LIMIT_OFF) || trimmed == SIZE_LIMIT_ZERO {
        return Ok(None);
    }

    // The suffix starts at the first letter; everything before it is the number.
    // Splitting on the first alphabetic character (rather than parsing greedily)
    // keeps `1.5MiB` working without a second pass.
    let split = trimmed
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(trimmed.len());
    let (number, suffix) = trimmed.split_at(split);

    let value: f64 = number
        .trim()
        .parse()
        .map_err(|_| format!("'{input}' is not a valid size (try {SIZE_PARSE_EXAMPLES})"))?;
    if value < 0.0 {
        return Err(format!("'{input}' is negative"));
    }

    let suffix = suffix.trim();
    let key = suffix.to_ascii_lowercase();
    let multiplier = SIZE_SUFFIX_MULTIPLIERS
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, multiplier)| *multiplier)
        // The message quotes the suffix as typed, not as folded, so the user can
        // see their own input in the error.
        .ok_or_else(|| format!("unknown size suffix '{suffix}' in '{input}'"))?;

    Ok(Some((value * multiplier) as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    // `bytes` names both the sibling module and the function it re-exports;
    // they live in different namespaces, so the call below resolves to the
    // function.
    use super::super::{Units, bytes};

    #[test]
    fn sizes_parse_in_both_conventions() {
        assert_eq!(parse_size("1024"), Ok(Some(1024)));
        assert_eq!(parse_size("1K"), Ok(Some(1024)));
        assert_eq!(parse_size("1KiB"), Ok(Some(1024)));
        assert_eq!(parse_size("1kB"), Ok(Some(1000)));
        assert_eq!(parse_size("10G"), Ok(Some(10 * 1024 * 1024 * 1024)));
        assert_eq!(parse_size("1.5M"), Ok(Some(1024 * 1024 * 3 / 2)));
    }

    #[test]
    fn off_and_zero_mean_no_limit() {
        assert_eq!(parse_size("off"), Ok(None));
        assert_eq!(parse_size("OFF"), Ok(None));
        assert_eq!(parse_size("0"), Ok(None));
    }

    #[test]
    fn bad_sizes_are_rejected_with_a_helpful_message() {
        assert!(parse_size("banana").is_err());
        assert!(parse_size("10X").is_err());
        assert!(parse_size("-5M").is_err());
    }

    #[test]
    fn size_round_trips_through_display() {
        let parsed = parse_size("4MiB").unwrap().unwrap();
        assert_eq!(bytes(parsed, Units::Binary), "4.00 MiB");
    }

    #[test]
    fn every_table_suffix_is_reachable() {
        // A row nobody can spell is dead weight; this catches one added with an
        // upper-case key or a stray space.
        for (suffix, multiplier) in SIZE_SUFFIX_MULTIPLIERS {
            let written = format!("1{suffix}");
            assert_eq!(
                parse_size(&written),
                Ok(Some(*multiplier as u64)),
                "'{written}' did not resolve to its own multiplier"
            );
        }
    }

    #[test]
    fn suffixes_are_case_insensitive_and_space_tolerant() {
        // Users copy sizes out of documentation, and documentation is not
        // consistent about either.
        assert_eq!(parse_size("1gib"), parse_size("1GiB"));
        assert_eq!(parse_size("1GIB"), parse_size("1GiB"));
        assert_eq!(parse_size("  10 G  "), Ok(Some(10 * 1024 * 1024 * 1024)));
    }

    #[test]
    fn the_binary_decimal_split_is_the_documented_one() {
        // `10G` is 10 GiB (rclone-compatible); `10GB` is the invoice's 10 GB.
        assert_eq!(parse_size("10G"), Ok(Some(10_737_418_240)));
        assert_eq!(parse_size("10GB"), Ok(Some(10_000_000_000)));
        assert_ne!(parse_size("1T"), parse_size("1TB"));
    }

    #[test]
    fn a_zero_with_a_unit_is_a_real_zero_not_a_disabled_limit() {
        // Only a bare `0` (or `off`) disables a limit. `0K` asked for a size and
        // must come back as one, or "match nothing" silently becomes "match all".
        assert_eq!(parse_size("0K"), Ok(Some(0)));
        assert_eq!(parse_size("0"), Ok(None));
    }

    #[test]
    fn an_empty_or_unit_only_input_is_an_error() {
        assert!(parse_size("").is_err());
        assert!(parse_size("MiB").is_err());
        assert!(parse_size("  ").is_err());
    }

    #[test]
    fn a_fractional_size_truncates_rather_than_rounds() {
        // Truncation keeps `--max-size` a true ceiling: rounding up would admit a
        // file the user asked to exclude.
        assert_eq!(parse_size("1.9"), Ok(Some(1)));
        assert_eq!(parse_size("0.5K"), Ok(Some(512)));
    }
}
