//! Plain cardinal numbers — file counts, error counts, retry counts.
//!
//! Separate from [`super::bytes()`] because a count has no unit ladder: seven
//! million files is `7,000,000`, never `7.00 M`. Rounding a file count would
//! hide exactly the digits that matter when a run reports "one file failed".

use crate::constants::{THOUSANDS_GROUP_SIZE, THOUSANDS_SEPARATOR};

/// Format a plain count with thousands separators: `1,234,567`.
///
/// Hand-rolled rather than pulling in a locale crate: DCTL's output is parsed by
/// scripts, so the separator must be stable regardless of the user's locale. A
/// number that renders as `1.234.567` on a German desktop would break every
/// pipeline written against the English one.
#[must_use]
pub fn count(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / THOUSANDS_GROUP_SIZE);
    for (index, digit) in digits.chars().enumerate() {
        // A separator goes before every position whose distance from the end is
        // a whole number of groups — except the very first, which would leave a
        // leading comma.
        if index > 0 && (digits.len() - index) % THOUSANDS_GROUP_SIZE == 0 {
            out.push(THOUSANDS_SEPARATOR);
        }
        out.push(digit);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_get_separators() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1_000), "1,000");
        assert_eq!(count(1_234_567), "1,234,567");
    }

    #[test]
    fn no_leading_separator_at_a_group_boundary() {
        // The `index > 0` guard: a three-digit number must not render as ",100".
        assert_eq!(count(100), "100");
        assert_eq!(count(123_456), "123,456");
    }

    #[test]
    fn the_largest_count_is_grouped_correctly() {
        assert_eq!(count(u64::MAX), "18,446,744,073,709,551,615");
    }

    #[test]
    fn separators_appear_once_per_group() {
        // Ten-million-file runs are the design target
        // (https://doc.dctl.sh/project/plan §16.2), so the grouping has to hold
        // at that magnitude.
        let rendered = count(10_000_000);
        assert_eq!(rendered, "10,000,000");
        assert_eq!(
            rendered.matches(THOUSANDS_SEPARATOR).count(),
            (rendered.chars().filter(char::is_ascii_digit).count() - 1) / THOUSANDS_GROUP_SIZE
        );
    }
}
