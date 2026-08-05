//! Fitting a long logical path into a fixed-width label.
//!
//! A per-file bar has one narrow column for a name that can be a hundred
//! characters of nested directories. Cutting the head loses the location; cutting
//! the tail loses the filename, which is the only part that identifies the row
//! among a dozen concurrent transfers. So both ends are kept and the middle goes.
//!
//! The whole module works in `char`s, never bytes. Vault paths are UTF-8 and
//! routinely non-ASCII ([the plan](https://doc.dctl.sh/project/plan) §14 and the
//! NFC rule in `platform::path`), and byte-slicing one would panic mid-codepoint
//! — an unacceptable way for a progress bar to take down a transfer.

use crate::constants::{
    TRUNCATE_MIN_WIDTH, TRUNCATE_TAIL_DENOMINATOR, TRUNCATE_TAIL_NUMERATOR, TRUNCATION_ELLIPSIS,
};

/// Shorten a long path for display, keeping the start and the filename.
///
/// `photos/2024/holiday/…/IMG_9921.CR3` reads better than either end alone: the
/// prefix says where it is, the suffix says which file. The split is biased
/// toward the tail by [`TRUNCATE_TAIL_NUMERATOR`]/[`TRUNCATE_TAIL_DENOMINATOR`]
/// because the filename is what distinguishes one row from the next.
///
/// The result is at most `max` characters wide, and exactly `max` whenever the
/// input was longer than that — the callers rely on it to keep columns aligned.
/// The one exception is `max == 0`, which yields a single marker rather than an
/// empty string: a zero-width label would render as nothing at all and leave a
/// bar with no identity.
#[must_use]
pub fn truncate_middle(text: &str, max: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max {
        return text.to_string();
    }

    // Too narrow to say anything useful: a lone leading and trailing character
    // would look like data without being any.
    if max <= TRUNCATE_MIN_WIDTH {
        return TRUNCATION_ELLIPSIS.repeat(max.max(1));
    }

    // The marker occupies part of the width, so it comes out of the budget
    // before the split — otherwise the result would overrun the column.
    // `saturating_sub` because the floor above is the only thing keeping this
    // positive, and a future change to it must not turn into an underflow.
    let budget = max.saturating_sub(TRUNCATION_ELLIPSIS.chars().count());
    let tail = budget * TRUNCATE_TAIL_NUMERATOR / TRUNCATE_TAIL_DENOMINATOR;
    let head = budget - tail;

    let head_part: String = chars[..head].iter().collect();
    let tail_part: String = chars[chars.len() - tail..].iter().collect();
    format!("{head_part}{TRUNCATION_ELLIPSIS}{tail_part}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn middle_truncation_keeps_both_ends() {
        assert_eq!(truncate_middle("short.txt", 20), "short.txt");
        let long = "photos/2024/holiday/spain/day3/IMG_9921.CR3";
        let out = truncate_middle(long, 24);
        assert_eq!(out.chars().count(), 24);
        assert!(out.starts_with("photo"));
        assert!(out.ends_with("9921.CR3"));
        assert!(out.contains('…'));
    }

    #[test]
    fn truncation_handles_degenerate_widths() {
        assert_eq!(truncate_middle("abcdef", 1), "…");
        assert_eq!(truncate_middle("abcdef", 3), "………");
    }

    #[test]
    fn truncation_is_char_safe_for_multibyte_text() {
        // Slicing by byte here would panic mid-codepoint.
        let text = "фотографии/двадцать-четыре/изображение.raw";
        let out = truncate_middle(text, 20);
        assert_eq!(out.chars().count(), 20);
    }

    #[test]
    fn a_zero_width_label_still_shows_a_marker() {
        // An empty string would leave a bar with no identity at all, so the
        // floor is one marker even when nothing was asked for.
        assert_eq!(truncate_middle("abcdef", 0), "…");
    }

    #[test]
    fn text_that_exactly_fills_the_width_is_untouched() {
        // The boundary case between "fits" and "truncate": off by one here and
        // every full-width filename would grow an ellipsis it does not need.
        assert_eq!(truncate_middle("abcdef", 6), "abcdef");
        assert_eq!(truncate_middle("abcdef", 5), "ab…ef");
    }

    #[test]
    fn the_tail_gets_the_larger_share() {
        // The filename identifies the row, so it must never be the side that
        // gets squeezed.
        let out = truncate_middle("aaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbb", 21);
        let split = out.split_once(TRUNCATION_ELLIPSIS);
        assert!(split.is_some(), "truncated label must contain the marker");
        if let Some((head, tail)) = split {
            assert!(
                tail.chars().count() > head.chars().count(),
                "tail {tail:?} should outweigh head {head:?}"
            );
        }
    }

    #[test]
    fn output_never_exceeds_the_requested_width() {
        // Swept rather than spot-checked: the head/tail arithmetic has to hold
        // for every width, including the ones either side of the floor.
        let text = "photos/2024/holiday/spain/day3/IMG_9921.CR3";
        for max in 1..=text.chars().count() + 4 {
            let out = truncate_middle(text, max);
            assert!(
                out.chars().count() <= max.max(1),
                "width {max} produced {} chars: {out:?}",
                out.chars().count()
            );
        }
    }

    #[test]
    fn truncated_output_fills_the_column_exactly() {
        // Alignment across concurrent rows depends on this: a short result would
        // let the bar that follows it slide left.
        let text = "photos/2024/holiday/spain/day3/IMG_9921.CR3";
        for max in TRUNCATE_MIN_WIDTH + 1..text.chars().count() {
            assert_eq!(
                truncate_middle(text, max).chars().count(),
                max,
                "width {max} did not fill the column"
            );
        }
    }

    #[test]
    fn empty_input_is_returned_unchanged() {
        assert_eq!(truncate_middle("", 10), "");
        assert_eq!(truncate_middle("", 0), "");
    }
}
