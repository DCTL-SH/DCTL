//! How a listing line is spelled.
//!
//! Three of the six verbs print a row of measured columns followed by a path,
//! and they must agree about the widths or the family stops reading as one
//! tool. Sharing the column functions — rather than three `format!` strings with
//! the same numbers in them — is what makes `dctl ls` and `dctl lsl` line up
//! their size columns on a screen where both are visible.
//!
//! ## Why not [`crate::output::table::Table`]
//!
//! `Table` measures its columns by scanning every row, which means holding every
//! row: exactly the thing `PLAN.md` §16.2 forbids for a listing. Fixed widths
//! taken from [`crate::constants`] cost one property — a run where every file is
//! under a kilobyte still reserves ten columns for the size — and buy the ability
//! to print the first line before the last object has been read. For a command
//! whose output is piped into `head` as often as it is read, that is the right
//! trade.
//!
//! ## The path column is last, and never padded
//!
//! It is the only field whose width is unbounded, and trailing whitespace on a
//! path is pure noise in a pipe. `awk '{print $NF}'` therefore gets the path on
//! every row of every listing verb.

use crate::constants::{
    LISTING_COUNT_COLUMN_WIDTH, LISTING_DIR_SUFFIX, LISTING_FIELD_SEPARATOR,
    LISTING_MODTIME_COLUMN_WIDTH, LISTING_SIZE_COLUMN_WIDTH, TABLE_PAD_CHAR, UNKNOWN_VALUE,
};
use crate::output::Units;
use crate::output::size::{bytes, count};

use super::time::rfc3339;

/// A byte count in the size column.
#[must_use]
pub fn size_column(value: u64, units: Units) -> String {
    right_align(&bytes(value, units), LISTING_SIZE_COLUMN_WIDTH)
}

/// An object count in the count column.
#[must_use]
pub fn count_column(value: u64) -> String {
    right_align(&count(value), LISTING_COUNT_COLUMN_WIDTH)
}

/// A modification time in the time column, or a placeholder when the index
/// recorded none.
///
/// The placeholder occupies the full width so that a listing containing a mix of
/// known and unknown times still aligns — an index rebuilt from object headers
/// can legitimately produce both.
#[must_use]
pub fn modtime_column(modified_unix: Option<i64>) -> String {
    let rendered = modified_unix.map_or_else(|| UNKNOWN_VALUE.to_string(), rfc3339);
    right_align(&rendered, LISTING_MODTIME_COLUMN_WIDTH)
}

/// Assemble one listing row from its fields.
#[must_use]
pub fn row(fields: &[&str]) -> String {
    fields.join(LISTING_FIELD_SEPARATOR)
}

/// A directory path as the text listings show it.
#[must_use]
pub fn directory_path(path: &str) -> String {
    format!("{path}{LISTING_DIR_SUFFIX}")
}

/// Right-align `text` in a column of `width` characters.
///
/// Measured in characters rather than bytes, like every other width in the
/// output layer: an accented or CJK path misaligns badly if you count bytes.
/// Never truncates — a cut-off size is worse than a shifted column.
fn right_align(text: &str, width: usize) -> String {
    let length = text.chars().count();
    if length >= width {
        return text.to_string();
    }
    let mut out = String::with_capacity(width);
    for _ in 0..width - length {
        out.push(TABLE_PAD_CHAR);
    }
    out.push_str(text);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_size_column_is_fixed_width_and_right_aligned() {
        let small = size_column(7, Units::Binary);
        let large = size_column(1_536_000, Units::Binary);
        assert_eq!(small.chars().count(), LISTING_SIZE_COLUMN_WIDTH);
        assert_eq!(large.chars().count(), LISTING_SIZE_COLUMN_WIDTH);
        assert!(small.starts_with(TABLE_PAD_CHAR));
        assert!(small.ends_with("7 B"));
        assert!(large.trim_start().starts_with("1.46"));
    }

    #[test]
    fn the_size_column_follows_the_unit_convention() {
        assert!(size_column(1000, Units::Decimal).contains("kB"));
        assert!(size_column(1024, Units::Binary).contains("KiB"));
    }

    #[test]
    fn the_count_column_is_grouped_and_aligned() {
        let rendered = count_column(1_234);
        assert_eq!(rendered.chars().count(), LISTING_COUNT_COLUMN_WIDTH);
        assert!(rendered.ends_with("1,234"));
    }

    #[test]
    fn a_known_time_fills_the_column_exactly() {
        let rendered = modtime_column(Some(1_704_067_200));
        assert_eq!(rendered, "2024-01-01T00:00:00Z");
        assert_eq!(rendered.chars().count(), LISTING_MODTIME_COLUMN_WIDTH);
    }

    #[test]
    fn an_unknown_time_keeps_the_column_aligned() {
        // A mixed listing is normal after an index rebuild, and a short
        // placeholder would shift every path on those rows.
        let rendered = modtime_column(None);
        assert_eq!(rendered.chars().count(), LISTING_MODTIME_COLUMN_WIDTH);
        assert!(rendered.ends_with(UNKNOWN_VALUE));
    }

    #[test]
    fn a_row_is_separated_by_exactly_one_space_per_boundary() {
        assert_eq!(row(&["a", "b", "c"]), "a b c");
        assert_eq!(row(&["only"]), "only");
    }

    #[test]
    fn the_path_column_is_never_padded() {
        // `awk '{print $NF}'` has to keep working, which it does not if the last
        // field carries trailing spaces.
        let rendered = row(&[&size_column(1, Units::Binary), "a/b.txt"]);
        assert!(!rendered.ends_with(TABLE_PAD_CHAR));
        assert!(rendered.ends_with("a/b.txt"));
    }

    #[test]
    fn a_value_wider_than_its_column_pushes_rather_than_truncates() {
        // Truncating a size would silently misreport it, which is the one thing
        // this tool must never do.
        let rendered = right_align("1023.99 GiB", 4);
        assert_eq!(rendered, "1023.99 GiB");
    }

    #[test]
    fn width_is_measured_in_characters_not_bytes() {
        // Five characters, ten bytes.
        assert_eq!(right_align("caf\u{e9}!", 6).chars().count(), 6);
    }

    #[test]
    fn a_directory_is_visibly_a_directory() {
        assert_eq!(directory_path("photos/2024"), "photos/2024/");
    }
}
