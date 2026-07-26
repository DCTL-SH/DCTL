//! Column definitions: what a column is called, which way its cells sit, and
//! how the whole table is framed.
//!
//! These are pure description with no rendering in them, which is what lets a
//! command declare its table shape once and let the renderer decide, at write
//! time, whether the terminal gets colour or a pipe gets plain text.

use anstyle::Style;

/// How a column is aligned within its width.
///
/// Only two options, deliberately. Centring a column of numbers or paths makes
/// both harder to scan, and neither `awk` nor a human benefits from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Align {
    /// Ragged right — for text, where the first character is the identifier.
    Left,
    /// Ragged left — for numbers, where the last digit is the magnitude anchor
    /// and a column of sizes should line up on its ones place.
    Right,
}

/// A column definition.
pub struct Column {
    /// Text shown in the header row, and the minimum width under
    /// [`Border::Header`].
    pub header: String,
    /// Which edge the cells are flushed against.
    pub align: Align,
    /// Style applied to every cell in this column.
    ///
    /// Per column rather than per cell because meaning in a listing is carried
    /// by the column: sizes are numbers, the last column is a path. A per-cell
    /// style would let one row disagree with the rest for no stated reason.
    pub style: Style,
}

impl Column {
    /// A column with no styling — the right default, since a table that is only
    /// ever piped should not pay for a decision it will never use.
    pub fn new(header: impl Into<String>, align: Align) -> Self {
        Self {
            header: header.into(),
            align,
            style: Style::new(),
        }
    }

    /// Attach a style, taken from the active [`crate::output::Palette`] so the
    /// `--color` decision made at startup is the only one in play.
    #[must_use]
    pub const fn with_style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }
}

/// Border style for a rendered table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Border {
    /// Values only, single-space separated. Script-friendly; the default for
    /// listing commands.
    #[default]
    None,
    /// A header row with an underline. Used by summary/report commands.
    Header,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_column_carries_no_style() {
        // The default has to be plain: `dctl ls | awk` must not receive escapes
        // just because a column was declared.
        let column = Column::new("Size", Align::Right);
        assert_eq!(column.header, "Size");
        assert_eq!(column.align, Align::Right);
        assert_eq!(column.style, Style::new());
    }

    #[test]
    fn with_style_replaces_only_the_style() {
        let styled = Style::new().bold();
        let column = Column::new("Path", Align::Left).with_style(styled);
        assert_eq!(column.header, "Path");
        assert_eq!(column.align, Align::Left);
        assert_eq!(column.style, styled);
    }

    #[test]
    fn the_default_border_is_the_script_friendly_one() {
        // Listings are the common case and machine-read far more often than a
        // report is, so the borderless form has to be what a caller gets for
        // free.
        assert_eq!(Border::default(), Border::None);
        assert_ne!(Border::None, Border::Header);
    }

    #[test]
    fn a_header_can_be_built_from_anything_string_like() {
        let owned = Column::new(String::from("Owned"), Align::Left);
        let borrowed = Column::new("Owned", Align::Left);
        assert_eq!(owned.header, borrowed.header);
    }
}
