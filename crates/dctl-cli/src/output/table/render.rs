//! Turning an accumulated [`Table`] into text.
//!
//! Width is measured in **characters**, never bytes. A listing full of CJK or
//! accented filenames misaligns badly if you count bytes — `café` is five
//! characters and six bytes, and a byte-counted column would under-pad it by
//! one. (Characters, not display columns: a full-width glyph still occupies two
//! cells on screen, which is a deeper problem than a table can solve without a
//! width table, and one that never arises in the size/count columns that are
//! actually padded.)
//!
//! Styling is applied per cell at write time rather than baked into the strings,
//! so the same table renders with colour on a terminal and as clean text through
//! a pipe.

use crate::constants::{TABLE_COLUMN_GAP, TABLE_PAD_CHAR, TABLE_RULE_CHAR};
use crate::output::color::Palette;

use super::{Align, Border, Table};

impl Table {
    /// Render to a string, applying `palette` styling.
    ///
    /// The output always ends in a newline when non-empty and is exactly empty
    /// when there are no rows, so a caller can write it straight to stdout
    /// without deciding whether to add a separator.
    #[must_use]
    pub fn render(&self, palette: &Palette) -> String {
        let widths = self.column_widths();
        let mut out = String::new();

        if self.border == Border::Header {
            let header = palette.header();
            for (index, column) in self.columns.iter().enumerate() {
                if index > 0 {
                    out.push_str(TABLE_COLUMN_GAP);
                }
                let padded = pad(&column.header, widths[index], column.align);
                out.push_str(&format!("{header}{padded}{header:#}"));
            }
            out.push('\n');

            let dim = palette.dim();
            let rule: String = widths
                .iter()
                .map(|width| String::from(TABLE_RULE_CHAR).repeat(*width))
                .collect::<Vec<_>>()
                .join(TABLE_COLUMN_GAP);
            out.push_str(&format!("{dim}{rule}{dim:#}\n"));
        }

        for row in &self.rows {
            for (index, column) in self.columns.iter().enumerate() {
                if index > 0 {
                    out.push_str(TABLE_COLUMN_GAP);
                }
                let cell = row.get(index).map_or("", String::as_str);
                // The final column is never padded — trailing whitespace on a
                // path column is pure noise in a pipe.
                let is_last = index + 1 == self.columns.len();
                let text = if is_last {
                    cell.to_string()
                } else {
                    pad(cell, widths[index], column.align)
                };
                let style = column.style;
                out.push_str(&format!("{style}{text}{style:#}"));
            }
            out.push('\n');
        }

        out
    }

    /// Width of each column, measured in characters.
    ///
    /// Headers only contribute a floor under [`Border::Header`]: a borderless
    /// listing never prints them, so letting `"Modified"` widen a column of
    /// short timestamps would indent data for a heading nobody sees.
    fn column_widths(&self) -> Vec<usize> {
        let mut widths: Vec<usize> = self
            .columns
            .iter()
            .map(|column| {
                if self.border == Border::Header {
                    column.header.chars().count()
                } else {
                    0
                }
            })
            .collect();

        for row in &self.rows {
            for (index, cell) in row.iter().enumerate() {
                // Extra cells in a ragged row are ignored rather than growing
                // the table: a row with more cells than columns is a bug in the
                // caller, and widening the table would hide it while corrupting
                // the alignment of every other row.
                if index < widths.len() {
                    widths[index] = widths[index].max(cell.chars().count());
                }
            }
        }
        widths
    }
}

/// Pad `text` to `width` characters on the requested side.
///
/// Never truncates. An over-long cell pushes its column out of alignment for one
/// row, which is ugly; a truncated one silently shows the wrong filename, which
/// is wrong. Ugly beats wrong.
fn pad(text: &str, width: usize, align: Align) -> String {
    let len = text.chars().count();
    if len >= width {
        return text.to_string();
    }
    let fill: String = std::iter::repeat_n(TABLE_PAD_CHAR, width - len).collect();
    match align {
        Align::Left => format!("{text}{fill}"),
        Align::Right => format!("{fill}{text}"),
    }
}

#[cfg(test)]
mod tests {
    use super::super::Column;
    use super::*;

    fn size_path_table() -> Table {
        Table::new(vec![
            Column::new("Size", Align::Right),
            Column::new("Path", Align::Left),
        ])
    }

    #[test]
    fn plain_tables_are_script_friendly() {
        let mut table = size_path_table();
        table.push(vec!["1024".into(), "a.txt".into()]);
        table.push(vec!["7".into(), "b.txt".into()]);

        let rendered = table.render(&Palette::plain());
        // Right-aligned size column, no header, no trailing padding.
        assert_eq!(rendered, "1024  a.txt\n   7  b.txt\n");
    }

    #[test]
    fn header_border_adds_a_rule() {
        let mut table = size_path_table().with_border(Border::Header);
        table.push(vec!["1".into(), "x".into()]);
        let rendered = table.render(&Palette::plain());
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 3, "header + rule + one row");
        assert!(lines[0].starts_with("Size"));
        assert!(lines[1].starts_with("----"));
    }

    #[test]
    fn width_is_measured_in_characters_not_bytes() {
        let mut table = size_path_table();
        // 5 characters, 10 bytes in UTF-8.
        table.push(vec!["1".into(), "café!".into()]);
        table.push(vec!["22".into(), "ascii".into()]);
        let rendered = table.render(&Palette::plain());

        // The size column pads to 2 characters for both rows.
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines[0], " 1  café!");
        assert_eq!(lines[1], "22  ascii");
    }

    #[test]
    fn ragged_rows_render_without_panicking() {
        let mut table = size_path_table();
        table.push(vec!["1".into()]); // missing the path cell
        table.push(vec!["2".into(), "b".into(), "extra".into()]);
        let rendered = table.render(&Palette::plain());
        assert_eq!(rendered.lines().count(), 2);
    }

    #[test]
    fn empty_table_renders_empty() {
        let table = size_path_table();
        assert!(table.is_empty());
        assert_eq!(table.render(&Palette::plain()), "");
    }

    #[test]
    fn styled_render_wraps_cells_in_escapes() {
        let mut table = size_path_table();
        table.push(vec!["1".into(), "a".into()]);
        let styled = table.render(&Palette::new(true));
        let plain = table.render(&Palette::plain());
        // Default column styles are empty, so the two agree until a column
        // carries a style — this guards the `{style:#}` reset syntax.
        assert_eq!(styled, plain);
    }

    #[test]
    fn column_styles_are_applied() {
        let mut table = Table::new(vec![
            Column::new("Size", Align::Right),
            Column::new("Path", Align::Left).with_style(Palette::new(true).path()),
        ]);
        table.push(vec!["1".into(), "a".into()]);
        let rendered = table.render(&Palette::new(true));
        assert!(rendered.contains("\u{1b}["), "expected ANSI escapes");
    }

    #[test]
    fn padding_never_truncates() {
        assert_eq!(pad("toolong", 3, Align::Left), "toolong");
        assert_eq!(pad("a", 3, Align::Right), "  a");
        assert_eq!(pad("a", 3, Align::Left), "a  ");
    }

    #[test]
    fn padding_counts_characters_not_bytes() {
        // Six bytes, five characters: a byte-counted pad would come up short.
        assert_eq!(pad("café!", 7, Align::Left).chars().count(), 7);
        assert_eq!(pad("café!", 7, Align::Right), "  café!");
    }

    #[test]
    fn headers_only_set_a_floor_when_they_are_printed() {
        // Borderless: the short cell must not be indented to the header's width.
        let mut plain = size_path_table();
        plain.push(vec!["1".into(), "x".into()]);
        assert_eq!(plain.render(&Palette::plain()), "1  x\n");

        // With a header: the same cell pads out under `Size`.
        let mut headed = size_path_table().with_border(Border::Header);
        headed.push(vec!["1".into(), "x".into()]);
        let rendered = headed.render(&Palette::plain());
        assert!(rendered.ends_with("   1  x\n"), "got {rendered:?}");
    }

    #[test]
    fn the_rule_is_as_wide_as_the_columns_it_underlines() {
        let mut table = size_path_table().with_border(Border::Header);
        table.push(vec!["1048576".into(), "a".into()]);
        let rendered = table.render(&Palette::plain());
        let lines: Vec<&str> = rendered.lines().collect();
        // "1048576" is wider than "Size", so the first rule segment follows the
        // data, not the heading.
        assert_eq!(lines[1], "-------  ----");
    }

    #[test]
    fn a_single_column_table_never_pads() {
        // The last column is always unpadded, and in a one-column table every
        // column is the last one — so `dctl ls` output carries no trailing
        // whitespace at all.
        let mut table = Table::new(vec![Column::new("Path", Align::Left)]);
        table.push(vec!["short".into()]);
        table.push(vec!["a-much-longer-path".into()]);
        assert_eq!(
            table.render(&Palette::plain()),
            "short\na-much-longer-path\n"
        );
    }

    #[test]
    fn a_table_with_no_columns_still_emits_its_rows() {
        // Degenerate, but it must not panic or index out of bounds.
        let mut table = Table::new(Vec::new());
        table.push(vec!["ignored".into()]);
        assert_eq!(table.render(&Palette::plain()), "\n");
    }
}
