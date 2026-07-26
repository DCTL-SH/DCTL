//! Column-aligned table rendering.
//!
//! Deliberately hand-rolled rather than pulling in a table crate, for two
//! reasons. First, DCTL's default listing output must stay **byte-stable and
//! script-friendly** — `dctl ls | awk '{print $2}'` has to keep working, so the
//! plain style emits nothing but values and single-space padding. Second, width
//! must be measured in *characters*, not bytes: a listing full of CJK or
//! accented filenames misaligns badly if you count bytes.
//!
//! The split mirrors the three things a table is: a *shape* ([`column`]), an
//! *accumulator* (the [`Table`] below), and a *renderer* ([`render`]). Only the
//! accumulator holds state, which is why it is the only thing in this file.
//!
//! Nothing here consults the terminal width. Every table this crate renders is
//! either narrow by construction (two label/value columns) or ends in an
//! unbounded path column that must not be truncated — a shortened path is a
//! path a script cannot use — so the renderer stays a pure function of its rows
//! and lets the terminal do the wrapping.

mod column;
mod render;

pub use column::{Align, Border, Column};

/// An accumulating table.
///
/// Rows are collected in full before anything is written because column widths
/// are not knowable until the last row has been seen. That is a bounded cost for
/// a listing page ([`crate::constants::LIST_PAGE_SIZE`] rows), and it is why
/// listings paginate instead of streaming a single table: `PLAN.md` §16.2
/// requires memory to stay ~O(concurrency), never O(files).
pub struct Table {
    /// Column definitions, in display order. Also decides how many cells of a
    /// row are rendered.
    columns: Vec<Column>,
    /// Rows as raw cell text, unpadded and unstyled — styling belongs to the
    /// render pass, which is the only place that knows about the palette.
    rows: Vec<Vec<String>>,
    /// Framing style, applied at render time.
    border: Border,
}

impl Table {
    /// Start an empty table with the given columns.
    #[must_use]
    pub fn new(columns: Vec<Column>) -> Self {
        Self {
            columns,
            rows: Vec::new(),
            border: Border::None,
        }
    }

    /// Switch the framing. Defaults to [`Border::None`], the pipeable form.
    #[must_use]
    pub const fn with_border(mut self, border: Border) -> Self {
        self.border = border;
        self
    }

    /// Append a row. Extra cells are ignored and missing cells render empty, so
    /// a ragged row can never panic mid-listing.
    ///
    /// That tolerance is deliberate: a listing that dies on row 900,000 of a
    /// million because one object had no modification time would lose the
    /// 899,999 rows that were fine.
    pub fn push(&mut self, cells: Vec<String>) {
        self.rows.push(cells);
    }

    /// Whether any rows have been pushed. Commands use this to decide between
    /// printing a table and printing nothing at all — an empty table with only a
    /// header reads as an error.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Number of rows, excluding any header.
    ///
    /// Test-only. A command decides *whether* to print a table, never how many
    /// rows it has — the row count it reports to the user comes from the listing
    /// or the plan that produced the rows, not from the renderer that is about
    /// to draw them. Counting them here would be counting them twice, and two
    /// counts of one thing eventually differ.
    #[cfg(test)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn size_path_table() -> Table {
        Table::new(vec![
            Column::new("Size", Align::Right),
            Column::new("Path", Align::Left),
        ])
    }

    #[test]
    fn a_new_table_is_empty_and_borderless() {
        let table = size_path_table();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert_eq!(table.border, Border::None);
    }

    #[test]
    fn rows_accumulate_in_order() {
        let mut table = size_path_table();
        table.push(vec!["1".into(), "first".into()]);
        table.push(vec!["2".into(), "second".into()]);
        assert_eq!(table.len(), 2);
        assert!(!table.is_empty());
        assert_eq!(table.rows[0][1], "first");
        assert_eq!(table.rows[1][1], "second");
    }

    #[test]
    fn the_row_count_ignores_the_header() {
        // `len` answers "how many results", which a header is not — a command
        // that printed "1 result" for an empty headed table would be lying.
        let mut table = size_path_table().with_border(Border::Header);
        table.push(vec!["1".into(), "x".into()]);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn with_border_is_chainable_and_keeps_the_rows() {
        let mut table = size_path_table();
        table.push(vec!["1".into(), "x".into()]);
        let table = table.with_border(Border::Header);
        assert_eq!(table.border, Border::Header);
        assert_eq!(table.len(), 1);
    }
}
