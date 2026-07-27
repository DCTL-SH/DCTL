//! What a rebuild reports.
//!
//! How many files the index now knows about, how many of those rows are
//! *described* — size, modification time and content hash, read from each
//! object's own header — and which index file holds them. The counts are the
//! point: `files` is what an operator compares against what they expected the
//! vault to contain, and a rebuild that found *fewer* files than the last listing
//! is the signal that objects have gone missing at the provider.
//!
//! `unmeasured` is here because it used to be every row and nobody was told. A
//! rebuild wrote the path and the object key and left the size at zero, the time
//! absent and the hash empty, which is an index `dctl check` cannot compare,
//! `dctl size` under-reports from and `dctl sync` re-uploads the whole dataset
//! against. Rows are now described from the object header, so the number is
//! normally zero — and when it is not, it names exactly how many objects the
//! backend could not describe rather than leaving that to be discovered one
//! `cat` at a time.
//!
//! Follows the same split as the integrity family's reports: `render` is a pure
//! function returning exactly the bytes stdout should receive, `emit` is the only
//! thing that writes. The machine-readable contract is therefore something a unit
//! test asserts on directly, rather than something only a human ever sees.

use serde::Serialize;

use crate::constants::{INDEX_COLUMN_FILES, INDEX_COLUMN_INDEX, INDEX_COLUMN_UNMEASURED};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::output::{Align, Border, Column, Format, Out, Table};

/// The result of one `dctl index rebuild`.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    /// The remote whose name records were scanned, as the user spelled it.
    pub remote: String,
    /// The index database that was written.
    pub index: String,
    /// How many files the rebuilt index holds.
    pub files: u64,
    /// How many of those rows carry a size, a modification time and a content
    /// hash taken from the object's own authenticated header.
    pub measured: u64,
    /// How many rows are mapped but not described, because their object could not
    /// be read. Always rendered, including as `0`: an absent field would be read
    /// as "none", which is the same claim made by a report that never counted.
    pub unmeasured: u64,
}

impl Report {
    #[must_use]
    pub fn new(
        remote: impl Into<String>,
        index: impl Into<String>,
        rebuilt: dctl_core::Rebuilt,
    ) -> Self {
        Self {
            remote: remote.into(),
            index: index.into(),
            files: rebuilt.files,
            measured: rebuilt.measured,
            unmeasured: rebuilt.unmeasured,
        }
    }

    /// Render exactly the bytes stdout should receive.
    ///
    /// # Errors
    /// Only if serialisation fails, which is reported rather than swallowed.
    pub fn render(&self, out: &Out) -> Result<String> {
        match out.format() {
            Format::Text => Ok(self.render_text(out)),
            // One rebuild is one result, so the line-oriented format carries the
            // same single document rather than an empty stream — a consumer
            // reading `json-lines` must not have to special-case this command by
            // discovering it emits nothing.
            Format::Json | Format::JsonLines => {
                encode(out.format(), self).map(|json| format!("{json}\n"))
            }
        }
    }

    /// Write the report to stdout.
    ///
    /// # Errors
    /// Propagates a stdout write failure other than a broken pipe.
    pub fn emit(&self, out: &Out) -> Result<()> {
        let rendered = self.render(out)?;
        out.write(rendered)?;
        Ok(())
    }

    /// The aligned table a human reads.
    ///
    /// The unmeasured column is always present, even at zero. A column that
    /// appeared only when something went wrong would make its absence carry
    /// meaning nobody agreed on, and "the number is zero" is a stronger statement
    /// than "the report did not mention it".
    fn render_text(&self, out: &Out) -> String {
        let mut table = Table::new(vec![
            Column::new(INDEX_COLUMN_FILES, Align::Right),
            Column::new(INDEX_COLUMN_UNMEASURED, Align::Right),
            Column::new(INDEX_COLUMN_INDEX, Align::Left).with_style(out.palette().path()),
        ])
        .with_border(Border::Header);
        table.push(vec![
            self.files.to_string(),
            self.unmeasured.to_string(),
            self.index.clone(),
        ]);
        table.render(out.palette())
    }
}

/// Serialise a value, turning a serde failure into a classified CLI error.
fn encode<T: Serialize>(format: Format, value: &T) -> Result<String> {
    format.encode(value).map_err(|error| {
        CliError::new(
            ExitCode::Uncategorised,
            format!("cannot serialise the index report: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{ColorChoice, Units};

    fn out(format: Format) -> Out {
        Out::new(format, ColorChoice::Never, Units::Binary, false, 0)
    }

    fn rebuilt(files: u64, measured: u64, unmeasured: u64) -> dctl_core::Rebuilt {
        dctl_core::Rebuilt {
            files,
            measured,
            unmeasured,
        }
    }

    fn sample() -> Report {
        Report::new(
            "archive:",
            "/var/lib/dctl/index.redb",
            rebuilt(1204, 1204, 0),
        )
    }

    #[test]
    fn the_text_report_leads_with_the_count() {
        // The count is what an operator compares against what they expected the
        // vault to hold, so it is the first column rather than a suffix.
        let rendered = sample().render(&Out::plain()).unwrap();
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines[0].starts_with(INDEX_COLUMN_FILES));
        assert!(lines[2].contains("1204"));
        assert!(lines[2].contains("index.redb"));
    }

    #[test]
    fn json_names_the_remote_the_index_and_the_count() {
        let rendered = sample().render(&out(Format::Json)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["remote"], "archive:");
        assert_eq!(parsed["index"], "/var/lib/dctl/index.redb");
        assert_eq!(parsed["files"], 1204);
    }

    #[test]
    fn the_line_oriented_format_still_emits_the_one_result() {
        // A command with a single result must not silently produce nothing under
        // --format json-lines; a consumer would read that as "no rebuild".
        let rendered = sample().render(&out(Format::JsonLines)).unwrap();
        assert_eq!(rendered.lines().count(), 1);
        let parsed: serde_json::Value = serde_json::from_str(rendered.trim()).unwrap();
        assert_eq!(parsed["files"], 1204);
    }

    #[test]
    fn an_empty_vault_reports_zero_rather_than_nothing() {
        // Zero is information: it says the scan ran and found no name records,
        // which is a very different statement from a command that printed
        // nothing at all.
        let rendered = Report::new("archive:", "i.redb", rebuilt(0, 0, 0))
            .render(&out(Format::Json))
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["files"], 0);
    }

    #[test]
    fn a_fully_described_rebuild_still_says_so_in_both_formats() {
        // The healthy case has to be *stated*, not implied by an absent field: a
        // consumer that reads `unmeasured` to decide whether the index can be
        // compared must get a number from every rebuild, not from some of them.
        let json = sample().render(&out(Format::Json)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["measured"], 1204);
        assert_eq!(parsed["unmeasured"], 0);

        let text = sample().render(&Out::plain()).unwrap();
        assert!(
            text.lines()
                .next()
                .is_some_and(|header| header.contains(INDEX_COLUMN_UNMEASURED)),
            "the text report must carry the column too: {text}"
        );
    }

    #[test]
    fn a_rebuild_that_could_not_describe_every_object_reports_the_shortfall() {
        // Nine rows the index can compare and one it cannot. The one is the whole
        // reason this field exists: it is a path whose object is not where the
        // name record says it is, and it must not disappear into a count of ten.
        let report = Report::new("archive:", "i.redb", rebuilt(10, 9, 1));

        let parsed: serde_json::Value =
            serde_json::from_str(&report.render(&out(Format::Json)).unwrap()).unwrap();
        assert_eq!(parsed["files"], 10);
        assert_eq!(parsed["measured"], 9);
        assert_eq!(parsed["unmeasured"], 1);

        let text = report.render(&Out::plain()).unwrap();
        let row = text.lines().nth(2).expect("a data row");
        assert!(row.contains("10") && row.contains('1'), "{row}");
    }
}
