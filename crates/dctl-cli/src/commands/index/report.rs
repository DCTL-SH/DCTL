//! What a rebuild reports.
//!
//! One number and one path, because that is the whole result: how many files the
//! index now knows about, and which index file holds them. The number is the
//! point — it is what an operator compares against what they expected the vault
//! to contain, and a rebuild that found *fewer* files than the last listing is
//! the signal that objects have gone missing at the provider.
//!
//! Follows the same split as the integrity family's reports: `render` is a pure
//! function returning exactly the bytes stdout should receive, `emit` is the only
//! thing that writes. The machine-readable contract is therefore something a unit
//! test asserts on directly, rather than something only a human ever sees.

use serde::Serialize;

use crate::constants::{INDEX_COLUMN_FILES, INDEX_COLUMN_INDEX};
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
}

impl Report {
    #[must_use]
    pub fn new(remote: impl Into<String>, index: impl Into<String>, files: u64) -> Self {
        Self {
            remote: remote.into(),
            index: index.into(),
            files,
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
    fn render_text(&self, out: &Out) -> String {
        let mut table = Table::new(vec![
            Column::new(INDEX_COLUMN_FILES, Align::Right),
            Column::new(INDEX_COLUMN_INDEX, Align::Left).with_style(out.palette().path()),
        ])
        .with_border(Border::Header);
        table.push(vec![self.files.to_string(), self.index.clone()]);
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

    fn sample() -> Report {
        Report::new("archive:", "/var/lib/dctl/index.redb", 1204)
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
        let rendered = Report::new("archive:", "i.redb", 0)
            .render(&out(Format::Json))
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["files"], 0);
    }
}
