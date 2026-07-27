//! The shape of a `verify` result, in every output format.
//!
//! Rendering is a **pure function of the report** — `render` returns the exact
//! string stdout should receive and `emit` is the only thing that writes. That
//! split is what lets the JSON shape, the column layout and the JSON Lines
//! record separator be asserted in a unit test without capturing the process's
//! stdout, which in turn is what keeps the machine-readable contract from
//! drifting the first time someone tweaks a column.
//!
//! The formats differ in one deliberate way. `--format json` emits a single
//! document that carries the run's summary, because a whole document can afford
//! to; `--format json-lines` emits one object record per line and *no* summary,
//! because the entire point of JSON Lines is that a consumer never has to buffer
//! the result — and a trailing summary record would force exactly that, or force
//! every consumer to branch on the record's shape.

use serde::Serialize;

use crate::commands::integrity::failure::{self, Verdict};
use crate::constants::{
    INTEGRITY_COLUMN_DETAIL, INTEGRITY_COLUMN_PATH, INTEGRITY_COLUMN_SIZE, INTEGRITY_COLUMN_STATUS,
    UNKNOWN_VALUE,
};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::output::{Align, Border, Column, Format, Out, Table, size};

/// One object's verification result.
#[derive(Clone, Debug, Serialize)]
pub struct Record {
    /// Logical vault path.
    pub path: String,
    /// The verdict, serialised as its stable slug.
    pub status: Verdict,
    /// Plaintext size, as recorded in the index, or `null` when the index holds
    /// no size for this object.
    ///
    /// The same absence [`crate::source::Entry::size`] carries, preserved
    /// instead of flattened: a row written by `dctl index rebuild` has never
    /// been measured, and a verification record claiming a real object is zero
    /// bytes long misdescribes exactly the object somebody is checking.
    pub size: Option<u64>,
    /// Why a non-`ok` verdict was reached. Absent when there is nothing to add.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Record {
    /// A record for one object.
    #[must_use]
    pub fn new(path: impl Into<String>, status: Verdict, size: Option<u64>) -> Self {
        Self {
            path: path.into(),
            status,
            size,
            detail: None,
        }
    }

    /// Attach the reason behind a failure.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Run-level tally.
///
/// `examined` is carried explicitly rather than derived from the record count so
/// that a run which stopped early (`--fail-fast`) reports how much of the target
/// it actually looked at, instead of implying it covered everything.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Summary {
    pub examined: u64,
    pub verified: u64,
    pub failed: u64,
    /// Bytes examined, or `null` when any object had no recorded size. See
    /// [`Record::size`]; the total is only a fact when every part of it was.
    pub bytes: Option<u64>,
    /// Bytes of the objects that did carry a recorded size — always a number, so
    /// the countable part of the run is never lost behind the null.
    pub measured_bytes: u64,
    /// How many examined objects carried no recorded size.
    pub unmeasured: u64,
}

impl Default for Summary {
    /// A run that has examined nothing has read a *known* zero bytes. Derived,
    /// `bytes` would start as `None` and no run could ever total itself.
    fn default() -> Self {
        Self {
            examined: 0,
            verified: 0,
            failed: 0,
            bytes: Some(0),
            measured_bytes: 0,
            unmeasured: 0,
        }
    }
}

/// The whole result of one `verify` run.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    /// The target as the command resolved it, not as it was typed.
    pub target: String,
    /// Which `--verify` strength produced these verdicts.
    pub verify_mode: String,
    /// Whether the run stopped at the first failure because `--fail-fast` asked
    /// it to.
    ///
    /// Published, because a report that ended early describes less of the target
    /// than it was pointed at, and a consumer reading only the JSON would
    /// otherwise read `"failed": 1` as the full extent of the damage.
    pub stopped_early: bool,
    pub objects: Vec<Record>,
    pub summary: Summary,
    /// The worst verdict seen, which decides the exit code. Not serialised: it
    /// is a reduction of `objects`, and publishing a derived field invites a
    /// consumer to trust it over the records it came from.
    #[serde(skip)]
    worst: Verdict,
}

impl Report {
    /// An empty report for `target`, verified at `verify_mode`.
    #[must_use]
    pub fn new(target: impl Into<String>, verify_mode: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            verify_mode: verify_mode.into(),
            stopped_early: false,
            objects: Vec::new(),
            summary: Summary::default(),
            worst: Verdict::Ok,
        }
    }

    /// Note that the run stopped at the first failure.
    ///
    /// A method rather than a public assignment so the reason it exists travels
    /// with it: `--fail-fast` trades the answer to "how much is damaged" for
    /// speed, and the report has to say that the trade was made.
    pub fn stopped_early(&mut self) {
        self.stopped_early = true;
    }

    /// Record one object's result, updating the tally.
    pub fn push(&mut self, record: Record) {
        self.summary.examined += 1;
        match record.size {
            Some(size) => {
                self.summary.measured_bytes = self.summary.measured_bytes.saturating_add(size);
                self.summary.bytes = self.summary.bytes.map(|t| t.saturating_add(size));
            }
            None => {
                self.summary.unmeasured = self.summary.unmeasured.saturating_add(1);
                self.summary.bytes = None;
            }
        }
        if record.status.is_failure() {
            self.summary.failed += 1;
        } else {
            self.summary.verified += 1;
        }
        self.worst = self.worst.worse(record.status);
        self.objects.push(record);
    }

    /// The worst verdict in the run.
    ///
    /// `cfg(test)` deliberately. Production reads [`Report::outcome`], which is
    /// the reduction *and* the wording *and* the exit code in one place; a
    /// command that could read the raw verdict instead would be a command that
    /// could grow a second opinion about what a corrupt object means. What is
    /// left is the observation point a test needs to assert the reduction
    /// directly, which is worth having because the ordering — corruption
    /// outranks everything — is the part that decides the exit status.
    #[cfg(test)]
    #[must_use]
    pub const fn worst(&self) -> Verdict {
        self.worst
    }

    /// The error this run ends with, or `None` when everything verified.
    ///
    /// Delegating to [`failure::failure`] rather than building an error here is
    /// what guarantees `verify` and `scrub` fail identically: one wording, one
    /// exit code, one hint.
    #[must_use]
    pub fn outcome(&self) -> Option<CliError> {
        failure::failure(self.worst, self.summary.failed, self.summary.examined)
    }

    /// Whether any record carries a detail, and therefore whether the text table
    /// needs a fourth column.
    ///
    /// A clean run should not pay a column of dashes for failures that did not
    /// happen; a run with damage should not hide the reason on stderr where a
    /// redirected stdout would lose it.
    fn has_details(&self) -> bool {
        self.objects.iter().any(|record| record.detail.is_some())
    }

    /// Render exactly the bytes stdout should receive.
    ///
    /// # Errors
    /// Only if serialisation fails, which for these types cannot happen in
    /// practice — it is reported rather than ignored because silently emitting
    /// nothing would be a success message for work that produced no output.
    pub fn render(&self, out: &Out) -> Result<String> {
        match out.format() {
            Format::Text => Ok(self.render_text(out)),
            Format::Json => encode(Format::Json, self).map(|json| format!("{json}\n")),
            Format::JsonLines => {
                let mut rendered = String::new();
                for record in &self.objects {
                    rendered.push_str(&encode(Format::JsonLines, record)?);
                    rendered.push('\n');
                }
                Ok(rendered)
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
        // A bare header with no rows under it is noise in a pipe, and reads as
        // output where there is none.
        if self.objects.is_empty() {
            return String::new();
        }

        let details = self.has_details();
        let mut columns = vec![
            Column::new(INTEGRITY_COLUMN_STATUS, Align::Left),
            Column::new(INTEGRITY_COLUMN_SIZE, Align::Right),
        ];
        if details {
            columns.push(Column::new(INTEGRITY_COLUMN_DETAIL, Align::Left));
        }
        // Path is always last: the final column is never padded, so a piped
        // listing carries no trailing whitespace.
        columns
            .push(Column::new(INTEGRITY_COLUMN_PATH, Align::Left).with_style(out.palette().path()));

        let mut table = Table::new(columns).with_border(Border::Header);
        for record in &self.objects {
            let mut cells = vec![
                record.status.slug().to_string(),
                size::bytes_or_unknown(record.size, out.units()),
            ];
            if details {
                cells.push(
                    record
                        .detail
                        .clone()
                        .unwrap_or_else(|| UNKNOWN_VALUE.to_string()),
                );
            }
            cells.push(record.path.clone());
            table.push(cells);
        }
        table.render(out.palette())
    }
}

/// Serialise a value, turning a serde failure into a classified CLI error.
fn encode<T: Serialize>(format: Format, value: &T) -> Result<String> {
    format.encode(value).map_err(|error| {
        CliError::new(
            ExitCode::Uncategorised,
            format!("cannot serialise the verify report: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{ColorChoice, Units};

    fn json_out(format: Format) -> Out {
        Out::new(format, ColorChoice::Never, Units::Binary, false, 0)
    }

    fn sample() -> Report {
        let mut report = Report::new("vault:photos", "strict");
        report.push(Record::new("photos/a.jpg", Verdict::Ok, Some(2048)));
        report.push(
            Record::new("photos/b.jpg", Verdict::Corrupt, Some(4096))
                .with_detail("chunk 3 failed authentication"),
        );
        report
    }

    #[test]
    fn the_tally_separates_verified_from_failed() {
        let report = sample();
        assert_eq!(report.summary.examined, 2);
        assert_eq!(report.summary.verified, 1);
        assert_eq!(report.summary.failed, 1);
        assert_eq!(report.summary.bytes, Some(2048 + 4096));
    }

    #[test]
    fn a_run_that_stopped_early_says_so_in_the_document() {
        // Without it, `"failed": 1` from a `--fail-fast` run reads as the full
        // extent of the damage rather than as the first of it.
        let mut report = Report::new("vault:", "strict");
        report.push(Record::new("a", Verdict::Corrupt, Some(1)));
        assert!(!report.stopped_early);
        report.stopped_early();

        let rendered = report.render(&json_out(Format::Json)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["stopped_early"], true);
    }

    #[test]
    fn a_clean_run_has_no_outcome_error() {
        let mut report = Report::new("vault:", "checksum");
        report.push(Record::new("a", Verdict::Ok, Some(1)));
        assert!(report.outcome().is_none());
        assert_eq!(report.worst(), Verdict::Ok);
    }

    #[test]
    fn a_corrupt_object_ends_the_run_with_exit_twenty_one() {
        let error = sample().outcome().expect("damage must fail the run");
        assert_eq!(error.code(), ExitCode::IntegrityFailure);
        assert!(
            error.message().contains("NOT served"),
            "got: {}",
            error.message()
        );
    }

    #[test]
    fn corruption_outranks_an_unreadable_object() {
        // The worst verdict decides, whatever order the records arrived in.
        let mut report = Report::new("vault:", "strict");
        report.push(Record::new("a", Verdict::Unreadable, Some(0)));
        report.push(Record::new("b", Verdict::Corrupt, Some(0)));
        report.push(Record::new("c", Verdict::Missing, Some(0)));
        assert_eq!(report.worst(), Verdict::Corrupt);
        assert_eq!(report.outcome().unwrap().code(), ExitCode::IntegrityFailure);
    }

    #[test]
    fn json_carries_the_mode_the_verdicts_were_reached_under() {
        // A count without its mode overstates what was proved.
        let rendered = sample().render(&json_out(Format::Json)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["target"], "vault:photos");
        assert_eq!(parsed["verify_mode"], "strict");
        assert_eq!(parsed["summary"]["failed"], 1);
        assert_eq!(parsed["objects"][0]["status"], "ok");
        assert_eq!(parsed["objects"][1]["status"], "corrupt");
        assert_eq!(
            parsed["objects"][1]["detail"],
            "chunk 3 failed authentication"
        );
    }

    #[test]
    fn a_clean_record_omits_the_detail_key_entirely() {
        // `"detail": null` would make every consumer handle a field that never
        // carries information.
        let rendered = sample().render(&json_out(Format::Json)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert!(parsed["objects"][0].get("detail").is_none());
    }

    #[test]
    fn json_lines_emits_one_parseable_record_per_line_and_no_summary() {
        let rendered = sample().render(&json_out(Format::JsonLines)).unwrap();
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 2, "one line per object, nothing else");
        for line in lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed.get("path").is_some());
            assert!(parsed.get("summary").is_none());
        }
    }

    #[test]
    fn the_text_table_puts_the_path_last_and_untrimmed() {
        let rendered = sample().render(&Out::plain()).unwrap();
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines[0].starts_with(INTEGRITY_COLUMN_STATUS));
        assert!(lines[0].trim_end().ends_with(INTEGRITY_COLUMN_PATH));
        for line in &lines[2..] {
            assert!(!line.ends_with(' '), "trailing padding in: {line:?}");
        }
        assert!(rendered.contains("photos/a.jpg"));
        assert!(rendered.contains("corrupt"));
    }

    #[test]
    fn the_detail_column_appears_only_when_something_failed() {
        // A clean run should not pay for a column of dashes.
        let mut clean = Report::new("vault:", "checksum");
        clean.push(Record::new("a", Verdict::Ok, Some(1)));
        let rendered = clean.render(&Out::plain()).unwrap();
        assert!(!rendered.contains(INTEGRITY_COLUMN_DETAIL));

        let rendered = sample().render(&Out::plain()).unwrap();
        assert!(rendered.contains(INTEGRITY_COLUMN_DETAIL));
        assert!(rendered.contains("chunk 3 failed authentication"));
    }

    #[test]
    fn an_empty_report_puts_nothing_on_stdout() {
        // Not even a header: a bare header row reads as output to a pipeline,
        // and to most humans.
        let report = Report::new("vault:", "checksum");
        for format in [Format::Text, Format::JsonLines] {
            assert_eq!(report.render(&json_out(format)).unwrap(), "");
        }
        // The whole-document form still describes the run that found nothing.
        let parsed: serde_json::Value =
            serde_json::from_str(&report.render(&json_out(Format::Json)).unwrap()).unwrap();
        assert_eq!(parsed["summary"]["examined"], 0);
    }
}
