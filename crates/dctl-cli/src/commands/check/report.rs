//! The shape of a `check` result, in every output format.
//!
//! Follows the same split as [`crate::commands::verify::report`]: `render` is a
//! pure function returning exactly the bytes stdout should receive, `emit` is the
//! only thing that writes. The machine-readable contract is therefore something a
//! unit test can assert on directly.
//!
//! Two decisions are worth spelling out.
//!
//! **Matches are not listed by default.** A check of a million objects that
//! agree should print a summary, not a million lines saying so; the interesting
//! output is the disagreements, and `--match FILE` exists for the case where the
//! full list really is wanted. The tally still counts every path, so the summary
//! never understates what was compared.
//!
//! **The comparison is reported alongside the count.** "0 differences" under a
//! size-and-time comparison is a much weaker statement than under `--checksum`,
//! and a report that omitted which one ran would let the weaker claim be read as
//! the stronger one.

use serde::Serialize;

use crate::constants::{
    COMPARISON_CHECKSUM, COMPARISON_SIZE_AND_MODTIME, COMPARISON_SIZE_ONLY, INTEGRITY_COLUMN_PATH,
    INTEGRITY_COLUMN_STATUS,
};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::output::{Align, Border, Column, Format, Out, Table};

use super::difference::{Comparison, Difference};

/// One path's verdict.
#[derive(Clone, Debug, Serialize)]
pub struct Record {
    pub path: String,
    /// The verdict, serialised as its stable slug.
    pub status: Difference,
}

impl Record {
    #[must_use]
    pub fn new(path: impl Into<String>, status: Difference) -> Self {
        Self {
            path: path.into(),
            status,
        }
    }
}

/// Counts per verdict.
///
/// Every verdict has its own field rather than a generic map, so a consumer can
/// depend on the keys existing — a `differ` of `0` is information, and an absent
/// key is ambiguous between "none" and "not measured".
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Summary {
    pub checked: u64,
    pub matched: u64,
    pub differ: u64,
    pub missing_on_src: u64,
    pub missing_on_dst: u64,
    pub errors: u64,
}

impl Summary {
    /// Paths that did not match, for whatever reason.
    #[must_use]
    pub const fn differences(&self) -> u64 {
        self.differ + self.missing_on_src + self.missing_on_dst + self.errors
    }
}

/// The whole result of one `check` run.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub source: String,
    pub dest: String,
    /// Which fields decided equality, as the flag that selects it is spelled.
    pub comparison: &'static str,
    /// Whether that comparison proves the contents are identical.
    pub proves_contents: bool,
    /// Whether extra paths at the destination were ignored (`--one-way`).
    pub one_way: bool,
    /// The disagreements. Matches are counted but not listed — see the module
    /// documentation.
    pub differences: Vec<Record>,
    pub summary: Summary,
}

impl Report {
    /// An empty report for one comparison.
    #[must_use]
    pub fn new(
        source: impl Into<String>,
        dest: impl Into<String>,
        comparison: Comparison,
        one_way: bool,
    ) -> Self {
        Self {
            source: source.into(),
            dest: dest.into(),
            comparison: comparison_slug(comparison),
            proves_contents: comparison.proves_contents(),
            one_way,
            differences: Vec::new(),
            summary: Summary::default(),
        }
    }

    /// Record one verdict, updating the tally.
    ///
    /// Under `--one-way`, a path that exists only at the destination is not
    /// counted at all: it is not a finding, so counting it would inflate the
    /// difference total and change the exit code.
    pub fn push(&mut self, record: Record) {
        if self.one_way && record.status.suppressed_by_one_way() {
            return;
        }

        self.summary.checked += 1;
        match record.status {
            Difference::Match => self.summary.matched += 1,
            Difference::Differ => self.summary.differ += 1,
            Difference::MissingOnSrc => self.summary.missing_on_src += 1,
            Difference::MissingOnDst => self.summary.missing_on_dst += 1,
            Difference::Error => self.summary.errors += 1,
        }

        if record.status.is_difference() {
            self.differences.push(record);
        }
    }

    /// The error this run ends with, or `None` when the two sides agree.
    ///
    /// Differences are not an *integrity* failure — nothing failed to
    /// authenticate — so this is deliberately not exit 21. It is
    /// [`ExitCode::PartialFailure`], which is the code that means "the run
    /// finished and the result is not clean": a script can branch on it without
    /// confusing "these trees differ" with "stored data is damaged".
    #[must_use]
    pub fn outcome(&self) -> Option<CliError> {
        let differences = self.summary.differences();
        if differences == 0 {
            return None;
        }
        Some(
            CliError::new(
                ExitCode::PartialFailure,
                format!(
                    "{differences} of {} paths differ between '{}' and '{}'",
                    self.summary.checked, self.source, self.dest
                ),
            )
            .with_hint(
                "Nothing was transferred: `check` only compares. Re-run with \
                 --missing-on-dst FILE to capture a list you can feed to \
                 `dctl copy --files-from`.",
            ),
        )
    }

    /// Render exactly the bytes stdout should receive.
    ///
    /// # Errors
    /// Only if serialisation fails, which is reported rather than swallowed.
    pub fn render(&self, out: &Out) -> Result<String> {
        match out.format() {
            Format::Text => Ok(self.render_text(out)),
            Format::Json => encode(Format::Json, self).map(|json| format!("{json}\n")),
            Format::JsonLines => {
                let mut rendered = String::new();
                for record in &self.differences {
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
        // Two trees that agree produce no stdout at all: a bare header would
        // read as a finding to anything downstream, and to most humans.
        if self.differences.is_empty() {
            return String::new();
        }

        let mut table = Table::new(vec![
            Column::new(INTEGRITY_COLUMN_STATUS, Align::Left),
            Column::new(INTEGRITY_COLUMN_PATH, Align::Left).with_style(out.palette().path()),
        ])
        .with_border(Border::Header);

        for record in &self.differences {
            table.push(vec![record.status.slug().to_string(), record.path.clone()]);
        }
        table.render(out.palette())
    }
}

/// The flag spelling of a comparison, for the report.
///
/// Derived from the enum rather than stored on it, because this is presentation:
/// the comparison itself has no opinion about what a user types.
const fn comparison_slug(comparison: Comparison) -> &'static str {
    match comparison {
        Comparison::SizeAndModTime => COMPARISON_SIZE_AND_MODTIME,
        Comparison::SizeOnly => COMPARISON_SIZE_ONLY,
        Comparison::Checksum => COMPARISON_CHECKSUM,
    }
}

/// Serialise a value, turning a serde failure into a classified CLI error.
fn encode<T: Serialize>(format: Format, value: &T) -> Result<String> {
    format.encode(value).map_err(|error| {
        CliError::new(
            ExitCode::Uncategorised,
            format!("cannot serialise the check report: {error}"),
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

    fn sample(one_way: bool) -> Report {
        let mut report = Report::new("vault:photos", "./photos", Comparison::Checksum, one_way);
        report.push(Record::new("a.jpg", Difference::Match));
        report.push(Record::new("b.jpg", Difference::Differ));
        report.push(Record::new("c.jpg", Difference::MissingOnDst));
        report.push(Record::new("d.jpg", Difference::MissingOnSrc));
        report.push(Record::new("e.jpg", Difference::Error));
        report
    }

    #[test]
    fn every_verdict_is_counted_separately() {
        let summary = sample(false).summary;
        assert_eq!(summary.checked, 5);
        assert_eq!(summary.matched, 1);
        assert_eq!(summary.differ, 1);
        assert_eq!(summary.missing_on_dst, 1);
        assert_eq!(summary.missing_on_src, 1);
        assert_eq!(summary.errors, 1);
        assert_eq!(summary.differences(), 4);
    }

    #[test]
    fn matches_are_counted_but_not_listed() {
        // A million agreeing objects should produce a summary, not a million
        // lines; the count still proves they were compared.
        let report = sample(false);
        assert_eq!(report.differences.len(), 4);
        assert!(!report.differences.iter().any(|r| r.path == "a.jpg"));
        assert_eq!(report.summary.matched, 1);
    }

    #[test]
    fn one_way_ignores_extra_files_at_the_destination() {
        // `copy` leaves extra files behind by design, so they are not a finding
        // and must not change the count or the exit code.
        let report = sample(true);
        assert_eq!(report.summary.missing_on_src, 0);
        assert_eq!(report.summary.checked, 4);
        assert_eq!(report.summary.differences(), 3);
        assert!(!report.differences.iter().any(|r| r.path == "d.jpg"));
    }

    #[test]
    fn agreement_produces_no_error() {
        let mut report = Report::new("src:", "dst:", Comparison::SizeOnly, false);
        report.push(Record::new("x", Difference::Match));
        assert!(report.outcome().is_none());
    }

    #[test]
    fn differences_are_a_partial_failure_not_an_integrity_failure() {
        // Nothing failed to authenticate; conflating the two would send someone
        // hunting for corruption that is not there.
        let error = sample(false)
            .outcome()
            .expect("differences must be reported");
        assert_eq!(error.code(), ExitCode::PartialFailure);
        assert_ne!(error.code(), ExitCode::IntegrityFailure);
        assert!(error.message().contains("4 of 5"));
        assert!(error.hint().is_some());
    }

    #[test]
    fn an_unreadable_path_still_fails_the_run() {
        // "I could not tell" must never be rolled up into "they agree".
        let mut report = Report::new("src:", "dst:", Comparison::Checksum, false);
        report.push(Record::new("x", Difference::Error));
        assert!(report.outcome().is_some());
    }

    #[test]
    fn json_states_which_comparison_produced_the_count() {
        let rendered = sample(false).render(&out(Format::Json)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["source"], "vault:photos");
        assert_eq!(parsed["dest"], "./photos");
        assert_eq!(parsed["comparison"], "checksum");
        assert_eq!(parsed["proves_contents"], true);
        assert_eq!(parsed["one_way"], false);
        assert_eq!(parsed["summary"]["differ"], 1);
        assert_eq!(parsed["differences"][0]["status"], "differ");
    }

    #[test]
    fn a_metadata_comparison_does_not_claim_to_prove_contents() {
        let report = Report::new("src:", "dst:", Comparison::SizeAndModTime, false);
        let parsed: serde_json::Value =
            serde_json::from_str(&report.render(&out(Format::Json)).unwrap()).unwrap();
        assert_eq!(parsed["comparison"], "size-and-modtime");
        assert_eq!(parsed["proves_contents"], false);
    }

    #[test]
    fn json_lines_emits_one_difference_per_line() {
        let rendered = sample(false).render(&out(Format::JsonLines)).unwrap();
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 4);
        for line in lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed.get("path").is_some());
            assert!(parsed.get("summary").is_none());
        }
    }

    #[test]
    fn the_text_table_lists_the_verdict_then_the_path() {
        let rendered = sample(false).render(&Out::plain()).unwrap();
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines[0].starts_with(INTEGRITY_COLUMN_STATUS));
        assert!(lines[2].starts_with("differ"));
        assert!(lines[2].ends_with("b.jpg"));
        // Matches never reach the table.
        assert!(!rendered.contains("a.jpg"));
    }

    #[test]
    fn two_trees_that_agree_produce_no_stdout() {
        // Not even a header: `dctl check … && echo clean` has to work, and
        // anything on stdout reads as a finding.
        let mut report = Report::new("src:", "dst:", Comparison::SizeOnly, false);
        report.push(Record::new("x", Difference::Match));
        assert_eq!(report.render(&out(Format::JsonLines)).unwrap(), "");
        assert_eq!(report.render(&Out::plain()).unwrap(), "");
        // The whole-document form still reports what was compared.
        let parsed: serde_json::Value =
            serde_json::from_str(&report.render(&out(Format::Json)).unwrap()).unwrap();
        assert_eq!(parsed["summary"]["matched"], 1);
    }
}
