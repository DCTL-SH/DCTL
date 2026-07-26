//! The health verdict a scrub produces.
//!
//! A scrub's output is one number people act on — "is my data still there?" —
//! and three grades, because collapsing them would hide the difference at the
//! moment it matters most:
//!
//! * **healthy** — everything read authenticated.
//! * **degraded** — damage was found and *all of it* was repaired from
//!   redundancy. The system worked as designed; the underlying storage did not.
//! * **damaged** — damage was found that could not be repaired. This is a
//!   countdown to data loss and the only grade that ends in exit code 21.
//!
//! The report also carries what the run actually covered. A sampled scrub proves
//! something about the slice it read and nothing about the rest, so the
//! percentage and the seed travel with the verdict — the seed because a run that
//! found damage in a 10% sample is a run somebody will want to repeat over
//! exactly the same 10%.

// Some of what follows is not reachable from this build's `run` body: the engine
// has no entry point yet for the step that would call it (see the command's
// module documentation). It is written and unit-tested now, with the tests that
// pin its contract, rather than left until the engine lands — a machine-readable
// output format that first appears on the day it is needed is a format nobody
// reviewed.
#![allow(dead_code)]

use serde::Serialize;

use crate::commands::integrity::failure::{self, Verdict};
use crate::constants::{
    HEALTH_DAMAGED, HEALTH_DEGRADED, HEALTH_HEALTHY, INTEGRITY_COLUMN_PATH, INTEGRITY_COLUMN_SIZE,
    INTEGRITY_COLUMN_STATUS,
};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::output::{Align, Border, Column, Format, Out, Table, size};
use crate::source::Assurance;

/// One damaged object, and what was done about it.
#[derive(Clone, Debug, Serialize)]
pub struct Record {
    pub path: String,
    /// The verdict, serialised as its stable slug.
    pub status: Verdict,
    pub size: u64,
    /// Whether the object was rebuilt from redundancy or parity.
    pub repaired: bool,
}

impl Record {
    #[must_use]
    pub fn new(path: impl Into<String>, status: Verdict, size: u64) -> Self {
        Self {
            path: path.into(),
            status,
            size,
            repaired: false,
        }
    }

    /// Mark this object as rebuilt from redundancy.
    #[must_use]
    pub const fn repaired(mut self) -> Self {
        self.repaired = true;
        self
    }
}

/// What the run covered and what it found.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Coverage {
    /// Objects read and authenticated.
    pub scanned: u64,
    /// Objects the sample skipped. Carried explicitly so "healthy" can never be
    /// read as "all of it is healthy" when most of it was not looked at.
    pub skipped: u64,
    /// Bytes read back from the provider.
    pub bytes: u64,
    pub healthy: u64,
    pub damaged: u64,
    pub repaired: u64,
}

impl Coverage {
    /// Damage that is still damage: found, and not repaired.
    #[must_use]
    pub const fn unrepaired(&self) -> u64 {
        self.damaged.saturating_sub(self.repaired)
    }
}

/// The whole result of one `scrub` run.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub target: String,
    /// `healthy`, `degraded` or `damaged`.
    pub health: &'static str,
    /// Which `--verify` strength the objects were read under.
    pub verify_mode: String,
    /// What a clean read actually proved: `authenticated` or `read-back`.
    ///
    /// Carried beside the strength because the two answer different questions
    /// and only both together are a complete claim. `verify_mode` says *how much
    /// was read*; this says *what the reading could prove*. A full read of a
    /// remote that records no hashes is still only a retrievability check, and
    /// `healthy` over one of those must not be mistaken for `healthy` over a
    /// vault (`PLAN.md` §6).
    pub assurance: &'static str,
    /// The share of the dataset this run read.
    pub sample_percent: u8,
    /// The sampling seed, in hex, so a sampled run can be replayed exactly.
    pub seed: String,
    /// Whether repair was enabled for this run.
    pub repair_enabled: bool,
    /// Whether the run stopped early because `--max-errors` was reached.
    pub stopped_early: bool,
    pub coverage: Coverage,
    /// The damaged objects. Healthy ones are counted, not listed.
    pub findings: Vec<Record>,
    /// The worst verdict seen, which decides the exit code. Derived from
    /// `findings`, so it is not published as its own field.
    #[serde(skip)]
    worst: Verdict,
}

impl Report {
    /// An empty report for one run.
    #[must_use]
    pub fn new(
        target: impl Into<String>,
        verify_mode: impl Into<String>,
        assurance: Assurance,
        sample_percent: u8,
        seed: u64,
        repair_enabled: bool,
    ) -> Self {
        Self {
            target: target.into(),
            health: HEALTH_HEALTHY,
            verify_mode: verify_mode.into(),
            assurance: assurance.slug(),
            sample_percent,
            seed: format!("{seed:016x}"),
            repair_enabled,
            stopped_early: false,
            coverage: Coverage::default(),
            findings: Vec::new(),
            worst: Verdict::Ok,
        }
    }

    /// Record an object the sample did not select.
    pub fn skip(&mut self) {
        self.coverage.skipped += 1;
    }

    /// Record an object that was read.
    pub fn push(&mut self, record: Record) {
        self.coverage.scanned += 1;
        self.coverage.bytes += record.size;

        if record.status.is_failure() {
            self.coverage.damaged += 1;
            if record.repaired {
                self.coverage.repaired += 1;
            }
            self.worst = self.worst.worse(record.status);
            self.findings.push(record);
        } else {
            self.coverage.healthy += 1;
        }

        self.health = self.grade();
    }

    /// Note that the run stopped because `--max-errors` was reached.
    ///
    /// Recorded rather than merely logged: a report that ended early covered
    /// less than it was asked to, and a consumer reading only the JSON has to be
    /// able to tell.
    pub fn stopped_early(&mut self) {
        self.stopped_early = true;
    }

    /// The health grade implied by what was found.
    const fn grade(&self) -> &'static str {
        if self.coverage.damaged == 0 {
            HEALTH_HEALTHY
        } else if self.coverage.unrepaired() == 0 {
            HEALTH_DEGRADED
        } else {
            HEALTH_DAMAGED
        }
    }

    /// The worst verdict seen.
    #[must_use]
    pub const fn worst(&self) -> Verdict {
        self.worst
    }

    /// The error this run ends with, or `None` when nothing is still damaged.
    ///
    /// Repaired damage does **not** fail the run: the object is readable again,
    /// and exiting non-zero would train an operator to ignore the one code that
    /// means data is gone. It is still reported as `degraded`, and the findings
    /// list still names every object that had to be rebuilt.
    #[must_use]
    pub fn outcome(&self) -> Option<CliError> {
        failure::failure(
            self.worst,
            self.coverage.unrepaired(),
            self.coverage.scanned,
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
                for record in &self.findings {
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

    /// The findings table a human reads. The grade and the coverage go to
    /// stderr with the rest of the run's commentary; stdout carries the list of
    /// objects, which is the part a pipeline consumes.
    fn render_text(&self, out: &Out) -> String {
        // A bare header with no rows under it is noise in a pipe, and worse, it
        // reads as output — a healthy scrub must put nothing at all on stdout.
        if self.findings.is_empty() {
            return String::new();
        }

        let mut table = Table::new(vec![
            Column::new(INTEGRITY_COLUMN_STATUS, Align::Left),
            Column::new(INTEGRITY_COLUMN_SIZE, Align::Right),
            Column::new(INTEGRITY_COLUMN_PATH, Align::Left).with_style(out.palette().path()),
        ])
        .with_border(Border::Header);

        for record in &self.findings {
            table.push(vec![
                record.status.slug().to_string(),
                size::bytes(record.size, out.units()),
                record.path.clone(),
            ]);
        }
        table.render(out.palette())
    }
}

/// Serialise a value, turning a serde failure into a classified CLI error.
fn encode<T: Serialize>(format: Format, value: &T) -> Result<String> {
    format.encode(value).map_err(|error| {
        CliError::new(
            ExitCode::Uncategorised,
            format!("cannot serialise the scrub report: {error}"),
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

    fn clean() -> Report {
        let mut report = Report::new(
            "vault:",
            "strict",
            Assurance::Authenticated,
            100,
            0x0123_4567_89ab_cdef,
            false,
        );
        report.push(Record::new("a.jpg", Verdict::Ok, 1024));
        report.push(Record::new("b.jpg", Verdict::Ok, 2048));
        report
    }

    #[test]
    fn a_run_that_found_nothing_is_healthy_and_exits_zero() {
        let report = clean();
        assert_eq!(report.health, HEALTH_HEALTHY);
        assert_eq!(report.coverage.scanned, 2);
        assert_eq!(report.coverage.healthy, 2);
        assert_eq!(report.coverage.bytes, 3072);
        assert!(report.outcome().is_none());
        assert!(report.findings.is_empty());
    }

    #[test]
    fn repaired_damage_is_degraded_but_does_not_fail_the_run() {
        // The object is readable again. Failing here would teach an operator to
        // ignore the one exit code that means data is actually gone.
        let mut report = clean();
        report.push(Record::new("c.jpg", Verdict::Corrupt, 512).repaired());
        assert_eq!(report.health, HEALTH_DEGRADED);
        assert_eq!(report.coverage.damaged, 1);
        assert_eq!(report.coverage.repaired, 1);
        assert_eq!(report.coverage.unrepaired(), 0);
        assert!(report.outcome().is_none());
        // It is still named: the storage underneath is failing.
        assert_eq!(report.findings.len(), 1);
    }

    #[test]
    fn unrepairable_damage_is_the_loud_case() {
        let mut report = clean();
        report.push(Record::new("c.jpg", Verdict::Corrupt, 512));
        assert_eq!(report.health, HEALTH_DAMAGED);
        assert_eq!(report.worst(), Verdict::Corrupt);

        let error = report.outcome().expect("unrepaired damage must fail");
        assert_eq!(error.code(), ExitCode::IntegrityFailure);
        assert_eq!(error.code().as_i32(), 21);
        assert!(
            error.message().contains("NOT served"),
            "got: {}",
            error.message()
        );
    }

    #[test]
    fn partly_repaired_damage_is_still_damaged() {
        let mut report = clean();
        report.push(Record::new("c.jpg", Verdict::Corrupt, 1).repaired());
        report.push(Record::new("d.jpg", Verdict::Corrupt, 1));
        assert_eq!(report.coverage.unrepaired(), 1);
        assert_eq!(report.health, HEALTH_DAMAGED);
        assert!(report.outcome().is_some());
    }

    #[test]
    fn a_missing_object_is_not_reported_as_corruption() {
        let mut report = clean();
        report.push(Record::new("gone.jpg", Verdict::Missing, 0));
        assert_eq!(report.health, HEALTH_DAMAGED);
        assert_eq!(report.outcome().unwrap().code(), ExitCode::FileNotFound);
    }

    #[test]
    fn skipped_objects_are_counted_so_coverage_cannot_be_overstated() {
        // "healthy" over a 10% sample is a claim about a tenth of the vault.
        let mut report = Report::new("vault:", "sample", Assurance::Authenticated, 10, 7, false);
        report.push(Record::new("a", Verdict::Ok, 1));
        report.skip();
        report.skip();
        assert_eq!(report.coverage.scanned, 1);
        assert_eq!(report.coverage.skipped, 2);
        assert_eq!(report.sample_percent, 10);
    }

    #[test]
    fn a_grade_always_says_what_the_reading_could_prove() {
        // `healthy` over a remote that records no hashes is a statement about
        // retrievability, not about the bytes. The report has to carry the
        // difference or the weaker claim reads as the stronger one.
        let mut report = Report::new("store:", "strict", Assurance::ReadBack, 100, 0, false);
        report.push(Record::new("a", Verdict::Ok, 1));
        assert_eq!(report.health, HEALTH_HEALTHY);

        let parsed: serde_json::Value =
            serde_json::from_str(&report.render(&out(Format::Json)).unwrap()).unwrap();
        assert_eq!(parsed["assurance"], Assurance::ReadBack.slug());
        assert_ne!(parsed["assurance"], Assurance::Authenticated.slug());
    }

    #[test]
    fn json_carries_the_grade_the_coverage_and_the_replay_seed() {
        let mut report = clean();
        report.push(Record::new("c.jpg", Verdict::Corrupt, 512));
        report.stopped_early();

        let rendered = report.render(&out(Format::Json)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["target"], "vault:");
        assert_eq!(parsed["health"], HEALTH_DAMAGED);
        assert_eq!(parsed["verify_mode"], "strict");
        assert_eq!(parsed["assurance"], Assurance::Authenticated.slug());
        assert_eq!(parsed["sample_percent"], 100);
        assert_eq!(parsed["seed"], "0123456789abcdef");
        assert_eq!(parsed["stopped_early"], true);
        assert_eq!(parsed["repair_enabled"], false);
        assert_eq!(parsed["coverage"]["damaged"], 1);
        assert_eq!(parsed["findings"][0]["status"], "corrupt");
        assert_eq!(parsed["findings"][0]["repaired"], false);
    }

    #[test]
    fn json_lines_emits_one_finding_per_line() {
        let mut report = clean();
        report.push(Record::new("c.jpg", Verdict::Corrupt, 1));
        report.push(Record::new("d.jpg", Verdict::Missing, 2));
        let rendered = report.render(&out(Format::JsonLines)).unwrap();
        assert_eq!(rendered.lines().count(), 2);
        for line in rendered.lines() {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed.get("path").is_some());
            assert!(parsed.get("coverage").is_none());
        }
    }

    #[test]
    fn a_healthy_run_lists_nothing_on_stdout() {
        // Nothing is wrong; the grade belongs on stderr with the commentary.
        assert_eq!(clean().render(&out(Format::JsonLines)).unwrap(), "");
        assert_eq!(clean().render(&Out::plain()).unwrap(), "");
    }

    #[test]
    fn the_text_table_lists_only_the_findings() {
        let mut report = clean();
        report.push(Record::new("c.jpg", Verdict::Corrupt, 512));
        let rendered = report.render(&Out::plain()).unwrap();
        assert!(rendered.contains("corrupt"));
        assert!(rendered.contains("c.jpg"));
        assert!(
            !rendered.contains("a.jpg"),
            "healthy objects are counted, not listed"
        );
    }
}
