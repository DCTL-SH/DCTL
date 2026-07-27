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

use serde::Serialize;

use crate::commands::integrity::failure::{self, Verdict};
use crate::constants::{
    HEALTH_DAMAGED, HEALTH_DEGRADED, HEALTH_HEALTHY, HEALTH_UNVERIFIED, INTEGRITY_COLUMN_PATH,
    INTEGRITY_COLUMN_SIZE, INTEGRITY_COLUMN_STATUS, SCRUB_NOTHING_VERIFIED,
    SCRUB_NOTHING_VERIFIED_HINT,
};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::output::size::count;
use crate::output::{Align, Border, Column, Format, Out, Table, Units, size};
use crate::source::Assurance;

/// One damaged object, and what was done about it.
#[derive(Clone, Debug, Serialize)]
pub struct Record {
    pub path: String,
    /// The verdict, serialised as its stable slug.
    pub status: Verdict,
    /// The object's size, when the index recorded one.
    ///
    /// `null` rather than `0` for a row nothing has measured — see
    /// [`Coverage::bytes`]. A finding that named a damaged object and claimed it
    /// was zero bytes long would misdescribe the loss in the one report written
    /// to be kept.
    pub size: Option<u64>,
    /// Whether the object was rebuilt from redundancy or parity.
    pub repaired: bool,
}

impl Record {
    #[must_use]
    pub fn new(path: impl Into<String>, status: Verdict, size: Option<u64>) -> Self {
        Self {
            path: path.into(),
            status,
            size,
            repaired: false,
        }
    }

    /// Mark this object as rebuilt from redundancy.
    ///
    /// Nothing in this build calls it, and that is the honest state of affairs
    /// rather than an oversight: `--repair` is refused because no redundancy is
    /// written for it to read (`PLAN.md` §13.3). The `repaired` field is still
    /// published on every finding, so a consumer can depend on the key existing
    /// and read `false`; this is the setter that will make it `true`, and the
    /// grading logic that turns it into `degraded` is tested through it below.
    #[allow(dead_code)]
    #[must_use]
    pub const fn repaired(mut self) -> Self {
        self.repaired = true;
        self
    }
}

/// What the run covered and what it found.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Coverage {
    /// Objects read and authenticated.
    pub scanned: u64,
    /// Objects the sample skipped. Carried explicitly so "healthy" can never be
    /// read as "all of it is healthy" when most of it was not looked at.
    pub skipped: u64,
    /// Bytes read back from the provider, or `null` when at least one scanned
    /// object had no recorded size.
    ///
    /// This is a line in an audit trail: it is the record of how much of the
    /// dataset a scheduled run actually put through the reader. A vault whose
    /// index was rebuilt from object headers holds no sizes at all (see
    /// [`crate::source::Entry::size`]), and the old behaviour totalled those
    /// absences as zeroes — so a full, honest scrub of a forty-terabyte vault
    /// filed itself as having read nothing. Null says the run cannot total its
    /// own bytes, which is true and is a thing an auditor can chase;
    /// `measured_bytes` still carries what was countable.
    pub bytes: Option<u64>,
    /// Bytes of the scanned objects that did carry a recorded size.
    ///
    /// Always a number, so the figure is never lost when `bytes` is null. It is
    /// a lower bound on what the run read, never an upper one.
    pub measured_bytes: u64,
    /// How many scanned objects carried no recorded size.
    pub unmeasured: u64,
    pub healthy: u64,
    pub damaged: u64,
    pub repaired: u64,
}

impl Default for Coverage {
    /// A run that has recorded nothing has read a *known* zero bytes.
    ///
    /// Hand-written rather than derived precisely because of `bytes`: the
    /// derived default would be `None`, which would make every scrub — including
    /// one over a fully measured vault — start out unable to total itself and
    /// never recover.
    fn default() -> Self {
        Self {
            scanned: 0,
            skipped: 0,
            bytes: Some(0),
            measured_bytes: 0,
            unmeasured: 0,
            healthy: 0,
            damaged: 0,
            repaired: 0,
        }
    }
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
            // A report that has recorded nothing has verified nothing. Starting
            // at `healthy` and relying on the first `push` to correct it is what
            // let a run that pushed nothing publish a clean grade.
            health: HEALTH_UNVERIFIED,
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
        match record.size {
            Some(size) => {
                self.coverage.measured_bytes = self.coverage.measured_bytes.saturating_add(size);
                self.coverage.bytes = self.coverage.bytes.map(|total| total.saturating_add(size));
            }
            // One unmeasured object is enough: the run's byte total is no longer
            // a fact, and it does not become one again later.
            None => {
                self.coverage.unmeasured = self.coverage.unmeasured.saturating_add(1);
                self.coverage.bytes = None;
            }
        }

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
    ///
    /// Zero objects read is [`HEALTH_UNVERIFIED`], not [`HEALTH_HEALTHY`]. A
    /// grade is a claim about objects that were put through the reader, and over
    /// none of them there is no claim — publishing `healthy` for it is how
    /// `dctl --json scrub replica:` reported a store full of real objects as
    /// sound while verifying not one of them.
    const fn grade(&self) -> &'static str {
        if self.coverage.scanned == 0 {
            HEALTH_UNVERIFIED
        } else if self.coverage.damaged == 0 {
            HEALTH_HEALTHY
        } else if self.coverage.unrepaired() == 0 {
            HEALTH_DEGRADED
        } else {
            HEALTH_DAMAGED
        }
    }

    /// The worst verdict seen.
    ///
    /// The run body does not consult it — [`Report::outcome`] already reduces it
    /// to the error that ends the run — but the reduction is the part most worth
    /// pinning, and a test cannot assert on a private field. Exposed rather than
    /// made `pub(crate)` so the accessor and the exit code it decides stay
    /// documented together.
    #[allow(dead_code)]
    #[must_use]
    pub const fn worst(&self) -> Verdict {
        self.worst
    }

    /// The error this run ends with, or `None` when the run both covered
    /// something and found nothing still damaged.
    ///
    /// Repaired damage does **not** fail the run: the object is readable again,
    /// and exiting non-zero would train an operator to ignore the one code that
    /// means data is gone. It is still reported as `degraded`, and the findings
    /// list still names every object that had to be rebuilt.
    ///
    /// ## Reading nothing is not passing
    ///
    /// A run that scanned zero objects exits
    /// [`ExitCode::NoFilesTransferred`] (9), not `0`. This is the whole of
    /// defect D2: `dctl scrub archive:` over a real dataset and
    /// `dctl scrub archive:typo` over nothing were the same silent exit-zero, so
    /// a cron entry could verify nothing every night and stay green for years —
    /// and the first time anyone found out would be a restore. Health is a claim
    /// about objects that were read; over zero objects there is no claim to
    /// make, and reporting `healthy` for it is the misreport `PLAN.md` §6
    /// forbids.
    ///
    /// Code 9 rather than a new one: it is already published as "succeeded, but
    /// nothing was transferred", it is already the code scripts branch on for
    /// "the run worked and did no work", and inventing a second spelling of that
    /// would leave every existing wrapper unable to tell the two apart. It is
    /// deliberately *not* an error code — nothing failed, the operator asked for
    /// a scrub of a place with nothing in it — but it is not zero either, which
    /// is the only property the cron case actually needs.
    ///
    /// Every route to zero coverage lands here on purpose: an empty vault, a
    /// prefix that matches nothing, filters that admit nothing, and a
    /// `--sample-percent` so small it selected nothing. All four mean the same
    /// thing to the person reading the exit code — this run proved nothing — and
    /// the message names which one it was.
    #[must_use]
    pub fn outcome(&self) -> Option<CliError> {
        // Damage first: an object that failed to authenticate outranks any
        // statement about coverage, and a run that found damage plainly did not
        // scan zero objects anyway.
        if let Some(error) = failure::failure(
            self.worst,
            self.coverage.unrepaired(),
            self.coverage.scanned,
        ) {
            return Some(error);
        }

        if self.coverage.scanned == 0 {
            return Some(
                CliError::new(
                    ExitCode::NoFilesTransferred,
                    format!(
                        "{SCRUB_NOTHING_VERIFIED}: {}",
                        self.nothing_verified_cause()
                    ),
                )
                .with_hint(SCRUB_NOTHING_VERIFIED_HINT),
            );
        }

        None
    }

    /// Why this run covered nothing, in the words of whichever cause applied.
    ///
    /// Four causes reach the same exit code and want four different next
    /// actions, so the message has to separate them: a mistyped prefix is a
    /// typo, an empty dataset is a backup that never ran, filters are the user's
    /// own command line, and a sample that selected nothing is a `--sample-
    /// percent` too small for how few objects there are. Ordered from the most
    /// specific evidence to the least, so the reason quoted is the one the run
    /// actually observed rather than the first one that could be true.
    fn nothing_verified_cause(&self) -> String {
        if self.coverage.skipped > 0 {
            return format!(
                "the {}% sample selected none of the {} {} under '{}'",
                self.sample_percent,
                count(self.coverage.skipped),
                objects(self.coverage.skipped),
                self.target
            );
        }
        format!("no object was listed under '{}'", self.target)
    }

    /// The one line a text-mode scrub always prints, whatever it found.
    ///
    /// Defect D2 in one sentence: everything this command said about a healthy
    /// run went through [`Out::info`], which is silent below `-v`, and the
    /// findings table renders empty when there are no findings. So the default
    /// output of a successful scrub was *nothing at all*, on both streams —
    /// indistinguishable from a scrub that had found nothing to read, and from a
    /// binary that had not run. A scrub's product is its coverage; the coverage
    /// has to be visible without being asked for.
    ///
    /// It names the assurance as well as the counts, because `healthy` over a
    /// plain store is a retrievability claim and `healthy` over a vault is a
    /// claim about the bytes, and the summary is the line that will be pasted
    /// into a ticket without its context.
    #[must_use]
    pub fn summary(&self, units: Units) -> String {
        if self.coverage.scanned == 0 {
            // No counts and no byte figure: there is nothing to count, and
            // "0 objects, 0 B, healthy" is the sentence this whole change exists
            // to delete.
            return format!(
                "{}: {SCRUB_NOTHING_VERIFIED} — {}",
                self.health,
                self.nothing_verified_cause()
            );
        }

        let mut line = format!(
            "{}: {} {} read and checked, {} ({}) under '{}'",
            self.health,
            count(self.coverage.scanned),
            objects(self.coverage.scanned),
            size::bytes_or_unknown(self.coverage.bytes, units),
            self.assurance,
            self.target
        );
        if self.coverage.unmeasured > 0 {
            line.push_str(&format!(
                "; {} of them carried no recorded size, so the byte figure is a \
                 lower bound",
                count(self.coverage.unmeasured)
            ));
        }
        if self.coverage.skipped > 0 {
            line.push_str(&format!(
                "; {} {} skipped by the {}% sample and not covered by this \
                 grade",
                count(self.coverage.skipped),
                were(self.coverage.skipped),
                self.sample_percent
            ));
        }
        if self.coverage.damaged > 0 {
            line.push_str(&format!(
                "; {} damaged, {} of those repaired",
                count(self.coverage.damaged),
                count(self.coverage.repaired)
            ));
        }
        line
    }

    /// Put the coverage where the operator is already looking.
    ///
    /// stderr, not stdout: stdout is the findings channel that `--json` and a
    /// pipeline consume, and a summary line appended to it would break
    /// `dctl scrub --format json-lines | jq`. `--quiet` still silences it, which
    /// is the contract for every confirmation this binary prints — a caller that
    /// asked for silence gets the exit code, and the exit code now carries the
    /// zero-coverage case that used to hide here.
    ///
    /// A run that covered nothing says nothing *here*, because
    /// [`Report::outcome`] is about to say it louder: that case ends in an
    /// error, whose message names the cause and whose hint names the remedy, and
    /// which prints even under `--quiet`. Printing the same sentence twice would
    /// train the reader to skip the first one.
    pub fn announce(&self, out: &Out) {
        if self.coverage.scanned > 0 {
            out.success(self.summary(out.units()));
        }
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
                size::bytes_or_unknown(record.size, out.units()),
                record.path.clone(),
            ]);
        }
        table.render(out.palette())
    }
}

/// `object` or `objects`, agreeing with `count`.
///
/// A summary line is the sentence most likely to be pasted into a ticket, and
/// "1 objects read and checked" reads as a tool that was not finished. Written
/// as a function rather than an `if` at each of the three call sites, so the
/// three cannot disagree.
const fn objects(count: u64) -> &'static str {
    if count == 1 { "object" } else { "objects" }
}

/// `was` or `were`, agreeing with `count`. See [`objects`].
const fn were(count: u64) -> &'static str {
    if count == 1 { "was" } else { "were" }
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
        report.push(Record::new("a.jpg", Verdict::Ok, Some(1024)));
        report.push(Record::new("b.jpg", Verdict::Ok, Some(2048)));
        report
    }

    #[test]
    fn a_run_that_found_nothing_is_healthy_and_exits_zero() {
        let report = clean();
        assert_eq!(report.health, HEALTH_HEALTHY);
        assert_eq!(report.coverage.scanned, 2);
        assert_eq!(report.coverage.healthy, 2);
        assert_eq!(report.coverage.bytes, Some(3072));
        assert!(report.outcome().is_none());
        assert!(report.findings.is_empty());
    }

    #[test]
    fn repaired_damage_is_degraded_but_does_not_fail_the_run() {
        // The object is readable again. Failing here would teach an operator to
        // ignore the one exit code that means data is actually gone.
        let mut report = clean();
        report.push(Record::new("c.jpg", Verdict::Corrupt, Some(512)).repaired());
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
        report.push(Record::new("c.jpg", Verdict::Corrupt, Some(512)));
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
        report.push(Record::new("c.jpg", Verdict::Corrupt, Some(1)).repaired());
        report.push(Record::new("d.jpg", Verdict::Corrupt, Some(1)));
        assert_eq!(report.coverage.unrepaired(), 1);
        assert_eq!(report.health, HEALTH_DAMAGED);
        assert!(report.outcome().is_some());
    }

    #[test]
    fn a_missing_object_is_not_reported_as_corruption() {
        let mut report = clean();
        report.push(Record::new("gone.jpg", Verdict::Missing, Some(0)));
        assert_eq!(report.health, HEALTH_DAMAGED);
        assert_eq!(report.outcome().unwrap().code(), ExitCode::FileNotFound);
    }

    #[test]
    fn skipped_objects_are_counted_so_coverage_cannot_be_overstated() {
        // "healthy" over a 10% sample is a claim about a tenth of the vault.
        let mut report = Report::new("vault:", "sample", Assurance::Authenticated, 10, 7, false);
        report.push(Record::new("a", Verdict::Ok, Some(1)));
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
        report.push(Record::new("a", Verdict::Ok, Some(1)));
        assert_eq!(report.health, HEALTH_HEALTHY);

        let parsed: serde_json::Value =
            serde_json::from_str(&report.render(&out(Format::Json)).unwrap()).unwrap();
        assert_eq!(parsed["assurance"], Assurance::ReadBack.slug());
        assert_ne!(parsed["assurance"], Assurance::Authenticated.slug());
    }

    #[test]
    fn json_carries_the_grade_the_coverage_and_the_replay_seed() {
        let mut report = clean();
        report.push(Record::new("c.jpg", Verdict::Corrupt, Some(512)));
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
        report.push(Record::new("c.jpg", Verdict::Corrupt, Some(1)));
        report.push(Record::new("d.jpg", Verdict::Missing, Some(2)));
        let rendered = report.render(&out(Format::JsonLines)).unwrap();
        assert_eq!(rendered.lines().count(), 2);
        for line in rendered.lines() {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed.get("path").is_some());
            assert!(parsed.get("coverage").is_none());
        }
    }

    #[test]
    fn a_run_that_read_nothing_is_not_graded_healthy_and_does_not_exit_zero() {
        // Defect D2. `dctl scrub archive:` over a real dataset and
        // `dctl scrub archive:typo` over nothing were both a silent exit 0, so a
        // nightly cron could verify nothing for years and stay green. Health is
        // a claim about objects that were read; over none there is no claim.
        let report = Report::new(
            "vault:typo",
            "strict",
            Assurance::Authenticated,
            100,
            0,
            false,
        );
        assert_eq!(report.coverage.scanned, 0);
        assert_eq!(report.health, HEALTH_UNVERIFIED);
        assert_ne!(report.health, HEALTH_HEALTHY);

        let error = report
            .outcome()
            .expect("a run that verified nothing must not exit zero");
        assert_eq!(error.code(), ExitCode::NoFilesTransferred);
        assert_eq!(error.code().as_i32(), 9);
        assert!(error.message().contains(SCRUB_NOTHING_VERIFIED));
        // And it names the target, so the operator can see it was the prefix.
        assert!(
            error.message().contains("vault:typo"),
            "got: {}",
            error.message()
        );
        assert!(error.hint().is_some(), "a refusal must say what to do next");
    }

    #[test]
    fn a_sample_that_selected_nothing_says_so_rather_than_blaming_the_prefix() {
        // Same exit code, different cause, different next action: the objects
        // are there and the sample passed over all of them.
        let mut report = Report::new("vault:", "sample", Assurance::Authenticated, 10, 7, false);
        report.skip();
        report.skip();

        let error = report.outcome().expect("nothing was read");
        assert_eq!(error.code(), ExitCode::NoFilesTransferred);
        assert!(
            error.message().contains("sample"),
            "got: {}",
            error.message()
        );
        assert!(report.summary(Units::Binary).contains("sample"));
    }

    #[test]
    fn a_run_that_covered_nothing_leaves_the_confirmation_to_the_error() {
        // The exit code and its message carry that case, and they print even
        // under `--quiet`. A tick beside it would read as a pass, and a second
        // copy of the same sentence trains the reader to skip the first.
        let out = Out::new(Format::Text, ColorChoice::Never, Units::Binary, false, 0);
        let report = Report::new(
            "vault:typo",
            "strict",
            Assurance::Authenticated,
            100,
            0,
            false,
        );
        report.announce(&out);
        assert!(report.outcome().is_some(), "the error is what reports it");
    }

    #[test]
    fn a_summary_agrees_with_itself_about_one_object() {
        // The summary line is the sentence most likely to be pasted into a
        // ticket, and "1 objects read and checked" reads as an unfinished tool.
        let mut report = Report::new("vault:", "strict", Assurance::Authenticated, 100, 0, false);
        report.push(Record::new("a.jpg", Verdict::Ok, Some(1)));
        let one = report.summary(Units::Binary);
        assert!(one.contains("1 object read"), "got: {one}");
        assert!(!one.contains("1 objects"), "got: {one}");

        report.push(Record::new("b.jpg", Verdict::Ok, Some(1)));
        assert!(report.summary(Units::Binary).contains("2 objects read"));
    }

    #[test]
    fn a_clean_run_still_says_what_it_covered() {
        // The other half of D2: a healthy scrub printed nothing at all at
        // default verbosity, so it was indistinguishable from a scrub that had
        // found nothing to read — and from a binary that never ran.
        let summary = clean().summary(Units::Binary);
        assert!(summary.starts_with(HEALTH_HEALTHY), "got: {summary}");
        assert!(summary.contains('2'), "the object count: {summary}");
        assert!(summary.contains("3.00 KiB"), "the byte figure: {summary}");
        // And what the reading proved, because `healthy` over a plain store is
        // a different claim from `healthy` over a vault.
        assert!(
            summary.contains(Assurance::Authenticated.slug()),
            "got: {summary}"
        );
        assert!(summary.contains("vault:"), "got: {summary}");
    }

    #[test]
    fn an_unmeasured_object_makes_the_byte_total_unknown_rather_than_short() {
        // Defect D3 reaching the audit trail. A vault whose index was rebuilt
        // records no sizes, and totalling those absences as zeroes filed a full
        // scrub of a real dataset as having read nothing.
        let mut report = Report::new("vault:", "strict", Assurance::Authenticated, 100, 0, false);
        report.push(Record::new("a.jpg", Verdict::Ok, Some(10)));
        report.push(Record::new("b.jpg", Verdict::Ok, None));

        assert_eq!(report.coverage.scanned, 2);
        assert_eq!(report.coverage.bytes, None);
        assert_eq!(
            report.coverage.measured_bytes, 10,
            "the countable part survives"
        );
        assert_eq!(report.coverage.unmeasured, 1);
        // The grade is untouched: the objects authenticated, and that is what a
        // scrub is for. Only the byte figure is unknown.
        assert_eq!(report.health, HEALTH_HEALTHY);
        assert!(report.outcome().is_none());

        let parsed: serde_json::Value =
            serde_json::from_str(&report.render(&out(Format::Json)).unwrap()).unwrap();
        assert_eq!(parsed["coverage"]["bytes"], serde_json::Value::Null);
        assert_eq!(parsed["coverage"]["unmeasured"], 1);
    }

    #[test]
    fn a_fully_measured_run_publishes_a_real_total_including_a_real_zero() {
        // The trap the fix must not fall into: an object that genuinely is zero
        // bytes long has a recorded size, and a run over only such objects has a
        // known total of zero rather than an unknown one.
        let mut report = Report::new("vault:", "strict", Assurance::Authenticated, 100, 0, false);
        report.push(Record::new("empty.txt", Verdict::Ok, Some(0)));
        assert_eq!(report.coverage.bytes, Some(0));
        assert_eq!(report.coverage.unmeasured, 0);
        assert_eq!(report.health, HEALTH_HEALTHY);
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
        report.push(Record::new("c.jpg", Verdict::Corrupt, Some(512)));
        let rendered = report.render(&Out::plain()).unwrap();
        assert!(rendered.contains("corrupt"));
        assert!(rendered.contains("c.jpg"));
        assert!(
            !rendered.contains("a.jpg"),
            "healthy objects are counted, not listed"
        );
    }
}
