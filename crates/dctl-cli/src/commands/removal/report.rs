//! What a removal tells the user, written as it happens.
//!
//! A removal report is a stream, not a document assembled at the end, and that
//! is a correctness property rather than a performance one. `PLAN.md` §6 forbids
//! reporting work that did not happen; the surest way to honour it is for each
//! record to be written **at the moment** the work either happened or did not,
//! so there is no window in which a buffer of intentions could be flushed as a
//! buffer of outcomes. It is also what keeps memory at O(1) on a removal of ten
//! million objects (`PLAN.md` §16.2) — including the failure records, which are
//! emitted individually precisely because there is no bound on how many of them
//! a broken provider can produce.
//!
//! ## One document, three renderings
//!
//! The report is a single sequence: the **plan** (what was asked for), then one
//! record per object, then a **summary**. Every record carries a `status`, and
//! the statuses are a closed, tested set ([`crate::constants`]), so a consumer
//! branches on a name rather than on a position.
//!
//! * `--json` wraps the sequence in one array, streamed element by element, so
//!   `dctl purge --json vault:old | jq` receives one valid document.
//! * `--format json-lines` emits the same elements one per line, which is the
//!   shape that survives a pipeline.
//! * Text prints the plan as the familiar two-column table, then one aligned
//!   line per object; the totals go to **stderr**, so a run's data and its
//!   commentary stay on separate streams.
//!
//! The plan is on stdout in all three, as the sequence's first element, and that
//! is a deliberate uniformity rather than an oversight about pipes. Two separate
//! documents on one stdout is not parseable JSON, so the machine formats have no
//! choice; making text differ would mean the three renderings no longer describe
//! the same document, which is how a consumer written against one of them
//! quietly breaks on another. A report that shows results without showing what
//! was asked for is also a report nobody can audit.
//!
//! ## Why `would-remove` is not `removed`
//!
//! A dry run's records say `would-remove`. A consumer must be able to tell a
//! rehearsal from a run by reading the output, without also having seen the
//! command line — a log line that reads `removed photos/2024/a.jpg` when nothing
//! was removed is the single most dangerous sentence this tool could print.

use serde::Serialize;

use crate::commands::listing::emit::Emitter;
use crate::constants::{
    REMOVAL_KIND_OBJECT, REMOVAL_SIZE_ABSENT, REMOVAL_SIZE_WIDTH, REMOVAL_STATUS_ABSENT,
    REMOVAL_STATUS_FAILED, REMOVAL_STATUS_NOT_STAGED, REMOVAL_STATUS_REMOVED,
    REMOVAL_STATUS_SUMMARY, REMOVAL_STATUS_UNSUPPORTED, REMOVAL_STATUS_WIDTH,
    REMOVAL_STATUS_WOULD_REMOVE,
};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::logging::fields;
use crate::output::size;

use super::plan::{self, Plan, PlanOptions};
use super::selection::Item;

/// One line of the report.
///
/// Every optional field is omitted when it does not apply rather than filled
/// with a placeholder. A `"size": 0` on a record whose size nobody measured
/// would be a number a consumer could total.
#[derive(Debug, Serialize)]
struct Record<'a> {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<&'static str>,
    /// Why a removal failed, or why a class could not be swept.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// The closing record: what the run actually did.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Totals {
    /// Whether this run was forbidden from changing anything.
    pub dry_run: bool,
    /// Objects a real run removed. Always zero on a dry run.
    pub removed: u64,
    /// Objects a dry run would have removed. Always zero on a real run.
    pub would_remove: u64,
    /// Objects that were already gone when the removal reached them.
    pub absent: u64,
    /// Objects that could not be removed. Non-zero means exit 6.
    pub failed: u64,
    /// Debris classes this backend cannot enumerate.
    pub unsupported: u64,
    /// Debris classes this backend does not have. Never an error: the question
    /// was answered, and the answer was "there is no such thing here".
    pub not_staged: u64,
    /// Bytes accounted for by `removed` (or by `would_remove` on a dry run), or
    /// `null` when any of those objects had no recorded size.
    ///
    /// Never a total of everything that was *looked at*: the figure a user acts
    /// on is how much storage stopped being billed, and an object that failed to
    /// delete is still being billed for. By the same argument it must be `null`
    /// rather than short: "you freed 0 B" after deleting a rebuilt vault's
    /// contents is a number somebody would act on, and it would be wrong.
    pub bytes: Option<u64>,
    /// Bytes of the accounted objects that did carry a recorded size — the
    /// honest lower bound behind a null `bytes`.
    pub measured_bytes: u64,
    /// How many accounted objects carried no recorded size.
    pub unmeasured: u64,
}

impl Default for Totals {
    /// A run that removed nothing freed a *known* zero bytes. Derived, `bytes`
    /// would start as `None` and no run could ever report a total.
    fn default() -> Self {
        Self {
            dry_run: false,
            removed: 0,
            would_remove: 0,
            absent: 0,
            failed: 0,
            unsupported: 0,
            not_staged: 0,
            bytes: Some(0),
            measured_bytes: 0,
            unmeasured: 0,
        }
    }
}

impl Totals {
    /// Fold one removed object's size into the running figures.
    ///
    /// One method rather than three lines repeated at each call site, because
    /// the three fields are only correct together: a caller that added to
    /// `measured_bytes` and forgot to clear `bytes` would publish a short total
    /// as a total, which is the exact defect this shape exists to prevent.
    fn account(&mut self, size: Option<u64>) {
        match size {
            Some(bytes) => {
                self.measured_bytes = self.measured_bytes.saturating_add(bytes);
                self.bytes = self.bytes.map(|total| total.saturating_add(bytes));
            }
            None => {
                self.unmeasured = self.unmeasured.saturating_add(1);
                self.bytes = None;
            }
        }
    }
}

/// A removal report in progress.
pub struct Report<'a> {
    ctx: &'a Ctx,
    /// Present only for the machine formats. Text is written line by line
    /// through the sink, because a text report has no punctuation to balance.
    emitter: Option<Emitter<'a>>,
    totals: Totals,
}

impl<'a> Report<'a> {
    /// Open a report for this run.
    #[must_use]
    pub fn new(ctx: &'a Ctx) -> Self {
        Self {
            emitter: ctx.out.is_json().then(|| Emitter::new(&ctx.out)),
            totals: Totals {
                dry_run: ctx.is_dry_run(),
                ..Totals::default()
            },
            ctx,
        }
    }

    /// Write the request the run resolved to, as the first element.
    ///
    /// # Errors
    /// A stdout write failure other than a broken pipe.
    pub fn plan<O: PlanOptions>(&mut self, plan: &Plan<'_, O>) -> Result<()> {
        match self.emitter.as_mut() {
            Some(emitter) => emitter.push(plan),
            // The text branch renders the two-column table every other command
            // in this family already prints, so a `--dry-run` reads the same way
            // it did before there was an engine behind it.
            None => plan::emit(self.ctx, plan),
        }
    }

    /// Record an object a dry run would have removed.
    ///
    /// # Errors
    /// A stdout write failure other than a broken pipe.
    pub fn would_remove(&mut self, item: &Item) -> Result<()> {
        self.totals.would_remove += 1;
        self.totals.account(item.size);
        self.item(REMOVAL_STATUS_WOULD_REMOVE, item, None)
    }

    /// Record an object that is now gone.
    ///
    /// # Errors
    /// A stdout write failure other than a broken pipe.
    pub fn removed(&mut self, item: &Item) -> Result<()> {
        self.totals.removed += 1;
        self.totals.account(item.size);
        // The counter the end-of-run summary and `dctl`'s exit logic read. Fed
        // here rather than at the call site so that a record and a count can
        // never disagree about the same object.
        self.ctx.stats.file_deleted();
        tracing::info!({ fields::PATH } = item.path, kind = item.kind, "removed");
        self.item(REMOVAL_STATUS_REMOVED, item, None)
    }

    /// Record an object that was already gone.
    ///
    /// Neither a removal nor a failure: something else deleted it between the
    /// listing and the delete. Counting it either way would be inventing an
    /// outcome for work nobody did.
    ///
    /// # Errors
    /// A stdout write failure other than a broken pipe.
    pub fn absent(&mut self, item: &Item) -> Result<()> {
        self.totals.absent += 1;
        self.item(REMOVAL_STATUS_ABSENT, item, None)
    }

    /// Record an object that could not be removed, and why.
    ///
    /// Counted as an error, which is what downgrades the whole run to
    /// [`ExitCode::PartialFailure`](crate::exit::ExitCode::PartialFailure).
    /// `PLAN.md` §7 forbids rolling a partial failure into a success, and the
    /// only way to guarantee that is for the failure to be counted at the moment
    /// it is observed.
    ///
    /// # Errors
    /// A stdout write failure other than a broken pipe.
    pub fn failed(&mut self, item: &Item, reason: impl Into<String>) -> Result<()> {
        let reason = reason.into();
        self.totals.failed += 1;
        self.ctx.stats.error();
        tracing::warn!(
            { fields::PATH } = item.path,
            kind = item.kind,
            error = %reason,
            "removal failed"
        );
        // Always on stderr, even under `--quiet`: silence about a failure is the
        // one thing the output layer never does.
        self.ctx
            .out
            .error(format!("could not remove '{}': {reason}", item.path));
        self.item(REMOVAL_STATUS_FAILED, item, Some(reason))
    }

    /// Record a class of debris this backend cannot enumerate.
    ///
    /// # Errors
    /// A stdout write failure other than a broken pipe.
    pub fn unsupported(&mut self, class: &'static str, reason: impl Into<String>) -> Result<()> {
        let reason = reason.into();
        self.totals.unsupported += 1;
        self.ctx.out.warn(format!("{class}: {reason}"));
        self.write(&Record {
            status: REMOVAL_STATUS_UNSUPPORTED,
            path: None,
            size: None,
            kind: Some(class),
            reason: Some(reason),
        })
    }

    /// Record a class of debris this backend does not have, and why.
    ///
    /// Distinct from [`unsupported`](Report::unsupported) in every way that
    /// matters: that one means "I could not look", this one means "I looked at
    /// the question and there is nothing of this kind here". It raises no error
    /// however the class was asked for, because nothing failed — and it is said
    /// out loud rather than left to `removed: 0`, because a bare zero from a
    /// sweep is precisely the sentence this command spent a release printing
    /// untruthfully on the backends where the debris does accumulate.
    ///
    /// # Errors
    /// A stdout write failure other than a broken pipe.
    pub fn not_staged(&mut self, class: &'static str, reason: impl Into<String>) -> Result<()> {
        let reason = reason.into();
        self.totals.not_staged += 1;
        self.ctx.out.warn(format!("{class}: {reason}"));
        self.write(&Record {
            status: REMOVAL_STATUS_NOT_STAGED,
            path: None,
            size: None,
            kind: Some(class),
            reason: Some(reason),
        })
    }

    /// The totals so far, for a caller that has to decide what to say next.
    #[must_use]
    pub const fn totals(&self) -> Totals {
        self.totals
    }

    /// Close the report with its summary.
    ///
    /// # Errors
    /// A stdout write failure other than a broken pipe.
    pub fn finish(self) -> Result<()> {
        // Destructured rather than matched in place: the summary either closes a
        // JSON document or is spoken on stderr, and the two arms need different
        // halves of `self`.
        let Self {
            ctx,
            emitter,
            totals,
        } = self;

        match emitter {
            Some(mut emitter) => {
                emitter.push(&Summary::of(&totals))?;
                emitter.finish()?;
            }
            None => human_totals(ctx, &totals),
        }
        Ok(())
    }

    /// Write one per-object record in whichever format is active.
    fn item(&mut self, status: &'static str, item: &Item, reason: Option<String>) -> Result<()> {
        self.write(&Record {
            status,
            path: Some(&item.path),
            size: item.size,
            kind: Some(item.kind),
            reason,
        })
    }

    fn write(&mut self, record: &Record<'_>) -> Result<()> {
        match self.emitter.as_mut() {
            Some(emitter) => emitter.push(record),
            None => Ok(self.ctx.out.line(text_line(record, self.ctx.out.units()))?),
        }
    }
}

/// The human closing line, on stderr beside the standard summary.
///
/// Stderr because it is commentary on the data, not data; and worded from the
/// counters rather than from the request, so it can only ever describe what
/// happened.
fn human_totals(ctx: &Ctx, totals: &Totals) {
    let (verb, acted) = if totals.dry_run {
        (REMOVAL_STATUS_WOULD_REMOVE, totals.would_remove)
    } else {
        (REMOVAL_STATUS_REMOVED, totals.removed)
    };
    let line = format!(
        "{verb}: {} object(s), {}",
        size::count(acted),
        size::bytes_or_unknown(totals.bytes, ctx.out.units())
    );

    if totals.failed > 0 {
        // A run with survivors is not a success, and the closing line is the
        // last thing a person reads.
        ctx.out.error(format!(
            "{line}; {} object(s) could not be removed",
            size::count(totals.failed)
        ));
    } else {
        ctx.out.success(line);
    }
}

/// The serialised form of [`Totals`], with its status attached.
///
/// A wrapper rather than a `status` field on `Totals` itself, because the status
/// is a constant of the shape and a struct field would let a caller set it to
/// something else.
#[derive(Debug, Serialize)]
struct Summary<'a> {
    status: &'static str,
    #[serde(flatten)]
    totals: &'a Totals,
}

impl<'a> Summary<'a> {
    const fn of(totals: &'a Totals) -> Self {
        Self {
            status: REMOVAL_STATUS_SUMMARY,
            totals,
        }
    }
}

/// One line of the text report.
///
/// Pure, so the exact bytes are testable without a terminal — the alignment is
/// what makes `awk '{print $NF}'` work on the output, and it is worth pinning.
fn text_line(record: &Record<'_>, units: crate::output::Units) -> String {
    let status = record.status;
    let size = match record.size {
        Some(bytes) => size::bytes(bytes, units),
        None => REMOVAL_SIZE_ABSENT.to_string(),
    };
    // A record with no path names its class instead — the `unsupported` line has
    // no object to point at, and an empty last column would look like a bug.
    let path: &str = match record.path {
        Some(path) => path,
        None => record.kind.unwrap_or(REMOVAL_KIND_OBJECT),
    };
    format!("{status:<REMOVAL_STATUS_WIDTH$}{size:>REMOVAL_SIZE_WIDTH$}  {path}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::globals::GlobalArgs;
    use crate::constants::{REMOVAL_KIND_DIRECTORY, REMOVAL_KIND_STAGING, REMOVAL_STATUS_PLANNED};
    use crate::output::Units;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        Ctx::new(Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals)
    }

    fn item(path: &str, size: u64) -> Item {
        Item {
            path: path.to_string(),
            size: Some(size),
            kind: REMOVAL_KIND_OBJECT,
        }
    }

    fn record<'a>(status: &'static str, path: &'a str, size: Option<u64>) -> Record<'a> {
        Record {
            status,
            path: Some(path),
            size,
            kind: Some(REMOVAL_KIND_OBJECT),
            reason: None,
        }
    }

    #[test]
    fn a_dry_run_never_says_removed() {
        // The single most dangerous sentence this tool could print.
        let ctx = ctx(&["--dry-run", "--quiet"]);
        let mut report = Report::new(&ctx);
        report.would_remove(&item("a.txt", 10)).unwrap();

        let totals = report.totals();
        assert!(totals.dry_run);
        assert_eq!(totals.would_remove, 1);
        assert_eq!(totals.removed, 0);
        assert_eq!(totals.bytes, Some(10));
        // And nothing was counted as deleted, which is what the exit logic and
        // the end-of-run summary both read.
        assert_eq!(ctx.stats.snapshot().files_deleted, 0);
    }

    #[test]
    fn a_removal_moves_the_counter_the_summary_reads() {
        let ctx = ctx(&["--quiet"]);
        let mut report = Report::new(&ctx);
        report.removed(&item("a.txt", 4)).unwrap();
        report.removed(&item("b.txt", 6)).unwrap();

        assert_eq!(report.totals().removed, 2);
        assert_eq!(report.totals().bytes, Some(10));
        assert_eq!(ctx.stats.snapshot().files_deleted, 2);
        assert_eq!(ctx.stats.snapshot().errors, 0);
    }

    #[test]
    fn a_failure_is_counted_as_an_error_and_never_as_a_removal() {
        // PLAN.md §7: a partial failure may not be rolled into a success, and
        // the exit code is derived from this counter.
        let ctx = ctx(&["--quiet"]);
        let mut report = Report::new(&ctx);
        report.removed(&item("a.txt", 4)).unwrap();
        report
            .failed(&item("b.txt", 6), "permission denied")
            .unwrap();

        assert_eq!(report.totals().removed, 1);
        assert_eq!(report.totals().failed, 1);
        // The bytes figure counts what stopped being billed, so the survivor is
        // not in it.
        assert_eq!(report.totals().bytes, Some(4));
        assert_eq!(ctx.stats.snapshot().errors, 1);
        assert_eq!(ctx.outcome(), crate::exit::ExitCode::PartialFailure);
    }

    #[test]
    fn an_object_that_vanished_is_neither_removed_nor_failed() {
        let ctx = ctx(&["--quiet"]);
        let mut report = Report::new(&ctx);
        report.absent(&item("gone.txt", 3)).unwrap();

        let totals = report.totals();
        assert_eq!(totals.absent, 1);
        assert_eq!(totals.removed, 0);
        assert_eq!(totals.failed, 0);
        assert_eq!(totals.bytes, Some(0), "nothing stopped being billed");
        assert_eq!(ctx.stats.snapshot().errors, 0);
    }

    #[test]
    fn the_byte_total_saturates_rather_than_wrapping() {
        // A wrapped total would print a small number for an enormous removal.
        let ctx = ctx(&["--quiet"]);
        let mut report = Report::new(&ctx);
        report.removed(&item("a", u64::MAX)).unwrap();
        report.removed(&item("b", 1)).unwrap();
        assert_eq!(report.totals().bytes, Some(u64::MAX));
    }

    #[test]
    fn a_class_this_backend_does_not_have_is_neither_an_error_nor_a_removal() {
        // The third answer. `unsupported` means "I could not look" and raises
        // the run's error count when the class was named; this one means "I
        // looked and there is no such thing here", which nothing failed at. A
        // sweep of an object store, whose uploads never touch a temporary key,
        // has to be able to say so without failing and without printing the bare
        // `removed: 0` that made this report untrustworthy on the backends where
        // the debris does accumulate.
        let ctx = ctx(&["--quiet"]);
        let mut report = Report::new(&ctx);
        report
            .not_staged(
                REMOVAL_KIND_STAGING,
                "this backend uploads straight to the final key",
            )
            .unwrap();

        let totals = report.totals();
        assert_eq!(totals.not_staged, 1);
        assert_eq!(totals.unsupported, 0, "it is not the same answer");
        assert_eq!(totals.removed, 0);
        assert_eq!(totals.failed, 0);
        assert_eq!(ctx.stats.snapshot().errors, 0, "nothing failed");
        assert_eq!(ctx.outcome(), crate::exit::ExitCode::Success);
    }

    #[test]
    fn the_two_answers_that_are_not_counts_are_distinguishable_in_the_json() {
        // A consumer branches on the status, and the two facts have different
        // remedies: one is "use the provider's console", the other is "there is
        // nothing to do".
        let inapplicable = serde_json::to_value(Record {
            status: REMOVAL_STATUS_NOT_STAGED,
            path: None,
            size: None,
            kind: Some(REMOVAL_KIND_STAGING),
            reason: Some("never stages".into()),
        })
        .unwrap();
        let unavailable = serde_json::to_value(Record {
            status: REMOVAL_STATUS_UNSUPPORTED,
            path: None,
            size: None,
            kind: Some(REMOVAL_KIND_STAGING),
            reason: Some("no API".into()),
        })
        .unwrap();
        assert_ne!(inapplicable["status"], unavailable["status"]);
        assert_eq!(inapplicable["status"], REMOVAL_STATUS_NOT_STAGED);
    }

    #[test]
    fn every_format_completes_a_report_without_error() {
        for args in [
            vec!["--quiet"],
            vec!["--json", "--quiet"],
            vec!["--format", "json-lines", "--quiet"],
        ] {
            let ctx = ctx(&args);
            let mut report = Report::new(&ctx);
            report.removed(&item("a.txt", 1)).unwrap();
            report.failed(&item("b.txt", 1), "nope").unwrap();
            assert!(report.finish().is_ok(), "failed for {args:?}");
        }
    }

    #[test]
    fn the_summary_record_carries_its_status_beside_the_counters() {
        let totals = Totals {
            dry_run: true,
            would_remove: 3,
            bytes: Some(99),
            measured_bytes: 99,
            unmeasured: 0,
            ..Totals::default()
        };
        let value = serde_json::to_value(Summary::of(&totals)).unwrap();
        assert_eq!(value["status"], REMOVAL_STATUS_SUMMARY);
        assert_eq!(value["would_remove"], 3);
        assert_eq!(value["removed"], 0);
        assert_eq!(value["bytes"], 99);
        assert_eq!(value["dry_run"], true);
    }

    #[test]
    fn a_record_omits_what_it_does_not_know() {
        // A `"size": 0` on an unmeasured record is a number a consumer could
        // total, which is worse than an absent field.
        let value = serde_json::to_value(Record {
            status: REMOVAL_STATUS_UNSUPPORTED,
            path: None,
            size: None,
            kind: Some(REMOVAL_KIND_DIRECTORY),
            reason: Some("no API".into()),
        })
        .unwrap();
        assert!(value.get("path").is_none());
        assert!(value.get("size").is_none());
        assert_eq!(value["reason"], "no API");
    }

    #[test]
    fn the_text_line_puts_the_path_last_and_in_a_stable_column() {
        // `dctl delete vault:x | awk '{print $NF}'` has to keep working, and the
        // columns have to line up between statuses of different lengths.
        let removed = text_line(
            &record(REMOVAL_STATUS_REMOVED, "a/b.txt", Some(1024)),
            Units::Binary,
        );
        let would = text_line(
            &record(REMOVAL_STATUS_WOULD_REMOVE, "a/b.txt", Some(1024)),
            Units::Binary,
        );
        assert!(removed.ends_with("a/b.txt"), "{removed:?}");
        assert!(removed.contains("1.00 KiB"), "{removed:?}");
        assert_eq!(
            removed.find("1.00 KiB"),
            would.find("1.00 KiB"),
            "columns must not move with the status:\n{removed:?}\n{would:?}"
        );
    }

    #[test]
    fn an_unmeasured_line_prints_a_dash_rather_than_a_zero() {
        let line = text_line(&record(REMOVAL_STATUS_FAILED, "a.txt", None), Units::Binary);
        assert!(line.contains(REMOVAL_SIZE_ABSENT), "{line:?}");
        assert!(!line.contains(" 0 B"), "{line:?}");
    }

    #[test]
    fn sizes_follow_the_run_s_chosen_units() {
        let binary = text_line(
            &record(REMOVAL_STATUS_REMOVED, "a", Some(1000)),
            Units::Binary,
        );
        let decimal = text_line(
            &record(REMOVAL_STATUS_REMOVED, "a", Some(1000)),
            Units::Decimal,
        );
        assert_ne!(binary, decimal, "units must reach the report");
    }

    #[test]
    fn a_plan_opens_the_document_in_every_format() {
        let target = super::super::Target::parse("vault:photos").unwrap();
        let options = super::super::NoOptions {};
        let plan = Plan::new("delete", &target, true, None, &options);
        assert_eq!(
            serde_json::to_value(&plan).unwrap()["status"],
            REMOVAL_STATUS_PLANNED
        );

        for args in [vec!["--quiet"], vec!["--json", "--quiet"]] {
            let ctx = ctx(&args);
            let mut report = Report::new(&ctx);
            assert!(report.plan(&plan).is_ok(), "{args:?}");
            assert!(report.finish().is_ok(), "{args:?}");
        }
    }
}
