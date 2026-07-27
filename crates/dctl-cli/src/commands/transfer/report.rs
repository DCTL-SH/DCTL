//! Printing a plan.
//!
//! A plan is **data**, so it goes to stdout in whichever `--format` was asked
//! for — `dctl sync a b --dry-run --json | jq '.actions[] | select(.action ==
//! "delete")'` has to work, and so does piping the text form through `grep`.
//! Progress, warnings and the end-of-run summary stay on stderr, where they
//! cannot corrupt that stream (see [`crate::output`]).
//!
//! Every format shows the same rows. Only entries that *do* something are
//! listed: a plan is a list of actions, and ten million "unchanged" lines would
//! bury the three deletions the reader is actually there to check. The skipped
//! count is reported in the summary instead, so nothing is hidden — only
//! summarised.
//!
//! ## A real run emits a document too
//!
//! The paragraph above used to be true only of `--dry-run`. [`render`] was
//! called inside `if ctx.is_dry_run()` and nowhere else, so a real transfer
//! rendered nothing in any format — and because the end-of-run statistics block
//! is suppressed in the JSON formats, `dctl --json copy src dst` produced
//! **zero bytes on both streams** while `dctl --dry-run --json copy src dst`
//! produced a full document. With a per-file failure the JSON channel was still
//! empty while the process exited 6.
//!
//! [`outcome`] closes that. It emits the same plan plus a `result` object built
//! from the executor's own counters, so a consumer can tell what was attempted
//! from what was achieved. Text is unchanged: it already has per-file lines and
//! a statistics block on the two streams they belong on.

use serde::Serialize;

use crate::constants::{PLAN_COLUMN_ACTION, PLAN_COLUMN_PATH, PLAN_COLUMN_SIZE};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::{Align, Border, Column, Format, Table, size};

use crate::remote::RemoteSpec;

use super::plan::{Plan, Summary};

/// The whole-document JSON shape.
///
/// Both endpoints are included because a plan read out of a log or a CI artefact
/// has to be self-describing: "delete photos/2024/a.jpg" means nothing without
/// knowing which destination it was going to be deleted from.
#[derive(Debug, Serialize)]
struct Document<'a> {
    /// The command this plan belongs to, e.g. `sync`.
    command: &'a str,
    /// The root every action's `source` is relative to.
    source: String,
    /// The root every action's `dest` is relative to.
    ///
    /// Joining this to an action's `dest` yields the object's full spec — which
    /// is why it is a *root* and not always the `DEST` the user typed: for
    /// `copyto`/`moveto` the user typed the object's name, and repeating it in
    /// both halves would name a path one level too deep.
    destination: String,
    /// Whether this plan was printed instead of executed.
    dry_run: bool,
    /// Aggregate counts.
    summary: Summary,
    /// One record per action **the run set out to perform**.
    ///
    /// On a dry run that is the whole document. On a real run it is still the
    /// plan — an entry here is not a claim that that entry succeeded — and
    /// [`Document::result`] is what says how the run ended.
    actions: Vec<ActionRecord<'a>>,
    /// What the run actually achieved. Absent on a dry run, which achieved
    /// nothing by design.
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<RunResult>,
}

/// The measured outcome of a real run.
///
/// Every field is a **counter the executor incremented**, never a figure derived
/// from the plan: `files` counts files whose durable commit returned, and
/// `errors` counts the ones that failed. A consumer that wants to know whether a
/// run was clean reads `errors` and `checksum_mismatches`, not the length of
/// `actions`.
#[derive(Debug, Serialize)]
struct RunResult {
    /// Files whose durable commit returned. Never the plan's count.
    files: u64,
    /// Bytes the upload stage measured going past.
    bytes: u64,
    /// Files removed at the destination (`sync`) or the source (`move`).
    deleted: u64,
    /// Files proven identical and therefore not transferred.
    skipped: u64,
    /// Per-file failures. **Non-zero means the run did not do everything the
    /// `actions` list describes.**
    errors: u64,
    /// Failures where the destination stored something other than what was
    /// sent. Counted apart from `errors` because exit code 20 exists so a script
    /// can tell that apart from a timeout.
    checksum_mismatches: u64,
}

/// One action, as a machine reads it.
#[derive(Debug, Serialize)]
struct ActionRecord<'a> {
    /// Stable action slug: `copy`, `update`, `delete`, `mkdir`.
    action: &'a str,
    /// Path at the source; empty for a delete.
    source: &'a str,
    /// Path at the destination.
    dest: &'a str,
    /// Bytes moved, or freed by a delete; `null` when the side reported no size.
    size: Option<u64>,
    /// Stable slug explaining the decision.
    reason: &'a str,
}

impl<'a> ActionRecord<'a> {
    fn of(entry: &'a super::plan::PlanEntry) -> Self {
        Self {
            action: entry.action.slug(),
            source: entry.source.as_str(),
            dest: entry.dest.as_str(),
            size: entry.size,
            reason: entry.reason,
        }
    }
}

/// Print `plan` on stdout in the active format.
///
/// # Errors
/// Propagates stdout write failures other than a broken pipe, which the sink
/// deliberately tolerates so `dctl sync --dry-run | head` is a success.
pub fn render(
    ctx: &Ctx,
    command: &str,
    plan: &Plan,
    source: &RemoteSpec,
    dest: &RemoteSpec,
) -> Result<()> {
    render_with(ctx, command, plan, source, dest, None)
}

/// Print what a **real** run did, on stdout, in the active format.
///
/// ## The hole this closes
///
/// `render` was called only inside `if ctx.is_dry_run()`. A real run therefore
/// rendered no document in any format — and under `--json` the stderr statistics
/// block is suppressed too, so the whole output was nothing at all:
///
/// ```text
/// $ dctl --json copy src dst | wc -c
/// 0
/// $ dctl --dry-run --json copy src dst | wc -c
/// 427
/// ```
///
/// With a real per-file failure the JSON channel was *still* empty while the
/// process exited 6. A CI job running `dctl --json sync /srv/data backup: >
/// run.json` and then reading `run.json` to record what moved got an empty file
/// on every run, including the ones where files failed.
///
/// Text is deliberately unchanged: its per-file lines and its end-of-run
/// statistics block are already on the two streams they belong on, and printing
/// the plan table again after the work would be noise. The JSON formats have no
/// such block, which is exactly why they had nothing.
///
/// # Errors
/// As [`render`].
pub fn outcome(
    ctx: &Ctx,
    command: &str,
    plan: &Plan,
    source: &RemoteSpec,
    dest: &RemoteSpec,
) -> Result<()> {
    if ctx.out.format() == Format::Text {
        return Ok(());
    }
    let stats = ctx.stats.snapshot();
    render_with(
        ctx,
        command,
        plan,
        source,
        dest,
        Some(RunResult {
            files: stats.files_done,
            bytes: stats.bytes_transferred,
            deleted: stats.files_deleted,
            skipped: stats.files_skipped,
            errors: stats.errors,
            checksum_mismatches: stats.checksum_mismatches,
        }),
    )
}

fn render_with(
    ctx: &Ctx,
    command: &str,
    plan: &Plan,
    source: &RemoteSpec,
    dest: &RemoteSpec,
    result: Option<RunResult>,
) -> Result<()> {
    match ctx.out.format() {
        Format::Text => render_text(ctx, plan),
        Format::Json => render_json(ctx, command, plan, source, dest, result),
        Format::JsonLines => render_json_lines(ctx, plan, result),
    }
}

/// The human view: an aligned table of actions, and nothing else on stdout.
fn render_text(ctx: &Ctx, plan: &Plan) -> Result<()> {
    let mut table = Table::new(vec![
        Column::new(PLAN_COLUMN_ACTION, Align::Left),
        Column::new(PLAN_COLUMN_SIZE, Align::Right).with_style(ctx.out.palette().number()),
        Column::new(PLAN_COLUMN_PATH, Align::Left).with_style(ctx.out.palette().path()),
    ])
    .with_border(Border::Header);

    for entry in plan.actions() {
        table.push(vec![
            entry.action.slug().to_string(),
            size::bytes_or_unknown(entry.size, ctx.out.units()),
            entry.display_path(),
        ]);
    }

    if !table.is_empty() {
        ctx.out.table(&table)?;
    }
    Ok(())
}

/// One JSON document for the whole plan.
fn render_json(
    ctx: &Ctx,
    command: &str,
    plan: &Plan,
    source: &RemoteSpec,
    dest: &RemoteSpec,
    result: Option<RunResult>,
) -> Result<()> {
    let document = Document {
        command,
        source: source.to_string(),
        destination: dest.to_string(),
        dry_run: ctx.is_dry_run(),
        summary: plan.summary(),
        actions: plan.actions().map(ActionRecord::of).collect(),
        result,
    };
    ctx.out.json(&document)?;
    Ok(())
}

/// One JSON object per line.
///
/// No wrapping document: the newline is the record separator, so a consumer can
/// read, parse and drop one action at a time and stay flat in memory on a plan
/// far larger than RAM.
fn render_json_lines(ctx: &Ctx, plan: &Plan, result: Option<RunResult>) -> Result<()> {
    for entry in plan.actions() {
        ctx.out.json(&ActionRecord::of(entry))?;
    }
    // Last, and only on a real run: a consumer streaming this format reads
    // records until the stream ends, so the summary has to be the final one or
    // it would arrive before the records it summarises.
    if let Some(result) = result {
        ctx.out.json(&result)?;
    }
    Ok(())
}

/// Announce a plan's shape on stderr, before it is executed or printed.
///
/// Stderr, not stdout: this is commentary, and mixing it into the data stream
/// would break `--dry-run | jq`. Shown at `-v` and above, plus one unconditional
/// warning when a `sync` is about to remove a large share of its destination —
/// that one is not commentary, it is the last chance to notice a typo.
pub fn announce(ctx: &Ctx, plan: &Plan, dest_file_count: usize) {
    let summary = plan.summary();
    ctx.out.info(format!(
        "{} to copy, {} to update, {} to delete, {} unchanged ({})",
        summary.copy,
        summary.update,
        summary.delete,
        summary.skip,
        size::bytes_or_unknown(summary.bytes, ctx.out.units()),
    ));

    if is_mass_deletion(summary.delete, dest_file_count) {
        ctx.out.warn(format!(
            "this would delete {} of the {} files at the destination",
            summary.delete, dest_file_count,
        ));
    }
}

/// Whether a deletion count is large enough to warrant an unconditional warning.
///
/// A sync that removes most of what it found is usually a mistyped source or a
/// listing that failed open. It is never blocked — emptying a tree is a real
/// thing to want — but it is never silent either.
fn is_mass_deletion(deletions: usize, dest_file_count: usize) -> bool {
    if deletions == 0 || dest_file_count == 0 {
        return false;
    }
    let fraction = deletions as f64 / dest_file_count as f64;
    fraction >= crate::constants::SYNC_DELETE_ALARM_FRACTION
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::transfer::compare::ComparePolicy;
    use crate::commands::transfer::entry::Entry;
    use crate::commands::transfer::plan::Policy;
    use crate::commands::transfer::testing::ctx;

    fn sample_plan() -> Plan {
        let source = [Entry::file("new.txt", 10), Entry::file("same.txt", 5)];
        let dest = [Entry::file("same.txt", 5), Entry::file("extra.txt", 7)];
        Plan::compute(
            &source,
            &dest,
            &Policy::syncing(ComparePolicy {
                size_only: true,
                ..ComparePolicy::default()
            }),
        )
        .unwrap()
    }

    fn endpoints() -> (RemoteSpec, RemoteSpec) {
        (
            RemoteSpec::parse("/srv/src").unwrap(),
            RemoteSpec::parse("vault:dst").unwrap(),
        )
    }

    #[test]
    fn every_format_renders_without_error() {
        // Rule: every command that produces structured results supports all
        // three formats. A format that panicked or bailed would make the command
        // unusable from a script.
        let plan = sample_plan();
        let (source, dest) = endpoints();
        for flags in [vec![], vec!["--json"], vec!["--format", "json-lines"]] {
            let ctx = ctx(&flags);
            assert!(
                render(&ctx, "sync", &plan, &source, &dest).is_ok(),
                "{flags:?}"
            );
        }
    }

    #[test]
    fn only_actions_are_rendered() {
        // Skips stay in the plan for accounting but never reach the report.
        let plan = sample_plan();
        assert_eq!(plan.summary().skip, 1);
        assert_eq!(plan.actions().count(), 2, "one copy, one delete");
    }

    #[test]
    fn the_json_document_names_both_sides() {
        // A plan pulled out of a CI log has to say what it would have deleted
        // *from*, or it cannot be reviewed after the fact.
        let plan = sample_plan();
        let (source, dest) = endpoints();
        let document = Document {
            command: "sync",
            source: source.to_string(),
            destination: dest.to_string(),
            dry_run: true,
            summary: plan.summary(),
            actions: plan.actions().map(ActionRecord::of).collect(),
            result: None,
        };
        let json = serde_json::to_string(&document).unwrap();
        assert!(json.contains("/srv/src"), "{json}");
        assert!(json.contains("vault:dst"), "{json}");
        assert!(json.contains("\"delete\""), "{json}");
        assert!(json.contains("\"dry_run\":true"), "{json}");
        // A rehearsal achieved nothing, so it claims nothing: the key is absent
        // rather than present with zeros, which a consumer could read as "the
        // run moved no files" instead of "no run happened".
        assert!(!json.contains("result"), "{json}");
    }

    #[test]
    fn a_real_run_carries_measured_counters_beside_the_plan() {
        // The hole this closes: `--json` on a real transfer emitted **zero
        // bytes**, because the plan was rendered only under `--dry-run` and the
        // stderr statistics block is suppressed in the JSON formats. A CI job
        // reading the file it redirected got nothing, on every run, including
        // the ones where files failed.
        let plan = sample_plan();
        let (source, dest) = endpoints();
        let document = Document {
            command: "sync",
            source: source.to_string(),
            destination: dest.to_string(),
            dry_run: false,
            summary: plan.summary(),
            actions: plan.actions().map(ActionRecord::of).collect(),
            result: Some(RunResult {
                files: 2,
                bytes: 4096,
                deleted: 1,
                skipped: 7,
                errors: 1,
                checksum_mismatches: 0,
            }),
        };
        let json = serde_json::to_string(&document).unwrap();
        assert!(json.contains("\"dry_run\":false"), "{json}");
        assert!(json.contains("\"files\":2"), "{json}");
        assert!(json.contains("\"bytes\":4096"), "{json}");
        // The field that stops `actions` being read as a list of successes.
        assert!(json.contains("\"errors\":1"), "{json}");
    }

    #[test]
    fn json_lines_records_never_span_a_line() {
        let plan = sample_plan();
        for entry in plan.actions() {
            let encoded = Format::JsonLines.encode(&ActionRecord::of(entry)).unwrap();
            assert!(!encoded.contains('\n'), "{encoded}");
        }
    }

    #[test]
    fn a_mass_deletion_is_flagged() {
        assert!(is_mass_deletion(5, 10), "half is the alarm threshold");
        assert!(is_mass_deletion(10, 10), "emptying a tree is the loud case");
        assert!(!is_mass_deletion(1, 10));
        // No destination and no deletions must never divide by zero.
        assert!(!is_mass_deletion(0, 0));
        assert!(!is_mass_deletion(3, 0));
    }

    #[test]
    fn an_empty_plan_prints_nothing_at_all() {
        // Not "0 actions", not an empty table header — nothing, so a pipeline
        // consuming the output sees an empty stream rather than a phantom row.
        let plan = Plan::default();
        let (source, dest) = endpoints();
        let ctx = ctx(&[]);
        assert!(plan.is_noop());
        assert!(render(&ctx, "copy", &plan, &source, &dest).is_ok());
    }
}
