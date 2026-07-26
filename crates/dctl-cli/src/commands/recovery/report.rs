//! Rendering a recovery's result in each of the three output formats.
//!
//! One document, three encodings, and the stdout/stderr split from
//! [`crate::output`] obeyed throughout: the pre-flight findings and the planned
//! entries are **data** and go to stdout, while counts, notices and warnings are
//! commentary and go to stderr. That is what makes
//! `dctl restore vault: /out --dry-run --json | jq '.preflight[]'` work while a
//! progress display is still animating on the terminal.
//!
//! The three encodings answer three different questions:
//!
//! * [`Format::Text`] — a person reading two tables.
//! * [`Format::Json`] — one document describing the whole run, for a consumer
//!   that wants the totals and the findings together.
//! * [`Format::JsonLines`] — one self-describing record per line, so a plan over
//!   ten million files streams instead of being buffered. Every line carries a
//!   `record` discriminator, because a stream whose shapes are ambiguous is a
//!   stream nobody can parse a line at a time.
//!
//! `entries` is [`Option`] rather than a possibly-empty list on purpose. An
//! empty array means "computed, and there is nothing to do"; an absent field
//! means "not computed", which is what a run that stopped at the pre-flight has
//! to say. Collapsing the two would let a consumer read "nothing to restore"
//! from a run that never got as far as looking.

use serde::Serialize;

use crate::constants::{
    PLAN_COLUMN_ACTION, PLAN_COLUMN_PATH, PLAN_COLUMN_SIZE, PLAN_PATH_ARROW, PREFLIGHT_COLUMN_PATH,
    PREFLIGHT_COLUMN_PROBLEM, PREFLIGHT_COLUMN_SEVERITY,
};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::{Align, Border, Column, Format, Table, size};

use super::plan::Entry;
use super::preflight::Finding;
use super::snapshot::SnapshotName;

/// Discriminator on a JSON Lines record.
///
/// A stream that mixes shapes without saying which is which cannot be consumed
/// one line at a time, which is the only reason JSON Lines exists.
const RECORD_PREFLIGHT: &str = "preflight";
/// See [`RECORD_PREFLIGHT`].
const RECORD_ENTRY: &str = "entry";
/// See [`RECORD_PREFLIGHT`].
const RECORD_SUMMARY: &str = "summary";

/// Everything one recovery has to say about what it would do.
#[derive(Debug, Serialize)]
pub struct Document<'a> {
    /// The command that produced this: `backup` or `restore`.
    pub operation: &'a str,
    /// The source operand, exactly as the user wrote it.
    pub source: &'a str,
    /// The destination operand, exactly as the user wrote it.
    pub destination: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<&'a SnapshotName>,
    /// The resolved `--at` instant, in Unix seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<i64>,
    /// Whether this run was forbidden from changing anything.
    pub dry_run: bool,
    /// Files the plan covers, and their total size.
    pub files: usize,
    /// See [`Document::files`].
    pub bytes: u64,
    /// Every pre-flight finding, always present — an empty array is the honest
    /// way to say "we looked and found nothing".
    pub preflight: &'a [Finding],
    /// The planned entries, or `None` when the run stopped before planning.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<&'a [Entry]>,
}

/// A JSON Lines pre-flight record.
#[derive(Serialize)]
struct PreflightLine<'a> {
    record: &'static str,
    #[serde(flatten)]
    finding: &'a Finding,
}

/// A JSON Lines plan record.
#[derive(Serialize)]
struct EntryLine<'a> {
    record: &'static str,
    #[serde(flatten)]
    entry: &'a Entry,
}

/// A JSON Lines closing record, so a consumer knows the stream ended rather
/// than being truncated.
#[derive(Serialize)]
struct SummaryLine<'a> {
    record: &'static str,
    operation: &'a str,
    dry_run: bool,
    files: usize,
    bytes: u64,
    preflight: usize,
    blocking: usize,
}

/// Write the document to stdout in whichever format was requested.
///
/// # Errors
/// Propagates any stdout failure other than a broken pipe, which
/// [`crate::output::Out`] absorbs so `| head` stays a success.
pub fn emit(ctx: &Ctx, document: &Document<'_>) -> Result<()> {
    match ctx.out.format() {
        Format::Json => ctx.out.json(document)?,
        Format::JsonLines => emit_lines(ctx, document)?,
        Format::Text => emit_text(ctx, document)?,
    }
    Ok(())
}

/// One self-describing JSON object per line.
fn emit_lines(ctx: &Ctx, document: &Document<'_>) -> Result<()> {
    for finding in document.preflight {
        ctx.out.json(&PreflightLine {
            record: RECORD_PREFLIGHT,
            finding,
        })?;
    }

    for entry in document.entries.unwrap_or(&[]) {
        ctx.out.json(&EntryLine {
            record: RECORD_ENTRY,
            entry,
        })?;
    }

    ctx.out.json(&SummaryLine {
        record: RECORD_SUMMARY,
        operation: document.operation,
        dry_run: document.dry_run,
        files: document.files,
        bytes: document.bytes,
        preflight: document.preflight.len(),
        blocking: document
            .preflight
            .iter()
            .filter(|finding| finding.is_blocking())
            .count(),
    })?;

    Ok(())
}

/// Two aligned tables, or nothing at all when there is nothing to say.
fn emit_text(ctx: &Ctx, document: &Document<'_>) -> Result<()> {
    if !document.preflight.is_empty() {
        let mut table = Table::new(vec![
            Column::new(PREFLIGHT_COLUMN_SEVERITY, Align::Left),
            Column::new(PREFLIGHT_COLUMN_PATH, Align::Left).with_style(ctx.out.palette().path()),
            // The slug lives in the JSON; a person reading a terminal wants the
            // sentence that says what is actually wrong with the name.
            Column::new(PREFLIGHT_COLUMN_PROBLEM, Align::Left),
        ])
        .with_border(Border::Header);

        for finding in document.preflight {
            table.push(vec![
                finding.severity.to_string(),
                finding.path.clone(),
                finding.detail.clone(),
            ]);
        }
        ctx.out.table(&table)?;
    }

    let Some(entries) = document.entries else {
        return Ok(());
    };
    if entries.is_empty() {
        return Ok(());
    }

    // Headed, like the pre-flight table above it: the rule row is what keeps
    // two adjacent tables from reading as one, and both are a report rather
    // than a listing something is piped into.
    let mut table = Table::new(vec![
        Column::new(PLAN_COLUMN_ACTION, Align::Left),
        Column::new(PLAN_COLUMN_SIZE, Align::Right).with_style(ctx.out.palette().number()),
        Column::new(PLAN_COLUMN_PATH, Align::Left).with_style(ctx.out.palette().path()),
    ])
    .with_border(Border::Header);

    for entry in entries {
        table.push(vec![
            entry.action.to_string(),
            size::bytes(entry.size, ctx.out.units()),
            format!("{}{PLAN_PATH_ARROW}{}", entry.source, entry.destination),
        ]);
    }
    ctx.out.table(&table)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::cli::globals::GlobalArgs;
    use crate::constants::{
        PLAN_ACTION_RESTORE, PREFLIGHT_PROBLEM_ILLEGAL_NAME, PREFLIGHT_SEVERITY_BLOCKING,
    };
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        Ctx::new(Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals)
    }

    fn finding() -> Finding {
        Finding {
            path: "a:b.txt".into(),
            problem: PREFLIGHT_PROBLEM_ILLEGAL_NAME,
            severity: PREFLIGHT_SEVERITY_BLOCKING,
            detail: "'a:b.txt' contains ':'".into(),
        }
    }

    fn entries() -> Vec<Entry> {
        vec![Entry::new(
            PLAN_ACTION_RESTORE,
            "vault:a.txt",
            "/out/a.txt",
            7,
        )]
    }

    fn document<'a>(findings: &'a [Finding], entries: Option<&'a [Entry]>) -> Document<'a> {
        Document {
            operation: "restore",
            source: "vault:",
            destination: "/out",
            snapshot: None,
            at: None,
            dry_run: true,
            files: entries.map_or(0, <[Entry]>::len),
            bytes: 7,
            preflight: findings,
            entries,
        }
    }

    #[test]
    fn every_format_renders_without_error() {
        let findings = vec![finding()];
        let planned = entries();
        for args in [vec![], vec!["--json"], vec!["--format", "json-lines"]] {
            let ctx = ctx(&args);
            let document = document(&findings, Some(&planned));
            assert!(emit(&ctx, &document).is_ok(), "{args:?}");
        }
    }

    #[test]
    fn an_uncomputed_plan_is_absent_rather_than_empty() {
        // A consumer must be able to tell "we did not look" from "nothing to do".
        let findings = vec![finding()];
        let stopped = document(&findings, None);
        let json = serde_json::to_string(&stopped).unwrap();
        assert!(!json.contains("\"entries\""), "{json}");

        let planned = Vec::new();
        let looked = document(&findings, Some(&planned));
        let json = serde_json::to_string(&looked).unwrap();
        assert!(json.contains("\"entries\":[]"), "{json}");
    }

    #[test]
    fn the_preflight_array_is_always_present() {
        // An absent findings list would read as "not checked", and a restore
        // that did not check is exactly what §13.6 forbids.
        let clean = document(&[], Some(&[]));
        let json = serde_json::to_string(&clean).unwrap();
        assert!(json.contains("\"preflight\":[]"), "{json}");
    }

    #[test]
    fn json_lines_records_carry_a_discriminator_and_stay_on_one_line() {
        let finding = finding();
        let line = serde_json::to_string(&PreflightLine {
            record: RECORD_PREFLIGHT,
            finding: &finding,
        })
        .unwrap();
        assert!(line.starts_with("{\"record\":\"preflight\""), "{line}");
        assert!(!line.contains('\n'));
        // The flattened finding is inlined, not nested under a key.
        assert!(line.contains("\"path\":\"a:b.txt\""), "{line}");
    }

    #[test]
    fn the_summary_line_counts_blocking_findings_separately() {
        let line = serde_json::to_string(&SummaryLine {
            record: RECORD_SUMMARY,
            operation: "restore",
            dry_run: true,
            files: 1,
            bytes: 7,
            preflight: 2,
            blocking: 1,
        })
        .unwrap();
        assert!(line.contains("\"blocking\":1"), "{line}");
    }

    #[test]
    fn a_snapshot_is_named_in_the_document_only_when_there_is_one() {
        let planned = entries();
        let mut document = document(&[], Some(&planned));
        assert!(
            !serde_json::to_string(&document)
                .unwrap()
                .contains("snapshot")
        );

        let snapshot = SnapshotName::parse("nightly").unwrap();
        document.snapshot = Some(&snapshot);
        let json = serde_json::to_string(&document).unwrap();
        assert!(json.contains("\"snapshot\":\"nightly\""), "{json}");
    }
}
