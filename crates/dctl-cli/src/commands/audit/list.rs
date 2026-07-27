//! `dctl audit list` — show what the log says happened.
//!
//! A listing is not a verification, and the two must never be confused. So the
//! chain is walked anyway, and if it is broken the records are still printed —
//! an investigator needs to see them — and the command then **exits 24**. A
//! listing of a forged log that exits 0 is worse than no listing at all, because
//! it puts the forged rows on screen with an implicit clean bill of health.
//!
//! For the same reason the text listing shows only a short hash prefix
//! ([`crate::constants::AUDIT_HASH_DISPLAY_LEN`]): it is there to tell adjacent
//! rows apart, not to let anyone believe a row was checked by looking at it.
//!
//! Filters narrow *which* records are shown and never *whether* the chain is
//! walked. Verifying only the records that survived a `--since` would verify
//! nothing at all — the chain's strength is that it covers everything.

use std::path::PathBuf;

use clap::Args;

use crate::commands::recovery::timespec;
use crate::constants::{
    AUDIT_COLUMN_BYTES, AUDIT_COLUMN_DIRECTION, AUDIT_COLUMN_HASH, AUDIT_COLUMN_INDEX,
    AUDIT_COLUMN_OP, AUDIT_COLUMN_PATH, AUDIT_COLUMN_RESULT, AUDIT_COLUMN_TIME,
    AUDIT_LIST_UNLIMITED,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::output::{Align, Border, Column, Format, Table, size};
use crate::platform::path as logical;

use super::chain;
use super::record::AuditRecord;
use super::source;
use super::verify::break_error;

/// Arguments for `dctl audit list`.
#[derive(Args, Debug)]
pub struct ListArgs {
    /// Chain to read. Defaults to the log beside the configured index.
    #[arg(long, value_name = "PATH")]
    pub audit_log: Option<PathBuf>,

    /// Show only this operation, using `dctl`'s own command names.
    #[arg(long, value_name = "OP")]
    pub op: Option<String>,

    /// Show only records touching this logical path or a path beneath it.
    #[arg(long, value_name = "PATH")]
    pub path: Option<String>,

    /// Show only records that moved bytes this way: in, out or internal.
    ///
    /// `--direction out` is the egress query — everything that left the remote.
    #[arg(long, value_name = "DIRECTION")]
    pub direction: Option<String>,

    /// Show only records at or after this instant.
    #[arg(long, value_name = "TIME")]
    pub since: Option<String>,

    /// Show only records before this instant.
    #[arg(long, value_name = "TIME")]
    pub until: Option<String>,

    /// Show at most this many records, most recent last. 0 shows every record.
    #[arg(long, value_name = "N", default_value_t = AUDIT_LIST_UNLIMITED)]
    pub limit: usize,
}

/// The resolved filter set.
#[derive(Debug)]
struct Window {
    op: Option<String>,
    path: Option<String>,
    direction: Option<String>,
    since: Option<i64>,
    until: Option<i64>,
}

/// The directions `--direction` accepts, spelled as the record spells them.
///
/// Checked rather than passed through, because the failure mode of an unchecked
/// value is the worst one this command has: `--direction outbound` would match no
/// record, print nothing, exit 0, and read as **"nothing ever left the vault"**.
/// A typo must be a usage error, not an all-clear.
const DIRECTIONS: [&str; 3] = [
    crate::constants::AUDIT_DIRECTION_IN,
    crate::constants::AUDIT_DIRECTION_OUT,
    crate::constants::AUDIT_DIRECTION_INTERNAL,
];

impl Window {
    /// Resolve the flags against a single reference instant, so `--since` and
    /// `--until` cannot drift apart by however long the parse took.
    fn resolve(args: &ListArgs) -> Result<Self> {
        let reference = timespec::now();

        // A filter that cannot be canonicalised is refused rather than dropped:
        // silently widening a query is how an investigator ends up reading a
        // different question's answer.
        let path = match args.path.as_deref() {
            None => None,
            Some(raw) => Some(logical::clean_logical(raw).ok_or_else(|| {
                CliError::usage(format!("--path '{raw}' escapes the vault root with '..'"))
                    .with_hint("Audit paths are logical vault paths, relative to the root.")
            })?),
        };

        let direction = match args.direction.as_deref() {
            None => None,
            Some(value) if DIRECTIONS.contains(&value) => Some(value.to_string()),
            Some(value) => {
                return Err(CliError::usage(format!(
                    "--direction '{value}' is not one of {}",
                    DIRECTIONS.join(", ")
                ))
                .with_hint(
                    "An unrecognised direction would match no record and print \
                     nothing, which reads as 'no data ever moved that way'.",
                ));
            }
        };

        Ok(Self {
            op: args.op.clone(),
            path,
            direction,
            since: args
                .since
                .as_deref()
                .map(|value| timespec::parse(value, reference))
                .transpose()?,
            until: args
                .until
                .as_deref()
                .map(|value| timespec::parse(value, reference))
                .transpose()?,
        })
    }

    /// Whether a record falls inside the window.
    ///
    /// A record whose timestamp cannot be parsed is **kept**, not dropped. A
    /// malformed timestamp is a defect in the log, and quietly hiding the record
    /// carrying it is the one behaviour an audit tool must never have.
    fn admits(&self, record: &AuditRecord) -> bool {
        if self.op.as_deref().is_some_and(|op| record.op != op) {
            return false;
        }
        if self
            .path
            .as_deref()
            .is_some_and(|prefix| !logical::is_under(prefix, &record.path))
        {
            return false;
        }
        // Exact, so a v1 record — which has no direction at all — is excluded
        // from every `--direction` query rather than silently counted as one.
        // A log that spans an upgrade must not answer "what left the vault?"
        // with rows that could not have said.
        if self
            .direction
            .as_deref()
            .is_some_and(|wanted| record.direction != wanted)
        {
            return false;
        }
        if self.since.is_none() && self.until.is_none() {
            return true;
        }

        let Ok(at) = timespec::parse(&record.time, 0) else {
            return true;
        };
        // Half-open: inclusive at the start, exclusive at the end, so two
        // adjacent windows partition the log instead of sharing a record.
        self.since.is_none_or(|since| at >= since) && self.until.is_none_or(|until| at < until)
    }
}

pub async fn run(ctx: &Ctx, args: &ListArgs) -> Result<()> {
    let log = source::load(&ctx.globals, args.audit_log.as_deref())?;

    // Walked over the whole log, never over the filtered subset: a chain that
    // covers only what you asked to see covers nothing.
    let outcome = chain::verify(&log.records);

    let window = Window::resolve(args)?;
    let mut shown: Vec<&AuditRecord> = log
        .records
        .iter()
        .filter(|record| window.admits(record))
        .collect();

    // The tail is what an operator wants: the most recent records, still in
    // chronological order so the chain reads forwards.
    if args.limit != AUDIT_LIST_UNLIMITED && shown.len() > args.limit {
        shown.drain(..shown.len() - args.limit);
    }

    emit(ctx, &shown)?;

    if let Err(broken) = outcome {
        // The rows are on screen; the exit code says not to trust them.
        return Err(break_error(&log, &broken));
    }
    ctx.out
        .info(format!("{} of {} records", shown.len(), log.records.len()));
    Ok(())
}

/// Render the selected records in the active format.
fn emit(ctx: &Ctx, records: &[&AuditRecord]) -> Result<()> {
    match ctx.out.format() {
        Format::Json => ctx.out.json(&records)?,
        Format::JsonLines => {
            for record in records {
                ctx.out.json(record)?;
            }
        }
        // `Dir` and `Bytes` sit between the outcome and the path, because "which
        // way did the data go, and how much of it" is what an auditor scans a
        // listing for — and in schema v1 neither question had an answer at all.
        // A v1 record renders `-` and `0`, which is the honest rendering of a
        // record that could not state them.
        Format::Text => {
            let mut table = Table::new(vec![
                Column::new(AUDIT_COLUMN_INDEX, Align::Right)
                    .with_style(ctx.out.palette().number()),
                Column::new(AUDIT_COLUMN_TIME, Align::Left),
                Column::new(AUDIT_COLUMN_OP, Align::Left),
                Column::new(AUDIT_COLUMN_RESULT, Align::Left),
                Column::new(AUDIT_COLUMN_DIRECTION, Align::Left),
                Column::new(AUDIT_COLUMN_BYTES, Align::Right)
                    .with_style(ctx.out.palette().number()),
                Column::new(AUDIT_COLUMN_HASH, Align::Left).with_style(ctx.out.palette().hash()),
                Column::new(AUDIT_COLUMN_PATH, Align::Left).with_style(ctx.out.palette().path()),
            ])
            .with_border(Border::Header);

            for record in records {
                table.push(vec![
                    record.index.to_string(),
                    record.time.clone(),
                    record.op.clone(),
                    record.result.clone(),
                    record.direction_display().to_string(),
                    size::bytes(record.bytes, ctx.out.units()),
                    record.short_hash().to_string(),
                    record.path.clone(),
                ]);
            }
            ctx.out.table(&table)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::cli::globals::GlobalArgs;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,

        #[command(flatten)]
        list: ListArgs,
    }

    fn parse(args: &[&str]) -> Harness {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()))
    }

    fn record(index: u64, op: &str, path: &str, time: &str) -> AuditRecord {
        AuditRecord {
            index,
            time: time.into(),
            op: op.into(),
            result: "success".into(),
            path: path.into(),
            ..AuditRecord::default()
        }
    }

    fn corpus() -> Vec<AuditRecord> {
        vec![
            record(0, "copy", "photos/a.jpg", "2026-07-24T10:00:00Z"),
            record(1, "delete", "photos/b.jpg", "2026-07-25T10:00:00Z"),
            record(2, "copy", "docs/c.txt", "2026-07-26T10:00:00Z"),
        ]
    }

    /// A corpus spanning the schema change: one v1 record with no direction at
    /// all, one v2 ingest, one v2 egress.
    fn mixed_corpus() -> Vec<AuditRecord> {
        let mut legacy = record(0, "copy", "photos/a.jpg", "2026-07-24T10:00:00Z");
        legacy.v = None;

        let mut ingest = record(1, "copy", "photos/b.jpg", "2026-07-25T10:00:00Z");
        ingest.v = Some(crate::constants::AUDIT_RECORD_VERSION);
        ingest.direction = crate::constants::AUDIT_DIRECTION_IN.into();
        ingest.bytes = 40;

        let mut egress = record(2, "copy", "docs/c.txt", "2026-07-26T10:00:00Z");
        egress.v = Some(crate::constants::AUDIT_RECORD_VERSION);
        egress.direction = crate::constants::AUDIT_DIRECTION_OUT.into();
        egress.bytes = 199_680;

        vec![legacy, ingest, egress]
    }

    fn window(args: &[&str]) -> Window {
        Window::resolve(&parse(args).list).unwrap()
    }

    fn kept(args: &[&str]) -> Vec<u64> {
        let window = window(args);
        corpus()
            .iter()
            .filter(|record| window.admits(record))
            .map(|record| record.index)
            .collect()
    }

    #[test]
    fn no_filters_keeps_every_record() {
        assert_eq!(kept(&[]), vec![0, 1, 2]);
    }

    #[test]
    fn the_operation_filter_is_an_exact_match() {
        // A prefix match would make `--op copy` also select a future `copyto`.
        assert_eq!(kept(&["--op", "copy"]), vec![0, 2]);
        assert_eq!(kept(&["--op", "cop"]), Vec::<u64>::new());
    }

    #[test]
    fn the_path_filter_compares_whole_components() {
        assert_eq!(kept(&["--path", "photos"]), vec![0, 1]);
        assert_eq!(kept(&["--path", "photos/a.jpg"]), vec![0]);
        // `photos` must not capture a sibling called `photos-old`.
        assert_eq!(kept(&["--path", "photo"]), Vec::<u64>::new());
    }

    #[test]
    fn the_path_filter_is_canonicalised_like_every_other_path() {
        assert_eq!(kept(&["--path", "./photos/"]), vec![0, 1]);
    }

    #[test]
    fn the_time_window_is_half_open() {
        // Inclusive at the start, exclusive at the end, so two adjacent windows
        // partition the log instead of double-counting the boundary.
        assert_eq!(kept(&["--since", "2026-07-25T10:00:00Z"]), vec![1, 2]);
        assert_eq!(kept(&["--until", "2026-07-25T10:00:00Z"]), vec![0]);
        assert_eq!(
            kept(&[
                "--since",
                "2026-07-25T00:00:00Z",
                "--until",
                "2026-07-26T00:00:00Z"
            ]),
            vec![1]
        );
    }

    #[test]
    fn a_record_with_an_unreadable_timestamp_is_never_hidden() {
        // Hiding the one malformed record is precisely how a forgery would
        // escape a listing.
        let window = window(&["--since", "2026-07-25T00:00:00Z"]);
        let mut broken = record(9, "copy", "x", "not-a-time");
        broken.result = "success".into();
        assert!(window.admits(&broken));
    }

    #[test]
    fn an_unparseable_filter_is_a_usage_error() {
        let error = Window::resolve(&parse(&["--since", "yesterday"]).list).unwrap_err();
        assert_eq!(error.code(), crate::exit::ExitCode::Usage);
    }

    /// Indices of the mixed corpus that survive `args`.
    fn kept_mixed(args: &[&str]) -> Vec<u64> {
        let selected = window(args);
        mixed_corpus()
            .iter()
            .filter(|record| selected.admits(record))
            .map(|record| record.index)
            .collect()
    }

    #[test]
    fn the_direction_filter_answers_the_egress_question() {
        // The query the whole schema change exists to make possible: what left
        // this remote, and how much of it.
        assert_eq!(kept_mixed(&["--direction", "out"]), vec![2]);
        assert_eq!(kept_mixed(&["--direction", "in"]), vec![1]);
    }

    #[test]
    fn a_v1_record_is_never_counted_as_a_direction_it_could_not_state() {
        // A log spanning the upgrade must not answer "what left the vault?"
        // with rows written before the field existed.
        for direction in ["in", "out", "internal"] {
            let window = window(&["--direction", direction]);
            assert!(
                !window.admits(&mixed_corpus()[0]),
                "a v1 record matched --direction {direction}"
            );
        }
    }

    #[test]
    fn an_unknown_direction_is_refused_rather_than_matching_nothing() {
        // The dangerous failure: `--direction outbound` printing nothing and
        // exiting 0 reads as "no data ever left".
        let error = Window::resolve(&parse(&["--direction", "outbound"]).list).unwrap_err();
        assert_eq!(error.code(), crate::exit::ExitCode::Usage);
        assert!(error.message().contains("outbound"), "{}", error.message());
        assert!(error.hint().is_some_and(|hint| hint.contains("no data")));
    }

    #[test]
    fn the_limit_keeps_the_most_recent_records_in_order() {
        let records = corpus();
        let mut shown: Vec<&AuditRecord> = records.iter().collect();
        let limit = 2;
        shown.drain(..shown.len() - limit);
        let indices: Vec<u64> = shown.iter().map(|record| record.index).collect();
        assert_eq!(indices, vec![1, 2], "the tail, still in chain order");
    }

    #[test]
    fn zero_means_no_limit() {
        assert_eq!(parse(&[]).list.limit, AUDIT_LIST_UNLIMITED);
        assert_eq!(AUDIT_LIST_UNLIMITED, 0);
    }

    #[test]
    fn every_format_renders_without_error() {
        let records = corpus();
        let selected: Vec<&AuditRecord> = records.iter().collect();
        for args in [vec![], vec!["--json"], vec!["--format", "json-lines"]] {
            let harness = parse(&args);
            let ctx = Ctx::new(harness.globals);
            assert!(emit(&ctx, &selected).is_ok(), "{args:?}");
        }
    }
}
