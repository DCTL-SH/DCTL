//! `dctl audit head` — print the anchor to keep somewhere else.
//!
//! The chain proves that nothing inside the log was altered. It cannot prove
//! that nothing was removed from the **end**, because nothing inside a log
//! attests to how many records it should have — and the records an attacker
//! most wants gone are the most recent ones. The only defence is a value
//! recorded where the writer cannot reach it, and this is the command that
//! produces it. `docs/AUDIT_LOG.md` §10 is the procedure for keeping it;
//! `dctl audit verify --expect-head` is what checks it.
//!
//! ## What it prints, and why it is not only a hash
//!
//! One token: `<records>:<head>` — the anchor of [`crate::audit::anchor`]. One
//! shell word, one line, copy-pasteable into a ticket and `diff`-able by a
//! script, exactly as a bare hash would be.
//!
//! The record count is there because a bare hash cannot answer the question an
//! investigator asks next. A hash carries no length, so when a log stops ending
//! at it there is nothing to subtract: "the head does not match" is the whole
//! finding. With the count, the same comparison says *"seventeen records have
//! been removed from the end"*. That sentence is the reason the command exists,
//! so the value it hands out is the one that can produce it.
//!
//! A bare hash is still accepted by `--expect-head`, and still gives the honest
//! weaker answer, because an operator who pasted the `head` field out of
//! `dctl audit verify --json` has an anchor rather than a mistake.
//!
//! ## A broken chain yields no anchor
//!
//! [`verify`], [`super::list`] and [`super::export`] all produce their output and
//! *then* exit 24, because an investigator needs the rows even from a forged
//! log. This command does the opposite and prints nothing, because its output is
//! not evidence to read — it is a value whose only use is to be trusted later.
//! Emitting one from a chain that does not verify would invite an operator to
//! anchor a forgery, and an anchor taken from a broken chain attests to the
//! break.

use std::path::PathBuf;

use clap::Args;
use serde::Serialize;

use crate::audit::anchor::Anchor;
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::Format;

use super::chain;
use super::source;
use super::verify::break_error;

/// Arguments for `dctl audit head`.
#[derive(Args, Debug)]
pub struct HeadArgs {
    /// Chain to read. Defaults to the log beside the configured index.
    #[arg(long, value_name = "PATH")]
    pub audit_log: Option<PathBuf>,
}

/// The anchor, in the shape a machine consumer reads.
///
/// Carries the head and the count separately as well as joined, so a pipeline
/// that already stores one of them does not have to split a string, and one that
/// stores the anchor does not have to join two.
#[derive(Debug, Serialize)]
struct Report<'a> {
    /// The file that was walked.
    log: String,
    /// How many records it holds.
    records: usize,
    /// The last record's hash, or the genesis link for a chain with none.
    head: &'a str,
    /// Both of the above as the one token `--expect-head` takes.
    anchor: &'a Anchor,
}

pub async fn run(ctx: &Ctx, args: &HeadArgs) -> Result<()> {
    let log = source::load(&ctx.globals, args.audit_log.as_deref())?;

    // Walked before anything is printed. An anchor is a promise about a chain,
    // and a chain that does not verify has nothing to promise.
    let verified = chain::verify(&log.records).map_err(|broken| break_error(&log, &broken))?;

    let anchor = Anchor::of(verified.records, &verified.head);

    match ctx.out.format() {
        Format::Text => ctx.out.line(anchor.to_string())?,
        Format::Json | Format::JsonLines => ctx.out.json(&Report {
            log: log.path.display().to_string(),
            records: verified.records,
            head: anchor.head(),
            anchor: &anchor,
        })?,
    }

    ctx.out.info(format!(
        "{} records; keep this anchor where this machine cannot rewrite it, and \
         check it with `dctl audit verify --expect-head {anchor}`",
        verified.records
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::audit::anchor;
    use crate::audit::record::AuditRecord;
    use crate::cli::globals::GlobalArgs;
    use crate::constants::{AUDIT_ANCHOR_SEPARATOR, AUDIT_CHAIN_GENESIS_PREV, AUDIT_LOG_FILE_NAME};
    use crate::exit::ExitCode;
    use clap::Parser;
    use std::path::Path;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn globals(args: &[&str]) -> GlobalArgs {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals
    }

    fn ctx(args: &[&str]) -> Ctx {
        Ctx::new(globals(args))
    }

    /// Write a real chain of `count` records to a real file, the way the writer
    /// would — so the tests below read a log rather than a fixture in memory.
    fn write_chain(dir: &Path, count: u64) -> (PathBuf, Vec<AuditRecord>) {
        let path = dir.join(AUDIT_LOG_FILE_NAME);
        let mut records = Vec::new();
        let mut previous = AUDIT_CHAIN_GENESIS_PREV.to_string();
        let mut body = String::new();

        for index in 0..count {
            let mut record = AuditRecord {
                index,
                time: format!("2026-07-26T00:00:{index:02}Z"),
                op: "copy".into(),
                result: "success".into(),
                path: format!("photos/{index}.jpg"),
                prev: previous.clone(),
                ..AuditRecord::default()
            };
            record.hash = chain::compute_hash(&record);
            previous.clone_from(&record.hash);
            body.push_str(&serde_json::to_string(&record).unwrap());
            body.push('\n');
            records.push(record);
        }

        std::fs::write(&path, body).unwrap();
        (path, records)
    }

    #[tokio::test]
    async fn the_anchor_names_the_head_and_the_count() {
        let dir = tempfile::tempdir().unwrap();
        let (path, records) = write_chain(dir.path(), 4);

        let log = source::load(&globals(&[]), Some(&path)).unwrap();
        let verified = chain::verify(&log.records).unwrap();
        let anchor = Anchor::of(verified.records, &verified.head);

        assert_eq!(anchor.head(), records[3].hash);
        assert_eq!(
            anchor.to_string(),
            format!("4{AUDIT_ANCHOR_SEPARATOR}{}", records[3].hash)
        );

        // And the command itself runs clean over the same file.
        run(
            &ctx(&[]),
            &HeadArgs {
                audit_log: Some(path),
            },
        )
        .await
        .expect("an intact chain yields an anchor");
    }

    #[tokio::test]
    async fn the_anchor_it_prints_is_the_anchor_verify_accepts() {
        // The round trip that makes the pair usable: whatever `head` hands an
        // operator has to satisfy `--expect-head` on the same log, or the
        // procedure documented in AUDIT_LOG.md §10 does not work.
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = write_chain(dir.path(), 6);

        let log = source::load(&globals(&[]), Some(&path)).unwrap();
        let verified = chain::verify(&log.records).unwrap();
        let printed = Anchor::of(verified.records, &verified.head).to_string();

        let parsed = Anchor::parse(&printed).expect("the printed form parses back");
        anchor::compare(&parsed, &verified, &log.records)
            .expect("and matches the log it came from");
    }

    #[tokio::test]
    async fn an_empty_chain_anchors_at_genesis_rather_than_failing() {
        // "Nothing has been appended" is a real state, and a fresh vault needs an
        // anchor before its first record — otherwise the very first operation is
        // the one no anchor covers.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG_FILE_NAME);
        std::fs::write(&path, "").unwrap();

        let log = source::load(&globals(&[]), Some(&path)).unwrap();
        let verified = chain::verify(&log.records).unwrap();
        assert_eq!(
            Anchor::of(verified.records, &verified.head).to_string(),
            format!("0{AUDIT_ANCHOR_SEPARATOR}{AUDIT_CHAIN_GENESIS_PREV}")
        );

        run(
            &ctx(&[]),
            &HeadArgs {
                audit_log: Some(path),
            },
        )
        .await
        .expect("an empty chain has a head");
    }

    #[tokio::test]
    async fn a_broken_chain_yields_no_anchor_at_all() {
        // The refusal that keeps an operator from anchoring a forgery. Unlike
        // `list` and `export`, there is nothing here an investigator needs to
        // read — only a value whose whole purpose is to be trusted later.
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = write_chain(dir.path(), 4);
        let forged = std::fs::read_to_string(&path)
            .unwrap()
            .replace("photos/2.jpg", "photos/x.jpg");
        std::fs::write(&path, forged).unwrap();

        let error = run(
            &ctx(&[]),
            &HeadArgs {
                audit_log: Some(path),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::AuditChainBroken);
        assert!(error.message().contains("record 2"), "{}", error.message());
    }

    #[tokio::test]
    async fn a_missing_log_is_not_answered_with_a_genesis_anchor() {
        // Handing back `0:000…` for a file nobody found would anchor a chain
        // that was never looked at.
        let dir = tempfile::tempdir().unwrap();
        let error = run(
            &ctx(&[]),
            &HeadArgs {
                audit_log: Some(dir.path().join("nothing.jsonl")),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::FileNotFound);
    }

    #[test]
    fn the_json_report_carries_the_parts_and_the_whole() {
        let anchor = Anchor::of(4, &"ab".repeat(32));
        let json = serde_json::to_string(&Report {
            log: "/tmp/audit.jsonl".into(),
            records: 4,
            head: anchor.head(),
            anchor: &anchor,
        })
        .unwrap();

        assert!(json.contains("\"records\":4"), "{json}");
        assert!(
            json.contains(&format!("\"head\":\"{}\"", "ab".repeat(32))),
            "{json}"
        );
        assert!(
            json.contains(&format!("\"anchor\":\"4:{}\"", "ab".repeat(32))),
            "{json}"
        );
    }
}
