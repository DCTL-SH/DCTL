//! `dctl audit verify` — walk the chain and say whether it holds.
//!
//! The verdict is **data**, so it goes to stdout: a cron job's whole test is
//! `[ "$(dctl audit verify)" = intact ]`, and a machine reading `--json` gets a
//! document carrying the head hash or the exact break position. The exit code
//! carries the same answer for anything that branches on `$?`:
//! [`ExitCode::AuditChainBroken`] (24) and nothing else means the log failed.
//!
//! On a break the document is written **before** the error is returned. A
//! consumer that only gets a non-zero exit knows something is wrong; one that
//! also gets the record position knows where to look, and losing that because
//! the command failed would be exactly the wrong trade for a security event.

use std::path::PathBuf;

use clap::Args;
use serde::Serialize;

use crate::constants::{AUDIT_VERDICT_BROKEN, AUDIT_VERDICT_INTACT};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::output::Format;

use super::chain::{self, Break, Verified};
use super::source::{self, Log};

/// Arguments for `dctl audit verify`.
#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Chain to verify. Defaults to the log beside the configured index.
    #[arg(long, value_name = "PATH")]
    pub audit_log: Option<PathBuf>,
}

/// The verdict, in the shape a machine consumer reads.
#[derive(Debug, Serialize)]
struct Verdict<'a> {
    /// [`AUDIT_VERDICT_INTACT`] or [`AUDIT_VERDICT_BROKEN`].
    verdict: &'static str,
    /// The file that was walked.
    log: String,
    /// How many records were read.
    records: usize,
    /// Head hash, present only when the chain held.
    #[serde(skip_serializing_if = "Option::is_none")]
    head: Option<&'a str>,
    /// Where it failed, present only when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    broken_at: Option<&'a Break>,
}

pub async fn run(ctx: &Ctx, args: &VerifyArgs) -> Result<()> {
    let log = source::load(&ctx.globals, args.audit_log.as_deref())?;
    report(ctx, &log, chain::verify(&log.records))
}

/// Emit the verdict, then fail if it was a failure.
fn report(ctx: &Ctx, log: &Log, outcome: std::result::Result<Verified, Break>) -> Result<()> {
    match outcome {
        Ok(verified) => {
            emit(
                ctx,
                &Verdict {
                    verdict: AUDIT_VERDICT_INTACT,
                    log: log.path.display().to_string(),
                    records: verified.records,
                    head: Some(verified.head.as_str()),
                    broken_at: None,
                },
            )?;
            ctx.out.info(format!(
                "{} records verified, head {}",
                verified.records, verified.head
            ));
            Ok(())
        }

        Err(broken) => {
            emit(
                ctx,
                &Verdict {
                    verdict: AUDIT_VERDICT_BROKEN,
                    log: log.path.display().to_string(),
                    records: log.records.len(),
                    head: None,
                    broken_at: Some(&broken),
                },
            )?;
            Err(break_error(log, &broken))
        }
    }
}

/// The one place a chain break becomes an error, so its code and its wording
/// cannot drift between callers.
///
/// Shared with `list` and `export`: whichever subcommand notices a break must
/// exit 24, because a listing of a forged log that exits 0 is worse than no
/// listing at all.
pub fn break_error(log: &Log, broken: &Break) -> CliError {
    CliError::new(
        ExitCode::AuditChainBroken,
        format!("{}: {broken}", log.path.display()),
    )
    .with_hint(
        "The audit log no longer proves what it claims. Do not delete it: keep \
         this copy, compare it against any mirrored or offline copy, and treat \
         every operation recorded after the break as unattested.",
    )
}

/// Write the verdict in whichever format was asked for.
///
/// Text gets the bare word, because that is what a shell test compares; both
/// JSON formats get the whole document, since a machine that asked for structure
/// wants the head hash and the break position too.
fn emit(ctx: &Ctx, verdict: &Verdict<'_>) -> Result<()> {
    match ctx.out.format() {
        Format::Text => ctx.out.line(verdict.verdict)?,
        Format::Json | Format::JsonLines => ctx.out.json(verdict)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::super::record::AuditRecord;
    use super::*;
    use crate::cli::globals::GlobalArgs;
    use crate::constants::AUDIT_CHAIN_GENESIS_PREV;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        Ctx::new(Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals)
    }

    fn sealed_chain(count: u64) -> Vec<AuditRecord> {
        let mut records = Vec::new();
        let mut previous = AUDIT_CHAIN_GENESIS_PREV.to_string();
        for index in 0..count {
            let mut record = AuditRecord {
                index,
                time: "2026-07-26T00:00:00Z".into(),
                op: "copy".into(),
                result: "success".into(),
                prev: previous.clone(),
                ..AuditRecord::default()
            };
            record.hash = record.computed_hash();
            previous.clone_from(&record.hash);
            records.push(record);
        }
        records
    }

    fn log(records: Vec<AuditRecord>) -> Log {
        Log {
            path: PathBuf::from("/tmp/audit.jsonl"),
            records,
        }
    }

    #[test]
    fn an_intact_chain_succeeds_in_every_format() {
        for args in [vec![], vec!["--json"], vec!["--format", "json-lines"]] {
            let ctx = ctx(&args);
            let log = log(sealed_chain(3));
            let outcome = chain::verify(&log.records);
            assert!(report(&ctx, &log, outcome).is_ok(), "{args:?}");
        }
    }

    #[test]
    fn a_broken_chain_exits_twenty_four() {
        // The exit code is a published contract; scripts branch on 24.
        let mut records = sealed_chain(4);
        records[2].op = "forged".into();

        let log = log(records);
        let outcome = chain::verify(&log.records);
        let error = report(&ctx(&[]), &log, outcome).unwrap_err();
        assert_eq!(error.code(), ExitCode::AuditChainBroken);
        assert_eq!(error.code().as_i32(), 24);
    }

    #[test]
    fn the_error_names_the_exact_record_and_the_file() {
        let mut records = sealed_chain(6);
        records[4].path = "forged.jpg".into();
        let log = log(records);
        let broken = chain::verify(&log.records).unwrap_err();

        let error = break_error(&log, &broken);
        assert!(error.message().contains("record 4"), "{}", error.message());
        assert!(error.message().contains("audit.jsonl"));
        // The hint must tell an operator what *not* to do first.
        assert!(error.hint().unwrap().contains("Do not delete"));
    }

    #[test]
    fn the_verdict_document_carries_the_head_or_the_break_but_never_both() {
        let intact = Verdict {
            verdict: AUDIT_VERDICT_INTACT,
            log: "/tmp/a.jsonl".into(),
            records: 2,
            head: Some("ab"),
            broken_at: None,
        };
        let json = serde_json::to_string(&intact).unwrap();
        assert!(json.contains("\"verdict\":\"intact\""), "{json}");
        assert!(json.contains("\"head\":\"ab\""), "{json}");
        assert!(!json.contains("broken_at"), "{json}");

        let mut records = sealed_chain(3);
        records[1].size += 1;
        let broken = chain::verify(&records).unwrap_err();
        let failed = Verdict {
            verdict: AUDIT_VERDICT_BROKEN,
            log: "/tmp/a.jsonl".into(),
            records: 3,
            head: None,
            broken_at: Some(&broken),
        };
        let json = serde_json::to_string(&failed).unwrap();
        assert!(json.contains("\"verdict\":\"broken\""), "{json}");
        assert!(json.contains("\"position\":1"), "{json}");
        assert!(!json.contains("\"head\""), "{json}");
    }

    #[test]
    fn an_empty_chain_is_reported_as_intact_with_no_records() {
        // Honest: nothing has been appended. The module docs are explicit that
        // this is not a claim that nothing happened.
        let log = log(Vec::new());
        let verified = chain::verify(&log.records).unwrap();
        assert_eq!(verified.records, 0);
    }
}
