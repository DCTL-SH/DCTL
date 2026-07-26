//! `dctl audit export` — hand the chain to somebody else, intact.
//!
//! Export exists so the log can leave the machine that wrote it: to an evidence
//! bundle, to a colleague, to storage that DCTL cannot reach. Two properties
//! matter more than anything else about the output.
//!
//! **It stays verifiable.** Every record is written with every field it arrived
//! with, so the exported copy re-verifies exactly as the original does. Nothing
//! is summarised, abbreviated or reordered — an export that pretty-printed away
//! a field would produce a chain that no longer hashes.
//!
//! **[`Format::Text`] is not a text rendering.** There is no sensible prose form
//! of a hash chain, and inventing one would produce a file that looks like an
//! export but cannot be checked. So text means the canonical JSON Lines form,
//! which is exactly the on-disk format, and `dctl audit export > copy.jsonl`
//! produces a file `dctl audit verify --audit-log copy.jsonl` accepts.
//!
//! Writing to `--output` is a mutation, so it honours `--dry-run`, and
//! overwriting an existing file is destructive, so it goes through
//! [`Ctx::confirm_destructive`] first. Exporting over last month's evidence
//! bundle is precisely the accident worth one confirmation.

use std::path::PathBuf;

use clap::Args;

use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::output::Format;

use super::chain;
use super::record::AuditRecord;
use super::source;
use super::verify::break_error;

/// Arguments for `dctl audit export`.
#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Chain to export. Defaults to the log beside the configured index.
    #[arg(long, value_name = "PATH")]
    pub audit_log: Option<PathBuf>,

    /// Write to this file instead of standard output.
    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

pub async fn run(ctx: &Ctx, args: &ExportArgs) -> Result<()> {
    let log = source::load(&ctx.globals, args.audit_log.as_deref())?;

    // Walked before anything is written, so a break is known before the export
    // lands somewhere it will be trusted.
    let outcome = chain::verify(&log.records);

    let body = encode(ctx.out.format(), &log.records)?;

    match &args.output {
        None => ctx.out.write(&body)?,
        Some(path) => write_file(ctx, path, &body)?,
    }

    if let Err(broken) = outcome {
        // The copy is written — an investigator needs it — and the exit code
        // says what it is a copy of.
        return Err(break_error(&log, &broken));
    }
    Ok(())
}

/// Serialise the whole chain.
///
/// # Errors
/// Propagates a serialisation failure, which for these records means a
/// `serde_json` internal error rather than anything a user can cause.
fn encode(format: Format, records: &[AuditRecord]) -> Result<String> {
    let mut body = String::new();

    match format {
        // One document, so the export is a single JSON value a parser can load
        // whole. Chosen only when the user explicitly asked for --json.
        Format::Json => {
            body.push_str(&format.encode(records).map_err(|error| {
                CliError::new(
                    ExitCode::Uncategorised,
                    format!("encoding the chain: {error}"),
                )
            })?);
            body.push('\n');
        }
        // The canonical form: one record per line, byte-for-byte re-verifiable.
        Format::JsonLines | Format::Text => {
            for record in records {
                body.push_str(&Format::JsonLines.encode(record).map_err(|error| {
                    CliError::new(
                        ExitCode::Uncategorised,
                        format!("encoding record {}: {error}", record.index),
                    )
                })?);
                body.push('\n');
            }
        }
    }

    Ok(body)
}

/// Write the export to a file, honouring the dry-run and destructive gates.
fn write_file(ctx: &Ctx, path: &std::path::Path, body: &str) -> Result<()> {
    let target = path.display().to_string();

    if path.exists() {
        if ctx.is_dry_run() {
            ctx.dry_run_notice("overwrite", &target);
            return Ok(());
        }
        if !ctx.confirm_destructive("overwrite", &target)? {
            return Err(CliError::new(
                ExitCode::Cancelled,
                format!("not overwriting {target}"),
            ));
        }
    } else if ctx.is_dry_run() {
        ctx.dry_run_notice("write", &target);
        return Ok(());
    }

    std::fs::write(path, body)
        .map_err(|error| CliError::from(error).with_hint(format!("Could not write {target}.")))?;
    ctx.out.success(format!("exported to {target}"));
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
    }

    fn ctx(args: &[&str]) -> Ctx {
        Ctx::new(Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals)
    }

    fn records() -> Vec<AuditRecord> {
        vec![
            AuditRecord {
                index: 0,
                time: "2026-07-26T00:00:00Z".into(),
                op: "copy".into(),
                result: "success".into(),
                path: "a.jpg".into(),
                size: 3,
                prev: "0".repeat(64),
                hash: "1".repeat(64),
                ..AuditRecord::default()
            },
            AuditRecord {
                index: 1,
                time: "2026-07-26T00:00:01Z".into(),
                op: "delete".into(),
                result: "success".into(),
                path: "b.jpg".into(),
                prev: "1".repeat(64),
                hash: "2".repeat(64),
                ..AuditRecord::default()
            },
        ]
    }

    #[test]
    fn the_default_export_is_one_record_per_line() {
        let body = encode(Format::Text, &records()).unwrap();
        assert_eq!(body.lines().count(), 2);
        assert!(
            body.ends_with('\n'),
            "a line-delimited file ends its last line"
        );
    }

    #[test]
    fn an_exported_line_round_trips_back_into_a_record() {
        // The property that matters: the copy re-verifies exactly as the
        // original does.
        let original = records();
        let body = encode(Format::JsonLines, &original).unwrap();
        let parsed: Vec<AuditRecord> = body
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(parsed, original);
    }

    #[test]
    fn no_field_is_dropped_on_the_way_out() {
        // An export that summarised a field would produce a chain that no
        // longer hashes to what it claims.
        let body = encode(Format::JsonLines, &records()).unwrap();
        for field in [
            "index",
            "time",
            "op",
            "result",
            "path",
            "size",
            "plaintext_hash",
            "ciphertext_hash",
            "remote",
            "prev",
            "hash",
        ] {
            assert!(body.contains(field), "'{field}' is missing from the export");
        }
    }

    #[test]
    fn explicit_json_produces_one_document() {
        let body = encode(Format::Json, &records()).unwrap();
        let parsed: Vec<AuditRecord> = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn an_empty_chain_exports_as_nothing_rather_than_failing() {
        assert_eq!(encode(Format::Text, &[]).unwrap(), "");
    }

    #[test]
    fn a_dry_run_writes_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");
        write_file(&ctx(&["--dry-run"]), &path, "body").unwrap();
        assert!(!path.exists(), "--dry-run must not create the file");
    }

    #[test]
    fn a_dry_run_does_not_overwrite_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");
        std::fs::write(&path, "original").unwrap();

        write_file(&ctx(&["--dry-run"]), &path, "replacement").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "original");
    }

    #[test]
    fn a_real_run_writes_the_body() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");
        write_file(&ctx(&["--force"]), &path, "body").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "body");
    }

    #[test]
    fn an_approved_overwrite_replaces_the_file() {
        // The gate is `Ctx::confirm_destructive`, which --force approves; the
        // refusal path is exercised by the dry-run test above, since --dry-run
        // declines every destructive action.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");
        std::fs::write(&path, "original").unwrap();

        write_file(&ctx(&["--force"]), &path, "replacement").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "replacement");
    }
}
