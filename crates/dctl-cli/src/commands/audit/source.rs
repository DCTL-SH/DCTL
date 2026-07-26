//! Finding the audit log and reading it in.
//!
//! The log lives beside the encrypted index, because the two are the same kind
//! of thing: local state belonging to one vault. Point `--index` somewhere else
//! and the log follows, so a machine that works with two vaults keeps two
//! independent chains rather than interleaving them into one that describes
//! neither.
//!
//! ## A missing log is not an empty log
//!
//! `PLAN.md` §7 requires the engine to append a chained record after every
//! operation, and this build's engine does not do that yet. So when the file is
//! absent, the honest answer is *"the writer is not implemented"* — an error
//! with a real exit code — and not "0 records, chain intact", which would be a
//! clean bill of health for a system that has never recorded anything. The
//! reader is complete and works today: point `--audit-log` at a chain written
//! anywhere and it is verified for real.
//!
//! ## A record that will not parse is treated as tampering
//!
//! Not as a formatting inconvenience. A line that is not a record is
//! indistinguishable from a line somebody edited badly, and the two must be
//! reported the same way — loudly, with the line number, at exit code 24. A
//! crash mid-append produces the same signature, which is the right trade: an
//! operator who is told "line 88 812 is not a record" can look, and one who is
//! told nothing cannot.

use std::path::{Path, PathBuf};

use crate::cli::globals::GlobalArgs;
use crate::constants::{AUDIT_LOG_FILE_NAME, AUDIT_WRITER_FEATURE, AUDIT_WRITER_HINT};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

use super::record::AuditRecord;

/// A loaded audit log.
#[derive(Debug)]
pub struct Log {
    /// Where it was read from, so every message can name the file.
    pub path: PathBuf,
    /// Its records, in file order. Order is evidence: the chain's position is
    /// the position in the file, never a value the file supplied.
    pub records: Vec<AuditRecord>,
}

/// Where the audit log lives for this invocation.
///
/// An explicit `--audit-log` wins. Otherwise the log sits next to the index if
/// one was named, and in the platform data directory if not — which is where the
/// index defaults to as well, so the two stay together either way.
#[must_use]
pub fn resolve_path(globals: &GlobalArgs, explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    if let Some(parent) = globals.index.as_deref().and_then(Path::parent) {
        return parent.join(AUDIT_LOG_FILE_NAME);
    }
    dctl_meta::paths::data_dir().join(AUDIT_LOG_FILE_NAME)
}

/// Read and parse the log.
///
/// # Errors
/// [`ExitCode::FatalError`] when no log exists, because the writer described in
/// `PLAN.md` §7 is not implemented in this build.
/// [`ExitCode::AuditChainBroken`] when a line cannot be parsed as a record —
/// see the module docs for why that is tampering and not a formatting problem.
/// Any other read failure is classified by [`CliError`]'s I/O conversion.
pub fn load(globals: &GlobalArgs, explicit: Option<&Path>) -> Result<Log> {
    let path = resolve_path(globals, explicit);

    if !path.exists() {
        return Err(
            CliError::unimplemented(AUDIT_WRITER_FEATURE).with_hint(format!(
                "{AUDIT_WRITER_HINT} Looked for {}.",
                path.display()
            )),
        );
    }

    let text = std::fs::read_to_string(&path).map_err(|error| {
        CliError::from(error).with_hint(format!("Could not read {}.", path.display()))
    })?;

    let mut records = Vec::new();
    for (offset, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: AuditRecord = serde_json::from_str(line).map_err(|error| {
            CliError::new(
                ExitCode::AuditChainBroken,
                format!(
                    "{}: line {} is not an audit record: {error}",
                    path.display(),
                    offset + 1
                ),
            )
            .with_hint(
                "A line that is not a record is indistinguishable from one that was \
                 edited, so it is reported as a chain failure. Compare the file \
                 against a mirrored copy before trusting anything in it.",
            )
        })?;
        records.push(record);
    }

    Ok(Log { path, records })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn globals(args: &[&str]) -> GlobalArgs {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals
    }

    fn write_log(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join(AUDIT_LOG_FILE_NAME);
        std::fs::write(&path, body).unwrap();
        path
    }

    /// One record, on exactly one line — the log is line-delimited, so a test
    /// fixture that wrapped would not be testing the same thing at all.
    fn record_json(index: u64) -> String {
        let prev = "0".repeat(64);
        let hash = "1".repeat(64);
        format!(
            r#"{{"index":{index},"time":"2026-07-26T00:00:00Z","op":"copy","result":"success","path":"a.jpg","size":1,"prev":"{prev}","hash":"{hash}"}}"#
        )
    }

    #[test]
    fn an_explicit_path_wins_over_everything() {
        let path = resolve_path(
            &globals(&["--index", "/data/vault.redb"]),
            Some(Path::new("/x/a.jsonl")),
        );
        assert_eq!(path, PathBuf::from("/x/a.jsonl"));
    }

    #[test]
    fn the_log_lives_beside_the_index() {
        // Two vaults on one machine must keep two independent chains.
        let path = resolve_path(&globals(&["--index", "/data/vaults/one.redb"]), None);
        assert_eq!(
            path,
            PathBuf::from("/data/vaults").join(AUDIT_LOG_FILE_NAME)
        );
    }

    #[test]
    fn without_an_index_the_log_falls_back_to_the_data_directory() {
        let path = resolve_path(&globals(&[]), None);
        assert!(path.ends_with(AUDIT_LOG_FILE_NAME));
        assert!(path.starts_with(dctl_meta::paths::data_dir()));
    }

    #[test]
    fn a_missing_log_is_reported_as_an_unimplemented_writer() {
        // Never as "0 records, intact": that would be a clean bill of health for
        // a system that has never recorded anything.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nothing.jsonl");
        let error = load(&globals(&[]), Some(&missing)).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("audit log writer"));
        assert!(error.hint().unwrap().contains("nothing.jsonl"));
    }

    #[test]
    fn records_are_read_in_file_order() {
        let dir = tempfile::tempdir().unwrap();
        let body = format!("{}\n{}\n", record_json(0), record_json(1));
        let path = write_log(dir.path(), &body);

        let log = load(&globals(&[]), Some(&path)).unwrap();
        assert_eq!(log.records.len(), 2);
        assert_eq!(log.records[0].index, 0);
        assert_eq!(log.records[1].index, 1);
        assert_eq!(log.path, path);
    }

    #[test]
    fn blank_lines_are_ignored() {
        // A trailing newline is normal; a blank line is not evidence of anything.
        let dir = tempfile::tempdir().unwrap();
        let body = format!("\n{}\n\n{}\n", record_json(0), record_json(1));
        let path = write_log(dir.path(), &body);
        assert_eq!(load(&globals(&[]), Some(&path)).unwrap().records.len(), 2);
    }

    #[test]
    fn an_empty_log_loads_as_a_chain_with_no_records() {
        // The file exists, so the writer is not the problem; there is simply
        // nothing appended yet. `verify` decides what that means.
        let dir = tempfile::tempdir().unwrap();
        let path = write_log(dir.path(), "");
        assert!(load(&globals(&[]), Some(&path)).unwrap().records.is_empty());
    }

    #[test]
    fn an_unparseable_line_is_a_chain_failure_naming_the_line() {
        let dir = tempfile::tempdir().unwrap();
        let body = format!("{}\n{{ not json\n{}\n", record_json(0), record_json(1));
        let path = write_log(dir.path(), &body);

        let error = load(&globals(&[]), Some(&path)).unwrap_err();
        assert_eq!(error.code(), ExitCode::AuditChainBroken);
        assert!(error.message().contains("line 2"), "{}", error.message());
        assert!(error.hint().is_some());
    }

    #[test]
    fn a_record_missing_a_required_field_is_a_chain_failure() {
        // `prev` and `hash` are what make the log a chain; a record without
        // them is not a record.
        let dir = tempfile::tempdir().unwrap();
        let path = write_log(
            dir.path(),
            r#"{"index":0,"time":"t","op":"copy","result":"ok"}"#,
        );
        let error = load(&globals(&[]), Some(&path)).unwrap_err();
        assert_eq!(error.code(), ExitCode::AuditChainBroken);
    }
}
