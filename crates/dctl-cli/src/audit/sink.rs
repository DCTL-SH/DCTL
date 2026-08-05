//! The run's one audit-log handle, and what happens when it cannot be written.
//!
//! [`super::write::Writer`] knows how to append a record; this decides *where*
//! the log is, *when* it is opened, and — the part that is policy rather than
//! mechanism — what a failure to write one means for the command that was being
//! recorded.
//!
//! ## One handle per run, opened on first use
//!
//! A [`Sink`] lives on [`crate::ctx::Ctx`], so a transfer of a million files
//! pays the open, the tail scan and the permission hardening once rather than a
//! million times. It is opened **lazily**, on the first record, which is what
//! keeps `dctl ls` from creating an evidence file it has nothing to put in: a
//! log that exists is a claim that something was recorded, and a read-only
//! command has nothing to record.
//!
//! Interior mutability rather than `&mut self`, because every command receives
//! `&Ctx`. A [`std::sync::Mutex`] is enough and is never held across an `await`:
//! [`Sink::record`] is synchronous from lock to `fsync`, so the guard cannot
//! escape into a future and the whole context stays `Send`.
//!
//! ## Where the log lives is decided in exactly one place
//!
//! [`crate::commands::audit::source::resolve_path`] — the *reader's* resolver,
//! called here rather than restated. A writer that resolved the path its own way
//! would eventually write a chain the reader never looks at, and the failure
//! mode is silent: `dctl audit verify` would report a clean, short log while the
//! records that mattered accumulated somewhere else.
//!
//! ## A dry run records nothing
//!
//! `--dry-run` performs no durable change, so there is nothing to attest to. A
//! record saying `copy / success` for a rehearsal would be the precise thing
//! [the plan](https://doc.dctl.sh/project/plan) §6 forbids — a true-looking statement about work that did not
//! happen — and it would be indistinguishable from a real one forever after.
//!
//! ## If the log cannot be written, the command fails
//!
//! [The plan](https://doc.dctl.sh/project/plan) §7 makes the chained record mandatory, and a mandatory thing that
//! is skipped when it is inconvenient is optional. So a failed append is a
//! failed command, and [`Sink::classify`] chooses between exactly two codes:
//!
//! * [`ExitCode::AuditChainBroken`] (24) when the file *is* a log and is not one
//!   we may extend — a head that does not hash to its own content, a last line
//!   that is not a record. That is tampering or damage, it is the diagnosis an
//!   operator can act on, and `dctl audit verify` names the record.
//! * [`ExitCode::FatalError`] (7) for everything else — the disk is full, the
//!   directory is not writable, the volume went away. Deliberately *not* the
//!   underlying I/O classification: a `NotFound` from the log's directory would
//!   surface as exit 4 ("a source or destination file was not found"), which
//!   tells a script something false about the user's data. Exit 7 is "the run
//!   cannot continue", which is exactly what has happened, and it is already in
//!   [`crate::commands::transfer::pipeline::is_fatal`] — so a transfer stops on
//!   the first unrecordable file instead of emitting one identical error per
//!   file for the rest of a ten-million-file run.
//!
//! Neither code is reused for "the operation itself failed": the record's
//! `result` field carries that, and the command's own error carries it to the
//! shell.
//!
//! ## What is recorded, and what deliberately is not
//!
//! One record per **attempt on the store**. A file that was read, sealed and
//! refused by the destination is recorded, with the refusal, because that is an
//! event somebody has to account for. A command rejected before it reached the
//! store — a malformed `REMOTE:PATH`, a remote no configuration defines, a
//! `deletefile` naming a path the vault does not hold — records nothing: it
//! attempted nothing and changed nothing, its failure is already in the
//! structured log and the exit code, and putting it here would fill the one file
//! an auditor reads end to end with typing.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::cli::globals::GlobalArgs;
use crate::constants::AUDIT_UNRECORDED_HINT;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

use super::record::Entry;
use super::write::Writer;

/// The audit log this invocation appends to.
pub struct Sink {
    /// Where the log is, so every message can name the file.
    path: PathBuf,
    /// Whether this run may append at all. False under `--dry-run`.
    recording: bool,
    /// Opened on the first record and held for the rest of the run.
    writer: Mutex<Option<Writer>>,
    /// Test-only scratch directory backing [`Sink::path`].
    ///
    /// A unit test must never append to the developer's own audit log. It would
    /// put fictional records in a real evidence file, and — worse for the suite
    /// — every test would share one chain, so a test that wrote a record would
    /// change what the next test's `Writer::open` reads as the head. Owned here
    /// so the directory dies with the context that created it, leaving nothing
    /// behind in the temporary directory.
    #[cfg(test)]
    _scratch: Option<tempfile::TempDir>,
}

impl std::fmt::Debug for Sink {
    /// Written by hand because [`Writer`] holds an open file handle whose
    /// derived rendering says nothing useful, and because the only fact worth
    /// reporting is whether the log has been opened yet.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sink")
            .field("path", &self.path)
            .field("recording", &self.recording)
            .field("opened", &self.writer.lock().is_ok_and(|w| w.is_some()))
            .finish()
    }
}

impl Sink {
    /// Resolve the log for one invocation.
    ///
    /// Nothing is opened and nothing is created here: a command that never
    /// records must leave no trace of having considered it.
    #[must_use]
    pub fn new(globals: &GlobalArgs) -> Self {
        #[cfg(test)]
        let scratch = tempfile::tempdir().ok();

        // Under `cargo test` the log is redirected into that scratch directory,
        // and it falls back to the real resolver only if no temporary directory
        // could be made — in which case the suite has bigger problems than where
        // its records land.
        #[cfg(test)]
        let path = scratch.as_ref().map_or_else(
            || crate::commands::audit::source::resolve_path(globals, None),
            |dir| dir.path().join(crate::constants::AUDIT_LOG_FILE_NAME),
        );

        #[cfg(not(test))]
        let path = crate::commands::audit::source::resolve_path(globals, None);

        Self {
            path,
            recording: !globals.dry_run,
            writer: Mutex::new(None),
            #[cfg(test)]
            _scratch: scratch,
        }
    }

    /// Where records are appended.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether this run appends records at all.
    #[must_use]
    pub const fn is_recording(&self) -> bool {
        self.recording
    }

    /// Append one record and return only once it is on stable storage.
    ///
    /// Call this **after** the durable commit that made the operation real
    /// ([the plan](https://doc.dctl.sh/project/plan) §6 step 8), never before, and call it for a failure too: a log
    /// that contains only successes cannot answer "what went wrong on the 3rd?",
    /// which is most of why anybody reads one.
    ///
    /// # Errors
    /// [`ExitCode::AuditChainBroken`] when the file on disk is not a chain this
    /// run may extend; [`ExitCode::FatalError`] for any other failure to write.
    /// Either way the operation the record describes is **not** recorded, and
    /// the caller must not report it as audited.
    pub fn record(&self, entry: &Entry) -> Result<()> {
        if !self.is_recording() {
            return Ok(());
        }

        let mut held = self
            .writer
            .lock()
            .map_err(|_| self.unusable("the audit log handle is poisoned"))?;

        let writer = match held.as_mut() {
            Some(writer) => writer,
            None => held.insert(Writer::open(&self.path).map_err(|error| self.classify(error))?),
        };

        writer
            .append(entry)
            .map(|_| ())
            .map_err(|error| self.classify(error))
    }

    /// Re-code a writer failure into the one the operator should act on.
    ///
    /// See the module documentation for why there are exactly two answers. The
    /// original message is kept whole — it names the file and the syscall — and
    /// only the classification and the hint change.
    ///
    /// The hint is always rewritten to lead with what happened to the *data*.
    /// [`Writer`]'s own hints speak about the log, and it is speaking to a caller
    /// that only ever writes logs; here the reader is an operator who has just
    /// been told a copy failed, and "no record was appended" read on its own is
    /// easily taken for "no file was written". Whether the file landed is the
    /// question they will act on, so it goes first.
    fn classify(&self, error: CliError) -> CliError {
        if error.code() == ExitCode::AuditChainBroken {
            // The chain diagnosis keeps its own code and its repair advice: it is
            // the one failure here an operator can investigate, and `dctl audit
            // verify` names the record.
            let repair = error.hint().unwrap_or_default().to_string();
            return CliError::new(ExitCode::AuditChainBroken, error.message().to_string())
                .with_hint(format!("{AUDIT_UNRECORDED_HINT} {repair}"));
        }

        CliError::new(ExitCode::FatalError, error.message().to_string()).with_hint(format!(
            "{AUDIT_UNRECORDED_HINT} The log is {}.",
            self.path().display()
        ))
    }

    /// The refusal used when the handle itself cannot be reached.
    fn unusable(&self, why: &str) -> CliError {
        CliError::new(
            ExitCode::FatalError,
            format!("cannot record to {}: {why}", self.path().display()),
        )
        .with_hint(AUDIT_UNRECORDED_HINT)
    }
}

/// The outcome slug a record should carry for `result`.
///
/// Centralised so every call site spells a success the same way and — the part
/// that matters — so a failure carries the command's *own* classified code
/// rather than a generic "error". The [exit-code reference](https://doc.dctl.sh/reference/exit-codes)'s vocabulary is what a
/// compliance query filters on years later, and a log in which one command
/// wrote `checksum_mismatch` and another wrote `fatal_error` for the same event
/// is a log nobody can query.
#[must_use]
pub fn outcome<T>(result: &Result<T>) -> ExitCode {
    match result {
        Ok(_) => ExitCode::Success,
        Err(error) => error.code(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::audit::chain;
    use crate::audit::record::AuditRecord;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn sink(args: &[&str]) -> Sink {
        Sink::new(&Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals)
    }

    fn records(sink: &Sink) -> Vec<AuditRecord> {
        std::fs::read_to_string(sink.path())
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn nothing_is_created_until_the_first_record() {
        // A log that exists is a claim that something was recorded, so a
        // read-only command must not leave one behind.
        let sink = sink(&[]);
        assert!(!sink.path().exists());
    }

    #[test]
    fn a_record_lands_and_the_chain_verifies() {
        let sink = sink(&[]);
        sink.record(&Entry::new("copy", ExitCode::Success).path("a.jpg"))
            .unwrap();
        sink.record(&Entry::new("delete", ExitCode::Success).path("b.jpg"))
            .unwrap();

        let written = records(&sink);
        assert_eq!(written.len(), 2);
        assert_eq!(written[0].op, "copy");
        chain::verify(&written).expect("the sink writes a valid chain");
    }

    #[test]
    fn a_dry_run_records_nothing() {
        // A rehearsal changed nothing, so there is nothing to attest to — and a
        // record saying otherwise could never be told apart from a real one.
        let sink = sink(&["--dry-run"]);
        assert!(!sink.is_recording());
        sink.record(&Entry::new("copy", ExitCode::Success).path("a.jpg"))
            .unwrap();
        assert!(!sink.path().exists());
    }

    #[test]
    fn a_failed_operation_is_recorded_with_its_own_code() {
        // A log of successes cannot answer "what went wrong on the 3rd?".
        let sink = sink(&[]);
        sink.record(&Entry::new("copy", ExitCode::ChecksumMismatch).path("a.jpg"))
            .unwrap();
        assert_eq!(records(&sink)[0].result, "checksum_mismatch");
    }

    #[test]
    fn a_log_that_is_not_a_chain_is_refused_at_24() {
        // Tampering keeps its own code, because it is the one diagnosis an
        // operator can act on and `dctl audit verify` names the record.
        let sink = sink(&[]);
        std::fs::write(sink.path(), "{ not a record\n").unwrap();

        let error = sink
            .record(&Entry::new("copy", ExitCode::Success))
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::AuditChainBroken);

        // The hint has to answer the operator's question — what happened to my
        // data? — before the log's. "No record was appended", read on its own by
        // somebody who has just been told their copy failed, is easily taken for
        // "no file was written", which would be a false statement about a file
        // that may be sitting durably in the vault.
        let hint = error.hint().unwrap_or_default();
        assert!(hint.contains("NOT recorded"), "{hint}");
        assert!(
            hint.contains("audit verify"),
            "the repair advice must survive: {hint}"
        );
    }

    #[test]
    fn an_unwritable_log_fails_the_command_at_7() {
        // Not the underlying I/O classification: a NotFound from the log's own
        // directory surfacing as exit 4 would tell a script something false
        // about the user's data.
        let dir = tempfile::tempdir().unwrap();
        let sink = Sink {
            // A path whose parent is a *file*, so the directory cannot be made.
            path: {
                let file = dir.path().join("occupied");
                std::fs::write(&file, b"x").unwrap();
                file.join("audit.jsonl")
            },
            recording: true,
            writer: Mutex::new(None),
            _scratch: None,
        };

        let error = sink
            .record(&Entry::new("copy", ExitCode::Success))
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error
                .hint()
                .is_some_and(|hint| hint.contains("NOT recorded")),
            "the operator must be told the operation is unrecorded"
        );
    }

    #[test]
    fn the_outcome_is_the_commands_own_classification() {
        let ok: Result<()> = Ok(());
        assert_eq!(outcome(&ok), ExitCode::Success);

        let failed: Result<()> = Err(CliError::new(ExitCode::IntegrityFailure, "bad tag"));
        assert_eq!(outcome(&failed), ExitCode::IntegrityFailure);
    }

    #[test]
    fn two_contexts_keep_two_chains_in_the_suite() {
        // The scratch directory is per-context on purpose: one shared log would
        // make every test's head depend on whichever test ran before it.
        let first = sink(&[]);
        let second = sink(&[]);
        assert_ne!(first.path(), second.path());
    }
}
