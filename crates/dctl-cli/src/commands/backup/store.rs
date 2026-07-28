//! Storing a scanned tree in a vault, one streamed file at a time.
//!
//! ## Why this is not the transfer pipeline
//!
//! `copy` used to move a file by reading its plaintext into a buffer and handing
//! that buffer to [`Vault::put_file`](dctl_core::Vault::put_file), which is why
//! the transfer family carried a one-gibibyte ceiling above which it refused
//! rather than being OOM-killed. It no longer does either: the transfer engine
//! streams, and the ceiling is deleted.
//!
//! What follows is therefore no longer a *difference* between `backup` and
//! `copy` — both stream now — but it remains the reason this module reaches for
//! the streaming API directly rather than through the buffered one.
//!
//! `backup` is the verb most likely to meet a fifty-gigabyte video, and a backup
//! tool that cannot store the largest file on the disk is not a backup tool. So
//! it uses [`Vault::put_file_from_path`](dctl_core::Vault::put_file_from_path),
//! which seals the source straight from disk into a temporary object and hands
//! *that* to the backend's streaming write: no stage ever holds the whole file
//! or the whole object, so peak memory is O(chunk) per file regardless of size,
//! which is what `PLAN.md` §16.2 asks for. There is therefore no size limit here
//! and no size check — not because one was forgotten, but because the path this
//! module uses does not have the failure the limit exists to prevent.
//!
//! The guarantee is the same one `copy` gets, because it is the same order
//! inside the core: the content object is written and verified, then the
//! authoritative §5 name record, then the durable index commit. Success is
//! returned only after all three, so a file this module reports as stored *is*
//! stored (`PLAN.md` §6).
//!
//! ## One bad file does not abandon the run
//!
//! A tree with one unreadable file must still back up the other four million.
//! Per-file failures are counted through [`Ctx::stats`], reported by name, and
//! the run continues; the recorded errors downgrade the process exit code
//! through [`Ctx::outcome`] so nothing is rolled up into success (`PLAN.md` §7).
//!
//! A *fatal* failure is different, and [`pipeline::is_fatal`] draws the same line
//! the transfer executor draws: a locked vault makes every remaining file fail
//! identically, so the run stops instead of emitting four million copies of one
//! error.

use std::path::Path;

use dctl_core::Modified;

use crate::audit::record::{Direction as AuditDirection, Entry as AuditEntry};
use crate::audit::sink;
use crate::commands::transfer::pipeline;
use crate::constants::REMOTE_SEPARATOR;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::output::Stage;
use crate::remote::RemoteSpec;
use crate::session::{self, Session};

use super::super::recovery::Target;
use super::scan::ScannedFile;

/// A connected backup engine: one unlocked vault, for the whole run.
pub struct Store {
    session: Session,
    /// The logical prefix every stored path is placed under — the `PATH` half of
    /// the `REMOTE:PATH` operand.
    prefix: String,
}

impl std::fmt::Debug for Store {
    /// Written by hand so the unlocked vault cannot be rendered; see
    /// [`Session`]'s own implementation for why that matters.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("remote", &self.session.remote)
            .field("prefix", &self.prefix)
            .finish()
    }
}

impl Store {
    /// Unlock the vault this backup writes into.
    ///
    /// Once, before the first file, so a missing password costs one error rather
    /// than one error per file — and so an operator is never prompted twice for
    /// the same secret in one run.
    ///
    /// # Errors
    /// Whatever [`session::open`] reported: an unresolvable remote
    /// ([`ExitCode::FatalError`](crate::exit::ExitCode::FatalError)), a missing
    /// password ([`ExitCode::VaultLocked`](crate::exit::ExitCode::VaultLocked)),
    /// or an envelope that will not unwrap.
    pub async fn connect(ctx: &Ctx, target: &Target) -> Result<Self> {
        // The whole spec, never the remote's name on its own: a bare name has no
        // colon and would be re-read as the *relative directory* of that name,
        // which is how a backup ends up writing plaintext into `./archive`.
        let spec = RemoteSpec::Named {
            remote: target.remote.clone(),
            path: target.path.clone(),
        };

        // Asked before the vault is opened, so a refusal costs no password
        // prompt, and answered from the configuration rather than from what the
        // destination currently holds. `dctl backup ./photos archive-store:`
        // names a vault's *object* namespace, and storing plaintext beside the
        // ciphertext there is the failure `crate::addressing` exists to prevent.
        crate::addressing::refuse_plain_write(ctx, &spec)?;

        Ok(Self {
            session: session::open(ctx, &spec).await?,
            prefix: target.path.clone(),
        })
    }

    /// Where a scanned file lands inside the vault.
    ///
    /// The root case is why this is a function: `vault:` needs nothing before
    /// the logical path while `vault:photos` needs a separator, and getting it
    /// wrong stores `photosa.jpg` — a key no later command could address.
    #[must_use]
    pub fn logical_path(&self, logical: &str) -> String {
        crate::platform::path::join(&self.prefix, logical)
    }

    /// Store one file, streaming, recorded as last modified when the source was.
    ///
    /// The time is read here rather than carried from the scan, and rather than
    /// being left for the core to read out of the file it is about to seal.
    ///
    /// *Not from the scan*, because a scan of ten million files can finish hours
    /// before this file's turn comes, and a record is worth having only if it
    /// describes the bytes that were actually stored.
    ///
    /// *Not by the core*, because the core cannot tell a real source from a
    /// spool: `dctl rcat` hands the same call a temporary file whose own
    /// modification time is the moment of the spool. The caller is the only one
    /// that knows which it has.
    ///
    /// A source that changes between this `stat` and the seal records the
    /// *older* time, so the next run sees a newer source and stores it again.
    /// That is the direction to be wrong in — the alternative is a record that
    /// claims to be current and stops the file ever being backed up again.
    ///
    /// # Errors
    /// Whatever the core reported. The caller decides whether that ends the run.
    /// A metadata failure is *not* one of them: the file is stored with no
    /// recorded time, which every later comparison reads as "not comparable" and
    /// re-stores, rather than abandoning a backup over a timestamp.
    async fn store_one(&self, logical: &str, native: &Path) -> Result<()> {
        let modified = tokio::fs::metadata(native)
            .await
            .map_or(Modified::Unknown, |meta| Modified::of(&meta));
        self.session
            .vault
            .put_file_from_path(logical, native, modified)
            .await?;
        Ok(())
    }

    /// The vault's name as the audit log spells it.
    ///
    /// The trailing [`REMOTE_SEPARATOR`] is stripped for the same reason the
    /// transfer engine strips it: a [`Session`] carries the spec exactly as it
    /// was typed (`archive:`), the removal family carries the parsed name
    /// (`archive`), and two spellings of one remote is a log a compliance query
    /// cannot filter — `remote == archive` would silently exclude every backup.
    fn remote(&self) -> &str {
        self.session.remote.trim_end_matches(REMOTE_SEPARATOR)
    }
}

/// Store every scanned file, reporting each one as it lands.
///
/// ## Every stored file leaves a record
///
/// `backup` moves data **into** a vault and, until this was wired, moved it
/// there without appending a single line to the tamper-evident chain: 195 KiB
/// could enter a vault and the log would say nothing at all. That is the one
/// thing an audit log may not do, and it is the reason the record is appended
/// here — per file, after the core's durable commit returns, exactly where
/// `PLAN.md` §6 step 8 puts it and exactly where the transfer pipeline puts its
/// own.
///
/// A failure is recorded too, with the command's own classified code and zero
/// bytes moved, because "which four files did last night's backup fail to
/// store?" is a question only the log can answer the next morning.
///
/// # Errors
/// Only a fatal failure — the per-file kind is counted and skipped. See the
/// module documentation. An operation that could not be *audited* is fatal by
/// construction: the log is unwritable for every file behind it too, and
/// continuing would store four million files unrecorded.
pub async fn everything(ctx: &Ctx, store: &Store, files: &[ScannedFile]) -> Result<()> {
    for file in files {
        let logical = store.logical_path(&file.logical);

        let handle = ctx.progress.start_file(&logical, file.size);
        ctx.progress.set_stage(&handle, Stage::Uploading);
        let outcome = store.store_one(&logical, &file.native).await;
        ctx.progress.set_stage(&handle, Stage::Committing);
        ctx.progress.finish_file(handle);

        // `?`, so an unrecordable file ends the run rather than letting the rest
        // of the tree enter the vault unattested.
        ctx.audit.record(
            &AuditEntry::new(super::VERB, sink::outcome(&outcome))
                .path(&logical)
                .size(file.size)
                // The scanned length is the measurement here: the core streams
                // the file straight from disk and reports success only after the
                // whole of it is sealed, verified and committed, so a successful
                // store moved exactly this many bytes. A failure moved none that
                // anything can attest to.
                .moved(
                    AuditDirection::In,
                    if outcome.is_ok() { file.size } else { 0 },
                )
                .objects(1)
                .remote(store.remote()),
        )?;

        match outcome {
            Ok(()) => {
                // Counted only after the core returned, which is after the
                // durable index commit: a file is "done" when it is stored, not
                // when it was attempted.
                ctx.stats.add_bytes(file.size);
                ctx.stats.file_done();
                tracing::debug!(path = %logical, bytes = file.size, "stored");
            }
            Err(error) if pipeline::is_fatal(&error) => {
                // Every remaining file would fail the same way. Stopping is what
                // keeps one locked vault from producing four million identical
                // lines, and the error still carries its own exit code.
                return Err(error);
            }
            Err(error) => {
                ctx.stats.error();
                ctx.out
                    .warn(format!("failed to store {logical}: {}", error.message()));
            }
        }
    }
    Ok(())
}

/// Refuse to claim a snapshot this build cannot restore.
///
/// The mirror image of `restore`'s `--at` refusal, and it belongs on the *write*
/// side for a reason worth stating plainly: storing the files and quietly
/// dropping the snapshot name leaves an operator believing a named point in time
/// exists. They would discover it does not on the day they reached for it, which
/// is the single worst moment (`PLAN.md` §13.6). A backup that refuses today
/// costs one flag; one that lies costs the restore.
///
/// `--dry-run` is exempt: planning a snapshot is not claiming one, and the plan
/// document is where an operator checks what a future build would record.
///
/// # Errors
/// [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError), naming the phase
/// that makes snapshots real.
pub fn refuse_unsupported_snapshot(ctx: &Ctx, wanted: bool) -> Result<()> {
    if !wanted || ctx.is_dry_run() {
        return Ok(());
    }
    Err(CliError::unimplemented(crate::constants::SNAPSHOT_FEATURE)
        .with_hint(crate::constants::SNAPSHOT_HINT))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::exit::ExitCode;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: crate::cli::globals::GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        let parsed = Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()));
        Ctx::new(parsed.globals)
    }

    #[test]
    fn a_snapshot_is_refused_on_a_real_run_and_planned_on_a_dry_one() {
        // Planning is not claiming: `--dry-run --snapshot nightly` still prints
        // what a future build would record, which is the only way to check it.
        assert!(refuse_unsupported_snapshot(&ctx(&["--dry-run"]), true).is_ok());
        assert!(refuse_unsupported_snapshot(&ctx(&[]), false).is_ok());

        let error = refuse_unsupported_snapshot(&ctx(&[]), true).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains("--snapshot"),
            "{}",
            error.message()
        );
        assert!(error.hint().is_some_and(|hint| hint.contains("13.5")));
    }
}
