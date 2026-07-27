//! Storing a scanned tree in a vault, one streamed file at a time.
//!
//! ## Why this is not the transfer pipeline
//!
//! `copy` moves a file by reading its plaintext into a buffer and handing that
//! buffer to [`Vault::put_file`](dctl_core::Vault::put_file). That is fine for
//! documents and it is why the transfer family carries
//! [`TRANSFER_WHOLE_FILE_LIMIT`](crate::constants::TRANSFER_WHOLE_FILE_LIMIT) —
//! a ceiling above which it refuses rather than being OOM-killed.
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

use crate::commands::transfer::pipeline;
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

    /// Store one file, streaming.
    ///
    /// # Errors
    /// Whatever the core reported. The caller decides whether that ends the run.
    async fn store_one(&self, logical: &str, native: &Path) -> Result<()> {
        self.session
            .vault
            .put_file_from_path(logical, native)
            .await?;
        Ok(())
    }
}

/// Store every scanned file, reporting each one as it lands.
///
/// # Errors
/// Only a fatal failure — the per-file kind is counted and skipped. See the
/// module documentation.
pub async fn everything(ctx: &Ctx, store: &Store, files: &[ScannedFile]) -> Result<()> {
    for file in files {
        let logical = store.logical_path(&file.logical);

        let handle = ctx.progress.start_file(&logical, file.size);
        ctx.progress.set_stage(&handle, Stage::Uploading);
        let outcome = store.store_one(&logical, &file.native).await;
        ctx.progress.set_stage(&handle, Stage::Committing);
        ctx.progress.finish_file(handle);

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
