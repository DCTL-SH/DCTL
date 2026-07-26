//! The verified-write pipeline, and the progress display that shows it moving.
//!
//! `PLAN.md` §6 numbers the steps a file goes through before DCTL will call it
//! stored: read and hash, encrypt, stage the upload, verify what the provider
//! actually stored, optionally verify harder, then commit the index entry. That
//! commit — step 6 — is the only thing that makes a file count as stored, and
//! nothing before it may be reported as success.
//!
//! Two things live here, and they are the same thing seen from two sides:
//!
//! * [`transfer_file`] walks those steps in order, driving [`Stage`] through the
//!   progress display so the per-file bar shows the real pipeline position. A
//!   row sitting at `verify` has been uploaded but is *not yet durable*; a row at
//!   `commit` is being made durable. That distinction is the product, so the
//!   display shows it rather than a single undifferentiated percentage.
//! * [`move_file`] adds step 7 — deleting the source — and does it strictly
//!   after the commit returns. The ordering is the promise `move` makes, so it
//!   is encoded as a data dependency (`transfer_file(...).await?` before the
//!   reaper is even reachable) rather than as a comment asking future readers to
//!   be careful.
//!
//! ## Why a trait
//!
//! The steps themselves belong to `dctl-core`'s transfer engine, not to the CLI.
//! [`StageDriver`] is the seam: this module owns the *order* and the reporting,
//! the driver owns the work. The only production driver is [`super::engine`]'s,
//! which performs it for real; the walk, the ordering guarantee and the progress
//! wiring are additionally tested against a recording driver, so a regression in
//! either half shows up on its own. Note that a vault destination collapses
//! steps 2–6 into one core call at [`Stage::Uploading`] — the engine documents
//! why that is stronger than performing them separately — so this order is the
//! contract the stages report, not a claim about how many round trips happen.

use crate::cli::VerifyMode;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::logging::fields;
use crate::output::{FileHandle, Progress, Stage};

use super::plan::PlanEntry;

/// The stages a file passes through, in order.
///
/// Public and const so a test can assert the walk visited all of them: an engine
/// that skipped `Verifying` would still transfer bytes, still print a bar, and
/// still be a violation of the core promise.
pub const PIPELINE_STAGES: &[Stage] = &[
    Stage::Reading,
    Stage::Encrypting,
    Stage::Uploading,
    Stage::Verifying,
    Stage::Committing,
];

/// A file's handle on the progress display, handed to the driver.
///
/// The driver reports bytes as they move without being given access to the bar
/// registry — it cannot finish another file's row, and it cannot outlive the row
/// it was issued for.
pub struct StageReporter<'a> {
    progress: &'a Progress,
    handle: &'a FileHandle,
}

impl<'a> StageReporter<'a> {
    /// Bind a reporter to one in-flight file.
    #[must_use]
    pub const fn new(progress: &'a Progress, handle: &'a FileHandle) -> Self {
        Self { progress, handle }
    }

    /// Record bytes moved, on this file's bar and on the aggregate.
    pub fn advance(&self, bytes: u64) {
        self.progress.advance(self.handle, bytes);
    }
}

/// The work behind each pipeline stage.
///
/// Implemented once for real (by [`super::engine`]) and once per test. Static
/// dispatch throughout: the trait is never a `dyn` object, so `async fn` in a
/// trait is safe to use here and the missing `Send` bound the lint warns about
/// cannot bite — the executor awaits these sequentially on one task.
#[allow(async_fn_in_trait)]
pub trait StageDriver {
    /// Step 1 — stream the source and hash the plaintext.
    async fn read(&self, entry: &PlanEntry) -> Result<()>;

    /// Step 2 — seal the plaintext into chunked AEAD.
    async fn encrypt(&self, entry: &PlanEntry) -> Result<()>;

    /// Step 3 — stage the upload under a temporary object key, returning the
    /// number of bytes actually put on the wire.
    ///
    /// The count comes back rather than being reported through a callback
    /// because the pipeline owns the display: one place decides what "progress"
    /// means, and a driver cannot double-count or forget. When the engine can
    /// stream a 50 GB file, [`StageReporter`] is the seam that grows a
    /// per-chunk callback — it already carries the handle this file's bar needs.
    async fn upload(&self, entry: &PlanEntry) -> Result<u64>;

    /// Steps 4 and 5 — compare the provider's stored checksum with ours, and
    /// apply whatever extra assurance `--verify` asked for.
    ///
    /// A mismatch here must hard-abort: nothing is committed and no source is
    /// touched.
    async fn verify(&self, entry: &PlanEntry, mode: VerifyMode) -> Result<()>;

    /// Step 6 — the durable index commit. Returning `Ok` from this method is the
    /// only thing that makes a file count as stored.
    async fn commit(&self, entry: &PlanEntry) -> Result<()>;

    /// Recreate an empty source directory (`--create-empty-src-dirs`).
    ///
    /// Not part of the stage walk: there are no bytes to read, encrypt, verify
    /// or commit, so pretending otherwise would put a five-stage bar on a
    /// zero-byte operation.
    async fn create_dir(&self, entry: &PlanEntry) -> Result<()>;
}

/// Removal of something that already exists.
///
/// One trait for two jobs that are the same shape and must never be confused:
/// `sync` removing a destination extra, and `move` removing a source after a
/// durable commit. [`Reaper::target`] names which, so every message and every
/// audit record says what was deleted from where.
#[allow(async_fn_in_trait)]
pub trait Reaper {
    /// Remove one logical path.
    async fn remove(&self, path: &str) -> Result<()>;

    /// Which side this reaper deletes from — `"source"` or `"destination"`.
    fn target(&self) -> &'static str;
}

/// Run one file through steps 1–6, reporting each stage on the display.
///
/// # Errors
/// Whatever the driver returns. A failure anywhere in 1–6 means the file is not
/// stored, so the error propagates unchanged and the caller must not count the
/// file as done — [`transfer_file`] only increments the "files done" counter
/// after the commit returns.
pub async fn transfer_file<D: StageDriver>(ctx: &Ctx, driver: &D, entry: &PlanEntry) -> Result<()> {
    let started = std::time::Instant::now();
    let handle = ctx.progress.start_file(&entry.dest, entry.size);
    let outcome = run_stages(ctx, driver, entry, &handle).await;
    // The row is retired whether the file succeeded or failed: a bar left behind
    // by a failed transfer would be redrawn over the error message explaining it.
    ctx.progress.finish_file(handle);

    // Logged whichever way it went, and after the row is retired so the record
    // is not overdrawn by a bar. The progress display is ephemeral — it is gone
    // the moment the run ends — so this is the only place a completed file
    // leaves a durable trace of how long it took, which is what turns "the
    // backup got slower" into a question with an answer.
    tracing::debug!(
        { fields::PATH } = entry.dest.as_str(),
        { fields::BYTES } = entry.size,
        { fields::DURATION_MS } = elapsed_ms(started),
        stored = outcome.is_ok(),
        "file finished"
    );
    outcome
}

/// Milliseconds since `started`, saturating.
///
/// `as` on a `u128` saturates at the maximum rather than wrapping, so a clock
/// that jumps cannot turn a duration into a small plausible-looking number —
/// an absurd figure in a log is investigated, a wrong one is believed.
fn elapsed_ms(started: std::time::Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

/// The stage walk itself.
async fn run_stages<D: StageDriver>(
    ctx: &Ctx,
    driver: &D,
    entry: &PlanEntry,
    handle: &FileHandle,
) -> Result<()> {
    let progress = ctx.progress.as_ref();
    let reporter = StageReporter::new(progress, handle);

    // Driven from [`PIPELINE_STAGES`] rather than from a hand-written sequence,
    // so the order the display shows and the order the work happens in are one
    // list. Two copies of an ordering are two chances for the bar to claim a
    // file is committed while it is still being verified.
    for stage in PIPELINE_STAGES {
        progress.set_stage(handle, *stage);
        // The same position the bar is showing, in the log. A transfer that
        // stalls does so *at* a stage, and which one separates a slow network
        // from a slow disk from an index that will not commit — the display
        // shows it to whoever is watching, and this shows it to whoever reads
        // the log afterwards, which is usually the person who has to fix it.
        tracing::trace!(
            { fields::STAGE } = stage.label(),
            { fields::PATH } = entry.dest.as_str(),
            "stage entered"
        );
        match stage {
            Stage::Reading => driver.read(entry).await?,
            Stage::Encrypting => driver.encrypt(entry).await?,
            Stage::Uploading => reporter.advance(driver.upload(entry).await?),

            // Step 4 is mandatory. Everything before this line moved bytes;
            // nothing before it proved they arrived intact.
            Stage::Verifying => {
                driver.verify(entry, ctx.verify_mode()).await?;
                ctx.stats.add_verified_bytes(entry.size);
            }

            // Step 6. Until this returns, the file is not stored.
            Stage::Committing => driver.commit(entry).await?,

            // Not a unit of work: `Done` is the label a finished row parks on.
            Stage::Done => {}
        }
    }

    progress.set_stage(handle, Stage::Done);
    ctx.stats.file_done();
    Ok(())
}

/// Steps 1–7: transfer, then delete the source — in that order, always.
///
/// This function is the whole difference between `move` and `copy`, and its
/// shape is the guarantee. `transfer_file` returns `Ok` only after the durable
/// index commit of step 6; the `?` means the reaper is unreachable on any other
/// outcome. A checksum mismatch, a failed commit, a cancelled run — all of them
/// leave the source exactly where it was.
///
/// # Errors
/// The transfer's error, unchanged, or the source deletion's. A failure to
/// delete the source is *not* a failure of the transfer: the data is safely at
/// the destination, and the operator needs to know which of the two happened.
pub async fn move_file<D: StageDriver, R: Reaper>(
    ctx: &Ctx,
    driver: &D,
    source_reaper: &R,
    entry: &PlanEntry,
) -> Result<()> {
    transfer_file(ctx, driver, entry).await?;
    source_reaper.remove(&entry.source).await
}

/// Record a per-file failure without aborting the run.
///
/// `PLAN.md` §7 forbids rolling a partial failure up into success, so the error
/// is counted (which downgrades the process exit code through
/// [`Ctx::outcome`](crate::ctx::Ctx::outcome)) and reported on stderr, where it
/// cannot corrupt whatever data stdout is carrying.
///
/// A checksum mismatch is counted separately, because it outranks a generic
/// error: it means the destination stored something other than what was sent,
/// and exit code 20 exists so a script can tell that apart from a timeout.
pub fn record_failure(ctx: &Ctx, path: &str, error: &CliError) {
    if error.code() == ExitCode::ChecksumMismatch {
        ctx.stats.checksum_mismatch();
    } else {
        ctx.stats.error();
    }
    ctx.out.error(format!("{path}: {error}"));
}

/// Whether a failure should stop the whole run rather than skip one file.
///
/// The distinction is what makes a ten-million-file job survivable. One
/// unreadable file should not abandon the other 9,999,999; a locked vault, a
/// full disk or a cancelled run makes every remaining file fail identically, and
/// grinding through them produces ten million identical errors instead of one.
#[must_use]
pub const fn is_fatal(error: &CliError) -> bool {
    matches!(
        error.code(),
        ExitCode::FatalError
            | ExitCode::Cancelled
            | ExitCode::VaultLocked
            | ExitCode::IndexError
            | ExitCode::Usage
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::transfer::plan::Op;
    use crate::commands::transfer::testing::ctx;
    use std::cell::RefCell;

    fn entry(path: &str, size: u64) -> PlanEntry {
        PlanEntry {
            action: Op::Copy,
            source: path.to_string(),
            dest: path.to_string(),
            size,
            reason: "test",
        }
    }

    /// A driver that records the stages it was asked to perform.
    ///
    /// `RefCell` rather than a lock: the executor awaits stages sequentially on
    /// one task, which is exactly the property the recording is asserting.
    #[derive(Default)]
    struct Recording {
        calls: RefCell<Vec<Stage>>,
        /// Stage at which every call starts failing.
        fail_at: Option<Stage>,
    }

    impl Recording {
        fn failing_at(stage: Stage) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                fail_at: Some(stage),
            }
        }

        fn note(&self, stage: Stage) -> Result<()> {
            self.calls.borrow_mut().push(stage);
            if self.fail_at == Some(stage) {
                return Err(CliError::new(ExitCode::TemporaryError, "stage failed"));
            }
            Ok(())
        }

        fn stages(&self) -> Vec<Stage> {
            self.calls.borrow().clone()
        }
    }

    impl StageDriver for Recording {
        async fn read(&self, _entry: &PlanEntry) -> Result<()> {
            self.note(Stage::Reading)
        }
        async fn encrypt(&self, _entry: &PlanEntry) -> Result<()> {
            self.note(Stage::Encrypting)
        }
        async fn upload(&self, entry: &PlanEntry) -> Result<u64> {
            self.note(Stage::Uploading)?;
            Ok(entry.size)
        }
        async fn verify(&self, _entry: &PlanEntry, _mode: VerifyMode) -> Result<()> {
            self.note(Stage::Verifying)
        }
        async fn commit(&self, _entry: &PlanEntry) -> Result<()> {
            self.note(Stage::Committing)
        }
        async fn create_dir(&self, _entry: &PlanEntry) -> Result<()> {
            Ok(())
        }
    }

    /// A reaper that records what it was asked to delete.
    #[derive(Default)]
    struct RecordingReaper {
        removed: RefCell<Vec<String>>,
    }

    impl Reaper for RecordingReaper {
        async fn remove(&self, path: &str) -> Result<()> {
            self.removed.borrow_mut().push(path.to_string());
            Ok(())
        }
        fn target(&self) -> &'static str {
            "source"
        }
    }

    #[tokio::test]
    async fn a_file_walks_every_stage_in_order() {
        let ctx = ctx(&[]);
        let driver = Recording::default();
        transfer_file(&ctx, &driver, &entry("a.txt", 100))
            .await
            .unwrap();
        assert_eq!(driver.stages(), PIPELINE_STAGES);
    }

    #[tokio::test]
    async fn bytes_and_files_are_counted_only_after_the_commit() {
        let ctx = ctx(&[]);
        transfer_file(&ctx, &Recording::default(), &entry("a.txt", 100))
            .await
            .unwrap();

        let snapshot = ctx.stats.snapshot();
        assert_eq!(snapshot.bytes_transferred, 100, "upload reported its bytes");
        assert_eq!(snapshot.bytes_verified, 100);
        assert_eq!(snapshot.files_done, 1);
    }

    #[tokio::test]
    async fn a_failure_before_the_commit_never_counts_the_file() {
        // The core promise: bytes may have moved, but nothing is "stored".
        for stage in [
            Stage::Reading,
            Stage::Encrypting,
            Stage::Uploading,
            Stage::Verifying,
            Stage::Committing,
        ] {
            let ctx = ctx(&[]);
            let driver = Recording::failing_at(stage);
            let result = transfer_file(&ctx, &driver, &entry("a.txt", 100)).await;

            assert!(result.is_err(), "{stage:?} should have failed");
            assert_eq!(ctx.stats.snapshot().files_done, 0, "{stage:?}");
            // And the walk stopped there rather than carrying on.
            assert_eq!(driver.stages().last(), Some(&stage));
        }
    }

    #[tokio::test]
    async fn nothing_is_verified_before_the_verify_stage() {
        let ctx = ctx(&[]);
        let driver = Recording::failing_at(Stage::Uploading);
        let _ = transfer_file(&ctx, &driver, &entry("a.txt", 100)).await;
        assert_eq!(
            ctx.stats.snapshot().bytes_verified,
            0,
            "bytes uploaded are not bytes proven durable"
        );
    }

    #[tokio::test]
    async fn move_deletes_the_source_only_after_a_durable_commit() {
        let ctx = ctx(&[]);
        let driver = Recording::default();
        let reaper = RecordingReaper::default();

        move_file(&ctx, &driver, &reaper, &entry("a.txt", 10))
            .await
            .unwrap();

        assert_eq!(driver.stages(), PIPELINE_STAGES, "all six steps ran");
        assert_eq!(reaper.removed.borrow().as_slice(), ["a.txt"]);
    }

    #[tokio::test]
    async fn move_never_deletes_the_source_when_any_step_fails() {
        // This is the product promise. If it ever regresses, `move` becomes a
        // data-loss tool.
        for stage in PIPELINE_STAGES {
            let ctx = ctx(&[]);
            let driver = Recording::failing_at(*stage);
            let reaper = RecordingReaper::default();

            let result = move_file(&ctx, &driver, &reaper, &entry("a.txt", 10)).await;

            assert!(result.is_err(), "{stage:?}");
            assert!(
                reaper.removed.borrow().is_empty(),
                "source deleted after a failure at {stage:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_checksum_mismatch_leaves_the_source_untouched() {
        // The specific §6 step-4 case: the provider stored the wrong bytes.
        struct Mismatching;
        impl StageDriver for Mismatching {
            async fn read(&self, _: &PlanEntry) -> Result<()> {
                Ok(())
            }
            async fn encrypt(&self, _: &PlanEntry) -> Result<()> {
                Ok(())
            }
            async fn upload(&self, _: &PlanEntry) -> Result<u64> {
                Ok(0)
            }
            async fn verify(&self, _: &PlanEntry, _: VerifyMode) -> Result<()> {
                Err(CliError::new(
                    ExitCode::ChecksumMismatch,
                    "stored bytes differ",
                ))
            }
            async fn commit(&self, _: &PlanEntry) -> Result<()> {
                Ok(())
            }
            async fn create_dir(&self, _: &PlanEntry) -> Result<()> {
                Ok(())
            }
        }

        let ctx = ctx(&[]);
        let reaper = RecordingReaper::default();
        let error = move_file(&ctx, &Mismatching, &reaper, &entry("a.txt", 10))
            .await
            .unwrap_err();

        assert_eq!(error.code(), ExitCode::ChecksumMismatch);
        assert!(reaper.removed.borrow().is_empty());
        assert_eq!(ctx.stats.snapshot().files_done, 0);
    }

    #[test]
    fn a_mismatch_is_counted_apart_from_a_generic_error() {
        let ctx = ctx(&[]);
        record_failure(
            &ctx,
            "a.txt",
            &CliError::new(ExitCode::ChecksumMismatch, "differs"),
        );
        record_failure(
            &ctx,
            "b.txt",
            &CliError::new(ExitCode::TemporaryError, "timeout"),
        );

        let snapshot = ctx.stats.snapshot();
        assert_eq!(snapshot.checksum_mismatches, 1);
        assert_eq!(snapshot.errors, 2, "a mismatch is also an error");
        assert_eq!(ctx.outcome(), ExitCode::ChecksumMismatch);
    }

    #[test]
    fn only_run_ending_failures_are_fatal() {
        // One unreadable file must not abandon the other 9,999,999.
        assert!(!is_fatal(&CliError::new(ExitCode::TemporaryError, "")));
        assert!(!is_fatal(&CliError::new(ExitCode::FileNotFound, "")));
        assert!(!is_fatal(&CliError::new(ExitCode::ChecksumMismatch, "")));

        // These make every remaining file fail identically.
        assert!(is_fatal(&CliError::new(ExitCode::VaultLocked, "")));
        assert!(is_fatal(&CliError::new(ExitCode::Cancelled, "")));
        assert!(is_fatal(&CliError::unimplemented("dctl copy")));
    }

    #[test]
    fn the_stage_walk_covers_the_whole_contract() {
        // A pipeline that skipped verification would still move bytes and still
        // draw a bar; the list is asserted so that cannot happen quietly.
        assert!(PIPELINE_STAGES.contains(&Stage::Verifying));
        assert!(PIPELINE_STAGES.contains(&Stage::Committing));
        assert_eq!(PIPELINE_STAGES.last(), Some(&Stage::Committing));
    }
}
