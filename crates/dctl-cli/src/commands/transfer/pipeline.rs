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
//! ## Where the audit record goes, and why exactly one per file
//!
//! `PLAN.md` §6 numbers the chained audit append step 8 — *after* the durable
//! commit — and §7 makes it mandatory. Both functions above therefore run the
//! whole operation to a conclusion, append one record describing how it ended,
//! and only then hand the outcome back. Two consequences are deliberate:
//!
//! * **The record is written for a failure too.** A log containing only
//!   successes cannot answer "what went wrong on the 3rd?", which is most of why
//!   anybody reads one. The `result` field carries the command's own classified
//!   exit code, so `checksum_mismatch` and `file_not_found` stay distinguishable
//!   years later.
//! * **A `move` produces one record, not two.** The record is appended after the
//!   source removal, because until the source is gone the move has not happened
//!   — a record written between the commit and the removal would attest to a
//!   `move` that a failure one line later turned into a `copy`.
//!
//! If the record cannot be written the file's outcome becomes that failure, at
//! [`ExitCode::FatalError`], which [`is_fatal`] stops the run on. Continuing
//! unaudited is exactly the misreporting §7 forbids, and grinding on would
//! produce one identical error per remaining file.
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

use crate::audit::record::{Direction as AuditDirection, Entry as AuditEntry};
use crate::audit::sink;
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

    /// The destination this driver writes to, for the audit record's `remote`
    /// field. Empty when there is no remote — a filesystem-to-filesystem copy.
    ///
    /// Asked of the driver rather than passed down from the command, because the
    /// driver is what actually connected: a name threaded through five call
    /// layers can be the wrong one, and an audit record naming the wrong vault is
    /// worse than one naming none.
    fn remote(&self) -> &str;

    /// Which way this driver moves bytes, for the audit record's `direction`.
    ///
    /// Asked of the driver for the same reason as [`StageDriver::remote`], and
    /// for a sharper one besides: the driver is the only thing that knows which
    /// end is the remote. `dctl copy vault:tree /out` and `dctl copy /out
    /// vault:tree` are the same verb with the same two operands, and telling them
    /// apart from the command line alone means re-deriving a classification the
    /// engine already made. Getting it wrong records an egress as an ingest,
    /// which is the exact failure this field exists to prevent.
    fn direction(&self) -> AuditDirection;

    /// BLAKE3 of the plaintext this entry moved, lower-case hex, or empty.
    ///
    /// Taken rather than borrowed: the driver computed it while the bytes were in
    /// hand and has no reason to keep them addressable afterwards. Empty is a
    /// legitimate answer — the format allows it, and a failed transfer never
    /// produced one — so a driver that cannot supply it is not a broken driver.
    ///
    /// This is the field that makes the log evidence about *content* rather than
    /// merely about activity: "a file called `q4.xlsx` was copied at 14:32" is an
    /// activity log, and "the file whose plaintext hashes to `d749…` was copied
    /// at 14:32" is something a dispute can be settled with.
    fn take_plaintext_hash(&self, entry: &PlanEntry) -> String;
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

    /// The remote this reaper deletes from, for the audit record's `remote`
    /// field. Empty when it deletes from the local filesystem.
    fn remote(&self) -> &str;
}

/// Run one file through steps 1–6, then record it (step 8).
///
/// # Errors
/// Whatever the driver returned, or — if the operation could not be recorded —
/// the audit failure instead, because a transfer this build cannot attest to is
/// not a transfer it may report as done. A failure anywhere in 1–6 means the
/// file is not stored, so the error propagates unchanged and the caller must not
/// count the file as done: only [`run_stages`] increments the "files done"
/// counter, and only after the commit returns.
pub async fn transfer_file<D: StageDriver>(
    ctx: &Ctx,
    op: &str,
    driver: &D,
    entry: &PlanEntry,
) -> Result<()> {
    let walked = walk(ctx, driver, entry).await;
    let moved = walked.as_ref().copied().unwrap_or_default();
    record(ctx, op, driver, entry, moved, walked.map(|_| ()))
}

/// Steps 1–6 alone, with no audit record. Returns the bytes that moved.
///
/// Private, and that is the whole point: every public entry point below appends
/// a record, so there is no route through this module that moves a file and
/// leaves no trace of having done it.
async fn walk<D: StageDriver>(ctx: &Ctx, driver: &D, entry: &PlanEntry) -> Result<u64> {
    let started = std::time::Instant::now();
    // A bar needs a number. An entry with no recorded size draws as a bar of
    // length zero, which is what an indeterminate bar looks like — and unlike a
    // report, the bar is ephemeral and makes no claim anyone can act on later.
    let handle = ctx
        .progress
        .start_file(&entry.dest, entry.size.unwrap_or_default());
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
        { fields::BYTES } = tracing::field::debug(entry.size),
        { fields::DURATION_MS } = elapsed_ms(started),
        stored = outcome.is_ok(),
        "file finished"
    );
    outcome
}

/// Step 8 — append the chained record, and let a failure to do so become the
/// file's outcome.
///
/// The order is the promise: the operation has already run to a conclusion by
/// the time this is called, so the record describes what happened rather than
/// what was about to be attempted. `PLAN.md` §6 puts the append after the
/// durable commit for exactly that reason — a record for work that then failed
/// is a false statement in the one artefact whose entire value is being true.
///
/// The size is recorded whichever way it went. It describes the object the
/// operation concerned, not a claim that those bytes landed; `moved` is the
/// claim that they did, and losing "what were you moving?" from every failure
/// record would make the failures the least investigable entries in the log.
///
/// `moved` is a **measurement**, taken by [`StageDriver::upload`] as the bytes
/// went past, and it is recorded exactly as measured whichever way the run
/// ended. A transfer that failed before the upload stage measured nothing and
/// records zero — never the plan's figure, which is a statement about intent. A
/// `move` whose destination commit succeeded and whose source removal then
/// failed records the bytes that genuinely landed, because they genuinely
/// landed; `result` is the field that says the move did not complete.
///
/// The direction comes from the driver, so `dctl copy vault:tree /out` records
/// `out` and the upload that put the tree there records `in`. Those two were
/// indistinguishable in schema v1, which is most of why there is a schema v2.
fn record<D: StageDriver>(
    ctx: &Ctx,
    op: &str,
    driver: &D,
    entry: &PlanEntry,
    moved: u64,
    outcome: Result<()>,
) -> Result<()> {
    let record = AuditEntry::new(op, sink::outcome(&outcome))
        .path(&entry.dest)
        // The audit record's byte fields are part of the hash-chain preimage
        // (`audit::chain`) and are `u64` by that format's definition, so an
        // unrecorded size is written as zero here rather than changing what the
        // chain covers.
        .size(entry.size.unwrap_or_default())
        .moved(driver.direction(), moved)
        // One record, one object. A run-level record — `cleanup`, `index
        // rebuild` — carries its whole count instead, so a chain of a hundred
        // records still totals correctly however the work was divided up.
        .objects(1)
        .plaintext_hash(&driver.take_plaintext_hash(entry))
        .remote(driver.remote());

    // `?` rather than a fold into `outcome`: an unrecordable operation is a
    // failure of the run whatever happened to the file, and it outranks a
    // per-file error because it is the reason the run must stop.
    ctx.audit.record(&record)?;
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

/// The stage walk itself, returning the bytes the upload stage measured.
///
/// The count comes back rather than being read off the plan, because the plan is
/// what was *intended* and the audit record has to carry what happened. They
/// differ whenever a source changed under the run, and the log is the artefact
/// where that difference matters.
async fn run_stages<D: StageDriver>(
    ctx: &Ctx,
    driver: &D,
    entry: &PlanEntry,
    handle: &FileHandle,
) -> Result<u64> {
    let progress = ctx.progress.as_ref();
    let reporter = StageReporter::new(progress, handle);
    let mut moved = 0;

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
            Stage::Uploading => {
                moved = driver.upload(entry).await?;
                reporter.advance(moved);
            }

            // Step 4 is mandatory. Everything before this line moved bytes;
            // nothing before it proved they arrived intact.
            Stage::Verifying => {
                driver.verify(entry, ctx.verify_mode()).await?;
                ctx.stats.add_verified_bytes(entry.size.unwrap_or_default());
            }

            // Step 6. Until this returns, the file is not stored.
            Stage::Committing => driver.commit(entry).await?,

            // Not a unit of work: `Done` is the label a finished row parks on.
            Stage::Done => {}
        }
    }

    progress.set_stage(handle, Stage::Done);
    ctx.stats.file_done();
    Ok(moved)
}

/// Steps 1–7 then 8: transfer, delete the source, record it — in that order,
/// always.
///
/// This function is the whole difference between `move` and `copy`, and its
/// shape is the guarantee. [`walk`] returns `Ok` only after the durable index
/// commit of step 6; the `?` means the reaper is unreachable on any other
/// outcome. A checksum mismatch, a failed commit, a cancelled run — all of them
/// leave the source exactly where it was.
///
/// The audit record is appended **after the removal**, and describes the move as
/// a whole. Recording between the two steps would attest to a `move` that a
/// failure one line later turned into a `copy` — the source still there, the log
/// saying otherwise, and nothing to tell them apart afterwards.
///
/// # Errors
/// The transfer's error, unchanged, or the source deletion's, or the audit
/// append's. A failure to delete the source is *not* a failure of the transfer:
/// the data is safely at the destination, and the operator needs to know which
/// of the two happened — which is why the record carries the classified code
/// rather than a bare "failed".
pub async fn move_file<D: StageDriver, R: Reaper>(
    ctx: &Ctx,
    op: &str,
    driver: &D,
    source_reaper: &R,
    entry: &PlanEntry,
) -> Result<()> {
    let (moved, outcome) = match walk(ctx, driver, entry).await {
        Ok(moved) => (moved, source_reaper.remove(&entry.source).await),
        Err(error) => (0, Err(error)),
    };
    record(ctx, op, driver, entry, moved, outcome)
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
///
/// [`ExitCode::AuditChainBroken`] is on the list for a second reason as well as
/// that one. A log that cannot be extended stays unextendable for every file
/// behind this one, so the run would emit ten million copies of the same
/// message; and every one of those files would be transferred *unrecorded*,
/// which `PLAN.md` §7 forbids outright. Stopping is the only outcome that leaves
/// the vault and the log describing the same run.
#[must_use]
pub const fn is_fatal(error: &CliError) -> bool {
    matches!(
        error.code(),
        ExitCode::FatalError
            | ExitCode::Cancelled
            | ExitCode::VaultLocked
            | ExitCode::IndexError
            | ExitCode::Usage
            | ExitCode::AuditChainBroken
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::transfer::plan::Op;
    use crate::commands::transfer::testing::ctx;
    use std::cell::RefCell;

    /// The remote the fake drivers claim to be connected to.
    const TEST_REMOTE: &str = "archive";

    /// The verb the tests drive the walk with.
    const TEST_OP: &str = "copy";

    fn entry(path: &str, size: u64) -> PlanEntry {
        PlanEntry {
            action: Op::Copy,
            source: path.to_string(),
            dest: path.to_string(),
            size: Some(size),
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
            Ok(entry.size.unwrap_or_default())
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
        fn remote(&self) -> &str {
            TEST_REMOTE
        }
        fn direction(&self) -> AuditDirection {
            AuditDirection::In
        }
        fn take_plaintext_hash(&self, _entry: &PlanEntry) -> String {
            String::new()
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
        fn remote(&self) -> &str {
            TEST_REMOTE
        }
    }

    #[tokio::test]
    async fn a_file_walks_every_stage_in_order() {
        let ctx = ctx(&[]);
        let driver = Recording::default();
        transfer_file(&ctx, TEST_OP, &driver, &entry("a.txt", 100))
            .await
            .unwrap();
        assert_eq!(driver.stages(), PIPELINE_STAGES);
    }

    #[tokio::test]
    async fn bytes_and_files_are_counted_only_after_the_commit() {
        let ctx = ctx(&[]);
        transfer_file(&ctx, TEST_OP, &Recording::default(), &entry("a.txt", 100))
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
            let result = transfer_file(&ctx, TEST_OP, &driver, &entry("a.txt", 100)).await;

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
        let _ = transfer_file(&ctx, TEST_OP, &driver, &entry("a.txt", 100)).await;
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

        move_file(&ctx, TEST_OP, &driver, &reaper, &entry("a.txt", 10))
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

            let result = move_file(&ctx, TEST_OP, &driver, &reaper, &entry("a.txt", 10)).await;

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
            fn remote(&self) -> &str {
                TEST_REMOTE
            }
            fn direction(&self) -> AuditDirection {
                AuditDirection::In
            }
            fn take_plaintext_hash(&self, _: &PlanEntry) -> String {
                String::new()
            }
        }

        let ctx = ctx(&[]);
        let reaper = RecordingReaper::default();
        let error = move_file(&ctx, TEST_OP, &Mismatching, &reaper, &entry("a.txt", 10))
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

        // A log that cannot be extended stays unextendable for every file
        // behind this one, and each of them would move unrecorded.
        assert!(is_fatal(&CliError::new(ExitCode::AuditChainBroken, "")));
    }

    /// The records this run appended, parsed the way the reader parses them.
    fn recorded(ctx: &Ctx) -> Vec<crate::audit::record::AuditRecord> {
        std::fs::read_to_string(ctx.audit.path())
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn a_transferred_file_leaves_exactly_one_verifiable_record() {
        let ctx = ctx(&[]);
        transfer_file(&ctx, TEST_OP, &Recording::default(), &entry("a.txt", 100))
            .await
            .unwrap();

        let records = recorded(&ctx);
        assert_eq!(records.len(), 1, "one file, one record");
        assert_eq!(records[0].op, TEST_OP);
        assert_eq!(records[0].path, "a.txt");
        assert_eq!(records[0].result, ExitCode::Success.slug());
        assert_eq!(records[0].size, 100);
        assert_eq!(records[0].remote, TEST_REMOTE);
        assert_eq!(records[0].direction, AuditDirection::In.slug());
        assert_eq!(records[0].bytes, 100, "the measured count, not the plan's");
        assert_eq!(records[0].objects, 1);
        crate::audit::chain::verify(&records).expect("the chain holds");
    }

    #[tokio::test]
    async fn the_recorded_byte_count_is_measured_and_not_read_off_the_plan() {
        // The plan says 100; the driver moves 7. A record that echoed the plan
        // would report bytes that never went anywhere, which is the same class
        // of false statement as reporting a file stored that was not.
        struct Short;
        impl StageDriver for Short {
            async fn read(&self, _: &PlanEntry) -> Result<()> {
                Ok(())
            }
            async fn encrypt(&self, _: &PlanEntry) -> Result<()> {
                Ok(())
            }
            async fn upload(&self, _: &PlanEntry) -> Result<u64> {
                Ok(7)
            }
            async fn verify(&self, _: &PlanEntry, _: VerifyMode) -> Result<()> {
                Ok(())
            }
            async fn commit(&self, _: &PlanEntry) -> Result<()> {
                Ok(())
            }
            async fn create_dir(&self, _: &PlanEntry) -> Result<()> {
                Ok(())
            }
            fn remote(&self) -> &str {
                TEST_REMOTE
            }
            fn direction(&self) -> AuditDirection {
                AuditDirection::Out
            }
            fn take_plaintext_hash(&self, _: &PlanEntry) -> String {
                String::new()
            }
        }

        let ctx = ctx(&[]);
        transfer_file(&ctx, TEST_OP, &Short, &entry("a.txt", 100))
            .await
            .unwrap();

        let records = recorded(&ctx);
        assert_eq!(records[0].size, 100, "what the object was believed to be");
        assert_eq!(records[0].bytes, 7, "what actually moved");
    }

    #[tokio::test]
    async fn a_read_out_of_a_remote_is_distinguishable_from_a_write_into_it() {
        // Finding 7: in schema v1, `dctl copy vault:tree /out` — data leaving —
        // was recorded exactly like the upload that put it there. The direction
        // is what tells them apart, and it comes from the driver because the
        // driver is what knows which end is the remote.
        struct Egress;
        impl StageDriver for Egress {
            async fn read(&self, _: &PlanEntry) -> Result<()> {
                Ok(())
            }
            async fn encrypt(&self, _: &PlanEntry) -> Result<()> {
                Ok(())
            }
            async fn upload(&self, entry: &PlanEntry) -> Result<u64> {
                Ok(entry.size.unwrap_or_default())
            }
            async fn verify(&self, _: &PlanEntry, _: VerifyMode) -> Result<()> {
                Ok(())
            }
            async fn commit(&self, _: &PlanEntry) -> Result<()> {
                Ok(())
            }
            async fn create_dir(&self, _: &PlanEntry) -> Result<()> {
                Ok(())
            }
            fn remote(&self) -> &str {
                TEST_REMOTE
            }
            fn direction(&self) -> AuditDirection {
                AuditDirection::Out
            }
            fn take_plaintext_hash(&self, _: &PlanEntry) -> String {
                String::new()
            }
        }

        let ctx = ctx(&[]);
        transfer_file(&ctx, TEST_OP, &Recording::default(), &entry("in.txt", 40))
            .await
            .unwrap();
        transfer_file(&ctx, TEST_OP, &Egress, &entry("out.txt", 195_000))
            .await
            .unwrap();

        let records = recorded(&ctx);
        assert_eq!(records[0].direction, "in");
        assert_eq!(records[1].direction, "out");
        assert_eq!(records[1].bytes, 195_000, "the egress is quantified");
        // Same op, same remote — only the direction and the count tell them
        // apart, which is exactly the point.
        assert_eq!(records[0].op, records[1].op);
        assert_eq!(records[0].remote, records[1].remote);
        crate::audit::chain::verify(&records).expect("the chain holds");
    }

    #[tokio::test]
    async fn a_failed_transfer_is_recorded_with_its_own_classification() {
        // A log of successes cannot answer "what went wrong on the 3rd?", and a
        // failure recorded as a generic "error" cannot answer "what kind?".
        let ctx = ctx(&[]);
        let driver = Recording::failing_at(Stage::Uploading);
        let error = transfer_file(&ctx, TEST_OP, &driver, &entry("a.txt", 100))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::TemporaryError);

        let records = recorded(&ctx);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].result, ExitCode::TemporaryError.slug());
        // Nothing was stored, so nothing was hashed — an empty field rather than
        // a digest of bytes that never landed.
        assert_eq!(records[0].plaintext_hash, "");
        // And nothing was measured, so nothing is claimed to have moved. The
        // plan's figure survives in `size`, which is what makes the failure
        // investigable without making it a claim.
        assert_eq!(records[0].bytes, 0);
        assert_eq!(records[0].size, 100);
    }

    #[tokio::test]
    async fn a_move_whose_source_survived_still_records_the_bytes_that_landed() {
        // The destination commit succeeded, so the bytes are genuinely there;
        // recording zero would understate an egress that happened. `result`
        // carries the fact that the move did not complete.
        struct Stubborn;
        impl Reaper for Stubborn {
            async fn remove(&self, _: &str) -> Result<()> {
                Err(CliError::new(ExitCode::TemporaryError, "provider said no"))
            }
            fn target(&self) -> &'static str {
                "source"
            }
            fn remote(&self) -> &str {
                TEST_REMOTE
            }
        }

        let ctx = ctx(&[]);
        let _ = move_file(
            &ctx,
            "move",
            &Recording::default(),
            &Stubborn,
            &entry("a.txt", 64),
        )
        .await;

        let records = recorded(&ctx);
        assert_eq!(records[0].bytes, 64);
        assert_eq!(records[0].result, ExitCode::TemporaryError.slug());
    }

    #[tokio::test]
    async fn a_move_records_once_and_only_after_the_source_is_gone() {
        // The ordering that makes the record true. A record written between the
        // commit and the removal would attest to a `move` that the failure one
        // line later turned into a `copy` — the source still there, and the log
        // saying otherwise.
        struct Stubborn;
        impl Reaper for Stubborn {
            async fn remove(&self, _: &str) -> Result<()> {
                Err(CliError::new(ExitCode::TemporaryError, "provider said no"))
            }
            fn target(&self) -> &'static str {
                "source"
            }
            fn remote(&self) -> &str {
                TEST_REMOTE
            }
        }

        let ctx = ctx(&[]);
        let error = move_file(
            &ctx,
            "move",
            &Recording::default(),
            &Stubborn,
            &entry("a.txt", 10),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::TemporaryError);

        let records = recorded(&ctx);
        assert_eq!(records.len(), 1, "one file, one record — never two");
        assert_eq!(records[0].op, "move");
        assert_eq!(
            records[0].result,
            ExitCode::TemporaryError.slug(),
            "the destination commit succeeded, but the move did not"
        );
    }

    #[tokio::test]
    async fn a_dry_run_transfers_nothing_and_therefore_records_nothing() {
        // Belt and braces: no transfer verb reaches this function under
        // --dry-run, and if one ever did the record would still not be written.
        let ctx = ctx(&["--dry-run"]);
        transfer_file(&ctx, TEST_OP, &Recording::default(), &entry("a.txt", 1))
            .await
            .unwrap();
        assert!(recorded(&ctx).is_empty());
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
