//! Running a plan.
//!
//! The executor never decides anything. It walks the [`Plan`] it was handed, in
//! plan order, and asks a [`StageDriver`] or a [`Reaper`] to perform each entry.
//! That is deliberate: `--dry-run` prints the same plan this function consumes,
//! so what a reviewer approved and what the machine performs are provably the
//! same list — not two independent traversals that happen to agree today.
//!
//! ## Failure policy
//!
//! One bad file must not abandon the rest of the run: a ten-million-file job
//! that aborted on the first permission error would be unusable. So a per-file
//! failure is counted and reported, the loop continues, and the recorded errors
//! downgrade the process exit code to [`ExitCode::PartialFailure`] through
//! [`Ctx::outcome`] — never rolled up into success (`PLAN.md` §7).
//!
//! A *fatal* failure is different, and [`pipeline::is_fatal`] draws the line: a
//! locked vault or a cancelled run makes every remaining file fail identically,
//! so the run stops rather than emitting ten million copies of one error.

use crate::audit::record::Entry as AuditEntry;
use crate::audit::sink;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

use super::pipeline::{self, Reaper, StageDriver};
use super::plan::{Op, Plan};

/// Ask for approval before a destructive run, and stop if it is refused.
///
/// Wraps [`Ctx::confirm_destructive`] so the whole family answers a refusal the
/// same way: with [`ExitCode::Cancelled`], never with a silent exit 0. A command
/// that declined to do the work it was asked to do has not succeeded, and a
/// script must be able to tell the two apart.
///
/// **Callers must handle `--dry-run` before reaching this.** A dry run declines
/// every confirmation by design; treating that as a cancellation would turn
/// `--dry-run` — the safe way to inspect a plan — into a non-zero exit.
///
/// # Errors
/// [`ExitCode::Cancelled`] when the user declines, and whatever
/// [`Ctx::confirm_destructive`] raises when there is no terminal to ask.
pub fn confirm(ctx: &Ctx, action: &str, target: &str) -> Result<()> {
    debug_assert!(
        !ctx.is_dry_run(),
        "a dry run must return before asking for confirmation"
    );

    if ctx.confirm_destructive(action, target)? {
        return Ok(());
    }
    Err(CliError::new(
        ExitCode::Cancelled,
        format!("cancelled: {action} '{target}' was not confirmed"),
    )
    .with_hint("Nothing was changed. Pass --force to approve without prompting."))
}

/// Transfer every copy/update entry, and create every empty directory.
///
/// `op` is the verb the user typed, and it reaches this far down for one
/// purpose: it is the `op` field of every audit record the run appends, and a
/// log in which `sync` recorded itself as `copy` would misstate which files were
/// at risk of deletion.
///
/// # Errors
/// Only a fatal failure — the per-file kind is recorded and skipped. See the
/// module docs. An operation that could not be *audited* is fatal by
/// construction, because the log is unwritable for every file behind it too.
pub async fn transfers<D: StageDriver>(
    ctx: &Ctx,
    op: &'static str,
    driver: &D,
    plan: &Plan,
) -> Result<()> {
    for entry in plan.entries.iter().filter(|e| e.action.is_action()) {
        match entry.action {
            Op::Copy | Op::Update => {
                perform(
                    ctx,
                    &entry.dest,
                    pipeline::transfer_file(ctx, op, driver, entry).await,
                )?;
            }
            Op::CreateDir => {
                perform(ctx, &entry.dest, driver.create_dir(entry).await)?;
            }
            // Deletes are the reaper's job, and skips are not actions.
            Op::Delete | Op::Skip => {}
        }
    }
    Ok(())
}

/// Transfer every entry, then delete each source once its commit is durable.
///
/// The ordering lives in [`pipeline::move_file`], one file at a time, rather
/// than as two passes over the plan. Two passes would be measurably faster and
/// would also mean a run interrupted between them had copied everything and
/// deleted nothing — or, with the passes the other way round, the reverse. Per
/// file, the guarantee holds at every instant the process could be killed.
///
/// # Errors
/// Only a fatal failure; see [`transfers`].
pub async fn moves<D: StageDriver, R: Reaper>(
    ctx: &Ctx,
    op: &'static str,
    driver: &D,
    source_reaper: &R,
    plan: &Plan,
) -> Result<()> {
    for entry in plan.entries.iter().filter(|e| e.action.is_action()) {
        match entry.action {
            Op::Copy | Op::Update => {
                let outcome = pipeline::move_file(ctx, op, driver, source_reaper, entry).await;
                perform(ctx, &entry.dest, outcome)?;
            }
            Op::CreateDir => {
                perform(ctx, &entry.dest, driver.create_dir(entry).await)?;
            }
            Op::Delete | Op::Skip => {}
        }
    }
    Ok(())
}

/// Remove every entry the plan marks for deletion.
///
/// This is `sync`'s destructive half — the files that exist only at the
/// destination — so each removal is audited exactly like a transfer is, after
/// the deletion has been confirmed. A `sync` whose additions were provable and
/// whose deletions were not would leave the log describing the half of the run
/// nobody worries about.
///
/// # Errors
/// Only a fatal failure; see [`transfers`].
pub async fn deletions<R: Reaper>(
    ctx: &Ctx,
    op: &'static str,
    reaper: &R,
    plan: &Plan,
) -> Result<()> {
    for entry in plan.deletions() {
        let outcome = reaper.remove(&entry.dest).await;
        let succeeded = outcome.is_ok();

        // No size, no hash and no direction: a deletion stores nothing, hashes
        // nothing and moves no object bytes anywhere. The size the destination
        // *used* to be is not a fact this run measured, and an empty `direction`
        // is the format's spelling of "no bytes crossed a boundary" — which is
        // the truth about a removal and must not be dressed up as an egress.
        ctx.audit.record(
            &AuditEntry::new(op, sink::outcome(&outcome))
                .path(&entry.dest)
                .objects(1)
                .remote(reaper.remote()),
        )?;

        perform(ctx, &removal_subject(reaper, &entry.dest), outcome)?;
        if succeeded {
            ctx.stats.file_deleted();
        }
    }
    Ok(())
}

/// Fold one entry's outcome into the run's counters.
///
/// The family's whole failure policy, in one place. Public because
/// [`super::super::sync::execute`] interleaves transfers and deletions itself
/// under `--delete-during` and must apply exactly this policy rather than a
/// second, subtly different one.
///
/// `subject` is what a failure message names — a destination path for a
/// transfer, and a side-qualified path for a removal (see [`removal_subject`]).
///
/// # Errors
/// Re-raises a fatal error so the caller stops; a per-file error is recorded and
/// swallowed so the run continues.
pub fn perform(ctx: &Ctx, subject: &str, outcome: Result<()>) -> Result<()> {
    match outcome {
        Ok(()) => Ok(()),
        Err(error) => {
            if pipeline::is_fatal(&error) {
                return Err(error);
            }
            pipeline::record_failure(ctx, subject, &error);
            Ok(())
        }
    }
}

/// How a failed removal names what it could not remove.
///
/// Always says *which side*, because for `move` the difference is the whole
/// story: a failed destination write means the data did not arrive, while a
/// failed source removal means it arrived and there are now two copies. An
/// operator reading "could not delete a.txt" cannot tell those apart.
pub fn removal_subject<R: Reaper>(reaper: &R, path: &str) -> String {
    format!("{} {path}", reaper.target())
}

/// Record the skipped entries against the run's counters.
///
/// Called once, before execution, so the end-of-run summary reports what was
/// *considered* and not merely what was moved. "Skipped" in that report means
/// "proven identical", never "ignored" — which is why the number comes from the
/// plan rather than from a difference between two other counts.
pub fn account_for_skips(ctx: &Ctx, plan: &Plan) {
    // Declared as well as counted. The summary omits the Checks row entirely
    // while the total is zero, so a run that incremented `check_done` for every
    // comparison and never stated the total reported none of them — the work
    // was done, counted, and then invisible.
    //
    // The total is knowable exactly here because the plan is already complete:
    // every entry in it, skipped or not, is one comparison that has happened.
    let compared = plan.with_op(Op::Skip).count() + plan.actions().count();
    ctx.stats.set_total_checks(compared as u64);

    for _ in plan.with_op(Op::Skip) {
        ctx.stats.file_skipped();
        ctx.stats.check_done();
    }
    // Every action was compared too — the checks are what produced the plan.
    for _ in plan.actions() {
        ctx.stats.check_done();
    }
    ctx.progress
        // Zero when the plan cannot total itself: an aggregate bar with no
        // known length is drawn as indeterminate, which is the truthful
        // rendering of "we do not know how much this will move".
        .set_totals(
            plan.bytes_to_transfer().unwrap_or_default(),
            plan.transfers().count() as u64,
        );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::VerifyMode;
    use crate::commands::transfer::compare::ComparePolicy;
    use crate::commands::transfer::entry::Entry;
    use crate::commands::transfer::plan::PlanEntry;
    use crate::commands::transfer::plan::Policy;
    use crate::commands::transfer::testing::ctx;
    use crate::error::CliError;
    use crate::exit::ExitCode;
    use std::cell::RefCell;

    /// The remote the fake drivers claim to be connected to, so a record written
    /// during a test still carries a plausible one.
    const TEST_REMOTE: &str = "archive";

    /// The verb the tests drive the executor with.
    const TEST_OP: &str = "copy";

    /// A driver that records the paths it transferred, and can fail chosen ones.
    #[derive(Default)]
    struct Driver {
        transferred: RefCell<Vec<String>>,
        created: RefCell<Vec<String>>,
        fail: Vec<&'static str>,
        fatal: bool,
    }

    impl Driver {
        fn failing(paths: &[&'static str]) -> Self {
            Self {
                fail: paths.to_vec(),
                ..Self::default()
            }
        }

        fn fatal() -> Self {
            Self {
                fatal: true,
                ..Self::default()
            }
        }

        fn check(&self, entry: &PlanEntry) -> Result<()> {
            if self.fatal {
                return Err(CliError::new(ExitCode::VaultLocked, "locked"));
            }
            if self.fail.contains(&entry.dest.as_str()) {
                return Err(CliError::new(ExitCode::TemporaryError, "flaky"));
            }
            Ok(())
        }
    }

    impl StageDriver for Driver {
        async fn read(&self, entry: &PlanEntry) -> Result<()> {
            self.check(entry)
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
        async fn commit(&self, entry: &PlanEntry) -> Result<()> {
            self.transferred.borrow_mut().push(entry.dest.clone());
            Ok(())
        }
        async fn create_dir(&self, entry: &PlanEntry) -> Result<()> {
            self.created.borrow_mut().push(entry.dest.clone());
            Ok(())
        }
        fn remote(&self) -> &str {
            TEST_REMOTE
        }
        fn direction(&self) -> crate::audit::record::Direction {
            crate::audit::record::Direction::In
        }
        fn take_plaintext_hash(&self, _: &PlanEntry) -> String {
            String::new()
        }
    }

    #[derive(Default)]
    struct Sink {
        removed: RefCell<Vec<String>>,
    }

    impl Reaper for Sink {
        async fn remove(&self, path: &str) -> Result<()> {
            self.removed.borrow_mut().push(path.to_string());
            Ok(())
        }
        fn target(&self) -> &'static str {
            "destination"
        }
        fn remote(&self) -> &str {
            TEST_REMOTE
        }
    }

    fn plan_of(source: &[Entry], dest: &[Entry], policy: &Policy) -> Plan {
        Plan::compute(source, dest, policy).unwrap()
    }

    fn sync_policy() -> Policy {
        Policy::syncing(ComparePolicy {
            size_only: true,
            ..ComparePolicy::default()
        })
    }

    #[tokio::test]
    async fn transfers_run_every_copy_and_update() {
        let ctx = ctx(&[]);
        let plan = plan_of(
            &[
                Entry::file("a", 1),
                Entry::file("b", 2),
                Entry::file("c", 3),
            ],
            &[Entry::file("b", 9), Entry::file("c", 3)],
            &sync_policy(),
        );

        let driver = Driver::default();
        transfers(&ctx, TEST_OP, &driver, &plan).await.unwrap();

        // `a` is new, `b` differs in size, `c` is identical.
        assert_eq!(driver.transferred.borrow().as_slice(), ["a", "b"]);
        assert_eq!(ctx.stats.snapshot().files_done, 2);
    }

    #[tokio::test]
    async fn one_bad_file_does_not_abandon_the_run() {
        let ctx = ctx(&[]);
        let plan = plan_of(
            &[
                Entry::file("a", 1),
                Entry::file("bad", 1),
                Entry::file("c", 1),
            ],
            &[],
            &sync_policy(),
        );

        let driver = Driver::failing(&["bad"]);
        transfers(&ctx, TEST_OP, &driver, &plan).await.unwrap();

        assert_eq!(driver.transferred.borrow().as_slice(), ["a", "c"]);
        // …but the failure is never rolled up into success.
        assert_eq!(ctx.stats.snapshot().errors, 1);
        assert_eq!(ctx.outcome(), ExitCode::PartialFailure);
    }

    #[tokio::test]
    async fn a_fatal_failure_stops_the_run_immediately() {
        let ctx = ctx(&[]);
        let plan = plan_of(
            &[Entry::file("a", 1), Entry::file("b", 1)],
            &[],
            &sync_policy(),
        );

        let error = transfers(&ctx, TEST_OP, &Driver::fatal(), &plan)
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::VaultLocked);
        // A locked vault fails every remaining file identically; emitting one
        // error per file would bury the cause.
        assert_eq!(ctx.stats.snapshot().errors, 0);
    }

    #[tokio::test]
    async fn deletions_are_counted_only_when_they_happen() {
        let ctx = ctx(&[]);
        let plan = plan_of(
            &[],
            &[Entry::file("gone", 5), Entry::file("also", 6)],
            &sync_policy(),
        );

        let reaper = Sink::default();
        deletions(&ctx, TEST_OP, &reaper, &plan).await.unwrap();

        assert_eq!(reaper.removed.borrow().as_slice(), ["gone", "also"]);
        assert_eq!(ctx.stats.snapshot().files_deleted, 2);
    }

    #[tokio::test]
    async fn moves_delete_each_source_after_its_own_commit() {
        let ctx = ctx(&[]);
        let plan = plan_of(
            &[Entry::file("a", 1), Entry::file("b", 1)],
            &[],
            &sync_policy(),
        );

        let driver = Driver::default();
        let reaper = Sink::default();
        moves(&ctx, TEST_OP, &driver, &reaper, &plan).await.unwrap();

        assert_eq!(driver.transferred.borrow().as_slice(), ["a", "b"]);
        assert_eq!(reaper.removed.borrow().as_slice(), ["a", "b"]);
    }

    #[tokio::test]
    async fn a_failed_move_leaves_that_source_alone_and_continues() {
        let ctx = ctx(&[]);
        let plan = plan_of(
            &[Entry::file("ok", 1), Entry::file("bad", 1)],
            &[],
            &sync_policy(),
        );

        let driver = Driver::failing(&["bad"]);
        let reaper = Sink::default();
        moves(&ctx, TEST_OP, &driver, &reaper, &plan).await.unwrap();

        // The failed file's source survives; the successful one's does not.
        assert_eq!(reaper.removed.borrow().as_slice(), ["ok"]);
        assert_eq!(ctx.stats.snapshot().errors, 1);
    }

    #[tokio::test]
    async fn empty_directories_are_created_without_a_transfer() {
        let ctx = ctx(&[]);
        let plan = plan_of(
            &[Entry::empty_dir("empty"), Entry::file("a", 1)],
            &[],
            &Policy::syncing(ComparePolicy::default()).with_empty_src_dirs(true),
        );

        let driver = Driver::default();
        transfers(&ctx, TEST_OP, &driver, &plan).await.unwrap();

        assert_eq!(driver.created.borrow().as_slice(), ["empty"]);
        assert_eq!(driver.transferred.borrow().as_slice(), ["a"]);
    }

    #[test]
    fn a_declined_confirmation_is_a_cancellation_not_a_success() {
        // Exit 0 after doing nothing would be indistinguishable from exit 0
        // after doing the work.
        let ctx = ctx(&["--interactive"]);
        // No terminal under `cargo test`, so the prompt refuses rather than
        // hanging — which is itself the behaviour an unattended job needs.
        let error = confirm(&ctx, "delete 3 files from", "vault:old").unwrap_err();
        assert_ne!(error.code(), ExitCode::Success);
        assert!(error.hint().is_some());
    }

    #[test]
    fn force_approves_a_destructive_run_without_asking() {
        let ctx = ctx(&["--force"]);
        assert!(confirm(&ctx, "delete 3 files from", "vault:old").is_ok());
    }

    #[test]
    fn skips_are_accounted_for_before_execution() {
        // The summary has to say what was considered, not only what moved —
        // "skipped" means proven identical, and that is worth reporting.
        let ctx = ctx(&[]);
        let plan = plan_of(
            &[Entry::file("same", 4), Entry::file("new", 8)],
            &[Entry::file("same", 4)],
            &sync_policy(),
        );

        account_for_skips(&ctx, &plan);

        let snapshot = ctx.stats.snapshot();
        assert_eq!(snapshot.files_skipped, 1);
        assert_eq!(snapshot.checks_done, 2, "both files were compared");
        assert_eq!(snapshot.bytes_total, 8);
        assert_eq!(snapshot.files_total, 1);
    }
}
