//! Running a `sync` plan — and, specifically, *when* the deletions happen.
//!
//! `sync` is the only verb in the family that both adds and removes, so it is
//! the only one where ordering is a user-visible choice. The three modes are
//! rclone's, and each is the right answer to a different question:
//!
//! | mode | ordering | choose it when |
//! |------|----------|----------------|
//! | [`DeleteMode::Before`] | every delete, then every transfer | the destination is nearly full and cannot hold both copies |
//! | [`DeleteMode::During`] | interleaved, in plan order | the default — bounded peak usage without a long delete-only phase |
//! | [`DeleteMode::After`]  | every transfer, then every delete | the destination is the only copy: nothing is removed until every replacement is durably committed |
//!
//! The trade is the same one in every direction. `Before` guarantees the
//! destination never needs room for the old and new copies at once, and is the
//! only mode where an interrupted run can leave the destination holding
//! *neither*. `After` guarantees an interrupted run leaves a superset — never a
//! gap — and is the only mode that needs room for both. `During` sits between
//! them, which is why it is the default.
//!
//! Whatever the mode, the plan is fixed before any of this runs. The executor
//! reorders the entries it was given; it never recomputes them, so the list a
//! `--dry-run` printed is the list that gets performed.

use crate::audit::record::Entry as AuditEntry;
use crate::audit::sink;
use crate::constants::TRANSFER_COMMAND_SYNC;
use crate::ctx::Ctx;
use crate::error::Result;

use crate::commands::transfer::DeleteMode;
use crate::commands::transfer::execute as shared;
use crate::commands::transfer::pipeline::{self, Reaper, StageDriver};
use crate::commands::transfer::plan::{Op, Plan};

/// Execute a sync plan in the requested deletion order.
///
/// # Errors
/// Only a fatal failure stops the run; per-file failures are counted and
/// reported, and downgrade the process exit code through
/// [`Ctx::outcome`](crate::ctx::Ctx::outcome).
pub async fn run<D: StageDriver, R: Reaper>(
    ctx: &Ctx,
    driver: &D,
    reaper: &R,
    plan: &Plan,
    mode: DeleteMode,
) -> Result<()> {
    match mode {
        DeleteMode::Before => {
            shared::deletions(ctx, TRANSFER_COMMAND_SYNC, reaper, plan).await?;
            shared::transfers(ctx, TRANSFER_COMMAND_SYNC, driver, plan).await
        }
        DeleteMode::After => {
            shared::transfers(ctx, TRANSFER_COMMAND_SYNC, driver, plan).await?;
            shared::deletions(ctx, TRANSFER_COMMAND_SYNC, reaper, plan).await
        }
        DeleteMode::During => interleaved(ctx, driver, reaper, plan).await,
    }
}

/// Walk the plan once, performing each entry as it comes.
///
/// Plan order is destination-path order for the transfers followed by the
/// deletions, which is close enough to "as the tree is walked" to keep peak
/// destination usage bounded without the bookkeeping of a true streaming diff —
/// and, unlike a streaming diff, it is a fixed list that was printed and
/// approved before the first byte moved.
async fn interleaved<D: StageDriver, R: Reaper>(
    ctx: &Ctx,
    driver: &D,
    reaper: &R,
    plan: &Plan,
) -> Result<()> {
    for entry in plan.entries.iter().filter(|entry| entry.action.is_action()) {
        match entry.action {
            Op::Copy | Op::Update => {
                let outcome =
                    pipeline::transfer_file(ctx, TRANSFER_COMMAND_SYNC, driver, entry).await;
                shared::perform(ctx, &entry.dest, outcome)?;
            }
            Op::CreateDir => {
                let outcome = driver.create_dir(entry).await;
                shared::perform(ctx, &entry.dest, outcome)?;
            }
            Op::Delete => {
                let outcome = reaper.remove(&entry.dest).await;
                let removed = outcome.is_ok();
                // The same record `shared::deletions` writes for the other two
                // modes. Interleaving changes when a deletion happens, never
                // whether it is attested — a mode that quietly stopped recording
                // them would make `--delete-during`, the *default*, the one
                // ordering with no evidence behind it.
                ctx.audit.record(
                    &AuditEntry::new(TRANSFER_COMMAND_SYNC, sink::outcome(&outcome))
                        .path(&entry.dest)
                        .objects(1)
                        .remote(Reaper::remote(reaper)),
                )?;
                shared::perform(ctx, &shared::removal_subject(reaper, &entry.dest), outcome)?;
                if removed {
                    ctx.stats.file_deleted();
                }
            }
            Op::Skip => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::VerifyMode;
    use crate::commands::transfer::compare::ComparePolicy;
    use crate::commands::transfer::entry::Entry;
    use crate::commands::transfer::plan::{PlanEntry, Policy};
    use crate::commands::transfer::testing::ctx;
    use crate::error::CliError;
    use crate::exit::ExitCode;
    use std::cell::RefCell;

    /// One shared log, so the *relative* order of transfers and deletions is
    /// observable — which is the only thing the delete modes change.
    #[derive(Default)]
    struct Journal {
        events: RefCell<Vec<String>>,
    }

    impl Journal {
        fn note(&self, event: String) {
            self.events.borrow_mut().push(event);
        }
        fn events(&self) -> Vec<String> {
            self.events.borrow().clone()
        }
    }

    struct Driver<'a>(&'a Journal);
    struct Sink<'a>(&'a Journal);

    /// The remote the fake driver and reaper claim to be connected to.
    const TEST_REMOTE: &str = "archive";

    impl StageDriver for Driver<'_> {
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
        async fn commit(&self, entry: &PlanEntry) -> Result<()> {
            self.0.note(format!("copy {}", entry.dest));
            Ok(())
        }
        async fn create_dir(&self, entry: &PlanEntry) -> Result<()> {
            self.0.note(format!("mkdir {}", entry.dest));
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

    impl Reaper for Sink<'_> {
        async fn remove(&self, path: &str) -> Result<()> {
            self.0.note(format!("delete {path}"));
            Ok(())
        }
        fn target(&self) -> &'static str {
            "destination"
        }
        fn remote(&self) -> &str {
            TEST_REMOTE
        }
    }

    /// One new file at the source, one extra at the destination.
    fn plan() -> Plan {
        Plan::compute(
            &[Entry::file("new.txt", 10)],
            &[Entry::file("stale.txt", 20)],
            &Policy::syncing(ComparePolicy::default()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn delete_before_removes_everything_first() {
        let ctx = ctx(&[]);
        let journal = Journal::default();
        run(
            &ctx,
            &Driver(&journal),
            &Sink(&journal),
            &plan(),
            DeleteMode::Before,
        )
        .await
        .unwrap();

        assert_eq!(journal.events(), ["delete stale.txt", "copy new.txt"]);
    }

    #[tokio::test]
    async fn delete_after_removes_nothing_until_every_transfer_is_committed() {
        // The safe ordering: an interrupted run leaves a superset, never a gap.
        let ctx = ctx(&[]);
        let journal = Journal::default();
        run(
            &ctx,
            &Driver(&journal),
            &Sink(&journal),
            &plan(),
            DeleteMode::After,
        )
        .await
        .unwrap();

        assert_eq!(journal.events(), ["copy new.txt", "delete stale.txt"]);
    }

    #[tokio::test]
    async fn delete_during_follows_plan_order() {
        let ctx = ctx(&[]);
        let journal = Journal::default();
        run(
            &ctx,
            &Driver(&journal),
            &Sink(&journal),
            &plan(),
            DeleteMode::During,
        )
        .await
        .unwrap();

        // Transfers come first in plan order, deletions are appended.
        assert_eq!(journal.events(), ["copy new.txt", "delete stale.txt"]);
    }

    #[tokio::test]
    async fn every_mode_performs_exactly_the_planned_actions() {
        // Reordering is the only freedom a mode has; the set is fixed.
        for mode in [DeleteMode::Before, DeleteMode::During, DeleteMode::After] {
            let ctx = ctx(&[]);
            let journal = Journal::default();
            run(&ctx, &Driver(&journal), &Sink(&journal), &plan(), mode)
                .await
                .unwrap();

            let mut events = journal.events();
            events.sort();
            assert_eq!(events, ["copy new.txt", "delete stale.txt"], "{mode:?}");

            let snapshot = ctx.stats.snapshot();
            assert_eq!(snapshot.files_done, 1, "{mode:?}");
            assert_eq!(snapshot.files_deleted, 1, "{mode:?}");
        }
    }

    #[tokio::test]
    async fn a_failed_deletion_is_counted_but_never_counted_as_done() {
        struct Failing;
        impl Reaper for Failing {
            async fn remove(&self, _: &str) -> Result<()> {
                Err(CliError::new(ExitCode::TemporaryError, "provider said no"))
            }
            fn target(&self) -> &'static str {
                "destination"
            }
            fn remote(&self) -> &str {
                TEST_REMOTE
            }
        }

        let ctx = ctx(&[]);
        let journal = Journal::default();
        run(
            &ctx,
            &Driver(&journal),
            &Failing,
            &plan(),
            DeleteMode::During,
        )
        .await
        .unwrap();

        let snapshot = ctx.stats.snapshot();
        assert_eq!(snapshot.files_deleted, 0, "nothing was actually removed");
        assert_eq!(snapshot.errors, 1);
        assert_eq!(ctx.outcome(), ExitCode::PartialFailure);
    }

    #[tokio::test]
    async fn empty_source_directories_are_created_in_every_mode() {
        let plan = Plan::compute(
            &[Entry::empty_dir("empty")],
            &[],
            &Policy::syncing(ComparePolicy::default()).with_empty_src_dirs(true),
        )
        .unwrap();

        for mode in [DeleteMode::Before, DeleteMode::During, DeleteMode::After] {
            let ctx = ctx(&[]);
            let journal = Journal::default();
            run(&ctx, &Driver(&journal), &Sink(&journal), &plan, mode)
                .await
                .unwrap();
            assert_eq!(journal.events(), ["mkdir empty"], "{mode:?}");
        }
    }
}
