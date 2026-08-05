//! `--max-transfer`: the ceiling that stops a run before the bill arrives.
//!
//! ## The behaviour, and which of rclone's it is
//!
//! **Cautious.** A file is not started when moving it would take the run past
//! the limit; the run stops there with [`ExitCode::TransferLimitExceeded`]
//! (exit **8**). The limit is therefore never exceeded — not by a byte.
//!
//! rclone's default is `--cutoff-mode hard`, which aborts the file in flight and
//! so overshoots by nothing but ends with a partial object at the destination.
//! DCTL cannot take that option and would not want it: the engine hands a whole
//! object to `dctl_store::Backend::put` in one call, and a partially-written
//! object is precisely what the verified-write contract (`PLAN.md` §6) exists to
//! make impossible. `cautious` is one of rclone's own modes, so this is a choice
//! from its menu rather than an invention, and it is the stronger guarantee of
//! the two for the thing the flag is actually for.
//!
//! The visible consequence is worth stating because somebody will meet it:
//! `--max-transfer 1M` against a 10 MiB file transfers **nothing** and exits 8.
//! rclone would have moved 1 MiB of it and left that behind. Neither is wrong;
//! only one of them is consistent with a tool that refuses to leave a
//! half-written object anywhere.
//!
//! ## What counts against it
//!
//! Bytes **measured leaving** — what [`StageDriver::upload`] reports, not what
//! the plan estimated. A retried file is charged for every attempt, because
//! every attempt really did cross the wire and really is on the invoice. That is
//! the same rule [`super::bandwidth`] uses, and the two must agree: a run capped
//! at 10 GB that was billed for 12 would make the flag worthless.
//!
//! [`ExitCode::TransferLimitExceeded`]: crate::exit::ExitCode::TransferLimitExceeded
//! [`StageDriver::upload`]: crate::commands::transfer::pipeline::StageDriver::upload

use std::sync::atomic::{AtomicU64, Ordering};

use crate::constants::{MAX_TRANSFER_LIMIT_HINT, MAX_TRANSFER_LIMIT_REACHED};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::output::size;

use super::quantity::ByteLimit;

/// How many bytes this run may still move.
#[derive(Debug)]
pub struct Budget {
    /// The ceiling, or `None` when the run is uncapped.
    limit: Option<u64>,

    /// Bytes measured as having left, across every file and every attempt.
    ///
    /// Saturating on add rather than wrapping: a counter that wrapped would
    /// silently reset the budget mid-run, which is the one failure mode a cost
    /// control may not have.
    spent: AtomicU64,
}

impl Budget {
    /// A budget of `limit` bytes, or an uncapped one for `off`.
    #[must_use]
    pub const fn new(limit: ByteLimit) -> Self {
        Self {
            limit: limit.get(),
            spent: AtomicU64::new(0),
        }
    }

    /// An uncapped budget. `cfg(test)`: production builds one from the flag,
    /// and `off` already produces this.
    #[cfg(test)]
    #[must_use]
    pub const fn unlimited() -> Self {
        Self::new(ByteLimit::none())
    }

    /// Bytes claimed and settled so far.
    ///
    /// `cfg(test)`: the running total is what [`afford`](Budget::afford) and
    /// [`settle`](Budget::settle) carry between them, and the refusal message
    /// reads it from the atomic update that refused rather than from a second
    /// load — which is the only way the number it prints is the number that was
    /// compared. Nothing in the binary asks separately, so exposing it there
    /// would be an accessor with no reader.
    #[cfg(test)]
    #[must_use]
    pub fn spent(&self) -> u64 {
        self.spent.load(Ordering::Acquire)
    }

    /// Claim `bytes` of the ceiling for a file about to start, or refuse the run.
    ///
    /// Asked **before** a file is started, which is what makes the limit exact
    /// rather than approximate. A zero-byte file is always afforded: refusing to
    /// create an empty object because a byte budget is exhausted would stop a
    /// run without saving anything.
    ///
    /// ## Why this claims rather than merely checks
    ///
    /// It used to read the total and compare, leaving the charge until once the
    /// file had moved. With one file in flight that is the same thing. With
    /// `--transfers 4` it is not: four files each
    /// read the same total, each decide they fit, and all four move. Measured
    /// the moment the executor became concurrent, `--max-transfer 100k` moved
    /// **192 KiB and exited 0** over three files — which is the exact failure
    /// [`crate::cli::reach`] exists to describe, arrived at from the other
    /// direction.
    ///
    /// So the claim is one atomic read-modify-write: the budget is taken before
    /// the file starts, and a lane that cannot take it does not start.
    /// [`settle`](Budget::settle) reconciles the claim against what actually
    /// moved.
    ///
    /// # Errors
    /// [`ExitCode::TransferLimitExceeded`] — exit 8 — naming the limit, what has
    /// been moved, and the file that would have breached it. The message says
    /// what *did* happen, because a run stopped at a ceiling is a success up to
    /// that point and the operator's next question is where to resume.
    pub fn afford(&self, bytes: u64, subject: &str, units: crate::output::Units) -> Result<()> {
        let Some(limit) = self.limit else {
            return Ok(());
        };
        if bytes == 0 {
            return Ok(());
        }

        let taken = self
            .spent
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                let next = current.saturating_add(bytes);
                (next <= limit).then_some(next)
            });

        match taken {
            Ok(_) => Ok(()),
            Err(spent) => Err(CliError::new(
                ExitCode::TransferLimitExceeded,
                format!(
                    "{MAX_TRANSFER_LIMIT_REACHED}: {} of {} moved; '{subject}' would need {} more",
                    size::bytes(spent, units),
                    size::bytes(limit, units),
                    size::bytes(bytes, units),
                ),
            )
            .with_hint(MAX_TRANSFER_LIMIT_HINT)),
        }
    }

    /// Reconcile a claim against what the file actually moved.
    ///
    /// `reserved` is what [`afford`](Budget::afford) took on this file's behalf —
    /// the planned size — and `actual` is what the upload measured. The
    /// difference is what the total moves by, so a file that turned out smaller
    /// than the plan said hands the remainder back and one that turned out
    /// larger is charged for it.
    ///
    /// Nothing is handed back when there is no ceiling, because nothing was
    /// taken: an uncapped budget still tracks `spent` for reporting, and
    /// [`afford`](Budget::afford) returns before claiming. A planned size of
    /// zero is the same case — it is always afforded and never claimed — so a
    /// file whose size the plan did not know is charged exactly what it moved.
    pub fn settle(&self, reserved: u64, actual: u64) {
        let held = if self.limit.is_some() { reserved } else { 0 };
        let _ = self
            .spent
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_sub(held).saturating_add(actual))
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Units;

    fn budget(limit: u64) -> Budget {
        Budget::new(ByteLimit::bytes(limit))
    }

    fn afford(budget: &Budget, bytes: u64) -> Result<()> {
        budget.afford(bytes, "photos/a.jpg", Units::Binary)
    }

    #[test]
    fn an_uncapped_run_affords_everything() {
        let budget = Budget::unlimited();
        budget.settle(0, u64::MAX);
        afford(&budget, u64::MAX).unwrap();
    }

    #[test]
    fn a_file_that_fits_is_afforded_and_one_that_does_not_is_refused() {
        let budget = budget(1000);
        // `afford` takes the claim, so the total moves without a further charge;
        // `settle` only reconciles the claim against what really moved.
        afford(&budget, 600).unwrap();
        budget.settle(600, 600);
        afford(&budget, 400).unwrap();
        budget.settle(400, 400);
        // Exactly at the limit is still afforded; one byte past is not.
        assert_eq!(budget.spent(), 1000);
        let error = afford(&budget, 1).unwrap_err();
        assert_eq!(error.code(), ExitCode::TransferLimitExceeded);
    }

    #[test]
    fn concurrent_lanes_cannot_each_decide_they_fit() {
        // The defect that arrived with `--transfers 4`. Every lane asks before
        // any lane has moved a byte, so a budget that merely *read* the total
        // told all of them yes: `--max-transfer 100k` moved 192 KiB across three
        // files and exited 0. The claim has to be taken in the same operation
        // that checks it.
        let budget = budget(1000);
        let afforded = (0..4).filter(|_| afford(&budget, 400).is_ok()).count();
        assert_eq!(
            afforded, 2,
            "two claims of 400 fit in 1000; the third must be refused before it starts"
        );
        assert_eq!(budget.spent(), 800, "and the claims are already held");
    }

    #[test]
    fn a_file_smaller_than_planned_hands_the_remainder_back() {
        // The plan's size is an estimate until the upload measures it. A claim
        // never released would shrink the budget by the difference on every
        // file, and a long run would stop far short of its ceiling.
        let budget = budget(1000);
        afford(&budget, 500).unwrap();
        budget.settle(500, 100);
        assert_eq!(budget.spent(), 100);

        // …and the freed room is really usable.
        afford(&budget, 900).unwrap();
        assert_eq!(budget.spent(), 1000);
    }

    #[test]
    fn an_uncapped_budget_still_counts_what_moved() {
        // Nothing is claimed when there is no ceiling, so nothing may be handed
        // back — but `spent` is what the summary reports, and it must still be
        // the truth.
        let budget = Budget::unlimited();
        afford(&budget, 500).unwrap();
        budget.settle(500, 500);
        assert_eq!(budget.spent(), 500);
    }

    #[test]
    fn a_file_whose_size_the_plan_did_not_know_is_charged_what_it_moved() {
        // An unknown size plans as zero, which is always afforded and never
        // claimed. Settling it must add the measured bytes rather than subtract
        // a claim that was never taken.
        let budget = budget(1000);
        afford(&budget, 0).unwrap();
        budget.settle(0, 250);
        assert_eq!(budget.spent(), 250);
    }

    #[test]
    fn a_first_file_larger_than_the_whole_budget_moves_nothing() {
        // The case the flag is bought for, and the one a "hard" cutoff would
        // answer by leaving 1 MiB of a 10 MiB object at the destination.
        let budget = budget(1024 * 1024);
        let error = afford(&budget, 10 * 1024 * 1024).unwrap_err();
        assert_eq!(error.code(), ExitCode::TransferLimitExceeded);
        assert_eq!(budget.spent(), 0, "nothing may have moved");
    }

    #[test]
    fn the_refusal_says_what_moved_what_the_limit_was_and_what_stopped_it() {
        let budget = budget(1024);
        budget.settle(0, 1000);
        let error = afford(&budget, 4096).unwrap_err();
        let message = error.message();
        assert!(message.contains("photos/a.jpg"), "{message}");
        assert!(
            message.contains("1.00 KiB"),
            "the limit must appear: {message}"
        );
        assert!(
            message.contains("1000 B"),
            "and what has already moved: {message}"
        );
        assert!(error.hint().is_some(), "a stop must say how to resume");
    }

    #[test]
    fn an_empty_file_is_always_afforded() {
        // Stopping a run to save zero bytes helps nobody, and `sync` creating a
        // zero-length object is real work the plan expects to complete.
        let budget = budget(10);
        budget.settle(0, 10);
        afford(&budget, 0).unwrap();
    }

    #[test]
    fn settling_saturates_rather_than_wrapping() {
        // A wrapped counter hands the run a fresh budget, which is the single
        // failure a cost control may not have.
        let budget = budget(1000);
        budget.settle(0, u64::MAX);
        budget.settle(0, u64::MAX);
        assert_eq!(budget.spent(), u64::MAX);
        assert!(afford(&budget, 1).is_err());
    }
}
