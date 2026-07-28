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

    /// Bytes measured as moved so far.
    #[must_use]
    pub fn spent(&self) -> u64 {
        self.spent.load(Ordering::Relaxed)
    }

    /// Record `bytes` as having left.
    pub fn spend(&self, bytes: u64) {
        // `fetch_update` rather than `fetch_add` so the saturation is real: a
        // plain add would wrap at `u64::MAX` and hand the run a fresh budget.
        let _ = self
            .spent
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(bytes))
            });
    }

    /// Refuse the run when moving `bytes` next would breach the ceiling.
    ///
    /// Asked **before** a file is started, which is what makes the limit exact
    /// rather than approximate. A zero-byte file is always afforded: refusing to
    /// create an empty object because a byte budget is exhausted would stop a
    /// run without saving anything.
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

        let spent = self.spent();
        if spent.saturating_add(bytes) <= limit {
            return Ok(());
        }

        Err(CliError::new(
            ExitCode::TransferLimitExceeded,
            format!(
                "{MAX_TRANSFER_LIMIT_REACHED}: {} of {} moved; '{subject}' would need {} more",
                size::bytes(spent, units),
                size::bytes(limit, units),
                size::bytes(bytes, units),
            ),
        )
        .with_hint(MAX_TRANSFER_LIMIT_HINT))
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
        budget.spend(u64::MAX);
        afford(&budget, u64::MAX).unwrap();
    }

    #[test]
    fn a_file_that_fits_is_afforded_and_one_that_does_not_is_refused() {
        let budget = budget(1000);
        afford(&budget, 600).unwrap();
        budget.spend(600);
        afford(&budget, 400).unwrap();
        budget.spend(400);
        // Exactly at the limit is still afforded; one byte past is not.
        assert_eq!(budget.spent(), 1000);
        let error = afford(&budget, 1).unwrap_err();
        assert_eq!(error.code(), ExitCode::TransferLimitExceeded);
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
        budget.spend(1000);
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
        budget.spend(10);
        afford(&budget, 0).unwrap();
    }

    #[test]
    fn spending_saturates_rather_than_wrapping() {
        // A wrapped counter hands the run a fresh budget, which is the single
        // failure a cost control may not have.
        let budget = budget(1000);
        budget.spend(u64::MAX);
        budget.spend(u64::MAX);
        assert_eq!(budget.spent(), u64::MAX);
        assert!(afford(&budget, 1).is_err());
    }
}
