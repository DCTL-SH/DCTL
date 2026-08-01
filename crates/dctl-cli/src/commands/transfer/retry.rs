//! `--retries`: repeating a file that failed for a reason a repeat can fix.
//!
//! The flag's own help has always said "retries of a whole failed file", and
//! that is what this implements — DCTL's documented contract rather than
//! rclone's, whose `--retries` re-runs the entire operation. A per-file retry is
//! the stronger of the two here: `sync` is incremental, so a whole-run repeat
//! would re-list both sides to discover the one file that failed, and would
//! append a second set of audit records describing work that had already
//! succeeded.
//!
//! Until now nothing read the flag. The end-of-run summary has carried a
//! *Retries* row since it was written, and the counter behind it could never be
//! anything but zero.
//!
//! ## Which failures are repeated, and why the list is exhaustive
//!
//! [`is_worth_repeating`] matches on every [`ExitCode`] with no wildcard arm, so
//! adding a code to the contract forces a decision about it here rather than
//! defaulting it into silence. Two are repeated:
//!
//! * [`ExitCode::TemporaryError`] — a reset connection, a 503, a dropped ssh
//!   session. `dctl_store` classifies every backend failure into this, so it is
//!   the code a transient really arrives as.
//! * [`ExitCode::ChecksumMismatch`] — the destination stored something other
//!   than what was sent. It is repeated because that is overwhelmingly a
//!   corrupted transfer rather than a corrupt provider, and because nothing was
//!   committed: the verified write refused, so a second attempt starts from
//!   exactly the same place. rclone treats it the same way. A mismatch that
//!   survives every attempt still ends the file at exit 20, and the *Retries*
//!   row is what shows the destination needed persuading.
//!
//! Everything else is not repeated, and the interesting refusals are worth
//! naming. [`ExitCode::IntegrityFailure`] means AEAD authentication failed:
//! those bytes will not authenticate on the second read either, and repeating
//! would burn egress to confirm damage that has already been detected.
//! [`ExitCode::FileNotFound`] will not find the file next time.
//! [`ExitCode::TransferLimitExceeded`] is the run being *stopped on purpose*.
//!
//! ## No sleep between attempts
//!
//! Matching rclone, whose `--retries-sleep` defaults to zero. The layer that
//! genuinely needs backoff is the request layer, and B2's has its own schedule
//! with `Retry-After` honoured. Introducing an unrequested delay here would slow
//! every failing run without a flag to turn it off.

use crate::ctx::Ctx;
use crate::error::CliError;
use crate::exit::ExitCode;
use crate::logging::fields;

/// Whether a failed file should be attempted again.
///
/// Exhaustive by construction: no wildcard arm, so a new exit code cannot be
/// added to the contract without someone deciding whether it is transient.
#[must_use]
pub const fn is_worth_repeating(error: &CliError) -> bool {
    match error.code() {
        // Transient by definition, and what every backend failure classifies as.
        ExitCode::TemporaryError => true,
        // Nothing was committed; the wire is the likely culprit. See the docs.
        ExitCode::ChecksumMismatch => true,

        // Deterministic: the same input produces the same answer.
        ExitCode::Success
        | ExitCode::Usage
        | ExitCode::Uncategorised
        | ExitCode::DirNotFound
        | ExitCode::FileNotFound
        | ExitCode::PartialFailure
        | ExitCode::FatalError
        | ExitCode::NoFilesTransferred
        | ExitCode::IntegrityFailure
        | ExitCode::VaultLocked
        | ExitCode::IndexError
        | ExitCode::AuditChainBroken
        // An anchor that does not match the log will not match it on a second
        // look either, and this code is produced by `dctl audit verify` rather
        // than by any transfer — repeating a file on the strength of it would be
        // retrying somebody else's finding.
        | ExitCode::AuditHeadMismatch
        // A remote that records no digest a re-read could be compared against
        // will record none on the next attempt either. This code is produced by
        // `verify` and `scrub` rather than by any transfer, so repeating a file
        // on the strength of it would be retrying somebody else's finding.
        | ExitCode::VerificationNotPossible
        // The run has already spent a whole schedule of attempts on a link that
        // answered nothing, and stopped. Repeating the file cannot reach it —
        // every call refuses before it opens a connection — so a repeat here
        // would add a *Retries* count and a log line over requests that were
        // never made, which is the class `PLAN.md` §6 forbids.
        | ExitCode::LinkSilent => false,

        // The run was stopped deliberately. Repeating either of these would be
        // working around the operator rather than for them.
        ExitCode::TransferLimitExceeded | ExitCode::DurationLimitExceeded | ExitCode::Cancelled => {
            false
        }
    }
}

/// How many attempts a file gets, from `--retries`.
///
/// One more than the retry count: `--retries 3` means the original attempt plus
/// three repeats. `--retries 0` therefore still tries once, which is what
/// "do not retry" means and is not the same as "do nothing".
#[must_use]
pub fn attempts(ctx: &Ctx) -> u32 {
    ctx.globals.retries.saturating_add(1)
}

/// Note that an attempt is being repeated, on the counters and in the log.
///
/// Centralised so the summary's *Retries* row and the log record can never
/// disagree about how many repeats happened, and so a repeat is never silent:
/// a run that quietly retried a hundred files looks identical to a healthy one
/// in every output, which is how a failing disk stays undiagnosed for months.
pub fn note(ctx: &Ctx, path: &str, attempt: u32, error: &CliError) {
    ctx.stats.retry();
    tracing::warn!(
        { fields::PATH } = path,
        { fields::ERROR_CODE } = error.code().slug(),
        attempt,
        "retrying"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::transfer::testing::ctx;

    fn error(code: ExitCode) -> CliError {
        CliError::new(code, "boom")
    }

    #[test]
    fn a_transient_failure_is_repeated() {
        assert!(is_worth_repeating(&error(ExitCode::TemporaryError)));
    }

    #[test]
    fn a_checksum_mismatch_is_repeated_because_nothing_was_committed() {
        assert!(is_worth_repeating(&error(ExitCode::ChecksumMismatch)));
    }

    #[test]
    fn a_deterministic_failure_is_not_repeated() {
        for code in [
            ExitCode::FileNotFound,
            ExitCode::DirNotFound,
            ExitCode::Usage,
            ExitCode::FatalError,
            ExitCode::VaultLocked,
            ExitCode::IndexError,
            ExitCode::AuditChainBroken,
            // AEAD authentication failed: the bytes are wrong, and reading them
            // again costs egress to learn the same thing.
            ExitCode::IntegrityFailure,
        ] {
            assert!(!is_worth_repeating(&error(code)), "{code:?}");
        }
    }

    #[test]
    fn a_deliberate_stop_is_never_worked_around() {
        for code in [
            ExitCode::TransferLimitExceeded,
            ExitCode::DurationLimitExceeded,
            ExitCode::Cancelled,
        ] {
            assert!(!is_worth_repeating(&error(code)), "{code:?}");
        }
    }

    #[test]
    fn a_run_that_stopped_asking_is_never_repeated_into() {
        // The run has already spent a whole schedule of attempts on a link that
        // answered nothing. Every call now refuses before it opens a
        // connection, so a repeat would add a *Retries* count and a log line
        // over requests that were never made — a report of work that did not
        // happen, which is the class `PLAN.md` §6 forbids and the exact defect
        // the *Retries* row was built to stop telling.
        //
        // This is also why `dctl_store::StoreError::Stalled` does not map to
        // exit 5: 5 IS repeated here, correctly, and a stalled run wearing it
        // would repeat every remaining file `--retries` times.
        assert!(!is_worth_repeating(&error(ExitCode::LinkSilent)));
        assert!(
            is_worth_repeating(&error(ExitCode::TemporaryError)),
            "and the ordinary transient must still be repeated, or this bound \
             has been bought by breaking the flag it sits next to"
        );
    }

    #[test]
    fn the_attempt_count_is_the_retry_count_plus_the_original() {
        assert_eq!(attempts(&ctx(&["--retries", "3"])), 4);
        // Zero retries still means one attempt: the file is transferred, just
        // never repeated.
        assert_eq!(attempts(&ctx(&["--retries", "0"])), 1);
    }

    #[test]
    fn a_noted_retry_moves_the_counter_the_summary_reads() {
        let ctx = ctx(&[]);
        assert_eq!(ctx.stats.snapshot().retries, 0);
        note(&ctx, "a.jpg", 1, &error(ExitCode::TemporaryError));
        note(&ctx, "a.jpg", 2, &error(ExitCode::TemporaryError));
        assert_eq!(ctx.stats.snapshot().retries, 2);
    }
}
