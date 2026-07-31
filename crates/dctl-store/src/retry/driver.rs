//! The loop: run an operation, ask [`verdict`] whether to run it again, wait,
//! and report honestly however it ends.
//!
//! The only part of this module tree that sleeps, and the only part that keeps
//! state. Everything it decides was decided by a pure function it called.
//!
//! # The count is the point
//!
//! An operation that failed once and was classified as permanent returns its
//! error **unchanged** — same variant, same message, no claim about retrying.
//! An operation that really was tried more than once returns
//! [`StoreError::Retried`] carrying the number of attempts and the failure
//! underneath it.
//!
//! That is not bookkeeping. Every backend failure used to reach the operator
//! with the hint *"Retries were exhausted"* over a run that had made exactly one
//! attempt in ten milliseconds — a sentence describing work that did not happen,
//! which is the class `PLAN.md` §6 forbids outright, and the worse kind of false
//! because it tells somebody the tool has already done the thing they would
//! otherwise go and do. The hint is now worded from this number.

use std::future::Future;
use std::time::Duration;

use crate::deadline::RunDeadline;
use crate::error::{Result, StoreError};

use super::backoff;
use super::classify::{Verdict, verdict};
use super::policy::RetryPolicy;

/// Run `operation` until it succeeds, until another attempt cannot help, until
/// the budget is spent, or until the run's own deadline passes — whichever
/// comes first.
///
/// `op` names the operation in the log line each retry emits, which is what
/// makes a slow run explicable afterwards. `attempt` is handed the 1-based
/// attempt number so a caller that must do something different on a retry can
/// see that it is one.
///
/// # `deadline` is why this layer is the one §11.3 item 2 names
///
/// `--timeout` bounds one attempt. This loop is what multiplies it: six attempts
/// with exponential backoff, run in full by each of the several distinct
/// requests one copy makes, and multiplied again by `--retries`. §32.9 measured
/// the product — a black-holed 160 MiB upload under `--timeout 30 --retries 1`
/// had **not ended 943.6 s after the cut**. Nothing in that arithmetic is a bug;
/// what was missing was a term that could end it. `deadline` is that term, and
/// it acts twice: a wait is never longer than what is left of the run, and an
/// attempt is never *begun* once the window has closed.
///
/// [`RunDeadline::unbounded`] restores exactly the previous behaviour, which is
/// what a run with no `--max-duration` gets — the same default rclone has
/// (`fs/config.go:361`).
///
/// # Errors
/// The last failure, wrapped in [`StoreError::Retried`] when more than one
/// attempt was made; or [`StoreError::RunDeadline`] when the run's window closed
/// before another attempt could be made.
pub async fn run<T, A, F>(
    op: &'static str,
    policy: RetryPolicy,
    deadline: RunDeadline,
    mut attempt: A,
) -> Result<T>
where
    A: FnMut(u32) -> F,
    F: Future<Output = Result<T>>,
{
    let mut number = 1u32;
    let mut waited = Duration::ZERO;
    loop {
        // Asked before the attempt and not only before the retry, because the
        // first request of an operation is as much work as the sixth. A run
        // whose window has closed must not open another connection — that is
        // precisely what "the run continued 943.6 s past the cut" was made of.
        //
        // The exception is the very first attempt of the very first operation
        // in a run whose deadline was already zero, and it is not an exception
        // worth carving out: `--max-duration 0` means unbounded, so a spent
        // window here is always a run that really has used its time.
        if let Some(exceeded) = deadline.exceeded() {
            tracing::debug!(
                op,
                attempts = number.saturating_sub(1),
                "the run's deadline passed; no further attempt was made"
            );
            return Err(exceeded.into_store_error());
        }

        match attempt(number).await {
            Ok(value) => {
                if number > 1 {
                    tracing::info!(
                        op,
                        attempts = number,
                        waited_ms = waited.as_millis(),
                        "request succeeded on a retry"
                    );
                }
                return Ok(value);
            }
            Err(error) => {
                let observed = super::observed::Observed::of(&error);
                match verdict(&observed, number, waited, &policy) {
                    Verdict::Never => {
                        tracing::debug!(
                            op,
                            attempts = number,
                            status = observed.status,
                            "request will not be retried"
                        );
                        return Err(record(error, number));
                    }
                    Verdict::After(scheduled) => {
                        // A `Retry-After` the server sent is obeyed exactly; only
                        // the client's own schedule is spread. See
                        // [`super::backoff`] for why shortening a server's
                        // number is how a rate limit becomes a ban.
                        let delay = if observed.retry_after.is_some() {
                            scheduled
                        } else {
                            backoff::jittered(scheduled, backoff::entropy())
                        };
                        // Never longer than what is left of the run. A two-minute
                        // backoff begun with thirty seconds of the window left is
                        // ninety seconds of a run that was supposed to be over,
                        // and the check at the top of the loop would then refuse
                        // the attempt this wait was for.
                        let delay = deadline.shorten(Some(delay)).unwrap_or(delay);
                        // WARN, not DEBUG. A retried request is the difference
                        // between a backup that took twenty minutes and one that
                        // took two hours, and an operator diagnosing the second
                        // must not have to raise the log level to discover it
                        // happened.
                        tracing::warn!(
                            op,
                            attempt = number,
                            of = policy.max_attempts,
                            status = observed.status,
                            code = observed.code.as_deref(),
                            delay_ms = delay.as_millis(),
                            error = %error,
                            "request failed for a reason that may not last; retrying"
                        );
                        tokio::time::sleep(delay).await;
                        waited = waited.saturating_add(delay);
                        number = number.saturating_add(1);
                    }
                }
            }
        }
    }
}

/// Attach the attempt count to a failure, and only when there is one to attach.
///
/// One attempt is not a retry, and wrapping it would put a retry-shaped claim on
/// an error that was never retried — the same misreport in the other direction.
/// An error that already carries a count keeps the one it came with, because
/// that layer's number is the true one: this layer, by
/// [`verdict`](super::classify::verdict)'s first rule, made no further attempt.
fn record(error: StoreError, attempts: u32) -> StoreError {
    if attempts <= 1 || matches!(error, StoreError::Retried { .. }) {
        return error;
    }
    StoreError::Retried {
        attempts,
        source: Box::new(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A policy that retries as usual but never actually waits, so the suite
    /// spends no wall-clock time on a schedule this module's siblings already
    /// assert exactly.
    fn instant() -> RetryPolicy {
        RetryPolicy {
            first_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            ..RetryPolicy::network()
        }
    }

    fn busy() -> StoreError {
        StoreError::Provider {
            backend: "s3",
            status: 503,
            code: "SlowDown".to_string(),
            retry_after_secs: None,
        }
    }

    #[tokio::test]
    async fn the_driver_returns_the_first_success_and_counts_its_attempts() {
        let calls = AtomicU32::new(0);
        let value = run("test", instant(), RunDeadline::unbounded(), |number| {
            let seen = calls.fetch_add(1, Ordering::SeqCst) + 1;
            async move { if seen < 3 { Err(busy()) } else { Ok(number) } }
        })
        .await
        .expect("the third attempt succeeds");

        assert_eq!(value, 3, "the closure is told which attempt it is");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_permanent_failure_is_attempted_once_and_says_nothing_about_retries() {
        // The exact defect: an sftp connection failure reached the operator
        // claiming exhausted retries over a run that made one attempt. An error
        // that was never retried must carry no retry record at all.
        let calls = AtomicU32::new(0);
        let error = run("test", instant(), RunDeadline::unbounded(), |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async {
                Err::<(), _>(StoreError::Provider {
                    backend: "b2",
                    status: 401,
                    code: "bad_auth_token".to_string(),
                    retry_after_secs: None,
                })
            }
        })
        .await
        .expect_err("a wrong key cannot succeed");

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a permanent failure must be attempted exactly once"
        );
        assert_eq!(
            error.attempts(),
            None,
            "no retry happened, so none is claimed"
        );
        assert!(error.to_string().contains("bad_auth_token"));
    }

    #[tokio::test]
    async fn an_exhausted_budget_reports_the_number_of_attempts_it_really_made() {
        let policy = instant();
        let calls = AtomicU32::new(0);
        let error = run("test", policy, RunDeadline::unbounded(), |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err::<(), _>(busy()) }
        })
        .await
        .expect_err("a permanently busy provider cannot succeed");

        assert_eq!(calls.load(Ordering::SeqCst), policy.max_attempts);
        assert_eq!(error.attempts(), Some(policy.max_attempts));
        // The failure underneath is untouched, so the exit code and the message
        // an operator acts on are the provider's own.
        assert_eq!(error.code(), busy().code());
        assert!(error.to_string().contains("SlowDown"), "{error}");
    }

    #[tokio::test]
    async fn an_error_a_lower_layer_already_retried_is_attempted_once_and_keeps_its_count() {
        // B2 retries at the request level; this layer must not spend a second
        // budget on the same failure, and the number reported must stay the one
        // that was actually made rather than becoming a product of two
        // schedules.
        let calls = AtomicU32::new(0);
        let error = run("test", instant(), RunDeadline::unbounded(), |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async {
                Err::<(), _>(StoreError::Retried {
                    attempts: 6,
                    source: Box::new(busy()),
                })
            }
        })
        .await
        .expect_err("still busy");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(error.attempts(), Some(6));
    }

    #[tokio::test]
    async fn a_policy_of_one_attempt_makes_exactly_one() {
        let calls = AtomicU32::new(0);
        let _ = run(
            "test",
            RetryPolicy::none(),
            RunDeadline::unbounded(),
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), _>(busy()) }
            },
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_server_that_named_a_time_is_waited_for_exactly() {
        // Jitter must not shorten a `Retry-After`: waiting less than a throttling
        // server asked for is how being rate-limited becomes being blocked. Timed
        // rather than asserted structurally, because the shortening would happen
        // in the driver and not in a function a unit test could call.
        let policy = RetryPolicy {
            max_attempts: 2,
            ..RetryPolicy::network()
        };
        let started = std::time::Instant::now();
        let _ = run("test", policy, RunDeadline::unbounded(), |_| async {
            Err::<(), _>(StoreError::Provider {
                backend: "s3",
                status: 503,
                code: "SlowDown".to_string(),
                retry_after_secs: Some(1),
            })
        })
        .await;
        assert!(
            started.elapsed() >= Duration::from_millis(900),
            "the server asked for a second and got {:?}",
            started.elapsed()
        );
    }

    // ── the run's own deadline ───────────────────────────────────────────
    //
    // §32.9 measured this loop as the multiplier: `--timeout 30` fired at
    // exactly 30 s and the run went on for 943.6 s, because six attempts of a
    // black hole is six times the flag and a copy makes several distinct
    // requests. The tests below are about the term that ends it.

    /// A window short enough to fire inside a test, long enough that a loaded
    /// scheduler is not what decides the outcome.
    const WINDOW: Duration = Duration::from_millis(300);

    /// The schedule §32.9 measured, in miniature: several attempts, each
    /// waiting longer than the last, adding up to far more than [`WINDOW`].
    fn patient() -> RetryPolicy {
        RetryPolicy {
            max_attempts: 6,
            first_backoff: WINDOW,
            max_backoff: WINDOW * 8,
            total_budget: Duration::from_secs(600),
            ..RetryPolicy::network()
        }
    }

    #[tokio::test]
    async fn the_loop_is_not_re_entered_once_the_runs_window_has_closed() {
        // The defect, at the layer §11.3 item 2 names. Without the deadline this
        // makes six attempts and sleeps the whole schedule between them; with it
        // the loop stops as soon as the window is gone.
        let calls = AtomicU32::new(0);
        let started = std::time::Instant::now();
        let error = run(
            "test",
            patient(),
            RunDeadline::starting_now(Some(WINDOW)),
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), _>(busy()) }
            },
        )
        .await
        .expect_err("a permanently busy provider cannot succeed");

        assert!(
            matches!(error.cause(), StoreError::RunDeadline { .. }),
            "the run ended because its window closed, and must say so: {error}"
        );
        assert!(
            calls.load(Ordering::SeqCst) < patient().max_attempts,
            "the schedule must be cut short, not run in full: {} attempts",
            calls.load(Ordering::SeqCst)
        );
        assert!(
            started.elapsed() < WINDOW * 4,
            "the loop must end at the window, not at the end of the schedule: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_backoff_is_never_longer_than_what_is_left_of_the_run() {
        // A wait outliving the window it is inside is the §32.9 arithmetic in
        // miniature: the schedule sleeps for minutes and the run was over
        // before the first of them ended.
        let calls = AtomicU32::new(0);
        let started = std::time::Instant::now();
        let policy = RetryPolicy {
            max_attempts: 2,
            first_backoff: Duration::from_secs(120),
            max_backoff: Duration::from_secs(120),
            total_budget: Duration::from_secs(600),
            ..RetryPolicy::network()
        };
        let _ = run(
            "test",
            policy,
            RunDeadline::starting_now(Some(WINDOW)),
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), _>(busy()) }
            },
        )
        .await;
        assert!(
            started.elapsed() < WINDOW * 4,
            "a two-minute backoff was taken inside a {WINDOW:?} window: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn an_operation_that_starts_after_the_window_has_closed_makes_no_request_at_all() {
        // The other direction of the same rule: a run whose window is already
        // gone must not open another connection. This is what turns "the retry
        // loop stopped" into "the run stopped" — every later operation refuses
        // in microseconds instead of spending a schedule of its own.
        let calls = AtomicU32::new(0);
        let error = run(
            "test",
            patient(),
            RunDeadline::starting_at(std::time::Instant::now() - WINDOW * 4, Some(WINDOW)),
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Ok::<(), StoreError>(()) }
            },
        )
        .await
        .expect_err("the window is gone");

        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "no request may be made after the run's deadline"
        );
        assert!(matches!(error, StoreError::RunDeadline { .. }), "{error}");
    }

    #[tokio::test]
    async fn a_run_with_time_left_is_retried_exactly_as_before() {
        // The direction that matters more, and the one this whole feature could
        // have broken: a deadline the run is comfortably inside must not change
        // a single thing about the schedule.
        let calls = AtomicU32::new(0);
        let value = run(
            "test",
            instant(),
            RunDeadline::starting_now(Some(Duration::from_secs(600))),
            |number| {
                let seen = calls.fetch_add(1, Ordering::SeqCst) + 1;
                async move { if seen < 3 { Err(busy()) } else { Ok(number) } }
            },
        )
        .await
        .expect("the third attempt succeeds");
        assert_eq!(value, 3);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_deadline_error_is_never_retried_by_the_layer_above() {
        // Belt as well as braces. Even if a lower layer hands this loop a
        // run-deadline failure — `IdleWatch` does exactly that when a request is
        // cancelled by the window — it must be terminal. A `--max-duration`
        // classified as transient is the §32.9 defect wearing a new error type.
        let calls = AtomicU32::new(0);
        let error = run("test", instant(), RunDeadline::unbounded(), |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async {
                Err::<(), _>(StoreError::RunDeadline {
                    limit: Duration::from_secs(30),
                })
            }
        })
        .await
        .expect_err("a closed window cannot re-open");

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a run-deadline failure must be attempted exactly once"
        );
        assert_eq!(
            error.attempts(),
            None,
            "no retry happened, so none is claimed"
        );
    }
}
