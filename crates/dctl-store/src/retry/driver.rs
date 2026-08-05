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

use crate::deadline::{RunDeadline, RunStall};
use crate::error::{Result, StoreError};

use super::backoff;
use super::classify::{Verdict, verdict};
use super::observed::Reach;
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
/// # `deadline` is why this layer is the one that has to carry the bound
///
/// `--timeout` bounds one attempt. This loop is what multiplies it: six attempts
/// with exponential backoff, run in full by each of the several distinct
/// requests one copy makes, and multiplied again by `--retries`. The product was
/// measured — a black-holed 160 MiB upload under `--timeout 30 --retries 1` had
/// **not ended 943.6 s after the cut**. Nothing in that arithmetic is a bug;
/// what was missing was a term that could end it. `deadline` is that term, and
/// it acts twice: a wait is never longer than what is left of the run, and an
/// attempt is never *begun* once the window has closed.
///
/// [`RunDeadline::unbounded`] restores exactly the previous behaviour, which is
/// what a run with no `--max-duration` gets — the same default rclone has.
///
/// # `stall` is why `--timeout` is a bound and not a factor
///
/// `deadline` ends a run that is *taking too long*, which is a different
/// question from a run that is *getting nothing back*. The second one was
/// measured too: `--timeout 30` against a black-holed B2 returned the shell
/// after **288.7 s**, and 46.3 s and 136.6 s on two other runs of the same
/// command against the same fault, because the cost was
/// `--timeout × attempts × distinct requests` and the last factor depended on
/// which request the cut landed on.
///
/// `stall` counts, **for the whole run**, attempts that got no answer at all,
/// and it is reset by any answer. Its limit is not smaller than this schedule's
/// own length, so an operation's retries are never cut short — the first request
/// to meet a dead link spends its whole schedule exactly as before. What it
/// stops is the *next* request repeating the discovery. See
/// [`crate::deadline::stall`].
///
/// [`RunStall::unbounded`] restores exactly the previous behaviour, and is what
/// `--timeout 0` gets.
///
/// # Errors
/// The last failure, wrapped in [`StoreError::Retried`] when more than one
/// attempt was made; [`StoreError::RunDeadline`] when the run's window closed
/// before another attempt could be made; or [`StoreError::Stalled`] when the run
/// had already stopped asking.
pub async fn run<T, A, F>(
    op: &'static str,
    policy: RetryPolicy,
    deadline: RunDeadline,
    stall: &RunStall,
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

        // Asked in the same place and for the same reason: a run that has
        // stopped asking must not open the next connection either. The two are
        // separate questions — one is "your window closed", the other is
        // "nothing has answered for a whole schedule" — and they send an
        // operator to opposite places, so they stay two checks and two errors
        // rather than one merged "gave up".
        if let Some(stalled) = stall.exhausted() {
            tracing::debug!(
                op,
                attempts = stalled.attempts,
                "the run has had no answer for a whole schedule; no further attempt was made"
            );
            return Err(stalled.into_store_error());
        }

        match attempt(number).await {
            Ok(value) => {
                // Any success is an answer, and it puts the whole count back.
                // Before the attempt count is even looked at, because a run that
                // is working must be able to survive an unlimited number of
                // isolated silences.
                stall.answered();
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
                match observed.reach {
                    Reach::Silent => {
                        stall.unanswered();
                    }
                    Reach::Answered => stall.answered(),
                    // Neither. This failure says nothing about whether the far
                    // end is there — a budget a lower layer already spent, an
                    // unclassified backend string — so the run's count is left
                    // exactly as it was. Clearing here is the defect a live B2
                    // run found: B2's inner schedule counts six silences and
                    // hands up `Retried(Backend(..))`, which read as an answer
                    // and reset the count to zero at the moment the bound
                    // should have fired. See `super::observed::Reach`.
                    Reach::Unknown => {}
                }
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
    use crate::deadline::constants::UNANSWERED_ATTEMPT_LIMIT;
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

    /// A failure where **nothing came back** — the shape a black-holed route
    /// produces, and the only shape this run-level counter counts.
    fn silence() -> StoreError {
        StoreError::Transport {
            backend: "b2",
            detail: "no data moved for 30s (--timeout 30s)".to_string(),
        }
    }

    /// The stall a run with `--timeout 30` gets.
    fn stall() -> RunStall {
        RunStall::from_idle(Some(Duration::from_secs(30)))
    }

    /// One operation against a link that answers nothing, counting the attempts
    /// it really made.
    async fn silent_operation(stall: &RunStall, calls: &AtomicU32) -> StoreError {
        run("test", instant(), RunDeadline::unbounded(), stall, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err::<(), _>(silence()) }
        })
        .await
        .expect_err("nothing answers")
    }

    // ── the run's own silence ────────────────────────────────────────────
    //
    // Measured: `--timeout 30` against a black-holed B2 returned the shell after
    // **288.7 s**, and 46.3 s and 136.6 s on two other runs of the same command
    // against the same fault. The flag was exact every time and the run was not
    // bounded by it, because the cost was `--timeout × attempts × DISTINCT
    // REQUESTS` and the last factor is unbounded. Every test below is about
    // that third factor.

    #[tokio::test]
    async fn a_second_request_does_not_repeat_the_first_ones_silence() {
        // The defect, stated as small as it goes. Two operations, one run, a
        // link that answers nothing: before this counter existed the second
        // operation spent a whole fresh schedule discovering what the first had
        // already established — and so did the third, and every request after
        // it, which is why the measured cost depended on how many requests the
        // copy had left to make rather than on the operator's flag.
        let stall = stall();
        let first = AtomicU32::new(0);
        let error = silent_operation(&stall, &first).await;
        assert_eq!(
            first.load(Ordering::SeqCst),
            instant().max_attempts,
            "the FIRST operation must still spend its whole schedule: this bound \
             is a change in what a run does, never in what one request does"
        );
        assert!(matches!(error, StoreError::Retried { .. }));

        let second = AtomicU32::new(0);
        let error = silent_operation(&stall, &second).await;
        assert_eq!(
            second.load(Ordering::SeqCst),
            0,
            "the run had already had no answer for a whole schedule and must not \
             have opened another connection"
        );
        assert!(
            matches!(error, StoreError::Stalled { .. }),
            "and it must say so rather than reporting the link failing again: {error}"
        );
    }

    #[tokio::test]
    async fn the_report_multiplies_out_to_the_operators_own_flag() {
        // What `--help` now states is `--timeout × attempts`. The error is where
        // an operator checks that arithmetic against the number they set, so
        // both halves of it have to be in the message.
        let stall = stall();
        let calls = AtomicU32::new(0);
        let _ = silent_operation(&stall, &calls).await;
        let error = silent_operation(&stall, &AtomicU32::new(0)).await;
        let StoreError::Stalled { attempts, idle } = error else {
            panic!("expected a stall, got {error}");
        };
        assert_eq!(attempts, stall.limit().expect("a bounded run"));
        assert_eq!(idle, Duration::from_secs(30));
        let rendered = StoreError::Stalled { attempts, idle }.to_string();
        assert!(rendered.contains("--timeout 30s"), "{rendered}");
        assert!(rendered.contains(&attempts.to_string()), "{rendered}");
    }

    #[tokio::test]
    async fn a_flaky_link_never_accumulates_its_way_into_giving_up() {
        // The direction that matters more, and the one a careless bound would
        // fail: **consecutive**, never cumulative. This makes many times the
        // limit's worth of unanswered attempts in total — a link that drops the
        // first two attempts of every request and answers the third, which is a
        // flaky route rather than a dead one — and the run must still be asking
        // at the end.
        let stall = stall();
        let silences_per_request = instant().max_attempts - 1;
        let requests = 10;
        for _ in 0..requests {
            let calls = AtomicU32::new(0);
            let value = run("test", instant(), RunDeadline::unbounded(), &stall, |_| {
                let seen = calls.fetch_add(1, Ordering::SeqCst) + 1;
                async move {
                    if seen < silences_per_request {
                        Err(silence())
                    } else {
                        Ok(seen)
                    }
                }
            })
            .await
            .expect("the link answers in the end, every time");
            assert_eq!(value, silences_per_request);
            assert_eq!(
                stall.count(),
                0,
                "an answer must put the whole count back, not decrement it"
            );
        }
        // Far more silences than the limit, and not one of them consecutive
        // enough to matter.
        assert!(
            requests * (silences_per_request - 1) > stall.limit().expect("bounded") * 2,
            "the test has to make more silences than the limit for it to prove \
             anything about accumulation"
        );
        assert_eq!(stall.exhausted(), None);
    }

    #[tokio::test]
    async fn a_whole_schedule_of_silence_ends_the_run_even_though_retries_remain() {
        // The cost of this bound, pinned rather than left to be discovered.
        //
        // One request's schedule is exactly the run's budget — that is what the
        // compile-time rule in `deadline::constants` holds, and it is what makes
        // the first request's behaviour identical to the build before this. The
        // consequence is that a link which answers **nothing** for a whole
        // schedule ends the run, where `--retries` would previously have
        // repeated the file into the same silence. That is the 288.7 s being
        // removed and not collateral: `--retries` keeps its meaning for every
        // failure that has an *answer*, which is every other failure there is.
        //
        // `--timeout 0` is the documented escape, and
        // `a_run_with_no_idle_deadline_is_never_stopped` is it.
        let stall = stall();
        let calls = AtomicU32::new(0);
        let _ = silent_operation(&stall, &calls).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            instant().max_attempts,
            "the request itself is unaffected: it spends its whole schedule"
        );

        // What the file-level `--retries` loop would do next.
        let again = AtomicU32::new(0);
        let error = silent_operation(&stall, &again).await;
        assert_eq!(again.load(Ordering::SeqCst), 0);
        assert!(matches!(error, StoreError::Stalled { .. }), "{error}");
    }

    #[tokio::test]
    async fn an_answer_that_is_a_refusal_is_still_an_answer() {
        // A `503` is the provider talking. It is exactly the case retrying
        // exists for, and counting it as silence would turn a busy bucket into a
        // run that gives up — the false failure this counter must not introduce.
        let stall = stall();
        for _ in 0..4 {
            let calls = AtomicU32::new(0);
            let error = run("test", instant(), RunDeadline::unbounded(), &stall, |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), _>(busy()) }
            })
            .await
            .expect_err("the bucket stays busy");
            assert_eq!(calls.load(Ordering::SeqCst), instant().max_attempts);
            assert!(!matches!(error, StoreError::Stalled { .. }), "{error}");
        }
        assert_eq!(stall.count(), 0, "every attempt was answered");
    }

    #[tokio::test]
    async fn a_budget_a_lower_layer_already_spent_neither_counts_nor_clears() {
        // **The defect a live run found and this file could not.** Every other
        // test here hands the driver a `StoreError::Transport`, which is the
        // shape a backend with no inner retry layer produces. B2 has one: its
        // request-level schedule counts its own silences and then hands the
        // exhausted failure up as `Retried` wrapping `Backend(String)` — an
        // unclassified string, because that is what a `reqwest` transport error
        // formats to there.
        //
        // With `Observed` carrying a two-state answer, "not silent" meant
        // "answered", so this layer read that string as an answer and reset the
        // run's count to **zero** every time the inner layer finished counting
        // six. The bound never fired on B2 at all: a black-holed 160 MiB upload
        // ran `b2_authorize_account`, `b2_list_buckets`, `b2_upload_part` and
        // `b2_list_buckets` again, each spending a whole schedule, and exited 6
        // after 116.5 s. That exit is the upload giving up, not this bound
        // firing: the unbounded run reproduced with the fix installed.
        //
        // `Reach::Unknown` is the third state, and this is what it is for.
        let stall = stall();
        let already = StoreError::Retried {
            attempts: 6,
            source: Box::new(StoreError::Backend(
                "error sending request for url (https://api003.backblazeb2.com/…)".into(),
            )),
        };
        assert_eq!(
            super::super::observed::Observed::of(&already).reach,
            Reach::Unknown
        );

        // A count the inner layer legitimately earned...
        for _ in 0..UNANSWERED_ATTEMPT_LIMIT {
            stall.unanswered();
        }
        // ...must survive this layer seeing the exhausted failure travel past.
        let error = run(
            "test",
            instant(),
            RunDeadline::unbounded(),
            &stall,
            |_| async {
                // Rebuilt per attempt rather than cloned: `StoreError` is not
                // `Clone` (it holds an `io::Error`), and the closure is `FnMut`.
                Err::<(), _>(StoreError::Retried {
                    attempts: 6,
                    source: Box::new(StoreError::Backend(
                        "error sending request for url (https://api003.backblazeb2.com/…)".into(),
                    )),
                })
            },
        )
        .await
        .expect_err("the run has stopped asking");
        assert!(
            matches!(error, StoreError::Stalled { .. }),
            "the count was cleared by a failure that said nothing: {error}"
        );
    }

    #[tokio::test]
    async fn a_failure_from_the_far_end_clears_the_count_and_a_silence_does_not() {
        // The three states, asserted directly rather than through a loop, so a
        // variant reclassified by mistake is caught here and not by a live run.
        use super::super::observed::Observed;
        assert_eq!(Observed::of(&silence()).reach, Reach::Silent);
        assert_eq!(Observed::of(&busy()).reach, Reach::Answered);
        assert_eq!(
            Observed::of(&StoreError::NotFound("a/b.bin".into())).reach,
            Reach::Answered,
            "a provider that said 'no such key' is a provider that is there"
        );
        assert_eq!(
            Observed::of(&StoreError::Backend("something nobody classified".into())).reach,
            Reach::Unknown,
            "a string must not be allowed to decide either way"
        );
        assert_eq!(
            Observed::of(&StoreError::RunDeadline {
                limit: Duration::from_secs(30)
            })
            .reach,
            Reach::Unknown,
            "DCTL's own clock says nothing about the link"
        );
    }

    #[tokio::test]
    async fn a_run_with_no_idle_deadline_is_never_stopped() {
        // `--timeout 0` is "wait as long as it takes". An operator who said that
        // has also said they want it asked again, and this is the control that
        // proves the bound above is the flag rather than something unconditional.
        let stall = RunStall::unbounded();
        for _ in 0..6 {
            let calls = AtomicU32::new(0);
            let error = silent_operation(&stall, &calls).await;
            assert_eq!(
                calls.load(Ordering::SeqCst),
                instant().max_attempts,
                "every request must still get its whole schedule"
            );
            assert!(!matches!(error, StoreError::Stalled { .. }), "{error}");
        }
    }

    #[tokio::test]
    async fn the_driver_returns_the_first_success_and_counts_its_attempts() {
        let calls = AtomicU32::new(0);
        let value = run(
            "test",
            instant(),
            RunDeadline::unbounded(),
            &RunStall::unbounded(),
            |number| {
                let seen = calls.fetch_add(1, Ordering::SeqCst) + 1;
                async move { if seen < 3 { Err(busy()) } else { Ok(number) } }
            },
        )
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
        let error = run(
            "test",
            instant(),
            RunDeadline::unbounded(),
            &RunStall::unbounded(),
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                async {
                    Err::<(), _>(StoreError::Provider {
                        backend: "b2",
                        status: 401,
                        code: "bad_auth_token".to_string(),
                        retry_after_secs: None,
                    })
                }
            },
        )
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
        let error = run(
            "test",
            policy,
            RunDeadline::unbounded(),
            &RunStall::unbounded(),
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), _>(busy()) }
            },
        )
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
        let error = run(
            "test",
            instant(),
            RunDeadline::unbounded(),
            &RunStall::unbounded(),
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                async {
                    Err::<(), _>(StoreError::Retried {
                        attempts: 6,
                        source: Box::new(busy()),
                    })
                }
            },
        )
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
            &RunStall::unbounded(),
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
        let _ = run(
            "test",
            policy,
            RunDeadline::unbounded(),
            &RunStall::unbounded(),
            |_| async {
                Err::<(), _>(StoreError::Provider {
                    backend: "s3",
                    status: 503,
                    code: "SlowDown".to_string(),
                    retry_after_secs: Some(1),
                })
            },
        )
        .await;
        assert!(
            started.elapsed() >= Duration::from_millis(900),
            "the server asked for a second and got {:?}",
            started.elapsed()
        );
    }

    // ── the run's own deadline ───────────────────────────────────────────
    //
    // This loop was measured as the multiplier: `--timeout 30` fired at
    // exactly 30 s and the run went on for 943.6 s, because six attempts of a
    // black hole is six times the flag and a copy makes several distinct
    // requests. The tests below are about the term that ends it.

    /// A window short enough to fire inside a test, long enough that a loaded
    /// scheduler is not what decides the outcome.
    const WINDOW: Duration = Duration::from_millis(300);

    /// The schedule behind the 943.6 s overrun, in miniature: several attempts,
    /// each waiting longer than the last, adding up to far more than [`WINDOW`].
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
        // The defect, at the layer that has to carry the bound. Without the
        // deadline this makes six attempts and sleeps the whole schedule between
        // them; with it the loop stops as soon as the window is gone.
        let calls = AtomicU32::new(0);
        let started = std::time::Instant::now();
        let error = run(
            "test",
            patient(),
            RunDeadline::starting_now(Some(WINDOW)),
            &RunStall::unbounded(),
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
        // A wait outliving the window it is inside is the 943.6 s arithmetic in
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
            &RunStall::unbounded(),
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
            &RunStall::unbounded(),
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
            &RunStall::unbounded(),
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
        // classified as transient is the overrun wearing a new error type.
        let calls = AtomicU32::new(0);
        let error = run(
            "test",
            instant(),
            RunDeadline::unbounded(),
            &RunStall::unbounded(),
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                async {
                    Err::<(), _>(StoreError::RunDeadline {
                        limit: Duration::from_secs(30),
                    })
                }
            },
        )
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
