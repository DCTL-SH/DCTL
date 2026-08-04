//! Trying a B2 request again when the reason it failed will not last.
//!
//! Until this module existed there was no retry anywhere in `dctl-store` — the
//! only mention of one was a doc comment in [`crate::error`] pointing at a
//! "higher retry layer" that was never written, and a hint on every backend
//! failure reading *"Retries were exhausted."* over a run that made exactly one
//! attempt in ten milliseconds. Both statements were false, and the second is the
//! worse kind of false: it tells an operator the tool already did the thing they
//! would otherwise go and do.
//!
//! What made it a defect rather than a gap is what B2 actually returns. The
//! restore drill against a real bucket failed on its first run with five of ten
//! files reporting
//!
//! ```text
//! b2 api error 503: {"code":"service_unavailable","message":"no tomes available"}
//! ```
//!
//! which is B2's documented way of saying *this upload pod is busy, ask for
//! another URL and send it again*. Not retrying turned a routine provider signal
//! into a half-stored backup and exit 6.
//!
//! ## The decision is separated from the waiting
//!
//! [`verdict`] is a pure function of what was observed and how many attempts have
//! already been made. It performs no I/O, sleeps for nothing, and reaches no
//! network, so every rule below is asserted directly in this file's tests rather
//! than inferred from a run against a provider that was in a good mood.
//! [`run`] is the only part that waits, and it waits for exactly as long as the
//! verdict said.
//!
//! ## What is retried, and what is emphatically not
//!
//! | Observed | Verdict | Why |
//! |---|---|---|
//! | no answer at all (connect, timeout, reset mid-body) | retry | the request may never have reached B2 |
//! | `401` + `expired_auth_token` | retry, after re-authorizing | B2 tokens expire after 24 h; a long sync outlives one |
//! | `401` any other code | **never** | a wrong application key is not a temporary condition |
//! | `403` | **never** | a storage or transaction cap; the next second is the same second |
//! | `408`, `429` | retry, honouring `Retry-After` | the server named a time; arguing with it is how a cap becomes a ban |
//! | `5xx` | retry | includes the `503 no tomes available` above |
//! | anything else (`400`, `404`, `416`, …) | **never** | the request is wrong, and it will be equally wrong next time |
//! | a `200` whose body contradicts the request | **never** | see [`Observed::settled`] |
//!
//! The `401` split is the one worth stating twice. Classifying every `401` as
//! temporary is what made a permanently wrong `DCTL_B2_APP_KEY` report an exit
//! code that tells a scheduler to back off and try again — forever, on a
//! credential that no amount of waiting invents.
//!
//! ## The schedule is deterministic
//!
//! Exponential, from [`RETRY_FIRST_BACKOFF`] and doubling to
//! [`RETRY_MAX_BACKOFF`], with no jitter. Jitter exists to stop a fleet of
//! clients re-colliding after a shared outage; one CLI process retrying one
//! request is not a fleet, and what an operator gains instead is a schedule they
//! can state — [`RETRY_MAX_ATTEMPTS`] attempts, bounded by the sum of the
//! backoffs — rather than a distribution. A `Retry-After` the server sent always
//! wins over the schedule, capped at [`RETRY_AFTER_CAP`] so a header of
//! `86400` cannot wedge a backup for a day without saying so.

use std::future::Future;
use std::time::Duration;

use crate::deadline::{RunDeadline, RunStall};
use crate::error::{Result, StoreError};

use super::constants::{
    RETRY_AFTER_CAP, RETRY_FIRST_BACKOFF, RETRY_MAX_ATTEMPTS, RETRY_MAX_BACKOFF,
};

/// B2's own error code for a token that has aged out — the one `401` that
/// another attempt can fix, and only after re-authorizing.
pub(super) const CODE_EXPIRED_AUTH_TOKEN: &str = "expired_auth_token";

/// What one attempt observed when it failed.
///
/// Deliberately not the `StoreError` it will become. A `StoreError::Backend`
/// carries a formatted string, and deciding whether to retry by searching that
/// string for `"503"` is a rule that breaks the first time a message is reworded
/// — silently, and in the direction of not retrying.
#[derive(Debug, Default, Clone)]
pub(super) struct Observed {
    /// The HTTP status B2 answered with, or `None` when nothing answered.
    pub status: Option<u16>,
    /// B2's `code` field from the error body, when the body carried one.
    pub code: Option<String>,
    /// The server's `Retry-After`, already parsed, when it sent one.
    pub retry_after: Option<Duration>,
    /// Nothing another attempt can change, whatever the status says.
    ///
    /// Two things set it, and both are rows the status table cannot express
    /// because there is no failing status to key them on.
    ///
    /// The first is an answer that *is* the finding. B2 verifies an upload's body against the
    /// `X-Bz-Content-Sha1` header it was sent and rejects a mismatch with `400`;
    /// so a `200` whose `contentSha1` is a *different* digest is B2 saying it
    /// accepted the bytes and holds something else. That is a settled fact about
    /// the object, not a pod that was busy, and re-sending the part cannot
    /// change it — it only spends the whole upload again, six times, before
    /// reporting the same thing.
    ///
    /// The second is the run's own `--max-duration` having closed while the
    /// request was in flight. A window that has shut does not re-open, and
    /// treating that as a transport failure is exactly what §32.9 measured:
    /// the deadline fires on time and the schedule spends itself anyway.
    pub settled: bool,
}

impl Observed {
    /// A request that never got an answer.
    pub(super) const fn transport() -> Self {
        Self {
            status: None,
            code: None,
            retry_after: None,
            settled: false,
        }
    }

    /// A request that was answered, and whose answer is the problem.
    ///
    /// Distinct from a `4xx` — nothing was refused — and from a transport
    /// failure, where the absence of a status is precisely what makes another
    /// attempt worth making. See [`Observed::settled`].
    pub(super) const fn settled() -> Self {
        Self {
            status: None,
            code: None,
            retry_after: None,
            settled: true,
        }
    }

    /// Whether this failure is the expired-token case, which the caller must
    /// clear its cached authorization for before the next attempt can differ.
    pub(super) fn is_expired_token(&self) -> bool {
        self.status == Some(HTTP_UNAUTHORIZED)
            && self.code.as_deref() == Some(CODE_EXPIRED_AUTH_TOKEN)
    }
}

/// One failed attempt: what was observed, and what to report if it was the last.
pub(super) struct Attempt {
    pub observed: Observed,
    pub error: StoreError,
}

impl Attempt {
    /// A failure with nothing observed about the wire — a transport error, or a
    /// local one (reading the file being uploaded) that reached this layer.
    pub(super) const fn transport(error: StoreError) -> Self {
        Self {
            observed: Observed::transport(),
            error,
        }
    }

    /// A failure the answer itself established, which no further attempt can
    /// change. See [`Observed::settled`].
    pub(super) const fn settled(error: StoreError) -> Self {
        Self {
            observed: Observed::settled(),
            error,
        }
    }

    /// Classify a failed authorization for a retry loop.
    ///
    /// A bucket the account's credentials cannot list is an answered fact —
    /// six identical attempts against the same account answer it six times —
    /// so it settles after one. Everything else about a failed auth is
    /// transport-shaped: no status was observed, and another attempt is
    /// exactly what might differ.
    pub(super) fn auth(error: StoreError) -> Self {
        match error.cause() {
            StoreError::BucketNotFound { .. } => Self::settled(error),
            _ => Self::transport(error),
        }
    }

    /// A failure the run's own deadline established.
    ///
    /// Classified as settled rather than as transport, which is what makes the
    /// difference visible in the one place it decides anything: `verdict`
    /// refuses to retry it. The loop also refuses on its own, before the next
    /// request; both are here because a classification that said "worth another
    /// attempt" about a closed window would be a trap for the next caller who
    /// reads it.
    pub(super) const fn run_deadline(error: StoreError) -> Self {
        Self {
            observed: Observed::settled(),
            error,
        }
    }
}

/// Whether another attempt can change the outcome, and how long to wait first.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Try again after this delay.
    After(Duration),
    /// Do not try again: the answer will be the same.
    Never,
}

/// HTTP statuses this module names.
const HTTP_UNAUTHORIZED: u16 = 401;
const HTTP_FORBIDDEN: u16 = 403;
const HTTP_REQUEST_TIMEOUT: u16 = 408;
const HTTP_TOO_MANY_REQUESTS: u16 = 429;
/// The first server-error status; everything at or above it is B2's problem
/// rather than the request's.
const HTTP_SERVER_ERROR: u16 = 500;

/// Decide whether the `attempt`-th try (1-based) failing as `observed` should be
/// followed by another.
///
/// Pure: no clock, no sleep, no network. See the module documentation for the
/// table this implements and the argument for each row.
pub(super) fn verdict(observed: &Observed, attempt: u32) -> Verdict {
    if attempt >= RETRY_MAX_ATTEMPTS {
        return Verdict::Never;
    }
    // Before the status is consulted, because there is no failing status to
    // consult: the request was answered, and the answer is the finding.
    if observed.settled {
        return Verdict::Never;
    }
    let Some(status) = observed.status else {
        // Nothing answered. The request may not have reached B2 at all, which is
        // the case retrying exists for.
        return Verdict::After(backoff(attempt));
    };
    match status {
        // The only `401` another attempt can fix, and only because the caller
        // drops its cached token first — see `is_expired_token`.
        HTTP_UNAUTHORIZED if observed.is_expired_token() => Verdict::After(backoff(attempt)),
        // Every other `401`, and every `403`: a wrong key and an exceeded cap are
        // both stable facts. Retrying them turns a clear failure into a slow one.
        HTTP_UNAUTHORIZED | HTTP_FORBIDDEN => Verdict::Never,
        HTTP_REQUEST_TIMEOUT | HTTP_TOO_MANY_REQUESTS => Verdict::After(
            observed
                .retry_after
                .map_or_else(|| backoff(attempt), |after| after.min(RETRY_AFTER_CAP)),
        ),
        code if code >= HTTP_SERVER_ERROR => Verdict::After(
            observed
                .retry_after
                .map_or_else(|| backoff(attempt), |after| after.min(RETRY_AFTER_CAP)),
        ),
        // A 4xx that is not one of the above says the request itself is wrong.
        _ => Verdict::Never,
    }
}

/// The delay before the attempt following the `attempt`-th (1-based).
///
/// Doubles from [`RETRY_FIRST_BACKOFF`] and saturates at [`RETRY_MAX_BACKOFF`],
/// so the schedule cannot overflow however high the attempt counter is taken.
fn backoff(attempt: u32) -> Duration {
    let doubled = RETRY_FIRST_BACKOFF
        .checked_mul(
            1u32.checked_shl(attempt.saturating_sub(1))
                .unwrap_or(u32::MAX),
        )
        .unwrap_or(RETRY_MAX_BACKOFF);
    doubled.min(RETRY_MAX_BACKOFF)
}

/// Run `attempt` until it succeeds, until [`verdict`] says another try cannot
/// help, until the attempt budget is spent, or until the run's own window
/// closes — whichever comes first.
///
/// `attempt` is handed the 1-based attempt number so a caller that must do
/// something different on a retry (fetch a fresh upload URL, re-authorize) can
/// see that it is one. `op` names the operation in the log line each retry
/// emits, which is what makes a slow run explicable afterwards.
///
/// # Why `deadline` and `stall` are here as well as in [`crate::retry::driver`]
///
/// Because this loop is a *second* multiplier and §32.9 caught it being one.
/// The 160 MiB upload that had not ended 943.6 s after the route was cut spent
/// that time in `b2_upload_part`, `b2_cancel_large_file` and `b2_list_buckets`
/// — three distinct requests, each running this schedule in full, underneath
/// the operation-level loop that was running its own. A run-level bound
/// enforced only at the layer above would have been a bound this layer could
/// outlast.
///
/// `stall` is the same argument for the other bound, and on B2 it is the layer
/// that matters most. An error this loop exhausts arrives at
/// [`crate::retry::driver`] marked
/// [`Retried`](crate::StoreError::Retried), which that layer declines to retry
/// again — so on B2 the outer counter never sees the silences at all, and a
/// stall counted only there would not have counted them. It is **the same
/// counter**, shared through [`crate::deadline::Deadlines`], for the same
/// reason: six here plus six there is twelve, and the whole point is that the
/// run stops at six.
pub(super) async fn run<T, A, F>(
    op: &'static str,
    deadline: RunDeadline,
    stall: &RunStall,
    mut attempt: A,
) -> Result<T>
where
    A: FnMut(u32) -> F,
    F: Future<Output = std::result::Result<T, Attempt>>,
{
    let mut number = 1u32;
    loop {
        // Before the request, not merely before the retry: a run whose window
        // has closed must not open another connection to B2, on the first
        // attempt or the sixth.
        if let Some(exceeded) = deadline.exceeded() {
            tracing::debug!(
                op,
                attempts = number.saturating_sub(1),
                "the run's deadline passed; no further b2 request was made"
            );
            return Err(exceeded.into_store_error());
        }

        // And before the request for the same reason: a run that has had no
        // answer for a whole schedule must not open the next connection to B2
        // either.
        if let Some(stalled) = stall.exhausted() {
            tracing::debug!(
                op,
                attempts = stalled.attempts,
                "the run has had no answer for a whole schedule; no further b2 request was made"
            );
            return Err(stalled.into_store_error());
        }

        match attempt(number).await {
            Ok(value) => {
                // Any success is an answer, and it puts the whole count back.
                stall.answered();
                if number > 1 {
                    tracing::info!(op, attempts = number, "b2 request succeeded on a retry");
                }
                return Ok(value);
            }
            Err(failed) => {
                // Three outcomes, matching `crate::retry::observed::Reach`,
                // because two would make one of them a lie. A status is B2
                // answering. `status: None` and not settled is this module's own
                // spelling of "nothing came back" — a connect that never
                // completed, an idle deadline, a reset mid-body. `settled` is
                // neither: it is the run's own `--max-duration`, or a `200`
                // whose body contradicts the request, and neither says anything
                // about whether the link is there.
                if failed.observed.status.is_some() {
                    stall.answered();
                } else if !failed.observed.settled {
                    stall.unanswered();
                }
                match verdict(&failed.observed, number) {
                    Verdict::Never => {
                        tracing::debug!(
                            op,
                            attempts = number,
                            status = failed.observed.status,
                            "b2 request will not be retried"
                        );
                        return Err(record(failed.error, number));
                    }
                    Verdict::After(delay) => {
                        // Never longer than what is left of the run: a wait that
                        // outlives the window it is inside is time spent on a run
                        // that was supposed to be over.
                        let delay = deadline.shorten(Some(delay)).unwrap_or(delay);
                        // WARN, not DEBUG. A retried request is the difference
                        // between a backup that took twenty minutes and one that took
                        // two hours, and an operator diagnosing the second one must
                        // not have to raise the log level to discover it happened.
                        tracing::warn!(
                            op,
                            attempt = number,
                            of = RETRY_MAX_ATTEMPTS,
                            status = failed.observed.status,
                            code = failed.observed.code.as_deref(),
                            delay_ms = delay.as_millis(),
                            error = %failed.error,
                            "b2 request failed for a reason that may not last; retrying"
                        );
                        tokio::time::sleep(delay).await;
                        number = number.saturating_add(1);
                    }
                }
            }
        }
    }
}

/// Attach the attempt count to a failure, and only when there is one to attach.
///
/// Two things depend on it. The operator's hint is worded from this number
/// rather than from an assumption, so a failure that was tried once no longer
/// arrives claiming that retries were exhausted. And the operation-level layer
/// above ([`crate::retry`]) reads it and declines to spend a second budget on
/// the same failure — six attempts under six would otherwise be thirty-six, and
/// the number finally reported would be the product of two schedules instead of
/// a fact.
fn record(error: StoreError, attempts: u32) -> StoreError {
    if attempts <= 1 {
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

    fn status(code: u16) -> Observed {
        Observed {
            status: Some(code),
            ..Observed::default()
        }
    }

    #[test]
    fn a_request_that_never_got_an_answer_is_retried() {
        assert!(matches!(
            verdict(&Observed::transport(), 1),
            Verdict::After(_)
        ));
    }

    #[test]
    fn the_status_b2_returns_when_a_pod_is_busy_is_retried() {
        // The exact failure that broke the first live restore drill:
        // `503 {"code":"service_unavailable","message":"no tomes available"}`.
        let observed = Observed {
            status: Some(503),
            code: Some("service_unavailable".to_string()),
            retry_after: None,
            settled: false,
        };
        assert!(matches!(verdict(&observed, 1), Verdict::After(_)));
    }

    #[test]
    fn every_server_error_is_retried_and_every_ordinary_client_error_is_not() {
        for code in [500, 502, 503, 504, 599] {
            assert!(
                matches!(verdict(&status(code), 1), Verdict::After(_)),
                "{code} should be retried"
            );
        }
        for code in [400, 404, 405, 409, 416] {
            assert_eq!(verdict(&status(code), 1), Verdict::Never, "{code}");
        }
    }

    #[test]
    fn a_wrong_application_key_is_never_retried_and_an_expired_token_always_is() {
        // The distinction the exit code depends on. A `401` meaning "this key is
        // wrong" told a scheduler to back off and try again forever; a `401`
        // meaning "this token aged out" is fixed by re-authorizing and retrying.
        let bad_key = Observed {
            status: Some(401),
            code: Some("bad_auth_token".to_string()),
            retry_after: None,
            settled: false,
        };
        assert_eq!(verdict(&bad_key, 1), Verdict::Never);
        assert!(!bad_key.is_expired_token());

        let expired = Observed {
            status: Some(401),
            code: Some(CODE_EXPIRED_AUTH_TOKEN.to_string()),
            retry_after: None,
            settled: false,
        };
        assert!(matches!(verdict(&expired, 1), Verdict::After(_)));
        assert!(expired.is_expired_token());

        // A `401` with no code at all is the wrong-credential case too: nothing
        // observed says otherwise, and guessing "temporary" is the guess that
        // loops forever.
        assert_eq!(verdict(&status(401), 1), Verdict::Never);
    }

    #[test]
    fn an_answer_that_contradicts_the_request_is_never_retried() {
        // The row with no status to key it on. B2 checks an upload body against
        // the `X-Bz-Content-Sha1` header it was sent and refuses a mismatch with
        // `400`; a `200` naming a *different* digest is therefore B2 saying it
        // took the bytes and holds something else, which is a fact about the
        // object rather than a pod that was busy.
        //
        // This used to be `Attempt::transport`, whose `Observed` carries no
        // status — and no status is the one case that means "nothing answered",
        // so the whole part was re-sent five more times before reporting the
        // same mismatch. The comment at the call site already said it should be
        // reported on the first attempt; only the code disagreed.
        assert_eq!(verdict(&Observed::settled(), 1), Verdict::Never);
        // And it stays never however early the attempt is, which is what
        // separates it from the transport case immediately above.
        assert!(matches!(
            verdict(&Observed::transport(), 1),
            Verdict::After(_)
        ));
    }

    #[test]
    fn an_exceeded_cap_is_not_a_temporary_condition() {
        assert_eq!(verdict(&status(403), 1), Verdict::Never);
    }

    #[test]
    fn the_servers_retry_after_wins_over_the_schedule_but_not_over_the_cap() {
        let asked = Observed {
            status: Some(429),
            code: None,
            retry_after: Some(Duration::from_secs(7)),
            settled: false,
        };
        assert_eq!(verdict(&asked, 1), Verdict::After(Duration::from_secs(7)));

        let absurd = Observed {
            status: Some(503),
            code: None,
            retry_after: Some(Duration::from_secs(86_400)),
            settled: false,
        };
        assert_eq!(verdict(&absurd, 1), Verdict::After(RETRY_AFTER_CAP));
    }

    #[test]
    fn the_budget_is_finite_and_the_waits_grow() {
        // Whatever the failure, the last permitted attempt is the last one.
        assert_eq!(
            verdict(&Observed::transport(), RETRY_MAX_ATTEMPTS),
            Verdict::Never
        );
        assert_eq!(
            verdict(&status(503), RETRY_MAX_ATTEMPTS + 1),
            Verdict::Never
        );

        // And each wait is at least as long as the one before it, never longer
        // than the cap. An arithmetic slip here is a retry storm, so it is
        // asserted rather than read off the constants.
        let mut previous = Duration::ZERO;
        for attempt in 1..RETRY_MAX_ATTEMPTS {
            let Verdict::After(delay) = verdict(&status(503), attempt) else {
                panic!("attempt {attempt} of {RETRY_MAX_ATTEMPTS} should be retried");
            };
            assert!(delay >= previous, "backoff went backwards at {attempt}");
            assert!(delay <= RETRY_MAX_BACKOFF, "backoff exceeded its cap");
            previous = delay;
        }
    }

    // ── the run's own silence ────────────────────────────────────────────
    //
    // This loop is where B2 multiplies `--timeout`. §32.9 read the log of the
    // 160 MiB upload that had not ended 943.6 s after the cut: `b2_upload_part`,
    // `b2_cancel_large_file` and `b2_list_buckets`, each running this schedule in
    // full against a link that had already proved silent. The counter is shared
    // with `crate::retry::driver` precisely so those are one budget and not
    // several.

    /// A B2 failure where nothing came back at all.
    fn silence() -> Attempt {
        Attempt::transport(StoreError::Transport {
            backend: "b2",
            detail: "no data moved for 30s (--timeout 30s)".to_string(),
        })
    }

    /// One B2 request against a link that answers nothing.
    async fn silent_request(stall: &RunStall, calls: &std::sync::atomic::AtomicU32) -> StoreError {
        use std::sync::atomic::Ordering;
        run("test", RunDeadline::unbounded(), stall, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err::<(), _>(silence()) }
        })
        .await
        .expect_err("nothing answers")
    }

    #[tokio::test]
    async fn a_second_b2_request_does_not_repeat_the_first_ones_silence() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let stall = RunStall::from_idle(Some(Duration::from_secs(30)));
        let first = AtomicU32::new(0);
        let error = silent_request(&stall, &first).await;
        assert_eq!(
            first.load(Ordering::SeqCst),
            RETRY_MAX_ATTEMPTS,
            "the first request must still spend its whole schedule"
        );
        assert!(matches!(error, StoreError::Retried { .. }), "{error}");

        let second = AtomicU32::new(0);
        let error = silent_request(&stall, &second).await;
        assert_eq!(
            second.load(Ordering::SeqCst),
            0,
            "the run had had no answer for a whole schedule and must not have \
             opened another connection to B2"
        );
        assert!(matches!(error, StoreError::Stalled { .. }), "{error}");
    }

    #[tokio::test]
    async fn the_counter_is_the_same_cell_the_outer_layer_reads() {
        use std::sync::atomic::AtomicU32;

        // The property the whole bound rests on. An error this loop exhausts
        // arrives at `crate::retry::driver` marked `Retried`, which that layer
        // declines to retry — so on B2 the outer counter never sees these
        // silences, and six here plus six there would be twelve. It is one cell
        // and the handle is what clones.
        let stall = RunStall::from_idle(Some(Duration::from_secs(30)));
        let outer = stall.clone();
        let _ = silent_request(&stall, &AtomicU32::new(0)).await;
        assert!(
            outer.exhausted().is_some(),
            "the outer layer's handle did not see this loop's silences"
        );
        outer.answered();
        assert_eq!(stall.count(), 0, "and a reset there did not reach here");
    }

    #[tokio::test]
    async fn an_answer_from_b2_is_never_counted_as_silence() {
        use std::sync::atomic::{AtomicU32, Ordering};

        // `503 no tomes available` is B2 talking, and it is the exact failure
        // this module was written for — five of ten files in the first live
        // restore drill. Counting it as silence would turn a busy pod into a run
        // that gives up.
        let stall = RunStall::from_idle(Some(Duration::from_secs(30)));
        for _ in 0..4 {
            let calls = AtomicU32::new(0);
            let error = run("test", RunDeadline::unbounded(), &stall, |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                async {
                    Err::<(), _>(Attempt {
                        observed: Observed {
                            status: Some(503),
                            code: Some("service_unavailable".to_string()),
                            retry_after: Some(Duration::ZERO),
                            settled: false,
                        },
                        error: StoreError::Backend("no tomes available".into()),
                    })
                }
            })
            .await
            .expect_err("the pod stays busy");
            assert_eq!(calls.load(Ordering::SeqCst), RETRY_MAX_ATTEMPTS);
            assert!(!matches!(error, StoreError::Stalled { .. }), "{error}");
        }
        assert_eq!(stall.count(), 0, "every attempt was answered");
    }

    #[tokio::test]
    async fn the_driver_returns_the_first_success_and_counts_its_attempts() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let calls = AtomicU32::new(0);
        let value = run(
            "test",
            RunDeadline::unbounded(),
            &RunStall::unbounded(),
            |number| {
                let seen = calls.fetch_add(1, Ordering::SeqCst) + 1;
                async move {
                    if seen < 3 {
                        Err(Attempt {
                            observed: Observed {
                                status: Some(503),
                                code: None,
                                // Zero, so the test does not spend the real schedule
                                // sleeping; the schedule itself is asserted above.
                                retry_after: Some(Duration::ZERO),
                                settled: false,
                            },
                            error: StoreError::Backend("busy".into()),
                        })
                    } else {
                        Ok(number)
                    }
                }
            },
        )
        .await
        .expect("the third attempt succeeds");

        assert_eq!(value, 3, "the closure is told which attempt it is");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn the_driver_reports_the_last_error_and_stops_on_a_permanent_one() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let calls = AtomicU32::new(0);
        let error = run(
            "test",
            RunDeadline::unbounded(),
            &RunStall::unbounded(),
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                async {
                    Err::<(), _>(Attempt {
                        observed: Observed {
                            status: Some(401),
                            code: Some("bad_auth_token".to_string()),
                            retry_after: None,
                            settled: false,
                        },
                        error: StoreError::Backend("b2 api error 401: bad_auth_token".into()),
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
        assert!(error.to_string().contains("bad_auth_token"));
        assert_eq!(
            error.attempts(),
            None,
            "one attempt is not a retry, and must not be reported as one"
        );
    }

    #[tokio::test]
    async fn an_exhausted_request_reports_the_attempts_it_really_made() {
        // The half the hint depends on. Without this the operation-level layer
        // above would spend a second budget on the same failure, and the
        // operator would be told a number that is the product of two schedules.
        let error = run(
            "test",
            RunDeadline::unbounded(),
            &RunStall::unbounded(),
            |_| async {
                Err::<(), _>(Attempt {
                    observed: Observed {
                        status: Some(503),
                        code: None,
                        retry_after: Some(Duration::ZERO),
                        settled: false,
                    },
                    error: StoreError::Backend("busy".into()),
                })
            },
        )
        .await
        .expect_err("permanently busy");

        assert_eq!(error.attempts(), Some(RETRY_MAX_ATTEMPTS));
        assert!(error.to_string().contains("busy"), "{error}");
    }

    #[tokio::test]
    async fn no_b2_request_is_made_once_the_runs_window_has_closed() {
        // §32.9's 160 MiB row spent its 943.6 s in three distinct B2 requests,
        // each running this schedule in full. A run-level bound the layer above
        // enforced alone would have been a bound this loop could outlast.
        use std::sync::atomic::{AtomicU32, Ordering};

        let calls = AtomicU32::new(0);
        let error = run(
            "test",
            RunDeadline::starting_at(
                std::time::Instant::now() - Duration::from_secs(60),
                Some(Duration::from_secs(30)),
            ),
            &RunStall::unbounded(),
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Ok::<(), Attempt>(()) }
            },
        )
        .await
        .expect_err("the window is gone");

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(matches!(error, StoreError::RunDeadline { .. }), "{error}");
    }

    #[test]
    fn a_request_the_runs_deadline_ended_is_never_retried() {
        // The classification, asserted where it decides something. A closed
        // window handed to `verdict` as a transport failure would be retried
        // five more times into a run that is already over.
        let ended = Attempt::run_deadline(StoreError::RunDeadline {
            limit: Duration::from_secs(30),
        });
        assert_eq!(verdict(&ended.observed, 1), Verdict::Never);
    }

    #[tokio::test]
    async fn a_run_with_time_left_is_retried_exactly_as_before() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let calls = AtomicU32::new(0);
        let value = run(
            "test",
            RunDeadline::starting_now(Some(Duration::from_secs(600))),
            &RunStall::unbounded(),
            |number| {
                let seen = calls.fetch_add(1, Ordering::SeqCst) + 1;
                async move {
                    if seen < 3 {
                        Err(Attempt {
                            observed: Observed {
                                status: Some(503),
                                code: None,
                                retry_after: Some(Duration::ZERO),
                                settled: false,
                            },
                            error: StoreError::Backend("busy".into()),
                        })
                    } else {
                        Ok(number)
                    }
                }
            },
        )
        .await
        .expect("the third attempt succeeds");
        assert_eq!(value, 3);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
}
