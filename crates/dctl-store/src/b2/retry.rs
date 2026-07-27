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
}

impl Observed {
    /// A request that never got an answer.
    pub(super) const fn transport() -> Self {
        Self {
            status: None,
            code: None,
            retry_after: None,
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
/// help, or until the attempt budget is spent — whichever comes first.
///
/// `attempt` is handed the 1-based attempt number so a caller that must do
/// something different on a retry (fetch a fresh upload URL, re-authorize) can
/// see that it is one. `op` names the operation in the log line each retry
/// emits, which is what makes a slow run explicable afterwards.
pub(super) async fn run<T, A, F>(op: &'static str, mut attempt: A) -> Result<T>
where
    A: FnMut(u32) -> F,
    F: Future<Output = std::result::Result<T, Attempt>>,
{
    let mut number = 1u32;
    loop {
        match attempt(number).await {
            Ok(value) => {
                if number > 1 {
                    tracing::info!(op, attempts = number, "b2 request succeeded on a retry");
                }
                return Ok(value);
            }
            Err(failed) => match verdict(&failed.observed, number) {
                Verdict::Never => {
                    tracing::debug!(
                        op,
                        attempts = number,
                        status = failed.observed.status,
                        "b2 request will not be retried"
                    );
                    return Err(failed.error);
                }
                Verdict::After(delay) => {
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
            },
        }
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
        };
        assert_eq!(verdict(&bad_key, 1), Verdict::Never);
        assert!(!bad_key.is_expired_token());

        let expired = Observed {
            status: Some(401),
            code: Some(CODE_EXPIRED_AUTH_TOKEN.to_string()),
            retry_after: None,
        };
        assert!(matches!(verdict(&expired, 1), Verdict::After(_)));
        assert!(expired.is_expired_token());

        // A `401` with no code at all is the wrong-credential case too: nothing
        // observed says otherwise, and guessing "temporary" is the guess that
        // loops forever.
        assert_eq!(verdict(&status(401), 1), Verdict::Never);
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
        };
        assert_eq!(verdict(&asked, 1), Verdict::After(Duration::from_secs(7)));

        let absurd = Observed {
            status: Some(503),
            code: None,
            retry_after: Some(Duration::from_secs(86_400)),
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

    #[tokio::test]
    async fn the_driver_returns_the_first_success_and_counts_its_attempts() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let calls = AtomicU32::new(0);
        let value = run("test", |number| {
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
                        },
                        error: StoreError::Backend("busy".into()),
                    })
                } else {
                    Ok(number)
                }
            }
        })
        .await
        .expect("the third attempt succeeds");

        assert_eq!(value, 3, "the closure is told which attempt it is");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn the_driver_reports_the_last_error_and_stops_on_a_permanent_one() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let calls = AtomicU32::new(0);
        let error = run("test", |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async {
                Err::<(), _>(Attempt {
                    observed: Observed {
                        status: Some(401),
                        code: Some("bad_auth_token".to_string()),
                        retry_after: None,
                    },
                    error: StoreError::Backend("b2 api error 401: bad_auth_token".into()),
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
        assert!(error.to_string().contains("bad_auth_token"));
    }
}
