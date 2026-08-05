//! The decision: can another attempt change this outcome, and how long should
//! the caller wait first?
//!
//! Pure. No clock, no sleep, no network, no randomness — so every rule below is
//! asserted directly in this file's tests rather than inferred from a run
//! against a provider that happened to be in a good mood. The jitter that makes
//! a real wait differ from the number returned here is applied by
//! [`super::backoff`] at the moment of waiting, deliberately kept out so that
//! this function stays a total function of its inputs.
//!
//! ## The table this implements
//!
//! | Observed | Verdict | Why |
//! |---|---|---|
//! | a lower layer already retried it | **never** | its budget is spent; spending a second one multiplies the wait and reports a count nobody can predict |
//! | the attempt budget is used up | **never** | the last permitted attempt is the last one |
//! | the waiting budget is used up | **never** | the ceiling that makes the schedule statable |
//! | nothing answered | retry | the request may never have arrived |
//! | a reset / timed-out / `EAGAIN` I/O error | retry | rclone retries the same set |
//! | a status this provider calls temporary | retry, honouring `Retry-After` | see [`RetryPolicy::retries_status`] |
//! | anything else | **never** | the request is wrong, and it will be equally wrong next time |

use std::time::Duration;

use super::observed::Observed;
use super::policy::RetryPolicy;

/// Whether another attempt can change the outcome, and how long to wait first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Try again after this deterministic delay. [`super::backoff::jittered`]
    /// turns it into the delay actually slept.
    After(Duration),
    /// Do not try again: the answer will be the same.
    Never,
}

/// Decide whether the `attempt`-th try (1-based) failing as `observed` should be
/// followed by another, given that `waited` has already been spent waiting.
#[must_use]
pub fn verdict(
    observed: &Observed,
    attempt: u32,
    waited: Duration,
    policy: &RetryPolicy,
) -> Verdict {
    // A layer below has already spent a budget on this. Spending a second one
    // multiplies the total wait by the inner attempt count and — the part that
    // matters more — makes the number finally reported to the operator a product
    // of two schedules rather than a fact. rclone marks the same case on the
    // error itself.
    if observed.already_attempted.is_some() {
        return Verdict::Never;
    }
    if attempt >= policy.max_attempts {
        return Verdict::Never;
    }
    if waited >= policy.total_budget {
        return Verdict::Never;
    }

    let delay = match observed.status {
        // Nothing answered, or the transport itself failed in a way that another
        // attempt could survive.
        None => {
            if observed.transient {
                backoff(attempt, policy)
            } else {
                return Verdict::Never;
            }
        }
        Some(status) if policy.retries_status(status) => observed.retry_after.map_or_else(
            || backoff(attempt, policy),
            |after| after.min(policy.retry_after_cap),
        ),
        Some(_) => return Verdict::Never,
    };

    // Never wait past the budget: a delay that would overshoot it is clamped to
    // whatever remains, so the ceiling is the ceiling rather than an
    // approximation of one.
    let remaining = policy.total_budget.saturating_sub(waited);
    Verdict::After(delay.min(remaining))
}

/// The deterministic delay before the attempt following the `attempt`-th
/// (1-based).
///
/// Doubles from [`RetryPolicy::first_backoff`] and saturates at
/// [`RetryPolicy::max_backoff`], so the schedule cannot overflow however high
/// the attempt counter is taken.
fn backoff(attempt: u32, policy: &RetryPolicy) -> Duration {
    let doubled = policy
        .first_backoff
        .checked_mul(
            1u32.checked_shl(attempt.saturating_sub(1))
                .unwrap_or(u32::MAX),
        )
        .unwrap_or(policy.max_backoff);
    doubled.min(policy.max_backoff)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network() -> RetryPolicy {
        RetryPolicy::network()
    }

    fn status(code: u16) -> Observed {
        Observed::status(code)
    }

    fn first(observed: &Observed) -> Verdict {
        verdict(observed, 1, Duration::ZERO, &network())
    }

    #[test]
    fn a_request_that_never_got_an_answer_is_retried() {
        assert!(matches!(first(&Observed::transport()), Verdict::After(_)));
    }

    #[test]
    fn the_status_a_busy_bucket_returns_is_retried_on_every_http_provider() {
        // The two failures this exists for, named: B2's `503 no tomes
        // available`, which took five of ten files out of the first live restore
        // drill, and S3's `503 SlowDown`, which AWS documents as "retry with
        // backoff" and which failed a DCTL write on the first response.
        for code in ["service_unavailable", "SlowDown"] {
            let observed = Observed {
                code: Some(code.to_string()),
                ..status(503)
            };
            assert!(matches!(first(&observed), Verdict::After(_)), "{code}");
        }
    }

    #[test]
    fn every_server_error_is_retried_and_every_ordinary_client_error_is_not() {
        for code in [500, 502, 503, 504, 599] {
            assert!(
                matches!(first(&status(code)), Verdict::After(_)),
                "{code} should be retried"
            );
        }
        for code in [400, 401, 403, 404, 405, 409, 416] {
            assert_eq!(first(&status(code)), Verdict::Never, "{code}");
        }
    }

    #[test]
    fn a_permanent_local_failure_is_not_retried_however_transient_looking() {
        // `transient: false` with no status is what an unclassified backend
        // failure and a full disk both look like, and neither is a wait.
        assert_eq!(first(&Observed::terminal()), Verdict::Never);
    }

    #[test]
    fn the_servers_retry_after_wins_over_the_schedule_but_not_over_the_cap() {
        let asked = Observed {
            retry_after: Some(Duration::from_secs(7)),
            ..status(429)
        };
        assert_eq!(first(&asked), Verdict::After(Duration::from_secs(7)));

        let absurd = Observed {
            retry_after: Some(Duration::from_secs(86_400)),
            ..status(503)
        };
        assert_eq!(first(&absurd), Verdict::After(network().retry_after_cap));
    }

    #[test]
    fn the_attempt_budget_is_finite_and_the_deterministic_waits_grow() {
        let policy = network();
        assert_eq!(
            verdict(
                &Observed::transport(),
                policy.max_attempts,
                Duration::ZERO,
                &policy
            ),
            Verdict::Never
        );

        // Each deterministic wait is at least as long as the one before it and
        // never longer than the cap. An arithmetic slip here is a retry storm,
        // so it is asserted rather than read off the constants.
        let mut previous = Duration::ZERO;
        for attempt in 1..policy.max_attempts {
            let Verdict::After(delay) = verdict(&status(503), attempt, Duration::ZERO, &policy)
            else {
                panic!(
                    "attempt {attempt} of {} should be retried",
                    policy.max_attempts
                );
            };
            assert!(delay >= previous, "backoff went backwards at {attempt}");
            assert!(delay <= policy.max_backoff, "backoff exceeded its cap");
            previous = delay;
        }
    }

    #[test]
    fn the_waiting_budget_is_a_ceiling_and_not_a_suggestion() {
        let policy = network();
        // Spent: no further attempt, whatever the status says.
        assert_eq!(
            verdict(&status(503), 1, policy.total_budget, &policy),
            Verdict::Never
        );
        // Nearly spent: the next wait is clipped to what is left rather than
        // overshooting the ceiling the constants advertise.
        let nearly = policy.total_budget - Duration::from_millis(50);
        let asked = Observed {
            retry_after: Some(Duration::from_secs(30)),
            ..status(503)
        };
        assert_eq!(
            verdict(&asked, 1, nearly, &policy),
            Verdict::After(Duration::from_millis(50))
        );
    }

    #[test]
    fn an_error_a_lower_layer_already_retried_is_not_retried_again() {
        // Without this, B2's six request-level attempts under six operation-level
        // ones would be thirty-six attempts and up to twelve minutes of waiting
        // for one object — and the count finally reported would be the product of
        // two schedules rather than a fact.
        let exhausted = Observed {
            already_attempted: Some(6),
            ..status(503)
        };
        assert_eq!(first(&exhausted), Verdict::Never);
    }

    #[test]
    fn the_local_policy_retries_an_errno_and_not_a_status() {
        let policy = RetryPolicy::local();
        assert!(matches!(
            verdict(&Observed::transport(), 1, Duration::ZERO, &policy),
            Verdict::After(_)
        ));
        assert_eq!(
            verdict(&status(503), 1, Duration::ZERO, &policy),
            Verdict::Never,
            "a local filesystem does not answer with a status"
        );
    }

    #[test]
    fn a_policy_of_one_attempt_never_retries_anything() {
        let policy = RetryPolicy::none();
        for observed in [Observed::transport(), status(503)] {
            assert_eq!(
                verdict(&observed, 1, Duration::ZERO, &policy),
                Verdict::Never
            );
        }
    }
}
