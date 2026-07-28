//! What one provider considers worth another attempt, and how patient it is.
//!
//! Two shapes, and the split is a real one rather than tidiness.
//!
//! * [`RetryPolicy::network`] — `sftp`, `b2`, `s3`, `r2`. A request crosses a
//!   link and may meet a busy pod, a rate limit, or a socket that died. Six
//!   attempts over up to two minutes of waiting.
//! * [`RetryPolicy::local`] — `local:`. Nothing crosses a link, and the only
//!   errors worth another attempt are the ones a briefly-wedged network mount
//!   produces. Three attempts over one second: they clear immediately or they do
//!   not clear at all.
//! * [`RetryPolicy::none`] — for a caller that must see the first failure
//!   exactly as it happened. Used by the tests that assert what one attempt
//!   returns, so those assertions cannot be made vacuous by a retry silently
//!   turning a failure into a success.
//!
//! # Which statuses, per provider
//!
//! Every HTTP provider retries `5xx`, `408` and `429`; that is the intersection
//! of what Backblaze and AWS both document and what rclone implements
//! (`backend/s3/s3.go:1267-1271` lists exactly `429`, `500`, `503`). What no
//! policy here retries is `401` or `403`: a wrong key and an exhausted cap are
//! both stable facts, and classifying them as temporary is what once made a
//! permanently wrong `DCTL_B2_APP_KEY` report an exit code telling a scheduler
//! to back off and try again forever.
//!
//! B2's own `401 expired_auth_token` **is** retryable — after re-authorizing —
//! and stays where the re-authorization is: `b2::retry`, one layer down. A rule
//! here could not perform the step that makes the next attempt differ, so
//! carrying the rule would be carrying a lie.

use std::time::Duration;

use super::constants::{
    HTTP_REQUEST_TIMEOUT, HTTP_SERVER_ERROR, HTTP_TOO_MANY_REQUESTS, LOCAL_FIRST_BACKOFF,
    LOCAL_MAX_ATTEMPTS, LOCAL_MAX_BACKOFF, LOCAL_TOTAL_BUDGET, NETWORK_FIRST_BACKOFF,
    NETWORK_MAX_ATTEMPTS, NETWORK_MAX_BACKOFF, NETWORK_TOTAL_BUDGET, RETRY_AFTER_CAP,
};

/// A provider's retry schedule and the statuses it treats as temporary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Attempts including the first. `1` disables retrying entirely.
    pub max_attempts: u32,
    /// The deterministic wait before the second attempt; each later one doubles
    /// it, up to [`RetryPolicy::max_backoff`].
    pub first_backoff: Duration,
    /// The ceiling on one wait.
    pub max_backoff: Duration,
    /// The ceiling on a `Retry-After` the server sent.
    pub retry_after_cap: Duration,
    /// The ceiling on the sum of every wait for one operation.
    pub total_budget: Duration,
    /// Whether HTTP statuses mean anything to this provider at all.
    ///
    /// `false` for `local:`, where a status is not a thing that exists — and
    /// where a policy that pretended otherwise would be a dial that does
    /// nothing, which is the class of defect `HANDOVER.md` §13 is about.
    pub understands_http: bool,
}

impl RetryPolicy {
    /// The schedule for a provider reached over a network.
    #[must_use]
    pub const fn network() -> Self {
        Self {
            max_attempts: NETWORK_MAX_ATTEMPTS,
            first_backoff: NETWORK_FIRST_BACKOFF,
            max_backoff: NETWORK_MAX_BACKOFF,
            retry_after_cap: RETRY_AFTER_CAP,
            total_budget: NETWORK_TOTAL_BUDGET,
            understands_http: true,
        }
    }

    /// The schedule for a filesystem on this machine.
    #[must_use]
    pub const fn local() -> Self {
        Self {
            max_attempts: LOCAL_MAX_ATTEMPTS,
            first_backoff: LOCAL_FIRST_BACKOFF,
            max_backoff: LOCAL_MAX_BACKOFF,
            retry_after_cap: RETRY_AFTER_CAP,
            total_budget: LOCAL_TOTAL_BUDGET,
            understands_http: false,
        }
    }

    /// No retrying at all: the first failure is the answer.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            max_attempts: 1,
            ..Self::local()
        }
    }

    /// The schedule named by a backend's own [`Backend::name`](crate::Backend::name).
    ///
    /// A match with no wildcard arm, for the reason `remote::registry::Built`
    /// gives about the meter: a provider added later must be given an answer
    /// deliberately rather than inheriting one by falling through. An unknown
    /// name gets the network schedule, which is the safe direction — it retries
    /// a filesystem error a little longer than necessary, where the other
    /// default would leave a new cloud provider with no retry at all and nothing
    /// to indicate it.
    #[must_use]
    pub fn for_backend(name: &str) -> Self {
        match name {
            "local" => Self::local(),
            "sftp" | "b2" | "s3" | "r2" => Self::network(),
            _ => Self::network(),
        }
    }

    /// Whether this provider treats `status` as temporary.
    #[must_use]
    pub fn retries_status(&self, status: u16) -> bool {
        self.understands_http
            && (status >= HTTP_SERVER_ERROR
                || status == HTTP_REQUEST_TIMEOUT
                || status == HTTP_TOO_MANY_REQUESTS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_http_provider_retries_the_three_documented_classes() {
        let policy = RetryPolicy::network();
        for status in [408, 429, 500, 502, 503, 504, 599] {
            assert!(policy.retries_status(status), "{status} should be retried");
        }
    }

    #[test]
    fn a_wrong_key_and_an_exhausted_cap_are_never_temporary() {
        // The distinction the exit code depends on: retrying these turns a clear
        // failure into a slow one and tells a scheduler to come back forever.
        let policy = RetryPolicy::network();
        for status in [400, 401, 403, 404, 405, 409, 416] {
            assert!(!policy.retries_status(status), "{status}");
        }
    }

    #[test]
    fn a_local_filesystem_has_no_opinion_about_http() {
        // Not "retries nothing" — it retries `EAGAIN` through the errno rules —
        // but a status is not a thing `local:` can observe, and a policy that
        // answered one would be describing a request it never makes.
        let policy = RetryPolicy::local();
        for status in [408, 429, 500, 503] {
            assert!(!policy.retries_status(status), "{status}");
        }
    }

    #[test]
    fn every_provider_this_build_ships_gets_a_named_schedule() {
        // The guard against a provider being added and silently inheriting
        // whatever the wildcard happened to be.
        assert_eq!(RetryPolicy::for_backend("local"), RetryPolicy::local());
        for name in ["sftp", "b2", "s3", "r2"] {
            assert_eq!(
                RetryPolicy::for_backend(name),
                RetryPolicy::network(),
                "{name}"
            );
        }
    }

    #[test]
    fn disabling_retries_leaves_exactly_one_attempt() {
        assert_eq!(RetryPolicy::none().max_attempts, 1);
    }
}
