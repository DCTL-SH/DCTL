//! The numbers that bound how long DCTL will keep asking.
//!
//! Every one of them answers the same operator question — *how long will this
//! command sit on a destination that is refusing?* — so they live together and
//! each carries the reasoning for its value rather than a number somebody can
//! "adjust". The per-provider selections built from them are in
//! [`super::policy`].

use std::time::Duration;

// ── the network schedule: sftp, b2, s3, r2 ───────────────────────────────────

/// How many attempts one network request gets, the first one included.
///
/// Five retries after the original. Enough to ride out the pod rotation behind
/// B2's `503 no tomes available` — which took five of ten files out of the first
/// live restore drill — and S3's documented `503 SlowDown`, without turning a
/// genuinely broken bucket into a run that looks hung. The same number the B2
/// module already ran with, kept deliberately: the two schedules being equal is
/// what makes one sentence in `docs/GLOBAL_FLAGS.md` true of every provider.
pub const NETWORK_MAX_ATTEMPTS: u32 = 6;

/// The deterministic wait before the second network attempt; each later one
/// doubles it.
///
/// Half a second, because the failures this schedule is for are decided by
/// another machine picking a different pod or shedding load, not by anything
/// healing. Retrying instantly spends the whole budget inside the window that
/// made the first attempt fail.
pub const NETWORK_FIRST_BACKOFF: Duration = Duration::from_millis(500);

/// The longest the schedule itself will wait between two network attempts.
///
/// Eight seconds: past this the doubling stops buying resilience and starts
/// buying a run nobody can tell from a hang.
pub const NETWORK_MAX_BACKOFF: Duration = Duration::from_secs(8);

/// The longest a server-sent `Retry-After` is obeyed.
///
/// A minute. A server that names a time knows something the schedule does not,
/// and arguing with it is how a rate limit becomes a ban — so it wins over the
/// schedule. It does not win unboundedly: a header of `86400` on a nightly
/// backup would produce a process that sits silent for a day, and a failure an
/// operator can see beats a wait they cannot.
pub const RETRY_AFTER_CAP: Duration = Duration::from_secs(60);

/// The total time one network operation may spend *waiting* across all of its
/// retries.
///
/// The ceiling that makes the schedule statable rather than merely bounded.
/// Without it the worst case is the attempt count times [`RETRY_AFTER_CAP`] —
/// five minutes of silence per object, which on a ten-thousand-object sync is a
/// run that never ends. Two minutes is long enough to outlast every transient
/// condition these providers document and short enough that a stuck object
/// fails while somebody is still watching.
pub const NETWORK_TOTAL_BUDGET: Duration = Duration::from_secs(120);

// ── the local schedule ───────────────────────────────────────────────────────

/// How many attempts one local-filesystem operation gets.
///
/// Three, and far fewer than the network's six, because the errors worth
/// retrying here are a different species. A local write does not meet a busy
/// storage pod; it meets `EAGAIN` or `ETIMEDOUT` on a network mount that is
/// briefly wedged. Those clear in milliseconds or they do not clear at all, and
/// six attempts would only lengthen the report of a disk that is genuinely
/// gone.
pub const LOCAL_MAX_ATTEMPTS: u32 = 3;

/// The deterministic wait before the second local attempt.
pub const LOCAL_FIRST_BACKOFF: Duration = Duration::from_millis(100);

/// The longest wait between two local attempts.
pub const LOCAL_MAX_BACKOFF: Duration = Duration::from_millis(500);

/// The total waiting one local operation may accumulate.
///
/// A second. Anything on a local filesystem that has not cleared within a second
/// is a condition an operator has to be told about, not waited out.
pub const LOCAL_TOTAL_BUDGET: Duration = Duration::from_secs(1);

// ── jitter ───────────────────────────────────────────────────────────────────

/// The fraction of a computed backoff that is **never** jittered away, as a
/// numerator over [`JITTER_FLOOR_DENOMINATOR`].
///
/// Half. This is "equal jitter" rather than AWS's "full jitter", and the
/// difference matters here: full jitter draws uniformly from `[0, backoff)` and
/// can therefore collapse a wait to almost nothing, which retries inside the
/// very window that made the first attempt fail. Keeping half the deterministic
/// wait preserves the schedule's purpose while the other half still decorrelates
/// a fleet of clients that all met the same outage — which is the only thing
/// jitter is for.
pub const JITTER_FLOOR_NUMERATOR: u32 = 1;

/// Denominator for [`JITTER_FLOOR_NUMERATOR`].
pub const JITTER_FLOOR_DENOMINATOR: u32 = 2;

// ── HTTP statuses ────────────────────────────────────────────────────────────

/// The first server-error status. Everything at or above it is the provider's
/// problem rather than the request's, and is retried by every HTTP provider.
pub const HTTP_SERVER_ERROR: u16 = 500;

/// `408 Request Timeout` — the server gave up waiting for a request that may
/// never have arrived whole.
pub const HTTP_REQUEST_TIMEOUT: u16 = 408;

/// `429 Too Many Requests` — a rate limit, and the status most likely to carry
/// a `Retry-After` worth obeying.
pub const HTTP_TOO_MANY_REQUESTS: u16 = 429;

// ── the rules these numbers have to keep ─────────────────────────────────────
//
// Compile-time rather than in a test, because a constant that has drifted out of
// range is not a behaviour worth discovering at `cargo test` — it is a build
// that should not produce a binary. The `const _: () = assert!(…)` form is what
// makes a violated invariant a compiler error naming this file.

/// The local schedule is the impatient one. If these ever converge, one of the
/// two justifications above has stopped being true and should be deleted rather
/// than quietly kept.
const _: () = assert!(LOCAL_MAX_ATTEMPTS < NETWORK_MAX_ATTEMPTS);
const _: () = assert!(LOCAL_MAX_BACKOFF.as_nanos() < NETWORK_MAX_BACKOFF.as_nanos());
const _: () = assert!(LOCAL_TOTAL_BUDGET.as_nanos() < NETWORK_TOTAL_BUDGET.as_nanos());

/// The jitter floor is a real fraction strictly below one: at zero the schedule
/// could collapse to nothing, and at one there would be no jitter at all.
const _: () = assert!(JITTER_FLOOR_NUMERATOR >= 1);
const _: () = assert!(JITTER_FLOOR_NUMERATOR < JITTER_FLOOR_DENOMINATOR);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_deterministic_schedule_fits_inside_its_own_budget() {
        // A budget smaller than the sum of the waits would make the attempt
        // count a fiction: the run would stop early and report a number of
        // attempts nobody could predict from the constants. Arithmetic over a
        // loop rather than a comparison of two constants, which is why it is a
        // test and the rules above are not.
        for (attempts, first, cap, budget) in [
            (
                NETWORK_MAX_ATTEMPTS,
                NETWORK_FIRST_BACKOFF,
                NETWORK_MAX_BACKOFF,
                NETWORK_TOTAL_BUDGET,
            ),
            (
                LOCAL_MAX_ATTEMPTS,
                LOCAL_FIRST_BACKOFF,
                LOCAL_MAX_BACKOFF,
                LOCAL_TOTAL_BUDGET,
            ),
        ] {
            let mut total = Duration::ZERO;
            let mut wait = first;
            for _ in 1..attempts {
                total += wait.min(cap);
                wait = wait.saturating_mul(2);
            }
            assert!(
                total <= budget,
                "the schedule waits {total:?}, which its budget of {budget:?} cuts short"
            );
        }
    }
}
