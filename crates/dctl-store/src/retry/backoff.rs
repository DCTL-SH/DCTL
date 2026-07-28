//! Turning the schedule's deterministic delay into the delay actually slept.
//!
//! # Why jitter at all
//!
//! Because the failures worth retrying are usually *shared*. A provider sheds
//! load, or a link flaps, and every client that was mid-request meets it at the
//! same instant. A purely deterministic schedule then has all of them come back
//! at the same instant too, and again half a second later, and again a second
//! after that — so the retry storm reproduces the outage it was meant to ride
//! out. Spreading the return over a window is the whole of the fix, and it is
//! the only thing jitter is for.
//!
//! B2's original retry module argued the opposite — *"one CLI process retrying
//! one request is not a fleet"* — and that was true of one process. It stopped
//! being true the moment the schedule covered every provider and every object of
//! a run: a `--transfers 8` sync is eight requests meeting the same `503` in the
//! same millisecond, and a nightly cron on a fleet of machines is however many
//! machines there are. What an operator loses is a schedule they can recite; what
//! they keep is a schedule they can **bound**, which is what
//! [`RetryPolicy::total_budget`](super::policy::RetryPolicy::total_budget) is
//! for and what the reciting was really wanted for.
//!
//! # Equal jitter, not full jitter
//!
//! AWS's "full jitter" draws uniformly from `[0, backoff)`, which can collapse a
//! wait to almost nothing — retrying inside the very window that made the first
//! attempt fail. This keeps the first half of the deterministic wait and
//! randomises the second: the delay always lands in `[backoff/2, backoff]`. The
//! fraction is [`JITTER_FLOOR_NUMERATOR`]/[`JITTER_FLOOR_DENOMINATOR`] so the
//! trade is stated in one place rather than implied by a `/ 2`.
//!
//! # A `Retry-After` is never jittered
//!
//! The server named a time. Waiting less than it was asked to is how a client
//! that is being throttled becomes a client that is being blocked, so
//! [`jittered`] is applied to the *schedule's* delay only, and
//! [`super::classify::verdict`] hands back the server's number untouched.
//! Distinguishing the two is the caller's job, and [`super::driver`] is the one
//! caller.
//!
//! # Where the randomness comes from
//!
//! [`std::hash::RandomState`], seeded by the operating system once per process,
//! hashed together with a monotonically increasing counter. That is decorrelated
//! across processes and across calls, which is all jitter requires — it makes no
//! cryptographic claim and needs none, and it keeps this crate free of a
//! random-number dependency for a use with no secrecy in it.
//!
//! The function that consumes it takes the entropy as a **parameter**, so the
//! distribution's two ends are asserted exactly rather than sampled.

use std::hash::{BuildHasher as _, RandomState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::constants::{JITTER_FLOOR_DENOMINATOR, JITTER_FLOOR_NUMERATOR};

/// Spread `delay` over `[delay * floor, delay]`, using `entropy` to pick a point.
///
/// Pure: the same `entropy` always yields the same delay, which is what makes
/// the two ends of the window assertable.
#[must_use]
pub fn jittered(delay: Duration, entropy: u64) -> Duration {
    let nanos = u64::try_from(delay.as_nanos()).unwrap_or(u64::MAX);
    let floor = nanos / u64::from(JITTER_FLOOR_DENOMINATOR) * u64::from(JITTER_FLOOR_NUMERATOR);
    let window = nanos.saturating_sub(floor);
    if window == 0 {
        return delay;
    }
    // `% (window + 1)` so the top of the window is reachable: the deterministic
    // delay must remain a possible outcome, or the schedule an operator reads in
    // the constants would never actually occur.
    Duration::from_nanos(floor.saturating_add(entropy % (window.saturating_add(1))))
}

/// A fresh entropy value for one wait.
///
/// Not `pub`: nothing outside the driver should be picking its own source, or
/// two waits in the same run would be spread by two different distributions and
/// the schedule would stop being one thing.
pub(super) fn entropy() -> u64 {
    // One `RandomState` per process, seeded by the OS. The counter is what makes
    // successive calls differ; the hasher is what makes two processes that
    // started together differ, which is the case jitter exists for.
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    thread_local! {
        static STATE: RandomState = RandomState::new();
    }
    STATE.with(|state| state.hash_one(COUNTER.fetch_add(1, Ordering::Relaxed)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lowest_entropy_gives_the_floor_and_the_top_of_the_window_gives_the_whole_delay() {
        // Both ends, exactly, rather than a sample: this is the property the
        // whole module is, and a sampled assertion would pass over an
        // off-by-one that clipped the deterministic schedule out of existence —
        // which would mean the schedule an operator reads in `constants.rs`
        // never actually occurs.
        let delay = Duration::from_millis(800);
        let floor = Duration::from_millis(400);
        assert_eq!(jittered(delay, 0), floor);

        // The window is `delay - floor` nanoseconds wide and is selected by
        // `entropy % (window + 1)`, so the value that lands on its top is the
        // window itself. Spelled out rather than reached for with `u64::MAX`,
        // which lands wherever the modulus happens to put it.
        let window = (delay - floor).as_nanos() as u64;
        assert_eq!(jittered(delay, window), delay);
    }

    #[test]
    fn every_outcome_lies_inside_the_window() {
        let delay = Duration::from_millis(500);
        let floor = delay / 2;
        for entropy in [0, 1, 7, 999, 1 << 40, u64::MAX] {
            let actual = jittered(delay, entropy);
            assert!(actual >= floor, "{entropy}: {actual:?} below the floor");
            assert!(actual <= delay, "{entropy}: {actual:?} above the schedule");
        }
    }

    #[test]
    fn a_zero_delay_stays_zero() {
        // The `RetryPolicy::none()` and budget-exhausted paths both produce one,
        // and a modulo by zero here would be a panic in a crate that forbids
        // them.
        assert_eq!(jittered(Duration::ZERO, 12_345), Duration::ZERO);
    }

    #[test]
    fn an_absurd_delay_does_not_overflow_into_a_short_one() {
        // `Duration::MAX` has more nanoseconds than a `u64` can hold. Saturating
        // rather than wrapping is what stops a wait of nearly forever from
        // becoming a wait of nearly nothing — the failure that would look
        // exactly like a retry storm.
        let huge = jittered(Duration::MAX, u64::MAX);
        assert!(huge >= Duration::from_secs(1));
    }

    #[test]
    fn successive_draws_differ() {
        // Not a distribution test — a wiring test. An `entropy()` that returned a
        // constant would satisfy every other assertion in this file and defeat
        // the entire point of the module.
        let draws: Vec<u64> = (0..8).map(|_| entropy()).collect();
        assert!(
            draws.windows(2).any(|pair| pair[0] != pair[1]),
            "entropy() returned the same value every time: {draws:?}"
        );
    }

    #[test]
    fn the_spread_actually_covers_more_than_one_point() {
        // The property a fleet depends on: two clients that met the same outage
        // must not come back together. Asserted over the real source, since a
        // jitter that is deterministic in practice is no jitter at all.
        let delay = Duration::from_millis(1000);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            seen.insert(jittered(delay, entropy()));
        }
        assert!(seen.len() > 1, "every draw produced the same delay");
    }
}
