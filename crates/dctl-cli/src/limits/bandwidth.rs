//! `--bwlimit`: pacing the run so its average rate does not exceed the limit.
//!
//! ## What this does, exactly
//!
//! Every file that finishes is **charged for the bytes it actually moved**, and
//! the next file waits until that charge has been paid off at the configured
//! rate. Over a run the average throughput converges on the limit from above by
//! at most one file: the first file is never delayed, because there is nothing
//! before it to be delayed by.
//!
//! ## What it does not do, said plainly
//!
//! It does not shape the wire. `--bwlimit 1M` will still put a 100 MiB file onto
//! the link as fast as the link takes it, and then wait ~100 s before the next
//! one. rclone's limiter is finer — it charges every buffer as `io.Reader.Read`
//! returns it — and DCTL's cannot be, because this engine hands a whole object
//! to `dctl_store::Backend::put` in one call and gets a byte count back at the
//! end. There is no per-buffer seam to charge, and inventing one would mean
//! rewriting the upload path rather than adding a limiter.
//!
//! That limitation is stated in `--help`, in `docs/GLOBAL_FLAGS.md` and here,
//! rather than hidden, because the two uses of this flag are affected very
//! differently:
//!
//! * **Capping a bill or a metered link** — the thing an operator sets it for —
//!   is served exactly. The average rate over the run is the limit, so the bytes
//!   per month are the limit.
//! * **Keeping a video call usable while a backup runs** is served only at file
//!   granularity. A tree of small files behaves as expected; one enormous file
//!   will saturate the uplink for its duration.
//!
//! Charging **after** the transfer rather than before is deliberate on both
//! counts. The bytes are then a measurement rather than the plan's estimate, so
//! a source that changed under the run is accounted for as it really was; and a
//! file that failed and was retried is charged for every attempt, because every
//! attempt really did use the link.
//!
//! ## Why not a token bucket with a burst
//!
//! Because a bucket that can hold a second's worth of credit is only
//! distinguishable from this one at sub-file granularity, which is exactly the
//! resolution this limiter does not have. The virtual-clock form below is the
//! same policy with one fewer tunable to explain.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::quantity::ByteLimit;

/// Paces a run to a byte rate.
///
/// Shared behind an `Arc` on [`crate::ctx::Ctx`] and charged from the transfer
/// pipeline, so a single limit applies to the whole run rather than one per
/// destination — which is what "do not use more than 1 MB/s of my uplink"
/// means.
#[derive(Debug)]
pub struct Bandwidth {
    /// Bytes per second, or `None` for an unpaced run.
    rate: Option<u64>,

    /// The instant at which the *next* charge may proceed — a virtual clock
    /// running ahead of the wall clock by exactly the debt still owed.
    ///
    /// A `std::sync::Mutex` rather than a `tokio` one because it is never held
    /// across an await: the wait is computed under the lock and slept for after
    /// it is released. Holding an async mutex across the sleep would serialise
    /// the *waiting* as well as the accounting, which would make two concurrent
    /// callers queue behind each other instead of sharing the rate.
    next: Mutex<Instant>,
}

impl Bandwidth {
    /// A limiter for `limit` bytes per second, or an unpaced one for `off`.
    #[must_use]
    pub fn new(limit: ByteLimit) -> Self {
        Self {
            rate: limit.get(),
            next: Mutex::new(Instant::now()),
        }
    }

    // The two below are `cfg(test)`, and for the reason `crate::remote::spec`
    // gives for the same arrangement: they are how the limiter is *observed*,
    // and production has no question to ask it. [`Bandwidth::charge`] already
    // short-circuits an unpaced run inside [`Bandwidth::debt`], so a caller that
    // consulted `is_limited` first would be asking the same question twice and
    // could get it wrong once.

    /// An unpaced limiter.
    #[cfg(test)]
    #[must_use]
    pub fn unlimited() -> Self {
        Self::new(ByteLimit::none())
    }

    /// Whether this run is paced at all.
    #[cfg(test)]
    #[must_use]
    pub const fn is_limited(&self) -> bool {
        self.rate.is_some()
    }

    /// Account for `bytes` having been moved, and sleep off any resulting debt.
    ///
    /// Called after the bytes are on the wire, so the wait it produces is felt
    /// by whatever comes next. Returns immediately when the run is unpaced or
    /// nothing moved.
    pub async fn charge(&self, bytes: u64) {
        let Some(wait) = self.debt(bytes) else {
            return;
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }

    /// Advance the virtual clock by what `bytes` cost, and return the wait that
    /// leaves for the caller.
    ///
    /// Split out of [`Bandwidth::charge`] so the arithmetic is testable without
    /// a runtime and without spending the wall-clock time it computes: a test
    /// that had to sleep for the answer could only ever check small ones.
    fn debt(&self, bytes: u64) -> Option<Duration> {
        let rate = self.rate?;
        if bytes == 0 {
            return None;
        }

        // A poisoned lock is recovered from rather than propagated. The only
        // state behind it is a timestamp; the worst a torn update could do is
        // pace one file wrongly, and refusing to transfer anything else because
        // a rate limiter panicked would be a far larger failure than the one
        // being handled.
        let mut next = self
            .next
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let now = Instant::now();
        // Credit does not accumulate: an idle minute must not buy a minute of
        // unpaced transfer afterwards, which is the difference between an
        // average-rate cap and a cap on nothing at all.
        let start = (*next).max(now);
        let wait = start.saturating_duration_since(now);

        // `f64` rather than integer division: at 1 kB/s a 100-byte file costs
        // 0.1 s, and integer arithmetic would round every small file to zero and
        // let a tree of them past the limit entirely.
        #[allow(clippy::cast_precision_loss)]
        let cost = Duration::from_secs_f64(bytes as f64 / rate as f64);
        *next = start + cost;

        Some(wait)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rate that makes the arithmetic below readable: one byte per
    /// millisecond.
    const KIBIBYTE_PER_SECOND: u64 = 1000;

    fn limiter(rate: u64) -> Bandwidth {
        Bandwidth::new(ByteLimit::bytes(rate))
    }

    #[test]
    fn an_unpaced_run_never_waits() {
        let bandwidth = Bandwidth::unlimited();
        assert!(!bandwidth.is_limited());
        assert_eq!(bandwidth.debt(u64::MAX), None);
    }

    #[test]
    fn the_first_charge_is_free_and_the_next_one_pays_for_it() {
        // The documented shape of the limiter: nothing is delayed before the
        // first byte moves, and the debt it created is felt by what follows.
        let bandwidth = limiter(KIBIBYTE_PER_SECOND);
        assert_eq!(bandwidth.debt(1000), Some(Duration::ZERO));

        let wait = bandwidth.debt(1000).expect("a paced run returns a wait");
        assert!(
            wait >= Duration::from_millis(900),
            "1000 bytes at 1000 B/s must owe about a second, got {wait:?}"
        );
        assert!(wait <= Duration::from_millis(1100), "{wait:?}");
    }

    #[test]
    fn the_debt_accumulates_across_files_rather_than_resetting() {
        // The property that makes this an average-rate cap. If each charge only
        // looked at the wall clock, ten files in quick succession would each
        // wait for the previous one alone and nine tenths of the run would be
        // unpaced.
        let bandwidth = limiter(KIBIBYTE_PER_SECOND);
        let _ = bandwidth.debt(1000);
        let first = bandwidth.debt(1000).unwrap_or_default();
        let second = bandwidth.debt(1000).unwrap_or_default();
        assert!(
            second > first + Duration::from_millis(500),
            "the second file must wait for both of its predecessors: \
             {first:?} then {second:?}"
        );
    }

    #[test]
    fn a_small_file_is_not_rounded_down_to_free() {
        // Integer division would make every file below the per-second rate cost
        // zero, and a tree of small files would move at full speed under a
        // limit the user believed they had set.
        let bandwidth = limiter(KIBIBYTE_PER_SECOND);
        let _ = bandwidth.debt(100);
        let wait = bandwidth.debt(100).unwrap_or_default();
        assert!(
            wait >= Duration::from_millis(90),
            "100 bytes at 1000 B/s must owe about 0.1 s, got {wait:?}"
        );
    }

    #[test]
    fn moving_nothing_costs_nothing() {
        let bandwidth = limiter(KIBIBYTE_PER_SECOND);
        assert_eq!(bandwidth.debt(0), None);
        // …and it did not advance the clock either.
        assert_eq!(bandwidth.debt(1000), Some(Duration::ZERO));
    }

    #[tokio::test]
    async fn charging_actually_spends_the_time_it_computed() {
        // The arithmetic tests above never sleep. This one does, because a
        // limiter whose `charge` returned without awaiting would pass every one
        // of them and limit nothing.
        let bandwidth = limiter(KIBIBYTE_PER_SECOND);
        bandwidth.charge(500).await;
        let started = Instant::now();
        bandwidth.charge(500).await;
        assert!(
            started.elapsed() >= Duration::from_millis(400),
            "the second charge must have waited, took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn an_unlimited_run_spends_no_time_at_all() {
        let bandwidth = Bandwidth::unlimited();
        let started = Instant::now();
        for _ in 0..100 {
            bandwidth.charge(u64::MAX / 2).await;
        }
        assert!(started.elapsed() < Duration::from_millis(200));
    }
}
