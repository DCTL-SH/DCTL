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
//! ## Where the charge is made, and why that used to be the whole problem
//!
//! At every **window**, as it crosses the wire — through
//! [`dctl_store::Meter`], which the storage layer calls from inside each of its
//! copy loops. This limiter is installed as that meter for the run, so one rate
//! covers every backend a command touches.
//!
//! It was charged once per **file**, and the consequence was not subtle: a run of
//! one object was not paced at all. Measured, before the change: 8 MiB moved as a
//! single file at `--bwlimit 1M` took **47 ms**; the same 8 MiB as eight files
//! took **7051 ms**. The last file of every run was unpaced for the same reason —
//! its debt was charged and then the process exited. `--help` said "one large
//! object is not split, so the run's average rate is what is capped", and the
//! second half of that was false whenever there was one object, which is DCTL's
//! own headline case.
//!
//! The limiter was never wrong. Its arithmetic is unchanged; it was simply never
//! asked often enough, because the engine handed a whole file to the storage
//! layer in one call and got a byte count back at the end. Now that bytes move in
//! bounded windows there is a seam every few megabytes, and this is charged at
//! each one — which is the granularity rclone has always had, charging its
//! token bucket on every read of the underlying reader.
//!
//! Charging **after** each window rather than before is deliberate. The bytes are
//! then a measurement rather than an intention, so a window that failed and was
//! retried is charged for every attempt — because every attempt really did use
//! the link — and the pause it produces lands between that window and the next
//! rather than inside one. The first window of a run is therefore free, which
//! costs one window's worth of burst at the very start and nothing after.
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

    /// Advance the virtual clock by what `bytes` cost, and return the wait that
    /// leaves for the caller.
    ///
    /// Split out of [`Bandwidth::charge`] so the arithmetic is testable without
    /// a runtime and without spending the wall-clock time it computes: a test
    /// that had to sleep for the answer could only ever check small ones. It is
    /// also exactly the shape [`dctl_store::Meter`] asks for — do the sums, hand
    /// back the pause — which is why this type can be that meter without an
    /// adapter.
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

impl dctl_store::Meter for Bandwidth {
    /// The pause this window bought, for the storage layer's copy loop to take.
    ///
    /// [`dctl_store::Meter`] deliberately returns the wait instead of awaiting
    /// it, because half the loops that must charge are not async — the `local:`
    /// backend copies under `spawn_blocking` — and this limiter's arithmetic was
    /// already written that way for its own reasons. The two shapes met without
    /// either being bent.
    fn moved(&self, bytes: u64) -> Option<Duration> {
        self.debt(bytes)
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
        // limiter that computed a debt and never waited would pass every one of
        // them and limit nothing.
        //
        // Driven through `dctl_store::meter::charge` rather than through a
        // method of this type's own, because that is the call the storage layer
        // makes: a limiter that is correct only when spent by a wrapper nothing
        // in production uses is not a limiter.
        let bandwidth = limiter(KIBIBYTE_PER_SECOND);
        dctl_store::meter::charge(&bandwidth, 500).await;
        let started = Instant::now();
        dctl_store::meter::charge(&bandwidth, 500).await;
        assert!(
            started.elapsed() >= Duration::from_millis(400),
            "the second charge must have waited, took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn the_limiter_is_the_meter_the_storage_layer_asks() {
        // The join that makes any of this reach a copy loop. `Meter::moved` and
        // `debt` must be the same answer; if the trait implementation ever
        // stopped delegating, pacing would silently become a no-op everywhere
        // while every arithmetic test above still passed.
        use dctl_store::Meter as _;

        let bandwidth = limiter(KIBIBYTE_PER_SECOND);
        assert_eq!(bandwidth.moved(0), None, "nothing moved, nothing owed");
        let first = bandwidth.moved(1000);
        assert_eq!(first, Some(Duration::ZERO), "the first window is free");
        let second = bandwidth.moved(1000).unwrap_or_default();
        assert!(
            second >= Duration::from_millis(900),
            "1000 bytes at 1000 B/s must owe about a second, got {second:?}"
        );

        // And an unpaced run costs a branch and nothing else.
        assert_eq!(Bandwidth::unlimited().moved(u64::MAX), None);
    }

    #[tokio::test]
    async fn an_unlimited_run_spends_no_time_at_all() {
        let bandwidth = Bandwidth::unlimited();
        let started = Instant::now();
        for _ in 0..100 {
            dctl_store::meter::charge(&bandwidth, u64::MAX / 2).await;
        }
        assert!(started.elapsed() < Duration::from_millis(200));
    }
}
