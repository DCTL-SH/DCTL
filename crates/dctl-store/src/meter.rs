//! Who is told about bytes, as they cross a backend's wire.
//!
//! A backend moves an object in windows — a part, a body chunk, a working
//! buffer — and this is the seam where each window is declared as it goes past.
//! Two things above this crate need that seam and neither can be served from
//! outside it, because the loop is in here:
//!
//! * **Pacing.** `--bwlimit` is a cap on a link, and a cap that can only be
//!   applied between whole files is not a cap at all on the run DCTL exists for:
//!   one object. Charging after each *file* left 8 MiB moved as a single file at
//!   1 MB/s taking 47 ms, and the same 8 MiB as eight files taking 7051 ms. The
//!   limiter was never wrong; it was never asked often enough.
//! * **Progress.** A per-file counter cannot move while a 40 GB object is in
//!   flight, so the bar stalls for an hour on a run that is working perfectly.
//!
//! ## Why this returns a [`Duration`] instead of awaiting
//!
//! Because half the loops that must charge are **not** async. The `local:`
//! backend's copy runs inside `spawn_blocking` — filesystem I/O has no business
//! on a runtime worker — while B2's part upload and the shared HTTP body drain
//! are futures. A trait with `async fn moved` would be uncallable from the first
//! group, and a trait with a blocking `moved` would park a runtime worker in the
//! second.
//!
//! So the meter does the *arithmetic* and hands back the pause it produced;
//! [`charge`] and [`charge_blocking`] are the two ways of observing that pause,
//! and each loop uses the one that suits where it runs. It also keeps the
//! implementation honest: the calculation is pure, testable without a clock, and
//! cannot accidentally hold a lock across an await.
//!
//! ## What a window means
//!
//! The charge is made **after** the bytes are on the wire, never before. The
//! count is then a measurement rather than an intention — a part that failed and
//! was retried really did use the link, and it is charged for every attempt —
//! and the pause it produces lands between that window and the next rather than
//! inside one. The first window of a run is therefore free, which is the same
//! shape [`crate::backend::Backend`]'s callers already had per file, only three
//! orders of magnitude finer.

use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

/// Something told about bytes as a backend moves them.
///
/// Implemented above this crate — the policy (a rate, a progress bar) belongs to
/// the process running the transfer, not to the storage layer. `dctl-store`'s
/// only interest is that every loop which moves bytes declares them.
///
/// `Debug` is required because every backend holds one and every backend is
/// `Debug`; a meter that could not be rendered would force each of them to hand-
/// write an implementation to hide a field.
pub trait Meter: Send + Sync + Debug {
    /// Account for `bytes` having just crossed the wire, and return how long the
    /// caller must pause before moving the next window.
    ///
    /// [`None`] means "do not pause" and is the answer whenever nothing is being
    /// paced, which is the overwhelmingly common case — so an unpaced run costs
    /// one virtual call and one branch per window.
    ///
    /// **Must not block and must not await.** The pause is returned rather than
    /// taken so that a blocking loop and an async loop can both use it; see the
    /// module documentation.
    fn moved(&self, bytes: u64) -> Option<Duration>;
}

/// The meter for a backend nobody is watching.
///
/// Not an `Option<Arc<dyn Meter>>` on each backend, because an `Option` is a
/// branch every call site can forget to write, and a forgotten one is a window
/// that silently escapes the rate limit. A null object cannot be forgotten.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unmetered;

impl Meter for Unmetered {
    /// Never pauses, and never records: there is nothing on the other end.
    fn moved(&self, _bytes: u64) -> Option<Duration> {
        None
    }
}

/// The shared meter a backend uses until one is installed.
#[must_use]
pub fn unmetered() -> Arc<dyn Meter> {
    Arc::new(Unmetered)
}

/// Charge `bytes` and wait out the pause on the async runtime.
///
/// For the loops that are futures: an HTTP body being drained, a part being
/// `PUT`. `tokio::time::sleep` yields the worker, so a paced upload does not
/// stop every other task on the runtime.
pub async fn charge(meter: &dyn Meter, bytes: u64) {
    if let Some(pause) = meter.moved(bytes) {
        tokio::time::sleep(pause).await;
    }
}

/// Charge `bytes` and wait out the pause on the thread that is already blocking.
///
/// For the loops that run under `spawn_blocking`: the `local:` copy, the sealed
/// temp file being streamed to disk. The thread is a blocking-pool thread by
/// construction, so sleeping on it is exactly what that pool is for — and
/// bridging back to the runtime to sleep would cost a channel round trip per
/// 128 KiB.
pub fn charge_blocking(meter: &dyn Meter, bytes: u64) {
    if let Some(pause) = meter.moved(bytes) {
        std::thread::sleep(pause);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A meter that records every window and pauses for a fixed time.
    #[derive(Debug, Default)]
    struct Recorder {
        windows: Mutex<Vec<u64>>,
        pause: Option<Duration>,
    }

    impl Meter for Recorder {
        fn moved(&self, bytes: u64) -> Option<Duration> {
            self.windows.lock().unwrap().push(bytes);
            self.pause
        }
    }

    #[test]
    fn an_unmetered_backend_never_pauses() {
        assert_eq!(Unmetered.moved(u64::MAX), None);
        assert_eq!(Unmetered.moved(0), None);
    }

    #[tokio::test]
    async fn charging_spends_the_pause_the_meter_asked_for() {
        // A `charge` that returned without awaiting would satisfy every
        // arithmetic test and limit nothing — the exact failure the file-level
        // limiter had.
        let meter = Recorder {
            pause: Some(Duration::from_millis(120)),
            ..Recorder::default()
        };
        let started = std::time::Instant::now();
        charge(&meter, 4096).await;
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert_eq!(meter.windows.lock().unwrap().as_slice(), [4096]);
    }

    #[test]
    fn the_blocking_form_spends_it_too() {
        let meter = Recorder {
            pause: Some(Duration::from_millis(120)),
            ..Recorder::default()
        };
        let started = std::time::Instant::now();
        charge_blocking(&meter, 4096);
        assert!(started.elapsed() >= Duration::from_millis(100));
    }

    #[tokio::test]
    async fn an_unpaced_window_costs_no_time() {
        let meter = Recorder::default();
        let started = std::time::Instant::now();
        for _ in 0..1000 {
            charge(&meter, 1 << 20).await;
        }
        assert!(started.elapsed() < Duration::from_millis(200));
        assert_eq!(meter.windows.lock().unwrap().len(), 1000);
    }
}
