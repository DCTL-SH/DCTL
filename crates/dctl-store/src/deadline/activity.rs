//! When bytes last moved.
//!
//! One shared clock per operation, written by whatever is carrying the data and
//! read by the watchdog that decides the operation has stalled. It is the whole
//! of what makes [`super::watch::IdleWatch`] an *inactivity* deadline rather
//! than a stopwatch: rclone re-arms its socket deadline on every successful read
//! and write, and this is the same idea expressed where DCTL can actually
//! observe progress.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// A shared "bytes last moved at" clock.
///
/// Nanoseconds since a fixed origin rather than an `Instant`, because an
/// `Instant` is not atomic and the alternative — a mutex on the hot path of
/// every 64 KiB frame — would put a lock acquisition between DCTL and the wire
/// for no benefit. A `u64` of nanoseconds runs for 584 years from the origin,
/// which is the process start.
#[derive(Debug)]
pub struct Activity {
    /// The zero point every stored value is measured from.
    origin: Instant,
    /// Nanoseconds after [`Activity::origin`] at which progress was last seen.
    last: AtomicU64,
}

impl Activity {
    /// A clock that has just seen progress.
    ///
    /// Starting at "now" rather than at zero matters: an operation whose first
    /// act is to open a connection has not stalled merely because no byte has
    /// moved yet, and a clock that began in the past would give it less than the
    /// deadline the operator asked for.
    #[must_use]
    pub fn started() -> Arc<Self> {
        Arc::new(Self {
            origin: Instant::now(),
            last: AtomicU64::new(0),
        })
    }

    /// Record that bytes moved.
    ///
    /// [`Ordering::Relaxed`] is correct and is not a shortcut. The only reader
    /// is the watchdog, which is asking "roughly how long has it been?" and acts
    /// on the answer only when it exceeds a deadline measured in seconds; there
    /// is no other memory whose visibility this value is ordering, so nothing
    /// downstream depends on a happens-before edge. A stronger ordering would
    /// buy a guarantee no reader uses and pay for it on every frame.
    pub fn touch(&self) {
        let elapsed = u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.last.store(elapsed, Ordering::Relaxed);
    }

    /// How long since progress was last recorded.
    ///
    /// Saturating rather than wrapping: if the clock has run for longer than a
    /// `u64` of nanoseconds can hold, the honest answer is "a very long time",
    /// and an arithmetic wrap would say "no time at all" — which is the one
    /// answer that would silently disable the deadline.
    #[must_use]
    pub fn quiet_for(&self) -> Duration {
        let last = Duration::from_nanos(self.last.load(Ordering::Relaxed));
        self.origin.elapsed().saturating_sub(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_clock_has_just_seen_progress() {
        // The property `started` exists for: an operation is not born stalled.
        let activity = Activity::started();
        assert!(activity.quiet_for() < Duration::from_millis(50));
    }

    #[test]
    fn quiet_time_grows_until_something_touches_it() {
        let activity = Activity::started();
        std::thread::sleep(Duration::from_millis(30));
        let before = activity.quiet_for();
        assert!(
            before >= Duration::from_millis(25),
            "the clock must actually advance: {before:?}"
        );
        activity.touch();
        assert!(
            activity.quiet_for() < before,
            "and a touch must reset it, not merely slow it"
        );
    }

    #[test]
    fn the_clock_is_shared_through_the_handle_it_is_cloned_into() {
        // The shape every caller uses: the body reports progress through one
        // handle while the watchdog reads it through another. Two clocks that
        // happened not to be the same object would make the watchdog fire on a
        // transfer that was moving perfectly well.
        let activity = Activity::started();
        let writer = Arc::clone(&activity);
        std::thread::sleep(Duration::from_millis(30));
        assert!(activity.quiet_for() >= Duration::from_millis(25));
        writer.touch();
        assert!(activity.quiet_for() < Duration::from_millis(25));
    }
}
