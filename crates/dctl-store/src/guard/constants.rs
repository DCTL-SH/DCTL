//! How often a store is asked whether it is still itself.

use std::time::Duration;

/// The shortest time between two identity probes for one backend.
///
/// Five seconds, and the number is a measurement rather than a preference. A
/// probe costs one `stat` on `local:` and a `b2_list_buckets` round trip on B2 —
/// a **billed transaction**. Probing before every write turned a three-object
/// copy into a bucket into eighteen seconds and would add one API call per
/// object to every sync; a guard nobody can afford to leave switched on is not a
/// guard, so the rate is bounded rather than the guard being optional.
///
/// Five rather than sixty because the window is what an operator loses: a store
/// that vanishes is caught within this interval, so up to this much of a run can
/// be written before it stops. Five seconds is a few objects on any link DCTL
/// runs over, and it is under one per cent of a per-object cost even on a sync
/// moving one small file per second.
///
/// It is a floor on the *interval*, not a timer: nothing probes on a schedule of
/// its own, and a run that writes nothing makes no probes at all.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_interval_is_short_enough_to_be_a_guard_and_long_enough_to_be_free() {
        // Both halves of the trade, pinned. Below a second this is a per-write
        // probe again with extra machinery; above a minute a run could write for
        // a minute into a container it did not choose.
        assert!(PROBE_INTERVAL >= Duration::from_secs(1));
        assert!(PROBE_INTERVAL <= Duration::from_secs(60));
    }
}
