//! What it costs a source to serve a byte window.
//!
//! [`Source::read_range`](super::Source::read_range) has one signature and two
//! wildly different prices. A plain object store issues a ranged `GET`: seeking
//! 40 GB into an object costs one request and transfers only the window. A
//! sealed vault has no such call — `dctl_core` exposes
//! [`get_file`](dctl_core::Vault::get_file) and nothing narrower — so it fetches
//! and decrypts the *entire* object and slices the result.
//!
//! That difference is documented on both implementations, and the vault's
//! behaviour is deliberately not faked: returning a short read, or refusing
//! above some size, would trade a known cost for an unknown wrong answer, and
//! `PLAN.md` §6 is unambiguous about which of those is worse.
//!
//! ## Documented is not the same as visible
//!
//! Being written down in the source tree is where this stopped being enough.
//! `dctl cat b2vault:film.mkv --offset 0 --count 4` on a 40 GB object is a 40 GB
//! download, and the person who typed it had no reason to suspect that: they
//! asked for four bytes, the command returned four bytes, and it succeeded. The
//! cost arrives later, on an invoice, with nothing connecting it to the command
//! that caused it.
//!
//! So the cost is announced at the moment it is about to be paid, above
//! [`RANGED_READ_WHOLE_OBJECT_WARN_BYTES`]. This type is what lets that happen
//! without any command asking "am I reading a vault?" — the question
//! [`super::open`] exists to keep unasked. A caller learns what its *next read*
//! will cost, which is a fact about the operation, not about the implementation
//! behind it.
//!
//! ## Why a type rather than a `bool`
//!
//! `fn reads_whole_object(&self) -> bool` would answer the same question and
//! read, at every call site, as a test of which implementation is in hand. The
//! two named variants describe the read instead, so the branch stays about cost.
//! It also leaves room for the third answer this will eventually need: when
//! `dctl-core` grows a chunked reader, a vault becomes [`RangedRead::Windowed`]
//! and every site here keeps working unchanged.

use crate::constants::{RANGED_READ_WHOLE_OBJECT_NOTE, RANGED_READ_WHOLE_OBJECT_WARN_BYTES};
use crate::output::size::{self, Units};

/// How much of an object a source must move to serve a window of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangedRead {
    /// Only the requested bytes are transferred.
    ///
    /// A plain store's ranged `GET`, and a local file's `seek`.
    Windowed,

    /// The whole object is transferred and decrypted, then sliced.
    ///
    /// A sealed vault, because `dctl_core` exposes no narrower read. Cost is
    /// O(object) in memory *and* in egress, not O(window).
    WholeObject,
}

impl RangedRead {
    /// Bytes this read moves that the caller did not ask for.
    ///
    /// [`None`] when nothing is wasted — either the source serves windows
    /// natively, or the "window" is the whole object, in which case the transfer
    /// is exactly what was requested and there is no surprise to report.
    ///
    /// Saturating rather than wrapping: a `window` larger than `object` is
    /// nonsense this function must not turn into an enormous overshoot, and a
    /// range clamped past the end of a shrinking object can legitimately produce
    /// one.
    #[must_use]
    pub const fn unrequested_bytes(self, object: u64, window: u64) -> Option<u64> {
        match self {
            Self::Windowed => None,
            Self::WholeObject => match object.saturating_sub(window) {
                0 => None,
                wasted => Some(wasted),
            },
        }
    }

    /// The warning to print before this read, if its cost is worth announcing.
    ///
    /// Gated on the size of the *object*, not on the size of the overshoot: the
    /// object is what is transferred and billed, and a threshold on the
    /// difference would fall silent for exactly the case that costs most — a
    /// tiny window of an enormous file.
    ///
    /// Returns the rendered line rather than printing it, so the decision is
    /// testable without an output sink and the caller keeps control of which
    /// stream it lands on.
    ///
    /// `units` is the run's own choice rather than always the decimal units a
    /// provider bills in: a warning that quoted `MB` while every other line of
    /// the same run said `MiB` would read as a different measurement rather than
    /// the same one.
    #[must_use]
    pub fn warning(self, object: u64, window: u64, units: Units) -> Option<String> {
        if object < RANGED_READ_WHOLE_OBJECT_WARN_BYTES {
            return None;
        }
        let wasted = self.unrequested_bytes(object, window)?;
        Some(format!(
            "reading {} of a {} object will transfer all {} of it ({} more than \
             requested): {RANGED_READ_WHOLE_OBJECT_NOTE}",
            size::bytes(window, units),
            size::bytes(object, units),
            size::bytes(object, units),
            size::bytes(wasted, units),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An object comfortably over the threshold, and one comfortably under.
    const BIG: u64 = RANGED_READ_WHOLE_OBJECT_WARN_BYTES * 4;
    const SMALL: u64 = RANGED_READ_WHOLE_OBJECT_WARN_BYTES / 4;

    #[test]
    fn a_windowed_source_never_wastes_anything() {
        // The plain store's whole point: a four-byte window of a 40 GB object
        // costs four bytes, so there is nothing to warn about at any size.
        assert_eq!(RangedRead::Windowed.unrequested_bytes(BIG, 4), None);
        assert_eq!(RangedRead::Windowed.warning(BIG, 4, Units::Binary), None);
    }

    #[test]
    fn a_whole_object_read_reports_what_the_caller_did_not_ask_for() {
        assert_eq!(
            RangedRead::WholeObject.unrequested_bytes(BIG, 4),
            Some(BIG - 4)
        );
    }

    #[test]
    fn asking_for_the_whole_object_is_not_a_surprise() {
        // The cost is real, but it is exactly what was requested. Warning here
        // would fire on every ordinary `dctl cat` of a large object, which is
        // how a warning stops being read.
        assert_eq!(RangedRead::WholeObject.unrequested_bytes(BIG, BIG), None);
        assert_eq!(
            RangedRead::WholeObject.warning(BIG, BIG, Units::Binary),
            None
        );
    }

    #[test]
    fn a_small_object_is_read_whole_without_comment() {
        // Below the threshold the whole-object read is genuinely cheap, and a
        // warning on routine work is one an operator learns to skip.
        assert_eq!(
            RangedRead::WholeObject.warning(SMALL, 4, Units::Binary),
            None
        );
        // The waste is still real and still reported; only the warning is gated.
        assert_eq!(
            RangedRead::WholeObject.unrequested_bytes(SMALL, 4),
            Some(SMALL - 4)
        );
    }

    #[test]
    fn the_threshold_is_inclusive_at_its_own_value() {
        // An object exactly at the limit warns. Stated as a test because "at or
        // above" and "above" differ by exactly the object that sits on the
        // boundary, and that is the one a reader will check by hand.
        assert!(
            RangedRead::WholeObject
                .warning(RANGED_READ_WHOLE_OBJECT_WARN_BYTES, 4, Units::Binary)
                .is_some()
        );
        assert!(
            RangedRead::WholeObject
                .warning(RANGED_READ_WHOLE_OBJECT_WARN_BYTES - 1, 4, Units::Binary)
                .is_none()
        );
    }

    #[test]
    fn the_warning_quotes_both_sizes_and_names_the_cause() {
        let warning = RangedRead::WholeObject
            .warning(BIG, 4, Units::Binary)
            .expect("a tiny window of a huge object must be announced");
        // The object size has to appear, because that is the number that gets
        // billed and the only one the reader can act on.
        assert!(
            warning.contains(&size::bytes(BIG, Units::Binary)),
            "{warning}"
        );
        assert!(
            warning.contains(RANGED_READ_WHOLE_OBJECT_NOTE),
            "the warning must say why, not only that: {warning}"
        );
    }

    #[test]
    fn a_window_past_the_end_of_the_object_does_not_underflow() {
        // `Span::resolve` clamps, but an object that shrank between the stat and
        // the read could still present a window longer than itself. Subtracting
        // the other way round would report an overshoot of eighteen exabytes.
        assert_eq!(RangedRead::WholeObject.unrequested_bytes(4, BIG), None);
        assert_eq!(RangedRead::WholeObject.warning(4, BIG, Units::Binary), None);
    }
}
