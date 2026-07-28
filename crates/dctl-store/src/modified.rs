//! When the content being stored was last changed, as the writer knows it.
//!
//! Every backend already reports a modification time on the way out
//! ([`ObjectMeta::modified_unix`](crate::model::ObjectMeta::modified_unix)).
//! Until this type existed, none of them accepted one on the way *in*, so the
//! number that came back was always the moment the provider accepted the upload
//! — a true fact about a different event.
//!
//! That single omission is what made `dctl sync` re-transfer its entire source on
//! every run. The default comparison is size and modification time; the
//! destination's time was the write time; the source's was the file's own; the
//! two never agreed, so every file looked modified forever and a nightly backup
//! re-uploaded the dataset. `dctl check` used the same fields and therefore
//! called a tree it had just copied byte-for-byte `3 of 3 paths differ`.
//!
//! So a write carries the time now, and it is a **parameter of
//! [`Backend::put`](crate::Backend::put) rather than a later `set_modified`
//! call**. That is not a stylistic preference: on B2 the time is a file-info
//! field fixed at upload, and changing it afterwards means copying the object to
//! itself, which costs a second API call and creates a second version of every
//! file on every run.
//!
//! ## Whole seconds, deliberately
//!
//! DCTL's stored metadata is whole unix seconds everywhere — the index row, the
//! sealed object's own header, and every backend's listing. Carrying finer
//! resolution here would create a number that no reader of it could preserve, and
//! the sub-second half of it would be silently dropped somewhere downstream
//! rather than at the boundary that decided to drop it. What the disagreement
//! between a nanosecond source clock and a whole-second record costs is one
//! second of tolerance in the comparison, which is exactly what a modify window
//! is for.
//!
//! ## Unknown is a value, not a zero
//!
//! [`SourceModified::unknown`] is the honest answer when the writer has no time
//! to give — a plain object store being read, a filesystem that records nothing,
//! or an object that is DCTL's own bookkeeping rather than a user's file. The
//! backend then leaves the provider's own timestamp standing. Substituting the
//! epoch would stamp those objects `1970-01-01`, which makes every one of them
//! look older than every local file and inverts `--update`.

use std::time::SystemTime;

/// Milliseconds in a second — the unit B2's `src_last_modified_millis` uses.
const MILLIS_PER_SECOND: i64 = 1_000;

/// The last-modified time of the content being stored, in whole unix seconds.
///
/// A newtype rather than a bare `Option<i64>` so a call site reads as the
/// decision it is: `SourceModified::unknown()` at a write that genuinely has no
/// time to record, `SourceModified::at(secs)` at one that does. A bare `None`
/// three arguments into a `put` is the same code and none of the meaning.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceModified(Option<i64>);

impl SourceModified {
    /// The writer has no modification time to record.
    ///
    /// The backend leaves whatever the provider stamps. See the module
    /// documentation for why this is not the epoch.
    #[must_use]
    pub const fn unknown() -> Self {
        Self(None)
    }

    /// The content was last modified at `unix_seconds`.
    ///
    /// Negative values are ordinary: a restored archive legitimately holds files
    /// dated before 1970, and clamping one to the epoch would rewrite a fact the
    /// record exists to state. A backend whose protocol cannot represent it says
    /// so in its own documentation rather than silently storing something else.
    #[must_use]
    pub const fn at(unix_seconds: i64) -> Self {
        Self(Some(unix_seconds))
    }

    /// Build from the same `Option<i64>` shape the rest of the model uses.
    #[must_use]
    pub const fn from_unix(unix_seconds: Option<i64>) -> Self {
        Self(unix_seconds)
    }

    /// The time in whole unix seconds, or [`None`] when it is unknown.
    #[must_use]
    pub const fn unix(self) -> Option<i64> {
        self.0
    }

    /// The time in whole unix milliseconds, for a provider that stores millis.
    ///
    /// [`None`] on overflow as well as on absence, because a value that does not
    /// fit is not a time this can express and sending a wrapped one would record
    /// a confidently wrong date.
    #[must_use]
    pub fn millis(self) -> Option<i64> {
        self.0.and_then(|secs| secs.checked_mul(MILLIS_PER_SECOND))
    }

    /// The time as a [`SystemTime`], for the platform calls that take one.
    ///
    /// [`None`] for a value this platform's clock cannot represent, which keeps
    /// "unrepresentable" distinguishable from "the epoch".
    #[must_use]
    pub fn system_time(self) -> Option<SystemTime> {
        let seconds = self.0?;
        let magnitude = std::time::Duration::from_secs(seconds.unsigned_abs());
        if seconds >= 0 {
            SystemTime::UNIX_EPOCH.checked_add(magnitude)
        } else {
            SystemTime::UNIX_EPOCH.checked_sub(magnitude)
        }
    }

    /// Whether there is a time to record at all.
    #[must_use]
    pub const fn is_known(self) -> bool {
        self.0.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_time_is_absent_rather_than_the_epoch() {
        // The substitution this type exists to refuse: an object stamped 1970
        // looks older than every local file and inverts `--update`.
        assert_eq!(SourceModified::unknown().unix(), None);
        assert_eq!(SourceModified::unknown().millis(), None);
        assert_eq!(SourceModified::unknown().system_time(), None);
        assert!(!SourceModified::unknown().is_known());
        assert_eq!(SourceModified::default(), SourceModified::unknown());
    }

    #[test]
    fn a_known_time_survives_every_representation() {
        let when = SourceModified::at(1_700_000_000);
        assert_eq!(when.unix(), Some(1_700_000_000));
        assert_eq!(when.millis(), Some(1_700_000_000_000));
        assert_eq!(
            when.system_time(),
            Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000))
        );
        assert!(when.is_known());
    }

    #[test]
    fn a_pre_epoch_time_is_ordinary_rather_than_an_error() {
        // A restored archive holds them, and clamping to zero would silently
        // rewrite the fact.
        let when = SourceModified::at(-86_400);
        assert_eq!(when.millis(), Some(-86_400_000));
        assert_eq!(
            when.system_time(),
            Some(SystemTime::UNIX_EPOCH - std::time::Duration::from_secs(86_400))
        );
    }

    #[test]
    fn a_time_too_large_for_millis_is_absent_rather_than_wrapped() {
        // A wrapped value is a confidently wrong date, which is worse than no
        // date at all: the provider would report it and every comparison would
        // believe it.
        assert_eq!(SourceModified::at(i64::MAX).millis(), None);
        assert_eq!(SourceModified::at(i64::MIN).millis(), None);
    }

    #[test]
    fn an_option_round_trips_through_the_newtype() {
        assert_eq!(SourceModified::from_unix(Some(42)), SourceModified::at(42));
        assert_eq!(SourceModified::from_unix(None), SourceModified::unknown());
    }
}
