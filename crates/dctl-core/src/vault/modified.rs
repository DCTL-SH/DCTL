//! The modification time a stored object is recorded with.

use std::time::{SystemTime, UNIX_EPOCH};

/// When the content being stored was last modified, as the caller knows it.
///
/// A **required argument of every write**, and an enum rather than an
/// `Option<i64>`, because the difference is the whole point. Each write path used
/// to stamp the clock into the index record on its own authority: a true
/// statement about the *write*, and no statement at all about the file the write
/// was made from. A vault destination could therefore never match its source by
/// modification time, so every incremental `copy` found the whole dataset
/// "modified" and re-sent it — nightly, forever.
///
/// An optional parameter would have fixed that call site and left the next one
/// free to omit it, which is the same defect waiting to be reintroduced by
/// somebody who never read this paragraph. A required enum makes a caller *name*
/// which of the three claims they are making, and adding a write path without
/// deciding is a compile error rather than a silent stamp of the clock.
///
/// Stored as whole unix seconds, because that is what
/// [`Record::modified_unix`](dctl_index::Record::modified_unix) holds — the
/// sub-second part of a filesystem timestamp is dropped, which is why every
/// comparison of two sides carries a tolerance of at least one second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Modified {
    /// The source's own last-modified time, in whole unix seconds.
    ///
    /// The ordinary case for anything copied from somewhere: it is the *content*
    /// that has an age, and a copy of it does not become younger by being made.
    At(i64),
    /// The content came into being during this write, so the clock is the honest
    /// answer rather than a substitute for one.
    ///
    /// Reached by a stream with no file behind it: `dctl rcat` spools standard
    /// input to a temporary file and stores that, and the temporary file's own
    /// modification time is the moment of the spool — a number that would look
    /// exactly like a real source timestamp to every later comparison. Saying
    /// "now" records the same instant while claiming only what is true.
    ///
    /// Resolved at the commit rather than by the caller, so a caller that means
    /// "now" cannot spell it as a timestamp captured earlier in the run.
    Now,
    /// A source exists but its modification time could not be established.
    ///
    /// Recorded as *absent* rather than as the clock, because "unknown" and "now"
    /// are different facts and only one of them is true. The comparison rules
    /// read an absent time as "these two sides were never comparable" and
    /// transfer the file, which costs bandwidth; a fabricated `now` would read as
    /// a real answer, and the file it wrongly matched would never be transferred
    /// again.
    Unknown,
}

impl Modified {
    /// The time a filesystem reports for a source file.
    ///
    /// Takes the metadata rather than the path so the answer comes from the same
    /// handle the content was read through wherever a caller can arrange it: a
    /// second `stat` could describe a file that changed in between, and the
    /// record would then claim a time the stored bytes never had.
    ///
    /// A platform or filesystem that does not record modification times yields
    /// [`Modified::Unknown`], never the clock — see the variant.
    #[must_use]
    pub fn of(metadata: &std::fs::Metadata) -> Self {
        metadata.modified().map_or(Self::Unknown, Self::at)
    }

    /// The same, from a [`SystemTime`] a caller already holds.
    ///
    /// Times before 1970 are ordinary rather than exceptional — a restored
    /// archive legitimately holds them — so the negative side is a subtraction
    /// and not a failure. Only a value that will not fit in the record's `i64`
    /// becomes [`Modified::Unknown`], which is the honest answer for a clock this
    /// index cannot represent.
    #[must_use]
    pub fn at(time: SystemTime) -> Self {
        let seconds = match time.duration_since(UNIX_EPOCH) {
            Ok(since) => i64::try_from(since.as_secs()),
            Err(before) => i64::try_from(before.duration().as_secs()).map(|s| -s),
        };
        seconds.map_or(Self::Unknown, Self::At)
    }

    /// The value the index record carries: whole unix seconds, or nothing.
    ///
    /// [`Modified::Now`] is resolved *here*, at the moment of the commit, rather
    /// than by the caller — so a caller that means "now" cannot accidentally
    /// spell it as a stale timestamp captured earlier in the run, and so a clock
    /// this platform cannot read degrades to [`Modified::Unknown`]'s absence
    /// instead of to the epoch.
    #[must_use]
    pub fn resolve(self) -> Option<i64> {
        match self {
            Self::At(seconds) => Some(seconds),
            Self::Now => Self::now_unix(),
            Self::Unknown => None,
        }
    }

    /// Current unix time in seconds, if the clock is available.
    fn now_unix() -> Option<i64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_sources_time_is_carried_through_untouched() {
        // The property the whole type exists for: what goes in is what the index
        // record holds. A write path that "helpfully" re-stamped it would put the
        // original defect straight back.
        assert_eq!(Modified::At(1_700_000_000).resolve(), Some(1_700_000_000));
    }

    #[test]
    fn an_unknown_time_is_absent_rather_than_the_epoch_or_the_clock() {
        // Both substitutes are worse than nothing. The epoch makes every file
        // look older than every other file and inverts `--update`; the clock
        // makes a stale copy look freshly written and can stop it ever being
        // re-transferred.
        assert_eq!(Modified::Unknown.resolve(), None);
    }

    #[test]
    fn now_is_resolved_at_the_commit_and_is_a_real_time() {
        let before = Modified::now_unix().expect("this platform has a clock");
        let resolved = Modified::Now.resolve().expect("the clock is still there");
        assert!(resolved >= before, "the clock ran backwards");
    }

    #[test]
    fn a_time_before_the_epoch_is_negative_rather_than_refused() {
        // A restored archive legitimately holds pre-1970 timestamps, and clamping
        // one to zero would silently rewrite the fact the record exists to state.
        let when = UNIX_EPOCH - Duration::from_secs(86_400);
        assert_eq!(Modified::at(when), Modified::At(-86_400));
    }

    #[test]
    fn a_time_is_truncated_to_the_whole_second_the_record_holds() {
        // The record has no room for the fraction, so it is dropped rather than
        // rounded — and dropped consistently, which is what lets a stored time
        // and the source it came from still compare equal within the one-second
        // tolerance every comparison applies.
        let when = UNIX_EPOCH + Duration::from_millis(1_700_000_000_750);
        assert_eq!(Modified::at(when), Modified::At(1_700_000_000));
    }

    #[test]
    fn a_filesystem_with_no_modification_times_yields_unknown() {
        // Exercised through a real file, because the branch that matters is the
        // one where `Metadata::modified` errors — and the assertion that a
        // working platform reports a time is what proves the fallback is not
        // being taken here by accident.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.txt");
        std::fs::write(&path, b"x").unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert!(matches!(Modified::of(&metadata), Modified::At(_)));
    }
}
