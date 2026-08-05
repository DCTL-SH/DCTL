//! What a walk has to say about the links it met.
//!
//! Counts are always exact; names are sampled. Both halves matter. A count on its
//! own tells an operator that something was passed over but not what, and a full
//! list of names is unbounded — a home directory can hold tens of thousands of
//! links, and a listing that promises O(page) memory
//! ([the plan](https://doc.dctl.sh/project/plan) §16.2) must not quietly grow a
//! second structure that is O(tree). So the number is the truth and the names are
//! a sample large enough to identify a layout.

use super::LinkVerdict;

/// How many links a report names before it stops collecting names.
///
/// The count keeps rising past this; only the naming stops. Sixty-four is chosen
/// against two bounds. Below: the canonical layouts are a handful of links at the
/// top of a tree (`data -> /mnt/bigdisk/data`, `current -> 2026-07-27`), and a
/// sample that could not hold all of those would fail at naming the thing an
/// operator has to act on. Above: each note carries a path, so the worst case is
/// roughly sixty-four path lengths — a few hundred kilobytes against a listing
/// page's megabyte, which is noise — while a report that named every link in a
/// tree of a million would be the memory ceiling this crate promises not to have.
/// Nobody reads past sixty-four names in a warning anyway; past that the count
/// and the flag are the actionable part.
pub const LINK_NOTE_SAMPLE: usize = 64;

/// One link the walk passed over or followed, kept by name.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct LinkNote {
    /// The link's path relative to the walk root, in the same spelling the
    /// listing uses — so a name in a warning can be pasted into an `--include`.
    pub path: String,
    /// What the walk did about it, and why.
    pub verdict: LinkVerdict,
}

/// What one walk did about every symbolic link it met.
///
/// Merged rather than replaced when a listing is assembled from parts, so a
/// paged listing reports the whole walk once and not one page's worth per page.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct LinkReport {
    followed: u64,
    skipped: u64,
    broken: u64,
    notes: Vec<LinkNote>,
    /// Links whose names were not kept because the sample was full. Reported so
    /// that "and 4 more" is a fact rather than a subtraction the reader has to
    /// do, and so a truncated sample can never be mistaken for a complete list.
    unnamed: u64,
}

impl LinkReport {
    /// Record one link.
    ///
    /// The single entry point, so a counter and its name cannot come apart: a
    /// caller that bumped a count directly is how a report ends up claiming four
    /// skipped links and naming five.
    pub fn observe(&mut self, path: impl Into<String>, verdict: LinkVerdict) {
        match verdict {
            LinkVerdict::Followed => self.followed += 1,
            LinkVerdict::Broken => self.broken += 1,
            LinkVerdict::NotFollowed
            | LinkVerdict::OutOfTree
            | LinkVerdict::Cycle
            | LinkVerdict::NotStorable => self.skipped += 1,
        }
        if self.notes.len() < LINK_NOTE_SAMPLE {
            self.notes.push(LinkNote {
                path: path.into(),
                verdict,
            });
        } else {
            self.unnamed += 1;
        }
    }

    /// Fold another walk's findings into this one.
    ///
    /// The sample stays capped across the merge, and the counts stay exact,
    /// which is what lets a transfer add up both sides of a diff without the
    /// combined report becoming the memory the paging exists to avoid.
    pub fn merge(&mut self, other: &Self) {
        self.followed += other.followed;
        self.skipped += other.skipped;
        self.broken += other.broken;
        let room = LINK_NOTE_SAMPLE.saturating_sub(self.notes.len());
        let taken = room.min(other.notes.len());
        self.notes.extend_from_slice(&other.notes[..taken]);
        self.unnamed += other.unnamed + (other.notes.len() - taken) as u64;
    }

    /// Links whose targets were read and stored.
    #[must_use]
    pub const fn followed(&self) -> u64 {
        self.followed
    }

    /// Links passed over: by policy, for leaving the tree, for closing a cycle,
    /// or for pointing at something that is not a file.
    #[must_use]
    pub const fn skipped(&self) -> u64 {
        self.skipped
    }

    /// Links followed to nothing.
    #[must_use]
    pub const fn broken(&self) -> u64 {
        self.broken
    }

    /// Every link the walk met, however it ended up.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.followed + self.skipped + self.broken
    }

    /// Whether the walk met no links at all — the case that must stay silent.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total() == 0
    }

    /// The names kept, in the order the walk met them.
    #[must_use]
    pub fn notes(&self) -> &[LinkNote] {
        &self.notes
    }

    /// Links the sample had no room to name.
    #[must_use]
    pub const fn unnamed(&self) -> u64 {
        self.unnamed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_untouched_report_says_nothing() {
        // The ordinary tree has no links in it, and a run over one must not
        // print a line about symbolic links at all.
        let report = LinkReport::default();
        assert!(report.is_empty());
        assert_eq!(report.total(), 0);
        assert!(report.notes().is_empty());
    }

    #[test]
    fn each_verdict_lands_in_the_counter_that_describes_it() {
        let mut report = LinkReport::default();
        report.observe("a", LinkVerdict::Followed);
        report.observe("b", LinkVerdict::NotFollowed);
        report.observe("c", LinkVerdict::OutOfTree);
        report.observe("d", LinkVerdict::Cycle);
        report.observe("e", LinkVerdict::NotStorable);
        report.observe("f", LinkVerdict::Broken);

        assert_eq!(report.followed(), 1);
        assert_eq!(report.skipped(), 4);
        assert_eq!(report.broken(), 1);
        assert_eq!(report.total(), 6);
    }

    #[test]
    fn the_count_keeps_rising_after_the_names_stop() {
        // The property the whole module is built around: a tree with a hundred
        // thousand links reports a hundred thousand, and holds sixty-four names.
        let mut report = LinkReport::default();
        for index in 0..LINK_NOTE_SAMPLE * 3 {
            report.observe(format!("link-{index}"), LinkVerdict::NotFollowed);
        }
        assert_eq!(report.skipped(), (LINK_NOTE_SAMPLE * 3) as u64);
        assert_eq!(report.notes().len(), LINK_NOTE_SAMPLE);
        assert_eq!(report.unnamed(), (LINK_NOTE_SAMPLE * 2) as u64);
    }

    #[test]
    fn merging_keeps_the_counts_exact_and_the_sample_capped() {
        let mut left = LinkReport::default();
        let mut right = LinkReport::default();
        for index in 0..LINK_NOTE_SAMPLE {
            left.observe(format!("l{index}"), LinkVerdict::NotFollowed);
            right.observe(format!("r{index}"), LinkVerdict::Followed);
        }

        left.merge(&right);
        assert_eq!(left.skipped(), LINK_NOTE_SAMPLE as u64);
        assert_eq!(left.followed(), LINK_NOTE_SAMPLE as u64);
        assert_eq!(left.notes().len(), LINK_NOTE_SAMPLE);
        // Every name the merge had no room for is still accounted for.
        assert_eq!(left.unnamed(), LINK_NOTE_SAMPLE as u64);
        assert_eq!(
            left.total(),
            left.notes().len() as u64 + left.unnamed(),
            "every link is either named or counted as unnamed"
        );
    }

    #[test]
    fn merging_an_empty_report_changes_nothing() {
        let mut report = LinkReport::default();
        report.observe("a", LinkVerdict::Followed);
        let before = report.clone();
        report.merge(&LinkReport::default());
        assert_eq!(report, before);
    }
}
