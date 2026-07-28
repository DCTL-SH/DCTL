//! What a walk has to say about the special files it met.
//!
//! Counts are always exact; names are sampled. The reasoning is
//! [`crate::links::report`]'s, and it is the same reasoning because it is the
//! same promise: a count on its own tells an operator that something was passed
//! over but not what, and a full list of names is unbounded — `/dev` alone holds
//! hundreds of device nodes, and a listing that promises O(page) memory
//! (`PLAN.md` §16.2) must not quietly grow a second structure that is O(tree).

use super::SpecialKind;

/// How many special files a report names before it stops collecting names.
///
/// The count keeps rising past this; only the naming stops. Sixteen rather than
/// [`LINK_NOTE_SAMPLE`](crate::links::LINK_NOTE_SAMPLE)'s sixty-four, and the
/// difference is deliberate: a sampled *link* name is often the thing an
/// operator has to act on — `data -> /mnt/bigdisk/data` is where the dataset
/// went — whereas special files are acted on as a *class*. Nobody moves a socket
/// out of `/run`; they satisfy themselves that the tree they pointed at was the
/// tree they meant. Sixteen names is enough to recognise `/dev` or `/run` at a
/// glance, and small enough that a walk over a directory of device nodes adds a
/// line of output rather than a screen of it.
pub const SPECIAL_NOTE_SAMPLE: usize = 16;

/// One special file the walk passed over, kept by name.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SpecialNote {
    /// The path relative to the walk root, in the same spelling the listing
    /// uses — so a name in a warning can be pasted into an `--exclude`.
    pub path: String,
    /// What it is, and therefore why it could not be carried.
    pub kind: SpecialKind,
}

/// What one walk did about every special file it met.
///
/// Merged rather than replaced when a listing is assembled from parts, so a
/// paged listing reports the whole walk once and not one page's worth per page.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct SpecialReport {
    skipped: u64,
    notes: Vec<SpecialNote>,
    /// Special files whose names were not kept because the sample was full.
    /// Reported so that "and 40 more" is a fact rather than a subtraction the
    /// reader has to do, and so a truncated sample can never be mistaken for a
    /// complete list.
    unnamed: u64,
}

impl SpecialReport {
    /// Record one special file.
    ///
    /// The single entry point, so a counter and its name cannot come apart: a
    /// caller that bumped a count directly is how a report ends up claiming four
    /// skipped entries and naming five.
    pub fn observe(&mut self, path: impl Into<String>, kind: SpecialKind) {
        self.skipped += 1;
        if self.notes.len() < SPECIAL_NOTE_SAMPLE {
            self.notes.push(SpecialNote {
                path: path.into(),
                kind,
            });
        } else {
            self.unnamed += 1;
        }
    }

    /// Fold another walk's findings into this one.
    ///
    /// The sample stays capped across the merge and the count stays exact, which
    /// is what lets a paged listing add up every page without the combined report
    /// becoming the memory the paging exists to avoid.
    pub fn merge(&mut self, other: &Self) {
        self.skipped += other.skipped;
        let room = SPECIAL_NOTE_SAMPLE.saturating_sub(self.notes.len());
        let taken = room.min(other.notes.len());
        self.notes.extend_from_slice(&other.notes[..taken]);
        self.unnamed += other.unnamed + (other.notes.len() - taken) as u64;
    }

    /// Special files the walk passed over. Every one of them, named or not.
    #[must_use]
    pub const fn skipped(&self) -> u64 {
        self.skipped
    }

    /// Whether the walk met none at all — the case that must stay silent.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.skipped == 0
    }

    /// The names kept, in the order the walk met them.
    #[must_use]
    pub fn notes(&self) -> &[SpecialNote] {
        &self.notes
    }

    /// Special files the sample had no room to name.
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
        // The ordinary tree holds no special files, and a run over one must not
        // print a line about them at all.
        let report = SpecialReport::default();
        assert!(report.is_empty());
        assert_eq!(report.skipped(), 0);
        assert!(report.notes().is_empty());
    }

    #[test]
    fn every_kind_lands_in_the_one_counter_and_keeps_its_name() {
        let mut report = SpecialReport::default();
        report.observe("run/docker.sock", SpecialKind::Socket);
        report.observe("var/spool/pipe", SpecialKind::Fifo);
        report.observe("dev/null", SpecialKind::CharDevice);
        report.observe("dev/sda", SpecialKind::BlockDevice);

        assert_eq!(report.skipped(), 4);
        assert_eq!(report.notes().len(), 4);
        assert_eq!(report.notes()[0].kind, SpecialKind::Socket);
        assert_eq!(report.notes()[3].path, "dev/sda");
    }

    #[test]
    fn the_count_keeps_rising_after_the_names_stop() {
        // The property the module is built around: a walk over `/dev` reports
        // every node and holds sixteen names.
        let mut report = SpecialReport::default();
        for index in 0..SPECIAL_NOTE_SAMPLE * 3 {
            report.observe(format!("dev/node{index}"), SpecialKind::CharDevice);
        }
        assert_eq!(report.skipped(), (SPECIAL_NOTE_SAMPLE * 3) as u64);
        assert_eq!(report.notes().len(), SPECIAL_NOTE_SAMPLE);
        assert_eq!(report.unnamed(), (SPECIAL_NOTE_SAMPLE * 2) as u64);
    }

    #[test]
    fn merging_keeps_the_count_exact_and_the_sample_capped() {
        let mut left = SpecialReport::default();
        let mut right = SpecialReport::default();
        for index in 0..SPECIAL_NOTE_SAMPLE {
            left.observe(format!("l{index}"), SpecialKind::Fifo);
            right.observe(format!("r{index}"), SpecialKind::Socket);
        }

        left.merge(&right);
        assert_eq!(left.skipped(), (SPECIAL_NOTE_SAMPLE * 2) as u64);
        assert_eq!(left.notes().len(), SPECIAL_NOTE_SAMPLE);
        assert_eq!(left.unnamed(), SPECIAL_NOTE_SAMPLE as u64);
        assert_eq!(
            left.skipped(),
            left.notes().len() as u64 + left.unnamed(),
            "every entry is either named or counted as unnamed"
        );
    }

    #[test]
    fn merging_an_empty_report_changes_nothing() {
        let mut report = SpecialReport::default();
        report.observe("run/x.sock", SpecialKind::Socket);
        let before = report.clone();
        report.merge(&SpecialReport::default());
        assert_eq!(report, before);
    }
}
