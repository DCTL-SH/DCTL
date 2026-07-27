//! Vocabulary shared by the audit & recovery family — `audit`, `backup` and
//! `restore`.
//!
//! These three commands exist because of the two promises a plain copier does
//! not make. `audit` backs the tamper-evident log (`PLAN.md` §7): you can *prove*
//! what happened, and a deletion from the record is detectable. `backup` and
//! `restore` back the tested-restore principle (`PLAN.md` §13.6): a backup you
//! never restored is not a backup, so the things that make a restore fail —
//! illegal filenames, case collisions, paths too long for the destination — are
//! found before the first byte moves rather than 3.9 TB into a 4 TB run.
//!
//! Six concerns are shared, and each lives in its own file rather than being
//! written twice:
//!
//! * [`target`] — turning a `REMOTE:PATH` argument into a remote name plus a
//!   canonical logical path, with the drive-letter and `..` rules applied once.
//! * [`timespec`] — the point-in-time arguments (`--at`, `--since`, `--until`).
//! * [`snapshot`] — what a snapshot may be called, and what it is called when
//!   the user does not say.
//! * [`selection`] — which files a run considers, resolved through the one
//!   filter engine ([`crate::filter`]) every other command family uses.
//! * [`preflight`] — every reason a name could fail to be written, gathered
//!   before anything is.
//! * [`plan`] and [`report`] — what a run *would* do, and how that is rendered
//!   in each of the three output formats.
//!
//! It is deliberately not a `util` module: everything here is recovery domain
//! vocabulary, and a helper unrelated to proving a backup restorable does not
//! belong in it.

pub mod plan;
pub mod preflight;
pub mod report;
pub mod selection;
pub mod snapshot;
pub mod target;
pub mod timespec;

pub use plan::{Entry, Plan};
pub use preflight::Audience;
pub use selection::Selection;
pub use snapshot::SnapshotName;
pub use target::Target;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::{Selection, Target};

    #[test]
    fn the_family_shares_one_vocabulary_for_the_vault_side() {
        // `backup` writes into a `Target` and `restore` reads out of one, so a
        // single parse decides both. Asserted here rather than twice, because
        // two parses of `REMOTE:PATH` are two chances to disagree about scope —
        // and disagreeing about scope means restoring the wrong tree.
        let target = Target::parse("archive:photos").unwrap();
        assert_eq!(target.remote, "archive");
        assert!(target.covers("photos/2024/a.jpg"));
        assert_eq!(target.relative("photos/2024/a.jpg"), "2024/a.jpg");
    }

    #[test]
    fn an_unfiltered_selection_is_shared_by_both_verbs() {
        // The default has to admit everything: a `Selection` that quietly
        // restricted would make a backup store less than it was asked to.
        let selection = Selection::default();
        assert!(selection.admits_file("anything/at/all.bin", u64::MAX));
        assert!(!selection.is_restricting());
    }
}
