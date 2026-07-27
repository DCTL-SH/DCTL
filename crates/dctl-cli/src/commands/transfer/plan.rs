//! The transfer plan: what would happen, computed before anything happens.
//!
//! This is the module `--dry-run` exists for. A plan is a pure function of two
//! listings and a [`Policy`] — no I/O, no clock, no mutation — so the same value
//! can be printed for review or handed to the executor, and the two can never
//! disagree about what the command was going to do.
//!
//! That property is worth more in `sync` than anywhere else. A sync deletes, and
//! the only defensible way to let someone approve a deletion is to show them the
//! exact list first. If the plan were recomputed at execution time, or if the
//! executor made its own decisions as it walked, the approved list and the
//! performed list would be two different things.

use serde::{Serialize, Serializer};

use crate::constants::{
    PLAN_ACTION_COPY, PLAN_ACTION_DELETE, PLAN_ACTION_MKDIR, PLAN_ACTION_SKIP, PLAN_ACTION_UPDATE,
    PLAN_REASON_EMPTY_SOURCE_DIR, PLAN_REASON_EXTRA, PLAN_REASON_IDENTICAL, PLAN_REASON_MISSING,
    PLAN_REASON_UNTRAVERSED,
};
use crate::error::Result;

use super::compare::{Action, ComparePolicy, decide};
use super::entry::Entry;

/// One thing a plan would do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Transfer a file the destination does not have.
    Copy,
    /// Transfer a file the destination has, but differently.
    Update,
    /// Remove a file the destination has and the source does not.
    Delete,
    /// Do nothing — recorded so the counts add up and the reason survives.
    Skip,
    /// Recreate an empty source directory.
    CreateDir,
}

impl Op {
    /// The stable slug used in text and JSON alike.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Copy => PLAN_ACTION_COPY,
            Self::Update => PLAN_ACTION_UPDATE,
            Self::Delete => PLAN_ACTION_DELETE,
            Self::Skip => PLAN_ACTION_SKIP,
            Self::CreateDir => PLAN_ACTION_MKDIR,
        }
    }

    /// Whether this op moves bytes.
    #[must_use]
    pub const fn transfers(self) -> bool {
        matches!(self, Self::Copy | Self::Update)
    }

    /// Whether this op destroys something at the destination.
    #[must_use]
    pub const fn destroys(self) -> bool {
        matches!(self, Self::Delete)
    }

    /// Whether this op changes something the destination already holds.
    ///
    /// The exact question `--immutable` asks, and the reason it is a
    /// classification here rather than a `matches!` at the call site: `Copy` and
    /// `CreateDir` give the destination a name it did not have, while `Update`
    /// replaces bytes and `Delete` removes them. Sitting next to
    /// [`Op::transfers`] and [`Op::destroys`] means a future op cannot be added
    /// without someone deciding which side of that line it falls on — and
    /// getting that wrong silently un-protects a write-once archive.
    #[must_use]
    pub const fn replaces_existing(self) -> bool {
        matches!(self, Self::Update | Self::Delete)
    }

    /// Whether this op does any work at all.
    ///
    /// Skips are kept in the plan for accounting but never rendered as actions:
    /// a listing of ten million unchanged files is not a plan, it is noise, and
    /// the count in the summary says the same thing in one line.
    #[must_use]
    pub const fn is_action(self) -> bool {
        !matches!(self, Self::Skip)
    }
}

impl Serialize for Op {
    /// Serialises as the same slug the text renderer prints.
    ///
    /// Hand-written rather than derived so the JSON value and the first column
    /// of the plan table are provably one constant. A `rename_all` attribute
    /// would produce a second, independent spelling that could drift.
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.slug())
    }
}

/// One entry of a plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlanEntry {
    /// What would be done.
    pub action: Op,
    /// Logical path at the source, relative to the source root. Empty for a
    /// delete, which has no source by definition.
    pub source: String,
    /// Logical path at the destination, relative to the destination root.
    ///
    /// Usually identical to [`PlanEntry::source`]. They differ for `copyto` and
    /// `moveto`, where `DEST` names the object rather than its container — which
    /// is exactly why both are carried rather than one path and a rule.
    pub dest: String,
    /// Bytes this entry would move (or free, for a delete) — [`None`] when the
    /// side it came from recorded no size.
    ///
    /// Only reachable when the *source* is a vault whose index was rebuilt from
    /// object headers: those rows carry no size until the file is written again
    /// (see [`crate::source::Entry::size`]). The plan then genuinely does not
    /// know how much it is about to move, and saying `0 B` — in the table, in
    /// the `--json` plan, and in the run's byte estimate — would describe a real
    /// download of real files as moving nothing.
    pub size: Option<u64>,
    /// Stable slug explaining the decision.
    pub reason: &'static str,
}

impl PlanEntry {
    /// The path to show a human: one path, or `source -> dest` when they differ.
    #[must_use]
    pub fn display_path(&self) -> String {
        if self.source == self.dest || self.source.is_empty() {
            self.dest.clone()
        } else {
            format!(
                "{}{}{}",
                self.source,
                crate::constants::PLAN_PATH_ARROW,
                self.dest
            )
        }
    }
}

/// How a plan is computed.
#[derive(Clone, Copy, Debug, Default)]
pub struct Policy {
    /// How individual files are compared.
    pub compare: ComparePolicy,
    /// Whether files present only at the destination are removed.
    ///
    /// The single flag that separates `copy` from `sync`. `copy` never deletes,
    /// which is why it is the safe default verb and `sync` is the one that
    /// requires confirmation.
    pub delete_extras: bool,
    /// Whether empty source directories are recreated.
    pub create_empty_src_dirs: bool,
    /// Whether the destination was listed at all (`--no-traverse` inverts this).
    pub traversed: bool,
}

impl Policy {
    /// A policy that never deletes — the `copy`/`copyto` shape.
    #[must_use]
    pub fn copying(compare: ComparePolicy) -> Self {
        Self {
            compare,
            delete_extras: false,
            create_empty_src_dirs: false,
            traversed: true,
        }
    }

    /// A policy that removes destination extras — the `sync` shape.
    #[must_use]
    pub fn syncing(compare: ComparePolicy) -> Self {
        Self {
            compare,
            delete_extras: true,
            create_empty_src_dirs: false,
            traversed: true,
        }
    }

    /// Enable empty-directory recreation (`--create-empty-src-dirs`).
    #[must_use]
    pub const fn with_empty_src_dirs(mut self, enabled: bool) -> Self {
        self.create_empty_src_dirs = enabled;
        self
    }

    /// Record whether the destination was enumerated (`--no-traverse`).
    #[must_use]
    pub const fn with_traversal(mut self, traversed: bool) -> Self {
        self.traversed = traversed;
        self
    }
}

/// Everything a command would do, in the order it would do it.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Plan {
    /// Every entry, including skips.
    pub entries: Vec<PlanEntry>,
}

impl Plan {
    /// Diff two listings.
    ///
    /// Source order is preserved for the transfers and deletes are appended in
    /// destination order, so a plan printed twice from the same inputs is
    /// byte-identical.
    ///
    /// # Errors
    /// Propagates a comparison that cannot be made — today, `--checksum` where a
    /// side has no hash. A plan that cannot be computed is never approximated.
    pub fn compute(source: &[Entry], dest: &[Entry], policy: &Policy) -> Result<Self> {
        let mut entries = Vec::with_capacity(source.len());
        let mut matched = vec![false; dest.len()];

        // Indexed rather than scanned. A linear search per source file makes the
        // diff quadratic, which on the million-file datasets `PLAN.md` §16.2
        // targets is the difference between seconds and hours — and it would be
        // invisible in any test small enough to write by hand.
        let by_path: std::collections::HashMap<&str, usize> = dest
            .iter()
            .enumerate()
            .map(|(index, item)| (item.path.as_str(), index))
            .collect();

        for item in source {
            let position = by_path.get(item.path.as_str()).copied();
            if let Some(index) = position {
                if let Some(slot) = matched.get_mut(index) {
                    *slot = true;
                }
            }
            let counterpart = position.and_then(|index| dest.get(index));

            if !item.is_file() {
                entries.push(empty_dir_entry(item, counterpart.is_some(), policy));
                continue;
            }

            // With `--no-traverse` nothing was listed, so "absent" is an
            // assumption rather than an observation — and the plan says so.
            let action = if policy.traversed {
                decide(item, counterpart, &policy.compare)?
            } else {
                Action::Copy(PLAN_REASON_UNTRAVERSED)
            };

            entries.push(PlanEntry {
                action: match action {
                    Action::Copy(_) => Op::Copy,
                    Action::Update(_) => Op::Update,
                    Action::Skip(_) => Op::Skip,
                },
                source: item.path.clone(),
                dest: item.path.clone(),
                size: item.size,
                reason: action.reason(),
            });
        }

        if policy.delete_extras {
            for (index, item) in dest.iter().enumerate() {
                if matched.get(index).copied().unwrap_or(false) || !item.is_file() {
                    continue;
                }
                entries.push(PlanEntry {
                    action: Op::Delete,
                    source: String::new(),
                    dest: item.path.clone(),
                    size: item.size,
                    reason: PLAN_REASON_EXTRA,
                });
            }
        }

        Ok(Self { entries })
    }

    /// A plan for one file landing under an exact destination name.
    ///
    /// The `copyto`/`moveto` shape: the source keeps its own path, the
    /// destination gets the name the user typed, and no listing pairing happens
    /// because there is exactly one thing to move.
    ///
    /// # Errors
    /// Propagates the comparison, so `--ignore-existing` and `--update` behave
    /// identically to the way they do in a directory transfer.
    pub fn compute_exact(
        source: &Entry,
        dest: Option<&Entry>,
        dest_name: &str,
        policy: &Policy,
    ) -> Result<Self> {
        let action = if policy.traversed {
            decide(source, dest, &policy.compare)?
        } else {
            Action::Copy(PLAN_REASON_UNTRAVERSED)
        };

        Ok(Self {
            entries: vec![PlanEntry {
                action: match action {
                    Action::Copy(_) => Op::Copy,
                    Action::Update(_) => Op::Update,
                    Action::Skip(_) => Op::Skip,
                },
                source: source.path.clone(),
                dest: dest_name.to_string(),
                size: source.size,
                reason: action.reason(),
            }],
        })
    }

    /// Every entry carrying the given op.
    pub fn with_op(&self, op: Op) -> impl Iterator<Item = &PlanEntry> {
        self.entries.iter().filter(move |entry| entry.action == op)
    }

    /// Every entry that does something — the rows a report shows.
    pub fn actions(&self) -> impl Iterator<Item = &PlanEntry> {
        self.entries.iter().filter(|entry| entry.action.is_action())
    }

    /// Every entry that moves bytes, in plan order.
    pub fn transfers(&self) -> impl Iterator<Item = &PlanEntry> {
        self.entries.iter().filter(|entry| entry.action.transfers())
    }

    /// Every entry that removes something, in plan order.
    pub fn deletions(&self) -> impl Iterator<Item = &PlanEntry> {
        self.entries.iter().filter(|entry| entry.action.destroys())
    }

    /// How many entries carry the given op.
    #[must_use]
    pub fn count(&self, op: Op) -> usize {
        self.with_op(op).count()
    }

    /// Bytes the transfers would move, or [`None`] when any of them has no
    /// recorded size.
    ///
    /// Absorbing rather than partial, like every other total in this binary that
    /// can be missing a term: a sum that quietly dropped the unmeasured entries
    /// would be short by an unknown amount and would look complete.
    #[must_use]
    pub fn bytes_to_transfer(&self) -> Option<u64> {
        self.transfers().try_fold(0_u64, |total, entry| {
            entry.size.map(|size| total.saturating_add(size))
        })
    }

    /// Whether anything would be removed. Drives the destructive confirmation.
    #[must_use]
    pub fn destroys_anything(&self) -> bool {
        self.deletions().next().is_some()
    }

    /// Whether the plan would do nothing at all.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.actions().next().is_none()
    }

    /// Counts and totals, for the report header and the JSON document.
    #[must_use]
    pub fn summary(&self) -> Summary {
        Summary {
            copy: self.count(Op::Copy),
            update: self.count(Op::Update),
            delete: self.count(Op::Delete),
            skip: self.count(Op::Skip),
            mkdir: self.count(Op::CreateDir),
            bytes: self.bytes_to_transfer(),
        }
    }
}

/// Aggregate counts for a plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Files not present at the destination.
    pub copy: usize,
    /// Files present but different.
    pub update: usize,
    /// Files present only at the destination.
    pub delete: usize,
    /// Files proven identical, or excluded by a flag.
    pub skip: usize,
    /// Empty source directories to recreate.
    pub mkdir: usize,
    /// Bytes the transfers would move, or `null` when any of them has no
    /// recorded size. See [`Plan::bytes_to_transfer`].
    pub bytes: Option<u64>,
}

/// Turn an empty source directory into its plan entry.
fn empty_dir_entry(item: &Entry, exists_at_dest: bool, policy: &Policy) -> PlanEntry {
    let create = policy.create_empty_src_dirs && !exists_at_dest;
    PlanEntry {
        action: if create { Op::CreateDir } else { Op::Skip },
        source: item.path.clone(),
        dest: item.path.clone(),
        // A directory moves no bytes, and that is a measurement.
        size: Some(0),
        reason: if create {
            PLAN_REASON_EMPTY_SOURCE_DIR
        } else if exists_at_dest {
            PLAN_REASON_IDENTICAL
        } else {
            PLAN_REASON_MISSING
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{PLAN_REASON_EXTRA, PLAN_REASON_SIZE};
    use std::time::{Duration, SystemTime};

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn file(path: &str, size: u64, seconds: u64) -> Entry {
        Entry::file(path, size).with_modified(at(seconds))
    }

    fn ops(plan: &Plan) -> Vec<(Op, &str)> {
        plan.entries
            .iter()
            .map(|entry| (entry.action, entry.dest.as_str()))
            .collect()
    }

    #[test]
    fn a_copy_plan_adds_updates_and_skips_but_never_deletes() {
        let source = [
            file("new.txt", 10, 100),
            file("changed.txt", 20, 100),
            file("same.txt", 30, 100),
        ];
        let dest = [
            file("changed.txt", 21, 100),
            file("same.txt", 30, 100),
            file("extra.txt", 40, 100),
        ];

        let plan =
            Plan::compute(&source, &dest, &Policy::copying(ComparePolicy::default())).unwrap();

        assert_eq!(
            ops(&plan),
            [
                (Op::Copy, "new.txt"),
                (Op::Update, "changed.txt"),
                (Op::Skip, "same.txt"),
            ]
        );
        assert!(!plan.destroys_anything(), "copy must never delete");
        assert_eq!(plan.bytes_to_transfer(), Some(30));
    }

    #[test]
    fn a_sync_plan_deletes_the_extras() {
        let source = [file("keep.txt", 10, 100)];
        let dest = [file("keep.txt", 10, 100), file("gone.txt", 40, 100)];

        let plan =
            Plan::compute(&source, &dest, &Policy::syncing(ComparePolicy::default())).unwrap();

        assert_eq!(
            ops(&plan),
            [(Op::Skip, "keep.txt"), (Op::Delete, "gone.txt")]
        );
        assert!(plan.destroys_anything());
        let deletion = plan.deletions().next().unwrap();
        assert_eq!(deletion.reason, PLAN_REASON_EXTRA);
        // A delete has no source path — there is nothing at the source by
        // definition, and pretending otherwise would misreport the direction.
        assert!(deletion.source.is_empty());
    }

    #[test]
    fn a_prefix_collision_is_not_treated_as_the_same_file() {
        // The classic sync bug: `photos` must not shadow `photos-backup`.
        let source = [file("photos/a.jpg", 1, 100)];
        let dest = [file("photos-backup/a.jpg", 1, 100)];
        let plan =
            Plan::compute(&source, &dest, &Policy::syncing(ComparePolicy::default())).unwrap();
        assert_eq!(
            ops(&plan),
            [
                (Op::Copy, "photos/a.jpg"),
                (Op::Delete, "photos-backup/a.jpg")
            ]
        );
    }

    #[test]
    fn no_traverse_assumes_an_empty_destination_and_says_so() {
        let source = [file("a.txt", 10, 100)];
        let dest = [file("a.txt", 10, 100)];
        let policy = Policy::copying(ComparePolicy::default()).with_traversal(false);
        let plan = Plan::compute(&source, &dest, &policy).unwrap();

        assert_eq!(ops(&plan), [(Op::Copy, "a.txt")]);
        // The reason distinguishes an assumption from an observation.
        assert_eq!(plan.entries[0].reason, PLAN_REASON_UNTRAVERSED);
    }

    #[test]
    fn empty_source_directories_are_recreated_only_when_asked() {
        let source = [Entry::empty_dir("empty")];
        let dest: [Entry; 0] = [];

        let without =
            Plan::compute(&source, &dest, &Policy::copying(ComparePolicy::default())).unwrap();
        assert_eq!(without.count(Op::CreateDir), 0);
        assert!(without.is_noop());

        let with = Plan::compute(
            &source,
            &dest,
            &Policy::copying(ComparePolicy::default()).with_empty_src_dirs(true),
        )
        .unwrap();
        assert_eq!(ops(&with), [(Op::CreateDir, "empty")]);
        assert_eq!(
            with.bytes_to_transfer(),
            Some(0),
            "a directory moves no bytes"
        );
    }

    #[test]
    fn an_empty_directory_already_at_the_destination_is_skipped() {
        let source = [Entry::empty_dir("empty")];
        let dest = [Entry::empty_dir("empty")];
        let plan = Plan::compute(
            &source,
            &dest,
            &Policy::syncing(ComparePolicy::default()).with_empty_src_dirs(true),
        )
        .unwrap();
        assert_eq!(plan.count(Op::CreateDir), 0);
        // And it is not an "extra" to delete either.
        assert!(!plan.destroys_anything());
    }

    #[test]
    fn an_exact_plan_renames_the_destination() {
        let source = Entry::file("report.pdf", 100);
        let plan = Plan::compute_exact(
            &source,
            None,
            "archive-2024.pdf",
            &Policy::copying(ComparePolicy::default()),
        )
        .unwrap();

        assert_eq!(plan.entries.len(), 1);
        let entry = &plan.entries[0];
        assert_eq!(entry.source, "report.pdf");
        assert_eq!(entry.dest, "archive-2024.pdf");
        // The display form has to show both, or the user cannot see the rename.
        assert_eq!(
            entry.display_path(),
            format!(
                "report.pdf{}archive-2024.pdf",
                crate::constants::PLAN_PATH_ARROW
            )
        );
    }

    #[test]
    fn an_exact_plan_still_honours_the_comparison() {
        let source = Entry::file("a.txt", 10).with_modified(at(100));
        let dest = Entry::file("b.txt", 10).with_modified(at(100));
        let plan = Plan::compute_exact(
            &source,
            Some(&dest),
            "b.txt",
            &Policy::copying(ComparePolicy::default()),
        )
        .unwrap();
        assert_eq!(plan.entries[0].action, Op::Skip);
        assert!(plan.is_noop());
    }

    #[test]
    fn the_summary_counts_every_category() {
        let source = [file("new.txt", 10, 100), file("same.txt", 5, 100)];
        let dest = [file("same.txt", 5, 100), file("extra.txt", 7, 100)];
        let plan =
            Plan::compute(&source, &dest, &Policy::syncing(ComparePolicy::default())).unwrap();

        let summary = plan.summary();
        assert_eq!(
            summary,
            Summary {
                copy: 1,
                update: 0,
                delete: 1,
                skip: 1,
                mkdir: 0,
                bytes: Some(10),
            }
        );
    }

    #[test]
    fn a_plan_serialises_with_the_same_slugs_it_prints() {
        // The whole point of the hand-written `Serialize`: a script may filter
        // the text plan or the JSON plan and must select the same rows.
        let source = [file("a.txt", 10, 100)];
        let dest: [Entry; 0] = [];
        let plan =
            Plan::compute(&source, &dest, &Policy::copying(ComparePolicy::default())).unwrap();
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains(&format!("\"{PLAN_ACTION_COPY}\"")), "{json}");
        assert!(json.contains(PLAN_REASON_MISSING), "{json}");
    }

    #[test]
    fn an_uncomputable_comparison_fails_rather_than_guessing() {
        // `--checksum` with no hashes: the plan is refused, not approximated.
        let source = [file("a.txt", 10, 100)];
        let dest = [file("a.txt", 10, 100)];
        let policy = Policy::copying(ComparePolicy {
            checksum: true,
            ..ComparePolicy::default()
        });
        assert!(Plan::compute(&source, &dest, &policy).is_err());
    }

    #[test]
    fn ops_classify_themselves_consistently() {
        assert!(Op::Copy.transfers() && Op::Copy.is_action() && !Op::Copy.destroys());
        assert!(Op::Update.transfers());
        assert!(Op::Delete.destroys() && !Op::Delete.transfers());
        assert!(!Op::Skip.is_action());
        assert!(Op::CreateDir.is_action() && !Op::CreateDir.transfers());
    }

    #[test]
    fn only_the_ops_that_touch_an_existing_object_replace_it() {
        // What `--immutable` reads. A copy into a name the destination does not
        // have is an addition and must stay allowed; anything that overwrites or
        // removes is what the flag forbids.
        assert!(
            !Op::Copy.replaces_existing(),
            "an addition, not an overwrite"
        );
        assert!(!Op::CreateDir.replaces_existing());
        assert!(!Op::Skip.replaces_existing());
        assert!(Op::Update.replaces_existing());
        assert!(Op::Delete.replaces_existing());
    }

    #[test]
    fn size_differences_are_reported_as_updates() {
        let source = [file("a.txt", 10, 100)];
        let dest = [file("a.txt", 11, 100)];
        let plan =
            Plan::compute(&source, &dest, &Policy::copying(ComparePolicy::default())).unwrap();
        assert_eq!(plan.entries[0].reason, PLAN_REASON_SIZE);
    }
}
