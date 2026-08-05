//! What a replication would do, decided before it does anything.
//!
//! The plan is the value `--dry-run` prints and the value the executor walks, so
//! the two can never disagree about what the command was going to do. That
//! matters less here than it does in `sync` — replication destroys nothing — but
//! it matters for a different reason: an offsite job's `--dry-run` output is what
//! an operator attaches to a change ticket, and a plan that were recomputed at
//! execution time would make that attachment a guess.
//!
//! ## Object keys are carried, never derived
//!
//! Every key the source lists is written to the destination **byte for byte**.
//! Nothing here parses, normalises, re-cases or re-encodes one. A vault's keys
//! are derived from its own key material, so a key this command "tidied" would
//! address an object the vault can never find again, and the damage would be
//! invisible until a restore. The index is likewise never opened: the objects
//! are opaque, the index that describes them is one of them, and a replica is
//! correct precisely because nothing in this command understands either.
//!
//! ## What decides an object's fate
//!
//! Metadata only — the key and the byte count on each side — because a plan that
//! needed object bytes to exist could not be printed without paying for the run
//! it was rehearsing.
//!
//! | at the destination | `--verify checksum` / `sample` | `--verify strict` |
//! |--------------------|-------------------------------|-------------------|
//! | absent             | replicate                      | replicate         |
//! | present, different size | replicate                 | replicate         |
//! | present, same size | skip                           | reverify          |
//!
//! The interesting cell is the last one. At the default strength a stored object
//! with the same key and the same size is taken to be the same object and is
//! skipped, which is what makes a weekly offsite job cost the week's new objects
//! rather than the whole vault. `--verify strict` refuses that inference and
//! reads the object back from both ends to compare BLAKE3s — the mode to schedule
//! quarterly, and the only one that proves a replica rather than assuming it. The
//! report says which of the two happened, per object, so the weaker claim is
//! never mistaken for the stronger one.
//!
//! Objects present only at the **destination** are counted and never touched.
//! Replication is not a sync: deleting from the second copy is the one action
//! that could turn a redundancy job into a data-loss event, and no flag here
//! enables it.

use serde::Serialize;

use std::collections::BTreeMap;
use std::sync::Arc;

use dctl_store::Backend;

use crate::cli::VerifyMode;
use crate::constants::{
    PLAN_ACTION_SKIP, PLAN_REASON_EXISTS, PLAN_REASON_MISSING, PLAN_REASON_SIZE,
    REPLICATE_ACTION_FAILED, REPLICATE_ACTION_REPLICATE, REPLICATE_ACTION_REVERIFY,
};
use crate::error::{CliError, Result};

/// What a replication would do with one object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Copy the object's bytes to the destination under the same key.
    Replicate,
    /// Read both copies back and compare their hashes before deciding.
    Reverify,
    /// Leave it alone.
    Skip,
    /// It could not be moved. Only an execution produces this.
    Failed,
}

impl Action {
    /// The stable slug used in text and JSON alike.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Replicate => REPLICATE_ACTION_REPLICATE,
            Self::Reverify => REPLICATE_ACTION_REVERIFY,
            Self::Skip => PLAN_ACTION_SKIP,
            Self::Failed => REPLICATE_ACTION_FAILED,
        }
    }

    /// Whether this action reads object bytes, and therefore costs egress.
    ///
    /// The question an operator asks before scheduling a run, and the reason
    /// `Reverify` is not folded into `Skip`: both leave the destination as it
    /// was, and only one of them is free.
    #[must_use]
    pub const fn reads_bytes(self) -> bool {
        matches!(self, Self::Replicate | Self::Reverify)
    }

    /// Whether this action is worth printing.
    ///
    /// Skips are counted rather than listed, for the same reason the transfer
    /// family counts them: a plan is a list of things that will happen, and ten
    /// million "unchanged" lines bury the fifty that will.
    #[must_use]
    pub const fn is_action(self) -> bool {
        !matches!(self, Self::Skip)
    }
}

impl Serialize for Action {
    /// Serialises as the slug the text renderer prints, so the JSON value and
    /// the first column of the table are provably one constant.
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.slug())
    }
}

/// One object, and what is to become of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Item {
    /// What would be, or was, done.
    pub action: Action,
    /// The object key, exactly as the source store spells it.
    pub key: String,
    /// The object's size at the source, in bytes.
    pub size: u64,
    /// Stable slug explaining the decision.
    pub reason: &'static str,
}

/// Aggregate counts for a whole plan.
///
/// Carried as its own value so the summary a report prints and the summary a
/// script parses are the same arithmetic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Objects the source store holds.
    pub objects: u64,
    /// Objects that would be, or were, copied.
    pub replicated: u64,
    /// Objects read back from both stores and proved identical
    /// (`--verify strict`).
    ///
    /// Kept apart from [`Summary::skipped`] because the two make different
    /// claims: a skip *assumes* the replica already holds the object, a
    /// reverification *proves* it. A single field would let the quarterly proof
    /// be reported by a run that checked nothing.
    pub reverified: u64,
    /// Objects already present at the destination with the same size, and
    /// therefore assumed to be the same object.
    pub skipped: u64,
    /// Objects that could not be moved. Only an execution sets this.
    pub failed: u64,
    /// Bytes written to the destination.
    ///
    /// In a plan this is a **floor**, not an estimate, and the difference is
    /// worth stating: a `--verify strict` run cannot know how many of its
    /// reverifications will turn out to disagree and become writes, so it counts
    /// none of them. The bytes such a run will *read* are a different quantity
    /// and are reported by [`Plan::egress_bytes`], which is what sizes the
    /// progress display. A single field would have to overstate one or
    /// understate the other.
    pub bytes: u64,
    /// Objects the destination holds and the source does not.
    ///
    /// Counted and never touched: replication adds a copy, it never removes one.
    /// Reported because drift at a replica is worth knowing about even though
    /// nothing here acts on it.
    pub extra: u64,
}

/// A whole replication, decided.
#[derive(Clone, Debug, Default)]
pub struct Plan {
    items: Vec<Item>,
    summary: Summary,
}

impl Plan {
    /// Build a plan from what the two stores hold.
    ///
    /// # Errors
    /// Whatever either backend's listing fails with, classified by
    /// [`CliError`]. A listing that could not be completed is never treated as
    /// an empty one: replicating "nothing" because the source could not be read
    /// would report a successful, and entirely fictional, backup.
    pub async fn build(
        source: &Arc<dyn Backend>,
        destination: &Arc<dyn Backend>,
        verify: VerifyMode,
    ) -> Result<Self> {
        let at_source = list_all(source).await?;
        let at_destination = list_all(destination).await?;
        Ok(Self::decide(&at_source, &at_destination, verify))
    }

    /// Decide a plan from two listings.
    ///
    /// Pure, so the table in the module documentation is testable without a
    /// store, a network or a temporary directory — which is what lets the
    /// `--verify strict` cell be pinned by a test rather than by review.
    #[must_use]
    pub fn decide(
        at_source: &BTreeMap<String, u64>,
        at_destination: &BTreeMap<String, u64>,
        verify: VerifyMode,
    ) -> Self {
        let mut items = Vec::with_capacity(at_source.len());
        let mut summary = Summary {
            objects: at_source.len() as u64,
            ..Summary::default()
        };

        for (key, &size) in at_source {
            let (action, reason) = classify(size, at_destination.get(key).copied(), verify);
            match action {
                Action::Replicate => {
                    summary.replicated += 1;
                    summary.bytes += size;
                }
                // Deliberately not counted in `summary.bytes`: a reverification
                // writes nothing unless the two copies disagree, and claiming
                // the bytes up front would have a clean strict run report a
                // transfer that never happened.
                Action::Reverify => summary.reverified += 1,
                Action::Skip => summary.skipped += 1,
                // Unreachable from a plan: only an execution fails an object.
                Action::Failed => summary.failed += 1,
            }
            items.push(Item {
                action,
                key: key.clone(),
                size,
                reason,
            });
        }

        summary.extra = at_destination
            .keys()
            .filter(|key| !at_source.contains_key(*key))
            .count() as u64;

        Self { items, summary }
    }

    /// Every object, in the order the source listed them.
    #[must_use]
    pub fn items(&self) -> &[Item] {
        &self.items
    }

    /// The aggregate counts.
    #[must_use]
    pub const fn summary(&self) -> Summary {
        self.summary
    }

    /// Whether this plan would move or read a single byte.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.items.iter().any(|item| item.action.reads_bytes())
    }

    /// Bytes this run will read from the source, which is what the progress
    /// display is sized against.
    ///
    /// Larger than [`Summary::bytes`] whenever `--verify strict` has objects to
    /// reverify: those are read and, usually, not written. Sizing the bar
    /// against the written total instead would have a quarterly proof appear to
    /// finish instantly and then keep going.
    #[must_use]
    pub fn egress_bytes(&self) -> u64 {
        self.items
            .iter()
            .filter(|item| item.action.reads_bytes())
            .map(|item| item.size)
            .sum()
    }
}

/// Decide one object's fate. See the table in the module documentation.
const fn classify(
    size: u64,
    at_destination: Option<u64>,
    verify: VerifyMode,
) -> (Action, &'static str) {
    match at_destination {
        None => (Action::Replicate, PLAN_REASON_MISSING),
        Some(stored) if stored != size => (Action::Replicate, PLAN_REASON_SIZE),
        // Same key, same byte count. Whether that is proof or an assumption is
        // exactly what `--verify` buys, so the answer is the mode's to give.
        Some(_) => match verify {
            VerifyMode::Strict => (Action::Reverify, PLAN_REASON_EXISTS),
            VerifyMode::Checksum | VerifyMode::Sample => (Action::Skip, PLAN_REASON_EXISTS),
        },
    }
}

/// Every object in a store, as key and size.
///
/// Paged, so memory stays proportional to the number of objects rather than to
/// the bytes they hold ([the plan](https://doc.dctl.sh/project/plan) §16.2).
/// The loop refuses to continue on a cursor a backend handed back unchanged: a
/// provider that paginates in a circle would otherwise turn a listing into an
/// unbounded one, and a replication that never starts is a worse failure than
/// one that reports a broken provider.
async fn list_all(backend: &Arc<dyn Backend>) -> Result<BTreeMap<String, u64>> {
    let mut objects = BTreeMap::new();
    let mut cursor: Option<String> = None;

    loop {
        let page = backend.list_page("", cursor.clone()).await?;
        for object in page.items {
            objects.insert(object.key.as_str().to_string(), object.size);
        }

        match page.next_cursor {
            None => return Ok(objects),
            Some(next) if Some(&next) == cursor.as_ref() => {
                return Err(CliError::from(dctl_store::StoreError::Backend(format!(
                    "the store returned the same listing cursor twice ({next}), so \
                     its objects cannot be enumerated"
                ))));
            }
            Some(next) => cursor = Some(next),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing(entries: &[(&str, u64)]) -> BTreeMap<String, u64> {
        entries
            .iter()
            .map(|(key, size)| ((*key).to_string(), *size))
            .collect()
    }

    #[test]
    fn an_object_the_destination_lacks_is_replicated() {
        let plan = Plan::decide(
            &listing(&[("data/aa", 10), ("data/bb", 20)]),
            &listing(&[]),
            VerifyMode::Checksum,
        );
        assert_eq!(plan.summary().objects, 2);
        assert_eq!(plan.summary().replicated, 2);
        assert_eq!(plan.summary().bytes, 30);
        assert!(!plan.is_empty());
        for item in plan.items() {
            assert_eq!(item.action, Action::Replicate);
            assert_eq!(item.reason, PLAN_REASON_MISSING);
        }
    }

    #[test]
    fn a_stored_object_of_a_different_size_is_replicated_again() {
        // A half-written object from an interrupted run. Leaving it would make
        // the replica silently unusable.
        let plan = Plan::decide(
            &listing(&[("data/aa", 10)]),
            &listing(&[("data/aa", 4)]),
            VerifyMode::Checksum,
        );
        assert_eq!(plan.items()[0].action, Action::Replicate);
        assert_eq!(plan.items()[0].reason, PLAN_REASON_SIZE);
    }

    #[test]
    fn a_stored_object_of_the_same_size_is_skipped_by_default() {
        // What makes a weekly offsite job cost the week rather than the vault.
        let plan = Plan::decide(
            &listing(&[("data/aa", 10)]),
            &listing(&[("data/aa", 10)]),
            VerifyMode::Checksum,
        );
        assert_eq!(plan.summary().skipped, 1);
        assert_eq!(plan.summary().bytes, 0);
        assert!(plan.is_empty(), "a fully replicated store moves nothing");
        assert!(!plan.items()[0].action.is_action());
    }

    #[test]
    fn strict_refuses_to_assume_and_reads_both_copies_back() {
        // The distinction the mode exists for: `skip` assumes the replica is
        // intact, `reverify` proves it. Folding the two together would let a
        // quarterly proof be reported by a run that checked nothing.
        let plan = Plan::decide(
            &listing(&[("data/aa", 10)]),
            &listing(&[("data/aa", 10)]),
            VerifyMode::Strict,
        );
        assert_eq!(plan.items()[0].action, Action::Reverify);
        assert_eq!(plan.summary().reverified, 1);
        assert_eq!(plan.summary().skipped, 0);
        assert!(plan.items()[0].action.reads_bytes());
        assert!(
            !plan.is_empty(),
            "strict pays egress even for a clean replica"
        );

        // The two byte counts say different things, and conflating them would
        // have a clean strict run claim a transfer that never happened: nothing
        // is written unless the copies disagree, but every byte is still read.
        assert_eq!(plan.summary().bytes, 0, "nothing is written yet");
        assert_eq!(plan.egress_bytes(), 10, "but everything is read");

        // Sampling is the cheap mode and behaves like the default here: it
        // verifies what it writes, not what somebody else already wrote.
        let sampled = Plan::decide(
            &listing(&[("data/aa", 10)]),
            &listing(&[("data/aa", 10)]),
            VerifyMode::Sample,
        );
        assert_eq!(sampled.items()[0].action, Action::Skip);
    }

    #[test]
    fn an_object_only_the_destination_holds_is_counted_and_left_alone() {
        // Replication adds a copy; it never removes one. A `delete` here would
        // turn a redundancy job into a data-loss event.
        let plan = Plan::decide(
            &listing(&[("data/aa", 10)]),
            &listing(&[("data/aa", 10), ("data/gone", 5)]),
            VerifyMode::Checksum,
        );
        assert_eq!(plan.summary().extra, 1);
        assert_eq!(plan.items().len(), 1, "extras are never planned actions");
    }

    #[test]
    fn object_keys_are_carried_through_untouched() {
        // The keys a vault derives are not paths and must not be tidied: a key
        // this command re-cased or re-encoded would address an object the vault
        // can never find again.
        let awkward = "obj/AB/cd%2Fef .bin";
        let plan = Plan::decide(
            &listing(&[(awkward, 1)]),
            &listing(&[]),
            VerifyMode::Checksum,
        );
        assert_eq!(plan.items()[0].key, awkward);
    }

    #[test]
    fn an_empty_source_plans_nothing_and_claims_nothing() {
        let plan = Plan::decide(&listing(&[]), &listing(&[("x", 1)]), VerifyMode::Strict);
        assert_eq!(
            plan.summary(),
            Summary {
                extra: 1,
                ..Summary::default()
            }
        );
        assert!(plan.is_empty());
    }

    #[test]
    fn every_action_has_a_distinct_stable_slug() {
        // The slugs land in --json and in an audit record, so a collision would
        // make "moved with no key" and "could not be moved" indistinguishable.
        let slugs: Vec<&str> = [
            Action::Replicate,
            Action::Reverify,
            Action::Skip,
            Action::Failed,
        ]
        .iter()
        .map(|action| action.slug())
        .collect();
        for (index, slug) in slugs.iter().enumerate() {
            assert!(!slug.is_empty());
            assert!(!slugs[index + 1..].contains(slug), "'{slug}' is duplicated");
        }
        assert_eq!(
            serde_json::to_value(Action::Replicate).unwrap(),
            serde_json::json!(REPLICATE_ACTION_REPLICATE)
        );
    }

    #[tokio::test]
    async fn a_real_pair_of_stores_on_disk_plans_the_difference() {
        // End to end against the one backend a test can build without
        // credentials. This is what catches a listing walked with the wrong
        // prefix, which no amount of `decide` testing would.
        let dir = tempfile::tempdir().unwrap();
        let source_dir = dir.path().join("source");
        let dest_dir = dir.path().join("dest");
        std::fs::create_dir_all(source_dir.join("data")).unwrap();
        std::fs::create_dir_all(dest_dir.join("data")).unwrap();
        std::fs::write(source_dir.join("data").join("aa"), b"hello").unwrap();
        std::fs::write(source_dir.join("data").join("bb"), b"world!").unwrap();
        std::fs::write(dest_dir.join("data").join("aa"), b"hello").unwrap();

        let source: Arc<dyn Backend> = Arc::new(dctl_store::LocalFs::new(source_dir));
        let destination: Arc<dyn Backend> = Arc::new(dctl_store::LocalFs::new(dest_dir));

        let plan = Plan::build(&source, &destination, VerifyMode::Checksum)
            .await
            .unwrap();
        assert_eq!(plan.summary().objects, 2);
        assert_eq!(plan.summary().replicated, 1);
        assert_eq!(plan.summary().skipped, 1);
        assert_eq!(plan.summary().bytes, 6);
    }
}
