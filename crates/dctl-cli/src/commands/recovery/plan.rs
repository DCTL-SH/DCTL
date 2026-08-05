//! What a recovery *would* do, computed before it does any of it.
//!
//! The plan is what makes `--dry-run` worth trusting: it is the same value the
//! executor will consume, so what a dry run prints is exactly what a real run
//! performs — not a second implementation that reports its own opinion. When the
//! engine lands, it walks this list; until then, the list is the honest half of
//! the command and the execution is an error ([the plan](https://doc.dctl.sh/project/plan) §6: never report work
//! that did not happen).
//!
//! One [`Entry`] per file, one action per entry. In particular
//! [`crate::constants::PLAN_ACTION_OVERWRITE`] is spelled differently from
//! [`crate::constants::PLAN_ACTION_RESTORE`] everywhere, because exactly one of
//! the two destroys something that already exists and a reader skimming a
//! thousand rows must be able to see which.

use serde::Serialize;

/// One planned file operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Entry {
    /// Stable action slug from [`crate::constants`].
    pub action: &'static str,
    /// Where the bytes come from, in the notation the user typed.
    pub source: String,
    /// Where they land, in the notation the user typed.
    pub destination: String,
    /// Plaintext size in bytes, as far as it is known before the transfer.
    pub size: u64,
    /// Why this entry has the action it has, when that is not obvious. Omitted
    /// from the JSON when there is nothing to say.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

impl Entry {
    /// Build an entry with no explanatory reason.
    #[must_use]
    pub fn new(
        action: &'static str,
        source: impl Into<String>,
        destination: impl Into<String>,
        size: u64,
    ) -> Self {
        Self {
            action,
            source: source.into(),
            destination: destination.into(),
            size,
            reason: None,
        }
    }

    /// Attach the reason this action was chosen.
    #[must_use]
    pub fn because(mut self, reason: &'static str) -> Self {
        self.reason = Some(reason);
        self
    }
}

/// An accumulated plan.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Plan {
    entries: Vec<Entry>,
}

impl Plan {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn push(&mut self, entry: Entry) {
        self.entries.push(entry);
    }

    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many entries carry this action.
    #[must_use]
    pub fn count(&self, action: &str) -> usize {
        self.entries.iter().filter(|e| e.action == action).count()
    }

    /// Total bytes across every entry that moves data.
    ///
    /// Saturating rather than wrapping: a plan over a multi-petabyte tree must
    /// report a wrong-but-huge number rather than a small one, because a small
    /// one would look plausible.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.entries
            .iter()
            .fold(0_u64, |total, entry| total.saturating_add(entry.size))
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Sort by destination so the plan reads in the order the tree is laid out,
    /// and so two runs over the same input produce identical output.
    pub fn sort(&mut self) {
        self.entries
            .sort_by(|a, b| a.destination.cmp(&b.destination));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::constants::{PLAN_ACTION_OVERWRITE, PLAN_ACTION_RESTORE, PLAN_REASON_EXISTS};

    fn plan() -> Plan {
        let mut plan = Plan::new();
        plan.push(Entry::new(
            PLAN_ACTION_RESTORE,
            "vault:b.txt",
            "/out/b.txt",
            10,
        ));
        plan.push(
            Entry::new(PLAN_ACTION_OVERWRITE, "vault:a.txt", "/out/a.txt", 5)
                .because(PLAN_REASON_EXISTS),
        );
        plan
    }

    #[test]
    fn a_new_plan_is_empty() {
        let plan = Plan::new();
        assert!(plan.is_empty());
        assert_eq!(plan.len(), 0);
        assert_eq!(plan.total_bytes(), 0);
    }

    #[test]
    fn entries_are_counted_by_action() {
        let plan = plan();
        assert_eq!(plan.len(), 2);
        assert_eq!(plan.count(PLAN_ACTION_RESTORE), 1);
        assert_eq!(plan.count(PLAN_ACTION_OVERWRITE), 1);
        assert_eq!(plan.total_bytes(), 15);
    }

    #[test]
    fn sorting_makes_the_output_reproducible() {
        let mut plan = plan();
        plan.sort();
        let order: Vec<&str> = plan
            .entries()
            .iter()
            .map(|e| e.destination.as_str())
            .collect();
        assert_eq!(order, ["/out/a.txt", "/out/b.txt"]);
    }

    #[test]
    fn a_reason_is_omitted_from_the_json_when_there_is_none() {
        // A consumer should not have to distinguish null from absent.
        let plain = Entry::new(PLAN_ACTION_RESTORE, "a", "b", 1);
        let json = serde_json::to_string(&plain).unwrap();
        assert!(!json.contains("reason"), "{json}");

        let explained = plain.because(PLAN_REASON_EXISTS);
        let json = serde_json::to_string(&explained).unwrap();
        assert!(json.contains(PLAN_REASON_EXISTS), "{json}");
    }

    #[test]
    fn an_absurd_total_saturates_rather_than_wrapping() {
        // A wrapped total would print a small, believable number for a plan
        // that is anything but.
        let mut plan = Plan::new();
        plan.push(Entry::new(PLAN_ACTION_RESTORE, "a", "b", u64::MAX));
        plan.push(Entry::new(PLAN_ACTION_RESTORE, "c", "d", 1));
        assert_eq!(plan.total_bytes(), u64::MAX);
    }
}
