//! The ordered list of directories one `mkdir` would create.
//!
//! Without `--parents` that list has exactly one entry. With it, the list is the
//! whole ancestor chain, **outermost first** — `a`, then `a/b`, then `a/b/c`.
//! The order is not cosmetic: a parent has to exist before its child can be
//! created on a filesystem, and a plan printed in creation order is one a reader
//! can check against what actually happened.
//!
//! Nothing here touches a backend. The chain is computed from the path alone, so
//! `--dry-run` prints it without a vault, a network or a password — and so a
//! `mkdir` on a backend that has no directories can report the chain it would
//! have needed while creating none of it.

use serde::Serialize;

use crate::commands::directory::Target;

/// One directory in a `mkdir` plan.
///
/// A newtype over the path rather than a bare `String`, because the plan is a
/// JSON document users script against: `"directories": [{"path": "a"}]` has room
/// for a per-directory outcome the day the engine reports one, where an array of
/// strings would have to change shape to gain it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlannedDirectory {
    /// Canonical logical path of the directory itself.
    pub path: String,
}

impl PlannedDirectory {
    /// Describe one already-parsed target.
    #[must_use]
    fn of(target: &Target) -> Self {
        Self {
            path: target.path.clone(),
        }
    }
}

/// Build the creation chain for `target`.
///
/// With `parents`, every ancestor is included, outermost first. Without it, only
/// the target — and whether its parent exists is then the backend's problem to
/// report, exactly as `mkdir(1)` reports `No such file or directory`.
#[must_use]
pub fn build(target: &Target, parents: bool) -> Vec<PlannedDirectory> {
    if !parents {
        return vec![PlannedDirectory::of(target)];
    }

    let mut chain = Vec::new();
    let mut current = Some(target.clone());
    while let Some(directory) = current {
        current = directory.parent();
        chain.push(PlannedDirectory::of(&directory));
    }
    // Built leaf-first by walking upwards; creation order is the reverse.
    chain.reverse();
    chain
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(spec: &str) -> Target {
        Target::parse(spec, "directory").unwrap()
    }

    #[test]
    fn without_parents_only_the_named_directory_is_planned() {
        let chain = build(&target("vault:a/b/c"), false);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].path, "a/b/c");
    }

    #[test]
    fn with_parents_the_whole_chain_is_planned_outermost_first() {
        // Creation order, so a reader can check the plan against what happened —
        // and so a filesystem run creates each parent before its child.
        let chain = build(&target("vault:a/b/c"), true);
        let paths: Vec<&str> = chain.iter().map(|d| d.path.as_str()).collect();
        assert_eq!(paths, ["a", "a/b", "a/b/c"]);
    }

    #[test]
    fn a_top_level_directory_has_no_parents_to_add() {
        for parents in [true, false] {
            let chain = build(&target("vault:photos"), parents);
            assert_eq!(chain.len(), 1, "parents={parents}");
            assert_eq!(chain[0].path, "photos");
        }
    }

    #[test]
    fn the_json_shape_is_one_object_per_directory() {
        let chain = build(&target("vault:a/b"), true);
        let value = serde_json::to_value(&chain).unwrap();
        assert_eq!(value[0]["path"], "a");
        assert_eq!(value[1]["path"], "a/b");
        // No marker field: DCTL writes no marker object, so a document naming one
        // would describe a write that never happens.
        assert!(value[1].get("marker").is_none());
    }

    #[test]
    fn a_deep_chain_stays_in_order() {
        let chain = build(&target("vault:a/b/c/d/e"), true);
        assert_eq!(chain.len(), 5);
        for pair in chain.windows(2) {
            assert!(
                pair[1].path.starts_with(&pair[0].path),
                "{} does not follow {}",
                pair[1].path,
                pair[0].path
            );
        }
    }
}
