//! The ordered list of directories one `mkdir` would create.
//!
//! Without `--parents` that list has exactly one entry. With it, the list is the
//! whole ancestor chain, **outermost first** — `a`, then `a/b`, then `a/b/c`.
//! The order is not cosmetic: a backend that later grows real directories, and
//! an index that records a parent link, both need the parent to exist before the
//! child does, and a plan printed in creation order is one a reader can check
//! against what actually happened.
//!
//! Each entry carries the marker object it resolves to, because that is the only
//! thing that ever gets written. Nothing here touches a backend: the chain is
//! computed from the path alone, so `--dry-run` prints it without a vault, a
//! network or a password.

use serde::Serialize;

use crate::commands::directory::Target;

/// One directory in a `mkdir` plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlannedDirectory {
    /// Canonical logical path of the directory itself.
    pub path: String,
    /// The zero-byte object that will represent it.
    pub marker: String,
}

impl PlannedDirectory {
    /// Describe one already-parsed target.
    #[must_use]
    fn of(target: &Target) -> Self {
        Self {
            path: target.path.clone(),
            marker: target.marker(),
        }
    }
}

/// Build the creation chain for `target`.
///
/// With `parents`, every ancestor is included, outermost first. Without it, only
/// the target — and whether its parent exists is then the engine's problem to
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
    use crate::constants::DIRECTORY_MARKER_NAME;

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
        // Creation order, so a reader can check the plan against what happened.
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
    fn every_entry_carries_the_marker_it_would_write() {
        // The marker is the only object that is ever created, so a plan that
        // omitted it would not describe the write it is planning.
        for directory in build(&target("vault:a/b"), true) {
            assert_eq!(
                directory.marker,
                format!("{}/{DIRECTORY_MARKER_NAME}", directory.path)
            );
        }
    }

    #[test]
    fn the_json_shape_is_path_plus_marker() {
        let chain = build(&target("vault:a/b"), true);
        let value = serde_json::to_value(&chain).unwrap();
        assert_eq!(value[0]["path"], "a");
        assert_eq!(value[1]["path"], "a/b");
        assert_eq!(value[1]["marker"], format!("a/b/{DIRECTORY_MARKER_NAME}"));
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
