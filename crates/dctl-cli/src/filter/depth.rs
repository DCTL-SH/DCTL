//! `--max-depth` against a logical path.
//!
//! Depth is counted in **path components below the transfer root**, so the root
//! itself is 0, a file sitting directly in it is 1, and `a/b.txt` is 2. That is
//! rclone's reading, in which `--max-depth 1` means "the top level only" — and
//! it is the reading a person checks against their own shell, where
//! `ls` shows exactly the entries at depth 1.
//!
//! Counting from the *logical* path rather than from a walk's own recursion
//! counter is what keeps a local walk and a remote listing in step. A remote
//! never recurses at all: it returns a flat set of keys, and the only depth it
//! has is the one written in the key. If the two derived depth separately,
//! `dctl copy` and `dctl ls` would disagree about which files `--max-depth 2`
//! covers, and the listing an operator read before deleting would not describe
//! the transfer that followed.
//!
//! ## Why a negative depth is a usage error, not a clamp
//!
//! `-1` is the documented "no limit" sentinel ([`MAX_DEPTH_UNLIMITED`]). Any
//! *other* negative number is a mistake — most often an arithmetic slip in a
//! wrapper script — and it has no defensible reading. Clamping it to zero would
//! silently transfer nothing; clamping it to unlimited would silently transfer
//! everything. Both are answers the operator never asked for, so DCTL refuses.

use std::fmt;

use crate::constants::{FILTER_FLAG_MAX_DEPTH, MAX_DEPTH_UNLIMITED, PATH_SEPARATOR};

/// Why a depth flag was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepthProblem {
    given: i32,
}

impl DepthProblem {
    /// Advice for the reader.
    pub fn hint(&self) -> String {
        format!(
            "Use a depth of 0 or more, or {MAX_DEPTH_UNLIMITED} for no limit. \
             Depth 1 is a file sitting directly in the transfer root."
        )
    }
}

impl fmt::Display for DepthProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{FILTER_FLAG_MAX_DEPTH} {} is not a depth", self.given)
    }
}

impl std::error::Error for DepthProblem {}

/// How deep below the transfer root a logical path sits.
///
/// The root is `""` and has depth 0. Empty components — which a well-formed
/// logical path never has, but a hand-written `--files-from` line might before
/// cleaning — are not counted, so `a//b` is depth 2 rather than 3.
pub fn depth_of(path: &str) -> usize {
    path.split(PATH_SEPARATOR)
        .filter(|part| !part.is_empty())
        .count()
}

/// The recursion limit in force, if any.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DepthLimit {
    limit: Option<usize>,
}

impl DepthLimit {
    /// No limit at all.
    pub const fn unlimited() -> Self {
        Self { limit: None }
    }

    /// Read the flag, turning the `-1` sentinel into the absence of a limit.
    ///
    /// # Errors
    /// [`DepthProblem`] for a negative depth that is not the sentinel; see the
    /// module documentation for why that is refused rather than clamped.
    pub fn from_flag(value: i32) -> Result<Self, DepthProblem> {
        if value == MAX_DEPTH_UNLIMITED {
            return Ok(Self::unlimited());
        }
        match usize::try_from(value) {
            Ok(limit) => Ok(Self { limit: Some(limit) }),
            Err(_) => Err(DepthProblem { given: value }),
        }
    }

    /// Replace the limit outright.
    ///
    /// `lsd` and `tree` synthesise directories from the objects beneath them, so
    /// they have to see objects the operator's `--max-depth` would have hidden
    /// and apply the limit to the *directories* they derive instead. Without
    /// this, `--max-depth 1` would report a top-level directory as empty because
    /// every object in it sits at depth 2 or deeper.
    pub const fn replaced_with(self, limit: Option<usize>) -> Self {
        Self { limit }
    }

    /// Whether something at this depth is in scope.
    pub fn admits(&self, depth: usize) -> bool {
        self.limit.is_none_or(|limit| depth <= limit)
    }

    /// Whether this logical path is in scope.
    pub fn admits_path(&self, path: &str) -> bool {
        self.admits(depth_of(path))
    }

    /// Whether a walk may still descend into a directory at this depth.
    ///
    /// A directory *at* the limit still has to be entered — the limit applies to
    /// what is inside it, not to the act of opening it — so this is deliberately
    /// one deeper than [`DepthLimit::admits`]. Conflating the two is how a walk
    /// ends up reporting the deepest permitted level as empty.
    pub fn may_descend(&self, depth: usize) -> bool {
        self.limit.is_none_or(|limit| depth < limit)
    }

    /// Whether a limit is in force.
    pub const fn is_limited(&self) -> bool {
        self.limit.is_some()
    }

    /// The limit, if any.
    pub const fn limit(&self) -> Option<usize> {
        self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_root_is_depth_zero_and_a_top_level_file_is_one() {
        assert_eq!(depth_of(""), 0);
        assert_eq!(depth_of("a.txt"), 1);
        assert_eq!(depth_of("a/b.txt"), 2);
        assert_eq!(depth_of("a/b/c/d.txt"), 4);
    }

    #[test]
    fn empty_components_are_not_levels() {
        // A hand-written list may carry `a//b` or a trailing slash. Counting the
        // gap as a level would make the same directory answer to two depths.
        assert_eq!(depth_of("a//b"), 2);
        assert_eq!(depth_of("a/"), 1);
        assert_eq!(depth_of("/a"), 1);
    }

    #[test]
    fn max_depth_one_is_the_top_level_only() {
        let limit = DepthLimit::from_flag(1).expect("a depth of 1 is legal");
        assert!(limit.admits_path("a.txt"));
        assert!(!limit.admits_path("a/b.txt"));
        assert!(limit.is_limited());
        assert_eq!(limit.limit(), Some(1));
    }

    #[test]
    fn max_depth_zero_admits_the_root_and_nothing_in_it() {
        let limit = DepthLimit::from_flag(0).expect("a depth of 0 is legal");
        assert!(limit.admits_path(""));
        assert!(!limit.admits_path("a.txt"));
    }

    #[test]
    fn the_unlimited_sentinel_means_no_limit() {
        let limit = DepthLimit::from_flag(MAX_DEPTH_UNLIMITED).expect("the sentinel is legal");
        assert!(!limit.is_limited());
        assert!(limit.admits_path("a/b/c/d/e/f/g.txt"));
        assert_eq!(limit, DepthLimit::unlimited());
        assert_eq!(DepthLimit::default(), DepthLimit::unlimited());
    }

    #[test]
    fn any_other_negative_depth_is_refused_rather_than_clamped() {
        // Clamping to zero would silently transfer nothing and clamping to
        // unlimited would silently transfer everything; neither was asked for.
        let error = DepthLimit::from_flag(-7).expect_err("-7 is not a depth");
        assert!(error.to_string().contains("-7"));
        assert!(error.to_string().contains(FILTER_FLAG_MAX_DEPTH));
        assert!(error.hint().contains(&MAX_DEPTH_UNLIMITED.to_string()));
        assert!(DepthLimit::from_flag(i32::MIN).is_err());
    }

    #[test]
    fn descending_is_permitted_one_level_shallower_than_listing() {
        // A directory *at* the limit still has to be opened, or the deepest
        // permitted level reports itself as empty.
        let limit = DepthLimit::from_flag(2).expect("a depth of 2 is legal");
        assert!(limit.may_descend(0), "the root");
        assert!(limit.may_descend(1), "a directory holding depth-2 files");
        assert!(!limit.may_descend(2), "its children would be depth 3");
        assert!(limit.admits(2));
        assert!(!limit.admits(3));
    }

    #[test]
    fn an_unlimited_walk_always_descends() {
        let limit = DepthLimit::unlimited();
        assert!(limit.may_descend(0));
        assert!(limit.may_descend(1_000));
    }

    #[test]
    fn the_limit_can_be_moved_to_the_directory_layer_and_back() {
        let limit = DepthLimit::from_flag(1).expect("a depth of 1 is legal");
        assert!(!limit.replaced_with(None).is_limited());
        assert!(limit.replaced_with(None).admits_path("a/b/c.txt"));
        assert!(!limit.replaced_with(Some(1)).admits_path("a/b/c.txt"));
    }
}
