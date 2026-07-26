//! The four characters a tree is drawn from.
//!
//! Two sets, both exactly four columns per slot so an indent is always a
//! multiple of four and the two are interchangeable mid-design without shifting
//! anything. Which set is used is decided once per run and then obeyed for every
//! line, because a tree that mixed them would look like a rendering fault.
//!
//! ## Why the choice is the flag alone, and not a terminal probe
//!
//! [`crate::output::progress`] sniffs the locale and the Windows console host to
//! decide whether its bars can use box-drawing characters. That is right for a
//! progress bar, which is *chrome*: it exists only for the human watching, is
//! redrawn constantly, and is thrown away.
//!
//! A tree is **data**. It goes to stdout, gets redirected into a file, piped
//! into `less`, and committed to a ticket. If the glyphs depended on whether
//! stdout happened to be a terminal, `dctl tree > out.txt` and
//! `dctl tree | tee out.txt` would produce different files from the same vault —
//! and a user comparing two runs would be reading a difference in their
//! plumbing, not in their data. So the only input is `--ascii`, which the user
//! chose deliberately and which produces the same bytes everywhere.

use crate::constants::{
    TREE_BRANCH_ASCII, TREE_BRANCH_UNICODE, TREE_INDENT, TREE_LAST_BRANCH_ASCII,
    TREE_LAST_BRANCH_UNICODE, TREE_VERTICAL_ASCII, TREE_VERTICAL_UNICODE,
};

/// The glyph set one run draws with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Glyphs {
    /// Connector to a node that has later siblings.
    pub branch: &'static str,
    /// Connector to the last node in a directory.
    pub last_branch: &'static str,
    /// Continuation drawn beneath a [`Glyphs::branch`].
    pub vertical: &'static str,
    /// Continuation drawn beneath a [`Glyphs::last_branch`].
    pub indent: &'static str,
}

impl Glyphs {
    /// Box-drawing characters, the default.
    pub const UNICODE: Self = Self {
        branch: TREE_BRANCH_UNICODE,
        last_branch: TREE_LAST_BRANCH_UNICODE,
        vertical: TREE_VERTICAL_UNICODE,
        indent: TREE_INDENT,
    };

    /// The `--ascii` set, which renders identically on every console ever
    /// shipped.
    pub const ASCII: Self = Self {
        branch: TREE_BRANCH_ASCII,
        last_branch: TREE_LAST_BRANCH_ASCII,
        vertical: TREE_VERTICAL_ASCII,
        indent: TREE_INDENT,
    };

    /// Pick a set. `--ascii` is the only input; see the module documentation.
    #[must_use]
    pub const fn resolve(force_ascii: bool) -> Self {
        if force_ascii {
            Self::ASCII
        } else {
            Self::UNICODE
        }
    }

    /// The connector for a node, given whether it is its parent's last child.
    #[must_use]
    pub const fn connector(&self, last: bool) -> &'static str {
        if last { self.last_branch } else { self.branch }
    }

    /// The continuation drawn beneath that connector.
    #[must_use]
    pub const fn continuation(&self, last: bool) -> &'static str {
        if last { self.indent } else { self.vertical }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flag_is_the_only_input() {
        assert_eq!(Glyphs::resolve(true), Glyphs::ASCII);
        assert_eq!(Glyphs::resolve(false), Glyphs::UNICODE);
    }

    #[test]
    fn every_slot_is_the_same_width_in_both_sets() {
        // An indent is a repeated slot, so unequal widths would make a deep tree
        // drift sideways one column per level.
        let widths: Vec<usize> = [Glyphs::UNICODE, Glyphs::ASCII]
            .iter()
            .flat_map(|set| {
                [set.branch, set.last_branch, set.vertical, set.indent]
                    .map(|slot| slot.chars().count())
            })
            .collect();
        assert!(
            widths.windows(2).all(|pair| pair[0] == pair[1]),
            "slot widths disagree: {widths:?}"
        );
    }

    #[test]
    fn the_fallback_set_is_pure_ascii() {
        // The whole reason it exists: nothing in it can become mojibake.
        for slot in [
            Glyphs::ASCII.branch,
            Glyphs::ASCII.last_branch,
            Glyphs::ASCII.vertical,
            Glyphs::ASCII.indent,
        ] {
            assert!(slot.is_ascii(), "{slot:?}");
        }
        assert!(!Glyphs::UNICODE.branch.is_ascii());
    }

    #[test]
    fn the_two_sets_really_are_different() {
        // A copy-paste slip that aliased them would silently disable --ascii.
        assert_ne!(Glyphs::ASCII, Glyphs::UNICODE);
    }

    #[test]
    fn the_last_child_gets_a_corner_and_a_blank_continuation() {
        for set in [Glyphs::UNICODE, Glyphs::ASCII] {
            assert_eq!(set.connector(true), set.last_branch);
            assert_eq!(set.connector(false), set.branch);
            // Nothing may be drawn below the last child, or the tree grows a
            // line that leads nowhere.
            assert_eq!(set.continuation(true), TREE_INDENT);
            assert!(set.continuation(true).trim().is_empty());
            assert!(!set.continuation(false).trim().is_empty());
        }
    }
}
