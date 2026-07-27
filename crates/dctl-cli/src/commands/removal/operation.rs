//! What each of the six commands actually asks the engine to remove.
//!
//! The commands differ in exactly one dimension — *which objects* — and every
//! other part of a removal (the gate, the plan, the report, the ordering, the
//! partial-failure accounting) is shared. Naming that one dimension as a value
//! is what keeps it that way: [`super::selection`] matches on this enum once,
//! and no command contains a second opinion about what its own verb means.
//!
//! It is an enum rather than a trait for the same reason
//! [`crate::remote::registry::Target`] is: the arms are a closed set fixed by
//! the command line, and an exhaustive `match` makes a seventh verb a compile
//! error in the one place that would have to handle it, rather than a runtime
//! surprise months later.
//!
//! ## The distinctions the arms encode
//!
//! | arm | selects | filters | directory markers |
//! |-----|---------|---------|-------------------|
//! | [`Operation::Delete`] | objects under the target | honoured | left standing unless `--rmdirs` |
//! | [`Operation::DeleteFile`] | one named object | ignored | refuses a directory outright |
//! | [`Operation::Purge`] | everything under the target | ignored | removed with the tree |
//! | [`Operation::Rmdir`] | one directory, if empty | ignored | the only thing removed |
//! | [`Operation::Rmdirs`] | every empty directory below | ignored | the only thing removed |
//! | [`Operation::Cleanup`] | backend debris | ignored | never touched |

use std::time::Duration;

use super::reclaim::Class;

/// The removal one command invocation is asking for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    /// `delete`: every object under the target that the filters select.
    ///
    /// Directory markers are excluded from the selection unless `rmdirs` is set,
    /// which is the mechanical form of "delete leaves the directory structure
    /// standing": a marker is what declares a directory, so removing one while
    /// claiming to preserve structure would be a contradiction.
    Delete {
        /// Sweep the directories the deletion emptied.
        rmdirs: bool,
    },

    /// `deletefile`: exactly one named object, whatever the filters say.
    DeleteFile,

    /// `purge`: the target and everything beneath it, markers included.
    Purge,

    /// `rmdir`: one directory, and only if it is already empty.
    Rmdir,

    /// `rmdirs`: every empty directory under the target, deepest first.
    Rmdirs {
        /// Keep the target directory itself even when the sweep empties it.
        leave_root: bool,
    },

    /// `cleanup`: debris on the backend that no logical path addresses.
    Cleanup {
        /// Which classes this run will sweep, in the order they were requested.
        classes: Vec<Class>,
        /// How old debris must be before it is considered abandoned.
        min_age: Duration,
        /// Whether the user named these classes with `--class`.
        ///
        /// The difference decides one thing only, and it is the exit code: a
        /// class this backend cannot enumerate is a *failure to do what was
        /// asked* when it was asked for by name, and merely "nothing to do
        /// there" when the run took the default selection. Without the
        /// distinction, every default `cleanup` on a provider with no multipart
        /// API would exit 6 for ever, and operators would learn to ignore it.
        named: bool,
    },
}

impl Operation {
    /// Whether this operation acts on the objects a user stored, rather than on
    /// containers or on backend debris.
    ///
    /// Read by [`super::report`] to decide whether an empty result deserves a
    /// note. "No objects matched" is worth saying after a `delete`; after a
    /// `rmdirs` that found no empty directories it is the ordinary outcome.
    #[must_use]
    pub const fn removes_user_data(&self) -> bool {
        matches!(self, Self::Delete { .. } | Self::DeleteFile | Self::Purge)
    }

    /// Whether this operation reads the vault's logical path set at all.
    ///
    /// `cleanup` does not: it works from provider keys, which is why it is the
    /// one arm that needs a backend handle rather than an unlocked listing.
    #[must_use]
    pub const fn is_cleanup(&self) -> bool {
        matches!(self, Self::Cleanup { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_verbs_that_destroy_user_data_are_the_three_that_say_so() {
        // The predicate exists to word an empty report, and wording a `purge`
        // that found nothing as though it were a routine sweep would hide the
        // fact that the user aimed at a tree and hit air.
        assert!(Operation::Delete { rmdirs: false }.removes_user_data());
        assert!(Operation::DeleteFile.removes_user_data());
        assert!(Operation::Purge.removes_user_data());

        assert!(!Operation::Rmdir.removes_user_data());
        assert!(!Operation::Rmdirs { leave_root: false }.removes_user_data());
        assert!(
            !Operation::Cleanup {
                classes: Vec::new(),
                min_age: Duration::ZERO,
                named: false,
            }
            .removes_user_data()
        );
    }

    #[test]
    fn only_cleanup_works_outside_the_logical_path_set() {
        assert!(
            Operation::Cleanup {
                classes: vec![Class::Staging],
                min_age: Duration::from_secs(1),
                named: true,
            }
            .is_cleanup()
        );
        assert!(!Operation::Purge.is_cleanup());
    }

    #[test]
    fn the_option_carrying_arms_keep_their_options_apart() {
        // `--rmdirs` and `--leave-root` are opposite intentions that both live
        // in this enum; a copy-paste that swapped them would be silent.
        assert_ne!(
            Operation::Delete { rmdirs: true },
            Operation::Delete { rmdirs: false }
        );
        assert_ne!(
            Operation::Rmdirs { leave_root: true },
            Operation::Rmdirs { leave_root: false }
        );
    }
}
