//! What a real `mkdir` or `touch` actually did.
//!
//! A dry run reports a *plan* and the plan's status is always `planned`. A real
//! run has to say something else, and the interesting property of this family is
//! that "it worked" has five different meanings — four of which involve writing
//! nothing at all:
//!
//! * [`Outcome::Created`] — a directory or an empty object now exists that did
//!   not before. The only outcome that wrote anything.
//! * [`Outcome::AlreadyPresent`] — it was there, and nothing was touched.
//! * [`Outcome::NotRequired`] — this backend has no directories to create. Not a
//!   failure and not a no-op that hides one: the postcondition a user wants from
//!   `mkdir` (an object may now be stored under this path) already holds.
//! * [`Outcome::Skipped`] — `touch --no-create` against an object that is not
//!   there, which is exactly what `touch -c` promises to do.
//! * [`Outcome::Stamped`] — an existing object's modification time was rewritten.
//!
//! Collapsing those into one word would be the misreport `PLAN.md` §6 forbids in
//! its quietest form: a script that checks `status == "created"` must not be told
//! a directory was created when the command decided there was nothing to create.
//! So the distinction is carried in a stable slug, in every format, and the
//! human sentence is derived from the same value rather than written beside it.
//!
//! Every variant is a **success**. A failure leaves through the error channel
//! with an exit code; there is no outcome word for one, and adding one would
//! give a `--json` consumer two places to look for the same fact.

use crate::constants::{
    DIRECTORY_OUTCOME_CREATED, DIRECTORY_OUTCOME_NOT_REQUIRED, DIRECTORY_OUTCOME_PRESENT,
    DIRECTORY_OUTCOME_SKIPPED, DIRECTORY_OUTCOME_STAMPED, DIRECTORY_SAID_CREATED_DIRECTORY,
    DIRECTORY_SAID_CREATED_OBJECT, DIRECTORY_SAID_PRESENT_DIRECTORY, DIRECTORY_SAID_SKIPPED_OBJECT,
    DIRECTORY_SAID_STAMPED_OBJECT,
};

/// The result of one directory-family operation that really ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Something was written: a directory, or an empty object.
    Created,
    /// It was already there. Nothing was written.
    AlreadyPresent,
    /// This backend has no directories, so there was nothing to create.
    NotRequired,
    /// `--no-create`, and the object is not there.
    Skipped,
    /// An existing object's modification time was rewritten.
    Stamped,
}

impl Outcome {
    /// The stable slug: the JSON `status` value and the `Outcome` row.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Created => DIRECTORY_OUTCOME_CREATED,
            Self::AlreadyPresent => DIRECTORY_OUTCOME_PRESENT,
            Self::NotRequired => DIRECTORY_OUTCOME_NOT_REQUIRED,
            Self::Skipped => DIRECTORY_OUTCOME_SKIPPED,
            Self::Stamped => DIRECTORY_OUTCOME_STAMPED,
        }
    }

    /// The phrase printed before the target on stderr, e.g.
    /// `created directory: archive:photos/2024`.
    ///
    /// `noun` distinguishes the two verbs' vocabularies where they differ:
    /// `mkdir` creates a *directory*, `touch` creates an *object*, and the same
    /// slug therefore reads correctly in both reports without either command
    /// spelling its own sentences.
    #[must_use]
    pub const fn phrase(self, creating_a_directory: bool) -> &'static str {
        match self {
            Self::Created if creating_a_directory => DIRECTORY_SAID_CREATED_DIRECTORY,
            Self::Created => DIRECTORY_SAID_CREATED_OBJECT,
            Self::AlreadyPresent => DIRECTORY_SAID_PRESENT_DIRECTORY,
            Self::NotRequired => DIRECTORY_SAID_CREATED_DIRECTORY,
            Self::Skipped => DIRECTORY_SAID_SKIPPED_OBJECT,
            Self::Stamped => DIRECTORY_SAID_STAMPED_OBJECT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Outcome; 5] = [
        Outcome::Created,
        Outcome::AlreadyPresent,
        Outcome::NotRequired,
        Outcome::Skipped,
        Outcome::Stamped,
    ];

    #[test]
    fn every_outcome_has_a_distinct_slug() {
        // A collision would make two different results indistinguishable to the
        // script that branches on them.
        for (index, outcome) in ALL.iter().enumerate() {
            assert!(!outcome.slug().is_empty());
            for other in &ALL[index + 1..] {
                assert_ne!(outcome.slug(), other.slug(), "{outcome:?} collides");
            }
        }
    }

    #[test]
    fn creating_is_the_only_outcome_that_reads_as_creation() {
        // The distinction the whole module exists for: "there was nothing to
        // create" must never be reported with the word that means "I made one".
        assert_eq!(Outcome::Created.slug(), DIRECTORY_OUTCOME_CREATED);
        assert_ne!(Outcome::NotRequired.slug(), DIRECTORY_OUTCOME_CREATED);
        assert_ne!(Outcome::AlreadyPresent.slug(), DIRECTORY_OUTCOME_CREATED);
    }

    #[test]
    fn the_outcomes_that_wrote_nothing_never_borrow_a_creating_word() {
        // Three of the five results wrote nothing at all, and none of them may
        // be reported with the vocabulary of one that did — a script grepping
        // `created` or a person reading a line must not have to know which.
        for outcome in [
            Outcome::AlreadyPresent,
            Outcome::NotRequired,
            Outcome::Skipped,
        ] {
            assert_ne!(outcome.slug(), Outcome::Created.slug());
            assert_ne!(outcome.slug(), Outcome::Stamped.slug());
        }
    }

    #[test]
    fn the_two_verbs_name_what_they_created() {
        // `mkdir` made a directory and `touch` made an object; one sentence for
        // both would be wrong for one of them.
        assert_eq!(
            Outcome::Created.phrase(true),
            DIRECTORY_SAID_CREATED_DIRECTORY
        );
        assert_eq!(
            Outcome::Created.phrase(false),
            DIRECTORY_SAID_CREATED_OBJECT
        );
    }

    #[test]
    fn every_phrase_is_a_sentence_fragment_a_target_can_follow() {
        // Rendered as "<phrase>: <target>", so a trailing colon or period would
        // read as a typo in every line of output the family produces.
        for outcome in ALL {
            for directory in [true, false] {
                let phrase = outcome.phrase(directory);
                assert!(!phrase.is_empty());
                assert!(!phrase.ends_with(':'), "'{phrase}' punctuates itself");
                assert!(!phrase.ends_with('.'), "'{phrase}' punctuates itself");
            }
        }
    }
}
