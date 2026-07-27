//! Vocabulary shared by the directory family — `mkdir` and `touch`.
//!
//! Both verbs exist because a shell script assumes two things that only a
//! filesystem provides: a directory, and a modification time you can set. What
//! DCTL does about that depends entirely on where the target is, and the family
//! is honest about the three answers rather than smoothing them into one:
//!
//! | | filesystem remote | sealed vault | object store |
//! |---|---|---|---|
//! | `mkdir` | creates a real directory | nothing to create ([`Outcome::NotRequired`]) | nothing to create |
//! | `touch` (missing) | creates an empty file | creates an empty object | refused: no plain write path |
//! | `touch` (existing) | sets the time | refused: no such call in `dctl-core` | refused |
//! | `--timestamp` | honoured | refused before anything is written | refused |
//!
//! The middle column is the one worth reading twice. A vault maps logical paths
//! to sealed objects; `photos/2024` exists exactly while something is stored
//! under it. There is no state for `mkdir` to establish, so it establishes none
//! and says so — see [`crate::constants::DIRECTORY_NOTHING_TO_CREATE`] for why
//! that is a success rather than a refusal, and
//! [`crate::constants::DIRECTORY_MARKER_NAME`] for why it is not a marker object.
//!
//! Four things are shared rather than written twice:
//!
//! * [`target`] — turning a `REMOTE:PATH` argument into a remote name plus a
//!   canonical logical path, with the drive-letter, `..` and empty-path rules
//!   applied once.
//! * [`plan`] — the one document both verbs emit, describing a rehearsal or
//!   reporting a completed run, in every `--format`.
//! * [`outcome`] — the five things "it worked" can mean, as stable slugs.
//! * [`command_name`] — how a command names itself in an error message.
//!
//! Which *kind* of place a target names is not here: that is
//! [`crate::remote::Place`], because `rcat` needs the same answer and a second
//! copy of the question is a second answer that can disagree with the first.
//!
//! It is deliberately not a `util` module. Everything here is directory-family
//! domain vocabulary; a helper with nothing to do with naming or creating an
//! object does not belong in it.

pub mod outcome;
pub mod plan;
pub mod target;

pub use outcome::Outcome;
pub use plan::{Plan, PlanOptions, Row, emit, yes_no};
pub use target::Target;

/// The fully-qualified name of a command, e.g. `dctl mkdir`.
///
/// Built from [`dctl_meta::BINARY_NAME`] rather than typed out, so the messages
/// that name a command — most importantly the `unimplemented` error, which tells
/// the user exactly what to run once the engine supports it — follow a rebrand
/// automatically instead of quietly naming a binary that no longer exists.
#[must_use]
pub fn command_name(verb: &str) -> String {
    format!("{} {verb}", dctl_meta::BINARY_NAME)
}

/// Test-only helpers shared by the family's unit tests.
///
/// Building a [`crate::ctx::Ctx`] by hand means re-deriving the whole global
/// flag block, so it is done once here. Every command's tests then drive a real
/// context — the same one `main` builds — rather than a mock that could diverge
/// from it.
#[cfg(test)]
pub(crate) mod testing {
    use clap::Parser;

    use crate::cli::GlobalArgs;
    use crate::ctx::Ctx;

    /// Minimal parser that exposes the global block on its own.
    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    /// A context built from global flags, with the progress display silenced.
    ///
    /// `--quiet` is forced on because a unit test run from a terminal would
    /// otherwise paint real progress bars over the test harness's output.
    pub fn ctx(args: &[&str]) -> Ctx {
        let argv = std::iter::once("dctl")
            .chain(args.iter().copied())
            .chain(std::iter::once("--quiet"));
        Ctx::new(Harness::parse_from(argv).globals)
    }
}

#[cfg(test)]
mod tests {
    use super::command_name;

    #[test]
    fn command_names_carry_the_binary_name() {
        // The string lands in an error a user is expected to act on, so it has
        // to name the binary they actually typed.
        let name = command_name("mkdir");
        assert!(name.starts_with(dctl_meta::BINARY_NAME));
        assert!(name.ends_with(" mkdir"));
    }
}
