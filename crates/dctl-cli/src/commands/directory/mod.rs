//! Vocabulary shared by the directory family — `mkdir` and `touch`.
//!
//! Both verbs exist because an object store has neither of the two things a
//! shell script assumes: a directory, and a modification time you can set. DCTL
//! supplies both — a directory is a zero-byte marker object
//! ([`crate::constants::DIRECTORY_MARKER_NAME`]), and a modification time is a
//! field in the index — and the two commands then overlap in exactly three
//! places, each of which lives here rather than being written twice:
//!
//! * [`target`] — turning a `REMOTE:PATH` argument into a remote name plus a
//!   canonical logical path, with the drive-letter, `..` and empty-path rules
//!   applied once.
//! * [`plan`] — the request document: what would be written, where, and under
//!   which options, rendered in every `--format`.
//! * [`command_name`] — how a command names itself in an error message.
//!
//! It is deliberately not a `util` module. Everything here is directory-family
//! domain vocabulary; a helper with nothing to do with naming or creating an
//! object does not belong in it.

pub mod plan;
pub mod target;

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
