//! Vocabulary shared by the integrity family — `verify`, `check`, `scrub` and
//! `hashsum`.
//!
//! These four commands are the reason DCTL exists rather than a shell script
//! around a provider SDK (`PLAN.md` §6, §13.4), and they overlap in three
//! places. Each of the three lives here rather than being written four times:
//!
//! * [`target`] — turning a `REMOTE:PATH` argument into a remote name plus a
//!   canonical logical path, with the drive-letter and `..` rules applied once.
//! * [`failure`] — the verdict for a single object, and the single error
//!   constructor that guarantees a corrupt object always exits 21 with a message
//!   saying the data was **not** served.
//! * [`mode`] — how the global `--verify` strength is reported and what it costs.
//! * [`assurance`] — the claim a run must be able to make before it starts, and
//!   the refusal when it cannot.
//!
//! It is deliberately not a `util` module. Everything here is integrity domain
//! vocabulary; a helper that has nothing to do with proving data intact does not
//! belong in it.

pub mod assurance;
pub mod failure;
pub mod mode;
pub mod target;

pub use target::Target;

/// The fully-qualified name of a command, e.g. `dctl verify`.
///
/// Built from [`dctl_meta::BINARY_NAME`] rather than typed out, so the messages
/// that name a command — most importantly the `unimplemented` error, which tells
/// the user exactly what to run once the engine supports it — follow a rebrand
/// automatically instead of quietly naming a binary that no longer exists.
#[must_use]
pub fn command_name(verb: &str) -> String {
    format!("{} {verb}", dctl_meta::BINARY_NAME)
}

#[cfg(test)]
mod tests {
    use super::command_name;

    #[test]
    fn command_names_carry_the_binary_name() {
        let name = command_name("verify");
        assert!(name.starts_with(dctl_meta::BINARY_NAME));
        assert!(name.ends_with(" verify"));
    }
}
