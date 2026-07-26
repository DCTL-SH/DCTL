//! Vocabulary shared by the byte-stream family — `cat` and `rcat`.
//!
//! These two commands are different from every other verb in the tool: their
//! **stdout and stdin are the payload**, not a report about it. `dctl cat
//! vault:film.mkv | ffplay -` and `pg_dump | dctl rcat vault:db.sql` only work
//! if the data stream stays absolutely clean, so both commands obey one rule
//! without exception — object bytes on stdout, everything a human might want to
//! read (progress, warnings, the discard report) on stderr.
//!
//! Three things are shared rather than written twice:
//!
//! * [`spec`] — turning a `REMOTE:PATH` argument into a destination, including
//!   the local-path case that `cat` and `rcat` accept and the removal family
//!   refuses.
//! * [`failure`] — attaching the offending path to an I/O error without
//!   re-deriving its exit-code classification.
//! * [`command_name`] — the fully-qualified verb used in the `unimplemented`
//!   error, so the message names the binary the user actually invoked.
//!
//! It is deliberately not a `util` module: everything here is byte-stream domain
//! vocabulary, and a helper unrelated to moving bytes does not belong in it.

pub mod failure;
pub mod spec;

pub use failure::at_path;
pub use spec::ObjectSpec;

/// The fully-qualified name of a command, e.g. `dctl cat`.
///
/// Built from [`dctl_meta::BINARY_NAME`] rather than typed out, so an error that
/// names a command — above all [`crate::error::CliError::unimplemented`], whose
/// whole job is to tell the user what to run once the engine supports it —
/// follows a rebrand automatically instead of quoting a binary that no longer
/// exists.
#[must_use]
pub fn command_name(verb: &str) -> String {
    format!("{} {verb}", dctl_meta::BINARY_NAME)
}

#[cfg(test)]
mod tests {
    use super::command_name;

    #[test]
    fn command_names_carry_the_binary_name() {
        let name = command_name("cat");
        assert!(name.starts_with(dctl_meta::BINARY_NAME));
        assert!(name.ends_with(" cat"));
    }
}
