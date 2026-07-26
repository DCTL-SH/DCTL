//! Vocabulary shared by the audit & recovery family — `audit`, `backup` and
//! `restore`.
//!
//! These three commands exist because of the two promises a plain copier does
//! not make. `audit` backs the tamper-evident log (`PLAN.md` §7): you can *prove*
//! what happened, and a deletion from the record is detectable. `backup` and
//! `restore` back the tested-restore principle (`PLAN.md` §13.6): a backup you
//! never restored is not a backup, so the things that make a restore fail —
//! illegal filenames, case collisions, paths too long for the destination — are
//! found before the first byte moves rather than 3.9 TB into a 4 TB run.
//!
//! Six concerns are shared, and each lives in its own file rather than being
//! written twice:
//!
//! * [`target`] — turning a `REMOTE:PATH` argument into a remote name plus a
//!   canonical logical path, with the drive-letter and `..` rules applied once.
//! * [`timespec`] — the point-in-time arguments (`--at`, `--since`, `--until`).
//! * [`snapshot`] — what a snapshot may be called, and what it is called when
//!   the user does not say.
//! * [`selection`] — which files a run considers, and the loud refusal of the
//!   filters that cannot yet be honoured.
//! * [`preflight`] — every reason a name could fail to be written, gathered
//!   before anything is.
//! * [`plan`] and [`report`] — what a run *would* do, and how that is rendered
//!   in each of the three output formats.
//!
//! It is deliberately not a `util` module: everything here is recovery domain
//! vocabulary, and a helper unrelated to proving a backup restorable does not
//! belong in it.

pub mod plan;
pub mod preflight;
pub mod report;
pub mod selection;
pub mod snapshot;
pub mod target;
pub mod timespec;

pub use plan::{Entry, Plan};
pub use preflight::Audience;
pub use selection::Selection;
pub use snapshot::SnapshotName;
pub use target::Target;

/// The fully-qualified name of a command, e.g. `dctl restore`.
///
/// Built from [`dctl_meta::BINARY_NAME`] rather than typed out, so the messages
/// that name a command — most importantly the `unimplemented` error, which tells
/// the user exactly what to run once the engine supports it — follow a rebrand
/// automatically instead of quietly naming a binary that no longer exists.
///
/// The integrity family carries its own copy of this for the same reason it
/// carries its own `target.rs`: the two families are independent, and neither
/// should break because the other was restructured.
#[must_use]
pub fn command_name(verb: &str) -> String {
    format!("{} {verb}", dctl_meta::BINARY_NAME)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::command_name;

    #[test]
    fn command_names_carry_the_binary_name() {
        let name = command_name("restore");
        assert!(name.starts_with(dctl_meta::BINARY_NAME));
        assert!(name.ends_with(" restore"));
    }
}
