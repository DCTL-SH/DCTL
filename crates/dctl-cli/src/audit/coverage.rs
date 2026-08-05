//! Which commands append to the chain, which do not, and the reason for every
//! one — checked against the command tree rather than against memory.
//!
//! This module is a test and nothing else, and it exists because of the shape of
//! the defect it prevents. `dctl backup` moved 195 KiB into a vault and appended
//! nothing to the tamper-evident log. Nothing was broken: the command worked,
//! the files were stored, every test passed, and the only thing wrong was an
//! absence — a record that was never written, in a file nobody reads until the
//! day it matters. `restore` and `touch` had the same absence. Three commands,
//! and the way each of them got there was that somebody wrote a command and did
//! not think about the log.
//!
//! An absence cannot be caught by reading the code that is there. So the policy
//! is written down here as a table with one row per subcommand, and
//! [`tests::every_command_states_whether_it_appends_to_the_chain`] asks **clap**
//! for the list of subcommands and fails if any of them is missing a row. A new
//! verb therefore cannot be added without somebody deciding, in writing, whether
//! it belongs in the audit log — which is the decision that was skipped three
//! times.
//!
//! ## The rule the table encodes
//!
//! > **A record is appended for every operation that moves object content, in
//! > either direction, and for every operation that changes what is stored.
//! > Nothing else appends.**
//!
//! That is a *wider* rule than schema v1's ("every operation that changes stored
//! data"), and the widening is the point. Under the old rule a read was not an
//! event, so `dctl cat archive:q4.xlsx` — an object decrypted and put on a pipe
//! — was invisible. For a product sold on an audit story, "who took data out" is
//! the question the log exists to answer, and a log that records only writes
//! cannot answer it.
//!
//! Enumeration is deliberately *not* content. `ls`, `lsd`, `tree`, `size` and
//! `about` read names and lengths, never object bodies, and a log that recorded
//! every listing would bury the events that matter under the events that do not.
//! The file whose value is that somebody will read it end to end is the file that
//! has to stay short enough to read.
//!
//! ## Why an exemption carries a reason
//!
//! [`Recording::Exempt`] takes the reason as a string, and the test rejects an
//! empty one. Adding an exemption is meant to be a visible, reviewable decision
//! that a reader has to justify — the same discipline
//! [`crate::cli::mentions`]'s exemption list applies, and for the same reason:
//! the alternative is a list that rots into a blanket allow.
//!
//! ## What the table cannot prove, said plainly
//!
//! It proves that somebody decided, and — through
//! [`tests::every_recording_command_has_an_appender_that_still_appends`] — that
//! the module named as the appender still contains an append. It does not prove
//! that the append is reached on every path through that module. That is what
//! the per-command behavioural tests are for, and where they exist they are
//! named in the row's comment. A table is a floor, not a ceiling.

/// Whether a command appends to the audit chain, and where from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recording {
    /// Appends, through this module — a path under `crates/dctl-cli/src/`.
    ///
    /// The module is named rather than assumed, because the appending code is
    /// usually not in the command's own file: every transfer verb records
    /// through `commands/transfer/pipeline.rs`, which is the whole reason they
    /// all record consistently.
    Through(&'static str),

    /// Appends nothing, for this reason.
    Exempt(&'static str),
}

/// One row per subcommand `dctl` exposes, in `dctl --help` order.
///
/// The name is the one `clap` knows, which is also
/// [`crate::cli::Command::name`]'s and therefore the `op` field of the record.
pub const COVERAGE: &[(&str, Recording)] = &[
    // ── Setup ────────────────────────────────────────────────────────────
    (
        "config",
        Recording::Exempt(
            "Changes the configuration file, never stored data. A remote \
             definition is a local preference; the operations it enables are \
             each recorded where they happen.",
        ),
    ),
    ("init", Recording::Through("commands/init/mod.rs")),
    // ── Listing: names and lengths, never object bodies ──────────────────
    (
        "ls",
        Recording::Exempt("Enumerates names and sizes. No object body is read."),
    ),
    (
        "lsd",
        Recording::Exempt("Enumerates directory names. No object body is read."),
    ),
    (
        "lsl",
        Recording::Exempt("Enumerates names, sizes and times. No object body is read."),
    ),
    (
        "lsjson",
        Recording::Exempt("Enumerates metadata as JSON. No object body is read."),
    ),
    (
        "tree",
        Recording::Exempt("Enumerates names. No object body is read."),
    ),
    (
        "size",
        Recording::Exempt("Sums recorded lengths. No object body is read."),
    ),
    // ── Transfer: the pipeline records every one, per file ───────────────
    // Behavioural cover: `commands::transfer::pipeline::tests`, including
    // `a_read_out_of_a_remote_is_distinguishable_from_a_write_into_it`.
    ("copy", Recording::Through("commands/transfer/pipeline.rs")),
    ("move", Recording::Through("commands/transfer/pipeline.rs")),
    ("sync", Recording::Through("commands/transfer/pipeline.rs")),
    (
        "copyto",
        Recording::Through("commands/transfer/pipeline.rs"),
    ),
    (
        "moveto",
        Recording::Through("commands/transfer/pipeline.rs"),
    ),
    // ── Replication ──────────────────────────────────────────────────────
    (
        "replicate",
        Recording::Through("commands/replicate/execute.rs"),
    ),
    // ── Content ──────────────────────────────────────────────────────────
    // `cat` is the shortest route out of a vault, and under the v1 rule it was
    // not an event at all.
    ("cat", Recording::Through("commands/cat/mod.rs")),
    ("rcat", Recording::Through("commands/rcat/mod.rs")),
    // ── Removal: changes stored data, moves no bytes ─────────────────────
    ("delete", Recording::Through("commands/removal/remove.rs")),
    (
        "deletefile",
        Recording::Through("commands/removal/remove.rs"),
    ),
    ("purge", Recording::Through("commands/removal/remove.rs")),
    ("rmdir", Recording::Through("commands/removal/remove.rs")),
    ("rmdirs", Recording::Through("commands/removal/remove.rs")),
    ("cleanup", Recording::Through("commands/removal/reclaim.rs")),
    // ── Directories ──────────────────────────────────────────────────────
    (
        "mkdir",
        Recording::Exempt(
            "NOT DONE, and not a decision. `mkdir` changes stored data on the \
             one backend that has directories, so by the rule above it belongs \
             in the chain — see HANDOVER.md. It is exempt here rather than \
             silently absent so that the gap is visible in the table an auditor \
             is pointed at, instead of being an absence nobody can see.",
        ),
    ),
    // Behavioural cover: none yet beyond the unit tests in `touch::engine`.
    ("touch", Recording::Through("commands/touch/mod.rs")),
    // ── Integrity ────────────────────────────────────────────────────────
    (
        "verify",
        Recording::Exempt(
            "Reads object bodies back and emits a verdict, never their content. \
             The bytes reach this process and go no further, so nothing left the \
             remote in the sense the log records. Recording the *run* — 'the \
             vault was verified on the 3rd, 4.2 TB read, healthy' — is a real \
             improvement and is not done.",
        ),
    ),
    (
        "check",
        Recording::Exempt(
            "Compares two sides and emits a verdict. Under `--checksum` it reads \
             bodies to digest them, and the same reasoning as `verify` applies.",
        ),
    ),
    (
        "scrub",
        Recording::Exempt("Reads object bodies back and emits a verdict. See `verify`."),
    ),
    (
        "hashsum",
        Recording::Exempt(
            "Reads object bodies to digest them and emits digests, never \
             content. See `verify`.",
        ),
    ),
    ("index", Recording::Through("commands/index/rebuild.rs")),
    // ── Audit & recovery ─────────────────────────────────────────────────
    ("vault", Recording::Through("commands/vault/recover.rs")),
    (
        "audit",
        Recording::Exempt(
            "Reads the log. A verifier that appended to the thing it verifies \
             would change the head every time anyone looked at it — and since \
             `audit head` hands that head out as the anchor an operator keeps, \
             an appending verifier would invalidate its own answer between the \
             two halves of the check.",
        ),
    ),
    // Behavioural cover:
    // `restore::tests::a_backup_and_a_restore_are_both_in_the_chain_and_say_which_way`.
    ("backup", Recording::Through("commands/backup/store.rs")),
    ("restore", Recording::Through("commands/restore/mod.rs")),
    // ── Mount ────────────────────────────────────────────────────────────
    // Behavioural cover:
    // `mount::state::tests::the_first_read_through_the_mount_lands_in_the_audit_chain_and_says_out`
    // and `mount::state::tests::a_read_that_cannot_be_recorded_serves_no_bytes`.
    // A session record when the filesystem attaches, and one first-read record
    // per object — per-read records were rejected, because a 128 KiB kernel
    // read is not an event anybody wants a line for. See `mount/audit.rs` for
    // what the byte totals therefore do and do not claim.
    ("mount", Recording::Through("mount/audit.rs")),
    // ── Utility ──────────────────────────────────────────────────────────
    (
        "about",
        Recording::Exempt("Reports usage and capabilities. No object body is read."),
    ),
    (
        "home",
        Recording::Exempt(
            "Reports where this machine keeps its configuration, index, audit \
             chain and logs, and whether each is owner-only. Reads metadata \
             only — no remote, no vault, no object body — and is run precisely \
             when something is already wrong, so it must not be able to make \
             anything worse.",
        ),
    ),
    (
        "version",
        Recording::Exempt("Prints build information. Touches no remote at all."),
    ),
    (
        "completion",
        Recording::Exempt("Prints a shell script. Touches no remote at all."),
    ),
    // ── Compatibility aliases ────────────────────────────────────────────
    ("put", Recording::Through("commands/transfer/pipeline.rs")),
    ("get", Recording::Through("commands/transfer/pipeline.rs")),
    ("rm", Recording::Through("commands/removal/remove.rs")),
];

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::cli::Cli;
    use clap::CommandFactory;
    use std::path::{Path, PathBuf};

    /// The call every appender makes, with the whitespace taken out.
    ///
    /// Compared against a whitespace-stripped copy of the file, because
    /// `rustfmt` is entitled to break `ctx.audit.record(…)` across lines
    /// wherever the argument list gets long — and it does, in half the
    /// appenders. A scan that only matched the one-line spelling would report
    /// "this module no longer appends" every time a call site grew an argument,
    /// which is a check nobody would keep.
    const APPEND_CALL: &str = "audit.record(";

    /// This crate's `src` directory.
    ///
    /// From `CARGO_MANIFEST_DIR` rather than from a macro over the file that
    /// happens to hold this test, so moving the module does not silently change
    /// what is scanned — the same reasoning `crate::cli::mentions` gives.
    fn source_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    #[test]
    fn every_command_states_whether_it_appends_to_the_chain() {
        // The mechanical half. A new subcommand cannot ship without somebody
        // deciding, in writing, whether it belongs in the audit log — which is
        // exactly the decision `backup`, `restore` and `touch` skipped.
        let tree = Cli::command();
        let missing: Vec<String> = tree
            .get_subcommands()
            .map(|sub| sub.get_name().to_string())
            .filter(|name| !COVERAGE.iter().any(|(listed, _)| listed == name))
            .collect();

        assert!(
            missing.is_empty(),
            "these commands have no audit-coverage decision: {missing:?}\n\
             Add a row to audit::coverage::COVERAGE saying whether the command \
             appends to the chain, and why."
        );
    }

    #[test]
    fn no_row_outlives_the_command_it_describes() {
        // The other direction: a row for a command that no longer exists is a
        // policy about nothing, and it makes the table read as more complete
        // than it is.
        let tree = Cli::command();
        let names: Vec<String> = tree
            .get_subcommands()
            .map(|sub| sub.get_name().to_string())
            .collect();

        let stale: Vec<&str> = COVERAGE
            .iter()
            .map(|(name, _)| *name)
            .filter(|name| !names.iter().any(|listed| listed == name))
            .collect();
        assert!(
            stale.is_empty(),
            "rows for commands that do not exist: {stale:?}"
        );
    }

    #[test]
    fn every_recording_command_has_an_appender_that_still_appends() {
        // The half that catches a *removal*: if somebody deletes the record call
        // from `backup::store`, the table would still claim `backup` is
        // recorded. The claim is checked against the file.
        for (command, recording) in COVERAGE {
            let Recording::Through(module) = recording else {
                continue;
            };
            let path = source_root().join(module);
            let body = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{command}: cannot read {module}: {error}"));
            let dense: String = body.chars().filter(|c| !c.is_whitespace()).collect();
            assert!(
                dense.contains(APPEND_CALL),
                "{command} is listed as recording through {module}, but that file \
                 contains no `{APPEND_CALL}` call"
            );
        }
    }

    #[test]
    fn every_exemption_carries_a_reason() {
        // An exemption without a reason is an omission with a label on it.
        for (command, recording) in COVERAGE {
            if let Recording::Exempt(reason) = recording {
                assert!(
                    reason.len() > 20,
                    "{command} is exempt with no real reason given: {reason:?}"
                );
            }
        }
    }

    #[test]
    fn every_command_that_moves_object_content_is_recorded() {
        // The rule, asserted as a rule rather than left to the rows. These are
        // the verbs whose whole job is to move object bodies; each of them being
        // in the chain is the product claim, and `backup`, `restore` and `cat`
        // are on this list precisely because none of them was.
        for command in [
            "copy",
            "move",
            "sync",
            "copyto",
            "moveto",
            "backup",
            "restore",
            "cat",
            "rcat",
            "replicate",
            "put",
            "get",
            // A mounted vault hands decrypted plaintext to anything that can
            // read a filesystem, which is object content leaving by the widest
            // door the tool has. It was exempt from this list for a release.
            "mount",
        ] {
            let row = COVERAGE
                .iter()
                .find(|(name, _)| *name == command)
                .unwrap_or_else(|| panic!("{command} has no coverage row"));
            assert!(
                matches!(row.1, Recording::Through(_)),
                "{command} moves object content and must append to the chain"
            );
        }
    }

    #[test]
    fn the_scan_actually_reaches_the_modules_it_claims_to() {
        // A guard against the failure mode this whole module exists to prevent:
        // a check that quietly verifies nothing while reporting success. If
        // `source_root` is wrong, every `Through` row above would still "pass"
        // by reading zero files, so the count is pinned.
        let appenders = COVERAGE
            .iter()
            .filter(|(_, recording)| matches!(recording, Recording::Through(_)))
            .count();
        assert!(
            appenders >= 15,
            "only {appenders} recording rows — the table has been gutted"
        );
        assert!(source_root().join("audit").join("sink.rs").is_file());
    }
}
