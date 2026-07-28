//! The restore drill: `PLAN.md` §13.6, executed rather than described.
//!
//! > *A backup you never restored isn't a backup.*
//!
//! Everything else DCTL does is instrumental. The encryption, the chunking, the
//! index, the audit log and the provider backends exist so that one command, run
//! on the worst day, gives the data back. That claim is not provable by unit
//! tests: each of them holds one layer still while checking another, and the
//! failure this suite exists for is the one where every layer works and the
//! *sequence* does not — a rebuild that cannot create its own directory, a
//! recovery phrase that opens a vault but not a restore, a name that survives
//! storage and not retrieval.
//!
//! So this suite runs the whole sequence against the shipped binary, on a
//! realistic tree, having first deleted the local index outright.
//!
//! | Module | What it is |
//! |---|---|
//! | [`harness`] | the sandbox, the process runner, and capturing the phrase from the block a human reads |
//! | [`dataset`] | the tree, and the failure each entry in it makes possible |
//! | [`manifest`] | path + size + BLAKE3, recorded before the backup and diffed after the restore |
//! | [`drill`] | the six steps, over any backend |
//! | [`local`] | the drill against a local store — runs on every `cargo test` |
//! | [`b2`] | the same drill against a real bucket — `#[ignore]`, and a failure rather than a skip when asked for without credentials |
//! | [`normalisation`] | the collision at the sharp edge of the NFC rule, which this drill found |
//! | [`links`] | what comes back where a followed symbolic link used to be |
//!
//! ## The one difference between what goes in and what comes out
//!
//! A filename stored in NFD comes back in NFC. The file's bytes are identical;
//! the spelling of its name is not. This is correct, it is asserted rather than
//! tolerated, and [`drill`] explains at length why reverting it would reintroduce
//! a silent-duplicate bug. `docs/RESTORE_DRILL.md` states it in the terms an
//! auditor will ask about.
//!
//! ## What a run of this suite does not prove
//!
//! It does not prove the drill works against a cloud provider — [`b2`] does, and
//! only when it is asked for. It does not prove that objects sitting untouched
//! for a year are still readable; that is `dctl scrub`'s job and it needs a
//! calendar, not a test runner. And it proves nothing about a vault written by
//! an older format version, which needs golden fixtures rather than a fresh
//! `dctl init` (`PLAN.md` §13.6, second half).

mod dataset;
mod drill;
mod harness;
mod manifest;

mod b2;
#[cfg(unix)]
mod links;
mod local;
mod normalisation;
