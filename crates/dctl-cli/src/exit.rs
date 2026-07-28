//! Stable process exit codes (`PLAN.md` §7, §16.3).
//!
//! These are a **public contract**: scripts branch on them, so a code's meaning
//! must never change once released. New conditions get new numbers.
//!
//! Codes 0–10 deliberately mirror rclone's taxonomy so existing automation ports
//! across with minimal edits. Codes 20+ are DCTL-specific and cover the failures
//! rclone has no concept of — verified-write refusal, AEAD authentication
//! failure, index/WAL damage, and audit-chain tampering.
//!
//! ## Why this module allows dead code
//!
//! The enum is an *inventory of the contract*, not an inventory of what this
//! build happens to emit. One code — 10 — belongs to `--max-duration`, which is
//! rclone's and which DCTL has no flag for. (9 was on that list until a scrub
//! that covered nothing needed a non-zero status to say so, and it is now
//! produced by [`crate::commands::scrub`]. 8 was on it too, for longer than it
//! should have been: `--max-transfer` parsed and was never enforced, so a run
//! capped at 1 MiB moved 10 MiB and exited 0. [`crate::limits::budget`] produces
//! it now, and `tests/cli.rs` asserts a process really exits with it.)
//!
//! [`ExitCode::all`] and [`ExitCode::describe`] have no caller outside this
//! file's own tests. They exist so the contract can be enumerated rather than
//! transcribed, and the table in `docs/EXIT_CODES.md` is currently kept in step
//! by hand. This used to say they fed a `help exitcodes` topic; no such
//! subcommand exists, in this or any build, and a comment that names one
//! teaches the next reader to repeat it in a user-facing hint — which is
//! exactly how three of those got written.
//!
//! Deleting a variant because nothing constructs it today is how a published
//! number silently changes meaning tomorrow: the next feature that needs "the
//! run stopped at a limit" would find 8 free and take it, and every script that
//! branches on 8 would be wrong in a way nothing detects. So the gap is held
//! open deliberately, and the tests below assert the whole set stays unique,
//! ordered and described. The allow is scoped to this file, which contains
//! nothing but the contract.
#![allow(dead_code)]

/// Exit status returned to the operating system.
///
/// `#[repr(i32)]` so the discriminants *are* the wire values — the numbers below
/// are the documented contract, not an implementation detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    // ── rclone-compatible range ───────────────────────────────────────────
    /// Completed successfully.
    Success = 0,
    /// Command-line syntax or usage error.
    Usage = 1,
    /// An error not otherwise categorised.
    Uncategorised = 2,
    /// A source or destination directory was not found.
    DirNotFound = 3,
    /// A source or destination file was not found.
    FileNotFound = 4,
    /// A temporary error; retries were exhausted without success.
    TemporaryError = 5,
    /// Less serious errors: the run finished but some files failed.
    PartialFailure = 6,
    /// Fatal error — the run cannot continue.
    ///
    /// Three families reach it, and the middle one only started to once
    /// something read the errno. A **bad configuration**, a **destination with
    /// no room** (`ENOSPC`/`EDQUOT`/`EFBIG`/`EROFS`, plus a short write that
    /// reported nothing), and a **location that is not a vault**. All three
    /// share the property [`crate::commands::transfer::pipeline::is_fatal`]
    /// selects on: every remaining file in the run fails identically, so
    /// grinding through them produces ten million copies of one message.
    ///
    /// A full disk used to arrive as exit 2 "uncategorised" and, worse, as exit
    /// 20 "checksum mismatch" — see `docs/EXIT_CODES.md` §20.
    FatalError = 7,
    /// `--max-transfer` limit was reached.
    TransferLimitExceeded = 8,
    /// Completed successfully, but the run did no work.
    ///
    /// rclone's "nothing was transferred", and DCTL keeps the number and the
    /// slug for the transfer verbs that mean exactly that. It also carries the
    /// read-only shape of the same statement: `dctl scrub` returns it when the
    /// run read **no object at all**, because a scrub that verified nothing and
    /// exited 0 was indistinguishable from one that verified a whole dataset —
    /// which let a nightly cron stay green for years while proving nothing.
    ///
    /// Deliberately not an error code. Nothing failed, and treating it as a
    /// failure would be its own misreport; it is simply not zero, which is the
    /// only property a wrapper needs to notice that the work did not happen.
    NoFilesTransferred = 9,
    /// `--max-duration` limit was reached.
    DurationLimitExceeded = 10,

    // ── DCTL-specific range (20+) ─────────────────────────────────────────
    /// A verified write refused to commit: the stored bytes did not match the
    /// expected checksum. Nothing was committed and no source was touched.
    ChecksumMismatch = 20,
    /// AEAD authentication failed on read — wrong key, tampered ciphertext, or
    /// wrong context. The data was **not** served.
    IntegrityFailure = 21,
    /// The vault could not be unlocked: wrong password/factor, or a missing or
    /// corrupted envelope.
    VaultLocked = 22,
    /// The encrypted index or write-ahead journal could not be read or written.
    IndexError = 23,
    /// The tamper-evident audit log failed its hash-chain verification.
    AuditChainBroken = 24,
    /// The operation was cancelled (Ctrl-C / SIGTERM). In-flight work was rolled
    /// back or left resumable; nothing was reported as successful.
    Cancelled = 25,
    /// The audit chain verified, but it does not end at the head the caller
    /// anchored with `--expect-head`: records were removed from the end, the
    /// chain diverged, or the anchor is older than the log.
    ///
    /// **Deliberately not 24.** A chain hash detects every edit made *inside* a
    /// log and none made to its end, so these are two different findings with
    /// two different remedies: 24 says the links failed, 26 says the links held
    /// and the log is not the one you left. Folding the second into the first
    /// would put the common benign case — an anchor that is simply older than
    /// the log — behind the code operators are told to treat as a security
    /// event, which is how a loud code gets ignored. This module's own rule is
    /// that a new condition gets a new number.
    AuditHeadMismatch = 26,
}

impl ExitCode {
    /// The integer handed to the operating system.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Short stable slug used in `--json` output and log records, so machine
    /// consumers can branch on a name rather than a bare number.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Usage => "usage",
            Self::Uncategorised => "uncategorised",
            Self::DirNotFound => "dir_not_found",
            Self::FileNotFound => "file_not_found",
            Self::TemporaryError => "temporary_error",
            Self::PartialFailure => "partial_failure",
            Self::FatalError => "fatal_error",
            Self::TransferLimitExceeded => "transfer_limit_exceeded",
            Self::NoFilesTransferred => "no_files_transferred",
            Self::DurationLimitExceeded => "duration_limit_exceeded",
            Self::ChecksumMismatch => "checksum_mismatch",
            Self::IntegrityFailure => "integrity_failure",
            Self::VaultLocked => "vault_locked",
            Self::IndexError => "index_error",
            Self::AuditChainBroken => "audit_chain_broken",
            Self::Cancelled => "cancelled",
            Self::AuditHeadMismatch => "audit_head_mismatch",
        }
    }

    /// One-line explanation of the code, and the wording `docs/EXIT_CODES.md`
    /// carries for it. Nothing calls this outside the tests below; it is the
    /// contract written once so the published table has a single source to be
    /// checked against.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Success => "Completed successfully",
            Self::Usage => "Command-line syntax or usage error",
            Self::Uncategorised => "Error not otherwise categorised",
            Self::DirNotFound => "Directory not found",
            Self::FileNotFound => "File not found",
            Self::TemporaryError => "Temporary error; retries exhausted",
            Self::PartialFailure => "Some files failed to transfer",
            Self::FatalError => "Fatal error; cannot continue (bad config, disk full, not a vault)",
            Self::TransferLimitExceeded => "--max-transfer limit reached",
            Self::NoFilesTransferred => "Succeeded, but the run did no work",
            Self::DurationLimitExceeded => "--max-duration limit reached",
            Self::ChecksumMismatch => "Verified write refused: checksum mismatch",
            Self::IntegrityFailure => "AEAD authentication failed on read",
            Self::VaultLocked => "Vault locked: wrong password or corrupt envelope",
            Self::IndexError => "Encrypted index or journal error",
            Self::AuditChainBroken => "Audit log hash chain verification failed",
            Self::Cancelled => "Operation cancelled",
            Self::AuditHeadMismatch => "Audit log head does not match the expected anchor",
        }
    }

    /// Every code, in numeric order — the single source for the docs table.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Success,
            Self::Usage,
            Self::Uncategorised,
            Self::DirNotFound,
            Self::FileNotFound,
            Self::TemporaryError,
            Self::PartialFailure,
            Self::FatalError,
            Self::TransferLimitExceeded,
            Self::NoFilesTransferred,
            Self::DurationLimitExceeded,
            Self::ChecksumMismatch,
            Self::IntegrityFailure,
            Self::VaultLocked,
            Self::IndexError,
            Self::AuditChainBroken,
            Self::Cancelled,
            Self::AuditHeadMismatch,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::ExitCode;

    #[test]
    fn wire_values_are_the_documented_contract() {
        // These numbers are published. Changing one breaks user scripts.
        assert_eq!(ExitCode::Success.as_i32(), 0);
        assert_eq!(ExitCode::Usage.as_i32(), 1);
        assert_eq!(ExitCode::PartialFailure.as_i32(), 6);
        assert_eq!(ExitCode::NoFilesTransferred.as_i32(), 9);
        assert_eq!(ExitCode::ChecksumMismatch.as_i32(), 20);
        assert_eq!(ExitCode::IntegrityFailure.as_i32(), 21);
        assert_eq!(ExitCode::VaultLocked.as_i32(), 22);
        assert_eq!(ExitCode::AuditChainBroken.as_i32(), 24);
        assert_eq!(ExitCode::AuditHeadMismatch.as_i32(), 26);
    }

    #[test]
    fn a_head_mismatch_is_not_a_broken_chain() {
        // Two findings, two numbers. A chain whose links all hold but which no
        // longer ends where it was anchored is not the same event as a chain
        // whose links failed, and a script that pages on 24 must not be woken by
        // a stale anchor.
        assert_ne!(
            ExitCode::AuditHeadMismatch.as_i32(),
            ExitCode::AuditChainBroken.as_i32()
        );
        assert_ne!(
            ExitCode::AuditHeadMismatch.slug(),
            ExitCode::AuditChainBroken.slug()
        );
        assert_ne!(ExitCode::AuditHeadMismatch.as_i32(), 0);
    }

    #[test]
    fn codes_are_unique_and_ordered() {
        let all = ExitCode::all();
        for pair in all.windows(2) {
            assert!(
                pair[0].as_i32() < pair[1].as_i32(),
                "exit codes must be listed in strictly increasing order"
            );
        }
    }

    #[test]
    fn every_code_has_a_slug_and_description() {
        for code in ExitCode::all() {
            assert!(!code.slug().is_empty());
            assert!(!code.describe().is_empty());
        }
    }
}
