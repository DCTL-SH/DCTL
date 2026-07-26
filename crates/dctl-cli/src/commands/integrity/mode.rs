//! Reporting the global `--verify` strength.
//!
//! `PLAN.md` §6 step 5 makes verification strength an explicit cost/assurance
//! dial, which means a report that does not say which setting produced it is
//! incomplete: "1,204 objects verified" means something very different under
//! `checksum` (the provider's stored checksum agreed with ours) and under
//! `strict` (every byte was fetched, decrypted, authenticated and re-hashed).
//! Every integrity report therefore carries the mode, and this module is where
//! the two things a report needs — the slug and the sentence — come from.
//!
//! The slug is taken from clap's own value table rather than written out again,
//! so `--verify strict` on the command line and `"verify_mode": "strict"` in the
//! JSON are the same string by construction and cannot drift when a mode is
//! added or renamed.

use clap::ValueEnum as _;

use crate::cli::VerifyMode;
use crate::constants::UNKNOWN_VALUE;

/// The stable slug for a verification strength (`checksum`, `sample`, `strict`).
#[must_use]
pub fn slug(mode: VerifyMode) -> String {
    mode.to_possible_value().map_or_else(
        || UNKNOWN_VALUE.to_string(),
        |value| value.get_name().to_string(),
    )
}

/// Whether this mode reads object bytes back from the provider.
///
/// The expensive question, and the one that decides whether a `verify` over a
/// 50 TB vault is a metadata sweep or a full egress bill. Commands use it to
/// warn before starting rather than after the invoice arrives.
#[must_use]
pub const fn reads_object_bytes(mode: VerifyMode) -> bool {
    matches!(mode, VerifyMode::Sample | VerifyMode::Strict)
}

/// Whether this mode proves the *plaintext* is intact.
///
/// Only [`VerifyMode::Strict`] does: sampling proves some chunks decrypt, and a
/// checksum comparison proves the provider still holds the ciphertext we sent.
/// Both are useful; neither is the same claim, and a report must not imply it.
#[must_use]
pub const fn proves_whole_plaintext(mode: VerifyMode) -> bool {
    matches!(mode, VerifyMode::Strict)
}

/// One-line explanation of what a mode actually checked.
///
/// Shown under `-v` beside the result, because the number on its own invites the
/// reader to assume the strongest interpretation.
#[must_use]
pub const fn describe(mode: VerifyMode) -> &'static str {
    match mode {
        VerifyMode::Checksum => {
            "compared the provider's stored checksum against ours; no object bytes were read"
        }
        VerifyMode::Sample => {
            "read, decrypted and authenticated a sample of chunks from each object"
        }
        VerifyMode::Strict => {
            "read and decrypted every object in full and confirmed its whole-file BLAKE3"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_match_the_spellings_the_flag_accepts() {
        // Taken from clap's table, so this test is really asserting that the
        // report and `--verify` can never disagree.
        assert_eq!(slug(VerifyMode::Checksum), "checksum");
        assert_eq!(slug(VerifyMode::Sample), "sample");
        assert_eq!(slug(VerifyMode::Strict), "strict");
    }

    #[test]
    fn only_the_deeper_modes_cost_egress() {
        assert!(!reads_object_bytes(VerifyMode::Checksum));
        assert!(reads_object_bytes(VerifyMode::Sample));
        assert!(reads_object_bytes(VerifyMode::Strict));
    }

    #[test]
    fn only_strict_proves_the_whole_plaintext() {
        // Sampling proves *some* chunks decrypt. Claiming more would be exactly
        // the overstatement `PLAN.md` §6 forbids.
        assert!(proves_whole_plaintext(VerifyMode::Strict));
        assert!(!proves_whole_plaintext(VerifyMode::Sample));
        assert!(!proves_whole_plaintext(VerifyMode::Checksum));
    }

    #[test]
    fn every_mode_explains_itself() {
        for mode in [VerifyMode::Checksum, VerifyMode::Sample, VerifyMode::Strict] {
            assert!(!describe(mode).is_empty());
            assert!(!slug(mode).is_empty());
        }
    }
}
