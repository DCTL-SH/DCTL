//! The algorithms `hashsum` speaks, and the exact line format it writes.
//!
//! The line format is the whole point of this file. `dctl hashsum` is not
//! interesting because it prints hashes — it is interesting because its output
//! is *byte-identical to coreutils*, so a vault can be handed to tools that have
//! never heard of DCTL:
//!
//! ```text
//! dctl hashsum sha256 vault: > SUMS
//! sha256sum -c SUMS
//! ```
//!
//! That means `<hash>` then **exactly two spaces** then `<path>`, with the second
//! space replaced by `*` in binary mode. GNU's parser reads the character after
//! the first space as the mode flag, so a single space, a tab, or an aligned
//! column would produce a file that looks right and cannot be checked. The
//! separator therefore lives in [`crate::constants`] with that reasoning
//! attached, and [`format_line`] is the only thing allowed to assemble a line.
//!
//! Digest computation deliberately does **not** live here. The vault records a
//! plaintext BLAKE3 for every object at write time, so `blake3` is answered from
//! the index; SHA-1 and SHA-256 are not recorded and can only be produced by
//! reading and decrypting the object, which is engine work. Putting a
//! half-implemented `hash()` here would invite exactly the kind of quiet
//! fallback this tool is not allowed to have.

// Some of what follows is not reachable from this build's `run` body: the engine
// has no entry point yet for the step that would call it (see the command's
// module documentation). It is written and unit-tested now, with the tests that
// pin its contract, rather than left until the engine lands — a machine-readable
// output format that first appears on the day it is needed is a format nobody
// reviewed.
#![allow(dead_code)]

use clap::ValueEnum;

use crate::constants::{
    HASH_HEX_LEN_BLAKE3, HASH_HEX_LEN_SHA1, HASH_HEX_LEN_SHA256, HASHSUM_BINARY_MARKER,
    HASHSUM_FIELD_SEPARATOR, UNKNOWN_VALUE,
};

/// A content-hash algorithm.
///
/// BLAKE3 first because it is what DCTL actually stores (`PLAN.md` §13.3's
/// integrity manifest); SHA-1 and SHA-256 exist for interoperability with
/// systems that predate it — a 20-year tool has to be able to hand its
/// checksums to software that does not know BLAKE3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum Algorithm {
    /// The vault's native plaintext hash, recorded for every object.
    Blake3,
    /// Legacy interoperability, including B2's per-object checksum.
    Sha1,
    /// The interchange default outside DCTL.
    Sha256,
}

impl Algorithm {
    /// The stable slug, taken from clap's own value table so the word a user
    /// types and the word the report prints cannot drift apart.
    #[must_use]
    pub fn slug(self) -> String {
        self.to_possible_value().map_or_else(
            || UNKNOWN_VALUE.to_string(),
            |value| value.get_name().to_string(),
        )
    }

    /// The number of hex characters a digest occupies.
    ///
    /// Used to reject a malformed checksum file before it is trusted, and to
    /// size a column. A fixed property of the algorithm, not a preference.
    #[must_use]
    pub const fn hex_len(self) -> usize {
        match self {
            Self::Blake3 => HASH_HEX_LEN_BLAKE3,
            Self::Sha1 => HASH_HEX_LEN_SHA1,
            Self::Sha256 => HASH_HEX_LEN_SHA256,
        }
    }

    /// Whether the vault already records this hash for every object.
    ///
    /// Only BLAKE3 does, which is exactly the difference between a `hashsum`
    /// that answers from the index and one that has to read, decrypt and re-hash
    /// every object. Commands warn about the second case before starting it,
    /// because the surprise otherwise arrives as an egress bill.
    #[must_use]
    pub const fn is_recorded_in_the_index(self) -> bool {
        matches!(self, Self::Blake3)
    }

    /// Whether `digest` is a plausible hex digest for this algorithm.
    ///
    /// Length and alphabet only — it cannot tell a wrong hash from a right one,
    /// and does not pretend to. It exists so a truncated or mangled checksum file
    /// is rejected as malformed rather than reported as a mismatch, which would
    /// send someone looking for corruption that is not there.
    #[must_use]
    pub fn is_well_formed(self, digest: &str) -> bool {
        digest.len() == self.hex_len() && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    }
}

/// Assemble one coreutils-compatible checksum line, without its newline.
///
/// `binary` selects GNU's binary-mode marker. DCTL's objects are opaque bytes,
/// so binary mode is the more truthful description; text mode is the default
/// because it is what `sha256sum` writes unless asked otherwise, and matching
/// the common case is what keeps a diff of two SUMS files readable.
#[must_use]
pub fn format_line(digest: &str, path: &str, binary: bool) -> String {
    if binary {
        // The marker replaces the *second* space, never the first: GNU reads
        // the character immediately after the single separating space as the
        // mode flag.
        let mut separator = HASHSUM_FIELD_SEPARATOR.to_string();
        separator.pop();
        format!("{digest}{separator}{HASHSUM_BINARY_MARKER}{path}")
    } else {
        format!("{digest}{HASHSUM_FIELD_SEPARATOR}{path}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLAKE3_ZERO: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

    #[test]
    fn the_flag_spellings_are_the_ones_people_type() {
        assert_eq!(Algorithm::Blake3.slug(), "blake3");
        assert_eq!(Algorithm::Sha1.slug(), "sha1");
        assert_eq!(Algorithm::Sha256.slug(), "sha256");
    }

    #[test]
    fn a_text_mode_line_is_exactly_the_coreutils_shape() {
        // Two spaces. `sha256sum -c` reads the character after the first space
        // as the mode flag, so anything else produces an uncheckable file.
        let line = format_line(BLAKE3_ZERO, "photos/a.jpg", false);
        assert_eq!(line, format!("{BLAKE3_ZERO}  photos/a.jpg"));
        assert_eq!(&line[HASH_HEX_LEN_BLAKE3..HASH_HEX_LEN_BLAKE3 + 2], "  ");
    }

    #[test]
    fn a_binary_mode_line_replaces_the_second_space_with_a_star() {
        let line = format_line(BLAKE3_ZERO, "photos/a.jpg", true);
        assert_eq!(line, format!("{BLAKE3_ZERO} *photos/a.jpg"));
        // The first separator stays a space in both modes.
        assert_eq!(line.as_bytes()[HASH_HEX_LEN_BLAKE3], b' ');
        assert_eq!(line.as_bytes()[HASH_HEX_LEN_BLAKE3 + 1], b'*');
    }

    #[test]
    fn a_line_splits_back_into_its_two_fields() {
        // The round trip a checker performs.
        let line = format_line(BLAKE3_ZERO, "a b/c.txt", false);
        let (digest, path) = line.split_once(HASHSUM_FIELD_SEPARATOR).unwrap();
        assert_eq!(digest, BLAKE3_ZERO);
        // Paths may contain spaces; only the *first* double space separates.
        assert_eq!(path, "a b/c.txt");
    }

    #[test]
    fn a_line_never_contains_a_newline_of_its_own() {
        // The caller adds the record separator, so a path is never able to
        // smuggle an extra record into the stream by ending in one.
        assert!(!format_line(BLAKE3_ZERO, "a.txt", false).contains('\n'));
    }

    #[test]
    fn digest_widths_match_the_algorithms() {
        assert_eq!(Algorithm::Blake3.hex_len(), BLAKE3_ZERO.len());
        assert_eq!(Algorithm::Sha1.hex_len(), 40);
        assert_eq!(Algorithm::Sha256.hex_len(), 64);
    }

    #[test]
    fn a_malformed_digest_is_rejected_as_malformed() {
        // Not as a mismatch: telling someone their data is corrupt because their
        // SUMS file was truncated would be worse than useless.
        assert!(Algorithm::Blake3.is_well_formed(BLAKE3_ZERO));
        assert!(Algorithm::Blake3.is_well_formed(&BLAKE3_ZERO.to_uppercase()));
        assert!(!Algorithm::Blake3.is_well_formed(&BLAKE3_ZERO[..63]));
        assert!(!Algorithm::Sha1.is_well_formed(BLAKE3_ZERO));
        assert!(!Algorithm::Blake3.is_well_formed(&"z".repeat(64)));
        assert!(!Algorithm::Blake3.is_well_formed(""));
    }

    #[test]
    fn only_blake3_can_be_answered_from_the_index() {
        // The difference between a metadata sweep and reading the whole vault.
        assert!(Algorithm::Blake3.is_recorded_in_the_index());
        assert!(!Algorithm::Sha1.is_recorded_in_the_index());
        assert!(!Algorithm::Sha256.is_recorded_in_the_index());
    }

    #[test]
    fn the_documented_blake3_constant_is_the_real_digest_of_the_empty_input() {
        // Guards the fixture the rest of this file is written against.
        assert_eq!(blake3::hash(b"").to_hex().as_str(), BLAKE3_ZERO);
    }
}
