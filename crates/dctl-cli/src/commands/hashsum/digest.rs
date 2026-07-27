//! Computing one digest, over plaintext.
//!
//! ## Why plaintext, and why that word appears in every doc comment here
//!
//! `dctl hashsum sha256 archive:photos/a.jpg` is asked by somebody who is about
//! to compare the answer with `sha256sum photos/a.jpg` on their own disk. The
//! only digest that makes that comparison mean anything is the digest of the
//! **file**, not of the sealed object the provider is holding. Hashing the
//! ciphertext would produce a perfectly well-formed 64-character string that
//! never matches anything the user has, and — worse — would change every time
//! the object were re-sealed under a fresh nonce while the file itself had not
//! moved a byte. It would answer a different question in a way that looks
//! exactly like an answer to the one that was asked.
//!
//! So this module only ever sees what [`Source::read`](crate::source::Source::read)
//! returned, which for a vault is the authenticated plaintext and for a plain
//! store is the object as stored — in both cases, the bytes a user would get
//! from `dctl cat`. The invariant is enforced by the call site
//! ([`super::engine`]) rather than restated here, because a function that takes
//! a `&[u8]` cannot check where the slice came from.
//!
//! ## Why this is not in [`super::algo`]
//!
//! `algo` owns the *line format* — the thing that has to stay byte-identical to
//! coreutils for twenty years — and nothing else. Digest computation is the part
//! that grows a dependency and an allocation per object, and keeping the two
//! apart means the format's tests never need a hasher and the hasher's tests
//! never need to know what a checksum file looks like.

use sha1::{Digest as _, Sha1};
use sha2::{Digest as _, Sha256};

use super::algo::Algorithm;

/// The digest of `plaintext` under `algorithm`, as lower-case hex.
///
/// Takes the whole buffer rather than a reader because
/// [`Source::read`](crate::source::Source::read) hands back a whole buffer and
/// nothing narrower exists — a streaming hasher here would be a façade over a
/// `Vec` that has already been allocated. The cost is stated on the source trait
/// and repeated by the command before the run starts, which is the honest place
/// for it.
#[must_use]
pub fn of(algorithm: Algorithm, plaintext: &[u8]) -> String {
    match algorithm {
        // The vault's own hash, recomputed. Identical by construction to the one
        // recorded at write time, which is what makes answering from the index
        // (see [`super::engine`]) a shortcut rather than a second opinion.
        Algorithm::Blake3 => crate::output::hex::encode(blake3::hash(plaintext).as_bytes()),
        Algorithm::Sha1 => crate::output::hex::encode(&Sha1::digest(plaintext)),
        Algorithm::Sha256 => crate::output::hex::encode(&Sha256::digest(plaintext)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published digests of the empty input, which is the one test vector
    /// every one of these algorithms agrees on and nobody has to trust this
    /// crate for.
    const EMPTY_BLAKE3: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    const EMPTY_SHA1: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn every_algorithm_reproduces_its_published_empty_digest() {
        assert_eq!(of(Algorithm::Blake3, b""), EMPTY_BLAKE3);
        assert_eq!(of(Algorithm::Sha1, b""), EMPTY_SHA1);
        assert_eq!(of(Algorithm::Sha256, b""), EMPTY_SHA256);
    }

    #[test]
    fn the_sha256_of_abc_is_the_one_in_the_standard() {
        // FIPS 180-4's own worked example. A digest that is merely *stable* is
        // worth nothing here: the whole point is that `sha256sum` agrees.
        assert_eq!(
            of(Algorithm::Sha256, b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            of(Algorithm::Sha1, b"abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn a_digest_is_lower_case_hex_of_the_right_width() {
        // Length and alphabet are what `Algorithm::is_well_formed` guards a
        // checksum file with, so the producer has to satisfy the same rule.
        for algorithm in [Algorithm::Blake3, Algorithm::Sha1, Algorithm::Sha256] {
            let hex = of(algorithm, b"some bytes");
            assert_eq!(hex.len(), algorithm.hex_len());
            assert!(algorithm.is_well_formed(&hex));
            assert_eq!(hex, hex.to_lowercase());
        }
    }

    #[test]
    fn the_blake3_here_is_the_one_the_index_records() {
        // The shortcut in the engine — answering `blake3` from the recorded
        // content hash instead of reading the object — is only sound because
        // these two are the same function of the same bytes.
        let plaintext = b"sealed and returned";
        assert_eq!(
            of(Algorithm::Blake3, plaintext),
            crate::output::hex::encode(blake3::hash(plaintext).as_bytes())
        );
    }

    #[test]
    fn different_inputs_do_not_collide_under_any_algorithm() {
        for algorithm in [Algorithm::Blake3, Algorithm::Sha1, Algorithm::Sha256] {
            assert_ne!(of(algorithm, b"a"), of(algorithm, b"b"));
        }
    }
}
