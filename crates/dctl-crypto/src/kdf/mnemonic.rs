//! BIP-39 recovery-mnemonic KDF.
//!
//! The BIP-39 seed (PBKDF2-HMAC-SHA512 over the mnemonic, a public standard so it
//! reproduces on any device) is fed to Argon2id, giving the recovery path the same
//! KEK strength as the password path. Used by the mnemonic key slot (FORMAT.md §2).
//!
//! Parsing is done in exactly one place here, and that placement is load-bearing:
//! the seed BIP-39 defines is a function of the *word indices*, not of the typed
//! text, so a phrase copied off paper across four lines, or typed back with
//! doubled spaces, derives the identical KEK to the single line that was printed.
//! That is what makes a paper backup usable in twenty years, and it is not
//! visible from the call sites — they hand this module a `&str` and get a key.

use bip39::Mnemonic;
use zeroize::Zeroizing;

use crate::constants::{KEY_LEN, RECOVERY_MNEMONIC_ENTROPY_BYTES};
use crate::error::{CryptoError, Result};

use super::derive::argon2id;

/// Parse a BIP-39 mnemonic, checking its word list **and its checksum**.
///
/// The checksum is what makes a mistyped phrase distinguishable from a valid
/// phrase belonging to another vault: BIP-39 spends the trailing bits of the
/// last word on a hash of the entropy, so a single wrong or transposed word is
/// rejected here rather than deriving a KEK that silently opens nothing.
fn parse(mnemonic: &str) -> Result<Mnemonic> {
    Mnemonic::parse(mnemonic).map_err(|e| CryptoError::Kdf(format!("invalid mnemonic: {e}")))
}

/// Check that `mnemonic` is a well-formed BIP-39 phrase, deriving nothing.
///
/// Exists so a host can tell *"you typed the phrase wrong"* apart from *"that is
/// a valid phrase, but not this vault's"*. Those need opposite responses — one
/// is fixed by looking at the paper again, the other means the wrong vault is
/// being addressed — and an unlock attempt cannot tell them apart, because both
/// end as "no slot unwrapped". It shares [`parse`] with
/// [`derive_kek_from_mnemonic`] rather than restating the rule, so a phrase this
/// accepts is by construction one the KDF can use.
///
/// # Errors
/// [`CryptoError::Kdf`] naming what is wrong with the phrase — an unknown word
/// and its position, a bad word count, or a failed checksum.
pub fn validate_mnemonic(mnemonic: &str) -> Result<()> {
    parse(mnemonic).map(|_| ())
}

/// Derive a KEK from a BIP-39 mnemonic + salt + validated Argon2id params.
pub fn derive_kek_from_mnemonic(
    mnemonic: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_lanes: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let parsed = parse(mnemonic)?;
    let seed = Zeroizing::new(parsed.to_seed(""));
    argon2id(&seed[..], salt, m_cost, t_cost, p_lanes)
}

/// Generate a fresh 24-word (256-bit) BIP-39 recovery mnemonic, wiped on drop.
pub fn generate_mnemonic() -> Result<Zeroizing<String>> {
    let mut entropy = Zeroizing::new([0u8; RECOVERY_MNEMONIC_ENTROPY_BYTES]);
    crate::rng::fill(entropy.as_mut());
    let mnemonic = Mnemonic::from_entropy(&entropy[..])
        .map_err(|e| CryptoError::Kdf(format!("mnemonic generation: {e}")))?;
    Ok(Zeroizing::new(mnemonic.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{DEFAULT_SALT_LEN, RECOVERY_MNEMONIC_WORDS};

    /// Argon2id parameters deliberately far below the production defaults.
    ///
    /// These tests are about the *mnemonic* — word count, checksum, whitespace
    /// tolerance — and the shipped defaults would spend 128 MiB and several
    /// hundred milliseconds per derivation to prove nothing extra. The
    /// production values are exercised where they matter, by the vault tests
    /// that create real envelopes.
    const CHEAP: (u32, u32, u32) = (64, 1, 1);

    fn kek_with_salt(phrase: &str, salt: u8) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        derive_kek_from_mnemonic(phrase, &[salt; DEFAULT_SALT_LEN], CHEAP.0, CHEAP.1, CHEAP.2)
    }

    fn kek(phrase: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        kek_with_salt(phrase, 7)
    }

    #[test]
    fn a_generated_phrase_has_the_documented_word_count() {
        let phrase = generate_mnemonic().unwrap();
        assert_eq!(phrase.split_whitespace().count(), RECOVERY_MNEMONIC_WORDS);
        validate_mnemonic(&phrase).unwrap();
    }

    #[test]
    fn two_generated_phrases_differ() {
        // A generator that returned a constant would pass every other test here
        // and give every vault in the world the same second key.
        let a = generate_mnemonic().unwrap();
        let b = generate_mnemonic().unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn whitespace_in_a_transcribed_phrase_does_not_change_the_key() {
        // The property a paper backup depends on: 24 words written across four
        // lines and typed back with the line breaks intact must derive the same
        // KEK as the single line that was printed.
        let phrase = generate_mnemonic().unwrap();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let wrapped = words
            .chunks(6)
            .map(|line| line.join("  "))
            .collect::<Vec<_>>()
            .join("\n");
        assert_ne!(wrapped, *phrase, "the fixture must really differ textually");

        assert_eq!(kek(&phrase).unwrap()[..], kek(&wrapped).unwrap()[..]);
    }

    #[test]
    fn a_mistyped_word_is_rejected_rather_than_deriving_a_useless_key() {
        // Without the checksum this would derive *some* key and the caller would
        // be told their vault did not open, rather than that they had mistyped a
        // word. `zoo` is a real BIP-39 word, so this is a checksum failure — the
        // harder of the two to catch.
        let phrase = generate_mnemonic().unwrap();
        let mut words: Vec<&str> = phrase.split_whitespace().collect();
        words[0] = "zoo";
        let mangled = words.join(" ");

        assert!(validate_mnemonic(&mangled).is_err());
        assert!(kek(&mangled).is_err());
    }

    #[test]
    fn a_word_outside_the_list_is_reported_as_a_mnemonic_problem() {
        let phrase = generate_mnemonic().unwrap();
        let first = phrase.split_whitespace().next().unwrap().to_string();
        let mangled = phrase.replacen(&first, "notabip39word", 1);
        let error = validate_mnemonic(&mangled).unwrap_err().to_string();
        assert!(error.contains("mnemonic"), "{error}");
    }

    #[test]
    fn validation_and_derivation_agree_about_what_is_a_phrase() {
        // They share `parse`, and this is what holds them together: a phrase one
        // accepts and the other rejects would let a host validate a recovery
        // phrase and then fail to use it.
        for candidate in ["", "not a phrase at all", "abandon abandon abandon"] {
            assert_eq!(
                validate_mnemonic(candidate).is_ok(),
                kek(candidate).is_ok(),
                "disagreement on {candidate:?}"
            );
        }
        let good = generate_mnemonic().unwrap();
        assert!(validate_mnemonic(&good).is_ok() && kek(&good).is_ok());
    }

    #[test]
    fn the_same_phrase_and_salt_always_produce_the_same_key() {
        // The whole promise of a recovery phrase: it works again, later, on
        // another machine.
        let phrase = generate_mnemonic().unwrap();
        assert_eq!(kek(&phrase).unwrap()[..], kek(&phrase).unwrap()[..]);
    }

    #[test]
    fn a_different_salt_produces_a_different_key() {
        let phrase = generate_mnemonic().unwrap();
        assert_ne!(
            kek_with_salt(&phrase, 7).unwrap()[..],
            kek_with_salt(&phrase, 9).unwrap()[..]
        );
    }
}
