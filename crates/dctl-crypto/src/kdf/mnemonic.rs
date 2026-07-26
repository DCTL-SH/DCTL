//! BIP-39 recovery-mnemonic KDF.
//!
//! The BIP-39 seed (PBKDF2-HMAC-SHA512 over the mnemonic, a public standard so it
//! reproduces on any device) is fed to Argon2id, giving the recovery path the same
//! KEK strength as the password path. Used by the mnemonic key slot (FORMAT.md §2).

use bip39::Mnemonic;
use zeroize::Zeroizing;

use crate::constants::KEY_LEN;
use crate::error::{CryptoError, Result};

use super::derive::argon2id;

/// Derive a KEK from a BIP-39 mnemonic + salt + validated Argon2id params.
pub fn derive_kek_from_mnemonic(
    mnemonic: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_lanes: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let parsed = Mnemonic::parse(mnemonic)
        .map_err(|e| CryptoError::Kdf(format!("invalid mnemonic: {e}")))?;
    let seed = Zeroizing::new(parsed.to_seed(""));
    argon2id(&seed[..], salt, m_cost, t_cost, p_lanes)
}

/// Generate a fresh 24-word (256-bit) BIP-39 recovery mnemonic, wiped on drop.
pub fn generate_mnemonic() -> Result<Zeroizing<String>> {
    let mut entropy = Zeroizing::new([0u8; 32]);
    crate::rng::fill(entropy.as_mut());
    let mnemonic = Mnemonic::from_entropy(&entropy[..])
        .map_err(|e| CryptoError::Kdf(format!("mnemonic generation: {e}")))?;
    Ok(Zeroizing::new(mnemonic.to_string()))
}
