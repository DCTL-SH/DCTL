//! Argon2id key derivation.
//!
//! The passphrase is **NFC-normalized and UTF-8-encoded** before hashing so the
//! same passphrase typed on any OS/keyboard yields byte-identical KDF input
//! (FORMAT.md §2 / §10 — required for cross-device unlock). BLAKE3 normalizes the
//! optional binary factor. Cost params are validated against mandatory ceilings
//! before the (expensive) KDF runs, since envelope params come from untrusted
//! storage. Changing the hash, concatenation order, or normalization would
//! re-derive a different KEK, so those choices are frozen.

use argon2::{Algorithm, Argon2, Params, Version};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::constants::{
    ARGON2_MAX_M_COST, ARGON2_MAX_P_LANES, ARGON2_MAX_T_COST, ARGON2_MIN_M_COST,
    DEFAULT_ARGON2_M_COST, DEFAULT_ARGON2_P_LANES, DEFAULT_ARGON2_T_COST, KEY_LEN,
};
use crate::error::{CryptoError, Result};

/// NFC-normalize a passphrase to its canonical UTF-8 bytes, wiped on drop.
#[must_use]
pub fn normalize_passphrase(passphrase: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(passphrase.nfc().collect::<String>().into_bytes())
}

/// Validate Argon2id cost parameters against the mandatory ceilings. Callers MUST
/// call this (or a function that does) before running Argon2id on untrusted params.
pub fn validate_params(m_cost: u32, t_cost: u32, p_lanes: u32) -> Result<()> {
    let m_ok = (ARGON2_MIN_M_COST..=ARGON2_MAX_M_COST).contains(&m_cost);
    let t_ok = (1..=ARGON2_MAX_T_COST).contains(&t_cost);
    let p_ok = (1..=ARGON2_MAX_P_LANES).contains(&p_lanes);
    if m_ok && t_ok && p_ok {
        Ok(())
    } else {
        Err(CryptoError::InvalidKdfParams(format!(
            "m={m_cost} t={t_cost} p={p_lanes}; allowed m in {ARGON2_MIN_M_COST}..={ARGON2_MAX_M_COST}, t in 1..={ARGON2_MAX_T_COST}, p in 1..={ARGON2_MAX_P_LANES}"
        )))
    }
}

/// Run Argon2id over `secret` (already-normalized bytes) with validated params.
pub(crate) fn argon2id(
    secret: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_lanes: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    validate_params(m_cost, t_cost, p_lanes)?;
    let params = Params::new(m_cost, t_cost, p_lanes, Some(KEY_LEN))
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out: Zeroizing<[u8; KEY_LEN]> = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(secret, salt, out.as_mut())
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(out)
}

/// Derive the KEK from a passphrase (+ optional factor) and salt, default params.
pub fn derive_kek(
    passphrase: &str,
    factor: Option<&[u8]>,
    salt: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    derive_kek_with_params(
        passphrase,
        factor,
        salt,
        DEFAULT_ARGON2_M_COST,
        DEFAULT_ARGON2_T_COST,
        DEFAULT_ARGON2_P_LANES,
    )
}

/// Derive the KEK with explicit Argon2id parameters (re-deriving from the params
/// stored in an envelope slot). Input = NFC(passphrase) ‖ BLAKE3(factor)?.
pub fn derive_kek_with_params(
    passphrase: &str,
    factor: Option<&[u8]>,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_lanes: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut input: Zeroizing<Vec<u8>> = normalize_passphrase(passphrase);
    if let Some(factor) = factor {
        input.extend_from_slice(blake3::hash(factor).as_bytes());
    }
    argon2id(&input, salt, m_cost, t_cost, p_lanes)
}
