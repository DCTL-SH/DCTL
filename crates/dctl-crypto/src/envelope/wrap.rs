//! Wrap the root key into DKE1 slots and unwrap with a key-committing gate (§2).

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::aead;
use crate::constants::{
    COMMIT_LEN, KEY_LEN, SLOT_AAD_PREFIX, SLOT_COMMIT_INFO, WRAP_ALGO_XCHACHA20_POLY1305,
};
use crate::error::{CryptoError, Result};
use crate::keys::derive_subkey;

use super::model::Slot;

/// Framed slot wrap-AAD (§2): `prefix ‖ vault_id ‖ slot_type ‖ flags ‖ kdf_id ‖
/// wrap_algo ‖ salt_len(u8) ‖ salt ‖ aux_len(u16 LE) ‖ aux`. Binds the vault, the
/// wrap/KDF selectors (anti-downgrade), and length-framed salt/aux.
fn slot_aad(
    vault_id: &[u8; 16],
    slot_type: u8,
    flags: u8,
    kdf_id: u8,
    wrap_algo: u8,
    salt: &[u8],
    aux: &[u8],
) -> Result<Vec<u8>> {
    let salt_len: u8 = salt
        .len()
        .try_into()
        .map_err(|_| CryptoError::Format("salt too long".into()))?;
    let aux_len: u16 = aux
        .len()
        .try_into()
        .map_err(|_| CryptoError::Format("aux too long".into()))?;
    let mut aad =
        Vec::with_capacity(SLOT_AAD_PREFIX.len() + 16 + 4 + 1 + salt.len() + 2 + aux.len());
    aad.extend_from_slice(SLOT_AAD_PREFIX);
    aad.extend_from_slice(vault_id);
    aad.push(slot_type);
    aad.push(flags);
    aad.push(kdf_id);
    aad.push(wrap_algo);
    aad.push(salt_len);
    aad.extend_from_slice(salt);
    aad.extend_from_slice(&aux_len.to_le_bytes());
    aad.extend_from_slice(aux);
    Ok(aad)
}

/// Key-commitment for a KEK: `SUBKEY(KEK, "dctl-slot-commit-v1")`.
fn commitment(kek: &[u8; KEY_LEN]) -> Result<[u8; COMMIT_LEN]> {
    let sub = derive_subkey(kek, SLOT_COMMIT_INFO)?;
    let mut c = [0u8; COMMIT_LEN];
    c.copy_from_slice(&sub[..]);
    Ok(c)
}

/// Wrap `root_key` into a slot under `kek` (XChaCha20-Poly1305). `m/t/p` record the
/// Argon2id params that produced `kek` (informational; `kek` itself is the input).
#[allow(clippy::too_many_arguments)]
pub fn wrap_slot(
    kek: &[u8; KEY_LEN],
    root_key: &[u8; KEY_LEN],
    vault_id: &[u8; 16],
    slot_type: u8,
    kdf_id: u8,
    m_cost: u32,
    t_cost: u32,
    p_lanes: u32,
    salt: Vec<u8>,
    aux: Vec<u8>,
) -> Result<Slot> {
    let flags = 0u8;
    let wrap_algo = WRAP_ALGO_XCHACHA20_POLY1305;
    let aad = slot_aad(vault_id, slot_type, flags, kdf_id, wrap_algo, &salt, &aux)?;
    let wrapped_root = aead::encrypt(kek, root_key, &aad)?;
    let commit = commitment(kek)?;
    Ok(Slot {
        slot_type,
        flags,
        kdf_id,
        wrap_algo,
        m_cost,
        t_cost,
        p_lanes,
        commit,
        salt,
        aux,
        wrapped_root,
    })
}

/// Unwrap the root from `slot` under `kek`: constant-time commitment gate, then AEAD.
///
/// A wrong KEK fails the commitment (fast, no AEAD attempt); a substituted vault/slot
/// fails the AEAD (the framed AAD binds `vault_id` and every selector).
pub fn unwrap_slot(
    slot: &Slot,
    kek: &[u8; KEY_LEN],
    vault_id: &[u8; 16],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let expected = commitment(kek)?;
    if expected.ct_eq(&slot.commit).unwrap_u8() != 1 {
        return Err(CryptoError::Aead);
    }
    let aad = slot_aad(
        vault_id,
        slot.slot_type,
        slot.flags,
        slot.kdf_id,
        slot.wrap_algo,
        &slot.salt,
        &slot.aux,
    )?;
    let pt = aead::decrypt(kek, &slot.wrapped_root, &aad)?;
    if pt.len() != KEY_LEN {
        return Err(CryptoError::Format("unwrapped root wrong length".into()));
    }
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(&pt);
    Ok(out)
}
