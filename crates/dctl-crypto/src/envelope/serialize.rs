//! DKE1 envelope (de)serialization with mandatory structural validation
//! (`docs/FORMAT.md` §2). All integers little-endian.

use crate::constants::{
    COMMIT_LEN, ENVELOPE_MAGIC, ENVELOPE_VERSION, MAX_SLOT_COUNT, SLOT_FIXED_PREFIX_LEN,
    VAULT_ID_LEN, WRAP_ALGO_XCHACHA20_POLY1305,
};
use crate::error::{CryptoError, Result};

use super::model::{Envelope, Slot, WRAPPED_ROOT_LEN};

/// Envelope header before the slots: `magic(4)+ver(1)+vault_id(16)+slot_count(2)`.
const ENV_HEADER_LEN: usize = 4 + 1 + VAULT_ID_LEN + 2;

/// Serialize an envelope to its on-disk bytes.
pub fn serialize(env: &Envelope) -> Result<Vec<u8>> {
    if env.slots.is_empty() || env.slots.len() > MAX_SLOT_COUNT as usize {
        return Err(CryptoError::Format(
            "slot_count out of range (1..=64)".into(),
        ));
    }
    let mut out = Vec::with_capacity(ENV_HEADER_LEN + env.slots.len() * 128);
    out.extend_from_slice(&ENVELOPE_MAGIC);
    out.push(ENVELOPE_VERSION);
    out.extend_from_slice(&env.vault_id);
    out.extend_from_slice(&(env.slots.len() as u16).to_le_bytes());
    for slot in &env.slots {
        serialize_slot(slot, &mut out)?;
    }
    Ok(out)
}

fn serialize_slot(slot: &Slot, out: &mut Vec<u8>) -> Result<()> {
    let salt_len: u8 = slot
        .salt
        .len()
        .try_into()
        .map_err(|_| CryptoError::Format("slot salt too long".into()))?;
    let aux_len: u16 = slot
        .aux
        .len()
        .try_into()
        .map_err(|_| CryptoError::Format("slot aux too long".into()))?;
    let wrap_len: u16 = slot
        .wrapped_root
        .len()
        .try_into()
        .map_err(|_| CryptoError::Format("slot wrapped_root too long".into()))?;
    let slot_len = SLOT_FIXED_PREFIX_LEN
        .checked_add(salt_len as usize)
        .and_then(|v| v.checked_add(aux_len as usize))
        .and_then(|v| v.checked_add(wrap_len as usize))
        .ok_or_else(|| CryptoError::Format("slot_len overflow".into()))?;
    let slot_len: u32 = slot_len
        .try_into()
        .map_err(|_| CryptoError::Format("slot_len overflow".into()))?;

    out.extend_from_slice(&slot_len.to_le_bytes());
    out.push(slot.slot_type);
    out.push(slot.flags);
    out.push(slot.kdf_id);
    out.push(slot.wrap_algo);
    out.extend_from_slice(&slot.m_cost.to_le_bytes());
    out.extend_from_slice(&slot.t_cost.to_le_bytes());
    out.extend_from_slice(&slot.p_lanes.to_le_bytes());
    out.extend_from_slice(&slot.commit);
    out.push(salt_len);
    out.extend_from_slice(&slot.salt);
    out.extend_from_slice(&aux_len.to_le_bytes());
    out.extend_from_slice(&slot.aux);
    out.extend_from_slice(&wrap_len.to_le_bytes());
    out.extend_from_slice(&slot.wrapped_root);
    Ok(())
}

/// Parse envelope bytes, enforcing every §2 structural bound.
pub fn parse(bytes: &[u8]) -> Result<Envelope> {
    if bytes.len() < ENV_HEADER_LEN {
        return Err(CryptoError::Format("envelope too short".into()));
    }
    if bytes[0..4] != ENVELOPE_MAGIC {
        return Err(CryptoError::Format("bad envelope magic".into()));
    }
    if bytes[4] != ENVELOPE_VERSION {
        return Err(CryptoError::Format("unsupported envelope version".into()));
    }
    let mut vault_id = [0u8; VAULT_ID_LEN];
    vault_id.copy_from_slice(&bytes[5..5 + VAULT_ID_LEN]);
    let slot_count = u16::from_le_bytes([bytes[21], bytes[22]]);
    if slot_count == 0 || slot_count > MAX_SLOT_COUNT {
        return Err(CryptoError::Format(
            "slot_count out of range (1..=64)".into(),
        ));
    }

    let mut slots = Vec::with_capacity(slot_count as usize);
    let mut off = ENV_HEADER_LEN;
    for _ in 0..slot_count {
        let (slot, next) = parse_slot(bytes, off)?;
        slots.push(slot);
        off = next;
    }
    if off != bytes.len() {
        return Err(CryptoError::Format("trailing bytes after slots".into()));
    }
    Ok(Envelope { vault_id, slots })
}

fn parse_slot(bytes: &[u8], off: usize) -> Result<(Slot, usize)> {
    // Need at least the fixed prefix to read the length fields.
    let need_prefix = off
        .checked_add(SLOT_FIXED_PREFIX_LEN)
        .ok_or_else(|| CryptoError::Format("slot offset overflow".into()))?;
    if need_prefix > bytes.len() {
        return Err(CryptoError::Format("slot truncated (prefix)".into()));
    }
    let rd_u32 =
        |o: usize| u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
    let rd_u16 = |o: usize| u16::from_le_bytes([bytes[o], bytes[o + 1]]);

    let slot_len = rd_u32(off) as usize;
    let slot_type = bytes[off + 4];
    let flags = bytes[off + 5];
    let kdf_id = bytes[off + 6];
    let wrap_algo = bytes[off + 7];
    let m_cost = rd_u32(off + 8);
    let t_cost = rd_u32(off + 12);
    let p_lanes = rd_u32(off + 16);
    let mut commit = [0u8; COMMIT_LEN];
    commit.copy_from_slice(&bytes[off + 20..off + 52]);
    let salt_len = bytes[off + 52] as usize;

    // Field positions (relative to `off`): salt @53, aux_len @53+salt_len, aux @55+salt_len,
    // wrap_len @55+salt_len+aux_len, wrapped_root @57+salt_len+aux_len. Every position is
    // bounds-checked before slicing, and the frozen identity below rejects any overrun.
    let salt_start = off + 53;
    let aux_len_pos = off
        .checked_add(53)
        .and_then(|v| v.checked_add(salt_len))
        .ok_or_else(|| CryptoError::Format("slot salt overruns".into()))?;
    if aux_len_pos + 2 > bytes.len() {
        return Err(CryptoError::Format("slot truncated (aux_len)".into()));
    }
    let aux_len = rd_u16(aux_len_pos) as usize;
    let wrap_len_pos = aux_len_pos
        .checked_add(2)
        .and_then(|v| v.checked_add(aux_len))
        .ok_or_else(|| CryptoError::Format("slot aux overruns".into()))?;
    if wrap_len_pos + 2 > bytes.len() {
        return Err(CryptoError::Format("slot truncated (wrap_len)".into()));
    }
    let wrap_len = rd_u16(wrap_len_pos) as usize;

    // Frozen structural identity: slot_len == 57 + salt_len + aux_len + wrap_len.
    let expected = SLOT_FIXED_PREFIX_LEN
        .checked_add(salt_len)
        .and_then(|v| v.checked_add(aux_len))
        .and_then(|v| v.checked_add(wrap_len))
        .ok_or_else(|| CryptoError::Format("slot length overflow".into()))?;
    if slot_len != expected {
        return Err(CryptoError::Format(
            "slot_len != 57 + salt_len + aux_len + wrap_len".into(),
        ));
    }
    let slot_end = off
        .checked_add(slot_len)
        .ok_or_else(|| CryptoError::Format("slot end overflow".into()))?;
    if slot_end > bytes.len() {
        return Err(CryptoError::Format("slot overruns envelope".into()));
    }
    if wrap_algo == WRAP_ALGO_XCHACHA20_POLY1305 && wrap_len != WRAPPED_ROOT_LEN {
        return Err(CryptoError::Format(
            "wrap_len != 72 for XChaCha20-Poly1305 slot".into(),
        ));
    }

    let salt = bytes[salt_start..salt_start + salt_len].to_vec();
    let aux_start = aux_len_pos + 2;
    let aux = bytes[aux_start..aux_start + aux_len].to_vec();
    let wr_start = wrap_len_pos + 2;
    let wrapped_root = bytes[wr_start..wr_start + wrap_len].to_vec();

    Ok((
        Slot {
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
        },
        slot_end,
    ))
}
