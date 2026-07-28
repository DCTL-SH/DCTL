//! DSF1 fixed 68-byte head: build, parse, structural validation (§3).

use crate::constants::{
    ALGO_XCHACHA20_POLY1305, FLAG_FOOTER, KEM_ID_HYBRID, KEM_ID_NONE, MAX_CHUNK_SIZE, NONCE_LEN,
    OBJECT_HEAD_LEN, OBJECT_MAGIC, OBJECT_VERSION,
};
use crate::error::{CryptoError, Result};

/// The fixed head — folded verbatim into every object AAD (DEK wrap, metadata, chunks).
#[derive(Clone)]
pub struct Head {
    pub algo: u8,
    pub kem_id: u8,
    pub flags: u8,
    pub chunk_size: u32,
    pub plaintext_len: u64,
    pub chunk_count: u64,
    pub base_nonce: [u8; NONCE_LEN],
    pub file_id: [u8; 16],
}

impl Head {
    /// Whether a whole-object BLAKE3 footer is present.
    #[must_use]
    pub const fn has_footer(&self) -> bool {
        self.flags & FLAG_FOOTER != 0
    }
}

/// Serialize a head to its 68 on-disk bytes.
pub fn build_head(h: &Head) -> [u8; OBJECT_HEAD_LEN] {
    let mut out = [0u8; OBJECT_HEAD_LEN];
    out[0..4].copy_from_slice(&OBJECT_MAGIC);
    out[4] = OBJECT_VERSION;
    out[5] = h.algo;
    out[6] = h.kem_id;
    out[7] = h.flags;
    out[8..12].copy_from_slice(&h.chunk_size.to_le_bytes());
    out[12..20].copy_from_slice(&h.plaintext_len.to_le_bytes());
    out[20..28].copy_from_slice(&h.chunk_count.to_le_bytes());
    out[28..52].copy_from_slice(&h.base_nonce);
    out[52..68].copy_from_slice(&h.file_id);
    out
}

/// Parse and structurally validate a head from the object's leading bytes (§3).
pub fn parse_head(bytes: &[u8]) -> Result<Head> {
    if bytes.len() < OBJECT_HEAD_LEN {
        return Err(CryptoError::Format("object shorter than head".into()));
    }
    if bytes[0..4] != OBJECT_MAGIC {
        return Err(CryptoError::Format("bad object magic".into()));
    }
    if bytes[4] != OBJECT_VERSION {
        return Err(CryptoError::Format("unsupported object version".into()));
    }
    let algo = bytes[5];
    if algo != ALGO_XCHACHA20_POLY1305 {
        return Err(CryptoError::Format("unsupported algo".into()));
    }
    let kem_id = bytes[6];
    if kem_id != KEM_ID_NONE && kem_id != KEM_ID_HYBRID {
        return Err(CryptoError::Format("unsupported kem_id".into()));
    }
    let flags = bytes[7];
    // Only the FOOTER bit is defined; every other bit is CRITICAL → reject if set (§8).
    if flags & !FLAG_FOOTER != 0 {
        return Err(CryptoError::Format("unknown critical object flag".into()));
    }
    let chunk_size = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(CryptoError::Format("chunk_size out of range".into()));
    }
    let plaintext_len = read_u64(&bytes[12..20])?;
    let chunk_count = read_u64(&bytes[20..28])?;
    if chunk_count != plaintext_len.div_ceil(chunk_size as u64) {
        return Err(CryptoError::Format(
            "chunk_count != ceil(plaintext_len/chunk_size)".into(),
        ));
    }
    let mut base_nonce = [0u8; NONCE_LEN];
    base_nonce.copy_from_slice(&bytes[28..52]);
    let mut file_id = [0u8; 16];
    file_id.copy_from_slice(&bytes[52..68]);
    Ok(Head {
        algo,
        kem_id,
        flags,
        chunk_size,
        plaintext_len,
        chunk_count,
        base_nonce,
        file_id,
    })
}

fn read_u64(b: &[u8]) -> Result<u64> {
    let arr: [u8; 8] = b
        .try_into()
        .map_err(|_| CryptoError::Format("bad u64 field".into()))?;
    Ok(u64::from_le_bytes(arr))
}
