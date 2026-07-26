//! §5 name records — the authoritative, rewritable path→object map.
//!
//! The public backend key is `"n/" ‖ hex(BLAKE3_keyed(name-hash-key, NFC(path)))`; the
//! value AEAD-encrypts `file_id ‖ metadata_gen ‖ path` under a *separate* name-value-key
//! (so publishing `n/*` keys never exposes value-encryption material). A fresh CSPRNG
//! nonce is used on every write (records are rewritten in place on rename), and the AAD
//! binds the record to its own key and the vault. Rename is a single O(1) rewrite; the
//! content object is never touched.

use zeroize::Zeroizing;

use crate::aead;
use crate::constants::{
    INFO_NAME_HASH, INFO_NAME_VALUE, KEY_LEN, NAME_AAD_PREFIX, NAME_KEY_PREFIX,
};
use crate::error::{CryptoError, Result};
use crate::keys::derive_subkey;

/// Fixed value-plaintext prefix: `file_id(16) ‖ metadata_gen(8) ‖ path_len(2)`.
const VALUE_FIXED_PREFIX: usize = 16 + 8 + 2;

/// The two name-layer sub-keys derived from the vault root.
pub struct NameKeys {
    hash_key: Zeroizing<[u8; KEY_LEN]>,
    value_key: Zeroizing<[u8; KEY_LEN]>,
}

/// A decoded name record: the authoritative mapping for one path.
#[derive(Clone, Debug)]
pub struct NameRecord {
    pub file_id: [u8; 16],
    pub metadata_gen: u64,
    pub path: String,
}

impl NameKeys {
    /// Derive the name-hash / name-value sub-keys from the vault root.
    pub fn derive(root: &[u8; KEY_LEN]) -> Result<Self> {
        Ok(Self {
            hash_key: derive_subkey(root, INFO_NAME_HASH)?,
            value_key: derive_subkey(root, INFO_NAME_VALUE)?,
        })
    }

    /// Public backend object key for `nfc_path`:
    /// `"n/" ‖ hex(BLAKE3_keyed(name-hash-key, NFC(path)))`.
    #[must_use]
    pub fn record_key(&self, nfc_path: &str) -> String {
        let h = blake3::keyed_hash(&self.hash_key, nfc_path.as_bytes());
        format!("{NAME_KEY_PREFIX}{}", hex::encode(h.as_bytes()))
    }

    /// Seal a name record value for `nfc_path` → `file_id`/`metadata_gen`.
    /// Output = `nonce(24) ‖ ct ‖ tag(16)` with a fresh CSPRNG nonce.
    pub fn seal_record(
        &self,
        vault_id: &[u8; 16],
        nfc_path: &str,
        file_id: &[u8; 16],
        metadata_gen: u64,
    ) -> Result<(String, Vec<u8>)> {
        let key = self.record_key(nfc_path);
        let path_len: u16 = nfc_path
            .len()
            .try_into()
            .map_err(|_| CryptoError::Format("name path too long".into()))?;
        let mut pt = Vec::with_capacity(VALUE_FIXED_PREFIX + nfc_path.len());
        pt.extend_from_slice(file_id);
        pt.extend_from_slice(&metadata_gen.to_le_bytes());
        pt.extend_from_slice(&path_len.to_le_bytes());
        pt.extend_from_slice(nfc_path.as_bytes());
        let aad = name_aad(vault_id, key.as_bytes());
        let value = aead::encrypt(&self.value_key, &pt, &aad)?;
        Ok((key, value))
    }

    /// Open a name record, verifying rename-safe self-consistency: the record's own
    /// stored path MUST hash back to `record_key` (§5) — rejecting a corrupt or
    /// transplanted record. Returns the authoritative `{file_id, metadata_gen, path}`.
    pub fn open_record(
        &self,
        vault_id: &[u8; 16],
        record_key: &str,
        value: &[u8],
    ) -> Result<NameRecord> {
        let aad = name_aad(vault_id, record_key.as_bytes());
        let pt = aead::decrypt(&self.value_key, value, &aad)?;
        if pt.len() < VALUE_FIXED_PREFIX {
            return Err(CryptoError::Format("name record too short".into()));
        }
        let mut file_id = [0u8; 16];
        file_id.copy_from_slice(&pt[0..16]);
        let metadata_gen = u64::from_le_bytes(
            pt[16..24]
                .try_into()
                .map_err(|_| CryptoError::Format("bad metadata_gen".into()))?,
        );
        let path_len = u16::from_le_bytes([pt[24], pt[25]]) as usize;
        if VALUE_FIXED_PREFIX + path_len != pt.len() {
            return Err(CryptoError::Format("name record length mismatch".into()));
        }
        let path = String::from_utf8(pt[VALUE_FIXED_PREFIX..].to_vec())
            .map_err(|_| CryptoError::Format("name path not UTF-8".into()))?;
        // Rename-safe rebuild check: the stored path must hash to the key it was under.
        if self.record_key(&path) != record_key {
            return Err(CryptoError::Format(
                "name record path does not match its key (corrupt/transplanted)".into(),
            ));
        }
        Ok(NameRecord {
            file_id,
            metadata_gen,
            path,
        })
    }
}

/// Name-record value AAD: `"dctl-name-v1::" ‖ vault_id ‖ key_bytes`.
fn name_aad(vault_id: &[u8; 16], key_bytes: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(NAME_AAD_PREFIX.len() + vault_id.len() + key_bytes.len());
    a.extend_from_slice(NAME_AAD_PREFIX);
    a.extend_from_slice(vault_id);
    a.extend_from_slice(key_bytes);
    a
}
