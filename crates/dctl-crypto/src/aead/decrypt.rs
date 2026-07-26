//! Authenticated decryption of a single blob.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

use crate::constants::{KEY_LEN, NONCE_LEN, TAG_LEN};
use crate::error::{CryptoError, Result};

/// Decrypt a `nonce ‖ ciphertext ‖ tag` blob under `key`, verifying `aad`.
///
/// Returns the plaintext in a `Zeroizing<Vec<u8>>` (wiped on drop, incl. panic
/// unwind). A wrong key, tampered bytes, or mismatched `aad` all surface as the
/// same [`CryptoError::Aead`] — no oracle.
pub fn decrypt(key: &[u8; KEY_LEN], blob: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::Format("aead blob too short".into()));
    }
    let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::Aead)?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)?;
    Ok(Zeroizing::new(plaintext))
}
