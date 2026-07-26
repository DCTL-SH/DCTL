//! AEAD with a caller-supplied nonce, returning detached `ct ‖ tag` (no nonce
//! prefix). Used by the DSF1 object layer, whose chunk nonces are counter-derived
//! and whose metadata nonce is domain-marked — never random-per-call.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

use crate::constants::{KEY_LEN, NONCE_LEN, TAG_LEN};
use crate::error::{CryptoError, Result};

/// Encrypt with an explicit `nonce`; returns `ciphertext ‖ tag` (nonce NOT prepended).
pub fn encrypt_with_nonce(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::Aead)?;
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

/// Decrypt `ciphertext ‖ tag` with an explicit `nonce`; verifies `aad`.
pub fn decrypt_with_nonce(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ct_and_tag: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if ct_and_tag.len() < TAG_LEN {
        return Err(CryptoError::Format("aead ciphertext too short".into()));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::Aead)?;
    let pt = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct_and_tag,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)?;
    Ok(Zeroizing::new(pt))
}
