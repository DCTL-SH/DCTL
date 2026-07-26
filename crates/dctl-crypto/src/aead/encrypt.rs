//! Authenticated encryption of a single blob.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::constants::{KEY_LEN, NONCE_LEN};
use crate::error::{CryptoError, Result};
use crate::rng;

/// Encrypt `plaintext` under `key`, binding `aad`.
///
/// Output layout: `nonce(24) ‖ ciphertext ‖ tag(16)`. A fresh random nonce is
/// generated per call; XChaCha20's 192-bit nonce makes random nonces safe.
///
/// Callers must pass a non-empty, identity-specific `aad`.
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::Aead)?;

    let mut nonce = [0u8; NONCE_LEN];
    rng::fill(&mut nonce);

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}
