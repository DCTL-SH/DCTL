//! XChaCha20-Poly1305 single-shot AEAD with mandatory context-binding AAD.
//!
//! Every encrypted blob in DCTL is bound to its identity via `aad`, so a
//! ciphertext produced for one context cannot be substituted into another that
//! shares the same key. Used for wrapping the root key (envelope), wrapping
//! per-file DEKs, and small metadata blobs. Bulk payloads use [`crate::stream`].

mod decrypt;
mod encrypt;
mod raw;

pub use crate::constants::{NONCE_LEN, TAG_LEN};
pub use decrypt::decrypt;
pub use encrypt::encrypt;
pub use raw::{decrypt_with_nonce, encrypt_with_nonce};
