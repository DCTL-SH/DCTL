//! HKDF-SHA512 domain-separated sub-key derivation from the root key.

use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::constants::KEY_LEN;
use crate::error::{CryptoError, Result};

/// Derive a domain-separated 32-byte sub-key from the root key under `info`.
pub fn derive_subkey(root: &[u8; KEY_LEN], info: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    derive_subkey_from_ikm(root, info)
}

/// The pinned §1 `SUBKEY` construction with an arbitrary-length IKM and `info`.
///
/// This is the **same** RFC 5869 HKDF-SHA512 (salt = 64 zero bytes = `None`,
/// Extract-then-Expand, L = 32) that [`derive_subkey`] performs — the only difference
/// is that `ikm` need not be a 32-byte key. The §12 hybrid combiner (§12.1) needs it:
/// its IKM is `ss_x(32) ‖ K_m(32)` (64 bytes) and its `info` is the full 2471-byte KEM
/// transcript. Keeping a single implementation guarantees the two paths stay bit-for-bit
/// identical to the frozen spec.
pub fn derive_subkey_from_ikm(ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    // `new(None, ikm)` performs HKDF-Extract with the all-zero HashLen (64-byte) salt.
    let hkdf = Hkdf::<Sha512>::new(None, ikm);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(info, out.as_mut())
        .map_err(|_| CryptoError::Hkdf)?;
    Ok(out)
}
