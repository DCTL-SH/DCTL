//! Random key generation (root key and per-file DEKs).

use zeroize::Zeroizing;

use crate::constants::KEY_LEN;
use crate::rng;

/// Generate a random 32-byte key (root key or per-file DEK), wiped on drop.
#[must_use]
pub fn generate_key() -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    rng::fill(key.as_mut());
    key
}
