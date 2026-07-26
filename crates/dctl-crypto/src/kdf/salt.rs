//! Argon2id salt generation.

use crate::constants::DEFAULT_SALT_LEN;
use crate::rng;

/// Fresh random Argon2id salt.
#[must_use]
pub fn generate_salt() -> [u8; DEFAULT_SALT_LEN] {
    let mut salt = [0u8; DEFAULT_SALT_LEN];
    rng::fill(&mut salt);
    salt
}
