//! Central OS CSPRNG access.
//!
//! Every random byte in the crate (salts, nonces, keys, file ids) comes through
//! here, so there is a single, auditable entropy source and no RNG calls
//! scattered across modules.

/// Fill `buf` with cryptographically secure random bytes from the OS CSPRNG.
///
/// # Panics
/// Panics if the OS RNG is unavailable. For a crypto tool this is unrecoverable —
/// we must never proceed with predictable keys, nonces, or salts. This is the one
/// audited exception to the crate-wide no-panic policy.
#[allow(clippy::expect_used)]
pub fn fill(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS CSPRNG unavailable");
}
