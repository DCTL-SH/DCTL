//! Prints the Argon2id cost this build of `dctl-crypto` writes into a new vault.
//!
//! It exists to be compiled with `--release` and run, by
//! `tests/kdf_cost.rs::a_release_build_writes_the_production_cost`. A test can
//! assert plenty about the gate from inside the debug build it runs in, but the
//! claim that matters — *a shipped build cannot reach the reduced cost* — is a
//! claim about a **release binary**, and the only way to settle it is to build
//! one and ask it.
//!
//! Four whitespace-separated fields on one line: `m_cost t_cost p_lanes
//! is_production`.

fn main() {
    let cost = dctl_crypto::kdf::Cost::shipped();
    println!(
        "{} {} {} {}",
        cost.m_cost,
        cost.t_cost,
        cost.p_lanes,
        dctl_crypto::kdf::Cost::is_production()
    );
}
