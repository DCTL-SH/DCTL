//! Bakes this build's Argon2id cost decision into the crate as generated source.
//!
//! The reasoning — why the cost depends on the Cargo profile, and why nothing
//! reachable from a command line, an environment variable or a `cfg` is allowed
//! to influence it — lives in `src/kdf/gate.rs`, which this script compiles as a
//! module so that the rule has exactly one definition in the tree.

#[path = "src/kdf/gate.rs"]
mod gate;

use std::error::Error;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    // The gate *is* the security property. A change to either file has to
    // re-run this script, or a stale constant survives in `OUT_DIR` and the
    // built crate no longer matches the rule that is in the tree.
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=src/kdf/gate.rs");

    let profile = std::env::var("PROFILE").ok();
    let production = gate::writes_production_cost(profile.as_deref());

    if !production {
        // Printed on every build of a non-shipped profile, and there is no flag
        // that silences it. Whoever built this is told, before they ever run
        // the binary, that vaults it creates are cheap to open — which is the
        // one thing a person compiling from source needs to know and the one
        // thing a reduced-cost build must never be quiet about.
        println!(
            "cargo::warning=dctl-crypto: this is a '{}' build, not '{}' — new vaults are \
             written with the REDUCED test Argon2id cost and must not hold real data. Build \
             with --release for the shipped cost.",
            profile.as_deref().unwrap_or(gate::CARGO_DEBUG_PROFILE),
            gate::CARGO_RELEASE_PROFILE,
        );
    }

    let out_dir = std::env::var_os("OUT_DIR")
        .ok_or("OUT_DIR is unset; this file only runs as a Cargo build script")?;
    let generated = PathBuf::from(out_dir).join(gate::GENERATED_FILE);
    std::fs::write(&generated, gate::generated_source(production))?;
    Ok(())
}
