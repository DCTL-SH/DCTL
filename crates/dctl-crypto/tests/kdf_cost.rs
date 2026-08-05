//! The reduced Argon2id cost must be unreachable in anything that ships.
//!
//! DCTL's test suite writes and opens hundreds of vaults per run, and at the
//! shipped cost — 128 MiB, three passes — that is minutes of Argon2id per test
//! file. So a non-shipped build writes the frozen §2 floor instead, and every
//! assertion survives untouched because an envelope carries the parameters it
//! was written with.
//!
//! The whole design therefore rests on one claim, and it is a security claim
//! rather than a convenience one: **a released DCTL cannot be made to write the
//! reduced cost.** A vault created under it is permanently brute-forceable and
//! looks entirely ordinary — same commands, same output, no warning ever again
//! — so "unlikely" is not good enough and neither is "you would have to pass a
//! flag".
//!
//! This file takes that claim apart into the things that have to be true and
//! checks each one where it can actually fail:
//!
//! | What is checked | How it could fail |
//! |---|---|
//! | the gate's rule | someone widens it, or makes it fail *open* on an unknown profile |
//! | the contract between `build.rs` and `kdf::cost` | the generated constant is renamed on one side only |
//! | Cargo's `PROFILE` really is `release`, and really cannot be talked out of it | a future Cargo lets the environment or `RUSTFLAGS` influence it |
//! | an actual release build | anything at all, end to end — this is the one that answers the claim |
//! | the second, independent `debug_assertions` gate | the pair is reduced to one input |
//!
//! The `PROFILE` tests build a throwaway crate of their own rather than reason
//! about Cargo from the outside. It has no dependencies, so all three builds
//! together cost about a second, and they fail loudly if Cargo ever changes the
//! behaviour this design is standing on.

use std::path::{Path, PathBuf};
use std::process::Command;

use dctl_crypto::constants::{
    DEFAULT_ARGON2_M_COST, DEFAULT_ARGON2_P_LANES, DEFAULT_ARGON2_T_COST, TEST_ARGON2_M_COST,
    TEST_ARGON2_P_LANES, TEST_ARGON2_T_COST,
};
use dctl_crypto::kdf::{self, Cost, gate};
use tempfile::TempDir;

// ── the rule itself ──────────────────────────────────────────────────────────

#[test]
fn only_cargos_debug_profile_turns_the_production_cost_off() {
    assert!(!gate::writes_production_cost(Some(
        gate::CARGO_DEBUG_PROFILE
    )));
    assert!(gate::writes_production_cost(Some(
        gate::CARGO_RELEASE_PROFILE
    )));
}

#[test]
fn the_gate_fails_closed_on_anything_it_does_not_recognise() {
    // The two failure directions are not symmetric. Guessing "shipped" when the
    // build was a test one costs a slow suite; guessing "test" when the build
    // was a shipped one costs every vault it creates. So everything that is not
    // literally Cargo's word for an unoptimized build has to come out
    // production — including a profile name a future Cargo invents, a differently
    // cased one, and no answer at all.
    for unknown in [
        None,
        Some(""),
        Some("Debug"),
        Some("DEBUG"),
        Some("dev"),
        Some("test"),
        Some("bench"),
        Some("release-with-debug"),
        Some("dist"),
    ] {
        assert!(
            gate::writes_production_cost(unknown),
            "an unrecognised profile {unknown:?} must be treated as a shipped build"
        );
    }
}

#[test]
fn the_generated_source_declares_the_constant_the_crate_includes() {
    // `build.rs` writes this and `kdf::cost` includes it: two files agreeing on
    // one identifier, with the compiler unable to warn about a rename on one
    // side because the other side is a string. If they ever disagree the crate
    // stops building, but it stops building with "cannot find value
    // WRITES_PRODUCTION_COST", which is a long way from the reason.
    for production in [true, false] {
        let source = gate::generated_source(production);
        assert!(
            source.contains(&format!(
                "const {}: bool = {production};",
                gate::GENERATED_CONST
            )),
            "generated source does not declare the expected constant:\n{source}"
        );
    }
}

// ── the external fact the whole design rests on ──────────────────────────────

#[test]
fn cargo_reports_release_for_a_release_build_and_ignores_an_environment_that_disagrees() {
    assert_eq!(
        profile_reported_for(&["--release"], &[]),
        gate::CARGO_RELEASE_PROFILE,
        "a --release build must report the release profile"
    );

    // The reason `PROFILE` was chosen over every settable mechanism: Cargo
    // computes it and does not let the caller's environment supply it. If that
    // ever stops being true, the gate has an input a mistaken CI job — or a
    // malicious one — can reach, and this test is where it is noticed.
    assert_eq!(
        profile_reported_for(&["--release"], &[("PROFILE", gate::CARGO_DEBUG_PROFILE)]),
        gate::CARGO_RELEASE_PROFILE,
        "exporting PROFILE must not change what Cargo reports to a build script"
    );

    // `cfg(debug_assertions)` alone would have been defeated by exactly this,
    // which is why it is the *second* gate rather than the only one.
    assert_eq!(
        profile_reported_for(&["--release"], &[("RUSTFLAGS", "-C debug-assertions=on")]),
        gate::CARGO_RELEASE_PROFILE,
        "forcing debug assertions on must not make a release build look like a debug one"
    );

    // And the other direction, or the suite would be slow for no reason.
    assert_eq!(
        profile_reported_for(&[], &[]),
        gate::CARGO_DEBUG_PROFILE,
        "an ordinary `cargo build` must report the debug profile"
    );
}

/// Build a throwaway crate and return the `PROFILE` its build script was handed.
///
/// Built rather than reasoned about: the claim is about Cargo's behaviour, and
/// the only witness to Cargo's behaviour is Cargo. The crate has no
/// dependencies, so a build is a fraction of a second.
///
/// A **fresh** directory every time, which is not fussiness. Cargo does not
/// re-run a build script when only the environment around it changed — it did
/// not consider `PROFILE=debug` a reason to rebuild at all, which is its own
/// small piece of evidence that Cargo does not read that variable. Reusing one
/// directory would therefore have had the second and third calls silently
/// re-reading the first one's answer, and the test would have passed without
/// ever asking the question.
fn profile_reported_for(args: &[&str], env: &[(&str, &str)]) -> String {
    let dir = TempDir::new().expect("a temporary directory");
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).expect("create src");
    // `[workspace]` detaches the probe from any workspace the temporary
    // directory might sit inside, so it cannot inherit a profile table.
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\n\
         [package]\n\
         name = \"dctl-profile-probe\"\n\
         version = \"0.0.0\"\n\
         edition = \"2021\"\n\
         build = \"build.rs\"\n",
    )
    .expect("write Cargo.toml");
    std::fs::write(
        root.join("build.rs"),
        "fn main() {\n\
         \x20   let seen = std::env::var(\"PROFILE\").unwrap_or_default();\n\
         \x20   std::fs::write(\"profile-seen.txt\", seen).unwrap();\n\
         }\n",
    )
    .expect("write build.rs");
    std::fs::write(root.join("src/lib.rs"), "").expect("write src/lib.rs");

    let mut cargo = Command::new(cargo_binary());
    cargo
        .current_dir(root)
        .arg("build")
        .args(args)
        // Its own target directory, and none of the outer build's flags: a probe
        // that inherited `CARGO_TARGET_DIR` would write into the workspace's,
        // and one that inherited `CARGO_ENCODED_RUSTFLAGS` would not be testing
        // what this test says it tests.
        .env("CARGO_TARGET_DIR", root.join("target"))
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS");
    for (key, value) in env {
        cargo.env(key, value);
    }
    let output = cargo.output().expect("cargo runs");
    assert!(
        output.status.success(),
        "probe build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    std::fs::read_to_string(root.join("profile-seen.txt")).unwrap_or_else(|error| {
        panic!(
            "the probe's build script recorded no profile ({error}); cargo said:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// The Cargo that is running this test, or the one on `PATH`.
fn cargo_binary() -> PathBuf {
    std::env::var_os("CARGO").map_or_else(|| PathBuf::from("cargo"), PathBuf::from)
}

// ── the claim itself, against a real release build ───────────────────────────

#[test]
fn a_release_build_writes_the_production_cost() {
    // Everything above checks a piece. This checks the product: an optimized
    // build of this very crate, compiled the way a release is compiled, asked
    // what cost it would write. Delete the profile check from `build.rs` and
    // this is the test that goes red.
    //
    // It shares the workspace target directory on purpose — the release
    // artifacts are then reused between runs, so this costs a one-off compile
    // and effectively nothing afterwards.
    let mut cargo = Command::new(cargo_binary());
    cargo
        .current_dir(workspace_root())
        .args([
            "build",
            "--release",
            "--quiet",
            "-p",
            "dctl-crypto",
            "--example",
            "kdf_cost_probe",
        ])
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS");
    let build = cargo.output().expect("cargo runs");
    assert!(
        build.status.success(),
        "release build of the probe failed:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );

    let probe = workspace_root().join("target/release/examples/kdf_cost_probe");
    let output = Command::new(&probe).output().expect("the probe runs");
    let printed = String::from_utf8_lossy(&output.stdout).trim().to_string();

    assert_eq!(
        printed,
        format!(
            "{} {} {} true",
            Cost::PRODUCTION.m_cost,
            Cost::PRODUCTION.t_cost,
            Cost::PRODUCTION.p_lanes
        ),
        "a release build must write the production Argon2id cost"
    );
}

/// The workspace root, from this crate's manifest directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .expect("dctl-crypto sits two levels below the workspace root")
}

// ── the second gate, and the properties of the two costs ─────────────────────

#[test]
fn the_reduced_cost_also_requires_debug_assertions() {
    // The runtime face of the `const _: () = assert!(…)` in `kdf::cost`. Two
    // independent signals have to agree before the reduced cost is compiled in:
    // Cargo's profile, which the environment cannot touch, and the compiler's
    // own view of the build, which `RUSTFLAGS` can. Neither alone is enough, so
    // neither alone can be turned against the vault.
    assert!(
        Cost::is_production() || cfg!(debug_assertions),
        "a build without debug assertions reached the reduced cost"
    );
}

#[test]
fn the_production_cost_is_the_one_the_format_document_publishes() {
    // `crates/dctl-decode/FORMAT.md` §2.1 prints these three numbers in its worked example,
    // and `dctl-core`'s conformance test asserts an envelope carries them. This is the other
    // half of that: the figures the product ships are the figures the document names.
    assert_eq!(
        Cost::PRODUCTION,
        Cost {
            m_cost: DEFAULT_ARGON2_M_COST,
            t_cost: DEFAULT_ARGON2_T_COST,
            p_lanes: DEFAULT_ARGON2_P_LANES,
        }
    );
    assert_eq!(Cost::PRODUCTION.m_cost, 131_072);
    assert_eq!(Cost::PRODUCTION.t_cost, 3);
    assert_eq!(Cost::PRODUCTION.p_lanes, 4);
}

#[test]
fn whichever_cost_this_build_ships_is_a_legal_one_that_really_derives_a_key() {
    // The reduced cost sits on the frozen §2 floor, and a floor is exactly where
    // an off-by-one lives: one less and Argon2id refuses the parameters, and the
    // suite would be proving things about envelopes no decoder would accept.
    let cost = Cost::shipped();
    cost.validate()
        .expect("the shipped cost is within the §2 ceilings");

    let salt = kdf::generate_salt();
    let key =
        kdf::derive_kek("a passphrase", None, &salt, cost).expect("the shipped cost derives a key");
    assert_ne!(*key, [0u8; 32]);

    // And it is one of exactly two values — never something a caller supplied.
    let reduced = Cost {
        m_cost: TEST_ARGON2_M_COST,
        t_cost: TEST_ARGON2_T_COST,
        p_lanes: TEST_ARGON2_P_LANES,
    };
    assert!(
        cost == Cost::PRODUCTION || cost == reduced,
        "the shipped cost must be one of the two the gate can select, got {cost:?}"
    );
}
