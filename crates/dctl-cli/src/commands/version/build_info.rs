//! What this binary knows about how it was built.
//!
//! Everything here is decided at **compile time** and costs nothing to read: no
//! file is opened, no process is spawned, no environment variable is consulted
//! at run time. That is the whole reason the module exists as its own file —
//! `dctl version` has to work on a machine where the config is unreadable, the
//! network is down and the vault will not unlock, so it must not depend on
//! anything that could fail.
//!
//! ## Where the values come from
//!
//! [`VERSION`], [`ARCH`] and [`debug_assertions`] are known to the compiler
//! directly. The rest — the commit, the compiler, the target triple, the profile
//! and the feature list — are not discoverable from inside a running process at
//! all, so `build.rs` learns them while the crate is being built and passes them
//! in as compile-time environment variables.
//!
//! ## Absent is a real answer
//!
//! Every stamped value is an `Option`, and a missing one is reported as missing.
//! A build from a source tarball has no git hash; a builder with no `git` on
//! `PATH` cannot find one either. Both are ordinary, and both must produce a
//! visible gap rather than a plausible-looking value — a wrong commit hash in a
//! bug report is believed, and then costs somebody an afternoon.
//!
//! Blank values are treated as absent for the same reason. `option_env!` reads
//! the environment of the *compiler* invocation, not just what `build.rs`
//! emitted, so an exported-but-empty `DCTL_BUILD_GIT_HASH` in someone's shell
//! would otherwise become an empty string in the report.

use crate::constants::BUILD_FEATURE_SEPARATOR;

/// This crate's version, as `Cargo.toml` spells it.
///
/// The one fact that is always present, and the one a user is asked for first.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// CPU architecture this binary runs on (`x86_64`, `aarch64`).
///
/// Available from the standard library, unlike the full target triple: the
/// vendor and ABI halves of `x86_64-unknown-linux-musl` are not exposed at run
/// time, which is why [`target`] is stamped rather than assembled.
pub const ARCH: &str = std::env::consts::ARCH;

// The raw stamps. Private, because a caller must go through the accessors that
// normalise a blank value away; a `pub const` would let one leak.
const GIT_HASH: Option<&str> = option_env!("DCTL_BUILD_GIT_HASH");
const RUSTC: Option<&str> = option_env!("DCTL_BUILD_RUSTC");
const TARGET: Option<&str> = option_env!("DCTL_BUILD_TARGET");
const PROFILE: Option<&str> = option_env!("DCTL_BUILD_PROFILE");
const FEATURES: Option<&str> = option_env!("DCTL_BUILD_FEATURES");

/// The commit this build came from, abbreviated.
#[must_use]
pub fn git_hash() -> Option<&'static str> {
    present(GIT_HASH)
}

/// The compiler that produced this binary, as `rustc --version` reports it.
#[must_use]
pub fn rustc() -> Option<&'static str> {
    present(RUSTC)
}

/// The target triple this binary was built for.
#[must_use]
pub fn target() -> Option<&'static str> {
    present(TARGET)
}

/// The cargo profile this binary was built under (`debug`, `release`).
#[must_use]
pub fn profile() -> Option<&'static str> {
    present(PROFILE)
}

/// Whether debug assertions are compiled in.
///
/// Worth reporting on its own, beside [`profile`]: a custom profile can enable
/// them in a release build, and a binary that is checking its own invariants
/// behaves and performs differently from one that is not.
#[must_use]
pub const fn debug_assertions() -> bool {
    cfg!(debug_assertions)
}

/// The cargo features this build enabled, in the order `build.rs` sorted them.
///
/// Empty in a default build, because this crate declares no optional features
/// today. The field exists so that the day one is added — a FUSE mount, a
/// provider behind a flag — it appears in every bug report without anyone having
/// to remember to put it there.
#[must_use]
pub fn features() -> Vec<&'static str> {
    present(FEATURES)
        .map(|list| {
            list.split(BUILD_FEATURE_SEPARATOR)
                .map(str::trim)
                .filter(|feature| !feature.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Treat a blank stamp as no stamp at all.
fn present(value: Option<&'static str>) -> Option<&'static str> {
    value
        .map(str::trim)
        .filter(|value: &&'static str| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        BUILD_ENV_FEATURES, BUILD_ENV_GIT_HASH, BUILD_ENV_PROFILE, BUILD_ENV_RUSTC,
        BUILD_ENV_TARGET,
    };

    #[test]
    fn the_stamp_names_match_the_documented_contract() {
        // `option_env!` demands a string literal, so each variable name is
        // spelled once in `constants` (the contract), once in `build.rs` (the
        // producer) and once above (the consumer). This is the joint that keeps
        // the three from drifting: rename the constant and the assertion fails.
        assert_eq!(BUILD_ENV_GIT_HASH, "DCTL_BUILD_GIT_HASH");
        assert_eq!(BUILD_ENV_RUSTC, "DCTL_BUILD_RUSTC");
        assert_eq!(BUILD_ENV_TARGET, "DCTL_BUILD_TARGET");
        assert_eq!(BUILD_ENV_PROFILE, "DCTL_BUILD_PROFILE");
        assert_eq!(BUILD_ENV_FEATURES, "DCTL_BUILD_FEATURES");
    }

    #[test]
    fn the_version_is_always_known() {
        // The one value that cannot be missing: it comes from the manifest the
        // crate was compiled from.
        assert!(!VERSION.is_empty());
        assert!(VERSION.chars().next().is_some_and(|c| c.is_ascii_digit()));
    }

    #[test]
    fn the_architecture_is_always_known() {
        assert!(!ARCH.is_empty());
    }

    #[test]
    fn the_build_script_stamps_the_target_and_the_compiler() {
        // These two are produced by `build.rs` from cargo's own `TARGET` and
        // from the `RUSTC` cargo is driving, so their absence means the build
        // script did not run — which would silently hollow out `dctl version`.
        assert!(target().is_some(), "the target triple was not stamped");
        assert!(rustc().is_some(), "the compiler version was not stamped");
        assert!(profile().is_some(), "the cargo profile was not stamped");
    }

    #[test]
    fn a_stamped_value_never_comes_back_blank() {
        // The normalisation that keeps an exported-but-empty variable from
        // rendering as an empty cell in the report.
        assert_eq!(present(Some("")), None);
        assert_eq!(present(Some("   ")), None);
        assert_eq!(present(None), None);
        assert_eq!(present(Some("  abc  ")), Some("abc"));
    }

    #[test]
    fn every_reported_value_is_trimmed_and_non_empty() {
        for value in [git_hash(), rustc(), target(), profile()]
            .into_iter()
            .flatten()
        {
            assert_eq!(value, value.trim());
            assert!(!value.is_empty());
        }
    }

    #[test]
    fn the_feature_list_never_contains_an_empty_name() {
        // A trailing separator in the stamp would otherwise produce a nameless
        // feature in the JSON array.
        for feature in features() {
            assert!(!feature.is_empty());
            assert!(!feature.contains(BUILD_FEATURE_SEPARATOR));
        }
    }

    #[test]
    fn debug_assertions_are_reported_as_the_compiler_sees_them() {
        // Tests run with them on; asserting the identity keeps the accessor from
        // being quietly inverted.
        assert_eq!(debug_assertions(), cfg!(debug_assertions));
        assert!(debug_assertions(), "the test profile has them enabled");
    }
}
