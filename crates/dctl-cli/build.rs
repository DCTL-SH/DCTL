//! Build-time stamping for `dctl version`.
//!
//! Three of the facts a bug report needs — which commit the binary came from,
//! which compiler produced it, and which target it was built for — are simply
//! not discoverable from inside a running process. They are known at *build*
//! time and nowhere else, so this script learns them and hands them to the crate
//! as compile-time environment variables that
//! `crate::commands::version::build_info` reads with `option_env!`.
//!
//! ## Why the crate carries a build script at all
//!
//! `dctl version` is the first thing someone runs when something is wrong, and
//! the answer "0.0.1" on its own does not identify a binary. Two builds of the
//! same version number from different commits, or from different compilers, fail
//! differently — and the person who has to work that out is reading a pasted
//! terminal transcript, not holding the machine.
//!
//! ## Two rules this script obeys
//!
//! 1. **It never fails the build.** Every probe is fallible and every failure is
//!    swallowed: no git, a source tarball with no repository, a `rustc` that
//!    cannot be executed in a sandboxed builder — all of them are ordinary
//!    situations, and none of them is a reason to refuse to compile a storage
//!    tool. What they produce is an *absent* value, which the version report
//!    prints as a dash.
//! 2. **It never guesses.** A variable is emitted only when a real value was
//!    obtained. Emitting an empty string, or a plausible-looking placeholder,
//!    would put a wrong commit hash into a bug report — strictly worse than
//!    putting none there, because a wrong one gets believed.
//!
//! The environment always wins over the probe, so a release pipeline that
//! already knows the commit (from its own checkout metadata, which is more
//! trustworthy than whatever happens to be in the build directory) can export
//! the variable and have it used verbatim.

use std::path::Path;
use std::process::Command;

/// Compile-time variable names. These are duplicated in `src/constants.rs`,
/// which documents them as the contract; `option_env!` demands a literal at the
/// call site, and a build script cannot import from the crate it builds, so the
/// spellings are held together by a test in the version module instead.
const ENV_GIT_HASH: &str = "DCTL_BUILD_GIT_HASH";
const ENV_RUSTC: &str = "DCTL_BUILD_RUSTC";
const ENV_TARGET: &str = "DCTL_BUILD_TARGET";
const ENV_PROFILE: &str = "DCTL_BUILD_PROFILE";
const ENV_FEATURES: &str = "DCTL_BUILD_FEATURES";

/// Separator between feature names, matching `constants::BUILD_FEATURE_SEPARATOR`.
const FEATURE_SEPARATOR: char = ',';

/// Prefix cargo gives every enabled-feature variable in a build script's
/// environment.
const CARGO_FEATURE_PREFIX: &str = "CARGO_FEATURE_";

/// Length of the abbreviated commit hash. Twelve hexadecimal digits is what
/// `git log --abbrev=12` uses for a repository large enough for seven to
/// collide, and it is short enough to read back over a support call.
const GIT_HASH_LENGTH: &str = "12";

fn main() {
    // Without this, cargo reruns the script whenever any file in the package
    // changes, which would re-shell-out to git and rustc on every single edit.
    println!("cargo:rerun-if-changed=build.rs");
    rerun_when_the_commit_changes();

    for name in [
        ENV_GIT_HASH,
        ENV_RUSTC,
        ENV_TARGET,
        ENV_PROFILE,
        ENV_FEATURES,
    ] {
        // A pipeline that exports one of these must be able to change it and
        // have the change take effect without a clean build.
        println!("cargo:rerun-if-env-changed={name}");
    }

    stamp(ENV_TARGET, std::env::var("TARGET").ok());
    stamp(ENV_PROFILE, std::env::var("PROFILE").ok());
    stamp(ENV_RUSTC, or_probe(ENV_RUSTC, rustc_version));
    stamp(ENV_GIT_HASH, or_probe(ENV_GIT_HASH, git_hash));
    stamp(ENV_FEATURES, or_probe(ENV_FEATURES, enabled_features));
}

/// Emit a compile-time variable, but only when there is something real to say.
fn stamp(name: &str, value: Option<String>) {
    let Some(value) = value.map(|value| value.trim().to_string()) else {
        return;
    };
    if !value.is_empty() {
        println!("cargo:rustc-env={name}={value}");
    }
}

/// Take an exported value if the caller supplied one, otherwise probe for it.
fn or_probe(name: &str, probe: fn() -> Option<String>) -> Option<String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => probe(),
    }
}

/// The compiler that is building this crate.
///
/// Asks the `RUSTC` cargo is itself using rather than whatever `rustc` is on
/// `PATH`, so a build driven by a pinned toolchain reports that toolchain.
fn rustc_version() -> Option<String> {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    output(Command::new(rustc).arg("--version"))
}

/// The abbreviated commit this build came from, if it came from a checkout.
fn git_hash() -> Option<String> {
    output(Command::new("git").args(["rev-parse", &format!("--short={GIT_HASH_LENGTH}"), "HEAD"]))
}

/// The cargo features enabled for this build, lower-cased and joined.
///
/// Cargo exports one `CARGO_FEATURE_<NAME>` variable per enabled feature and
/// nothing that lists them, so the list is reassembled from the environment.
/// Sorted, because the environment's iteration order is not stable and a build
/// stamp that reorders itself between builds is noise in a diff.
fn enabled_features() -> Option<String> {
    let mut features: Vec<String> = std::env::vars()
        .filter_map(|(key, _)| key.strip_prefix(CARGO_FEATURE_PREFIX).map(str::to_string))
        // Cargo upper-cases the name and turns `-` into `_`; the first is
        // reversible and the second is not, so the reported name is the
        // lower-cased form and a hyphenated feature reports with underscores.
        .map(|name| name.to_lowercase())
        .collect();
    features.sort();

    if features.is_empty() {
        return None;
    }
    Some(features.join(&FEATURE_SEPARATOR.to_string()))
}

/// Run a command and take its stdout, or nothing at all.
///
/// A non-zero exit, a missing executable and non-UTF-8 output are all treated
/// identically: the fact could not be established, so it is not reported.
fn output(command: &mut Command) -> Option<String> {
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

/// Ask cargo to rerun this script when the checked-out commit changes.
///
/// Without it the stamp is captured once and then frozen for as long as
/// `build.rs` itself is untouched, so a binary built after ten commits would
/// still report the first one — the exact failure mode that makes a build stamp
/// worse than none.
///
/// Watching `.git/HEAD` catches a branch switch; watching the file `HEAD` points
/// at catches a commit on the current branch. A detached HEAD needs only the
/// first, and a worktree — where `.git` is a file rather than a directory — is
/// simply not watched, which degrades to the frozen-stamp behaviour rather than
/// to a wrong one, because `git rev-parse` still runs whenever anything else
/// triggers the script.
fn rerun_when_the_commit_changes() {
    let Some(git_dir) = git_dir() else {
        return;
    };

    let head = git_dir.join("HEAD");
    if !head.is_file() {
        return;
    }
    println!("cargo:rerun-if-changed={}", head.display());

    let Ok(contents) = std::fs::read_to_string(&head) else {
        return;
    };
    if let Some(reference) = contents.trim().strip_prefix("ref: ") {
        let target = git_dir.join(reference);
        if target.is_file() {
            println!("cargo:rerun-if-changed={}", target.display());
        }
    }
}

/// The repository's `.git` directory, found by walking up from the crate root.
///
/// The crate is one member of a workspace, so its own directory holds no `.git`;
/// the search stops at the filesystem root and returns nothing when this is not
/// a checkout at all.
fn git_dir() -> Option<std::path::PathBuf> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let mut directory: Option<&Path> = Some(Path::new(&manifest));

    while let Some(current) = directory {
        let candidate = current.join(".git");
        if candidate.is_dir() {
            return Some(candidate);
        }
        directory = current.parent();
    }
    None
}
