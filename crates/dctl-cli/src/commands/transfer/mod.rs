//! Shared machinery for the transfer family — `copy`, `move`, `sync`, `copyto`
//! and `moveto`.
//!
//! These five verbs differ in exactly three ways: whether the destination may
//! lose files, whether the source is deleted afterwards, and whether `DEST`
//! names a container or an exact object. Everything else — how a `REMOTE:PATH`
//! is parsed, how the two sides are enumerated, how a file is judged identical,
//! how a plan is printed, how the verified-write pipeline drives the progress
//! display — is the same work. It lives here once, so a fix to the comparison
//! rules cannot land in `copy` and be forgotten in `sync`, where getting it
//! wrong deletes data.
//!
//! One concern per file:
//!
//! | file | concern |
//! |------|---------|
//! | [`endpoint`] | splitting `DEST` into a container and an object name |
//! | [`entry`]    | what a transferable thing is |
//! | [`listing`]  | how one side is enumerated, and which filters apply |
//! | [`checksum`] | producing the digest `--checksum` compares |
//! | [`compare`]  | whether a file needs transferring at all |
//! | [`plan`]     | the add/update/delete diff, computed without executing |
//! | [`immutable`] | the `--immutable` gate, applied to a plan before it runs |
//! | [`prepare`]  | two command-line specs in, one reviewable plan out |
//! | [`report`]   | how a plan is printed in each `--format` |
//! | [`pipeline`] | the `PLAN.md` §6 stage walk and its progress wiring |
//! | [`engine`]   | the binding to `dctl-core`, and what is still missing |
//! | [`execute`]  | running a plan's actions through a driver |
//! | [`options`]  | the rclone-compatible per-command flags |
//!
//! Classifying `SOURCE` and `DEST` is deliberately *not* on that list. It is
//! [`crate::remote::spec`]'s job, and the Windows drive-letter rule it encodes
//! must have exactly one implementation in the binary — a second one here would
//! eventually disagree, and the way it disagrees is by writing data somewhere
//! nobody named.
//!
//! ## Why the plan is a first-class value
//!
//! `--dry-run` is only worth anything if the thing it prints is the thing that
//! would have run. So a plan is *computed* by [`plan::Plan::compute`] from two
//! listings and a policy, with no I/O and no mutation, and is then either
//! printed ([`report`]) or executed ([`execute`]). There is no second code path
//! that decides what to do while doing it — which is what lets a reviewer trust
//! a `sync --dry-run` before letting it delete anything.

pub mod checksum;
pub mod compare;
pub mod endpoint;
pub mod engine;
pub mod entry;
pub mod execute;
pub mod immutable;
pub mod listing;
pub mod options;
pub mod pipeline;
pub mod plan;
pub mod prepare;
pub mod report;

// Only the vocabulary a *command body* writes is re-exported. Everything else
// keeps its module path, so a reader of `copy.rs` can tell at a glance which
// file decides a thing — `plan::Policy`, `listing::ListOptions`,
// `pipeline::StageDriver` — rather than meeting a dozen bare names from one
// `use`.
pub use engine::{Engine, ReapTarget};
pub use options::{CompareFlags, DeleteFlags, DeleteMode, TraversalFlags};
pub use plan::Op;
pub use prepare::Prepared;

/// Test-only helpers shared by the family's unit tests.
///
/// Building a [`crate::ctx::Ctx`] by hand means re-deriving the whole global
/// flag block, so it is done once here. Every command's tests then drive a real
/// context — the same one `main` builds — rather than a mock that could diverge
/// from it.
#[cfg(test)]
pub(crate) mod testing {
    use clap::Parser;

    use crate::cli::GlobalArgs;
    use crate::config::{self, Config};
    use crate::ctx::Ctx;

    /// The flag that pins which configuration a test context reads.
    const CONFIG_FLAG: &str = "--config";

    /// Minimal parser that exposes the global block on its own.
    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    /// A context built from global flags, with the progress display silenced.
    ///
    /// `--quiet` is forced on because a unit test run from a terminal would
    /// otherwise paint real progress bars over the test harness's output.
    ///
    /// `--config` is forced on for a sharper reason. Every transfer now decides
    /// whether its destination belongs to a vault's namespace by reading the
    /// configuration ([`crate::addressing`]), so a context that resolved to the
    /// platform default would read the *developer's own* `config.toml` — and the
    /// suite would pass or fail depending on whose machine it ran on. A test
    /// that wants a configuration says so through [`ctx_with_config`].
    pub fn ctx(args: &[&str]) -> Ctx {
        let mut argv: Vec<String> = std::iter::once("dctl")
            .chain(args.iter().copied())
            .chain(std::iter::once("--quiet"))
            .map(String::from)
            .collect();

        if !args.contains(&CONFIG_FLAG) {
            argv.push(CONFIG_FLAG.to_string());
            argv.push(config::absent_path().to_string_lossy().into_owned());
        }

        Ctx::new(Harness::parse_from(argv).globals)
    }

    /// A context reading a configuration written for this test.
    ///
    /// The temporary directory is returned alongside it because dropping it
    /// deletes the file, which has to outlive the call under test.
    ///
    /// The configuration is *saved* rather than hand-written as TOML, so a
    /// fixture holding a native path is spelled correctly on every platform and
    /// a fixture that would not survive validation fails here rather than
    /// silently exercising a different rule.
    pub fn ctx_with_config(config: &Config) -> (tempfile::TempDir, Ctx) {
        ctx_with_config_and(config, &[])
    }

    /// The same, with further global flags.
    ///
    /// `--no-ask-password` is the flag this exists for. Whether a command asks
    /// for a password is exactly what several of the engine's tests are
    /// asserting, and a test that left the prompt reachable could pass by being
    /// answered on a developer's terminal while failing in CI — or, worse, pass
    /// in both places for a run that should never have asked at all.
    pub fn ctx_with_config_and(config: &Config, flags: &[&str]) -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("config.toml");
        config::save(config, &path).expect("the fixture must be a valid configuration");

        let spelled = path.to_string_lossy().into_owned();
        let mut argv: Vec<&str> = vec![CONFIG_FLAG, &spelled];
        argv.extend_from_slice(flags);
        let ctx = ctx(&argv);
        (dir, ctx)
    }
}
