//! `dctl mkdir` — create a directory, where the backend has directories.
//!
//! ## What a directory is here, and why the answer differs by backend
//!
//! A filesystem has directories: objects that exist in their own right, can be
//! empty, and can be created before anything is put in them. An object store has
//! none. `photos/2024/a.jpg` is a single flat key that happens to contain
//! slashes, and a "directory" there is nothing more than a shared prefix among
//! keys — so it exists exactly while some key sits under it, and a directory
//! containing no objects does not exist at all. A vault inherits that exactly:
//! its index maps logical paths to sealed objects, and a prefix nothing is
//! stored under is simply a prefix nothing is stored under.
//!
//! So the command does two different things, and reports which:
//!
//! * On a **filesystem remote** it creates a real directory, with `mkdir(1)`'s
//!   division of labour for `--parents` — see [`engine`].
//! * On a **vault or an object store** there is nothing to create. The command
//!   succeeds with the outcome `not_required` and says why: the path will exist
//!   the moment an object is stored under it, and it is not missing now.
//!
//! ## Why succeeding rather than refusing, and why not a marker object
//!
//! Refusing would fail the ordinary `dctl mkdir vault:a/b && dctl copy ./x
//! vault:a/b/` for a condition that is not an error — the postcondition the user
//! wants already holds — and a command that refuses when its goal is met teaches
//! its users to ignore exit codes.
//!
//! Writing a zero-byte marker at `<dir>/.dctl-dir` was the previous design and
//! is rejected. The marker is a real object in the user's own namespace: `ls`,
//! `size`, `check`, `sync`, `hashsum` and every restore would carry it as data,
//! and a file fabricated to simulate a directory is a larger misreport than the
//! absence it hides. `PLAN.md` §6 forbids reporting work that did not happen; it
//! equally forbids inventing data so that a report can be made.
//!
//! **`--parents` follows the same rule**, because the alternative is
//! incoherent. Where directories exist it creates the chain and makes an
//! existing directory a success (`mkdir -p`). Where they do not, there is
//! nothing to create at any level of the chain, so the flag changes nothing and
//! the plan still lists the chain it would have needed — a report of the request
//! rather than of an outcome.
//!
//! ## What this command never does
//!
//! It never asks for a password. Whether a place has directories is a property
//! of the configuration, not of the data, so a vault is classified without being
//! unlocked and a bucket without being contacted. It also never deletes or
//! overwrites: `mkdir` is the exact inverse of `rmdir` and the only command in
//! this family that cannot destroy anything.

pub mod chain;
pub mod engine;

use clap::Args;
use serde::Serialize;

use crate::commands::directory::{self, Outcome, Plan, PlanOptions, Row, Target};
use crate::constants::{
    DIRECTORY_ACTION_MKDIR, DIRECTORY_LABEL_DIRECTORY, DIRECTORY_LABEL_PARENTS,
    DIRECTORY_LABEL_PLACE,
};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::logging::fields;
use crate::remote::Place;

use chain::PlannedDirectory;

/// Stable command name. Matches `Command::name()` in `cli/mod.rs`, because it is
/// the `command` field of the JSON plan and the `op` field of every log record
/// the command emits — two places a script may branch on.
const VERB: &str = "mkdir";

/// What this command calls the thing it addresses, in its diagnostics.
const NOUN: &str = "directory";

/// Arguments for `dctl mkdir`.
///
/// Global flags — `--dry-run`, `--json`, `--format`, `--quiet` — are not
/// repeated here: they live in [`crate::cli::GlobalArgs`] and reach the command
/// through [`Ctx`].
#[derive(Args, Debug)]
pub struct MkdirArgs {
    /// Directory to create, as REMOTE:PATH.
    #[arg(value_name = "REMOTE:PATH")]
    pub target: String,

    /// Create missing parent directories as well.
    ///
    /// Mirrors `mkdir -p`: `scratch:a/b/c` creates `a`, then `a/b`, then
    /// `a/b/c`, and an existing directory is not an error. On a backend with no
    /// directories there is nothing to create at any level, so the flag changes
    /// nothing there.
    #[arg(short, long)]
    pub parents: bool,
}

/// The `mkdir`-specific half of the plan.
///
/// Carries the resolved chain rather than just the flag, so `--dry-run --json`
/// shows every directory that would be created instead of leaving the reader to
/// re-derive it — and carries the kind of place, because that is what decides
/// whether any of them will be.
#[derive(Debug, Serialize)]
struct Options {
    parents: bool,
    backend: &'static str,
    directories: Vec<PlannedDirectory>,
}

impl PlanOptions for Options {
    fn rows(&self) -> Vec<Row> {
        let mut rows = vec![
            (DIRECTORY_LABEL_PLACE, self.backend.to_string()),
            (DIRECTORY_LABEL_PARENTS, directory::yes_no(self.parents)),
        ];
        for planned in &self.directories {
            rows.push((DIRECTORY_LABEL_DIRECTORY, planned.path.clone()));
        }
        rows
    }
}

/// Create a directory.
///
/// # Errors
/// [`crate::exit::ExitCode::Usage`] for an unparseable target or a file already
/// occupying the name; [`crate::exit::ExitCode::FatalError`] for an unknown
/// remote, an unreadable configuration, or a destination the addressing rule
/// claims for a vault's object store; and whatever the operating system reported
/// while creating a directory — a missing parent without `--parents` is
/// [`crate::exit::ExitCode::FileNotFound`], exactly as `mkdir(1)` reports it.
pub async fn run(ctx: &Ctx, args: &MkdirArgs) -> Result<()> {
    let target = Target::parse(&args.target, NOUN)?;
    // Before the dry-run branch, deliberately: an unknown remote is a typo the
    // user can fix, and a rehearsal that printed a confident plan for a remote
    // that does not exist would hide it until the real run.
    let place = Place::of(ctx, &target.spec())?;

    let options = Options {
        parents: args.parents,
        backend: place.label(),
        directories: chain::build(&target, args.parents),
    };

    tracing::debug!(
        { fields::REMOTE } = target.remote.as_str(),
        { fields::PATH } = target.path.as_str(),
        backend = place.label(),
        parents = args.parents,
        directories = options.directories.len(),
        "planned mkdir"
    );

    if ctx.is_dry_run() {
        directory::emit(ctx, &Plan::new(VERB, &target, true, &options))?;
        ctx.dry_run_notice(DIRECTORY_ACTION_MKDIR, &target.to_string());
        return Ok(());
    }

    let outcome = engine::create(ctx, &place, &target, &options.directories, args.parents)?;

    directory::emit(ctx, &Plan::done(VERB, &target, &options, outcome))?;
    if outcome == Outcome::NotRequired {
        // The reason travels with the result rather than being left for the
        // documentation: "nothing to create" is a surprising success, and a user
        // who is not told why will assume the command silently failed.
        ctx.out
            .success(format!("{target}: {}", engine::nothing_to_create(&place)));
    } else {
        ctx.out
            .success(format!("{}: {target}", outcome.phrase(true)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::directory::testing::ctx;
    use crate::exit::ExitCode;
    use clap::Parser;

    /// Minimal parser that exposes `MkdirArgs` on its own.
    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        args: MkdirArgs,
    }

    fn parse(argv: &[&str]) -> MkdirArgs {
        Harness::parse_from(std::iter::once("dctl").chain(argv.iter().copied())).args
    }

    /// A context whose configuration file is the fixture written here.
    ///
    /// Always `--config`, never the platform default: a test that read the
    /// developer's own remotes would pass or fail depending on the machine.
    fn ctx_with_config(body: &str, extra: &[&str]) -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, body).expect("the fixture is writable");

        let mut flags = vec!["--config".to_string(), path.to_string_lossy().into_owned()];
        flags.extend(extra.iter().map(|flag| (*flag).to_string()));
        let borrowed: Vec<&str> = flags.iter().map(String::as_str).collect();
        (dir, ctx(&borrowed))
    }

    /// A configuration with one plain local remote rooted at `root`.
    fn plain_local(root: &std::path::Path) -> String {
        format!(
            "[remotes.scratch]\ntype = \"local\"\npath = {:?}\n",
            root.to_string_lossy()
        )
    }

    /// A configuration with the vault pair `dctl init` writes.
    fn vault_pair(root: &std::path::Path) -> String {
        format!(
            "[remotes.archive-store]\ntype = \"local\"\npath = {:?}\nrequire_vault = true\n\n\
             [remotes.archive]\ntype = \"vault\"\nbase = \"archive-store\"\n",
            root.to_string_lossy()
        )
    }

    #[test]
    fn the_target_is_positional_and_required() {
        let args = parse(&["vault:photos/2024"]);
        assert_eq!(args.target, "vault:photos/2024");
        assert!(!args.parents);
        assert!(Harness::try_parse_from(["dctl"]).is_err());
    }

    #[test]
    fn parents_has_the_short_form_muscle_memory_expects() {
        assert!(parse(&["vault:a", "-p"]).parents);
        assert!(parse(&["vault:a", "--parents"]).parents);
    }

    #[tokio::test]
    async fn a_dry_run_reports_and_writes_nothing() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with_config(&plain_local(root.path()), &["--dry-run"]);

        assert!(run(&ctx, &parse(&["scratch:photos/2024"])).await.is_ok());
        assert!(
            !root.path().join("photos").exists(),
            "a dry run must create nothing"
        );
    }

    #[tokio::test]
    async fn a_real_run_creates_a_real_directory_on_a_local_remote() {
        // The end-to-end claim this command now makes: a directory exists on
        // disk afterwards, not a plan describing one.
        let root = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with_config(&plain_local(root.path()), &[]);

        run(&ctx, &parse(&["scratch:photos/2024", "-p"]))
            .await
            .expect("the directory is created");

        assert!(root.path().join("photos").join("2024").is_dir());
    }

    #[tokio::test]
    async fn a_vault_succeeds_without_creating_anything_or_asking_for_a_password() {
        // The documented no-op. `--no-ask-password` is what pins the second half
        // of the claim: if the command unlocked the vault it would fail with
        // VaultLocked instead of succeeding.
        let root = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with_config(&vault_pair(root.path()), &["--no-ask-password"]);

        run(&ctx, &parse(&["archive:photos/2024", "-p"]))
            .await
            .expect("a vault mkdir succeeds");

        // Nothing may appear in the vault's own store, marker or otherwise.
        let entries: Vec<_> = std::fs::read_dir(root.path())
            .expect("the store is readable")
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(entries.is_empty(), "the vault store gained {entries:?}");
    }

    #[tokio::test]
    async fn a_vault_run_reports_not_required_and_never_created() {
        // The misreport this outcome exists to prevent: a script checking for
        // `created` must not be told a directory was made when none was.
        let root = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with_config(&vault_pair(root.path()), &["--no-ask-password"]);
        let target = Target::parse("archive:photos", NOUN).unwrap();
        let options = Options {
            parents: false,
            backend: Place::Sealed.label(),
            directories: chain::build(&target, false),
        };

        let plan = Plan::done(VERB, &target, &options, Outcome::NotRequired);
        let value = serde_json::to_value(&plan).unwrap();
        assert_eq!(value["status"], Outcome::NotRequired.slug());
        assert_ne!(value["status"], Outcome::Created.slug());
        assert!(run(&ctx, &parse(&["archive:photos"])).await.is_ok());
    }

    #[tokio::test]
    async fn a_directory_inside_a_vaults_object_store_is_refused() {
        // The addressing rule applies to a directory as it does to a file: the
        // store's namespace belongs to the vault that owns it.
        let root = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with_config(&vault_pair(root.path()), &[]);

        let error = run(&ctx, &parse(&["archive-store:photos"]))
            .await
            .expect_err("a plain write into a vault's store is refused");

        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            !root.path().join("photos").exists(),
            "it was created anyway"
        );
    }

    #[tokio::test]
    async fn every_format_runs_the_same_command() {
        let root = tempfile::tempdir().expect("a temporary directory");
        for format in [
            vec!["--dry-run"],
            vec!["--dry-run", "--json"],
            vec!["--dry-run", "--format", "json-lines"],
        ] {
            let (_dir, ctx) = ctx_with_config(&plain_local(root.path()), &format);
            assert!(
                run(&ctx, &parse(&["scratch:a/b", "-p"])).await.is_ok(),
                "failed for {format:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_bad_target_is_a_usage_error_not_a_backend_error() {
        // Classification matters: a typo must not look like a missing feature.
        let root = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with_config(&plain_local(root.path()), &[]);
        for spec in ["", "/tmp/x", "scratch:", "scratch:../escape"] {
            let error = run(&ctx, &parse(&[spec])).await.unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "accepted '{spec}'");
        }
    }

    #[tokio::test]
    async fn an_unknown_remote_is_named_rather_than_planned_around() {
        // Resolved before the dry-run branch, so a rehearsal cannot print a
        // confident plan for a remote that does not exist.
        let (_dir, ctx) = ctx_with_config("", &["--dry-run"]);
        let error = run(&ctx, &parse(&["nosuchremote:photos"]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("nosuchremote"));
    }

    #[test]
    fn the_plan_names_the_backend_and_every_directory() {
        let target = Target::parse("vault:a/b", NOUN).unwrap();
        let options = Options {
            parents: true,
            backend: Place::Sealed.label(),
            directories: chain::build(&target, true),
        };
        let rows = options.rows();
        assert_eq!(rows[0], (DIRECTORY_LABEL_PLACE, "vault".to_string()));
        assert_eq!(rows[1].0, DIRECTORY_LABEL_PARENTS);
        assert_eq!(rows[2], (DIRECTORY_LABEL_DIRECTORY, "a".to_string()));
        assert_eq!(rows[3], (DIRECTORY_LABEL_DIRECTORY, "a/b".to_string()));
    }

    #[test]
    fn the_json_plan_names_the_command_and_every_directory() {
        let target = Target::parse("vault:a/b", NOUN).unwrap();
        let options = Options {
            parents: true,
            backend: Place::Sealed.label(),
            directories: chain::build(&target, true),
        };
        let plan = Plan::new(VERB, &target, true, &options);
        let value = serde_json::to_value(&plan).unwrap();

        assert_eq!(value["command"], VERB);
        assert_eq!(value["options"]["parents"], true);
        assert_eq!(value["options"]["backend"], "vault");
        assert_eq!(value["options"]["directories"][0]["path"], "a");
        assert_eq!(value["options"]["directories"][1]["path"], "a/b");
        // A rehearsal claims nothing about what happened.
        assert_eq!(value["status"], crate::constants::DIRECTORY_STATUS_PLANNED);
        assert!(value.get("created").is_none());
    }
}
