//! `dctl touch` — create an object, or update its modification time.
//!
//! ## What a modification time is here
//!
//! An object store has no `utimes()`. A provider's "last modified" is the time
//! *it* accepted the upload, and nothing a client sends can change it. DCTL
//! therefore keeps the file's real modification time in the index
//! ([`dctl_index::Record::modified_unix`]), which is also what makes a
//! `copy`/`sync` comparison meaningful across providers that disagree about
//! their own clocks.
//!
//! This is why `touch` is not a niche convenience: `sync` decides what to
//! transfer from size and modification time, so being able to set a time is
//! being able to say "this file is current, do not re-upload 40 GB of it".
//!
//! ## What runs, per kind of place
//!
//! * **A filesystem remote** — both halves. A missing file is created empty, an
//!   existing one is re-stamped without losing a byte, and `--timestamp` is
//!   honoured exactly, because the operating system owns the timestamps.
//! * **A sealed vault** — creation works, `--timestamp` and all.
//!   `Vault::put_file(path, b"", when)` stores a real empty object through the
//!   same verified write and durable index commit every other object gets,
//!   carrying `when`, and the time reported afterwards is read back out of the
//!   index rather than assumed. **Re-stamping does not work and is refused**:
//!   `dctl-core` exposes no operation that updates a record's modification time,
//!   and re-storing the object would need contents `touch` does not have. See
//!   [`engine`] for the full account.
//! * **An object store** — refused. A provider assigns `Last-Modified` itself
//!   and exposes no way to move it, which is the one thing `touch` exists to do.
//!
//! ## Rules this command enforces before the engine sees anything
//!
//! * Every accepted timestamp is **UTC** and whole seconds — see [`timestamp`],
//!   which explains why an offset is refused rather than converted.
//! * `--no-create` together with the global `--immutable` is refused: the first
//!   forbids creating, the second forbids modifying, and a command that is
//!   guaranteed to do nothing is a mistake worth naming rather than a no-op
//!   worth performing.
//! * `--no-create` on its own keeps `touch -c`'s meaning everywhere: an object
//!   that is not there is left alone and the run reports `skipped`, which is a
//!   success with a distinct word rather than a silent zero.

pub mod engine;
pub mod timestamp;

use clap::Args;
use serde::Serialize;

use crate::commands::directory::{self, Plan, PlanOptions, Row, Target};
use crate::constants::{
    DIRECTORY_ACTION_TOUCH, DIRECTORY_LABEL_CREATE, DIRECTORY_LABEL_OBJECT, DIRECTORY_LABEL_PLACE,
    DIRECTORY_LABEL_TIMESTAMP, DIRECTORY_LABEL_TIMESTAMP_SOURCE,
    DIRECTORY_TIMESTAMP_SOURCE_EXPLICIT, DIRECTORY_TIMESTAMP_SOURCE_NOW,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::logging::fields;
use crate::remote::Place;

use timestamp::Timestamp;

/// Stable command name. Matches `Command::name()` in `cli/mod.rs`, because it is
/// the `command` field of the JSON plan and the `op` field of every log record
/// the command emits — two places a script may branch on.
const VERB: &str = "touch";

/// What this command calls the thing it addresses, in its diagnostics.
const NOUN: &str = "object";

/// Arguments for `dctl touch`.
///
/// Global flags — `--dry-run`, `--immutable`, `--json`, `--quiet` — are not
/// repeated here: they live in [`crate::cli::GlobalArgs`] and reach the command
/// through [`Ctx`].
#[derive(Args, Debug)]
pub struct TouchArgs {
    /// Object to create or re-stamp, as REMOTE:PATH.
    #[arg(value_name = "REMOTE:PATH")]
    pub target: String,

    /// Modification time to set, instead of the current time.
    ///
    /// UTC, in one of: 2024-05-01T12:00:00Z, '2024-05-01 12:00', 2024-05-01, or
    /// @1714564800 (seconds since the Unix epoch). Honoured on a filesystem
    /// remote, and by a vault when the object is being created; a vault cannot
    /// re-stamp one it already holds.
    #[arg(short = 't', long, value_name = "TIME", value_parser = Timestamp::parse)]
    pub timestamp: Option<Timestamp>,

    /// Do not create the object if it does not exist.
    ///
    /// Mirrors `touch -c`: re-stamp what is there, and stay silent about what is
    /// not.
    #[arg(short = 'c', long)]
    pub no_create: bool,
}

/// The `touch`-specific half of the plan.
///
/// The timestamp appears twice on purpose: once canonically for a human
/// (`2024-05-01T12:00:00Z`) and once as the integer the index will actually
/// store, so a script never has to re-parse the string DCTL just printed.
#[derive(Debug, Serialize)]
struct Options {
    object: String,
    backend: &'static str,
    timestamp: String,
    timestamp_unix: i64,
    timestamp_source: &'static str,
    create_if_missing: bool,
}

impl PlanOptions for Options {
    fn rows(&self) -> Vec<Row> {
        vec![
            (DIRECTORY_LABEL_OBJECT, self.object.clone()),
            (DIRECTORY_LABEL_PLACE, self.backend.to_string()),
            (DIRECTORY_LABEL_TIMESTAMP, self.timestamp.clone()),
            (
                DIRECTORY_LABEL_TIMESTAMP_SOURCE,
                self.timestamp_source.to_string(),
            ),
            (
                DIRECTORY_LABEL_CREATE,
                directory::yes_no(self.create_if_missing),
            ),
        ]
    }
}

/// Create an object, or update its modification time.
///
/// # Errors
/// [`crate::exit::ExitCode::Usage`] for an unparseable target, a combination of
/// flags that could not do anything, or an existing object under `--immutable`;
/// [`crate::exit::ExitCode::FatalError`] for an unknown remote, a write path
/// this build does not have, or a re-stamp `dctl-core` cannot perform;
/// [`crate::exit::ExitCode::VaultLocked`] when a vault will not unlock.
pub async fn run(ctx: &Ctx, args: &TouchArgs) -> Result<()> {
    let target = Target::parse(&args.target, NOUN)?;

    // Neither flag is wrong on its own; together they forbid both halves of what
    // this command does, and a run that cannot possibly act is a mistake worth
    // naming rather than a silent success.
    if args.no_create && ctx.globals.immutable {
        return Err(CliError::usage(
            "--no-create and --immutable together allow neither creating nor \
             modifying anything",
        )
        .with_hint(
            "Drop --immutable to re-stamp an object that exists, or drop \
             --no-create to create one that does not.",
        ));
    }

    // Before the dry-run branch: an unknown remote is a typo, and a rehearsal
    // that printed a confident plan for one would hide it until the real run.
    let place = Place::of(ctx, &target.spec())?;

    let stamp = args.timestamp.unwrap_or_else(Timestamp::now);
    let options = Options {
        object: target.path.clone(),
        backend: place.label(),
        timestamp: stamp.to_rfc3339(),
        timestamp_unix: stamp.unix_seconds(),
        timestamp_source: if args.timestamp.is_some() {
            DIRECTORY_TIMESTAMP_SOURCE_EXPLICIT
        } else {
            DIRECTORY_TIMESTAMP_SOURCE_NOW
        },
        create_if_missing: !args.no_create,
    };

    tracing::debug!(
        { fields::REMOTE } = target.remote.as_str(),
        { fields::PATH } = target.path.as_str(),
        backend = place.label(),
        timestamp = options.timestamp_unix,
        create = options.create_if_missing,
        "planned touch"
    );

    if ctx.is_dry_run() {
        directory::emit(ctx, &Plan::new(VERB, &target, true, &options))?;
        ctx.dry_run_notice(DIRECTORY_ACTION_TOUCH, &target.to_string());
        return Ok(());
    }

    let outcome = engine::apply(
        ctx,
        &place,
        engine::Request {
            target: &target,
            stamp,
            create: !args.no_create,
        },
    )
    .await?;

    directory::emit(ctx, &Plan::done(VERB, &target, &options, outcome))?;
    ctx.out
        .success(format!("{}: {target}", outcome.phrase(false)));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::directory::Outcome;
    use crate::commands::directory::testing::ctx;
    use crate::exit::ExitCode;
    use clap::Parser;

    /// Minimal parser that exposes `TouchArgs` on its own.
    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        args: TouchArgs,
    }

    fn parse(argv: &[&str]) -> TouchArgs {
        Harness::parse_from(std::iter::once("dctl").chain(argv.iter().copied())).args
    }

    /// A context whose configuration file is the fixture written here.
    fn ctx_with_config(body: &str, extra: &[&str]) -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, body).expect("the fixture is writable");

        let mut flags = vec!["--config".to_string(), path.to_string_lossy().into_owned()];
        flags.extend(extra.iter().map(|flag| (*flag).to_string()));
        let borrowed: Vec<&str> = flags.iter().map(String::as_str).collect();
        (dir, ctx(&borrowed))
    }

    fn plain_local(root: &std::path::Path) -> String {
        format!(
            "[remotes.scratch]\ntype = \"local\"\npath = {:?}\n",
            root.to_string_lossy()
        )
    }

    #[test]
    fn the_target_is_positional_and_required() {
        let args = parse(&["vault:notes.txt"]);
        assert_eq!(args.target, "vault:notes.txt");
        assert!(args.timestamp.is_none());
        assert!(!args.no_create);
        assert!(Harness::try_parse_from(["dctl"]).is_err());
    }

    #[test]
    fn the_flags_carry_the_short_forms_muscle_memory_expects() {
        let args = parse(&["vault:a", "-t", "2024-05-01T12:00:00Z", "-c"]);
        assert!(args.no_create);
        assert_eq!(
            args.timestamp.map(Timestamp::unix_seconds),
            Some(1_714_564_800)
        );
        assert!(parse(&["vault:a", "--no-create"]).no_create);
    }

    #[test]
    fn a_malformed_timestamp_is_rejected_by_the_parser() {
        // Validation at the edge: the command body never sees a bad value, and
        // the failure is clap's own usage error rather than a runtime surprise.
        assert!(Harness::try_parse_from(["dctl", "vault:a", "-t", "yesterday"]).is_err());
        assert!(Harness::try_parse_from(["dctl", "vault:a", "-t", "2024-02-30"]).is_err());
    }

    #[tokio::test]
    async fn a_dry_run_reports_and_writes_nothing() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with_config(&plain_local(root.path()), &["--dry-run"]);

        assert!(run(&ctx, &parse(&["scratch:notes.txt"])).await.is_ok());
        assert!(!root.path().join("notes.txt").exists());
    }

    #[tokio::test]
    async fn a_real_run_creates_and_stamps_a_file_on_a_local_remote() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with_config(&plain_local(root.path()), &[]);

        run(&ctx, &parse(&["scratch:notes.txt", "-t", "@1714564800"]))
            .await
            .expect("the object is created");

        let created = root.path().join("notes.txt");
        assert!(created.is_file(), "nothing was created");
        assert_eq!(std::fs::metadata(&created).unwrap().len(), 0);
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
                run(&ctx, &parse(&["scratch:a.txt", "-t", "@0"]))
                    .await
                    .is_ok(),
                "failed for {format:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_bad_target_is_a_usage_error_not_a_backend_error() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with_config(&plain_local(root.path()), &[]);
        for spec in ["", "/tmp/x", "scratch:", "scratch:../escape"] {
            let error = run(&ctx, &parse(&[spec])).await.unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "accepted '{spec}'");
        }
    }

    #[tokio::test]
    async fn a_run_that_could_not_act_is_refused_before_anything_else() {
        // --no-create forbids creating; --immutable forbids modifying. Together
        // they describe a command with nothing left to do — refused before the
        // remote is even resolved, so it fails the same way for every remote.
        let root = tempfile::tempdir().expect("a temporary directory");
        let (_dir, immutable) =
            ctx_with_config(&plain_local(root.path()), &["--immutable", "--dry-run"]);
        let error = run(&immutable, &parse(&["scratch:a.txt", "--no-create"]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some());

        // Either flag alone is fine.
        assert!(run(&immutable, &parse(&["scratch:a.txt"])).await.is_ok());
        let (_dir, mutable) = ctx_with_config(&plain_local(root.path()), &["--dry-run"]);
        assert!(
            run(&mutable, &parse(&["scratch:a.txt", "--no-create"]))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_plain_object_store_is_refused_rather_than_half_attempted() {
        // Nothing in this build writes a plain object into a bucket, and the
        // refusal says so instead of failing later with a credential error.
        let (_dir, ctx) = ctx_with_config("", &[]);
        let error = run(&ctx, &parse(&["b2:mybucket/sentinel"]))
            .await
            .expect_err("there is no plain object write path");
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.hint().is_some());
    }

    #[test]
    fn the_plan_carries_the_timestamp_twice_for_two_readers() {
        let target = Target::parse("vault:a.txt", NOUN).unwrap();
        let stamp = Timestamp::parse("2024-05-01T12:00:00Z").unwrap();
        let options = Options {
            object: target.path.clone(),
            backend: Place::Sealed.label(),
            timestamp: stamp.to_rfc3339(),
            timestamp_unix: stamp.unix_seconds(),
            timestamp_source: DIRECTORY_TIMESTAMP_SOURCE_EXPLICIT,
            create_if_missing: true,
        };
        let plan = Plan::new(VERB, &target, true, &options);
        let value = serde_json::to_value(&plan).unwrap();

        assert_eq!(value["command"], VERB);
        assert_eq!(value["options"]["object"], "a.txt");
        assert_eq!(value["options"]["backend"], "vault");
        assert_eq!(value["options"]["timestamp"], "2024-05-01T12:00:00Z");
        assert_eq!(value["options"]["timestamp_unix"], 1_714_564_800_i64);
        assert_eq!(
            value["options"]["timestamp_source"],
            DIRECTORY_TIMESTAMP_SOURCE_EXPLICIT
        );
        assert_eq!(value["options"]["create_if_missing"], true);
        // Nothing in a rehearsal may suggest the write happened.
        assert_eq!(value["status"], crate::constants::DIRECTORY_STATUS_PLANNED);
        assert!(value.get("modified").is_none());
    }

    #[test]
    fn a_completed_run_reports_what_it_did() {
        let target = Target::parse("vault:a.txt", NOUN).unwrap();
        let stamp = Timestamp::parse("@0").unwrap();
        let options = Options {
            object: target.path.clone(),
            backend: Place::Sealed.label(),
            timestamp: stamp.to_rfc3339(),
            timestamp_unix: stamp.unix_seconds(),
            timestamp_source: DIRECTORY_TIMESTAMP_SOURCE_NOW,
            create_if_missing: true,
        };
        for outcome in [Outcome::Created, Outcome::Skipped] {
            let value = serde_json::to_value(Plan::done(VERB, &target, &options, outcome)).unwrap();
            assert_eq!(value["status"], outcome.slug());
            assert_eq!(value["dry_run"], false);
        }
    }

    #[test]
    fn the_text_rows_name_the_object_the_backend_and_the_time() {
        let stamp = Timestamp::parse("@0").unwrap();
        let options = Options {
            object: "a.txt".to_string(),
            backend: Place::Sealed.label(),
            timestamp: stamp.to_rfc3339(),
            timestamp_unix: stamp.unix_seconds(),
            timestamp_source: DIRECTORY_TIMESTAMP_SOURCE_NOW,
            create_if_missing: false,
        };
        let rows = options.rows();
        assert_eq!(rows[0], (DIRECTORY_LABEL_OBJECT, "a.txt".to_string()));
        assert_eq!(rows[1], (DIRECTORY_LABEL_PLACE, "vault".to_string()));
        assert_eq!(
            rows[2],
            (
                DIRECTORY_LABEL_TIMESTAMP,
                "1970-01-01T00:00:00Z".to_string()
            )
        );
        assert_eq!(rows[3].1, DIRECTORY_TIMESTAMP_SOURCE_NOW);
        assert_eq!(rows[4].0, DIRECTORY_LABEL_CREATE);
    }
}
