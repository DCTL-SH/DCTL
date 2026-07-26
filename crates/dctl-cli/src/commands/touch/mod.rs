//! `dctl touch` — create an object, or update its modification time.
//!
//! ## What a modification time is here
//!
//! An object store has no `utimes()`. A provider's "last modified" is the time
//! *it* accepted the upload, and nothing a client sends can change it. DCTL
//! therefore keeps the file's real modification time in the index
//! ([`dctl_index::Record::modified_unix`]), which is also what makes a
//! `copy`/`sync` comparison meaningful across providers that disagree about
//! their own clocks. `touch` writes that field — and, when the object does not
//! exist yet, an empty object to attach it to.
//!
//! This is why `touch` is not a niche convenience: `sync` decides what to
//! transfer from size and modification time, so being able to set a time is
//! being able to say "this file is current, do not re-upload 40 GB of it".
//!
//! ## Rules this command enforces before the engine sees anything
//!
//! * Every accepted timestamp is **UTC** and whole seconds — see [`timestamp`],
//!   which explains why an offset is refused rather than converted.
//! * `--no-create` together with the global `--immutable` is refused: the first
//!   forbids creating, the second forbids modifying, and a command that is
//!   guaranteed to do nothing is a mistake worth naming rather than a no-op
//!   worth performing.
//!
//! ## Engine reality (`PLAN.md` §6, §11)
//!
//! Parsing, validation, timestamp conversion, the `--dry-run` report and the
//! JSON shape are complete and tested here. Writing is not: `dctl-core::Vault`
//! can `put_file`, but it has no "set the modification time of an existing
//! record" operation, and the command context does not yet carry an unlocked
//! vault to call either on. So a real run emits its plan and then fails with
//! [`CliError::unimplemented`] — an error with a real exit code — rather than
//! printing a success message for a write that never happened. A `--dry-run`
//! succeeds, because a dry run promises a report and delivers exactly that.

pub mod timestamp;

use clap::Args;
use serde::Serialize;

use crate::commands::directory::{self, Plan, PlanOptions, Row, Target};
use crate::constants::{
    DIRECTORY_ACTION_TOUCH, DIRECTORY_ENGINE_HINT, DIRECTORY_LABEL_CREATE, DIRECTORY_LABEL_OBJECT,
    DIRECTORY_LABEL_TIMESTAMP, DIRECTORY_LABEL_TIMESTAMP_SOURCE,
    DIRECTORY_TIMESTAMP_SOURCE_EXPLICIT, DIRECTORY_TIMESTAMP_SOURCE_NOW,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::logging::fields;

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
    /// @1714564800 (seconds since the Unix epoch).
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
    timestamp: String,
    timestamp_unix: i64,
    timestamp_source: &'static str,
    create_if_missing: bool,
}

impl PlanOptions for Options {
    fn rows(&self) -> Vec<Row> {
        vec![
            (DIRECTORY_LABEL_OBJECT, self.object.clone()),
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
/// [`crate::exit::ExitCode::Usage`] for an unparseable target or a combination
/// of flags that could not do anything, and
/// [`crate::exit::ExitCode::FatalError`] from [`CliError::unimplemented`] when a
/// real run reaches the engine boundary described in the module docs.
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

    let stamp = args.timestamp.unwrap_or_else(Timestamp::now);
    let options = Options {
        object: target.path.clone(),
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
        timestamp = options.timestamp_unix,
        create = options.create_if_missing,
        "planned touch"
    );

    let plan = Plan::new(VERB, &target, ctx.is_dry_run(), &options);
    directory::emit(ctx, &plan)?;

    if ctx.is_dry_run() {
        ctx.dry_run_notice(DIRECTORY_ACTION_TOUCH, &target.to_string());
        return Ok(());
    }

    Err(CliError::unimplemented(directory::command_name(VERB)).with_hint(DIRECTORY_ENGINE_HINT))
}

#[cfg(test)]
mod tests {
    use super::*;
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
    async fn a_dry_run_reports_and_succeeds() {
        let ctx = ctx(&["--dry-run"]);
        assert!(run(&ctx, &parse(&["vault:notes.txt"])).await.is_ok());
    }

    #[tokio::test]
    async fn a_real_run_fails_loudly_rather_than_claiming_success() {
        // PLAN.md §6: work that did not happen is never reported as done.
        let ctx = ctx(&[]);
        let error = run(&ctx, &parse(&["vault:notes.txt"])).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("touch"));
        assert!(error.hint().is_some(), "a refusal must say what is missing");
    }

    #[tokio::test]
    async fn every_format_runs_the_same_command() {
        for format in [
            vec!["--dry-run"],
            vec!["--dry-run", "--json"],
            vec!["--dry-run", "--format", "json-lines"],
        ] {
            let ctx = ctx(&format);
            assert!(
                run(&ctx, &parse(&["vault:a.txt", "-t", "@0"]))
                    .await
                    .is_ok(),
                "failed for {format:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_bad_target_is_a_usage_error_not_an_engine_error() {
        let ctx = ctx(&[]);
        for spec in ["", "/tmp/x", "vault:", "vault:../escape"] {
            let error = run(&ctx, &parse(&[spec])).await.unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "accepted '{spec}'");
        }
    }

    #[tokio::test]
    async fn a_run_that_could_not_act_is_refused_before_anything_else() {
        // --no-create forbids creating; --immutable forbids modifying. Together
        // they describe a command with nothing left to do.
        let immutable = ctx(&["--immutable", "--dry-run"]);
        let error = run(&immutable, &parse(&["vault:a.txt", "--no-create"]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some());

        // Either flag alone is fine.
        assert!(run(&immutable, &parse(&["vault:a.txt"])).await.is_ok());
        let mutable = ctx(&["--dry-run"]);
        assert!(
            run(&mutable, &parse(&["vault:a.txt", "--no-create"]))
                .await
                .is_ok()
        );
    }

    #[test]
    fn the_plan_carries_the_timestamp_twice_for_two_readers() {
        let target = Target::parse("vault:a.txt", NOUN).unwrap();
        let stamp = Timestamp::parse("2024-05-01T12:00:00Z").unwrap();
        let options = Options {
            object: target.path.clone(),
            timestamp: stamp.to_rfc3339(),
            timestamp_unix: stamp.unix_seconds(),
            timestamp_source: DIRECTORY_TIMESTAMP_SOURCE_EXPLICIT,
            create_if_missing: true,
        };
        let plan = Plan::new(VERB, &target, true, &options);
        let value = serde_json::to_value(&plan).unwrap();

        assert_eq!(value["command"], VERB);
        assert_eq!(value["options"]["object"], "a.txt");
        assert_eq!(value["options"]["timestamp"], "2024-05-01T12:00:00Z");
        assert_eq!(value["options"]["timestamp_unix"], 1_714_564_800_i64);
        assert_eq!(
            value["options"]["timestamp_source"],
            DIRECTORY_TIMESTAMP_SOURCE_EXPLICIT
        );
        assert_eq!(value["options"]["create_if_missing"], true);
        // Nothing in the document may suggest the write happened.
        assert!(value.get("modified").is_none());
        assert!(value.get("created").is_none());
    }

    #[test]
    fn the_text_rows_name_the_object_and_where_the_time_came_from() {
        let stamp = Timestamp::parse("@0").unwrap();
        let options = Options {
            object: "a.txt".to_string(),
            timestamp: stamp.to_rfc3339(),
            timestamp_unix: stamp.unix_seconds(),
            timestamp_source: DIRECTORY_TIMESTAMP_SOURCE_NOW,
            create_if_missing: false,
        };
        let rows = options.rows();
        assert_eq!(rows[0], (DIRECTORY_LABEL_OBJECT, "a.txt".to_string()));
        assert_eq!(
            rows[1],
            (
                DIRECTORY_LABEL_TIMESTAMP,
                "1970-01-01T00:00:00Z".to_string()
            )
        );
        assert_eq!(rows[2].1, DIRECTORY_TIMESTAMP_SOURCE_NOW);
        assert_eq!(rows[3].0, DIRECTORY_LABEL_CREATE);
    }
}
