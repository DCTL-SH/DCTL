//! `dctl cleanup` — reclaim the space nothing is using any more.
//!
//! The other five removal commands remove things a user put there. This one
//! removes the debris DCTL and the provider leave behind, all of which is
//! invisible in a listing and all of which is billed for:
//!
//! * **Stale staging objects.** A staged upload that never reached its commit is
//!   left under a staging name `dctl_store::staging` reserves. The
//!   verified-write contract deliberately writes to a temporary key first, so
//!   this litter is a *consequence* of the durability guarantee, not a bug.
//! * **Orphaned content objects.** A sealed object stored by a write that never
//!   reached its index commit — which is exactly what a verified write that
//!   aborts leaves behind ([the plan](https://doc.dctl.sh/project/plan) §6 step
//!   6). This is the command that cleans up after that contract.
//! * **Abandoned multipart uploads.** A crash between parts leaves one open. The
//!   parts already stored are charged for and no *object* listing shows them —
//!   which is why they have a listing of their own.
//! * **Superseded versions.** On a versioned bucket, every overwrite and delete
//!   keeps the previous object alive and billable.
//!
//! **Age is the safety margin.** Every one of those classes is
//! indistinguishable, from the outside, from work another DCTL process is doing
//! right now — an upload three seconds old is either abandoned or in flight,
//! and nothing in the object itself says which. `--min-age` is therefore the
//! load-bearing flag, not a tuning knob: it defaults to
//! [`CLEANUP_DEFAULT_MIN_AGE`], comfortably longer than any single verified
//! write, and lowering it risks deleting a concurrent run's staged parts.
//!
//! It is the **global** `--min-age` ([`crate::filter`]), not one of this
//! command's own, and that is a correction. This command used to declare a
//! second flag of the same name with a second parser behind it, in which `1M`
//! meant one *minute* while the same string means one *month* to rclone and to
//! every other age DCTL reads. Two dialects for one flag name inside one binary
//! is the drift that ends with a sweep deleting parts thirty times younger than
//! the operator intended, so there is now one spelling, one parser
//! ([`crate::filter::parse_age`]) and one meaning: "at least this old".
//!
//! The default survives the merge and is applied here rather than by `clap`,
//! because the global flag has no default and must not acquire one — an absent
//! `--min-age` on `copy` means "no age filter", while an absent `--min-age` on
//! `cleanup` has to mean [`CLEANUP_DEFAULT_MIN_AGE`] or the safety margin
//! disappears the moment somebody stops typing it.
//!
//! ## One class cannot be swept, and says so
//!
//! [`dctl_store::Backend`] exposes no way to list an object's superseded
//! versions. A sweep reporting "0 reclaimed" for a class it was never able to
//! *look* at would be the misreport
//! [the plan](https://doc.dctl.sh/project/plan) §6 forbids, so it emits an
//! explicit `unsupported` record naming the missing capability — and counts as
//! an error only when the user asked for it by name. See
//! [`super::removal::reclaim`], which also explains why the orphan sweep proves
//! the index is complete before it trusts an absence.
//!
//! `multipart` used to be the second and is not: the trait now carries
//! [`list_incomplete_uploads`](dctl_store::Backend::list_incomplete_uploads) and
//! [`abort_incomplete_upload`](dctl_store::Backend::abort_incomplete_upload) on
//! all five backends, so an upload a `SIGKILL` left open is reclaimed rather than
//! named.
//!
//! What was reclaimed is counted through
//! [`Stats::file_deleted`](crate::output::Stats::file_deleted) and the bytes
//! through the report's own summary record; this command introduces no second
//! vocabulary for the same numbers.

use clap::Args;

use std::time::Duration;

use crate::constants::{
    AGE_PARSE_EXAMPLES, CLEANUP_DEFAULT_MIN_AGE, FILTER_FLAG_MIN_AGE, REMOTE_ROOT_VALUE_NAME,
    REMOVAL_ACTION_CLEANUP, REMOVAL_LABEL_CLASSES, REMOVAL_LABEL_MIN_AGE, REMOVAL_LIST_SEPARATOR,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::output::size;
use serde::Serialize;

use super::removal::{Operation, PlanOptions, Removal, Row, Target, execute};

/// Stable command name. Must match `Command::name()` in `cli/mod.rs`.
const COMMAND: &str = "cleanup";

/// A class of reclaimable debris.
///
/// Defined in [`super::removal::reclaim`] beside the sweep that implements it,
/// and re-exported here because this is the command whose `--class` flag parses
/// it. Two definitions of one vocabulary is how a flag value and the thing it
/// selects drift apart.
pub use super::removal::Class as CleanupClass;

/// `dctl cleanup REMOTE:`
#[derive(Args, Debug)]
pub struct CleanupArgs {
    /// The remote to sweep, written REMOTE:. A path scopes the sweep to the
    /// objects beneath it, where the provider can list by prefix.
    ///
    /// Named `path` rather than `remote` because clap argument identifiers are
    /// unique across the whole command, and `--remote` is already a global
    /// flag — two arguments sharing an id is a startup panic, not a warning.
    /// It also keeps every command in the family reading `args.path`.
    #[arg(value_name = REMOTE_ROOT_VALUE_NAME)]
    pub path: String,

    /// Class of debris to reclaim. Repeatable; every class by default.
    #[arg(long = "class", value_enum, value_name = "CLASS")]
    pub classes: Vec<CleanupClass>,
}

impl CleanupArgs {
    /// The classes this run will sweep.
    ///
    /// An empty `--class` list means all of them: a cleanup that swept nothing
    /// by default would be a command that appeared to work and reclaimed
    /// nothing.
    #[must_use]
    pub fn selected(&self) -> Vec<CleanupClass> {
        if self.classes.is_empty() {
            CleanupClass::ALL.to_vec()
        } else {
            self.classes.clone()
        }
    }

    /// Whether the user named the classes rather than taking the default set.
    ///
    /// Decides one thing only, and it is the exit code: a class this backend
    /// cannot enumerate is a *failure to do what was asked* when it was asked
    /// for by name, and merely "nothing to do there" otherwise. Without the
    /// distinction, every default `cleanup` against a provider with no version
    /// API would exit 6 for ever and operators would learn to ignore it.
    #[must_use]
    pub fn named(&self) -> bool {
        !self.classes.is_empty()
    }
}

/// The `cleanup`-specific half of the plan.
#[derive(Debug, Serialize)]
struct CleanupOptions {
    classes: Vec<CleanupClass>,
    /// The margin in seconds, so a machine consumer never has to parse `24h`.
    min_age_secs: u64,
    /// The key infix that marks a staged object, quoted so the plan explains
    /// what the `staging` class will match.
    staging_marker: &'static str,
}

impl PlanOptions for CleanupOptions {
    fn rows(&self) -> Vec<Row> {
        let classes = self
            .classes
            .iter()
            .map(|class| class.slug())
            .collect::<Vec<_>>()
            .join(REMOVAL_LIST_SEPARATOR);
        vec![
            (REMOVAL_LABEL_CLASSES, classes),
            (REMOVAL_LABEL_MIN_AGE, size::duration(self.min_age_secs)),
        ]
    }
}

/// Run `dctl cleanup`.
///
/// # Errors
/// [`crate::exit::ExitCode::Usage`] for a malformed remote or an unparseable
/// `--min-age`; [`crate::exit::ExitCode::Cancelled`] if the user declines;
/// whatever opening the remote reported. A class that could not be swept is
/// reported rather than returned, and exits
/// [`crate::exit::ExitCode::PartialFailure`] when it was asked for by name.
pub async fn run(ctx: &Ctx, args: &CleanupArgs) -> Result<()> {
    let target = Target::parse(&args.path)?;
    let min_age = safety_margin(ctx.globals.min_age.as_deref())?;

    let removal = Removal {
        command: COMMAND,
        action: REMOVAL_ACTION_CLEANUP,
        target,
        // Debris has no logical path, so a path filter cannot select it.
        filters: None,
        options: CleanupOptions {
            classes: args.selected(),
            min_age_secs: min_age.as_secs(),
            staging_marker: dctl_store::STAGING_NAME_PREFIX,
        },
        operation: Operation::Cleanup {
            classes: args.selected(),
            min_age,
            named: args.named(),
        },
    };

    execute(ctx, &removal).await
}

/// The margin this sweep will leave, from the global `--min-age`.
///
/// An absent flag is [`CLEANUP_DEFAULT_MIN_AGE`]; an explicit `off` or `0` is a
/// margin of zero, which is a thing an operator may legitimately ask for after
/// stopping every other writer and is not silently substituted with the default.
/// The plan prints whichever it got, so a zero margin is visible on the line
/// above the destructive gate rather than discovered afterwards.
///
/// # Errors
/// [`crate::exit::ExitCode::Usage`] for an age that will not parse.
fn safety_margin(flag: Option<&str>) -> Result<Duration> {
    let written = flag.unwrap_or(CLEANUP_DEFAULT_MIN_AGE);
    let seconds = crate::filter::parse_age(written).map_err(|detail| {
        CliError::usage(format!("{FILTER_FLAG_MIN_AGE}: {detail}"))
            .with_hint(format!("Ages are written as {AGE_PARSE_EXAMPLES}."))
    })?;
    Ok(Duration::from_secs(
        seconds.unwrap_or(0).try_into().unwrap_or(0),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::globals::GlobalArgs;
    use crate::exit::ExitCode;
    use crate::output::Format;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
        #[command(flatten)]
        args: CleanupArgs,
    }

    fn parse(args: &[&str]) -> Harness {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()))
    }

    async fn run_with(args: &[&str]) -> Result<()> {
        let parsed = parse(args);
        run(&Ctx::new(parsed.globals), &parsed.args).await
    }

    fn options(args: &[&str]) -> CleanupOptions {
        let parsed = parse(args);
        CleanupOptions {
            classes: parsed.args.selected(),
            min_age_secs: safety_margin(parsed.globals.min_age.as_deref())
                .unwrap()
                .as_secs(),
            staging_marker: dctl_store::STAGING_NAME_PREFIX,
        }
    }

    #[test]
    fn the_target_is_positional_and_the_defaults_are_the_constants() {
        let parsed = parse(&["vault:"]);
        assert_eq!(parsed.args.path, "vault:");
        assert_eq!(
            safety_margin(parsed.globals.min_age.as_deref())
                .unwrap()
                .as_secs(),
            24 * 60 * 60,
            "an absent --min-age must still leave the default safety margin"
        );
        assert!(parsed.args.classes.is_empty());
        assert!(Harness::try_parse_from(["dctl"]).is_err());
    }

    #[test]
    fn no_class_selection_means_every_class() {
        // A default that swept nothing would be a command that only looked
        // like it worked.
        assert_eq!(parse(&["vault:"]).args.selected(), CleanupClass::ALL);
        assert_eq!(CleanupClass::ALL.len(), 4);
    }

    #[test]
    fn classes_are_repeatable_and_kept_in_order() {
        let parsed = parse(&["vault:", "--class", "staging", "--class", "multipart"]);
        assert_eq!(
            parsed.args.selected(),
            [CleanupClass::Staging, CleanupClass::Multipart]
        );
    }

    #[test]
    fn an_unknown_class_is_rejected_by_the_parser() {
        assert!(Harness::try_parse_from(["dctl", "vault:", "--class", "everything"]).is_err());
    }

    #[test]
    fn naming_a_class_is_distinguishable_from_taking_the_default_set() {
        // The bit that decides whether an unsweepable class is an error.
        assert!(!parse(&["vault:"]).args.named());
        assert!(parse(&["vault:", "--class", "staging"]).args.named());
    }

    #[tokio::test]
    async fn an_unparseable_age_fails_before_the_destructive_gate() {
        let error = run_with(&["vault:", "--min-age", "banana", "--force"])
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_malformed_remote_is_refused() {
        let error = run_with(&["vault", "--force"]).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_sweep_of_an_unknown_remote_fails_rather_than_reclaiming_nothing() {
        // The specific lie this guards against: "reclaimed 0 bytes" from a
        // sweep that was never able to look at anything.
        let error = run_with(&["vault:", "--force", "--quiet", "--no-ask-password"])
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("vault"), "{}", error.message());
    }

    #[test]
    fn the_json_plan_quotes_the_age_in_seconds_and_names_the_classes() {
        let target = Target::parse("vault:").unwrap();
        let options = options(&["vault:", "--class", "staging", "--min-age", "2h"]);
        let plan =
            crate::commands::removal::plan::Plan::new(COMMAND, &target, true, None, &options);

        let encoded = Format::Json.encode(&plan).unwrap();
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(value["command"], COMMAND);
        assert_eq!(value["options"]["classes"][0], "staging");
        assert_eq!(value["options"]["min_age_secs"], 7200);
        assert_eq!(
            value["options"]["staging_marker"],
            dctl_store::STAGING_NAME_PREFIX
        );
        assert!(value.get("filters").is_none());
    }

    #[test]
    fn the_text_plan_shows_the_age_the_way_dctl_prints_durations() {
        let rows = options(&["vault:", "--min-age", "2h"]).rows();
        assert_eq!(rows[1].0, REMOVAL_LABEL_MIN_AGE);
        assert_eq!(
            rows[1].1,
            size::duration(2 * crate::constants::SECONDS_PER_HOUR)
        );
    }
}
