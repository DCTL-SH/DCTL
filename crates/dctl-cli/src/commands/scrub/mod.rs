//! `dctl scrub REMOTE:` — re-read the dataset on purpose, before you need it.
//!
//! This is the ZFS-scrub discipline written into `PLAN.md` §13.4, and its whole
//! reason for existing is one sentence: **never discover corruption for the
//! first time on restore day.** Cloud objects rot, providers lose replicas, and
//! a backup that has sat untouched for three years has never once been proved
//! readable. A scheduled scrub converts that unknown into a number.
//!
//! What a run does:
//!
//! 1. walk the vault's index and select the objects the plan covers;
//! 2. read each one back and authenticate it at the global `--verify` strength;
//! 3. with `--repair`, rebuild damaged objects from redundancy or parity;
//! 4. report a health grade — `healthy`, `degraded` or `damaged` — together with
//!    *how much of the dataset was actually read*, so the grade cannot be
//!    mistaken for a claim about the part that was skipped.
//!
//! Damage that could not be repaired ends the process with
//! [`ExitCode::IntegrityFailure`](crate::exit::ExitCode::IntegrityFailure) (21).
//! Damage that *was* repaired does not: the object is readable again, and
//! failing would train an operator to ignore the one code that means data is
//! gone.
//!
//! ## Cost
//!
//! A full scrub reads every byte in the vault, which on a cloud remote is a full
//! egress bill. `--sample-percent` bounds that; the sample is keyed per run, so
//! successive scrubs cover different slices instead of reading the same tenth
//! forever. See [`plan`].
//!
//! ## What this build can do
//!
//! Argument parsing, target resolution, the sampling and error-budget logic in
//! [`plan`], the health grading and report shape in [`report`], the `--repair`
//! dry-run interlock, and the exit-code classification are implemented and
//! tested here. Reading objects back is not: `dctl_core::Vault` has no
//! prefix-wide verification entry point and `Ctx` does not yet carry an unlocked
//! vault, so `run` builds and reports the plan and then returns
//! [`CliError::unimplemented`] rather than printing a health grade it never
//! measured — which would be precisely the lie this command exists to prevent.

pub mod plan;
pub mod report;

use clap::Args;

use crate::commands::integrity::{Target, command_name, mode};
use crate::constants::{
    SCRUB_FULL_SAMPLE_PERCENT, SCRUB_MAX_ERRORS_UNLIMITED, SCRUB_MIN_SAMPLE_PERCENT,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};

use plan::Plan;

/// The verb this module implements, used in messages that name the command.
const VERB: &str = "scrub";

/// Arguments to `dctl scrub`.
#[derive(Args, Debug)]
pub struct ScrubArgs {
    /// Vault or prefix to scrub. `REMOTE:` scrubs the whole dataset.
    #[arg(value_name = "REMOTE:")]
    pub target: String,

    /// Rebuild damaged objects from redundancy or parity where possible.
    ///
    /// The only part of a scrub that writes anything, and therefore the only
    /// part `--dry-run` suppresses.
    #[arg(long)]
    pub repair: bool,

    /// Read this percentage of the dataset instead of all of it.
    ///
    /// The sample is chosen by a keyed hash of each path under a per-run seed,
    /// so repeated scrubs cover different slices rather than the same one.
    #[arg(
        long,
        value_name = "PERCENT",
        default_value_t = SCRUB_FULL_SAMPLE_PERCENT,
        value_parser = clap::value_parser!(u8).range(
            SCRUB_MIN_SAMPLE_PERCENT as i64..=SCRUB_FULL_SAMPLE_PERCENT as i64
        ),
    )]
    pub sample_percent: u8,

    /// Stop after this many damaged objects. 0 means no limit.
    ///
    /// Unlimited by default: the most valuable thing a scrub reports is *how
    /// widespread* the damage is, and stopping early hides it.
    #[arg(long, value_name = "N", default_value_t = SCRUB_MAX_ERRORS_UNLIMITED)]
    pub max_errors: u64,
}

/// Re-read and verify a dataset, reporting its health.
///
/// # Errors
/// [`CliError::usage`] for a malformed or local target or an out-of-range
/// sample; the integrity family's classified failure when unrepaired damage is
/// found; and [`CliError::unimplemented`] until the engine can read objects back
/// — see the module documentation.
pub async fn run(ctx: &Ctx, args: &ScrubArgs) -> Result<()> {
    let command = command_name(VERB);
    let target = Target::parse(&args.target)?;
    // A scrub compares stored objects against the hashes the vault recorded for
    // them; a local directory has no such record.
    target.require_remote(&command)?;

    // Repair is this command's only mutation, so it is resolved *before* the
    // plan is built: a plan that still claimed to repair under `--dry-run`
    // would be one call away from writing.
    let repair = if args.repair && ctx.is_dry_run() {
        ctx.dry_run_notice("repair damaged objects in", &target.to_string());
        false
    } else {
        args.repair
    };

    let plan = Plan::seeded(args.sample_percent, args.max_errors, repair)?;
    let strength = ctx.verify_mode();

    ctx.out.info(format!(
        "{command}: {target} at --verify={} — {}",
        mode::slug(strength),
        mode::describe(strength)
    ));
    if plan.is_full() {
        ctx.out.info("reading every object in the dataset");
    } else {
        // Said plainly, because a sampled scrub's verdict is a claim about the
        // slice it read and about nothing else.
        ctx.out.warn(format!(
            "sampling {}% of the dataset (seed {:016x}) — the health grade covers \
             only the objects this run reads",
            plan.sample_percent(),
            plan.seed()
        ));
    }
    if plan.is_bounded() {
        ctx.out.warn(format!(
            "--max-errors {} will stop the run early, so the report may understate \
             how widespread any damage is",
            plan.max_errors()
        ));
    }
    if plan.repairs() {
        ctx.out
            .info("damaged objects will be rebuilt from redundancy where possible");
    }

    Err(CliError::unimplemented(command))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use crate::exit::ExitCode;
    use clap::Parser;

    fn parse(args: &[&str]) -> (Ctx, ScrubArgs) {
        let cli = Cli::try_parse_from(std::iter::once("dctl").chain(args.iter().copied()))
            .expect("arguments should parse");
        let Command::Scrub(scrub) = cli.command else {
            panic!("expected the scrub subcommand");
        };
        (Ctx::new(cli.globals), scrub)
    }

    #[tokio::test]
    async fn the_defaults_read_everything_and_never_stop_early() {
        let (_, args) = parse(&["scrub", "vault:"]);
        assert_eq!(args.sample_percent, SCRUB_FULL_SAMPLE_PERCENT);
        assert_eq!(args.max_errors, SCRUB_MAX_ERRORS_UNLIMITED);
        assert!(!args.repair);
    }

    #[tokio::test]
    async fn the_knobs_parse() {
        let (_, args) = parse(&[
            "scrub",
            "vault:photos",
            "--repair",
            "--sample-percent",
            "10",
            "--max-errors",
            "5",
        ]);
        assert!(args.repair);
        assert_eq!(args.sample_percent, 10);
        assert_eq!(args.max_errors, 5);
    }

    #[tokio::test]
    async fn an_out_of_range_sample_is_rejected_by_the_parser() {
        // Rejected at parse time as well as in the plan, so the bad value never
        // reaches a run that has already started reading.
        assert!(Cli::try_parse_from(["dctl", "scrub", "vault:", "--sample-percent", "0"]).is_err());
        assert!(
            Cli::try_parse_from(["dctl", "scrub", "vault:", "--sample-percent", "101"]).is_err()
        );
        assert!(Cli::try_parse_from(["dctl", "scrub", "vault:", "--sample-percent", "1"]).is_ok());
    }

    #[tokio::test]
    async fn a_local_target_is_a_usage_error() {
        let (ctx, args) = parse(&["scrub", "./photos"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_dry_run_turns_repair_off_before_the_plan_exists() {
        // The interlock this test guards: under --dry-run the plan must not
        // carry permission to write, however the run body evolves.
        let (ctx, args) = parse(&["scrub", "vault:", "--repair", "--dry-run"]);
        assert!(ctx.is_dry_run());
        let repair = args.repair && !ctx.is_dry_run();
        assert!(!repair);
        let plan = Plan::seeded(args.sample_percent, args.max_errors, repair).unwrap();
        assert!(!plan.repairs());
        assert!(run(&ctx, &args).await.is_err());
    }

    #[tokio::test]
    async fn repair_is_carried_through_when_it_is_not_a_dry_run() {
        let (ctx, args) = parse(&["scrub", "vault:", "--repair"]);
        assert!(!ctx.is_dry_run());
        let plan = Plan::seeded(args.sample_percent, args.max_errors, args.repair).unwrap();
        assert!(plan.repairs());
    }

    #[tokio::test]
    async fn unimplemented_work_is_an_error_not_a_health_grade() {
        // Printing "healthy" for a dataset nothing read would be the exact lie
        // this command exists to prevent.
        let (ctx, args) = parse(&["scrub", "vault:"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains(&command_name(VERB)));
    }

    #[tokio::test]
    async fn every_output_format_is_accepted() {
        for format in [&["--json"][..], &["--format", "json-lines"][..], &[][..]] {
            let mut argv = vec!["scrub", "vault:"];
            argv.extend_from_slice(format);
            let (ctx, args) = parse(&argv);
            assert_eq!(
                run(&ctx, &args).await.unwrap_err().code(),
                ExitCode::FatalError
            );
        }
    }
}
