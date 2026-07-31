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
//! 1. walk the remote and select the objects the plan covers;
//! 2. read each one back in full and check it as strongly as that remote allows;
//! 3. report a health grade — `healthy`, `degraded` or `damaged` — together with
//!    *how much of the dataset was actually read* and *what the reading proved*,
//!    so the grade cannot be mistaken for a claim about the part that was
//!    skipped, or for a stronger claim than the remote can support.
//!
//! ## The coverage is the report, and it is always printed
//!
//! Step 3 is not optional and is not behind `-v`. Everything this command said
//! about a healthy run used to go through [`Out::info`](crate::output::Out::info),
//! which is silent below `-v`, and the findings table renders empty when there
//! are no findings — so the default output of a successful scrub was *nothing at
//! all*, on both streams. `dctl scrub archive:` over a real dataset and
//! `dctl scrub archive:typo` over nothing produced byte-identical output and the
//! same exit code.
//!
//! So a text-mode run always writes one line to stderr naming the grade, the
//! objects read, the bytes, the assurance and the target
//! ([`Report::announce`](report::Report::announce)). JSON mode does not: the
//! document already carries every one of those numbers, and a second prose
//! rendering is a second thing that can disagree with the data.
//!
//! ## Reading nothing is a distinct outcome, and it is not zero
//!
//! A run that scanned no object grades
//! [`HEALTH_UNVERIFIED`](crate::constants::HEALTH_UNVERIFIED) and exits
//! [`ExitCode::NoFilesTransferred`](crate::exit::ExitCode::NoFilesTransferred)
//! (9). Health is a claim about objects that were read; over none of them there
//! is no claim, and `healthy` is the most reassuring of the four words to pick
//! for it. The exit code moves because that is the only part a cron wrapper
//! reads — see [`Report::outcome`](report::Report::outcome) for why 9 rather
//! than a new number, and for the four causes the message distinguishes.
//!
//! ## `--repair` is refused, not ignored
//!
//! Repair means rebuilding a damaged object from redundancy — the par2-style
//! Reed-Solomon parity of `PLAN.md` §13.3 — and this build writes no parity, so
//! there is nothing to rebuild from. The flag is therefore **refused with an
//! error** rather than accepted and quietly dropped: a run that printed
//! `damaged` after silently doing nothing would leave the operator believing a
//! repair had been attempted and failed for some other reason, which is worse
//! than being told plainly that the capability is not there yet.
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
//! ## What a pass proves, and why the report says so
//!
//! A sealed vault checks every chunk's authentication tag and the object's own
//! recorded content hash, so `healthy` there means *these are the bytes that
//! were written*. A plain remote — including the object store a vault's
//! ciphertext lives in — records no hash of its own, so the strongest honest
//! claim is *the object was still there and every byte of it came back*. That is
//! genuinely useful (it is how a replica quietly losing objects is caught) and it
//! is not the same statement, so the report carries which one it is. See
//! [`crate::source::Assurance`].
//!
//! ## The `--verify` dial
//!
//! Every selected object is read back **in full**, whatever `--verify` says.
//! There is no provider-checksum comparison behind a scrub in this build — the
//! only integrity primitives `dctl_core` exposes read the object — so a cheaper
//! strength cannot be honoured. The run warns when one was asked for, and the
//! report records the strength that actually ran rather than the one requested,
//! because a report naming a check that did not happen is the misreport
//! `PLAN.md` §6 forbids.

pub mod engine;
pub mod plan;
pub mod report;

use clap::Args;

use crate::cli::VerifyMode;
use crate::commands::integrity::assurance::{self, AssuranceArgs};
use crate::commands::integrity::{Target, command_name, mode};
use crate::commands::listing::Filter;
use crate::constants::{
    SCRUB_FULL_SAMPLE_PERCENT, SCRUB_MAX_ERRORS_UNLIMITED, SCRUB_MIN_SAMPLE_PERCENT,
    SCRUB_REPAIR_UNAVAILABLE, SCRUB_REPAIR_UNAVAILABLE_HINT,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};

use plan::Plan;
use report::Report;

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
    /// Refused by this build: no redundancy is written for it to read. The flag
    /// stays declared so the refusal names it and explains what would have to
    /// exist first — silently accepting a flag that does nothing is how an
    /// operator comes to believe a repair was attempted.
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

    /// What this run will accept as proof. See
    /// [`assurance`](crate::commands::integrity::assurance).
    #[command(flatten)]
    pub assurance: AssuranceArgs,
}

/// Re-read and verify a dataset, reporting its health.
///
/// # Errors
/// [`CliError::usage`] for a malformed or local target, an out-of-range sample,
/// or `--repair`, which this build cannot honour; whatever opening the remote
/// reported; and the integrity family's classified failure when damage is found
/// — [`ExitCode::IntegrityFailure`](crate::exit::ExitCode::IntegrityFailure) for
/// objects that did not authenticate, and the availability codes for objects
/// that were missing or unreachable.
///
/// Also
/// [`ExitCode::NoFilesTransferred`](crate::exit::ExitCode::NoFilesTransferred)
/// when the run read no object at all. Nothing failed there; nothing was proved
/// either, and a scheduled scrub that exits 0 while verifying nothing is the
/// exact failure `PLAN.md` §13.4 exists to prevent.
pub async fn run(ctx: &Ctx, args: &ScrubArgs) -> Result<()> {
    let command = command_name(VERB);
    let target = Target::parse(&args.target)?;
    // A scrub reads stored objects back from a remote. A local directory is not
    // a remote holding a copy of anything, so there is nothing here to scrub —
    // and saying so beats reporting "0 objects, healthy".
    target.require_remote(&command)?;

    // Refused before anything opens, so the run never gets far enough to look
    // like it tried. `--dry-run` does not soften this: a dry run of an
    // impossible operation is still impossible, and printing "would repair"
    // would promise a capability that does not exist.
    if args.repair {
        return Err(
            CliError::usage(SCRUB_REPAIR_UNAVAILABLE).with_hint(SCRUB_REPAIR_UNAVAILABLE_HINT)
        );
    }

    // `false`, and not `args.repair`: the plan carries what will happen, and
    // nothing in this build repairs.
    let plan = Plan::seeded(args.sample_percent, args.max_errors, false)?;

    // Compiled before the remote opens, so a malformed `--include` fails before
    // a password is asked for.
    let filter = Filter::from_globals(&ctx.globals)?;

    let opened = crate::source::open(ctx, &target.spec()).await?;
    let assurance = opened.source().assurance();

    // Every object is read back in full, so the strength that ran is `strict`
    // whatever was asked for. Reporting the requested one instead would name a
    // check that did not happen.
    let performed = VerifyMode::Strict;
    ctx.out.info(format!(
        "{command}: {target} at --verify={} — {}",
        mode::slug(performed),
        mode::describe(performed)
    ));

    // The target's own policy, not the flag alone: `verify = "strict"` on the
    // remote being scrubbed is the operator saying how hard this destination is
    // checked, and it was read by nothing until §29.
    let requested = ctx.verify_mode_for(&target.spec())?;
    if !mode::proves_whole_plaintext(requested) {
        ctx.out.warn(format!(
            "--verify={} asks for a cheaper check than a scrub can perform in this \
             build: there is no provider-checksum comparison behind `{command}`, so \
             every selected object is read back in full",
            mode::slug(requested)
        ));
    }
    // Before a byte is read, and for the reason `verify` refuses in the same
    // place: a scheduled scrub that grades a plain remote `healthy` is telling
    // an operator nothing while they believe they are being told everything.
    assurance::require(&command, &target.to_string(), assurance, &args.assurance)?;
    if !assurance.detects_corruption() {
        // Reached only when the operator asked for this with `--allow-read-back`.
        // The grade would otherwise be read as a statement about the bytes, and
        // this remote cannot make one.
        ctx.out.warn(format!(
            "'{target}' records no hash of its own — {}",
            assurance.describe()
        ));
    }

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

    let mut report = Report::new(
        target.to_string(),
        mode::slug(performed),
        assurance,
        plan.sample_percent(),
        plan.seed(),
        plan.repairs(),
    );
    engine::scrub(
        ctx,
        opened.source(),
        opened.prefix(),
        &filter,
        &plan,
        &mut report,
    )
    .await?;

    report.emit(&ctx.out)?;
    // Text mode only: the JSON document already carries `health` and the whole
    // `coverage` object, and a second, prose rendering of the same numbers on
    // stderr would be one more thing that can disagree with the data. In text
    // mode there is no such document, and the coverage would otherwise be
    // invisible — which was the defect.
    if !ctx.out.is_json() {
        report.announce(&ctx.out);
    }
    report.outcome().map_or(Ok(()), Err)
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
    async fn repair_is_refused_rather_than_quietly_ignored() {
        // Accepting the flag and doing nothing would leave the operator
        // believing a repair was attempted and failed for some other reason.
        let (ctx, args) = parse(&["scrub", "vault:", "--repair"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("--repair"));
        // The refusal has to name what would have to exist first.
        let hint = error.hint().expect("a refusal must say what to do next");
        assert!(hint.contains("§13.3"), "got: {hint}");
    }

    #[tokio::test]
    async fn a_dry_run_does_not_soften_the_repair_refusal() {
        // A dry run of an impossible operation is still impossible, and
        // "[dry-run] would repair" would promise a capability that is not there.
        let (ctx, args) = parse(&["scrub", "vault:", "--repair", "--dry-run"]);
        assert!(ctx.is_dry_run());
        assert_eq!(run(&ctx, &args).await.unwrap_err().code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn an_unresolvable_remote_is_an_error_rather_than_a_health_grade() {
        // Printing "healthy" for a dataset nothing read would be the exact lie
        // this command exists to prevent.
        let (ctx, args) = parse(&["scrub", "nosuchremote:", "--no-ask-password"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("nosuchremote"));
    }

    /// A configured plain remote over a temporary directory, plus the argument
    /// that points DCTL at the configuration naming it.
    fn plain_remote(files: &[(&str, &[u8])]) -> (tempfile::TempDir, String) {
        let dir = tempfile::TempDir::new().expect("a temporary directory");
        let root = dir.path().join("root");
        for (relative, bytes) in files {
            let path = root.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("the parent directory is created");
            }
            std::fs::write(&path, bytes).expect("the fixture file is written");
        }
        std::fs::create_dir_all(&root).expect("the root exists even when empty");

        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[remotes.store]\ntype = \"local\"\npath = {:?}\n",
                root.to_string_lossy()
            ),
        )
        .expect("the configuration is written");
        let path = config.to_string_lossy().into_owned();
        (dir, path)
    }

    #[tokio::test]
    async fn a_clean_remote_scrubs_to_healthy_and_exits_zero() {
        // `local:` records no digest, so the run has to say which check it is
        // asking for. With that said, an intact store passes it.
        let (_dir, config) = plain_remote(&[("a.txt", b"1"), ("sub/b.txt", b"22")]);
        let (ctx, args) = parse(&["scrub", "store:", "--config", &config, "--allow-read-back"]);
        run(&ctx, &args)
            .await
            .expect("an intact remote must not fail the run");
    }

    #[tokio::test]
    async fn a_plain_remote_is_refused_rather_than_graded_healthy() {
        // `scrub`'s half of the defect, and it needs its own test because the
        // two commands reach the gate down different paths — `verify` from a
        // listing walk, `scrub` from the index — and a claim only one of them
        // enforced is a claim nobody can rely on. That is the exact history of
        // the `assurance` field itself (`HANDOVER.md` §31.4).
        let (_dir, config) = plain_remote(&[("a.txt", b"1"), ("sub/b.txt", b"22")]);
        let (ctx, args) = parse(&["scrub", "store:", "--config", &config]);

        let error = run(&ctx, &args)
            .await
            .expect_err("a remote that cannot detect rot must not be graded healthy");
        assert_eq!(error.code(), ExitCode::VerificationNotPossible);
        assert_eq!(error.code().as_i32(), 27);
        assert_ne!(error.code(), ExitCode::IntegrityFailure);
    }

    #[tokio::test]
    async fn a_prefix_scrubs_only_what_is_under_it() {
        let (_dir, config) = plain_remote(&[("photos/a.jpg", b"1"), ("other/b.jpg", b"2")]);
        let (ctx, args) = parse(&[
            "scrub",
            "store:photos",
            "--config",
            &config,
            "--allow-read-back",
        ]);
        run(&ctx, &args).await.expect("the prefix reads back clean");
    }

    #[tokio::test]
    async fn every_output_format_is_accepted() {
        let (_dir, config) = plain_remote(&[("a.txt", b"1")]);
        for format in [&["--json"][..], &["--format", "json-lines"][..], &[][..]] {
            let mut argv = vec![
                "scrub",
                "store:",
                "--config",
                config.as_str(),
                "--allow-read-back",
            ];
            argv.extend_from_slice(format);
            let (ctx, args) = parse(&argv);
            run(&ctx, &args)
                .await
                .expect("the format must not change the outcome");
        }
    }

    #[tokio::test]
    async fn a_sealed_vault_scrubs_end_to_end_and_reports_damage() {
        // The whole command, wired: configuration, vault chain, unlock, index
        // walk, authenticated read-back, grade, exit code.
        use std::sync::Arc;

        use dctl_core::Vault;
        use dctl_store::{Backend, LocalFs};

        let dir = tempfile::TempDir::new().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        let index = dir.path().join("index.redb");

        {
            let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(&store));
            let vault = Vault::init(backend, &index, "pw").await.unwrap().vault;
            vault
                .put_file("photos/a.jpg", b"aaa", dctl_core::Modified::Now)
                .await
                .unwrap();
            vault
                .put_file("notes.txt", b"n", dctl_core::Modified::Now)
                .await
                .unwrap();
        }

        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[remotes.store]\ntype = \"local\"\npath = {:?}\nrequire_vault = true\n\n\
                 [remotes.archive]\ntype = \"vault\"\nbase = \"store\"\n",
                store.to_string_lossy()
            ),
        )
        .unwrap();

        let config = config.to_string_lossy().into_owned();
        let index = index.to_string_lossy().into_owned();
        let argv = [
            "scrub",
            "archive:",
            "--config",
            &config,
            "--index",
            &index,
            "--password",
            "pw",
        ];

        let (ctx, args) = parse(&argv);
        run(&ctx, &args)
            .await
            .expect("an intact vault scrubs healthy");

        // Now damage what the provider is holding, reaching past DCTL entirely,
        // and confirm the same command notices.
        for entry in std::fs::read_dir(store.join("o")).unwrap() {
            let path = entry.unwrap().path();
            let length = std::fs::metadata(&path).unwrap().len();
            std::fs::write(&path, vec![0xA5; length as usize]).unwrap();
        }

        let (ctx, args) = parse(&argv);
        let error = run(&ctx, &args)
            .await
            .expect_err("damaged objects must fail the run");
        assert_eq!(error.code(), ExitCode::IntegrityFailure);
        assert_eq!(error.code().as_i32(), 21);
        assert!(
            error.message().contains("NOT served"),
            "got: {}",
            error.message()
        );
    }
}
