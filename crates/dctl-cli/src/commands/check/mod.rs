//! `dctl check SOURCE DEST` — compare two trees without transferring anything.
//!
//! `PLAN.md` §13.6 is blunt about why this exists: a backup nobody ever compared
//! against its source is a hope, not a backup. `check` is the command that turns
//! the hope into a measurement, and it is also the safest command in the tool —
//! it reads, it never writes to either side, and it cannot be talked into
//! copying something "while it is there".
//!
//! Every path lands in exactly one of five buckets:
//!
//! | verdict          | meaning                                    |
//! |------------------|--------------------------------------------|
//! | `match`          | on both sides and the same                 |
//! | `differ`         | on both sides, contents disagree           |
//! | `missing-on-dst` | only at the source                         |
//! | `missing-on-src` | only at the destination                    |
//! | `error`          | could not be compared — never a silent pass |
//!
//! *What* "the same" means is the global comparison dial: size and modification
//! time by default, `--size-only`, or `--checksum` — the only one that proves
//! the contents match. The report always names which one ran, because "0
//! differences" is a very different claim under each.
//!
//! The `--combined`, `--differ`, `--match` and `--missing-on-*` flags write the
//! verdicts to files. A per-verdict file carries bare paths, so
//! `dctl check src: dst: --missing-on-dst todo.txt` followed by
//! `dctl copy src: dst: --files-from todo.txt` is the whole repair loop.
//!
//! ## What this build can do
//!
//! Argument parsing, target resolution, output-file validation (including the
//! two-flags-one-file mistake), the comparison logic in
//! [`difference`], the file writers in [`sinks`], the report shape in all three
//! formats and the exit-code classification are implemented and tested here. The
//! step that enumerates two remotes is not: `dctl_core::Vault` can list one
//! prefix but `Ctx` does not yet carry an unlocked vault, and there is no local
//! walker. `run` therefore validates everything it can, creates nothing, and
//! returns [`CliError::unimplemented`] rather than printing a comparison it
//! never performed.

pub mod difference;
pub mod report;
pub mod sinks;

use std::path::PathBuf;

use clap::Args;

use crate::commands::integrity::{Target, command_name};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};

use difference::Comparison;
use sinks::Destinations;

/// The verb this module implements, used in messages that name the command.
const VERB: &str = "check";

/// Arguments to `dctl check`.
#[derive(Args, Debug)]
pub struct CheckArgs {
    /// Tree to compare from.
    #[arg(value_name = "SOURCE")]
    pub source: String,

    /// Tree to compare against.
    #[arg(value_name = "DEST")]
    pub dest: String,

    /// Ignore paths that exist only at the destination.
    ///
    /// Asks "is everything from the source present and correct at the
    /// destination?", which is the right question after a `copy` — extra files
    /// at the destination are what `copy` leaves behind by design.
    #[arg(long)]
    pub one_way: bool,

    /// Write every path with its one-character verdict mark to FILE.
    #[arg(long, value_name = "FILE")]
    pub combined: Option<PathBuf>,

    /// Write paths that exist only at the destination to FILE.
    #[arg(long, value_name = "FILE")]
    pub missing_on_src: Option<PathBuf>,

    /// Write paths that exist only at the source to FILE.
    #[arg(long, value_name = "FILE")]
    pub missing_on_dst: Option<PathBuf>,

    /// Write paths that exist on both sides but differ to FILE.
    #[arg(long, value_name = "FILE")]
    pub differ: Option<PathBuf>,

    /// Write paths that matched to FILE.
    // Named explicitly because `match` is a Rust keyword; the flag a user types
    // must still be `--match`.
    #[arg(long = "match", value_name = "FILE")]
    pub matched: Option<PathBuf>,
}

impl CheckArgs {
    /// The verdict files this run was asked to produce.
    #[must_use]
    pub fn destinations(&self) -> Destinations {
        Destinations {
            combined: self.combined.clone(),
            missing_on_src: self.missing_on_src.clone(),
            missing_on_dst: self.missing_on_dst.clone(),
            differ: self.differ.clone(),
            matched: self.matched.clone(),
        }
    }
}

/// Compare two trees and report their differences.
///
/// # Errors
/// [`CliError::usage`] for a malformed path or an unusable output file;
/// [`ExitCode::PartialFailure`](crate::exit::ExitCode::PartialFailure) when the
/// two sides disagree; and [`CliError::unimplemented`] until the engine can
/// enumerate both sides — see the module documentation.
pub async fn run(ctx: &Ctx, args: &CheckArgs) -> Result<()> {
    let command = command_name(VERB);
    let source = Target::parse(&args.source)?;
    let dest = Target::parse(&args.dest)?;

    // Check the output files before comparing anything: the mistake is almost
    // always a typo, and finding it after a multi-hour walk helps nobody. This
    // deliberately creates nothing — see `sinks`.
    let destinations = args.destinations();
    destinations.validate()?;

    let comparison = Comparison::from_globals(&ctx.globals);
    ctx.out.info(format!(
        "{command}: '{source}' against '{dest}'{}",
        if args.one_way {
            ", ignoring paths that exist only at the destination"
        } else {
            ""
        }
    ));
    if !comparison.proves_contents() {
        // Worth saying plainly: a metadata comparison can call two files equal
        // when their contents are not, and someone using `check` to validate a
        // backup usually wants the stronger claim.
        ctx.out
            .info("comparing metadata only — pass --checksum to prove the contents match");
    }

    // Writing the verdict files is this command's only mutation, so it is the
    // only thing --dry-run has to suppress. Nothing is created here or below.
    if ctx.is_dry_run() && !destinations.is_empty() {
        for path in [
            args.combined.as_ref(),
            args.missing_on_src.as_ref(),
            args.missing_on_dst.as_ref(),
            args.differ.as_ref(),
            args.matched.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            ctx.dry_run_notice("write", &path.display().to_string());
        }
    }

    Err(CliError::unimplemented(command))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use crate::exit::ExitCode;
    use clap::Parser;

    fn parse(args: &[&str]) -> (Ctx, CheckArgs) {
        let cli = Cli::try_parse_from(std::iter::once("dctl").chain(args.iter().copied()))
            .expect("arguments should parse");
        let Command::Check(check) = cli.command else {
            panic!("expected the check subcommand");
        };
        (Ctx::new(cli.globals), check)
    }

    #[tokio::test]
    async fn both_sides_are_required() {
        assert!(Cli::try_parse_from(["dctl", "check", "vault:"]).is_err());
        assert!(Cli::try_parse_from(["dctl", "check"]).is_err());
    }

    #[tokio::test]
    async fn the_verdict_files_parse_under_their_flag_names() {
        // `--match` is spelled with a keyword; the field behind it is not.
        let (_, args) = parse(&[
            "check",
            "vault:photos",
            "./photos",
            "--combined",
            "all.txt",
            "--missing-on-src",
            "src.txt",
            "--missing-on-dst",
            "dst.txt",
            "--differ",
            "differ.txt",
            "--match",
            "same.txt",
            "--one-way",
        ]);
        assert!(args.one_way);
        let destinations = args.destinations();
        assert!(!destinations.is_empty());
        assert_eq!(destinations.combined, Some(PathBuf::from("all.txt")));
        assert_eq!(destinations.matched, Some(PathBuf::from("same.txt")));
        assert_eq!(destinations.differ, Some(PathBuf::from("differ.txt")));
    }

    #[tokio::test]
    async fn no_flags_means_no_output_files() {
        let (_, args) = parse(&["check", "src:", "dst:"]);
        assert!(args.destinations().is_empty());
        assert!(!args.one_way);
    }

    #[tokio::test]
    async fn a_malformed_path_is_a_usage_error() {
        let (ctx, args) = parse(&["check", "vault:../escape", "./photos"]);
        assert_eq!(run(&ctx, &args).await.unwrap_err().code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn two_flags_aimed_at_one_file_are_rejected_before_any_work() {
        let (ctx, args) = parse(&[
            "check", "src:", "dst:", "--differ", "out.txt", "--match", "out.txt",
        ]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some());
    }

    #[tokio::test]
    async fn a_missing_output_directory_is_reported_up_front() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope").join("out.txt");
        let path = missing.to_string_lossy().into_owned();
        let (ctx, args) = parse(&["check", "src:", "dst:", "--combined", &path]);
        assert_eq!(
            run(&ctx, &args).await.unwrap_err().code(),
            ExitCode::DirNotFound
        );
    }

    #[tokio::test]
    async fn a_dry_run_creates_no_verdict_files() {
        // The command's only mutation is writing these files, so --dry-run must
        // leave the directory exactly as it found it.
        let dir = tempfile::tempdir().unwrap();
        let combined = dir.path().join("all.txt");
        let path = combined.to_string_lossy().into_owned();
        let (ctx, args) = parse(&["check", "src:", "dst:", "--combined", &path, "--dry-run"]);
        assert!(ctx.is_dry_run());
        assert!(run(&ctx, &args).await.is_err());
        assert!(!combined.exists(), "--dry-run must write nothing");
    }

    #[tokio::test]
    async fn a_failed_run_leaves_no_empty_files_behind() {
        // Creating the files up front and then failing would leave artefacts a
        // later script could mistake for "no differences found".
        let dir = tempfile::tempdir().unwrap();
        let differ = dir.path().join("differ.txt");
        let path = differ.to_string_lossy().into_owned();
        let (ctx, args) = parse(&["check", "src:", "dst:", "--differ", &path]);
        assert!(run(&ctx, &args).await.is_err());
        assert!(!differ.exists());
    }

    #[tokio::test]
    async fn unimplemented_work_is_an_error_not_a_success() {
        let (ctx, args) = parse(&["check", "vault:photos", "./photos"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains(&command_name(VERB)));
    }

    #[tokio::test]
    async fn the_comparison_follows_the_global_flags() {
        let (ctx, _) = parse(&["check", "src:", "dst:", "--checksum"]);
        assert_eq!(Comparison::from_globals(&ctx.globals), Comparison::Checksum);
        let (ctx, _) = parse(&["check", "src:", "dst:", "--size-only"]);
        assert_eq!(Comparison::from_globals(&ctx.globals), Comparison::SizeOnly);
    }

    #[tokio::test]
    async fn every_output_format_is_accepted() {
        for format in [&["--json"][..], &["--format", "json-lines"][..], &[][..]] {
            let mut argv = vec!["check", "src:", "dst:"];
            argv.extend_from_slice(format);
            let (ctx, args) = parse(&argv);
            assert_eq!(
                run(&ctx, &args).await.unwrap_err().code(),
                ExitCode::FatalError
            );
        }
    }
}
