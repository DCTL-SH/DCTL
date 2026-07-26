//! `dctl backup LOCAL REMOTE:` — store a local tree in a vault.
//!
//! `backup` is `copy` with two additions that only make sense for an archive:
//! it can mark the run as a **snapshot**, and it runs the name pre-flight over
//! everything it is about to store (`PLAN.md` §13.6). The second is the point.
//! A filename that is legal on this machine and illegal on the machine that will
//! one day restore it — `report:final.pdf`, `aux.txt`, `data.` — is a defect
//! introduced at *backup* time and discovered years later, at the worst possible
//! moment. Reporting it while the operator is still here to rename the file is
//! most of the value.
//!
//! Those findings are warnings, not refusals, unless `--strict-names` is given.
//! The bytes are perfectly storable; refusing to back up a legal local file
//! because Windows dislikes its name would lose data today to protect a machine
//! that may never exist. The one exception is a control character in a name,
//! which no filesystem anywhere accepts and which therefore guarantees an object
//! nobody can ever restore.
//!
//! ## What runs today
//!
//! Everything up to the first byte: argument and snapshot validation, the tree
//! walk, the filters DCTL can evaluate exactly, the pre-flight, and the full
//! plan in all three output formats. What does not exist is the verified-write
//! engine (`PLAN.md` §6), so a real run stops at
//! [`crate::constants::TRANSFER_ENGINE_FEATURE`] — an error with a real exit
//! code, never a success message for work that did not happen.
//!
//! The engine check comes **before** the walk on a real run, deliberately.
//! Scanning four million files to then report that the transfer cannot happen
//! wastes an hour to tell the operator something a millisecond of argument
//! checking already knew; `--dry-run` is the flag that asks for the scan, and
//! the error's hint says so.

pub mod scan;

use std::path::PathBuf;

use clap::Args;

use crate::constants::{
    PATH_SEPARATOR, PLAN_ACTION_STORE, TRANSFER_ENGINE_FEATURE, TRANSFER_ENGINE_HINT,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::output::size;

use super::recovery::report::{self, Document};
use super::recovery::{Audience, Entry, Plan, Selection, SnapshotName, Target, command_name};
use super::recovery::{preflight, timespec};

/// The verb this module implements.
///
/// Named once because it appears in the `operation` field of the plan document
/// *and* in the message that tells the user which command is not implemented; a
/// rename that updated one and not the other would produce a document
/// describing a command the error does not name.
const VERB: &str = "backup";

/// Arguments for `dctl backup`.
#[derive(Args, Debug)]
pub struct BackupArgs {
    /// Local directory or file to back up.
    #[arg(value_name = "LOCAL")]
    pub source: PathBuf,

    /// Vault to store it in, written REMOTE:PATH.
    #[arg(value_name = "REMOTE")]
    pub destination: String,

    /// Record this run as a snapshot, so it can be restored as one point in
    /// time.
    #[arg(long)]
    pub snapshot: bool,

    /// Name the snapshot. Without this, one is generated from the start time.
    #[arg(long, value_name = "NAME", requires = "snapshot")]
    pub snapshot_name: Option<String>,

    /// Store what symbolic links point at, rather than skipping them.
    #[arg(long)]
    pub follow_symlinks: bool,

    /// Refuse to store any name that could not be restored on every supported
    /// platform.
    #[arg(long)]
    pub strict_names: bool,
}

pub async fn run(ctx: &Ctx, args: &BackupArgs) -> Result<()> {
    // Cheap, total validation first: a typo must cost a millisecond, not an
    // hour of walking.
    let target = Target::parse(&args.destination)?;
    let selection = Selection::resolve(&ctx.globals)?;
    let started = timespec::now();
    let snapshot = SnapshotName::resolve(args.snapshot, args.snapshot_name.as_deref(), started)?;

    if !args.source.exists() {
        return Err(CliError::new(
            ExitCode::DirNotFound,
            format!("{} does not exist", args.source.display()),
        )
        .with_hint("The first operand is the local tree to back up."));
    }

    // Nothing below this line can move a byte, so say so before spending an
    // hour proving it.
    if !ctx.is_dry_run() {
        return Err(
            CliError::unimplemented(command_name(VERB)).with_hint(format!(
                "{TRANSFER_ENGINE_HINT} ({TRANSFER_ENGINE_FEATURE})"
            )),
        );
    }

    let scan = scan::walk(&args.source, &selection, args.follow_symlinks);
    for problem in &scan.problems {
        // Counted, not swallowed: the run's exit code reflects them.
        ctx.stats.error();
        ctx.out
            .warn(format!("{}: {}", problem.path, problem.detail));
    }
    for link in &scan.skipped_links {
        ctx.out.info(format!("skipped symbolic link {link}"));
    }

    // Names are checked for *any* platform: this tree may be restored anywhere.
    let findings = preflight::inspect(&scan.logical_paths(), None, Audience::AnyPlatform);

    let mut plan = Plan::new();
    for file in &scan.files {
        plan.push(Entry::new(
            PLAN_ACTION_STORE,
            file.native.display().to_string(),
            vault_path(&target, &file.logical),
            file.size,
        ));
    }
    plan.sort();

    if let Some(name) = &snapshot {
        ctx.out.info(format!("snapshot {}", name.as_str()));
    }
    if plan.is_empty() {
        // Said out loud, because "no output and exit 0" is indistinguishable
        // from "it worked", and a backup that stored nothing is worth noticing.
        ctx.out.warn(format!(
            "nothing to back up under {}",
            args.source.display()
        ));
    }

    ctx.stats.set_total_files(plan.len() as u64);
    ctx.stats.set_total_bytes(plan.total_bytes());

    report::emit(
        ctx,
        &Document {
            operation: VERB,
            source: &args.source.display().to_string(),
            destination: &args.destination,
            snapshot: snapshot.as_ref(),
            at: None,
            dry_run: true,
            files: plan.len(),
            bytes: plan.total_bytes(),
            preflight: &findings.findings,
            entries: Some(plan.entries()),
        },
    )?;

    summarise(ctx, &scan, &findings, args.strict_names)
}

/// Where a scanned file lands in the vault, written the way a user would type
/// it back.
///
/// The root case is the one worth having a function for: `vault:` needs nothing
/// after the colon while `vault:photos` needs a separator, and getting it wrong
/// prints `vault:photosa.jpg` — a path nobody could act on.
fn vault_path(target: &Target, logical: &str) -> String {
    if target.is_root() {
        format!("{target}{logical}")
    } else {
        format!("{target}{PATH_SEPARATOR}{logical}")
    }
}

/// Report the pre-flight outcome, and decide whether it stops the run.
fn summarise(
    ctx: &Ctx,
    scan: &scan::Scan,
    findings: &preflight::Report,
    strict: bool,
) -> Result<()> {
    if findings.is_clean() {
        ctx.out.info(format!(
            "{} files ({}), {} skipped links, no name problems",
            scan.files.len(),
            size::bytes(scan.total_bytes(), ctx.out.units()),
            scan.skipped_links.len()
        ));
        return Ok(());
    }

    let blocking = findings.blocking_count();
    if blocking > 0 {
        // A control character is the only finding that reaches here, and it
        // guarantees an object no platform could ever restore.
        return Err(CliError::new(
            ExitCode::FatalError,
            format!("{blocking} name(s) cannot be restored on any platform"),
        )
        .with_hint(
            "These names contain characters no filesystem accepts. Rename them at \
             the source; DCTL will not silently store a name it cannot give back.",
        ));
    }

    if strict {
        return Err(CliError::new(
            ExitCode::FatalError,
            format!(
                "{} name(s) would not restore on every supported platform",
                findings.findings.len()
            ),
        )
        .with_hint("Rename them, or drop --strict-names to store them with a warning."));
    }

    ctx.out.warn(format!(
        "{} name(s) may not restore on every platform; see the report above",
        findings.findings.len()
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::cli::globals::GlobalArgs;
    use crate::constants::WALK_FOLLOW_SYMLINKS;
    use clap::{CommandFactory, Parser};

    #[derive(Parser, Debug)]
    #[command(name = "dctl")]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,

        #[command(flatten)]
        backup: BackupArgs,
    }

    fn parse(args: &[&str]) -> Harness {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()))
    }

    /// A context and the command's own arguments, from one command line.
    fn setup(args: &[&str]) -> (Ctx, BackupArgs) {
        let harness = parse(args);
        (Ctx::new(harness.globals.clone()), harness.backup)
    }

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "aaaa").unwrap();
        std::fs::write(dir.path().join("b.txt"), "bb").unwrap();
        dir
    }

    #[test]
    fn the_argument_tree_is_internally_consistent() {
        Harness::command().debug_assert();
    }

    #[test]
    fn both_operands_are_required() {
        assert!(Harness::try_parse_from(["dctl"]).is_err());
        assert!(Harness::try_parse_from(["dctl", "/tmp/src"]).is_err());
        assert!(Harness::try_parse_from(["dctl", "/tmp/src", "vault:"]).is_ok());
    }

    #[test]
    fn naming_a_snapshot_requires_asking_for_one() {
        // Otherwise `--snapshot-name nightly` would silently do nothing.
        assert!(
            Harness::try_parse_from(["dctl", "/tmp/s", "vault:", "--snapshot-name", "nightly"])
                .is_err()
        );
        assert!(
            Harness::try_parse_from([
                "dctl",
                "/tmp/s",
                "vault:",
                "--snapshot",
                "--snapshot-name",
                "nightly"
            ])
            .is_ok()
        );
    }

    #[test]
    fn links_are_skipped_unless_asked_for() {
        // The default matches the walk's documented policy constant.
        assert_eq!(
            parse(&["/tmp/s", "vault:"]).backup.follow_symlinks,
            WALK_FOLLOW_SYMLINKS
        );
    }

    #[tokio::test]
    async fn a_local_destination_is_refused_before_anything_is_read() {
        let (ctx, args) = setup(&["/tmp/src", "/tmp/dst", "--dry-run"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_missing_source_is_reported_before_the_engine_check() {
        // A typo in the source must not be reported as "not implemented".
        let (ctx, args) = setup(&["/nonexistent/tree", "vault:", "--dry-run"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::DirNotFound);
    }

    #[tokio::test]
    async fn a_real_run_fails_loudly_rather_than_claiming_success() {
        // PLAN.md §6: never report work that did not happen.
        let dir = tree();
        let source = dir.path().display().to_string();
        let (ctx, args) = setup(&[source.as_str(), "vault:archive"]);

        let error = run(&ctx, &args).await.unwrap_err();
        assert_ne!(error.code(), ExitCode::Success);
        assert!(error.message().contains("backup"));
        assert!(error.hint().unwrap().contains("--dry-run"));
    }

    #[tokio::test]
    async fn a_dry_run_plans_the_whole_tree() {
        let dir = tree();
        let source = dir.path().display().to_string();
        let (ctx, args) = setup(&[source.as_str(), "vault:archive", "--dry-run"]);

        run(&ctx, &args).await.unwrap();

        // The counters describe what *would* move, and nothing is marked done.
        let snapshot = ctx.stats.snapshot();
        assert_eq!(snapshot.files_total, 2);
        assert_eq!(snapshot.bytes_total, 6);
        assert_eq!(snapshot.files_done, 0, "a dry run transfers nothing");
    }

    #[tokio::test]
    async fn a_glob_filter_is_refused_before_the_tree_is_walked() {
        let dir = tree();
        let source = dir.path().display().to_string();
        let (ctx, args) = setup(&[source.as_str(), "vault:", "--dry-run", "--exclude", "*.txt"]);

        let error = run(&ctx, &args).await.unwrap_err();
        assert!(error.message().contains("glob filtering"));
    }

    #[test]
    fn a_name_no_platform_accepts_stops_the_backup() {
        // A control character cannot be restored anywhere, so it is fatal even
        // without --strict-names. Built as a logical path rather than a real
        // file, since not every test filesystem will hold one.
        let findings = preflight::inspect(
            &["bad\u{7}name.txt".to_string()],
            None,
            Audience::AnyPlatform,
        );
        assert_eq!(findings.blocking_count(), 1);

        let (ctx, _) = setup(&["/tmp/s", "vault:"]);
        let error = summarise(&ctx, &scan::Scan::default(), &findings, false).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
    }

    #[test]
    fn strict_names_turns_a_portability_warning_into_a_refusal() {
        let findings = preflight::inspect(
            &["report:final.pdf".to_string()],
            None,
            Audience::AnyPlatform,
        );
        assert_eq!(findings.blocking_count(), 0, "not fatal on its own");

        let scan = scan::Scan::default();
        let (context, _) = setup(&["/tmp/s", "vault:"]);
        // Warned by default...
        assert!(summarise(&context, &scan, &findings, false).is_ok());
        // ...refused when asked to be strict.
        let error = summarise(&context, &scan, &findings, true).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
    }

    #[test]
    fn the_vault_side_of_a_plan_row_is_a_usable_path() {
        // The bug this catches: `vault:photosa.jpg`.
        let root = Target::parse("vault:").unwrap();
        assert_eq!(vault_path(&root, "a.jpg"), "vault:a.jpg");

        let nested = Target::parse("vault:photos").unwrap();
        assert_eq!(vault_path(&nested, "a.jpg"), "vault:photos/a.jpg");
    }
}
