//! `dctl backup LOCAL REMOTE:` — store a local tree in a vault.
//!
//! `backup` is `copy` with two additions that only make sense for an archive: it
//! runs the name pre-flight over everything it is about to store (`PLAN.md`
//! §13.6), and it stores by **streaming** rather than by buffering.
//!
//! The pre-flight is the first. A filename that is legal on this machine and
//! illegal on the machine that will one day restore it — `report:final.pdf`,
//! `aux.txt`, `data.` — is a defect introduced at *backup* time and discovered
//! years later, at the worst possible moment. Reporting it while the operator is
//! still here to rename the file is most of the value.
//!
//! Those findings are warnings, not refusals, unless `--strict-names` is given.
//! The bytes are perfectly storable; refusing to back up a legal local file
//! because Windows dislikes its name would lose data today to protect a machine
//! that may never exist. The one exception is a control character in a name,
//! which no filesystem anywhere accepts and which therefore guarantees an object
//! nobody can ever restore.
//!
//! The second is [`store`], and it is why `backup` exists as its own verb rather
//! than as a flag on `copy`: it uses the core's constant-memory streaming store,
//! so the largest file on the disk is storable rather than refused.
//!
//! ## What is refused, and why it is refused rather than approximated
//!
//! `--snapshot` names a point in time that this build cannot restore, so a real
//! run refuses it ([`crate::constants::SNAPSHOT_FEATURE`]). Storing the files and
//! dropping the name would leave an operator believing a named point in time
//! exists — and they would find out it does not on the day they reached for it.
//! A dry run still plans it, because planning is not claiming.
//!
//! ## Order of operations
//!
//! Cheap total validation, then the walk, then the pre-flight, then the report,
//! then — on a real run — the vault is unlocked and the bytes move. The
//! unlocking comes *after* the report so `--dry-run` never asks for a password,
//! and the validation comes before the walk so a typo costs a millisecond rather
//! than an hour of scanning four million files.

pub mod scan;
pub mod store;

use std::path::PathBuf;

use clap::Args;
use dctl_store::LinkPolicy;

use crate::constants::PLAN_ACTION_STORE;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::output::size;
use crate::platform::collision;

use super::recovery::report::{self, Document};
use super::recovery::{Audience, Entry, Plan, Selection, SnapshotName, Target};
use super::recovery::{preflight, timespec};

/// The verb this module implements.
///
/// Named once because it appears in the `operation` field of the plan document
/// *and* in the messages that name the command; a rename that updated one and
/// not the other would produce a document describing a command the error does
/// not name.
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
    ///
    /// The older spelling of the global `--links follow`, kept because scripts
    /// carry it. It is resolved against `--links` in one place
    /// ([`link_policy`]) and the two are refused together when they disagree,
    /// rather than one silently winning — a run that followed links because of
    /// an argument the operator thought they had overridden is the shape of
    /// surprise this whole area exists to remove.
    #[arg(long)]
    pub follow_symlinks: bool,

    /// Refuse to store any name that could not be restored on every supported
    /// platform.
    #[arg(long)]
    pub strict_names: bool,
}

/// The link policy this run walks under, from the global flag and the older
/// per-command boolean.
///
/// Two spellings of one decision, resolved once. They are refused together when
/// they disagree rather than one quietly winning: `--links skip
/// --follow-symlinks` is a contradiction, and picking either reading would mean
/// a backup that stored — or omitted — a tree the operator believed they had
/// decided about. Agreeing spellings are accepted, because `--links follow
/// --follow-symlinks` says one thing twice.
///
/// # Errors
/// [`ExitCode::Usage`] when the two disagree.
fn link_policy(ctx: &Ctx, args: &BackupArgs) -> Result<LinkPolicy> {
    if !args.follow_symlinks {
        return Ok(ctx.globals.links);
    }
    if ctx.globals.links == LinkPolicy::Skip {
        // The default, which nobody can have meant to assert alongside the flag
        // that turns it off.
        return Ok(LinkPolicy::Follow);
    }
    if ctx.globals.links == LinkPolicy::Follow {
        return Ok(LinkPolicy::Follow);
    }
    Err(CliError::usage(format!(
        "--follow-symlinks contradicts --links {}",
        ctx.globals.links
    ))
    .with_hint("--follow-symlinks is the older spelling of --links follow. Give one of them."))
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

    // Nothing below this line can honour a snapshot, so say so before spending
    // an hour proving it — and before a single byte is stored under a name that
    // would suggest it can be restored as one.
    store::refuse_unsupported_snapshot(ctx, args.snapshot)?;

    let scan = scan::walk(&args.source, &selection, link_policy(ctx, args)?);
    for problem in &scan.problems {
        // Counted, not swallowed: the run's exit code reflects them.
        ctx.stats.error();
        ctx.out
            .warn(format!("{}: {}", problem.path, problem.detail));
    }
    // One implementation of "say what happened to the links", shared with the
    // transfer and listing families so an operator who checks with `ls` and then
    // runs `backup` is told the same thing about the same tree.
    crate::links::report(ctx, &scan.links);

    // Names are checked for *any* platform: this tree may be restored anywhere.
    let mut findings = preflight::inspect(&scan.logical_paths(), None, Audience::AnyPlatform);
    // Two local files that share one logical path are invisible to that
    // inspection — by the time a path set reaches it, both spellings have
    // already become the same string. Only the walk saw two files, so only the
    // walk can report them, and they join the same report every other name
    // problem lands in.
    findings.absorb(collision::findings(&scan.collisions));

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
    // `collisions` is the third reason a plan can be empty, and the only one
    // where saying "nothing to back up" would be false: there *are* files under
    // the source, and they were withheld because storing them would lose one.
    // The refusal below says so precisely, so this says nothing at all.
    if plan.is_empty() && scan.collisions.is_empty() {
        // Said out loud, because "no output and exit 0" is indistinguishable
        // from "it worked", and a backup that stored nothing is worth noticing.
        // The wording separates the two reasons: an empty tree and a tree the
        // filters emptied are different problems with different fixes.
        ctx.out.warn(if selection.is_restricting() {
            format!(
                "nothing to back up under {}: every file was excluded by the filters",
                args.source.display()
            )
        } else {
            format!("nothing to back up under {}", args.source.display())
        });
    }

    ctx.stats.set_total_files(plan.len() as u64);
    ctx.stats.set_total_bytes(plan.total_bytes());
    ctx.progress
        .set_totals(plan.total_bytes(), plan.len() as u64);

    report::emit(
        ctx,
        &Document {
            operation: VERB,
            source: &args.source.display().to_string(),
            destination: &args.destination,
            snapshot: snapshot.as_ref(),
            at: None,
            dry_run: ctx.is_dry_run(),
            files: plan.len(),
            bytes: plan.total_bytes(),
            preflight: &findings.findings,
            entries: Some(plan.entries()),
        },
    )?;

    // The name gate runs before anything is stored, so a `--strict-names` run
    // that would have refused halfway refuses at the start instead.
    summarise(ctx, &scan, &findings, args.strict_names)?;

    if ctx.is_dry_run() {
        return Ok(());
    }

    // The vault is opened only now: a dry run must never ask for a password,
    // and a run refused above must never have asked for one either.
    let store = store::Store::connect(ctx, &target).await?;
    store::everything(ctx, &store, &scan.files).await
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
        format!("{target}{}{logical}", crate::constants::PATH_SEPARATOR)
    }
}

/// Report the pre-flight outcome, and decide whether it stops the run.
///
/// # Errors
/// [`ExitCode::FatalError`] for a normalisation collision (checked first, since
/// it is the one with a specific remedy), for a name no filesystem anywhere
/// accepts, or for any finding at all under `--strict-names`.
fn summarise(
    ctx: &Ctx,
    scan: &scan::Scan,
    findings: &preflight::Report,
    strict: bool,
) -> Result<()> {
    // Before the generic blocking branch below, which speaks about characters no
    // filesystem accepts and would be the wrong account of this. Refused rather
    // than warned about because there is no correct file to keep: whichever is
    // stored, the other is lost, while the operator's own filesystem shows both.
    collision::refuse(&scan.collisions, true)?;

    if findings.is_clean() {
        ctx.out.info(format!(
            "{} files ({}), {} skipped links, no name problems",
            scan.files.len(),
            size::bytes(scan.total_bytes(), ctx.out.units()),
            scan.links.skipped()
        ));
        return Ok(());
    }

    let blocking = findings.blocking_count();
    if blocking > 0 {
        // A control character is the only finding that reaches here *now*: the
        // other blocking kind, a normalisation collision, was refused above with
        // a message naming the two files. Ordered that way deliberately — this
        // wording is about characters no filesystem accepts, which is a true but
        // useless account of two names that are both perfectly legal.
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
    ///
    /// `--config` is pinned to a path that does not exist, so a unit test never
    /// reads the developer's own configuration and the suite does not pass or
    /// fail depending on whose machine it runs on.
    fn setup(args: &[&str]) -> (Ctx, BackupArgs) {
        let mut argv: Vec<String> = std::iter::once("dctl")
            .chain(args.iter().copied())
            .map(String::from)
            .collect();
        if !args.contains(&"--config") {
            argv.push("--config".to_string());
            argv.push(crate::config::absent_path().to_string_lossy().into_owned());
        }
        let harness = Harness::parse_from(argv);
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
        // Both spellings default to the storage layer's own default, so the
        // flag surface and the walk cannot disagree about what "nothing said"
        // means.
        let parsed = parse(&["/tmp/s", "vault:"]);
        assert!(!parsed.backup.follow_symlinks);
        assert_eq!(parsed.globals.links, LinkPolicy::default());
        assert_eq!(LinkPolicy::default(), LinkPolicy::Skip);
    }

    #[test]
    fn the_two_spellings_of_one_decision_are_resolved_in_one_place() {
        // `--follow-symlinks` predates `--links` and scripts carry it.
        let (ctx, args) = setup(&["/tmp/src", "vault:", "--follow-symlinks"]);
        assert_eq!(link_policy(&ctx, &args).unwrap(), LinkPolicy::Follow);

        let (ctx, args) = setup(&["/tmp/src", "vault:", "--links", "in-tree"]);
        assert_eq!(link_policy(&ctx, &args).unwrap(), LinkPolicy::InTree);

        // Saying the same thing twice is not a contradiction.
        let (ctx, args) = setup(&[
            "/tmp/src",
            "vault:",
            "--links",
            "follow",
            "--follow-symlinks",
        ]);
        assert_eq!(link_policy(&ctx, &args).unwrap(), LinkPolicy::Follow);
    }

    #[test]
    fn two_spellings_that_disagree_are_refused_rather_than_ranked() {
        // Picking a winner here would mean a backup that stored — or omitted —
        // a whole tree on the strength of a precedence rule nobody wrote down.
        let (ctx, args) = setup(&[
            "/tmp/src",
            "vault:",
            "--links",
            "in-tree",
            "--follow-symlinks",
        ]);
        let error = link_policy(&ctx, &args).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(
            error.message().contains("--follow-symlinks"),
            "{}",
            error.message()
        );
    }

    #[tokio::test]
    async fn a_local_destination_is_refused_before_anything_is_read() {
        let (ctx, args) = setup(&["/tmp/src", "/tmp/dst", "--dry-run"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_missing_source_is_reported_before_anything_else() {
        // A typo in the source must not be reported as a missing feature.
        let (ctx, args) = setup(&["/nonexistent/tree", "vault:", "--dry-run"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::DirNotFound);
    }

    #[tokio::test]
    async fn a_snapshot_is_refused_on_a_real_run_rather_than_silently_dropped() {
        // PLAN.md §13.6: an operator who believes a named point in time exists
        // discovers otherwise on the day they reach for it.
        let dir = tree();
        let source = dir.path().display().to_string();
        let (ctx, args) = setup(&[source.as_str(), "vault:archive", "--snapshot"]);

        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains("--snapshot"),
            "{}",
            error.message()
        );
        assert!(error.hint().is_some_and(|hint| hint.contains("13.5")));
    }

    #[tokio::test]
    async fn an_unconfigured_remote_is_named_rather_than_read_as_a_directory() {
        // S6 on the write side: `vault:` has no colon once the name is taken
        // alone, so a re-parse would turn it into the directory `./vault` and a
        // backup would store plaintext there and report success.
        let dir = tree();
        let source = dir.path().display().to_string();
        let (ctx, args) = setup(&[source.as_str(), "vault:archive", "--no-ask-password"]);

        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("vault"), "{}", error.message());
        assert!(!dir.path().join("vault").exists(), "nothing was created");
    }

    #[tokio::test]
    async fn a_dry_run_plans_the_whole_tree_without_asking_for_a_password() {
        let dir = tree();
        let source = dir.path().display().to_string();
        // `--no-ask-password` is the proof: a dry run that reached the unlock
        // would fail with VaultLocked instead of succeeding.
        let (ctx, args) = setup(&[
            source.as_str(),
            "vault:archive",
            "--dry-run",
            "--no-ask-password",
        ]);

        run(&ctx, &args).await.unwrap();

        // The counters describe what *would* move, and nothing is marked done.
        let snapshot = ctx.stats.snapshot();
        assert_eq!(snapshot.files_total, 2);
        assert_eq!(snapshot.bytes_total, 6);
        assert_eq!(snapshot.files_done, 0, "a dry run transfers nothing");
    }

    #[tokio::test]
    async fn a_glob_filter_narrows_the_backup_rather_than_stopping_it() {
        // The engine is wired in: `--exclude` used to refuse the command
        // outright, which meant a backup could not be narrowed at all.
        let dir = tree();
        let source = dir.path().display().to_string();
        let (ctx, args) = setup(&[
            source.as_str(),
            "vault:",
            "--dry-run",
            "--no-ask-password",
            "--exclude",
            "b.txt",
        ]);

        run(&ctx, &args).await.unwrap();
        assert_eq!(ctx.stats.snapshot().files_total, 1);
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
