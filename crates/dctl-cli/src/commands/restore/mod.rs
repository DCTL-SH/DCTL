//! `dctl restore REMOTE: LOCAL` — write a vault, or part of one, back to disk.
//!
//! A backup you never restored is not a backup (`PLAN.md` §13.6), and the way a
//! restore fails is almost never the network. It is a filename: `report:final.pdf`
//! landing on Windows, `README.md` and `readme.md` landing on the same
//! case-insensitive volume, a path four characters past `MAX_PATH`, or a vault
//! entry that needs `a/b` to be a directory when another entry needs it to be a
//! file. Each of those fails *partway through*, leaving a tree that is neither
//! the old one nor the new one, and each is knowable before the first byte
//! moves.
//!
//! So **every path is pre-flighted before anything is written**, and every
//! problem is reported — not the first one. An operator who fixes one name,
//! waits six hours and hits the next has been told the truth three times and
//! helped none. The report is data on stdout, in whichever format was asked for,
//! so it can be read by a person or fed to a script.
//!
//! A blocked path stops the whole restore unless `--skip-unwritable` is given.
//! That default is the conservative one: a partial restore that *looks* complete
//! is the failure mode this command exists to prevent, so leaving files out has
//! to be something the operator asked for out loud.
//!
//! ## What runs today
//!
//! Argument, snapshot and point-in-time validation; the destination checks; the
//! full pre-flight; the overwrite policy and its destructive gate; and the plan
//! in all three formats. Two things do not exist yet, and each is reported as an
//! error rather than worked around:
//!
//! * **Enumerating the vault** ([`REMOTE_ENUMERATION_FEATURE`]) needs an
//!   unlocked vault the command context does not yet carry. `--files-from`
//!   supplies the path set in the meantime, which is what makes the pre-flight
//!   usable today.
//! * **The verified-write engine** ([`TRANSFER_ENGINE_FEATURE`]) does the
//!   writing. Until it lands, a real run ends in an error with a real exit code
//!   — never a success message for files that were never written.

use std::path::PathBuf;

use clap::Args;

use crate::constants::{
    PLAN_ACTION_OVERWRITE, PLAN_ACTION_RESTORE, PLAN_ACTION_SKIP, PLAN_REASON_EXISTS,
    POINT_IN_TIME_FEATURE, POINT_IN_TIME_HINT, PREFLIGHT_SEVERITY_BLOCKING,
    REMOTE_ENUMERATION_FEATURE, REMOTE_ENUMERATION_HINT, REMOTE_SEPARATOR, TRANSFER_ENGINE_FEATURE,
    TRANSFER_ENGINE_HINT,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::platform::path as logical;

use super::recovery::report::{self, Document};
use super::recovery::{Audience, Entry, Plan, Selection, SnapshotName, Target, command_name};
use super::recovery::{preflight, timespec};

/// The verb this module implements.
///
/// Named once because it appears in the `operation` field of the plan document
/// *and* in the message that tells the user which command is not implemented.
const VERB: &str = "restore";

/// Arguments for `dctl restore`.
#[derive(Args, Debug)]
pub struct RestoreArgs {
    /// Vault to restore from, written REMOTE:PATH.
    #[arg(value_name = "REMOTE")]
    pub source: String,

    /// Local directory to restore into.
    #[arg(value_name = "LOCAL")]
    pub destination: PathBuf,

    /// Restore the tree as it stood in this named snapshot.
    #[arg(long, value_name = "NAME")]
    pub snapshot: Option<String>,

    /// Restore the tree as it stood at this instant.
    #[arg(long, value_name = "TIME", conflicts_with = "snapshot")]
    pub at: Option<String>,

    /// Restore what can be written and report the rest, instead of refusing the
    /// whole run when a name cannot be created here.
    #[arg(long)]
    pub skip_unwritable: bool,

    /// Replace local files that already exist. Without it, a restore that would
    /// overwrite anything refuses.
    #[arg(long)]
    pub overwrite: bool,
}

pub async fn run(ctx: &Ctx, args: &RestoreArgs) -> Result<()> {
    let target = Target::parse(&args.source)?;
    let selection = Selection::resolve(&ctx.globals)?;

    // Validated even though it cannot yet be honoured: a malformed `--at` is a
    // usage error, and reporting it as "unimplemented" would send the operator
    // looking for a missing feature instead of a typo.
    let reference = timespec::now();
    let at = args
        .at
        .as_deref()
        .map(|value| timespec::parse(value, reference))
        .transpose()?;
    let snapshot = args
        .snapshot
        .as_deref()
        .map(SnapshotName::parse)
        .transpose()?;

    if at.is_some() || snapshot.is_some() {
        return Err(CliError::unimplemented(POINT_IN_TIME_FEATURE).with_hint(POINT_IN_TIME_HINT));
    }

    if args.destination.exists() && !args.destination.is_dir() {
        return Err(
            CliError::usage(format!("{} is not a directory", args.destination.display()))
                .with_hint("A restore writes a tree, so its destination is a directory."),
        );
    }

    // The path set. Without an unlocked vault the only source of one is an
    // explicit list, and saying so is better than pretending the vault was empty.
    let Some(explicit) = selection.explicit_paths() else {
        return Err(CliError::unimplemented(REMOTE_ENUMERATION_FEATURE)
            .with_hint(format!("{REMOTE_ENUMERATION_HINT} A restore can be pre-flighted today by naming the paths with --files-from.")));
    };
    let paths: Vec<String> = explicit
        .iter()
        .filter(|path| target.covers(path))
        .cloned()
        .collect();

    // Everything that could stop a name being written, before anything is.
    let findings = preflight::inspect(&paths, Some(&args.destination), Audience::ThisPlatform);

    let plan = build_plan(args, &target, &paths, &findings);
    if plan.is_empty() {
        // Said out loud: "no output and exit 0" reads as success, and a restore
        // that wrote nothing is exactly the case worth noticing.
        ctx.out.warn(format!("nothing to restore under {target}"));
    }
    ctx.stats.set_total_files(plan.len() as u64);
    ctx.stats.set_total_bytes(plan.total_bytes());

    // Everything is reported before anything is refused, so an operator facing
    // three separate problems learns all three from one run.
    report::emit(
        ctx,
        &Document {
            operation: VERB,
            source: &args.source,
            destination: &args.destination.display().to_string(),
            snapshot: None,
            at,
            dry_run: ctx.is_dry_run(),
            files: plan.len(),
            bytes: plan.total_bytes(),
            preflight: &findings.findings,
            // A real run stops at the engine below, so it has no plan to show;
            // absent says that, where an empty list would claim "nothing to do".
            entries: ctx.is_dry_run().then_some(plan.entries()),
        },
    )?;

    // The safety gate outranks the engine gate: a restore that would have
    // half-written a tree must say so even in a build that could not write it.
    let blocked = findings.blocked_paths();
    if !blocked.is_empty() && !args.skip_unwritable {
        return Err(CliError::new(
            ExitCode::FatalError,
            format!(
                "{} of {} path(s) cannot be written on this platform",
                blocked.len(),
                paths.len()
            ),
        )
        .with_hint(
            "Every one is listed above. Rename them in the vault, restore \
             somewhere with different rules, or pass --skip-unwritable to \
             restore the rest and be told exactly what was left out.",
        ));
    }
    if !blocked.is_empty() {
        ctx.out.warn(format!(
            "{} path(s) will be skipped: they cannot be written here",
            blocked.len()
        ));
    }

    gate_overwrites(ctx, args, plan.count(PLAN_ACTION_OVERWRITE))?;

    if !ctx.is_dry_run() {
        return Err(
            CliError::unimplemented(command_name(VERB)).with_hint(format!(
                "{TRANSFER_ENGINE_HINT} ({TRANSFER_ENGINE_FEATURE})"
            )),
        );
    }
    Ok(())
}

/// Turn the path set into the list of file operations a restore would perform.
///
/// Pure: it reads the destination but changes nothing and refuses nothing, so
/// the plan can be printed before any policy decides to stop the run.
///
/// Sizes are zero because the plaintext size of an object lives in the index,
/// which needs an unlocked vault. Reporting a made-up number would be worse than
/// reporting none.
fn build_plan(
    args: &RestoreArgs,
    target: &Target,
    paths: &[String],
    findings: &preflight::Report,
) -> Plan {
    let mut plan = Plan::new();

    for path in paths {
        // The full vault path, not just the operand: a plan row has to name the
        // object precisely enough to look it up.
        let source = format!("{}{REMOTE_SEPARATOR}{path}", target.remote);
        let native = logical::from_logical(&args.destination, target.relative(path));
        let destination = native.display().to_string();

        if findings.blocks(path) {
            // Listed as a skip rather than omitted: a plan that silently drops
            // the interesting rows is how a partial restore looks complete.
            plan.push(
                Entry::new(PLAN_ACTION_SKIP, source, destination, 0)
                    .because(PREFLIGHT_SEVERITY_BLOCKING),
            );
        } else if native.exists() {
            plan.push(
                Entry::new(PLAN_ACTION_OVERWRITE, source, destination, 0)
                    .because(PLAN_REASON_EXISTS),
            );
        } else {
            plan.push(Entry::new(PLAN_ACTION_RESTORE, source, destination, 0));
        }
    }

    plan.sort();
    plan
}

/// Decide whether a restore that would replace existing files may proceed.
///
/// Three gates, in order of how absolute they are: `--immutable` forbids
/// touching anything that exists at all; without `--overwrite` a restore that
/// would replace something refuses; and with it, the replacement still goes
/// through [`Ctx::confirm_destructive`], because overwriting a live directory is
/// the one thing in this command that destroys data.
fn gate_overwrites(ctx: &Ctx, args: &RestoreArgs, overwrites: usize) -> Result<()> {
    if overwrites == 0 {
        return Ok(());
    }

    let summary = format!(
        "{overwrites} existing file(s) under {}",
        args.destination.display()
    );

    if ctx.globals.immutable {
        return Err(CliError::new(
            ExitCode::FatalError,
            format!("--immutable, but the restore would replace {summary}"),
        )
        .with_hint("Restore into an empty directory, or drop --immutable."));
    }

    if !args.overwrite {
        return Err(CliError::new(
            ExitCode::FatalError,
            format!("the restore would replace {summary}"),
        )
        .with_hint(
            "Restore into an empty directory, or pass --overwrite to replace what \
             is already there.",
        ));
    }

    // A dry run declines here and prints the `[dry-run] would overwrite` notice;
    // a real run that is declined has been cancelled by the operator.
    if !ctx.confirm_destructive("overwrite", &summary)? && !ctx.is_dry_run() {
        return Err(CliError::new(
            ExitCode::Cancelled,
            "restore cancelled: nothing was written",
        ));
    }
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
        restore: RestoreArgs,
    }

    fn parse(args: &[&str]) -> Harness {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()))
    }

    /// A context and the command's own arguments, from one command line.
    fn setup(args: &[&str]) -> (Ctx, RestoreArgs) {
        let harness = parse(args);
        (Ctx::new(harness.globals.clone()), harness.restore)
    }

    /// A `--files-from` list, since that is the only path source that exists
    /// until the vault can be enumerated.
    fn manifest(dir: &std::path::Path, body: &str) -> String {
        let path = dir.join("manifest.txt");
        std::fs::write(&path, body).unwrap();
        path.display().to_string()
    }

    #[test]
    fn the_argument_tree_is_internally_consistent() {
        Harness::command().debug_assert();
    }

    #[test]
    fn both_operands_are_required() {
        assert!(Harness::try_parse_from(["dctl", "vault:"]).is_err());
        assert!(Harness::try_parse_from(["dctl", "vault:", "/tmp/out"]).is_ok());
    }

    #[test]
    fn a_snapshot_and_an_instant_cannot_both_be_named() {
        // They are two spellings of the same question with different answers.
        assert!(
            Harness::try_parse_from([
                "dctl",
                "vault:",
                "/tmp/out",
                "--snapshot",
                "nightly",
                "--at",
                "2d"
            ])
            .is_err()
        );
    }

    #[tokio::test]
    async fn a_local_source_is_refused() {
        let (ctx, args) = setup(&["/tmp/in", "/tmp/out"]);
        assert_eq!(run(&ctx, &args).await.unwrap_err().code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_malformed_instant_is_a_usage_error_not_an_unimplemented_feature() {
        // The distinction matters: one is a typo, the other sends the operator
        // looking for a missing feature.
        let (ctx, args) = setup(&["vault:", "/tmp/out", "--at", "yesterday"]);
        assert_eq!(run(&ctx, &args).await.unwrap_err().code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_point_in_time_restore_is_refused_rather_than_approximated() {
        // Planning today's contents for `--at 2d` would answer a question
        // nobody asked.
        for flag in [vec!["--at", "2d"], vec!["--snapshot", "nightly"]] {
            let mut argv = vec!["vault:", "/tmp/out", "--dry-run"];
            argv.extend(flag);
            let (ctx, args) = setup(&argv);
            let error = run(&ctx, &args).await.unwrap_err();
            assert!(
                error.message().contains("point in time"),
                "{}",
                error.message()
            );
        }
    }

    #[tokio::test]
    async fn a_destination_that_is_a_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, "x").unwrap();
        let file_arg = file.display().to_string();

        let (ctx, args) = setup(&["vault:", file_arg.as_str(), "--dry-run"]);
        assert_eq!(run(&ctx, &args).await.unwrap_err().code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn without_a_path_list_the_vault_cannot_be_enumerated() {
        // Honest: the command cannot know what to restore, and says which
        // capability is missing rather than pretending the vault was empty.
        let (ctx, args) = setup(&["vault:", "/tmp/out", "--dry-run"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert!(error.message().contains("listing a remote"));
        assert!(error.hint().unwrap().contains("--files-from"));
    }

    #[tokio::test]
    async fn a_dry_run_over_an_explicit_manifest_plans_every_path() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let out_arg = out.display().to_string();
        let list = manifest(dir.path(), "photos/a.jpg\nphotos/b.jpg\n");

        let (ctx, args) = setup(&[
            "vault:",
            out_arg.as_str(),
            "--dry-run",
            "--files-from",
            list.as_str(),
        ]);
        run(&ctx, &args).await.unwrap();
        assert_eq!(ctx.stats.snapshot().files_total, 2);
        assert!(!out.exists(), "--dry-run must not create the destination");
    }

    #[tokio::test]
    async fn only_paths_under_the_named_tree_are_restored() {
        let dir = tempfile::tempdir().unwrap();
        let out_arg = dir.path().join("out").display().to_string();
        let list = manifest(dir.path(), "photos/a.jpg\ndocs/b.txt\n");

        let (ctx, args) = setup(&[
            "vault:photos",
            out_arg.as_str(),
            "--dry-run",
            "--files-from",
            list.as_str(),
        ]);
        run(&ctx, &args).await.unwrap();
        assert_eq!(ctx.stats.snapshot().files_total, 1);
    }

    #[tokio::test]
    async fn an_unwritable_name_stops_the_whole_restore_by_default() {
        // The failure this prevents: 3.9 TB of a 4 TB restore, then a name that
        // cannot be created, and a tree that is neither old nor new.
        let dir = tempfile::tempdir().unwrap();
        let out_arg = dir.path().join("out").display().to_string();
        let list = manifest(dir.path(), "photos/ok.jpg\nphotos/bad\u{7}name.jpg\n");

        let (ctx, args) = setup(&[
            "vault:",
            out_arg.as_str(),
            "--dry-run",
            "--files-from",
            list.as_str(),
        ]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("1 of 2"), "{}", error.message());
        assert!(error.hint().unwrap().contains("--skip-unwritable"));
    }

    #[tokio::test]
    async fn skip_unwritable_restores_the_rest_and_says_what_was_left() {
        let dir = tempfile::tempdir().unwrap();
        let out_arg = dir.path().join("out").display().to_string();
        let list = manifest(dir.path(), "photos/ok.jpg\nphotos/bad\u{7}name.jpg\n");

        let (ctx, args) = setup(&[
            "vault:",
            out_arg.as_str(),
            "--dry-run",
            "--skip-unwritable",
            "--files-from",
            list.as_str(),
        ]);
        run(&ctx, &args).await.unwrap();
        // Both paths appear in the plan: one to restore, one marked skipped, so
        // the row that was dropped is visible rather than absent.
        assert_eq!(ctx.stats.snapshot().files_total, 2);
    }

    /// A destination that already holds `photos/a.jpg`.
    fn occupied(dir: &std::path::Path) -> String {
        let out = dir.join("out");
        std::fs::create_dir_all(out.join("photos")).unwrap();
        std::fs::write(out.join("photos/a.jpg"), "old").unwrap();
        out.display().to_string()
    }

    #[test]
    fn an_existing_file_is_planned_as_an_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let out_arg = occupied(dir.path());
        let (_, args) = setup(&["vault:", out_arg.as_str(), "--dry-run"]);

        let plan = build_plan(
            &args,
            &Target::parse("vault:").unwrap(),
            &["photos/a.jpg".to_string()],
            &preflight::Report::default(),
        );
        assert_eq!(plan.count(PLAN_ACTION_OVERWRITE), 1);
        assert_eq!(plan.count(PLAN_ACTION_RESTORE), 0);
        // The row names the object precisely enough to look up.
        assert_eq!(plan.entries()[0].source, "vault:photos/a.jpg");
    }

    #[test]
    fn a_blocked_path_is_planned_as_a_visible_skip() {
        // Omitting it would be how a partial restore looks complete.
        let dir = tempfile::tempdir().unwrap();
        let out_arg = dir.path().join("out").display().to_string();
        let (_, args) = setup(&["vault:", out_arg.as_str(), "--dry-run"]);

        let paths = vec!["bad\u{7}name.jpg".to_string()];
        let findings = preflight::inspect(&paths, Some(&args.destination), Audience::ThisPlatform);
        let plan = build_plan(&args, &Target::parse("vault:").unwrap(), &paths, &findings);

        assert_eq!(plan.count(PLAN_ACTION_SKIP), 1);
        assert_eq!(plan.len(), 1, "the row is present, not dropped");
    }

    #[test]
    fn overwriting_is_refused_unless_it_was_asked_for() {
        let dir = tempfile::tempdir().unwrap();
        let out_arg = occupied(dir.path());

        let (ctx, args) = setup(&["vault:", out_arg.as_str(), "--dry-run"]);
        let error = gate_overwrites(&ctx, &args, 1).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("replace"));

        let (ctx, args) = setup(&["vault:", out_arg.as_str(), "--dry-run", "--overwrite"]);
        assert!(gate_overwrites(&ctx, &args, 1).is_ok());
    }

    #[test]
    fn nothing_to_replace_needs_no_permission() {
        let (ctx, args) = setup(&["vault:", "/tmp/out"]);
        assert!(gate_overwrites(&ctx, &args, 0).is_ok());
    }

    #[test]
    fn immutable_refuses_even_with_the_overwrite_flag() {
        let dir = tempfile::tempdir().unwrap();
        let out_arg = occupied(dir.path());
        let (ctx, args) = setup(&[
            "vault:",
            out_arg.as_str(),
            "--dry-run",
            "--overwrite",
            "--immutable",
        ]);

        let error = gate_overwrites(&ctx, &args, 1).unwrap_err();
        assert!(error.message().contains("--immutable"));
    }

    #[test]
    fn a_fresh_destination_plans_plain_restores() {
        let dir = tempfile::tempdir().unwrap();
        let out_arg = dir.path().join("out").display().to_string();
        let (_, args) = setup(&["vault:photos", out_arg.as_str(), "--dry-run"]);

        let plan = build_plan(
            &args,
            &Target::parse("vault:photos").unwrap(),
            &["photos/a.jpg".to_string(), "photos/b.jpg".to_string()],
            &preflight::Report::default(),
        );
        assert_eq!(plan.count(PLAN_ACTION_RESTORE), 2);
        // The named tree is not repeated beneath the destination.
        assert!(
            plan.entries()[0].destination.ends_with("a.jpg"),
            "{:?}",
            plan.entries()[0]
        );
        assert!(!plan.entries()[0].destination.contains("photos/photos"));
    }
}
