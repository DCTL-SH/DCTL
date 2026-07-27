//! `dctl restore REMOTE: LOCAL` — write a vault, or part of one, back to disk.
//!
//! A backup you never restored is not a backup (`PLAN.md` §13.6), and the way a
//! restore fails is almost never the network. It is a filename:
//! `report:final.pdf` landing on Windows, `README.md` and `readme.md` landing on
//! the same case-insensitive volume, a path four characters past `MAX_PATH`, or
//! a vault entry that needs `a/b` to be a directory when another entry needs it
//! to be a file. Each of those fails *partway through*, leaving a tree that is
//! neither the old one nor the new one, and each is knowable before the first
//! byte moves.
//!
//! So **every path is pre-flighted before anything is written**, and every
//! problem is reported — not the first. An operator who fixes one name, waits
//! six hours and hits the next has been told the truth three times and helped
//! none. The report is data on stdout, in whichever format was asked for, so it
//! can be read by a person or fed to a script.
//!
//! A blocked path stops the whole restore unless `--skip-unwritable` is given.
//! That default is the conservative one: a partial restore that *looks* complete
//! is the failure mode this command exists to prevent, so leaving files out has
//! to be something the operator asked for out loud.
//!
//! ## The order, and why it is that order
//!
//! Parse and validate; refuse what cannot be honoured; unlock; enumerate;
//! pre-flight every name; plan; report; gate; write. The pre-flight sits between
//! the listing and the first write because that is the only position from which
//! it can report *all* of the problems while none of them has cost anything yet.
//!
//! Unlocking happens even for `--dry-run`, and that is not an oversight: a
//! restore cannot pre-flight names it has not read, so a rehearsal that skipped
//! the listing would rehearse nothing. It is a read-only operation and it writes
//! nothing.
//!
//! ## Names are checked as they will be written
//!
//! The pre-flight inspects each path **relative to the destination**, not as it
//! is spelled in the vault. `dctl restore archive:photos /out` writes
//! `photos/2024/a.jpg` to `/out/2024/a.jpg`, so `photos` is not a component that
//! has to be creatable and its length is not part of the destination's. Checking
//! the stored spelling would report problems in a name nobody is about to
//! create, and miss nothing — which is the wrong trade in a report whose whole
//! value is that every line is actionable.
//!
//! ## What is still refused
//!
//! `--at` and `--snapshot` select a point in time this build cannot produce
//! ([`POINT_IN_TIME_FEATURE`]). The index records one current version per path;
//! selecting an earlier one needs the versioned, snapshot-backed index of
//! `PLAN.md` §13.5. Planning today's contents in answer to `--at 2d` would
//! produce a plan that does not answer the question asked, and a restore whose
//! output does not match its arguments is worse than one that refuses.

pub mod archive;

use std::path::PathBuf;

use clap::Args;

use crate::constants::{
    PLAN_ACTION_OVERWRITE, PLAN_ACTION_RESTORE, PLAN_ACTION_SKIP, PLAN_REASON_EXISTS,
    POINT_IN_TIME_FEATURE, POINT_IN_TIME_HINT, PREFLIGHT_SEVERITY_BLOCKING, REMOTE_SEPARATOR,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::output::Stage;
use crate::platform::path as logical;

use super::recovery::report::{self, Document};
use super::recovery::{Audience, Entry, Plan, Selection, SnapshotName, Target};
use super::recovery::{preflight, timespec};
use super::transfer::pipeline;
use archive::{Archive, Object};

/// The verb this module implements.
///
/// Named once because it appears in the `operation` field of the plan document
/// *and* in the messages that name the command.
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

/// One object, paired with everything the plan and the writer need to know
/// about it.
///
/// Built once so the pre-flight, the plan and the writer all act on the same
/// list: three traversals that each re-derived a destination path would be three
/// chances to disagree about where a file goes.
struct Candidate {
    /// The object as the vault holds it.
    object: Object,
    /// Its path relative to the tree that was named — what is actually created
    /// beneath the destination, and therefore what the pre-flight inspects.
    relative: String,
    /// Where it lands on this machine.
    native: PathBuf,
}

pub async fn run(ctx: &Ctx, args: &RestoreArgs) -> Result<()> {
    let target = Target::parse(&args.source)?;
    let selection = Selection::resolve(&ctx.globals)?;

    // Validated even though it cannot be honoured: a malformed `--at` is a usage
    // error, and reporting it as "unimplemented" would send the operator looking
    // for a missing feature instead of a typo.
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

    // Read-only, and unavoidable even for a dry run: a restore cannot pre-flight
    // names it has not read.
    let archive = Archive::open(ctx, &target).await?;
    let candidates = select(&archive, &target, &selection, &args.destination)?;

    // Everything that could stop a name being written, before anything is.
    let paths: Vec<String> = candidates.iter().map(|c| c.relative.clone()).collect();
    let findings = preflight::inspect(&paths, Some(&args.destination), Audience::ThisPlatform);

    let plan = build_plan(&target, &candidates, &findings);
    if plan.is_empty() {
        // Said out loud: "no output and exit 0" reads as success, and a restore
        // that wrote nothing is exactly the case worth noticing. The two reasons
        // are worded differently because they have different fixes.
        ctx.out.warn(if selection.is_restricting() {
            format!("nothing to restore under {target}: every path was excluded by the filters")
        } else {
            format!("nothing to restore under {target}")
        });
    }
    warn_about_unmeasured(ctx, &candidates);

    ctx.stats.set_total_files(plan.len() as u64);
    ctx.stats.set_total_bytes(plan.total_bytes());
    ctx.progress
        .set_totals(plan.total_bytes(), plan.len() as u64);

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
            entries: Some(plan.entries()),
        },
    )?;

    let blocked = findings.blocked_paths();
    if !blocked.is_empty() && !args.skip_unwritable {
        return Err(CliError::new(
            ExitCode::FatalError,
            format!(
                "{} of {} path(s) cannot be written on this platform",
                blocked.len(),
                candidates.len()
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

    if ctx.is_dry_run() {
        return Ok(());
    }

    write_everything(ctx, &archive, &candidates, &findings).await
}

/// Everything under the named tree that survives the filters.
///
/// The filters are applied to the path **relative to the tree that was named**,
/// matching how `copy` treats a source directory: `--include '2024/**'` under
/// `dctl restore archive:photos /out` means what a reader of `/out` expects,
/// rather than silently requiring the `photos/` prefix that is about to be
/// stripped.
fn select(
    archive: &Archive,
    target: &Target,
    selection: &Selection,
    destination: &std::path::Path,
) -> Result<Vec<Candidate>> {
    let mut candidates: Vec<Candidate> = archive
        .contents()?
        .into_iter()
        .filter_map(|object| {
            let relative = target.relative(&object.logical).to_string();
            // The tree's own name, if it is itself an object, has no place
            // beneath the destination: there is nothing left to call it.
            if relative.is_empty() || !selection.admits_file(&relative, object.size) {
                return None;
            }
            let native = logical::from_logical(destination, &relative);
            Some(Candidate {
                object,
                relative,
                native,
            })
        })
        .collect();

    // Deterministic order, so two runs over an unchanged vault produce
    // byte-identical reports and a diff of them shows only real change.
    candidates.sort_by(|a, b| a.relative.cmp(&b.relative));
    Ok(candidates)
}

/// Turn the candidate set into the list of file operations a restore performs.
///
/// Pure: it reads the destination but changes nothing and refuses nothing, so
/// the plan can be printed before any policy decides to stop the run. It is also
/// the *same* list [`write_everything`] walks, which is what makes `--dry-run`
/// worth trusting — not a second traversal that happens to agree today.
fn build_plan(target: &Target, candidates: &[Candidate], findings: &preflight::Report) -> Plan {
    let mut plan = Plan::new();

    for candidate in candidates {
        // The full vault path, not just the operand: a plan row has to name the
        // object precisely enough to look it up.
        let source = format!(
            "{}{REMOTE_SEPARATOR}{}",
            target.remote, candidate.object.logical
        );
        let destination = candidate.native.display().to_string();
        let size = candidate.object.size;

        if findings.blocks(&candidate.relative) {
            // Listed as a skip rather than omitted: a plan that silently drops
            // the interesting rows is how a partial restore looks complete.
            plan.push(
                Entry::new(PLAN_ACTION_SKIP, source, destination, size)
                    .because(PREFLIGHT_SEVERITY_BLOCKING),
            );
        } else if candidate.native.exists() {
            plan.push(
                Entry::new(PLAN_ACTION_OVERWRITE, source, destination, size)
                    .because(PLAN_REASON_EXISTS),
            );
        } else {
            plan.push(Entry::new(PLAN_ACTION_RESTORE, source, destination, size));
        }
    }

    plan.sort();
    plan
}

/// Write every candidate the pre-flight did not block.
///
/// One bad object does not abandon the rest: a per-file failure is counted,
/// reported by name and skipped, and the recorded errors downgrade the exit code
/// through [`Ctx::outcome`] rather than being rolled up into success
/// (`PLAN.md` §7). A *fatal* failure stops the run, on the same line
/// [`pipeline::is_fatal`] draws for the transfer executor: a locked vault would
/// otherwise produce one identical error per file.
async fn write_everything(
    ctx: &Ctx,
    archive: &Archive,
    candidates: &[Candidate],
    findings: &preflight::Report,
) -> Result<()> {
    for candidate in candidates {
        if findings.blocks(&candidate.relative) {
            // Already reported, and already visible in the plan as a skip.
            ctx.stats.file_skipped();
            continue;
        }

        let handle = ctx
            .progress
            .start_file(&candidate.relative, candidate.object.size);
        ctx.progress.set_stage(&handle, Stage::Reading);
        let outcome = archive.fetch(&candidate.object, &candidate.native).await;
        ctx.progress.set_stage(&handle, Stage::Verifying);
        ctx.progress.finish_file(handle);

        match outcome {
            Ok(()) => {
                ctx.stats.add_bytes(candidate.object.size);
                ctx.stats.file_done();
                tracing::debug!(
                    path = %candidate.object.logical,
                    destination = %candidate.native.display(),
                    "restored"
                );
            }
            Err(error) if pipeline::is_fatal(&error) => return Err(error),
            Err(error) => {
                if error.code() == ExitCode::IntegrityFailure {
                    ctx.stats.checksum_mismatch();
                }
                ctx.stats.error();
                ctx.out.warn(format!(
                    "failed to restore {}: {}",
                    candidate.object.logical,
                    error.message()
                ));
            }
        }
    }
    Ok(())
}

/// Say so when the plan's totals are known to understate the restore.
///
/// A vault whose index was rebuilt from the backend carries rows with no
/// recorded size (see [`Object::measured`]). Those files restore perfectly well
/// — the size is not needed to fetch them — but a plan that showed their zero
/// without comment would tell an operator a 4 TB restore is about to write
/// nothing. Naming the count and the remedy is the difference between a wrong
/// number and a wrong number nobody was warned about (`PLAN.md` §6).
fn warn_about_unmeasured(ctx: &Ctx, candidates: &[Candidate]) {
    let unmeasured = candidates.iter().filter(|c| !c.object.measured).count();
    if unmeasured == 0 {
        return;
    }
    ctx.out.warn(format!(
        "{unmeasured} object(s) have no recorded size, so the totals above understate \
         this restore: their index rows were rebuilt from the store and sizes are \
         populated on first read. The files themselves restore normally."
    ));
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

    /// A context and the command's own arguments, from one command line.
    ///
    /// `--config` is pinned to a path that does not exist unless a test supplies
    /// one, so the suite never reads the developer's own configuration.
    fn setup(args: &[&str]) -> (Ctx, RestoreArgs) {
        let mut argv: Vec<String> = std::iter::once("dctl")
            .chain(args.iter().copied())
            .map(String::from)
            .collect();
        if !args.contains(&"--config") {
            argv.push("--config".to_string());
            argv.push(crate::config::absent_path().to_string_lossy().into_owned());
        }
        let harness = Harness::parse_from(argv);
        (Ctx::new(harness.globals.clone()), harness.restore)
    }

    fn object(path: &str, size: u64) -> Object {
        Object {
            logical: path.to_string(),
            size,
            measured: true,
        }
    }

    fn candidate(target: &Target, root: &std::path::Path, path: &str, size: u64) -> Candidate {
        let relative = target.relative(path).to_string();
        let native = logical::from_logical(root, &relative);
        Candidate {
            object: object(path, size),
            relative,
            native,
        }
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
        // nobody asked. The refusal names the phase that makes it real.
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
            assert!(error.hint().is_some_and(|hint| hint.contains("13.5")));
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
    async fn an_unconfigured_remote_is_named_rather_than_read_as_a_directory() {
        // S6 in the read direction: `vault` has no colon on its own, so a
        // re-parse would make it the relative directory `./vault` and the
        // restore would report an empty vault instead of a missing remote.
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out").display().to_string();
        let (ctx, args) = setup(&["vault:", out.as_str(), "--dry-run", "--no-ask-password"]);

        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("vault"), "{}", error.message());
    }

    #[test]
    fn an_existing_file_is_planned_as_an_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir_all(out.join("photos")).unwrap();
        std::fs::write(out.join("photos/a.jpg"), "old").unwrap();

        let target = Target::parse("vault:").unwrap();
        let candidates = vec![candidate(&target, &out, "photos/a.jpg", 3)];
        let plan = build_plan(&target, &candidates, &preflight::Report::default());

        assert_eq!(plan.count(PLAN_ACTION_OVERWRITE), 1);
        assert_eq!(plan.count(PLAN_ACTION_RESTORE), 0);
        // The row names the object precisely enough to look up.
        assert_eq!(plan.entries()[0].source, "vault:photos/a.jpg");
    }

    #[test]
    fn a_blocked_path_is_planned_as_a_visible_skip() {
        // Omitting it would be how a partial restore looks complete.
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let target = Target::parse("vault:").unwrap();
        let candidates = vec![candidate(&target, &out, "bad\u{7}name.jpg", 4)];

        let paths = vec![candidates[0].relative.clone()];
        let findings = preflight::inspect(&paths, Some(&out), Audience::ThisPlatform);
        let plan = build_plan(&target, &candidates, &findings);

        assert_eq!(plan.count(PLAN_ACTION_SKIP), 1);
        assert_eq!(plan.len(), 1, "the row is present, not dropped");
    }

    #[test]
    fn a_plan_row_carries_the_size_the_index_recorded() {
        // The old plan reported zero for every row because it had no vault to
        // ask. A restore that says it will write nothing, and then writes four
        // terabytes, is the misreport PLAN.md §6 forbids.
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let target = Target::parse("vault:").unwrap();
        let candidates = vec![
            candidate(&target, &out, "a.txt", 1_024),
            candidate(&target, &out, "b.txt", 2_048),
        ];
        let plan = build_plan(&target, &candidates, &preflight::Report::default());
        assert_eq!(plan.total_bytes(), 3_072);
    }

    #[test]
    fn overwriting_is_refused_unless_it_was_asked_for() {
        let dir = tempfile::tempdir().unwrap();
        let out_arg = dir.path().join("out").display().to_string();

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
        let out_arg = dir.path().join("out").display().to_string();
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
    fn the_named_tree_is_not_repeated_under_the_destination() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let target = Target::parse("vault:photos").unwrap();
        let candidates = vec![
            candidate(&target, &out, "photos/a.jpg", 1),
            candidate(&target, &out, "photos/2024/b.jpg", 2),
        ];
        let plan = build_plan(&target, &candidates, &preflight::Report::default());

        assert_eq!(plan.count(PLAN_ACTION_RESTORE), 2);
        for entry in plan.entries() {
            assert!(
                !entry.destination.contains("photos"),
                "the named tree must not be repeated: {}",
                entry.destination
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The round trip, against a real vault
    // ─────────────────────────────────────────────────────────────────────────
    //
    // Nothing below is mocked. A vault is initialised over temporary
    // directories exactly as `dctl init` would leave one, `dctl backup` seals a
    // tree into it, and `dctl restore` writes it back out. The assertion is the
    // only one that matters for this command: the two trees are byte-identical.
    // `PLAN.md` §13.6 — a backup you never restored is not a backup — and a
    // test that stopped at "the plan looked right" would be exactly the kind of
    // proof that is worthless on the day it is needed.

    use crate::commands::backup::{self, BackupArgs};
    use dctl_store::{Backend, LocalFs};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    /// The password every fixture vault is sealed with.
    const FIXTURE_PASSWORD: &str = "correct horse battery staple";

    /// A real vault, and the arguments that address it.
    struct Vaulted {
        _store: tempfile::TempDir,
        _index: tempfile::TempDir,
        _config: tempfile::TempDir,
        /// Global flags pinning this run to the fixture's config, index and
        /// password — never the developer's own.
        globals: Vec<String>,
    }

    impl Vaulted {
        /// Initialise a vault the way `dctl init --name archive` leaves one.
        async fn new() -> Self {
            use crate::config::{Config, LocalDef, RemoteDef, VaultDef};

            let store = tempfile::tempdir().unwrap();
            let index = tempfile::tempdir().unwrap();
            let config_dir = tempfile::tempdir().unwrap();

            let index_path = index.path().join("index.redb");
            let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(store.path()));
            dctl_core::Vault::init(backend, &index_path, FIXTURE_PASSWORD)
                .await
                .expect("a fresh vault initialises");

            let mut config = Config::default();
            config.insert(
                "archive-store",
                RemoteDef::Local(LocalDef {
                    path: store.path().to_path_buf(),
                    verify: None,
                    require_vault: true,
                }),
            );
            config.insert(
                "archive",
                RemoteDef::Vault(VaultDef {
                    base: "archive-store".into(),
                    base_path: None,
                    chunk_size: None,
                    verify: None,
                }),
            );
            let config_path = config_dir.path().join("config.toml");
            crate::config::save(&config, &config_path).expect("a valid fixture configuration");

            Self {
                globals: vec![
                    "--config".into(),
                    config_path.to_string_lossy().into_owned(),
                    "--index".into(),
                    index_path.to_string_lossy().into_owned(),
                    "--password".into(),
                    FIXTURE_PASSWORD.into(),
                    "--quiet".into(),
                ],
                _store: store,
                _index: index,
                _config: config_dir,
            }
        }

        /// A context for one command against this vault.
        fn ctx(&self, extra: &[&str]) -> Ctx {
            let argv: Vec<String> = std::iter::once("dctl".to_string())
                .chain(self.globals.iter().cloned())
                .chain(extra.iter().map(|s| (*s).to_string()))
                // Two placeholder operands, because the harness parses the
                // restore arguments alongside the globals.
                .chain(["vault:".to_string(), "/tmp/unused".to_string()])
                .collect();
            Ctx::new(Harness::parse_from(argv).globals)
        }
    }

    /// Every file under `root`, keyed by logical path.
    fn snapshot_tree(root: &std::path::Path) -> BTreeMap<String, Vec<u8>> {
        let mut out = BTreeMap::new();
        let mut stack = vec![(root.to_path_buf(), String::new())];
        while let Some((dir, prefix)) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name().to_string_lossy().into_owned();
                let path = logical::join(&prefix, &name);
                if entry.file_type().unwrap().is_dir() {
                    stack.push((entry.path(), path));
                } else {
                    out.insert(path, std::fs::read(entry.path()).unwrap());
                }
            }
        }
        out
    }

    /// A tree with the shapes that break naive implementations: nesting, an
    /// empty file, binary content, a non-ASCII name, and a file larger than one
    /// streaming chunk.
    fn source_tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("photos/2024")).unwrap();
        std::fs::create_dir_all(dir.path().join("notes")).unwrap();

        std::fs::write(dir.path().join("README.md"), b"# archive\n").unwrap();
        std::fs::write(dir.path().join("notes/empty.txt"), b"").unwrap();
        std::fs::write(dir.path().join("notes/caf\u{e9}.txt"), "expresso\n").unwrap();
        std::fs::write(
            dir.path().join("photos/2024/a.jpg"),
            (0_u32..300_000)
                .map(|i| (i % 251) as u8)
                .collect::<Vec<u8>>(),
        )
        .unwrap();
        dir
    }

    #[tokio::test]
    async fn a_tree_backed_up_and_restored_is_byte_identical() {
        // The headline. Everything else in this file is a detail of this.
        let vault = Vaulted::new().await;
        let source = source_tree();
        let out = tempfile::tempdir().unwrap();

        let backup_ctx = vault.ctx(&[]);
        backup::run(
            &backup_ctx,
            &BackupArgs {
                source: source.path().to_path_buf(),
                destination: "archive:".into(),
                snapshot: false,
                snapshot_name: None,
                follow_symlinks: false,
                strict_names: false,
            },
        )
        .await
        .expect("the backup stores the tree");
        assert_eq!(backup_ctx.outcome(), ExitCode::Success);
        assert_eq!(backup_ctx.stats.snapshot().files_done, 4);

        let restore_ctx = vault.ctx(&[]);
        run(
            &restore_ctx,
            &RestoreArgs {
                source: "archive:".into(),
                destination: out.path().to_path_buf(),
                snapshot: None,
                at: None,
                skip_unwritable: false,
                overwrite: false,
            },
        )
        .await
        .expect("the restore writes the tree back");
        assert_eq!(restore_ctx.outcome(), ExitCode::Success);
        assert_eq!(restore_ctx.stats.snapshot().files_done, 4);

        let before = snapshot_tree(source.path());
        let after = snapshot_tree(out.path());
        assert_eq!(
            before.keys().collect::<Vec<_>>(),
            after.keys().collect::<Vec<_>>(),
            "the restored tree must hold exactly the same paths"
        );
        assert_eq!(before, after, "the two trees must be byte-identical");
    }

    #[tokio::test]
    async fn a_subtree_restores_without_repeating_its_own_name() {
        // `restore archive:photos /out` writes `photos/2024/a.jpg` to
        // `/out/2024/a.jpg`. Getting this wrong nests the result one level
        // deeper than anybody asked for, on every file.
        let vault = Vaulted::new().await;
        let source = source_tree();
        let out = tempfile::tempdir().unwrap();

        backup::run(
            &vault.ctx(&[]),
            &BackupArgs {
                source: source.path().to_path_buf(),
                destination: "archive:".into(),
                snapshot: false,
                snapshot_name: None,
                follow_symlinks: false,
                strict_names: false,
            },
        )
        .await
        .unwrap();

        let ctx = vault.ctx(&[]);
        run(
            &ctx,
            &RestoreArgs {
                source: "archive:photos".into(),
                destination: out.path().to_path_buf(),
                snapshot: None,
                at: None,
                skip_unwritable: false,
                overwrite: false,
            },
        )
        .await
        .unwrap();

        let restored = snapshot_tree(out.path());
        assert_eq!(restored.keys().collect::<Vec<_>>(), ["2024/a.jpg"]);
        assert_eq!(
            restored["2024/a.jpg"],
            std::fs::read(source.path().join("photos/2024/a.jpg")).unwrap()
        );
    }

    #[tokio::test]
    async fn a_dry_run_reports_the_real_sizes_and_writes_nothing() {
        // The plan used to report `0 B` for every row because it had no vault to
        // ask. A rehearsal that says a restore will write nothing, before a run
        // that writes 300 KB, is the misreport PLAN.md §6 forbids.
        let vault = Vaulted::new().await;
        let source = source_tree();
        let out = tempfile::tempdir().unwrap();

        backup::run(
            &vault.ctx(&[]),
            &BackupArgs {
                source: source.path().to_path_buf(),
                destination: "archive:".into(),
                snapshot: false,
                snapshot_name: None,
                follow_symlinks: false,
                strict_names: false,
            },
        )
        .await
        .unwrap();

        let ctx = vault.ctx(&["--dry-run"]);
        run(
            &ctx,
            &RestoreArgs {
                source: "archive:".into(),
                destination: out.path().to_path_buf(),
                snapshot: None,
                at: None,
                skip_unwritable: false,
                overwrite: false,
            },
        )
        .await
        .unwrap();

        let stats = ctx.stats.snapshot();
        assert_eq!(stats.files_total, 4);
        assert_eq!(
            stats.bytes_total,
            300_000 + 10 + "expresso\n".len() as u64,
            "the plan must carry the plaintext sizes the index recorded"
        );
        assert_eq!(stats.files_done, 0, "a dry run writes nothing");
        assert!(
            snapshot_tree(out.path()).is_empty(),
            "a dry run must not create a single file"
        );
    }

    #[tokio::test]
    async fn a_filter_narrows_a_restore_rather_than_stopping_it() {
        // `--exclude` used to refuse the command outright. Now it removes
        // exactly what it names, and nothing else.
        let vault = Vaulted::new().await;
        let source = source_tree();
        let out = tempfile::tempdir().unwrap();

        backup::run(
            &vault.ctx(&[]),
            &BackupArgs {
                source: source.path().to_path_buf(),
                destination: "archive:".into(),
                snapshot: false,
                snapshot_name: None,
                follow_symlinks: false,
                strict_names: false,
            },
        )
        .await
        .unwrap();

        let ctx = vault.ctx(&["--exclude", "photos/**"]);
        run(
            &ctx,
            &RestoreArgs {
                source: "archive:".into(),
                destination: out.path().to_path_buf(),
                snapshot: None,
                at: None,
                skip_unwritable: false,
                overwrite: false,
            },
        )
        .await
        .unwrap();

        let restored = snapshot_tree(out.path());
        assert_eq!(
            restored.keys().collect::<Vec<_>>(),
            ["README.md", "notes/café.txt", "notes/empty.txt"]
        );
    }

    #[tokio::test]
    async fn an_existing_file_is_refused_until_overwrite_is_asked_for() {
        // The destructive gate, exercised against a real vault rather than a
        // synthesised plan: the local file must still hold its old bytes.
        let vault = Vaulted::new().await;
        let source = source_tree();
        let out = tempfile::tempdir().unwrap();
        std::fs::write(out.path().join("README.md"), b"local edits").unwrap();

        backup::run(
            &vault.ctx(&[]),
            &BackupArgs {
                source: source.path().to_path_buf(),
                destination: "archive:".into(),
                snapshot: false,
                snapshot_name: None,
                follow_symlinks: false,
                strict_names: false,
            },
        )
        .await
        .unwrap();

        let args = |overwrite: bool| RestoreArgs {
            source: "archive:".into(),
            destination: out.path().to_path_buf(),
            snapshot: None,
            at: None,
            skip_unwritable: false,
            overwrite,
        };

        let error = run(&vault.ctx(&[]), &args(false)).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert_eq!(
            std::fs::read(out.path().join("README.md")).unwrap(),
            b"local edits",
            "a refused restore must not have written anything"
        );

        // `--force` approves the destructive confirmation without prompting.
        run(&vault.ctx(&["--force"]), &args(true)).await.unwrap();
        assert_eq!(
            std::fs::read(out.path().join("README.md")).unwrap(),
            b"# archive\n"
        );
    }

    #[tokio::test]
    async fn a_corrupted_object_fails_the_restore_and_leaves_no_file_behind() {
        // What "verified as it lands" has to mean. The stored object is
        // overwritten behind DCTL's back; the restore must refuse it, count a
        // checksum mismatch, and leave *nothing* under that name — a
        // wrong-length file under the right name is worse than no file at all.
        let vault = Vaulted::new().await;
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("only.txt"), b"the original bytes").unwrap();
        let out = tempfile::tempdir().unwrap();

        backup::run(
            &vault.ctx(&[]),
            &BackupArgs {
                source: source.path().to_path_buf(),
                destination: "archive:".into(),
                snapshot: false,
                snapshot_name: None,
                follow_symlinks: false,
                strict_names: false,
            },
        )
        .await
        .unwrap();

        let objects = vault._store.path().join("o");
        for entry in std::fs::read_dir(&objects).expect("the object directory exists") {
            let path = entry.unwrap().path();
            let length = std::fs::metadata(&path).unwrap().len();
            std::fs::write(&path, vec![0xA5; length as usize]).unwrap();
        }

        let ctx = vault.ctx(&[]);
        run(
            &ctx,
            &RestoreArgs {
                source: "archive:".into(),
                destination: out.path().to_path_buf(),
                snapshot: None,
                at: None,
                skip_unwritable: false,
                overwrite: false,
            },
        )
        .await
        .expect("one bad object is counted, not raised");

        assert_eq!(ctx.stats.snapshot().files_done, 0);
        assert_ne!(ctx.outcome(), ExitCode::Success);
        assert!(
            !out.path().join("only.txt").exists(),
            "no file may be left under the name of an object that did not authenticate"
        );
    }

    #[test]
    fn the_preflight_inspects_the_name_that_will_actually_be_created() {
        // `archive:report:final` names a tree whose own component Windows would
        // refuse — but that component is stripped, never created, so reporting
        // it would be a line no operator could act on.
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let target = Target::parse("vault:reports").unwrap();
        let candidate = candidate(&target, &out, "reports/a.txt", 1);
        assert_eq!(candidate.relative, "a.txt");
    }
}
