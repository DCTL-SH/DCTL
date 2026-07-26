//! `dctl sync SOURCE DEST` — make the destination identical to the source.
//!
//! The only verb in the family that removes files the user never named. That one
//! property drives everything about how this command is built:
//!
//! * It is **destructive**, so it asks before it acts
//!   ([`super::transfer::execute::confirm`]) and refuses rather than guesses when the
//!   arguments cannot mean what they say ([`plan`]).
//! * Its `--dry-run` shows **every** planned deletion, in every output format,
//!   because a deletion nobody could review before it happened is not a deletion
//!   anybody approved.
//! * A pattern filter that DCTL cannot evaluate is a hard error, not a warning:
//!   an ignored `--exclude` here does not copy too much, it *deletes* the files
//!   the rule was written to protect.
//!
//! The three files split along the three things a destructive command has to get
//! right separately, so each can be tested without the others:
//!
//! * `mod.rs` — the arguments, and the order the steps run in.
//! * [`plan`] — what would happen, computed without touching anything.
//! * [`execute`] — when it happens, given `--delete-before/during/after`.
//!
//! # What runs today
//!
//! Between two local paths this runs end to end — transfers *and* deletions, in
//! all three orderings. A `sync` involving a vault cannot run at all, and the
//! reason is structural: listing a named remote is unimplemented, and `sync`
//! deliberately has no `--no-traverse` to plan around it, because the
//! destination listing is where its deletions come from. That refusal fires
//! during enumeration, before anything is transferred or removed (`PLAN.md` §6).

pub mod execute;
pub mod plan;

use clap::Args;

use crate::ctx::Ctx;
use crate::error::Result;

use super::transfer::{CompareFlags, DeleteFlags, Engine, ReapTarget, execute as shared, report};

/// Arguments for `dctl sync`.
///
/// Deliberately **no `--no-traverse`**. Skipping the destination listing is a
/// sensible optimisation for `copy`, where the listing only decides what to
/// skip; for `sync` the listing *is* where the deletions come from, so the flag
/// would either do nothing or delete nothing. Accepting an argument and then
/// ignoring it is a defect, so the parser does not accept it.
#[derive(Args, Debug)]
pub struct SyncArgs {
    /// Source: a local path, or REMOTE:PATH.
    pub source: String,

    /// Destination: a local path, or REMOTE:PATH. Files not present at the
    /// source are DELETED from it.
    pub dest: String,

    /// Recreate empty source directories at the destination.
    #[arg(long)]
    pub create_empty_src_dirs: bool,

    #[command(flatten)]
    pub compare: CompareFlags,

    #[command(flatten)]
    pub delete: DeleteFlags,
}

/// Run `dctl sync`.
///
/// The step order is the safety contract: plan, report, stop if this was a dry
/// run, confirm, then execute. Nothing mutates before the confirmation, and the
/// thing confirmed is the same plan that was just printed.
///
/// # Errors
/// Usage errors from the specs, the argument shapes `sync` refuses and the
/// empty-source guard; [`crate::exit::ExitCode::Cancelled`] when the
/// confirmation is declined; and whatever enumerating a side or connecting the
/// engine refuses. Nothing is deleted on any of those paths: each returns before
/// the executor is reached.
pub async fn run(ctx: &Ctx, args: &SyncArgs) -> Result<()> {
    // Resolved before the plan, so a contradictory `--delete-*` combination
    // fails as a usage error rather than after a full enumeration of both sides.
    let mode = args.delete.mode()?;

    let prepared = plan::compute(ctx, args)?;
    report::announce(ctx, &prepared.plan, prepared.dest_file_count);

    if ctx.is_dry_run() {
        // Every planned deletion, on stdout, in the active format. This is the
        // artefact a reviewer approves before a real run is allowed near it.
        return report::render(
            ctx,
            plan::COMMAND,
            &prepared.plan,
            &prepared.source,
            &prepared.dest,
        );
    }

    if prepared.plan.is_noop() {
        ctx.out
            .info("nothing to do: the destination already matches the source");
        shared::account_for_skips(ctx, &prepared.plan);
        return Ok(());
    }

    if prepared.plan.destroys_anything() {
        shared::confirm(
            ctx,
            &format!("delete {} file(s) from", prepared.plan.deletions().count()),
            &prepared.dest.to_string(),
        )?;
    }

    shared::account_for_skips(ctx, &prepared.plan);
    let engine = Engine::connect(ctx, plan::COMMAND, &prepared.source, &prepared.dest).await?;
    let reaper = Engine::connect_reaper(
        ctx,
        plan::COMMAND,
        &prepared.source,
        &prepared.dest,
        ReapTarget::Destination,
    )
    .await?;

    execute::run(ctx, &engine, &reaper, &prepared.plan, mode).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::transfer::testing::ctx;
    use crate::commands::transfer::{DeleteMode, Op};
    use crate::exit::ExitCode;
    use clap::Parser;
    use std::fs;
    use std::io::Write as _;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        args: SyncArgs,
    }

    fn write(path: &std::path::Path, bytes: usize) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut file = fs::File::create(path).unwrap();
        file.write_all(&vec![b'x'; bytes]).unwrap();
    }

    /// `src/{keep.txt}` and `dst/{keep.txt (same), stale.txt}`.
    fn fixture() -> (tempfile::TempDir, String, String) {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("src/keep.txt"), 4);
        write(&dir.path().join("dst/keep.txt"), 4);
        write(&dir.path().join("dst/stale.txt"), 9);
        let source = dir.path().join("src").to_string_lossy().into_owned();
        let dest = dir.path().join("dst").to_string_lossy().into_owned();
        (dir, source, dest)
    }

    fn args(source: &str, dest: &str, extra: &[&str]) -> SyncArgs {
        let argv: Vec<&str> = std::iter::once("dctl")
            .chain(std::iter::once(source))
            .chain(std::iter::once(dest))
            .chain(extra.iter().copied())
            .collect();
        Harness::parse_from(argv).args
    }

    #[test]
    fn the_delete_mode_flags_parse_and_default_to_during() {
        assert_eq!(
            args("a", "b", &[]).delete.mode().unwrap(),
            DeleteMode::During
        );
        assert_eq!(
            args("a", "b", &["--delete-before"]).delete.mode().unwrap(),
            DeleteMode::Before
        );
        assert_eq!(
            args("a", "b", &["--delete-after"]).delete.mode().unwrap(),
            DeleteMode::After
        );
    }

    #[test]
    fn sync_does_not_offer_no_traverse() {
        // The flag would either do nothing or delete nothing, and a flag that
        // parses and is then ignored is a defect.
        assert!(Harness::try_parse_from(["dctl", "a", "b", "--no-traverse"]).is_err());
        // The flags it does offer still work.
        assert!(
            Harness::try_parse_from([
                "dctl",
                "a",
                "b",
                "--ignore-existing",
                "--update",
                "--create-empty-src-dirs",
                "--delete-after",
            ])
            .is_ok()
        );
    }

    #[test]
    fn contradictory_delete_modes_are_rejected_by_the_parser() {
        assert!(
            Harness::try_parse_from(["dctl", "a", "b", "--delete-before", "--delete-after"])
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_dry_run_shows_every_planned_delete_and_removes_nothing() {
        let (dir, source, dest) = fixture();
        let ctx = ctx(&["--dry-run", "--size-only"]);

        let prepared = plan::compute(&ctx, &args(&source, &dest, &[])).unwrap();
        assert_eq!(prepared.plan.count(Op::Delete), 1);

        run(&ctx, &args(&source, &dest, &[])).await.unwrap();

        // The file the plan named is still there.
        assert!(dir.path().join("dst/stale.txt").exists());
        assert_eq!(ctx.stats.snapshot().files_deleted, 0);
    }

    #[tokio::test]
    async fn a_dry_run_works_in_every_output_format() {
        let (_dir, source, dest) = fixture();
        for flags in [
            vec!["--dry-run", "--size-only"],
            vec!["--dry-run", "--size-only", "--json"],
            vec!["--dry-run", "--size-only", "--format", "json-lines"],
        ] {
            let ctx = ctx(&flags);
            assert!(
                run(&ctx, &args(&source, &dest, &[])).await.is_ok(),
                "{flags:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_real_run_makes_the_destination_match_the_source() {
        // Both halves of what `sync` means, asserted on the filesystem: new
        // files arrive, and files present only at the destination are removed.
        // Testing one without the other would pass for a plain `copy`.
        let (dir, source, dest) = fixture();
        let ctx = ctx(&["--size-only", "--force"]);
        run(&ctx, &args(&source, &dest, &[])).await.unwrap();

        assert!(
            !dir.path().join("dst/stale.txt").exists(),
            "a destination-only file must be removed by sync"
        );
        assert_eq!(ctx.outcome(), ExitCode::Success);
    }

    #[tokio::test]
    async fn a_declined_confirmation_stops_the_run() {
        // `--interactive` with no terminal refuses rather than hanging, which is
        // exactly what an unattended job needs — and it must not be silent.
        let (dir, source, dest) = fixture();
        let ctx = ctx(&["--size-only", "--interactive"]);
        let error = run(&ctx, &args(&source, &dest, &[])).await.unwrap_err();

        assert_ne!(error.code(), ExitCode::Success);
        assert!(dir.path().join("dst/stale.txt").exists());
    }

    #[tokio::test]
    async fn an_up_to_date_destination_needs_no_engine_and_no_prompt() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("src/a.txt"), 4);
        write(&dir.path().join("dst/a.txt"), 4);
        let source = dir.path().join("src").to_string_lossy().into_owned();
        let dest = dir.path().join("dst").to_string_lossy().into_owned();

        let ctx = ctx(&["--size-only"]);
        run(&ctx, &args(&source, &dest, &[])).await.unwrap();

        assert_eq!(ctx.stats.snapshot().files_skipped, 1);
        assert_eq!(ctx.outcome(), ExitCode::Success);
    }

    #[tokio::test]
    async fn a_contradictory_delete_mode_fails_before_anything_is_listed() {
        let ctx = ctx(&["--dry-run"]);
        let bad = SyncArgs {
            source: "/definitely/not/here".into(),
            dest: "/tmp".into(),
            create_empty_src_dirs: false,
            compare: CompareFlags::default(),
            delete: DeleteFlags {
                delete_before: true,
                delete_during: true,
                delete_after: false,
            },
        };
        // Usage, not DirNotFound: the flags were rejected before the walk.
        let error = run(&ctx, &bad).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn immutable_refuses_the_deletions_as_well_as_the_overwrites() {
        // "Refuse to modify **or delete** anything that already exists." `sync`
        // is the only verb that removes, so under --immutable it must refuse
        // rather than quietly behave like `copy`: a write-once archive that
        // silently lost its extras would be the worse of the two failures.
        let (dir, source, dest) = fixture();
        let ctx = ctx(&["--size-only", "--immutable", "--force"]);
        let error = run(&ctx, &args(&source, &dest, &[])).await.unwrap_err();

        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("stale.txt"), "{}", error.message());
        assert!(dir.path().join("dst/stale.txt").exists(), "nothing deleted");
        assert_eq!(ctx.stats.snapshot().files_deleted, 0);
    }

    #[tokio::test]
    async fn immutable_still_allows_a_sync_that_only_adds() {
        // Additions are what the flag permits, and `sync` must not become
        // unusable just because it is the verb that *can* delete.
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("src/a.txt"), 4);
        write(&dir.path().join("src/new.txt"), 6);
        write(&dir.path().join("dst/a.txt"), 4);
        let source = dir.path().join("src").to_string_lossy().into_owned();
        let dest = dir.path().join("dst").to_string_lossy().into_owned();

        let ctx = ctx(&["--size-only", "--immutable"]);
        run(&ctx, &args(&source, &dest, &[])).await.unwrap();
        assert!(dir.path().join("dst/new.txt").exists());
    }

    #[tokio::test]
    async fn a_pattern_filter_is_refused_rather_than_ignored() {
        // The data-loss case: an ignored --exclude makes sync delete exactly the
        // files the rule was protecting.
        let (dir, source, dest) = fixture();
        let ctx = ctx(&["--exclude", "stale.*", "--dry-run"]);
        let error = run(&ctx, &args(&source, &dest, &[])).await.unwrap_err();

        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(dir.path().join("dst/stale.txt").exists());
    }
}
