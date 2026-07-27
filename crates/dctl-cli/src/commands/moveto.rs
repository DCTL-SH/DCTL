//! `dctl moveto SOURCE DEST` — one thing, to an exact destination name, then
//! delete the source.
//!
//! [`super::copyto`]'s destination semantics with [`super::mv`]'s ordering
//! guarantee. `DEST` names the object rather than the directory it lands in, and
//! the source is removed **only after** the destination commit is durable
//! (`PLAN.md` §6 step 7).
//!
//! ```text
//! dctl moveto scratch/render.mov vault:films/2024/final.mov
//! ```
//!
//! This is the verb for promoting a finished artefact out of a working directory
//! under its real name. It is also the most dangerous one in the family for a
//! single file, because a wrong `DEST` moves the only copy somewhere unexpected
//! — so it is classified destructive, prompts under `--interactive`, and refuses
//! rather than guesses when the argument shapes are ambiguous.
//!
//! The ordering guarantee is not re-implemented here. It lives in
//! [`super::transfer::pipeline::move_file`], which this command reaches through
//! [`super::transfer::execute::moves`], so `move` and `moveto` cannot drift apart.
//!
//! # What runs today
//!
//! Between two local paths this runs end to end: the file is written under its
//! new name, flushed, and only then removed. Promoting *into a vault* stops at
//! connect time with [`crate::exit::ExitCode::IndexError`] — like [`super::mv`],
//! this command opens a second [`crate::session::Session`] for its reaper and
//! the index database admits one writer — which happens before the transfer, so
//! the source survives it. A vault *source* cannot be enumerated yet.

use clap::Args;

use crate::constants::TRANSFER_COMMAND_MOVETO;
use crate::ctx::Ctx;
use crate::error::Result;

use super::transfer::{CompareFlags, Engine, ReapTarget, TraversalFlags, execute, prepare, report};

/// Arguments for `dctl moveto`.
#[derive(Args, Debug)]
pub struct MovetoArgs {
    /// Source: a local path, or REMOTE:PATH. Deleted only after a durable
    /// commit at the destination.
    pub source: String,

    /// Destination, named exactly: the object's full path, not the directory it
    /// goes in.
    pub dest: String,

    #[command(flatten)]
    pub compare: CompareFlags,

    #[command(flatten)]
    pub traversal: TraversalFlags,
}

/// Run `dctl moveto`.
///
/// # Errors
/// Usage errors for the refused argument shapes,
/// [`crate::exit::ExitCode::Cancelled`] when the destructive confirmation is
/// declined, and whatever connecting the engine or its reaper refuses. The
/// source is untouched on every one of those paths: each returns before the
/// transfer, and the transfer must succeed before the reaper is reachable.
pub async fn run(ctx: &Ctx, args: &MovetoArgs) -> Result<()> {
    let request = prepare::Request {
        globals: &ctx.globals,
        source_spec: &args.source,
        dest_spec: &args.dest,
        compare: &args.compare,
        traversal: args.traversal.clone(),
        create_empty_src_dirs: false,
        delete_extras: false,
    };

    let prepared = prepare::exact_transfer(ctx, &request).await?;
    report::announce(ctx, &prepared.plan, prepared.dest_file_count);

    if ctx.is_dry_run() {
        return report::render(
            ctx,
            TRANSFER_COMMAND_MOVETO,
            &prepared.plan,
            &prepared.source,
            &prepared.dest,
        );
    }

    if prepared.plan.is_noop() {
        // The destination already holds this exact object. Deleting the source
        // on that basis alone would be a deletion the plan never announced.
        ctx.out
            .info("nothing to move: the destination already matches");
        execute::account_for_skips(ctx, &prepared.plan);
        return Ok(());
    }

    execute::confirm(
        ctx,
        "move (deleting the source of)",
        &prepared.source.to_string(),
    )?;

    execute::account_for_skips(ctx, &prepared.plan);
    let engine = Engine::connect(
        ctx,
        TRANSFER_COMMAND_MOVETO,
        &prepared.source,
        &prepared.dest,
    )
    .await?;
    let reaper = Engine::connect_reaper(
        ctx,
        TRANSFER_COMMAND_MOVETO,
        &prepared.source,
        &prepared.dest,
        ReapTarget::Source,
    )
    .await?;

    execute::moves(
        ctx,
        TRANSFER_COMMAND_MOVETO,
        &engine,
        &reaper,
        &prepared.plan,
    )
    .await?;
    report::outcome(
        ctx,
        TRANSFER_COMMAND_MOVETO,
        &prepared.plan,
        &prepared.source,
        &prepared.dest,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::transfer::testing::ctx;
    use crate::exit::ExitCode;
    use clap::Parser;
    use std::fs;
    use std::io::Write as _;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        args: MovetoArgs,
    }

    fn write(path: &std::path::Path, bytes: usize) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut file = fs::File::create(path).unwrap();
        file.write_all(&vec![b'x'; bytes]).unwrap();
    }

    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("render.mov"), 16);
        fs::create_dir_all(dir.path().join("existing-dir")).unwrap();
        dir
    }

    fn args(source: &str, dest: &str, extra: &[&str]) -> MovetoArgs {
        let argv: Vec<&str> = std::iter::once("dctl")
            .chain(std::iter::once(source))
            .chain(std::iter::once(dest))
            .chain(extra.iter().copied())
            .collect();
        Harness::parse_from(argv).args
    }

    fn path(dir: &tempfile::TempDir, name: &str) -> String {
        dir.path().join(name).to_string_lossy().into_owned()
    }

    #[test]
    fn the_positional_arguments_are_source_then_exact_dest() {
        let parsed = args("scratch/a.mov", "vault:films/final.mov", &[]);
        assert_eq!(parsed.source, "scratch/a.mov");
        assert_eq!(parsed.dest, "vault:films/final.mov");
    }

    #[test]
    fn the_rclone_flags_are_accepted() {
        let parsed = args(
            "a",
            "b",
            &["--ignore-existing", "--update", "--no-traverse"],
        );
        assert!(parsed.compare.ignore_existing);
        assert!(parsed.compare.update);
        assert!(parsed.traversal.no_traverse);
    }

    #[tokio::test]
    async fn a_dry_run_leaves_the_source_in_place() {
        let dir = fixture();
        let ctx = ctx(&["--dry-run"]);
        run(
            &ctx,
            &args(&path(&dir, "render.mov"), &path(&dir, "out/final.mov"), &[]),
        )
        .await
        .unwrap();

        assert!(dir.path().join("render.mov").exists());
        assert!(!dir.path().join("out").exists());
        assert_eq!(ctx.stats.snapshot().files_deleted, 0);
    }

    #[tokio::test]
    async fn the_source_is_removed_only_after_the_renamed_destination_exists() {
        // The product promise at single-file scale: the source goes only once
        // the destination — under its new name — genuinely holds the bytes.
        let dir = fixture();
        let ctx = ctx(&["--force"]);
        let original = std::fs::read(dir.path().join("render.mov")).unwrap();

        run(
            &ctx,
            &args(&path(&dir, "render.mov"), &path(&dir, "out/final.mov"), &[]),
        )
        .await
        .unwrap();

        let moved = dir.path().join("out/final.mov");
        assert!(moved.exists(), "renamed destination must exist");
        assert_eq!(std::fs::read(&moved).unwrap(), original);
        assert!(
            !dir.path().join("render.mov").exists(),
            "source must be gone once the destination is durable"
        );
    }

    #[tokio::test]
    async fn immutable_refuses_before_the_source_is_promoted_away() {
        // The worst version of S4: `moveto` deletes the source once the
        // destination commit is durable, so an overwrite caught at write time
        // would already have consumed the only copy. The plan-time refusal
        // leaves the source where it was and the destination as it was.
        let dir = fixture();
        write(&dir.path().join("out/final.mov"), 2);
        let ctx = ctx(&["--immutable", "--force"]);

        let error = run(
            &ctx,
            &args(&path(&dir, "render.mov"), &path(&dir, "out/final.mov"), &[]),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("final.mov"), "{}", error.message());
        assert!(
            dir.path().join("render.mov").exists(),
            "source must survive"
        );
        assert_eq!(
            std::fs::read(dir.path().join("out/final.mov"))
                .unwrap()
                .len(),
            2
        );
        assert_eq!(ctx.stats.snapshot().files_deleted, 0);
    }

    #[tokio::test]
    async fn an_existing_directory_destination_is_refused() {
        let dir = fixture();
        let ctx = ctx(&["--dry-run"]);
        let error = run(
            &ctx,
            &args(&path(&dir, "render.mov"), &path(&dir, "existing-dir"), &[]),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn moving_onto_itself_is_refused_before_anything_is_deleted() {
        // Without this guard the source and the destination are the same file,
        // and step 7 would delete what step 6 just committed.
        let dir = fixture();
        let ctx = ctx(&["--force"]);
        let same = path(&dir, "render.mov");
        let error = run(&ctx, &args(&same, &same, &[])).await.unwrap_err();

        assert_eq!(error.code(), ExitCode::Usage);
        assert!(dir.path().join("render.mov").exists());
    }

    #[tokio::test]
    async fn every_output_format_is_supported() {
        let dir = fixture();
        let source = path(&dir, "render.mov");
        let dest = path(&dir, "out/final.mov");
        for flags in [
            vec!["--dry-run"],
            vec!["--dry-run", "--json"],
            vec!["--dry-run", "--format", "json-lines"],
        ] {
            let ctx = ctx(&flags);
            assert!(
                run(&ctx, &args(&source, &dest, &[])).await.is_ok(),
                "{flags:?}"
            );
        }
    }
}
