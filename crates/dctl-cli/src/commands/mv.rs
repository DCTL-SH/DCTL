//! `dctl move SOURCE DEST` — copy, then delete the source, in that order.
//!
//! The module is `mv` because `move` is a Rust keyword; the verb the user types
//! is `move`, and the argument type is [`MoveArgs`].
//!
//! # The ordering *is* the product
//!
//! `PLAN.md` §6 step 7: *"`move` only: after the commit is durable, delete the
//! source."* Everything else about this command is `copy`. That one sentence is
//! why a `move` interrupted by a crash, a network failure, a bad checksum or a
//! Ctrl-C leaves the source file exactly where it was — and why DCTL can be
//! trusted with the one copy of something.
//!
//! The guarantee is encoded, not documented. Source deletion happens inside
//! [`super::transfer::pipeline::move_file`], on the far side of a `?` on the transfer's
//! result, per file. A reader cannot reorder it by accident, and the executor
//! cannot batch it into a second pass, because there is no second pass to batch
//! it into: at every instant the process could be killed, every file is either
//! still at the source or durably committed at the destination.
//!
//! Two consequences worth stating outright:
//!
//! * A checksum mismatch (`PLAN.md` §6 step 4) aborts before the commit, so the
//!   source survives. Exit code 20 says so specifically.
//! * A file that transferred but whose *source deletion* failed is reported as
//!   an error even though the data is safe. The operator needs to know they now
//!   have two copies, not one.
//!
//! # What runs today
//!
//! Between two local paths this runs end to end: each file is written, flushed,
//! and only then removed from the source. A move *into a vault* stops at
//! connect time with [`crate::exit::ExitCode::IndexError`], because this command
//! opens a second [`crate::session::Session`] for its reaper and the index
//! database admits one writer — which is a failure before any byte moves, so
//! both copies survive it. A move *out of* a vault cannot be planned yet:
//! listing a named remote is unimplemented, and that refusal fires during source
//! enumeration.

use clap::Args;

use crate::constants::TRANSFER_COMMAND_MOVE;
use crate::ctx::Ctx;
use crate::error::Result;

use super::transfer::{CompareFlags, Engine, ReapTarget, TraversalFlags, execute, prepare, report};

/// Arguments for `dctl move`.
#[derive(Args, Debug)]
pub struct MoveArgs {
    /// Source: a local path, or REMOTE:PATH. Deleted only after a durable
    /// commit at the destination.
    pub source: String,

    /// Destination: a local path, or REMOTE:PATH. Its existing contents are
    /// never removed.
    pub dest: String,

    /// Recreate empty source directories at the destination.
    #[arg(long)]
    pub create_empty_src_dirs: bool,

    #[command(flatten)]
    pub compare: CompareFlags,

    #[command(flatten)]
    pub traversal: TraversalFlags,
}

/// Run `dctl move`.
///
/// # Errors
/// Usage errors from the specs and flags, [`crate::exit::ExitCode::Cancelled`]
/// when the destructive confirmation is declined, and whatever connecting the
/// engine or its reaper refuses. Nothing is deleted on any of those paths: every
/// one of them returns before the first file is transferred.
pub async fn run(ctx: &Ctx, args: &MoveArgs) -> Result<()> {
    let request = prepare::Request {
        globals: &ctx.globals,
        source_spec: &args.source,
        dest_spec: &args.dest,
        compare: &args.compare,
        traversal: args.traversal.clone(),
        create_empty_src_dirs: args.create_empty_src_dirs,
        // `move` adds to the destination and removes from the *source*; it never
        // removes a destination file the source does not have. That is `sync`.
        delete_extras: false,
    };

    let prepared = prepare::directory_transfer(ctx, &request).await?;
    report::announce(ctx, &prepared.plan, prepared.dest_file_count);

    if ctx.is_dry_run() {
        return report::render(
            ctx,
            TRANSFER_COMMAND_MOVE,
            &prepared.plan,
            &prepared.source,
            &prepared.dest,
        );
    }

    if prepared.plan.is_noop() {
        // Every file is already at the destination. Deleting the sources anyway
        // would be defensible, but it is not what the plan said would happen —
        // and a `move` that removes files without transferring them is exactly
        // the surprise this command exists not to spring.
        ctx.out
            .info("nothing to move: every file is already at the destination");
        execute::account_for_skips(ctx, &prepared.plan);
        return Ok(());
    }

    execute::confirm(
        ctx,
        "move (deleting the source of) files from",
        &prepared.source.to_string(),
    )?;

    execute::account_for_skips(ctx, &prepared.plan);
    let engine =
        Engine::connect(ctx, TRANSFER_COMMAND_MOVE, &prepared.source, &prepared.dest).await?;
    // A second connection, bound to the source side. The target is carried by
    // the reaper rather than passed per call, so a reaper wired for one side can
    // never be handed the other side's path.
    let reaper = Engine::connect_reaper(
        ctx,
        TRANSFER_COMMAND_MOVE,
        &prepared.source,
        &prepared.dest,
        ReapTarget::Source,
    )
    .await?;

    execute::moves(ctx, TRANSFER_COMMAND_MOVE, &engine, &reaper, &prepared.plan).await?;
    report::outcome(
        ctx,
        TRANSFER_COMMAND_MOVE,
        &prepared.plan,
        &prepared.source,
        &prepared.dest,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::transfer::Op;
    use crate::commands::transfer::testing::ctx;
    use crate::exit::ExitCode;
    use clap::Parser;
    use std::fs;
    use std::io::Write as _;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        args: MoveArgs,
    }

    fn write(path: &std::path::Path, bytes: usize) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut file = fs::File::create(path).unwrap();
        file.write_all(&vec![b'x'; bytes]).unwrap();
    }

    fn fixture() -> (tempfile::TempDir, String, String) {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("src/a.txt"), 4);
        write(&dir.path().join("src/b.txt"), 8);
        fs::create_dir_all(dir.path().join("dst")).unwrap();
        let source = dir.path().join("src").to_string_lossy().into_owned();
        let dest = dir.path().join("dst").to_string_lossy().into_owned();
        (dir, source, dest)
    }

    fn args(source: &str, dest: &str, extra: &[&str]) -> MoveArgs {
        let argv: Vec<&str> = std::iter::once("dctl")
            .chain(std::iter::once(source))
            .chain(std::iter::once(dest))
            .chain(extra.iter().copied())
            .collect();
        Harness::parse_from(argv).args
    }

    #[test]
    fn the_verb_is_move_even_though_the_module_is_mv() {
        // The type name is part of the contract with `crate::cli::Command`.
        let parsed = args("from", "to", &[]);
        assert_eq!(parsed.source, "from");
        assert_eq!(parsed.dest, "to");
    }

    #[test]
    fn the_rclone_flags_are_accepted() {
        let parsed = args(
            "a",
            "b",
            &[
                "--create-empty-src-dirs",
                "--ignore-existing",
                "--update",
                "--no-traverse",
            ],
        );
        assert!(parsed.create_empty_src_dirs);
        assert!(parsed.compare.ignore_existing);
        assert!(parsed.compare.update);
        assert!(parsed.traversal.no_traverse);
    }

    #[tokio::test]
    async fn a_dry_run_deletes_nothing_from_the_source() {
        let (dir, source, dest) = fixture();
        let ctx = ctx(&["--dry-run"]);
        run(&ctx, &args(&source, &dest, &[])).await.unwrap();

        assert!(dir.path().join("src/a.txt").exists());
        assert!(dir.path().join("src/b.txt").exists());
        assert_eq!(ctx.stats.snapshot().files_deleted, 0);
    }

    #[tokio::test]
    async fn the_source_is_removed_only_after_the_destination_holds_it() {
        // `PLAN.md` §6 step 7, asserted on the filesystem: the destination must
        // hold the bytes *and* the source must be gone. Checking only the second
        // half would pass for a `move` that deleted without copying.
        let (dir, source, dest) = fixture();
        let ctx = ctx(&["--force"]);
        run(&ctx, &args(&source, &dest, &[])).await.unwrap();

        let moved = dir.path().join("dst/b.txt");
        assert!(moved.exists(), "destination must hold the file");
        assert!(
            !dir.path().join("src/b.txt").exists(),
            "source must be gone once the destination commit is durable"
        );
        assert_eq!(ctx.outcome(), ExitCode::Success);
    }

    #[tokio::test]
    async fn immutable_refuses_before_a_source_can_be_deleted() {
        // S4, in the shape that costs the most: `move` removes each source once
        // its destination commit is durable, so a `--immutable` overwrite that
        // was only caught at write time would already have destroyed the source
        // of the file it then refused. The refusal is a plan-time one, so both
        // sides are untouched.
        let (dir, source, dest) = fixture();
        write(&dir.path().join("dst/a.txt"), 99);

        let ctx = ctx(&["--immutable", "--force"]);
        let error = run(&ctx, &args(&source, &dest, &[])).await.unwrap_err();

        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("a.txt"), "{}", error.message());
        assert!(dir.path().join("src/a.txt").exists(), "source must survive");
        assert!(dir.path().join("src/b.txt").exists());
        assert_eq!(ctx.stats.snapshot().files_deleted, 0);
    }

    #[tokio::test]
    async fn move_plans_the_same_transfers_as_copy() {
        // `move` differs from `copy` in step 7 only; the diff itself is shared.
        let (_dir, source, dest) = fixture();
        let ctx = ctx(&[]);
        let request = prepare::Request {
            globals: &ctx.globals,
            source_spec: &source,
            dest_spec: &dest,
            compare: &CompareFlags::default(),
            traversal: TraversalFlags::default(),
            create_empty_src_dirs: false,
            delete_extras: false,
        };
        let prepared = prepare::directory_transfer(&ctx, &request).await.unwrap();

        assert_eq!(prepared.plan.count(Op::Copy), 2);
        assert!(
            !prepared.plan.destroys_anything(),
            "a move never plans a destination deletion"
        );
    }

    #[tokio::test]
    async fn every_output_format_is_supported() {
        let (_dir, source, dest) = fixture();
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
