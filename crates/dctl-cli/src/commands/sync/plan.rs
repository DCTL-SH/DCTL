//! Computing a `sync` plan — the add/update/delete diff, and the guards that
//! stand between a typo and an emptied destination.
//!
//! The diff itself is [`transfer::prepare::directory_transfer`] with one flag
//! flipped: `delete_extras`. Everything specific to `sync` is the checking that
//! happens around it, and it is here rather than inline in the command body for
//! one reason — a plan that can be computed without a `Ctx`, a network, or a
//! mutation is a plan that can be *tested*, and a destructive command's diff is
//! the last thing that should be tested only by running it.
//!
//! ## The empty-source guard
//!
//! `dctl sync /mnt/backup vault:photos` with `/mnt/backup` unmounted lists zero
//! files, which is a perfectly valid instruction to delete every photo. The
//! source and the failure are indistinguishable from inside the process — an
//! unmounted directory and an empty one are the same syscall result — so the
//! command refuses instead of guessing, and `--force` is how someone who really
//! is emptying a tree says so.
//!
//! Two related safeguards live nearby rather than here:
//! [`transfer::report::announce`] shouts when a sync would remove a large share
//! of its destination, and [`transfer::prepare`] refuses a single-file source
//! outright.

use crate::constants::TRANSFER_COMMAND_SYNC;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};

use crate::commands::transfer::{self, TraversalFlags, prepare};

use super::SyncArgs;

/// Compute the plan for a `sync`, and refuse the shapes that cannot be meant.
///
/// # Errors
/// Usage errors from the specs, from the argument shapes `sync` refuses, and
/// from the empty-source guard; enumeration failures from either side.
pub async fn compute(ctx: &Ctx, args: &SyncArgs) -> Result<transfer::Prepared> {
    let request = prepare::Request {
        globals: &ctx.globals,
        source_spec: &args.source,
        dest_spec: &args.dest,
        compare: &args.compare,
        // `sync` never accepts `--no-traverse`: the destination listing is not
        // an optimisation here, it is where the deletions come from. The parser
        // does not offer the flag, and this is the value that makes that true.
        traversal: TraversalFlags::default(),
        create_empty_src_dirs: args.create_empty_src_dirs,
        // The one line that separates `sync` from `copy`.
        delete_extras: true,
    };

    let prepared = prepare::directory_transfer(ctx, &request).await?;
    guard_empty_source(ctx, &prepared)?;
    Ok(prepared)
}

/// Refuse a sync whose source listed nothing but whose destination holds files.
///
/// See the module docs. `--force` is the escape hatch, because emptying a tree
/// on purpose is a real thing to want and DCTL's job is to make it deliberate
/// rather than impossible.
fn guard_empty_source(ctx: &Ctx, prepared: &transfer::Prepared) -> Result<()> {
    let source_is_empty = prepared.plan.transfers().next().is_none()
        && prepared.plan.with_op(transfer::Op::Skip).next().is_none();

    if !source_is_empty || !prepared.plan.destroys_anything() || ctx.globals.force {
        return Ok(());
    }

    Err(CliError::usage(format!(
        "'{}' contains no files, so '{}' would delete all {} of them",
        prepared.source,
        prepared.dest,
        prepared.plan.deletions().count(),
    ))
    .with_hint(
        "An unmounted volume and an empty directory look identical from here. \
         Check the source, or pass --force if the destination really should be \
         emptied. To remove a tree deliberately, use `dctl purge`.",
    ))
}

/// The command name used in reports and errors, so the three files of this
/// module cannot disagree about what to call themselves.
pub const COMMAND: &str = TRANSFER_COMMAND_SYNC;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::transfer::testing::ctx;
    use crate::commands::transfer::{CompareFlags, Op};
    use crate::exit::ExitCode;
    use std::fs;
    use std::io::Write as _;

    fn write(path: &std::path::Path, bytes: usize) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut file = fs::File::create(path).unwrap();
        file.write_all(&vec![b'x'; bytes]).unwrap();
    }

    fn args(source: &str, dest: &str) -> SyncArgs {
        SyncArgs {
            source: source.to_string(),
            dest: dest.to_string(),
            create_empty_src_dirs: false,
            compare: CompareFlags::default(),
            delete: transfer::DeleteFlags::default(),
        }
    }

    /// `src/{keep.txt}` and `dst/{keep.txt (same), stale.txt, old/deep.txt}`.
    fn fixture() -> (tempfile::TempDir, String, String) {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("src/keep.txt"), 4);
        write(&dir.path().join("dst/keep.txt"), 4);
        write(&dir.path().join("dst/stale.txt"), 9);
        write(&dir.path().join("dst/old/deep.txt"), 2);
        let source = dir.path().join("src").to_string_lossy().into_owned();
        let dest = dir.path().join("dst").to_string_lossy().into_owned();
        (dir, source, dest)
    }

    #[tokio::test]
    async fn a_sync_plan_names_every_deletion() {
        let (_dir, source, dest) = fixture();
        let ctx = ctx(&["--size-only"]);
        let prepared = compute(&ctx, &args(&source, &dest)).await.unwrap();

        let mut deleted: Vec<&str> = prepared
            .plan
            .deletions()
            .map(|entry| entry.dest.as_str())
            .collect();
        deleted.sort_unstable();
        assert_eq!(deleted, ["old/deep.txt", "stale.txt"]);
        assert_eq!(prepared.plan.count(Op::Skip), 1, "keep.txt is identical");
    }

    #[tokio::test]
    async fn the_plan_is_computable_without_executing_anything() {
        // The property the whole design rests on: `--dry-run` shows the truth
        // because there is no second traversal that decides while it acts.
        let (dir, source, dest) = fixture();
        let ctx = ctx(&["--size-only"]);
        let first = compute(&ctx, &args(&source, &dest)).await.unwrap();
        let second = compute(&ctx, &args(&source, &dest)).await.unwrap();

        assert_eq!(first.plan.entries, second.plan.entries, "not deterministic");
        // Nothing moved.
        assert!(dir.path().join("dst/stale.txt").exists());
        assert!(dir.path().join("dst/old/deep.txt").exists());
    }

    #[tokio::test]
    async fn an_empty_source_is_refused_rather_than_emptying_the_destination() {
        // The unmounted-volume case. This guard is the difference between a
        // typo and a restore.
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("empty")).unwrap();
        write(&dir.path().join("dst/precious.txt"), 100);
        let source = dir.path().join("empty").to_string_lossy().into_owned();
        let dest = dir.path().join("dst").to_string_lossy().into_owned();

        let ctx = ctx(&[]);
        let error = compute(&ctx, &args(&source, &dest)).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some_and(|hint| hint.contains("--force")));
    }

    #[tokio::test]
    async fn force_allows_a_deliberate_emptying() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("empty")).unwrap();
        write(&dir.path().join("dst/precious.txt"), 100);
        let source = dir.path().join("empty").to_string_lossy().into_owned();
        let dest = dir.path().join("dst").to_string_lossy().into_owned();

        let ctx = ctx(&["--force"]);
        let prepared = compute(&ctx, &args(&source, &dest)).await.unwrap();
        assert_eq!(prepared.plan.deletions().count(), 1);
    }

    #[tokio::test]
    async fn an_empty_source_and_an_empty_destination_is_simply_a_no_op() {
        // Nothing to delete means nothing to guard against.
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("a")).unwrap();
        fs::create_dir_all(dir.path().join("b")).unwrap();
        let source = dir.path().join("a").to_string_lossy().into_owned();
        let dest = dir.path().join("b").to_string_lossy().into_owned();

        let ctx = ctx(&[]);
        let prepared = compute(&ctx, &args(&source, &dest)).await.unwrap();
        assert!(prepared.plan.is_noop());
    }

    #[tokio::test]
    async fn syncing_a_tree_that_only_gained_files_deletes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("src/a.txt"), 1);
        write(&dir.path().join("src/b.txt"), 2);
        write(&dir.path().join("dst/a.txt"), 1);
        let source = dir.path().join("src").to_string_lossy().into_owned();
        let dest = dir.path().join("dst").to_string_lossy().into_owned();

        let ctx = ctx(&["--size-only"]);
        let prepared = compute(&ctx, &args(&source, &dest)).await.unwrap();
        assert!(!prepared.plan.destroys_anything());
        assert_eq!(prepared.plan.count(Op::Copy), 1);
    }
}
