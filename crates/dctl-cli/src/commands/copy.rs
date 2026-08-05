//! `dctl copy SOURCE DEST` — add and update, never remove.
//!
//! The safe verb of the family, and the one to reach for when unsure. `copy`
//! makes the destination a *superset* of the source: a file that exists only at
//! the destination is left exactly where it is, whatever the source looks like.
//! That is the whole difference from [`super::sync`], and it is why `copy` needs
//! no confirmation prompt while `sync` does.
//!
//! Identical files are skipped rather than re-sent. What counts as identical is
//! [`super::transfer::compare`]'s decision, not this module's — size and modification
//! time by default, content hashes under `--checksum`, size alone under
//! `--size-only`.
//!
//! # What runs today
//!
//! Filesystem to filesystem, and filesystem into a vault under `--no-traverse`,
//! run end to end: [`super::transfer::Engine`] reads, seals where a vault is
//! involved, writes durably and commits. What is still refused is refused
//! *loudly* — listing a named remote (so a vault **source** cannot be planned
//! at all), a second remote on the other side, and a plain write into a
//! directory that already holds a vault. **Size is no longer among them**: this
//! command refused any file above one gibibyte until the engine moved to
//! bounded windows, and there is now no size at which a copy stops fitting in
//! memory. No file is ever reported as copied when it was not
//! ([the plan](https://doc.dctl.sh/project/plan) §6).

use clap::Args;

use crate::constants::TRANSFER_COMMAND_COPY;
use crate::ctx::Ctx;
use crate::error::Result;

use super::transfer::{CompareFlags, Engine, TraversalFlags, execute, prepare, report};

/// Arguments for `dctl copy`.
#[derive(Args, Debug)]
pub struct CopyArgs {
    /// Source: a local path, or REMOTE:PATH.
    pub source: String,

    /// Destination: a local path, or REMOTE:PATH. Its contents are never
    /// removed.
    pub dest: String,

    /// Recreate empty source directories at the destination.
    ///
    /// An empty directory holds no objects, so it has no representation in a
    /// vault and would otherwise disappear on the round trip.
    #[arg(long)]
    pub create_empty_src_dirs: bool,

    #[command(flatten)]
    pub compare: CompareFlags,

    #[command(flatten)]
    pub traversal: TraversalFlags,
}

/// Run `dctl copy`.
///
/// The order below is the contract, and every verb in the family repeats it:
/// plan, report, stop if this was a dry run, then execute. Nothing mutates
/// before the report, so what `--dry-run` prints is what a real run performs.
///
/// # Errors
/// Usage errors from the specs and flags, enumeration failures from either side,
/// whatever [`super::transfer::Engine::connect`] refuses (a remote source, two
/// remotes, a vault that will not unlock), and per-file failures, which are
/// counted rather than raised — see [`super::transfer::execute`].
pub async fn run(ctx: &Ctx, args: &CopyArgs) -> Result<()> {
    let request = prepare::Request {
        globals: &ctx.globals,
        source_spec: &args.source,
        dest_spec: &args.dest,
        compare: &args.compare,
        traversal: args.traversal.clone(),
        create_empty_src_dirs: args.create_empty_src_dirs,
        // The line that makes this `copy` and not `sync`.
        delete_extras: false,
    };

    let prepared = prepare::directory_transfer(ctx, &request).await?;
    report::announce(ctx, &prepared.plan, prepared.dest_file_count);

    if ctx.is_dry_run() {
        // The plan *is* the output of a dry run, so it goes to stdout in the
        // active format and the command stops here without touching anything.
        return report::render(
            ctx,
            TRANSFER_COMMAND_COPY,
            &prepared.plan,
            &prepared.source,
            &prepared.dest,
        );
    }

    if prepared.plan.is_noop() {
        // Genuinely nothing to do: every file was proven identical. Saying so is
        // not the same as claiming work was done, so this is an honest success.
        ctx.out
            .info("nothing to transfer: the destination is up to date");
        execute::account_for_skips(ctx, &prepared.plan);
        // The result document, in the active format. `return Ok(())` here was
        // the whole of the output under `--json`: this branch emits only
        // `info`, which the JSON formats suppress, so a run with nothing to do
        // wrote zero bytes to either stream and exited 0. Since `sync` became
        // incremental that is the steady state of every scheduled run, and an
        // empty file is indistinguishable from a binary that never started.
        // `outcome` returns immediately in text mode, so the human view is
        // unchanged.
        return report::outcome(
            ctx,
            TRANSFER_COMMAND_COPY,
            &prepared.plan,
            &prepared.source,
            &prepared.dest,
        );
    }

    execute::account_for_skips(ctx, &prepared.plan);
    let engine =
        Engine::connect(ctx, TRANSFER_COMMAND_COPY, &prepared.source, &prepared.dest).await?;
    execute::transfers(ctx, TRANSFER_COMMAND_COPY, &engine, &prepared.plan).await?;

    // The result document, on a real run. `--json` had no output at all here:
    // the plan was rendered only under `--dry-run`, and the stderr statistics
    // block is suppressed in the JSON formats, so a CI job piping this to a file
    // got zero bytes on every run — including the ones where files failed.
    report::outcome(
        ctx,
        TRANSFER_COMMAND_COPY,
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

    /// Parses `CopyArgs` on its own; global flags reach the command through the
    /// context, exactly as they do in the real dispatcher.
    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        args: CopyArgs,
    }

    fn write(path: &std::path::Path, bytes: usize) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut file = fs::File::create(path).unwrap();
        file.write_all(&vec![b'x'; bytes]).unwrap();
    }

    /// `src/{a.txt,b.txt}` next to `dst/{a.txt (same size), extra.txt}`.
    fn fixture() -> (tempfile::TempDir, String, String) {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("src/a.txt"), 4);
        write(&dir.path().join("src/b.txt"), 8);
        write(&dir.path().join("dst/a.txt"), 4);
        write(&dir.path().join("dst/extra.txt"), 2);
        let source = dir.path().join("src").to_string_lossy().into_owned();
        let dest = dir.path().join("dst").to_string_lossy().into_owned();
        (dir, source, dest)
    }

    fn args(source: &str, dest: &str, extra: &[&str]) -> CopyArgs {
        let argv: Vec<&str> = std::iter::once("dctl")
            .chain(std::iter::once(source))
            .chain(std::iter::once(dest))
            .chain(extra.iter().copied())
            .collect();
        Harness::parse_from(argv).args
    }

    #[test]
    fn the_positional_arguments_are_source_then_dest() {
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
    async fn a_dry_run_reports_the_plan_and_changes_nothing() {
        let (dir, source, dest) = fixture();
        let ctx = ctx(&["--dry-run"]);
        run(&ctx, &args(&source, &dest, &[])).await.unwrap();

        // Nothing was created, nothing was removed.
        assert!(dir.path().join("dst/extra.txt").exists());
        assert!(!dir.path().join("dst/b.txt").exists());
        // And nothing was counted as transferred.
        assert_eq!(ctx.stats.snapshot().files_done, 0);
    }

    #[tokio::test]
    async fn a_dry_run_works_in_every_output_format() {
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

    #[tokio::test]
    async fn a_real_run_actually_moves_the_bytes() {
        // The counterpart to the dry-run test above: when it is not a dry run,
        // the file has to genuinely arrive. Asserting on the destination's
        // contents rather than on a counter is deliberate — a counter can be
        // incremented by a stage that did nothing, but bytes on disk cannot.
        let (dir, source, dest) = fixture();
        let ctx = ctx(&[]);
        run(&ctx, &args(&source, &dest, &[])).await.unwrap();

        let arrived = dir.path().join("dst/b.txt");
        assert!(arrived.exists(), "the planned file must actually arrive");
        assert_eq!(
            std::fs::read(&arrived).unwrap(),
            std::fs::read(dir.path().join("src/b.txt")).unwrap(),
            "the destination must be byte-identical to the source"
        );
        assert_eq!(ctx.outcome(), ExitCode::Success);
    }

    #[tokio::test]
    async fn a_real_copy_leaves_a_verifiable_record_of_what_it_moved() {
        // The whole engine, end to end: the file moves, and the chained record
        // that proves it moved is on disk and verifies. Asserted on the record's
        // *plaintext hash* rather than only its path, because that is what turns
        // the log from an activity log ("something called b.txt was copied") into
        // evidence ("the file whose plaintext hashes to … was copied").
        let (dir, source, dest) = fixture();
        let ctx = ctx(&[]);
        run(&ctx, &args(&source, &dest, &[])).await.unwrap();

        let body = std::fs::read_to_string(ctx.audit.path()).unwrap();
        let records: Vec<crate::audit::record::AuditRecord> = body
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();

        assert_eq!(records.len(), 1, "only b.txt was transferred: {body}");
        assert_eq!(records[0].op, TRANSFER_COMMAND_COPY);
        assert_eq!(records[0].path, "b.txt");
        assert_eq!(records[0].result, ExitCode::Success.slug());
        assert_eq!(
            records[0].plaintext_hash,
            dctl_store::ContentHash::blake3(&std::fs::read(dir.path().join("src/b.txt")).unwrap())
                .hex(),
            "the record must attest to the bytes that actually moved"
        );
        crate::audit::chain::verify(&records).expect("the chain holds");
    }

    #[tokio::test]
    async fn a_skipped_file_is_not_recorded_as_a_transfer() {
        // `a.txt` is identical at both ends, so nothing was written for it. A
        // record would claim a transfer that did not happen — and would make the
        // log grow with every no-op run of a nightly backup.
        let (_dir, source, dest) = fixture();
        let ctx = ctx(&["--size-only"]);
        run(&ctx, &args(&source, &dest, &[])).await.unwrap();

        let body = std::fs::read_to_string(ctx.audit.path()).unwrap_or_default();
        assert!(!body.contains("a.txt"), "{body}");
        assert!(body.contains("b.txt"), "{body}");
    }

    #[tokio::test]
    async fn copy_leaves_the_source_untouched() {
        // The property that separates `copy` from `move`, asserted on the
        // filesystem rather than on the plan.
        let (dir, source, dest) = fixture();
        let ctx = ctx(&[]);
        run(&ctx, &args(&source, &dest, &[])).await.unwrap();

        assert!(
            dir.path().join("src/b.txt").exists(),
            "copy must never remove a source file"
        );
    }

    #[tokio::test]
    async fn an_up_to_date_destination_needs_no_engine() {
        // Every file identical means there is genuinely nothing to do, so the
        // command must not fail on a capability it never needed.
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("src/a.txt"), 4);
        write(&dir.path().join("dst/a.txt"), 4);
        let source = dir.path().join("src").to_string_lossy().into_owned();
        let dest = dir.path().join("dst").to_string_lossy().into_owned();

        // `--size-only` avoids depending on the two files' mtimes.
        let ctx = ctx(&["--size-only"]);
        run(&ctx, &args(&source, &dest, &[])).await.unwrap();

        assert_eq!(ctx.stats.snapshot().files_skipped, 1);
        assert_eq!(ctx.outcome(), ExitCode::Success);
    }

    #[tokio::test]
    async fn copy_never_plans_a_deletion() {
        // The single property that separates this verb from `sync`.
        let (_dir, source, dest) = fixture();
        let ctx = ctx(&["--size-only"]);
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

        assert!(!prepared.plan.destroys_anything());
        assert_eq!(prepared.plan.count(Op::Copy), 1, "only b.txt is missing");
        assert_eq!(prepared.plan.count(Op::Skip), 1, "a.txt is identical");
    }

    #[tokio::test]
    async fn immutable_refuses_to_overwrite_and_leaves_the_destination_alone() {
        // S4: `--immutable` is documented as converting an overwrite into a hard
        // failure, and the transfer family ignored it entirely — this copy exited
        // 0 with dst/a.txt silently replaced, which is the exact failure a
        // write-once archival job uses the flag to prevent.
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("src/a.txt"), 6);
        write(&dir.path().join("src/new.txt"), 2);
        write(&dir.path().join("dst/a.txt"), 3);
        let source = dir.path().join("src").to_string_lossy().into_owned();
        let dest = dir.path().join("dst").to_string_lossy().into_owned();

        let ctx = ctx(&["--immutable"]);
        let error = run(&ctx, &args(&source, &dest, &[])).await.unwrap_err();

        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains("a.txt"),
            "the refusal must name the file it protected: {}",
            error.message()
        );
        // The whole run is refused before anything moves: the existing file keeps
        // its old bytes and the new one is not written either.
        assert_eq!(
            std::fs::read(dir.path().join("dst/a.txt")).unwrap().len(),
            3
        );
        assert!(!dir.path().join("dst/new.txt").exists());
    }

    #[tokio::test]
    async fn immutable_still_copies_a_destination_that_does_not_exist_yet() {
        // The other half of the contract: an absent destination is an addition,
        // not an overwrite, so a write-once job must still be able to add to it.
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("src/new.txt"), 5);
        fs::create_dir_all(dir.path().join("dst")).unwrap();
        let source = dir.path().join("src").to_string_lossy().into_owned();
        let dest = dir.path().join("dst").to_string_lossy().into_owned();

        let ctx = ctx(&["--immutable"]);
        run(&ctx, &args(&source, &dest, &[])).await.unwrap();
        assert!(dir.path().join("dst/new.txt").exists());
    }

    #[tokio::test]
    async fn a_missing_source_is_an_error_not_an_empty_success() {
        let ctx = ctx(&["--dry-run"]);
        let error = run(&ctx, &args("/definitely/not/here", "/tmp", &[]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::DirNotFound);
    }
}
