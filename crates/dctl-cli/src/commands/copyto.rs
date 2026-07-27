//! `dctl copyto SOURCE DEST` — one thing, to an exact destination name.
//!
//! The difference from [`super::copy`] is what `DEST` means, and it is the
//! difference between two shell commands people already know:
//!
//! ```text
//! dctl copy   report.pdf vault:archive      → vault:archive/report.pdf
//! dctl copyto report.pdf vault:archive/2024.pdf → vault:archive/2024.pdf
//! ```
//!
//! `copy` treats `DEST` as a container; `copyto` treats it as the object's name.
//! That makes `copyto` the verb for "upload this and call it that" — the one a
//! backup script uses when the destination name carries a date.
//!
//! For a **directory** source the two coincide: a tree copied under an exact
//! name is just a tree whose destination root is that name, so `copyto` behaves
//! exactly like `copy` and the relative paths inside are preserved.
//!
//! Two argument shapes are refused outright, because neither has a defensible
//! reading: a `DEST` that names no object at all (a bare `vault:` or `/`), and a
//! `DEST` that already exists as a directory — it cannot be both the object's
//! name and the place the object goes.
//!
//! # What runs today
//!
//! The transfer itself runs: filesystem to filesystem, and filesystem into a
//! vault under `--no-traverse`. A vault *source* still cannot be enumerated, so
//! the download direction is refused during listing, and two remotes are refused
//! outright. What lands in a vault is the destination's last component at the
//! vault root: [`super::transfer::Engine`] resolves the remote *name* as a
//! directory and does not yet apply the logical path inside it — the engine's
//! own module docs record both gaps.

use clap::Args;

use crate::constants::TRANSFER_COMMAND_COPYTO;
use crate::ctx::Ctx;
use crate::error::Result;

use super::transfer::{CompareFlags, Engine, TraversalFlags, execute, prepare, report};

/// Arguments for `dctl copyto`.
#[derive(Args, Debug)]
pub struct CopytoArgs {
    /// Source: a local path, or REMOTE:PATH.
    pub source: String,

    /// Destination, named exactly: the object's full path, not the directory it
    /// goes in.
    pub dest: String,

    #[command(flatten)]
    pub compare: CompareFlags,

    #[command(flatten)]
    pub traversal: TraversalFlags,
}

/// Run `dctl copyto`.
///
/// # Errors
/// Usage errors for the refused argument shapes described in the module docs,
/// enumeration failures, and whatever
/// [`super::transfer::Engine::connect`] refuses — a remote source, two remotes,
/// a vault that will not unlock, or a plain write into a vault directory.
pub async fn run(ctx: &Ctx, args: &CopytoArgs) -> Result<()> {
    let request = prepare::Request {
        globals: &ctx.globals,
        source_spec: &args.source,
        dest_spec: &args.dest,
        compare: &args.compare,
        traversal: args.traversal.clone(),
        // No `--create-empty-src-dirs`: rclone does not offer it here, and an
        // exact-name transfer of a single file has no directories to recreate.
        create_empty_src_dirs: false,
        delete_extras: false,
    };

    let prepared = prepare::exact_transfer(ctx, &request).await?;
    report::announce(ctx, &prepared.plan, prepared.dest_file_count);

    if ctx.is_dry_run() {
        return report::render(
            ctx,
            TRANSFER_COMMAND_COPYTO,
            &prepared.plan,
            &prepared.source,
            &prepared.dest,
        );
    }

    if prepared.plan.is_noop() {
        ctx.out
            .info("nothing to transfer: the destination already matches");
        execute::account_for_skips(ctx, &prepared.plan);
        return Ok(());
    }

    execute::account_for_skips(ctx, &prepared.plan);
    let engine = Engine::connect(
        ctx,
        TRANSFER_COMMAND_COPYTO,
        &prepared.source,
        &prepared.dest,
    )
    .await?;
    execute::transfers(ctx, TRANSFER_COMMAND_COPYTO, &engine, &prepared.plan).await
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
        args: CopytoArgs,
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
        write(&dir.path().join("report.pdf"), 12);
        write(&dir.path().join("tree/a.txt"), 3);
        write(&dir.path().join("tree/sub/b.txt"), 4);
        fs::create_dir_all(dir.path().join("existing-dir")).unwrap();
        dir
    }

    fn args(source: &str, dest: &str, extra: &[&str]) -> CopytoArgs {
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
        let parsed = args("from", "to/name.bin", &[]);
        assert_eq!(parsed.source, "from");
        assert_eq!(parsed.dest, "to/name.bin");
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
    async fn a_file_is_renamed_by_the_destination() {
        let dir = fixture();
        let ctx = ctx(&["--dry-run"]);
        let source = path(&dir, "report.pdf");
        let dest = path(&dir, "out/archive-2024.pdf");

        let request = prepare::Request {
            globals: &ctx.globals,
            source_spec: &source,
            dest_spec: &dest,
            compare: &CompareFlags::default(),
            traversal: TraversalFlags::default(),
            create_empty_src_dirs: false,
            delete_extras: false,
        };
        let prepared = prepare::exact_transfer(&ctx, &request).await.unwrap();

        assert_eq!(prepared.plan.entries.len(), 1);
        assert_eq!(prepared.plan.entries[0].source, "report.pdf");
        assert_eq!(prepared.plan.entries[0].dest, "archive-2024.pdf");

        // And the run itself changes nothing.
        run(&ctx, &args(&source, &dest, &[])).await.unwrap();
        assert!(!dir.path().join("out").exists());
    }

    #[tokio::test]
    async fn a_directory_source_keeps_its_relative_paths() {
        let dir = fixture();
        let ctx = ctx(&["--dry-run"]);
        let source = path(&dir, "tree");
        let dest = path(&dir, "out");

        let request = prepare::Request {
            globals: &ctx.globals,
            source_spec: &source,
            dest_spec: &dest,
            compare: &CompareFlags::default(),
            traversal: TraversalFlags::default(),
            create_empty_src_dirs: false,
            delete_extras: false,
        };
        let prepared = prepare::exact_transfer(&ctx, &request).await.unwrap();

        let mut dests: Vec<&str> = prepared
            .plan
            .actions()
            .map(|entry| entry.dest.as_str())
            .collect();
        dests.sort_unstable();
        assert_eq!(dests, ["a.txt", "sub/b.txt"]);
        assert_eq!(prepared.plan.count(Op::Copy), 2);

        run(&ctx, &args(&source, &dest, &[])).await.unwrap();
    }

    #[tokio::test]
    async fn an_existing_directory_destination_is_refused() {
        // It cannot be both the object's name and the place the object goes.
        let dir = fixture();
        let ctx = ctx(&["--dry-run"]);
        let error = run(
            &ctx,
            &args(&path(&dir, "report.pdf"), &path(&dir, "existing-dir"), &[]),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn immutable_refuses_to_write_over_the_named_destination() {
        // The exact-name path reaches the same gate as the directory one: an
        // existing DEST makes the single plan entry an `update`, which is what
        // --immutable forbids. Asserting on the bytes, because a refusal that
        // still wrote would be the defect wearing a passing test.
        let dir = fixture();
        write(&dir.path().join("out/x.pdf"), 1);
        let ctx = ctx(&["--immutable"]);

        let error = run(
            &ctx,
            &args(&path(&dir, "report.pdf"), &path(&dir, "out/x.pdf"), &[]),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("x.pdf"), "{}", error.message());
        assert_eq!(
            std::fs::read(dir.path().join("out/x.pdf")).unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn immutable_with_no_traverse_is_refused_as_a_usage_error() {
        // --no-traverse never looks the destination up, so every entry is
        // planned as a first-time copy and the overwrite --immutable exists to
        // forbid becomes invisible. Honouring the pair would be a guarantee
        // downgraded to a hope, so the pair is refused instead.
        let dir = fixture();
        let ctx = ctx(&["--immutable"]);
        let error = run(
            &ctx,
            &args(
                &path(&dir, "report.pdf"),
                &path(&dir, "out/x.pdf"),
                &["--no-traverse"],
            ),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), ExitCode::Usage);
        assert!(
            error.message().contains("--no-traverse"),
            "{}",
            error.message()
        );
    }

    #[tokio::test]
    async fn a_destination_that_names_nothing_is_refused() {
        let dir = fixture();
        let ctx = ctx(&["--dry-run"]);
        let error = run(&ctx, &args(&path(&dir, "report.pdf"), "vault:", &[]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_real_run_writes_the_exact_destination_name() {
        // The property that separates `copyto` from `copy`: DEST names the
        // object, not the directory to put it in. Asserting the file exists at
        // `out/x.pdf` — and not at `out/report.pdf` — is the whole verb.
        let dir = fixture();
        let ctx = ctx(&[]);
        run(
            &ctx,
            &args(&path(&dir, "report.pdf"), &path(&dir, "out/x.pdf"), &[]),
        )
        .await
        .unwrap();

        assert!(dir.path().join("out/x.pdf").exists(), "renamed destination");
        assert!(
            !dir.path().join("out/report.pdf").exists(),
            "copyto must not fall back to the source's own name"
        );
        assert_eq!(
            std::fs::read(dir.path().join("out/x.pdf")).unwrap(),
            std::fs::read(dir.path().join("report.pdf")).unwrap(),
        );
    }

    #[tokio::test]
    async fn every_output_format_is_supported() {
        let dir = fixture();
        let source = path(&dir, "report.pdf");
        let dest = path(&dir, "out/x.pdf");
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
