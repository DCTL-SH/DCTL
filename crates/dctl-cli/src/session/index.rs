//! Where the index database lives, and making sure it can be opened.
//!
//! Two questions, and they belong together because the second is only ever asked
//! about the answer to the first.
//!
//! ## Where
//!
//! `--index` wins; otherwise the platform data directory. Resolved in one place
//! so two commands in the same invocation can never disagree about which index
//! they are reading — a listing that consulted one database while the transfer
//! beside it wrote another would report a vault that does not exist.
//!
//! ## Why the directory has to be created here
//!
//! The index is a **cache**, not a source of truth (`PLAN.md` §13.5): a lost one
//! is rebuilt from the backend by `dctl index rebuild`. That promise is what
//! makes a wiped laptop an inconvenience instead of a disaster, and it is stated
//! in the command's own documentation — *"a machine that has never seen this
//! vault before needs exactly two things to become fully functional: the
//! password, and this command."*
//!
//! It was not true. `dctl init` created `~/.dctl/index/` on the way past;
//! nothing else did. So on the one machine where the recovery path is actually
//! used — a fresh one, where that directory has never existed — every command
//! that opens a vault failed with
//! `index database error: unable to open database file`, exit **23**, and the
//! hint attached to that failure told the operator to run `dctl index rebuild`:
//! the command that had just failed for that reason. The restore drill in
//! `crates/dctl-cli/tests/restore_drill` hit it at step 4, which is the step
//! whose entire purpose is recovering from a destroyed index.
//!
//! It is created during [`super::open::prepare`], **before** a secret is asked
//! for, which is that module's ordering rule: nothing that can fail on its own
//! may be left until after the operator has been asked for a password — or, on
//! the recovery path, until after they have transcribed twenty-four words off a
//! sheet of paper. A directory that cannot be created because of permissions is
//! exactly such a failure, and it costs nothing to discover it first.
//!
//! Creating a directory is a write, and it happens under `--dry-run` too. That
//! is deliberate and it is the smaller of two surprises: opening the index
//! already *creates the database file itself* on every rehearsal, because the
//! rehearsal has to read the index to have anything to rehearse. An empty
//! directory alongside it changes nothing about what a dry run reports, whereas
//! failing to create it would make `--dry-run` the one form of a command that
//! cannot run on a fresh machine.

use std::path::{Path, PathBuf};

use crate::constants::INDEX_FILE_NAME;
use crate::ctx::Ctx;
use crate::error::Result;

/// The index database this run should use.
pub fn path(ctx: &Ctx) -> PathBuf {
    ctx.globals
        .index
        .clone()
        .unwrap_or_else(|| dctl_meta::paths::data_dir().join(INDEX_FILE_NAME))
}

/// Create the directory `index` will be opened in.
///
/// A no-op when it already exists, which is every run after the first.
///
/// # Errors
/// Any filesystem failure, classified by
/// [`From<std::io::Error>`](crate::error::CliError) — a read-only home, a
/// permission the user does not have, or a parent that exists and is a file.
pub fn ensure_directory(index: &Path) -> Result<()> {
    if let Some(parent) = index.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        let parsed = Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()));
        Ctx::new(parsed.globals)
    }

    #[test]
    fn an_explicit_index_flag_wins() {
        let ctx = ctx(&["--index", "/tmp/custom.redb"]);
        assert_eq!(path(&ctx), PathBuf::from("/tmp/custom.redb"));
    }

    #[test]
    fn the_default_index_lives_in_the_platform_data_directory() {
        let ctx = ctx(&[]);
        let resolved = path(&ctx);
        assert!(resolved.ends_with(INDEX_FILE_NAME));
        // Named after the binary, so a rebrand moves it (dctl_meta owns that).
        assert!(
            resolved.to_string_lossy().contains(dctl_meta::BINARY_NAME),
            "got {}",
            resolved.display()
        );
    }

    #[test]
    fn a_directory_that_does_not_exist_yet_is_created() {
        // The recovery case, and the whole reason this function exists: on a
        // fresh machine nothing has created the index directory, and every
        // command that opens a vault used to fail with exit 23 — including
        // `dctl index rebuild`, whose entire purpose is that machine.
        let root = tempfile::TempDir::new().expect("a temporary directory");
        let index = root.path().join("never/existed/vault.redb");

        ensure_directory(&index).expect("the directory is created");

        assert!(
            index.parent().is_some_and(Path::is_dir),
            "{} was not created",
            index.display()
        );
        assert!(
            !index.exists(),
            "the database file itself must be left to the index layer"
        );
    }

    #[test]
    fn an_existing_directory_is_left_alone() {
        let root = tempfile::TempDir::new().expect("a temporary directory");
        let index = root.path().join("vault.redb");
        std::fs::write(root.path().join("sibling"), b"kept").expect("write a sibling");

        ensure_directory(&index).expect("an existing directory is not an error");

        assert!(
            root.path().join("sibling").exists(),
            "the directory was recreated"
        );
    }

    #[test]
    fn an_index_path_with_no_directory_component_is_not_an_error() {
        // `--index vault.redb` resolves against the working directory, which
        // exists by definition. `Path::parent` answers `Some("")` for it, and
        // `create_dir_all("")` fails — so the empty parent is filtered out
        // rather than passed on.
        ensure_directory(Path::new("vault.redb")).expect("a bare filename is fine");
    }
}
