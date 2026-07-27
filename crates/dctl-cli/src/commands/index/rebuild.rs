//! `dctl index rebuild REMOTE:` — rebuild the local index from the backend.
//!
//! The index is a **cache and a privacy layer, never a single point of failure**
//! (`PLAN.md` §13.5). Everything a read needs already lives in the shared
//! backend: the wrapped root key in the envelope, the path→object mapping in the
//! `n/*` name records, and self-describing objects that carry their own DEK and
//! metadata. So a wiped laptop, a corrupted database, or a machine that has never
//! seen this vault before needs exactly two things to become fully functional —
//! the password, and this command.
//!
//! That is the recovery story, and it is the reason a damaged index is an
//! inconvenience rather than a disaster. It is also why several of DCTL's error
//! hints name this command: an index error, an object that is indexed but absent
//! at the provider, and a `cat` of a file written on another machine all point
//! here. A hint that named a command which did not exist would be the same defect
//! class as a refusal naming a remote that cannot be addressed.
//!
//! ## What a rebuild costs, and what it loses
//!
//! It is a **list-only pass**: every `n/*` record is listed and decrypted, but no
//! object body is fetched, so a vault of any size rebuilds for the price of a
//! listing rather than of a restore.
//!
//! The consequence is that the rows it writes carry **no size and no content
//! hash** — those live in the object bodies, and fetching them would turn a cheap
//! reconciliation into a full read of the dataset. They populate again on first
//! read of each file. A listing taken straight after a rebuild therefore shows
//! zero-byte sizes for files that are not zero bytes, which is surprising enough
//! that the command says so before it starts rather than leaving it to be
//! discovered.
//!
//! ## Idempotent, and safe to repeat
//!
//! Existing rows are overwritten with the authoritative mapping from the
//! backend, and a name record that cannot be decrypted — one belonging to a
//! different vault sharing the bucket — is skipped rather than aborting the run.
//! Nothing in the backend is written or deleted, so a rebuild cannot lose data;
//! the worst it can do is replace a well-populated local cache with a sparser one
//! that refills as files are read.

use clap::Args;

use crate::audit::record::Entry as AuditEntry;
use crate::audit::sink;
use crate::commands::integrity::{Target, command_name};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::session;

use super::report::Report;

/// The verb this module implements, used in messages that name the command.
const VERB: &str = "index rebuild";

/// Arguments to `dctl index rebuild`.
#[derive(Args, Debug)]
pub struct RebuildArgs {
    /// Vault to rebuild the index for.
    #[arg(value_name = "REMOTE:")]
    pub target: String,
}

/// Rebuild the local index from the backend's name records.
///
/// # Errors
/// [`CliError::usage`] for a malformed target, a local path, or a target
/// carrying a path — a rebuild is whole-vault and a partial one would leave the
/// index describing two different points in time. Otherwise whatever
/// [`session::open`] reported (an unresolvable remote, a vault that will not
/// unlock) or whatever the scan itself hit.
pub async fn run(ctx: &Ctx, args: &RebuildArgs) -> Result<()> {
    let command = command_name(VERB);
    let target = Target::parse(&args.target)?;
    // The index maps a vault's plaintext paths to its objects. A local directory
    // has no such mapping and nothing to rebuild one from.
    let remote = target.require_remote(&command)?.to_string();

    if !target.path().is_empty() {
        // Refused rather than silently widened. `rebuild_index` enumerates every
        // name record in the backend — there is no prefix-scoped form — so
        // accepting `archive:photos` and rebuilding everything would do more
        // than was asked, and accepting it and rebuilding nothing would do less.
        return Err(CliError::usage(format!(
            "{command} rebuilds a whole vault, but '{target}' names a path inside one"
        ))
        .with_hint(
            "Drop the path and name the remote alone, for example 'archive:'. The \
             scan reads every name record in the backend and has no prefix-scoped \
             form, so a partial rebuild would leave the index describing two \
             different points in time.",
        ));
    }

    if ctx.is_dry_run() {
        // A rebuild writes to the local index, which is the one thing --dry-run
        // has to suppress. It is not opened at all: unlocking to then do nothing
        // would prompt for a password to perform no work.
        ctx.dry_run_notice("rebuild the index for", &target.to_string());
        return Ok(());
    }

    ctx.out.info(format!("{command}: {target}"));
    // Said before the scan, not after: someone watching a listing go to zeroes
    // afterwards should already know why.
    ctx.out.warn(
        "a rebuild is a list-only pass, so the rows it writes carry no size and no \
         content hash until each file is next read",
    );

    let session = session::open(ctx, &target.spec()).await?;
    let rebuilt = session.vault.rebuild_index().await.map_err(CliError::from);

    // A rebuild replaces the whole local index, so it is a change to stored
    // state and belongs in the chain — recorded after the rebuild returns, with
    // no path, because it is the vault as a whole that was rewritten and naming
    // one file inside it would understate the scope.
    //
    // A *failed* rebuild is recorded too, and it is the more interesting of the
    // two: an index that could not be rebuilt is the state in which a listing
    // and the backend disagree, and knowing when that started is the difference
    // between a diagnosis and a guess.
    ctx.audit
        .record(&AuditEntry::new(VERB, sink::outcome(&rebuilt)).remote(&remote))?;
    let files = rebuilt?;

    tracing::info!(
        files,
        index = %session.index.display(),
        "rebuilt the index from the backend"
    );

    Report::new(
        target.to_string(),
        session.index.display().to_string(),
        files,
    )
    .emit(&ctx.out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use crate::exit::ExitCode;
    use clap::Parser;

    fn parse(args: &[&str]) -> (Ctx, RebuildArgs) {
        let cli = Cli::try_parse_from(std::iter::once("dctl").chain(args.iter().copied()))
            .expect("arguments should parse");
        let Command::Index(index) = cli.command else {
            panic!("expected the index subcommand");
        };
        let super::super::Action::Rebuild(rebuild) = index.action;
        (Ctx::new(cli.globals), rebuild)
    }

    #[tokio::test]
    async fn a_target_is_required() {
        assert!(Cli::try_parse_from(["dctl", "index", "rebuild"]).is_err());
    }

    #[tokio::test]
    async fn a_local_target_is_a_usage_error() {
        let (ctx, args) = parse(&["index", "rebuild", "./photos"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains(VERB));
    }

    #[tokio::test]
    async fn a_path_inside_a_vault_is_refused_rather_than_widened() {
        let (ctx, args) = parse(&["index", "rebuild", "archive:photos"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some(), "a refusal must say what to type");
    }

    #[tokio::test]
    async fn a_dry_run_writes_nothing_and_asks_for_no_password() {
        // `--no-ask-password` is deliberately absent: if the dry run reached an
        // unlock it would block on a prompt or fail, and this asserts it does
        // neither.
        let (ctx, args) = parse(&["index", "rebuild", "archive:", "--dry-run"]);
        assert!(ctx.is_dry_run());
        run(&ctx, &args)
            .await
            .expect("a dry run promises a report and delivers exactly that");
    }

    #[tokio::test]
    async fn an_unresolvable_remote_is_an_error_rather_than_a_count_of_zero() {
        // `PLAN.md` §6: a rebuild that never ran must not report "0 files",
        // which a script would read as an empty vault.
        let (ctx, args) = parse(&["index", "rebuild", "nosuchremote:", "--no-ask-password"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("nosuchremote"));
    }

    #[tokio::test]
    async fn a_rebuild_restores_a_deleted_index_from_the_backend_alone() {
        // The recovery story `PLAN.md` §13.5 promises, exercised end to end: the
        // index database is destroyed, and the password plus the backend are
        // enough to make every path listable again.
        use std::sync::Arc;

        use dctl_core::{UnlockKey, Vault};
        use dctl_store::{Backend, LocalFs};

        let dir = tempfile::TempDir::new().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        let index = dir.path().join("index.redb");

        {
            let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(&store));
            let vault = Vault::init(backend, &index, "pw").await.unwrap().vault;
            vault.put_file("photos/a.jpg", b"aaa").await.unwrap();
            vault.put_file("notes.txt", b"n").await.unwrap();
        }

        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[remotes.store]\ntype = \"local\"\npath = {:?}\nrequire_vault = true\n\n\
                 [remotes.archive]\ntype = \"vault\"\nbase = \"store\"\n",
                store.to_string_lossy()
            ),
        )
        .unwrap();

        // Destroy the local cache, exactly as a wiped machine would have.
        std::fs::remove_file(&index).unwrap();

        let config = config.to_string_lossy().into_owned();
        let index_path = index.to_string_lossy().into_owned();
        let (ctx, args) = parse(&[
            "index",
            "rebuild",
            "archive:",
            "--config",
            &config,
            "--index",
            &index_path,
            "--password",
            "pw",
        ]);
        run(&ctx, &args).await.expect("the rebuild succeeds");

        // Both files are addressable again from the backend alone.
        let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(&store));
        let vault = Vault::unlock(backend, &index, UnlockKey::Password("pw"))
            .await
            .unwrap();
        let paths: Vec<String> = vault
            .list("")
            .unwrap()
            .into_iter()
            .map(|record| record.path)
            .collect();
        assert_eq!(paths, ["notes.txt", "photos/a.jpg"]);
        // And they still read back, which is the claim that matters.
        assert_eq!(vault.get_file("notes.txt").await.unwrap().as_slice(), b"n");
    }
}
