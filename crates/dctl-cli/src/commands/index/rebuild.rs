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
//! ## What a rebuild costs, and what it recovers
//!
//! Two bounded reads per file: the `n/*` name record, which gives the path and
//! the object key, and then the object's **own header**, which gives the size,
//! the modification time and the content hash the writer sealed. No object body
//! is ever fetched, so a vault of any size rebuilds for the price of a listing
//! plus a few kilobytes per object rather than of a restore.
//!
//! It was a listing-only pass, and the rows it wrote carried **no size, no
//! content hash and no modification time**. That is what `PLAN.md` §13.5 means by
//! an index *"rebuildable by scanning object headers"* — and the headers were not
//! being scanned. The result was an index that looked rebuilt and behaved
//! degraded: `dctl check` cannot compare a row with no size and no hash, `dctl
//! size` reports a lower bound in the shape of a total, and `dctl sync` treats
//! every file as changed and re-uploads the whole dataset. Nothing filled the
//! fields in afterwards either; `cat`, `hashsum` and a whole `scrub` all measure
//! the object and answer from it without writing back, so the only cure was
//! storing every file again.
//!
//! The modification time is the one whose absence reached furthest: a **restore**
//! from an unmeasured index stamps every file with the time of the restore,
//! because that is the only fact available, and a tree recovered that way reads
//! as entirely rewritten to anything that sorts or syncs by date. See
//! `docs/RESTORE_DRILL.md`, which measures it.
//!
//! ## When a header cannot be read
//!
//! The path is indexed anyway — the mapping is what makes the file readable at
//! all — and the row is counted as **unmeasured**. The command reports the count,
//! warns when it is not zero, and exits [`ExitCode::PartialFailure`]. There are
//! only two causes, an object that is not at the provider and a metadata schema
//! this build cannot parse, and an operator has to know which before they trust
//! the index. Reporting a complete rebuild over either would be `PLAN.md` §6's
//! misreport with the recovery story's authority behind it.
//!
//! ## Idempotent, and safe to repeat
//!
//! Existing rows are overwritten with the authoritative mapping from the
//! backend, and a name record that cannot be decrypted — one belonging to a
//! different vault sharing the bucket — is skipped rather than aborting the run.
//! Nothing in the backend is written or deleted, so a rebuild cannot lose data.

use clap::Args;

use crate::audit::record::Entry as AuditEntry;
use crate::audit::sink;
use crate::commands::integrity::{Target, command_name};
use crate::constants;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::session;

use super::report::Report;

/// The verb this module implements, used in messages that name the command.
const VERB: &str = "index rebuild";

/// What `index rebuild` means for a remote that is not a vault.
///
/// The generic refusal ([`crate::session::vault_present`]) says there is no
/// envelope here and no password involved. This says the rest, and it is the
/// half an operator running *this* command needs: DCTL indexes vaults and only
/// vaults, so on a plain remote there is no index, nothing to rebuild, and
/// nothing missing. A listing of a plain remote is read from the backend every
/// time it is asked for.
///
/// It matters more here than for any other verb because `index rebuild` is where
/// three of this binary's own error hints send people. Somebody arriving from one
/// of those is already looking for damage, and the answer they need is that
/// there is none to find.
const NOT_A_VAULT: &str = "A plain remote has no index: DCTL indexes vaults, and a plain \
                           remote's listings are read from the backend on every command, so \
                           there is nothing here to rebuild and nothing missing. \
                           `index rebuild` applies only to a vault.";

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
/// index describing two different points in time. [`ExitCode::FatalError`] with
/// [`NOT_A_VAULT`] when the remote holds no vault. Otherwise whatever
/// [`session::open_with`] reported (an unresolvable remote, a vault that will not
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
    // Said before the scan rather than after: the second read per object is what
    // makes the rows comparable and it is also what makes a large vault's rebuild
    // take twice as many requests, and an operator watching one deserves to know
    // that before they start wondering whether it has hung. This used to be a
    // `warn` saying the opposite — that the rows would carry nothing — which was
    // the honest description of a rebuild that produced a degraded index.
    ctx.out.info(constants::INDEX_REBUILD_NOTICE);

    // `open_with` rather than `open`: this verb has something specific to say
    // about a plain remote, and it is the verb most likely to be pointed at one.
    // See [`NOT_A_VAULT`].
    let session = session::open_with(ctx, &target.spec(), Some(NOT_A_VAULT)).await?;
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
    //
    // The object count is the whole rebuild's, not one per row: a rebuild is a
    // single event over a whole vault, and splitting it into a record per object
    // would bury the one line that matters under a million that do not. Zero
    // when the rebuild failed, because a failed rebuild counted nothing.
    ctx.audit.record(
        &AuditEntry::new(VERB, sink::outcome(&rebuilt))
            .objects(rebuilt.as_ref().map(|r| r.files).unwrap_or_default())
            .remote(&remote),
    )?;
    let rebuilt = rebuilt?;

    tracing::info!(
        files = rebuilt.files,
        measured = rebuilt.measured,
        unmeasured = rebuilt.unmeasured,
        index = %session.index.display(),
        "rebuilt the index from the backend"
    );

    Report::new(
        target.to_string(),
        session.index.display().to_string(),
        rebuilt,
    )
    .emit(&ctx.out)?;

    // Reported after the table, and as a *failure*, not a note. A row nothing
    // could describe is either an object missing at the provider or a schema this
    // build cannot read; both make the index incomparable for that path, and a
    // rebuild that exits 0 over either is a recovery reporting itself complete
    // when it is not (`PLAN.md` §6).
    if rebuilt.unmeasured > 0 {
        ctx.out.warn(format!(
            "{} {}",
            rebuilt.unmeasured,
            constants::INDEX_REBUILD_UNMEASURED_WARNING
        ));
        return Err(CliError::new(
            ExitCode::PartialFailure,
            format!(
                "{command}: {} of {} path(s) are indexed but not described",
                rebuilt.unmeasured, rebuilt.files
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
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
    async fn a_plain_remote_is_told_it_is_not_a_vault_rather_than_blamed_for_its_password() {
        // §16.2, end to end through the real command. Before this, the run
        // prompted for a vault password and then failed at exit 22 with
        //
        //   unlock failed: wrong password or corrupted envelope
        //   … the envelope itself may be damaged; it is stored as
        //   'system/envelope.bin' … restoring that one object from a replica …
        //
        // against a remote that has no envelope, cannot have one, and never had
        // a password. Every assertion below names one thing that message got
        // wrong.
        let dir = tempfile::TempDir::new().unwrap();
        let store = dir.path().join("plain");
        std::fs::create_dir_all(&store).unwrap();
        // A real file in it, so this is a *populated* plain remote rather than
        // an empty directory that might be excused as "nothing here".
        std::fs::write(store.join("notes.txt"), b"not sealed").unwrap();

        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[remotes.plainstore]\ntype = \"local\"\npath = {:?}\n",
                store.to_string_lossy()
            ),
        )
        .unwrap();

        let config = config.to_string_lossy().into_owned();
        let index_path = dir.path().join("index.redb").to_string_lossy().into_owned();
        // `--no-ask-password` is deliberate: if the refusal came *after* the
        // secret was acquired this would fail as VaultLocked instead, and the
        // whole point is that nobody is asked for a password they cannot use.
        let (ctx, args) = parse(&[
            "index",
            "rebuild",
            "plainstore:",
            "--config",
            &config,
            "--index",
            &index_path,
            "--no-ask-password",
        ]);

        let error = run(&ctx, &args).await.unwrap_err();

        assert_ne!(
            error.code(),
            ExitCode::VaultLocked,
            "a plain remote is not a locked vault: {}",
            error.message()
        );
        assert_eq!(error.code(), ExitCode::FatalError);

        let message = error.message();
        assert!(message.contains("not a vault"), "{message}");
        assert!(
            !message.contains("password"),
            "the message must not raise a password: {message}"
        );

        let hint = error.hint().expect("a refusal must say what is going on");
        assert!(
            hint.starts_with("A plain remote has no index"),
            "the verb must answer for itself: {hint}"
        );
        assert!(
            hint.contains("nothing here to rebuild"),
            "and say that nothing is missing: {hint}"
        );
        assert!(
            !hint.contains("Check the password"),
            "nobody should be sent to check a password: {hint}"
        );
        assert!(
            !hint.contains("recovery phrase"),
            "nor to transcribe twenty-four words: {hint}"
        );
        // The `system/envelope.bin` remedy may still be named — an envelope
        // really is unrebuildable — but only as "if a vault was here", never as
        // the diagnosis. What must not survive is the old ordering, where a file
        // that cannot exist at this address was the thing to go and restore.
        assert!(
            hint.contains("plain object store"),
            "the location has to be described correctly first: {hint}"
        );
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
            vault
                .put_file("photos/a.jpg", b"aaa", dctl_core::Modified::Now)
                .await
                .unwrap();
            vault
                .put_file("notes.txt", b"n", dctl_core::Modified::Now)
                .await
                .unwrap();
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
