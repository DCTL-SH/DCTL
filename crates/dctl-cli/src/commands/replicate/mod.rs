//! `dctl replicate SOURCE-STORE: DEST-STORE:` — key-free object replication.
//!
//! This is the command that makes `PLAN.md` §13.3's 3-2-1 redundancy real, and
//! its defining property is stated first because everything else follows from
//! it: **it needs no vault password.** It copies opaque ciphertext objects
//! between two object stores, byte for byte, under the same keys. Nothing here
//! derives a key, unwraps an envelope, opens the index or holds a byte of
//! plaintext.
//!
//! ## Separation of duties, as a structural property
//!
//! That is not an optimisation. It is the point.
//!
//! A backup operator can be given credentials for the primary store and the
//! offsite store, a cron entry, and nothing else — no vault password, no
//! recovery phrase, no ability to read a single file they are protecting. They
//! satisfy 3-2-1 without ever holding decryption capability. The person who can
//! read the data and the person who guarantees a second copy of it exists are
//! then two different people **because the tool cannot be run any other way**,
//! rather than because a policy document says so and an audit checks afterwards.
//!
//! This is why `dctl init` names the base store (`archive-store` beside
//! `archive`) instead of leaving it anonymous. A nameless base would force every
//! replication job to re-describe the location, and a location typed twice is a
//! location that eventually differs.
//!
//! ## Why a verb and not `copy --raw`
//!
//! Three reasons, none of them cosmetic.
//!
//! * **The audit log records `replicate`.** A compliance reviewer reading the
//!   trail needs to see that this operation moved ciphertext with no key
//!   present. That is a materially different act from a `copy` through a vault
//!   remote, and two acts differing in whether a decryption key was held must
//!   not share a name.
//! * **It can refuse filters outright.** A filtered replication is a broken
//!   vault — see [`filters`] — and `dctl copy --raw --include '*.jpg'` invites
//!   exactly that, from a *global* flag that could arrive out of a shell alias.
//!   A verb that owns its filter policy can say no; a flag bolted onto a verb
//!   that must honour filters cannot.
//! * **It has its own exit-code story.** A filter is a usage error here rather
//!   than a narrowing; a store that is not a store is a fatal configuration
//!   error rather than an empty transfer; and a destination that serves back
//!   something other than what it stored is exit 20 on a command where that
//!   means the *second copy* is suspect, not the first.
//!
//! ## The addressing model, in one table
//!
//! | typed | result |
//! |-------|--------|
//! | `archive:` (a vault remote) | refused — reading it would decrypt |
//! | `archive-store:` (declared a store) | replicated, no password, no probe |
//! | `local:/srv/vault` (holds an envelope) | replicated, no password |
//! | an undeclared, empty location | refused — declare it first |
//!
//! Nothing in that table is decided by what a destination happens to contain
//! *today* in the sense invariant I4 forbids: the verb fixes the encryption
//! behaviour (there is none — bytes pass through untouched), and the probe only
//! decides *eligibility*. Semantics follow the name typed; eligibility may be
//! demonstrated. See [`target`] for why that distinction holds.
//!
//! ## Layout
//!
//! One concern per file, in the order a run passes through them:
//!
//! | file | concern |
//! |------|---------|
//! | [`filters`] | why there are none, and the refusal that enforces it |
//! | [`target`]  | which two places this runs between, and what makes each one |
//! | [`plan`]    | what would happen, decided from metadata alone |
//! | [`execute`] | moving the bytes, and proving they arrived |
//! | [`report`]  | how the result reaches stdout in each format |
//!
//! ## What this build does not do
//!
//! Objects move **one at a time**, so `--transfers` is not yet honoured; the
//! limit is [`crate::constants::REPLICATE_WHOLE_OBJECT_LIMIT`], since
//! [`dctl_store::Backend::put`] takes a whole buffer and an object larger than
//! that is reported as a failure rather than attempted. Both are stated in
//! `docs/commands/dctl_replicate.md` rather than left for an operator to infer
//! from a slow run.

pub mod execute;
pub mod filters;
pub mod plan;
pub mod report;
pub mod target;

use clap::Args;

use crate::commands::integrity::{command_name, mode};
use crate::config;
use crate::constants::{REPLICATE_DEST_VALUE_NAME, REPLICATE_SOURCE_VALUE_NAME};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::logging::fields;

use plan::Plan;
use report::Report;
use target::Side;

/// The verb this module implements, used wherever the command names itself.
pub(super) const VERB: &str = "replicate";

/// Arguments to `dctl replicate`.
///
/// Two positionals and no flags of its own, which is deliberate: every knob this
/// command could grow — a filter, a prefix, a "replicate only the new ones"
/// switch — is a way to produce a partial replica, and a partial replica is not
/// a vault. The one dial that does apply is the global `--verify`.
#[derive(Args, Debug)]
pub struct ReplicateArgs {
    /// Object store to replicate from. Its whole object tree is copied.
    #[arg(value_name = REPLICATE_SOURCE_VALUE_NAME)]
    pub source: String,

    /// Object store to replicate to. Nothing is ever deleted from it.
    #[arg(value_name = REPLICATE_DEST_VALUE_NAME)]
    pub destination: String,
}

/// Replicate one object store onto another, holding no key.
///
/// # Errors
/// * [`ExitCode::Usage`](crate::exit::ExitCode::Usage) for any filter flag, a
///   malformed spec, a spec naming a path inside a store, a vault remote on
///   either side, or two arguments that address the same place.
/// * [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError) for an
///   unreadable configuration, an unresolvable remote, missing credentials, or a
///   location that is neither declared a vault's object store nor holds one.
/// * Whatever a listing failed with, since a listing that could not be completed
///   must never be replicated as though it were empty.
///
/// A per-object failure is *not* returned here. It is recorded against the
/// object and counted, so the run reaches every other object and the process
/// still exits 6 (or 20 for a destination that stored the wrong bytes) rather
/// than reporting a complete replica.
pub async fn run(ctx: &Ctx, args: &ReplicateArgs) -> Result<()> {
    let command = command_name(VERB);

    // First, before the configuration is read and before either store is
    // contacted: the answer to "did my filter apply?" must never depend on
    // whether the remotes happened to resolve.
    filters::refuse(&ctx.globals)?;

    let configured = config::load_or_default(&config::resolve_path(ctx.globals.config.as_deref()))?;
    let source = target::open(&configured, &args.source, Side::Source, ctx.globals.links).await?;
    let destination = target::open(
        &configured,
        &args.destination,
        Side::Destination,
        ctx.globals.links,
    )
    .await?;
    target::refuse_same_place(&source, &destination)?;

    let verify = ctx.verify_mode();
    let strength = mode::slug(verify);
    ctx.out.info(format!(
        "{command}: {} -> {} at --verify={strength} — {}",
        source.spec,
        destination.spec,
        execute::describe(verify)
    ));
    // Said out loud, because it is the reason this command exists and the reason
    // the operator running it may not be the operator who can read the data.
    ctx.out
        .info("no vault password is read: this run moves opaque ciphertext objects");

    let plan = Plan::build(source.backend(), destination.backend(), verify).await?;
    let planned = plan.summary();
    if planned.extra > 0 {
        // Never acted on — replication adds a copy and never removes one — but
        // drift at a replica is worth knowing about.
        ctx.out.warn(format!(
            "'{}' holds {} object(s) the source does not; replication never \
             deletes, so they are left alone",
            destination.spec, planned.extra
        ));
    }

    // Worth saying explicitly rather than leaving the operator to read a table
    // with no rows in it: a nightly job that finds nothing to do is the job
    // working, and silence reads as a job that did not run.
    if plan.is_empty() {
        ctx.out.info(format!(
            "'{}' already holds every object in '{}'",
            destination.spec, source.spec
        ));
    }

    if ctx.is_dry_run() {
        ctx.dry_run_notice(
            &format!(
                "replicate {} object(s) from '{}' to",
                planned.replicated + planned.reverified,
                source.spec
            ),
            &destination.spec,
        );
        return Report::new(
            VERB,
            &source,
            &destination,
            strength,
            true,
            planned,
            plan.items(),
        )
        .emit(&ctx.out);
    }

    let outcome = execute::run(ctx, &plan, &source, &destination).await?;

    tracing::info!(
        { fields::OP } = VERB,
        // The remote's *name*, because `provider=local` does not tell an
        // operator which of their three offsite stores this run filled.
        { fields::REMOTE } = destination.name(),
        destination = %destination.spec,
        source = %source.spec,
        replicated = outcome.summary.replicated,
        skipped = outcome.summary.skipped,
        failed = outcome.summary.failed,
        bytes = outcome.summary.bytes,
        verify = %strength,
        "replication finished"
    );

    Report::new(
        VERB,
        &source,
        &destination,
        strength,
        false,
        outcome.summary,
        &outcome.items,
    )
    .emit(&ctx.out)?;

    // Worded as what is now true rather than as what was done, because the
    // question an operator is really asking is whether a second copy exists.
    if outcome.summary.failed == 0 {
        ctx.out.success(format!(
            "'{}' now holds every object in '{}' ({} object(s), {} moved this run)",
            destination.spec, source.spec, outcome.summary.objects, outcome.summary.replicated
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use crate::config::{Config, LocalDef, RemoteDef};
    use crate::exit::ExitCode;
    use clap::Parser;
    use std::path::{Path, PathBuf};

    fn ctx(config: &Path, extra: &[&str]) -> Ctx {
        let mut argv = vec![
            "dctl".to_string(),
            "replicate".to_string(),
            "a:".to_string(),
            "b:".to_string(),
            "--config".to_string(),
            config.to_string_lossy().into_owned(),
        ];
        argv.extend(extra.iter().map(|arg| (*arg).to_string()));
        Ctx::new(
            Cli::try_parse_from(argv)
                .expect("arguments should parse")
                .globals,
        )
    }

    fn args(source: &str, destination: &str) -> ReplicateArgs {
        ReplicateArgs {
            source: source.to_string(),
            destination: destination.to_string(),
        }
    }

    /// Two declared stores on disk, the source seeded with one object.
    fn workspace() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let source = dir.path().join("primary");
        let destination = dir.path().join("offsite");
        std::fs::create_dir_all(source.join("data")).unwrap();
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(source.join("data").join("aa"), b"ciphertext").unwrap();

        let mut config = Config::default();
        for (name, path) in [("primary-store", &source), ("offsite-store", &destination)] {
            config.insert(
                name,
                RemoteDef::Local(LocalDef {
                    path: path.clone(),
                    verify: None,
                    require_vault: true,
                }),
            );
        }
        config::save(&config, &config_path).unwrap();

        (dir, config_path, source, destination)
    }

    #[test]
    fn the_command_takes_two_stores_and_no_flags_of_its_own() {
        let cli =
            Cli::try_parse_from(["dctl", "replicate", "archive-store:", "offsite-store:"]).unwrap();
        assert_eq!(cli.command.name(), VERB);
        let Command::Replicate(parsed) = cli.command else {
            panic!("expected the replicate subcommand");
        };
        assert_eq!(parsed.source, "archive-store:");
        assert_eq!(parsed.destination, "offsite-store:");

        // Both arguments are required: a replication with one end named is not a
        // narrower replication, it is a command with no meaning.
        assert!(Cli::try_parse_from(["dctl", "replicate", "archive-store:"]).is_err());
        assert!(Cli::try_parse_from(["dctl", "replicate"]).is_err());
    }

    #[test]
    fn replication_is_a_transfer_that_needs_no_vault() {
        // The two classifications the whole design rests on. `requires_vault`
        // being false is what lets a backup operator hold no password at all.
        let cli =
            Cli::try_parse_from(["dctl", "replicate", "archive-store:", "offsite-store:"]).unwrap();
        assert!(!cli.command.requires_vault());
        assert!(cli.command.is_transfer());
        assert!(!cli.command.is_destructive());
    }

    #[tokio::test]
    async fn a_whole_run_never_asks_for_a_password() {
        // The assertion the command exists for. No --password, no
        // --password-command, no --password-file, and *no* --no-ask-password
        // either: with the last one set a prompt would turn into a tidy error
        // and this test would pass without proving anything. A run that reached
        // the password path would block on a prompt or fail; it does neither,
        // because nothing in this command opens a vault.
        let (_dir, config_path, _source, destination) = workspace();
        let context = ctx(&config_path, &[]);

        run(&context, &args("primary-store:", "offsite-store:"))
            .await
            .unwrap();

        assert_eq!(context.outcome(), ExitCode::Success);
        assert_eq!(
            std::fs::read(destination.join("data").join("aa")).unwrap(),
            b"ciphertext"
        );
    }

    #[tokio::test]
    async fn the_index_is_never_created_or_opened() {
        // "Never touch the index" is structural — this command has no code path
        // that opens one — and asserted from outside so it stays that way: the
        // index file named here must not exist when the run is over.
        let (dir, config_path, _source, _destination) = workspace();
        let index = dir.path().join("must-not-appear.redb");
        let context = ctx(&config_path, &["--index", &index.to_string_lossy()]);

        run(&context, &args("primary-store:", "offsite-store:"))
            .await
            .unwrap();

        assert!(!index.exists(), "replication must not touch an index");
    }

    #[tokio::test]
    async fn a_dry_run_moves_nothing_and_reports_what_it_would_move() {
        let (_dir, config_path, _source, destination) = workspace();
        let context = ctx(&config_path, &["--dry-run"]);

        run(&context, &args("primary-store:", "offsite-store:"))
            .await
            .unwrap();

        assert!(
            !destination.join("data").exists(),
            "a dry run must not write an object"
        );
    }

    #[tokio::test]
    async fn every_filter_is_refused_before_anything_is_contacted() {
        // Refused first, so the answer never depends on whether the remotes
        // resolved. Both specs below are nonsense on purpose.
        let (_dir, config_path, _source, _destination) = workspace();
        let context = ctx(&config_path, &["--include", "*.jpg"]);
        let error = run(&context, &args("nonsense:", "rubbish:"))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("--include"), "{}", error.message());
    }

    #[tokio::test]
    async fn a_vault_remote_is_refused_on_either_side() {
        let (dir, config_path, source, _destination) = workspace();
        let mut config = config::load(&config_path).unwrap();
        config.insert(
            "archive",
            RemoteDef::Vault(crate::config::VaultDef {
                base: "primary-store".into(),
                base_path: None,
                chunk_size: None,
                verify: None,
            }),
        );
        config::save(&config, &config_path).unwrap();
        assert!(source.exists() && dir.path().exists());

        let context = ctx(&config_path, &[]);
        for pair in [
            ("archive:", "offsite-store:"),
            ("primary-store:", "archive:"),
        ] {
            let error = run(&context, &args(pair.0, pair.1)).await.unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "{pair:?}");
            assert!(error.message().contains("decrypts"), "{}", error.message());
        }
    }

    #[tokio::test]
    async fn every_output_format_is_supported() {
        for format in ["text", "json", "json-lines"] {
            let (_dir, config_path, _source, _destination) = workspace();
            let context = ctx(&config_path, &["--format", format]);
            assert!(
                run(&context, &args("primary-store:", "offsite-store:"))
                    .await
                    .is_ok(),
                "{format} failed"
            );
        }
    }
}
