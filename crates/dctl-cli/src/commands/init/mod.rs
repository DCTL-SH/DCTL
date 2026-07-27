//! `dctl init` — create a vault and register both of its remotes.
//!
//! Two things happen here, and they are one command because neither is useful
//! alone.
//!
//! **A vault is created.** A 256-bit root key from the system CSPRNG, wrapped
//! under the password with Argon2id, written to the store as a single envelope
//! object. Everything else in DCTL depends on that envelope: lose it, or replace
//! it, and every object already stored becomes permanently unreadable, because
//! the key that derives their object keys and content keys is gone.
//!
//! **Two remotes are registered.** A vault has two views, and both get names:
//!
//! ```text
//! $ dctl init --name archive --base local:/srv/vault
//!   [remotes.archive-store]  type = local  path = /srv/vault  require_vault
//!   [remotes.archive]        type = vault  base = archive-store
//! ```
//!
//! * `archive:` is the **sealed view**. Everything written through it is
//!   encrypted, and no flag turns that off (invariant I1).
//! * `archive-store:` is the **object view** — the opaque ciphertext objects as
//!   they sit on the provider.
//!
//! Naming the base is the point, not a side effect. Because it has a name, an
//! offsite replication job can be addressed at `archive-store:` and run with
//! **no vault password at all**: a backup operator replicates ciphertext to a
//! second provider and satisfies 3-2-1 without ever holding decryption
//! capability. `PLAN.md` §13.3 requires replicating a vault's object tree
//! provider-to-provider with no re-encryption, and that is unimplementable if
//! the base has no name to type.
//!
//! ## The order things happen in, and why
//!
//! Everything that can fail locally fails before anything is created, and the
//! two irreversible steps are as late as possible:
//!
//! 1. resolve the plan — names, base location, index path — touching nothing;
//! 2. load the configuration and **rehearse** the whole result against a copy,
//!    so a name collision is reported now rather than after a vault exists;
//! 3. stop here for `--dry-run`, which therefore contacts no store and asks for
//!    no password;
//! 4. build the backend and **probe the store for an existing envelope**;
//! 5. ask for confirmation, worded by what the probe found;
//! 6. read the password;
//! 7. write the envelope — irreversible;
//! 8. save the configuration naming both remotes — one atomic write.
//!
//! Step 8 can fail after step 7 has succeeded. That leaves a real vault on a
//! real store with no addressing, which is recoverable and is reported as
//! exactly that: `created: true, registered: false`, with a message naming the
//! `dctl config import` command that finishes the job. The data was never at
//! risk — the envelope is what matters and it is on the store — only the
//! addressing.
//!
//! ## What this build still cannot do
//!
//! **`--key-file` (`PLAN.md` §8).** `dctl_core::Vault::init` takes a password
//! and nothing else; the second factor has no way in. Passing `--key-file` is
//! refused rather than silently creating a vault protected by one factor when
//! the user asked for two. The refusal is delegated to
//! [`crate::session::factor`], which every unlock also goes through, so creating
//! a vault and opening one can never disagree about whether the factor applies.

// Public so `crate::session::password` can pin its first-line rule against this
// one in a test. The two must read a password file identically; a silent
// divergence creates vaults that can never be reopened, so the agreement is
// asserted rather than assumed.
pub mod password;
mod plan;
mod report;

use clap::Args;
use dctl_core::Vault;

use crate::audit::record::Entry as AuditEntry;
use crate::audit::sink;
use crate::config;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::logging::fields;
use crate::remote::envelope::{self, Verdict};

use plan::InitPlan;
use report::InitReport;

/// Stable command name. Must match `Command::name()` in `cli/mod.rs`, because it
/// is the `op` field of the audit record this command appends and a compliance
/// query filters on that word years later.
const COMMAND: &str = "init";

/// Verb used in the confirmation prompt when the store holds no vault.
const CREATE_ACTION: &str = "create a vault on";

/// Verb used when the store already holds an envelope and `--force` was given.
///
/// Worded as the worst case rather than the expected one: the user is being
/// asked to approve the outcome they cannot undo, not the one they intended.
const REPLACE_ACTION: &str = "replace the vault already on, orphaning everything stored under it,";

/// Arguments for `dctl init`.
#[derive(Args, Debug)]
pub struct InitArgs {
    /// Deprecated: the old form, `dctl init LOCATION`. Always an error.
    ///
    /// Still accepted by the parser so the failure can be a *message* rather
    /// than clap's "unexpected argument". Someone with the old command in a
    /// script needs to be told the exact new one to run, and clap cannot say
    /// that.
    ///
    /// Named `legacy_location` rather than `remote` so that the argument id does
    /// not collide with the global `--remote` flag: while it did, `dctl init
    /// --remote b2:media` failed with "unexpected argument" and the flag had to
    /// be written before the subcommand. A deprecated argument making a live one
    /// unusable is a poor trade.
    #[arg(value_name = "REMOTE", hide = true)]
    pub legacy_location: Option<String>,

    /// Name for the vault: the remote you write through. Everything through it
    /// is encrypted.
    ///
    /// Required, and deliberately not marked required by clap — see
    /// `plan::missing_name` for why the refusal is written by hand.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// Location for the ciphertext objects, e.g. 'local:/srv/vault' or
    /// 'b2:my-bucket'. Defaults to --remote.
    #[arg(long, value_name = "BASE")]
    pub base: Option<String>,

    /// Name for the object store remote. Defaults to '<NAME>-store'.
    #[arg(long, value_name = "NAME")]
    pub store_name: Option<String>,
}

/// Create a vault and register the two remotes that address it.
///
/// # Errors
/// * [`ExitCode::Usage`] for the old positional form, a missing `--name` or
///   `--base`, an unusable name, a base that names no location, or a name
///   already taken.
/// * [`ExitCode::FatalError`] when `--key-file` is given (not yet supported by
///   the engine), when an index already exists, or when the store already holds
///   a vault — the last two without `--force`.
/// * [`ExitCode::Cancelled`] when a confirmation prompt was declined.
/// * Whatever the backend or core layer classifies the failure as, once the
///   envelope write begins.
pub async fn run(ctx: &Ctx, args: &InitArgs) -> Result<()> {
    crate::session::factor::refuse_if_present(
        &ctx.globals,
        "dctl init",
        "Creating the vault with one factor when you asked for two would protect \
         it less than you asked for, so nothing was created.",
    )?;

    let plan = InitPlan::resolve(ctx, args)?;
    let mut configured = config::load_or_default(&plan.config_path)?;
    plan.preflight(ctx, &configured)?;

    // Before the backend is built, so `--dry-run` keeps its promise: it contacts
    // no store, needs no credentials and asks for no password.
    if ctx.is_dry_run() {
        ctx.dry_run_notice(CREATE_ACTION, &plan.base);
        ctx.dry_run_notice(
            "register remotes",
            &format!("{}, {}", plan.vault_name, plan.store_name),
        );
        return InitReport::new(&plan, false, false, None, true).emit(ctx);
    }

    let backend = crate::remote::build_backend(&plan.base)?;
    let occupant = envelope::probe(&backend).await?;
    let action = refuse_existing_vault(ctx, &plan, occupant)?;

    if !ctx.confirm_destructive(action, &plan.base)? {
        return Err(CliError::new(
            ExitCode::Cancelled,
            format!("initialisation of '{}' was declined", plan.base),
        )
        .with_hint("Nothing was created."));
    }

    let password = password::acquire_new(&ctx.globals)?;
    ctx.out.info(format!(
        "password read from {}",
        password.source().describe()
    ));

    plan.ensure_index_directory()?;
    let created = Vault::init(backend, &plan.index, password.expose())
        .await
        .map_err(CliError::from);

    // Step 8, at the one point in this command where it can be truthful. The
    // envelope write is the irreversible step and the only durable change `init`
    // makes to a store, so the record goes immediately after it — and is written
    // for a failure too, because "somebody tried to initialise over this store
    // on the 3rd and it did not take" is precisely the kind of event an operator
    // reads a log to find.
    //
    // This is also the record that gives every later one a beginning: it is
    // index 0 of the vault's chain, so a log whose first entry is not an `init`
    // is a log that starts mid-story.
    ctx.audit.record(
        &AuditEntry::new(COMMAND, sink::outcome(&created))
            .remote(&plan.vault_name)
            .path(&plan.base),
    )?;
    created?;

    tracing::info!(
        { fields::REMOTE } = %plan.base,
        vault = %plan.vault_name,
        store = %plan.store_name,
        index = %plan.index.display(),
        "vault created"
    );

    // From here the vault exists. Anything that fails below has to say so.
    register(&plan, &mut configured, ctx.globals.force)
        .map_err(|error| unregistered(&plan, &error))?;

    InitReport::new(&plan, true, true, Some(password.source()), false).emit(ctx)?;
    ctx.out.success(format!(
        "created vault '{}' on '{}'; its objects are addressable as '{}'",
        plan.vault_name, plan.base, plan.store_name
    ));
    Ok(())
}

/// Put both entries in the configuration and write it, in one save.
///
/// Separated from the command body so the "one save, both entries" rule has a
/// single call site: inserting and saving in two statements at the point of use
/// is how a later edit ends up saving between them.
fn register(plan: &InitPlan, configured: &mut config::Config, force: bool) -> Result<()> {
    plan.register(configured, force)?;
    config::save(configured, &plan.config_path)?;
    Ok(())
}

/// Refuse a store that already holds a vault, and pick the confirmation verb.
///
/// The check `dctl init` could not make until the envelope probe existed, and
/// the most valuable one in the command: re-initialising over a vault replaces
/// its root key and makes every object already stored permanently unreadable,
/// while the provider keeps billing for the bytes.
///
/// A [`Verdict::Foreign`] envelope — one written by a newer DCTL — is treated
/// exactly like a readable one. "There is a vault here I am too old to address"
/// and "there is nothing here" lead to opposite actions, and conflating them
/// would let an upgrade-shaped problem end as destroyed data.
///
/// # Errors
/// [`ExitCode::FatalError`] when the store is occupied and `--force` was not
/// given.
fn refuse_existing_vault(ctx: &Ctx, plan: &InitPlan, occupant: Verdict) -> Result<&'static str> {
    if !occupant.is_occupied() {
        return Ok(CREATE_ACTION);
    }

    if !ctx.globals.force {
        let detail = match occupant {
            Verdict::Vault { slots } => format!("with {slots} key slot(s)"),
            Verdict::Foreign { version } => {
                format!("of format version {version}, which this build cannot read")
            }
            Verdict::Absent => String::new(),
        };
        return Err(CliError::new(
            ExitCode::FatalError,
            format!(
                "refusing to initialise: '{}' already holds a vault {detail}",
                plan.base
            ),
        )
        .with_hint(format!(
            "Re-initialising generates a new root key and makes everything \
             already stored there permanently unreadable. To address the vault \
             that is already there, run `dctl config import {} --name {}`. Pass \
             --force only if you are certain the stored objects are worthless.",
            plan.base, plan.vault_name
        )));
    }

    ctx.out.warn(format!(
        "'{}' already holds a vault; --force will replace its root key and \
         orphan everything stored under it",
        plan.base
    ));
    Ok(REPLACE_ACTION)
}

/// Turn a failure to write the configuration into a report of what *did* happen.
///
/// The one place in this command where the honest message is longer than the
/// failure: the vault exists, the data is safe, and only the addressing is
/// missing. Saying "the configuration could not be written" alone would leave an
/// operator believing the run achieved nothing and re-running it — which, with
/// `--force`, would destroy the vault they had just made.
fn unregistered(plan: &InitPlan, error: &CliError) -> CliError {
    CliError::new(
        error.code(),
        format!(
            "the vault was created on '{}', but the configuration naming it \
             could not be written: {}",
            plan.base,
            error.message()
        ),
    )
    .with_hint(format!(
        "Your data is not at risk: the vault's envelope is on the store, and \
         only the addressing is missing. Do NOT re-run `dctl init` — with \
         --force it would replace the vault you just created. Fix the \
         configuration file, then run:\n\n    dctl config import {} --name {}",
        plan.base, plan.vault_name
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, GlobalArgs};
    use crate::constants;
    use clap::Parser;
    use std::path::{Path, PathBuf};

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(config: &Path, extra: &[&str]) -> Ctx {
        let mut args = vec![
            "dctl".to_string(),
            "--config".to_string(),
            config.to_string_lossy().into_owned(),
        ];
        args.extend(extra.iter().map(|a| (*a).to_string()));
        Ctx::new(Harness::parse_from(args).globals)
    }

    /// A temporary directory, a config path inside it, and an index path.
    fn workspace() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let index = dir.path().join("vault.redb");
        (dir, config, index)
    }

    fn args(name: Option<&str>, base: Option<&str>) -> InitArgs {
        InitArgs {
            legacy_location: None,
            name: name.map(str::to_string),
            base: base.map(str::to_string),
            store_name: None,
        }
    }

    #[test]
    fn the_new_surface_parses_and_the_old_one_still_reaches_the_command() {
        // The old form has to *parse* so that the command can answer it with a
        // message; a clap-level rejection could not name the replacement.
        assert!(
            Cli::try_parse_from(["dctl", "init", "--name", "archive", "--base", "b2:x"]).is_ok()
        );
        assert!(Cli::try_parse_from(["dctl", "init", "local:/srv/vault"]).is_ok());
        assert!(Cli::try_parse_from(["dctl", "init"]).is_ok());
        // The global flag is usable *after* the subcommand, which it was not
        // while the deprecated positional held the `remote` argument id.
        assert!(
            Cli::try_parse_from(["dctl", "init", "--name", "archive", "--remote", "b2:x"]).is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "dctl",
                "init",
                "--name",
                "archive",
                "--base",
                "b2:x",
                "--store-name",
                "objects"
            ])
            .is_ok()
        );
    }

    #[tokio::test]
    async fn the_old_form_errors_with_the_exact_new_command() {
        let (_dir, config, index) = workspace();
        let ctx = ctx(&config, &["--index", &index.to_string_lossy()]);
        let raw = InitArgs {
            legacy_location: Some("local:/srv/vault".into()),
            name: None,
            base: None,
            store_name: None,
        };

        let error = run(&ctx, &raw).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(
            error
                .hint()
                .unwrap_or_default()
                .contains("dctl init --name NAME --base local:/srv/vault"),
            "got hint: {:?}",
            error.hint()
        );
        assert!(!config.exists(), "nothing may be written on the old form");
    }

    #[tokio::test]
    async fn a_second_factor_is_refused_rather_than_silently_dropped() {
        // The whole point: a vault the user believes is two-factor must not be
        // created as one-factor.
        let (_dir, config, index) = workspace();
        let ctx = ctx(
            &config,
            &[
                "--key-file",
                "/dev/null",
                "--index",
                &index.to_string_lossy(),
            ],
        );
        let error = run(&ctx, &args(Some("archive"), Some("local:/srv/v")))
            .await
            .unwrap_err();
        assert_ne!(error.code(), ExitCode::Success);
        assert!(
            error.message().contains("--key-file"),
            "{}",
            error.message()
        );
    }

    #[tokio::test]
    async fn a_dry_run_creates_nothing_and_never_asks_for_a_password() {
        // No --password anywhere: if the dry run reached the password step it
        // would fail rather than return Ok, which is what this asserts. It also
        // must not touch the store or the configuration file.
        let (dir, config, index) = workspace();
        let store = dir.path().join("store");
        let ctx = ctx(
            &config,
            &[
                "--dry-run",
                "--no-ask-password",
                "--index",
                &index.to_string_lossy(),
            ],
        );

        run(
            &ctx,
            &args(Some("archive"), Some(&format!("local:{}", store.display()))),
        )
        .await
        .unwrap();

        assert!(!index.exists(), "a dry run must not create the index");
        assert!(!store.exists(), "a dry run must not touch the store");
        assert!(!config.exists(), "a dry run must not write the config");
    }

    #[tokio::test]
    async fn a_created_vault_is_addressable_by_both_names() {
        // The end-to-end promise of the command: one invocation, a real vault,
        // and a configuration in which the sealed view and the object view are
        // both typeable.
        let (dir, config, index) = workspace();
        let store = dir.path().join("store");
        let ctx = ctx(
            &config,
            &[
                "--index",
                &index.to_string_lossy(),
                "--password",
                "correct horse battery staple",
            ],
        );

        run(
            &ctx,
            &args(Some("archive"), Some(&format!("local:{}", store.display()))),
        )
        .await
        .unwrap();

        assert!(
            store.join("system").join("envelope.bin").is_file(),
            "the envelope must be on the store"
        );

        let written = config::load(&config).unwrap();
        assert_eq!(written.len(), 2, "both remotes, in one file");
        assert!(
            written
                .get("archive")
                .is_some_and(config::RemoteDef::is_vault)
        );
        assert!(
            written
                .get("archive-store")
                .is_some_and(config::RemoteDef::require_vault),
            "the store must declare its location vault-only"
        );
        assert_eq!(
            config::vault_chain(&written, "archive").unwrap(),
            ["archive", "archive-store"]
        );
    }

    #[tokio::test]
    async fn both_entries_are_written_by_one_save_or_neither_is() {
        // The atomicity requirement, observed from outside: a run that cannot
        // register must leave the configuration exactly as it was, never with a
        // vault entry whose base does not exist.
        let (dir, config, index) = workspace();
        let store = dir.path().join("store");
        let ctx = ctx(
            &config,
            &[
                "--index",
                &index.to_string_lossy(),
                "--password",
                "correct horse battery staple",
            ],
        );

        // A configuration that already owns the store name. The rehearsal must
        // catch it before anything at all is created.
        let mut existing = config::Config::default();
        existing.insert(
            "archive-store",
            config::RemoteDef::B2(config::B2Def {
                bucket: "unrelated".into(),
                endpoint: None,
                chunk_size: None,
                verify: None,
                require_vault: false,
            }),
        );
        config::save(&existing, &config).unwrap();
        let before = std::fs::read(&config).unwrap();

        let error = run(
            &ctx,
            &args(Some("archive"), Some(&format!("local:{}", store.display()))),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), ExitCode::Usage);
        assert_eq!(
            std::fs::read(&config).unwrap(),
            before,
            "a refused run must not touch the configuration"
        );
        assert!(!store.exists(), "and must not create the vault either");
        assert!(!index.exists());
    }

    #[tokio::test]
    async fn a_store_that_already_holds_a_vault_is_refused() {
        // The check that could not be made before the envelope probe existed,
        // and the most expensive mistake in the CLI if it is not made.
        //
        // It is also the only test that pins the probe against an envelope the
        // *engine* wrote rather than one a fixture assembled, which is what
        // catches a header read against the wrong offset or the wrong byte
        // order. A hand-built fixture agrees with whatever the reader believes;
        // this one does not.
        let (dir, config, index) = workspace();
        let store = dir.path().join("store");
        let password = "correct horse battery staple";
        let first = ctx(
            &config,
            &["--index", &index.to_string_lossy(), "--password", password],
        );
        let base = format!("local:{}", store.display());

        run(&first, &args(Some("archive"), Some(&base)))
            .await
            .unwrap();
        let envelope_bytes = std::fs::read(store.join("system").join("envelope.bin")).unwrap();

        // A second vault: different names, different index, same store.
        let second_index = dir.path().join("second.redb");
        let second = ctx(
            &config,
            &[
                "--index",
                &second_index.to_string_lossy(),
                "--password",
                password,
            ],
        );
        let error = run(&second, &args(Some("backup"), Some(&base)))
            .await
            .unwrap_err();

        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains("already holds a vault"),
            "{}",
            error.message()
        );
        assert!(
            error.hint().unwrap_or_default().contains("config import"),
            "the remediation must be the command that addresses the existing vault"
        );
        assert_eq!(
            std::fs::read(store.join("system").join("envelope.bin")).unwrap(),
            envelope_bytes,
            "the existing envelope must be untouched"
        );
        assert!(!second_index.exists());
    }

    #[tokio::test]
    async fn an_existing_index_is_refused_before_any_password_is_read() {
        let (_dir, config, index) = workspace();
        std::fs::write(&index, b"pretend index").unwrap();

        let ctx = ctx(&config, &["--index", &index.to_string_lossy()]);
        let error = run(&ctx, &args(Some("archive"), Some("local:/srv/v")))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("already exists"));
    }

    #[tokio::test]
    async fn a_base_that_addresses_nothing_fails_before_any_other_step() {
        let (_dir, config, index) = workspace();
        let ctx = ctx(&config, &["--index", &index.to_string_lossy()]);

        for base in ["", "b2:../escape", "b2:"] {
            let error = run(&ctx, &args(Some("archive"), Some(base)))
                .await
                .unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "'{base}'");
        }
        assert!(
            !index.exists(),
            "nothing may be written on the failure path"
        );
        assert!(!config.exists());
    }

    #[tokio::test]
    async fn a_missing_password_fails_instead_of_creating_a_weak_vault() {
        let (dir, config, index) = workspace();
        let store = dir.path().join("store");
        let ctx = ctx(
            &config,
            &["--no-ask-password", "--index", &index.to_string_lossy()],
        );
        let error = run(
            &ctx,
            &args(Some("archive"), Some(&format!("local:{}", store.display()))),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), ExitCode::Usage);
        assert!(
            !index.exists(),
            "nothing may be written on the failure path"
        );
        assert!(!config.exists());
    }

    #[test]
    fn the_confirmation_verbs_name_the_irreversible_outcome() {
        // The prompt has to describe what could be lost, not what was asked for.
        assert!(REPLACE_ACTION.contains("orphaning"));
        assert_ne!(CREATE_ACTION, REPLACE_ACTION);
        assert!(!constants::PASSWORD_CONFIRM_PROMPT.is_empty());
    }
}
