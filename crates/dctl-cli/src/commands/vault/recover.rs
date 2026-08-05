//! `dctl vault recover REMOTE:` — open a vault with its recovery phrase and set
//! a new password.
//!
//! The command somebody runs on the worst day: the password is gone, the
//! ciphertext is intact on a provider that keeps billing for it, and the only
//! thing left is a sheet of paper. It is named in the hint
//! [`crate::error`] attaches to every failed unlock, which is the one
//! instruction a frightened operator will follow — so it has to exist, do what
//! the hint says, and leave the vault usable afterwards.
//!
//! ## Two steps, one command
//!
//! Opening the vault with the phrase is not the request. "I lost my password"
//! means "give me my vault back", and a vault that can only be opened by typing
//! twenty-four words is not back. So this unlocks with the phrase and then
//! rewrites the password slot, which is the operation `dctl_core` exposes for
//! exactly this: `Vault::change_password` replaces the one `slot_type = 1` slot
//! and carries every other slot through byte-identical.
//!
//! The phrase therefore keeps working afterwards — the paper does not go stale
//! — and that is stated in the output, because somebody who assumes otherwise
//! will destroy their backup on the way to the filing cabinet.
//!
//! `--keep-password` covers the other real use: a **restore drill**
//! (`PLAN.md` §13.6). Proving the phrase opens the vault is something to do
//! every year, and it must not be a change to the vault, or nobody will do it.
//!
//! ## What it deliberately does not do
//!
//! It does not re-issue the phrase, and it does not touch any other slot. Both
//! are refusals rather than omissions: a recovery is performed by somebody whose
//! access is already precarious, and the moment it starts rewriting key material
//! it was not asked about is the moment a recovery can *cost* a way in.

use clap::Args;
use dctl_core::UnlockKey;

use crate::audit::record::Entry as AuditEntry;
use crate::audit::sink;
use crate::commands::init::password as new_password;
use crate::commands::integrity::{Target, command_name};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::session;

use super::report::Report;

/// The verb this module implements, used in messages that name the command.
const VERB: &str = "vault recover";

/// What the user is told did not happen when `--key-file` is refused here.
const NOTHING_HAPPENED: &str = "The vault was not opened and no key material was changed.";

/// What `vault recover` means for a remote that is not a vault.
///
/// A recovery phrase is a key slot in an envelope. Where there is no envelope
/// there is no slot, so no phrase — right, wrong or beautifully transcribed —
/// can open the location, and reading twenty-four words into a terminal to
/// discover that is the most expensive way DCTL has of saying nothing.
const NOT_A_VAULT: &str = "A recovery phrase opens a key slot in a vault's envelope, so there is \
                           nothing here for one to open and no words worth transcribing. \
                           `vault recover` applies only to a vault.";

/// Said after a successful recovery, because the alternative belief destroys the
/// backup.
///
/// Somebody who has just set a new password has every reason to assume the words
/// that got them here are now spent. They are not — the phrase slot was never
/// touched — and the sheet of paper is still the only other way in.
const PHRASE_STILL_WORKS: &str =
    "the recovery phrase is unchanged and still opens this vault; keep the paper";

/// Arguments to `dctl vault recover`.
#[derive(Args, Debug)]
pub struct RecoverArgs {
    /// Vault to recover.
    #[arg(value_name = "REMOTE:")]
    pub target: String,

    /// Only prove the phrase opens the vault; leave the password alone.
    ///
    /// The restore-drill mode (`PLAN.md` §13.6). A yearly "does my paper backup
    /// still work?" must not change the vault, or it will not be run yearly.
    #[arg(long)]
    pub keep_password: bool,
}

/// Open a vault with its recovery phrase, then replace its password.
///
/// # Errors
/// * [`ExitCode::Usage`] for a local target or one carrying a path — key
///   material belongs to a whole vault, and `archive:photos` names something
///   this command has no meaning for.
/// * [`ExitCode::VaultLocked`] when no phrase is available, when the phrase is
///   malformed, or when it opens no slot.
/// * [`ExitCode::FatalError`] when `--key-file` is given, or the remote cannot
///   be resolved.
/// * Whatever the backend classifies a failed envelope write as.
///
/// [`ExitCode::Usage`]: crate::exit::ExitCode::Usage
/// [`ExitCode::VaultLocked`]: crate::exit::ExitCode::VaultLocked
/// [`ExitCode::FatalError`]: crate::exit::ExitCode::FatalError
pub async fn run(ctx: &Ctx, args: &RecoverArgs) -> Result<()> {
    let command = command_name(VERB);

    // First, before the remote and before any secret is requested: a second
    // factor this build cannot apply is refused rather than dropped, exactly as
    // every other unlock refuses it. See `crate::session::factor`. It is quoted
    // the way the user typed it — `dctl vault recover`, via `command_name` —
    // because the refusal's job is to map onto the command line in front of
    // them, and a bare verb does not.
    session::factor::refuse_if_present(&ctx.globals, &command, NOTHING_HAPPENED)?;

    let target = Target::parse(&args.target)?;
    let remote = target.require_remote(&command)?.to_string();

    if !target.path().is_empty() {
        return Err(CliError::usage(format!(
            "{command} acts on a whole vault, but '{target}' names a path inside one"
        ))
        .with_hint(
            "Drop the path and name the remote alone, for example 'archive:'. A \
             vault has one envelope and one root key; there is no per-directory \
             key material to recover.",
        ));
    }

    // Before the phrase is requested, not after. Transcribing twenty-four words
    // is the most expensive thing this command asks of anybody, and a run that
    // accepted them, opened the vault, and only then discovered that
    // `--no-ask-password` forbids reading the new password would have spent that
    // effort to change nothing. The refusal names `--keep-password`, because an
    // unattended run that wanted to *check* the phrase rather than rotate the
    // password is by far the likeliest thing behind this combination.
    if !args.keep_password && ctx.globals.no_ask_password && !ctx.globals.has_password_source() {
        return Err(CliError::usage(format!(
            "{command} sets a new password, but no password source is available \
             and --no-ask-password forbids prompting"
        ))
        .with_hint(
            "Nothing was opened or changed. Supply the new password with \
             --password-command, --password-file or DCTL_PASSWORD, or pass \
             --keep-password to prove the recovery phrase opens the vault \
             without changing anything.",
        ));
    }

    if ctx.is_dry_run() {
        // Neither the phrase nor the new password is requested: a dry run that
        // prompted for two secrets in order to do nothing with them would be a
        // worse rehearsal than none.
        ctx.dry_run_notice("recover with the recovery phrase", &target.to_string());
        if !args.keep_password {
            ctx.dry_run_notice("set a new password on", &target.to_string());
        }
        return Report::new(target.to_string(), false, false).emit(ctx);
    }

    // Resolved before the phrase is requested — the same ordering rule
    // `session::open` follows, and it matters more here than anywhere else in
    // the binary: this is the command that asks somebody to transcribe
    // twenty-four words off a sheet of paper, and reporting "unknown remote"
    // afterwards would spend that on a typo visible from the first instruction.
    // `Prepared` is what makes the ordering structural rather than remembered.
    let spec = target.spec();
    let prepared = session::open::prepare(ctx, &spec)?;

    // And the same ordering rule for the same reason, one step further: whether
    // there is a vault at this location at all is answerable without any secret,
    // so it is answered first. Asking for twenty-four transcribed words and then
    // reporting "wrong password or corrupted envelope" — which is what a plain
    // remote used to get — is the single most expensive wrong diagnosis this
    // binary can produce.
    prepared
        .require_vault(ctx, &spec, Some(NOT_A_VAULT))
        .await?;

    let phrase = session::phrase::acquire_required(&ctx.globals)?;
    ctx.out.info(format!(
        "recovery phrase read from {}",
        phrase.source().describe()
    ));

    let session = prepared
        .unlock(&spec, UnlockKey::RecoveryPhrase(phrase.expose()))
        .await?;
    ctx.out
        .success(format!("the recovery phrase opened '{target}'"));

    if args.keep_password {
        // The drill. Say what was *not* done, because "it worked" on its own
        // reads as "and the vault is now as I left it" whether or not it is.
        ctx.out
            .info("--keep-password: the vault's password was left unchanged");
        return Report::new(target.to_string(), true, false).emit(ctx);
    }

    // The replacement slot is written at this build's shipped cost, so the
    // disclosure `dctl init` makes belongs here too: a recovery performed with a
    // reduced-cost build leaves the vault with a cheap password slot beside its
    // original, correctly-costed ones, and nothing afterwards looks wrong.
    crate::session::kdf_cost::warn_if_reduced(ctx);

    // Read after the unlock succeeded. Asking somebody to choose and confirm a
    // new password and *then* telling them their phrase did not work is a
    // cruelty with no upside — the phrase is the thing that might fail here.
    let password = new_password::acquire_new(&ctx.globals)?;
    ctx.out.info(format!(
        "new password read from {}",
        password.source().describe()
    ));

    let changed = session
        .vault
        .change_password(password.expose())
        .await
        .map_err(CliError::from);

    // Recorded either way, and the failure is the more interesting record: a
    // recovery that was attempted and did not complete is exactly the event an
    // operator reconstructs a timeline from months later. No path, because it is
    // the vault's key material rather than any file that was rewritten.
    ctx.audit
        .record(&AuditEntry::new(VERB, sink::outcome(&changed)).remote(&remote))?;
    changed?;

    tracing::info!(remote = %remote, "vault password replaced after phrase recovery");
    ctx.out.success(format!(
        "'{target}' now has a new password; {PHRASE_STILL_WORKS}"
    ));
    Report::new(target.to_string(), true, true).emit(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use crate::exit::ExitCode;
    use clap::Parser;

    fn parse(args: &[&str]) -> (Ctx, RecoverArgs) {
        let cli = Cli::try_parse_from(std::iter::once("dctl").chain(args.iter().copied()))
            .expect("arguments should parse");
        let Command::Vault(vault) = cli.command else {
            panic!("expected the vault subcommand");
        };
        let super::super::Action::Recover(recover) = vault.action;
        (Ctx::new(cli.globals), recover)
    }

    #[test]
    fn a_target_is_required() {
        assert!(Cli::try_parse_from(["dctl", "vault", "recover"]).is_err());
    }

    #[tokio::test]
    async fn a_local_target_is_a_usage_error() {
        let (ctx, args) = parse(&["vault", "recover", "./photos"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains(VERB), "{}", error.message());
    }

    #[tokio::test]
    async fn a_path_inside_a_vault_is_refused_rather_than_widened() {
        let (ctx, args) = parse(&["vault", "recover", "archive:photos"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some(), "a refusal must say what to type");
    }

    #[tokio::test]
    async fn a_second_factor_is_refused_before_any_secret_is_requested() {
        // Same rule as every other unlock: a factor this build cannot mix into
        // the KEK is refused, never silently dropped. Checked before the target,
        // so the more serious of two problems is the one reported.
        let (ctx, args) = parse(&[
            "vault",
            "recover",
            "./not-a-remote",
            "--key-file",
            "/dev/null",
        ]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains("--key-file"),
            "{}",
            error.message()
        );
    }

    #[tokio::test]
    async fn a_dry_run_asks_for_no_secret_and_claims_nothing() {
        // No phrase and no password are supplied: a dry run that reached either
        // acquisition would fail or block, so returning Ok is the assertion.
        let (ctx, args) = parse(&["vault", "recover", "archive:", "--dry-run"]);
        assert!(ctx.is_dry_run());
        run(&ctx, &args)
            .await
            .expect("a dry run promises a report and delivers exactly that");
    }

    #[tokio::test]
    async fn an_unresolvable_remote_fails_rather_than_reporting_a_recovery() {
        let (ctx, args) = parse(&[
            "vault",
            "recover",
            "nosuchremote:",
            "--no-ask-password",
            "--recovery-phrase",
            PHRASE,
            "--password",
            "a new password entirely",
        ]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("nosuchremote"));
    }

    #[tokio::test]
    async fn an_unresolvable_remote_is_reported_before_the_phrase_is_asked_for() {
        // The ordering that matters most in this command. No phrase source is
        // given and prompting is not forbidden, so a run that reached the
        // acquisition would block on a terminal prompt or fail as
        // `VaultLocked`; seeing the *remote* error proves the resolution
        // happened first. Transcribing twenty-four words and then being told
        // the remote was misspelled is the one avoidable cruelty here.
        let (ctx, args) = parse(&[
            "vault",
            "recover",
            "nosuchremote:",
            "--password",
            "a new password entirely",
        ]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains("nosuchremote"),
            "{}",
            error.message()
        );
    }

    #[tokio::test]
    async fn a_missing_phrase_is_reported_as_the_missing_secret() {
        // Needs a *resolvable* vault, because the remote is now resolved before
        // the phrase is asked for — pointing this at an unconfigured name would
        // assert the remote error and quietly stop testing the phrase at all.
        let fixture = a_real_vault().await;
        let (ctx, args) = fixture.command(&["--no-ask-password", "--password", "a new password"]);

        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::VaultLocked);
        assert!(
            error.message().contains("recovery phrase"),
            "the refusal must name the secret that was missing: {}",
            error.message()
        );
    }

    #[tokio::test]
    async fn an_unattended_run_with_no_new_password_refuses_before_asking_for_the_phrase() {
        // Transcribing twenty-four words is the most expensive thing this
        // command asks for. Accepting them, opening the vault, and only then
        // reporting that the new password cannot be read would spend that
        // effort to change nothing — and `--no-ask-password` is visible from
        // the moment the command starts.
        let (ctx, args) = parse(&["vault", "recover", "archive:", "--no-ask-password"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        let hint = error.hint().unwrap_or_default();
        assert!(
            hint.contains("--keep-password"),
            "an unattended run that only wanted to check the phrase must be \
             told the flag that does exactly that: {hint}"
        );
        assert!(
            hint.contains("Nothing was opened"),
            "and what did not happen: {hint}"
        );
    }

    #[tokio::test]
    async fn the_drill_is_not_blocked_by_no_ask_password() {
        // `--keep-password` needs no new password, so the preflight must not
        // refuse the one shape an unattended restore drill actually uses. It
        // gets as far as the phrase, which is the next thing missing.
        let fixture = a_real_vault().await;
        let (ctx, args) = fixture.command(&["--no-ask-password", "--keep-password"]);

        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::VaultLocked);
        assert!(error.message().contains("recovery phrase"));
    }

    #[tokio::test]
    async fn the_phrase_this_vault_was_created_with_opens_it_and_leaves_the_password_alone() {
        // The drill, all the way through, at the level where the phrase that
        // `Vault::init` actually issued is available — the end-to-end suite has
        // to scrape it off stderr, so this is the one place the two are known
        // to be the same words.
        let fixture = a_real_vault().await;
        let (ctx, args) = fixture.command(&[
            "--no-ask-password",
            "--keep-password",
            "--recovery-phrase",
            &fixture.phrase,
        ]);

        run(&ctx, &args).await.expect("the phrase must open it");

        // And the vault still opens under the password it was created with.
        let backend: std::sync::Arc<dyn dctl_store::Backend> =
            std::sync::Arc::new(dctl_store::LocalFs::new(&fixture.store));
        dctl_core::Vault::unlock(
            backend,
            &fixture.index,
            UnlockKey::Password(FIXTURE_PASSWORD),
        )
        .await
        .expect("--keep-password must leave the password in force");
    }

    /// The password every fixture vault is created with.
    const FIXTURE_PASSWORD: &str = "correct horse battery staple";

    /// A real vault on a local store, addressable as `archive:`.
    struct Fixture {
        _dir: tempfile::TempDir,
        store: std::path::PathBuf,
        index: std::path::PathBuf,
        config: String,
        index_arg: String,
        phrase: String,
    }

    impl Fixture {
        /// A parsed `dctl vault recover archive:` wired to this fixture.
        fn command(&self, extra: &[&str]) -> (Ctx, RecoverArgs) {
            let mut argv = vec![
                "vault",
                "recover",
                "archive:",
                "--config",
                &self.config,
                "--index",
                &self.index_arg,
            ];
            argv.extend_from_slice(extra);
            parse(&argv)
        }
    }

    /// Create a vault through the engine, and a configuration naming it.
    ///
    /// Built rather than mocked because the question every test above asks is
    /// about *ordering* against a remote that really resolves; a fixture that
    /// only pretended to be addressable would let the resolution step silently
    /// stop happening.
    async fn a_real_vault() -> Fixture {
        let dir = tempfile::TempDir::new().expect("a temporary directory");
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).expect("the store directory");
        let index = dir.path().join("index.redb");

        let backend: std::sync::Arc<dyn dctl_store::Backend> =
            std::sync::Arc::new(dctl_store::LocalFs::new(&store));
        let created = dctl_core::Vault::init(backend, &index, FIXTURE_PASSWORD)
            .await
            .expect("a fresh vault initialises");
        let phrase = created.recovery_phrase.to_string();
        drop(created);

        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[remotes.store]\ntype = \"local\"\npath = {:?}\nrequire_vault = true\n\n\
                 [remotes.archive]\ntype = \"vault\"\nbase = \"store\"\n",
                store.to_string_lossy()
            ),
        )
        .expect("write the configuration");

        Fixture {
            config: config.to_string_lossy().into_owned(),
            index_arg: index.to_string_lossy().into_owned(),
            store,
            index,
            phrase,
            _dir: dir,
        }
    }

    #[test]
    fn the_success_message_says_the_phrase_survives() {
        // Somebody who has just set a new password has every reason to assume
        // the words that got them here are spent, and to throw the paper away.
        assert!(PHRASE_STILL_WORKS.contains("still opens"));
        assert!(PHRASE_STILL_WORKS.contains("keep the paper"));
    }

    #[test]
    fn keep_password_is_opt_in() {
        let (_, args) = parse(&["vault", "recover", "archive:"]);
        assert!(!args.keep_password);
        let (_, drill) = parse(&["vault", "recover", "archive:", "--keep-password"]);
        assert!(drill.keep_password);
    }

    /// The BIP-39 specification's own 24-word test vector. Guards no data.
    const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank \
                          year wave sausage worth useful legal winner thank year wave sausage \
                          worth title";
}
