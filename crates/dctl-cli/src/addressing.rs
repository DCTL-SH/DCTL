//! Where bytes may land, and what happens to them on the way.
//!
//! rclone fuses those two questions: a `crypt` remote is both a location and a
//! transformation, so what a command encrypts depends on how the destination was
//! wrapped. DCTL cannot fuse them, because `PLAN.md` §13.3 requires replicating a
//! vault's object tree provider-to-provider **with no re-encryption** — which is
//! only expressible if the ciphertext objects have an address of their own.
//!
//! So `dctl init` registers two remotes for one vault: `archive:` is the sealed
//! view, `archive-store:` is the object view. Four invariants follow, and this
//! module enforces the ones that are about *addressing*:
//!
//! 1. A write through a vault remote is always sealed. No flag disables it.
//! 2. Foreign plaintext is never written into a vault's object store. Refused.
//! 3. A write to an ordinary location is plaintext, and that is fully supported.
//! 4. **DCTL never applies or omits encryption because of a destination's
//!    contents.** What a command encrypts is determined solely by the remote
//!    name typed. A destination's contents may cause DCTL to REFUSE, never to
//!    change what it does.
//!
//! ## I4, stated precisely, and why the precise form is the stronger one
//!
//! The outcome space for any destination is exactly `{sealed, plain, refused}`.
//! Contents can only ever move an outcome to `refused`. They can never turn
//! `plain` into `sealed` or `sealed` into `plain`.
//!
//! An earlier, looser wording said encryption behaviour "is a function of the
//! remote name typed, never of the destination's current contents" — full stop.
//! That is **false as written**, and it is worth saying so plainly rather than
//! leaving a comment nobody can verify. For a location no configured remote
//! describes, the third answer below *does* read the destination: it looks for a
//! vault envelope and refuses if it finds one. Contents are consulted there, so
//! the loose claim cannot hold.
//!
//! The precise claim covers that case and says something stronger. It does not
//! merely assert that the decision usually ignores contents; it bounds what
//! contents are *permitted to do* — they may stop a command, and nothing else.
//! An operator can therefore reason about a runbook the way they need to: the
//! command either does exactly what its remote names say, or it does nothing at
//! all and says why. It never quietly does the other thing.
//!
//! This is also the reason the fallback is not auto-detection, a distinction
//! that decides whether the design is sound. **Auto-detection changes
//! behaviour** — it would see an envelope and seal a write the user asked to be
//! plain, delivering something other than what was asked for on the basis of
//! state that was never named. **This only ever stops.** A refusal cannot
//! silently produce the wrong artefact, and it leaves the operator holding the
//! choice, which is where the choice belongs.
//!
//! `crates/dctl-cli/tests/invariant_i4/` proves all of this against the shipped
//! binary and the bytes on disk rather than restating it, because an invariant
//! asserted only in prose is an invariant nobody has checked. Every claim in
//! this comment has a test whose name is the claim.
//!
//! ## Three answers, in the order they are asked
//!
//! 1. **The configuration claims the destination.** A store remote declares its
//!    location vault-only ([`crate::config::VaultNamespace`]), so the refusal can
//!    name both views: which remote to type to store data sealed, and which one
//!    already addresses the objects. No filesystem contents are consulted, which
//!    is why a configured store answers identically whether or not an envelope
//!    is present.
//! 2. **The filesystem holds a vault the configuration knows nothing about.** The
//!    fallback, and the only place contents are read at all — for a location no
//!    section describes, there is no name to offer, so the message says exactly
//!    that rather than guessing. This is where an imported or hand-moved vault
//!    lands. Its only possible outcome is a refusal naming `dctl config import`.
//! 3. **Otherwise it is an ordinary place**, and a plaintext write is a
//!    first-class supported operation (invariant 3).
//!
//! ## Spelling is not contents, and is handled before either
//!
//! `vault`, `./vault`, `/srv/vault`, `staging/../vault` and a symlink to it are
//! one directory. An operator who reaches it by a different route has not asked
//! for different encryption behaviour, so both answers above resolve the paths
//! they compare ([`crate::platform::resolve`]) instead of comparing strings. The
//! gap that closes was real and severe: `dctl copy ./src staging/../vault` used
//! to miss the configured claim, fall through, miss the envelope check too — the
//! stat fails on a path whose intermediate component does not exist — and write
//! plaintext into a configured vault's object store, reporting success.
//!
//! ## Why every write path calls this
//!
//! The check used to live inside the transfer engine, where only `copy`, `move`
//! and `sync` could reach it — and `dctl rcat`, which writes to a local path by a
//! completely different route, streamed plaintext straight into a vault directory
//! and exited 0. A guard that protects one of several write paths is not a guard;
//! it is a false sense of one.

use std::path::Path;

use crate::config::{self, Config, VaultNamespace};
use crate::constants::PLAIN_WRITE_INTO_VAULT_HINT;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::remote::RemoteSpec;

/// Refuse a plaintext write to whatever `destination` addresses.
///
/// The single entry point for a caller that holds a parsed destination, which
/// every transfer verb does. Written once here rather than as a `match` at each
/// call site: the two arms answer the *same* question about two spellings of an
/// address, and a call site that grew a third arm — or forgot one — would be a
/// write path with no rule applied to it. That is not hypothetical. The check
/// lived inside the transfer engine, `dctl rcat` reached the filesystem by
/// another route, and plaintext streamed into a vault directory and exited 0.
///
/// # Errors
/// Whatever [`refuse_plain_write_to_path`] or [`refuse_plain_write_to_remote`]
/// raises for the arm that applies.
pub fn refuse_plain_write(ctx: &Ctx, destination: &RemoteSpec) -> Result<()> {
    match destination {
        RemoteSpec::Named { remote, .. } => refuse_plain_write_to_remote(ctx, remote),
        RemoteSpec::Local(path) => refuse_plain_write_to_path(ctx, path),
    }
}

/// Refuse a plaintext write to a local path that belongs to a vault.
///
/// The only two things this can do are return `Ok` — leaving the caller's
/// plaintext write exactly as the caller asked for it — and return an error.
/// There is deliberately no third return that would tell a caller to seal
/// instead: the type is how I4 is enforced, not a convention this function
/// follows.
///
/// An empty path is the destination of a direction that has no local side, and
/// is answered without reading anything: it must not be stat'ed, and it must not
/// resolve to the process's working directory.
///
/// # Errors
/// [`ExitCode::FatalError`] when the configuration claims the location, or when
/// the location holds a vault envelope that no configured remote describes.
/// Propagates whatever [`config::load_or_default`] produces for an unreadable or
/// inconsistent configuration — a file that cannot be trusted is not a file this
/// decision may be made without.
pub fn refuse_plain_write_to_path(ctx: &Ctx, destination: &Path) -> Result<()> {
    if destination.as_os_str().is_empty() {
        return Ok(());
    }

    if let Some(claimed) = VaultNamespace::of_path(&load(ctx)?, destination) {
        return Err(refusal(&claimed));
    }

    // Only now, and only for a location the configuration does not describe.
    // The filesystem cannot say which remote addresses what it found, so this
    // branch names the directory and stops — it never infers a mode.
    //
    // Resolved first, for the same reason the configured claim is: an envelope
    // one directory above `staging/../vault` is evidence about the destination
    // however the operator spelled the route to it, and a `stat` of the
    // unresolved spelling simply fails to see it.
    let real = crate::platform::resolve::real_path(destination);
    let looked_at = real.as_deref().unwrap_or(destination);

    if let Some(vault) = crate::session::store::enclosing_vault(looked_at) {
        return Err(CliError::new(
            ExitCode::FatalError,
            format!(
                "refusing to write plaintext into '{}': it contains a vault \
                 that no configured remote describes",
                vault.display()
            ),
        )
        .with_hint(PLAIN_WRITE_INTO_VAULT_HINT));
    }

    Ok(())
}

/// Refuse a plaintext write addressed at a vault's object view.
///
/// `dctl copy ./photos archive-store:` is the mistake this catches: the store
/// holds one vault's opaque objects, and a foreign plaintext file among them is
/// both unencrypted and unreadable to the vault that owns the tree.
///
/// # Errors
/// [`ExitCode::FatalError`] when `remote` is a configured vault's object store,
/// plus anything [`config::load_or_default`] produces.
pub fn refuse_plain_write_to_remote(ctx: &Ctx, remote: &str) -> Result<()> {
    match VaultNamespace::of_remote(&load(ctx)?, remote) {
        Some(claimed) => Err(refusal(&claimed)),
        None => Ok(()),
    }
}

/// The configuration this invocation is governed by.
///
/// `load_or_default`, because a machine that has never run `dctl config` is a
/// supported machine (`PLAN.md` §14) and must not be told it is misconfigured —
/// it simply has no vault namespaces, and the filesystem fallback is all that
/// applies.
fn load(ctx: &Ctx) -> Result<Config> {
    let path = config::resolve_path(ctx.globals.config.as_deref());
    Ok(config::load_or_default(&path)?)
}

/// The refusal for a destination the configuration claims.
///
/// Names both views deliberately. "You may not write here" leaves an operator
/// with a job to finish and no way to finish it; naming the sealed view gives
/// them the command that does what they meant, and naming the object view gives
/// the backup operator the one that copies ciphertext without a password —
/// which is the separation of duties the two-remote model exists to make
/// structural.
fn refusal(claimed: &VaultNamespace) -> CliError {
    let subject = claimed.subject();
    let store = claimed.store();

    match claimed.vault() {
        Some(vault) => CliError::new(
            ExitCode::FatalError,
            format!("'{subject}' is the object store for remote '{vault}'"),
        )
        .with_hint(format!(
            "Use `{vault}:` to store data sealed — every write through it is \
             encrypted, and no flag turns that off. To copy the objects already \
             stored there exactly as they are, run `dctl replicate {store}: \
             DEST-STORE:`, which needs no vault password. DCTL will not switch \
             between the two on its own: what a command encrypts is decided by \
             the remote name typed."
        )),

        None => CliError::new(
            ExitCode::FatalError,
            format!("'{subject}' is the object store declared by remote '{store}'"),
        )
        .with_hint(format!(
            "No vault remote in this configuration wraps '{store}', so there is \
             no sealed view to write through. Run `dctl config import` to \
             register the vault that owns these objects, or choose a \
             destination that is not a vault's object store."
        )),
    }
}

/// The refusal for a plain READ of a store the configuration claims.
///
/// The read-side twin of [`refusal`], for the same structural reason: a store
/// declared `require_vault = true` holds a vault's opaque objects, and a plain
/// `ls` of it shows `n/<hash>` rows where the operator expected their files —
/// measured at 1,005 ciphertext keys served with exit 0 and no warning. The
/// honest outcomes are sealed, plain, or refused, and configuration may move
/// an outcome to refused but never change what a command does (the addressing
/// model above), so this refuses and names the view that answers the question
/// the operator actually asked.
pub fn plain_read_refusal(claimed: &VaultNamespace) -> CliError {
    let subject = claimed.subject();
    let store = claimed.store();

    match claimed.vault() {
        Some(vault) => CliError::new(
            ExitCode::FatalError,
            format!(
                "'{subject}' is the object store for remote '{vault}': a plain \
                 read of it shows ciphertext objects, not the files stored \
                 through the vault"
            ),
        )
        .with_hint(format!(
            "Use `{vault}:` for the decrypted namespace (`dctl ls {vault}:`). \
             To work with the raw objects themselves — replication, object \
             counts — run `dctl replicate {store}: DEST-STORE:`, which needs \
             no vault password."
        )),

        None => CliError::new(
            ExitCode::FatalError,
            format!(
                "'{subject}' declares require_vault = true and holds a vault's \
                 opaque objects"
            ),
        )
        .with_hint(format!(
            "No vault remote in this configuration wraps '{store}'. Register \
             the sealed view with `dctl config create NAME vault base={store}` \
             (or `dctl config import` for a vault that already exists there), \
             then read through `NAME:`."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::config::{Config, LocalDef, RemoteDef, VaultDef};
    use clap::Parser;
    use std::path::PathBuf;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    /// A context pointed at a configuration written for this test.
    ///
    /// The directory is returned because dropping it deletes the file, which has
    /// to outlive the call under test.
    fn ctx_with(config: &Config) -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("config.toml");
        config::save(config, &path).expect("the fixture must save");
        (dir, ctx_at(&path))
    }

    /// A context whose configuration file does not exist.
    fn ctx_without_config() -> Ctx {
        ctx_at(&config::absent_path())
    }

    fn ctx_at(path: &Path) -> Ctx {
        let argv = [
            "dctl".to_string(),
            "--quiet".to_string(),
            "--config".to_string(),
            path.to_string_lossy().into_owned(),
        ];
        Ctx::new(Harness::parse_from(argv).globals)
    }

    /// The pair `dctl init` writes, for a store at `path`.
    fn initialised(path: &Path) -> Config {
        let mut config = Config::default();
        config.insert(
            "archive-store",
            RemoteDef::Local(LocalDef {
                path: path.to_path_buf(),
                verify: None,
                require_vault: true,
            }),
        );
        config.insert(
            "archive",
            RemoteDef::Vault(VaultDef {
                base: "archive-store".into(),
                base_path: None,
                chunk_size: None,
                verify: None,
            }),
        );
        config
    }

    #[test]
    fn a_configured_store_is_refused_by_name_with_nothing_on_disk() {
        // Invariant I4 in one assertion: the store directory is empty — no
        // envelope, no objects — and the refusal still fires, because the answer
        // comes from the configuration rather than from what is there.
        let store = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with(&initialised(store.path()));

        let error = refuse_plain_write_to_path(&ctx, store.path()).expect_err("must be refused");
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains("object store"),
            "got: {}",
            error.message()
        );
        assert!(
            error.message().contains("archive"),
            "the refusal must name the remote to use: {}",
            error.message()
        );
        let hint = error.hint().unwrap_or_default();
        assert!(hint.contains("archive:"), "got hint: {hint}");
        assert!(
            hint.contains("archive-store:"),
            "the object view is how ciphertext is replicated: {hint}"
        );
    }

    #[test]
    fn a_subdirectory_of_a_configured_store_is_refused_too() {
        // `vault/photos` is the bypass an exact-path rule leaves open.
        let store = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with(&initialised(store.path()));

        let error = refuse_plain_write_to_path(&ctx, &store.path().join("photos"))
            .expect_err("must be refused");
        assert!(
            error
                .message()
                .contains(&store.path().display().to_string()),
            "the configured root is what the operator needs named: {}",
            error.message()
        );
    }

    #[test]
    fn the_object_view_is_refused_when_addressed_by_name() {
        let store = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with(&initialised(store.path()));

        let error =
            refuse_plain_write_to_remote(&ctx, "archive-store").expect_err("must be refused");
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("archive-store"));
        assert!(error.hint().is_some_and(|hint| hint.contains("archive:")));
    }

    #[test]
    fn the_sealed_view_is_never_refused() {
        // Invariant I1: everything through `archive:` is encrypted, so the write
        // must reach the vault rather than be stopped here.
        let store = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with(&initialised(store.path()));
        assert!(refuse_plain_write_to_remote(&ctx, "archive").is_ok());
    }

    #[test]
    fn an_ordinary_destination_is_a_first_class_plaintext_write() {
        // Invariant I3. The rule must cost nothing to the ordinary case.
        let store = tempfile::tempdir().expect("a temporary directory");
        let elsewhere = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with(&initialised(store.path()));

        assert!(refuse_plain_write_to_path(&ctx, elsewhere.path()).is_ok());
        assert!(refuse_plain_write_to_remote(&ctx, "b2prod").is_ok());
    }

    #[test]
    fn a_vault_the_configuration_does_not_know_is_refused_and_says_so() {
        // The fallback. There is no remote to name, so the message must not
        // pretend there is — and it must never quietly seal the write instead.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let envelope = dir.path().join("system").join("envelope.bin");
        std::fs::create_dir_all(envelope.parent().unwrap_or(dir.path())).expect("system dir");
        std::fs::write(&envelope, b"DKE1").expect("envelope");

        let ctx = ctx_without_config();
        let error = refuse_plain_write_to_path(&ctx, dir.path()).expect_err("must be refused");
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains("plaintext"),
            "the refusal must name the risk: {}",
            error.message()
        );
        assert!(
            error.message().contains("no configured remote"),
            "the message must say why no remote is named: {}",
            error.message()
        );
        assert!(
            error
                .hint()
                .is_some_and(|hint| hint.contains("vault remote"))
        );
    }

    #[test]
    fn an_empty_destination_reads_nothing_and_refuses_nothing() {
        let ctx = ctx_without_config();
        assert!(refuse_plain_write_to_path(&ctx, Path::new("")).is_ok());
    }

    #[test]
    fn the_configuration_answers_before_the_filesystem_does() {
        // Both signals present. The message must be the config-derived one,
        // because it is the only one that can name the remote to type — and
        // because the ordering is what makes the rule independent of state.
        let store = tempfile::tempdir().expect("a temporary directory");
        let envelope = store.path().join("system").join("envelope.bin");
        std::fs::create_dir_all(envelope.parent().unwrap_or(store.path())).expect("system dir");
        std::fs::write(&envelope, b"DKE1").expect("envelope");

        let (_dir, ctx) = ctx_with(&initialised(store.path()));
        let error = refuse_plain_write_to_path(&ctx, store.path()).expect_err("must be refused");
        assert!(
            error
                .message()
                .contains("object store for remote 'archive'"),
            "got: {}",
            error.message()
        );
    }

    #[test]
    fn a_store_no_vault_remote_wraps_does_not_invent_one() {
        // Hand-edited configuration: the flag without the pair. Sending the user
        // to type a remote that does not exist would be worse than the refusal.
        let store = tempfile::tempdir().expect("a temporary directory");
        let mut config = Config::default();
        config.insert(
            "orphan-store",
            RemoteDef::Local(LocalDef {
                path: store.path().to_path_buf(),
                verify: None,
                require_vault: true,
            }),
        );
        let (_dir, ctx) = ctx_with(&config);

        let error = refuse_plain_write_to_path(&ctx, store.path()).expect_err("must be refused");
        assert!(error.message().contains("orphan-store"));
        assert!(
            error
                .hint()
                .is_some_and(|hint| hint.contains("config import"))
        );
    }

    #[test]
    fn an_unreadable_configuration_stops_the_write_rather_than_guessing() {
        // A file that cannot be parsed cannot be shown not to describe a vault
        // store, and continuing would be deciding the encryption question by
        // accident.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[remotes.broken\n").expect("write");
        let ctx = ctx_at(&path);

        assert!(refuse_plain_write_to_path(&ctx, &PathBuf::from("/srv/anywhere")).is_err());
    }
}
