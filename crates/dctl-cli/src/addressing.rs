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
//! 4. Encryption behaviour is a function of the **remote name typed**, never of
//!    the destination's current contents.
//!
//! The fourth is the enterprise invariant and the reason this module exists. A
//! command's encryption semantics must be fixed for as long as the command line
//! and the configuration are unchanged — independent of whether a directory
//! happens to hold an envelope this afternoon. There is therefore **no
//! auto-detection anywhere**: nothing here ever promotes a plain write into a
//! sealed one, and a destination that belongs to a vault is refused with the
//! name of the remote that addresses it, so the operator makes the choice.
//!
//! ## Three answers, in the order they are asked
//!
//! 1. **The configuration claims the destination.** A store remote declares its
//!    location vault-only ([`crate::config::VaultNamespace`]), so the refusal can
//!    name both views: which remote to type to store data sealed, and which one
//!    already addresses the objects.
//! 2. **The filesystem holds a vault the configuration knows nothing about.** The
//!    fallback, and only the fallback — for a location no section describes,
//!    there is no name to offer, so the message says exactly that rather than
//!    guessing. This is where an imported or hand-moved vault lands.
//! 3. **Otherwise it is an ordinary place**, and a plaintext write is a
//!    first-class supported operation (invariant 3).
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

/// Refuse a plaintext write to a local path that belongs to a vault.
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
    if let Some(vault) = crate::session::store::enclosing_vault(destination) {
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
