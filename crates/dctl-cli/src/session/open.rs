//! Building an unlocked vault from what the user typed.

use std::path::PathBuf;
use std::sync::Arc;

use dctl_core::{UnlockKey, Vault};
use dctl_store::Backend;

use crate::ctx::Ctx;
use crate::error::Result;
use crate::logging::fields;
use crate::remote::RemoteSpec;

use super::{factor, index, secret};

/// What the user is told did not happen when `--key-file` is refused here.
///
/// Unlocking is the step every read and every write is built on, so "the vault
/// was not opened" is the complete account of the run's effects — nothing was
/// listed, transferred or written. Saying so explicitly stops the reader from
/// wondering whether a partial transfer needs cleaning up.
const NOTHING_HAPPENED: &str = "The vault was not opened and no data was read or written.";

/// An unlocked vault plus the context needed to describe it in messages.
pub struct Session {
    /// The unlocked vault.
    pub vault: Vault,
    /// The remote spec as resolved, for messages and audit records.
    pub remote: String,
    /// The index database backing this session.
    pub index: PathBuf,
}

impl std::fmt::Debug for Session {
    /// Written by hand, and deliberately omitting the vault.
    ///
    /// An unlocked [`Vault`] holds the root key and every derived sub-key. A
    /// derived `Debug` would put that reach one `{:?}` away from any struct that
    /// ever contains a `Session` — including a panic message or a `tracing`
    /// field, neither of which is reviewed as carefully as this line is.
    /// `PLAN.md` §7 makes redaction mandatory; the cheapest way to honour it is
    /// to make the unsafe rendering impossible to write by accident.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("remote", &self.remote)
            .field("index", &self.index)
            .field("vault", &crate::logging::redact::REDACTED)
            .finish()
    }
}

/// Open the vault addressed by `spec`.
///
/// Takes the **whole parsed spec**, never the remote's name on its own, and that
/// is the entire reason for the signature. A bare name is indistinguishable from
/// a relative directory — `RemoteSpec::parse("b2")` finds no colon and answers
/// `Local("b2")` — so a caller that passed one had its remote silently
/// reinterpreted as a filesystem path: `dctl copy ./src b2:mybucket` unlocked a
/// vault in `./b2`, discarded the bucket entirely, and reported a clean success.
/// A [`RemoteSpec`] has already decided which of the two it is, and cannot be
/// re-decided here.
///
/// # Errors
/// Propagates the typed failure of whichever step failed: a `--key-file` this
/// build cannot apply or an unresolvable remote or unreadable config
/// ([`ExitCode::FatalError`]), a missing password ([`ExitCode::VaultLocked`]),
/// or an envelope that will not unwrap ([`ExitCode::VaultLocked`], via
/// [`dctl_core::CoreError::Unlock`]).
///
/// [`ExitCode::FatalError`]: crate::exit::ExitCode::FatalError
/// [`ExitCode::VaultLocked`]: crate::exit::ExitCode::VaultLocked
pub async fn open(ctx: &Ctx, spec: &RemoteSpec) -> Result<Session> {
    let prepared = prepare(ctx, spec)?;

    // Acquired after the preparation so a typo in the remote name fails before
    // the user is asked for a secret. Being prompted for a password and *then*
    // told the remote does not exist is a small cruelty that is easy to avoid.
    //
    // Which secret — password or recovery phrase — is [`super::secret`]'s single
    // decision, so every command that opens a vault accepts a phrase without
    // knowing that phrases exist. That is what makes a second key worth having:
    // it has to open `ls`, `cat`, `copy` and `restore`, not just a command named
    // after recovery.
    let secret = secret::acquire(&ctx.globals)?;
    ctx.out.info(secret.describe());
    tracing::debug!(recovery = secret.is_recovery(), "unlock secret resolved");

    prepared.unlock(spec, secret.key()).await
}

/// Everything an unlock needs except the secret.
///
/// The type exists to make one ordering rule structural instead of remembered:
/// **nothing that can fail on its own may be left until after a secret has been
/// asked for.** A caller has to hold one of these before it can unlock, and
/// obtaining one has already refused an inapplicable `--key-file`, resolved the
/// index, followed the vault chain and built the backend.
///
/// That ordering costs nothing on the password path and matters a great deal on
/// the recovery path: `dctl vault recover` asks somebody to transcribe
/// twenty-four words off a sheet of paper, and reporting *"unknown remote"*
/// afterwards would spend the most expensive thing the tool ever asks for on a
/// typo that was visible from the first instruction.
pub struct Prepared {
    backend: Arc<dyn Backend>,
    index: PathBuf,
}

/// Do everything an unlock needs doing before a secret is worth asking for.
///
/// Takes the **whole parsed spec**, never the remote's name on its own, and that
/// is the entire reason for the signature. A bare name is indistinguishable from
/// a relative directory — `RemoteSpec::parse("b2")` finds no colon and answers
/// `Local("b2")` — so a caller that passed one had its remote silently
/// reinterpreted as a filesystem path: `dctl copy ./src b2:mybucket` unlocked a
/// vault in `./b2`, discarded the bucket entirely, and reported a clean success.
/// A [`RemoteSpec`] has already decided which of the two it is, and cannot be
/// re-decided here.
///
/// # Errors
/// [`ExitCode::FatalError`] for a `--key-file` this build cannot apply, an
/// unresolvable remote, or an unreadable configuration. Plus whatever creating
/// the index's directory reported ([`super::index::ensure_directory`]) — a
/// read-only home or a permission the user does not have, surfaced here rather
/// than after they have been asked for a secret.
///
/// [`ExitCode::FatalError`]: crate::exit::ExitCode::FatalError
pub fn prepare(ctx: &Ctx, spec: &RemoteSpec) -> Result<Prepared> {
    // First, ahead of even the remote: a second factor this build cannot mix
    // into the KEK is refused rather than dropped, because unlocking with the
    // password alone would give the caller weaker protection than they asked
    // for while exiting 0. See `super::factor` for the full reasoning. It is
    // checked before the remote so the more serious of two problems is the one
    // reported — a misspelled remote is a typo, a discarded factor is not.
    factor::refuse_if_present(&ctx.globals, "unlocking a vault", NOTHING_HAPPENED)?;

    let backend = build_backend(ctx, spec)?;

    // After the remote has resolved, so a typo does not leave a directory
    // behind, and before the secret is acquired, which is this module's ordering
    // rule: an index directory that cannot be created is a failure that has
    // nothing to do with the password, and asking for one first — or for
    // twenty-four transcribed words — spends the most expensive thing the tool
    // ever asks for on a problem that was visible without it.
    let index = index::path(ctx);
    index::ensure_directory(&index)?;

    Ok(Prepared { backend, index })
}

impl Prepared {
    /// Unwrap the root key with `key` and hand back a [`Session`].
    ///
    /// Consumes `self`, so the backend is built exactly once per invocation:
    /// two constructions of "the backend for this spec" are two chances for
    /// them to disagree.
    ///
    /// # Errors
    /// [`ExitCode::VaultLocked`] when the envelope is missing, unparseable, or
    /// holds no slot this secret opens (via [`dctl_core::CoreError::Unlock`]).
    ///
    /// [`ExitCode::VaultLocked`]: crate::exit::ExitCode::VaultLocked
    pub async fn unlock(self, spec: &RemoteSpec, key: UnlockKey<'_>) -> Result<Session> {
        let vault = Vault::unlock(self.backend, &self.index, key).await?;

        tracing::debug!(
            { fields::REMOTE } = %spec,
            index = %self.index.display(),
            "vault unlocked"
        );

        Ok(Session {
            vault,
            remote: spec.to_string(),
            index: self.index,
        })
    }
}

/// Build the storage backend a vault's objects actually live in.
///
/// Two resolutions, not one, and the second is the one that was missing.
///
/// A vault remote **stores nothing itself** — it is a wrapper that seals on the
/// way through to a base store, which is why the registry refuses to build one
/// directly. Handing it `archive:` therefore failed with *"remote 'archive' is a
/// vault wrapper, which stores nothing itself"*, and the sealed view — the whole
/// point of a vault remote — was unreachable. So when the spec names a vault,
/// this follows [`config::vault_chain`] to the remote at the end of the chain and
/// builds *that*, which is the object store the ciphertext belongs in.
///
/// The catalog is the user's real configuration. It used to be `&()` — the empty
/// catalog knowing only the `local:`/`b2:`/`s3:`/`r2:` shorthands — and a comment
/// here argued that made "every command agree about which remotes exist". They
/// did agree: that none did. DCTL would refuse a plain write, name `archive:` as
/// the remedy, then reject `archive:` as unknown. A tool whose own suggested fix
/// does not work is worse than one that just refuses.
///
/// A missing config is not fatal: `load_or_default` yields an empty one, which
/// is the headless case `PLAN.md` §14 requires to keep working from environment
/// variables alone.
fn build_backend(ctx: &Ctx, spec: &RemoteSpec) -> Result<Arc<dyn Backend>> {
    let path = crate::config::resolve_path(ctx.globals.config.as_deref());
    let config = crate::config::load_or_default(&path)?;

    let storage = storage_remote(&config, spec)?;
    let resolved = crate::remote::resolve::resolve(&storage, &config)?;
    crate::remote::registry::build(&resolved)
}

/// The spec whose backend actually holds bytes.
///
/// For anything but a vault remote this is the spec unchanged. For a vault it is
/// the far end of the chain, so `archive:` becomes `archive-store:`.
fn storage_remote(config: &crate::config::Config, spec: &RemoteSpec) -> Result<RemoteSpec> {
    let RemoteSpec::Named { remote, path } = spec else {
        return Ok(spec.clone());
    };

    // Not configured at all: leave it alone so the provider shorthands
    // (`b2:bucket`) and the "unknown remote" diagnosis both still work.
    if !config.contains(remote) {
        return Ok(spec.clone());
    }

    // Walking the chain is also what detects a cycle or a dangling base, so a
    // broken configuration is diagnosed here rather than producing a confident
    // wrong backend.
    let chain = crate::config::vault_chain(config, remote)?;
    let storage = chain.last().copied().unwrap_or(remote.as_str());

    if storage == remote.as_str() {
        return Ok(spec.clone());
    }

    Ok(RemoteSpec::Named {
        remote: storage.to_string(),
        path: path.clone(),
    })
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

    fn spec(input: &str) -> RemoteSpec {
        RemoteSpec::parse(input).expect("a well-formed spec")
    }

    #[tokio::test]
    async fn a_second_factor_is_refused_rather_than_silently_dropped() {
        // The regression this guards: `--key-file` was accepted and never read,
        // so a vault the user believed was two-factor was unlocked by the
        // password alone. Weaker protection than was asked for, reported as
        // success, is the failure `PLAN.md` §6 forbids.
        let ctx = ctx(&["--key-file", "/dev/null", "--no-ask-password"]);
        let error = open(&ctx, &spec("local:/srv/v")).await.unwrap_err();
        assert_eq!(error.code(), crate::exit::ExitCode::FatalError);
        assert!(
            error.message().contains("--key-file"),
            "the message must name the flag that was refused: {}",
            error.message()
        );
    }

    #[tokio::test]
    async fn the_second_factor_is_refused_before_any_other_step() {
        // Both the remote and the password are unusable here. Whichever check
        // runs first decides the exit code, and it must be the factor: telling
        // someone their remote is misspelled while quietly dropping a security
        // factor buries the more serious of the two problems.
        let ctx = ctx(&["--key-file", "/dev/null", "--no-ask-password"]);
        let error = open(&ctx, &spec("nosuchscheme:bucket")).await.unwrap_err();
        assert_eq!(error.code(), crate::exit::ExitCode::FatalError);
        assert!(
            error.message().contains("--key-file"),
            "{}",
            error.message()
        );
    }

    #[tokio::test]
    async fn an_unknown_remote_fails_before_asking_for_a_password() {
        // --no-ask-password would turn a prompt into a VaultLocked error, so if
        // the remote were resolved second we would see that code instead. Seeing
        // the backend error proves the ordering.
        let ctx = ctx(&["--no-ask-password"]);
        let error = open(&ctx, &spec("nosuchscheme:bucket")).await.unwrap_err();
        assert_ne!(
            error.code(),
            crate::exit::ExitCode::VaultLocked,
            "the remote must be rejected before a password is requested"
        );
    }

    #[tokio::test]
    async fn an_unknown_remote_is_named_rather_than_read_as_a_directory() {
        // S6. The old signature took the remote's *name*, which the backend
        // builder re-parsed — and a name has no colon, so it became a relative
        // path. `dctl copy ./src vault:photos` therefore wrote into a directory
        // called `vault`, discarded `photos`, and exited 0.
        //
        // A spec cannot be re-decided, so the resolver sees `Named` and says so.
        let ctx = ctx(&["--no-ask-password"]);
        let error = open(&ctx, &spec("vault:photos")).await.unwrap_err();
        assert_eq!(error.code(), crate::exit::ExitCode::FatalError);
        assert!(
            error.message().contains("unknown remote 'vault'"),
            "the refusal must name the remote: {}",
            error.message()
        );
    }

    #[tokio::test]
    async fn the_path_portion_of_a_spec_is_not_thrown_away() {
        // The bucket half of the same defect: only the name used to survive, so
        // `b2:mybucket` reached the registry as `b2` alone. The bucketless
        // diagnosis below can only be produced by a resolver that read the path,
        // and unlike a credential error it needs nothing exported to reach.
        let ctx = ctx(&["--no-ask-password"]);
        let error = open(&ctx, &spec("b2:")).await.unwrap_err();
        assert_eq!(error.code(), crate::exit::ExitCode::FatalError);
        assert!(
            error.message().contains("bucket"),
            "the spec's path portion must have been read: {}",
            error.message()
        );
    }
}
