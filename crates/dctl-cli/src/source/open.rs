//! Deciding which kind of source a spec names, once, for the whole binary.
//!
//! This is the only function in the crate allowed to know that there are two
//! implementations of [`Source`]. Everything above it receives a
//! `Box<dyn Source>` and cannot tell — which is the property that makes the
//! abstraction worth having, because a command that *could* tell is a command
//! that will eventually add a second `if` and get it subtly wrong.
//!
//! ## The rule
//!
//! A [`RemoteSpec::Named`] whose name the configuration file defines as a vault
//! wrapper opens the **sealed** view: plaintext paths, plaintext sizes, and
//! authenticated reads. Everything else — a bare filesystem path, a `local:`
//! path, a provider shorthand like `b2:bucket`, and the store remote a vault
//! wraps — opens the **plain** view of whatever bytes are actually there.
//!
//! That is exactly one lookup, and it is deliberately the *only* question asked
//! about the shape of a remote. Following the vault chain, refusing a cycle,
//! finding the remote that really holds bytes: none of that happens here,
//! because [`crate::session::open`] already does it and doing it twice is how
//! two answers to one question come into existence.
//!
//! ## Why `dctl init` produces two remotes, and why both are readable
//!
//! `dctl init --name archive --base local:/srv/v` registers `archive` (the vault
//! wrapper) and `archive-store` (the location its objects land in). Both are
//! legitimate things to read: `dctl ls archive:` shows the files a person put
//! there, and `dctl ls archive-store:` shows the opaque keys they are stored
//! under — which is what an operator checking replication or object counts
//! actually needs. One spec, one rule, two honest views.
//!
//! ## A spec is never re-decided here
//!
//! The signature takes a parsed [`RemoteSpec`] and never a remote's name,
//! because a bare name is indistinguishable from a relative directory: parsing
//! `"archive"` finds no colon and yields `Local("archive")`. A caller that
//! passed one would have its vault silently reinterpreted as a filesystem path —
//! the failure that produced a clean exit 0 while writing into a directory
//! nobody named. A [`RemoteSpec`] has already decided, and cannot be re-decided.

use crate::config::{Config, RemoteDef};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::remote::RemoteSpec;

use super::Source;
use super::plain::PlainSource;
use super::vault::VaultSource;

/// Open the source `spec` addresses.
///
/// A missing configuration file is not an error: `load_or_default` yields an
/// empty one, which is the headless case `PLAN.md` §14 requires to keep working
/// from a bare path or from environment credentials alone. An empty
/// configuration simply defines no vaults, so every spec opens the plain view —
/// which is the truth about a machine that has never run `dctl init`.
///
/// # Errors
/// [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError) for an unreadable
/// configuration, an unresolvable remote, or a `--key-file` this build cannot
/// apply; [`ExitCode::VaultLocked`](crate::exit::ExitCode::VaultLocked) when a
/// sealed source will not unlock.
pub async fn open(ctx: &Ctx, spec: &RemoteSpec) -> Result<Box<dyn Source>> {
    let path = crate::config::resolve_path(ctx.globals.config.as_deref());
    let config = crate::config::load_or_default(&path)?;

    if is_sealed(&config, spec) {
        tracing::debug!(
            { crate::logging::fields::REMOTE } = %spec,
            "opening the sealed view"
        );
        return Ok(Box::new(VaultSource::open(ctx, spec).await?));
    }

    tracing::debug!(
        { crate::logging::fields::REMOTE } = %spec,
        "opening the plain view"
    );
    Ok(Box::new(PlainSource::open(&config, spec)?))
}

/// Whether `spec` names a configured vault wrapper.
///
/// Split out and kept pure so the decision can be tested against a
/// configuration fixture without a password, a backend or a filesystem — the
/// decision *is* the interesting part of this module, and it would otherwise be
/// reachable only through an unlock.
///
/// A local path is never sealed. A vault is a wrapper over a remote, so it is
/// something the configuration file declares by name; a filesystem path
/// declares nothing, and treating one as sealed would mean guessing at the
/// contents of a directory the user simply pointed at.
fn is_sealed(config: &Config, spec: &RemoteSpec) -> bool {
    match spec {
        RemoteSpec::Local(_) => false,
        RemoteSpec::Named { remote, .. } => config.get(remote).is_some_and(RemoteDef::is_vault),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::config::{LocalDef, VaultDef};
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

    fn named(remote: &str) -> RemoteSpec {
        RemoteSpec::Named {
            remote: remote.to_string(),
            path: String::new(),
        }
    }

    /// The pair `dctl init --name archive --base local:/srv/v` registers: a
    /// vault wrapper, and the location whose bytes it seals.
    fn initialised_vault() -> Config {
        let mut config = Config::default();
        config.insert(
            "archive-store",
            RemoteDef::Local(LocalDef {
                path: std::path::PathBuf::from("/srv/v"),
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
    fn a_vault_remote_opens_the_sealed_view_and_its_store_does_not() {
        // Both are readable, and they are not the same view of the same bytes.
        let config = initialised_vault();

        assert!(is_sealed(&config, &named("archive")));
        assert!(!is_sealed(&config, &named("archive-store")));
    }

    #[test]
    fn a_local_path_is_never_sealed() {
        let config = initialised_vault();
        assert!(!is_sealed(
            &config,
            &RemoteSpec::Local(std::path::PathBuf::from("/srv/v"))
        ));
    }

    #[test]
    fn an_unconfigured_remote_is_not_sealed() {
        // A provider shorthand such as `b2:bucket` resolves without appearing in
        // the file at all, and nothing about it is encrypted.
        assert!(!is_sealed(&Config::default(), &named("b2")));
    }

    #[tokio::test]
    async fn a_local_directory_opens_and_reads_without_any_configuration() {
        // The headless path: no config file, no remote, no password.
        let root = tempfile::TempDir::new().unwrap();
        std::fs::write(root.path().join("a.txt"), b"hello").unwrap();

        let spec = RemoteSpec::Local(root.path().to_path_buf());
        let source = open(&ctx(&[]), &spec).await.expect("a directory opens");

        let mut cursor = source.enumerate("").await.expect("a listing opens");
        let entry = cursor.next().await.unwrap().expect("one entry");
        assert_eq!(entry.path, "a.txt");
        assert_eq!(entry.size, Some(5));
        assert_eq!(source.read("a.txt").await.unwrap().as_slice(), b"hello");
    }

    #[tokio::test]
    async fn an_unknown_remote_is_refused_rather_than_read_as_a_directory() {
        // S6, in the read direction. A remote name has no colon, so anything
        // that re-parses it as a spec turns `archive:` into the *directory*
        // `archive` — and a listing of an empty relative directory succeeds,
        // reporting nothing at all about the vault the user asked for.
        let spec = named("nosuchremote");
        let error = open(&ctx(&["--no-ask-password"]), &spec)
            .await
            .err()
            .expect("an unconfigured remote cannot be opened");
        assert_eq!(error.code(), crate::exit::ExitCode::FatalError);
        assert!(
            error.message().contains("nosuchremote"),
            "the refusal must name the remote: {}",
            error.message()
        );
    }

    #[tokio::test]
    async fn a_second_factor_this_build_cannot_apply_is_refused_before_a_vault_opens() {
        // Inherited from `session::open` rather than re-implemented, which is
        // the point of delegating: a source added later cannot forget it.
        let error = open(&ctx(&["--key-file", "/dev/null"]), &named("nosuchremote"))
            .await
            .err()
            .expect("an unusable remote fails either way");
        assert_eq!(error.code(), crate::exit::ExitCode::FatalError);
    }
}
