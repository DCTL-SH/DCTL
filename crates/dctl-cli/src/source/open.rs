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
//! ## Why `dctl init` produces two remotes, and why only one is readable here
//!
//! `dctl init --name archive --base local:/srv/v` registers `archive` (the vault
//! wrapper) and `archive-store` (the location its objects land in). Only the
//! wrapper opens here: `dctl ls archive:` shows the files a person put there,
//! and a plain read of `archive-store:` is REFUSED with a hint naming both
//! views — measured, it served 1,005 `n/<hash>` ciphertext keys with exit 0
//! where the operator expected their files, which is a listing wearing the
//! wrong meaning. The object-level workflows that genuinely want raw keys —
//! replication, object counts — go through `dctl replicate`, which builds its
//! own key-free backend view and never passes this door. The line is drawn
//! where the write side draws it: `require_vault`, the declaration that a
//! store's contents belong to a vault.
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

/// An open source, together with the prefix that scopes a read inside it.
///
/// ## Why the two travel together
///
/// They are one answer to one question and were being taken from two places. A
/// source is built from the **resolved** remote — `b2:DCTL001` builds a client
/// for the bucket `DCTL001` — while every read-side verb scoped its listing with
/// the **spec's** path, which still said `DCTL001`. So `dctl ls b2:DCTL001`
/// enumerated keys under `DCTL001/` inside the bucket of that name and reported
/// nothing, on all three object-store shorthands. Nine call sites made the same
/// mistake because each one had a spec in hand and nothing else, and the cost is
/// not an empty listing: an incremental `sync` reads an empty destination on
/// every run and re-uploads the whole dataset for as long as the job is
/// scheduled (`HANDOVER.md` §11.3 item 6).
///
/// Returning a bare `Box<dyn Source>` is what made that reachable. A caller that
/// receives one of these has the prefix in the same value as the source, and the
/// spec's path is not a thing it needs to look at — which is the only version of
/// this fix that a tenth call site cannot opt out of.
pub struct Opened {
    /// The source itself: sealed vault or plain store, indistinguishable above
    /// this module.
    source: Box<dyn Source>,
    /// The logical prefix inside `source` that the spec addressed.
    prefix: String,
}

impl Opened {
    /// The prefix a read of this source must be scoped by.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The source, for a caller that keeps its own scope.
    #[must_use]
    pub fn source(&self) -> &dyn Source {
        self.source.as_ref()
    }

    /// Take the source, discarding the prefix.
    ///
    /// For the callers that address one *object* by name rather than a subtree —
    /// `cat` opens a remote and each argument supplies its own path — and for
    /// those that have already copied the prefix out. Named `into_` rather than
    /// offered as a `Deref` so that discarding the scope is a visible decision at
    /// the call site: `dctl ls` discarding it is the defect this type exists for.
    #[must_use]
    pub fn into_source(self) -> Box<dyn Source> {
        self.source
    }

    /// Pair a source with a prefix, for a test that needs an [`Opened`] without
    /// a configuration file to open.
    ///
    /// `#[cfg(test)]` and no other constructor exists, which is the point. The
    /// three integrity engines take an `Opened` rather than a source and a
    /// prefix precisely so that a call site cannot supply a prefix from
    /// somewhere else — and a constructor reachable from production would hand
    /// that ability straight back. The engines' own tests still need to drive
    /// prefix scoping, and this is how they do it.
    #[cfg(test)]
    #[must_use]
    pub fn for_test(source: Box<dyn Source>, prefix: impl Into<String>) -> Self {
        Self {
            source,
            prefix: prefix.into(),
        }
    }

    /// Open a cursor over everything under this source's own prefix.
    ///
    /// The shape almost every caller wants, offered here so the prefix and the
    /// source cannot be separated on the way to the one call that uses both.
    ///
    /// # Errors
    /// Whatever the index or provider reported while opening the listing.
    pub async fn enumerate(&self) -> Result<Box<dyn super::Entries>> {
        self.source.enumerate(&self.prefix).await
    }
}

/// Open the source `spec` addresses, scoped as `spec` scopes it.
///
/// A missing configuration file is not an error: `load_or_default` yields an
/// empty one, which is the headless case `PLAN.md` §14 requires to keep working
/// from a bare path or from environment credentials alone. An empty
/// configuration simply defines no vaults, so every spec opens the plain view —
/// which is the truth about a machine that has never run `dctl init`.
///
/// The prefix comes back with the source, from
/// [`logical_prefix`](crate::remote::resolve::logical_prefix), and never from the
/// spec — see [`Opened`] for the failure that made the difference matter.
///
/// # Errors
/// [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError) for an unreadable
/// configuration, an unresolvable remote, or a `--key-file` this build cannot
/// apply; [`ExitCode::VaultLocked`](crate::exit::ExitCode::VaultLocked) when a
/// sealed source will not unlock.
pub async fn open(ctx: &Ctx, spec: &RemoteSpec) -> Result<Opened> {
    let path = crate::config::resolve_path(ctx.globals.config.as_deref());
    let config = crate::config::load_or_default(&path)?;

    // Before the source is built, so an unresolvable remote is diagnosed by the
    // resolver rather than by a backend constructor that has already asked for a
    // credential.
    let prefix = crate::remote::resolve::logical_prefix(spec, &config)?;

    if is_sealed(&config, spec) {
        tracing::debug!(
            { crate::logging::fields::REMOTE } = %spec,
            prefix = %prefix,
            "opening the sealed view"
        );
        return Ok(Opened {
            source: Box::new(VaultSource::open(ctx, spec).await?),
            prefix,
        });
    }

    // A store the configuration claims for a vault does not open plain: its
    // listing is ciphertext keys wearing the meaning of a file listing, and
    // the honest outcomes here are sealed, plain, or refused — never a quiet
    // switch of view. The same line the write side draws, drawn at the one
    // choke point every read verb passes through.
    if let RemoteSpec::Named { remote, .. } = spec
        && let Some(claimed) = crate::config::VaultNamespace::of_remote(&config, remote)
    {
        return Err(crate::addressing::plain_read_refusal(&claimed));
    }

    tracing::debug!(
        { crate::logging::fields::REMOTE } = %spec,
        prefix = %prefix,
        "opening the plain view"
    );
    Ok(Opened {
        source: Box::new(PlainSource::open(
            &config,
            spec,
            ctx.globals.links,
            ctx.deadlines.clone(),
        )?),
        prefix,
    })
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
        // The wrapper is sealed; the store is not — and not-sealed no longer
        // means plain-readable: `open` refuses the claimed store outright,
        // which the two tests below pin end to end.
        let config = initialised_vault();

        assert!(is_sealed(&config, &named("archive")));
        assert!(!is_sealed(&config, &named("archive-store")));
    }

    #[tokio::test]
    async fn reading_a_vault_store_plain_is_refused_and_names_the_sealed_view() {
        // Measured before the guard: 1,005 ciphertext keys served with exit 0
        // where the operator expected their files. The refusal names both the
        // store and the view that answers the question actually asked.
        let dir = tempfile::TempDir::new().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[remotes.archive-store]\ntype = \"local\"\npath = {:?}\nrequire_vault = true\n\n\
                 [remotes.archive]\ntype = \"vault\"\nbase = \"archive-store\"\n",
                dir.path().join("v").to_string_lossy()
            ),
        )
        .unwrap();
        let context = ctx(&["--config", &config.to_string_lossy()]);

        let refused = open(&context, &named("archive-store"))
            .await
            .err()
            .expect("a claimed store does not open plain");
        assert_eq!(refused.code(), crate::exit::ExitCode::FatalError);
        assert!(
            refused.message().contains("archive-store")
                && refused.message().contains("object store"),
            "the refusal says what this remote is: {}",
            refused.message()
        );
        assert!(
            refused.hint().is_some_and(|hint| hint.contains("archive:")),
            "the hint names the sealed view"
        );
    }

    #[tokio::test]
    async fn a_store_no_vault_wraps_says_how_to_register_one() {
        // The shape the benchmark actually hit: a hand-configured store remote
        // carrying require_vault = true with no wrapper registered anywhere.
        // The refusal cannot name a sealed view that does not exist, so it
        // says how to create one.
        let dir = tempfile::TempDir::new().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[remotes.bench]\ntype = \"local\"\npath = {:?}\nrequire_vault = true\n",
                dir.path().join("v").to_string_lossy()
            ),
        )
        .unwrap();
        let context = ctx(&["--config", &config.to_string_lossy()]);

        let refused = open(&context, &named("bench"))
            .await
            .err()
            .expect("a claimed store does not open plain");
        assert!(
            refused
                .hint()
                .is_some_and(|hint| hint.contains("config create") && hint.contains("base=bench")),
            "the hint says how to register the sealed view: {:?}",
            refused.hint()
        );
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
        let opened = open(&ctx(&[]), &spec).await.expect("a directory opens");

        // A bare path is its own root, so the scope that comes back is empty and
        // the whole tree is in view — the property `prefix_is_the_resolvers_and_
        // never_the_specs` states for every other shape.
        assert_eq!(opened.prefix(), "");
        let mut cursor = opened.enumerate().await.expect("a listing opens");
        let entry = cursor.next().await.unwrap().expect("one entry");
        assert_eq!(entry.path, "a.txt");
        assert_eq!(entry.size, Some(5));
        assert_eq!(
            opened.source().read("a.txt").await.unwrap().as_slice(),
            b"hello"
        );
    }

    #[tokio::test]
    async fn a_named_remotes_scope_travels_with_the_source_it_scopes() {
        // The end-to-end half of `HANDOVER.md` §11.3 item 6, on the one provider
        // shape a test can reach without a credential. A configured `local`
        // remote carries its root in a setting, so the whole spec path is the
        // prefix; the shorthands are the shape where it is not, and they are
        // asserted in `remote::resolve` because building one needs a key pair.
        //
        // What this pins is the *wiring*: the number `open` hands back is the
        // number the listing is taken at, on a real directory, through the real
        // resolver. A source opened at the wrong scope lists nothing, and an
        // empty listing is what a `sync` reads as "copy it all again".
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("photos")).unwrap();
        std::fs::write(root.join("photos/a.jpg"), b"1").unwrap();
        std::fs::write(root.join("other.txt"), b"2").unwrap();

        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[remotes.store]\ntype = \"local\"\npath = {:?}\n",
                root.to_string_lossy()
            ),
        )
        .unwrap();
        let context = ctx(&["--config", &config.to_string_lossy()]);

        let opened = open(
            &context,
            &RemoteSpec::Named {
                remote: "store".into(),
                path: "photos".into(),
            },
        )
        .await
        .expect("the remote opens");
        assert_eq!(opened.prefix(), "photos");

        let mut cursor = opened.enumerate().await.expect("a listing opens");
        let first = cursor.next().await.unwrap().expect("one entry");
        assert_eq!(first.path, "photos/a.jpg");
        assert!(
            cursor.next().await.unwrap().is_none(),
            "scoped to the prefix"
        );
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
