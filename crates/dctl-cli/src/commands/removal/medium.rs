//! Where a removal reads its candidates and where it deletes them.
//!
//! Two things are stored under a `REMOTE:` name and both can legitimately be
//! removed from: a **sealed vault**, whose objects are addressed by plaintext
//! path through an encrypted index, and a **plain object store**, whose objects
//! are addressed by the provider's own key. They are the same two implementations
//! [`crate::source`] draws for reading, and the decision between them is the same
//! one lookup — a configured remote that declares itself a vault wrapper is
//! sealed, everything else is not.
//!
//! ## Why this exists beside `crate::source` rather than inside it
//!
//! [`Source`](crate::source::Source) is a *read* abstraction: enumerate, read,
//! stat, verify. It has no `remove`, and it must not grow one casually — every
//! listing verb in the binary holds a `Box<dyn Source>`, and a delete method on
//! that trait would be one autocomplete away from a renderer.
//!
//! So removal has its own narrow capability, and gets enumeration from the
//! shared abstraction wherever it can. For the plain side that is exactly what
//! happens: [`PlainSource`] does the paging and this module only supplies the
//! `delete`. For the sealed side it cannot, and the reason is worth stating
//! plainly rather than hiding: [`VaultSource::new`](crate::source::vault::VaultSource::new)
//! consumes the [`Session`], and a removal needs the [`Vault`] back afterwards to
//! call `delete_file` on it. Opening a second session instead would mean a second
//! password acquisition — a second prompt, or an unattended job hanging on one —
//! which is a far worse outcome than the six lines of enumeration below. Those
//! six lines are the same two operations `crate::source::vault` performs —
//! `Vault::list`, then the whole-component prefix check that stops `photos` from
//! matching `photos-backup` — and the property that matters is asserted against
//! a real vault in this file's tests. The day `dctl-core` grows a borrowing
//! listing API, or `VaultSource` grows an accessor, they collapse into a
//! delegation.
//!
//! ## The backend handle
//!
//! `cleanup` works below the logical path set: staged keys and orphaned content
//! objects have no plaintext path, so they can only be reached through
//! [`Backend`]. A vault remote stores nothing itself — it wraps a base store —
//! so [`Medium::store`] follows the same chain [`crate::session::open`] follows
//! and builds *that* remote's backend, on demand. On demand rather than eagerly
//! because for B2, S3 and R2 a backend is a client with credentials behind it,
//! and the five commands that never sweep debris should not pay for one.

use std::sync::Arc;

use dctl_store::{Backend, ObjectKey};

use crate::config::{self, Config, RemoteDef};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::platform::path;
use crate::remote::RemoteSpec;
use crate::session::{self, Session};
use crate::source::plain::PlainSource;
use crate::source::{Entry, Source as _};

use super::target::Target;

/// The spec a removal opens its store with, from the target the operator typed.
///
/// A function of its own so it can be asserted without opening anything, which
/// is the whole of what was missing: this is one line, it was wrong once — the
/// path was blanked, so `deletefile b2:DCTL001/a.txt` reached the resolver as
/// `b2:` and answered "'b2' needs a bucket name" about a command line that had
/// given one — and blanking it again left `cargo test --workspace` entirely
/// green (`HANDOVER.md` §35.3).
///
/// The whole spec, never the bare name: a name has no colon, so anything that
/// re-parses one turns `archive:` into the *directory* `archive`. And the whole
/// spec means **with its path**, because for a provider shorthand the first path
/// component is the bucket and the resolver is the thing that splits it off.
fn spec_of(target: &Target) -> RemoteSpec {
    RemoteSpec::Named {
        remote: target.remote.clone(),
        path: target.path.clone(),
    }
}

/// A store a removal may read from and delete in.
pub enum Medium {
    /// A sealed vault, addressed by plaintext path.
    Vault {
        /// The unlocked vault plus the remote name and index path that name it
        /// in a message. Held whole for the same reason
        /// [`crate::source::vault`] holds it whole.
        ///
        /// Boxed because an unlocked [`Vault`](dctl_core::Vault) carries the
        /// root key and every sub-key derived from it — hundreds of bytes that
        /// every `Medium`, including a plain one that has no vault at all, would
        /// otherwise have to be sized for. The indirection also keeps that key
        /// material at one address rather than being memcpy'd around the stack
        /// on every move, which is what `PLAN.md` §7 wants of anything
        /// key-adjacent.
        session: Box<Session>,
        /// The remote at the end of the vault chain — the one whose backend
        /// really holds bytes. Kept as a spec, not a backend, so that
        /// [`Medium::store`] can build the client only if something asks.
        storage: RemoteSpec,
    },
    /// A plain object store, addressed by provider key.
    Plain {
        /// Enumeration, paged, through the binary's one read abstraction.
        source: PlainSource,
        /// The same backend the source reads, for the deletes.
        backend: Arc<dyn Backend>,
    },
}

impl Medium {
    /// Open the store `target` addresses.
    ///
    /// # Errors
    /// Whatever resolving the configuration, building the backend or unlocking
    /// the vault reported — [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError)
    /// for an unknown remote, [`ExitCode::VaultLocked`](crate::exit::ExitCode::VaultLocked)
    /// for a vault that will not open.
    pub async fn open(ctx: &Ctx, target: &Target) -> Result<Self> {
        let config = load(ctx)?;
        // The whole spec, never the bare name: a name has no colon, so anything
        // that re-parses one turns `archive:` into the *directory* `archive`.
        // That is S6, and in this family it would mean deleting from a folder
        // nobody named while reporting success.
        //
        // And the whole spec means **with its path**. Blanking it here was the
        // §11.3 item 6 defect on the removal side: for a provider shorthand the
        // first path component is the *bucket*, so `deletefile b2:DCTL001/a.txt`
        // resolved `b2:` with nothing after it and answered "'b2' needs a bucket
        // name" about a command line that had given one. The read family was
        // fixed at `2e6d180`; these six verbs were not, and `purge`, `cleanup`
        // and `deletefile` all failed the same way.
        let spec = spec_of(target);

        if is_sealed(&config, &target.remote) {
            tracing::debug!(
                { crate::logging::fields::REMOTE } = %spec,
                "removing from the sealed view"
            );
            let storage = storage_spec(&config, &target.remote)?;
            return Ok(Self::Vault {
                session: Box::new(session::open(ctx, &spec).await?),
                storage,
            });
        }

        tracing::debug!(
            { crate::logging::fields::REMOTE } = %spec,
            "removing from the plain view"
        );
        let resolved = crate::remote::resolve::resolve(&spec, &config)?;
        // Unmetered: a delete moves no body. Pacing it would charge a rate
        // limit for bytes that never crossed the link.
        let backend = crate::remote::registry::build(
            &resolved,
            ctx.globals.links,
            dctl_store::unmetered(),
            ctx.deadlines.clone(),
        )?;
        Ok(Self::Plain {
            source: PlainSource::new(Arc::clone(&backend)),
            backend,
        })
    }

    /// Every object under `prefix`, in ascending path order.
    ///
    /// `prefix` matches **whole path components**, so listing `photos` never
    /// reports `photos-backup/a.jpg`. Both halves of the store match prefixes by
    /// bytes — the index does, and so does every provider — and a plain
    /// `starts_with` here is the bug that makes a `purge` take a neighbouring
    /// tree.
    ///
    /// The result is a `Vec` and not a cursor, and that is a real cost with a
    /// real reason. A removal has to know its *whole* selection before it deletes
    /// the first object: `rmdirs` cannot tell whether a directory is empty
    /// without having seen everything below it, `delete --rmdirs` cannot tell
    /// which directories its own deletion emptied, and `rmdir` cannot refuse a
    /// non-empty directory it has not finished reading. Deleting while
    /// enumerating would also mean mutating the index a cursor is walking.
    /// Reading first is therefore the correctness requirement, not a shortcut —
    /// and on the sealed side [`Vault::list`](dctl_core::Vault::list)
    /// materialises regardless.
    ///
    /// # Errors
    /// Whatever the index or the provider reported. A failure part-way through
    /// is an error and never a short listing: a removal that acted on a
    /// truncated view of a directory would report that directory empty.
    pub async fn list(&self, prefix: &str) -> Result<Vec<Entry>> {
        match self {
            Self::Vault { session, .. } => {
                // Sorted ascending by path by the core, which is what the rest
                // of this family relies on for its deepest-first ordering.
                let records = session.vault.list(prefix)?;
                Ok(records
                    .into_iter()
                    .filter(|record| path::is_under(prefix, &record.path))
                    // The shared conversion, not a local copy of it: a second
                    // spelling is a second place that can forget an index row
                    // carries no size until the file is written again.
                    .map(crate::source::vault::from_record)
                    .collect())
            }
            Self::Plain { source, .. } => {
                let mut cursor = source.enumerate(prefix).await?;
                let mut entries = Vec::new();
                while let Some(entry) = cursor.next().await? {
                    entries.push(entry);
                }
                Ok(entries)
            }
        }
    }

    /// Remove one object, reporting whether it was there to remove.
    ///
    /// The ordering of the sub-steps a sealed removal performs — and what a
    /// crash between them leaves behind — is documented in [`super::remove`],
    /// which is where the decision belongs.
    ///
    /// # Errors
    /// Whatever the vault or the provider reported. A failure here is a failure
    /// of *this object*; the caller records it and carries on, so that one
    /// unreachable object does not abandon the other nine hundred.
    pub async fn remove(&self, logical: &str) -> Result<bool> {
        match self {
            Self::Vault { session, .. } => Ok(session.vault.delete_file(logical).await?),
            Self::Plain { backend, .. } => {
                let key = ObjectKey::new(logical);
                // `Backend::delete` is idempotent and cannot say whether it
                // removed anything, so existence is established first. Two round
                // trips buys the difference between "removed" and "was already
                // gone", and reporting the second as the first is exactly the
                // claim `PLAN.md` §6 forbids.
                let existed = backend.exists(&key).await?;
                backend.delete(&key).await?;
                Ok(existed)
            }
        }
    }

    /// The backend object key of every row in a vault's index, or [`None`] for
    /// a plain store, which has no index.
    ///
    /// This is the one place in the CLI that handles an object key, and it is
    /// deliberately the narrowest possible handling: the keys are used for set
    /// membership by `cleanup`'s orphan sweep and are never joined to a
    /// plaintext path. [`crate::source::Entry`] drops the field precisely so no
    /// renderer can print the mapping the metadata-privacy design exists to
    /// withhold (`PLAN.md` §2, §7); an orphan, by definition, has no plaintext
    /// path to be printed beside, so naming one leaks nothing.
    ///
    /// One entry per row, not a set, because the *count* is what proves the
    /// index is complete — see [`super::reclaim`] for why that proof is what
    /// makes an orphan sweep safe at all.
    ///
    /// # Errors
    /// Whatever reading the index reported.
    pub fn indexed_object_keys(&self) -> Result<Option<Vec<String>>> {
        match self {
            Self::Plain { .. } => Ok(None),
            Self::Vault { session, .. } => Ok(Some(
                session
                    .vault
                    .list("")?
                    .into_iter()
                    .map(|record| record.object_key)
                    .collect(),
            )),
        }
    }

    /// The backend holding this store's bytes.
    ///
    /// For a vault that is the remote at the end of its chain, built here rather
    /// than borrowed from the session because [`Vault`](dctl_core::Vault) keeps
    /// its backend private. Building a second client for the same remote is
    /// cheap for `local:` and one connection for the cloud providers, and it is
    /// only ever reached by `cleanup`.
    ///
    /// # Errors
    /// Whatever resolving the storage remote or building its backend reported.
    pub fn store(&self, ctx: &Ctx) -> Result<Arc<dyn Backend>> {
        match self {
            Self::Plain { backend, .. } => Ok(Arc::clone(backend)),
            Self::Vault { storage, .. } => {
                let config = load(ctx)?;
                let resolved = crate::remote::resolve::resolve(storage, &config)?;
                crate::remote::registry::build(
                    &resolved,
                    ctx.globals.links,
                    dctl_store::unmetered(),
                    ctx.deadlines.clone(),
                )
            }
        }
    }

    /// Whether this medium is a sealed vault.
    ///
    /// The one question above this module that has an honest answer, and it is
    /// asked for exactly one reason: an *orphan* is defined as a content object
    /// no index row refers to, and a plain store has no index, so the class does
    /// not apply there. Saying "not applicable" is the honest report; sweeping
    /// every object in a plain bucket because nothing indexes them would be a
    /// catastrophe dressed as a feature.
    #[must_use]
    pub const fn is_vault(&self) -> bool {
        matches!(self, Self::Vault { .. })
    }
}

/// The configuration this invocation is governed by.
///
/// `load_or_default`, because a machine that has never run `dctl config` is a
/// supported machine (`PLAN.md` §14): it simply defines no vaults, so every
/// remote is plain, which is the truth about that machine.
fn load(ctx: &Ctx) -> Result<Config> {
    let path = config::resolve_path(ctx.globals.config.as_deref());
    Ok(config::load_or_default(&path)?)
}

/// Whether the configuration declares `remote` a vault wrapper.
///
/// Exactly one lookup, and deliberately the only question asked about the shape
/// of a remote. Following the chain, refusing a cycle and finding the remote
/// that really holds bytes all happen elsewhere — doing any of it twice is how
/// two answers to one question come into existence.
fn is_sealed(config: &Config, remote: &str) -> bool {
    config.get(remote).is_some_and(RemoteDef::is_vault)
}

/// The remote at the end of `remote`'s vault chain.
///
/// A vault remote stores nothing itself, so `archive:` becomes `archive-store:`.
/// Walking the chain is also what detects a cycle or a dangling base, which is
/// why a broken configuration is diagnosed here rather than producing a
/// confident wrong backend.
///
/// The path is empty here and that is correct rather than the defect above: this
/// spec exists to *build a backend* for a sweep that works below the logical
/// path set, and a vault's own path is a plaintext path in its namespace which
/// says nothing about where the ciphertext objects sit. The store at the end of
/// the chain is always a configured remote, so its container is a setting rather
/// than the first component of a path, and there is nothing to consume.
fn storage_spec(config: &Config, remote: &str) -> Result<RemoteSpec> {
    let chain = config::vault_chain(config, remote)?;
    Ok(RemoteSpec::Named {
        remote: chain.last().copied().unwrap_or(remote).to_string(),
        path: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LocalDef, VaultDef};
    use std::path::PathBuf;

    #[test]
    fn the_store_a_removal_opens_is_addressed_by_the_whole_argument() {
        // **The line nothing could turn red.** `Medium::open` builds the spec it
        // resolves from the target the operator typed, and it once built it with
        // the path blanked. For a configured remote that is invisible — the
        // remote's own settings say where the store is — so every test passed.
        // For a **provider shorthand** the first path component is the bucket,
        // and blanking the path leaves the resolver `b2:` with nothing to split:
        //
        //     dctl deletefile b2:DCTL001/a.txt   error: 'b2' needs a bucket name
        //     dctl purge b2:DCTL001 --force      error: 'b2' needs a bucket name
        //     dctl cleanup b2:DCTL001 --dry-run  error: 'b2' needs a bucket name
        //
        // Asserted here rather than through `open`, because opening a `b2:`
        // store needs a credential in the process environment and this is the
        // half that goes wrong without one.
        for spelling in [
            "b2:DCTL001/a.txt",
            "b2:DCTL001",
            "archive:photos/2024",
            "archive:",
        ] {
            let target = Target::parse(spelling).expect("a well-formed target");
            assert_eq!(
                spec_of(&target),
                RemoteSpec::Named {
                    remote: target.remote.clone(),
                    path: target.path.clone(),
                },
                "'{spelling}' would open a store the operator did not name"
            );
        }
        // And the shorthand, spelled out: what reaches the resolver still has a
        // bucket in it. A blank path is the defect, so it is named as one.
        let shorthand = Target::parse("b2:DCTL001/2019").expect("a well-formed target");
        match spec_of(&shorthand) {
            RemoteSpec::Named { remote, path } => {
                assert_eq!(remote, "b2");
                assert_eq!(path, "DCTL001/2019", "the bucket was thrown away");
            }
            RemoteSpec::Local(_) => panic!("a removal target is never a local path"),
        }
    }

    /// The pair `dctl init --name archive --base local:/srv/v` registers.
    fn initialised() -> Config {
        let mut config = Config::default();
        config.insert(
            "archive-store",
            RemoteDef::Local(LocalDef {
                path: PathBuf::from("/srv/v"),
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
    fn a_vault_remote_is_sealed_and_its_store_is_not() {
        // Both are removable, and they are not the same view of the same bytes:
        // `delete archive:a.jpg` removes a file, `delete archive-store:o/ab…`
        // removes an opaque object.
        let config = initialised();
        assert!(is_sealed(&config, "archive"));
        assert!(!is_sealed(&config, "archive-store"));
    }

    #[test]
    fn an_unconfigured_remote_is_not_sealed() {
        // A provider shorthand such as `b2:bucket` resolves without appearing in
        // the file at all, and nothing about it is encrypted.
        assert!(!is_sealed(&Config::default(), "b2"));
    }

    #[test]
    fn a_vault_resolves_to_the_remote_that_really_holds_bytes() {
        let spec = storage_spec(&initialised(), "archive").expect("the chain resolves");
        assert_eq!(spec.to_string(), "archive-store:");
    }

    /// A real vault over two temporary directories, presented as a medium.
    ///
    /// Nothing is mocked: the objects are sealed, stored and indexed exactly as
    /// a write through `archive:` stores them, so the enumeration below is the
    /// one a removal really performs.
    async fn vault_with(files: &[(&str, &[u8])]) -> (tempfile::TempDir, tempfile::TempDir, Medium) {
        use std::sync::Arc as StdArc;

        let store = tempfile::TempDir::new().expect("a temporary store");
        let index = tempfile::TempDir::new().expect("a temporary index");
        let backend: StdArc<dyn Backend> = StdArc::new(dctl_store::LocalFs::new(store.path()));
        let index_path = index.path().join("index.redb");

        let vault = dctl_core::Vault::init(StdArc::clone(&backend), &index_path, "pw")
            .await
            .expect("a fresh vault initialises")
            .vault;
        for (path, bytes) in files {
            vault
                .put_file(path, bytes, dctl_core::Modified::Now)
                .await
                .expect("a verified write");
        }

        let medium = Medium::Vault {
            session: Box::new(Session {
                vault,
                remote: "archive:".to_string(),
                index: index_path,
            }),
            storage: RemoteSpec::Local(PathBuf::new()),
        };
        (store, index, medium)
    }

    #[tokio::test]
    async fn a_prefix_scopes_a_sealed_listing_to_whole_components() {
        // The check that keeps a `purge archive:photos` from taking the
        // neighbouring tree: the index matches prefixes by bytes and would
        // report `photos-backup/b.jpg` as though the user had named it.
        let (_store, _index, medium) = vault_with(&[
            ("photos/a.jpg", b"a"),
            ("photos-backup/b.jpg", b"b"),
            ("other/c.jpg", b"c"),
        ])
        .await;

        let listed: Vec<String> = medium
            .list("photos")
            .await
            .expect("the listing succeeds")
            .into_iter()
            .map(|entry| entry.path)
            .collect();
        assert_eq!(listed, ["photos/a.jpg"]);
    }

    #[tokio::test]
    async fn a_sealed_listing_reports_every_object_once_in_path_order() {
        // Ascending path order is what the family's deepest-first marker
        // ordering is derived from, so it is asserted rather than assumed.
        let (_store, _index, medium) = vault_with(&[
            ("b/second.txt", b"22"),
            ("a.txt", b"1"),
            ("b/first.txt", b"333"),
        ])
        .await;

        let listed: Vec<String> = medium
            .list("")
            .await
            .expect("the listing succeeds")
            .into_iter()
            .map(|entry| entry.path)
            .collect();
        assert_eq!(listed, ["a.txt", "b/first.txt", "b/second.txt"]);
    }

    #[tokio::test]
    async fn a_rebuilt_sealed_listing_carries_the_sizes_its_objects_declare() {
        // A rebuild describes each object from its own header, so the sizes come
        // back. This used to assert the opposite — that every row after a rebuild
        // was unmeasured — which was a faithful description of an index that
        // `dctl check` could not compare and `dctl size` under-reported from.
        let (_store, _index, medium) =
            vault_with(&[("a.txt", b"hello world"), ("empty.txt", b"")]).await;

        let before = medium.list("").await.expect("the listing succeeds");
        assert_eq!(before[0].size, Some(11));
        assert_eq!(
            before[1].size,
            Some(0),
            "a genuinely empty file is measured, not unknown"
        );

        let Medium::Vault { session, .. } = &medium else {
            panic!("the fixture is a sealed medium");
        };
        let rebuilt = session
            .vault
            .rebuild_index()
            .await
            .expect("the index rebuilds from the backend");
        assert_eq!(rebuilt.unmeasured, 0);

        let after = medium.list("").await.expect("the listing still succeeds");
        assert_eq!(
            after.iter().map(|entry| entry.size).collect::<Vec<_>>(),
            vec![Some(11), Some(0)],
            "a rebuild recovers the sizes the objects were sealed with"
        );
    }

    #[tokio::test]
    async fn a_sealed_listing_carries_an_unmeasured_row_as_unmeasured() {
        // This listing used to build its entries with its own copy of the
        // record-to-entry conversion, and that copy kept handing on the zero an
        // unmeasured index row carries after the shared one stopped. The visible
        // result was `dctl delete --dry-run archive:` naming three real files
        // and reporting `0 B` freed — a figure somebody reads before deciding
        // the deletion is harmless.
        //
        // The row is produced the only way one still can be: the objects are
        // removed from the store, so the rebuild can map every path from its name
        // record and describe none of them. That is also the real scenario — a
        // provider that has lost the bodies — rather than a contrived fixture.
        let (store, _index, medium) =
            vault_with(&[("a.txt", b"hello world"), ("empty.txt", b"")]).await;
        std::fs::remove_dir_all(store.path().join("o")).expect("the object tree is removable");

        let Medium::Vault { session, .. } = &medium else {
            panic!("the fixture is a sealed medium");
        };
        let rebuilt = session
            .vault
            .rebuild_index()
            .await
            .expect("a rebuild over missing objects still maps every path");
        assert_eq!(rebuilt.files, 2);
        assert_eq!(
            rebuilt.unmeasured, 2,
            "an object that is not there cannot be described, and the count says so"
        );

        let after = medium.list("").await.expect("the listing still succeeds");
        assert_eq!(after.len(), 2);
        for entry in &after {
            assert_eq!(
                entry.size, None,
                "an unmeasured row has no size, and '{}' must not claim one",
                entry.path
            );
        }
    }

    #[tokio::test]
    async fn a_sealed_removal_reports_whether_the_object_was_there() {
        // The distinction the report is built on: `true` means this run removed
        // it, `false` means it was already gone. Neither may be invented.
        let (_store, _index, medium) = vault_with(&[("a.txt", b"hello")]).await;
        assert!(medium.remove("a.txt").await.expect("the delete succeeds"));
        assert!(!medium.remove("a.txt").await.expect("the delete succeeds"));
        assert!(
            medium
                .list("")
                .await
                .expect("the listing succeeds")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn only_a_vault_can_answer_which_objects_the_index_refers_to() {
        // A plain store has no index, so "no index row refers to this object" is
        // not a statement it can make — and `cleanup` must not sweep on it.
        let (_store, _index, medium) = vault_with(&[("a.txt", b"hello")]).await;
        assert!(medium.is_vault());
        let keys = medium
            .indexed_object_keys()
            .expect("the index reads")
            .expect("a vault has an index");
        assert_eq!(keys.len(), 1);
        assert!(
            keys[0].starts_with(crate::constants::VAULT_OBJECT_KEY_PREFIX),
            "an index row must point at a content object: {}",
            keys[0]
        );
    }

    #[test]
    fn a_broken_chain_is_diagnosed_rather_than_guessed_at() {
        // A vault whose base does not exist must not silently become a backend
        // pointing at the vault's own name.
        let mut config = Config::default();
        config.insert(
            "archive",
            RemoteDef::Vault(VaultDef {
                base: "nowhere".into(),
                base_path: None,
                chunk_size: None,
                verify: None,
            }),
        );
        assert!(storage_spec(&config, "archive").is_err());
    }
}
