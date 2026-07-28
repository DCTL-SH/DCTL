//! A plain named remote, opened for reading *and writing* its objects.
//!
//! [`crate::source`] can already read one: `dctl ls backup:` goes through a
//! `Box<dyn Source>` and never learns which kind of place answered. That is the
//! right shape for a listing and the wrong shape for a transfer, because a
//! `Source` is deliberately read-only — a caller holding one cannot store an
//! object, and giving it a `put` would hand every reader a write path it has no
//! business having.
//!
//! So this is the write-side counterpart, and it is the whole of it: a live
//! [`Backend`] plus the prefix the user named, with the three operations a
//! transfer performs — `get`, `put`, `delete`.
//!
//! ## Nothing here is sealed, and nothing here asks for a password
//!
//! A vault is opened by [`crate::session::open`], which unwraps a root key. This
//! module never does: it resolves a remote, builds its backend, and moves opaque
//! bytes. That is exactly what makes `dctl copy ./src backup:` work under
//! `--no-ask-password` — there is no key to unwrap, because an ordinary
//! destination stores ordinary bytes (`crate::addressing`, invariant I3).
//!
//! **Deciding whether a remote is sealed is not this module's job.** It does not
//! ask, and it must never grow the question: [`crate::remote::Place`] answers it
//! from [`RemoteDef::is_vault`](crate::config::RemoteDef::is_vault), and a
//! second definition of "is this sealed" is precisely the defect that made a
//! plain configured remote demand a vault password — the transfer engine decided
//! from the *shape* of the argument (`backup:` has a colon, therefore vault)
//! while `crate::source` decided from the configuration. One question, one
//! answer, asked where it is already answered.
//!
//! ## The prefix belongs to the key, and comes from the resolver
//!
//! `copy ./src backup:photos` must land `a.txt` at `photos/a.txt`, because that
//! is where the *listing* of `backup:photos` would find it again. Taking the
//! prefix from [`Resolved::path`] rather than from the spec is what keeps the
//! two sides agreeing for a provider shorthand as well: `b2:mybucket/photos`
//! resolves to the bucket `mybucket` and the path `photos`, so using the spec's
//! own path would address `mybucket/photos` *inside* `mybucket` and every
//! subsequent run would copy the same files again.
//!
//! ## Verified writes come from the backend, not from a wrapper here
//!
//! [`Backend::put`] must not report success unless the stored bytes match the
//! hash it was given, and must leave nothing committed on a mismatch. That is a
//! trait-level invariant every provider upholds — `LocalFs` fsyncs a staging
//! file, reads it back, compares, then renames — so [`PlainRemote::put`] hands
//! down a BLAKE3 of the buffer and lets the contract do its job. Re-implementing
//! a staged write here would be a second, weaker copy of a guarantee that
//! already exists one layer down.
//!
//! ## The source's modification time travels with the bytes
//!
//! An ordinary object is stored **as itself**: it has no encrypted header to
//! carry facts about it, so what the provider records is all there is. If the
//! source's modification time is not written here, the destination reports the
//! moment of the upload, every later comparison finds every file changed, and a
//! nightly `sync` re-uploads the whole dataset for the life of the remote. That
//! was true of every plain destination until this parameter existed, on local
//! disk, over SFTP and on B2 alike.
//!
//! Unlike a vault, there is nothing to leak by recording it: the object's *name*
//! and *contents* are already in the clear at the destination the user named, so
//! its age discloses nothing the provider cannot already read.

use std::sync::Arc;

use bytes::Bytes;
use dctl_store::{Backend, ContentHash, ObjectKey, SourceModified};
use zeroize::Zeroizing;

use crate::config;
use crate::ctx::Ctx;
use crate::error::Result;
use crate::platform::path as logical;

use super::registry;
use super::resolve::{self, Resolved};
use super::spec::RemoteSpec;

/// A live, unsealed remote: its backend, and the prefix inside it.
pub struct PlainRemote {
    /// The remote as the resolver understood it — its name, for messages and
    /// audit records, and its prefix, for every key built below.
    resolved: Resolved,
    /// The provider connection. Keys pass through it untouched.
    backend: Arc<dyn Backend>,
}

/// Written by hand because a live backend has no `Debug` and would be noise if
/// it had one: what a reader of a `{:?}` needs is *which* remote this is.
impl std::fmt::Debug for PlainRemote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlainRemote")
            .field("remote", &self.resolved.name())
            .field("prefix", &self.resolved.path())
            .field("provider", &self.backend.name())
            .finish()
    }
}

impl PlainRemote {
    /// Connect to the plain remote `spec` names.
    ///
    /// Takes the **whole parsed spec**, never a remote's name: a bare name
    /// carries no colon, so anything that re-parses one gets a relative
    /// directory of that name back and writes the user's data into the working
    /// directory. A [`RemoteSpec`] has already been classified and cannot be
    /// reclassified here.
    ///
    /// A missing configuration file is not an error. `load_or_default` yields an
    /// empty catalogue, which is the headless case `PLAN.md` §14 requires: a
    /// provider shorthand plus exported credentials, and no config on disk.
    ///
    /// # Errors
    /// [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError) for an
    /// unreadable configuration, a remote nobody configured, one whose settings
    /// are incomplete, or a credential the environment does not carry.
    pub fn open(ctx: &Ctx, spec: &RemoteSpec) -> Result<Self> {
        let path = config::resolve_path(ctx.globals.config.as_deref());
        let configured = config::load_or_default(&path)?;
        let resolved = resolve::resolve(spec, &configured)?;
        let backend = registry::build(&resolved)?;
        Ok(Self { resolved, backend })
    }

    /// The remote's name, for the `remote` field of an audit record.
    #[must_use]
    pub fn name(&self) -> &str {
        self.resolved.name()
    }

    /// The object key a plan-relative path addresses.
    ///
    /// One function, used by all three operations, because a `get` that composed
    /// its key differently from the matching `put` would read past the object it
    /// just wrote — and the two would disagree only for the users who named a
    /// prefix.
    fn key(&self, relative: &str) -> ObjectKey {
        ObjectKey::new(logical::join(self.resolved.path(), relative))
    }

    /// Fetch one object whole.
    ///
    /// Wrapped in [`Zeroizing`] like every other buffer this tool holds. These
    /// bytes are not secret — they were stored in the clear and are on their way
    /// to a plaintext destination — but a transfer engine that wiped *some* of
    /// its buffers depending on where they came from is one edit away from not
    /// wiping the ones that matter.
    ///
    /// # Errors
    /// Whatever the provider reported: a missing object, a refused credential, a
    /// network failure.
    pub async fn get(&self, relative: &str) -> Result<Zeroizing<Vec<u8>>> {
        let bytes = self.backend.get(&self.key(relative)).await?;
        Ok(Zeroizing::new(bytes.to_vec()))
    }

    /// Store one object, verified, carrying the source's modification time.
    ///
    /// The hash is computed here and handed to [`Backend::put`], which is the
    /// party that can actually check it: it compares what the store holds
    /// against this digest and commits nothing if they differ. Success from this
    /// call therefore means the bytes are stored *and* were checked, which is
    /// what the pipeline's `upload` stage is allowed to claim.
    ///
    /// `modified` describes the **content** — see
    /// [`SourceModified`](dctl_store::SourceModified) — and is a required
    /// argument rather than an option, so a write path added later cannot omit it
    /// and quietly make `sync` non-incremental again on that one route.
    ///
    /// The copy into [`Bytes`] is unavoidable at this seam — the trait takes an
    /// owned, cheaply-cloneable buffer because a provider may retry a request —
    /// and it is not wiped on drop. It holds a plaintext object being written
    /// *as* plaintext to a destination the user named, so the exposure is the
    /// destination file itself; nothing sealed passes through here.
    ///
    /// # Errors
    /// [`ExitCode::ChecksumMismatch`](crate::exit::ExitCode::ChecksumMismatch)
    /// when the store did not hold what was sent, plus whatever the provider
    /// reported.
    pub async fn put(&self, relative: &str, bytes: &[u8], modified: SourceModified) -> Result<()> {
        let expected = ContentHash::blake3(bytes);
        self.backend
            .put(
                &self.key(relative),
                Bytes::copy_from_slice(bytes),
                &expected,
                modified,
            )
            .await?;
        Ok(())
    }

    /// Remove one object.
    ///
    /// Idempotent by the trait's contract — deleting what is not there succeeds
    /// — which is what a retried `move` needs: the first attempt may already
    /// have removed it, and failing the second would turn a completed operation
    /// into a reported failure.
    ///
    /// # Errors
    /// Whatever the provider reported.
    pub async fn delete(&self, relative: &str) -> Result<()> {
        self.backend.delete(&self.key(relative)).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::config::{Config, LocalDef, RemoteDef};
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    /// A context reading a configuration written for this test.
    ///
    /// `--no-ask-password` is on every one of them deliberately: the property
    /// this module exists for is that a plain remote needs no password at all,
    /// and a test that left the prompt available could pass by being answered.
    fn ctx_with(config: &Config) -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("config.toml");
        config::save(config, &path).expect("the fixture must be a valid configuration");

        let argv = [
            "dctl".to_string(),
            "--quiet".to_string(),
            "--no-ask-password".to_string(),
            "--config".to_string(),
            path.to_string_lossy().into_owned(),
        ];
        (dir, Ctx::new(Harness::parse_from(argv).globals))
    }

    /// `dctl config create backup local path=<root>` — an ordinary remote that
    /// no vault wraps.
    fn plain_remote_at(root: &std::path::Path) -> Config {
        let mut config = Config::default();
        config.insert(
            "backup",
            RemoteDef::Local(LocalDef {
                path: root.to_path_buf(),
                verify: None,
                require_vault: false,
            }),
        );
        config
    }

    fn named(remote: &str, path: &str) -> RemoteSpec {
        RemoteSpec::Named {
            remote: remote.to_string(),
            path: path.to_string(),
        }
    }

    #[tokio::test]
    async fn an_object_round_trips_through_a_configured_plain_remote() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with(&plain_remote_at(root.path()));

        let remote = PlainRemote::open(&ctx, &named("backup", "")).expect("no password is needed");
        remote
            .put("a.txt", b"real bytes", SourceModified::unknown())
            .await
            .expect("stored");

        // Asserted on the filesystem, not on the return value: the point is that
        // the bytes are *there*, under the name a later listing would find.
        assert_eq!(
            std::fs::read(root.path().join("a.txt")).expect("the object exists"),
            b"real bytes"
        );
        assert_eq!(remote.get("a.txt").await.unwrap().as_slice(), b"real bytes");
    }

    #[tokio::test]
    async fn the_prefix_the_user_named_is_part_of_every_key() {
        // `copy ./src backup:photos` must land under `photos/`, because that is
        // where a listing of `backup:photos` looks. Dropping the prefix would
        // write to the remote's root and re-copy the same files every run.
        let root = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with(&plain_remote_at(root.path()));

        let remote = PlainRemote::open(&ctx, &named("backup", "photos")).expect("opens");
        remote
            .put("2024/a.jpg", b"image", SourceModified::unknown())
            .await
            .expect("stored");

        assert!(root.path().join("photos/2024/a.jpg").exists());
        assert!(
            !root.path().join("2024/a.jpg").exists(),
            "the prefix must not be dropped"
        );
    }

    #[tokio::test]
    async fn deleting_something_already_gone_succeeds() {
        // Idempotence: a retried `move` must not fail because the first attempt
        // already removed the object.
        let root = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with(&plain_remote_at(root.path()));

        let remote = PlainRemote::open(&ctx, &named("backup", "")).expect("opens");
        assert!(remote.delete("never-existed.txt").await.is_ok());

        remote
            .put("gone.txt", b"x", SourceModified::unknown())
            .await
            .expect("stored");
        remote.delete("gone.txt").await.expect("removed");
        assert!(!root.path().join("gone.txt").exists());
    }

    #[tokio::test]
    async fn an_unconfigured_remote_is_refused_rather_than_becoming_a_directory() {
        // A remote's name carries no colon, so anything that re-parses one turns
        // `backup:` into the relative directory `backup` — and a transfer into
        // it reports success while the data sits in the working directory.
        let root = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with(&plain_remote_at(root.path()));

        let error = PlainRemote::open(&ctx, &named("nosuchremote", ""))
            .expect_err("an unconfigured remote cannot be opened");
        assert_eq!(error.code(), crate::exit::ExitCode::FatalError);
        assert!(
            error.message().contains("nosuchremote"),
            "the refusal must name the remote: {}",
            error.message()
        );
    }

    #[test]
    fn the_debug_rendering_names_the_remote_and_holds_no_bytes() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with(&plain_remote_at(root.path()));

        let remote = PlainRemote::open(&ctx, &named("backup", "photos")).expect("opens");
        let rendered = format!("{remote:?}");
        assert!(rendered.contains("backup"), "got: {rendered}");
        assert!(rendered.contains("photos"), "got: {rendered}");
    }
}
