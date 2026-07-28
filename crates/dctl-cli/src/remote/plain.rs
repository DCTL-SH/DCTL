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
//! transfer performs — fetch, store, delete — each of which moves its bytes in
//! bounded windows and never holds an object.
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

use std::path::Path;
use std::sync::Arc;

use dctl_core::Streamed;
use dctl_store::{Backend, ByteRange, ContentHash, HashAlgo, ObjectKey, SourceModified};

use crate::config;
use crate::constants::{READ_BACK_WINDOW_BYTES, TRANSFER_STREAM_WINDOW_BYTES};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
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
        // Metered: this is the *write* view, and it is what a transfer moves
        // bytes through. The run's `--bwlimit` is installed here so the storage
        // layer's copy loops can charge it window by window.
        let backend = registry::build(&resolved, ctx.globals.links, ctx.limits.meter())?;
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

    /// Store the file at `source` under `relative`, verified, streaming.
    ///
    /// This replaced a `put` taking a slice, and the slice is where a plain
    /// upload's memory went: the whole file was resident *and* copied again into
    /// the owned buffer [`Backend::put`] wants, because a provider may retry a
    /// request. Two copies of every object.
    /// [`Backend::put_from_path`] streams the body instead, in whatever windows
    /// the provider's protocol uses, and there is no second spelling of a plain
    /// write left for a call site to reach for by accident.
    ///
    /// The digest is folded in one bounded pass over the source before the
    /// upload, because the verified write needs it up front: it is what
    /// [`Backend::put_from_path`] compares the stored bytes against, and it is
    /// what makes success from this call mean "stored *and* checked". It is
    /// returned as well as used, so the audit record does not pay a third pass.
    ///
    /// `modified` describes the **content** — see
    /// [`SourceModified`](dctl_store::SourceModified) — and is a required
    /// argument rather than an option, so a write path added later cannot omit
    /// it and quietly make `sync` non-incremental again on that one route.
    ///
    /// # Errors
    /// [`ExitCode::ChecksumMismatch`](crate::exit::ExitCode::ChecksumMismatch)
    /// when the store did not hold what was sent, plus whatever the provider
    /// reported.
    pub async fn put_from_path(
        &self,
        relative: &str,
        source: &Path,
        modified: SourceModified,
    ) -> Result<Streamed> {
        let (bytes, plaintext_hash) = hash_path(source).await?;
        self.backend
            .put_from_path(
                &self.key(relative),
                source,
                &ContentHash {
                    algo: HashAlgo::Blake3,
                    bytes: plaintext_hash.to_vec(),
                },
                modified,
            )
            .await?;
        Ok(Streamed {
            bytes,
            plaintext_hash,
        })
    }

    /// Fetch one object onto the local file `dest`, streaming, atomically, and
    /// carrying the source's time.
    ///
    /// This replaced a `get` returning the object as one buffer.
    /// [`Backend::get_to_path`] writes the body straight to a file in whatever
    /// windows the provider serves it in, so nothing here is ever the size of
    /// the object.
    ///
    /// It writes to a **staging sibling** and publishes with a rename rather
    /// than letting the backend write `dest` directly, for the reason every
    /// other write in this program does: a transfer interrupted mid-body would
    /// otherwise leave a truncated file under the destination's own name, which
    /// the next run compares by size, finds different, and re-fetches — while
    /// anything reading the tree in between sees a file that is simply wrong.
    ///
    /// The digest costs one further bounded pass over the staging file, and that
    /// is a real cost stated rather than hidden: a plain object carries no
    /// recorded hash to fold against, so unlike the sealed path there is nothing
    /// to learn on the way past. It buys the audit record's digest and
    /// `--verify`'s comparison, both of which would otherwise have to read the
    /// file again anyway.
    ///
    /// # Errors
    /// Whatever the provider reported, plus any I/O error from writing,
    /// stamping, syncing or publishing the destination.
    pub async fn get_to_path(
        &self,
        relative: &str,
        dest: &Path,
        modified: dctl_core::Modified,
    ) -> Result<Streamed> {
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let staging = dctl_store::staging::staging_sibling(dest);

        let outcome = async {
            self.backend
                .get_to_path(&self.key(relative), &staging)
                .await?;
            let (bytes, plaintext_hash) = hash_path(&staging).await?;
            let file = tokio::fs::File::options()
                .write(true)
                .open(&staging)
                .await?;
            let file = crate::platform::times::stamp_open(file, modified).await?;
            file.sync_all().await?;
            Ok::<Streamed, CliError>(Streamed {
                bytes,
                plaintext_hash,
            })
        }
        .await;

        let streamed = match outcome {
            Ok(streamed) => streamed,
            Err(error) => {
                let _ = tokio::fs::remove_file(&staging).await;
                return Err(error);
            }
        };
        if let Err(error) = tokio::fs::rename(&staging, dest).await {
            let _ = tokio::fs::remove_file(&staging).await;
            return Err(error.into());
        }
        Ok(streamed)
    }

    /// Hash one stored object without materialising it, in ranged windows.
    ///
    /// What `--verify` asks of a plain destination: read the object back and
    /// prove it is what was sent. Doing that through a whole-object `get` held
    /// the entire thing in memory to hash it, which made `--verify` unusable at
    /// exactly the sizes it matters most for. [`Backend::get_range`] is on the
    /// trait and every backend implements it as a genuine ranged request, so the
    /// object is walked in [`READ_BACK_WINDOW_BYTES`] windows and only the
    /// running hash survives between them.
    ///
    /// The length comes from a [`Backend::head`], so a window is never asked for
    /// past the end and the walk terminates on the object's own declared size
    /// rather than on a short answer — which a provider serving a truncated body
    /// would otherwise present as a complete, differently-hashed object.
    ///
    /// # Errors
    /// Whatever the provider reported, and
    /// [`ExitCode::IntegrityFailure`](crate::exit::ExitCode::IntegrityFailure)
    /// if it stopped serving bytes before the length it declared.
    pub async fn hash_object(&self, relative: &str) -> Result<String> {
        let key = self.key(relative);
        let size = self.backend.head(&key).await?.size;

        let mut hasher = blake3::Hasher::new();
        let mut at = 0_u64;
        while at < size {
            let want = READ_BACK_WINDOW_BYTES.min(size - at);
            let window = self
                .backend
                .get_range(&key, ByteRange::new(at, Some(want)))
                .await?;
            if window.is_empty() {
                return Err(CliError::new(
                    ExitCode::IntegrityFailure,
                    format!("'{relative}' stopped serving bytes at {at} of the {size} it declares"),
                )
                .with_hint(
                    "The provider returned an empty range inside the object. Re-run \
                     the check; if it persists the stored object is truncated.",
                ));
            }
            hasher.update(&window);
            at += window.len() as u64;
        }
        Ok(crate::output::hex::encode(hasher.finalize().as_bytes()))
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

/// Stream a local file, returning its length and the BLAKE3 of its contents.
///
/// The digest a verified write compares against and the digest an audit record
/// carries are the same number, and both are wanted for a file nobody wishes to
/// hold. One bounded pass answers both; asking twice would double the I/O on
/// every object a plain transfer moves, and asking after the upload would hash
/// whatever the source says by then rather than what was actually sent.
async fn hash_path(path: &Path) -> Result<(u64, [u8; 32])> {
    use tokio::io::AsyncReadExt as _;

    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|error| CliError::from(error).with_hint(format!("hashing {}", path.display())))?;

    let mut window = vec![0_u8; TRANSFER_STREAM_WINDOW_BYTES];
    let mut hasher = blake3::Hasher::new();
    let mut bytes = 0_u64;
    loop {
        let read = file.read(&mut window).await?;
        if read == 0 {
            break;
        }
        // `read` never exceeds the window's length, so the slice is always in
        // range; the fallback keeps this file free of an indexing panic.
        let Some(chunk) = window.get(..read) else {
            break;
        };
        hasher.update(chunk);
        bytes += read as u64;
    }
    Ok((bytes, *hasher.finalize().as_bytes()))
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
        let source = root.path().join("source.txt");
        std::fs::write(&source, b"real bytes").expect("a source file");
        let stored = remote
            .put_from_path("a.txt", &source, SourceModified::unknown())
            .await
            .expect("stored");

        // Asserted on the filesystem, not on the return value: the point is that
        // the bytes are *there*, under the name a later listing would find.
        assert_eq!(
            std::fs::read(root.path().join("a.txt")).expect("the object exists"),
            b"real bytes"
        );
        // The digest the upload folded is the digest of what was uploaded, and
        // it is the one the verified write was made against.
        assert_eq!(stored.bytes, 10);
        assert_eq!(
            stored.hash_hex(),
            blake3::hash(b"real bytes").to_hex().to_string()
        );

        // And reading it back costs no buffer the size of the object: the same
        // digest comes out of a ranged walk over the stored bytes.
        assert_eq!(
            remote.hash_object("a.txt").await.expect("hashed"),
            stored.hash_hex()
        );

        let back = root.path().join("back.txt");
        let fetched = remote
            .get_to_path("a.txt", &back, dctl_core::Modified::At(1_500_000_000))
            .await
            .expect("fetched");
        assert_eq!(std::fs::read(&back).expect("written"), b"real bytes");
        assert_eq!(fetched.hash_hex(), stored.hash_hex());
        // A download that dropped the source's time is what made every later
        // run re-fetch the same object forever.
        assert_eq!(
            std::fs::metadata(&back)
                .expect("stat")
                .modified()
                .expect("mtime")
                .duration_since(std::time::UNIX_EPOCH)
                .expect("after the epoch")
                .as_secs(),
            1_500_000_000
        );
        // Publishing is a rename, so no staging file may survive it.
        let leftovers: Vec<_> = std::fs::read_dir(root.path())
            .expect("readable")
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| dctl_store::staging::is_staging_name(name))
            .collect();
        assert!(leftovers.is_empty(), "staging debris: {leftovers:?}");
    }

    #[tokio::test]
    async fn the_prefix_the_user_named_is_part_of_every_key() {
        // `copy ./src backup:photos` must land under `photos/`, because that is
        // where a listing of `backup:photos` looks. Dropping the prefix would
        // write to the remote's root and re-copy the same files every run.
        let root = tempfile::tempdir().expect("a temporary directory");
        let (_dir, ctx) = ctx_with(&plain_remote_at(root.path()));

        let remote = PlainRemote::open(&ctx, &named("backup", "photos")).expect("opens");
        let source = root.path().join("source.jpg");
        std::fs::write(&source, b"image").expect("a source file");
        remote
            .put_from_path("2024/a.jpg", &source, SourceModified::unknown())
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

        let source = root.path().join("source.bin");
        std::fs::write(&source, b"x").expect("a source file");
        remote
            .put_from_path("gone.txt", &source, SourceModified::unknown())
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
