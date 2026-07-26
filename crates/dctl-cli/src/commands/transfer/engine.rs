//! The binding between the transfer commands and `dctl-core`.
//!
//! Everything above this file decides *what* to do: specs are parsed, both sides
//! enumerated, the plan diffed, filtered, printed and guarded. This file does
//! it, by driving [`dctl_core::Vault`].
//!
//! ## Why the stage walk does not map one-to-one onto the core
//!
//! `PLAN.md` §6 describes six steps — read, encrypt, stage, verify, commit,
//! delete-source. `Vault::put_file` today performs steps 1–6 as a single
//! whole-file operation: it seals the plaintext, does a verified write to the
//! backend, and commits the index entry, returning `Ok` only after all of it.
//!
//! That is *stronger* than the stage split, not weaker — there is no window in
//! which a file is uploaded but uncommitted. So the stages here are honest about
//! where the work actually happens: [`Engine::upload`] performs the verified
//! write and the durable commit together, and [`Engine::commit`] confirms what
//! already succeeded rather than pretending to do it again. The stage display
//! stays useful because it still reports true positions in the pipeline, and
//! when `dctl-core` grows a streaming API the stages separate without any change
//! above this file.
//!
//! ## What is genuinely refused
//!
//! Vault-to-vault transfers need two unlocked vaults and a re-encrypting path
//! that `dctl-core` does not expose. That is refused, loudly, at connect time —
//! before a single file is attempted.
//!
//! So is a plaintext write into a vault's object namespace, and that decision is
//! not made here: [`crate::addressing`] owns it, because `rcat` reaches the
//! filesystem by a completely different route and has to reach the same answer.
//! What matters at this seam is *which* address is checked — the destination,
//! whichever side it is on — and that the check runs before the vault is opened,
//! so a refusal costs no password prompt.
//!
//! ## What addressing does *not* do yet
//!
//! Recorded here rather than left for a user to discover, because the gap puts
//! objects somewhere other than the spec reads.
//!
//! [`Engine::build`] hands [`session::open()`] the destination's whole
//! [`RemoteSpec`], so the provider and its container are both honoured and an
//! unconfigured name is a hard failure. The **logical path inside the remote is
//! still dropped**: `copy ./src b2:mybucket/photos` connects to `mybucket` — the
//! right bucket — but an entry's plan-relative path becomes its key at the
//! vault's root, so it stores `a.txt` rather than `photos/a.txt`.
//!
//! Closing that needs the [`Resolved`](crate::remote::resolve::Resolved) remote,
//! not just the spec, to survive into [`Session`] and prefix every key — a
//! change to what a session carries rather than to the engine's own logic.
//! `docs/commands/dctl_copy.md` states the current behaviour plainly so nobody
//! plans a backup around the intended one.
//!
//! Only the shorthands (`b2:`, `s3:`, `r2:`, `local:`) resolve, because the
//! session resolves against the empty catalogue exactly as `dctl init` does; a
//! remote defined in the config file is still reported as unknown rather than
//! connected to.
//!
//! ## Memory
//!
//! `Vault::put_file` and `get_file` take and return whole buffers, so one file's
//! plaintext is resident while it moves. Files above
//! [`WHOLE_FILE_LIMIT`](crate::constants::TRANSFER_WHOLE_FILE_LIMIT) are refused
//! rather than attempted: a 50 GB video would otherwise take the machine down,
//! and `PLAN.md` §16.2 is explicit that memory must stay O(concurrency). The
//! limit disappears when the streaming engine lands.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use dctl_store::ContentHash;
use zeroize::Zeroizing;

use crate::addressing;
use crate::cli::VerifyMode;
use crate::constants::{LOCAL_STAGING_SUFFIX, TRANSFER_ENGINE_HINT, TRANSFER_WHOLE_FILE_LIMIT};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::platform::path as logical;
use crate::remote::RemoteSpec;
use crate::session::{self, Session};

use super::pipeline::{Reaper, StageDriver};
use super::plan::PlanEntry;

/// Which way bytes move, and therefore which side needs a vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Local filesystem into a vault: seal, verified write, index commit.
    Upload,
    /// Vault out to the local filesystem: fetch, authenticate, write.
    Download,
    /// Filesystem to filesystem, with no vault involved on either side.
    LocalOnly,
}

/// Which side a [`Reaper`] is allowed to delete from.
///
/// A type rather than a bare string, because "delete from the source" and
/// "delete from the destination" differ by the entire meaning of the command,
/// and passing the wrong literal would be a data-loss bug that compiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReapTarget {
    /// `move`/`moveto`: the source, after a durable destination commit.
    Source,
    /// `sync`: files present only at the destination.
    Destination,
}

impl ReapTarget {
    /// Stable label used in messages and audit records.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Destination => "destination",
        }
    }
}

/// A connected transfer engine.
///
/// Constructed once per run, before any file is touched, so a missing
/// capability costs one error rather than one error per file.
pub struct Engine {
    direction: Direction,
    /// The unlocked vault, for whichever side is a vault. `None` for
    /// [`Direction::LocalOnly`].
    session: Option<Session>,
    /// Filesystem root the source side resolves against, when the source is
    /// local. Empty otherwise.
    source_root: PathBuf,
    /// Filesystem root the destination side resolves against, when the
    /// destination is local. Empty otherwise.
    ///
    /// Kept separate from [`Engine::source_root`] even though one of the two is
    /// always unused: a filesystem-to-filesystem copy has two *different* roots,
    /// and folding them into one field silently writes every destination under
    /// the source directory.
    dest_root: PathBuf,
    /// Which side this engine's reaper deletes from.
    reap_target: ReapTarget,
    /// Plaintext in flight, keyed by the entry's destination path.
    ///
    /// The stage trait takes `&self`, and a file's bytes have to survive from
    /// `read` to `upload`, so they live here rather than in a local. Entries are
    /// removed as soon as they are consumed: holding a file's plaintext one
    /// stage longer than necessary is exactly the kind of lifetime a crypto tool
    /// should not have.
    staged: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
}

impl std::fmt::Debug for Engine {
    /// Written by hand so neither the staged plaintext nor the unlocked vault
    /// can be rendered.
    ///
    /// A derived implementation would print every in-flight file's contents —
    /// `Zeroizing<Vec<u8>>` forwards `Debug` to the bytes it wraps, and wiping
    /// on drop does nothing about a copy already formatted into a panic message
    /// or a log line. Only the count is reported, which is all a diagnostic
    /// actually needs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let staged = self.staged.lock().map(|s| s.len());
        f.debug_struct("Engine")
            .field("direction", &self.direction)
            .field("source_root", &self.source_root)
            .field("dest_root", &self.dest_root)
            .field("reap_target", &self.reap_target)
            .field("vault", &self.session.as_ref().map(|_| "unlocked"))
            .field("staged_files", &staged.unwrap_or_default())
            .finish()
    }
}

impl Engine {
    /// Connect the engine for one command.
    ///
    /// # Errors
    /// [`ExitCode::FatalError`] when both sides are vaults (unsupported), or
    /// when the vault cannot be opened; [`ExitCode::VaultLocked`] when no
    /// password is available.
    pub async fn connect(
        ctx: &Ctx,
        command: &str,
        source: &RemoteSpec,
        dest: &RemoteSpec,
    ) -> Result<Self> {
        Self::build(ctx, command, source, dest, ReapTarget::Source).await
    }

    /// Connect an engine whose reaper deletes from `target`.
    pub async fn connect_reaper(
        ctx: &Ctx,
        command: &str,
        source: &RemoteSpec,
        dest: &RemoteSpec,
        target: ReapTarget,
    ) -> Result<Self> {
        Self::build(ctx, command, source, dest, target).await
    }

    async fn build(
        ctx: &Ctx,
        command: &str,
        source: &RemoteSpec,
        dest: &RemoteSpec,
        reap_target: ReapTarget,
    ) -> Result<Self> {
        // The fourth element is the **whole spec** of whichever side is a vault,
        // never its name. Passing the name alone is what S6 was: `session::open`
        // re-parsed it, found no colon in `b2`, and produced a relative
        // directory — so `copy ./src b2:mybucket` unlocked a vault in `./b2`,
        // threw the bucket away, and reported success. A `RemoteSpec` has
        // already been classified and cannot be reclassified downstream.
        let (direction, source_root, dest_root, vault_spec) = match (source, dest) {
            (RemoteSpec::Local(from), RemoteSpec::Named { .. }) => {
                (Direction::Upload, from.clone(), PathBuf::new(), Some(dest))
            }
            (RemoteSpec::Named { .. }, RemoteSpec::Local(to)) => (
                Direction::Download,
                PathBuf::new(),
                to.clone(),
                Some(source),
            ),
            (RemoteSpec::Local(from), RemoteSpec::Local(to)) => {
                (Direction::LocalOnly, from.clone(), to.clone(), None)
            }
            (RemoteSpec::Named { .. }, RemoteSpec::Named { .. }) => {
                return Err(CliError::unimplemented(format!(
                    "dctl {command}: transfers between two remotes"
                ))
                .with_hint(
                    "Copy to a local path first, then copy that up. A direct \
                     remote-to-remote path needs re-encryption support in \
                     dctl-core that does not exist yet (PLAN.md §6).",
                ));
            }
        };

        // Whether this transfer may write plaintext is a question about the
        // **destination's address**, and it is asked of the destination spec
        // rather than of the direction: `Local` here means a filesystem path,
        // which every direction but `Upload` writes to, and `Named` means a
        // remote, which only `Upload` writes to. Deriving it from the spec means
        // a direction added later cannot slip past by not being listed.
        //
        // Asked before the vault is opened, so a refusal costs no password
        // prompt — and answered from the configuration, so it is the same answer
        // whatever the destination currently holds.
        match dest {
            RemoteSpec::Named { remote, .. } => {
                addressing::refuse_plain_write_to_remote(ctx, remote)?;
            }
            RemoteSpec::Local(path) => addressing::refuse_plain_write_to_path(ctx, path)?,
        }

        let session = match vault_spec {
            Some(spec) => Some(session::open(ctx, spec).await?),
            None => None,
        };

        Ok(Self {
            direction,
            session,
            source_root,
            dest_root,
            reap_target,
            staged: Mutex::new(HashMap::new()),
        })
    }

    /// The vault, for a direction that has one.
    fn vault(&self) -> Result<&dctl_core::Vault> {
        self.session.as_ref().map(|s| &s.vault).ok_or_else(|| {
            CliError::new(
                ExitCode::FatalError,
                "internal: no vault for this transfer direction",
            )
        })
    }

    /// Absolute path of an entry's source on the local filesystem.
    fn source_path(&self, relative: &str) -> PathBuf {
        logical::from_logical(&self.source_root, relative)
    }

    /// Absolute path of an entry's destination on the local filesystem.
    fn dest_path(&self, relative: &str) -> PathBuf {
        logical::from_logical(&self.dest_root, relative)
    }

    /// Reject a file too large to hold in memory.
    ///
    /// Refusing beforehand is the whole point: attempting it would either be
    /// killed by the OOM killer or swap the machine to a standstill, and either
    /// way the user learns nothing actionable.
    fn check_size(&self, entry: &PlanEntry) -> Result<()> {
        if entry.size > TRANSFER_WHOLE_FILE_LIMIT {
            return Err(CliError::new(
                ExitCode::FatalError,
                format!(
                    "'{}' is {} bytes, above the {} byte whole-file limit",
                    entry.source, entry.size, TRANSFER_WHOLE_FILE_LIMIT
                ),
            )
            .with_hint(TRANSFER_ENGINE_HINT));
        }
        Ok(())
    }

    /// Take an entry's staged plaintext.
    fn take_staged(&self, key: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.staged
            .lock()
            .map_err(|_| CliError::new(ExitCode::FatalError, "internal: staging lock poisoned"))?
            .remove(key)
            .ok_or_else(|| {
                CliError::new(
                    ExitCode::FatalError,
                    format!("internal: no staged content for '{key}'"),
                )
            })
    }

    fn put_staged(&self, key: &str, bytes: Zeroizing<Vec<u8>>) -> Result<()> {
        self.staged
            .lock()
            .map_err(|_| CliError::new(ExitCode::FatalError, "internal: staging lock poisoned"))?
            .insert(key.to_string(), bytes);
        Ok(())
    }
}

impl StageDriver for Engine {
    /// Step 1 — obtain the plaintext.
    ///
    /// For an upload that means reading the source file; for a download it means
    /// fetching and authenticating the object, which `Vault::get_file` does
    /// together (a failed tag is an error, never returned data).
    async fn read(&self, entry: &PlanEntry) -> Result<()> {
        self.check_size(entry)?;

        let bytes = match self.direction {
            Direction::Upload | Direction::LocalOnly => {
                let path = self.source_path(&entry.source);
                Zeroizing::new(tokio::fs::read(&path).await.map_err(|error| {
                    CliError::from(error).with_hint(format!("reading source {}", path.display()))
                })?)
            }
            Direction::Download => self.vault()?.get_file(&entry.source).await?,
        };

        self.put_staged(&entry.dest, bytes)
    }

    /// Step 2 — sealing.
    ///
    /// `Vault::put_file` seals as part of its single verified-write operation,
    /// so there is nothing to do here and nothing is claimed. The stage remains
    /// because it is a real position in the pipeline the display reports, and
    /// because it is where the seal moves to when the streaming API lands.
    async fn encrypt(&self, _entry: &PlanEntry) -> Result<()> {
        Ok(())
    }

    /// Steps 3–6 — the verified write and the durable commit.
    ///
    /// These are one operation in `dctl-core`, and that is a stronger guarantee
    /// than performing them separately: there is no window in which bytes are
    /// stored but uncommitted.
    async fn upload(&self, entry: &PlanEntry) -> Result<u64> {
        let bytes = self.take_staged(&entry.dest)?;
        let written = bytes.len() as u64;

        match self.direction {
            Direction::Upload => {
                self.vault()?.put_file(&entry.dest, &bytes).await?;
            }
            Direction::Download | Direction::LocalOnly => {
                let path = self.dest_path(&entry.dest);
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                write_durably(&path, &bytes).await?;
            }
        }

        Ok(written)
    }

    /// Steps 4–5 — the extra assurance `--verify` asked for.
    ///
    /// The provider-checksum comparison already happened inside the verified
    /// write, so `checksum` has nothing further to do. The deeper modes read the
    /// object back and re-authenticate it, which is the egress cost `PLAN.md`
    /// §12 says must be opt-in.
    async fn verify(&self, entry: &PlanEntry, mode: VerifyMode) -> Result<()> {
        match (mode, self.direction) {
            (VerifyMode::Checksum, _) | (_, Direction::LocalOnly) => Ok(()),
            (VerifyMode::Sample | VerifyMode::Strict, Direction::Upload) => {
                self.vault()?.verify_file(&entry.dest).await.map_err(|_| {
                    CliError::new(
                        ExitCode::IntegrityFailure,
                        format!("read-back verification failed for '{}'", entry.dest),
                    )
                    .with_hint(
                        "The object did not authenticate when read back. It was \
                         written but must not be trusted; investigate before \
                         deleting any source.",
                    )
                })
            }
            (VerifyMode::Sample | VerifyMode::Strict, Direction::Download) => {
                // Confirm what landed on disk matches what was decrypted.
                let path = self.dest_path(&entry.dest);
                let written = tokio::fs::read(&path).await?;
                let expected = self.vault()?.get_file(&entry.source).await?;
                if ContentHash::blake3(&written) != ContentHash::blake3(&expected) {
                    return Err(CliError::new(
                        ExitCode::IntegrityFailure,
                        format!("written file does not match the vault: {}", path.display()),
                    ));
                }
                Ok(())
            }
        }
    }

    /// Step 6 — confirm the durable commit.
    ///
    /// Already performed inside [`StageDriver::upload`]. Returning `Ok` here is
    /// still what marks the file stored, so the contract above this file is
    /// unchanged; the work simply happened one stage earlier.
    async fn commit(&self, _entry: &PlanEntry) -> Result<()> {
        Ok(())
    }

    /// Recreate an empty source directory (`--create-empty-src-dirs`).
    ///
    /// Only meaningful on a filesystem destination. A vault has no directories:
    /// an empty one holds no objects and therefore has nothing to store.
    async fn create_dir(&self, entry: &PlanEntry) -> Result<()> {
        match self.direction {
            Direction::Download | Direction::LocalOnly => {
                tokio::fs::create_dir_all(self.dest_path(&entry.dest)).await?;
                Ok(())
            }
            Direction::Upload => Ok(()),
        }
    }
}

impl Reaper for Engine {
    /// Remove something that already exists.
    ///
    /// Which side is decided at connect time by [`ReapTarget`], never per call,
    /// so a reaper wired for the destination can never be handed a source path.
    async fn remove(&self, path: &str) -> Result<()> {
        let from_local = match (self.direction, self.reap_target) {
            // `move` deletes the source; `sync` deletes destination extras.
            (Direction::Upload, ReapTarget::Source) => true,
            (Direction::Upload, ReapTarget::Destination) => false,
            (Direction::Download, ReapTarget::Source) => false,
            (Direction::Download, ReapTarget::Destination) => true,
            (Direction::LocalOnly, _) => true,
        };

        if from_local {
            // A reaper deleting from the source resolves against the source
            // root; one deleting destination extras resolves against the
            // destination root. Using either for both is how `sync` deletes out
            // of the wrong tree.
            let full = match self.reap_target {
                ReapTarget::Source => self.source_path(path),
                ReapTarget::Destination => self.dest_path(path),
            };
            match tokio::fs::remove_file(&full).await {
                Ok(()) => Ok(()),
                // Already gone is the outcome we wanted.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(CliError::from(error)),
            }
        } else {
            self.vault()?.delete_file(path).await?;
            Ok(())
        }
    }

    fn target(&self) -> &'static str {
        self.reap_target.label()
    }
}

/// Write a file and make both the data *and its name* durable before returning.
///
/// Staging then renaming, rather than truncating in place, and syncing the
/// containing directory afterwards. Every step is load-bearing:
///
/// * Writing into a staging file means a crash mid-write cannot leave a
///   half-written file under the destination's name. The destination either has
///   its old contents or its new ones.
/// * `sync_all` puts the bytes on stable storage before any name points at them,
///   so a crash cannot produce a complete-looking file full of zeroes.
/// * `rename` publishes atomically.
/// * **Syncing the parent directory** is what makes the rename itself durable.
///   POSIX does not guarantee a rename survives a power cut until the containing
///   directory is synced, and this is the step that matters most to `move`: data
///   fsynced, source deleted, power lost before the directory entry lands, and
///   the file is gone from both sides.
///
/// This mirrors `crate::commands::rcat::local`, which already does it correctly.
async fn write_durably(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;

    let staging = staging_path(path);

    {
        let mut file = tokio::fs::File::create(&staging).await?;
        if let Err(error) = file.write_all(bytes).await {
            let _ = tokio::fs::remove_file(&staging).await;
            return Err(error.into());
        }
        file.sync_all().await?;
    }

    if let Err(error) = tokio::fs::rename(&staging, path).await {
        let _ = tokio::fs::remove_file(&staging).await;
        return Err(error.into());
    }

    sync_parent_directory(path).await
}

/// A staging path beside the destination, on the same filesystem so the rename
/// is atomic. The pid and a counter keep concurrent writers apart.
fn staging_path(dest: &std::path::Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);

    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let name = dest.file_name().map_or_else(
        || std::ffi::OsString::from("object"),
        std::ffi::OsStr::to_os_string,
    );
    let mut staged = name;
    staged.push(format!("{LOCAL_STAGING_SUFFIX}.{pid}.{seq}"));

    dest.parent()
        .map_or_else(|| PathBuf::from(&staged), |parent| parent.join(&staged))
}

/// Sync the directory containing `path`, so a rename into it is durable.
///
/// A directory cannot be opened for writing, so this opens it read-only and
/// syncs that handle — the portable way to flush a directory entry. On Windows
/// directories cannot be synced this way at all and the call is skipped: NTFS
/// makes the metadata update durable with the data, so there is nothing to force.
async fn sync_parent_directory(path: &std::path::Path) -> Result<()> {
    if cfg!(target_os = "windows") {
        return Ok(());
    }
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let parent = if parent.as_os_str().is_empty() {
        std::path::Path::new(".")
    } else {
        parent
    };

    let dir = tokio::fs::File::open(parent).await?;
    dir.sync_all().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::transfer::plan::Op;

    fn entry(source: &str, dest: &str, size: u64) -> PlanEntry {
        PlanEntry {
            action: Op::Copy,
            source: source.to_string(),
            dest: dest.to_string(),
            size,
            reason: "test",
        }
    }

    fn engine(direction: Direction, root: PathBuf) -> Engine {
        Engine {
            direction,
            session: None,
            source_root: root.clone(),
            dest_root: root,
            reap_target: ReapTarget::Source,
            staged: Mutex::new(HashMap::new()),
        }
    }

    /// An engine whose two sides are genuinely different directories — the
    /// arrangement that a single shared root would silently get wrong.
    fn split_engine(source: PathBuf, dest: PathBuf) -> Engine {
        Engine {
            direction: Direction::LocalOnly,
            session: None,
            source_root: source,
            dest_root: dest,
            reap_target: ReapTarget::Source,
            staged: Mutex::new(HashMap::new()),
        }
    }

    #[test]
    fn reap_targets_are_distinct_and_named() {
        // Deleting from the wrong side is the worst bug this family can have, so
        // the two are a type rather than two spellings of a string.
        assert_ne!(ReapTarget::Source.label(), ReapTarget::Destination.label());
        assert_eq!(ReapTarget::Source.label(), "source");
    }

    #[test]
    fn oversized_files_are_refused_before_being_attempted() {
        let engine = engine(Direction::Upload, PathBuf::from("/tmp"));
        let error = engine
            .check_size(&entry("big.mkv", "big.mkv", TRANSFER_WHOLE_FILE_LIMIT + 1))
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("whole-file limit"));
        assert!(error.hint().is_some());
    }

    #[test]
    fn files_within_the_limit_are_accepted() {
        let engine = engine(Direction::Upload, PathBuf::from("/tmp"));
        assert!(engine.check_size(&entry("a", "a", 1024)).is_ok());
    }

    #[test]
    fn staged_content_is_removed_once_consumed() {
        // Plaintext must not outlive the stage that needs it.
        let engine = engine(Direction::Upload, PathBuf::from("/tmp"));
        engine
            .put_staged("a.txt", Zeroizing::new(b"hello".to_vec()))
            .unwrap();
        assert_eq!(engine.take_staged("a.txt").unwrap().as_slice(), b"hello");
        assert!(engine.take_staged("a.txt").is_err(), "taken twice");
    }

    #[test]
    fn local_paths_are_built_from_logical_ones() {
        let engine = engine(Direction::Upload, PathBuf::from("/srv/data"));
        let path = engine.source_path("photos/2024/a.jpg");
        assert!(path.ends_with(std::path::Path::new("photos").join("2024").join("a.jpg")));
    }

    #[tokio::test]
    async fn the_destination_resolves_against_its_own_root() {
        // The regression this split exists to prevent: with one shared root the
        // destination is written *inside the source directory*, and every
        // filesystem-to-filesystem copy silently lands in the wrong tree.
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a.txt"), b"payload").unwrap();

        let engine = split_engine(src.path().to_path_buf(), dst.path().to_path_buf());
        let entry = entry("a.txt", "a.txt", 7);
        engine.read(&entry).await.unwrap();
        engine.upload(&entry).await.unwrap();

        assert!(dst.path().join("a.txt").exists(), "wrote to the dest root");
        assert!(
            !src.path().join("a.txt.tmp").exists() && src.path().read_dir().unwrap().count() == 1,
            "the source directory must gain nothing"
        );
    }

    #[tokio::test]
    async fn a_local_round_trip_moves_real_bytes() {
        // The regression this whole file exists to prevent: the engine must
        // actually move data, not describe moving it.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("in.txt"), b"real bytes").unwrap();

        let engine = engine(Direction::LocalOnly, dir.path().to_path_buf());
        let entry = entry("in.txt", "out.txt", 10);

        engine.read(&entry).await.unwrap();
        engine.encrypt(&entry).await.unwrap();
        let written = engine.upload(&entry).await.unwrap();
        engine.commit(&entry).await.unwrap();

        assert_eq!(written, 10);
        assert_eq!(
            std::fs::read(dir.path().join("out.txt")).unwrap(),
            b"real bytes"
        );
    }

    #[tokio::test]
    async fn a_missing_source_is_reported_with_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine(Direction::LocalOnly, dir.path().to_path_buf());
        let error = engine.read(&entry("absent.txt", "x", 1)).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FileNotFound);
        assert!(error.hint().is_some_and(|h| h.contains("absent.txt")));
    }

    #[tokio::test]
    async fn a_vault_directory_is_recognised_without_unlocking_it() {
        // The refusal happens at connect time, before a password is asked for:
        // `--no-ask-password` would turn a prompt into VaultLocked, and the code
        // below proves the guard answered first.
        let src = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ctx = crate::commands::transfer::testing::ctx(&[]);
        let source = RemoteSpec::parse(src.path().to_str().unwrap()).unwrap();
        let dest = RemoteSpec::parse(dir.path().to_str().unwrap()).unwrap();

        assert!(
            Engine::connect(&ctx, "copy", &source, &dest).await.is_ok(),
            "an empty directory is not a vault"
        );

        let envelope = dir.path().join("system").join("envelope.bin");
        std::fs::create_dir_all(envelope.parent().unwrap()).unwrap();
        std::fs::write(&envelope, b"DKE1").unwrap();

        let error = Engine::connect(&ctx, "copy", &source, &dest)
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
    }

    #[tokio::test]
    async fn a_vault_is_recognised_from_any_depth_beneath_it() {
        // S3: checking only the destination directory meant naming any
        // subdirectory defeated the guard entirely — `copy ./src ./vault` was
        // refused while `copy ./src ./vault/photos` wrote plaintext into the
        // vault and reported success. The rule is config-derived now; the
        // subdirectory bypass must still be closed.
        let src = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("system")).unwrap();
        std::fs::write(dir.path().join("system/envelope.bin"), b"DKE1").unwrap();

        let deep = dir.path().join("photos").join("2024").join("raw");
        std::fs::create_dir_all(&deep).unwrap();

        let ctx = crate::commands::transfer::testing::ctx(&[]);
        let source = RemoteSpec::parse(src.path().to_str().unwrap()).unwrap();

        for typed in [
            dir.path().to_path_buf(),
            dir.path().join("photos"),
            deep.clone(),
        ] {
            let dest = RemoteSpec::parse(typed.to_str().unwrap()).unwrap();
            assert!(
                Engine::connect(&ctx, "copy", &source, &dest).await.is_err(),
                "a write to {} must be refused",
                typed.display()
            );
        }
    }

    #[tokio::test]
    async fn a_sibling_of_a_vault_is_not_a_vault() {
        // The guard must not spread to unrelated directories that merely share
        // a parent with a vault.
        let src = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("vault/system")).unwrap();
        std::fs::write(dir.path().join("vault/system/envelope.bin"), b"DKE1").unwrap();
        let sibling = dir.path().join("ordinary");
        std::fs::create_dir_all(&sibling).unwrap();

        let ctx = crate::commands::transfer::testing::ctx(&[]);
        let source = RemoteSpec::parse(src.path().to_str().unwrap()).unwrap();
        let dest = RemoteSpec::parse(sibling.to_str().unwrap()).unwrap();
        assert!(Engine::connect(&ctx, "copy", &source, &dest).await.is_ok());
    }

    /// The pair `dctl init --name archive --base local:<path>` registers.
    fn initialised_at(path: &std::path::Path) -> crate::config::Config {
        use crate::config::{Config, LocalDef, RemoteDef, VaultDef};

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

    #[tokio::test]
    async fn a_configured_store_is_refused_with_nothing_written_in_it_yet() {
        // Invariant I4, at this seam: the destination directory is empty — no
        // envelope, nothing — and the refusal still fires, because the rule is
        // derived from the configuration rather than from the directory's
        // current contents. The same command is refused today and tomorrow.
        let src = tempfile::tempdir().unwrap();
        let store = tempfile::tempdir().unwrap();
        let (_config_dir, ctx) =
            crate::commands::transfer::testing::ctx_with_config(&initialised_at(store.path()));

        let source = RemoteSpec::parse(src.path().to_str().unwrap()).unwrap();
        let dest = RemoteSpec::parse(store.path().to_str().unwrap()).unwrap();

        let error = Engine::connect(&ctx, "copy", &source, &dest)
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error
                .message()
                .contains("object store for remote 'archive'"),
            "the refusal must name the remote to use instead: {}",
            error.message()
        );
        assert!(error.hint().is_some_and(|hint| hint.contains("archive:")));
    }

    #[tokio::test]
    async fn a_subdirectory_of_a_configured_store_is_refused_too() {
        // `vault/photos` again, this time against the configuration.
        let src = tempfile::tempdir().unwrap();
        let store = tempfile::tempdir().unwrap();
        let (_config_dir, ctx) =
            crate::commands::transfer::testing::ctx_with_config(&initialised_at(store.path()));

        let source = RemoteSpec::parse(src.path().to_str().unwrap()).unwrap();
        let inside = store.path().join("photos");
        let dest = RemoteSpec::parse(inside.to_str().unwrap()).unwrap();

        let error = Engine::connect(&ctx, "copy", &source, &dest)
            .await
            .unwrap_err();
        assert!(
            error
                .message()
                .contains(&store.path().display().to_string()),
            "the configured root is what the operator needs named: {}",
            error.message()
        );
    }

    #[tokio::test]
    async fn the_object_view_is_refused_when_it_is_typed_by_name() {
        // `dctl copy ./photos archive-store:` — foreign plaintext into a vault's
        // object tree. Refused by name, with no password asked for.
        let src = tempfile::tempdir().unwrap();
        let store = tempfile::tempdir().unwrap();
        let (_config_dir, ctx) =
            crate::commands::transfer::testing::ctx_with_config(&initialised_at(store.path()));

        let source = RemoteSpec::parse(src.path().to_str().unwrap()).unwrap();
        let dest = RemoteSpec::parse("archive-store:").unwrap();

        let error = Engine::connect(&ctx, "copy", &source, &dest)
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains("archive-store"),
            "got: {}",
            error.message()
        );
        assert!(error.hint().is_some_and(|hint| hint.contains("archive:")));
    }

    #[tokio::test]
    async fn the_sealed_view_is_not_refused_by_the_namespace_rule() {
        // Invariant I1: a write through `archive:` is sealed, so it must get
        // past this rule. It still fails further down — the session resolves
        // against the empty catalogue, so a configured remote is reported as
        // unknown — but it must not fail *here*, or the vault would be
        // unaddressable.
        let src = tempfile::tempdir().unwrap();
        let store = tempfile::tempdir().unwrap();
        let (_config_dir, ctx) =
            crate::commands::transfer::testing::ctx_with_config(&initialised_at(store.path()));

        let source = RemoteSpec::parse(src.path().to_str().unwrap()).unwrap();
        let dest = RemoteSpec::parse("archive:photos").unwrap();

        let error = Engine::connect(&ctx, "copy", &source, &dest)
            .await
            .unwrap_err();
        assert!(
            !error.message().contains("object store"),
            "the sealed view must not be mistaken for its own store: {}",
            error.message()
        );
    }

    #[tokio::test]
    async fn an_envelope_is_never_enough_to_switch_a_command_into_sealed_mode() {
        // The inference invariant I4 forbids, asserted as an absence: a bare
        // path holding a vault is *refused*, never quietly encrypted. Nothing
        // may be written into the vault directory by the attempt.
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a.txt"), b"payload").unwrap();
        let vault = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(vault.path().join("system")).unwrap();
        std::fs::write(vault.path().join("system/envelope.bin"), b"DKE1").unwrap();

        let ctx = crate::commands::transfer::testing::ctx(&[]);
        let source = RemoteSpec::parse(src.path().to_str().unwrap()).unwrap();
        let dest = RemoteSpec::parse(vault.path().to_str().unwrap()).unwrap();

        assert!(Engine::connect(&ctx, "copy", &source, &dest).await.is_err());
        assert!(
            !vault.path().join("a.txt").exists(),
            "nothing may be written, sealed or otherwise"
        );
    }

    #[tokio::test]
    async fn a_durable_write_leaves_no_staging_file_behind() {
        // S7: the write stages then renames, so a crash cannot publish a
        // half-written file under the destination's name. Nothing may survive
        // in the directory except the destination itself.
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out.bin");
        write_durably(&dest, b"durable payload").await.unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"durable payload");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name != "out.bin")
            .collect();
        assert!(
            leftovers.is_empty(),
            "staging files left behind: {leftovers:?}"
        );
    }

    #[tokio::test]
    async fn a_durable_write_replaces_existing_contents_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out.bin");
        std::fs::write(&dest, b"old contents that are longer").unwrap();

        write_durably(&dest, b"new").await.unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
    }

    #[test]
    fn an_empty_root_is_never_a_vault() {
        // Upload has no destination root; the check must not stat "", and must
        // not resolve it to the process's working directory.
        let ctx = crate::commands::transfer::testing::ctx(&[]);
        assert!(crate::addressing::refuse_plain_write_to_path(&ctx, &PathBuf::new()).is_ok());
    }

    #[tokio::test]
    async fn a_plain_copy_into_a_vault_is_refused() {
        // The defect this guard exists for: without it, `dctl copy x local:VAULT`
        // writes the plaintext next to the envelope and reports success.
        let src = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(vault.path().join("system")).unwrap();
        std::fs::write(vault.path().join("system/envelope.bin"), b"DKE1").unwrap();

        let ctx = crate::commands::transfer::testing::ctx(&[]);
        let source = RemoteSpec::parse(src.path().to_str().unwrap()).unwrap();
        let dest = RemoteSpec::parse(vault.path().to_str().unwrap()).unwrap();

        let error = Engine::connect(&ctx, "copy", &source, &dest)
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains("plaintext"),
            "the refusal must name the risk: {}",
            error.message()
        );
        assert!(error.hint().is_some_and(|h| h.contains("vault remote")));
    }

    #[tokio::test]
    async fn an_ordinary_directory_is_still_copyable() {
        // The guard must not make normal filesystem copies fail.
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let ctx = crate::commands::transfer::testing::ctx(&[]);
        let source = RemoteSpec::parse(src.path().to_str().unwrap()).unwrap();
        let dest = RemoteSpec::parse(dst.path().to_str().unwrap()).unwrap();
        assert!(Engine::connect(&ctx, "copy", &source, &dest).await.is_ok());
    }

    #[tokio::test]
    async fn an_unconfigured_remote_is_refused_rather_than_becoming_a_directory() {
        // S6, at the seam where it was introduced. `Engine::build` used to hand
        // `session::open` the remote's *name*, which was re-parsed as a spec —
        // and a name carries no colon, so it fell through to a relative path. A
        // remote nobody configured therefore became a directory of that name,
        // and the transfer into it reported success.
        //
        // `--no-ask-password` is what pins the ordering. If the spec still
        // resolved to a directory, the run would reach the password step and
        // fail with VaultLocked instead of naming the remote.
        let src = tempfile::tempdir().unwrap();
        let ctx = crate::commands::transfer::testing::ctx(&["--no-ask-password"]);
        let source = RemoteSpec::parse(src.path().to_str().unwrap()).unwrap();
        let dest = RemoteSpec::parse("vault:photos").unwrap();

        let error = Engine::connect(&ctx, "copy", &source, &dest)
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains("vault"),
            "the refusal must name the remote: {}",
            error.message()
        );
        assert!(
            error
                .hint()
                .is_some_and(|hint| hint.contains("config list")),
            "the refusal must say where configured remotes live"
        );
    }

    #[tokio::test]
    async fn the_path_half_of_a_named_destination_reaches_the_resolver() {
        // The other half of S6: `b2:mybucket` lost its bucket entirely, because
        // only the name was passed down. Asserted through the bucketless
        // shorthand, which is the one diagnosis that can *only* come from the
        // resolver having seen the path portion — and which needs no credentials
        // in the environment to reach.
        let src = tempfile::tempdir().unwrap();
        let ctx = crate::commands::transfer::testing::ctx(&["--no-ask-password"]);
        let source = RemoteSpec::parse(src.path().to_str().unwrap()).unwrap();
        let dest = RemoteSpec::parse("b2:").unwrap();

        let error = Engine::connect(&ctx, "copy", &source, &dest)
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains("bucket"),
            "the spec's path portion must have been read: {}",
            error.message()
        );
        assert!(error.hint().is_some_and(|hint| hint.contains("BUCKET")));
    }

    #[tokio::test]
    async fn removing_something_already_gone_succeeds() {
        // Idempotence: a retried `move` must not fail because the first attempt
        // already removed the source.
        let dir = tempfile::tempdir().unwrap();
        let engine = engine(Direction::LocalOnly, dir.path().to_path_buf());
        assert!(engine.remove("never-existed.txt").await.is_ok());
    }

    #[tokio::test]
    async fn nested_destinations_get_their_directories() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("in.txt"), b"x").unwrap();

        let engine = engine(Direction::LocalOnly, dir.path().to_path_buf());
        let entry = entry("in.txt", "a/b/c/out.txt", 1);
        engine.read(&entry).await.unwrap();
        engine.upload(&entry).await.unwrap();

        assert!(dir.path().join("a/b/c/out.txt").exists());
    }
}
