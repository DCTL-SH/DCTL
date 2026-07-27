//! The binding between the transfer commands and the two things that store
//! bytes: `dctl-core`'s [`Vault`](dctl_core::Vault), and a plain remote's
//! [`Backend`](dctl_store::Backend).
//!
//! Everything above this file decides *what* to do: specs are parsed, both sides
//! enumerated, the plan diffed, filtered, printed and guarded. This file does
//! it.
//!
//! ## Which of the two, and how that is decided
//!
//! From the **configuration**, through [`Place`], which answers it from
//! [`RemoteDef::is_vault`](crate::config::RemoteDef::is_vault) — the same
//! predicate [`crate::source`] asks on the read side. It is emphatically *not*
//! decided from the shape of the argument, and that distinction is the whole of
//! defect D4: this file used to read `(Local, Named) => Upload` and open a vault
//! session for **any** named destination, so `dctl config create backup local
//! path=/mnt/backup` followed by `dctl copy ./src backup:` demanded a vault
//! password for a remote that has no key, failed at exit 22, and wrote nothing.
//! Invariant I3 — "a write to an ordinary location is plaintext, and that is
//! fully supported" — was unreachable for every plain remote a user creates.
//!
//! Two spellings of one question is how that happened, so there is now one:
//! `Place::of`. A direction added later cannot re-answer it from a `match` on
//! spec shapes, because the shape no longer carries the answer.
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
//! ## The plain path, and why it goes through the backend
//!
//! An ordinary remote stores ordinary bytes, so a transfer into one is a
//! [`Backend::put`](dctl_store::Backend::put) under the prefix the user named
//! ([`PlainRemote`]) and nothing else — no envelope, no index, no password. The
//! verified-write contract still holds, and holds for free: `put` is required
//! not to report success unless the store holds the bytes it was given, and to
//! commit nothing on a mismatch.
//!
//! **Every** ordinary remote, including a bucket. `dctl copy ./src b2:mybucket`
//! writes plain objects through the same `PlainRemote` a `local:` remote uses,
//! because the difference between them is a `Backend` implementation and the
//! trait exists so that nothing above it has to know which one it holds. There
//! used to be a refusal here instead ("this build has no plain object write
//! path"), and it was not describing missing work: the write, the key mapping,
//! the prefix, the deletion and the read-back verification were all already
//! written and already exercised — against `LocalFs`, which is the same trait.
//!
//! What is *not* claimed: no run of this code has been made against live B2, S3
//! or R2 credentials. What backs it is that the provider `put` implementations
//! are the same ones every sealed vault write to those providers already uses,
//! and that nothing on this path is provider-specific. See
//! `docs/commands/dctl_copy.md` for the one behavioural consequence a user meets
//! — a plain destination stamps its own write time, so the default comparison
//! re-transfers.
//!
//! `mkdir`, `touch` and `rcat` reach a plain remote through the same
//! *classification* and then write through the filesystem path `Place` hands
//! back, which is right for them: they address one object a user named. A
//! transfer cannot, and the reason is the diff. Its destination was
//! **enumerated** through the backend's key space ([`super::listing`]), so an
//! object written under any other key mapping would be invisible to the next
//! run — which would copy it again, and again, reporting success every time. The
//! two commands agree on which remotes are sealed, which is the part that must
//! never diverge; they differ on how bytes get there, which is the part their
//! jobs genuinely differ on.
//!
//! ## What is genuinely refused
//!
//! Vault-to-vault transfers need two unlocked vaults and a re-encrypting path
//! that `dctl-core` does not expose. That is refused, loudly, at connect time —
//! before a single file is attempted. So is remote-to-remote between two *plain*
//! stores, which needs no re-encryption at all and is refused for its own,
//! different reason: nothing here holds two backends at once. The two refusals
//! say which is which, because "not yet built" and "cannot be built without
//! crypto support" are different waits.
//!
//! A plaintext write into a vault's object namespace is refused too, and that
//! decision is not made here: [`crate::addressing`] owns it, because `rcat` reaches the
//! filesystem by a completely different route and has to reach the same answer.
//! What matters at this seam is *which* address is checked — the destination,
//! whichever side it is on — and that the check runs before the vault is opened,
//! so a refusal costs no password prompt.
//!
//! ## What addressing does *not* do yet
//!
//! Recorded here rather than left for a user to discover, because the gap puts
//! objects somewhere other than the spec reads — and it now applies to **one of
//! the two paths only**, which is the more confusing state of the two to be left
//! guessing about.
//!
//! [`Engine::build`] hands [`session::open()`] the destination's whole
//! [`RemoteSpec`], so the provider and its container are both honoured and an
//! unconfigured name is a hard failure. For a **sealed** destination the logical
//! path inside the remote is still dropped: `copy ./src archive:photos` unlocks
//! the right vault, but an entry's plan-relative path becomes its key at the
//! vault's root, so it stores `a.txt` rather than `photos/a.txt`.
//!
//! Closing that needs the [`Resolved`](crate::remote::resolve::Resolved) remote,
//! not just the spec, to survive into [`Session`] and prefix every key — a
//! change to what a session carries rather than to the engine's own logic.
//! `docs/commands/dctl_copy.md` states the current behaviour plainly so nobody
//! plans a backup around the intended one.
//!
//! The **plain** path does not have that gap: [`PlainRemote`] keeps its
//! `Resolved` and prefixes every key, so `copy ./src backup:photos` stores
//! `photos/a.txt`. That is not a refinement, it is a requirement — the same
//! prefix is what the destination listing was taken under.
//!
//! ## Memory
//!
//! `Vault::put_file`, `get_file` and `Backend::put` take and return whole
//! buffers, so one file's contents are resident while it moves. Files above
//! [`WHOLE_FILE_LIMIT`](crate::constants::TRANSFER_WHOLE_FILE_LIMIT) are refused
//! rather than attempted: a 50 GB video would otherwise take the machine down,
//! and `PLAN.md` §16.2 is explicit that memory must stay O(concurrency). The
//! limit disappears when the streaming engine lands.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use dctl_core::Modified;
use dctl_store::ContentHash;
use zeroize::Zeroizing;

use crate::addressing;
use crate::audit::record::Direction as AuditDirection;
use crate::cli::VerifyMode;
use crate::commands::pipeline::command_name;
use crate::constants::{
    REMOTE_SEPARATOR, TRANSFER_ENGINE_HINT, TRANSFER_REMOTE_TO_REMOTE_FEATURE,
    TRANSFER_REMOTE_TO_REMOTE_HINT, TRANSFER_SEALED_REMOTE_TO_REMOTE_FEATURE,
    TRANSFER_SEALED_REMOTE_TO_REMOTE_HINT, TRANSFER_WHOLE_FILE_LIMIT,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::platform::path as logical;
use crate::remote::{Place, PlainRemote, RemoteSpec};
use crate::session::{self, Session};

use super::pipeline::{Reaper, StageDriver};
use super::plan::PlanEntry;
use super::staged::Staged;

/// Which way bytes move, and what stands at each end.
///
/// The two remote ends are separate variants rather than one "remote" variant
/// plus a flag, because every method below has to do genuinely different work
/// for them — seal or store, unlock or connect — and a `match` that is missing
/// an arm is a compile error, while a forgotten `if sealed` is a run that
/// encrypts something it was asked to store plainly, or the reverse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Local filesystem into a vault: seal, verified write, index commit.
    Upload,
    /// Vault out to the local filesystem: fetch, authenticate, write.
    Download,
    /// Local filesystem into a plain remote: a verified `Backend::put`, and no
    /// key anywhere in the path.
    PlainUpload,
    /// A plain remote out to the local filesystem: fetch the object as stored,
    /// write it durably.
    PlainDownload,
    /// Filesystem to filesystem, with no remote involved on either side.
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
    /// The unlocked vault, for whichever side is a vault. `None` whenever
    /// neither side is one.
    session: Option<Session>,
    /// The connected backend, for whichever side is a plain remote. `None`
    /// whenever neither side is one.
    ///
    /// Never `Some` at the same time as [`Engine::session`] in this build:
    /// remote-to-remote is refused, so at most one end is a remote. That is a
    /// property of the refusal rather than of these two fields, which is why
    /// each direction still names the one it uses.
    plain: Option<PlainRemote>,
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
    /// Logical prefix inside the vault that the sealed side addresses.
    ///
    /// The counterpart of [`Engine::dest_root`] for a sealed remote, and its
    /// absence was silent data loss. A [`Session`] carries the remote name but
    /// not the path, so `archive:site-a` and `archive:site-b` both resolved to
    /// the vault root: two copies to what look like different destinations
    /// collided, and the second **overwrote** the first while reporting
    /// `Files: 1 / 1, Errors: 0` and exiting 0.
    ///
    /// `PlainRemote` never had the bug because it keeps the prefix its spec was
    /// built from. The sealed path needed the same thing, and now has it —
    /// joined at every vault call rather than at some of them, since a prefix
    /// applied on write but not on read would be a subtler version of the same
    /// defect.
    vault_prefix: String,
    /// Which side this engine's reaper deletes from.
    reap_target: ReapTarget,
    /// Files in flight, keyed by the entry's destination path.
    ///
    /// The stage trait takes `&self`, and a file's contents have to survive from
    /// `read` to `upload`, so they live here rather than in a local. Entries are
    /// removed as soon as they are consumed: holding a file's plaintext one
    /// stage longer than necessary is exactly the kind of lifetime a crypto tool
    /// should not have.
    ///
    /// A [`Staged`] rather than the bytes alone, because the source's
    /// modification time has to make the same journey — see that module for what
    /// went wrong while it did not.
    staged: Mutex<HashMap<String, Staged>>,
    /// BLAKE3 of each entry's plaintext, keyed by destination path, waiting to
    /// be put in that file's audit record.
    ///
    /// Computed in [`StageDriver::upload`], where the bytes are already in hand,
    /// and taken by [`StageDriver::take_plaintext_hash`] once the file is
    /// finished. A digest is not plaintext and holds no key, so unlike
    /// [`Engine::staged`] it does not need wiping — but it is still removed on
    /// read, because a map that only grows is a memory leak on a
    /// ten-million-file run.
    hashes: Mutex<HashMap<String, String>>,
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
            .field("plain", &self.plain)
            .field("staged_files", &staged.unwrap_or_default())
            .finish()
    }
}

impl Engine {
    /// Connect the engine for one command.
    ///
    /// # Errors
    /// [`ExitCode::FatalError`] when both sides are remotes (unsupported), when
    /// the destination is an object store this build cannot write plainly, when
    /// a remote is unknown or incompletely configured, or when a vault cannot be
    /// opened; [`ExitCode::VaultLocked`] when a **sealed** side needs a password
    /// and none is available. A plain remote never reaches that last one: there
    /// is no key to unwrap, so `--no-ask-password` is not a limitation on it.
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
        // First, and before anything is classified or connected: whether this
        // transfer may write plaintext is a question about the **destination's
        // address**, and it is asked of the destination spec rather than of the
        // direction, so a direction added later cannot slip past by not being
        // listed in a `match` here.
        //
        // Asked a second time, deliberately. `super::prepare` already asked, so
        // that a `--dry-run` rehearses the refusal instead of printing a plan
        // the real run would reject. This one is the *write path's* own guard and
        // stays regardless: an engine is reachable from any caller that builds
        // one, and a rule enforced only by the caller that happens to run first
        // is a rule that a new caller silently opts out of.
        //
        // Asked before anything is opened, so a refusal costs no password prompt
        // and no credential — and answered from the configuration, so it is the
        // same answer whatever the destination currently holds. It is also the
        // *most* specific diagnosis available for a vault's object store, which
        // is why it outranks the classification below: `archive-store:` is a
        // perfectly ordinary local remote as far as `Place` is concerned, and
        // "writable" is the wrong thing to tell someone about it.
        addressing::refuse_plain_write(ctx, dest)?;

        // The remote spec passed on below is the **whole spec** of whichever
        // side is a remote, never its name. Passing the name alone is what S6
        // was: it was re-parsed, found no colon in `b2`, and produced a relative
        // directory — so `copy ./src b2:mybucket` unlocked a vault in `./b2`,
        // threw the bucket away, and reported success. A `RemoteSpec` has
        // already been classified and cannot be reclassified downstream.
        let (direction, source_root, dest_root, vault_spec, plain_spec) = match (source, dest) {
            (RemoteSpec::Local(from), RemoteSpec::Named { .. }) => {
                // D4: sealed or not is asked of the *configuration*, not of the
                // fact that this argument has a colon in it.
                let place = Place::of(ctx, dest)?;
                // Which end holds the destination follows from the direction and
                // is not decided a second time: a sealed write goes through the
                // vault session, and every other write through the backend.
                let direction = upload_direction(&place);
                let sealed = direction == Direction::Upload;
                (
                    direction,
                    from.clone(),
                    PathBuf::new(),
                    sealed.then_some(dest),
                    (!sealed).then_some(dest),
                )
            }
            (RemoteSpec::Named { .. }, RemoteSpec::Local(to)) => {
                // A read, so the sealed question is the only one there is: a
                // plain object store is a legitimate thing to copy *from*, and
                // has been for as long as it has been a legitimate thing to
                // list.
                if Place::of(ctx, source)? == Place::Sealed {
                    (
                        Direction::Download,
                        PathBuf::new(),
                        to.clone(),
                        Some(source),
                        None,
                    )
                } else {
                    (
                        Direction::PlainDownload,
                        PathBuf::new(),
                        to.clone(),
                        None,
                        Some(source),
                    )
                }
            }
            (RemoteSpec::Local(from), RemoteSpec::Local(to)) => {
                (Direction::LocalOnly, from.clone(), to.clone(), None, None)
            }
            (RemoteSpec::Named { .. }, RemoteSpec::Named { .. }) => {
                let sealed = Place::of(ctx, source)? == Place::Sealed
                    || Place::of(ctx, dest)? == Place::Sealed;
                return Err(refuse_remote_to_remote(command, sealed));
            }
        };

        // Taken from the spec before it is handed to `session::open`, which
        // keeps only the remote name.
        let vault_prefix = vault_spec
            .and_then(|spec| match spec {
                RemoteSpec::Named { path, .. } => Some(path.clone()),
                RemoteSpec::Local(_) => None,
            })
            .unwrap_or_default();

        let session = match vault_spec {
            Some(spec) => Some(session::open(ctx, spec).await?),
            None => None,
        };
        let plain = match plain_spec {
            Some(spec) => Some(PlainRemote::open(ctx, spec)?),
            None => None,
        };

        Ok(Self {
            direction,
            session,
            plain,
            source_root,
            dest_root,
            vault_prefix,
            reap_target,
            staged: Mutex::new(HashMap::new()),
            hashes: Mutex::new(HashMap::new()),
        })
    }

    /// A logical path inside the vault, under the prefix the spec named.
    ///
    /// Every vault call goes through here. Joining at the call sites instead
    /// would mean a new call site could forget, which is exactly how the prefix
    /// came to be honoured nowhere at all.
    fn sealed_path(&self, relative: &str) -> String {
        if self.vault_prefix.is_empty() {
            return relative.to_string();
        }
        if relative.is_empty() {
            return self.vault_prefix.clone();
        }
        format!(
            "{}{}{relative}",
            self.vault_prefix.trim_end_matches(logical::SEPARATOR),
            logical::SEPARATOR
        )
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

    /// The plain remote, for a direction that has one.
    fn plain(&self) -> Result<&PlainRemote> {
        self.plain.as_ref().ok_or_else(|| {
            CliError::new(
                ExitCode::FatalError,
                "internal: no plain remote for this transfer direction",
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
        // `is_some_and`: an entry whose size was never recorded cannot be
        // rejected on size, and refusing it on a guess would stop a download of
        // a rebuilt vault dead. The limit still bites where it can be applied,
        // and the read itself will fail loudly if the object really is too big
        // to hold — which is a worse error message, and the honest one.
        if entry
            .size
            .is_some_and(|size| size > TRANSFER_WHOLE_FILE_LIMIT)
        {
            return Err(CliError::new(
                ExitCode::FatalError,
                format!(
                    "'{}' is {} bytes, above the {} byte whole-file limit",
                    entry.source,
                    entry.size.unwrap_or_default(),
                    TRANSFER_WHOLE_FILE_LIMIT
                ),
            )
            .with_hint(TRANSFER_ENGINE_HINT));
        }
        Ok(())
    }

    /// Take an entry's staged file.
    fn take_staged(&self, key: &str) -> Result<Staged> {
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

    fn put_staged(&self, key: &str, staged: Staged) -> Result<()> {
        self.staged
            .lock()
            .map_err(|_| CliError::new(ExitCode::FatalError, "internal: staging lock poisoned"))?
            .insert(key.to_string(), staged);
        Ok(())
    }

    /// Remember an entry's plaintext digest for its audit record.
    ///
    /// A poisoned lock is *not* an error here, deliberately. The digest is
    /// evidence about a transfer that has already happened; failing the transfer
    /// because the note-taking failed would destroy more than it protects, and
    /// the record is still written — with an empty hash, which the format
    /// explicitly permits and which a reader can tell apart from a wrong one.
    fn note_hash(&self, key: &str, hash: String) {
        if let Ok(mut hashes) = self.hashes.lock() {
            hashes.insert(key.to_string(), hash);
        }
    }

    /// The digest [`StageDriver::upload`] noted, without consuming it.
    ///
    /// [`StageDriver::verify`] needs it while the audit record still has to have
    /// it, so this one borrows where `take_plaintext_hash` takes. Re-reading the
    /// source to recompute it instead would double the I/O and could hash
    /// something other than what was stored, if the source changed underneath
    /// the run — which is the failure a read-back check exists to catch, not one
    /// it may introduce.
    fn recorded_hash(&self, key: &str) -> Option<String> {
        self.hashes.lock().ok()?.get(key).cloned()
    }

    /// Confirm a stored object still hashes to what was written.
    ///
    /// Shared by both plain directions because it is one question — "are the
    /// bytes at rest the bytes we sent?" — and a second spelling of it would
    /// eventually compare something subtly different on one side.
    ///
    /// An *absent* record is a refusal, not a pass. It means the digest could
    /// not be kept (a poisoned lock, i.e. a panic elsewhere in this process), so
    /// nothing can be compared, and reporting a file verified on the strength of
    /// a check that did not happen is the one thing `--verify` must never do.
    fn confirm(&self, stored: &[u8], key: &str, subject: &str) -> Result<()> {
        let Some(expected) = self.recorded_hash(key) else {
            return Err(CliError::new(
                ExitCode::IntegrityFailure,
                format!("no digest was recorded for '{key}', so {subject} cannot be checked"),
            )
            .with_hint(
                "The transfer itself was verified by the store on write; this run \
                 simply cannot repeat the check. Re-run the transfer, or verify \
                 the destination with `dctl check`.",
            ));
        };

        if ContentHash::blake3(stored).hex() == expected {
            return Ok(());
        }

        Err(CliError::new(
            ExitCode::IntegrityFailure,
            format!("read-back verification failed for '{key}': {subject}"),
        )
        .with_hint(
            "What was read back is not what was written. It must not be trusted; \
             investigate before deleting any source.",
        ))
    }
}

impl StageDriver for Engine {
    /// Step 1 — obtain the contents, **and the time they were last changed**.
    ///
    /// For either upload that means reading the source file. For a *sealed*
    /// download it means fetching and authenticating the object, which
    /// `Vault::get_file` does together (a failed tag is an error, never returned
    /// data). For a *plain* download there is nothing to authenticate — the
    /// object was stored as it stands — so it is fetched as it stands, and the
    /// difference in what can be promised is why the two are separate arms
    /// rather than one call behind a shared name.
    ///
    /// Every arm also answers *when the content last changed*, because that fact
    /// belongs to the content and the destination has to record it — see
    /// [`super::staged`]. Four of the five can: a local file is asked through the
    /// same handle its bytes were read from, and a vault object carries the time
    /// in its index row. A plain object store cannot, and says so rather than
    /// substituting the clock: what it reports is when the provider accepted the
    /// object, which is a true fact about a different event.
    async fn read(&self, entry: &PlanEntry) -> Result<()> {
        self.check_size(entry)?;

        let staged = match self.direction {
            Direction::Upload | Direction::PlainUpload | Direction::LocalOnly => {
                let path = self.source_path(&entry.source);
                read_local(&path).await?
            }
            Direction::Download => {
                let path = self.sealed_path(&entry.source);
                let vault = self.vault()?;
                let bytes = vault.get_file(&path).await?;
                Staged::new(bytes, recorded_modification(vault, &path)?)
            }
            // Nothing better than "unknown" is available here, and inventing one
            // would be worse than the re-download it would avoid: see the arm's
            // note above and `docs/commands/dctl_copy.md`.
            Direction::PlainDownload => {
                Staged::new(self.plain()?.get(&entry.source).await?, Modified::Unknown)
            }
        };

        self.put_staged(&entry.dest, staged)
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
    ///
    /// The same holds for a plain remote, one layer lower: `Backend::put` may
    /// not report success unless the store holds the bytes it was handed, and
    /// must commit nothing otherwise. So a plain write is verified before this
    /// returns too, and the guarantee this stage makes does not depend on which
    /// kind of destination was named.
    async fn upload(&self, entry: &PlanEntry) -> Result<u64> {
        let staged = self.take_staged(&entry.dest)?;
        let written = staged.len();
        let bytes = &staged.bytes;

        // Hashed here, where the plaintext is already resident, rather than by
        // re-reading the file afterwards: a second read would double the I/O and
        // could hash something other than what was stored if the source changed
        // underneath the run. This is the digest the audit record carries.
        self.note_hash(&entry.dest, ContentHash::blake3(bytes).hex());

        match self.direction {
            Direction::Upload => {
                self.vault()?
                    .put_file(&self.sealed_path(&entry.dest), bytes, staged.modified)
                    .await?;
            }
            // No timestamp goes with it, because there is nowhere to put one:
            // `Backend::put` stores bytes under a key, and a bucket assigns its
            // own `Last-Modified` on acceptance. Stated here rather than left as
            // an omission a reader has to infer.
            Direction::PlainUpload => {
                self.plain()?.put(&entry.dest, bytes).await?;
            }
            Direction::Download | Direction::PlainDownload | Direction::LocalOnly => {
                let path = self.dest_path(&entry.dest);
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                write_durably(&path, bytes, staged.modified).await?;
            }
        }

        Ok(written)
    }

    /// Steps 4–5 — the extra assurance `--verify` asked for.
    ///
    /// The provider-checksum comparison already happened inside the verified
    /// write, so `checksum` has nothing further to do. The deeper modes read the
    /// object back — re-authenticating it where it is sealed, re-hashing it
    /// where it is not, which is as much as an unsealed object can be asked —
    /// and that read is the egress cost `PLAN.md` §12 says must be opt-in.
    async fn verify(&self, entry: &PlanEntry, mode: VerifyMode) -> Result<()> {
        match (mode, self.direction) {
            (VerifyMode::Checksum, _) | (_, Direction::LocalOnly) => Ok(()),
            (VerifyMode::Sample | VerifyMode::Strict, Direction::Upload) => self
                .vault()?
                .verify_file(&self.sealed_path(&entry.dest))
                .await
                .map_err(|_| {
                    CliError::new(
                        ExitCode::IntegrityFailure,
                        format!("read-back verification failed for '{}'", entry.dest),
                    )
                    .with_hint(
                        "The object did not authenticate when read back. It was \
                         written but must not be trusted; investigate before \
                         deleting any source.",
                    )
                }),
            (VerifyMode::Sample | VerifyMode::Strict, Direction::Download) => {
                // Confirm what landed on disk matches what was decrypted.
                let path = self.dest_path(&entry.dest);
                let written = tokio::fs::read(&path).await?;
                let expected = self
                    .vault()?
                    .get_file(&self.sealed_path(&entry.source))
                    .await?;
                if ContentHash::blake3(&written) != ContentHash::blake3(&expected) {
                    return Err(CliError::new(
                        ExitCode::IntegrityFailure,
                        format!("written file does not match the vault: {}", path.display()),
                    ));
                }
                Ok(())
            }
            (VerifyMode::Sample | VerifyMode::Strict, Direction::PlainUpload) => {
                // The object is read back out of the store and re-hashed. The
                // store already compared it once, on write; this is the second,
                // independent look the flag was asked for, and on a provider it
                // costs a full egress of the object — which is exactly why
                // `PLAN.md` §12 makes it opt-in.
                let stored = self.plain()?.get(&entry.dest).await?;
                self.confirm(&stored, &entry.dest, "the stored object")
            }
            (VerifyMode::Sample | VerifyMode::Strict, Direction::PlainDownload) => {
                // Confirm what landed on disk is what the remote holds. Compared
                // against the digest taken as the bytes went past rather than
                // against a second fetch: a second fetch would pass happily if
                // the remote had changed underneath the run, which is one of the
                // things this is meant to notice.
                let path = self.dest_path(&entry.dest);
                let written = tokio::fs::read(&path).await?;
                self.confirm(&written, &entry.dest, "the file written")
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
    /// Only meaningful on a filesystem destination. Neither kind of remote has
    /// directories: a vault's namespace and a store's key space are both flat,
    /// an empty directory holds no objects, and so there is nothing to store.
    /// That is the same answer for a plain `local:` remote as for a bucket,
    /// because a transfer into a remote goes through its backend — which has a
    /// `put` and no `mkdir` — and not through whatever filesystem may happen to
    /// sit underneath it. `dctl mkdir backup:photos` is the command that creates
    /// a directory in one, and it says so.
    async fn create_dir(&self, entry: &PlanEntry) -> Result<()> {
        match self.direction {
            Direction::Download | Direction::PlainDownload | Direction::LocalOnly => {
                tokio::fs::create_dir_all(self.dest_path(&entry.dest)).await?;
                Ok(())
            }
            Direction::Upload | Direction::PlainUpload => Ok(()),
        }
    }

    /// The remote this engine is connected to, or empty for a transfer with no
    /// remote on either side.
    ///
    /// A filesystem-to-filesystem copy genuinely has no remote, and `""` says so
    /// — the format defines the empty field for exactly this case. Inventing a
    /// name like `local` would put a remote in the log that no configuration
    /// defines and no later run could correlate against.
    ///
    /// One name whichever kind of remote it is, because an audit log is queried
    /// by remote and a query cannot know which of its runs happened to be
    /// sealed. The trailing [`REMOTE_SEPARATOR`] is stripped from the sealed
    /// side's, because a [`Session`] carries the spec exactly as it was typed
    /// (`archive:`) while the removal family carries the parsed name
    /// (`archive`). Two spellings of one remote is a log a compliance query
    /// cannot filter: `remote == archive` would silently exclude every transfer.
    /// The colon is a separator in the command line, not part of the remote's
    /// name — which is why the plain side reports the resolver's name, where the
    /// separator never appeared at all.
    fn remote(&self) -> &str {
        match (self.session.as_ref(), self.plain.as_ref()) {
            (Some(session), _) => session.remote.trim_end_matches(REMOTE_SEPARATOR),
            (None, Some(plain)) => plain.name(),
            (None, None) => "",
        }
    }

    /// Which way this engine moves bytes across the boundary of the remote it
    /// named, in the audit log's vocabulary.
    ///
    /// One `match`, exhaustive over [`Direction`], so a transfer direction added
    /// later has to state its answer here rather than inheriting whichever arm a
    /// wildcard happened to fall into. Recording an egress as an ingest is the
    /// single defect schema v2 exists to close, and it must not be reintroduced
    /// by a `_ =>`.
    ///
    /// `LocalOnly` is `internal` rather than empty: bytes really did move, they
    /// simply never crossed a remote's boundary. Empty means "no bytes", and a
    /// filesystem-to-filesystem copy of forty gigabytes is not that.
    fn direction(&self) -> AuditDirection {
        match self.direction {
            Direction::Upload | Direction::PlainUpload => AuditDirection::In,
            Direction::Download | Direction::PlainDownload => AuditDirection::Out,
            Direction::LocalOnly => AuditDirection::Internal,
        }
    }

    fn take_plaintext_hash(&self, entry: &PlanEntry) -> String {
        self.hashes
            .lock()
            .ok()
            .and_then(|mut hashes| hashes.remove(&entry.dest))
            .unwrap_or_default()
    }
}

impl Reaper for Engine {
    /// Remove something that already exists.
    ///
    /// Which side is decided at connect time by [`ReapTarget`], never per call,
    /// so a reaper wired for the destination can never be handed a source path.
    async fn remove(&self, path: &str) -> Result<()> {
        // Written out in full rather than as "local unless…": every row is a
        // deletion, this is the one function in the family that destroys data,
        // and an exhaustive `match` is what makes a direction added later a
        // compile error instead of a `sync` quietly deleting from the wrong end.
        let side = match (self.direction, self.reap_target) {
            // `move` deletes the source; `sync` deletes destination extras.
            (Direction::Upload, ReapTarget::Source) => ReapSide::Local,
            (Direction::Upload, ReapTarget::Destination) => ReapSide::Vault,
            (Direction::Download, ReapTarget::Source) => ReapSide::Vault,
            (Direction::Download, ReapTarget::Destination) => ReapSide::Local,
            (Direction::PlainUpload, ReapTarget::Source) => ReapSide::Local,
            (Direction::PlainUpload, ReapTarget::Destination) => ReapSide::Plain,
            (Direction::PlainDownload, ReapTarget::Source) => ReapSide::Plain,
            (Direction::PlainDownload, ReapTarget::Destination) => ReapSide::Local,
            (Direction::LocalOnly, _) => ReapSide::Local,
        };

        match side {
            ReapSide::Local => {
                // A reaper deleting from the source resolves against the source
                // root; one deleting destination extras resolves against the
                // destination root. Using either for both is how `sync` deletes
                // out of the wrong tree.
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
            }
            ReapSide::Vault => {
                self.vault()?.delete_file(&self.sealed_path(path)).await?;
                Ok(())
            }
            ReapSide::Plain => self.plain()?.delete(path).await,
        }
    }

    fn target(&self) -> &'static str {
        self.reap_target.label()
    }

    /// See [`StageDriver::remote`] — one engine, one answer, whichever half of
    /// the trait pair is asking.
    fn remote(&self) -> &str {
        <Self as StageDriver>::remote(self)
    }
}

/// Where a [`Reaper`]'s deletions actually land.
///
/// Derived from the direction and the [`ReapTarget`] together, because neither
/// answers it alone: `move` deletes from the source and `sync` from the
/// destination, and which of those is the local filesystem depends entirely on
/// which way the transfer runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReapSide {
    /// A file on this machine.
    Local,
    /// An object in the vault's namespace, removed through the index.
    Vault,
    /// An object in a plain remote, removed through its backend.
    Plain,
}

/// Which direction a write into a named remote runs in.
///
/// One `match`, exhaustive over [`Place`], so a kind of place added later has to
/// state its answer here rather than inheriting whichever arm a `==` comparison
/// happened to fall through to. That is not hypothetical caution: the previous
/// spelling was `if place == Place::Sealed { Upload } else { PlainUpload }` with
/// a refusal in front of it, and the refusal was the only thing standing between
/// an object store and a code path that already handled it correctly.
///
/// An **object store is a plain upload**, exactly like a plain local remote.
/// Both go through [`PlainRemote`], which resolves the prefix, builds the key and
/// calls [`Backend::put`](dctl_store::Backend::put); the trait's verified-write
/// contract — no success unless the store holds the bytes it was handed, nothing
/// committed on a mismatch — is upheld by the provider implementation and not by
/// anything above it. So b2, s3, r2 and a directory differ here in nothing at
/// all, which is the point of the `Backend` trait existing.
const fn upload_direction(place: &Place) -> Direction {
    match place {
        Place::Sealed => Direction::Upload,
        Place::Filesystem { .. } | Place::ObjectStore { .. } => Direction::PlainUpload,
    }
}

/// Refuse a transfer whose two ends are both remotes, naming the gap that
/// actually applies.
///
/// Two different waits, and telling a user the wrong one sends them to watch the
/// wrong release: a sealed end needs a re-encrypting path through `dctl-core`
/// that does not exist, while two plain ends need nothing of the sort and are
/// refused only because this engine connects one remote at a time. Saying
/// "re-encryption" about a copy between two ordinary buckets would be false, and
/// a false explanation of a refusal is worse than a bare one — it is acted on.
fn refuse_remote_to_remote(command: &str, sealed: bool) -> CliError {
    // The capability and the layer travel in the message, the phase in the hint,
    // and the command name in front of both — a refusal a reader can act on has
    // to answer "what is missing", "whose job is it" and "what do I type now",
    // and a message that answers only the last is where a roadmap goes to die.
    let (feature, hint) = if sealed {
        (
            TRANSFER_SEALED_REMOTE_TO_REMOTE_FEATURE,
            TRANSFER_SEALED_REMOTE_TO_REMOTE_HINT,
        )
    } else {
        (
            TRANSFER_REMOTE_TO_REMOTE_FEATURE,
            TRANSFER_REMOTE_TO_REMOTE_HINT,
        )
    };
    CliError::unimplemented(format!("{}: {feature}", command_name(command))).with_hint(hint)
}

/// Read a local source file, and the modification time of the bytes just read.
///
/// One open handle answers both questions. A `tokio::fs::read` followed by a
/// separate `stat` would be shorter and would occasionally lie: between the two
/// calls the file can be rewritten, and the destination would then be given
/// contents from before the edit stamped with the time of the edit — a
/// combination the next run reads as "already up to date" and never corrects.
///
/// A filesystem that will not report a modification time yields
/// [`Modified::Unknown`] and the transfer proceeds: the destination records no
/// time, every later run finds the two sides "not comparable" and re-transfers,
/// which costs bandwidth. That is the direction to fail in.
async fn read_local(path: &std::path::Path) -> Result<Staged> {
    use tokio::io::AsyncReadExt as _;

    let at = |error: std::io::Error| {
        CliError::from(error).with_hint(format!("reading source {}", path.display()))
    };

    let mut file = tokio::fs::File::open(path).await.map_err(at)?;
    let metadata = file.metadata().await.ok();
    let modified = metadata.as_ref().map_or(Modified::Unknown, Modified::of);

    // Sized from the same metadata, so the ordinary case reads into one
    // allocation. That is not only speed: a `Vec` that grows leaves the old
    // buffer's plaintext behind in freed memory, and `Zeroizing` wipes the
    // buffer it still owns rather than every buffer this value ever had.
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        metadata.map_or(0, |meta| usize::try_from(meta.len()).unwrap_or(0)),
    ));
    file.read_to_end(&mut bytes).await.map_err(at)?;

    Ok(Staged::new(bytes, modified))
}

/// The modification time a vault recorded for one of its objects.
///
/// A keyed index lookup ([`dctl_core::Vault::record`]), not a listing: this is
/// asked once per file of a download, and a prefix scan per file would turn a
/// restore of a large tree into a quadratic one.
///
/// An object the local index does not know about is [`Modified::Unknown`] rather
/// than an error. `get_file` resolves through the authoritative name records and
/// therefore succeeds on a device whose index has not been rebuilt, and refusing
/// to write a file that was fetched perfectly well — because its *timestamp* was
/// unavailable — would trade real data for metadata.
fn recorded_modification(vault: &dctl_core::Vault, path: &str) -> Result<Modified> {
    Ok(vault
        .record(path)?
        .and_then(|record| record.modified_unix)
        .map_or(Modified::Unknown, Modified::At))
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
/// * **The source's modification time is stamped on the staging file**, before
///   the rename rather than after it. A destination is never briefly visible
///   carrying the wrong time, and a run interrupted between the two cannot leave
///   a published file whose timestamp says it was written now — which the next
///   run would compare against the source and re-transfer.
/// * `rename` publishes atomically.
/// * **Syncing the parent directory** is what makes the rename itself durable.
///   POSIX does not guarantee a rename survives a power cut until the containing
///   directory is synced, and this is the step that matters most to `move`: data
///   fsynced, source deleted, power lost before the directory entry lands, and
///   the file is gone from both sides.
///
/// This mirrors `crate::commands::rcat::local`, which already does it correctly.
async fn write_durably(path: &std::path::Path, bytes: &[u8], modified: Modified) -> Result<()> {
    let staging = staging_path(path);

    if let Err(error) = fill(&staging, bytes, modified).await {
        let _ = tokio::fs::remove_file(&staging).await;
        return Err(error);
    }

    if let Err(error) = tokio::fs::rename(&staging, path).await {
        let _ = tokio::fs::remove_file(&staging).await;
        return Err(error.into());
    }

    sync_parent_directory(path).await
}

/// Fill the staging file with `bytes`, stamp it with `modified`, and put both on
/// stable storage — leaving it ready to publish with a rename.
///
/// The order is the contract: the time is set *before* the `fsync`, so the
/// metadata the sync flushes is the metadata the file is published with.
async fn fill(staging: &std::path::Path, bytes: &[u8], modified: Modified) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;

    let mut file = tokio::fs::File::create(staging).await?;
    file.write_all(bytes).await?;

    // Explicit, and not redundant with the `sync_all` below. `tokio::fs::File`
    // performs writes on the blocking pool and stashes a failure from the last
    // one in `last_write_err`; that error is surfaced by `poll_flush` and
    // *swallowed* by `complete_inflight`, which is what both `sync_all` and
    // `into_std` call. Without this line a write that failed after the final
    // `write_all` returned would be dropped on the floor, and the rename below
    // would publish a truncated file as a successful transfer.
    file.flush().await?;

    // The open handle rather than the path, so the time lands on the inode that
    // is about to be renamed into place — see `platform::times`.
    let file = crate::platform::times::stamp_open(file, modified).await?;
    file.sync_all().await?;

    Ok(())
}

/// A staging path beside the destination, on the same filesystem so the rename
/// is atomic.
///
/// The naming rule is [`dctl_store::staging`]'s, not one invented here. A
/// download destination can perfectly well be inside a directory that is also a
/// configured `local:` remote, and a staging file that the backend's listing did
/// not recognise as one would be enumerated as an object — a half-written file
/// nothing ever reported as stored, offered as data. Four spellings of "this is
/// mine" is what let a real `report.tmp.2024.csv` be hidden instead.
fn staging_path(dest: &std::path::Path) -> PathBuf {
    dctl_store::staging::staging_sibling(dest)
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
            size: Some(size),
            reason: "test",
        }
    }

    fn engine(direction: Direction, root: PathBuf) -> Engine {
        Engine {
            direction,
            session: None,
            plain: None,
            source_root: root.clone(),
            dest_root: root,
            vault_prefix: String::new(),
            reap_target: ReapTarget::Source,
            staged: Mutex::new(HashMap::new()),
            hashes: Mutex::new(HashMap::new()),
        }
    }

    /// An engine whose two sides are genuinely different directories — the
    /// arrangement that a single shared root would silently get wrong.
    fn split_engine(source: PathBuf, dest: PathBuf) -> Engine {
        Engine {
            direction: Direction::LocalOnly,
            session: None,
            plain: None,
            source_root: source,
            dest_root: dest,
            // Neither side is a vault in this arrangement, so there is no
            // sealed prefix to apply — the same empty value `engine` above uses.
            vault_prefix: String::new(),
            reap_target: ReapTarget::Source,
            staged: Mutex::new(HashMap::new()),
            hashes: Mutex::new(HashMap::new()),
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
            .put_staged(
                "a.txt",
                Staged::new(
                    Zeroizing::new(b"hello".to_vec()),
                    Modified::At(1_700_000_000),
                ),
            )
            .unwrap();

        let taken = engine.take_staged("a.txt").unwrap();
        assert_eq!(taken.bytes.as_slice(), b"hello");
        // The timestamp travels with the bytes or the destination invents one:
        // taking the contents and leaving the time behind is the shape of the
        // defect this pairing exists to prevent.
        assert_eq!(taken.modified, Modified::At(1_700_000_000));

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
        // past this rule. It still fails further down — this build cannot
        // enumerate a named remote, so an upload has no plan to execute — but it
        // must not fail *here*, or the vault would be unaddressable by the one
        // name that stores data safely.
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
        write_durably(&dest, b"durable payload", Modified::Unknown)
            .await
            .unwrap();

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

        write_durably(&dest, b"new", Modified::Unknown)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
    }

    #[tokio::test]
    async fn a_durable_write_publishes_the_source_time_rather_than_the_clock() {
        // Half the incremental-backup fix, at the layer that performs it. A
        // downloaded or locally-copied file that kept the moment it was written
        // compares unequal to the source it was made from, on the next run and
        // every run after — so the destination has to come out of this call
        // already carrying the source's time.
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out.bin");
        write_durably(&dest, b"aged", Modified::At(1_500_000_000))
            .await
            .unwrap();

        let modified = std::fs::metadata(&dest)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(modified, 1_500_000_000);
    }

    #[tokio::test]
    async fn a_source_with_no_time_leaves_the_destination_stamped_by_the_clock() {
        // The honest fallback. Nothing is invented — no epoch, no zero — so the
        // file simply carries the time it was written, and the comparison that
        // reads two incomparable timestamps transfers it again rather than
        // guessing.
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out.bin");
        let before = std::time::SystemTime::now() - std::time::Duration::from_secs(2);

        write_durably(&dest, b"unknown", Modified::Unknown)
            .await
            .unwrap();

        let modified = std::fs::metadata(&dest).unwrap().modified().unwrap();
        assert!(
            modified >= before,
            "the file was stamped with something old"
        );
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

    /// `dctl config create backup local path=<root>` — an ordinary remote that
    /// no vault wraps and nothing seals.
    fn plain_remote_at(path: &std::path::Path) -> crate::config::Config {
        use crate::config::{Config, LocalDef, RemoteDef};

        let mut config = Config::default();
        config.insert(
            "backup",
            RemoteDef::Local(LocalDef {
                path: path.to_path_buf(),
                verify: None,
                require_vault: false,
            }),
        );
        config
    }

    /// A context on that configuration, with prompting forbidden.
    ///
    /// Every plain-remote test below passes `--no-ask-password`, and that is the
    /// assertion rather than a convenience: D4 was a run that demanded a vault
    /// password for a destination that has no key, so a test which left the
    /// prompt reachable would be measuring the wrong thing.
    fn plain_ctx(store: &std::path::Path) -> (tempfile::TempDir, crate::ctx::Ctx) {
        crate::commands::transfer::testing::ctx_with_config_and(
            &plain_remote_at(store),
            &["--no-ask-password"],
        )
    }

    #[tokio::test]
    async fn a_plain_named_destination_needs_no_password_and_receives_real_bytes() {
        // D4: `dctl --no-ask-password copy ./src backup:` exited 22 demanding a
        // vault password, because the engine read the destination's *shape* —
        // any named remote was a vault — instead of asking the configuration.
        // Nothing was written. Invariant I3 says a write to an ordinary location
        // is plaintext and fully supported, so the assertion is on the bytes.
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a.txt"), b"plain payload").unwrap();
        let store = tempfile::tempdir().unwrap();
        let (_config_dir, ctx) = plain_ctx(store.path());

        let source = RemoteSpec::parse(src.path().to_str().unwrap()).unwrap();
        let dest = RemoteSpec::parse("backup:").unwrap();

        let engine = Engine::connect(&ctx, "copy", &source, &dest)
            .await
            .expect("an ordinary remote needs no password");
        assert_eq!(engine.direction, Direction::PlainUpload);

        let entry = entry("a.txt", "a.txt", 13);
        engine.read(&entry).await.unwrap();
        engine.encrypt(&entry).await.unwrap();
        assert_eq!(engine.upload(&entry).await.unwrap(), 13);
        engine.verify(&entry, VerifyMode::Strict).await.unwrap();
        engine.commit(&entry).await.unwrap();

        assert_eq!(
            std::fs::read(store.path().join("a.txt")).unwrap(),
            b"plain payload"
        );
        assert_eq!(
            <Engine as StageDriver>::remote(&engine),
            "backup",
            "the audit record names the remote"
        );
    }

    #[tokio::test]
    async fn a_plain_named_destination_honours_the_prefix_it_was_given() {
        // `copy ./src backup:photos` has to land under `photos/`, because that
        // is where listing `backup:photos` looks for it. Writing at the root
        // would make every subsequent run copy the same files again.
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a.txt"), b"x").unwrap();
        let store = tempfile::tempdir().unwrap();
        let (_config_dir, ctx) = plain_ctx(store.path());

        let source = RemoteSpec::parse(src.path().to_str().unwrap()).unwrap();
        let dest = RemoteSpec::parse("backup:photos").unwrap();

        let engine = Engine::connect(&ctx, "copy", &source, &dest).await.unwrap();
        let entry = entry("a.txt", "a.txt", 1);
        engine.read(&entry).await.unwrap();
        engine.upload(&entry).await.unwrap();

        assert!(store.path().join("photos/a.txt").exists());
        assert!(
            !store.path().join("a.txt").exists(),
            "the prefix must not be dropped"
        );
    }

    #[tokio::test]
    async fn a_plain_named_source_is_read_without_a_password_either() {
        // The same defect in the other direction: `copy backup: ./out` also
        // called `session::open` and also failed with VaultLocked.
        let store = tempfile::tempdir().unwrap();
        std::fs::write(store.path().join("b.txt"), b"from the remote").unwrap();
        let out = tempfile::tempdir().unwrap();
        let (_config_dir, ctx) = plain_ctx(store.path());

        let source = RemoteSpec::parse("backup:").unwrap();
        let dest = RemoteSpec::parse(out.path().to_str().unwrap()).unwrap();

        let engine = Engine::connect(&ctx, "copy", &source, &dest)
            .await
            .expect("reading an ordinary remote needs no password");
        assert_eq!(engine.direction, Direction::PlainDownload);

        let entry = entry("b.txt", "b.txt", 15);
        engine.read(&entry).await.unwrap();
        engine.upload(&entry).await.unwrap();
        engine.verify(&entry, VerifyMode::Strict).await.unwrap();

        assert_eq!(
            std::fs::read(out.path().join("b.txt")).unwrap(),
            b"from the remote"
        );
    }

    #[tokio::test]
    async fn a_real_engine_reports_the_direction_the_audit_log_records() {
        // The pipeline's own tests drive a *fake* driver, so they prove the
        // record carries whatever direction it was handed and nothing about
        // whether the engine hands over the right one. This asserts the mapping
        // on a connected engine, both ways, against the same plain remote —
        // because "an egress recorded as an ingest" is the exact failure schema
        // v2 exists to prevent, and it would be invisible everywhere else.
        let store = tempfile::tempdir().unwrap();
        std::fs::write(store.path().join("b.txt"), b"from the remote").unwrap();
        let local = tempfile::tempdir().unwrap();
        std::fs::write(local.path().join("a.txt"), b"to the remote").unwrap();
        let (_config_dir, ctx) = plain_ctx(store.path());

        let remote = RemoteSpec::parse("backup:").unwrap();
        let disk = RemoteSpec::parse(local.path().to_str().unwrap()).unwrap();

        let out = Engine::connect(&ctx, "copy", &remote, &disk).await.unwrap();
        assert_eq!(out.direction, Direction::PlainDownload);
        assert_eq!(
            StageDriver::direction(&out),
            AuditDirection::Out,
            "reading a remote onto a disk is data leaving it"
        );

        let into = Engine::connect(&ctx, "copy", &disk, &remote).await.unwrap();
        assert_eq!(into.direction, Direction::PlainUpload);
        assert_eq!(StageDriver::direction(&into), AuditDirection::In);

        // And a transfer with no remote at all is `internal`, never empty:
        // forty gigabytes moved between two directories is not "no bytes".
        let elsewhere = tempfile::tempdir().unwrap();
        let other = RemoteSpec::parse(elsewhere.path().to_str().unwrap()).unwrap();
        let within = Engine::connect(&ctx, "copy", &disk, &other).await.unwrap();
        assert_eq!(within.direction, Direction::LocalOnly);
        assert_eq!(StageDriver::direction(&within), AuditDirection::Internal);
    }

    #[tokio::test]
    async fn a_vault_remote_still_opens_a_session() {
        // The control, and the half of I1 that must not move: a write through a
        // vault remote is sealed, so it still needs the key — and under
        // `--no-ask-password` that is a VaultLocked refusal rather than a plain
        // write. If this ever passes without a password, the fix above has
        // turned a sealed destination into an ordinary one.
        let src = tempfile::tempdir().unwrap();
        let store = tempfile::tempdir().unwrap();
        let (_config_dir, ctx) = crate::commands::transfer::testing::ctx_with_config_and(
            &initialised_at(store.path()),
            &["--no-ask-password"],
        );

        let source = RemoteSpec::parse(src.path().to_str().unwrap()).unwrap();
        let dest = RemoteSpec::parse("archive:").unwrap();

        let error = Engine::connect(&ctx, "copy", &source, &dest)
            .await
            .expect_err("a sealed destination needs a password");
        assert_eq!(error.code(), ExitCode::VaultLocked);
    }

    #[test]
    fn an_object_store_destination_uploads_plainly_like_any_other_backend() {
        // The whole of the change that made `dctl copy ./src b2:mybucket` work.
        // A bucket is not sealed, so it takes the plain path — the same
        // `PlainRemote` and the same `Backend::put` a `local:` remote takes,
        // because the trait is the abstraction and the provider is behind it.
        //
        // Asserted on the direction rather than on a successful upload for an
        // honest reason: this test has no B2 credentials and could not perform
        // one. What it can pin is that a bucket is classified into the arm that
        // already round-trips real bytes below
        // (`a_plain_named_destination_needs_no_password_and_receives_real_bytes`),
        // and never into the sealed arm, which would demand a password for a
        // remote that has no key.
        assert_eq!(
            upload_direction(&Place::ObjectStore {
                provider: crate::constants::PROVIDER_B2
            }),
            Direction::PlainUpload
        );
        assert_eq!(
            upload_direction(&Place::Filesystem {
                root: std::path::PathBuf::from("/srv/data"),
                path: String::new(),
            }),
            Direction::PlainUpload,
            "a bucket and a directory must take the identical path"
        );
        assert_eq!(upload_direction(&Place::Sealed), Direction::Upload);
    }

    #[tokio::test]
    async fn an_object_store_destination_asks_for_a_credential_and_not_for_a_feature() {
        // The reachability proof for the b2/s3/r2 arms of `registry::build`,
        // which is as far as a machine with no cloud credentials can go — and it
        // is a real check, because every wrong answer is distinguishable:
        //
        //  * a refusal naming a missing feature would mean the write path is
        //    still closed;
        //  * `VaultLocked` would mean the bucket was misclassified as sealed and
        //    a password was demanded for a remote that has no key (defect S6/D4);
        //  * a *success* under `--no-ask-password` with no credentials exported
        //    would mean nothing tried to connect at all.
        //
        // What is left is the honest failure: the credential the provider needs
        // is not on the environment, named by variable.
        let src = tempfile::tempdir().unwrap();
        let ctx = crate::commands::transfer::testing::ctx(&["--no-ask-password"]);
        let source = RemoteSpec::parse(src.path().to_str().unwrap()).unwrap();
        let dest = RemoteSpec::parse("b2:mybucket/photos").unwrap();

        let error = Engine::connect(&ctx, "copy", &source, &dest)
            .await
            .expect_err("no B2 credentials are exported in a test run");
        // Not `VaultLocked`, which is what a bucket misclassified as sealed
        // would produce under `--no-ask-password`.
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error
                .message()
                .contains(&dctl_meta::env_var(crate::constants::ENV_B2_KEY_ID)),
            "the failure must name the missing credential variable: {}",
            error.message()
        );
        assert!(
            !error.message().contains("not implemented"),
            "writing a plain object is implemented: {}",
            error.message()
        );
    }

    #[tokio::test]
    async fn a_remote_to_remote_refusal_names_the_gap_that_actually_applies() {
        // Both are refused; the difference is what the operator is told to wait
        // for. Two plain stores need no re-encryption, so saying they do would
        // send someone looking for a vault they never created — and the fix for
        // D4 is exactly what makes a plain-to-plain pair reachable here at all.
        let store = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();

        let mut config = initialised_at(store.path());
        config.insert(
            "backup",
            crate::config::RemoteDef::Local(crate::config::LocalDef {
                path: other.path().to_path_buf(),
                verify: None,
                require_vault: false,
            }),
        );
        let (_config_dir, ctx) = crate::commands::transfer::testing::ctx_with_config_and(
            &config,
            &["--no-ask-password"],
        );

        let plain = RemoteSpec::parse("backup:").unwrap();
        let sealed = RemoteSpec::parse("archive:").unwrap();
        let elsewhere = RemoteSpec::parse("backup:mirror").unwrap();

        let both_plain = Engine::connect(&ctx, "copy", &plain, &elsewhere)
            .await
            .expect_err("remote to remote is refused");
        assert_eq!(both_plain.code(), ExitCode::FatalError);
        assert_eq!(
            both_plain.hint(),
            Some(TRANSFER_REMOTE_TO_REMOTE_HINT),
            "nothing here is encrypted, so nothing here needs re-encrypting"
        );

        let one_sealed = Engine::connect(&ctx, "copy", &sealed, &plain)
            .await
            .expect_err("remote to remote is refused");
        assert_eq!(
            one_sealed.hint(),
            Some(TRANSFER_SEALED_REMOTE_TO_REMOTE_HINT),
            "a sealed end is a different wait, and names `dctl replicate`"
        );
        // …and neither refusal asked for a password on the way to being made.
        assert_ne!(one_sealed.code(), ExitCode::VaultLocked);

        // The message — not just the hint — carries the capability and the crate
        // that owes it, because that is the half a `--json` consumer and a
        // support ticket quote. Checking only the hint is how "dctl copy:
        // transfers between two remotes" survived: true, useless, and identical
        // for two gaps that are years apart.
        assert!(
            both_plain.message().contains("dctl-cli"),
            "two plain ends are a CLI engine gap: {}",
            both_plain.message()
        );
        assert!(
            one_sealed.message().contains("dctl-core"),
            "a sealed end is a core gap: {}",
            one_sealed.message()
        );
        assert!(
            !both_plain.message().contains("re-encrypt"),
            "neither end is encrypted: {}",
            both_plain.message()
        );
    }

    #[tokio::test]
    async fn a_sync_reaps_extras_from_a_plain_destination() {
        let src = tempfile::tempdir().unwrap();
        let store = tempfile::tempdir().unwrap();
        std::fs::write(store.path().join("stale.txt"), b"old").unwrap();
        let (_config_dir, ctx) = plain_ctx(store.path());

        let source = RemoteSpec::parse(src.path().to_str().unwrap()).unwrap();
        let dest = RemoteSpec::parse("backup:").unwrap();

        let engine = Engine::connect_reaper(&ctx, "sync", &source, &dest, ReapTarget::Destination)
            .await
            .unwrap();
        engine.remove("stale.txt").await.unwrap();
        assert!(!store.path().join("stale.txt").exists());
    }

    #[tokio::test]
    async fn a_move_reaps_the_source_from_a_plain_remote() {
        let store = tempfile::tempdir().unwrap();
        std::fs::write(store.path().join("moved.txt"), b"payload").unwrap();
        let out = tempfile::tempdir().unwrap();
        let (_config_dir, ctx) = plain_ctx(store.path());

        let source = RemoteSpec::parse("backup:").unwrap();
        let dest = RemoteSpec::parse(out.path().to_str().unwrap()).unwrap();

        let engine = Engine::connect(&ctx, "move", &source, &dest).await.unwrap();
        engine.remove("moved.txt").await.unwrap();
        assert!(
            !store.path().join("moved.txt").exists(),
            "a move deletes from the remote it read"
        );
    }

    #[tokio::test]
    async fn a_plain_write_that_does_not_survive_the_store_is_an_integrity_failure() {
        // `--verify strict` reads the object back. The bytes are replaced behind
        // the engine's back, so the read-back cannot match what was recorded at
        // write time — the one outcome that must never be reported as stored.
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a.txt"), b"original").unwrap();
        let store = tempfile::tempdir().unwrap();
        let (_config_dir, ctx) = plain_ctx(store.path());

        let source = RemoteSpec::parse(src.path().to_str().unwrap()).unwrap();
        let dest = RemoteSpec::parse("backup:").unwrap();
        let engine = Engine::connect(&ctx, "copy", &source, &dest).await.unwrap();

        let entry = entry("a.txt", "a.txt", 8);
        engine.read(&entry).await.unwrap();
        engine.upload(&entry).await.unwrap();
        std::fs::write(store.path().join("a.txt"), b"tampered").unwrap();

        let error = engine
            .verify(&entry, VerifyMode::Strict)
            .await
            .expect_err("the stored object no longer matches");
        assert_eq!(error.code(), ExitCode::IntegrityFailure);
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
