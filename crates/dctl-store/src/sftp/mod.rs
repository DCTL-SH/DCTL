//! Native SFTP backend — a verified-write [`Backend`] over an SSH host, driven by
//! the **system `ssh`** so `~/.ssh/config` is honored transparently.
//!
//! # Why the system ssh (and not a pure-Rust SSH client)
//!
//! DCTL's target hosts are often only reachable through an `~/.ssh/config` entry —
//! e.g. `lsx-001` uses `ProxyCommand cloudflared access ssh --hostname %h` plus a
//! specific `IdentityFile`. A pure-Rust SSH library (russh/ssh2) would ignore that
//! `ProxyCommand` and could never connect. So this backend uses the [`openssh`]
//! crate, which drives the real `ssh` binary and keeps a persistent multiplexed
//! (`ControlMaster`) session: [`Session::connect_mux`] resolves the destination
//! exactly as `ssh <host>` would — `ProxyCommand`, `IdentityFile`, `User`, `Port`,
//! and every other `Host` directive apply — and [`openssh_sftp_client`] runs the
//! `sftp` subsystem over that same mux session for all file operations.
//!
//! # Path mapping
//!
//! An [`ObjectKey`] maps to the remote path `base/<key>` ([`path::remote_path`]).
//! `base` may be `~/…` (home-relative, since SFTP does not itself expand `~`) or an
//! absolute `/…` path; see [`path::normalize_base`]. Keys are validated against
//! traversal exactly like the local backend.
//!
//! # Verified write & atomicity
//!
//! Every write stages to a unique sibling in the object's own directory
//! (`crate::staging`), is
//! flushed with the `fsync@openssh.com` extension when the server supports it, and
//! is only then atomically renamed onto the final path (`posix-rename@openssh.com`
//! when available). Nothing is committed unless the bytes hash to `expected`, so a
//! failure at any step leaves no partial or committed object.
//!
//! # The modification time, and the one time this protocol cannot hold
//!
//! The writer's [`SourceModified`] is applied with a `SETSTAT` on the **staging
//! path, before the rename** — the object therefore appears at its final name
//! already carrying the source's time, and the next run's comparison finds it
//! unchanged rather than re-uploading it forever.
//!
//! SFTP version 3 stores `atime`/`mtime` as **unsigned 32-bit seconds**, so a
//! source modified before 1970 or after 2106 has no representation on the wire.
//! Those are left unstamped and keep the server's write time, which the
//! comparison reads as a difference and re-transfers: a cost, never a wrong
//! answer. Storing a wrapped value instead would give the file a confident,
//! fabricated date that every later run would believe.
//!
//! The rule and the order that carries it are in [`ops`] and [`write`], stated
//! against a trait so both are provable without an ssh host — which they were
//! not, and the cost of that is `HANDOVER.md` §15.4.

pub mod base;
mod ops;
mod path;
mod tree;
mod write;

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use openssh::{KnownHosts, Session};
use openssh_sftp_client::error::SftpErrorKind;
use openssh_sftp_client::{Error as SftpError, Sftp, SftpOptions};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::backend::Backend;
use crate::checksum::ContentHash;
use crate::error::{Result, StoreError};
use crate::links::{LinkPolicy, LinkReport};
use crate::meter::{self, Meter};
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};
use crate::modified::SourceModified;
use crate::specials::SpecialReport;
use crate::staging::{StagingListing, Want};

use path::{chunk_spans, join, normalize_base, prefix_dir, remote_path, temp_path};

/// Fixed transfer-chunk size for the streaming upload/download paths. Peak memory
/// on those paths is `O(CHUNK_LEN)`, independent of object size.
const CHUNK_LEN: u64 = 4 * 1024 * 1024;

/// Objects returned per [`Backend::list_page`] call.
const PAGE_SIZE: usize = 1000;

/// Connection settings for an [`SftpBackend`].
///
/// The one required field is [`host`](SftpConfig::host): a destination `ssh`
/// understands — a bare `Host` alias from `~/.ssh/config` (e.g. `"lsx-001"`), or a
/// full `user@host:port`. Resolving user/port/identity/ProxyCommand is delegated to
/// `ssh` and the user's config, which is exactly what makes cloudflared-proxied
/// hosts work. [`base`](SftpConfig::base) is the remote directory objects live under.
#[derive(Clone, Debug)]
pub struct SftpConfig {
    /// SSH destination as `ssh` resolves it: a `~/.ssh/config` `Host` alias or
    /// `user@host[:port]`. All other connection parameters come from ssh config.
    pub host: String,
    /// Remote base directory for objects. `~/…` is home-relative; `/…` is absolute.
    pub base: String,
    /// What the listing walk does with the symbolic links it finds.
    ///
    /// `/srv/data -> /mnt/bigdisk/data` is the canonical layout on exactly the
    /// kind of host this backend reaches, and the walk used to drop it without a
    /// word. See [`crate::links`].
    pub links: LinkPolicy,
}

impl SftpConfig {
    /// A config targeting `host` (an ssh-config alias or `user@host`) with objects
    /// stored under `base`.
    #[must_use]
    pub fn new(host: impl Into<String>, base: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            base: base.into(),
            links: LinkPolicy::default(),
        }
    }

    /// The same config, walking symbolic links under `policy`.
    #[must_use]
    pub fn with_links(mut self, policy: LinkPolicy) -> Self {
        self.links = policy;
        self
    }
}

/// A [`Backend`] over SFTP, on a persistent multiplexed system-`ssh` session.
///
/// Construct one with [`SftpBackend::connect`]. The session and SFTP channel stay
/// open for the lifetime of the value and are torn down on drop.
pub struct SftpBackend {
    /// Kept alive alongside the SFTP channel so the `ControlMaster` mux session
    /// persists for this backend's lifetime (and is available for future
    /// shell-command operations over the same connection if ever needed).
    #[allow(dead_code)]
    session: Arc<Session>,
    sftp: Sftp,
    /// Normalized remote base (see [`path::normalize_base`]).
    base: String,
    /// What this backend's listing does with symbolic links. Fixed for the
    /// backend's lifetime rather than passed per request, so a paged listing
    /// cannot follow on page two what it skipped on page one.
    links: LinkPolicy,
    /// Who is told about bytes as they cross the link, chunk by chunk.
    ///
    /// See [`crate::meter`]. This backend is the one where the difference is
    /// most visible: an SFTP transfer over a proxied tunnel is exactly the link
    /// an operator wants to leave usable while a backup runs.
    meter: Arc<dyn Meter>,
    /// Whether a write may create [`base`](Self::base) itself.
    ///
    /// Decided **once, at connect**, and it is the whole of the vanished-base
    /// guard's other half. If the base was not there when this backend opened,
    /// nothing can be lost by creating it and
    /// `dctl config create backup sftp host=… base=/srv/new` must keep working —
    /// the same rule `local:` follows, and the same one
    /// [`crate::guard::identity`] states for every provider: an *unrecorded*
    /// container admits the write that creates it.
    ///
    /// If it **was** there, a write must never put it back. That is what made a
    /// base renamed away mid-run get silently re-created underneath the run,
    /// with seventeen of twenty-five objects landing in the replacement and
    /// every one of them reported as stored and verified.
    ///
    /// At connect and not per write, because the question is about the run: a
    /// base that disappears while the run is using it must stay disappeared, and
    /// re-asking would answer "not there, so make it" — which is the defect
    /// exactly.
    may_create_base: bool,
}

impl SftpBackend {
    /// Connect to `cfg.host` over a multiplexed system-`ssh` session (honoring
    /// `~/.ssh/config`, including any `ProxyCommand`) and open the SFTP subsystem.
    ///
    /// Host keys use `accept-new` semantics ([`KnownHosts::Accept`]) so a
    /// first-time connection to a proxied host succeeds without an interactive
    /// prompt; transport authentication is still provided by ssh (and, for
    /// cloudflared hosts, the access tunnel).
    pub async fn connect(cfg: SftpConfig) -> Result<Self> {
        let session = Session::connect_mux(&cfg.host, KnownHosts::Accept)
            .await
            .map_err(|e| StoreError::Backend(format!("ssh connect to {}: {e}", cfg.host)))?;
        let session = Arc::new(session);
        let sftp = Sftp::from_clonable_session(Arc::clone(&session), SftpOptions::default())
            .await
            .map_err(|e| {
                StoreError::Backend(format!("open sftp subsystem on {}: {e}", cfg.host))
            })?;
        let base = normalize_base(&cfg.base);
        // One `stat` at connect. A base that is absent now may be created by the
        // first write; one that is present may never be re-created by any write
        // in this run. See [`SftpBackend::may_create_base`].
        let may_create_base = {
            let probe = if base.is_empty() { "." } else { &base };
            sftp.fs().metadata(probe).await.is_err()
        };
        Ok(Self {
            session,
            sftp,
            base,
            links: cfg.links,
            meter: meter::unmetered(),
            may_create_base,
        })
    }

    /// The same backend, declaring every chunk it moves to `meter`.
    ///
    /// A builder for the reason [`SftpConfig::with_links`] gives: only the CLI
    /// holds the run's `--bwlimit`, and every other construction here is an
    /// internal read nobody is pacing.
    #[must_use]
    pub fn with_meter(mut self, meter: Arc<dyn Meter>) -> Self {
        self.meter = meter;
        self
    }
}

#[async_trait]
impl Backend for SftpBackend {
    fn name(&self) -> &'static str {
        "sftp"
    }

    /// Whether the configured base is still a directory on the server.
    ///
    /// Existence, and nothing stronger, because SFTP version 3's
    /// `SSH_FXP_STAT` returns size, uid, gid, permissions and two timestamps and
    /// **no inode** — there is no field a replacement would have to change. The
    /// two it does carry that might look usable are not: a directory's `mtime`
    /// moves every time an object is written straight into the base, and its
    /// owner and mode are whatever the process that re-created it had. So the
    /// answer is [`StoreIdentity::existence_only`] and says so, rather than a
    /// token that would look like a comparison and never be one.
    ///
    /// What makes existence worth having here is that the write path no longer
    /// creates this directory ([`path::ancestor_dirs_below`]): a base that has
    /// been removed stays removed, so it is still absent when the next write
    /// checks, and every write that races past the check fails on the server
    /// rather than landing in a re-created replacement.
    ///
    /// A path that exists and is **not** a directory is `None` rather than an
    /// error: something is at the base and it is not a store, which is exactly
    /// what the guard's `Gone` verdict means.
    async fn store_identity(&self) -> Result<Option<crate::guard::StoreIdentity>> {
        let base = if self.base.is_empty() {
            "."
        } else {
            &self.base
        };
        let mut fs = self.sftp.fs();
        match fs.metadata(base).await {
            Ok(md) => Ok(md
                .file_type()
                .is_none_or(|kind| kind.is_dir())
                .then(crate::guard::StoreIdentity::existence_only)),
            Err(e) => match map_sftp_err(base, e) {
                StoreError::NotFound(_) => Ok(None),
                other => Err(other),
            },
        }
    }

    /// Verified, atomic write of bytes already in hand.
    ///
    /// The order — stage, flush, close, stamp, rename, and remove the staging
    /// file on any failure — lives in [`write::put_bytes`], stated against
    /// [`ops::RemoteFs`] so it is provable without a server. What is left here is
    /// the one thing that genuinely needs this backend: mapping the key into the
    /// remote path space, which is where traversal is refused.
    async fn put(
        &self,
        key: &ObjectKey,
        data: Bytes,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        let remote = remote_path(&self.base, key)?;
        let moved = data.len() as u64;
        let outcome = write::put_bytes(self, &remote, &data, expected, modified).await?;
        // One window, because the whole object was one window — the buffered
        // write is the path a small object takes.
        meter::charge(self.meter.as_ref(), moved).await;
        Ok(outcome)
    }

    /// The same write, fed from a file instead of memory, at `O(CHUNK_LEN)`
    /// peak regardless of object size.
    async fn put_from_path(
        &self,
        key: &ObjectKey,
        source: &Path,
        expected: &ContentHash,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        let remote = remote_path(&self.base, key)?;
        let mut src = tokio::fs::File::open(source).await?;
        let total = src.metadata().await?.len();
        write::put_stream(
            self,
            &remote,
            &mut src,
            write::Incoming {
                total,
                chunk: CHUNK_LEN,
                expected,
                modified,
            },
            self.meter.as_ref(),
        )
        .await
    }

    async fn get(&self, key: &ObjectKey) -> Result<Bytes> {
        let remote = remote_path(&self.base, key)?;
        let mut fs = self.sftp.fs();
        match fs.read(&remote).await {
            Ok(buf) => {
                let bytes = buf.freeze();
                meter::charge(self.meter.as_ref(), bytes.len() as u64).await;
                Ok(bytes)
            }
            Err(e) => Err(map_sftp_err(&remote, e)),
        }
    }

    async fn get_to_path(&self, key: &ObjectKey, dest: &Path) -> Result<()> {
        let remote = remote_path(&self.base, key)?;

        // Size first (also the missing→NotFound check), then stream the body down
        // in bounded chunks to a local temp, fsync, and atomically rename — so a
        // failure mid-transfer never leaves a partial object at `dest`.
        let mut file = self
            .sftp
            .open(&remote)
            .await
            .map_err(|e| map_sftp_err(&remote, e))?;
        let total = file
            .metadata()
            .await
            .map_err(|e| map_sftp_err(&remote, e))?
            .len()
            .ok_or_else(|| StoreError::Backend("sftp server did not return file size".into()))?;

        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let tmp = local_temp(dest);
        let out = tokio::fs::File::create(&tmp).await?;
        let mut writer = tokio::io::BufWriter::with_capacity(CHUNK_LEN as usize, out);

        for span in chunk_spans(total, CHUNK_LEN) {
            let chunk = match file.read_all(span.len as usize, BytesMut::new()).await {
                Ok(c) => c,
                Err(e) => {
                    let _ = tokio::fs::remove_file(&tmp).await;
                    return Err(map_sftp_err(&remote, e));
                }
            };
            if let Err(e) = writer.write_all(&chunk).await {
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(e.into());
            }
            // Charged per chunk, after it has landed. This loop is the whole
            // reason `--bwlimit` can now pace one enormous restore: the download
            // is already windowed, and it simply never said so.
            meter::charge(self.meter.as_ref(), chunk.len() as u64).await;
        }

        if let Err(e) = writer.flush().await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e.into());
        }
        let out = writer.into_inner();
        if let Err(e) = out.sync_all().await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e.into());
        }
        drop(out);
        if let Err(e) = tokio::fs::rename(&tmp, dest).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e.into());
        }
        Ok(())
    }

    async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> Result<Bytes> {
        let remote = remote_path(&self.base, key)?;
        let mut file = self
            .sftp
            .open(&remote)
            .await
            .map_err(|e| map_sftp_err(&remote, e))?;
        let size = file
            .metadata()
            .await
            .map_err(|e| map_sftp_err(&remote, e))?
            .len()
            .ok_or_else(|| StoreError::Backend("sftp server did not return file size".into()))?;

        if range.offset > size {
            return Err(StoreError::RangeOutOfBounds { size });
        }
        let available = size - range.offset;
        let to_read = range.length.map_or(available, |len| len.min(available));

        // Streaming seek: read exactly the requested window at `offset`, never the
        // whole object. `read_all` internally chunks to the sftp v3 max read length.
        file.seek(std::io::SeekFrom::Start(range.offset)).await?;
        let buf = file
            .read_all(to_read as usize, BytesMut::with_capacity(to_read as usize))
            .await
            .map_err(|e| map_sftp_err(&remote, e))?;
        let bytes = buf.freeze();
        meter::charge(self.meter.as_ref(), bytes.len() as u64).await;
        Ok(bytes)
    }

    async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta> {
        let remote = remote_path(&self.base, key)?;
        let mut fs = self.sftp.fs();
        let md = fs
            .metadata(&remote)
            .await
            .map_err(|e| map_sftp_err(&remote, e))?;
        // A directory (or other non-file) at the key is "not an object".
        if let Some(ft) = md.file_type() {
            if !ft.is_file() {
                return Err(StoreError::NotFound(key.to_string()));
            }
        }
        let size = md
            .len()
            .ok_or_else(|| StoreError::Backend("sftp server did not return file size".into()))?;
        Ok(ObjectMeta {
            key: key.clone(),
            size,
            modified_unix: md.modified().map(|t| t.as_duration().as_secs() as i64),
        })
    }

    async fn exists(&self, key: &ObjectKey) -> Result<bool> {
        let remote = remote_path(&self.base, key)?;
        let mut fs = self.sftp.fs();
        match fs.metadata(&remote).await {
            Ok(md) => Ok(md.file_type().is_none_or(|t| t.is_file())),
            Err(e) => match map_sftp_err(&remote, e) {
                StoreError::NotFound(_) => Ok(false),
                other => Err(other),
            },
        }
    }

    async fn delete(&self, key: &ObjectKey) -> Result<()> {
        let remote = remote_path(&self.base, key)?;
        let mut fs = self.sftp.fs();
        match fs.remove_file(&remote).await {
            Ok(()) => Ok(()),
            // Deleting a missing object is a no-op success (idempotent).
            Err(e) => match map_sftp_err(&remote, e) {
                StoreError::NotFound(_) => Ok(()),
                other => Err(other),
            },
        }
    }

    async fn list_page(&self, prefix: &str, cursor: Option<String>) -> Result<Page> {
        // Collect every object key under `base/<prefix-dir>` via a recursive
        // readdir (SFTP has no native recursive list), then filter by the full
        // `prefix`, sort, and page by cursor — mirroring the local backend. The
        // walk itself, and what it does about symbolic links, is [`tree`].
        let key_root = prefix_dir(prefix).to_string();
        let open_root = {
            let j = join(&self.base, &key_root);
            if j.is_empty() { ".".to_string() } else { j }
        };
        let walked =
            tree::collect(&self.sftp, open_root, key_root, self.links, Want::Objects).await?;

        // First page only. This backend re-walks the whole subtree per call
        // (`HANDOVER.md` §9.3 item 10), so attaching the report to every page
        // would multiply one tree's links by the page count and report a number
        // that was never true.
        let (links, specials) = if cursor.is_none() {
            (walked.links, walked.specials)
        } else {
            (LinkReport::default(), SpecialReport::default())
        };

        Ok(path::page(
            walked.found,
            prefix,
            cursor.as_deref(),
            PAGE_SIZE,
            links,
            specials,
        ))
    }

    /// One page of the debris an interrupted upload left on the server.
    ///
    /// This backend stages for the same reason the local one does — the rename
    /// is the commit — so it has real debris, and a killed `copy` leaves a
    /// full-size staging file in the store every time. The walk runs under
    /// [`LinkPolicy::Skip`] rather than the backend's own policy: DCTL writes
    /// its staging files straight into the store, so following a link out of it
    /// could only take a sweep somewhere it has no business deleting.
    async fn list_staging(&self, prefix: &str, cursor: Option<String>) -> Result<StagingListing> {
        let key_root = prefix_dir(prefix).to_string();
        let open_root = {
            let j = join(&self.base, &key_root);
            if j.is_empty() { ".".to_string() } else { j }
        };
        let walked = tree::collect(
            &self.sftp,
            open_root,
            key_root,
            LinkPolicy::Skip,
            Want::Staging,
        )
        .await?;
        Ok(StagingListing::Page(path::staging_page(
            walked.found,
            prefix,
            cursor.as_deref(),
            PAGE_SIZE,
        )))
    }
    // `prepare_upload` keeps the trait default: SFTP has no presigned/delegated
    // upload, so it returns a clear "unsupported" error.
}

/// Map an [`openssh_sftp_client`] error to a [`StoreError`], classified so that
/// [`crate::retry`] can decide from the shape rather than from the words.
///
/// Three outcomes, and each one is a different answer to "would another attempt
/// differ?".
///
/// * **The object is not there** — [`StoreError::NotFound`], for the protocol's
///   `NoSuchFile` and for a local `ErrorKind::NotFound`. Nothing to retry.
/// * **The request met an I/O fault** — [`StoreError::Io`], carrying the errno,
///   which is what decides it: a reset connection or an `EAGAIN` on the link is
///   retried, a permission denial is not
///   (`crate::retry::observed`, following `fs/fserrors/retriable_errors.go`).
/// * **The session itself is gone** — every remaining variant of
///   [`SftpError`] means the multiplexed `ssh` session or the remote
///   `sftp-server` has died, and **this backend cannot re-dial one**. So it is
///   reported as terminal, with a message that says the run has to be started
///   again, rather than being spent five times into a socket that is not there.
///   rclone re-dials from a connection pool (`backend/sftp/sftp.go`); DCTL does
///   not, and classifying this as temporary would buy nothing but a slower way
///   to report the same failure — the exact shape of claim `HANDOVER.md` §11.2
///   already records against the old hint.
///
/// The protocol's other server-side codes — `PermDenied`, `Failure`,
/// `BadMessage`, `OpUnsupported` — are statements about the request and are
/// equally true next time, so they take the same terminal path.
fn map_sftp_err(key: &str, e: SftpError) -> StoreError {
    match e {
        SftpError::SftpError(SftpErrorKind::NoSuchFile, _) => StoreError::NotFound(key.to_string()),
        SftpError::SftpError(kind, message) => {
            StoreError::Backend(format!("sftp server reported {kind:?}: {message}"))
        }
        SftpError::IOError(io) => {
            if io.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound(key.to_string())
            } else {
                StoreError::Io(io)
            }
        }
        other => StoreError::Backend(format!(
            "the sftp session to this host is no longer usable ({other});              run the command again to open a new one"
        )),
    }
}

/// A unique sibling temp path for the local download staging file: appending the
/// atomic-unique `.tmp.<pid>.<seq>` suffix keeps it in `dest`'s directory (same
/// filesystem), so the final rename onto `dest` is atomic.
fn local_temp(dest: &Path) -> std::path::PathBuf {
    std::path::PathBuf::from(temp_path(&dest.to_string_lossy()))
}
