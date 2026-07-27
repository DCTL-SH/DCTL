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
//! Every write stages to a unique temp sibling (`<key>.tmp.<pid>.<seq>`), is
//! flushed with the `fsync@openssh.com` extension when the server supports it, and
//! is only then atomically renamed onto the final path (`posix-rename@openssh.com`
//! when available). Nothing is committed unless the bytes hash to `expected`, so a
//! failure at any step leaves no partial or committed object.

mod path;

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use openssh::{KnownHosts, Session};
use openssh_sftp_client::error::SftpErrorKind;
use openssh_sftp_client::file::File;
use openssh_sftp_client::{Error as SftpError, Sftp, SftpOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_stream::StreamExt as _;

use crate::backend::Backend;
use crate::checksum::{ContentHash, Hasher};
use crate::error::{Result, StoreError};
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};

use path::{ancestor_dirs, chunk_spans, join, normalize_base, prefix_dir, remote_path, temp_path};

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
}

impl SftpConfig {
    /// A config targeting `host` (an ssh-config alias or `user@host`) with objects
    /// stored under `base`.
    #[must_use]
    pub fn new(host: impl Into<String>, base: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            base: base.into(),
        }
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
        Ok(Self {
            session,
            sftp,
            base: normalize_base(&cfg.base),
        })
    }

    // ---- internal helpers -------------------------------------------------

    /// Realize `mkdir -p` for the parent of a remote **file** path. Each ancestor
    /// is created shortest-first; an "already exists" (or otherwise non-fatal)
    /// error on an intermediate directory is ignored — a genuinely un-writable
    /// parent surfaces when the subsequent file open/rename fails.
    async fn mkdir_p(&self, remote_file: &str) {
        let mut fs = self.sftp.fs();
        for dir in ancestor_dirs(remote_file) {
            let _ = fs.create_dir(&dir).await;
        }
    }

    /// Best-effort remove of a remote path, ignoring any error (used to clean up a
    /// staging temp on the failure paths).
    async fn remove_quiet(&self, remote: &str) {
        let mut fs = self.sftp.fs();
        let _ = fs.remove_file(remote).await;
    }

    /// Best-effort durability: fsync the handle when the server advertises the
    /// `fsync@openssh.com` extension, otherwise a no-op.
    async fn fsync_best_effort(file: &mut File) {
        match file.sync_all().await {
            Ok(()) => {}
            // Server lacks the fsync extension — durability is best-effort here.
            Err(SftpError::UnsupportedExtension(_)) => {}
            Err(e) => {
                tracing::debug!("sftp fsync failed (ignored, best-effort): {e}");
            }
        }
    }

    /// Open a fresh remote file for writing (create + truncate).
    async fn create_remote(&self, remote: &str) -> Result<File> {
        self.sftp
            .options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(remote)
            .await
            .map_err(|e| map_sftp_err(remote, e))
    }
}

#[async_trait]
impl Backend for SftpBackend {
    fn name(&self) -> &'static str {
        "sftp"
    }

    async fn put(
        &self,
        key: &ObjectKey,
        data: Bytes,
        expected: &ContentHash,
    ) -> Result<PutOutcome> {
        let remote = remote_path(&self.base, key)?;

        // Verified write: the in-hand bytes must match the caller's declared hash
        // before anything is written. We then write exactly these verified bytes,
        // and the SSH transport is integrity-protected end to end.
        let computed = ContentHash::compute(expected.algo, &data);
        if !computed.matches(expected) {
            return Err(StoreError::ChecksumMismatch {
                expected: expected.hex(),
                actual: computed.hex(),
            });
        }

        self.mkdir_p(&remote).await;
        let tmp = temp_path(&remote);

        // Stage → flush → close, cleaning up the temp on any failure.
        let mut file = self.create_remote(&tmp).await?;
        if let Err(e) = file.write_all(&data).await {
            drop(file);
            self.remove_quiet(&tmp).await;
            return Err(map_sftp_err(&tmp, e));
        }
        Self::fsync_best_effort(&mut file).await;
        if let Err(e) = file.close().await {
            self.remove_quiet(&tmp).await;
            return Err(map_sftp_err(&tmp, e));
        }

        // Atomically publish.
        let mut fs = self.sftp.fs();
        if let Err(e) = fs.rename(&tmp, &remote).await {
            self.remove_quiet(&tmp).await;
            return Err(map_sftp_err(&remote, e));
        }

        Ok(PutOutcome {
            size: data.len() as u64,
            verified: computed,
        })
    }

    async fn put_from_path(
        &self,
        key: &ObjectKey,
        source: &Path,
        expected: &ContentHash,
    ) -> Result<PutOutcome> {
        let remote = remote_path(&self.base, key)?;

        let mut src = tokio::fs::File::open(source).await?;
        let total = src.metadata().await?.len();

        self.mkdir_p(&remote).await;
        let tmp = temp_path(&remote);
        let mut file = self.create_remote(&tmp).await?;

        // Stream source → remote temp in bounded chunks, hashing as we go so the
        // upload is verified without ever holding the whole file (peak memory is
        // O(CHUNK_LEN)). On any failure or a final hash mismatch, the temp is
        // removed and nothing is committed.
        let mut hasher = Hasher::new(expected.algo);
        let mut buf = vec![0u8; CHUNK_LEN as usize];
        for span in chunk_spans(total, CHUNK_LEN) {
            let n = span.len as usize;
            if let Err(e) = src.read_exact(&mut buf[..n]).await {
                drop(file);
                self.remove_quiet(&tmp).await;
                return Err(e.into());
            }
            hasher.update(&buf[..n]);
            if let Err(e) = file.write_all(&buf[..n]).await {
                drop(file);
                self.remove_quiet(&tmp).await;
                return Err(map_sftp_err(&tmp, e));
            }
        }

        let computed = hasher.finalize();
        if !computed.matches(expected) {
            drop(file);
            self.remove_quiet(&tmp).await;
            return Err(StoreError::ChecksumMismatch {
                expected: expected.hex(),
                actual: computed.hex(),
            });
        }

        Self::fsync_best_effort(&mut file).await;
        if let Err(e) = file.close().await {
            self.remove_quiet(&tmp).await;
            return Err(map_sftp_err(&tmp, e));
        }
        let mut fs = self.sftp.fs();
        if let Err(e) = fs.rename(&tmp, &remote).await {
            self.remove_quiet(&tmp).await;
            return Err(map_sftp_err(&remote, e));
        }

        Ok(PutOutcome {
            size: total,
            verified: computed,
        })
    }

    async fn get(&self, key: &ObjectKey) -> Result<Bytes> {
        let remote = remote_path(&self.base, key)?;
        let mut fs = self.sftp.fs();
        match fs.read(&remote).await {
            Ok(buf) => Ok(buf.freeze()),
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
        Ok(buf.freeze())
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
        // `prefix`, sort, and page by cursor — mirroring the local backend.
        let mut found: Vec<(String, u64, Option<i64>)> = Vec::new();

        let key_root = prefix_dir(prefix).to_string();
        let open_root = {
            let j = join(&self.base, &key_root);
            if j.is_empty() { ".".to_string() } else { j }
        };
        // Stack of (path to open on the wire, key-space path relative to base).
        let mut stack = vec![(open_root, key_root)];
        let mut fs = self.sftp.fs();

        while let Some((open_dir, key_dir)) = stack.pop() {
            let dir = match fs.open_dir(&open_dir).await {
                Ok(d) => d,
                Err(e) => match map_sftp_err(&open_dir, e) {
                    // A missing directory (e.g. the prefix has no objects) is an
                    // empty listing, not an error.
                    StoreError::NotFound(_) => continue,
                    other => return Err(other),
                },
            };
            let mut rd = Box::pin(dir.read_dir());
            while let Some(item) = rd.next().await {
                let entry = item.map_err(|e| map_sftp_err(&open_dir, e))?;
                let name = entry.filename().to_string_lossy().into_owned();
                if name == "." || name == ".." {
                    continue;
                }
                let open_child = if open_dir == "." {
                    name.clone()
                } else {
                    format!("{open_dir}/{name}")
                };
                let key_child = if key_dir.is_empty() {
                    name.clone()
                } else {
                    format!("{key_dir}/{name}")
                };
                match entry.file_type() {
                    Some(ft) if ft.is_dir() => stack.push((open_child, key_child)),
                    Some(ft) if ft.is_file() => {
                        if name.contains(".tmp.") {
                            continue; // in-flight verified-write staging file
                        }
                        let md = entry.metadata();
                        found.push((
                            key_child,
                            md.len().unwrap_or(0),
                            md.modified().map(|t| t.as_duration().as_secs() as i64),
                        ));
                    }
                    _ => {} // symlink/other: not an object
                }
            }
        }

        found.retain(|(k, _, _)| k.starts_with(prefix));
        found.sort_by(|a, b| a.0.cmp(&b.0));

        let start = match &cursor {
            Some(c) => found.partition_point(|(k, _, _)| k.as_str() <= c.as_str()),
            None => 0,
        };
        let end = (start + PAGE_SIZE).min(found.len());
        let items = found[start..end]
            .iter()
            .map(|(k, size, mtime)| ObjectMeta {
                key: ObjectKey::new(k.clone()),
                size: *size,
                modified_unix: *mtime,
            })
            .collect();
        let next_cursor = if end < found.len() {
            found.get(end - 1).map(|(k, _, _)| k.clone())
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }
    // `prepare_upload` keeps the trait default: SFTP has no presigned/delegated
    // upload, so it returns a clear "unsupported" error.
}

/// Map an [`openssh_sftp_client`] error to a [`StoreError`], distinguishing a
/// missing file/dir (→ [`StoreError::NotFound`]) from transient/transport failures
/// (→ [`StoreError::Io`] / [`StoreError::Backend`]).
fn map_sftp_err(key: &str, e: SftpError) -> StoreError {
    match e {
        SftpError::SftpError(SftpErrorKind::NoSuchFile, _) => StoreError::NotFound(key.to_string()),
        SftpError::IOError(io) => {
            if io.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound(key.to_string())
            } else {
                StoreError::Io(io)
            }
        }
        other => StoreError::Backend(other.to_string()),
    }
}

/// A unique sibling temp path for the local download staging file: appending the
/// atomic-unique `.tmp.<pid>.<seq>` suffix keeps it in `dest`'s directory (same
/// filesystem), so the final rename onto `dest` is atomic.
fn local_temp(dest: &Path) -> std::path::PathBuf {
    std::path::PathBuf::from(temp_path(&dest.to_string_lossy()))
}
