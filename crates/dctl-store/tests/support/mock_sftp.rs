//! An SFTP version-3 server, in this process, over a pipe, backed by a real
//! directory.
//!
//! ## Why this exists
//!
//! Three of the SFTP backend's guarantees were reachable only on the far side of
//! a real `sshd`: the `SETSTAT` that carries the source's modification time, the
//! `mkdir -p` that must never re-create the configured base, and the base probe
//! that tells the store guard whether the store is still there. Their only
//! witness was `tests/sftp_live.rs`, which is `#[ignore]`d and needs
//! `DCTL_SFTP_HOST`, so deleting any of the three left `cargo test --workspace`
//! entirely green (`HANDOVER.md` §23.0). A guarantee whose only witness needs a
//! server is a guarantee the stated gate does not hold, and the gate is what
//! every report in this project quotes as proof.
//!
//! [`super::mock_b2`] and [`super::mock_s3`] solve the same problem for the two
//! HTTP providers by speaking their wire protocol on loopback. This is that, one
//! layer lower: `openssh_sftp_client::Sftp::new` takes a byte sink and a byte
//! source rather than a session, so a pipe pair and a task that speaks version 3
//! of the protocol is a whole server — no `ssh`, no `sshd`, no host key, no
//! credentials, and nothing installed.
//!
//! ## What it proves, and what it cannot
//!
//! The **real** [`SftpBackend`] runs against it, unchanged, over the real client
//! library and the real packet encoding. So a request DCTL does not send is a
//! request this server does not see, which is exactly the assertion the three
//! guarantees above need. Operations land on a real directory, so a stamped time
//! is a stamped time and a created directory is a created directory — both
//! readable back with `std::fs` rather than taken from the server's own account
//! of itself.
//!
//! It proves nothing about OpenSSH's own behaviour: its permission model, its
//! `chroot`, its extension set beyond the two advertised here, its
//! concurrency, or how it answers a request this file happens to implement more
//! kindly than it does. `sftp_live.rs` is what covers those, and this is not a
//! substitute for it.
//!
//! ## Faithfulness where it decides a test
//!
//! Two choices are deliberate rather than convenient.
//!
//! * **`posix-rename@openssh.com` is advertised**, because OpenSSH advertises it
//!   and the client prefers it when it is there. Version 3's plain `SSH_FXP_RENAME`
//!   fails when the destination exists, which would make DCTL's stage-then-rename
//!   commit pass here and fail against a real server on the second write of an
//!   object.
//! * **`fsync@openssh.com` is advertised**, so the write path's flush is a real
//!   request that a real file receives. Left off, the client answers
//!   `UnsupportedExtension` — which `SftpStagedFile::sync` deliberately tolerates
//!   — and the flush would silently never happen in any test here.
//!
//! Paths are resolved under [`MockSftp::root`] like a chroot: an absolute path is
//! taken as root-relative, and a relative one is taken as relative to the same
//! place, which is what a real server's home directory does. Anything that would
//! climb out is refused with `SSH_FX_PERMISSION_DENIED` rather than followed.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── the wire, as version 3 defines it ────────────────────────────────────────

const SSH_FXP_INIT: u8 = 1;
const SSH_FXP_VERSION: u8 = 2;
const SSH_FXP_OPEN: u8 = 3;
const SSH_FXP_CLOSE: u8 = 4;
const SSH_FXP_READ: u8 = 5;
const SSH_FXP_WRITE: u8 = 6;
const SSH_FXP_LSTAT: u8 = 7;
const SSH_FXP_FSTAT: u8 = 8;
const SSH_FXP_SETSTAT: u8 = 9;
const SSH_FXP_FSETSTAT: u8 = 10;
const SSH_FXP_OPENDIR: u8 = 11;
const SSH_FXP_READDIR: u8 = 12;
const SSH_FXP_REMOVE: u8 = 13;
const SSH_FXP_MKDIR: u8 = 14;
const SSH_FXP_RMDIR: u8 = 15;
const SSH_FXP_REALPATH: u8 = 16;
const SSH_FXP_STAT: u8 = 17;
const SSH_FXP_RENAME: u8 = 18;
const SSH_FXP_READLINK: u8 = 19;
const SSH_FXP_SYMLINK: u8 = 20;
const SSH_FXP_STATUS: u8 = 101;
const SSH_FXP_HANDLE: u8 = 102;
const SSH_FXP_DATA: u8 = 103;
const SSH_FXP_NAME: u8 = 104;
const SSH_FXP_ATTRS: u8 = 105;
const SSH_FXP_EXTENDED: u8 = 200;

const SSH_FX_OK: u32 = 0;
const SSH_FX_EOF: u32 = 1;
const SSH_FX_NO_SUCH_FILE: u32 = 2;
const SSH_FX_PERMISSION_DENIED: u32 = 3;
const SSH_FX_FAILURE: u32 = 4;
const SSH_FX_OP_UNSUPPORTED: u32 = 8;

const ATTR_SIZE: u32 = 0x0000_0001;
const ATTR_UIDGID: u32 = 0x0000_0002;
const ATTR_PERMISSIONS: u32 = 0x0000_0004;
const ATTR_ACMODTIME: u32 = 0x0000_0008;
const ATTR_EXTENDED: u32 = 0x8000_0000;

const FXF_WRITE: u32 = 0x0000_0002;
const FXF_APPEND: u32 = 0x0000_0004;
const FXF_CREAT: u32 = 0x0000_0008;
const FXF_TRUNC: u32 = 0x0000_0010;
const FXF_EXCL: u32 = 0x0000_0020;

/// Pipe capacity in each direction.
///
/// One mebibyte, which is four times the client's default write buffer, so a
/// pipelined burst of requests never blocks the client's flush task against a
/// server that is mid-response. A smaller buffer would still work and would make
/// the deadlock harder to reason about, which is not a trade worth making inside
/// test support.
const PIPE_CAPACITY: usize = 1024 * 1024;

/// Every request the server answered, in arrival order.
///
/// The point of recording them: an operation DCTL claims to perform is a packet
/// this list either holds or does not, and "the file ended up with the right
/// mtime" can be true because a *later* call fixed it. `SETSTAT` on the staging
/// path before the rename is an ordering claim, and only the sequence can carry
/// one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seen {
    Open(String),
    Close,
    Read(String),
    Write(String, usize),
    Lstat(String),
    Fstat,
    Setstat(String, Option<(u32, u32)>),
    Fsetstat(Option<(u32, u32)>),
    Opendir(String),
    Readdir,
    Remove(String),
    Mkdir(String),
    Rmdir(String),
    Realpath(String),
    Stat(String),
    Rename(String, String),
    Readlink(String),
    Symlink(String, String),
    Fsync,
    Extended(String),
}

/// A running in-process SFTP server and the directory it serves.
pub struct MockSftp {
    root: tempfile::TempDir,
    log: Arc<Mutex<Vec<Seen>>>,
}

impl MockSftp {
    /// The directory every path in the conversation resolves under.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.root.path()
    }

    /// Every request the server has answered, in arrival order.
    #[must_use]
    pub fn seen(&self) -> Vec<Seen> {
        self.log
            .lock()
            .expect("the request log is not poisoned")
            .clone()
    }

    /// Whether any request of this shape arrived.
    #[must_use]
    pub fn saw(&self, matching: impl Fn(&Seen) -> bool) -> bool {
        self.seen().iter().any(matching)
    }
}

/// Start a server over a fresh temporary directory and hand back the pipe pair a
/// client connects with.
///
/// Returned separately from the [`MockSftp`] so the caller owns the server's
/// lifetime: dropping the handle removes the directory, and the tests below hold
/// it for as long as they read from it.
#[must_use]
pub fn start() -> (MockSftp, ClientPipes) {
    let root = tempfile::TempDir::new().expect("a temporary directory");
    let log: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));

    // Two simplex pipes rather than one duplex: the client is handed a sink for
    // its requests and a source for its responses, exactly as it would be handed
    // a subprocess's stdin and stdout.
    let (server_reads, client_writes) = tokio::io::simplex(PIPE_CAPACITY);
    let (client_reads, server_writes) = tokio::io::simplex(PIPE_CAPACITY);

    let mut server = Server {
        root: root.path().to_path_buf(),
        handles: BTreeMap::new(),
        next_handle: 0,
        log: Arc::clone(&log),
    };
    tokio::spawn(async move {
        // A pipe that closes is the client going away, which every test does at
        // the end. Nothing here should report it.
        let _ = server.serve(server_reads, server_writes).await;
    });

    (
        MockSftp { root, log },
        ClientPipes {
            writes: client_writes,
            reads: client_reads,
        },
    )
}

/// The two ends a client is built from.
pub struct ClientPipes {
    /// Where the client writes its requests.
    pub writes: tokio::io::WriteHalf<tokio::io::SimplexStream>,
    /// Where the client reads its responses.
    pub reads: tokio::io::ReadHalf<tokio::io::SimplexStream>,
}

/// One thing the client is holding open.
enum Handle {
    File(std::fs::File, PathBuf),
    /// A directory listing, already read, and how much of it has been handed
    /// over. Version 3 wants `SSH_FX_EOF` after the last batch, so the position
    /// has to survive between two `READDIR`s on one handle.
    Dir(Vec<PathBuf>, usize),
}

struct Server {
    root: PathBuf,
    handles: BTreeMap<u32, Handle>,
    next_handle: u32,
    log: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    async fn serve<R, W>(&mut self, mut input: R, mut output: W) -> std::io::Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        loop {
            let mut length = [0u8; 4];
            if input.read_exact(&mut length).await.is_err() {
                return Ok(());
            }
            let length = u32::from_be_bytes(length) as usize;
            let mut packet = vec![0u8; length];
            input.read_exact(&mut packet).await?;

            let Some((&kind, rest)) = packet.split_first() else {
                return Ok(());
            };
            let reply = if kind == SSH_FXP_INIT {
                version_packet()
            } else {
                let mut cursor = Cursor::new(rest);
                let id = cursor.u32();
                self.answer(kind, id, &mut cursor)
            };

            output
                .write_all(&(reply.len() as u32).to_be_bytes())
                .await?;
            output.write_all(&reply).await?;
            output.flush().await?;
        }
    }

    fn note(&self, seen: Seen) {
        if let Ok(mut log) = self.log.lock() {
            log.push(seen);
        }
    }

    /// One request, one response.
    #[allow(clippy::too_many_lines)]
    fn answer(&mut self, kind: u8, id: u32, cursor: &mut Cursor<'_>) -> Vec<u8> {
        match kind {
            SSH_FXP_REALPATH => {
                let raw = cursor.string();
                self.note(Seen::Realpath(raw.clone()));
                match self.resolve(&raw) {
                    // The canonical answer is what the *client* will compare
                    // against, so it has to be the path as this server names it —
                    // which is the wire path, not the host path underneath.
                    Some(_) => name_packet(id, &canonical(&raw)),
                    None => status(id, SSH_FX_PERMISSION_DENIED, "outside the served root"),
                }
            }
            SSH_FXP_STAT | SSH_FXP_LSTAT => {
                let raw = cursor.string();
                self.note(if kind == SSH_FXP_STAT {
                    Seen::Stat(raw.clone())
                } else {
                    Seen::Lstat(raw.clone())
                });
                let Some(path) = self.resolve(&raw) else {
                    return status(id, SSH_FX_PERMISSION_DENIED, "outside the served root");
                };
                let read = if kind == SSH_FXP_STAT {
                    std::fs::metadata(&path)
                } else {
                    std::fs::symlink_metadata(&path)
                };
                match read {
                    Ok(meta) => attrs_packet(id, &meta),
                    Err(e) => status(id, errno_status(&e), &e.to_string()),
                }
            }
            SSH_FXP_FSTAT => {
                self.note(Seen::Fstat);
                let handle = cursor.handle();
                match self.handles.get(&handle) {
                    Some(Handle::File(file, _)) => match file.metadata() {
                        Ok(meta) => attrs_packet(id, &meta),
                        Err(e) => status(id, errno_status(&e), &e.to_string()),
                    },
                    _ => status(id, SSH_FX_FAILURE, "not an open file"),
                }
            }
            SSH_FXP_OPEN => {
                let raw = cursor.string();
                let pflags = cursor.u32();
                self.note(Seen::Open(raw.clone()));
                let Some(path) = self.resolve(&raw) else {
                    return status(id, SSH_FX_PERMISSION_DENIED, "outside the served root");
                };
                let mut options = std::fs::OpenOptions::new();
                options.read(true);
                if pflags & FXF_WRITE != 0 {
                    options.write(true);
                }
                if pflags & FXF_APPEND != 0 {
                    options.append(true);
                }
                if pflags & FXF_CREAT != 0 {
                    options.create(true);
                }
                if pflags & FXF_TRUNC != 0 {
                    options.truncate(true);
                }
                if pflags & FXF_EXCL != 0 {
                    options.create_new(true);
                }
                match options.open(&path) {
                    Ok(file) => {
                        let handle = self.store(Handle::File(file, path));
                        handle_packet(id, handle)
                    }
                    Err(e) => status(id, errno_status(&e), &e.to_string()),
                }
            }
            SSH_FXP_CLOSE => {
                self.note(Seen::Close);
                let handle = cursor.handle();
                self.handles.remove(&handle);
                status(id, SSH_FX_OK, "closed")
            }
            SSH_FXP_READ => {
                let handle = cursor.handle();
                let offset = cursor.u64();
                let want = cursor.u32() as usize;
                let Some(Handle::File(file, path)) = self.handles.get_mut(&handle) else {
                    return status(id, SSH_FX_FAILURE, "not an open file");
                };
                self.log
                    .lock()
                    .map(|mut log| log.push(Seen::Read(wire_name(path))))
                    .unwrap_or_default();
                if file.seek(SeekFrom::Start(offset)).is_err() {
                    return status(id, SSH_FX_FAILURE, "seek");
                }
                let mut buffer = vec![0u8; want];
                let mut have = 0;
                while have < want {
                    match file.read(&mut buffer[have..]) {
                        Ok(0) => break,
                        Ok(n) => have += n,
                        Err(e) => return status(id, errno_status(&e), &e.to_string()),
                    }
                }
                if have == 0 {
                    return status(id, SSH_FX_EOF, "end of file");
                }
                buffer.truncate(have);
                data_packet(id, &buffer)
            }
            SSH_FXP_WRITE => {
                let handle = cursor.handle();
                let offset = cursor.u64();
                let data = cursor.bytes();
                let Some(Handle::File(file, path)) = self.handles.get_mut(&handle) else {
                    return status(id, SSH_FX_FAILURE, "not an open file");
                };
                let name = wire_name(path);
                let wrote = data.len();
                let outcome = file
                    .seek(SeekFrom::Start(offset))
                    .and_then(|_| file.write_all(data));
                self.log
                    .lock()
                    .map(|mut log| log.push(Seen::Write(name, wrote)))
                    .unwrap_or_default();
                match outcome {
                    Ok(()) => status(id, SSH_FX_OK, "written"),
                    Err(e) => status(id, errno_status(&e), &e.to_string()),
                }
            }
            SSH_FXP_SETSTAT | SSH_FXP_FSETSTAT => {
                // The one request the modification-time guarantee is made of.
                let (target, raw) = if kind == SSH_FXP_SETSTAT {
                    let raw = cursor.string();
                    (self.resolve(&raw), Some(raw))
                } else {
                    let handle = cursor.handle();
                    let path = match self.handles.get(&handle) {
                        Some(Handle::File(_, path)) => Some(path.clone()),
                        _ => None,
                    };
                    (path, None)
                };
                let times = read_attrs(cursor);
                self.note(match &raw {
                    Some(raw) => Seen::Setstat(raw.clone(), times),
                    None => Seen::Fsetstat(times),
                });
                let Some(path) = target else {
                    return status(id, SSH_FX_NO_SUCH_FILE, "no such path or handle");
                };
                match times {
                    None => status(id, SSH_FX_OK, "nothing to set"),
                    Some((accessed, modified)) => match set_times(&path, accessed, modified) {
                        Ok(()) => status(id, SSH_FX_OK, "stamped"),
                        Err(e) => status(id, errno_status(&e), &e.to_string()),
                    },
                }
            }
            SSH_FXP_OPENDIR => {
                let raw = cursor.string();
                self.note(Seen::Opendir(raw.clone()));
                let Some(path) = self.resolve(&raw) else {
                    return status(id, SSH_FX_PERMISSION_DENIED, "outside the served root");
                };
                match std::fs::read_dir(&path) {
                    Ok(entries) => {
                        let mut found: Vec<PathBuf> =
                            entries.filter_map(Result::ok).map(|e| e.path()).collect();
                        found.sort();
                        let handle = self.store(Handle::Dir(found, 0));
                        handle_packet(id, handle)
                    }
                    Err(e) => status(id, errno_status(&e), &e.to_string()),
                }
            }
            SSH_FXP_READDIR => {
                self.note(Seen::Readdir);
                let handle = cursor.handle();
                let Some(Handle::Dir(entries, position)) = self.handles.get_mut(&handle) else {
                    return status(id, SSH_FX_FAILURE, "not an open directory");
                };
                if *position >= entries.len() {
                    return status(id, SSH_FX_EOF, "end of directory");
                }
                let batch: Vec<PathBuf> = entries[*position..].to_vec();
                *position = entries.len();
                names_packet(id, &batch)
            }
            SSH_FXP_MKDIR => {
                let raw = cursor.string();
                self.note(Seen::Mkdir(raw.clone()));
                let Some(path) = self.resolve(&raw) else {
                    return status(id, SSH_FX_PERMISSION_DENIED, "outside the served root");
                };
                // One level, never `create_dir_all`: a server that quietly made
                // the whole chain would hide the very defect the ancestor rule
                // exists to prevent.
                match std::fs::create_dir(&path) {
                    Ok(()) => status(id, SSH_FX_OK, "created"),
                    Err(e) => status(id, errno_status(&e), &e.to_string()),
                }
            }
            SSH_FXP_RMDIR => {
                let raw = cursor.string();
                self.note(Seen::Rmdir(raw.clone()));
                let Some(path) = self.resolve(&raw) else {
                    return status(id, SSH_FX_PERMISSION_DENIED, "outside the served root");
                };
                match std::fs::remove_dir(&path) {
                    Ok(()) => status(id, SSH_FX_OK, "removed"),
                    Err(e) => status(id, errno_status(&e), &e.to_string()),
                }
            }
            SSH_FXP_REMOVE => {
                let raw = cursor.string();
                self.note(Seen::Remove(raw.clone()));
                let Some(path) = self.resolve(&raw) else {
                    return status(id, SSH_FX_PERMISSION_DENIED, "outside the served root");
                };
                match std::fs::remove_file(&path) {
                    Ok(()) => status(id, SSH_FX_OK, "removed"),
                    Err(e) => status(id, errno_status(&e), &e.to_string()),
                }
            }
            SSH_FXP_RENAME => {
                let from = cursor.string();
                let to = cursor.string();
                self.note(Seen::Rename(from.clone(), to.clone()));
                self.rename(id, &from, &to, false)
            }
            SSH_FXP_READLINK => {
                let raw = cursor.string();
                self.note(Seen::Readlink(raw.clone()));
                let Some(path) = self.resolve(&raw) else {
                    return status(id, SSH_FX_PERMISSION_DENIED, "outside the served root");
                };
                match std::fs::read_link(&path) {
                    Ok(target) => name_packet(id, &target.to_string_lossy()),
                    Err(e) => status(id, errno_status(&e), &e.to_string()),
                }
            }
            SSH_FXP_SYMLINK => {
                // Version 3 sends the *target* first and the link second, which
                // is the opposite of what the packet's field names suggest and is
                // a documented quirk of OpenSSH's implementation.
                let target = cursor.string();
                let link = cursor.string();
                self.note(Seen::Symlink(target.clone(), link.clone()));
                let (Some(link_path), Some(target_path)) =
                    (self.resolve(&link), self.resolve(&target))
                else {
                    return status(id, SSH_FX_PERMISSION_DENIED, "outside the served root");
                };
                #[cfg(unix)]
                match std::os::unix::fs::symlink(&target_path, &link_path) {
                    Ok(()) => status(id, SSH_FX_OK, "linked"),
                    Err(e) => status(id, errno_status(&e), &e.to_string()),
                }
                #[cfg(not(unix))]
                {
                    let _ = (link_path, target_path);
                    status(id, SSH_FX_OP_UNSUPPORTED, "no symlinks on this platform")
                }
            }
            SSH_FXP_EXTENDED => {
                let name = cursor.string();
                match name.as_str() {
                    "fsync@openssh.com" => {
                        self.note(Seen::Fsync);
                        let handle = cursor.handle();
                        match self.handles.get(&handle) {
                            Some(Handle::File(file, _)) => match file.sync_all() {
                                Ok(()) => status(id, SSH_FX_OK, "synced"),
                                Err(e) => status(id, errno_status(&e), &e.to_string()),
                            },
                            _ => status(id, SSH_FX_FAILURE, "not an open file"),
                        }
                    }
                    "posix-rename@openssh.com" => {
                        let from = cursor.string();
                        let to = cursor.string();
                        self.note(Seen::Rename(from.clone(), to.clone()));
                        self.rename(id, &from, &to, true)
                    }
                    other => {
                        self.note(Seen::Extended(other.to_string()));
                        status(id, SSH_FX_OP_UNSUPPORTED, other)
                    }
                }
            }
            other => status(id, SSH_FX_OP_UNSUPPORTED, &format!("packet type {other}")),
        }
    }

    /// Rename, with version 3's refusal to overwrite or POSIX's willingness to.
    fn rename(&self, id: u32, from: &str, to: &str, posix: bool) -> Vec<u8> {
        let (Some(from), Some(to)) = (self.resolve(from), self.resolve(to)) else {
            return status(id, SSH_FX_PERMISSION_DENIED, "outside the served root");
        };
        if !posix && to.exists() {
            // What OpenSSH's `SSH_FXP_RENAME` does, and the reason the client
            // prefers the extension. A server that silently overwrote here would
            // let a second write of the same object pass in this file and fail on
            // a real host.
            return status(id, SSH_FX_FAILURE, "destination exists");
        }
        match std::fs::rename(&from, &to) {
            Ok(()) => status(id, SSH_FX_OK, "renamed"),
            Err(e) => status(id, errno_status(&e), &e.to_string()),
        }
    }

    /// Take a wire path to a host path, or [`None`] when it would leave the root.
    fn resolve(&self, raw: &str) -> Option<PathBuf> {
        let relative = raw.trim_start_matches('/');
        let mut out = self.root.clone();
        for component in Path::new(relative).components() {
            match component {
                Component::Normal(part) => out.push(part),
                Component::CurDir => {}
                // Nothing DCTL sends contains one — `sftp::path::validate_key`
                // refuses them — so meeting one means the refusal has stopped
                // working, and answering it would hide that.
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
            }
        }
        Some(out)
    }

    fn store(&mut self, handle: Handle) -> u32 {
        self.next_handle += 1;
        let id = self.next_handle;
        self.handles.insert(id, handle);
        id
    }
}

// ── packet construction ──────────────────────────────────────────────────────

/// The `SSH_FXP_VERSION` reply, with the two extensions this server implements.
///
/// Both name and revision travel as strings, and the revision is read back with
/// a decimal parse — which is what OpenSSH sends and what the client expects.
fn version_packet() -> Vec<u8> {
    let mut out = vec![SSH_FXP_VERSION];
    out.extend_from_slice(&3u32.to_be_bytes());
    for (name, revision) in [
        ("posix-rename@openssh.com", "1"),
        ("fsync@openssh.com", "1"),
    ] {
        put_string(&mut out, name.as_bytes());
        put_string(&mut out, revision.as_bytes());
    }
    out
}

fn status(id: u32, code: u32, message: &str) -> Vec<u8> {
    let mut out = vec![SSH_FXP_STATUS];
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&code.to_be_bytes());
    put_string(&mut out, message.as_bytes());
    put_string(&mut out, b"en");
    out
}

fn handle_packet(id: u32, handle: u32) -> Vec<u8> {
    let mut out = vec![SSH_FXP_HANDLE];
    out.extend_from_slice(&id.to_be_bytes());
    put_string(&mut out, &handle.to_be_bytes());
    out
}

fn data_packet(id: u32, data: &[u8]) -> Vec<u8> {
    let mut out = vec![SSH_FXP_DATA];
    out.extend_from_slice(&id.to_be_bytes());
    put_string(&mut out, data);
    out
}

fn name_packet(id: u32, name: &str) -> Vec<u8> {
    let mut out = vec![SSH_FXP_NAME];
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut out, name.as_bytes());
    put_string(&mut out, name.as_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out
}

fn names_packet(id: u32, entries: &[PathBuf]) -> Vec<u8> {
    let mut out = vec![SSH_FXP_NAME];
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for path in entries {
        let name = wire_name(path);
        put_string(&mut out, name.as_bytes());
        put_string(&mut out, name.as_bytes());
        // `symlink_metadata`: a directory listing describes the entries, and a
        // link that reported its target's type would make the walk's link policy
        // unreachable.
        match std::fs::symlink_metadata(path) {
            Ok(meta) => put_attrs(&mut out, &meta),
            // Something is there and this server cannot describe it. Sending no
            // attribute flags is legal in version 3 and is what a walk reads as
            // "type unknown", which is the honest answer.
            Err(_) => out.extend_from_slice(&0u32.to_be_bytes()),
        }
    }
    out
}

fn attrs_packet(id: u32, meta: &std::fs::Metadata) -> Vec<u8> {
    let mut out = vec![SSH_FXP_ATTRS];
    out.extend_from_slice(&id.to_be_bytes());
    put_attrs(&mut out, meta);
    out
}

/// Size, ownership, mode and both timestamps — the whole of what version 3
/// carries.
///
/// The mode matters most: the client reads the file *type* out of the permission
/// bits, so a server that left them off would make every entry's type unknown and
/// every `is_dir`/`is_file` decision in the backend unreachable.
fn put_attrs(out: &mut Vec<u8>, meta: &std::fs::Metadata) {
    out.extend_from_slice(
        &(ATTR_SIZE | ATTR_UIDGID | ATTR_PERMISSIONS | ATTR_ACMODTIME).to_be_bytes(),
    );
    out.extend_from_slice(&meta.len().to_be_bytes());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        out.extend_from_slice(&meta.uid().to_be_bytes());
        out.extend_from_slice(&meta.gid().to_be_bytes());
        out.extend_from_slice(&meta.mode().to_be_bytes());
        out.extend_from_slice(&(meta.atime() as u32).to_be_bytes());
        out.extend_from_slice(&(meta.mtime() as u32).to_be_bytes());
    }
    #[cfg(not(unix))]
    {
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        let mode: u32 = if meta.is_dir() { 0o040_755 } else { 0o100_644 };
        out.extend_from_slice(&mode.to_be_bytes());
        let seconds = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs() as u32);
        out.extend_from_slice(&seconds.to_be_bytes());
        out.extend_from_slice(&seconds.to_be_bytes());
    }
}

/// The access/modification pair a `SETSTAT` carried, when it carried one.
///
/// Returned rather than applied so the *request* can be asserted separately from
/// its effect: a stamp that reached the server and a stamp the filesystem
/// happened to have anyway are different facts.
fn read_attrs(cursor: &mut Cursor<'_>) -> Option<(u32, u32)> {
    let flags = cursor.u32();
    if flags & ATTR_SIZE != 0 {
        cursor.u64();
    }
    if flags & ATTR_UIDGID != 0 {
        cursor.u32();
        cursor.u32();
    }
    if flags & ATTR_PERMISSIONS != 0 {
        cursor.u32();
    }
    if flags & ATTR_ACMODTIME != 0 {
        let accessed = cursor.u32();
        let modified = cursor.u32();
        return Some((accessed, modified));
    }
    if flags & ATTR_EXTENDED != 0 {
        let count = cursor.u32();
        for _ in 0..count {
            cursor.string();
            cursor.string();
        }
    }
    None
}

/// Apply a whole-second access/modification pair, through the standard library.
///
/// `std::fs::File::set_times` rather than a crate: this is the only timestamp
/// write in the workspace's test support, and a product sold on a small audited
/// dependency surface does not grow one for a file that never ships.
fn set_times(path: &Path, accessed: u32, modified: u32) -> std::io::Result<()> {
    let at =
        |seconds: u32| std::time::UNIX_EPOCH + std::time::Duration::from_secs(u64::from(seconds));
    let times = std::fs::FileTimes::new()
        .set_accessed(at(accessed))
        .set_modified(at(modified));
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.set_times(times))
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A leaf name as it goes onto the wire.
fn wire_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The path this server would canonicalize a request to.
fn canonical(raw: &str) -> String {
    if raw.starts_with('/') {
        raw.to_string()
    } else if raw == "." || raw.is_empty() {
        "/".to_string()
    } else {
        format!("/{raw}")
    }
}

/// The protocol status an I/O error maps to.
fn errno_status(error: &std::io::Error) -> u32 {
    match error.kind() {
        std::io::ErrorKind::NotFound => SSH_FX_NO_SUCH_FILE,
        std::io::ErrorKind::PermissionDenied => SSH_FX_PERMISSION_DENIED,
        _ => SSH_FX_FAILURE,
    }
}

/// A reader over one request's payload.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, count: usize) -> &'a [u8] {
        let end = (self.at + count).min(self.bytes.len());
        let slice = &self.bytes[self.at.min(end)..end];
        self.at = end;
        slice
    }

    fn u32(&mut self) -> u32 {
        let slice = self.take(4);
        let mut buffer = [0u8; 4];
        buffer[..slice.len()].copy_from_slice(slice);
        u32::from_be_bytes(buffer)
    }

    fn u64(&mut self) -> u64 {
        let slice = self.take(8);
        let mut buffer = [0u8; 8];
        buffer[..slice.len()].copy_from_slice(slice);
        u64::from_be_bytes(buffer)
    }

    fn bytes(&mut self) -> &'a [u8] {
        let length = self.u32() as usize;
        self.take(length)
    }

    fn string(&mut self) -> String {
        String::from_utf8_lossy(self.bytes()).into_owned()
    }

    /// A handle, which this server mints as four big-endian bytes.
    fn handle(&mut self) -> u32 {
        let slice = self.bytes();
        let mut buffer = [0u8; 4];
        buffer[..slice.len().min(4)].copy_from_slice(&slice[..slice.len().min(4)]);
        u32::from_be_bytes(buffer)
    }
}
