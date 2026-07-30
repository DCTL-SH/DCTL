//! Opening an SFTP conversation — the first time, and every time after that.
//!
//! # The entry this closes
//!
//! `HANDOVER.md` §11.2: *"Re-dial a dead connection."* Every backend retried,
//! on a per-provider schedule, and none of them could re-establish anything. On
//! `sftp` that is not a small gap, because a dropped session invalidates **every
//! open handle**: the staging file a write was streaming into, the directory
//! handle a listing was paging, all of it. So a dead session was classified
//! terminal and said *"run the command again to open a new one"*, which is an
//! honest report of a thing the tool would not do.
//!
//! Retrying without re-dialling would have been worse than not retrying. It
//! would spend five attempts into a socket that is not there and then report
//! that five attempts were made — true, and useless, and exactly the shape of
//! claim `PLAN.md` §6 forbids.
//!
//! # The shape, which is rclone's
//!
//! rclone keeps a pool: `getSftpConnection` (`backend/sftp/sftp.go:804-833`)
//! pops a connection, asks `c.closed()` whether it is still alive, **discards it
//! if not**, and dials a new one when the pool yields nothing;
//! `putSftpConnection` (`:843`) probes a connection that has just failed with
//! something other than a plain protocol status and closes it if the probe
//! fails.
//!
//! DCTL holds one connection rather than a pool — nothing here is concurrent
//! across sessions — so the same idea is one cell that is either full or empty.
//! An operation that fails in a way that means *the conversation is over* empties
//! it ([`super::SftpBackend::discard`]), and the next operation finds it empty
//! and dials. The retry layer above is what turns that into a recovered
//! transfer, and it is why the classification in [`super::map_sftp_err`] could
//! change from terminal to transient: the next attempt now genuinely differs.
//!
//! # Why a trait and not a host name
//!
//! Because a re-dial that only works against a real `sshd` is a re-dial the
//! stated gate cannot hold, and `HANDOVER.md` §11.3 item 10 already exists
//! because two of this backend's guarantees were in exactly that position.
//! [`SftpDial`] is the seam `tests/sftp_mock.rs` supplies an in-process server
//! through, so *the real backend* re-dials *a real SFTP conversation* in
//! `cargo test --workspace`, with no host, no credentials and nothing installed.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use openssh::{KnownHosts, Session, SessionBuilder};
use openssh_sftp_client::{Sftp, SftpOptions};
use tokio::sync::Mutex;

use crate::error::{Result, StoreError};

/// One live SFTP conversation.
///
/// The session is held beside the channel so the `ControlMaster` mux stays up
/// for as long as anything is talking over it. [`None`] for a conversation that
/// runs over a plain byte-stream pair, where there is no ssh session behind it
/// at all — which is a legitimate answer and not a missing one.
pub struct Link {
    /// Kept alive alongside the SFTP channel; nothing reads it.
    #[allow(dead_code)]
    session: Option<Arc<Session>>,
    /// The channel every request goes down.
    pub(crate) sftp: Sftp,
    /// Whether this conversation is known to be over.
    ///
    /// On the connection rather than only in the backend's cell, and the reason
    /// is a hole the first draft of this module had. A staging file being
    /// streamed to holds its own `Arc<Link>` and does **not** hold the backend,
    /// so when a session died mid-write it had no way to reach the cell and say
    /// so — the next attempt's `create` went back into the dead session, failed,
    /// and only then discarded it. One wasted attempt out of six, silently.
    ///
    /// rclone puts the same knowledge in the same place: `conn.closed()`
    /// (`backend/sftp/sftp.go:698`) is a property of the connection, and the
    /// pool merely consults it.
    dead: AtomicBool,
}

impl Link {
    /// A conversation over `sftp`, keeping `session` alive for its lifetime.
    #[must_use]
    pub(crate) fn new(session: Option<Arc<Session>>, sftp: Sftp) -> Self {
        Self {
            session,
            sftp,
            dead: AtomicBool::new(false),
        }
    }

    /// Record that this conversation is over.
    ///
    /// Idempotent, and callable from anywhere holding the connection — which is
    /// the point: the writer streaming a staging file can say so without a
    /// reference to the backend.
    pub(crate) fn mark_dead(&self) {
        self.dead.store(true, Ordering::Release);
    }

    /// Whether anything has declared this conversation over.
    #[must_use]
    pub(crate) fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    /// Open a conversation over a pair of byte streams.
    ///
    /// Public because a [`SftpDial`] that a **test** supplies has to be able to
    /// produce a `Link`, and a pipe is the only kind of conversation a test can
    /// produce without an `sshd`. Without this the re-dial seam would be a trait
    /// nothing outside this crate could implement, which is the same as not
    /// having it: the guarantee's only witness would once again need a host, and
    /// `HANDOVER.md` §11.3 item 10 exists because two other guarantees were in
    /// exactly that position.
    ///
    /// `destination` is only for the message a failure carries.
    ///
    /// # Errors
    /// Whatever opening the SFTP conversation reported.
    pub async fn over_stream<W, R>(stdin: W, stdout: R, destination: &str) -> Result<Self>
    where
        W: tokio::io::AsyncWrite + Send + Unpin + 'static,
        R: tokio::io::AsyncRead + Send + Unpin + 'static,
    {
        let sftp = Sftp::new(stdin, stdout, SftpOptions::default())
            .await
            .map_err(|e| StoreError::Transport {
                backend: super::SFTP_BACKEND_NAME,
                detail: format!("open sftp subsystem on {destination}: {e}"),
            })?;
        Ok(Self::new(None, sftp))
    }
}

/// Something that can open a fresh SFTP conversation.
///
/// Implemented by [`SshDialer`] in production and by the test support module
/// that serves the protocol in this process. The trait is what makes re-dialling
/// provable without a host.
#[async_trait]
pub trait SftpDial: Send + Sync {
    /// Open a new conversation, from nothing.
    ///
    /// Called once when the backend is built and again after any failure that
    /// ended the last one, so an implementation must be genuinely repeatable —
    /// or say clearly that it is not, which is what [`StreamDialer`] does.
    ///
    /// # Errors
    /// Whatever reaching the far end reported.
    async fn dial(&self) -> Result<Link>;

    /// How this dialer names its destination, for a message an operator reads.
    fn destination(&self) -> &str;
}

/// Dials a real host over the system `ssh`.
///
/// The destination is resolved exactly as `ssh <host>` would — `ProxyCommand`,
/// `IdentityFile`, `User`, `Port` and every other `Host` directive apply —
/// which is the whole reason this backend drives the real binary rather than
/// linking a pure-Rust SSH client.
pub struct SshDialer {
    /// SSH destination: a `~/.ssh/config` alias or `user@host[:port]`.
    host: String,
    /// `--contimeout`, as `ssh -o ConnectTimeout`.
    ///
    /// Given to `ssh` rather than imposed from outside, and the difference
    /// matters: a `ProxyCommand cloudflared access ssh` host builds a tunnel, a
    /// TLS session and an SSH handshake before DCTL sees anything, and only
    /// `ssh` is in a position to bound that whole chain. rclone hands the same
    /// number to the same place (`backend/sftp/sftp.go:946`,
    /// `ssh.ClientConfig.Timeout = ci.ConnectTimeout`).
    connect: Option<Duration>,
}

impl SshDialer {
    /// A dialer for `host`, giving up on a connection after `connect`.
    #[must_use]
    pub fn new(host: impl Into<String>, connect: Option<Duration>) -> Self {
        Self {
            host: host.into(),
            connect,
        }
    }
}

#[async_trait]
impl SftpDial for SshDialer {
    async fn dial(&self) -> Result<Link> {
        // Host keys use `accept-new` semantics so a first-time connection to a
        // proxied host succeeds without an interactive prompt; the transport is
        // still authenticated by ssh (and, for cloudflared hosts, by the access
        // tunnel).
        let mut builder = SessionBuilder::default();
        builder.known_hosts_check(KnownHosts::Accept);
        if let Some(connect) = self.connect {
            builder.connect_timeout(connect);
        }
        let session = builder
            .connect_mux(&self.host)
            .await
            // `Transport`, not `Backend`: nothing answered, so this is the case
            // retrying — and, now, re-dialling — exists for. A host that is
            // briefly unreachable and a host that is misconfigured produce the
            // same words here and want different treatment, and only the
            // variant can say which this is.
            .map_err(|e| StoreError::Transport {
                backend: super::SFTP_BACKEND_NAME,
                detail: format!("ssh connect to {}: {e}", self.host),
            })?;
        let session = Arc::new(session);
        let sftp = Sftp::from_clonable_session(Arc::clone(&session), SftpOptions::default())
            .await
            .map_err(|e| StoreError::Transport {
                backend: super::SFTP_BACKEND_NAME,
                detail: format!("open sftp subsystem on {}: {e}", self.host),
            })?;
        Ok(Link::new(Some(session), sftp))
    }

    fn destination(&self) -> &str {
        &self.host
    }
}

/// A dialer holding one pair of byte streams, and therefore one conversation.
///
/// The honest expression of what [`super::SftpBackend::over_stream`] is: a pipe
/// has exactly one conversation in it, and when that one ends there is nothing
/// to dial again. Rather than pretend otherwise, the second call says so in a
/// sentence that names the constructor — because the alternative, silently
/// reusing a dead channel, is the failure this whole module exists to remove.
pub struct StreamDialer {
    /// The streams, taken by the first dial and gone thereafter.
    once: Mutex<Option<(BoxedWrite, BoxedRead)>>,
    /// What to call this in a message.
    destination: String,
}

/// The request sink half of a stream pair.
type BoxedWrite = Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'static>;
/// The response source half of a stream pair.
type BoxedRead = Box<dyn tokio::io::AsyncRead + Send + Unpin + 'static>;

impl StreamDialer {
    /// A one-shot dialer over `stdin` (requests) and `stdout` (responses).
    #[must_use]
    pub fn new<W, R>(stdin: W, stdout: R, destination: impl Into<String>) -> Self
    where
        W: tokio::io::AsyncWrite + Send + Unpin + 'static,
        R: tokio::io::AsyncRead + Send + Unpin + 'static,
    {
        Self {
            once: Mutex::new(Some((Box::new(stdin), Box::new(stdout)))),
            destination: destination.into(),
        }
    }
}

#[async_trait]
impl SftpDial for StreamDialer {
    async fn dial(&self) -> Result<Link> {
        let Some((stdin, stdout)) = self.once.lock().await.take() else {
            return Err(StoreError::Backend(format!(
                "the sftp conversation on {} has ended and cannot be re-opened: it runs \
                 over a single pair of byte streams, which are consumed once. A backend \
                 built by SftpBackend::connect re-dials; one built by \
                 SftpBackend::over_stream cannot.",
                self.destination
            )));
        };
        Link::over_stream(stdin, stdout, &self.destination).await
    }

    fn destination(&self) -> &str {
        &self.destination
    }
}
