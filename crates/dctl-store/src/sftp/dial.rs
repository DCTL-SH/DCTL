//! Opening an SFTP conversation — the first time, and every time after that.
//!
//! # The defect this closes
//!
//! **Re-dialling a dead connection.** Every backend retried, on a per-provider
//! schedule, and none of them could re-establish anything. On `sftp` that is
//! not a small gap, because a dropped session invalidates **every open
//! handle**: the staging file a write was streaming into, the directory handle
//! a listing was paging, all of it. So a dead session was classified terminal
//! and said *"run the command again to open a new one"*, which is an honest
//! report of a thing the tool would not do.
//!
//! Retrying without re-dialling would have been worse than not retrying. It
//! would spend five attempts into a socket that is not there and then report
//! that five attempts were made — true, and useless, and exactly the shape of
//! claim [the plan](https://doc.dctl.sh/project/plan) §6 forbids.
//!
//! # The shape, which is rclone's
//!
//! rclone keeps a pool: acquiring a connection pops one, asks whether it is
//! still alive, **discards it if not**, and dials a new one when the pool
//! yields nothing. A connection handed back after failing with something other
//! than a plain protocol status is probed first, and closed if the probe fails.
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
//! stated gate cannot hold, and two of this backend's guarantees were already
//! in exactly that position. [`SftpDial`] is the seam `tests/sftp_mock.rs`
//! supplies an in-process server through, so *the real backend* re-dials *a
//! real SFTP conversation* in `cargo test --workspace`, with no host, no
//! credentials and nothing installed.

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
    /// Kept alive alongside the SFTP channel, and read by
    /// [`super::space`] when a write is refused without a reason.
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
    /// rclone puts the same knowledge in the same place: liveness is a property
    /// of the connection, and the pool merely consults it.
    dead: AtomicBool,
    /// Remote files this session has open, kept between ranged reads.
    ///
    /// On the connection rather than on the backend so that invalidation is
    /// structural: a session that dies takes its handles with it, and the
    /// fresh `Link` the next operation dials starts empty. See
    /// [`super::handles`].
    pub(crate) handles: super::handles::HandleCache,
}

impl Link {
    /// A conversation over `sftp`, keeping `session` alive for its lifetime.
    #[must_use]
    pub(crate) fn new(session: Option<Arc<Session>>, sftp: Sftp) -> Self {
        Self {
            session,
            sftp,
            dead: AtomicBool::new(false),
            handles: super::handles::HandleCache::default(),
        }
    }

    /// The ssh session this conversation runs over, where there is one.
    ///
    /// [`None`] for a conversation over a plain byte-stream pair, which is a
    /// legitimate answer and not a missing one — it is what every in-process
    /// test server produces. A caller that needs to ask the far end a question
    /// the SFTP channel cannot carry ([`super::space`]) has to be able to find
    /// out that there is nobody to ask.
    #[must_use]
    pub(crate) fn session(&self) -> Option<&Session> {
        self.session.as_deref()
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
    /// two other guarantees were already in exactly that position.
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
    /// SSH destination, with any `:port` suffix removed: a `~/.ssh/config`
    /// alias, `user@host`, or a bare IPv6 literal.
    ///
    /// The port is split off rather than passed through because OpenSSH
    /// accepts `host:port` only in its `ssh://` URI form — as a bare
    /// destination, `archive.example.com:2222` is a *hostname* containing a
    /// colon, and it dies at DNS resolution. The configuration surface has
    /// documented `user@host[:port]` all along, so the parse belongs here
    /// rather than in the settings that promise it.
    host: String,
    /// The port that suffix named, given to `ssh` as `-o Port=`.
    ///
    /// [`None`] leaves the choice to `ssh`, which is what makes a `Port`
    /// directive in `~/.ssh/config` still apply — the reason this backend
    /// drives the real binary at all.
    port: Option<u16>,
    /// `--contimeout`, as `ssh -o ConnectTimeout`.
    ///
    /// Given to `ssh` rather than imposed from outside, and the difference
    /// matters: a `ProxyCommand cloudflared access ssh` host builds a tunnel, a
    /// TLS session and an SSH handshake before DCTL sees anything, and only
    /// `ssh` is in a position to bound that whole chain. rclone hands the same
    /// number to the same place, as the ssh client's own connect timeout.
    connect: Option<Duration>,
}

impl SshDialer {
    /// A dialer for `host`, giving up on a connection after `connect`.
    ///
    /// `host` may carry a `:port` suffix — see [`split_port`] for how the one
    /// spelling that genuinely collides with it, a bare IPv6 literal, is kept
    /// whole.
    #[must_use]
    pub fn new(host: impl Into<String>, connect: Option<Duration>) -> Self {
        let (host, port) = split_port(&host.into());
        Self {
            host,
            port,
            connect,
        }
    }
}

/// Split an ssh destination into what `ssh` should be given and the port it
/// named, if any.
///
/// Three rules, and the second is the whole difficulty:
///
/// 1. The suffix after the last `:` must parse as a port, or there is none.
/// 2. A bare IPv6 literal is *full of* colons — `user@fe80::1` ends in `:1`,
///    which parses perfectly as port 1 and would leave `ssh` dialling
///    `user@fe80:`. So an unbracketed host part containing another colon is
///    taken whole, exactly as `ssh` itself takes it.
/// 3. `[addr]:port` is therefore how an IPv6 literal names a port, and the
///    brackets are stripped: OpenSSH accepts them only inside an `ssh://`
///    URI, and `-o Port=` carries the number separately anyway.
///
/// Deliberately not delegated to the `openssh` crate's `ssh://` parser, whose
/// `rfind`-based split has exactly the rule-2 defect on unbracketed literals.
fn split_port(host: &str) -> (String, Option<u16>) {
    let whole = || (host.to_string(), None);

    let Some(colon) = host.rfind(':') else {
        return whole();
    };
    let Ok(port) = host[colon + 1..].parse::<u16>() else {
        return whole();
    };
    if port == 0 {
        return whole();
    }

    let host_part = &host[..colon];
    let user_len = host_part.rfind('@').map_or(0, |at| at + 1);
    let host_only = &host_part[user_len..];

    if host_only.starts_with('[') && host_only.ends_with(']') && host_only.len() > 2 {
        // `[::1]:2222` — the bracketed form exists precisely to disambiguate,
        // so the brackets have done their job and come off.
        let inner = &host_only[1..host_only.len() - 1];
        return (format!("{}{inner}", &host_part[..user_len]), Some(port));
    }
    if host_only.contains(':') {
        // Rule 2: an unbracketed IPv6 literal. Taken whole, or its last group
        // is eaten as a port number.
        return whole();
    }
    (host_part.to_string(), Some(port))
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
        // Only when the destination named one: leaving it unset is what keeps
        // a `Port` directive in the operator's own ssh config in force.
        if let Some(port) = self.port {
            builder.port(port);
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

#[cfg(test)]
mod tests {
    use super::{SshDialer, split_port};

    #[test]
    fn a_port_suffix_is_split_off_rather_than_dialled_as_a_hostname() {
        // The documented `user@host[:port]` form: OpenSSH takes a bare
        // destination as a hostname, so `archive.example.com:2222` used to
        // reach DNS as a host called "archive.example.com:2222" and fail there.
        assert_eq!(
            split_port("root@archive.example.com:2222"),
            ("root@archive.example.com".to_string(), Some(2222))
        );
        assert_eq!(
            split_port("archive.example.com:22"),
            ("archive.example.com".to_string(), Some(22))
        );
    }

    #[test]
    fn a_destination_without_a_port_is_passed_through_untouched() {
        // An alias resolves through the operator's own ssh config, which is
        // the entire reason this backend drives the real binary.
        for host in [
            "archive.example.com",
            "root@archive.example.com",
            "build.example.com",
        ] {
            assert_eq!(split_port(host), (host.to_string(), None));
        }
        // Not a port: left alone rather than half-parsed.
        assert_eq!(
            split_port("host:notaport"),
            ("host:notaport".to_string(), None)
        );
        assert_eq!(split_port("host:0"), ("host:0".to_string(), None));
        assert_eq!(
            split_port("host:99999"),
            ("host:99999".to_string(), None),
            "a number outside the port range is not a port"
        );
    }

    #[test]
    fn a_bare_ipv6_literal_keeps_its_last_group() {
        // The collision this parse exists to survive: `fe80::1` ends in `:1`,
        // which parses as port 1 — and dialling `user@fe80:` reaches nothing.
        // A bare literal is taken whole, exactly as `ssh` takes it.
        for host in ["fe80::1", "user@fe80::1", "::1", "2001:db8::dead:beef"] {
            assert_eq!(
                split_port(host),
                (host.to_string(), None),
                "{host} must survive intact"
            );
        }
    }

    #[test]
    fn brackets_are_how_an_ipv6_literal_names_a_port_and_they_come_off() {
        // The bracketed form is the disambiguation, so once it has done its
        // job the brackets go: OpenSSH accepts them only inside an ssh:// URI,
        // and the port travels separately as `-o Port=`.
        assert_eq!(split_port("[::1]:2222"), ("::1".to_string(), Some(2222)));
        assert_eq!(
            split_port("root@[fe80::1]:2222"),
            ("root@fe80::1".to_string(), Some(2222))
        );
        // Bracketed with no port: still unwrapped by ssh itself, so left as
        // typed rather than half-processed here.
        assert_eq!(split_port("[::1]"), ("[::1]".to_string(), None));
    }

    #[test]
    fn the_dialer_reports_the_destination_it_will_actually_dial() {
        // What an operator reads in a connection failure has to be what was
        // attempted, not what they typed.
        let dialer = SshDialer::new("root@archive.example.com:2222", None);
        assert_eq!(dialer.host, "root@archive.example.com");
        assert_eq!(dialer.port, Some(2222));
    }
}
