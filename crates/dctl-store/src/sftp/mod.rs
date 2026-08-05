//! Native SFTP backend — a verified-write [`Backend`] over an SSH host, driven by
//! the **system `ssh`** so `~/.ssh/config` is honoured transparently.
//!
//! # Why the system ssh (and not a pure-Rust SSH client)
//!
//! DCTL's target hosts are often only reachable through an
//! `~/.ssh/config` entry — e.g. `backup.example.com` uses
//! `ProxyCommand cloudflared access ssh --hostname %h` plus a specific
//! `IdentityFile`. A pure-Rust SSH library (russh/ssh2) would ignore that
//! `ProxyCommand` and could never connect. So this backend uses the [`openssh`]
//! crate, which drives the real `ssh` binary and keeps a persistent multiplexed
//! (`ControlMaster`) session: [`Session::connect_mux`] resolves the destination
//! exactly as `ssh <host>` would — `ProxyCommand`, `IdentityFile`, `User`,
//! `Port`, and every other `Host` directive apply — and [`openssh_sftp_client`]
//! runs the `sftp` subsystem over that same mux session for all file
//! operations.
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
//! not, and the cost of that is what the next section sets out.
//!
//! # What is below the trait, and how it is reached
//!
//! The trait ends where the client library begins, and three guarantees live on
//! the far side of it: the `SETSTAT` above, the `mkdir -p` that must never
//! re-create the configured base ([`path::ancestor_dirs_below`]), and the base
//! probe [`Backend::store_identity`] answers from. Deleting any of the three
//! left `cargo test --workspace` green, because their only witness was
//! `tests/sftp_live.rs` and that needs `DCTL_SFTP_HOST`.
//!
//! [`SftpBackend::over_stream`] is the answer: this backend will speak its
//! protocol down any pair of byte streams, so `tests/sftp_mock.rs` runs it
//! against an SFTP version-3 server in the same process. Real client, real
//! packets, real files at the other end, and no host.

pub mod base;
pub mod dial;
mod handles;
mod ops;
mod path;
mod space;
mod status;
mod tree;
mod write;

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use openssh_sftp_client::Error as SftpError;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::sync::RwLock;

use crate::backend::Backend;
use crate::checksum::ContentHash;
use crate::deadline::{Deadlines, IdleWatch};
use crate::error::{Result, StoreError};
use crate::links::{LinkPolicy, LinkReport};
use crate::meter::{self, Meter};
use crate::model::{ByteRange, ObjectKey, ObjectMeta, Page, PutOutcome};
use crate::modified::SourceModified;
use crate::specials::SpecialReport;
use crate::staging::{StagingListing, Want};

use dial::{Link, SftpDial, SshDialer, StreamDialer};
use path::{chunk_spans, join, normalize_base, prefix_dir, remote_path, temp_path};

/// This backend's name, as [`Backend::name`] spells it and as a lost session or
/// a stalled request is attributed.
pub(crate) const SFTP_BACKEND_NAME: &str = "sftp";

/// Open remote read handles one session keeps between ranged reads.
///
/// Each is one open descriptor in the remote `sftp-server`. The protocol sets
/// no limit; the practical ceiling is the server's `RLIMIT_NOFILE`, whose
/// commonest soft default is 1024 — so sixteen sits two orders of magnitude
/// under it while covering what a mount actually does: a handful of concurrent
/// readers, each with `MOUNT_READ_AHEAD_DEPTH` windows in flight, all of them
/// inside a few distinct objects. See [`handles`] for what a kept handle
/// serves and why that is safe here.
pub(crate) const CACHED_READ_HANDLES: usize = 16;

/// Default transfer-chunk size for the streaming upload/download paths. Peak
/// memory on those paths is `O(chunk)`, independent of object size.
///
/// No longer *fixed*: a remote's `chunk_size` setting overrides it
/// ([`SftpConfig::with_chunk_size`]). It stays the default because 4 MiB is a
/// window a slow uplink fills often enough to keep the deadline's heartbeat
/// beating and large enough that a 4 GiB restore is not a million round trips.
const CHUNK_LEN: u64 = 4 * 1024 * 1024;

/// Smallest transfer window a remote may pin.
///
/// Below this the request overhead dominates the payload — an SFTP write is a
/// header, a handle and an offset per packet — so a smaller window buys no
/// memory worth the round trips it costs. It is a *clamp* rather than a
/// refusal for the reason `crate::b2` clamps its part size: the operator asked
/// for the smallest footprint they could get, and answering with an error
/// instead of the smallest footprint available serves nobody.
const MIN_CHUNK_LEN: u64 = 32 * 1024;

/// Largest transfer window a remote may pin.
///
/// The window *is* the peak of a streaming transfer, so the ceiling is what
/// stops a mistyped `chunk_size = 8589934592` from turning a memory setting into
/// an out-of-memory kill. 64 MiB is well past the point where a bigger window
/// buys throughput on any link this backend is used over.
const MAX_CHUNK_LEN: u64 = 64 * 1024 * 1024;

/// The default has to sit inside the range a remote may pin, or an operator
/// could not ask for the value they already have — and a zero window would spin
/// forever. Checked at compile time rather than by a test, because these are
/// constants and a test of a constant is a test that can only fail once.
const _: () = assert!(0 < MIN_CHUNK_LEN && MIN_CHUNK_LEN < CHUNK_LEN && CHUNK_LEN < MAX_CHUNK_LEN);

/// The transfer window a remote's `chunk_size` asks for, brought into the range
/// this backend can actually work in.
///
/// Clamped rather than refused, and [`None`] rather than a substituted default,
/// so the two states an operator can be in stay distinguishable: pinning
/// nothing takes [`CHUNK_LEN`], and pinning something unreachable takes the
/// nearest reachable value instead of failing a backup at 02:00.
const fn clamp_chunk_len(requested: Option<u64>) -> u64 {
    match requested {
        None => CHUNK_LEN,
        Some(size) if size < MIN_CHUNK_LEN => MIN_CHUNK_LEN,
        Some(size) if size > MAX_CHUNK_LEN => MAX_CHUNK_LEN,
        Some(size) => size,
    }
}

/// Objects returned per [`Backend::list_page`] call.
const PAGE_SIZE: usize = 1000;

/// Connection settings for an [`SftpBackend`].
///
/// The one required field is [`host`](SftpConfig::host): a destination `ssh`
/// understands — a bare `Host` alias from `~/.ssh/config` (e.g.
/// `"backup.example.com"`), or a full `user@host:port`. Resolving
/// user/port/identity/ProxyCommand is delegated to `ssh` and the user's config,
/// which is exactly what makes cloudflared-proxied hosts work.
/// [`base`](SftpConfig::base) is the remote directory objects live under.
#[derive(Clone, Debug)]
pub struct SftpConfig {
    /// SSH destination as `ssh` resolves it: a `~/.ssh/config` `Host` alias or
    /// `user@host[:port]`. All other connection parameters come from ssh config.
    ///
    /// A `:port` suffix is split off and given to `ssh` as `-o Port=`, because
    /// OpenSSH reads a bare `host:port` as a hostname and fails at DNS. An
    /// IPv6 literal with a port therefore needs brackets — `[fe80::1]:2222` —
    /// while a bare literal passes through whole.
    pub host: String,
    /// Remote base directory for objects. `~/…` is home-relative; `/…` is absolute.
    pub base: String,
    /// What the listing walk does with the symbolic links it finds.
    ///
    /// `/srv/data -> /mnt/bigdisk/data` is the canonical layout on exactly the
    /// kind of host this backend reaches, and the walk used to drop it without a
    /// word. See [`crate::links`].
    pub links: LinkPolicy,
    /// Transfer window for the streaming paths, in bytes.
    ///
    /// [`None`] takes [`CHUNK_LEN`]. This is the remote's `chunk_size` setting
    /// arriving, and it is a *window* rather than a part: SFTP has no multipart
    /// API, so peak memory on a streaming read or write is one of these and
    /// nothing else. An operator with a container smaller than the compiled-in
    /// default has no other way to say so.
    pub chunk_size: Option<u64>,
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
            chunk_size: None,
        }
    }

    /// The same config, walking symbolic links under `policy`.
    #[must_use]
    pub fn with_links(mut self, policy: LinkPolicy) -> Self {
        self.links = policy;
        self
    }

    /// The same config, transferring in windows of `chunk_size` bytes.
    ///
    /// Takes an [`Option`] rather than a `u64` so "the operator pinned nothing"
    /// stays distinguishable from "the operator pinned the default", which is
    /// the distinction that lets [`clamp_chunk_len`] refuse a useless value
    /// without refusing an absent one.
    #[must_use]
    pub fn with_chunk_size(mut self, chunk_size: Option<u64>) -> Self {
        self.chunk_size = chunk_size;
        self
    }
}

/// A [`Backend`] over SFTP, on a persistent multiplexed system-`ssh` session.
///
/// Construct one with [`SftpBackend::connect`]. The session and SFTP channel stay
/// open for the lifetime of the value and are torn down on drop.
pub struct SftpBackend {
    /// How a conversation with this destination is opened — the first one, and
    /// every one after a session dies. See [`dial`].
    dialer: Arc<dyn SftpDial>,
    /// The live conversation, or [`None`] when the last one ended and the next
    /// operation must open another.
    ///
    /// A cell rather than a field, because "the session is gone" has to be
    /// expressible. It is the one-connection form of rclone's connection pool,
    /// which discards a closed connection on the way out and dials when it
    /// finds nothing to hand over.
    ///
    /// An `RwLock` and not a `Mutex`: every ordinary operation only *reads* it,
    /// so concurrent requests on one healthy session do not queue behind each
    /// other, and only a dial or a discard takes the write side.
    link: RwLock<Option<Arc<Link>>>,
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
    ///
    /// Decided on the **first** dial and carried across every re-dial, which is
    /// the same rule stated against a new fact. A re-dial that re-probed would
    /// answer the question again on a session opened *after* the base was
    /// renamed away, get "not there, so make it", and re-create underneath the
    /// run precisely the directory this field exists to protect.
    may_create_base: bool,
    /// How long this run waits for a request that has stopped moving. See
    /// [`crate::deadline`].
    ///
    /// The connect half of the pair is not here: it belongs to the dialer, which
    /// is the only thing that connects.
    deadlines: Deadlines,
    /// The window every streaming read and write moves bytes in, already
    /// clamped. See [`clamp_chunk_len`].
    ///
    /// Held resolved rather than as the `Option` the operator wrote, so no call
    /// site can forget the clamp and no two call sites can disagree about the
    /// default — which is how `chunk_size` came to mean one thing in the resolver
    /// and nothing at all here.
    chunk: u64,
}

impl SftpBackend {
    /// Connect to `cfg.host` over a multiplexed system-`ssh` session (honoring
    /// `~/.ssh/config`, including any `ProxyCommand`) and open the SFTP subsystem.
    ///
    /// Host keys use `accept-new` semantics ([`KnownHosts::Accept`]) so a
    /// first-time connection to a proxied host succeeds without an interactive
    /// prompt; transport authentication is still provided by ssh (and, for
    /// cloudflared hosts, the access tunnel).
    /// `deadlines` is a required argument rather than a builder, for the reason
    /// [`crate::b2::B2Backend::new`] gives: a run-scoped setting that *can* be
    /// dropped eventually is, and this crate has already paid for that once.
    pub async fn connect(cfg: SftpConfig, deadlines: Deadlines) -> Result<Self> {
        let dialer = Arc::new(SshDialer::new(cfg.host.clone(), deadlines.connect));
        Ok(Self::over_dialer(dialer, &cfg.base, cfg.links, deadlines)
            .await?
            .with_chunk_size(cfg.chunk_size))
    }

    /// The same backend, speaking SFTP over an arbitrary byte-stream pair.
    ///
    /// **The only way into this backend that does not dial an ssh host**, and it
    /// exists for the reason [`crate::b2::B2Backend::with_authorize_url`] exists.
    /// Three of this backend's guarantees — the `SETSTAT` that carries the
    /// source's modification time, the `mkdir -p` that must never re-create the
    /// configured base, and the base probe the store guard rests on — live
    /// *below* the [`ops::RemoteFs`] seam, in the code that talks to the client
    /// library. Their only witness was `tests/sftp_live.rs`, which is
    /// `#[ignore]`d and needs `DCTL_SFTP_HOST`, so deleting any of the three left
    /// `cargo test --workspace` entirely green.
    ///
    /// `stdin` is where requests are written and `stdout` is where responses are
    /// read — the shape a subprocess's pipes have, and the shape
    /// `tests/support/mock_sftp.rs` hands over. Nothing in `dctl-cli` calls this;
    /// production always goes through [`connect`](Self::connect).
    ///
    /// # Errors
    /// Whatever opening the SFTP conversation reported.
    pub async fn over_stream<W, R>(
        stdin: W,
        stdout: R,
        base: &str,
        links: LinkPolicy,
        deadlines: Deadlines,
    ) -> Result<Self>
    where
        W: tokio::io::AsyncWrite + Send + Unpin + 'static,
        R: tokio::io::AsyncRead + Send + Unpin + 'static,
    {
        let dialer = Arc::new(StreamDialer::new(stdin, stdout, "a stream"));
        Self::over_dialer(dialer, base, links, deadlines).await
    }

    /// The same backend, opening every conversation through `dialer`.
    ///
    /// **The seam that makes re-dialling testable**, and the reason it is public.
    /// A re-dial whose only witness needs a real `sshd` is a re-dial the stated
    /// gate does not hold — which is the position two of this backend's other
    /// guarantees were in, and the gap this seam exists for. A dialer that
    /// serves the protocol in this process closes it: the real backend, the
    /// real client library, the real packets, dialled again for real after a
    /// session is severed.
    ///
    /// # Errors
    /// Whatever the first dial reported.
    pub async fn over_dialer(
        dialer: Arc<dyn SftpDial>,
        base: &str,
        links: LinkPolicy,
        deadlines: Deadlines,
    ) -> Result<Self> {
        let base = normalize_base(base);
        // The first dial is bounded exactly as every later one is. A run that
        // could not be ended while it was *opening* its first connection would
        // be a run `--max-duration` did not cover, and the case is not
        // hypothetical: the measured `sftp:` arm hung on a replacement `ssh`,
        // and nothing about the first `ssh` makes it different from the second.
        let link = Arc::new(dial_within(dialer.as_ref(), &deadlines).await?);
        // One `stat`, on the first connection only. A base that is absent now
        // may be created by the first write; one that is present may never be
        // re-created by any write in this run — and neither answer is re-asked
        // on a later connection. See [`SftpBackend::may_create_base`].
        //
        // Under the run's deadlines like every other request: a probe on a
        // session that has gone quiet is as unbounded as any other, and it is
        // the very first thing this backend does.
        let may_create_base = {
            let probe = if base.is_empty() { "." } else { &base };
            let watch = deadlines.watch();
            match watch.guard(link.sftp.fs().metadata(probe)).await {
                Ok(probed) => probed.is_err(),
                // A probe the deadline ended answers nothing, and answering it
                // "absent" would let a later write re-create a base that is
                // there — the defect `may_create_base` exists to prevent.
                Err(expired) => return Err(expired.into_store_error(SFTP_BACKEND_NAME)),
            }
        };
        Ok(Self {
            dialer,
            link: RwLock::new(Some(link)),
            base,
            links,
            meter: meter::unmetered(),
            may_create_base,
            deadlines,
            chunk: clamp_chunk_len(None),
        })
    }

    /// The same backend, moving bytes in windows of `chunk_size`.
    ///
    /// A builder for the reason [`SftpBackend::with_meter`] is one: the window is
    /// a property of the *invocation* — an operator's answer to how much memory
    /// this run may have — rather than of the destination, and threading it
    /// through [`over_dialer`](Self::over_dialer) would put it in the two
    /// constructors that exist for tests as well as the one that exists for
    /// production.
    ///
    /// [`None`] restores the default, so the setter is total rather than
    /// one-way.
    #[must_use]
    pub fn with_chunk_size(mut self, chunk_size: Option<u64>) -> Self {
        self.chunk = clamp_chunk_len(chunk_size);
        self
    }

    /// The window this backend moves bytes in, after clamping.
    ///
    /// The far end of the `chunk_size` journey, and public so a test can assert
    /// it without a server: the middle of a setting's path is where this
    /// project loses one, so both ends are pinned and the resolver's end alone
    /// is not enough.
    #[must_use]
    pub const fn chunk_size(&self) -> u64 {
        self.chunk
    }

    /// The live conversation, opening one if the last ended.
    ///
    /// Read-locked on the happy path so concurrent requests on a healthy session
    /// do not serialise. The re-check after taking the write lock is not
    /// belt-and-braces: two operations that both found the cell empty would
    /// otherwise dial twice and leave one connection with no owner.
    pub(crate) async fn link(&self) -> Result<Arc<Link>> {
        if let Some(live) = self.link.read().await.as_ref()
            && !live.is_dead()
        {
            return Ok(Arc::clone(live));
        }
        let mut cell = self.link.write().await;
        if let Some(live) = cell.as_ref()
            && !live.is_dead()
        {
            return Ok(Arc::clone(live));
        }
        tracing::debug!(
            destination = self.dialer.destination(),
            "re-dialling the sftp session"
        );
        let fresh = Arc::new(dial_within(self.dialer.as_ref(), &self.deadlines).await?);
        *cell = Some(Arc::clone(&fresh));
        Ok(fresh)
    }

    /// Drop `dead` so the next operation dials a new conversation.
    ///
    /// The [`Arc::ptr_eq`] guard is the whole correctness of this function. Two
    /// operations that fail on the same dead session both arrive here, and the
    /// second must not discard the *replacement* the first one's retry has
    /// already dialled — which would turn one dead connection into an unbounded
    /// sequence of them, each killed by the previous failure's bookkeeping.
    /// Forget any open read handle for `remote` on the live session.
    ///
    /// Called by every path that replaces or removes an object, so a cached
    /// handle can never serve the bytes of a file this backend itself has
    /// just written over. DCTL writes by staging and renaming, so the old
    /// handle would name a superseded inode — correct POSIX behaviour, and
    /// the wrong answer to "read the object at this key".
    pub(crate) async fn forget_handle(&self, remote: &str) {
        if let Some(link) = self.link.read().await.as_ref() {
            link.handles.evict(remote);
        }
    }

    pub(crate) async fn discard(&self, dead: &Arc<Link>) {
        // Marked first, so anything already holding this connection — a staging
        // file being written to, a listing being paged — sees it even if the
        // cell has since been refilled by somebody else's re-dial.
        dead.mark_dead();
        let mut cell = self.link.write().await;
        if cell.as_ref().is_some_and(|live| Arc::ptr_eq(live, dead)) {
            tracing::debug!(
                destination = self.dialer.destination(),
                "discarding a dead sftp session"
            );
            *cell = None;
        }
    }

    /// A fresh inactivity watch for one operation.
    ///
    /// Handed out for the write path, where the operation outlives any single
    /// call: `ops::SftpStagedFile` holds one for a whole object and every chunk
    /// that lands feeds it.
    pub(crate) fn watch(&self) -> IdleWatch {
        self.deadlines.watch()
    }

    /// Run one protocol operation on the live conversation, under this run's
    /// inactivity deadline, discarding the conversation if it does not survive.
    ///
    /// Every request this backend makes goes through here, which is what makes
    /// the two guarantees uniform rather than remembered. A stall and a lost
    /// session are treated identically and deliberately: dropping the future is
    /// how a timeout cancels a request, and a cancelled request leaves a reply
    /// nobody will read on a multiplexed channel, so a session that has just
    /// timed out is no more reusable than one that died. Putting it back would
    /// turn one slow request into every later request failing.
    pub(crate) async fn on_link<T, F, Fut>(&self, op: F) -> Result<T>
    where
        F: FnOnce(Arc<Link>) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        self.watched(|link, _| op(link)).await
    }

    /// The same, for an operation that moves a body and must therefore report
    /// its own progress.
    ///
    /// The distinction is not cosmetic and the first draft of this module got it
    /// wrong. [`on_link`](Self::on_link) is right for a request that is over in
    /// one exchange — a `stat`, a `rename` — where "the operation finished" and
    /// "bytes moved" are the same event. For a download that reads a 4 GiB
    /// object in 4 MiB chunks they are not: a watch nothing touched would be a
    /// deadline on the **whole transfer**, so `--timeout 300` would kill every
    /// restore that took longer than five minutes *while it was succeeding*.
    /// That is precisely the failure an idle timeout exists not to have.
    pub(crate) async fn watched<T, F, Fut>(&self, op: F) -> Result<T>
    where
        F: FnOnce(Arc<Link>, IdleWatch) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let link = self.link().await?;
        let watch = self.deadlines.watch();
        let outcome = match watch.guard(op(Arc::clone(&link), watch.clone())).await {
            Ok(result) => result,
            Err(expired) => Err(expired.into_store_error(SFTP_BACKEND_NAME)),
        };
        if let Err(error) = &outcome
            && is_session_lost(error)
        {
            self.discard(&link).await;
        }
        outcome
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
        let base = base.to_string();
        self.on_link(|link| async move {
            match link.sftp.fs().metadata(&base).await {
                Ok(md) => Ok(md
                    .file_type()
                    .is_none_or(|kind| kind.is_dir())
                    .then(crate::guard::StoreIdentity::existence_only)),
                Err(e) => match map_sftp_err(&base, e) {
                    StoreError::NotFound(_) => Ok(None),
                    other => Err(other),
                },
            }
        })
        .await
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
        // The rename gave this key a new inode; any handle still open names
        // the superseded one.
        self.forget_handle(&remote).await;
        // One window, because the whole object was one window — the buffered
        // write is the path a small object takes.
        meter::charge(self.meter.as_ref(), moved).await;
        Ok(outcome)
    }

    /// The same write, fed from a file instead of memory, at `O(self.chunk)`
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
        let outcome = write::put_stream(
            self,
            &remote,
            &mut src,
            write::Incoming {
                total,
                chunk: self.chunk,
                expected,
                modified,
            },
            self.meter.as_ref(),
        )
        .await;
        self.forget_handle(&remote).await;
        outcome
    }

    /// The same staged write, fed by a producer instead of by a file.
    ///
    /// SFTP takes a stream directly — the protocol has no parts and declares no
    /// content length — so a window goes onto the wire as it arrives and the peak
    /// is one window rather than one part. The order and every guarantee around it
    /// live in [`write::put_object_stream`], stated against [`ops::RemoteFs`] so
    /// they are provable with no server in reach.
    async fn put_stream(
        &self,
        key: &ObjectKey,
        mut source: crate::incoming::ObjectStream,
        modified: SourceModified,
    ) -> Result<PutOutcome> {
        let remote = remote_path(&self.base, key)?;
        let outcome =
            write::put_object_stream(self, &remote, &mut source, modified, self.meter.as_ref())
                .await;
        self.forget_handle(&remote).await;
        outcome
    }

    async fn get(&self, key: &ObjectKey) -> Result<Bytes> {
        let remote = remote_path(&self.base, key)?;
        let bytes = self
            .on_link(|link| async move {
                match link.sftp.fs().read(&remote).await {
                    Ok(buf) => Ok(buf.freeze()),
                    Err(e) => Err(map_sftp_err(&remote, e)),
                }
            })
            .await?;
        meter::charge(self.meter.as_ref(), bytes.len() as u64).await;
        Ok(bytes)
    }

    async fn get_to_path(&self, key: &ObjectKey, dest: &Path) -> Result<()> {
        let remote = remote_path(&self.base, key)?;

        // Size first (also the missing→NotFound check), then stream the body down
        // in bounded chunks to a local temp, fsync, and atomically rename — so a
        // failure mid-transfer never leaves a partial object at `dest`.
        //
        // One `on_link` for the whole download rather than one per chunk,
        // because the file handle belongs to the conversation that opened it: a
        // session that dies halfway invalidates the handle as well as the
        // request in flight, and the two have to end together. The deadline
        // therefore spans the transfer and is reset by every chunk that lands,
        // which is what makes an hours-long restore never approach it.
        //
        // Bound outside the closure: `self` is not in scope inside it, and the
        // loop below binds `chunk` to the *bytes* it read, so the window keeps a
        // name of its own rather than being shadowed by its own payload.
        let window = self.chunk;
        self.watched(|link, watch| async move {
            let mut file = link
                .sftp
                .open(&remote)
                .await
                .map_err(|e| map_sftp_err(&remote, e))?;
            let total = file
                .metadata()
                .await
                .map_err(|e| map_sftp_err(&remote, e))?
                .len()
                .ok_or_else(|| {
                    StoreError::Backend("sftp server did not return file size".into())
                })?;

            if let Some(parent) = dest.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let tmp = local_temp(dest);
            let out = tokio::fs::File::create(&tmp).await?;
            let mut writer = tokio::io::BufWriter::with_capacity(window as usize, out);

            for span in chunk_spans(total, window) {
                let chunk = match file.read_all(span.len as usize, BytesMut::new()).await {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = tokio::fs::remove_file(&tmp).await;
                        return Err(map_sftp_err(&remote, e));
                    }
                };
                // The deadline own heartbeat, and the reason this loop uses
                // `watched` rather than `on_link`: a chunk that arrived is proof
                // the link is alive, so an hours-long restore over a slow uplink
                // resets its patience every window instead of running out of it.
                watch.touch();
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
        })
        .await
    }

    async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> Result<Bytes> {
        let remote = remote_path(&self.base, key)?;
        let bytes = self
            .on_link(|link| async move {
                // The handle this session already holds, if it has one. A
                // mount fetches chunk after chunk of the same object, and
                // re-opening for each cost an OPEN and an FSTAT round trip on
                // top of the READ — the dominant per-request cost on a real
                // link. See `handles` for what a kept handle serves.
                let (mut file, size) = match link.handles.get(&remote) {
                    Some(open) => open,
                    None => {
                        let mut file = link
                            .sftp
                            .open(&remote)
                            .await
                            .map_err(|e| map_sftp_err(&remote, e))?;
                        let size = file
                            .metadata()
                            .await
                            .map_err(|e| map_sftp_err(&remote, e))?
                            .len()
                            .ok_or_else(|| {
                                StoreError::Backend("sftp server did not return file size".into())
                            })?;
                        link.handles.put(remote.clone(), file.clone(), size);
                        (file, size)
                    }
                };

                if range.offset > size {
                    return Err(StoreError::RangeOutOfBounds { size });
                }
                let available = size - range.offset;
                let to_read = range.length.map_or(available, |len| len.min(available));

                // Streaming seek: read exactly the requested window at `offset`,
                // never the whole object. `read_all` internally chunks to the
                // sftp v3 max read length. Seeking is local — the position
                // rides on this clone of the handle, not on the server — so a
                // shared handle cannot have its offset moved underneath it.
                if let Err(error) = file.seek(std::io::SeekFrom::Start(range.offset)).await {
                    // A handle that failed is a handle nothing should reuse.
                    link.handles.evict(&remote);
                    return Err(error.into());
                }
                let read = file
                    .read_all(to_read as usize, BytesMut::with_capacity(to_read as usize))
                    .await;
                match read {
                    Ok(buf) => Ok(buf.freeze()),
                    Err(error) => {
                        link.handles.evict(&remote);
                        Err(map_sftp_err(&remote, error))
                    }
                }
            })
            .await?;
        meter::charge(self.meter.as_ref(), bytes.len() as u64).await;
        Ok(bytes)
    }

    /// Nothing — the same answer [`crate::local::LocalFs`] gives, and for the
    /// same reason: the far end of this protocol is a filesystem.
    ///
    /// SFTP version 3 has no request that returns a digest of a file, and the
    /// two extensions OpenSSH does advertise (`fsync@openssh.com`,
    /// `statvfs@openssh.com`) are about durability and free space. A server
    /// that could hash a file on request would still be hashing whatever the
    /// file says today, which is not what a rot check needs.
    fn checksum_support(&self) -> crate::recorded::ChecksumSupport {
        crate::recorded::ChecksumSupport::None(crate::recorded::NO_RECORDED_CHECKSUM_FILESYSTEM)
    }

    /// Absent for every key, without a request: see
    /// [`checksum_support`](Backend::checksum_support).
    async fn stored_checksum(&self, _key: &ObjectKey) -> Result<crate::recorded::StoredChecksum> {
        Ok(crate::recorded::StoredChecksum::Absent(
            crate::recorded::NO_RECORDED_CHECKSUM_FILESYSTEM.to_string(),
        ))
    }

    async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta> {
        let remote = remote_path(&self.base, key)?;
        let md = self
            .on_link(|link| async move {
                link.sftp
                    .fs()
                    .metadata(&remote)
                    .await
                    .map_err(|e| map_sftp_err(&remote, e))
            })
            .await?;
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
        self.on_link(|link| async move {
            match link.sftp.fs().metadata(&remote).await {
                Ok(md) => Ok(md.file_type().is_none_or(|t| t.is_file())),
                Err(e) => match map_sftp_err(&remote, e) {
                    StoreError::NotFound(_) => Ok(false),
                    other => Err(other),
                },
            }
        })
        .await
    }

    async fn delete(&self, key: &ObjectKey) -> Result<()> {
        let remote = remote_path(&self.base, key)?;
        self.on_link(|link| async move {
            // Before the removal, so no window between the unlink and the
            // forget can hand a caller a handle to a deleted object.
            link.handles.evict(&remote);
            match link.sftp.fs().remove_file(&remote).await {
                Ok(()) => Ok(()),
                // Deleting a missing object is a no-op success (idempotent).
                Err(e) => match map_sftp_err(&remote, e) {
                    StoreError::NotFound(_) => Ok(()),
                    other => Err(other),
                },
            }
        })
        .await
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
        let links = self.links;
        let walked = self
            .on_link(|link| async move {
                tree::collect(&link.sftp, open_root, key_root, links, Want::Objects).await
            })
            .await?;

        // First page only. This backend re-walks the whole subtree on every
        // call, so attaching the report to every page would multiply one tree's
        // links by the page count and report a number that was never true.
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
        let walked = self
            .on_link(|link| async move {
                tree::collect(
                    &link.sftp,
                    open_root,
                    key_root,
                    LinkPolicy::Skip,
                    Want::Staging,
                )
                .await
            })
            .await?;
        Ok(StagingListing::Page(path::staging_page(
            walked.found,
            prefix,
            cursor.as_deref(),
            PAGE_SIZE,
        )))
    }
    /// SFTP writes one stream to one staging file — `SSH_FXP_WRITE` at an
    /// offset, over and over — so there is no upload to leave half-started. An
    /// interruption leaves staging debris, which
    /// [`list_staging`](Backend::list_staging) enumerates and `cleanup` reclaims.
    async fn list_incomplete_uploads(
        &self,
        _prefix: &str,
        _cursor: Option<String>,
    ) -> Result<crate::multipart::IncompleteUploads> {
        Ok(crate::multipart::IncompleteUploads::NotMultipart(
            crate::multipart::NOT_MULTIPART_REASON,
        ))
    }

    /// Unreachable by construction, and a refusal rather than a quiet success —
    /// see [`LocalFs::abort_incomplete_upload`](crate::LocalFs).
    async fn abort_incomplete_upload(
        &self,
        upload: &crate::multipart::IncompleteUpload,
    ) -> Result<()> {
        Err(StoreError::Backend(format!(
            "sftp: asked to cancel upload '{}', but this backend starts none",
            upload.id
        )))
    }
    // `prepare_upload` keeps the trait default: SFTP has no presigned/delegated
    // upload, so it returns a clear "unsupported" error.
}

/// One dial, bounded by `--contimeout` and by the run's own deadline.
///
/// **The hole measured on this backend.** Its `sftp:` arm reported the
/// deadline firing at exactly 30 s and the run *not terminated after 600 s*: the
/// session was discarded correctly, the retry layer asked for another, and the
/// replacement `ssh` hung on the same black hole. Everything above this function
/// was working; the dial was the only thing in the cycle with no bound on it.
///
/// It is bounded here rather than only by `ssh -o ConnectTimeout` because that
/// option covers the **TCP connect** and nothing after it. A route black-holed
/// once the connection is established, a host that completes the handshake and
/// never offers the `sftp` subsystem, and a `ProxyCommand` that authenticates
/// and then goes quiet are all past the point `ConnectTimeout` stops watching.
/// The number is still handed to `ssh` as well ([`dial::SshDialer`]) so the
/// whole `ProxyCommand` chain is bounded from the inside too, exactly as rclone
/// does by handing its own connect timeout to the ssh client. The two are
/// complementary, not duplicates: one bounds what `ssh` can see and one bounds
/// `ssh` itself.
///
/// A free function rather than a method because the **first** dial happens
/// before there is a backend to call a method on, and a first connection that
/// could hang while every later one could not would be the same defect with a
/// smaller window.
///
/// # Errors
/// Whatever the dial reported; a [`StoreError::Transport`] naming
/// `--contimeout` when nothing came back inside it; or
/// [`StoreError::RunDeadline`] when the run's window closed first.
async fn dial_within(dialer: &dyn SftpDial, deadlines: &Deadlines) -> Result<Link> {
    let dial = async {
        match deadlines.connect {
            // `--contimeout 0`: wait as long as it takes to reach the host,
            // which is a supported answer and not a degenerate one. See
            // `crate::deadline::constants::DISABLED_SECONDS`.
            None => dialer.dial().await,
            Some(connect) => match tokio::time::timeout(connect, dialer.dial()).await {
                Ok(dialled) => dialled,
                // `Transport`, matching every other "nothing answered" on this
                // backend, so the retry layer classifies a host that is briefly
                // unreachable as worth another attempt — which it is.
                Err(_) => Err(StoreError::Transport {
                    backend: SFTP_BACKEND_NAME,
                    detail: format!(
                        "no sftp session on {} within {}s (--contimeout {}s)",
                        dialer.destination(),
                        connect.as_secs(),
                        connect.as_secs()
                    ),
                }),
            },
        }
    };

    // Outside the connect timeout rather than inside it: the run's window is the
    // shorter answer whenever it is shorter, and a dial that would have been
    // allowed sixty seconds must not take them from a run with ten left.
    deadlines
        .run
        .guard(dial)
        .await
        .unwrap_or_else(|exceeded| Err(exceeded.into_store_error()))
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
///   (`crate::retry::observed`, following rclone's retriable-error set).
/// * **The session itself is gone** — every remaining variant of
///   [`SftpError`], plus the `io` kinds that mean the pipe to `ssh` has closed.
///   [`StoreError::Transport`], because nothing answered and because another
///   attempt now genuinely differs: [`SftpBackend::on_link`] discards the dead
///   conversation and the next one dials a fresh session.
///
///   This arm used to say the opposite — terminal, *"run the command again to open a
///   new one"* — and that was the honest classification for a backend that could not
///   re-dial: spending five attempts into a socket that is not there and then
///   reporting that five attempts were made is the shape of claim
///   [the plan](https://doc.dctl.sh/project/plan) §6 forbids. What changed is not
///   the wording but the capability, which is the only thing that makes the new
///   answer true. rclone reaches the same place from a connection pool.
///
/// The protocol's other server-side codes — `PermDenied`, `Failure`,
/// `BadMessage`, `OpUnsupported` — are statements about the request and are
/// equally true next time, so they stay terminal.
///
/// What each of them *means* is [`status::classify`]'s job, and used to be
/// nobody's: all four rendered as one `StoreError::Backend` string, so a full
/// disk over SFTP read as `sftp server reported Failure: Err Message: Failure,
/// Language Tag:` and reached none of the layers that act on an
/// [`std::io::ErrorKind`].
fn map_sftp_err(key: &str, e: SftpError) -> StoreError {
    match e {
        // The server answered. Whatever it said, the conversation carried it,
        // so the conversation is not what is wrong — only the request is.
        SftpError::SftpError(kind, message) => {
            let (text, _language) = message.get();
            status::classify(key, kind, text)
        }
        SftpError::IOError(io) => {
            if io.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound(key.to_string())
            } else if is_link_failure(io.kind()) {
                StoreError::Transport {
                    backend: SFTP_BACKEND_NAME,
                    detail: format!("the sftp session ended ({io})"),
                }
            } else {
                StoreError::Io(io)
            }
        }
        other => StoreError::Transport {
            backend: SFTP_BACKEND_NAME,
            detail: format!("the sftp session is no longer usable ({other})"),
        },
    }
}

/// Whether an `io` error kind means the conversation itself has ended.
///
/// The client library reads and writes one pair of pipes to the `ssh` process,
/// so these kinds are never a statement about a *file* on the server — they are
/// the channel closing under the request. A remote file error arrives as
/// `SftpError::SftpError` carrying a protocol status instead, which is why the
/// two can be told apart structurally rather than by reading a message.
const fn is_link_failure(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::TimedOut
    )
}

/// Whether this failure means the conversation must be thrown away.
///
/// One predicate, read off the error's *shape*, so the decision to re-dial is
/// made in exactly one place and cannot drift from the decision to retry:
/// `crate::retry::observed` reads the same variant as transient, so everything
/// discarded here is also everything the layer above will attempt again.
fn is_session_lost(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::Transport { backend, .. } if *backend == SFTP_BACKEND_NAME
    )
}

/// A unique sibling temp path for the local download staging file: appending the
/// atomic-unique `.tmp.<pid>.<seq>` suffix keeps it in `dest`'s directory (same
/// filesystem), so the final rename onto `dest` is atomic.
fn local_temp(dest: &Path) -> std::path::PathBuf {
    std::path::PathBuf::from(temp_path(&dest.to_string_lossy()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The transfer window is the operator's memory ceiling on this backend, and
    /// the clamp is what stops a typo turning it into an OOM kill.
    ///
    /// Pure — no server, no session — because this is the *policy* half. The
    /// other half is `SftpConfig::with_chunk_size` reaching this field, which
    /// `SftpBackend::chunk_size` exposes and `dctl_cli::config::reach` asserts
    /// from the configuration file's end.
    #[test]
    fn a_pinned_transfer_window_is_taken_and_an_absurd_one_is_clamped() {
        // Pinning nothing is not the same as pinning the default: it is what
        // lets a later release improve the default without rewriting configs.
        assert_eq!(clamp_chunk_len(None), CHUNK_LEN);

        // A value inside the range is taken exactly. 9 MiB is neither a bound
        // nor the default, so a clamp that ignored its argument would fail here.
        assert_eq!(clamp_chunk_len(Some(9 * 1024 * 1024)), 9 * 1024 * 1024);

        // Below the floor: an operator asking for the smallest footprint gets
        // the smallest one available, rather than a failed backup at 02:00.
        assert_eq!(clamp_chunk_len(Some(1)), MIN_CHUNK_LEN);
        assert_eq!(clamp_chunk_len(Some(0)), MIN_CHUNK_LEN);

        // Above the ceiling. `chunk_size = 8589934592` is a plausible typo for
        // 8 MiB written in bytes-of-GiB, and honouring it would turn a memory
        // setting into an out-of-memory kill.
        assert_eq!(clamp_chunk_len(Some(8 * 1024 * 1024 * 1024)), MAX_CHUNK_LEN);
        assert_eq!(clamp_chunk_len(Some(u64::MAX)), MAX_CHUNK_LEN);

        // The bounds themselves are reachable, or the range is narrower than it
        // claims to be.
        assert_eq!(clamp_chunk_len(Some(MIN_CHUNK_LEN)), MIN_CHUNK_LEN);
        assert_eq!(clamp_chunk_len(Some(MAX_CHUNK_LEN)), MAX_CHUNK_LEN);
    }

    /// A config carries the window to the backend, and back off it again.
    ///
    /// The setter and the getter are the two ends `dctl_cli::config::reach`
    /// cannot see between: it proves the resolver produces the number, and this
    /// proves the number a `SftpConfig` was built with is the number the
    /// backend's streaming paths will use.
    #[test]
    fn a_config_carries_its_window_and_the_default_is_not_zero() {
        let pinned = SftpConfig::new("h", "/srv/x").with_chunk_size(Some(9 * 1024 * 1024));
        assert_eq!(pinned.chunk_size, Some(9 * 1024 * 1024));
        assert_eq!(clamp_chunk_len(pinned.chunk_size), 9 * 1024 * 1024);

        // Unset stays unset through the builder chain, so the backend can tell
        // "pinned the default" from "pinned nothing".
        let plain = SftpConfig::new("h", "/srv/x").with_links(LinkPolicy::Skip);
        assert_eq!(plain.chunk_size, None);
        assert_eq!(clamp_chunk_len(plain.chunk_size), CHUNK_LEN);
    }
}
