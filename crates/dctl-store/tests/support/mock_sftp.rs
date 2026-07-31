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
//!
//! ## Answering wrongly, on purpose
//!
//! A server that always works can only reach the paths where nothing goes wrong,
//! and those are not the paths the refusals are for. [`Faults`] is the set of
//! ways this one can be told to answer badly, and the rule for adding to it is
//! that **a real server must be able to do it**: a fault nobody's `sshd` can
//! produce would test DCTL against a world it will never meet, and the guard it
//! reached would be dead code defended by a test that proves nothing. Each knob's
//! documentation names the real condition it stands for and the guard it drives.
//!
//! The two that are easiest to misread are worth naming here. `omit_size` is
//! *within* version 3 — the attribute block is a flags word followed by only the
//! fields it claims — which is why the client library surfaces a size as
//! `Option<u64>` at all. And `serve_at_most` answers `SSH_FX_EOF`, not an error,
//! because that is the whole hazard: to a client, a server that stopped serving
//! is indistinguishable from a file that really ended there.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use dctl_store::sftp::dial::{Link, SftpDial};
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

/// The ways this server can be told to misbehave, in one place.
///
/// One struct rather than a field per knob on each of the two server handles:
/// [`MockSftp`] and [`RedialableSftp`] both have to hand the same set to
/// [`Server`], and a knob wired into one and forgotten in the other is a test
/// that silently exercises a default while its name says otherwise. Cloning
/// shares the flags, so a handle a test holds and the task serving the wire are
/// looking at the same values.
///
/// Every one of these reproduces something a **real** server does. That is the
/// bar: a fault nobody's `sshd` can produce would test DCTL against a world it
/// will never meet, and the refusal it provoked would be dead code defended by a
/// test that proves nothing.
#[derive(Clone, Default)]
pub struct Faults {
    /// Answer the attribute requests without `SSH_FX_ATTR_SIZE`.
    ///
    /// Version 3's attribute structure is a **flags word followed by only the
    /// fields the flags claim**, so a size is optional on the wire and a server
    /// is within the protocol to omit it. OpenSSH always sends one; a `chroot`ed
    /// or virtual-filesystem server need not, and DCTL's own client library
    /// surfaces the absence as `Option<u64>` precisely because it can happen.
    ///
    /// What it drives: the three
    /// `sftp server did not return file size` refusals. Deleting any of them
    /// compiles to `unwrap_or(0)`, which turns every object into a zero-length
    /// one — `head` reports 0, a ranged read serves nothing, and a download
    /// writes an empty file over a good local copy and calls it done.
    ///
    /// Scoped to `SSH_FXP_STAT`, `LSTAT` and `FSTAT` — the three replies those
    /// guards read — and deliberately **not** to `READDIR`'s attribute lists. A
    /// listing that also lost its sizes would leave a failing test unable to say
    /// which of the two paths it had broken.
    pub omit_size: Arc<AtomicBool>,
    /// Refuse every request naming a path containing this fragment, with
    /// `SSH_FX_PERMISSION_DENIED`.
    ///
    /// The commonest real failure on a shared host: a base the operator can read
    /// and a subdirectory they cannot write, an ACL, or a quota'd tree. The
    /// server **answers** — this is not a dead connection — which is the whole
    /// point of the distinction [`dctl_store::sftp`]'s `map_sftp_err` draws: a
    /// refusal is equally true next time, so it must be terminal, while a
    /// severed session must not be. Both look like "the write failed" from
    /// above, and getting them the wrong way round costs either five attempts
    /// into a denial or one attempt at a recoverable drop.
    pub denied: Arc<Mutex<Option<String>>>,
    /// Serve at most this many bytes in total from `SSH_FXP_READ`, then answer
    /// `SSH_FX_EOF` — while `stat` goes on declaring the file's real length.
    ///
    /// A server whose own two answers disagree. It happens: a file truncated
    /// under the reader, a backing store that lost a block, a proxy that ended a
    /// transfer early. What it must never produce is a *short object that reads
    /// as complete*, because the digest taken over the prefix is internally
    /// consistent and wrong — the worst outcome this product has
    /// (`HANDOVER.md` §26.1).
    ///
    /// [`usize::MAX`] means unlimited, and is what [`Faults::new`] sets — which
    /// is why `new` exists beside the derived `Default`: a zero budget would
    /// mean "serve nothing" and would be a silently broken server.
    pub serve_at_most: Arc<AtomicUsize>,
    /// Stop answering once a write arrives. See
    /// [`RedialableSftp::go_silent_on_write`].
    pub silent_on_write: Arc<AtomicBool>,
    /// Accept this many bytes of `SSH_FXP_WRITE` and then refuse every one
    /// after it with `SSH_FX_FAILURE`.
    ///
    /// A quota met, a filesystem filled, a `chroot` whose device is full — the
    /// commonest way a write fails on a shared host, and the only one that fails
    /// **part-way through an object** rather than at the `open`. That distinction
    /// is the point: an `open` that fails leaves nothing behind, and a write that
    /// fails at 60% leaves a staging file holding 60% of an object under a name
    /// nobody will ever look at again. `HANDOVER.md` §24.1 is what that debris
    /// costs, and the arms that prevent it are the `remove_quiet` in **each of
    /// the three writers** — `put_bytes`, `put_stream` and `put_object_stream`
    /// — which is why the test driven by this knob puts an object through all
    /// three rather than through whichever one `Backend::put` happens to use.
    ///
    /// [`usize::MAX`] means unlimited, and is what [`Faults::new`] sets.
    pub accept_at_most: Arc<AtomicUsize>,
    /// Never complete a dial: the connection is opened and the server never
    /// speaks, so the client's protocol handshake waits forever.
    ///
    /// The **black hole**, at the one place `HANDOVER.md` §32.9 found nothing
    /// bounding it. Its `sftp:` arm dropped port 22 with `iptables`, watched the
    /// deadline fire at exactly 30 s, watched the dead session be discarded
    /// correctly — and then watched the *replacement* `ssh` hang on the same
    /// black hole, with the run still alive 601 s later. Every layer above the
    /// dial was working; the dial was the only step in the cycle with no
    /// deadline on it.
    ///
    /// Reproduces a real server, which is the bar for everything in this
    /// structure: a route black-holed after the TCP connect succeeds, a host
    /// that accepts the connection and never offers the subsystem, a
    /// `ProxyCommand` that builds its tunnel and then goes quiet. All three are
    /// past the point `ssh -o ConnectTimeout` stops watching, which is why the
    /// fault has to be at the dial rather than at the connect.
    pub hang_on_dial: Arc<AtomicBool>,
}

impl Faults {
    /// Unlimited reads, sizes reported, nothing denied, nothing silent.
    #[must_use]
    fn new() -> Self {
        Self {
            serve_at_most: Arc::new(AtomicUsize::new(usize::MAX)),
            accept_at_most: Arc::new(AtomicUsize::new(usize::MAX)),
            ..Self::default()
        }
    }

    /// Whether this wire path is one the server has been told to refuse.
    fn refuses(&self, wire: &str) -> bool {
        self.denied
            .lock()
            .map(|held| held.as_ref().is_some_and(|part| wire.contains(part)))
            .unwrap_or(false)
    }
}

/// A running in-process SFTP server and the directory it serves.
pub struct MockSftp {
    root: tempfile::TempDir,
    log: Arc<Mutex<Vec<Seen>>>,
    faults: Faults,
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

    /// Stop reporting file sizes. See [`Faults::omit_size`].
    pub fn omit_size(&self) {
        self.faults.omit_size.store(true, Ordering::SeqCst);
    }

    /// Refuse every path containing `fragment`. See [`Faults::denied`].
    pub fn deny(&self, fragment: &str) {
        if let Ok(mut held) = self.faults.denied.lock() {
            *held = Some(fragment.to_string());
        }
    }

    /// Serve no more than `bytes` in total from reads. See
    /// [`Faults::serve_at_most`].
    pub fn serve_at_most(&self, bytes: usize) {
        self.faults.serve_at_most.store(bytes, Ordering::SeqCst);
    }

    /// Accept no more than `bytes` of writes, then refuse. See
    /// [`Faults::accept_at_most`].
    pub fn accept_at_most(&self, bytes: usize) {
        self.faults.accept_at_most.store(bytes, Ordering::SeqCst);
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
    let faults = Faults::new();

    // Two simplex pipes rather than one duplex: the client is handed a sink for
    // its requests and a source for its responses, exactly as it would be handed
    // a subprocess's stdin and stdout.
    let (server_reads, client_writes) = tokio::io::simplex(PIPE_CAPACITY);
    let (client_reads, server_writes) = tokio::io::simplex(PIPE_CAPACITY);

    let mut server = Server {
        root: root.path().to_path_buf(),
        handles: BTreeMap::new(),
        next_handle: 0,
        served: 0,
        accepted: 0,
        log: Arc::clone(&log),
        faults: faults.clone(),
    };
    tokio::spawn(async move {
        // A pipe that closes is the client going away, which every test does at
        // the end. Nothing here should report it.
        let _ = server.serve(server_reads, server_writes).await;
    });

    (
        MockSftp { root, log, faults },
        ClientPipes {
            writes: client_writes,
            reads: client_reads,
        },
    )
}

// ── re-dialling: many conversations, one directory ───────────────────────────
//
// `start` above hands over one pipe pair and is right for every test whose
// subject is a request. It cannot express the subject of `HANDOVER.md` §11.2's
// last open entry — *re-dial a dead connection* — because that needs three
// things this file did not have: a **second** conversation, served on the **same
// directory** so the recovered operation can be seen to have really happened,
// and a way to **kill** the first one mid-run.
//
// Without them the re-dial would be provable only against a real `sshd`, which
// is the position `HANDOVER.md` §11.3 item 10 already records for two other
// guarantees: a promise whose only witness needs a host is a promise the stated
// gate does not hold.

/// A server that will answer as many conversations as it is asked for, all of
/// them over one directory.
///
/// Handed to the backend as a [`SftpDial`], so what runs is the real
/// `SftpBackend` re-dialling through the real client library and the real
/// version-3 packet encoding — not a stub that reports having reconnected.
pub struct RedialableSftp {
    root: tempfile::TempDir,
    log: Arc<Mutex<Vec<Seen>>>,
    /// Everything this server can be told to do wrong, shared with every
    /// conversation it serves — so a fault armed before a re-dial is still armed
    /// after one, which is what makes `the_base_decision_survives_a_re_dial`
    /// style assertions possible at all.
    faults: Faults,
    /// Conversations opened so far. The number a re-dial test asserts on.
    dials: Arc<AtomicUsize>,
    /// The task serving the newest conversation, so a test can end it.
    live: Arc<Mutex<Option<tokio::task::AbortHandle>>>,
}

impl RedialableSftp {
    /// A server over a fresh temporary directory, with nothing dialled yet.
    #[must_use]
    pub fn start() -> Self {
        Self {
            root: tempfile::TempDir::new().expect("a temporary directory"),
            log: Arc::new(Mutex::new(Vec::new())),
            faults: Faults::new(),
            dials: Arc::new(AtomicUsize::new(0)),
            live: Arc::new(Mutex::new(None)),
        }
    }

    /// The directory every conversation resolves paths under.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.root.path()
    }

    /// How many conversations have been opened.
    ///
    /// One after construction. Two means something re-dialled, which is the
    /// whole assertion — and it is a count rather than a boolean so a test can
    /// also prove the *absence* of a re-dial on the healthy path, where an extra
    /// connection per request would be a silent performance defect.
    #[must_use]
    pub fn dials(&self) -> usize {
        self.dials.load(Ordering::SeqCst)
    }

    /// Every request every conversation has answered, in arrival order.
    #[must_use]
    pub fn seen(&self) -> Vec<Seen> {
        self.log
            .lock()
            .expect("the request log is not poisoned")
            .clone()
    }

    /// Answer every request up to the first `SSH_FXP_WRITE`, and then nothing,
    /// ever.
    ///
    /// A different fault from [`sever`](Self::sever) and a more searching one.
    /// Severing kills the wire, which every layer notices sooner or later; this
    /// leaves the wire perfectly healthy and simply stops replying — a server
    /// whose disk has wedged, a network that black-holes one direction, a pod
    /// that has stopped scheduling. Nothing is broken, so nothing reports
    /// anything, and without a deadline the write waits for as long as TCP
    /// allows.
    ///
    /// Aimed at the **write** specifically because that is where the deadline
    /// was missing: `RemoteFs::create` was guarded and every `write_all` after
    /// it was not, so a session that went quiet mid-object hung. A test that
    /// stalled the `open` instead would have passed against that gap.
    pub fn go_silent_on_write(&self) {
        self.faults.silent_on_write.store(true, Ordering::SeqCst);
    }

    /// Stop reporting file sizes. See [`Faults::omit_size`].
    pub fn omit_size(&self) {
        self.faults.omit_size.store(true, Ordering::SeqCst);
    }

    /// Refuse every path containing `fragment`. See [`Faults::denied`].
    pub fn deny(&self, fragment: &str) {
        if let Ok(mut held) = self.faults.denied.lock() {
            *held = Some(fragment.to_string());
        }
    }

    /// Stop refusing. A denial an operator has just fixed is a real event, and
    /// it is what proves a refusal did not poison the session it arrived on.
    pub fn allow_everything(&self) {
        if let Ok(mut held) = self.faults.denied.lock() {
            *held = None;
        }
    }

    /// Serve no more than `bytes` in total from reads. See
    /// [`Faults::serve_at_most`].
    pub fn serve_at_most(&self, bytes: usize) {
        self.faults.serve_at_most.store(bytes, Ordering::SeqCst);
    }

    /// Accept every later dial and answer nothing on it, forever.
    ///
    /// See [`Faults::hang_on_dial`]. Armed **after** the first conversation in
    /// the tests that use it, because the interesting case is the replacement
    /// dial: a first connection that hangs is a run that never starts, and a
    /// re-dial that hangs is a run that never ends.
    pub fn hang_on_dial(&self) {
        self.faults.hang_on_dial.store(true, Ordering::SeqCst);
    }

    /// Kill the live conversation, as a dropped `ssh` session does.
    ///
    /// Aborting the task drops both pipe ends, so the client's next read reaches
    /// end-of-file and its next write meets a broken pipe — which is what the
    /// far end of a severed multiplexed session looks like from inside
    /// `openssh_sftp_client`, and what `sftp::is_link_failure` classifies.
    ///
    /// Deliberately *not* a clean protocol shutdown: a server that said goodbye
    /// would be testing a case that does not happen. A connection dies without
    /// warning or it does not die at all.
    pub fn sever(&self) {
        if let Some(task) = self
            .live
            .lock()
            .expect("the live-session handle is not poisoned")
            .take()
        {
            task.abort();
        }
    }

    /// A dialer for this server, for [`SftpBackend::over_dialer`].
    #[must_use]
    pub fn dialer(&self) -> Arc<RedialDialer> {
        Arc::new(RedialDialer {
            root: self.root.path().to_path_buf(),
            log: Arc::clone(&self.log),
            faults: self.faults.clone(),
            dials: Arc::clone(&self.dials),
            live: Arc::clone(&self.live),
        })
    }
}

/// The [`SftpDial`] half of [`RedialableSftp`].
pub struct RedialDialer {
    root: PathBuf,
    log: Arc<Mutex<Vec<Seen>>>,
    faults: Faults,
    dials: Arc<AtomicUsize>,
    live: Arc<Mutex<Option<tokio::task::AbortHandle>>>,
}

#[async_trait::async_trait]
impl SftpDial for RedialDialer {
    async fn dial(&self) -> dctl_store::Result<Link> {
        if self.faults.hang_on_dial.load(Ordering::SeqCst) {
            // Counted first: a test asserting that the dial was *attempted* and
            // never completed needs both halves, and a dial that returned
            // without being counted would look like one that never happened.
            self.dials.fetch_add(1, Ordering::SeqCst);
            // The black hole. Not a slow answer and not an error — nothing, for
            // as long as anybody is willing to wait.
            std::future::pending::<()>().await;
        }
        let (server_reads, client_writes) = tokio::io::simplex(PIPE_CAPACITY);
        let (client_reads, server_writes) = tokio::io::simplex(PIPE_CAPACITY);

        let mut server = Server {
            root: self.root.clone(),
            handles: BTreeMap::new(),
            next_handle: 0,
            // Per conversation, like the handle table beside it: `serve_at_most`
            // is a budget for one session, so a re-dial after a short read gets
            // a fresh one — which is what a real truncated-then-repaired file
            // would do, and what lets a recovery test show the retry succeeding.
            served: 0,
            accepted: 0,
            log: Arc::clone(&self.log),
            faults: self.faults.clone(),
        };
        // Handles are per conversation, exactly as they are on a real server:
        // the `Server` is new each time, so a handle issued before a sever is
        // meaningless afterwards. A shared handle table would let a re-dialled
        // client keep using a file it opened on a session that no longer exists,
        // which is the one thing this test must not accidentally permit.
        let task = tokio::spawn(async move {
            let _ = server.serve(server_reads, server_writes).await;
        });
        *self
            .live
            .lock()
            .expect("the live-session handle is not poisoned") = Some(task.abort_handle());
        self.dials.fetch_add(1, Ordering::SeqCst);

        Link::over_stream(client_writes, client_reads, "the in-process server").await
    }

    fn destination(&self) -> &str {
        "the in-process server"
    }
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
    /// Bytes already handed over by `SSH_FXP_READ` on this conversation, against
    /// [`Faults::serve_at_most`].
    served: usize,
    /// Bytes already accepted by `SSH_FXP_WRITE` on this conversation, against
    /// [`Faults::accept_at_most`].
    accepted: usize,
    log: Arc<Mutex<Vec<Seen>>>,
    /// What this server has been told to do wrong. See [`Faults`].
    faults: Faults,
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
            if kind == SSH_FXP_WRITE && self.faults.silent_on_write.load(Ordering::SeqCst) {
                // The wire stays up and the request is never answered. Returning
                // would close the pipes, which the client reports at once — and
                // an error it reports at once is not the case being tested.
                std::future::pending::<()>().await;
            }
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
                    Ok(_) => name_packet(id, &canonical(&raw)),
                    Err(why) => status(id, SSH_FX_PERMISSION_DENIED, why),
                }
            }
            SSH_FXP_STAT | SSH_FXP_LSTAT => {
                let raw = cursor.string();
                self.note(if kind == SSH_FXP_STAT {
                    Seen::Stat(raw.clone())
                } else {
                    Seen::Lstat(raw.clone())
                });
                let path = match self.resolve(&raw) {
                    Ok(path) => path,
                    Err(why) => return status(id, SSH_FX_PERMISSION_DENIED, why),
                };
                let read = if kind == SSH_FXP_STAT {
                    std::fs::metadata(&path)
                } else {
                    std::fs::symlink_metadata(&path)
                };
                let sized = self.reports_size();
                match read {
                    Ok(meta) => attrs_packet(id, &meta, sized),
                    Err(e) => status(id, errno_status(&e), &e.to_string()),
                }
            }
            SSH_FXP_FSTAT => {
                self.note(Seen::Fstat);
                let handle = cursor.handle();
                let sized = self.reports_size();
                match self.handles.get(&handle) {
                    Some(Handle::File(file, _)) => match file.metadata() {
                        Ok(meta) => attrs_packet(id, &meta, sized),
                        Err(e) => status(id, errno_status(&e), &e.to_string()),
                    },
                    _ => status(id, SSH_FX_FAILURE, "not an open file"),
                }
            }
            SSH_FXP_OPEN => {
                let raw = cursor.string();
                let pflags = cursor.u32();
                self.note(Seen::Open(raw.clone()));
                let path = match self.resolve(&raw) {
                    Ok(path) => path,
                    Err(why) => return status(id, SSH_FX_PERMISSION_DENIED, why),
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
                // The budget is applied to what is *asked for*, before the read,
                // so the file itself is never consulted beyond it. A server that
                // has stopped serving has stopped serving; it does not read the
                // block and then decline to send it.
                let budget = self.faults.serve_at_most.load(Ordering::SeqCst);
                let allowed = want.min(budget.saturating_sub(self.served));
                if allowed == 0 && budget != usize::MAX {
                    // `SSH_FX_EOF` and not an error, which is the whole hazard:
                    // to the client this is indistinguishable from a file that
                    // really ended here, so nothing below DCTL's own
                    // declared-length check can notice the object is short.
                    return status(id, SSH_FX_EOF, "end of file");
                }
                let mut buffer = vec![0u8; allowed];
                let mut have = 0;
                while have < allowed {
                    match file.read(&mut buffer[have..]) {
                        Ok(0) => break,
                        Ok(n) => have += n,
                        Err(e) => return status(id, errno_status(&e), &e.to_string()),
                    }
                }
                if have == 0 {
                    return status(id, SSH_FX_EOF, "end of file");
                }
                self.served += have;
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
                let budget = self.faults.accept_at_most.load(Ordering::SeqCst);
                // Refused **before** the bytes touch the file, which is what a
                // filesystem with no room does: nothing is written, and the
                // staging file keeps whatever the earlier writes put in it. A
                // server that stored the block and then reported failure would
                // be a different fault and a kinder one.
                if budget != usize::MAX && self.accepted.saturating_add(wrote) > budget {
                    self.log
                        .lock()
                        .map(|mut log| log.push(Seen::Write(name, 0)))
                        .unwrap_or_default();
                    return status(id, SSH_FX_FAILURE, "no space left on device");
                }
                let outcome = file
                    .seek(SeekFrom::Start(offset))
                    .and_then(|_| file.write_all(data));
                self.log
                    .lock()
                    .map(|mut log| log.push(Seen::Write(name, wrote)))
                    .unwrap_or_default();
                match outcome {
                    Ok(()) => {
                        self.accepted += wrote;
                        status(id, SSH_FX_OK, "written")
                    }
                    Err(e) => status(id, errno_status(&e), &e.to_string()),
                }
            }
            SSH_FXP_SETSTAT | SSH_FXP_FSETSTAT => {
                // The one request the modification-time guarantee is made of.
                let (target, raw) = if kind == SSH_FXP_SETSTAT {
                    let raw = cursor.string();
                    // The reason is dropped here on purpose: this arm has to
                    // read the attributes off the cursor before it can answer
                    // anything, or the next request decodes from the wrong
                    // offset and the conversation desynchronises. The refusal is
                    // taken below, after `read_attrs`.
                    (self.resolve(&raw).ok(), Some(raw))
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
                let path = match self.resolve(&raw) {
                    Ok(path) => path,
                    Err(why) => return status(id, SSH_FX_PERMISSION_DENIED, why),
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
                let path = match self.resolve(&raw) {
                    Ok(path) => path,
                    Err(why) => return status(id, SSH_FX_PERMISSION_DENIED, why),
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
                let path = match self.resolve(&raw) {
                    Ok(path) => path,
                    Err(why) => return status(id, SSH_FX_PERMISSION_DENIED, why),
                };
                match std::fs::remove_dir(&path) {
                    Ok(()) => status(id, SSH_FX_OK, "removed"),
                    Err(e) => status(id, errno_status(&e), &e.to_string()),
                }
            }
            SSH_FXP_REMOVE => {
                let raw = cursor.string();
                self.note(Seen::Remove(raw.clone()));
                let path = match self.resolve(&raw) {
                    Ok(path) => path,
                    Err(why) => return status(id, SSH_FX_PERMISSION_DENIED, why),
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
                let path = match self.resolve(&raw) {
                    Ok(path) => path,
                    Err(why) => return status(id, SSH_FX_PERMISSION_DENIED, why),
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
                let (Ok(link_path), Ok(target_path)) = (self.resolve(&link), self.resolve(&target))
                else {
                    return status(id, SSH_FX_PERMISSION_DENIED, "refused");
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
        let (Ok(from), Ok(to)) = (self.resolve(from), self.resolve(to)) else {
            return status(id, SSH_FX_PERMISSION_DENIED, "refused");
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
    /// The host path a wire path names, or the reason this server will not
    /// serve it.
    ///
    /// The reason travels with the refusal rather than being re-supplied at each
    /// of the eleven call sites, because the two refusals this returns are
    /// different findings that share a status code. *Outside the served root* is
    /// a **bug in DCTL** — `sftp::path::validate_key` is supposed to have made
    /// it impossible — while *denied* is a fixture doing what it was told, and a
    /// test that could not tell them apart would report the first as the second.
    fn resolve(&self, raw: &str) -> std::result::Result<PathBuf, &'static str> {
        if self.faults.refuses(raw) {
            return Err("permission denied");
        }
        let relative = raw.trim_start_matches('/');
        let mut out = self.root.clone();
        for component in Path::new(relative).components() {
            match component {
                Component::Normal(part) => out.push(part),
                Component::CurDir => {}
                // Nothing DCTL sends contains one — `sftp::path::validate_key`
                // refuses them — so meeting one means the refusal has stopped
                // working, and answering it would hide that.
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err("outside the served root");
                }
            }
        }
        Ok(out)
    }

    /// Whether attribute replies carry `SSH_FX_ATTR_SIZE`. See
    /// [`Faults::omit_size`].
    fn reports_size(&self) -> bool {
        !self.faults.omit_size.load(Ordering::SeqCst)
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
            // Always sized: `Faults::omit_size` is scoped to the attribute
            // replies the three size guards read, so that a test that turns it
            // on still gets an ordinary listing and a failure can only mean the
            // guard it named.
            Ok(meta) => put_attrs(&mut out, &meta, true),
            // Something is there and this server cannot describe it. Sending no
            // attribute flags is legal in version 3 and is what a walk reads as
            // "type unknown", which is the honest answer.
            Err(_) => out.extend_from_slice(&0u32.to_be_bytes()),
        }
    }
    out
}

fn attrs_packet(id: u32, meta: &std::fs::Metadata, sized: bool) -> Vec<u8> {
    let mut out = vec![SSH_FXP_ATTRS];
    out.extend_from_slice(&id.to_be_bytes());
    put_attrs(&mut out, meta, sized);
    out
}

/// Size, ownership, mode and both timestamps — the whole of what version 3
/// carries.
///
/// The mode matters most: the client reads the file *type* out of the permission
/// bits, so a server that left them off would make every entry's type unknown and
/// every `is_dir`/`is_file` decision in the backend unreachable.
fn put_attrs(out: &mut Vec<u8>, meta: &std::fs::Metadata, sized: bool) {
    // The flags word decides which fields follow, so dropping `ATTR_SIZE` means
    // dropping the eight bytes as well — an attribute block that advertised no
    // size and then sent one would desynchronise the whole conversation rather
    // than reproduce a server that does not report sizes.
    let mut flags = ATTR_UIDGID | ATTR_PERMISSIONS | ATTR_ACMODTIME;
    if sized {
        flags |= ATTR_SIZE;
    }
    out.extend_from_slice(&flags.to_be_bytes());
    if sized {
        out.extend_from_slice(&meta.len().to_be_bytes());
    }
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
