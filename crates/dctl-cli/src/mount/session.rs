//! Attaching the filesystem, running it, and — the part that matters — always
//! detaching it again.
//!
//! A stale mount is a real operational problem, not an untidy one. The
//! mountpoint becomes a directory that every process touching it blocks on; on
//! macOS that includes Finder, Spotlight and anything walking `/Volumes`, and the
//! only way out is finding the right `umount` incantation for a filesystem whose
//! server is gone. So this module's design goal is not "mount"; it is **there is
//! no path out of here that leaves a mount attached**, and every branch below is
//! shaped by it:
//!
//! * A failure while mounting unmounts before it returns.
//! * A signal unmounts and then waits for the session to end.
//! * A future dropped mid-mount — which is what happens when `main`'s own Ctrl-C
//!   race fires first — unmounts from [`Mounted`]'s `Drop`.
//! * The kernel is additionally told `auto_unmount` **where the ACL allows it**,
//!   so a process killed with `SIGKILL` — which runs no code at all — still
//!   leaves the mountpoint usable. This is the one gap in the list, and it is
//!   worth stating plainly rather than leaving to be discovered: at the default
//!   `SessionACL::Owner` the option is not requested, and `SIGKILL` therefore
//!   *does* leave a stale mountpoint. Measured on Linux 6.12 — default flags,
//!   `SIGKILL`: the entry stays in `/proc/mounts` and every access fails with
//!   `ENOTCONN`; the same test with `--allow-root`: the mountpoint comes free.
//!   Every signal a process can actually handle is covered; `SIGKILL` is covered
//!   only when the user has already widened access for their own reasons.
//!
//! ## Why the session runs on a thread of its own
//!
//! `fuser`'s session loop is synchronous: it reads a request, dispatches it, and
//! reads the next. DCTL's read path is `async`. The loop therefore runs on a
//! plain `std::thread` — deliberately *not* a Tokio worker or a `spawn_blocking`
//! thread — and the callbacks hand their work to the runtime through a
//! [`Handle`](tokio::runtime::Handle). A thread that is not part of the runtime
//! is a thread on which nothing can accidentally block a worker, and the boundary
//! is visible rather than depending on which pool a task happened to land in.
//!
//! ## Why a signal exits 25 rather than 0
//!
//! DCTL's contract is that cancellation is not success (`PLAN.md` §7, and
//! [`ExitCode::Cancelled`]): a wrapper script has to be able to tell "the
//! operator stopped it" from "it finished". A mount ended by `umount` *did*
//! finish, and exits 0; a mount ended by Ctrl-C or `SIGTERM` was stopped, and
//! exits 25.
//!
//! There is a second reason it must be this way round. `main` already races every
//! command against `ctrl_c`, so on Ctrl-C two futures become ready at once and
//! `tokio::select!` picks between them arbitrarily. Returning `Cancelled` from
//! here makes both outcomes the same exit code, which turns a race into a
//! decision. The unmount happens either way: on this path explicitly, and on the
//! other through [`Mounted`]'s `Drop`.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Instant;

use fuser::{Config, MountOption, Session, SessionUnmounter};

use crate::constants::{
    MOUNT_DETACH_GRACE, MOUNT_FS_NAME, MOUNT_FS_SUBTYPE, MOUNT_MACFUSE_HELPER_HINT,
    MOUNT_MACFUSE_TYPE_NAME, MOUNT_SHUTDOWN_GRACE, MOUNT_SHUTDOWN_POLL, MOUNT_STALE_HINT,
};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::logging::fields;
use crate::source::Source;

use super::config::MountConfig;
use super::fs::VaultFs;

/// What [`Mounted`] needs from the thing that detaches a filesystem.
///
/// A trait with exactly one implementation in production, and it exists for one
/// reason: `fuser::SessionUnmounter` can only be obtained from a live
/// `fuser::Session`, so with it named directly in the struct there was no way to
/// build a [`Mounted`] in a test, and therefore no way to assert what
/// [`Mounted::run`] *does with* the detach it performs.
///
/// That gap was real. The whole of `cc05f90` — "earn the word unmounted instead
/// of assuming it" — is [`Mounted::run`] consulting
/// [`Mounted::confirm_detached`] before it reports anything, and deleting that
/// one call restored the original defect with the entire test suite still green:
/// the nine tests in [`super::detached`] pin the *predicate*, and nothing pinned
/// the *call*. A regression test that a one-line deletion walks straight past is
/// not a regression test.
pub trait Detacher: Send {
    /// Detach the filesystem. Returning `Ok` means a detach was *requested*, not
    /// that the mountpoint is free — which is precisely why the caller checks.
    ///
    /// # Errors
    /// Whatever the platform's unmount path reported.
    fn unmount(&mut self) -> io::Result<()>;
}

impl Detacher for SessionUnmounter {
    fn unmount(&mut self) -> io::Result<()> {
        Self::unmount(self)
    }
}

/// What still has to be observed before a mount may be called live.
///
/// A second one-implementation-per-platform trait beside [`Detacher`], and for a
/// reason that is macFUSE's rather than this module's: on Linux the mount syscall
/// has already returned its verdict by the time a session exists, while on macOS
/// the verdict belongs to a helper process that **does not reach its `mount(2)`
/// until the filesystem has answered `FUSE_INIT` and the kernel's opening
/// `statfs`**. The confirmation therefore has to happen after the session loop is
/// running, which is a step Linux does not have and a `cfg` at the call site
/// would hide.
///
/// Written as a trait so [`mount`] has one body on both platforms. The
/// alternative — two `#[cfg]` copies of the whole function — is how the two come
/// to differ in something neither reviewer noticed.
pub trait Confirm: Send {
    /// Prove the filesystem is attached.
    ///
    /// # Errors
    /// Whatever the platform's mount path reported. An error means the mount did
    /// not happen, never that it half happened.
    fn confirm(self: Box<Self>) -> io::Result<()>;
}

/// The confirmation for a platform whose mount call has already answered.
///
/// Linux's `mount(2)` returns before `Session::new` does, so by the time there is
/// anything to confirm there is nothing left to ask.
///
/// Compiled off macOS, where nothing constructs it — and under `cfg(test)`
/// everywhere, so the one thing worth pinning about it (that it does not refuse)
/// is asserted on the machine that cannot otherwise reach it.
#[cfg(any(not(target_os = "macos"), test))]
pub struct Immediate;

#[cfg(any(not(target_os = "macos"), test))]
impl Confirm for Immediate {
    fn confirm(self: Box<Self>) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl Confirm for super::macfuse::helper::Helper {
    fn confirm(self: Box<Self>) -> io::Result<()> {
        Self::confirm(*self)
    }
}

/// A filesystem attached to a mountpoint and talking to the kernel, plus the two
/// things only the platform knows how to do with it.
///
/// The one shape both platforms produce, so that everything after the attach —
/// starting the thread, confirming, undoing a failure — is written once.
struct Attachment {
    /// Talking to the kernel; not yet running.
    session: Session<VaultFs>,
    /// Takes the mount down again.
    detacher: Box<dyn Detacher>,
    /// Establishes that it really went up. See [`Confirm`].
    confirm: Box<dyn Confirm>,
}

/// A filesystem currently attached to a mountpoint.
///
/// Holding one of these means a mount exists. Dropping one detaches it — which
/// is what makes the "no path out leaves a mount attached" rule hold even for
/// paths this module never sees, such as the caller's future being cancelled.
pub struct Mounted {
    /// The thread running `fuser`'s session loop.
    ///
    /// [`Option`] because [`Mounted::run`] takes it to join, and `Drop` must
    /// still be able to tell whether there is anything left to wait for.
    session: Option<JoinHandle<io::Result<()>>>,
    /// Detaches the filesystem. Boxed rather than named concretely so that
    /// [`Mounted::run`]'s decision can be exercised without a kernel — see
    /// [`Detacher`].
    unmounter: Box<dyn Detacher>,
    mountpoint: PathBuf,
    /// The device the mountpoint reported *before* the filesystem was attached.
    ///
    /// The only thing that distinguishes an attached mountpoint from a free one
    /// while the filesystem is still being served — see [`super::detached`] for
    /// why an errno cannot do it. [`None`] if the mountpoint could not be read at
    /// the time, which weakens the check rather than failing the mount.
    bare_device: Option<u64>,
    /// Whether the mount has already been detached, so `Drop` does not try again
    /// and log a spurious failure.
    detached: bool,
}

/// Attach `source` at `mountpoint` and start serving it.
///
/// Returns once the filesystem is live — the kernel has completed its handshake
/// and the mountpoint is usable — so a caller can print "mounted" and mean it.
///
/// # Errors
/// [`ExitCode::FatalError`] when the platform's FUSE layer is missing or refuses
/// the mount. The message quotes what the layer said, because "operation not
/// permitted" and "no such file or directory" from a mount attempt mean very
/// different things and only the second is about the mountpoint.
pub fn mount(
    source: Arc<dyn Source>,
    config: MountConfig,
    mountpoint: &Path,
    runtime: tokio::runtime::Handle,
) -> Result<Mounted> {
    // Size the source's cache for the read-ahead this mount schedules: the
    // windows in flight plus the one being consumed. Stated here, where the
    // depth is chosen, so budget and depth cannot drift apart — a cache one
    // window short evicts exactly what the reader is about to ask for, and
    // read-ahead becomes wasted egress. With read-ahead off, the cache keeps
    // its own floor.
    if config.read_ahead > 0 {
        let budget = config
            .read_ahead
            .saturating_mul(crate::constants::MOUNT_READ_AHEAD_DEPTH.saturating_add(1));
        let bytes = usize::try_from(budget).unwrap_or(usize::MAX);
        // The entry bound at the ratio the defaults argue for — one entry per
        // 64 KiB of budget — so it engages exactly where the default's does:
        // only for objects sealed with unusually small chunks.
        let per_entry = (crate::constants::VAULT_CHUNK_CACHE_BYTES
            / crate::constants::VAULT_CHUNK_CACHE_MAX_CHUNKS)
            .max(1);
        source.tune_cache(bytes, bytes / per_entry);
    }

    let filesystem = VaultFs::new(source, config.clone(), mountpoint, runtime);
    let session_config = session_config(&config);

    // Taken before the attach, because afterwards the mountpoint reports the
    // filesystem's device and the original is unrecoverable. This one number is
    // what lets the unmount be confirmed rather than assumed; a failure to read
    // it is not worth refusing a mount over, and is carried as `None`.
    let bare_device = super::detached::device_of(mountpoint).ok();

    // The attach performs the mount *and* the kernel handshake, both of which
    // block. It runs here rather than on the session thread so that a failure is
    // an ordinary error return with the platform's own message, rather than
    // something to be recovered from a thread.
    let Attachment {
        session,
        detacher,
        confirm,
    } = attach(filesystem, mountpoint, &session_config, &config)?;

    // Not a Tokio worker and not `spawn_blocking`: see the module docs. The
    // callbacks reach the runtime through the handle they were built with.
    let thread = std::thread::Builder::new()
        .name("dctl-mount".to_string())
        .spawn(move || session.run())
        .map_err(|error| {
            CliError::new(
                ExitCode::FatalError,
                format!("cannot start the filesystem thread: {error}"),
            )
        });

    let mounted = match thread {
        Ok(session) => Mounted {
            session: Some(session),
            unmounter: detacher,
            mountpoint: mountpoint.to_path_buf(),
            bare_device,
            detached: false,
        },
        Err(error) => {
            // The attach succeeded and the thread did not. Leaving a filesystem
            // attached with nothing serving it is the exact failure this module
            // exists to prevent, so it is undone before the error is returned.
            let mut detacher = detacher;
            let _ = detacher.unmount();
            return Err(error);
        }
    };

    // Now, and not before: on macOS the mount is not proven until the helper
    // says so, and the helper cannot say so until the loop above is answering.
    // `mounted` is built first so that a failure here takes the mountpoint down
    // through its `Drop` rather than leaving one behind.
    confirm
        .confirm()
        .map_err(|error| attach_failed(mountpoint, &error))?;

    Ok(mounted)
}

/// Attach `filesystem` at `mountpoint`, however this platform does that.
///
/// Linux: `fuser`'s pure-Rust mount path, unchanged — `/dev/fuse` and the
/// `mount(2)` it performs itself, with `fusermount3` only for the detach.
///
/// # Errors
/// [`ExitCode::FatalError`] when the FUSE layer refuses. The message quotes what
/// the layer said, because "operation not permitted" and "no such file or
/// directory" from a mount attempt mean very different things and only the second
/// is about the mountpoint.
#[cfg(not(target_os = "macos"))]
fn attach(
    filesystem: VaultFs,
    mountpoint: &Path,
    session_config: &Config,
    _config: &MountConfig,
) -> Result<Attachment> {
    let mut session = Session::new(filesystem, mountpoint, session_config)
        .map_err(|error| attach_failed(mountpoint, &error))?;
    let unmounter = session.unmount_callable();
    Ok(Attachment {
        session,
        detacher: Box::new(unmounter),
        // `mount(2)` has already returned by the time `Session::new` does.
        confirm: Box::new(Immediate),
    })
}

/// The same, on macOS, where the mount is a handshake DCTL performs itself.
///
/// `fuser` is compiled here with its `macos-no-mount` feature — protocol and
/// session layers, no mount implementation — and [`super::macfuse`] supplies the
/// mounted descriptor. See that module for why, and for the ordering that makes
/// [`Confirm`] a separate step on this platform.
///
/// # Errors
/// [`ExitCode::Usage`] for an option macFUSE cannot be asked for;
/// [`ExitCode::FatalError`] where macFUSE refused or the kernel handshake failed.
#[cfg(target_os = "macos")]
fn attach(
    filesystem: VaultFs,
    mountpoint: &Path,
    session_config: &Config,
    config: &MountConfig,
) -> Result<Attachment> {
    let attached = super::macfuse::attach(mountpoint, session_config, config.idle_seconds)?;

    // `from_fd` performs the FUSE handshake and nothing else: the descriptor it
    // is given is already mounted. The request is waiting on it by the time this
    // runs — macFUSE queues `FUSE_INIT` before the helper hands the descriptor
    // over — so this does not block on a mount that has not happened.
    let session = Session::from_fd(
        filesystem,
        attached.device,
        session_config.acl,
        session_config.clone(),
    )
    .map_err(|error| {
        // The handshake failed with a mount already attached. Detaching before
        // the error returns is the same rule as everywhere else in this module:
        // no path out leaves a filesystem attached with nothing serving it, and
        // on macOS that state survives until the machine reboots.
        let mut detacher = attached.detacher.clone();
        let _ = detacher.unmount();
        attach_failed(mountpoint, &error)
    })?;

    Ok(Attachment {
        session,
        detacher: Box::new(attached.detacher),
        confirm: Box::new(attached.helper),
    })
}

impl Mounted {
    /// Serve until the filesystem is unmounted or the process is asked to stop.
    ///
    /// Returns `Ok(())` when the mount ended on its own — somebody ran `umount`,
    /// or the kernel detached it — and [`ExitCode::Cancelled`] when a signal
    /// ended it. See the module docs for why a signal is not success.
    ///
    /// # Errors
    /// [`ExitCode::Cancelled`] on `SIGINT` or `SIGTERM`;
    /// [`ExitCode::Uncategorised`] if the session loop itself failed, which means
    /// the connection to the kernel broke rather than that the mount was ended.
    pub async fn run(mut self) -> Result<()> {
        let started = Instant::now();
        let stopped = tokio::select! {
            // Biased so that a session which has already ended is reported as
            // having ended, rather than as having been signalled, when both are
            // ready in the same poll. Ending is the more specific fact.
            biased;
            result = self.wait_for_session() => Ended::Session(result),
            () = interrupted() => Ended::Signal,
        };

        // Detached before anything is reported, on every branch: a message about
        // an unmount that has not happened yet is a message that can be wrong.
        // The outcome is discarded here on purpose — `confirm_detached` below
        // asks the mountpoint itself, which is the answer every message is
        // conditioned on.
        let _ = self.detach();

        // The order here is load-bearing and was got wrong once already.
        //
        // `unmount` reports that a detach was *requested*; on the `auto_unmount`
        // path it is a socket close handed to a `fusermount3` child and returns
        // success before that child has done anything. So the claim has to be
        // checked — but a mount that is still *live* answers `stat` perfectly
        // well, and `ENOTCONN` only appears once the connection is torn down.
        // Checking before the session thread ended therefore read a healthy mount
        // as a detached one, which is the false success the check exists to stop.
        //
        // `settle` runs on every branch for that reason, not just on the signal
        // path: it is what makes the answer below mean anything. It is a no-op
        // where the session has already ended, because `wait_for_session` has
        // taken the handle.
        self.settle().await;
        let detached = self.confirm_detached().await;

        match stopped {
            Ended::Session(Ok(())) if !detached => Err(self.still_attached()),
            Ended::Session(Ok(())) => {
                tracing::info!(
                    { fields::OP } = "mount",
                    mountpoint = %self.mountpoint.display(),
                    seconds = started.elapsed().as_secs(),
                    "unmounted"
                );
                Ok(())
            }
            Ended::Session(Err(error)) => Err(CliError::new(
                ExitCode::Uncategorised,
                format!(
                    "the filesystem serving '{}' stopped: {error}",
                    self.mountpoint.display()
                ),
            )
            // The same rule as everywhere else in this function: the hint states
            // the mountpoint's condition, so it has to be the observed one. It
            // read "The mount has been detached" unconditionally, which is a
            // claim about the world made without looking at it — and the case
            // this branch handles, the kernel connection breaking, is not the
            // case in which a detach is most likely to have worked.
            .with_hint(if detached {
                "The mount has been detached. This is the connection to the kernel \
                 failing rather than the vault: re-running the command re-attaches it."
            } else {
                MOUNT_STALE_HINT
            })),
            // `settle` above has already waited for the loop to notice the
            // unmount, so `destroy` has run and the cached listings are gone.
            Ended::Signal => Err(signal_outcome(&self.mountpoint, detached)),
        }
    }

    /// Wait for the session thread to finish, whatever it finished with.
    ///
    /// A `JoinHandle` cannot be awaited, so the wait is a poll every
    /// [`MOUNT_SHUTDOWN_POLL`] — one task asleep for the life of the mount, which
    /// costs a timer. A channel from the thread would avoid the poll and would
    /// then need its own handling for a thread that ends without sending, which
    /// is precisely the case that matters here.
    async fn wait_for_session(&mut self) -> io::Result<()> {
        loop {
            match &self.session {
                None => return Ok(()),
                Some(handle) if handle.is_finished() => {
                    return match self.session.take() {
                        Some(handle) => join_result(handle),
                        None => Ok(()),
                    };
                }
                Some(_) => tokio::time::sleep(MOUNT_SHUTDOWN_POLL).await,
            }
        }
    }

    /// Detach the filesystem, at most once.
    ///
    /// Returns what the attempt amounted to. The callers ignore it — `Drop` has
    /// nowhere to put it and [`Mounted::run`] asks the mountpoint itself a moment
    /// later — and it is returned anyway so the *decision* can be asserted. The
    /// same reasoning as [`Detacher`]: a message this function chooses between is
    /// a message worth a test, and a `tracing` call is not observable from one.
    fn detach(&mut self) -> Detachment {
        if self.detached {
            return Detachment::AlreadyDone;
        }
        if let Err(error) = self.unmounter.unmount() {
            // A failed unmount is not the same thing as a mountpoint still
            // carrying a filesystem, and only the second is worth alarming
            // anybody about. The case that made the difference visible: somebody
            // runs `umount` from another terminal, the session ends, and this
            // runs anyway — on macOS `unmount(2)` then answers `EINVAL`, because
            // there is nothing left at the path. Printing "could not detach the
            // filesystem" there tells an operator their mountpoint is stuck when
            // it is free, which is `PLAN.md` §6's misreport pointing the other
            // way. So the mountpoint is looked at before the warning is written,
            // by the same predicate that decides the word "unmounted".
            if super::detached::is_detached(&self.mountpoint, self.bare_device) {
                self.detached = true;
                tracing::debug!(
                    mountpoint = %self.mountpoint.display(),
                    "the mountpoint was already free when the detach was attempted: {error}"
                );
                return Detachment::AlreadyFree;
            }
            // Reported rather than swallowed: a mountpoint that is still attached
            // after the process exits is the failure worth being loud about, and
            // this is the only place that knows it happened.
            //
            // **Not latched**, which is the point of the missing `self.detached`
            // assignment on this branch: a failure here is usually a transient
            // `EBUSY` from a reader that has not quite let go, and the callers
            // ask again. Setting the flag on a failed attempt made the first
            // answer the only answer there was ever going to be.
            tracing::warn!(
                mountpoint = %self.mountpoint.display(),
                "could not detach the filesystem: {error}"
            );
            return Detachment::Failed;
        }
        self.detached = true;
        Detachment::Requested
    }

    /// Wait, briefly, for the mountpoint to actually come free — asking again
    /// each time it has not.
    ///
    /// Bounded by [`MOUNT_DETACH_GRACE`]. Returns whether it did — the answer
    /// every message below is conditioned on, so that "unmounted" is a thing this
    /// process observed rather than a thing it asked for.
    ///
    /// Called after [`Mounted::settle`], so that a mountpoint still answering
    /// with the filesystem's device is one nothing is going to come and free.
    ///
    /// ## Why the grace period is spent asking rather than watching
    ///
    /// It used to only watch, and that was the difference between a mountpoint
    /// that comes free and one that does not. `unmount(2)` answers `EBUSY` while
    /// any process still holds a file open on the mount — and [`Mounted::detach`]
    /// runs the instant the signal arrives, which is exactly when a reader is
    /// most likely to still be there. Measured on macOS 27: Ctrl-C a mount with a
    /// `cat` running through it and the single attempt fails, the reader notices
    /// its next read failing microseconds later and lets go, and nothing ever
    /// asks again. The mountpoint stays attached with no server behind it.
    ///
    /// So each round of the wait is another attempt. Its error is deliberately
    /// discarded: [`Mounted::detach`] already reported the first one, and a
    /// hundred more copies of a transient `EBUSY` would bury it.
    async fn confirm_detached(&mut self) -> bool {
        let deadline = Instant::now().checked_add(MOUNT_DETACH_GRACE);
        loop {
            if super::detached::is_detached(&self.mountpoint, self.bare_device) {
                return true;
            }
            // `checked_add` returning `None` means the clock cannot represent the
            // deadline, which is not a reason to spin forever.
            if deadline.is_none_or(|deadline| Instant::now() >= deadline) {
                return false;
            }
            tokio::time::sleep(MOUNT_SHUTDOWN_POLL).await;
            // Ask again. See the docs above: the answer that got us here is
            // usually `EBUSY` from a reader that has since let go.
            let _ = self.unmounter.unmount();
        }
    }

    /// Take the mount down and wait for the mountpoint to come free, for a caller
    /// that cannot await.
    ///
    /// The blocking twin of [`Mounted::detach`] followed by
    /// [`Mounted::confirm_detached`], and it exists for [`Drop`] — which on macOS
    /// is not the unusual path but the **Ctrl-C** path, and Ctrl-C is how most
    /// mounts end. `main` races every command against `ctrl_c`, so when the signal
    /// wins the command future is dropped rather than run to completion, and
    /// [`Mounted::run`] — its retry, its confirmation and its message — does not
    /// happen at all.
    ///
    /// Returns whether the mountpoint came free, because `Drop` has nowhere to
    /// return an error and a decision that is only a `tracing` call cannot be
    /// asserted. The same reasoning as [`Detacher`]'s own documentation.
    fn free_mountpoint(&mut self) -> bool {
        let _ = self.detach();
        let deadline = Instant::now().checked_add(MOUNT_DETACH_GRACE);
        loop {
            if super::detached::is_detached(&self.mountpoint, self.bare_device) {
                return true;
            }
            if deadline.is_none_or(|deadline| Instant::now() >= deadline) {
                return false;
            }
            std::thread::sleep(MOUNT_SHUTDOWN_POLL);
            let _ = self.unmounter.unmount();
        }
    }

    /// The refusal for a mountpoint this process could not free.
    fn still_attached(&self) -> CliError {
        tracing::warn!(
            { fields::OP } = "mount",
            mountpoint = %self.mountpoint.display(),
            "the filesystem ended but the mountpoint is still attached"
        );
        CliError::new(
            ExitCode::Uncategorised,
            format!(
                "the filesystem serving '{}' ended, but the mountpoint is still attached",
                self.mountpoint.display()
            ),
        )
        .with_hint(MOUNT_STALE_HINT)
    }

    /// Wait, briefly, for the session loop to end after an unmount.
    ///
    /// Bounded by [`MOUNT_SHUTDOWN_GRACE`]. Unmounting makes the kernel's end of
    /// the connection return `ENODEV`, which ends the loop within microseconds —
    /// but the loop may be inside a provider request that will never answer, and
    /// a `dctl mount` that would not exit on Ctrl-C is a worse failure than one
    /// that exits while a doomed request is still in flight.
    async fn settle(&mut self) {
        let Some(session) = self.session.take() else {
            return;
        };
        // `checked_add` rather than `+`: adding to an `Instant` panics on
        // overflow, and a panic on the shutdown path would leave the process
        // aborting with a mount it had just detached.
        let deadline = Instant::now().checked_add(MOUNT_SHUTDOWN_GRACE);
        while !session.is_finished() {
            if deadline.is_none_or(|deadline| Instant::now() >= deadline) {
                tracing::debug!(
                    "the filesystem thread did not finish within the shutdown grace period"
                );
                // Deliberately not joined: the mount is already detached, so
                // nothing the thread is still doing can affect the mountpoint,
                // and blocking here is how a process becomes unkillable.
                return;
            }
            tokio::time::sleep(MOUNT_SHUTDOWN_POLL).await;
        }
        let _ = join_result(session);
    }
}

impl Drop for Mounted {
    /// The last line of defence, and on macOS the ordinary one.
    ///
    /// Reached when the caller's future is cancelled rather than run to
    /// completion — which is exactly what happens when `main`'s own Ctrl-C race
    /// resolves in favour of the signal. Ctrl-C is how most mounts end, so this is
    /// not a corner: [`Mounted::run`]'s whole shutdown, including its retry and
    /// its message, is skipped on that path and this is all there is.
    ///
    /// It therefore does the same two things `run` does, as far as a `Drop` can:
    /// it keeps asking for the detach until the mountpoint comes free, and if it
    /// does not, it **says so**. It cannot return an error, and a mount left
    /// attached with no server is not a thing to leave an operator to discover
    /// from a hanging `ls`.
    fn drop(&mut self) {
        if self.free_mountpoint() {
            return;
        }
        tracing::warn!(
            { fields::OP } = "mount",
            mountpoint = %self.mountpoint.display(),
            hint = MOUNT_STALE_HINT,
            "the mountpoint is still attached after the mount ended"
        );
    }
}

/// What to report when a signal ended the mount.
///
/// A free function taking the observation rather than a method reading the world,
/// because the thing worth pinning is the *decision*: a signalled mount that
/// could not be detached must not be described as having been unmounted. That is
/// `PLAN.md` §6 applied to the one message an operator reads before walking away
/// from the terminal, and it was wrong until the detach was checked.
///
/// Cancelled either way — the operator did stop it, and
/// [`ExitCode::Cancelled`]'s meaning does not change because the cleanup was
/// incomplete — but the message and the hint do.
fn signal_outcome(mountpoint: &Path, detached: bool) -> CliError {
    if detached {
        return CliError::new(
            ExitCode::Cancelled,
            format!("unmounted '{}' on request", mountpoint.display()),
        );
    }
    tracing::warn!(
        { fields::OP } = "mount",
        mountpoint = %mountpoint.display(),
        "stopped on request, but the mountpoint is still attached"
    );
    CliError::new(
        ExitCode::Cancelled,
        format!(
            "stopped serving '{}' on request, but the mountpoint is still attached",
            mountpoint.display()
        ),
    )
    .with_hint(MOUNT_STALE_HINT)
}

/// What one call to [`Mounted::detach`] amounted to.
///
/// Three outcomes and not two, because the middle one is the whole reason this
/// type exists: an unmount that *failed* over a mountpoint that is *already free*
/// is not a problem, and reporting it as one tells an operator their directory is
/// stuck when it is fine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Detachment {
    /// The kernel accepted the request. Whether the mountpoint is free is a
    /// separate question, answered by [`super::detached`].
    Requested,
    /// The unmount failed and the mountpoint is free anyway — somebody else took
    /// it down first. Nothing to report.
    AlreadyFree,
    /// The unmount failed and the mountpoint is still carrying a filesystem.
    Failed,
    /// A detach had already been performed; this call did nothing.
    AlreadyDone,
}

/// How a mount ended.
enum Ended {
    /// The session loop returned, with whatever it returned.
    Session(io::Result<()>),
    /// A signal asked the process to stop.
    Signal,
}

/// The mount options `fuser` is given.
///
/// Read-only is set here **as well as** enforced in every callback
/// ([`super::refuse`]). Both, not either: this is the cheap defence, which the
/// kernel applies before a request is ever sent, and the callbacks are the true
/// one. A mount option that silently failed to apply on some platform must not
/// be the only thing between a vault and a write.
fn session_config(config: &MountConfig) -> Config {
    let mut options = vec![
        MountOption::RO,
        // Nothing in a vault is executable — no mode bits are stored — and a
        // filesystem that let a downloaded binary run straight out of a network
        // mount is offering a capability nobody asked for.
        MountOption::NoExec,
        // Set-user-id on a file served from a remote vault is a privilege
        // escalation waiting for a mistake.
        MountOption::NoSuid,
        // No device nodes: a vault cannot store one, and honouring one that
        // somehow appeared would be honouring something forged.
        MountOption::NoDev,
        // Access times cannot be recorded on a read-only filesystem, so asking
        // the kernel to maintain them would be asking for writes that must fail.
        MountOption::NoAtime,
        MountOption::FSName(MOUNT_FS_NAME.to_string()),
        // Two spellings of the same statement, because the platforms disagree
        // about how long it may be. macFUSE refuses a filesystem type name over
        // six characters *outright* — the mount does not happen — so the
        // thirteen-character portable one cannot be used there. The short form
        // still says whose the mount is and that it is read-only, which is what
        // the field is for; `mount(8)` prints it as `macfuse_dctlro`.
        MountOption::Subtype(
            if cfg!(target_os = "macos") {
                MOUNT_MACFUSE_TYPE_NAME
            } else {
                MOUNT_FS_SUBTYPE
            }
            .to_string(),
        ),
    ];

    if let Some(name) = &config.volume_name {
        // macOS's own option, passed through as written. On Linux there is no
        // volume-name concept and the flag is refused before this is reached —
        // see `commands::mount::plan`.
        options.push(MountOption::CUSTOM(format!("volname={name}")));
    }

    // `auto_unmount` asks the kernel to detach the filesystem when this process
    // goes away, which covers the one case no code can: `SIGKILL`. It is
    // requested only when the user has already widened access.
    //
    // Its absence is **not** free, and the comment here used to say it was: it
    // claimed `Drop` covered the remainder, but `Drop` is exactly what `SIGKILL`
    // does not run. Measured on this server, default flags, `SIGKILL`: the
    // mountpoint is left attached with no server behind it and has to be cleared
    // by hand. Requesting the option unconditionally is the obvious answer and is
    // deliberately not taken here without measuring it — `auto_unmount` is only
    // implemented via the setuid `fusermount3` helper, so switching it on for
    // every mount would route every mount through that helper and keep one alive
    // for the life of the mount. That is a trade worth making on purpose rather
    // than as a side effect of a docs fix.
    //
    // **macOS has no such option at all**, and this is not the place to pretend
    // otherwise. macFUSE was passed `auto_unmount` on this machine and mounted
    // happily without it doing anything, which is why `macfuse::options` refuses
    // the option rather than forwarding it — and why it is not asked for here.
    // The consequence is worth stating plainly: on macOS a `SIGKILL` leaves the
    // mountpoint attached whatever the ACL, and that directory stays unusable
    // until the machine is rebooted. Every signal a process can handle is still
    // covered.
    if config.acl != fuser::SessionACL::Owner && !cfg!(target_os = "macos") {
        options.push(MountOption::AutoUnmount);
    }

    // Built by mutation rather than by a struct literal: `fuser::Config` is
    // `#[non_exhaustive]`, so a literal here would stop compiling the day it
    // grows a field — which is exactly the day this code should keep working and
    // take the new default.
    let mut session = Config::default();
    session.mount_options = options;
    session.acl = config.acl;
    // One event-loop thread. `fuser` supports more only on Linux, and the
    // concurrency that matters here is not in the loop anyway: every callback
    // that can block hands its work to the runtime and returns, so the loop is
    // never what a slow provider is waiting behind.
    session.n_threads = None;
    session
}

/// Resolve when the process is asked to stop.
///
/// Both signals, because both mean it: `SIGINT` is a person at a terminal and
/// `SIGTERM` is a service manager or a shutdown. A mount that honoured only the
/// first would be killed uncleanly by every `systemctl stop` and every reboot,
/// leaving exactly the stale mountpoint this module exists to prevent.
///
/// A failure to install the `SIGTERM` handler is not fatal: the `SIGINT` half
/// still works, and refusing to mount because one of two signal handlers could
/// not be registered would be trading a working filesystem for a hypothetical.
async fn interrupted() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|error| {
            tracing::warn!("SIGTERM will not be handled: {error}");
        })
        .ok();

    match terminate.as_mut() {
        Some(terminate) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
        }
        None => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

/// Flatten a thread join into the session's own result.
///
/// A panicking session thread cannot happen — the callbacks are written not to,
/// and the release build aborts on panic rather than unwinding — but `join`
/// reports the possibility and it has to become an error rather than an
/// `unwrap`, because the one place that must not panic is the code that handles
/// a panic.
fn join_result(handle: JoinHandle<io::Result<()>>) -> io::Result<()> {
    match handle.join() {
        Ok(result) => result,
        Err(_) => Err(io::Error::other("the filesystem thread ended unexpectedly")),
    }
}

/// The refusal when the platform's FUSE layer will not attach the filesystem.
///
/// Quotes what the layer said, because the answers are not interchangeable:
/// "operation not permitted" is a missing `user_allow_other`, while "no such file
/// or directory" from a *mount* usually means the FUSE helper itself is not
/// installed. Only the second is worth checking the mountpoint for, and a message
/// that flattened them would send half of its readers to the wrong place.
///
/// The macOS hint used to send the reader to System Settings to approve macFUSE's
/// system extension. That advice is now **wrong by construction**:
/// [`preflight`](super::preflight) refuses before this is reached unless a
/// macFUSE device node exists, and a device node existing is proof the extension
/// is loaded and approved. Sending somebody to re-approve it cost an operator two
/// reboots and a boot-security downgrade once; it is not repeated here.
fn attach_failed(mountpoint: &Path, error: &io::Error) -> CliError {
    CliError::new(
        ExitCode::FatalError,
        format!("cannot mount at '{}': {error}", mountpoint.display()),
    )
    .with_hint(if cfg!(target_os = "macos") {
        MOUNT_MACFUSE_HELPER_HINT
    } else {
        "This mount needs FUSE: check that the fuse3 package and its `fusermount3` \
         helper are installed, that /dev/fuse exists, and — for --allow-other — \
         that `user_allow_other` is set in /etc/fuse.conf."
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuser::SessionACL;
    use std::time::Duration;

    fn config() -> MountConfig {
        MountConfig {
            root: String::new(),
            attr_ttl: Duration::from_secs(1),
            dir_ttl: Duration::from_secs(300),
            read_ahead: 0,
            acl: SessionACL::Owner,
            volume_name: None,
            idle_seconds: crate::constants::DEFAULT_TIMEOUT_SECS,
            no_modtime: false,
        }
    }

    fn has(options: &[MountOption], wanted: &MountOption) -> bool {
        options.contains(wanted)
    }

    #[test]
    fn the_kernel_is_told_the_filesystem_is_read_only() {
        // The cheap half of the read-only defence: most write attempts never
        // reach userspace at all.
        let session = session_config(&config());
        assert!(has(&session.mount_options, &MountOption::RO));
        assert!(!has(&session.mount_options, &MountOption::RW));
    }

    #[test]
    fn nothing_served_from_a_vault_may_execute_or_elevate() {
        // A vault stores no mode bits, so a binary read out of one has no
        // provenance a kernel could check.
        let session = session_config(&config());
        assert!(has(&session.mount_options, &MountOption::NoExec));
        assert!(has(&session.mount_options, &MountOption::NoSuid));
        assert!(has(&session.mount_options, &MountOption::NoDev));
    }

    #[test]
    fn access_times_are_not_maintained_on_a_read_only_filesystem() {
        // Asking the kernel to keep them would be asking for writes that must
        // fail on every read.
        let session = session_config(&config());
        assert!(has(&session.mount_options, &MountOption::NoAtime));
    }

    #[test]
    fn the_mount_table_names_the_tool_rather_than_the_users_remote() {
        // A remote name is the user's word for a vault and can be anything; the
        // metadata-privacy design does not stop at object keys.
        let session = session_config(&config());
        assert!(has(
            &session.mount_options,
            &MountOption::FSName(MOUNT_FS_NAME.to_string())
        ));

        // The subtype has two spellings because the platforms disagree about how
        // long one may be: macFUSE refuses a filesystem type name over six
        // characters *outright*, so the portable thirteen-character one cannot be
        // used there. Both still name the tool and say read-only, which is the
        // property this test is about.
        let subtype = if cfg!(target_os = "macos") {
            MOUNT_MACFUSE_TYPE_NAME
        } else {
            MOUNT_FS_SUBTYPE
        };
        assert!(has(
            &session.mount_options,
            &MountOption::Subtype(subtype.to_string())
        ));
        assert!(
            subtype.contains("dctl"),
            "the tool must be named: {subtype}"
        );
        assert!(
            subtype.contains("ro"),
            "and that it is read-only: {subtype}"
        );
    }

    #[test]
    fn a_volume_name_is_passed_through_only_when_one_was_given() {
        let mut named = config();
        named.volume_name = Some("Archive".into());
        assert!(has(
            &session_config(&named).mount_options,
            &MountOption::CUSTOM("volname=Archive".into())
        ));

        let session = session_config(&config());
        assert!(
            !session
                .mount_options
                .iter()
                .any(|option| matches!(option, MountOption::CUSTOM(value) if value.starts_with("volname="))),
            "a volume name was invented"
        );
    }

    #[test]
    fn the_default_acl_keeps_the_mount_to_the_user_who_unlocked_it() {
        // The security property in the module docs of `super`: an unlocked vault
        // is readable by whoever can talk to the mount.
        assert_eq!(session_config(&config()).acl, SessionACL::Owner);
    }

    #[test]
    fn auto_unmount_is_requested_only_where_the_kernel_can_honour_it() {
        // Pinning the *current* behaviour, and what it costs: at the default ACL
        // the option is absent, and a `SIGKILL` therefore leaves a stale
        // mountpoint — verified on Linux 6.12 against a real mount, not inferred.
        // See the reasoning at the option itself for why this is not simply
        // switched on for everyone.
        assert!(!has(
            &session_config(&config()).mount_options,
            &MountOption::AutoUnmount
        ));

        // Widening the ACL asks for it on Linux and must **not** on macOS, where
        // macFUSE has no such option. Measured: macFUSE accepts `auto_unmount`
        // and does nothing with it, so asking would promise a `--allow-other`
        // user a cleanup after `SIGKILL` that does not happen — and on macOS the
        // mountpoint that is left behind stays unusable until the machine
        // reboots. `macfuse::options` refuses the option for the same reason, so
        // the two would disagree if this were ever switched back on.
        let mut shared = config();
        shared.acl = SessionACL::All;
        assert_eq!(
            has(
                &session_config(&shared).mount_options,
                &MountOption::AutoUnmount
            ),
            !cfg!(target_os = "macos")
        );
    }

    #[test]
    fn the_options_never_conflict_with_each_other() {
        // `fuser` refuses a conflicting set outright, which would turn a
        // perfectly good mount into a startup failure.
        for acl in [SessionACL::Owner, SessionACL::RootAndOwner, SessionACL::All] {
            let mut config = config();
            config.acl = acl;
            config.volume_name = Some("Archive".into());
            let session = session_config(&config);
            for option in &session.mount_options {
                let opposite = match option {
                    MountOption::RO => Some(MountOption::RW),
                    MountOption::NoExec => Some(MountOption::Exec),
                    MountOption::NoSuid => Some(MountOption::Suid),
                    MountOption::NoDev => Some(MountOption::Dev),
                    MountOption::NoAtime => Some(MountOption::Atime),
                    _ => None,
                };
                if let Some(opposite) = opposite {
                    assert!(
                        !has(&session.mount_options, &opposite),
                        "{option:?} and its opposite are both set"
                    );
                }
            }
        }
    }

    #[test]
    fn a_mount_failure_names_the_mountpoint_and_what_the_layer_said() {
        // "Operation not permitted" and "no such file or directory" mean very
        // different things here, and only one of them is about the mountpoint.
        let error = attach_failed(
            Path::new("/mnt/vault"),
            &io::Error::from(io::ErrorKind::PermissionDenied),
        );
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("/mnt/vault"));
        assert!(error.hint().is_some());
    }

    #[test]
    fn a_mount_failure_never_sends_a_macos_reader_to_approve_a_loaded_extension() {
        // The hint here used to say the macFUSE system extension needed allowing
        // in System Settings. `preflight` refuses before this is reached unless a
        // macFUSE device node exists, and a device node existing is proof the
        // extension is loaded — so on every machine that gets this far, that
        // advice is wrong. It cost an operator two reboots and a boot-security
        // downgrade once, which is why it is asserted against rather than merely
        // deleted.
        let error = attach_failed(
            Path::new("/mnt/vault"),
            &io::Error::from(io::ErrorKind::PermissionDenied),
        );
        assert!(
            !error
                .hint()
                .is_some_and(|hint| hint.contains("System Settings")),
            "{:?}",
            error.hint()
        );
    }

    #[test]
    fn a_platform_whose_mount_call_has_already_answered_confirms_immediately() {
        // The Linux half of `Confirm`. Asserted rather than assumed, because the
        // whole point of the trait is that `mount` calls `confirm` on every
        // platform and only one of them has anything to do — and a version that
        // returned an error here would refuse every Linux mount.
        assert!(Box::new(Immediate).confirm().is_ok());
    }

    /// A detacher that does nothing, for a `Mounted` with no filesystem behind
    /// it. The session field is `None` in these tests, so there is nothing to
    /// detach and nothing for this to do — its whole purpose is to let a
    /// [`Mounted`] exist off a kernel.
    struct NoDetach;

    impl Detacher for NoDetach {
        fn unmount(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A detacher whose unmount always fails, the way `unmount(2)` does on macOS
    /// when there is nothing attached at the path.
    struct FailDetach(io::ErrorKind);

    impl Detacher for FailDetach {
        fn unmount(&mut self) -> io::Result<()> {
            Err(io::Error::from(self.0))
        }
    }

    /// A detacher that always fails and counts how often it was asked.
    ///
    /// The count is the whole point: `unmount(2)` answers `EBUSY` while any
    /// process still holds a file open on the mount, and that condition lasts
    /// microseconds. Whether the grace period is spent *asking again* or merely
    /// *watching* is the difference between a mountpoint that comes free and one
    /// that does not, and it is invisible in every other observable.
    #[derive(Clone)]
    struct CountingDetach {
        attempts: Arc<std::sync::atomic::AtomicUsize>,
        kind: io::ErrorKind,
    }

    impl CountingDetach {
        fn new(kind: io::ErrorKind) -> Self {
            Self {
                attempts: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                kind,
            }
        }

        fn attempts(&self) -> usize {
            self.attempts.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl Detacher for CountingDetach {
        fn unmount(&mut self) -> io::Result<()> {
            self.attempts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Err(io::Error::from(self.kind))
        }
    }

    #[tokio::test]
    async fn a_mountpoint_that_is_busy_is_asked_again_rather_than_given_up_on() {
        // Measured on macOS 27 / macFUSE 5.3.3, and it is the worst failure this
        // module has: Ctrl-C a mount while anything is reading through it and the
        // mountpoint is left attached with no server behind it. `mount(8)` still
        // lists it, every access to the directory fails, and only a hand-run
        // `umount` recovers it.
        //
        // The cause is one attempt at exactly the wrong moment. `unmount(2)`
        // answers EBUSY while a process still holds a file open on the mount —
        // `detach` is called the instant the signal arrives, which is precisely
        // when a reader is most likely to still be there — and nothing ever asked
        // again. The reader notices its next read failing microseconds later and
        // lets go, and by then the only attempt there was ever going to be had
        // already happened.
        //
        // So the grace period is spent re-asking, and this asks
        // [`Mounted::confirm_detached`] directly rather than going through
        // [`Mounted::run`].
        //
        // ## Why not through `run`, which is how it is really reached
        //
        // Because through `run` this assertion cannot fail, whatever the code
        // does. `run` takes `self` by value, so the `Drop` impl fires before the
        // test resumes — and `Drop` runs [`Mounted::free_mountpoint`], which has
        // a re-asking loop of its own. Written that way and with the retry
        // deleted outright, the count was still in the hundreds and the test
        // stayed green: it was measuring the drop path while claiming to measure
        // this one. Both wordings were tried against a build with the retry
        // removed, and only this one goes red.
        //
        // What `run` owes is pinned by the assertion below it — that a
        // mountpoint which never comes free is *reported*, not passed over — and
        // by the drop-path test that follows.
        let dir = tempfile::tempdir().unwrap();
        let real = super::super::detached::device_of(dir.path()).unwrap();

        let detacher = CountingDetach::new(io::ErrorKind::ResourceBusy);
        let mut mounted = unattached(dir.path(), Some(real.wrapping_add(1)));
        mounted.unmounter = Box::new(detacher.clone());

        assert!(
            !mounted.confirm_detached().await,
            "a mountpoint on somebody else's device has not come free"
        );

        // The threshold separates *asking throughout the grace period* from
        // *asking once*. The loop polls every [`MOUNT_SHUTDOWN_POLL`] for up to
        // [`MOUNT_DETACH_GRACE`] — two hundred attempts as those constants
        // stand — while an implementation that only watches makes none at all.
        // Ten sits far above the second and far below the first, so it tells
        // them apart without pinning the ratio between two constants either is
        // free to change.
        assert!(
            detacher.attempts() > 10,
            "the mountpoint was asked to detach {} time(s) and then watched for \
             {:?}; a transient EBUSY needs asking again, not watching",
            detacher.attempts(),
            MOUNT_DETACH_GRACE
        );

        // And the other half, so that what `run` does with the answer is still
        // covered: a mountpoint that never comes free is reported rather than
        // quietly accepted.
        let stubborn = CountingDetach::new(io::ErrorKind::ResourceBusy);
        let mut reported = unattached(dir.path(), Some(real.wrapping_add(1)));
        reported.unmounter = Box::new(stubborn);
        let error = reported.run().await.expect_err("it never came free");
        assert!(error.message().contains("still attached"));
    }

    #[test]
    fn the_drop_path_asks_again_too_and_says_so_when_the_mountpoint_stays_attached() {
        // `Drop` is not the unusual path — on macOS it is the **Ctrl-C** path, and
        // Ctrl-C is how most mounts end. `main` races every command against
        // `ctrl_c`, so when the signal wins the command future is dropped rather
        // than run to completion and `Mounted::run` — its retry, its confirmation
        // and its message — never happens at all. Measured: SIGTERM produced
        // "stopped on request, but the mountpoint is still attached" while SIGINT
        // in the same state produced only "cancelled", and left the operator with
        // an unusable directory and nothing pointing at it.
        //
        // So the drop path owes the same two things: ask again, and say so when
        // asking did not work. `Drop` has nowhere to return an error, which is why
        // the decision is a value here rather than only a `tracing` call — the
        // same reasoning as [`Detacher`]'s own documentation.
        let dir = tempfile::tempdir().unwrap();
        let real = super::super::detached::device_of(dir.path()).unwrap();

        let detacher = CountingDetach::new(io::ErrorKind::ResourceBusy);
        let mut mounted = unattached(dir.path(), Some(real.wrapping_add(1)));
        mounted.unmounter = Box::new(detacher.clone());

        assert!(
            !mounted.free_mountpoint(),
            "a mountpoint on somebody else's device has not come free"
        );
        assert!(
            detacher.attempts() > 1,
            "the drop path asked {} time(s)",
            detacher.attempts()
        );

        // And the other half, so the rule is not "retry for ever": a mountpoint
        // back on its own device is free at the first look and costs no waiting.
        let free = CountingDetach::new(io::ErrorKind::ResourceBusy);
        let mut ok = unattached(dir.path(), Some(real));
        ok.unmounter = Box::new(free.clone());
        let started = Instant::now();
        assert!(ok.free_mountpoint());
        assert!(
            started.elapsed() < MOUNT_DETACH_GRACE,
            "a free mountpoint must not be waited on"
        );
    }

    /// A `Mounted` over a real directory, with no filesystem attached, that
    /// believes the mountpoint's bare device is `bare`.
    ///
    /// `session: None` makes `wait_for_session` return immediately, so `run`
    /// reaches its decision without a thread — and the decision is the whole
    /// subject of these two tests.
    fn unattached(mountpoint: &Path, bare: Option<u64>) -> Mounted {
        Mounted {
            session: None,
            unmounter: Box::new(NoDetach),
            mountpoint: mountpoint.to_path_buf(),
            bare_device: bare,
            detached: false,
        }
    }

    #[tokio::test]
    async fn a_session_that_ended_over_a_mountpoint_that_never_came_free_is_refused() {
        // The regression `cc05f90` fixed, asserted at the level it happened:
        // `unmount` answers "a detach was requested", so `run` must check the
        // mountpoint before it says the word. Told that the bare device is some
        // other number, `run` can only conclude the mountpoint is still carrying
        // a filesystem — and must refuse rather than print `unmounted`.
        //
        // Deleting the `confirm_detached` call from `run` makes this pass a
        // success where a refusal is owed, which the predicate's own tests in
        // `super::detached` cannot see.
        let dir = tempfile::tempdir().unwrap();
        let real = super::super::detached::device_of(dir.path()).unwrap();

        let error = unattached(dir.path(), Some(real.wrapping_add(1)))
            .run()
            .await
            .expect_err("a mountpoint that is still attached is not an unmount");
        assert_eq!(error.code(), ExitCode::Uncategorised);
        assert!(
            error.message().contains("still attached"),
            "the message must say what is wrong: {}",
            error.message()
        );
    }

    #[tokio::test]
    async fn a_session_that_ended_over_a_mountpoint_that_came_free_succeeds() {
        // The other half, so the refusal above cannot be satisfied by refusing
        // everything: measured against its own device, the mountpoint is free and
        // the run ends cleanly.
        let dir = tempfile::tempdir().unwrap();
        let real = super::super::detached::device_of(dir.path()).unwrap();

        unattached(dir.path(), Some(real))
            .run()
            .await
            .expect("a mountpoint back on its own device is unmounted");
    }

    #[test]
    fn a_failed_unmount_over_a_free_mountpoint_is_not_reported_as_a_stuck_one() {
        // Measured on macOS: run `umount` from another terminal, the session
        // ends, and `Mounted::run` detaches anyway — at which point `unmount(2)`
        // answers EINVAL, because there is nothing at the path any more. The
        // command exited 0 and printed
        //   WARN could not detach the filesystem: Invalid argument
        // which tells an operator their mountpoint is stuck when it is free. That
        // is `PLAN.md` §6's misreport pointing the other way, and it is exactly
        // as bad: the whole value of the warning is that it means something.
        //
        // Described rather than mounted: the detacher always fails, and the only
        // thing that changes between the two halves is what the mountpoint says.
        let dir = tempfile::tempdir().unwrap();
        let real = super::super::detached::device_of(dir.path()).unwrap();

        let mut free = unattached(dir.path(), Some(real));
        free.unmounter = Box::new(FailDetach(io::ErrorKind::InvalidInput));
        assert_eq!(
            free.detach(),
            Detachment::AlreadyFree,
            "an unmount that failed over a mountpoint on its own device took nothing down \
             because there was nothing left to take down"
        );

        // The other half, so the rule is not "never warn": told the mountpoint is
        // still on some other device, the same failure is a real one.
        let mut stuck = unattached(dir.path(), Some(real.wrapping_add(1)));
        stuck.unmounter = Box::new(FailDetach(io::ErrorKind::ResourceBusy));
        assert_eq!(stuck.detach(), Detachment::Failed);

        // And a detach that the kernel accepted is neither.
        let mut ordinary = unattached(dir.path(), Some(real));
        assert_eq!(ordinary.detach(), Detachment::Requested);
        // Twice is a no-op: `run` detaches and `Drop` runs afterwards.
        assert_eq!(ordinary.detach(), Detachment::AlreadyDone);
    }

    #[test]
    fn a_signalled_mount_that_detached_says_so() {
        // The ordinary Ctrl-C: the mountpoint really is free, and saying so is
        // what lets an operator walk away.
        let outcome = signal_outcome(Path::new("/mnt/vault"), true);
        assert_eq!(outcome.code(), ExitCode::Cancelled);
        assert!(
            outcome.message().contains("unmounted"),
            "a completed unmount must be reported as one: {}",
            outcome.message()
        );
        assert!(
            outcome.hint().is_none(),
            "nothing to advise when the mountpoint came free"
        );
    }

    #[test]
    fn a_signalled_mount_that_did_not_detach_must_not_claim_it_unmounted() {
        // The regression this module exists for, measured on Linux 6.12: SIGTERM
        // to a mount started with --allow-other or --allow-root left the
        // mountpoint attached and dead, and the command printed
        // "unmounted '<path>' on request" and exited 25 anyway. An operator who
        // reads that walks away from a directory that fails every access with
        // ENOTCONN. `PLAN.md` §6: work that did not happen is not reported as
        // having happened.
        let outcome = signal_outcome(Path::new("/mnt/vault"), false);
        assert_eq!(
            outcome.code(),
            ExitCode::Cancelled,
            "the operator did stop it; only the cleanup is incomplete"
        );
        assert!(
            !outcome.message().contains("unmounted"),
            "an unmount that did not happen was reported as done: {}",
            outcome.message()
        );
        assert!(
            outcome.message().contains("still attached"),
            "the operator has to be told the mountpoint is unusable: {}",
            outcome.message()
        );
        assert!(
            outcome.message().contains("/mnt/vault"),
            "the refusal must name the mountpoint: {}",
            outcome.message()
        );
        assert!(
            outcome
                .hint()
                .is_some_and(|hint| hint.contains("fusermount3 -u")),
            "a recoverable failure must name the one command that recovers it"
        );
    }

    #[test]
    fn a_failed_thread_join_becomes_an_error_rather_than_a_panic() {
        // The one place that must not panic is the code that handles a panic.
        let handle = std::thread::spawn(|| -> io::Result<()> { Ok(()) });
        assert!(join_result(handle).is_ok());
    }
}
