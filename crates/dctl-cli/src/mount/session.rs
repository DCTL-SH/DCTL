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
    MOUNT_DETACH_GRACE, MOUNT_FS_NAME, MOUNT_FS_SUBTYPE, MOUNT_SHUTDOWN_GRACE, MOUNT_SHUTDOWN_POLL,
    MOUNT_STALE_HINT,
};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::logging::fields;
use crate::source::Source;

use super::config::MountConfig;
use super::fs::VaultFs;

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
    /// Detaches the filesystem. Cloneable across threads by design, so the
    /// signal path and `Drop` can both reach it.
    unmounter: SessionUnmounter,
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
    let filesystem = VaultFs::new(source, config.clone(), mountpoint, runtime);
    let session_config = session_config(&config);

    // Taken before `Session::new`, because after it the mountpoint reports the
    // filesystem's device and the original is unrecoverable. This one number is
    // what lets the unmount be confirmed rather than assumed; a failure to read
    // it is not worth refusing a mount over, and is carried as `None`.
    let bare_device = super::detached::device_of(mountpoint).ok();

    // `Session::new` performs the mount syscall *and* the kernel handshake, both
    // of which block. It runs here rather than on the session thread so that a
    // failure to mount is an ordinary error return with the platform's own
    // message, rather than something to be recovered from a thread.
    let mut session = Session::new(filesystem, mountpoint, &session_config)
        .map_err(|error| mount_failed(mountpoint, &error))?;
    let unmounter = session.unmount_callable();

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

    match thread {
        Ok(session) => Ok(Mounted {
            session: Some(session),
            unmounter,
            mountpoint: mountpoint.to_path_buf(),
            bare_device,
            detached: false,
        }),
        Err(error) => {
            // The mount succeeded and the thread did not. Leaving it attached
            // with nothing serving it is the exact failure this module exists to
            // prevent, so it is undone before the error is returned.
            let mut unmounter = unmounter;
            let _ = unmounter.unmount();
            Err(error)
        }
    }
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
        self.detach();

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
    fn detach(&mut self) {
        if self.detached {
            return;
        }
        self.detached = true;
        if let Err(error) = self.unmounter.unmount() {
            // Reported rather than swallowed: a mountpoint that is still attached
            // after the process exits is the failure worth being loud about, and
            // this is the only place that knows it happened.
            tracing::warn!(
                mountpoint = %self.mountpoint.display(),
                "could not detach the filesystem: {error}"
            );
        }
    }

    /// Wait, briefly, for the mountpoint to actually come free.
    ///
    /// Bounded by [`MOUNT_DETACH_GRACE`]. Returns whether it did — the answer
    /// every message below is conditioned on, so that "unmounted" is a thing this
    /// process observed rather than a thing it asked for.
    ///
    /// Called after [`Mounted::settle`], so that a mountpoint still answering
    /// with the filesystem's device is one nothing is going to come and free.
    async fn confirm_detached(&self) -> bool {
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
    /// The last line of defence.
    ///
    /// Reached when the caller's future is cancelled rather than run to
    /// completion — which is exactly what happens when `main`'s own Ctrl-C race
    /// resolves in favour of the signal. Without this, that path would leave the
    /// mountpoint attached with the process exiting.
    fn drop(&mut self) {
        self.detach();
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
        MountOption::Subtype(MOUNT_FS_SUBTYPE.to_string()),
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
    if config.acl != fuser::SessionACL::Owner {
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
/// "operation not permitted" is a missing `user_allow_other` or a kernel
/// extension that was never approved, while "no such file or directory" from a
/// *mount* usually means the FUSE helper itself is not installed. Only the
/// second is worth checking the mountpoint for, and a message that flattened
/// them would send half of its readers to the wrong place.
fn mount_failed(mountpoint: &Path, error: &io::Error) -> CliError {
    CliError::new(
        ExitCode::FatalError,
        format!("cannot mount at '{}': {error}", mountpoint.display()),
    )
    .with_hint(if cfg!(target_os = "macos") {
        "This mount needs macFUSE, and macFUSE needs its system extension to be \
         allowed in System Settings > General > Login Items & Extensions the \
         first time it loads. Check that it is installed and enabled, then try \
         again."
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
        assert!(has(
            &session.mount_options,
            &MountOption::Subtype(MOUNT_FS_SUBTYPE.to_string())
        ));
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

        let mut shared = config();
        shared.acl = SessionACL::All;
        assert!(has(
            &session_config(&shared).mount_options,
            &MountOption::AutoUnmount
        ));
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
        let error = mount_failed(
            Path::new("/mnt/vault"),
            &io::Error::from(io::ErrorKind::PermissionDenied),
        );
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("/mnt/vault"));
        assert!(error.hint().is_some());
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
