//! Mounting on macOS: the handshake DCTL performs itself.
//!
//! ## Why this module exists
//!
//! `fuser` is the Rust FUSE binding, and on macOS its build script does not
//! offer a mount at all. Its pure-Rust mount path is gated to a hardcoded list of
//! operating systems that excludes macOS; what macOS falls through to is a
//! `pkg-config` probe commented `// for macFUSE 4.x` and a `fuse_mount_compat25`
//! call that fails against **macFUSE 5**. The previous verdict here — "the
//! binding cannot reach this macFUSE" — was true of that configuration and read
//! as though mounting on macOS were impossible. It is not. rclone mounts on the
//! same machine, and the dependency's configuration is ours to change.
//!
//! So this build turns on `fuser`'s `macos-no-mount` feature, which compiles its
//! protocol and session layers with **no mount implementation at all** and leaves
//! the caller to supply an already-mounted descriptor through
//! [`fuser::Session::from_fd`]. Everything `fuser` is good at — the wire
//! protocol, the request dispatch, the reply types — is kept; the one thing it
//! cannot do on this platform is done here.
//!
//! ## The handshake, in four steps
//!
//! 1. [`handover::channel`] opens a `SOCK_STREAM` socketpair.
//! 2. [`helper::Helper::start`] runs macFUSE's setuid `mount_macfuse` with one
//!    half of that pair as its standard input. `mount(2)` is root-only on macOS
//!    and macFUSE's argument struct for it is private, so this program is the
//!    supported interface — the same one macFUSE's own libfuse, `hanwen/go-fuse`
//!    and the `cgofuse` layer rclone uses all go through.
//! 3. [`handover::receive`] takes the `/dev/macfuseN` descriptor back as an
//!    `SCM_RIGHTS` control message.
//! 4. The caller builds a session on that descriptor, starts it, and only then
//!    calls [`helper::Helper::confirm`] — because macFUSE's helper does not reach
//!    its `mount(2)` until the filesystem has answered `FUSE_INIT` and the
//!    kernel's opening `statfs`. Its exit status is the verdict.
//!
//! Step 4 is the ordering that makes `dctl mount` able to print "mounted" and
//! mean it, and it is also why the steps cannot be rearranged into something
//! tidier: waiting for the helper before serving the session deadlocks, and
//! reporting success when the descriptor arrives reports a mount that has not
//! happened yet.
//!
//! ## No `unsafe`, and no weakening of the rule
//!
//! `#![forbid(unsafe_code)]` holds unchanged, and two of the choices here are it
//! deciding rather than taste. The socket pair and the control message are
//! `rustix`, whose ancillary API hands a received descriptor back **owned** —
//! `nix` gives a bare integer that only `OwnedFd::from_raw_fd` can make own
//! anything, and that is `unsafe`. The descriptor reaches the child through
//! `Stdio::from(OwnedFd)`, which is safe stable `std`, and that is why the socket
//! sits on descriptor **zero** rather than the conventional three: putting one
//! anywhere else in a child needs `pre_exec`, which is also `unsafe`. macFUSE
//! reads the number out of the environment, so zero is as good as three. The
//! unmount is `nix`, because `rustix`'s mount module is Linux-only.
//!
//! ## What is compiled where
//!
//! [`options`] is compiled on **every** platform: it is a decision about strings,
//! and it is the decision that has to be right, because macFUSE accepts an option
//! it does not understand and does nothing with it. The Linux gates therefore
//! compile, lint and test the whole translation table. [`helper`]'s invocation is
//! the same — argv and environment as data — and only the spawn, the socket, the
//! unmount and the sequence that drives them are macOS-only.

// `allow(dead_code)` off macOS, deliberately: the translation is compiled and
// tested on every platform because the gates run on Linux and this table is the
// thing that must be right, but nothing outside macOS calls it in production.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub mod options;

#[cfg(target_os = "macos")]
pub mod detach;
#[cfg(target_os = "macos")]
pub mod handover;
/// The mount helper. Its invocation — argv and environment — is compiled
/// everywhere for the same reason [`options`] is; only running it needs macOS,
/// and only off macOS is the invocation dead but for its tests.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub mod helper;

/// The mount itself: the four steps above, in the order macFUSE requires.
#[cfg(target_os = "macos")]
pub mod attach;

// The function, so callers write `macfuse::attach(…)`. `Attached` is reachable
// as `macfuse::attach::Attached` and is never named: `session` destructures it.
#[cfg(target_os = "macos")]
pub use attach::attach;
