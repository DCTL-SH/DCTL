//! Performing the mount: the four steps of [`super`]'s handshake, in order.
//!
//! Split from [`super`] so that each of the pieces it drives — the socket, the
//! helper, the translation, the detacher — is a module of its own and this file
//! contains only the sequence and what each failure means. The sequence is not
//! rearrangeable; the reasoning is in [`super`]'s docs and the short version is
//! that macFUSE's helper does not reach its `mount(2)` until the filesystem it is
//! mounting has already started answering.

use std::os::fd::OwnedFd;
use std::path::Path;

use fuser::Config;

use super::{detach, handover, helper, options};
use crate::constants::MOUNT_MACFUSE_HELPER_HINT;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

/// A mounted filesystem's kernel descriptor, and the helper that is still
/// waiting to report whether the mount took.
pub struct Attached {
    /// The `/dev/macfuseN` connection, for [`fuser::Session::from_fd`].
    pub device: OwnedFd,
    /// Ask this once the session is answering; see the module docs.
    pub helper: helper::Helper,
    /// Detaches the mount. Built here because the caller cannot: a session
    /// made from a descriptor never learned which path it is attached to.
    pub detacher: detach::Unmount,
}

/// Attach a macFUSE filesystem at `mountpoint`.
///
/// Returns as soon as the kernel descriptor is in hand — which is *before*
/// the mount is proven. The caller must serve the session and then call
/// [`helper::Helper::confirm`]; the ordering is macFUSE's, not a choice, and
/// the module docs say why.
///
/// # Errors
/// [`ExitCode::Usage`] where an option cannot be expressed to macFUSE at all,
/// which is a flag the user passed or a defect in the option set this build
/// assembles — either way something to fix rather than to warn about.
/// [`ExitCode::FatalError`] where macFUSE refused, quoting the helper's own
/// message: it names the actual objection, and a paraphrase would be this
/// module guessing at a cause it was told.
pub fn attach(mountpoint: &Path, config: &Config, idle_seconds: u64) -> Result<Attached> {
    let options = options::translate(&config.mount_options, config.acl, idle_seconds).map_err(
        |unmappable| {
            CliError::new(
                ExitCode::Usage,
                format!("cannot mount at '{}': {unmappable}", mountpoint.display()),
            )
            .with_hint(
                "macOS mounts through macFUSE, whose options are not Linux's. This \
                 one is refused rather than dropped because macFUSE accepts an \
                 option it does not understand and does nothing with it — the \
                 mount would come up looking correct and behave differently.",
            )
        },
    )?;

    let channel = handover::channel().map_err(|error| {
        CliError::new(
            ExitCode::FatalError,
            format!("cannot prepare the macFUSE handover: {error}"),
        )
    })?;

    let invocation = helper::invocation(mountpoint, &options, &helper::daemon_path());
    // The whole channel, not half of it: the helper writes back over this socket
    // once its `mount(2)` returns, so this process's end has to stay open until
    // the helper has exited. It used to be dropped here, at the end of this
    // function, and every mount survived only because the helper had inherited a
    // copy of it. See [`helper::Helper::start`].
    let helper = helper::Helper::start(&invocation, channel)
        .map_err(|error| helper_failed(mountpoint, &error))?;

    match handover::receive(helper.channel()).map_err(|error| {
        CliError::new(
            ExitCode::FatalError,
            format!(
                "cannot mount at '{}': the macFUSE device was not handed over: {error}",
                mountpoint.display()
            ),
        )
        .with_hint(MOUNT_MACFUSE_HELPER_HINT)
    })? {
        handover::Received::Device(device) => Ok(Attached {
            device,
            helper,
            detacher: detach::Unmount::at(mountpoint),
        }),
        // The helper checks its options and its mountpoint before it opens a
        // device, so this is the ordinary refusal path and its own message is
        // the useful one. `confirm` reads it back off the error pipe.
        handover::Received::HelperGaveUp => Err(match helper.confirm() {
            Err(error) => helper_failed(mountpoint, &error),
            // It closed the socket and still exited successfully, which no
            // observed macFUSE does. Reported as itself rather than as a
            // success, because a mount that never got a descriptor is not one.
            Ok(()) => CliError::new(
                ExitCode::FatalError,
                format!(
                    "cannot mount at '{}': macFUSE's mount helper exited without \
                     handing over a device",
                    mountpoint.display()
                ),
            )
            .with_hint(MOUNT_MACFUSE_HELPER_HINT),
        }),
    }
}

/// The refusal when macFUSE's helper would not mount.
///
/// Quotes the helper, then adds the one thing it cannot know: on macOS a
/// mountpoint left attached by a killed process stays attached, and checking
/// for that is what an operator should do first.
fn helper_failed(mountpoint: &Path, error: &std::io::Error) -> CliError {
    CliError::new(
        ExitCode::FatalError,
        format!("cannot mount at '{}': {error}", mountpoint.display()),
    )
    .with_hint(MOUNT_MACFUSE_HELPER_HINT)
}
