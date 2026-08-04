//! Detaching a macFUSE mount, and why it is `unmount(2)` and nothing else.
//!
//! ## There is no helper for this half
//!
//! Attaching needs macFUSE's setuid program because `mount(2)` is root-only.
//! **Detaching does not**: macOS lets the user who made a mount take it down, so
//! `unmount(2)` is a direct call and `nix` wraps it without this crate needing
//! `unsafe`. That is also what macFUSE's own libfuse does, and what rclone does
//! through it — there is no `umount_macfuse` to defer to and none is wanted.
//!
//! ## `MNT_FORCE` is not used, and that is a decision
//!
//! `unmount(2)` answers `EBUSY` when something still has a file open on the
//! mount. The forcing flag would take it down anyway, and every open descriptor
//! on it would start failing. This module does not use it. A read-only vault
//! mount has no dirty state to lose, but the *reader* does: a program halfway
//! through a fifty-gigabyte file would get an I/O error it had no reason to
//! expect, on a mount somebody else asked to close. So a busy mountpoint is
//! reported as busy, [`session`](crate::mount::session) declines to call it
//! unmounted, and the operator decides.
//!
//! ## Success here is still not proof
//!
//! `unmount(2)` returning `Ok` means the kernel accepted the request. Commit
//! `cc05f90` — "earn the word unmounted instead of assuming it" — is the rule
//! that such an answer is not evidence, and it holds on macOS for the same reason
//! it holds on Linux. [`detached`](crate::mount::detached) is what actually
//! decides, by looking at the device the mountpoint reports; this module's job
//! ends at asking.
//!
//! ## What a mount left attached costs on this platform
//!
//! More than on Linux, which is why every path out of a mount detaches. Measured
//! here: killing a server while its filesystem was attached left the mountpoint
//! in a state where a *fresh* mount attempt on the same path hung in the kernel
//! and could not be recovered — no entry in `mount(8)` to unmount, and
//! `vfs.generic.macfuse.resourceusage.mounts` still counting instances that no
//! longer had a process. That directory is unusable until the machine reboots.

use std::io;
use std::path::{Path, PathBuf};

use nix::mount::{MntFlags, unmount};

use crate::mount::session::Detacher;

/// Detaches a macFUSE mount from the path it is attached to.
///
/// Holds the mountpoint rather than a session handle, because on macOS the
/// filesystem is attached to a *path* and that is the only thing `unmount(2)`
/// takes. `fuser`'s own unmounter cannot serve here: a session built with
/// [`fuser::Session::from_fd`] never learned a mountpoint — it was handed a
/// descriptor that was already mounted — so its `unmount` has nothing to do and
/// returns success without detaching anything. Using it would be exactly the
/// false success `cc05f90` was written against.
#[derive(Debug, Clone)]
pub struct Unmount {
    mountpoint: PathBuf,
}

impl Unmount {
    /// Detach whatever is attached at `mountpoint`.
    #[must_use]
    pub fn at(mountpoint: &Path) -> Self {
        Self {
            mountpoint: mountpoint.to_path_buf(),
        }
    }
}

impl Detacher for Unmount {
    /// Ask the kernel to detach the filesystem.
    ///
    /// # Errors
    /// `EBUSY` where a process still holds a file open on the mount, `EINVAL`
    /// where nothing is attached at the path — which is what a caller sees when
    /// the detach has already happened, and is why
    /// [`session`](crate::mount::session) treats the *mountpoint's* device rather
    /// than this result as the answer.
    fn unmount(&mut self) -> io::Result<()> {
        // No `MNT_FORCE`: see the module docs. A busy mount is reported as busy
        // rather than taken down under a reader who did not ask for it.
        unmount(self.mountpoint.as_path(), MntFlags::empty())
            .map_err(|error| io::Error::from_raw_os_error(error as i32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MOUNT_ENOTCONN;

    #[test]
    fn detaching_a_path_that_carries_no_filesystem_fails_rather_than_pretending() {
        // The property that matters: this is a real syscall with a real answer,
        // not a call that returns `Ok` because there was nothing to do. A
        // detacher that succeeded on an ordinary directory would report every
        // failed unmount as a success.
        let directory = tempfile::tempdir().expect("a temporary directory");
        let error = Unmount::at(directory.path())
            .unmount()
            .expect_err("an ordinary directory is not a mount");
        assert!(
            error.raw_os_error().is_some(),
            "the errno has to survive so callers can tell the cases apart: {error}"
        );
        // And specifically not the one errno that means a mount is still there
        // with nothing serving it — that answer must only ever come from a real
        // stale mount.
        assert_ne!(error.raw_os_error(), Some(MOUNT_ENOTCONN));
    }

    #[test]
    fn the_detacher_remembers_the_path_it_was_built_for() {
        // A session made from a descriptor never learned a mountpoint, so this
        // is the only place that knows which path to detach. Cloning must not
        // lose it: `session::Mounted` boxes the detacher and drops it on paths
        // that must still take the mount down.
        let directory = tempfile::tempdir().expect("a temporary directory");
        let detacher = Unmount::at(directory.path());
        assert_eq!(detacher.clone().mountpoint, directory.path());
    }
}
