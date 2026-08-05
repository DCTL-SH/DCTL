//! Proving the filesystem is really gone, rather than assuming the request took.
//!
//! [`session`](super::session) exists so that no path out of a mount leaves one
//! attached, and it enforced that by calling `unmount` on every branch. What it
//! did not do was **check**, and the difference is not academic: `fuser`'s
//! `SessionUnmounter::unmount` answers "the detach was requested", not "the
//! filesystem is detached". On the `auto_unmount` path it is literally a socket
//! close —
//!
//! ```text
//! if let Some(sock) = mem::take(&mut self.auto_unmount_socket) {
//!     drop(sock);
//!     // fusermount in auto-unmount mode, no more work to do.
//!     return Ok(());
//! }
//! ```
//!
//! — which hands the work to a `fusermount3` child and returns success before
//! that child has done any of it. Measured on Linux 6.12: `SIGTERM` to a mount
//! started with `--allow-other` or `--allow-root` left the mountpoint attached
//! and dead, and the command reported `unmounted '<path>' on request` and exited
//! 25 anyway. An operator reading that walks away from a directory on which every
//! subsequent access fails. That is [the plan](https://doc.dctl.sh/project/plan)
//! §6's misreport, and this module is the check that ends it.
//!
//! ## Why the device number, and not an errno
//!
//! The obvious signal is `ENOTCONN`: a FUSE mount whose server has gone is still
//! a mount, and the kernel answers every request on it with that. It is also, on
//! its own, **not enough** — and the first version of this module shipped with
//! exactly that hole. `ENOTCONN` appears only once the connection is torn down,
//! which for the failure above happens when the process *exits*. Asked from
//! inside the process, a mount that is about to be abandoned answers `stat`
//! perfectly normally, and an errno check reads it as detached: the false success
//! survives, now with a test in front of it.
//!
//! What distinguishes an attached mountpoint from a free one at any moment,
//! living or dead, is the **device it reports**. A mounted filesystem answers
//! with its own `st_dev`; the moment it is detached the directory answers with
//! the device of the filesystem it lives on again. So the mountpoint's device is
//! recorded *before* the mount is attached, and the mount is detached when — and
//! only when — the path answers with that number once more.
//!
//! Recorded rather than inferred from the parent directory, which is how
//! `mountpoint(1)` does it: comparing against the parent would call a mountpoint
//! "still attached" whenever it is legitimately the root of some *other*
//! filesystem, which is a mount inside a mount and a thing people really do.
//! Comparing against what this process saw before it mounted has no such case.
//!
//! Every other outcome means the mountpoint is not this process's problem, and is
//! deliberately treated as detached: a path that now returns `ENOENT` was
//! removed, which is nobody's stale mount, and a permission error is a statement
//! about the caller rather than about the filesystem.

use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::constants::MOUNT_ENOTCONN;

/// The device number `path` currently sits on.
///
/// A metadata read rather than an open: it is the cheapest call that answers the
/// question, it neither creates nor holds anything, and it is the same call that
/// returns `ENOTCONN` on an abandoned mount.
pub fn device_of(path: &Path) -> io::Result<u64> {
    std::fs::metadata(path).map(|metadata| metadata.dev())
}

/// Whether the mountpoint has come free, given what it looked like before.
///
/// `bare` is the device the mountpoint reported before anything was attached to
/// it, and `now` is what it reports currently. Split from the syscalls so the
/// decision is testable without a mount: the thing that must not be got wrong is
/// which observation means "still attached", and that is a judgement about two
/// values rather than about I/O.
///
/// A `bare` of [`None`] means the device was never learned — the mountpoint could
/// not be read before mounting. The comparison is then impossible and only
/// `ENOTCONN` can prove anything, which is deliberately the *permissive*
/// direction: inventing a stale mount from a missing measurement would send an
/// operator chasing a filesystem that was never there.
#[must_use]
pub fn detached(bare: Option<u64>, now: &io::Result<u64>) -> bool {
    match now {
        // A mounted filesystem answers with its own device; the bare directory
        // answers with the one it lives on.
        Ok(device) => bare.is_none_or(|bare| bare == *device),
        // Attached, with nothing serving it — the stale mount itself.
        Err(error) if error.raw_os_error() == Some(MOUNT_ENOTCONN) => false,
        // Removed, or not ours to stat. Neither is a mount this process left.
        Err(_) => true,
    }
}

/// Whether `mountpoint` is free of this process's filesystem, right now.
#[must_use]
pub fn is_detached(mountpoint: &Path, bare: Option<u64>) -> bool {
    detached(bare, &device_of(mountpoint))
}

/// Whether `mountinfo` still lists ANY attachment of the filesystem whose
/// device is `mount_device`.
///
/// The path check above asks about one path, and one path is not the whole
/// question: where a directory is visible at two places — bind mounts under
/// shared propagation, which is the ordinary layout of a machine with an
/// aliased data volume — attaching a filesystem at one attaches it at both,
/// and `umount` of one leaves the other. Measured on such a host: DCTL
/// reported `unmounted`, latched, and left a live attachment behind at the
/// alias, which is exactly the stale mount this module exists to prevent,
/// reached by the one route the device comparison cannot see.
///
/// Pure, over the text, so the parse is testable without a bind mount. Each
/// `/proc/self/mountinfo` line's third field is the mount's device as
/// `major:minor` (proc(5)); this formats the recorded `st_dev` the same way
/// and looks for it. A `None` device is permissive — the same direction the
/// `bare: None` case takes, and for the same reason: a measurement that was
/// never taken must not invent a stale mount.
#[must_use]
pub fn attached_anywhere(mountinfo: &str, mount_device: Option<u64>) -> bool {
    let Some(device) = mount_device else {
        return false;
    };
    // The Linux dev_t encoding proc(5) prints: 12 low bits and 20 high bits of
    // major, 8 low and 12 high of minor.
    let major = ((device >> 8) & 0xfff) | ((device >> 32) & !0xfff);
    let minor = (device & 0xff) | ((device >> 12) & !0xff);
    let wanted = format!("{major}:{minor}");
    mountinfo
        .lines()
        .filter_map(|line| line.split_whitespace().nth(2))
        .any(|field| field == wanted)
}

/// Whether the kernel still lists any attachment of this filesystem.
///
/// The real reader behind [`attached_anywhere`]. An unreadable mountinfo is
/// permissive for the reason the parser's `None` case is: this check exists to
/// catch an attachment the path comparison missed, never to manufacture one.
#[must_use]
pub fn any_attachment(mount_device: Option<u64>) -> bool {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/self/mountinfo")
            .map(|mountinfo| attached_anywhere(&mountinfo, mount_device))
            .unwrap_or(false)
    }
    // No mountinfo, and no bind-mount aliasing of this shape to find with it:
    // macOS mounts are not propagated between namespaces the way Linux's are,
    // so the path comparison is the whole question there.
    #[cfg(not(target_os = "linux"))]
    {
        let _ = mount_device;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two device numbers that are certainly not each other.
    const BARE: u64 = 64_772;
    const MOUNTED: u64 = 75;

    #[test]
    fn a_mountpoint_back_on_its_original_device_is_detached() {
        // The ordinary case: the unmount took, and the directory is a directory
        // on its own filesystem again.
        assert!(detached(Some(BARE), &Ok(BARE)));
    }

    #[test]
    fn a_mountpoint_still_reporting_the_filesystems_device_is_still_attached() {
        // The case an errno check cannot see, and the reason this module compares
        // devices at all: asked while the mount is still being served, `stat`
        // succeeds and tells the truth only through the device number.
        assert!(!detached(Some(BARE), &Ok(MOUNTED)));
    }

    #[test]
    fn enotconn_is_still_attached_even_though_the_device_is_unreadable() {
        // The stale mount in its final state: the server is gone, the mount is
        // not, and there is no device to compare because every call fails.
        let abandoned = Err(io::Error::from_raw_os_error(MOUNT_ENOTCONN));
        assert!(!detached(Some(BARE), &abandoned));
    }

    #[test]
    fn a_mountpoint_that_no_longer_exists_is_not_a_stale_mount() {
        // Removed out from under us is somebody else's problem, and it is
        // certainly not a mountpoint this process left attached.
        let gone = Err(io::Error::from(io::ErrorKind::NotFound));
        assert!(detached(Some(BARE), &gone));
    }

    #[test]
    fn a_permission_error_describes_the_caller_and_not_the_filesystem() {
        // Refusing to call the mount detached because *we* may not stat it would
        // turn an unrelated failure into a false alarm about a stale mount.
        let denied = Err(io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(detached(Some(BARE), &denied));
    }

    #[test]
    fn an_error_with_no_errno_behind_it_is_not_read_as_a_stale_mount() {
        // `raw_os_error` is `None` for errors this crate constructed rather than
        // received from the kernel; guessing "still attached" from one would
        // invent a stale mount that nothing observed.
        let synthetic = Err(io::Error::other("not from a syscall"));
        assert!(detached(Some(BARE), &synthetic));
    }

    #[test]
    fn an_unmeasured_mountpoint_falls_back_to_the_errno_and_nothing_else() {
        // Without a baseline the device says nothing, so a readable mountpoint
        // has to be taken as detached — but a demonstrably abandoned one is still
        // caught.
        assert!(detached(None, &Ok(MOUNTED)));
        assert!(!detached(
            None,
            &Err(io::Error::from_raw_os_error(MOUNT_ENOTCONN))
        ));
    }

    #[test]
    fn a_real_directory_reads_its_device_and_matches_itself() {
        // The syscall half, against something that certainly is not a mount: the
        // device it reports now is the device to compare against later.
        let dir = tempfile::tempdir().unwrap();
        let bare = device_of(dir.path()).unwrap();
        assert!(is_detached(dir.path(), Some(bare)));
    }

    #[test]
    fn a_real_directory_is_not_detached_when_measured_against_another_device() {
        // The negative of the case above, so the comparison is shown to be doing
        // work rather than always answering yes.
        let dir = tempfile::tempdir().unwrap();
        let bare = device_of(dir.path()).unwrap();
        assert!(!is_detached(dir.path(), Some(bare.wrapping_add(1))));
    }

    /// The device a FUSE mount reported on the host where this was measured,
    /// and the `major:minor` proc(5) prints for it.
    const FUSE_DEVICE: u64 = 0x4b; // major 0, minor 75
    const FUSE_FIELD: &str = "0:75";

    /// One mountinfo line carrying `device` in its third field.
    fn line(id: u32, device: &str, at: &str) -> String {
        format!("{id} 25 {device} / {at} rw,nosuid,nodev,noexec,relatime shared:1 - fuse dctl rw")
    }

    #[test]
    fn a_filesystem_listed_at_two_paths_is_attached_at_both() {
        // The defect's arrangement: one filesystem, two attachments, because
        // the directory is visible at two paths.
        let mountinfo = format!(
            "{}\n{}\n",
            line(90, FUSE_FIELD, "/mnt/data/bench/mnt"),
            line(91, FUSE_FIELD, "/mnt/DATA001/bench/mnt")
        );
        assert!(attached_anywhere(&mountinfo, Some(FUSE_DEVICE)));

        // Unmounting ONE alias leaves the other — and this is the whole point:
        // the recorded path now stats free while the filesystem is still up.
        let after_one = format!("{}\n", line(91, FUSE_FIELD, "/mnt/DATA001/bench/mnt"));
        assert!(
            attached_anywhere(&after_one, Some(FUSE_DEVICE)),
            "the surviving alias is exactly the stale mount"
        );
    }

    #[test]
    fn a_filesystem_no_longer_listed_is_detached() {
        let mountinfo = format!("{}\n", line(25, "259:2", "/"));
        assert!(!attached_anywhere(&mountinfo, Some(FUSE_DEVICE)));
    }

    #[test]
    fn an_unmeasured_device_never_invents_an_attachment() {
        // Permissive, exactly as `detached`'s `bare: None` case is: this check
        // exists to catch an attachment the path comparison missed, never to
        // manufacture one out of a measurement nobody took.
        let mountinfo = format!("{}\n", line(90, FUSE_FIELD, "/mnt/data/bench/mnt"));
        assert!(!attached_anywhere(&mountinfo, None));
    }

    #[test]
    fn malformed_lines_are_passed_over_rather_than_matched() {
        let mountinfo = format!("\n90\n90 25\n{}\n", line(90, FUSE_FIELD, "/mnt/a"));
        assert!(attached_anywhere(&mountinfo, Some(FUSE_DEVICE)));
        assert!(!attached_anywhere("\n90\n90 25\n", Some(FUSE_DEVICE)));
    }

    #[test]
    fn a_large_device_number_encodes_the_way_proc_prints_it() {
        // proc(5)'s dev_t split is not a plain two-byte pair: major takes 12
        // low bits and 20 high, minor 8 low and 12 high. A device above the
        // 8-bit minor range is where a naive split silently stops matching.
        let device: u64 = (259 << 8) | 130; // major 259, minor 130
        let mountinfo = format!("{}\n", line(25, "259:130", "/data"));
        assert!(attached_anywhere(&mountinfo, Some(device)));
    }
}
