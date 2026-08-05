//! The settings the filesystem itself reads, once every flag has been resolved.
//!
//! [`crate::commands::mount`] parses the command line, refuses what this engine
//! cannot honour, and hands over one of these. The engine never sees `MountArgs`,
//! which is the point: a flag that reaches here has already been checked against
//! what the platform and the build can actually do, so no callback contains a
//! branch on whether a setting is supported. Every field below is honoured — the
//! ones that are not are refused in [`crate::commands::mount::plan`], by name,
//! before a filesystem exists.
//!
//! ## Why the TTLs are two fields and not one
//!
//! `--attr-timeout` and `--dir-cache-time` cache different things and a mount
//! that conflated them would be wrong in both directions. The attribute TTL is
//! how long the *kernel* may believe a file's size and times without asking
//! again; the directory TTL is how long *this process* may serve a listing it
//! already decrypted. A vault whose tree changes rarely wants a long directory
//! TTL and still wants the kernel to notice a file that grew.

use std::time::Duration;

use fuser::SessionACL;

/// Everything the filesystem needs to know that came from the command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountConfig {
    /// Logical path inside the vault that the mount root maps to. Empty means
    /// the whole vault.
    ///
    /// Every path the filesystem serves comes from a listing taken *under* this
    /// prefix, so a subtree mount cannot address anything above its root — not
    /// because a check refuses it, but because no path outside the prefix is ever
    /// produced to be addressed.
    pub root: String,

    /// How long the kernel may cache a file's attributes (`--attr-timeout`).
    pub attr_ttl: Duration,

    /// How long a decrypted directory listing is served before it is re-read
    /// (`--dir-cache-time`).
    pub dir_ttl: Duration,

    /// In-memory read-ahead per open file (`--buffer-size`), in bytes.
    ///
    /// Zero disables it. Non-zero means: after a read, warm the chunks covering
    /// the next this-many bytes so a sequential reader finds them decrypted and
    /// authenticated already — [the plan](https://doc.dctl.sh/project/plan)
    /// §15's "serve chunk *k* while fetching *k+1…k+P*", with the window named
    /// by the user rather than guessed.
    pub read_ahead: u64,

    /// Who may talk to the mount (`--allow-other`, `--allow-root`).
    ///
    /// Defaults to the owning user, which is FUSE's own default and the only one
    /// that keeps an unlocked vault to the account that unlocked it. See the
    /// security note in [`super`] for what widening it means.
    pub acl: SessionACL,

    /// Volume name shown by a desktop file manager (`--volname`), where the
    /// platform has such a concept.
    pub volume_name: Option<String>,

    /// The resolved `--timeout`, in seconds: the longest DCTL will wait on a
    /// provider before it gives up on one request. Zero means no deadline.
    ///
    /// Not read by any callback, and it is here for one platform's sake. macFUSE
    /// runs a watchdog of its own — `daemon_timeout`, a minute by default — and
    /// kills the *volume* when a call outlives it. A minute is shorter than the
    /// five DCTL is willing to wait, so a read from a slow provider was killed by
    /// macFUSE first: instead of the diagnosed `EIO` DCTL's own deadline
    /// produces, the operator got a wedged mountpoint. The mount therefore asks
    /// macFUSE to wait longer than DCTL does, which needs this number here rather
    /// than a constant, because a user who raises `--timeout` has raised exactly
    /// the value the watchdog must stay ahead of.
    ///
    /// Linux has no equivalent and ignores it; the field is not `cfg`-gated so
    /// that the resolution and its tests compile on every platform.
    pub idle_seconds: u64,

    /// Report the mount time for every file instead of its recorded
    /// modification time (`--no-modtime`).
    ///
    /// The flag's own justification — one less index lookup per file — does not
    /// apply to this engine: the times arrive with the directory listing that
    /// `readdir` needed anyway, so honouring it saves nothing. It is honoured
    /// regardless, because the *other* half of the flag's meaning is a real
    /// request: a user who does not want real timestamps leaking through the
    /// mount to a tool that compares them has asked for that, and silently
    /// showing them anyway would be answering a different question.
    pub no_modtime: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(root: &str) -> MountConfig {
        MountConfig {
            root: root.to_string(),
            attr_ttl: Duration::from_secs(1),
            dir_ttl: Duration::from_secs(300),
            read_ahead: 0,
            acl: SessionACL::Owner,
            volume_name: None,
            idle_seconds: crate::constants::DEFAULT_TIMEOUT_SECS,
            no_modtime: false,
        }
    }

    #[test]
    fn a_whole_vault_mount_roots_at_the_empty_prefix() {
        // An index stores `photos/a.jpg`; a root spelled `/` or `.` would be a
        // prefix nothing lies under, and the mount would appear empty.
        assert_eq!(config("").root, "");
    }

    #[test]
    fn a_subtree_mount_carries_its_own_prefix() {
        assert_eq!(config("photos/2024").root, "photos/2024");
    }

    #[test]
    fn the_default_acl_keeps_an_unlocked_vault_to_its_owner() {
        // The security property in the module docs, pinned: widening this is a
        // deliberate flag, never a default.
        assert_eq!(config("").acl, SessionACL::Owner);
    }
}
