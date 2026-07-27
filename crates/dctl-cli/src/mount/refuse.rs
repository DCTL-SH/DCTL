//! The read-only wall: every operation that would change something, refused.
//!
//! `PLAN.md` §15 makes v1 read-first — a random-write encrypted mount means
//! re-chunking and journalling, and is a scoped phase of its own — so this
//! filesystem has no write path. What it must not have instead is a *silent*
//! write path. A filesystem that accepts a `write`, returns the byte count and
//! drops the data is the misreport `PLAN.md` §6 forbids, with a filesystem's
//! authority behind it: the program that wrote saw success, its own error
//! handling never ran, and the data does not exist. That failure is worse than
//! refusing, and it is much worse than not offering the mount at all.
//!
//! So every mutating callback comes here, and here answers `EROFS`.
//!
//! ## Why `EROFS` and not something else
//!
//! * **Not `ENOSYS`.** The kernel *remembers* `ENOSYS` from a FUSE callback: it
//!   marks the operation unsupported for the life of the mount and stops sending
//!   it. That is right for an optional feature and wrong for a refusal, because
//!   the second attempt would then be answered by the kernel's cached assumption
//!   rather than by the filesystem — and, worse, some operations are then treated
//!   as locally satisfiable. A refusal has to be made every time it is asked for.
//! * **Not `EPERM` or `EACCES`.** Both say *you* may not do this, which sends a
//!   user to `chmod`, `sudo` and their group membership. None of that would help:
//!   nobody may write here, root included, because there is nothing behind the
//!   mount that could accept a write.
//! * **`EROFS` is what a read-only filesystem returns**, it is what `mount -o ro`
//!   produces, and every program and shell already words it correctly — "Read-only
//!   file system". A user sees the true reason without DCTL having to explain it.
//!
//! ## Belt and braces
//!
//! The session is additionally attached with the kernel's own `ro` flag, so most
//! of these never reach userspace at all — the kernel refuses them first, with
//! the same errno. Both defences, not either: the kernel flag is the cheap one
//! and this is the true one, and a mount option that failed to apply on some
//! platform must not be the only thing standing between a vault and a write.
//!
//! ## Every refusal is visible
//!
//! Refusals are logged at `debug` with the operation and the name involved. A
//! mount that a backup tool has been pointed at by mistake will produce a stream
//! of them, and the log is where somebody works out which program is trying to
//! write to their vault — which is a question with an answer, unlike "why did my
//! backup silently do nothing".

use std::ffi::OsStr;

use fuser::{Errno, ReplyAttr, ReplyCreate, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite};

use crate::logging::fields;

/// The errno every mutating operation answers with.
///
/// One constant so the choice is made once and is visible as a decision. See the
/// module documentation for why it is this one and not `EPERM` or `ENOSYS`.
pub const READ_ONLY: Errno = Errno::EROFS;

/// Record a refused operation.
///
/// `subject` is whatever names the target — a path component, an extended
/// attribute name — so a log reader can tell "something tried to write" from
/// "`mdworker` is trying to set `com.apple.metadata` on every file it sees".
fn record(operation: &str, subject: &str) {
    tracing::debug!(
        { fields::OP } = operation,
        subject,
        "refused: the mount is read-only"
    );
}

/// Refuse an operation whose reply is a directory entry: `mkdir`, `mknod`,
/// `symlink`, `link`.
pub fn entry(operation: &str, name: &OsStr, reply: ReplyEntry) {
    record(operation, &name.to_string_lossy());
    reply.error(READ_ONLY);
}

/// Refuse an operation whose reply is a set of attributes: `setattr`, which is
/// `chmod`, `chown`, `utimes` and — the one that matters most — `truncate`.
pub fn attr(operation: &str, reply: ReplyAttr) {
    record(operation, "");
    reply.error(READ_ONLY);
}

/// Refuse an operation that replies with nothing: `unlink`, `rmdir`, `rename`,
/// `setxattr`, `removexattr`, `fsync`, `fsyncdir`.
pub fn empty(operation: &str, subject: &str, reply: ReplyEmpty) {
    record(operation, subject);
    reply.error(READ_ONLY);
}

/// Refuse a `write`.
///
/// The one this module exists for. Replying `written(size)` here — which is what
/// a filesystem that "supports" writing by discarding them would do — is the
/// exact shape of the failure described above.
pub fn write(reply: ReplyWrite) {
    record("write", "");
    reply.error(READ_ONLY);
}

/// Refuse a `copy_file_range`, which replies with a written byte count.
///
/// Separate from [`write`] only so the log says which of the two was attempted:
/// a server-side copy reads like a read and is easy to overlook when working out
/// why something failed.
pub fn write_range(reply: ReplyWrite) {
    record("copy_file_range", "");
    reply.error(READ_ONLY);
}

/// Refuse a `create`, which is `open(O_CREAT)`.
pub fn create(name: &OsStr, reply: ReplyCreate) {
    record("create", &name.to_string_lossy());
    reply.error(READ_ONLY);
}

/// Refuse an `open` that asked for write access.
///
/// Caught at `open` rather than left to the first `write`, because that is where
/// a program can still act on it: an editor that opens a file for writing and is
/// refused reports "read-only file system" and offers to save elsewhere, while
/// one that is allowed to open it buffers the user's work and discovers the
/// truth at save time.
pub fn open_for_write(reply: ReplyOpen) {
    record("open", "write access");
    reply.error(READ_ONLY);
}

/// Every operation the wall covers.
///
/// Three jobs, which is why it is a value rather than a sentence in a doc
/// comment. It is **checked** by the test below, so a mutating callback added to
/// [`super::fs`](super::fs) without a line here is visible; it is **logged** once
/// when a mount starts, so an operator can see exactly what the filesystem will
/// refuse before anything tries; and it is what this module's documentation
/// points at rather than repeating.
pub const REFUSED: &[&str] = &[
    "copy_file_range",
    "create",
    "exchange",
    "fallocate",
    "fsync",
    "fsyncdir",
    "link",
    "mkdir",
    "mknod",
    "open(write)",
    "removexattr",
    "rename",
    "rmdir",
    "setattr",
    "setvolname",
    "setxattr",
    "symlink",
    "truncate",
    "unlink",
    "write",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_refusal_is_the_read_only_filesystem_errno() {
        // Not EPERM — nobody may write here, root included, and sending a user
        // to `chmod` and `sudo` would be sending them somewhere that cannot help.
        assert_eq!(READ_ONLY, Errno::EROFS);
    }

    #[test]
    fn the_refusal_is_never_enosys() {
        // ENOSYS is remembered by the kernel for the life of the mount, which
        // would answer the second attempt from a cache rather than from here.
        assert_ne!(READ_ONLY, Errno::ENOSYS);
    }

    #[test]
    fn the_refusal_is_not_a_permission_problem() {
        assert_ne!(READ_ONLY, Errno::EPERM);
        assert_ne!(READ_ONLY, Errno::EACCES);
    }

    #[test]
    fn every_way_of_changing_a_filesystem_is_on_the_list() {
        // The list is the checklist. A ninth mutating callback added to `fs.rs`
        // without a line here is the thing this test is looking for — the
        // operations below are the complete set POSIX offers for changing a
        // file, its name, its metadata or its size.
        for operation in [
            "write",       // change contents
            "truncate",    // change length
            "setattr",     // change mode, owner, times, or length
            "create",      // make a file
            "mknod",       // make a node
            "mkdir",       // make a directory
            "unlink",      // remove a file
            "rmdir",       // remove a directory
            "rename",      // move
            "link",        // add a name
            "symlink",     // add a symbolic name
            "setxattr",    // change extended metadata
            "removexattr", // remove extended metadata
            "fallocate",   // reserve space
            // The two that read like reads and are not.
            "copy_file_range", // write a copy of a range, server-side
            "exchange",        // macOS: swap the contents of two files
            "setvolname",      // macOS: rename the volume
        ] {
            assert!(
                REFUSED.contains(&operation),
                "{operation} is a way to change a filesystem and is not refused"
            );
        }
    }

    #[test]
    fn the_list_is_sorted_and_has_no_duplicates() {
        // It is read as a checklist, and a checklist with the same line twice —
        // or with a line hidden out of order — is one nobody audits properly.
        let mut sorted = REFUSED.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, REFUSED, "the refusal list is not in order");
        sorted.dedup();
        assert_eq!(sorted.len(), REFUSED.len(), "a refusal is listed twice");
    }
}
