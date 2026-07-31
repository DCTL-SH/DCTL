//! How much room is left at the far end, asked when a write is refused without
//! a reason.
//!
//! ## Why a probe, and not a status code
//!
//! [`super::status`] carries the measurement: OpenSSH answers `ENOSPC` with
//! `SSH_FX_FAILURE` and the literal word `Failure`, exactly as it answers a
//! non-empty `rmdir`. Version 3's status packet has no field for an errno, so
//! **there is nothing in the reply to read**. A full disk can only be
//! established by asking a second question.
//!
//! ## Why `df` and not `statvfs@openssh.com`
//!
//! The protocol's own answer is the extended request `statvfs@openssh.com`,
//! which this server advertises. It is not reachable: `openssh-sftp-client`
//! exposes extended requests for `limits`, `fsync`, `hardlink`, `posix-rename`,
//! `expand-path` and `copy-data` and for nothing else, the request enum is
//! `#[non_exhaustive]` in a crate this workspace does not own, and the channel
//! is owned by the client library, so there is no seam to send a raw packet
//! through. Forking a dependency to add one is a larger and worse change than
//! the fallback.
//!
//! The fallback is rclone's own, for exactly this question: `About` prefers
//! `statvfs@openssh.com` and otherwise runs a shell command over the same
//! session (`backend/sftp/sftp.go:1880` for the extension,
//! `:1910-1955` for the shell). DCTL has the same `openssh::Session` in hand —
//! it is held open beside the SFTP channel for the lifetime of the conversation
//! — so the probe costs no new connection.
//!
//! ## What it is allowed to conclude
//!
//! Three answers, and the third is not a failure of this module:
//!
//! * [`FreeSpace::Exhausted`] — the filesystem has no usable room. This is the
//!   only answer that may name a full disk, and it is evidence rather than
//!   inference.
//! * [`FreeSpace::Available`] — there **is** room, so the refusal was something
//!   else. Worth as much as the first answer and more often actionable: it is
//!   what tells an operator to look at a quota, a read-only mount or an ACL
//!   rather than at `df`.
//! * [`FreeSpace::Unknown`] — the question could not be asked or the answer
//!   could not be read. An SFTP-only account has no shell and this is the
//!   ordinary case for one; a conversation running over a plain byte-stream pair
//!   has no session at all. Saying so is the honest sentence `HANDOVER.md`
//!   §11.3 item 6 asks for, and it is still strictly better than `Failure`.
//!
//! The probe runs **only on the failure path**, so a healthy transfer pays
//! nothing for it.

use std::io;

use openssh::Session;

use crate::error::StoreError;

use super::dial::Link;

/// Below this many bytes free, the filesystem is treated as having no usable
/// room left.
///
/// Not zero. A filesystem allocates in blocks — 4 KiB on ext4 and xfs at their
/// usual settings — so a write can be refused while `df` still reports a few
/// hundred bytes free, and several filesystems keep a small reserve that
/// ordinary writes cannot touch. One block is the smallest figure that does not
/// turn a genuinely full disk into "space was available", which is the answer
/// that would send an operator to the wrong place.
const FULL_WITHIN_BYTES: u64 = 4096;

/// The command the probe runs, and why these flags.
///
/// `-P` is POSIX output: one line per filesystem with a fixed six-column layout,
/// which is what makes the answer parseable rather than a guess about the
/// server's `df`. Without it a long device name wraps onto a second line and the
/// columns move. `-k` fixes the unit at 1024-byte blocks, so the arithmetic does
/// not depend on the server's `BLOCKSIZE` environment.
const DF_PROGRAM: &str = "df";
/// See [`DF_PROGRAM`].
const DF_FLAGS: &str = "-Pk";

/// What the far end said about the room left where DCTL is writing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum FreeSpace {
    /// No usable room. The only answer permitted to name a full disk.
    Exhausted {
        /// What `df` reported, carried so the message can quote it rather than
        /// assert it.
        free_bytes: u64,
    },
    /// There is room, so a refused write was refused for some other reason.
    Available {
        /// What `df` reported.
        free_bytes: u64,
    },
    /// The question could not be asked, or its answer could not be read.
    ///
    /// Carries the reason, because an operator told that DCTL could not find out
    /// is owed what stopped it — an account with no shell is a different next
    /// action from a `df` that is not on the path.
    Unknown(String),
}

/// Whether this much free space counts as none.
///
/// Split from [`probe`] so the threshold's behaviour is reachable without a
/// server. Written as a comparison against a constant it would be a test of two
/// literals — which is the kind of test that can only ever pass, and this
/// project has a standing count of instruments that could not fail.
const fn classify_free(free_bytes: u64) -> FreeSpace {
    if free_bytes <= FULL_WITHIN_BYTES {
        FreeSpace::Exhausted { free_bytes }
    } else {
        FreeSpace::Available { free_bytes }
    }
}

/// Read the `Available` column out of POSIX `df` output.
///
/// Split out from the request so the parsing is testable without a server, which
/// is where every mistake in this module would otherwise hide.
fn parse_df(stdout: &str) -> Option<u64> {
    // Line 0 is the header. The first line after it that has the full six
    // columns is the filesystem the path is on.
    stdout
        .lines()
        .skip(1)
        .find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // Filesystem, 1024-blocks, Used, Available, Capacity, Mounted-on.
            // A mount point containing spaces makes the last field longer, never
            // shorter, so `>=` rather than `==`.
            (fields.len() >= 6).then(|| fields[3].parse::<u64>().ok())?
        })
        .map(|blocks| blocks.saturating_mul(1024))
}

/// Ask the far end how much room is left on the filesystem holding `dir`.
pub(super) async fn probe(session: &Session, dir: &str) -> FreeSpace {
    let output = session
        .command(DF_PROGRAM)
        .arg(DF_FLAGS)
        .arg(dir)
        .output()
        .await;
    let output = match output {
        Ok(output) => output,
        // The commonest real case, and not an error in DCTL: an account
        // restricted to the SFTP subsystem cannot run a command at all.
        Err(e) => {
            return FreeSpace::Unknown(format!(
                "the server would not run '{DF_PROGRAM}' ({e}) — an account \
                 restricted to the sftp subsystem cannot"
            ));
        }
    };
    if !output.status.success() {
        return FreeSpace::Unknown(format!(
            "'{DF_PROGRAM} {DF_FLAGS}' on the server exited {}",
            output
                .status
                .code()
                .map_or_else(|| "on a signal".to_string(), |code| code.to_string())
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    match parse_df(&stdout) {
        Some(free_bytes) => classify_free(free_bytes),
        None => FreeSpace::Unknown(format!(
            "'{DF_PROGRAM} {DF_FLAGS}' answered in a layout this build could not read"
        )),
    }
}

/// The directory whose filesystem a write to `remote` lands on.
///
/// The *parent*, because the object being written may no longer exist by the
/// time this runs — a refused write has its staging file removed, which is the
/// write path's own guarantee — and `df` on a path that is not there answers
/// nothing.
fn parent_dir(remote: &str) -> &str {
    match remote.rfind('/') {
        // A path directly under the root: the filesystem to ask about is `/`.
        Some(0) => "/",
        Some(cut) => &remote[..cut],
        // A relative single-segment path resolves against the login directory.
        None => ".",
    }
}

/// Turn a reasonless refusal into a diagnosis, where the far end will supply one.
///
/// Anything that is not [`StoreError::Refused`] is returned untouched: a denial
/// and a missing file are already diagnosed by [`super::status::classify`], and
/// re-examining them would cost a round trip to learn nothing. That early return
/// is also what keeps a healthy transfer free of this module entirely.
pub(super) async fn diagnose(link: &Link, remote: &str, error: StoreError) -> StoreError {
    let StoreError::Refused {
        backend,
        path,
        detail,
    } = error
    else {
        return error;
    };
    let dir = parent_dir(remote);
    let Some(session) = link.session() else {
        // A conversation over a plain byte-stream pair has no ssh session, so
        // there is nothing to ask. Said rather than silently skipped.
        return StoreError::Refused {
            backend,
            path,
            detail: format!("{detail}; there is no ssh session here to ask for free space"),
        };
    };

    match probe(session, dir).await {
        // The one answer that may name the disk, and it is `local:`'s own
        // error kind — so it reaches `durable::is_out_of_space`, exits where a
        // full local disk exits, and is never retried.
        FreeSpace::Exhausted { free_bytes } => StoreError::Io(io::Error::new(
            io::ErrorKind::StorageFull,
            format!(
                "sftp: no space left on the device holding '{dir}' — the server refused the \
                 write to '{path}' and df reports {free_bytes} bytes free"
            ),
        )),
        // Still a refusal, and now with the one fact that rules out the
        // commonest cause. This is the answer that points at a quota or a
        // read-only mount.
        FreeSpace::Available { free_bytes } => StoreError::Refused {
            backend,
            path,
            detail: format!(
                "{detail}; the filesystem holding '{dir}' has {free_bytes} bytes free, so it is \
                 not out of space — a quota, a read-only mount or a permission on the directory \
                 would each produce this"
            ),
        },
        FreeSpace::Unknown(why) => StoreError::Refused {
            backend,
            path,
            detail: format!("{detail}; free space could not be checked either: {why}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_available_column_is_read_from_posix_df_output() {
        // Real output, from the server this was measured on.
        let full = "Filesystem     1024-blocks  Used Available Capacity Mounted on\n\
                    tmpfs                 2048  2048         0     100% /mnt/fullfs\n";
        assert_eq!(parse_df(full), Some(0));

        let roomy = "Filesystem     1024-blocks    Used Available Capacity Mounted on\n\
                     /dev/sda1         41922560 8388608  33533952      20% /\n";
        assert_eq!(parse_df(roomy), Some(33_533_952 * 1024));
    }

    #[test]
    fn a_mount_point_containing_spaces_does_not_shift_the_column() {
        // The last field is the only one that can contain spaces, so a `==` on
        // the field count would drop exactly the rows a NAS produces.
        let spaced = "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                      //nas/share 1000 900 100 90% /mnt/my backup share\n";
        assert_eq!(parse_df(spaced), Some(100 * 1024));
    }

    #[test]
    fn a_line_that_is_not_the_layout_that_was_asked_for_is_not_read_as_one() {
        // `df -P` is specified to print six columns, and the field count is the
        // only thing that says a line *is* one of them. Relaxing it left the
        // whole gate green (`HANDOVER.md` §35.5), because every case above has
        // six fields and every case below has one.
        //
        // The line that makes the difference is a **wrapped device name**: GNU
        // `df` puts a long `/dev/mapper/...` on a line of its own and the six
        // numbers on the next, so the continuation has five fields and its
        // fourth is `Use%` rather than `Available`. Reading it would report a
        // percentage as a byte count.
        let wrapped = "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                       /dev/mapper/vg--very--long--name-lv--also--long\n\
                       41922560 8388608 33533952 20% /\n";
        assert_eq!(
            parse_df(wrapped),
            None,
            "a wrapped line is not the row that was asked for, and \
             `Unknown` is the honest answer to a layout this build cannot read"
        );

        // And the four-column shape a `df --output=` would produce: numeric in
        // the fourth field, so nothing downstream could tell it was wrong.
        let narrowed = "Filesystem 1024-blocks Used Available\n\
                        /dev/sda1 41922560 8388608 33533952\n";
        assert_eq!(parse_df(narrowed), None);
    }

    #[test]
    fn output_this_build_cannot_read_is_unknown_rather_than_zero() {
        // The failure that would matter: a layout that parsed as 0 free would
        // report a full disk on a healthy server, which is a false diagnosis in
        // the loud direction.
        assert_eq!(parse_df(""), None);
        assert_eq!(parse_df("df: /nope: No such file or directory\n"), None);
        assert_eq!(parse_df("Filesystem 1024-blocks Used Available\n"), None);
    }

    #[test]
    fn the_filesystem_asked_about_is_the_one_the_object_is_written_to() {
        // The parent, not the object: a refused write has already had its
        // staging file removed, and `df` on a path that is gone answers nothing.
        assert_eq!(parent_dir("/srv/store/o/thing.bin"), "/srv/store/o");
        assert_eq!(parent_dir("/thing.bin"), "/");
        assert_eq!(parent_dir("thing.bin"), ".");
    }

    #[test]
    fn a_filesystem_with_less_than_a_block_to_spare_is_still_treated_as_full() {
        // Block rounding and reserved space mean a write is refused before `df`
        // reaches literal zero, so a strict `== 0` would report "space was
        // available" about a disk that is full -- the answer that sends an
        // operator to the quota instead of to `df`.
        for free in [0, 1, FULL_WITHIN_BYTES - 1, FULL_WITHIN_BYTES] {
            assert_eq!(
                classify_free(free),
                FreeSpace::Exhausted { free_bytes: free },
                "{free} bytes free is not enough to write into"
            );
        }
    }

    #[test]
    fn a_filesystem_with_room_is_not_reported_as_full() {
        // The other direction, and the one that would be a false diagnosis in
        // the loud direction: naming a full disk on a healthy server.
        for free in [FULL_WITHIN_BYTES + 1, 1 << 30] {
            assert_eq!(
                classify_free(free),
                FreeSpace::Available { free_bytes: free },
                "{free} bytes free is room"
            );
        }
    }
}
