//! What a walk does when it meets a fifo, a socket or a device node, and how it
//! says so.
//!
//! # The defect this exists to remove
//!
//! A tree holding `real.txt` and a named pipe copied as `Files: 1 / 1,
//! Errors: 0`, exit 0, with the pipe appearing **nowhere** in stdout, stderr or
//! the log, even at `-v`. The same was true of a unix socket, a character
//! device and a block device, and of `ls`, `lsl`, `tree` and `size` as well as
//! `copy`. An operator backing up `/srv` or `/var` — where sockets and device
//! nodes are ordinary — was told `Errors: 0` over a tree the run had not wholly
//! represented.
//!
//! *Skipping* them is right, and it is what rclone does: `Storable`
//! (`backend/local/local.go:1299`) matches
//! `os.ModeNamedPipe|os.ModeSocket|os.ModeDevice` and returns `false`. But the
//! very next line is `fs.Logf(o, "Can't transfer non file/directory")`
//! (`:1301`), emitted unless the operator asked for silence with
//! `skip_specials` (`:380`). rclone tells you. DCTL's own walk cited that line
//! as its authority for passing over them and omitted the half that speaks.
//!
//! As with [`crate::links`], the loss was never the skipping. It was the
//! silence. Everything here exists so that a walk which passes over a special
//! file says so, with a count that is always exact and a sample of names that is
//! bounded.
//!
//! # Why these are not links, and are reported separately
//!
//! A link is a *door*: it can lead to a whole tree, it has a policy
//! (`--links`), and following one changes what a backup contains. A fifo has no
//! bytes at all and no flag could make it storable — there is nothing to decide,
//! only something to disclose. Folding them into [`LinkReport`](crate::links::LinkReport)
//! would put "4 skipped links" on a run that met no links, which is a different
//! wrong answer to the same question.
//!
//! The asymmetry inside DCTL made the gap plainer still, and it is now gone: a
//! symlink *pointing at* a fifo was reported (`LinkVerdict::NotStorable`) while
//! the fifo itself was invisible.
//!
//! # Why one rule, keyed on the POSIX mode
//!
//! Four walks meet special files — the `local:` backend's, the `sftp:`
//! backend's, the transfer family's local walk and `backup`'s scan — and three
//! walks with three copies of a rule is how `local:`, `sftp:` and `backup` came
//! to disagree about what a symbolic link means. So the classification is one
//! pure function over the file-type bits of a POSIX mode, which both the local
//! filesystem and SFTP hand over directly, and which is exhaustively testable
//! without arranging a device node — a thing an unprivileged test cannot create
//! at all.

mod report;

pub use report::{SPECIAL_NOTE_SAMPLE, SpecialNote, SpecialReport};

use std::fmt;

/// The bits of a POSIX mode that name a file's *type*, as opposed to its
/// permissions — `S_IFMT`.
///
/// Spelled here rather than taken from `libc` because this crate links none:
/// it is `#![forbid(unsafe_code)]` and the value is fixed by POSIX, carried in
/// the SFTP protocol's own `FileType` discriminants
/// (`openssh-sftp-protocol`'s `Socket = 0o140000`, `FIFO = 0o10000`, …) and
/// stable on every platform DCTL reaches.
pub const POSIX_TYPE_MASK: u32 = 0o170_000;

/// A file that is neither a regular file, a directory nor a symbolic link.
///
/// The *kind* rather than a bare "special", because the four are four different
/// things for an operator to think about: a socket in `/var/run` is expected and
/// harmless, a device node under a backup root usually means the root is wrong,
/// and a fifo is the one that will block a naive reader forever.
///
/// Serialised as its [`slug`](SpecialKind::slug) — the same word `-v` prints and
/// the same word a script greps — so the human and machine renderings of a run
/// cannot come to disagree about what was passed over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SpecialKind {
    /// A named pipe. Opening one for reading blocks until a writer appears,
    /// which is how a backup of `/var` used to stop responding rather than fail.
    Fifo,
    /// A unix domain socket. Ordinary in `/run` and `/var/run`.
    Socket,
    /// A character device — `/dev/null`, a tty, `/dev/random`.
    CharDevice,
    /// A block device — a disk or a partition.
    BlockDevice,
    /// The filesystem would not say what it is.
    ///
    /// Reached when a `stat` fails between the directory read and the
    /// classification, and when an SFTP server sends a directory entry with no
    /// permissions attribute (the field the type lives in is optional in
    /// version 3 of the protocol). A variant rather than a guess, because
    /// "we could not tell" and "it is a socket" are different facts and a report
    /// that conflated them would name a type nothing observed.
    Unknown,
}

impl SpecialKind {
    /// Classify from the file-type bits of a POSIX mode.
    ///
    /// [`None`] for the three types that are **not** special — a regular file, a
    /// directory and a symbolic link — so a caller that arrived here by mistake
    /// gets a refusal rather than a plausible answer. Every walk reaches this
    /// only after excluding those three, so a `None` means the entry changed
    /// underneath the walk between its directory read and its `stat`; the walks
    /// record [`SpecialKind::Unknown`] for that, which is the honest description
    /// of an entry nothing can now name.
    ///
    /// `const` and total, so every arm is assertable without a filesystem —
    /// which matters more here than anywhere else in the crate, because a test
    /// process without `CAP_MKNOD` cannot create a device node to look at.
    #[must_use]
    pub const fn from_posix_mode(mode: u32) -> Option<Self> {
        match mode & POSIX_TYPE_MASK {
            0o010_000 => Some(Self::Fifo),
            0o140_000 => Some(Self::Socket),
            0o020_000 => Some(Self::CharDevice),
            0o060_000 => Some(Self::BlockDevice),
            // A regular file, a directory or a symbolic link: not this module's
            // business, and not something to invent a kind for.
            0o100_000 | 0o040_000 | 0o120_000 => None,
            // A type this build has no name for. Not `None`: something is there
            // and it is not one of the three storable shapes, so it is a thing
            // the run passed over and must disclose.
            _ => Some(Self::Unknown),
        }
    }

    /// A stable, lower-case word for the kind, for logs and `--format json`.
    ///
    /// Stable because scripts grep it: renaming one of these is a change to the
    /// tool's observable output, not a wording tweak.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Fifo => "fifo",
            Self::Socket => "socket",
            Self::CharDevice => "char-device",
            Self::BlockDevice => "block-device",
            Self::Unknown => "unknown",
        }
    }

    /// What to tell an operator, in the words they would use themselves.
    ///
    /// Phrased as a noun so it reads after a path — `pipe: a named pipe` — which
    /// is the same shape [`LinkVerdict::reason`](crate::links::LinkVerdict::reason)
    /// produces, so one `-v` line style covers both reports.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Fifo => "a named pipe",
            Self::Socket => "a unix socket",
            Self::CharDevice => "a character device",
            Self::BlockDevice => "a block device",
            Self::Unknown => "a file type this system would not name",
        }
    }
}

impl fmt::Display for SpecialKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every POSIX file type, by the mode bits POSIX fixes for it.
    const REGULAR: u32 = 0o100_000;
    const DIRECTORY: u32 = 0o040_000;
    const SYMLINK: u32 = 0o120_000;
    const FIFO: u32 = 0o010_000;
    const SOCKET: u32 = 0o140_000;
    const CHAR_DEVICE: u32 = 0o020_000;
    const BLOCK_DEVICE: u32 = 0o060_000;

    #[test]
    fn every_special_type_is_classified_by_its_own_name() {
        // The half a test process cannot arrange for itself: creating a device
        // node needs `CAP_MKNOD`, so the four kinds are pinned here and the two
        // an unprivileged test *can* create are pinned again against a real
        // filesystem in the walks.
        assert_eq!(SpecialKind::from_posix_mode(FIFO), Some(SpecialKind::Fifo));
        assert_eq!(
            SpecialKind::from_posix_mode(SOCKET),
            Some(SpecialKind::Socket)
        );
        assert_eq!(
            SpecialKind::from_posix_mode(CHAR_DEVICE),
            Some(SpecialKind::CharDevice)
        );
        assert_eq!(
            SpecialKind::from_posix_mode(BLOCK_DEVICE),
            Some(SpecialKind::BlockDevice)
        );
    }

    #[test]
    fn the_permission_bits_never_change_the_answer() {
        // `0o644` on a fifo and `0o777` on a fifo are one kind. A classifier
        // that tested the whole mode would call every differently-permissioned
        // socket a different thing.
        for permissions in [0o000, 0o644, 0o755, 0o777, 0o4755] {
            assert_eq!(
                SpecialKind::from_posix_mode(FIFO | permissions),
                Some(SpecialKind::Fifo),
                "{permissions:o}"
            );
        }
    }

    #[test]
    fn the_three_storable_shapes_are_refused_rather_than_named() {
        // A regular file arriving here means a walk mis-branched. Answering
        // "socket" would put a real file in a report of things passed over,
        // which is the same class of untruth as omitting a fifo.
        for mode in [REGULAR, DIRECTORY, SYMLINK] {
            assert_eq!(SpecialKind::from_posix_mode(mode), None, "{mode:o}");
        }
    }

    #[test]
    fn a_type_this_build_cannot_name_is_still_disclosed() {
        // The whole point of the module: something is there, it is not storable,
        // and the run may not stay quiet about it just because it has no word.
        assert_eq!(
            SpecialKind::from_posix_mode(0o030_000),
            Some(SpecialKind::Unknown)
        );
        assert_eq!(SpecialKind::from_posix_mode(0), Some(SpecialKind::Unknown));
    }

    #[test]
    fn every_kind_has_a_distinct_slug_and_a_reason() {
        let kinds = [
            SpecialKind::Fifo,
            SpecialKind::Socket,
            SpecialKind::CharDevice,
            SpecialKind::BlockDevice,
            SpecialKind::Unknown,
        ];
        for (index, kind) in kinds.iter().enumerate() {
            assert!(
                !kinds[index + 1..].iter().any(|o| o.slug() == kind.slug()),
                "'{}' twice",
                kind.slug()
            );
            assert!(!kind.reason().is_empty());
            assert_eq!(kind.to_string(), kind.slug());
        }
    }

    #[test]
    fn a_kind_serialises_as_the_word_it_prints() {
        // `dctl copy --format json` and `dctl copy -v` describe one run. Two
        // spellings of one kind is two answers to "what was that thing", and
        // the reader has no way to tell which is authoritative.
        for kind in [
            SpecialKind::Fifo,
            SpecialKind::Socket,
            SpecialKind::CharDevice,
            SpecialKind::BlockDevice,
            SpecialKind::Unknown,
        ] {
            let json = serde_json::to_string(&kind).expect("a kind serialises");
            assert_eq!(json, format!("\"{}\"", kind.slug()));
        }
    }

    #[test]
    fn the_mask_is_the_one_posix_fixes() {
        // Every discriminant above is a value under this mask, and the SFTP
        // protocol's own `FileType` uses the identical numbers. A mask that
        // drifted would silently reclassify every entry on both backends.
        for mode in [
            REGULAR,
            DIRECTORY,
            SYMLINK,
            FIFO,
            SOCKET,
            CHAR_DEVICE,
            BLOCK_DEVICE,
        ] {
            assert_eq!(mode & POSIX_TYPE_MASK, mode, "{mode:o}");
        }
    }
}
