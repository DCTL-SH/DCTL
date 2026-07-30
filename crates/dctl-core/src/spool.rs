//! Where a sealed object is assembled before it is uploaded — and why the answer
//! is not "the system temp directory" without looking.
//!
//! ## One caller is left, and it is the one that cannot be helped
//!
//! Storing a *file* into a vault no longer comes through here at all:
//! [`Vault::put_file_from_path`](crate::Vault::put_file_from_path) seals straight into the backend in
//! bounded windows and writes nothing to local disk, measured at 0 MiB of scratch
//! against an object size of 4 GiB. What still spools is `dctl rcat` — standard
//! input — and the reason is not the backend but the **format**: an object's head
//! carries `plaintext_len` and `chunk_count`, and a multipart upload has to plan
//! its parts, so the exact length must be known before the first byte is sealed.
//! A pipe has no length and cannot be rewound to find one. Capturing it is the
//! only way to learn what it was, and that is a property of pipes rather than a
//! shortcut taken here.
//!
//! So this module is smaller than it was and everything below still holds for the
//! one caller that remains — because for that caller the temporary file is the
//! whole object, and it is only bounded memory if the file is on a disk.
//!
//! **On a great many Linux installations it is not.** systemd has mounted `/tmp`
//! as `tmpfs` by default since v256, and Fedora, Arch and Ubuntu's cloud images
//! have done so for longer; `tmpfs` is RAM. A 10 GB upload staged there is 10 GB
//! of resident memory, and every peak-RSS measurement taken on a machine whose
//! `/tmp` happens to be a real filesystem would report a constant-memory result
//! that is simply false for the machine the operator is running on. A claim that
//! is true on the developer's box and false on the customer's is worse than no
//! claim, because it is the one nobody re-checks.
//!
//! So the directory is chosen deliberately, it is checked, and when the check
//! says RAM the run says so and names the remedy rather than quietly using it.
//!
//! ## The order, and what an operator can do about it
//!
//! 1. `DCTL_SPOOL_DIR`, if set. The explicit answer always wins, including when
//!    it is a RAM disk — an operator who says "stage in memory, I have 512 GB of
//!    it" is entitled to be believed, and is warned once rather than overruled.
//! 2. Otherwise the platform's temp directory, which honours `TMPDIR`.
//!
//! Either way, if the result is RAM-backed the run emits a warning naming the
//! variable to set. It is a warning and not a refusal because the overwhelming
//! majority of objects are small enough that staging them in `tmpfs` is both
//! harmless and faster, and refusing those would break working installations to
//! defend against a case that has not arrived. What must not happen is the case
//! arriving *silently*, which is what this module exists to prevent.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// The environment variable that names the staging directory outright.
pub const SPOOL_DIR_VAR: &str = "DCTL_SPOOL_DIR";

/// Filesystem types that are RAM rather than storage.
///
/// `tmpfs` covers systemd's `/tmp`, `/dev/shm` and most container scratch
/// mounts; `ramfs` is the older, unbounded form. Deliberately a short, explicit
/// list rather than a heuristic on the device number: being wrong in the
/// direction of *not warning* costs an operator an OOM they were not told about,
/// and being wrong the other way cries wolf on ordinary disks.
const RAM_FILESYSTEMS: [&str; 2] = ["tmpfs", "ramfs"];

/// Whether the RAM-backed warning has already been emitted this run.
///
/// The staging directory is chosen once per stored object, and a backup of forty
/// thousand files would otherwise print forty thousand identical warnings —
/// which is indistinguishable from printing none, because nobody reads the
/// forty-thousandth.
static WARNED: AtomicBool = AtomicBool::new(false);

/// The directory a sealed object is assembled in.
///
/// Emits one warning per run if it turns out to be RAM, naming
/// [`SPOOL_DIR_VAR`]. See the module documentation for the order and for why
/// this warns rather than refuses.
#[must_use]
pub fn spool_dir() -> PathBuf {
    let dir = choose(std::env::var_os(SPOOL_DIR_VAR), std::env::temp_dir());
    if ram_backed(&dir) == Some(true) && !WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            directory = %dir.display(),
            "staging directory is a RAM filesystem: a large object is assembled \
             there before upload, so it will consume memory equal to its size. \
             Set {SPOOL_DIR_VAR} to a directory on disk."
        );
    }
    dir
}

/// The directory to stage in, given what the environment said and what the
/// platform's default is.
///
/// Pure, and separate from [`spool_dir`] for one reason: this crate forbids
/// `unsafe`, `std::env::set_var` is `unsafe` since Rust 2024, and a rule that
/// cannot be tested is a rule that drifts. The precedence is the only thing
/// worth asserting and it is asserted here rather than inferred from a run.
#[must_use]
fn choose(explicit: Option<std::ffi::OsString>, default: PathBuf) -> PathBuf {
    explicit.map_or(default, PathBuf::from)
}

/// Whether `dir` sits on a RAM-backed filesystem.
///
/// [`None`] when the question cannot be answered on this platform — a
/// non-Linux host, or a `/proc` that is not mounted — which is treated as "do
/// not warn" rather than as "assume the worst": a warning that fires on every
/// macOS run would be trained away long before it was ever right.
#[must_use]
pub fn ram_backed(dir: &Path) -> Option<bool> {
    let mounts = std::fs::read_to_string("/proc/self/mounts").ok()?;
    Some(fstype_of(&mounts, dir).is_some_and(|fs| RAM_FILESYSTEMS.contains(&fs)))
}

/// The filesystem type of the mount that `dir` falls under, from the contents of
/// a `/proc/self/mounts`-shaped table.
///
/// Pure, so the parsing is testable against a real table without needing the
/// machine to be mounted that way — which matters, because the interesting cases
/// (`/tmp` on `tmpfs`, `/` on `ext4`) never coexist on one test host.
///
/// The **longest matching mount point wins**, which is the whole subtlety: `/`
/// is a prefix of every path, so a shortest-match or first-match rule would
/// report the root filesystem for `/tmp` on every machine and the warning would
/// never fire on precisely the systems it is for. Matching is on whole path
/// components, so `/tmpfoo` is not considered to be under `/tmp`.
#[must_use]
fn fstype_of<'a>(mounts: &'a str, dir: &Path) -> Option<&'a str> {
    let target = dir.to_str()?;
    let mut best: Option<(usize, &str)> = None;
    for line in mounts.lines() {
        let mut fields = line.split_whitespace();
        let (_source, point, fstype) = (fields.next()?, fields.next()?, fields.next()?);
        let under = target == point
            || (point == "/" && target.starts_with('/'))
            || (target.starts_with(point) && target.as_bytes().get(point.len()) == Some(&b'/'));
        if under && best.is_none_or(|(len, _)| point.len() > len) {
            best = Some((point.len(), fstype));
        }
    }
    best.map(|(_, fstype)| fstype)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `/proc/self/mounts` extract, trimmed to the lines that matter.
    const MOUNTS: &str = "\
/dev/mapper/root / ext4 rw,relatime 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev,size=16106127360 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0
/dev/nvme0n1p2 /var/tmp xfs rw,relatime 0 0
/dev/sdb1 /mnt/bigdisk ext4 rw,relatime 0 0
";

    #[test]
    fn the_longest_matching_mount_point_decides() {
        // The failure this rule exists to prevent: `/` is a prefix of every path,
        // so a first-match or shortest-match walk reports `ext4` for `/tmp` and
        // the warning never fires on the machines that need it.
        assert_eq!(fstype_of(MOUNTS, Path::new("/tmp")), Some("tmpfs"));
        assert_eq!(fstype_of(MOUNTS, Path::new("/tmp/dctl-123")), Some("tmpfs"));
        assert_eq!(fstype_of(MOUNTS, Path::new("/var/tmp")), Some("xfs"));
        assert_eq!(fstype_of(MOUNTS, Path::new("/mnt/bigdisk/x")), Some("ext4"));
        assert_eq!(fstype_of(MOUNTS, Path::new("/home/mx")), Some("ext4"));
    }

    #[test]
    fn a_mount_point_is_matched_on_whole_components() {
        // `/tmpfoo` is not inside `/tmp`, and a bare `starts_with` says it is —
        // which would report a disk directory as RAM and cry wolf.
        assert_eq!(fstype_of(MOUNTS, Path::new("/tmpfoo")), Some("ext4"));
        assert_eq!(fstype_of(MOUNTS, Path::new("/var/tmpish")), Some("ext4"));
    }

    #[test]
    fn ram_filesystems_are_the_ones_named() {
        assert!(RAM_FILESYSTEMS.contains(&fstype_of(MOUNTS, Path::new("/tmp")).unwrap()));
        assert!(RAM_FILESYSTEMS.contains(&fstype_of(MOUNTS, Path::new("/dev/shm")).unwrap()));
        assert!(!RAM_FILESYSTEMS.contains(&fstype_of(MOUNTS, Path::new("/var/tmp")).unwrap()));
    }

    #[test]
    fn an_unparseable_table_answers_nothing_rather_than_guessing() {
        assert_eq!(fstype_of("", Path::new("/tmp")), None);
        assert_eq!(fstype_of("garbage\n", Path::new("/tmp")), None);
    }

    #[test]
    fn an_explicit_spool_directory_wins_and_absence_falls_back() {
        assert_eq!(
            choose(Some("/mnt/bigdisk/spool".into()), PathBuf::from("/tmp")),
            PathBuf::from("/mnt/bigdisk/spool"),
            "an operator who names a directory must get it"
        );
        assert_eq!(
            choose(None, PathBuf::from("/tmp")),
            PathBuf::from("/tmp"),
            "and the platform default when they do not"
        );
    }
}
