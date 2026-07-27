//! The name a half-written object wears, and the only rule for recognising one.
//!
//! Every verified write in this crate stages its bytes under a temporary name in
//! the destination's own directory, fsyncs, checks what landed, and only then
//! `rename`s onto the final name. The rename is the commit (`PLAN.md` §6): a
//! crash before it leaves a staging file, and a staging file was never reported
//! to anybody as stored. Listings must therefore skip them — an object nothing
//! committed is not an object.
//!
//! ## Why this is its own module, with one rule
//!
//! Because the previous arrangement lost customer data, silently, and it is
//! worth writing down exactly how.
//!
//! Three writers each invented their own staging spelling — `<name>.tmp.<pid>.<seq>`,
//! `<name>.dctltmp.<pid>.<seq>`, `<path>.tmp.<pid>.<seq>` — and two listing walks
//! recognised them with `name.contains(".tmp.")`. A **substring test, anywhere in
//! the name**, used as though it identified something DCTL had written.
//!
//! Real filenames contain `.tmp.`:
//!
//! ```text
//! report.tmp.2024.csv        a dated temp-file convention
//! db.tmp.2024-07-27.sql      a Postgres dump pipeline
//! ~$report.tmp.docx          Office's own lock file, backed up with the tree
//! ```
//!
//! Every one of those was invisible to `ls`, to `size`, to `scrub`, to `copy` —
//! and to `sync`, which therefore never deleted them from a destination, and to
//! `purge`, which reported `OK removed: 4 object(s)` and left them on the server.
//! `dctl copy remote: /restore` said `Files: 5 / 5  Errors: 0`, exit 0, having
//! silently omitted them. On restore day they were simply absent and no command
//! had ever said so.
//!
//! ## The rule
//!
//! A staging file's **name** — never its path, never a substring of either — is
//! exactly [`STAGING_NAME_PREFIX`] followed by a process id and a counter. It
//! does not contain the final object's name at all. Recognition is
//! [`is_staging_name`], a prefix test on one path component, and there is one
//! implementation of it for every backend.
//!
//! Two consequences fall out of dropping the final name from the staging name,
//! and both are fixes rather than accidents:
//!
//! * **A file can no longer be too long to upload.** The old sftp spelling
//!   appended the suffix to the *filename*, so a 245-byte name exceeded
//!   `NAME_MAX` as a staging file while being perfectly legal as a final one.
//!   The upload failed with `Bad message` and a hint about connectivity. Worse,
//!   the suffix length depended on the process id's digit count, so the same
//!   backup job failed on some nights and not others. A staging name is now a
//!   fixed shape regardless of what it is staging.
//! * **The reserved namespace is narrow and stated.** A user file is hidden only
//!   if it is literally named `.dctl-staging.<something>`. That is a namespace
//!   DCTL claims, in a leading-dot spelling no ordinary tool produces, rather
//!   than a substring anybody's convention might collide with.
//!
//! ## What this module deliberately does not do
//!
//! It does not make staging debris *visible* to `dctl cleanup`. A listing that
//! skips staging files is a listing `cleanup --class staging` cannot sweep with,
//! which is a real and separate defect — `cleanup` currently reports
//! `OK removed: 0 object(s)` over a directory full of abandoned uploads. Closing
//! it needs a way for a backend to enumerate its own debris, which is a
//! `Backend` trait change and not this one. Naming the gap here is the honest
//! alternative to widening this module until it looks closed.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic counter making staging names unique across concurrent writers in
/// this process. Combined with the process id it is unique across processes too.
static STAGING_SEQ: AtomicU64 = AtomicU64::new(0);

/// The reserved prefix every staging file's name begins with.
///
/// Leading dot so it is hidden from an ordinary `ls` and sorts away from real
/// objects; the tool's own name so that a stray file found after a crash says
/// who left it; a trailing dot so the prefix cannot be a whole name and the
/// unique part is visibly separate.
///
/// **This is a claimed namespace.** A file whose name starts with it is treated
/// as DCTL's own half-written object and is not listed as data. That is a much
/// narrower claim than the substring test it replaced, and it is stated in
/// `docs/FORMAT.md` §5 so it is a contract rather than an implementation detail.
pub const STAGING_NAME_PREFIX: &str = ".dctl-staging.";

/// A fresh staging file name, unique within this process and across processes.
///
/// Deliberately carries **no trace of the object being staged**. Embedding the
/// final name was what made a legal filename un-storable once the suffix pushed
/// it past `NAME_MAX`, and a staging file needs no name of its own beyond being
/// unique: the rename that commits it supplies the real one.
#[must_use]
pub fn staging_name() -> String {
    let seq = STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    format!("{STAGING_NAME_PREFIX}{pid}.{seq}")
}

/// Whether one path **component** is a staging file's name.
///
/// Takes a name, not a path, and tests a prefix, not a substring. Both halves of
/// that sentence are the fix: a path test would match a directory somewhere
/// above the object, and a substring test is what hid `report.tmp.2024.csv`.
#[must_use]
pub fn is_staging_name(name: &str) -> bool {
    name.starts_with(STAGING_NAME_PREFIX)
}

/// A staging sibling of `destination`, in the same directory.
///
/// The same directory is not a preference: `rename` is only atomic within one
/// filesystem, and the destination's own directory is the one place guaranteed
/// to be on the same one.
#[must_use]
pub fn staging_sibling(destination: &Path) -> PathBuf {
    destination
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
        .join(staging_name())
}

/// A staging sibling of a remote forward-slash path, in the same directory.
///
/// The remote twin of [`staging_sibling`], kept here rather than in the sftp
/// backend so that both sides of the same rule live in one file. A path with no
/// directory part stages beside itself at the root.
#[must_use]
pub fn staging_sibling_remote(destination: &str) -> String {
    match destination.rfind('/') {
        Some(cut) => format!("{}/{}", &destination[..cut], staging_name()),
        None => staging_name(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real filenames that the substring test used to hide. Every one of
    /// these was a silent omission from a backup.
    const REAL_FILES_THAT_LOOK_TEMPORARY: &[&str] = &[
        "report.tmp.2024.csv",
        "db.tmp.2024-07-27.sql",
        "~$report.tmp.docx",
        "notes.tmp.bak",
        "client.tmp.2024.dat",
        "archive.tmp.tar.gz",
        // The old spellings themselves, now ordinary names: a tree backed up
        // from a machine that ran an older DCTL must still restore whole.
        "photo.jpg.tmp.4711.0",
        "photo.jpg.dctltmp.4711.0",
    ];

    #[test]
    fn a_users_file_is_never_mistaken_for_a_staging_file() {
        // The data-loss defect, asserted directly. Under the substring rule
        // every one of these vanished from every listing, and `copy` reported
        // success without them.
        for name in REAL_FILES_THAT_LOOK_TEMPORARY {
            assert!(
                !is_staging_name(name),
                "{name} would be silently dropped from every listing"
            );
        }
    }

    #[test]
    fn a_staging_file_is_recognised_by_its_own_name() {
        let name = staging_name();
        assert!(is_staging_name(&name), "{name}");
        assert!(name.starts_with(STAGING_NAME_PREFIX));
    }

    #[test]
    fn staging_names_are_unique_within_a_process() {
        let a = staging_name();
        let b = staging_name();
        assert_ne!(a, b, "two concurrent writers would collide");
    }

    #[test]
    fn a_staging_name_never_carries_the_object_it_stages() {
        // The name-length defect: appending to the final name made a legal
        // 245-byte filename un-storable, and the cutoff moved with the process
        // id's digit count, so the same job failed on some nights only.
        let long = "x".repeat(250);
        let staged = staging_sibling(Path::new(&format!("dir/{long}")));
        let name = staged
            .file_name()
            .and_then(|n| n.to_str())
            .expect("a staging sibling always has a name");

        assert!(
            !name.contains(&long),
            "the object's name leaked into {name}"
        );
        assert!(
            name.len() < 64,
            "a staging name must be short whatever it stages: {name}"
        );
        assert_eq!(staged.parent(), Some(Path::new("dir")), "same directory");
    }

    #[test]
    fn a_remote_staging_sibling_stays_in_its_own_directory() {
        // Same filesystem, same directory — the rename that commits the object
        // is only atomic there.
        let staged = staging_sibling_remote("srv/store/a/b/obj.bin");
        assert!(staged.starts_with("srv/store/a/b/"));
        assert!(is_staging_name(
            staged.rsplit('/').next().unwrap_or_default()
        ));

        // A root-level object still stages beside itself.
        let root = staging_sibling_remote("obj.bin");
        assert!(!root.contains('/'));
        assert!(is_staging_name(&root));
    }

    #[test]
    fn the_reserved_prefix_is_not_something_an_ordinary_tool_produces() {
        // A leading dot and the tool's own name: the namespace is claimed
        // deliberately and is narrow enough to state in one sentence.
        assert!(STAGING_NAME_PREFIX.starts_with('.'));
        assert!(STAGING_NAME_PREFIX.ends_with('.'));
        assert!(STAGING_NAME_PREFIX.contains("dctl"));
        // A bare prefix is not a name: the unique part is always present.
        assert!(!is_staging_name(STAGING_NAME_PREFIX.trim_end_matches('.')));
    }
}
