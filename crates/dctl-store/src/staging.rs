//! The name a half-written object wears, the only rule for recognising one, and
//! how a backend is asked to enumerate the ones it abandoned.
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
//! ## Enumerating the debris on purpose
//!
//! This module used to end by saying that it deliberately did *not* make staging
//! debris visible to `dctl cleanup`, that closing the gap needed a `Backend`
//! trait change, and that naming the gap was the honest alternative to widening
//! this module until it looked closed. That trait change is
//! [`Backend::list_staging`](crate::Backend::list_staging), and the two types it
//! answers with are below.
//!
//! The shape is the one the gap demanded: **a second question, asked separately**.
//! `list_page` answers "what is stored?" and still omits staging files, because
//! offering a half-written upload as an object is how a `copy` comes to restore
//! a truncated file. `list_staging` answers "what did we abandon?" and returns
//! *only* staging files. Neither can be derived from the other, and a sweep that
//! tried to — by filtering an object listing that had already dropped the very
//! keys it was looking for — reported `OK removed: 0 object(s)` over a directory
//! holding hundreds of gigabytes of abandoned uploads.
//!
//! ## Why the answer can be "there is no such thing here"
//!
//! Only the two filesystem-shaped backends stage: `rename` is what makes their
//! writes atomic, and a staging sibling is what there is to rename. The three
//! object stores upload straight to the final key — B2 verifies a SHA-1 the
//! client declares, S3 and R2 sign the payload — so a killed upload leaves
//! nothing under a temporary key because there is no temporary key. Measured,
//! not argued: a `SIGKILL` three seconds into a copy to B2 leaves a bucket
//! holding `system/envelope.bin` and nothing else.
//!
//! That is a different fact from "this backend cannot look", and
//! [`StagingListing`] keeps them apart deliberately. Reporting a bare `0` would
//! be the false all-clear again wearing a true number; reporting "unsupported"
//! would cry wolf on a backend that has genuinely nothing to sweep, and would
//! fail `dctl cleanup b2r: --class staging` for asking a question with a clean
//! answer. What an interrupted *large* upload leaves on those providers is an
//! unfinished multipart upload, which is a different class, is billed, and is
//! reported as `unsupported` by name because no provider API in this build can
//! list it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::model::ObjectMeta;

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
/// as DCTL's own half-written object: it is not listed as data, and
/// `dctl cleanup --class staging` will delete it once it is older than
/// `--min-age`. That is a much narrower claim than the substring test it
/// replaced, and it is stated in `docs/FORMAT.md` §5 so it is a contract rather
/// than an implementation detail.
pub const STAGING_NAME_PREFIX: &str = ".dctl-staging.";

/// A fresh staging file name, unique within this process and across processes.
///
/// Deliberately carries **no trace of the object being staged**. Embedding the
/// final name was what made a legal filename un-storable once the suffix pushed
/// it past `NAME_MAX`, and a staging file needs no name of its own beyond being
/// unique: the rename that commits it supplies the real one.
///
/// Unique *among live writers*, which is the property that matters and is worth
/// stating precisely, because the sweep now deletes these. A process id is
/// unique among running processes, so two writers alive at the same moment
/// cannot choose one name however their counters stand. What a process id is
/// **not** is unique over time: a later run that happens to be given the pid of
/// a crashed one will re-use that name, open it with `O_TRUNC`, write its own
/// bytes, verify them and rename them onto its own key — so the collision is
/// consumed correctly rather than corrupting anything, and the only visible
/// effect is that a piece of debris can occasionally disappear without `cleanup`
/// having removed it.
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

/// Whether a whole backend **key** names a staging file.
///
/// The last component, because a staging file is a sibling of the object it
/// stages, so the marker is on the file's own name. Testing the whole key would
/// let a *directory* called `.dctl-staging.x` condemn everything beneath it.
///
/// Here rather than repeated at each of the five backends and the sweep: this is
/// the predicate that decides what `dctl cleanup` deletes, and a second opinion
/// about which keys are DCTL's own is exactly how a user's `report.tmp.2024.csv`
/// came to be swept up as debris by one half of the tool and hidden from
/// listings by the other.
#[must_use]
pub fn is_staging_key(key: &str) -> bool {
    is_staging_name(key.rsplit('/').next().unwrap_or(key))
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

/// Why an object store has no staging debris, in the words `cleanup` prints.
///
/// One sentence shared by the three providers that upload straight to the final
/// key, so an operator sweeping B2 and R2 on the same night is not told two
/// different things about one fact.
pub(crate) const NOT_STAGED_REASON: &str = "this backend uploads straight to the object's final key, so no write is ever \
     abandoned under a temporary one";

/// Which of the two kinds of file in a store a walk is collecting.
///
/// One selection type shared by both walks that have to make the choice, and one
/// predicate behind it, because the two answers must be exact complements: a
/// file in neither is precisely the shape that let staging debris sit in a store
/// `cleanup` reported clean, and a file in both would offer a half-written
/// upload as an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Want {
    /// Committed objects — everything except the debris of a write that never
    /// reached its rename.
    Objects,
    /// Exactly that debris, and nothing else.
    Staging,
}

impl Want {
    /// Whether a walk asking this question keeps `key`.
    #[must_use]
    pub fn keeps(self, key: &str) -> bool {
        match self {
            Self::Objects => !is_staging_key(key),
            Self::Staging => is_staging_key(key),
        }
    }
}

/// One page of the debris a backend abandoned under a prefix.
///
/// A distinct type from [`Page`](crate::Page) rather than a reuse of it, for the
/// reason the whole trait method exists: "what is stored?" and "what did we
/// abandon?" must stop sharing one answer, and a shared type is the first step
/// back towards one call site serving both. It also carries no link or
/// special-file report, because it describes DCTL's own leftovers rather than a
/// user's tree — the tree was already described by the object listing, and
/// reporting its links twice would double every count an operator reads.
#[derive(Clone, Debug, Default)]
pub struct StagingPage {
    /// The debris found, oldest-first is not promised — only that every item's
    /// key is a staging key.
    pub items: Vec<ObjectMeta>,
    /// Pass back to continue; [`None`] means the enumeration is exhausted.
    pub next_cursor: Option<String>,
}

/// What a backend has to say when asked to enumerate its abandoned writes.
///
/// Two answers, never a bare number, because the two facts an operator can be
/// told about a class are different and only one of them is "nothing was found":
///
/// * [`Page`](StagingListing::Page) — this backend looked, on purpose, and here
///   is what is there. An empty page from this variant means the store really is
///   clean.
/// * [`NotStaged`](StagingListing::NotStaged) — this backend never writes under
///   a temporary key, so no write can be abandoned under one. Reported as the
///   sentence it carries rather than as `removed: 0`, which is a true number and
///   an untrue answer.
///
/// There is deliberately no third "cannot look" variant: no backend in this
/// build is in that position, and a variant nothing produces is documentation
/// pretending to be code. The class-level refusal for a capability nobody has —
/// multipart uploads, object versions — already exists one layer up, where the
/// sweep names the class and exits 6 if the user asked for it by name.
#[derive(Clone, Debug)]
pub enum StagingListing {
    /// One page of debris this backend enumerated.
    Page(StagingPage),
    /// This backend has no staging namespace, and this is why.
    NotStaged(&'static str),
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
    fn a_users_file_is_never_swept_as_debris_however_it_is_addressed() {
        // The same rule at key level, which is the one `cleanup` deletes on.
        // A second opinion here is what put `report.tmp.2024.csv` in the bin.
        for name in REAL_FILES_THAT_LOOK_TEMPORARY {
            assert!(!is_staging_key(name), "{name} would be deleted as debris");
            assert!(
                !is_staging_key(&format!("photos/2024/{name}")),
                "{name} would be deleted as debris"
            );
        }
        assert!(!is_staging_key("o/abcdef0123456789"));
        assert!(!is_staging_key("notes/tmp/a.txt"));
        assert!(!is_staging_key("archive.tmpfile"));
    }

    #[test]
    fn a_staging_key_is_recognised_at_the_root_and_below_it() {
        let name = staging_name();
        assert!(is_staging_key(&name));
        assert!(is_staging_key(&format!("o/{name}")));
        assert!(is_staging_key(&format!("a/b/c/{name}")));
    }

    #[test]
    fn a_directory_that_looks_like_debris_condemns_nothing_beneath_it() {
        // The reason the test is on the last component: a whole-key test would
        // sweep every object under a directory somebody named badly.
        assert!(!is_staging_key(&format!(
            "{STAGING_NAME_PREFIX}9.9/real-object.bin"
        )));
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
    fn a_staging_name_can_never_be_a_committed_objects_key() {
        // The question a sweep that deletes has to have answered: can a piece of
        // debris ever be mistaken for, or land on, a committed object?
        //
        // Not in a vault. Its keys are `o/<32 hex>`, `n/<32 hex>` and
        // `system/envelope.bin` — every one of them a name this prefix cannot
        // produce, because the prefix begins with a dot and the hash alphabet
        // does not. The staging file is a *sibling* of the object, never the
        // object's own key, and the rename is what makes the key exist at all,
        // so a reader asking for `o/<hash>` can never be handed staged bytes.
        let staged = staging_name();
        for committed in [
            "o/8f14e45fceea167a5a36dedd4bea2543",
            "n/c4ca4238a0b923820dcc509a6f75849b",
            "system/envelope.bin",
        ] {
            assert!(!is_staging_key(committed), "{committed}");
            assert_ne!(committed.rsplit('/').next(), Some(staged.as_str()));
        }
        // On a plain store the keys are the user's own paths, so the collision
        // is possible in exactly one way: a file literally named
        // `.dctl-staging.<something>`. That is the claimed namespace, stated in
        // `docs/FORMAT.md` §5, and it is why the claim is a leading-dot prefix
        // no ordinary tool produces rather than a substring.
        assert!(is_staging_key(&format!("{STAGING_NAME_PREFIX}anything")));
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

    #[test]
    fn the_two_selections_are_exact_complements_of_one_predicate() {
        // Every key in a store is in exactly one of the two answers. A key in
        // neither is how debris came to be invisible to the listing *and* to the
        // sweep; a key in both would offer a half-written upload as an object.
        for key in [
            "o/8f14e45fceea167a5a36dedd4bea2543",
            "report.tmp.2024.csv",
            "system/envelope.bin",
            &format!("o/{}", staging_name()),
            &staging_name(),
        ] {
            assert_ne!(
                Want::Objects.keeps(key),
                Want::Staging.keeps(key),
                "{key} is in both answers or in neither"
            );
        }
    }

    #[test]
    fn an_exhausted_staging_page_says_so_rather_than_looping() {
        // The pager contract the sweep loops on: `None` ends it. A page that
        // always answered `Some` would make `cleanup` run forever over a store
        // it had already swept.
        let page = StagingPage::default();
        assert!(page.items.is_empty());
        assert!(page.next_cursor.is_none());
    }
}
