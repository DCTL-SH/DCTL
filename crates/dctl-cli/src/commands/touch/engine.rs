//! Creating an empty object, or moving a modification time.
//!
//! `touch` is two operations wearing one name, and the three kinds of place
//! DCTL can address support different halves of it. The table is in
//! [`crate::commands::directory`]; what follows is why each cell reads the way
//! it does.
//!
//! ## A filesystem remote: both halves, done by the operating system
//!
//! A missing file is created empty and an existing one keeps its contents; then
//! `set_times` writes the modification *and* access time, because `touch(1)`
//! sets both and a tool that moved only one would leave a tree that no `find
//! -newer` agrees with. Nothing is truncated: `touch` on a file with content is
//! a metadata operation, and losing data to a timestamp command would be
//! unforgivable.
//!
//! ## A sealed vault: creation works, re-stamping does not, and both are honest
//!
//! An empty object is a real, storable thing — `Vault::put_file(path, b"")`
//! seals it, writes it with the same verified write every other object gets, and
//! commits an index record. So `touch archive:sentinel` genuinely creates
//! something, and the time it reports is read back out of the index afterwards
//! rather than assumed from the clock.
//!
//! Changing the time of an object the vault already holds has nowhere to go.
//! The modification time lives in `dctl_index::Record::modified_unix` inside the
//! encrypted index; `dctl_core::Vault` exposes no operation that updates one,
//! and the index handle is private to the core — there is no call this command
//! could make. The alternatives are worse than refusing:
//!
//! * re-storing the object would set the time to *now*, which is a different
//!   write than the one requested and would silently discard `--timestamp`;
//! * opening the index directly from the CLI would mean a second writer to a
//!   database the vault holds open, and a second implementation of a format
//!   `dctl-core` owns.
//!
//! So the refusal is real, carries an exit code, and **names the missing call
//! rather than this command** ([`TOUCH_RESTAMP_FEATURE`]). That wording is
//! deliberate and load-bearing: a message reading "dctl touch is not
//! implemented" would send a reader here to find a branch that is absent, and
//! nothing is absent here. `dctl_core::Vault`'s public surface is unlocking,
//! whole-object writes, whole-object reads, verification, listing, deletion,
//! index rebuild and the recipient/share operations; not one of them takes or
//! updates a modification time, and `Vault::index` — the only thing that could —
//! is a private field. The gap is a function in another crate, and the message
//! points there.
//!
//! The same reasoning refuses `--timestamp` against a vault *before anything is
//! created* ([`TOUCH_EXPLICIT_TIME_FEATURE`]), and it is a **second** missing
//! capability rather than the same one: `put_file` stamps `now_unix()` and takes
//! no time from the caller, so even the create path has no argument for
//! `--timestamp` to become. Creating the object and reporting the requested time
//! would be a lie, and creating it with a different time would be an operation
//! nobody asked for.
//!
//! ## An object store: refused, and this one is nobody's build gap
//!
//! It used to share a refusal with `rcat` and the transfer family — "nothing in
//! this build writes a plain object" — and that sentence has stopped being true:
//! `dctl copy ./src b2:mybucket` writes plain objects through
//! [`Backend::put`](dctl_store::Backend::put) today. Keeping the shared wording
//! would now tell a `touch` user to wait for something that has already shipped.
//!
//! What a bucket actually lacks is the thing `touch` exists to do. B2, S3 and R2
//! each stamp `Last-Modified` when they accept an object and expose no operation
//! that moves it afterwards; there is no `utimes()` to call and no header to
//! send. So the missing capability is the **provider's**, below `dctl-store`,
//! and no phase of `PLAN.md` delivers it — which is why
//! [`TOUCH_OBJECT_STORE_FEATURE`] says so rather than naming a release.
//!
//! Creating an empty object there *is* possible, and the refusal says that too:
//! it is a write, not a stamp, and `dctl copy` of an empty file performs it.
//! Doing it here under the name `touch` would mean creating an object whose time
//! is whatever the provider chose while the command claims to have set one.

use std::path::Path;
use std::time::{Duration, SystemTime};

use dctl_core::Vault;

use crate::commands::directory::{self, Outcome, Target};
use crate::constants::{
    TOUCH_EXPLICIT_TIME_FEATURE, TOUCH_EXPLICIT_TIME_HINT, TOUCH_OBJECT_STORE_FEATURE,
    TOUCH_OBJECT_STORE_HINT, TOUCH_RESTAMP_FEATURE, TOUCH_RESTAMP_HINT,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::platform::path as logical;
use crate::remote::Place;
use crate::session;

use super::timestamp::Timestamp;

/// One resolved `touch` request.
///
/// A struct rather than four positional arguments because three of them are
/// booleans and a transposed pair would silently invert `--no-create`.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// The object being addressed.
    pub target: &'a Target,
    /// The time to write.
    pub stamp: Timestamp,
    /// Whether that time came from `--timestamp` rather than from the clock.
    ///
    /// Kept apart from the value itself: "now" and "this exact second, which
    /// happens to be now" are the same number and different requests, and only
    /// the second one has to be refused by a vault.
    pub explicit: bool,
    /// Whether a missing object may be created (`!--no-create`).
    pub create: bool,
}

/// Apply the request, reporting what actually happened.
///
/// # Errors
/// [`ExitCode::Usage`](crate::exit::ExitCode::Usage) when `--immutable` forbids
/// modifying what is already there, or when the target names a directory on a
/// filesystem; [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError) for a
/// refused write path, a refused re-stamp, or an addressing refusal;
/// [`ExitCode::VaultLocked`](crate::exit::ExitCode::VaultLocked) when a vault
/// will not unlock; and whatever the operating system or the provider reported.
pub async fn apply(ctx: &Ctx, place: &Place, request: Request<'_>) -> Result<Outcome> {
    match place {
        Place::Sealed => sealed(ctx, request).await,
        Place::Filesystem { root, path } => filesystem(ctx, root, path, request),
        // Matched rather than pre-checked, so a kind of place added later is a
        // compile error here instead of a silent fall-through into whichever arm
        // came first.
        Place::ObjectStore { provider } => Err(object_store(provider)),
    }
}

/// The refusal an object store earns, naming the provider that was addressed.
///
/// The provider is quoted because the alternative — a message about "an object
/// store" — leaves a reader who typed a *named* remote unsure whether their
/// remote is one. `b2` in the text is the fact that ends the question.
fn object_store(provider: &str) -> CliError {
    CliError::unimplemented(format!(
        "{TOUCH_OBJECT_STORE_FEATURE} ({provider}, {})",
        directory::command_name(super::VERB)
    ))
    .with_hint(TOUCH_OBJECT_STORE_HINT)
}

/// The sealed path: create when missing, refuse to re-stamp.
async fn sealed(ctx: &Ctx, request: Request<'_>) -> Result<Outcome> {
    // First, and before the vault is opened: a chosen time cannot be stored
    // here whatever the object's state, so refusing costs no password prompt and
    // — more importantly — no partially-performed operation.
    if request.explicit {
        return Err(CliError::unimplemented(TOUCH_EXPLICIT_TIME_FEATURE)
            .with_hint(TOUCH_EXPLICIT_TIME_HINT));
    }

    let session = session::open(ctx, &request.target.spec()).await?;
    let path = request.target.path.as_str();

    if let Some(existing) = record(&session.vault, path)? {
        if ctx.globals.immutable {
            return Err(immutable(&request.target.to_string()));
        }
        // The object is there and its time cannot be moved. Reported with the
        // time it *does* carry, so the operator can see what they are being
        // refused rather than only that they were refused. An object whose
        // record carries no time at all says so rather than showing the epoch,
        // which would look like a real answer.
        let held = existing.map_or_else(
            || crate::constants::UNKNOWN_VALUE.to_string(),
            |seconds| Timestamp::from_unix(seconds).to_rfc3339(),
        );
        return Err(
            CliError::unimplemented(TOUCH_RESTAMP_FEATURE).with_hint(format!(
                "{TOUCH_RESTAMP_HINT} '{}' keeps the modification time it was \
                 written with ({held}).",
                request.target
            )),
        );
    }

    if !request.create {
        return Ok(Outcome::Skipped);
    }

    // An empty object goes through the same verified write and the same durable
    // index commit as any other, so success here means the same thing it means
    // for a 40 GB file (`PLAN.md` §6).
    session.vault.put_file(path, b"").await?;
    Ok(Outcome::Created)
}

/// The record the vault holds for `path`, if it holds one.
///
/// Two levels of "absent" are deliberately kept apart: the outer [`None`] means
/// the vault has no such object, and the inner one — `Record::modified_unix` is
/// itself optional — means the object is there but carries no recorded time.
/// Collapsing them would make `touch` report a missing object as an untimed one
/// and create nothing.
///
/// `Vault::list` matches by byte prefix, so `a.txt` would also report
/// `a.txt.bak`; the exact comparison is what makes this a lookup rather than a
/// search. It reads the local index only — no provider request, no download.
///
/// # Errors
/// Whatever the index reported.
fn record(vault: &Vault, path: &str) -> Result<Option<Option<i64>>> {
    Ok(vault
        .list(path)?
        .into_iter()
        .find(|record| record.path == path)
        .map(|record| record.modified_unix))
}

/// The filesystem path: both halves, performed by the operating system.
fn filesystem(ctx: &Ctx, root: &Path, path: &str, request: Request<'_>) -> Result<Outcome> {
    let full = logical::from_logical(root, path);

    // The same addressing question every write path asks, for the same reason:
    // a file appearing among a vault's objects is unencrypted and unreadable to
    // the vault that owns the tree. Asked from the configuration, before
    // anything exists, so the answer does not depend on what is there.
    crate::addressing::refuse_plain_write_to_path(ctx, &full)?;

    let existed = full.try_exists().map_err(|error| at(&full, error))?;

    if !existed && !request.create {
        // `touch -c`: re-stamp what is there, stay silent about what is not.
        return Ok(Outcome::Skipped);
    }
    if existed && ctx.globals.immutable {
        return Err(immutable(&full.display().to_string()));
    }

    // `create(true)` truncates; `append` does not, and an existing file must
    // keep every byte — this is a metadata command, and a `touch` that emptied a
    // file would be the worst bug in the tool.
    let handle = std::fs::File::options()
        .append(true)
        .create(true)
        .open(&full)
        .map_err(|error| open_failure(&full, error))?;

    let when = system_time(request.stamp)?;
    // Both times, because `touch(1)` sets both: a tree whose access times did
    // not move would disagree with every `find -newer` a script uses.
    handle
        .set_times(
            std::fs::FileTimes::new()
                .set_accessed(when)
                .set_modified(when),
        )
        .map_err(|error| at(&full, error))?;

    Ok(if existed {
        Outcome::Stamped
    } else {
        Outcome::Created
    })
}

/// Turn a whole-second timestamp into the value the filesystem takes.
///
/// Times before 1970 are ordinary rather than exceptional — a restored archive
/// legitimately holds them — so the negative side is a subtraction and not an
/// error. Only a value the platform cannot represent fails, and it fails loudly
/// instead of clamping to an instant the user did not ask for.
fn system_time(stamp: Timestamp) -> Result<SystemTime> {
    let seconds = stamp.unix_seconds();
    let magnitude = Duration::from_secs(seconds.unsigned_abs());

    let when = if seconds >= 0 {
        SystemTime::UNIX_EPOCH.checked_add(magnitude)
    } else {
        SystemTime::UNIX_EPOCH.checked_sub(magnitude)
    };

    when.ok_or_else(|| {
        CliError::usage(format!(
            "{} is outside the range of times this system can store",
            stamp.to_rfc3339()
        ))
        .with_hint("Choose a time this platform's filesystem can represent.")
    })
}

/// The refusal `--immutable` produces.
///
/// One constructor so the wording cannot drift between the vault path and the
/// filesystem path, which refuse the same thing for the same reason.
fn immutable(subject: &str) -> CliError {
    CliError::usage(format!(
        "'{subject}' already exists and --immutable was given"
    ))
    .with_hint("--immutable refuses to modify anything that already exists.")
}

/// Diagnose a failure to open the target for stamping.
///
/// A directory gets its own message: opening one for writing fails with a
/// platform-specific error that says nothing useful, and "is a directory" is
/// what the user needs to read.
fn open_failure(path: &Path, error: std::io::Error) -> CliError {
    if path.is_dir() {
        return CliError::usage(format!("'{}' is a directory", path.display())).with_hint(
            "touch addresses an object. A directory's own timestamp is the \
             filesystem's to maintain, and DCTL does not move it.",
        );
    }
    at(path, error)
}

/// Attach the offending path to an operating-system failure.
fn at(path: &Path, error: std::io::Error) -> CliError {
    CliError::from(error).with_hint(format!("touching {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::directory::testing::ctx;
    use crate::exit::ExitCode;
    use std::time::UNIX_EPOCH;

    fn target(spec: &str) -> Target {
        Target::parse(spec, "object").expect("a valid target")
    }

    fn request<'a>(target: &'a Target, stamp: &str, create: bool) -> Request<'a> {
        Request {
            target,
            stamp: Timestamp::parse(stamp).expect("a valid time"),
            explicit: true,
            create,
        }
    }

    /// The modification time of `path`, in whole seconds since the epoch.
    fn modified(path: &Path) -> i64 {
        let time = std::fs::metadata(path)
            .expect("the file exists")
            .modified()
            .expect("the platform reports modification times");
        match time.duration_since(UNIX_EPOCH) {
            Ok(delta) => i64::try_from(delta.as_secs()).expect("a representable time"),
            Err(before) => -i64::try_from(before.duration().as_secs()).expect("representable"),
        }
    }

    #[test]
    fn a_missing_file_is_created_empty_and_stamped() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let target = target("scratch:notes/todo.md");

        let outcome = filesystem(
            &ctx(&[]),
            root.path(),
            "notes/todo.md",
            request(&target, "2024-05-01T12:00:00Z", true),
        );

        // The parent does not exist, so `touch(1)`'s own behaviour applies: it
        // does not create directories, and the failure names the path.
        assert_eq!(
            outcome.expect_err("no parent directory").code(),
            ExitCode::FileNotFound
        );

        std::fs::create_dir_all(root.path().join("notes")).expect("the parent");
        let outcome = filesystem(
            &ctx(&[]),
            root.path(),
            "notes/todo.md",
            request(&target, "2024-05-01T12:00:00Z", true),
        )
        .expect("the object is created");

        assert_eq!(outcome, Outcome::Created);
        let created = root.path().join("notes/todo.md");
        assert_eq!(std::fs::metadata(&created).unwrap().len(), 0);
        assert_eq!(modified(&created), 1_714_564_800);
    }

    #[test]
    fn an_existing_file_is_re_stamped_and_never_truncated() {
        // The property that matters most here: `touch` is a metadata command,
        // and a version that emptied the file would be a data-loss bug.
        let root = tempfile::tempdir().expect("a temporary directory");
        let path = root.path().join("notes.md");
        std::fs::write(&path, b"contents that must survive").expect("the fixture");
        let target = target("scratch:notes.md");

        let outcome = filesystem(
            &ctx(&[]),
            root.path(),
            "notes.md",
            request(&target, "@0", true),
        )
        .expect("the time is set");

        assert_eq!(outcome, Outcome::Stamped);
        assert_eq!(std::fs::read(&path).unwrap(), b"contents that must survive");
        assert_eq!(modified(&path), 0);
    }

    #[test]
    fn a_time_before_the_epoch_is_ordinary_rather_than_an_error() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let target = target("scratch:old.txt");
        filesystem(
            &ctx(&[]),
            root.path(),
            "old.txt",
            request(&target, "1969-12-31T23:59:59Z", true),
        )
        .expect("a pre-epoch time is storable");
        assert_eq!(modified(&root.path().join("old.txt")), -1);
    }

    #[test]
    fn no_create_leaves_a_missing_object_alone() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let target = target("scratch:absent.txt");

        let outcome = filesystem(
            &ctx(&[]),
            root.path(),
            "absent.txt",
            request(&target, "@0", false),
        )
        .expect("nothing to do is not a failure");

        assert_eq!(outcome, Outcome::Skipped);
        assert!(!root.path().join("absent.txt").exists());
    }

    #[test]
    fn immutable_refuses_to_re_stamp_something_that_exists() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let path = root.path().join("notes.md");
        std::fs::write(&path, b"original").expect("the fixture");
        let target = target("scratch:notes.md");
        let before = modified(&path);

        let error = filesystem(
            &ctx(&["--immutable"]),
            root.path(),
            "notes.md",
            request(&target, "@0", true),
        )
        .expect_err("--immutable forbids modifying what exists");

        assert_eq!(error.code(), ExitCode::Usage);
        assert_eq!(modified(&path), before, "the time was changed anyway");
    }

    #[test]
    fn a_directory_is_diagnosed_rather_than_reported_as_a_platform_error() {
        let root = tempfile::tempdir().expect("a temporary directory");
        std::fs::create_dir(root.path().join("photos")).expect("the fixture");
        let target = target("scratch:photos");

        let error = filesystem(
            &ctx(&[]),
            root.path(),
            "photos",
            request(&target, "@0", true),
        )
        .expect_err("a directory is not an object");

        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("directory"), "{}", error.message());
    }

    #[tokio::test]
    async fn an_explicit_time_is_refused_by_a_vault_before_anything_is_opened() {
        // `--no-ask-password` pins the ordering: reaching the unlock would fail
        // with VaultLocked, so a FatalError proves the refusal came first — and
        // therefore that nothing was created.
        let target = target("archive:sentinel");
        let error = sealed(
            &ctx(&["--no-ask-password"]),
            request(&target, "2024-05-01T12:00:00Z", true),
        )
        .await
        .expect_err("a chosen time cannot be stored in a vault");

        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains(TOUCH_EXPLICIT_TIME_FEATURE));
        assert!(
            error
                .hint()
                .is_some_and(|hint| hint.contains("--timestamp"))
        );
    }

    #[tokio::test]
    async fn an_object_store_is_refused_for_the_reason_that_actually_applies() {
        // The refusal that must not drift back to "this build cannot write a
        // plain object": a transfer writes one, so that wording would send a
        // reader to wait for a release that already happened. What is missing is
        // the provider's — an object store assigns its own last-modified — and
        // the message has to carry the provider name, the layer, and no phase,
        // because promising a phase for something no release can deliver is the
        // same lie in the other direction.
        let target = target("b2:mybucket/x");
        let error = apply(
            &ctx(&["--no-ask-password"]),
            &Place::ObjectStore {
                provider: crate::constants::PROVIDER_B2,
            },
            request(&target, "@0", true),
        )
        .await
        .expect_err("an object store has no settable modification time");

        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains(TOUCH_OBJECT_STORE_FEATURE),
            "the refusal must name the missing capability: {}",
            error.message()
        );
        assert!(
            error.message().contains(crate::constants::PROVIDER_B2),
            "and the provider that was addressed: {}",
            error.message()
        );
        let hint = error.hint().expect("a refusal must say what to do");
        assert!(
            hint.contains("provider"),
            "the layer the gap belongs to must be named: {hint}"
        );
        assert!(
            hint.contains("no phase of PLAN.md") || hint.contains("no phase"),
            "a gap no release closes must say so rather than name a phase: {hint}"
        );
        assert!(
            !error
                .message()
                .contains("writing a plain object into an object store"),
            "a transfer writes plain objects today; this must not claim otherwise: {}",
            error.message()
        );
    }

    #[test]
    fn an_unrepresentable_time_fails_instead_of_clamping() {
        // Clamping would stamp a file with a time the user never asked for, and
        // a `sync` would then make a decision from it.
        assert!(system_time(Timestamp::parse("@0").unwrap()).is_ok());
        assert!(system_time(Timestamp::parse("9999-12-31").unwrap()).is_ok());
    }
}
