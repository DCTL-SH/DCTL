//! Turning two command-line specs into a reviewable plan.
//!
//! Every verb in the family starts the same way: parse `SOURCE` and `DEST`,
//! refuse the argument combinations that cannot mean what they say, enumerate
//! both sides, and diff them. Doing that once here is what makes `copy` and
//! `sync` agree about which files are identical — and getting that wrong in only
//! one of them is precisely how a sync tool deletes data.
//!
//! The validation is not decoration. Three of the checks below exist because the
//! alternative is silent damage:
//!
//! * **Source and destination are the same place.** A transfer onto itself is at
//!   best a no-op; under `sync` it is a race between listing a tree and deleting
//!   from it.
//! * **`sync` from a single file.** `dctl sync photo.jpg backups/` reads as
//!   "make `backups/` contain exactly `photo.jpg`" — which means deleting
//!   everything else in it. Almost nobody means that, so it is refused and the
//!   two verbs that *do* mean it are named in the hint.
//! * **An exact-name transfer onto a directory.** `copyto a.txt existing-dir`
//!   has no sensible reading: the destination cannot both be the object's name
//!   and contain it.
//!
//! Both sides are enumerated through [`super::listing`], which reaches a local
//! tree and a named remote alike — so `SOURCE` may be a vault, and the whole
//! transfer matrix is available rather than only the half that writes into one.
//! Both functions are therefore `async`: opening a sealed source unlocks a
//! vault, and that is I/O the planner has to await before it can diff anything.
//!
//! It is also the one place `--immutable` is applied, for the same reason: every
//! verb in the family funnels through the two public functions below, so the gate
//! sits on them rather than in five command bodies that could each forget it.
//! See [`super::immutable`] for why the decision belongs to the plan and not to
//! the write.
//!
//! The addressing rule ([`crate::addressing`]) is applied here on the same
//! grounds, and *first*: it decides whether the destination may be written at
//! all, and deciding that before anything is enumerated is what makes
//! `--dry-run` rehearse the refusal instead of printing a plan the real run
//! rejects. See [`refuse_a_plain_write_into_a_vault`].

use crate::cli::GlobalArgs;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::remote::RemoteSpec;

use super::compare::ComparePolicy;
use super::endpoint;
use super::entry::Entry;
use super::immutable;
use super::listing::{self, ListOptions, Listing};
use super::options::{CompareFlags, TraversalFlags};
use super::plan::{Plan, Policy};

/// Everything a command needs to know about one requested transfer.
#[derive(Debug)]
pub struct Prepared {
    /// The **root** the plan's source paths are relative to.
    ///
    /// Usually the `SOURCE` the user typed. It is the containing directory
    /// instead when `SOURCE` named a single file, so that joining this root to a
    /// [`super::plan::PlanEntry::source`] always yields the real object. A
    /// consumer of the JSON plan composes those two strings; if the root were
    /// the file itself, every composed path would gain a phantom component.
    pub source: RemoteSpec,
    /// The **root** the plan's destination paths are relative to, under the same
    /// rule as [`Prepared::source`].
    pub dest: RemoteSpec,
    /// What would happen.
    pub plan: Plan,
    /// How many files the destination already held.
    ///
    /// Only used to decide whether a `sync`'s deletions are a large enough share
    /// of the destination to warrant an unconditional warning.
    pub dest_file_count: usize,
}

/// What a command is asking for.
///
/// A struct rather than eight positional arguments, because four of them are
/// booleans and a transposed pair would silently turn `copy` into `sync`.
#[derive(Debug)]
pub struct Request<'a> {
    /// The resolved global flags.
    pub globals: &'a GlobalArgs,
    /// `SOURCE`, as typed.
    pub source_spec: &'a str,
    /// `DEST`, as typed.
    pub dest_spec: &'a str,
    /// The command's comparison flags.
    pub compare: &'a CompareFlags,
    /// The command's traversal flags. `sync` passes the default, because it must
    /// list the destination in order to find the extras it deletes.
    pub traversal: TraversalFlags,
    /// Whether empty source directories are recreated.
    pub create_empty_src_dirs: bool,
    /// Whether files present only at the destination are removed.
    pub delete_extras: bool,
}

impl Request<'_> {
    /// The comparison policy implied by the globals and the command's flags.
    ///
    /// Every input to it is something the user typed. A transfer used to add one
    /// of its own — a content comparison substituted whenever a side was a vault,
    /// because a vault could not answer by time — and that is gone: the vault
    /// answers by time like anything else now, so what runs is what was asked
    /// for.
    ///
    /// # Errors
    /// A `--modify-window` narrower than the resolution DCTL records — see
    /// [`crate::cli::window`].
    fn compare_policy(&self) -> Result<ComparePolicy> {
        ComparePolicy::resolve(self.globals, self.compare)
    }

    /// The plan policy implied by the whole request.
    ///
    /// Assembled through the named constructors rather than as a struct literal,
    /// so the one field that separates a `copy` from a `sync` is chosen by a
    /// word — `copying` or `syncing` — instead of by a bare `true` that a
    /// careless edit could flip.
    ///
    /// # Errors
    /// As [`Request::compare_policy`].
    fn plan_policy(&self) -> Result<Policy> {
        let compare = self.compare_policy()?;
        let base = if self.delete_extras {
            Policy::syncing(compare)
        } else {
            Policy::copying(compare)
        };
        Ok(base
            .with_empty_src_dirs(self.create_empty_src_dirs)
            .with_traversal(!self.traversal.no_traverse))
    }
}

/// Plan a directory-shaped transfer: `SOURCE`'s contents land inside `DEST`.
///
/// The shape `copy`, `move` and `sync` share. A single-file `SOURCE` is allowed
/// and lands *inside* `DEST` under its own name, matching rclone — except under
/// `sync`, where it is refused; see the module docs.
///
/// # Errors
/// Usage errors for the argument combinations described in the module docs,
/// whatever enumerating either side produces, and an `--immutable` refusal when
/// the diff would replace or remove anything at the destination.
pub async fn directory_transfer(ctx: &Ctx, request: &Request<'_>) -> Result<Prepared> {
    refuse_a_plain_write_into_a_vault(ctx, request)?;
    immutable::ensure_traversal_can_enforce_it(request.globals, &request.traversal)?;
    let prepared = diff_directory_transfer(ctx, request).await?;
    immutable::ensure_nothing_is_replaced(request.globals, &prepared.plan)?;
    Ok(prepared)
}

/// Refuse, before anything is listed, a destination this run may not write to.
///
/// The gate belongs here for the reason `--immutable`'s does: every verb in the
/// family funnels through the two public functions above, so one call site
/// covers five commands that could each forget it.
///
/// It is placed *first*, ahead of even the filter and traversal checks, for a
/// reason specific to `--dry-run`. Each verb's body reads "plan, report, stop if
/// this was a dry run, then execute", and the write path's own guard lives in
/// [`super::Engine::connect`] — after the stop. So `dctl --dry-run copy ./src
/// ./vault` printed a tidy plan to copy plaintext into a vault's object store,
/// exited 0, and the real run then refused. Every one of those statements is
/// individually defensible and together they are a lie: the whole value of a dry
/// run is that a reviewer can approve it knowing the real run does that and
/// nothing else. A rehearsal that omits the refusal is worse than no rehearsal,
/// because it is trusted.
///
/// Nothing is read from the destination to decide this — see
/// [`crate::addressing`] and invariant I4 — so asking early costs one config
/// read and cannot change the answer.
fn refuse_a_plain_write_into_a_vault(ctx: &Ctx, request: &Request<'_>) -> Result<()> {
    crate::addressing::refuse_plain_write(ctx, &RemoteSpec::parse(request.dest_spec)?)
}

/// The diff itself, without the `--immutable` gate.
///
/// Split out so the gate has exactly one call site per entry point. Folding it
/// into the body below would mean applying it next to each of the three
/// `Plan::compute` calls, and the one that eventually gets missed is a silently
/// unprotected transfer — the defect this whole file is closing.
async fn diff_directory_transfer(ctx: &Ctx, request: &Request<'_>) -> Result<Prepared> {
    let source = RemoteSpec::parse(request.source_spec)?;
    let dest = RemoteSpec::parse(request.dest_spec)?;
    reject_self_transfer(&source, &dest)?;

    let options = ListOptions::resolve(request.globals, request.create_empty_src_dirs)?;
    let source_listing = listing::source(ctx, &source, &options).await?;
    warn_about_omissions(ctx, &source_listing);

    if source_listing.is_single_file && request.delete_extras {
        return Err(CliError::usage(format!(
            "'{source}' is a file, so 'sync' would make '{dest}' contain nothing else"
        ))
        .with_hint(
            "Use 'copy' to add the file without deleting anything, or 'copyto' to \
             write it to an exact destination name.",
        ));
    }

    let dest_listing = enumerate_destination(ctx, &dest, &options, request).await?;
    reject_file_destination(&dest, &dest_listing)?;

    let plan = Plan::compute(
        &source_listing.entries,
        &dest_listing.entries,
        &request.plan_policy()?,
    )?;

    Ok(Prepared {
        source: listing_root(&source, &source_listing),
        dest,
        plan,
        dest_file_count: dest_listing.entries.len(),
    })
}

/// Plan an exact-name transfer: `SOURCE` becomes `DEST`, name and all.
///
/// The shape `copyto` and `moveto` share. A directory `SOURCE` behaves exactly
/// like [`directory_transfer`] — its contents land under `DEST` — because that
/// is already an exact-name transfer for a tree. A file `SOURCE` is the
/// interesting case: `DEST` names the object, so the plan's destination path is
/// `DEST`'s last component and its listing root is the directory above it.
///
/// # Errors
/// A usage error when `DEST` names no object (a bare root) or names an existing
/// directory, plus everything [`directory_transfer`] can raise.
pub async fn exact_transfer(ctx: &Ctx, request: &Request<'_>) -> Result<Prepared> {
    refuse_a_plain_write_into_a_vault(ctx, request)?;
    immutable::ensure_traversal_can_enforce_it(request.globals, &request.traversal)?;
    let prepared = diff_exact_transfer(ctx, request).await?;
    immutable::ensure_nothing_is_replaced(request.globals, &prepared.plan)?;
    Ok(prepared)
}

/// The exact-name diff, without the `--immutable` gate — see
/// [`diff_directory_transfer`] for why the split exists.
async fn diff_exact_transfer(ctx: &Ctx, request: &Request<'_>) -> Result<Prepared> {
    let source = RemoteSpec::parse(request.source_spec)?;
    let dest = RemoteSpec::parse(request.dest_spec)?;
    reject_self_transfer(&source, &dest)?;

    let options = ListOptions::resolve(request.globals, request.create_empty_src_dirs)?;
    let source_listing = listing::source(ctx, &source, &options).await?;
    warn_about_omissions(ctx, &source_listing);

    if !source_listing.is_single_file {
        // A whole tree under an exact name is just a directory transfer whose
        // destination root is the name itself.
        let dest_listing = enumerate_destination(ctx, &dest, &options, request).await?;
        reject_file_destination(&dest, &dest_listing)?;
        let plan = Plan::compute(
            &source_listing.entries,
            &dest_listing.entries,
            &request.plan_policy()?,
        )?;
        return Ok(Prepared {
            source,
            dest,
            plan,
            dest_file_count: dest_listing.entries.len(),
        });
    }

    let name = endpoint::leaf(&dest);
    if name.is_empty() {
        return Err(
            CliError::usage(format!("'{dest}' does not name an object")).with_hint(
                "An exact-name transfer needs a full destination path, such as \
                 'vault:archive/2024.tar'.",
            ),
        );
    }

    let source_entry = source_listing.entries.first().ok_or_else(|| {
        // The size filters can exclude the only file that was named. Silently
        // transferring nothing and reporting success is the failure mode this
        // guard exists to prevent.
        CliError::usage(format!("'{source}' was excluded by the size filters"))
            .with_hint("Relax --min-size/--max-size, or name a different file.")
    })?;

    let existing = existing_object(ctx, &dest, &options, request).await?;
    let plan = Plan::compute_exact(
        source_entry,
        existing.as_ref(),
        &name,
        &request.plan_policy()?,
    )?;

    Ok(Prepared {
        // Both sides report the *container*, because both plan paths are a bare
        // filename: `render.mov` at the source and `final.mov` at the
        // destination. Reporting the files themselves would make every composed
        // path a directory too deep.
        source: endpoint::parent(&source),
        dest: endpoint::parent(&dest),
        plan,
        dest_file_count: usize::from(existing.is_some()),
    })
}

/// The directory a listing's paths are relative to.
///
/// The same spec for a directory, and its parent for a single named file — see
/// [`Prepared::source`] for why the distinction has to survive into the report.
fn listing_root(spec: &RemoteSpec, listing: &Listing) -> RemoteSpec {
    if listing.is_single_file {
        endpoint::parent(spec)
    } else {
        spec.clone()
    }
}

/// Refuse a directory-shaped transfer into something that is already a file.
///
/// Without this the planner happily compares a tree against the one file it
/// found and produces a plan to write objects *inside* it — paths that no
/// filesystem and no vault can represent.
fn reject_file_destination(dest: &RemoteSpec, listing: &Listing) -> Result<()> {
    if listing.exists && listing.is_single_file {
        return Err(
            CliError::usage(format!("'{dest}' is a file, not a directory")).with_hint(
                "Name a directory, or use 'copyto'/'moveto' to write to an exact \
                 object name.",
            ),
        );
    }
    Ok(())
}

/// Enumerate the destination, unless `--no-traverse` said not to.
async fn enumerate_destination(
    ctx: &Ctx,
    dest: &RemoteSpec,
    options: &ListOptions,
    request: &Request<'_>,
) -> Result<Listing> {
    if request.traversal.no_traverse {
        return Ok(listing::untraversed());
    }
    listing::destination(ctx, dest, options).await
}

/// Look up the single object an exact-name transfer would overwrite.
///
/// Returns `None` when nothing is there — the ordinary case — and a usage error
/// when `DEST` is an existing directory, which cannot simultaneously be the
/// object's name and its container.
async fn existing_object(
    ctx: &Ctx,
    dest: &RemoteSpec,
    options: &ListOptions,
    request: &Request<'_>,
) -> Result<Option<Entry>> {
    if request.traversal.no_traverse {
        return Ok(None);
    }

    let listing = listing::destination(ctx, dest, options).await?;
    if !listing.exists {
        return Ok(None);
    }
    if !listing.is_single_file {
        return Err(
            CliError::usage(format!("'{dest}' is a directory")).with_hint(
                "An exact-name transfer needs the destination's full object name. \
                 Use 'copy' to place the file inside a directory instead.",
            ),
        );
    }
    Ok(listing.entries.into_iter().next())
}

/// Refuse a transfer whose two sides overlap.
///
/// Equality is only half of it. **Nesting is the dangerous half**: with
/// `sync ./data ./data/mirror`, the walk of the source enumerates the
/// destination's own contents as source files, so the plan simultaneously copies
/// `mirror/x` to `mirror/mirror/x` and deletes `mirror/x` for not existing at
/// the source. Under `--delete-before` the delete happens first and the copy
/// then fails, permanently destroying everything under `mirror/`.
///
/// It also breaks the promise `--dry-run` makes. The plan such a run prints is
/// self-contradictory and cannot be executed, so "what a dry run shows is what a
/// real run performs" would be false exactly when a user is checking before a
/// destructive operation — the moment they most need it to be true.
///
/// Both directions are refused. Source-inside-destination is the mirror image
/// and equally incoherent.
///
/// Canonicalisation resolves `./photos` versus `photos` and symlinked
/// duplicates. A canonicalisation failure is ignored rather than reported: it
/// means one side does not exist yet, which the listing step diagnoses far more
/// usefully.
fn reject_self_transfer(source: &RemoteSpec, dest: &RemoteSpec) -> Result<()> {
    if source == dest {
        return Err(same_place(source));
    }

    let (Some(source_path), Some(dest_path)) = (source.local_path(), dest.local_path()) else {
        return Ok(());
    };
    let (Ok(source_real), Ok(dest_real)) = (source_path.canonicalize(), dest_path.canonicalize())
    else {
        return Ok(());
    };

    if source_real == dest_real {
        return Err(same_place(source));
    }
    if dest_real.starts_with(&source_real) {
        return Err(nested(dest, source, "destination", "inside the source"));
    }
    if source_real.starts_with(&dest_real) {
        return Err(nested(source, dest, "source", "inside the destination"));
    }
    Ok(())
}

/// The two sides name the same place.
fn same_place(spec: &RemoteSpec) -> CliError {
    CliError::usage(format!("source and destination are the same: {spec}")).with_hint(
        "A transfer onto itself would compare a tree against itself while \
         modifying it.",
    )
}

/// One side lies within the other.
fn nested(inner: &RemoteSpec, outer: &RemoteSpec, which: &str, relation: &str) -> CliError {
    CliError::usage(format!("the {which} '{inner}' is {relation} '{outer}'")).with_hint(
        "Overlapping paths make the plan self-contradictory: the same files are \
         both transferred and deleted, and a sync would destroy them. Move one \
         side outside the other.",
    )
}

/// Report anything the walk passed over.
///
/// On stderr and unconditional (short of `--quiet`): a skipped symlink or an
/// unrepresentable filename is data the user asked for and did not get, and
/// finding that out from a restore is far too late.
///
/// The symbolic-link half is delegated to [`crate::links`], and the special-file
/// half to [`crate::specials`], rather than worded here, because the listing
/// family and `backup` have to say the same thing about the same tree — an
/// operator who checks with `ls` and then runs `copy` must not be told two
/// different stories.
fn warn_about_omissions(ctx: &Ctx, listing: &Listing) {
    if !listing.has_omissions() {
        return;
    }
    crate::links::report(ctx, &listing.links);
    crate::specials::report(ctx, &listing.specials);
    if listing.unrepresentable_skipped > 0 {
        ctx.out.warn(format!(
            "skipped {} entr(y/ies) whose names have no logical path: not valid UTF-8, \
             or containing '/' or '\\', which other platforms read as a separator",
            listing.unrepresentable_skipped
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::transfer::plan::Op;
    use crate::commands::transfer::testing::ctx;
    use crate::exit::ExitCode;
    use clap::Parser;
    use std::fs;
    use std::io::Write as _;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn globals(args: &[&str]) -> GlobalArgs {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals
    }

    fn write(path: &std::path::Path, bytes: usize) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut file = fs::File::create(path).unwrap();
        file.write_all(&vec![b'x'; bytes]).unwrap();
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        source: String,
        dest: String,
    }

    /// `src/{a.txt,sub/b.txt}` and `dst/{a.txt (different), stale.txt}`.
    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("src/a.txt"), 10);
        write(&dir.path().join("src/sub/b.txt"), 20);
        write(&dir.path().join("dst/a.txt"), 11);
        write(&dir.path().join("dst/stale.txt"), 5);

        Fixture {
            source: dir.path().join("src").to_string_lossy().into_owned(),
            dest: dir.path().join("dst").to_string_lossy().into_owned(),
            _dir: dir,
        }
    }

    fn request<'a>(
        globals: &'a GlobalArgs,
        compare: &'a CompareFlags,
        source: &'a str,
        dest: &'a str,
        delete_extras: bool,
    ) -> Request<'a> {
        Request {
            globals,
            source_spec: source,
            dest_spec: dest,
            compare,
            traversal: TraversalFlags::default(),
            create_empty_src_dirs: false,
            delete_extras,
        }
    }

    #[test]
    fn a_destination_nested_inside_the_source_is_refused() {
        // The data-loss case: `sync ./data ./data/mirror --delete-before`
        // enumerates mirror's own contents as source files, then deletes them
        // for "not existing at the source". Everything under mirror/ is gone.
        let dir = tempfile::tempdir().unwrap();
        let inner = dir.path().join("mirror");
        std::fs::create_dir_all(&inner).unwrap();

        let source = RemoteSpec::parse(dir.path().to_str().unwrap()).unwrap();
        let dest = RemoteSpec::parse(inner.to_str().unwrap()).unwrap();

        let error = reject_self_transfer(&source, &dest).unwrap_err();
        assert_eq!(error.code(), crate::exit::ExitCode::Usage);
        assert!(
            error.message().contains("inside the source"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn a_source_nested_inside_the_destination_is_refused() {
        // The mirror image, equally incoherent.
        let dir = tempfile::tempdir().unwrap();
        let inner = dir.path().join("sub");
        std::fs::create_dir_all(&inner).unwrap();

        let source = RemoteSpec::parse(inner.to_str().unwrap()).unwrap();
        let dest = RemoteSpec::parse(dir.path().to_str().unwrap()).unwrap();

        let error = reject_self_transfer(&source, &dest).unwrap_err();
        assert!(
            error.message().contains("inside the destination"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn siblings_and_lookalike_names_are_still_allowed() {
        // The guard must compare whole components: `data` is not a parent of
        // `data-backup`, and refusing that would block a legitimate transfer.
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("data");
        let b = dir.path().join("data-backup");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();

        let source = RemoteSpec::parse(a.to_str().unwrap()).unwrap();
        let dest = RemoteSpec::parse(b.to_str().unwrap()).unwrap();
        assert!(reject_self_transfer(&source, &dest).is_ok());
    }

    #[test]
    fn the_same_directory_spelled_two_ways_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let plain = RemoteSpec::parse(dir.path().to_str().unwrap()).unwrap();
        let dotted = RemoteSpec::parse(&format!("{}/.", dir.path().to_str().unwrap())).unwrap();
        assert!(reject_self_transfer(&plain, &dotted).is_err());
    }

    #[tokio::test]
    async fn a_directory_transfer_diffs_both_sides() {
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let prepared = directory_transfer(
            &ctx,
            &request(&globals, &flags, &fixture.source, &fixture.dest, false),
        )
        .await
        .unwrap();

        let mut actions: Vec<(Op, &str)> = prepared
            .plan
            .actions()
            .map(|entry| (entry.action, entry.dest.as_str()))
            .collect();
        actions.sort_by_key(|(_, path)| *path);

        assert_eq!(actions, [(Op::Update, "a.txt"), (Op::Copy, "sub/b.txt")]);
        // `copy` never deletes, so the stale file is not in the plan at all.
        assert!(!prepared.plan.destroys_anything());
        assert_eq!(prepared.dest_file_count, 2);
    }

    #[tokio::test]
    async fn a_sync_transfer_plans_the_deletions() {
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let prepared = directory_transfer(
            &ctx,
            &request(&globals, &flags, &fixture.source, &fixture.dest, true),
        )
        .await
        .unwrap();

        let deleted: Vec<&str> = prepared
            .plan
            .deletions()
            .map(|entry| entry.dest.as_str())
            .collect();
        assert_eq!(deleted, ["stale.txt"]);
    }

    #[tokio::test]
    async fn syncing_from_a_single_file_is_refused() {
        // `dctl sync photo.jpg backups/` would empty the destination. Nobody
        // means that, so it is a usage error rather than a data-loss surprise.
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let file = format!("{}/a.txt", fixture.source);

        let error =
            directory_transfer(&ctx, &request(&globals, &flags, &file, &fixture.dest, true))
                .await
                .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some_and(|hint| hint.contains("copyto")));

        // The same transfer under `copy` is perfectly ordinary.
        assert!(
            directory_transfer(
                &ctx,
                &request(&globals, &flags, &file, &fixture.dest, false)
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn a_transfer_onto_itself_is_refused() {
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();

        let error = directory_transfer(
            &ctx,
            &request(&globals, &flags, &fixture.source, &fixture.source, false),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);

        // …and the spelling does not matter: `src` and `src/.` are one place.
        let dotted = format!("{}/.", fixture.source);
        assert!(
            directory_transfer(
                &ctx,
                &request(&globals, &flags, &fixture.source, &dotted, false)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn no_traverse_plans_without_touching_the_destination() {
        // The one shape that works end-to-end against a remote today: the
        // destination is never listed, so nothing needs a vault.
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let mut req = request(&globals, &flags, &fixture.source, "vault:photos", false);
        req.traversal = TraversalFlags { no_traverse: true };

        let prepared = directory_transfer(&ctx, &req).await.unwrap();
        assert_eq!(prepared.plan.count(Op::Copy), 2);
        assert_eq!(prepared.dest_file_count, 0);
    }

    #[tokio::test]
    async fn an_exact_transfer_renames_a_single_file() {
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let file = format!("{}/a.txt", fixture.source);
        let target = format!("{}/renamed.txt", fixture.dest);

        let prepared = exact_transfer(&ctx, &request(&globals, &flags, &file, &target, false))
            .await
            .unwrap();

        assert_eq!(prepared.plan.entries.len(), 1);
        let entry = &prepared.plan.entries[0];
        assert_eq!(entry.source, "a.txt");
        assert_eq!(entry.dest, "renamed.txt");
        assert_eq!(entry.action, Op::Copy);
    }

    #[tokio::test]
    async fn an_exact_transfer_onto_a_directory_is_refused() {
        // The destination cannot be both the object's name and its container.
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let file = format!("{}/a.txt", fixture.source);

        let error = exact_transfer(
            &ctx,
            &request(&globals, &flags, &file, &fixture.dest, false),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn an_exact_transfer_compares_against_the_named_object() {
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let file = format!("{}/a.txt", fixture.source);
        let target = format!("{}/a.txt", fixture.dest);

        // Same name, different size: this is an update, not a first copy.
        let prepared = exact_transfer(&ctx, &request(&globals, &flags, &file, &target, false))
            .await
            .unwrap();
        assert_eq!(prepared.plan.entries[0].action, Op::Update);
    }

    #[tokio::test]
    async fn an_exact_destination_must_name_something() {
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let file = format!("{}/a.txt", fixture.source);

        let error = exact_transfer(&ctx, &request(&globals, &flags, &file, "vault:", false))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn an_exact_transfer_of_a_tree_behaves_like_a_directory_transfer() {
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let target = format!("{}/copy", fixture.dest);

        let prepared = exact_transfer(
            &ctx,
            &request(&globals, &flags, &fixture.source, &target, false),
        )
        .await
        .unwrap();
        assert_eq!(prepared.plan.count(Op::Copy), 2);
    }

    #[tokio::test]
    async fn a_pattern_filter_narrows_the_plan_rather_than_stopping_it() {
        // The engine is wired in, and what matters most is the `sync` direction:
        // an `--exclude` has to hide a file from *both* listings, so the
        // destination copy is not then seen as an extra and deleted. That is
        // precisely what an ignored rule used to do.
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&["--exclude", "stale.*"]);
        let flags = CompareFlags::default();
        let prepared = directory_transfer(
            &ctx,
            &request(&globals, &flags, &fixture.source, &fixture.dest, true),
        )
        .await
        .unwrap();

        let deleted: Vec<&str> = prepared
            .plan
            .deletions()
            .map(|entry| entry.dest.as_str())
            .collect();
        assert!(deleted.is_empty(), "the excluded file must be protected");

        // …while the transfers the rule says nothing about are untouched.
        let mut transferred: Vec<&str> = prepared
            .plan
            .transfers()
            .map(|entry| entry.dest.as_str())
            .collect();
        transferred.sort_unstable();
        assert_eq!(transferred, ["a.txt", "sub/b.txt"]);
    }

    #[tokio::test]
    async fn an_exclusion_that_names_a_source_file_leaves_it_behind() {
        // The other direction, and the ordinary reading of the flag.
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&["--exclude", "sub/**"]);
        let flags = CompareFlags::default();
        let prepared = directory_transfer(
            &ctx,
            &request(&globals, &flags, &fixture.source, &fixture.dest, false),
        )
        .await
        .unwrap();

        let transferred: Vec<&str> = prepared
            .plan
            .transfers()
            .map(|entry| entry.dest.as_str())
            .collect();
        assert_eq!(transferred, ["a.txt"], "sub/b.txt was excluded");
    }

    #[tokio::test]
    async fn a_malformed_pattern_stops_planning_before_anything_is_listed() {
        // A rule that will not compile cannot be honoured, and a transfer run
        // with a rule the operator believes is in force is the data-loss case.
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&["--exclude", "a{b"]);
        let flags = CompareFlags::default();
        let error = directory_transfer(
            &ctx,
            &request(&globals, &flags, &fixture.source, &fixture.dest, true),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn the_reported_roots_compose_with_the_plan_paths() {
        // A consumer joins `Prepared.source`/`.dest` to each action's relative
        // path. If a root were the file itself, every composed path would gain a
        // phantom component — and a script acting on the JSON plan would touch
        // something that does not exist.
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let file = format!("{}/a.txt", fixture.source);

        // Directory transfer of one named file: the source root is its parent.
        let prepared = directory_transfer(
            &ctx,
            &request(&globals, &flags, &file, &fixture.dest, false),
        )
        .await
        .unwrap();
        assert_eq!(prepared.source.to_string(), fixture.source);
        assert_eq!(prepared.dest.to_string(), fixture.dest);
        assert_eq!(prepared.plan.entries[0].source, "a.txt");

        // Exact-name transfer: both roots are containers.
        let target = format!("{}/renamed.txt", fixture.dest);
        let prepared = exact_transfer(&ctx, &request(&globals, &flags, &file, &target, false))
            .await
            .unwrap();
        assert_eq!(prepared.source.to_string(), fixture.source);
        assert_eq!(prepared.dest.to_string(), fixture.dest);
        assert_eq!(prepared.plan.entries[0].dest, "renamed.txt");
    }

    #[tokio::test]
    async fn a_directory_transfer_into_a_file_is_refused() {
        // Otherwise the planner compares a whole tree against the one file it
        // found and plans to write objects *inside* it.
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let file = format!("{}/a.txt", fixture.dest);

        let error = directory_transfer(
            &ctx,
            &request(&globals, &flags, &fixture.source, &file, false),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some_and(|hint| hint.contains("copyto")));
    }

    #[tokio::test]
    async fn a_missing_source_is_reported_before_the_destination_is_touched() {
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let error = directory_transfer(
            &ctx,
            &request(&globals, &flags, "/definitely/not/here", "/tmp", false),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::DirNotFound);
    }
}
