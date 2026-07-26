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
//! It is also the one place `--immutable` is applied, for the same reason: every
//! verb in the family funnels through the two public functions below, so the gate
//! sits on them rather than in five command bodies that could each forget it.
//! See [`super::immutable`] for why the decision belongs to the plan and not to
//! the write.

use crate::cli::GlobalArgs;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};

use crate::remote::RemoteSpec;

use super::compare::{ComparePolicy, ensure_filters_are_supported};
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
    fn compare_policy(&self) -> ComparePolicy {
        ComparePolicy::resolve(self.globals, self.compare)
    }

    /// The plan policy implied by the whole request.
    ///
    /// Assembled through the named constructors rather than as a struct literal,
    /// so the one field that separates a `copy` from a `sync` is chosen by a
    /// word — `copying` or `syncing` — instead of by a bare `true` that a
    /// careless edit could flip.
    fn plan_policy(&self) -> Policy {
        let compare = self.compare_policy();
        let base = if self.delete_extras {
            Policy::syncing(compare)
        } else {
            Policy::copying(compare)
        };
        base.with_empty_src_dirs(self.create_empty_src_dirs)
            .with_traversal(!self.traversal.no_traverse)
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
pub fn directory_transfer(ctx: &Ctx, request: &Request<'_>) -> Result<Prepared> {
    immutable::ensure_traversal_can_enforce_it(request.globals, &request.traversal)?;
    let prepared = diff_directory_transfer(ctx, request)?;
    immutable::ensure_nothing_is_replaced(request.globals, &prepared.plan)?;
    Ok(prepared)
}

/// The diff itself, without the `--immutable` gate.
///
/// Split out so the gate has exactly one call site per entry point. Folding it
/// into the body below would mean applying it next to each of the three
/// `Plan::compute` calls, and the one that eventually gets missed is a silently
/// unprotected transfer — the defect this whole file is closing.
fn diff_directory_transfer(ctx: &Ctx, request: &Request<'_>) -> Result<Prepared> {
    ensure_filters_are_supported(request.globals)?;

    let source = RemoteSpec::parse(request.source_spec)?;
    let dest = RemoteSpec::parse(request.dest_spec)?;
    reject_self_transfer(&source, &dest)?;

    let options = ListOptions::resolve(request.globals, request.create_empty_src_dirs)?;
    let source_listing = listing::source(&source, &options)?;
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

    let dest_listing = enumerate_destination(&dest, &options, request)?;
    reject_file_destination(&dest, &dest_listing)?;

    let plan = Plan::compute(
        &source_listing.entries,
        &dest_listing.entries,
        &request.plan_policy(),
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
pub fn exact_transfer(ctx: &Ctx, request: &Request<'_>) -> Result<Prepared> {
    immutable::ensure_traversal_can_enforce_it(request.globals, &request.traversal)?;
    let prepared = diff_exact_transfer(ctx, request)?;
    immutable::ensure_nothing_is_replaced(request.globals, &prepared.plan)?;
    Ok(prepared)
}

/// The exact-name diff, without the `--immutable` gate — see
/// [`diff_directory_transfer`] for why the split exists.
fn diff_exact_transfer(ctx: &Ctx, request: &Request<'_>) -> Result<Prepared> {
    ensure_filters_are_supported(request.globals)?;

    let source = RemoteSpec::parse(request.source_spec)?;
    let dest = RemoteSpec::parse(request.dest_spec)?;
    reject_self_transfer(&source, &dest)?;

    let options = ListOptions::resolve(request.globals, request.create_empty_src_dirs)?;
    let source_listing = listing::source(&source, &options)?;
    warn_about_omissions(ctx, &source_listing);

    if !source_listing.is_single_file {
        // A whole tree under an exact name is just a directory transfer whose
        // destination root is the name itself.
        let dest_listing = enumerate_destination(&dest, &options, request)?;
        reject_file_destination(&dest, &dest_listing)?;
        let plan = Plan::compute(
            &source_listing.entries,
            &dest_listing.entries,
            &request.plan_policy(),
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

    let existing = existing_object(&dest, &options, request)?;
    let plan = Plan::compute_exact(
        source_entry,
        existing.as_ref(),
        &name,
        &request.plan_policy(),
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
fn enumerate_destination(
    dest: &RemoteSpec,
    options: &ListOptions,
    request: &Request<'_>,
) -> Result<Listing> {
    if request.traversal.no_traverse {
        return Ok(listing::untraversed());
    }
    listing::destination(dest, options)
}

/// Look up the single object an exact-name transfer would overwrite.
///
/// Returns `None` when nothing is there — the ordinary case — and a usage error
/// when `DEST` is an existing directory, which cannot simultaneously be the
/// object's name and its container.
fn existing_object(
    dest: &RemoteSpec,
    options: &ListOptions,
    request: &Request<'_>,
) -> Result<Option<Entry>> {
    if request.traversal.no_traverse {
        return Ok(None);
    }

    let listing = listing::destination(dest, options)?;
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
fn warn_about_omissions(ctx: &Ctx, listing: &Listing) {
    if !listing.has_omissions() {
        return;
    }
    if listing.symlinks_skipped > 0 {
        ctx.out.warn(format!(
            "skipped {} symbolic link(s): links are never followed",
            listing.symlinks_skipped
        ));
    }
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

    #[test]
    fn a_directory_transfer_diffs_both_sides() {
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let prepared = directory_transfer(
            &ctx,
            &request(&globals, &flags, &fixture.source, &fixture.dest, false),
        )
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

    #[test]
    fn a_sync_transfer_plans_the_deletions() {
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let prepared = directory_transfer(
            &ctx,
            &request(&globals, &flags, &fixture.source, &fixture.dest, true),
        )
        .unwrap();

        let deleted: Vec<&str> = prepared
            .plan
            .deletions()
            .map(|entry| entry.dest.as_str())
            .collect();
        assert_eq!(deleted, ["stale.txt"]);
    }

    #[test]
    fn syncing_from_a_single_file_is_refused() {
        // `dctl sync photo.jpg backups/` would empty the destination. Nobody
        // means that, so it is a usage error rather than a data-loss surprise.
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let file = format!("{}/a.txt", fixture.source);

        let error =
            directory_transfer(&ctx, &request(&globals, &flags, &file, &fixture.dest, true))
                .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some_and(|hint| hint.contains("copyto")));

        // The same transfer under `copy` is perfectly ordinary.
        assert!(
            directory_transfer(
                &ctx,
                &request(&globals, &flags, &file, &fixture.dest, false)
            )
            .is_ok()
        );
    }

    #[test]
    fn a_transfer_onto_itself_is_refused() {
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();

        let error = directory_transfer(
            &ctx,
            &request(&globals, &flags, &fixture.source, &fixture.source, false),
        )
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);

        // …and the spelling does not matter: `src` and `src/.` are one place.
        let dotted = format!("{}/.", fixture.source);
        assert!(
            directory_transfer(
                &ctx,
                &request(&globals, &flags, &fixture.source, &dotted, false)
            )
            .is_err()
        );
    }

    #[test]
    fn no_traverse_plans_without_touching_the_destination() {
        // The one shape that works end-to-end against a remote today: the
        // destination is never listed, so nothing needs a vault.
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let mut req = request(&globals, &flags, &fixture.source, "vault:photos", false);
        req.traversal = TraversalFlags { no_traverse: true };

        let prepared = directory_transfer(&ctx, &req).unwrap();
        assert_eq!(prepared.plan.count(Op::Copy), 2);
        assert_eq!(prepared.dest_file_count, 0);
    }

    #[test]
    fn an_exact_transfer_renames_a_single_file() {
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let file = format!("{}/a.txt", fixture.source);
        let target = format!("{}/renamed.txt", fixture.dest);

        let prepared =
            exact_transfer(&ctx, &request(&globals, &flags, &file, &target, false)).unwrap();

        assert_eq!(prepared.plan.entries.len(), 1);
        let entry = &prepared.plan.entries[0];
        assert_eq!(entry.source, "a.txt");
        assert_eq!(entry.dest, "renamed.txt");
        assert_eq!(entry.action, Op::Copy);
    }

    #[test]
    fn an_exact_transfer_onto_a_directory_is_refused() {
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
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[test]
    fn an_exact_transfer_compares_against_the_named_object() {
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let file = format!("{}/a.txt", fixture.source);
        let target = format!("{}/a.txt", fixture.dest);

        // Same name, different size: this is an update, not a first copy.
        let prepared =
            exact_transfer(&ctx, &request(&globals, &flags, &file, &target, false)).unwrap();
        assert_eq!(prepared.plan.entries[0].action, Op::Update);
    }

    #[test]
    fn an_exact_destination_must_name_something() {
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let file = format!("{}/a.txt", fixture.source);

        let error =
            exact_transfer(&ctx, &request(&globals, &flags, &file, "vault:", false)).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[test]
    fn an_exact_transfer_of_a_tree_behaves_like_a_directory_transfer() {
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let target = format!("{}/copy", fixture.dest);

        let prepared = exact_transfer(
            &ctx,
            &request(&globals, &flags, &fixture.source, &target, false),
        )
        .unwrap();
        assert_eq!(prepared.plan.count(Op::Copy), 2);
    }

    #[test]
    fn a_pattern_filter_stops_planning_before_anything_is_listed() {
        // The refusal has to come first: a plan computed with the filter ignored
        // would be a plan to delete the protected files.
        let fixture = fixture();
        let ctx = ctx(&[]);
        let globals = globals(&["--exclude", "*.tmp"]);
        let flags = CompareFlags::default();
        let error = directory_transfer(
            &ctx,
            &request(&globals, &flags, &fixture.source, &fixture.dest, true),
        )
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
    }

    #[test]
    fn the_reported_roots_compose_with_the_plan_paths() {
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
        .unwrap();
        assert_eq!(prepared.source.to_string(), fixture.source);
        assert_eq!(prepared.dest.to_string(), fixture.dest);
        assert_eq!(prepared.plan.entries[0].source, "a.txt");

        // Exact-name transfer: both roots are containers.
        let target = format!("{}/renamed.txt", fixture.dest);
        let prepared =
            exact_transfer(&ctx, &request(&globals, &flags, &file, &target, false)).unwrap();
        assert_eq!(prepared.source.to_string(), fixture.source);
        assert_eq!(prepared.dest.to_string(), fixture.dest);
        assert_eq!(prepared.plan.entries[0].dest, "renamed.txt");
    }

    #[test]
    fn a_directory_transfer_into_a_file_is_refused() {
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
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some_and(|hint| hint.contains("copyto")));
    }

    #[test]
    fn a_missing_source_is_reported_before_the_destination_is_touched() {
        let ctx = ctx(&[]);
        let globals = globals(&[]);
        let flags = CompareFlags::default();
        let error = directory_transfer(
            &ctx,
            &request(&globals, &flags, "/definitely/not/here", "/tmp", false),
        )
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::DirNotFound);
    }
}
