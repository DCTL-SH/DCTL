//! Enumerating one side of a transfer.
//!
//! A plan is a diff, and a diff needs both sides listed before it can name a
//! single action. This module turns a [`RemoteSpec`] into the [`Entry`] set the
//! planner compares — for a local tree by walking it, and for a named remote
//! through [`crate::source`].
//!
//! ## Why a named remote goes through `crate::source` and not through a walk
//!
//! [`crate::source::open`] is the one place in the binary that decides whether a
//! spec addresses a sealed vault or a plain object store, and it is deliberately
//! the *only* place: a command that could tell would eventually add a second
//! `if` and get it wrong, which in this family means writing data somewhere
//! nobody named. So this module asks for a [`Source`](crate::source::Source) and
//! never learns which kind it got. The prefix rule (whole path components, so
//! listing `photos` never reports `photos-backup`), the plaintext sizes and the
//! recorded content hashes all arrive with it, already correct.
//!
//! That is what makes a vault a transfer **source**. `dctl copy archive: ./out`,
//! `dctl sync archive: ./mirror` and `dctl check ./src archive:` are all the same
//! diff as before with one side enumerated differently, so none of the planning,
//! reporting or execution above this file changed to gain them.
//!
//! ## What is honoured
//!
//! Every filter, through one engine. [`crate::filter::FilterSet`] evaluates
//! `--include`, `--exclude`, `--filter-from`, `--files-from`, `--min-size`,
//! `--max-size` and `--max-depth`, and it does so identically for the local walk
//! and the remote listing — which is the point of there being one engine. A rule
//! that meant two things on the two sides of a `sync` would show a file on one
//! side, hide it on the other, and delete it for being an extra.
//!
//! `--checksum` is the one filter-adjacent flag with a cost, and it is paid
//! here: a vault side carries the hash it recorded at write time, and a local
//! side is read and hashed ([`super::checksum`]). Both are only produced when
//! the flag asked for them, because hashing a local tree costs the entire read
//! the transfer itself would.
//!
//! ## Memory
//!
//! The listing is materialised into a `Vec`. `PLAN.md` §16.2 asks for streaming
//! everything, and the streaming diff genuinely belongs in `dctl-core` — but a
//! `sync` cannot name a destination *extra* until it has seen the whole source,
//! so some state is unavoidable and the honest place for the streaming,
//! on-disk-backed version is the engine that also does the transferring. What is
//! here is bounded by the filters, and is the same shape the engine consumes.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dctl_store::SpecialReport;
use dctl_store::links::{
    Ancestors, LinkPolicy, LinkReport, LinkTarget, LinkVerdict, decide, local_dir_id,
};

use crate::cli::GlobalArgs;
use crate::constants::CHECKSUM_READS_DESTINATION_NOTE;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::filter::FilterSet;
use crate::platform::path as logical;
use crate::remote::RemoteSpec;

use super::checksum;
use super::entry::Entry;

/// Which entries a walk keeps, and how hard it works to describe them.
///
/// The default admits everything and hashes nothing, which is what
/// [`FilterSet::everything`] and an unset `--checksum` mean.
#[derive(Clone, Debug, Default)]
pub struct ListOptions {
    /// The one filter engine, built from the global flags.
    ///
    /// Held rather than re-derived per side so the two listings a diff compares
    /// were produced by the identical rule set — the property that keeps a
    /// `sync` from deleting what an `--exclude` was written to protect.
    filter: FilterSet,
    /// Whether directories containing nothing are reported.
    ///
    /// Off unless `--create-empty-src-dirs` is given: an empty directory has no
    /// objects under it, so listing one costs a plan entry that would otherwise
    /// never turn into an action.
    pub include_empty_dirs: bool,
    /// Whether every entry must carry a content hash.
    ///
    /// A separate flag rather than something inferred from the comparison
    /// policy, because it is the *listing* that pays for it: a vault answers
    /// from its index for free, and a local tree is read end to end.
    ///
    /// Set by `--checksum` and by nothing else. A transfer used to raise it on
    /// its own whenever a side was a vault — a vault could not be compared by
    /// modification time, so content was substituted — which made an ordinary
    /// `copy` read its whole source tree. The vault records the source's time
    /// now, so the substitution and the flag it set are both gone.
    pub hash_contents: bool,
    /// What the local walk does with the symbolic links it finds.
    ///
    /// Carried on the options beside the filters, and for the same reason: the
    /// two sides of a diff must have been enumerated under identical rules. A
    /// `sync` whose source followed links and whose destination did not would
    /// see the followed files as destination *extras* and delete them.
    pub links: LinkPolicy,
}

impl ListOptions {
    /// Resolve the walk's limits from the global flags.
    ///
    /// # Errors
    /// [`ExitCode::Usage`] when a pattern will not compile, a size or depth does
    /// not parse, the two size bounds cross (a range no file can match would
    /// silently transfer nothing, and "nothing happened" is the hardest failure
    /// to notice), or a `--filter-from`/`--files-from` file cannot be read.
    pub fn resolve(globals: &GlobalArgs, include_empty_dirs: bool) -> Result<Self> {
        Ok(Self {
            filter: FilterSet::from_globals(globals)?,
            include_empty_dirs,
            hash_contents: globals.checksum,
            links: globals.links,
        })
    }

    /// Whether a file at this logical path and size is in scope.
    ///
    /// Asked in the form that also checks the file's ancestor directories
    /// ([`FilterSet::admits_enumerated`]), because the two enumerations below do
    /// not both prune. [`walk_local`] descends deliberately and refuses to open
    /// a directory a `--exclude 'cache/'` rule named; [`walk_remote`] receives a
    /// flat set of keys from an index or a provider and has no descent to
    /// refuse. Asking the cheaper question there would make one rule mean two
    /// things depending on which side of a transfer it landed on — and a `sync`
    /// whose two sides disagree deletes the difference.
    ///
    /// For the walking side the ancestor check is redundant rather than wrong:
    /// every file it offers has already come out of a directory it chose to
    /// enter, so the extra question can only agree.
    ///
    /// `modified` is the file's own last-modified time in unix seconds, when the
    /// side reporting it has one. It is a parameter rather than something the
    /// filter looks up because only the caller has it, and `--min-age` and
    /// `--max-age` silently doing nothing is exactly the failure this signature
    /// prevents: adding the flags without threading the time would have compiled.
    #[must_use]
    pub fn accepts_file(&self, path: &str, size: u64, modified: Option<i64>) -> bool {
        self.filter
            .admits_enumerated(&crate::filter::Candidate::file(path, size).at(modified))
    }

    /// Whether a file whose size nothing has measured is in scope.
    ///
    /// A separate method rather than an [`Option`] parameter, because every
    /// local walk in this file knows its sizes and would otherwise have to spell
    /// `Some(..)` at each call — which is where the one call site that should
    /// have said `None` eventually gets written as `Some(0)`. The size bounds do
    /// not apply here; see [`crate::filter::Candidate::unmeasured_file`] for the
    /// full argument, which is the same one the listing family follows so that
    /// `dctl ls --min-size` and the `copy` after it select the same files.
    pub fn accepts_unmeasured_file(&self, path: &str, modified: Option<i64>) -> bool {
        self.filter
            .admits_enumerated(&crate::filter::Candidate::unmeasured_file(path).at(modified))
    }

    /// Whether a walk may descend into this directory.
    ///
    /// Distinct from [`ListOptions::accepts_dir`]: a directory that is itself
    /// out of scope must still be entered when the rule that refused it says
    /// nothing about the tree below it. See [`FilterSet::may_descend`].
    #[must_use]
    pub fn may_descend(&self, path: &str) -> bool {
        self.filter.may_descend(path)
    }

    /// Whether an empty directory is itself in scope.
    #[must_use]
    pub fn accepts_dir(&self, path: &str) -> bool {
        self.filter.admits_dir(path)
    }
}

/// What one side of a transfer turned out to contain.
#[derive(Debug, Default)]
pub struct Listing {
    /// Entries found, with logical paths relative to the listing root.
    pub entries: Vec<Entry>,
    /// True when the endpoint named a single file rather than a directory.
    ///
    /// The exact-name commands (`copyto`, `moveto`) branch on this, and `copy`
    /// uses it to place a lone file *inside* the destination directory rather
    /// than treating the destination as its new name.
    pub is_single_file: bool,
    /// Whether the endpoint exists at all.
    pub exists: bool,
    /// What the walk did about every symbolic link it met: counts, and a bounded
    /// sample of names. Reported rather than hidden — see [`crate::links`] for
    /// why silence here was the one defect that destroyed data without saying
    /// so.
    pub links: LinkReport,
    /// What the walk met that was neither a file, a directory nor a link: a
    /// fifo, a socket, a device node. Counted and sampled by name, and reported
    /// for the same reason the links are — a tree holding a pipe copied as
    /// `Files: 1 / 1, Errors: 0` with the pipe named nowhere at any verbosity.
    pub specials: SpecialReport,
    /// Entries with no logical path: a name that is not valid UTF-8, or one
    /// containing a character another platform reads as a separator (see
    /// [`crate::platform::path`]). They cannot be stored under a name the user
    /// could later address, and they cannot be silently dropped either.
    pub unrepresentable_skipped: u64,
    /// Groups of local files whose names collapse onto one logical path.
    ///
    /// Only a local walk can populate this: two spellings of one name are two
    /// files on disk, and by the time they have become logical paths they are
    /// the same string. A remote listing is keyed by logical path already, so
    /// it cannot contain a collision — and if it could, the objects would
    /// already exist and refusing to read them would help nobody.
    ///
    /// See [`crate::platform::collision`] for why the run is refused rather
    /// than warned about.
    pub collisions: Vec<crate::platform::collision::Collision>,
}

impl Listing {
    /// Whether anything at all was skipped and therefore deserves a warning.
    #[must_use]
    pub fn has_omissions(&self) -> bool {
        crate::links::needs_saying(&self.links)
            || crate::specials::needs_saying(&self.specials)
            || self.unrepresentable_skipped > 0
    }
}

/// Enumerate the source side.
///
/// A missing source is an error: the user named something that is not there, and
/// continuing would report a successful transfer of nothing.
///
/// # Errors
/// [`ExitCode::DirNotFound`] when the endpoint does not exist;
/// [`ExitCode::FatalError`] when two or more local files share one logical path
/// once their names are normalised, which is refused before anything is read
/// (see [`crate::platform::collision`]); plus whatever opening or reading the
/// remote reported.
pub async fn source(ctx: &Ctx, endpoint: &RemoteSpec, options: &ListOptions) -> Result<Listing> {
    let listing = enumerate(ctx, endpoint, options, Side::Source).await?;
    if !listing.exists {
        return Err(CliError::new(
            ExitCode::DirNotFound,
            format!("source not found: {endpoint}"),
        )
        .with_hint("Check the path, and the remote name if one was given."));
    }
    // Every transfer verb's source side arrives here, which is why the refusal
    // lives at this one point rather than in each of `copy`, `sync`, `move`,
    // `copyto` and `moveto`. It is the source that matters: these are files the
    // command is about to promise it transferred, and only one of them can
    // exist at the destination.
    crate::platform::collision::refuse(&listing.collisions, false)?;
    Ok(listing)
}

/// Enumerate the destination side.
///
/// A missing destination is *not* an error — it is the ordinary first run, and
/// the answer is simply that nothing is there yet.
///
/// # Errors
/// I/O errors from the walk, and whatever opening or reading the remote
/// reported.
pub async fn destination(
    ctx: &Ctx,
    endpoint: &RemoteSpec,
    options: &ListOptions,
) -> Result<Listing> {
    enumerate(ctx, endpoint, options, Side::Destination).await
}

/// Which side of the transfer a walk is enumerating.
///
/// The destination side is the one a transfer is about to make promises
/// against, so it enumerates through
/// [`Source::enumerate_destination`](crate::source::Source::enumerate_destination)
/// — the listing that answers for the store, and marks index rows whose
/// object is gone. The source side keeps the ordinary listing and its price.
#[derive(Clone, Copy)]
enum Side {
    Source,
    Destination,
}

/// A destination that will not be listed at all (`--no-traverse`).
///
/// Returned instead of an empty [`Listing`] so the two cases stay
/// distinguishable: "nothing is there" and "we did not look" produce the same
/// plan but very different reasons, and the plan prints the reason.
#[must_use]
pub fn untraversed() -> Listing {
    Listing {
        exists: true,
        ..Listing::default()
    }
}

/// Enumerate an endpoint, whatever it turns out to be.
///
/// `side` matters only for a named remote: a local directory's listing is the
/// filesystem itself, and there is nothing for a destination walk to
/// reconcile it against.
async fn enumerate(
    ctx: &Ctx,
    endpoint: &RemoteSpec,
    options: &ListOptions,
    side: Side,
) -> Result<Listing> {
    match endpoint {
        RemoteSpec::Named { .. } => walk_remote(ctx, endpoint, options, side).await,
        RemoteSpec::Local(root) => walk_local(root, options),
    }
}

/// List everything under a named remote's prefix.
///
/// The listing arrives already ordered, already scoped to whole path components
/// and already carrying plaintext sizes, because [`crate::source`] guarantees
/// all three. What is left to do here is the part that is specific to a
/// *transfer*: re-rooting each path at the prefix the user named, applying the
/// filters, and deciding whether the prefix named one object or a tree.
///
/// The prefix is the **opened source's**, never the spec's. They differ on a
/// provider shorthand — `b2:DCTL001/photos` names the bucket `DCTL001` and the
/// prefix `photos` inside it — and using the spec's would enumerate a subtree
/// that cannot exist, so the transfer would see an empty destination and copy
/// everything again on every run. See [`crate::source::Opened`].
async fn walk_remote(
    ctx: &Ctx,
    endpoint: &RemoteSpec,
    options: &ListOptions,
    side: Side,
) -> Result<Listing> {
    let opened = crate::source::open(ctx, endpoint).await?;
    let prefix = opened.prefix().to_string();
    let prefix = prefix.as_str();
    let source = opened.into_source();
    let mut cursor = match side {
        Side::Source => source.enumerate(prefix).await?,
        // The side a transfer makes promises against answers for the store,
        // not for a local record of it — see `Source::enumerate_destination`.
        Side::Destination => source.enumerate_destination(prefix).await?,
    };

    let mut listing = Listing::default();
    // The object the prefix names exactly, if there is one. Held rather than
    // acted on inside the loop because a prefix can legitimately match both an
    // object and a tree beneath it, and only a second pass over the *whole*
    // listing establishes which shape was addressed.
    let mut exact: Option<crate::source::Entry> = None;

    while let Some(object) = cursor.next().await? {
        listing.exists = true;
        if object.path == prefix {
            exact = Some(object);
            continue;
        }
        let relative = relative_to(prefix, &object.path);
        if accepts(options, &relative, object.size, object.modified_unix) {
            listing
                .entries
                .push(remote_entry(ctx, source.as_ref(), relative, &object, options).await?);
        }
    }

    if let Some(object) = exact {
        // One object, addressed by its full path: `copy archive:notes/today.md
        // ./out` must land `today.md` in `./out` rather than recreating
        // `notes/` under it. Its logical path relative to the listing root is
        // therefore its own name — exactly the shape a lone local file produces.
        listing.is_single_file = true;
        listing.entries.clear();

        let leaf = logical::file_name(prefix).to_string();
        if accepts(options, &leaf, object.size, object.modified_unix) {
            listing
                .entries
                .push(remote_entry(ctx, source.as_ref(), leaf, &object, options).await?);
        }
    }

    // Taken from the exhausted cursor, because a skipped link produced no
    // object for the loop above to have seen. `local:` and `sftp:` are remotes
    // like any other here, and they are exactly the two that walk a filesystem:
    // `dctl copy local:/srv b2:archive` reaches this function and not the local
    // walk below, which is why the report has to travel with the listing rather
    // than being produced by whichever code path happened to enumerate.
    listing.links = cursor.links();
    listing.specials = cursor.specials();

    // Deterministic order, matching the local walk, so a plan printed twice is
    // byte-identical whichever side produced it.
    listing.entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(listing)
}

/// Ask the filter about one enumerated remote object, measured or not.
///
/// One place, so the two call sites above cannot answer the question two ways.
fn accepts(options: &ListOptions, path: &str, size: Option<u64>, modified: Option<i64>) -> bool {
    size.map_or_else(
        || options.accepts_unmeasured_file(path, modified),
        |size| options.accepts_file(path, size, modified),
    )
}

/// Build a transfer entry from one enumerated object.
///
/// The content hash is carried across only when `--checksum` asked for one.
/// Attaching it unconditionally would make a plan's JSON differ between a vault
/// side and a local side for reasons that have nothing to do with the transfer —
/// and, since a plain store has to *read* an object to answer, would put a full
/// pass over the remote behind a flag nobody set.
///
/// Where the digest comes from is [`Source::content_hash`]'s business and not
/// this function's, and the difference between the two implementations is the
/// whole of the fix: the listing itself carries one only for a vault, so reading
/// `object.content_hash` and stopping there is what made `--checksum` into a
/// plain remote fail on every run after the first.
async fn remote_entry(
    ctx: &Ctx,
    source: &dyn crate::source::Source,
    relative: String,
    object: &crate::source::Entry,
    options: &ListOptions,
) -> Result<Entry> {
    // An object the index never measured becomes an entry that says so, rather
    // than one claiming zero bytes: see `Entry::size` for what comparing that
    // zero would have skipped.
    let mut entry = match object.size {
        Some(size) => Entry::file(relative, size),
        None => Entry::unmeasured_file(relative),
    };
    // The reconciliation mark travels with the entry so the planner sees it;
    // it is never set on a source-side or ordinary listing.
    entry.object_missing = object.object_missing;
    if let Some(modified) = object.modified_unix.and_then(unix_seconds) {
        entry = entry.with_modified(modified);
    }
    if options.hash_contents {
        // The listing's own digest first — a vault index row carries one and
        // costs nothing. Only when it does not is the source asked, which for a
        // plain store means reading the object.
        entry.hash = match object.content_hash.as_deref() {
            Some(digest) => Some(checksum::encode(digest)),
            None => {
                announce_destination_read(ctx, source);
                source
                    .content_hash(&object.path)
                    .await?
                    .as_deref()
                    .map(checksum::encode)
            }
        };
    }
    Ok(entry)
}

/// Say once, on stderr, that `--checksum` is about to read the remote side.
///
/// A warning rather than a note, and therefore visible without `-v`, because it
/// is a cost the operator is about to pay on every run of a scheduled job: a
/// full read of the destination tree, which on a metered provider is an egress
/// bill. rclone announces its own `--checksum` degradation exactly once per run
/// for the same reason, and once is the right number — a line per object would
/// be noise nobody reads.
///
/// Not emitted for a source that answers from an index: a vault costs nothing
/// and a warning about it would be false.
fn announce_destination_read(ctx: &Ctx, source: &dyn crate::source::Source) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static ANNOUNCED: AtomicBool = AtomicBool::new(false);
    let _ = source;
    if !ANNOUNCED.swap(true, Ordering::Relaxed) {
        ctx.out.warn(CHECKSUM_READS_DESTINATION_NOTE);
    }
}

/// Turn a unix timestamp into a [`SystemTime`], including before the epoch.
///
/// `None` for a value no clock can represent, which keeps "unknown" and "the
/// epoch" distinguishable — a side that reported no usable time must not make
/// every file look older than every local file and invert `--update`.
/// A local file's modification time in unix seconds, when the filesystem has one.
///
/// The inverse of [`unix_seconds`], and the reason the age filter can be applied
/// during the walk rather than after it: a file `--max-age` excludes is one this
/// side never opens, hashes or reports.
///
/// A filesystem that records no time, or a time before the epoch that will not
/// fit, yields [`None`] — which the age bounds admit rather than guess at. See
/// [`crate::filter::AgeBounds`].
fn local_modified(metadata: &fs::Metadata) -> Option<i64> {
    let modified = metadata.modified().ok()?;
    match modified.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(since) => i64::try_from(since.as_secs()).ok(),
        Err(before) => i64::try_from(before.duration().as_secs())
            .ok()
            .and_then(i64::checked_neg),
    }
}

fn unix_seconds(seconds: i64) -> Option<SystemTime> {
    if seconds >= 0 {
        u64::try_from(seconds)
            .ok()
            .and_then(|secs| SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs)))
    } else {
        seconds
            .checked_neg()
            .and_then(|secs| u64::try_from(secs).ok())
            .and_then(|secs| SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(secs)))
    }
}

/// A logical path re-rooted at `prefix`.
///
/// Whole-component comparison is already guaranteed by the source, so this only
/// has to remove the prefix and the separator behind it. An empty result means
/// the path *is* the prefix.
fn relative_to(prefix: &str, path: &str) -> String {
    if prefix.is_empty() {
        return path.to_string();
    }
    path.strip_prefix(prefix).map_or_else(
        || path.to_string(),
        |rest| {
            rest.trim_start_matches(crate::constants::PATH_SEPARATOR)
                .to_string()
        },
    )
}

/// Walk a local tree, breadth-first, without recursion.
///
/// An explicit stack rather than a recursive function: a deeply nested tree is a
/// legitimate input, and a stack overflow is an abort with no error message, no
/// exit code, and no audit record — the one failure mode this crate's lint
/// configuration cannot express but must still avoid.
fn walk_local(root: &Path, options: &ListOptions) -> Result<Listing> {
    let mut listing = Listing::default();
    // Fed as the walk goes, because the native spelling is available only here:
    // an `Entry` deliberately carries the logical path and nothing else, and by
    // then both spellings have already become one string.
    let mut collisions = crate::platform::collision::Detector::new();

    // The link a walk *starts from* is not the links it *finds*, and applying
    // one rule to both was a data-loss path.
    //
    // `--links` decides the links a walk *finds*, and never reaches the root:
    // the root is entered exactly once and it *is* what the user named, so
    // `/data -> /mnt/disk/data` typed as the source is an ordinary layout and
    // not an escape from a tree. See `dctl_store::links` for the policy itself.
    //
    // Refusing it produced an empty listing with `exists = true`, so `dctl copy`
    // stored nothing and printed `Files: 0 / 0  Errors: 0` with exit 0, and
    // `dctl sync --force` read the same emptiness as permission to delete every
    // object at the destination. `dctl ls`, `dctl size`, `dctl tree`, `dctl
    // check` and `dctl backup` all resolved the root already, so the tree the
    // operator was shown was not the tree the transfer walked.
    let Ok(named) = fs::symlink_metadata(root) else {
        return Ok(listing);
    };
    let metadata = if named.file_type().is_symlink() {
        // A link with nothing behind it names nothing. It is the same missing
        // source as any other unreadable path — reported as "does not exist"
        // rather than as a tree that legitimately holds no files, which is the
        // distinction `sync` deletes on.
        let Ok(target) = fs::metadata(root) else {
            return Ok(listing);
        };
        target
    } else {
        named
    };
    listing.exists = true;

    if metadata.is_file() {
        // A lone file: its logical path is its own name, taken relative to the
        // directory that contains it.
        listing.is_single_file = true;
        match root.file_name().map(logical::to_logical_component) {
            Some(Ok(name)) => {
                if options.accepts_file(&name, metadata.len(), local_modified(&metadata)) {
                    listing
                        .entries
                        .push(file_entry(name, root, &metadata, options)?);
                }
            }
            // Either the name has no logical spelling, or the path ends in `..`
            // and names nothing at all. Both are a file the user asked for and
            // will not get, so both are counted.
            Some(Err(_)) | None => listing.unrepresentable_skipped += 1,
        }
        return Ok(listing);
    }

    if !metadata.is_dir() {
        // A socket, device or FIFO named directly: there is no tree beneath it
        // and no bytes a transfer could carry. Not counted as a skipped link,
        // because it is not one — the root's link, if there was one, has already
        // been resolved above. Counted as the special file it is, though:
        // `dctl copy /run/docker.sock backup:` used to report `Files: 0 / 0,
        // Errors: 0` and exit 0, which is the same wordless success over an
        // unrepresented source as every other case in this pass.
        listing.specials.observe(
            root.file_name().map_or_else(
                || root.display().to_string(),
                |name| name.to_string_lossy().into_owned(),
            ),
            crate::specials::kind_of(&metadata),
        );
        return Ok(listing);
    }

    // Resolved once, and only when something will ask: `in-tree` is the only
    // policy that needs to know where a link landed.
    let confine = if options.links.confined() {
        fs::canonicalize(root).ok()
    } else {
        None
    };

    // (directory, its logical path relative to the root, the chain above it)
    //
    // The chain is `None` unless links are followed. With nothing to follow
    // there is no cycle to close, so an ordinary walk builds no chain and pays
    // nothing for the guard.
    let mut stack: Vec<(PathBuf, String, Option<Arc<Ancestors>>)> = vec![(
        root.to_path_buf(),
        String::new(),
        options
            .links
            .follows()
            .then(|| Ancestors::root(local_dir_id(&metadata, root))),
    )];

    while let Some((directory, prefix, ancestors)) = stack.pop() {
        let children = fs::read_dir(&directory).map_err(|error| {
            CliError::from(error).with_hint(format!("Could not read {}", directory.display()))
        })?;

        let mut child_count = 0_u64;
        for child in children {
            let child = child?;
            child_count += 1;

            // One gate for every name, shared with the backup scan: a name that
            // is not UTF-8, or that contains a separator some other platform
            // would split on, has no logical path and cannot be stored under one
            // the user could later name.
            let name = match logical::to_logical_component(&child.file_name()) {
                Ok(name) => name,
                Err(_) => {
                    listing.unrepresentable_skipped += 1;
                    continue;
                }
            };
            let path = logical::join(&prefix, &name);

            // `symlink_metadata` rather than `metadata`: the difference *is* the
            // symlink policy, and following one here would silently undo it.
            let metadata = match fs::symlink_metadata(child.path()) {
                Ok(metadata) => metadata,
                Err(_) => {
                    // A file that vanished mid-walk is not this command's
                    // problem to solve, but it is not an entry either.
                    continue;
                }
            };

            // The two questions this walk asks about an entry — what is it, and
            // may it be entered — are the same two for a link and for anything
            // else. What differs is that a link's answer has to be *fetched*,
            // and that skipping one is a fact the run has to report.
            let metadata = if metadata.file_type().is_symlink() {
                match resolve_link(
                    &mut listing.links,
                    options.links,
                    confine.as_deref(),
                    ancestors.as_ref(),
                    &child.path(),
                    &path,
                ) {
                    Some(resolved) => resolved,
                    None => continue,
                }
            } else {
                metadata
            };

            if metadata.is_dir() {
                if options.may_descend(&path) {
                    let child_path = child.path();
                    // The metadata in hand, never a second `stat`: for a plain
                    // directory it is the one already read, and for a followed
                    // link it is the target's, which is the identity a cycle is
                    // detected against.
                    let chain = ancestors
                        .as_ref()
                        .map(|chain| chain.child(local_dir_id(&metadata, &child_path)));
                    stack.push((child_path, path, chain));
                }
            } else if metadata.is_file() {
                if options.accepts_file(&path, metadata.len(), local_modified(&metadata)) {
                    collisions.observe(&path, &child.path());
                    listing
                        .entries
                        .push(file_entry(path, &child.path(), &metadata, options)?);
                }
            } else {
                // A fifo, socket or device node. Unreachable for a *followed*
                // link — `resolve_link` has already answered `NotStorable` and
                // skipped one of those — so this is always the entry's own type,
                // and the mode it is classified from is the one already read.
                //
                // Reported before the filters and not after: an `--include` was
                // never asked about it, because it produced no entry to ask
                // about. The filter decides what is transferred, never what is
                // disclosed.
                listing
                    .specials
                    .observe(path, crate::specials::kind_of(&metadata));
            }
        }

        // An empty directory holds no objects, so it would vanish through a
        // vault unless it is carried across explicitly.
        if child_count == 0
            && !prefix.is_empty()
            && options.include_empty_dirs
            && options.accepts_dir(&prefix)
        {
            listing.entries.push(Entry::empty_dir(prefix));
        }
    }

    // Deterministic order, so a plan printed twice is byte-identical and a diff
    // of two dry runs shows only what actually changed.
    listing.entries.sort_by(|a, b| a.path.cmp(&b.path));
    listing.collisions = collisions.finish();
    Ok(listing)
}

/// Decide one symbolic link, returning the target's metadata when it is to be
/// followed and [`None`] when it is not.
///
/// Every `None` has first been *recorded*: the count is what a run reports and
/// the reason is what `-v` prints, so there is no path out of this function that
/// drops an entry without saying so. That was the defect.
fn resolve_link(
    report: &mut LinkReport,
    policy: LinkPolicy,
    confine: Option<&Path>,
    ancestors: Option<&Arc<Ancestors>>,
    native: &Path,
    logical: &str,
) -> Option<fs::Metadata> {
    if !policy.follows() {
        report.observe(logical, decide(policy, LinkTarget::Unread));
        return None;
    }

    // The one look behind the link: `metadata` traverses where
    // `symlink_metadata` above deliberately did not.
    let Ok(target) = fs::metadata(native) else {
        // Includes `ELOOP` from a link that points at itself, which the
        // filesystem refuses to resolve before this walk can.
        report.observe(logical, decide(policy, LinkTarget::Missing));
        return None;
    };

    let landed = match confine {
        None => LinkTarget::Inside,
        Some(base) => match fs::canonicalize(native) {
            Ok(resolved) if resolved.starts_with(base) => LinkTarget::Inside,
            Ok(_) => LinkTarget::Outside,
            Err(_) => LinkTarget::Missing,
        },
    };

    let verdict = decide(policy, landed);
    if !verdict.followed() {
        report.observe(logical, verdict);
        return None;
    }

    if target.is_dir() {
        let id = local_dir_id(&target, native);
        if ancestors.is_some_and(|chain| chain.contains(&id)) {
            report.observe(logical, LinkVerdict::Cycle);
            return None;
        }
    } else if !target.is_file() {
        report.observe(logical, LinkVerdict::NotStorable);
        return None;
    }

    report.observe(logical, LinkVerdict::Followed);
    Some(target)
}

/// Build a file entry from filesystem metadata.
///
/// # Errors
/// Only under `--checksum`, and only when the file cannot be read: a hash that
/// could not be computed is refused rather than left absent, because an absent
/// hash is what [`super::compare`] reads as "this side cannot answer".
fn file_entry(
    path: String,
    native: &Path,
    metadata: &fs::Metadata,
    options: &ListOptions,
) -> Result<Entry> {
    let mut entry = Entry::file(path, metadata.len());
    // A filesystem that does not record modification times leaves the field
    // unset, which is honest: substituting `now` would make every file look
    // freshly modified on every run and re-transfer the whole tree.
    if let Ok(modified) = metadata.modified() {
        entry = entry.with_modified(modified);
    }
    if options.hash_contents {
        entry.hash = Some(checksum::of_file(native)?);
    }
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::transfer::testing::ctx;
    use clap::Parser;
    use std::fs::File;
    use std::io::Write as _;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn globals(args: &[&str]) -> GlobalArgs {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals
    }

    fn options(args: &[&str]) -> ListOptions {
        ListOptions::resolve(&globals(args), false).unwrap()
    }

    /// Build a small tree: `a.txt`, `sub/b.txt`, `sub/deep/c.txt`, `empty/`.
    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("sub/deep")).unwrap();
        fs::create_dir_all(root.join("empty")).unwrap();

        for (path, bytes) in [
            ("a.txt", 1_usize),
            ("sub/b.txt", 20),
            ("sub/deep/c.txt", 300),
        ] {
            let mut file = File::create(root.join(path)).unwrap();
            file.write_all(&vec![b'x'; bytes]).unwrap();
        }
        dir
    }

    fn paths(listing: &Listing) -> Vec<&str> {
        listing.entries.iter().map(|e| e.path.as_str()).collect()
    }

    /// A fifo, which any process may create.
    #[cfg(unix)]
    fn make_fifo(path: &Path) {
        let status = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .expect("mkfifo runs on a unix host");
        assert!(status.success(), "mkfifo failed for {}", path.display());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_fifo_in_the_source_is_counted_and_named_rather_than_dropped() {
        // The skip was always right and always silent: `copy` over this tree
        // reported `Files: 3 / 3, Errors: 0`, exit 0, and the pipe appeared
        // nowhere at any verbosity — while rclone, which this walk cites as its
        // authority for skipping, logs `Can't transfer non file/directory`.
        let dir = tree();
        make_fifo(&dir.path().join("pipe"));
        let endpoint = RemoteSpec::Local(dir.path().to_path_buf());

        let listing = source(&ctx(&[]), &endpoint, &ListOptions::default())
            .await
            .unwrap();

        assert!(!paths(&listing).contains(&"pipe"), "{:?}", paths(&listing));
        assert_eq!(listing.specials.skipped(), 1);
        assert_eq!(listing.specials.notes()[0].path, "pipe");
        assert_eq!(
            listing.specials.notes()[0].kind,
            dctl_store::SpecialKind::Fifo
        );
        assert!(listing.has_omissions(), "the run must not stay quiet");
        // And it is not a link: the report that already existed is the wrong
        // one for an entry with no target and no policy.
        assert!(listing.links.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_filter_decides_what_is_transferred_and_never_what_is_disclosed() {
        // A special file produced no entry, so no `--include` was ever asked
        // about it. Reporting only the ones that "matched" would report none,
        // which is the silence being removed wearing a filter.
        let dir = tree();
        make_fifo(&dir.path().join("pipe"));
        let endpoint = RemoteSpec::Local(dir.path().to_path_buf());

        let listing = source(&ctx(&[]), &endpoint, &options(&["--include", "*.txt"]))
            .await
            .unwrap();
        assert_eq!(listing.specials.skipped(), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_source_that_is_itself_a_fifo_is_named_rather_than_listing_empty() {
        // `dctl copy /run/docker.sock backup:` reported `Files: 0 / 0,
        // Errors: 0` and exited 0 — a wordless success over a source that was
        // never represented, which is the same failure one level up.
        let dir = tempfile::tempdir().unwrap();
        let pipe = dir.path().join("pipe");
        make_fifo(&pipe);
        let endpoint = RemoteSpec::Local(pipe);

        let listing = source(&ctx(&[]), &endpoint, &ListOptions::default())
            .await
            .unwrap();
        assert!(listing.entries.is_empty());
        assert_eq!(listing.specials.skipped(), 1);
        assert_eq!(listing.specials.notes()[0].path, "pipe");
    }

    #[tokio::test]
    async fn a_tree_lists_as_logical_paths_in_sorted_order() {
        let dir = tree();
        let endpoint = RemoteSpec::Local(dir.path().to_path_buf());
        let listing = source(&ctx(&[]), &endpoint, &ListOptions::default())
            .await
            .unwrap();

        assert!(listing.exists);
        assert!(!listing.is_single_file);
        // Forward slashes on every platform, sorted for a stable plan.
        assert_eq!(paths(&listing), ["a.txt", "sub/b.txt", "sub/deep/c.txt"]);
    }

    #[tokio::test]
    async fn empty_directories_appear_only_when_asked_for() {
        let dir = tree();
        let endpoint = RemoteSpec::Local(dir.path().to_path_buf());
        let ctx = ctx(&[]);

        let without = source(&ctx, &endpoint, &ListOptions::default())
            .await
            .unwrap();
        assert!(!paths(&without).contains(&"empty"));

        let with = source(
            &ctx,
            &endpoint,
            &ListOptions {
                include_empty_dirs: true,
                ..ListOptions::default()
            },
        )
        .await
        .unwrap();
        assert!(paths(&with).contains(&"empty"));
        // It is a directory, not a zero-byte object.
        let entry = with.entries.iter().find(|e| e.path == "empty").unwrap();
        assert!(!entry.is_file());
    }

    #[tokio::test]
    async fn max_depth_limits_the_walk() {
        let dir = tree();
        let endpoint = RemoteSpec::Local(dir.path().to_path_buf());
        let listing = source(&ctx(&[]), &endpoint, &options(&["--max-depth", "2"]))
            .await
            .unwrap();
        // Depth 1 is the root's children, depth 2 is `sub/`'s.
        assert_eq!(paths(&listing), ["a.txt", "sub/b.txt"]);
    }

    #[tokio::test]
    async fn size_filters_are_evaluated_for_real() {
        let dir = tree();
        let endpoint = RemoteSpec::Local(dir.path().to_path_buf());
        let listing = source(
            &ctx(&[]),
            &endpoint,
            &options(&["--min-size", "10B", "--max-size", "100B"]),
        )
        .await
        .unwrap();
        assert_eq!(paths(&listing), ["sub/b.txt"]);
    }

    #[tokio::test]
    async fn a_pattern_filter_is_evaluated_rather_than_refused() {
        // The engine is wired in: an `--exclude` that used to stop the command
        // now removes exactly the files it names, and nothing else.
        let dir = tree();
        let endpoint = RemoteSpec::Local(dir.path().to_path_buf());
        let listing = source(&ctx(&[]), &endpoint, &options(&["--exclude", "sub/**"]))
            .await
            .unwrap();
        assert_eq!(paths(&listing), ["a.txt"]);
    }

    #[tokio::test]
    async fn an_include_drops_everything_it_did_not_name() {
        // rclone's asymmetry, honoured: one `--include` makes the unmatched
        // default an exclusion.
        let dir = tree();
        let endpoint = RemoteSpec::Local(dir.path().to_path_buf());
        let listing = source(&ctx(&[]), &endpoint, &options(&["--include", "sub/**"]))
            .await
            .unwrap();
        assert_eq!(paths(&listing), ["sub/b.txt", "sub/deep/c.txt"]);
    }

    #[tokio::test]
    async fn a_files_from_list_selects_exactly_those_paths() {
        let dir = tree();
        let list = dir.path().join("wanted.txt");
        fs::write(&list, "sub/b.txt\n").unwrap();
        let list_arg = list.display().to_string();

        let endpoint = RemoteSpec::Local(dir.path().to_path_buf());
        let listing = source(
            &ctx(&[]),
            &endpoint,
            &options(&["--files-from", list_arg.as_str()]),
        )
        .await
        .unwrap();
        assert_eq!(paths(&listing), ["sub/b.txt"]);
    }

    #[tokio::test]
    async fn a_malformed_pattern_is_a_usage_error_before_anything_is_walked() {
        let error = ListOptions::resolve(&globals(&["--exclude", "a{b"]), false).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn checksum_hashes_the_local_side() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        let endpoint = RemoteSpec::Local(dir.path().to_path_buf());

        let plain = source(&ctx(&[]), &endpoint, &options(&[])).await.unwrap();
        assert!(
            plain.entries[0].hash.is_none(),
            "never hashed speculatively"
        );

        let hashed = source(&ctx(&[]), &endpoint, &options(&["--checksum"]))
            .await
            .unwrap();
        assert_eq!(
            hashed.entries[0].hash.as_deref(),
            Some(blake3::hash(b"hello").to_hex().to_string().as_str())
        );
    }

    #[tokio::test]
    async fn a_single_file_lists_as_itself() {
        let dir = tree();
        let endpoint = RemoteSpec::Local(dir.path().join("a.txt"));
        let listing = source(&ctx(&[]), &endpoint, &ListOptions::default())
            .await
            .unwrap();
        assert!(listing.is_single_file);
        assert_eq!(paths(&listing), ["a.txt"]);
    }

    #[tokio::test]
    async fn a_missing_source_is_an_error_but_a_missing_destination_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let endpoint = RemoteSpec::Local(dir.path().join("nowhere"));
        let ctx = ctx(&[]);

        let error = source(&ctx, &endpoint, &ListOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::DirNotFound);

        // First run: the destination legitimately does not exist yet.
        let listing = destination(&ctx, &endpoint, &ListOptions::default())
            .await
            .unwrap();
        assert!(!listing.exists);
        assert!(listing.entries.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinks_are_skipped_and_counted_never_followed() {
        // A link to an ancestor would make the walk loop forever; a link out of
        // the tree would copy data the user never named.
        let dir = tree();
        std::os::unix::fs::symlink(dir.path(), dir.path().join("loop")).unwrap();

        let endpoint = RemoteSpec::Local(dir.path().to_path_buf());
        let listing = source(&ctx(&[]), &endpoint, &ListOptions::default())
            .await
            .unwrap();
        assert_eq!(listing.links.skipped(), 1);
        assert!(listing.has_omissions());
        assert_eq!(paths(&listing), ["a.txt", "sub/b.txt", "sub/deep/c.txt"]);
    }

    /// The transfer walk under a policy that follows, which is the only way to
    /// reach [`resolve_link`]'s cycle arm at all.
    fn following() -> ListOptions {
        ListOptions {
            links: LinkPolicy::Follow,
            ..ListOptions::default()
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_transfer_walk_stops_at_a_link_that_re_enters_its_own_ancestor() {
        // The transfer walk's own cycle guard, and it is separate code from the
        // backup scan's — `commands::backup::scan` has one, `dctl_store::links`
        // has the chain both are built on, and both of those are asserted
        // elsewhere. This one could be deleted outright and the workspace suite
        // stayed green, which is what makes it worth a test of its own: `dctl
        // copy` and `dctl sync` are the verbs that walk it.
        //
        // `inner/loop -> the root` is the oldest way to make a backup tool run
        // until the disk fills. Without the guard the walk descends
        // `inner/loop/inner/loop/…` and stores the same payload once per level
        // under a longer name each time, until the kernel's own forty-link
        // ceiling ends the run with an unreadable directory — a transfer that
        // either never finishes or fails somewhere nobody can act on.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir(root.join("inner")).unwrap();
        fs::write(root.join("inner/a.txt"), "a").unwrap();
        std::os::unix::fs::symlink(root, root.join("inner/loop")).unwrap();

        let listing = source(
            &ctx(&[]),
            &RemoteSpec::Local(root.to_path_buf()),
            &following(),
        )
        .await
        .expect("a tree whose only oddity is a loop still lists");

        // The payload is through, exactly once, under the name it really has.
        assert_eq!(paths(&listing), ["inner/a.txt"]);
        // And the loop is *named*, not merely absent: the count and the reason
        // are what tell an operator why one directory is not in the transfer.
        assert_eq!(listing.links.skipped(), 1);
        assert_eq!(listing.links.followed(), 0);
        assert_eq!(listing.links.notes()[0].path, "inner/loop");
        assert_eq!(listing.links.notes()[0].verdict, LinkVerdict::Cycle);
        assert!(listing.has_omissions(), "the run must not stay quiet");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn two_links_to_one_directory_are_both_transferred() {
        // The other half of the rule, and the reason the guard tracks ancestors
        // rather than every directory the walk has entered. `current` and
        // `latest` are two legitimate names for one release directory; a
        // visited-set implementation terminates just as well and silently drops
        // everything under the second of them — the same loss the link work
        // exists to remove, arrived at from the other side.
        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::write(shared.join("x.txt"), "x").unwrap();
        let root = dir.path().join("root");
        fs::create_dir(&root).unwrap();
        std::os::unix::fs::symlink(&shared, root.join("current")).unwrap();
        std::os::unix::fs::symlink(&shared, root.join("latest")).unwrap();

        let listing = source(&ctx(&[]), &RemoteSpec::Local(root), &following())
            .await
            .unwrap();

        assert_eq!(paths(&listing), ["current/x.txt", "latest/x.txt"]);
        assert_eq!(listing.links.followed(), 2);
        assert_eq!(listing.links.skipped(), 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_root_reached_through_a_symlink_is_walked_rather_than_skipped() {
        // The link the walk starts from is not the links it finds. `/data ->
        // /mnt/disk/data` is an ordinary layout and the root is the one path the
        // operator typed; refusing it produced an empty listing, which `copy`
        // reported as a successful transfer of nothing and `sync` read as
        // permission to delete everything at the destination.
        let dir = tree();
        let elsewhere = tempfile::tempdir().unwrap();
        let link = elsewhere.path().join("link-to-tree");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();

        let listing = source(&ctx(&[]), &RemoteSpec::Local(link), &ListOptions::default())
            .await
            .unwrap();

        assert!(listing.exists);
        assert_eq!(
            listing.links.skipped(),
            0,
            "the root was followed, so nothing was skipped"
        );
        assert!(!listing.has_omissions());
        assert_eq!(paths(&listing), ["a.txt", "sub/b.txt", "sub/deep/c.txt"]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_single_file_reached_through_a_symlink_lists_under_the_name_that_was_typed() {
        // The logical path is the name the operator wrote, not the link target's:
        // `dctl copy /tmp/latest.log archive:` must store `latest.log`, which is
        // the only spelling they can name it by afterwards.
        let dir = tree();
        let elsewhere = tempfile::tempdir().unwrap();
        let link = elsewhere.path().join("named.txt");
        std::os::unix::fs::symlink(dir.path().join("a.txt"), &link).unwrap();

        let listing = source(&ctx(&[]), &RemoteSpec::Local(link), &ListOptions::default())
            .await
            .unwrap();

        assert!(listing.is_single_file);
        assert_eq!(paths(&listing), ["named.txt"]);
        assert_eq!(listing.entries[0].size, Some(1), "the size is the target's");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_root_that_is_a_dangling_symlink_is_a_missing_source_not_an_empty_one() {
        // A link with nothing behind it names nothing. Reporting it as an empty
        // tree is the failure this whole family has: `sync` would treat it as a
        // source that legitimately holds no files.
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &link).unwrap();

        let error = source(&ctx(&[]), &RemoteSpec::Local(link), &ListOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::DirNotFound);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_backslash_in_a_name_is_refused_rather_than_keyed_two_ways() {
        // `a\b.txt` is one legal filename here and a two-component path on
        // Windows. Listing it as one component while every spec naming it means
        // two would give one file two index keys.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(r"a\b.txt"), "x").unwrap();
        fs::create_dir(dir.path().join(r"d\e")).unwrap();
        fs::write(dir.path().join(r"d\e").join("inside.txt"), "y").unwrap();
        fs::write(dir.path().join("clean.txt"), "z").unwrap();

        let endpoint = RemoteSpec::Local(dir.path().to_path_buf());
        let listing = source(&ctx(&[]), &endpoint, &ListOptions::default())
            .await
            .unwrap();

        // Only the representable file is listed, and the walk does not descend
        // into a directory whose own name has no logical spelling.
        assert_eq!(paths(&listing), ["clean.txt"]);
        assert_eq!(listing.unrepresentable_skipped, 2);
        assert!(listing.has_omissions());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_single_file_named_with_a_backslash_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(r"a\b.txt"), "x").unwrap();

        let endpoint = RemoteSpec::Local(dir.path().join(r"a\b.txt"));
        let listing = source(&ctx(&[]), &endpoint, &ListOptions::default())
            .await
            .unwrap();
        assert!(listing.is_single_file);
        assert!(listing.entries.is_empty());
        assert_eq!(listing.unrepresentable_skipped, 1);
    }

    #[tokio::test]
    async fn an_unconfigured_remote_is_reported_rather_than_read_as_a_directory() {
        // S6 in the read direction: a remote nobody configured must be named,
        // never quietly reinterpreted as the relative directory `vault`.
        let endpoint = RemoteSpec::Named {
            remote: "vault".into(),
            path: "photos".into(),
        };
        let error = source(
            &ctx(&["--no-ask-password"]),
            &endpoint,
            &ListOptions::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("vault"), "{}", error.message());
    }

    #[test]
    fn an_untraversed_destination_is_empty_but_present() {
        // The distinction matters: the plan says "destination-not-listed"
        // rather than "missing-at-destination".
        let listing = untraversed();
        assert!(listing.exists);
        assert!(listing.entries.is_empty());
    }

    #[test]
    fn options_come_from_the_global_flags() {
        let options =
            ListOptions::resolve(&globals(&["--min-size", "1k", "--max-depth", "3"]), true)
                .unwrap();
        assert!(options.include_empty_dirs);
        assert!(!options.accepts_file("a.txt", 1023, None));
        assert!(options.accepts_file("a.txt", 1024, None));
        assert!(!options.accepts_file("a/b/c/d.txt", 4096, None));
    }

    #[test]
    fn the_age_flags_reach_the_walk_rather_than_compiling_and_doing_nothing() {
        // The failure this test exists for: `--max-age` parsed, validated, and
        // then never consulted, because the walk had no time to give it. That
        // shape compiles, passes every filter-engine test, and quietly copies
        // the whole tree.
        let options = ListOptions::resolve(&globals(&["--max-age", "1d"]), true).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        assert!(options.accepts_file("fresh.txt", 1, Some(now - 60)));
        assert!(!options.accepts_file("stale.txt", 1, Some(now - 3 * 86_400)));
        // An unmeasured row carries no time and is not guessed at.
        assert!(options.accepts_unmeasured_file("rebuilt.bin", None));
    }

    #[test]
    fn a_local_file_reports_the_time_the_age_filter_needs() {
        // The other half: a walk that read a time but handed the filter `None`
        // would pass the test above and still copy everything.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.txt");
        File::create(&path).unwrap().write_all(b"x").unwrap();
        let metadata = fs::metadata(&path).unwrap();
        let seconds = local_modified(&metadata).expect("this filesystem records times");
        let now = std::time::SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        assert!(
            (now - seconds).abs() < 300,
            "a file created just now reported {seconds} against a clock of {now}"
        );
    }

    #[test]
    fn an_unsatisfiable_size_range_is_refused() {
        // A range no file can match would transfer nothing and report success.
        let error =
            ListOptions::resolve(&globals(&["--min-size", "10M", "--max-size", "1M"]), false)
                .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[test]
    fn an_unparseable_size_names_the_flag_that_was_wrong() {
        let error = ListOptions::resolve(&globals(&["--max-size", "banana"]), false).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("--max-size"));
    }

    #[test]
    fn a_remote_path_is_re_rooted_at_the_prefix_that_named_it() {
        assert_eq!(relative_to("", "photos/a.jpg"), "photos/a.jpg");
        assert_eq!(relative_to("photos", "photos/a.jpg"), "a.jpg");
        assert_eq!(relative_to("photos/2024", "photos/2024/a.jpg"), "a.jpg");
        // The prefix naming the object itself leaves nothing behind, which is
        // what marks the single-file case.
        assert_eq!(relative_to("photos/a.jpg", "photos/a.jpg"), "");
    }

    #[test]
    fn a_timestamp_survives_the_trip_in_both_directions() {
        assert_eq!(
            unix_seconds(1_700_000_000),
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000))
        );
        // Before the epoch is a real timestamp, not a missing one.
        assert_eq!(
            unix_seconds(-86_400),
            Some(SystemTime::UNIX_EPOCH - Duration::from_secs(86_400))
        );
    }
}
