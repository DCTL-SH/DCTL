//! Enumerating one side of a transfer.
//!
//! A plan is a diff, and a diff needs both sides listed before it can name a
//! single action. This module turns a [`RemoteSpec`] into the [`Entry`] set the
//! planner compares, and is the only place in the family that touches a
//! filesystem.
//!
//! ## What is honoured, and what is refused
//!
//! `--max-depth`, `--min-size` and `--max-size` are evaluated here, for real.
//! The pattern filters (`--include`, `--exclude`, `--filter-from`,
//! `--files-from`) are **refused** by [`super::compare::ensure_filters_are_supported`]
//! before a walk starts, because a dropped `--exclude` would make `sync` delete
//! the files the rule was written to protect.
//!
//! ## Memory
//!
//! The listing is materialised into a `Vec`. `PLAN.md` §16.2 asks for streaming
//! everything, and the streaming diff genuinely belongs in `dctl-core` — but a
//! `sync` cannot name a destination *extra* until it has seen the whole source,
//! so some state is unavoidable and the honest place for the streaming,
//! on-disk-backed version is the engine that also does the transferring. What is
//! here is bounded by `--max-depth` and the size filters, and is the same shape
//! the engine will consume.

use std::fs;
use std::path::Path;

use crate::cli::GlobalArgs;
use crate::constants::{
    MAX_DEPTH_UNLIMITED, REMOTE_ENUMERATION_FEATURE, REMOTE_ENUMERATION_HINT, SIZE_PARSE_EXAMPLES,
    WALK_FOLLOW_SYMLINKS,
};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::output::size::parse_size;
use crate::platform::path as logical;
use crate::remote::RemoteSpec;

use super::entry::Entry;

/// Which entries a walk keeps.
#[derive(Clone, Copy, Debug)]
pub struct ListOptions {
    /// Recursion limit; [`MAX_DEPTH_UNLIMITED`] for no limit.
    pub max_depth: i32,
    /// Smallest file kept, in bytes.
    pub min_size: Option<u64>,
    /// Largest file kept, in bytes.
    pub max_size: Option<u64>,
    /// Whether directories containing nothing are reported.
    ///
    /// Off unless `--create-empty-src-dirs` is given: an empty directory has no
    /// objects under it, so listing one costs a plan entry that would otherwise
    /// never turn into an action.
    pub include_empty_dirs: bool,
}

impl Default for ListOptions {
    fn default() -> Self {
        Self {
            max_depth: MAX_DEPTH_UNLIMITED,
            min_size: None,
            max_size: None,
            include_empty_dirs: false,
        }
    }
}

impl ListOptions {
    /// Resolve the walk's limits from the global flags.
    ///
    /// # Errors
    /// Returns a usage error when `--min-size`/`--max-size` cannot be parsed, or
    /// when they exclude each other — a range that can never match would
    /// silently transfer nothing, and "nothing happened" is the hardest failure
    /// to notice.
    pub fn resolve(globals: &GlobalArgs, include_empty_dirs: bool) -> Result<Self> {
        let min_size = parse_limit(globals.min_size.as_deref(), "--min-size")?;
        let max_size = parse_limit(globals.max_size.as_deref(), "--max-size")?;

        if let (Some(min), Some(max)) = (min_size, max_size) {
            if min > max {
                return Err(CliError::usage(format!(
                    "--min-size ({min}) is larger than --max-size ({max}): no file can match"
                )));
            }
        }

        Ok(Self {
            max_depth: globals.max_depth,
            min_size,
            max_size,
            include_empty_dirs,
        })
    }

    /// Whether a file of this size passes the size filters.
    #[must_use]
    pub fn accepts_size(&self, size: u64) -> bool {
        self.min_size.is_none_or(|min| size >= min) && self.max_size.is_none_or(|max| size <= max)
    }

    /// Whether a walk may descend into a directory at this depth.
    ///
    /// `depth` is the depth of the *directory's contents*: the root's immediate
    /// children are depth 1, matching `--max-depth 1` meaning "one level".
    #[must_use]
    pub const fn accepts_depth(&self, depth: i32) -> bool {
        self.max_depth == MAX_DEPTH_UNLIMITED || depth <= self.max_depth
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
    /// Symbolic links passed over. Reported rather than hidden — see
    /// [`WALK_FOLLOW_SYMLINKS`].
    pub symlinks_skipped: u64,
    /// Entries with no logical path: a name that is not valid UTF-8, or one
    /// containing a character another platform reads as a separator (see
    /// [`crate::platform::path`]). They cannot be stored under a name the user
    /// could later address, and they cannot be silently dropped either.
    pub unrepresentable_skipped: u64,
}

impl Listing {
    /// Whether anything at all was skipped and therefore deserves a warning.
    #[must_use]
    pub const fn has_omissions(&self) -> bool {
        self.symlinks_skipped > 0 || self.unrepresentable_skipped > 0
    }
}

/// Enumerate the source side.
///
/// A missing source is an error: the user named something that is not there, and
/// continuing would report a successful transfer of nothing.
///
/// # Errors
/// [`ExitCode::DirNotFound`] when the endpoint does not exist, and an
/// unimplemented error for a named remote.
pub fn source(endpoint: &RemoteSpec, options: &ListOptions) -> Result<Listing> {
    let listing = enumerate(endpoint, options)?;
    if !listing.exists {
        return Err(CliError::new(
            ExitCode::DirNotFound,
            format!("source not found: {endpoint}"),
        )
        .with_hint("Check the path, and the remote name if one was given."));
    }
    Ok(listing)
}

/// Enumerate the destination side.
///
/// A missing destination is *not* an error — it is the ordinary first run, and
/// the answer is simply that nothing is there yet.
///
/// # Errors
/// An unimplemented error for a named remote; I/O errors from the walk.
pub fn destination(endpoint: &RemoteSpec, options: &ListOptions) -> Result<Listing> {
    enumerate(endpoint, options)
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
fn enumerate(endpoint: &RemoteSpec, options: &ListOptions) -> Result<Listing> {
    match endpoint {
        RemoteSpec::Named { .. } => {
            Err(CliError::unimplemented(REMOTE_ENUMERATION_FEATURE)
                .with_hint(REMOTE_ENUMERATION_HINT))
        }
        RemoteSpec::Local(root) => walk_local(root, options),
    }
}

/// Walk a local tree, breadth-first, without recursion.
///
/// An explicit stack rather than a recursive function: a deeply nested tree is a
/// legitimate input, and a stack overflow is an abort with no error message, no
/// exit code, and no audit record — the one failure mode this crate's lint
/// configuration cannot express but must still avoid.
fn walk_local(root: &Path, options: &ListOptions) -> Result<Listing> {
    let mut listing = Listing::default();

    let Ok(metadata) = fs::symlink_metadata(root) else {
        return Ok(listing);
    };
    listing.exists = true;

    if metadata.is_file() {
        // A lone file: its logical path is its own name, taken relative to the
        // directory that contains it.
        listing.is_single_file = true;
        match root.file_name().map(logical::to_logical_component) {
            Some(Ok(name)) => {
                if options.accepts_size(metadata.len()) {
                    listing.entries.push(file_entry(name, &metadata));
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
        // A symlink, socket, device or FIFO named directly. Nothing to walk.
        listing.symlinks_skipped += u64::from(metadata.file_type().is_symlink());
        return Ok(listing);
    }

    // (directory, logical prefix, depth of the directory's *contents*)
    let mut stack = vec![(root.to_path_buf(), String::new(), 1_i32)];

    while let Some((directory, prefix, depth)) = stack.pop() {
        if !options.accepts_depth(depth) {
            continue;
        }

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

            if metadata.file_type().is_symlink() && !WALK_FOLLOW_SYMLINKS {
                listing.symlinks_skipped += 1;
                continue;
            }

            if metadata.is_dir() {
                stack.push((child.path(), path, depth + 1));
            } else if metadata.is_file() && options.accepts_size(metadata.len()) {
                listing.entries.push(file_entry(path, &metadata));
            }
        }

        // An empty directory holds no objects, so it would vanish through a
        // vault unless it is carried across explicitly.
        if child_count == 0 && !prefix.is_empty() && options.include_empty_dirs {
            listing.entries.push(Entry::empty_dir(prefix));
        }
    }

    // Deterministic order, so a plan printed twice is byte-identical and a diff
    // of two dry runs shows only what actually changed.
    listing.entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(listing)
}

/// Build a file entry from filesystem metadata.
fn file_entry(path: String, metadata: &fs::Metadata) -> Entry {
    let entry = Entry::file(path, metadata.len());
    match metadata.modified() {
        Ok(modified) => entry.with_modified(modified),
        // Some filesystems do not record modification times at all. Leaving the
        // field unset is honest; substituting `now` would make every file look
        // freshly modified on every run.
        Err(_) => entry,
    }
}

/// Parse one size limit, naming the flag in any failure.
fn parse_limit(value: Option<&str>, flag: &str) -> Result<Option<u64>> {
    match value {
        None => Ok(None),
        Some(raw) => parse_size(raw).map_err(|message| {
            CliError::usage(format!("{flag}: {message}"))
                .with_hint(format!("Accepted forms: {SIZE_PARSE_EXAMPLES}."))
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn a_tree_lists_as_logical_paths_in_sorted_order() {
        let dir = tree();
        let endpoint = RemoteSpec::Local(dir.path().to_path_buf());
        let listing = source(&endpoint, &ListOptions::default()).unwrap();

        assert!(listing.exists);
        assert!(!listing.is_single_file);
        // Forward slashes on every platform, sorted for a stable plan.
        assert_eq!(paths(&listing), ["a.txt", "sub/b.txt", "sub/deep/c.txt"]);
    }

    #[test]
    fn empty_directories_appear_only_when_asked_for() {
        let dir = tree();
        let endpoint = RemoteSpec::Local(dir.path().to_path_buf());

        let without = source(&endpoint, &ListOptions::default()).unwrap();
        assert!(!paths(&without).contains(&"empty"));

        let with = source(
            &endpoint,
            &ListOptions {
                include_empty_dirs: true,
                ..ListOptions::default()
            },
        )
        .unwrap();
        assert!(paths(&with).contains(&"empty"));
        // It is a directory, not a zero-byte object.
        let entry = with.entries.iter().find(|e| e.path == "empty").unwrap();
        assert!(!entry.is_file());
    }

    #[test]
    fn max_depth_limits_the_walk() {
        let dir = tree();
        let endpoint = RemoteSpec::Local(dir.path().to_path_buf());
        let options = ListOptions {
            max_depth: 2,
            ..ListOptions::default()
        };
        let listing = source(&endpoint, &options).unwrap();
        // Depth 1 is the root's children, depth 2 is `sub/`'s.
        assert_eq!(paths(&listing), ["a.txt", "sub/b.txt"]);
    }

    #[test]
    fn size_filters_are_evaluated_for_real() {
        let dir = tree();
        let endpoint = RemoteSpec::Local(dir.path().to_path_buf());
        let listing = source(
            &endpoint,
            &ListOptions {
                min_size: Some(10),
                max_size: Some(100),
                ..ListOptions::default()
            },
        )
        .unwrap();
        assert_eq!(paths(&listing), ["sub/b.txt"]);
    }

    #[test]
    fn a_single_file_lists_as_itself() {
        let dir = tree();
        let endpoint = RemoteSpec::Local(dir.path().join("a.txt"));
        let listing = source(&endpoint, &ListOptions::default()).unwrap();
        assert!(listing.is_single_file);
        assert_eq!(paths(&listing), ["a.txt"]);
    }

    #[test]
    fn a_missing_source_is_an_error_but_a_missing_destination_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let endpoint = RemoteSpec::Local(dir.path().join("nowhere"));

        let error = source(&endpoint, &ListOptions::default()).unwrap_err();
        assert_eq!(error.code(), ExitCode::DirNotFound);

        // First run: the destination legitimately does not exist yet.
        let listing = destination(&endpoint, &ListOptions::default()).unwrap();
        assert!(!listing.exists);
        assert!(listing.entries.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_skipped_and_counted_never_followed() {
        // A link to an ancestor would make the walk loop forever; a link out of
        // the tree would copy data the user never named.
        let dir = tree();
        std::os::unix::fs::symlink(dir.path(), dir.path().join("loop")).unwrap();

        let endpoint = RemoteSpec::Local(dir.path().to_path_buf());
        let listing = source(&endpoint, &ListOptions::default()).unwrap();
        assert_eq!(listing.symlinks_skipped, 1);
        assert!(listing.has_omissions());
        assert_eq!(paths(&listing), ["a.txt", "sub/b.txt", "sub/deep/c.txt"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_backslash_in_a_name_is_refused_rather_than_keyed_two_ways() {
        // `a\b.txt` is one legal filename here and a two-component path on
        // Windows. Listing it as one component while every spec naming it means
        // two would give one file two index keys.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(r"a\b.txt"), "x").unwrap();
        fs::create_dir(dir.path().join(r"d\e")).unwrap();
        fs::write(dir.path().join(r"d\e").join("inside.txt"), "y").unwrap();
        fs::write(dir.path().join("clean.txt"), "z").unwrap();

        let endpoint = RemoteSpec::Local(dir.path().to_path_buf());
        let listing = source(&endpoint, &ListOptions::default()).unwrap();

        // Only the representable file is listed, and the walk does not descend
        // into a directory whose own name has no logical spelling.
        assert_eq!(paths(&listing), ["clean.txt"]);
        assert_eq!(listing.unrepresentable_skipped, 2);
        assert!(listing.has_omissions());
    }

    #[cfg(unix)]
    #[test]
    fn a_single_file_named_with_a_backslash_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(r"a\b.txt"), "x").unwrap();

        let endpoint = RemoteSpec::Local(dir.path().join(r"a\b.txt"));
        let listing = source(&endpoint, &ListOptions::default()).unwrap();
        assert!(listing.is_single_file);
        assert!(listing.entries.is_empty());
        assert_eq!(listing.unrepresentable_skipped, 1);
    }

    #[test]
    fn a_remote_endpoint_is_refused_not_faked() {
        let endpoint = RemoteSpec::Named {
            remote: "vault".into(),
            path: "photos".into(),
        };
        let error = source(&endpoint, &ListOptions::default()).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.hint().is_some());
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
        assert_eq!(options.min_size, Some(1024));
        assert_eq!(options.max_size, None);
        assert_eq!(options.max_depth, 3);
        assert!(options.include_empty_dirs);
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
    fn depth_and_size_predicates_agree_with_their_flags() {
        let unlimited = ListOptions::default();
        assert!(unlimited.accepts_depth(1_000));
        assert!(unlimited.accepts_size(0));

        let bounded = ListOptions {
            max_depth: 2,
            min_size: Some(10),
            max_size: Some(20),
            include_empty_dirs: false,
        };
        assert!(bounded.accepts_depth(2));
        assert!(!bounded.accepts_depth(3));
        assert!(!bounded.accepts_size(9));
        assert!(bounded.accepts_size(10));
        assert!(bounded.accepts_size(20));
        assert!(!bounded.accepts_size(21));
    }
}
