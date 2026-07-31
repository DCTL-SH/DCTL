//! Deciding exactly which objects a removal will touch, before it touches one.
//!
//! Every verb resolves to the same shape — an ordered list of logical paths —
//! and the whole of the difference between `delete`, `purge`, `rmdir` and
//! `rmdirs` lives in this file. That is deliberate: the selection is the
//! dangerous part, so it is the part that is decided once, in full, and *before*
//! anything is removed.
//!
//! ## Selecting completely, then removing
//!
//! Nothing is deleted while the listing is still being read. Three reasons, and
//! only the first is about tidiness:
//!
//! 1. `--dry-run` must be able to print the exact set. A selection that emerged
//!    as the deletion progressed could only be printed by performing it.
//! 2. Emptiness is a property of the *whole* set. `rmdir` cannot refuse a
//!    directory it has not finished reading, and `delete --rmdirs` cannot know
//!    which directories its own deletion emptied until it knows what it is
//!    deleting.
//! 3. The sealed side deletes index rows, and the listing it would be walking
//!    comes out of that index.
//!
//! ## The order within a selection
//!
//! Objects first, in ascending path order — the order every listing verb prints,
//! so a `--dry-run` can be diffed against a `dctl ls`. Directory markers last,
//! deepest first. Two properties follow, and both are about what a crash leaves:
//!
//! * A directory's marker is never removed before the objects inside it, so an
//!   interrupted run never leaves a directory that has been *undeclared* while
//!   still holding files.
//! * A child's marker is never removed after its parent's, so an interrupted
//!   sweep never leaves a parent removed and a child stranded under it.
//!
//! Both intermediate states are therefore always the same shape: *fewer objects,
//! structure intact*. That is the shape a re-run converges from, and re-running
//! is safe because removal is idempotent (see [`super::remove`]).

use crate::commands::listing::{Entry as Matchable, Filter};
use crate::constants::{REMOVAL_KIND_DIRECTORY, REMOVAL_KIND_OBJECT, REMOVAL_NOT_EMPTY_HINT};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::source::Entry;

use super::dirs::{self, Directories};
use super::medium::Medium;
use super::operation::Operation;
use super::target::{Scoped, Target};

/// One thing a removal will remove.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// Logical path within the remote.
    pub path: String,
    /// Size in bytes, as the store reported it, or [`None`] when it reported
    /// none. For a vault this is the plaintext length, which is what `dctl ls`
    /// shows for the same file — a report that quoted the sealed length would
    /// not add up against the listing the user read before deciding to delete.
    ///
    /// And for the same reason it must be able to be absent: a vault index
    /// rebuilt from object headers records no sizes (see
    /// [`crate::source::Entry::size`]), so `dctl ls` shows `-` for those rows.
    /// A deletion report that answered `0 B` for the same objects would not add
    /// up against the listing either — and it is the listing somebody read
    /// before deciding what to lose.
    pub size: Option<u64>,
    /// Which of [`REMOVAL_KIND_OBJECT`] / [`REMOVAL_KIND_DIRECTORY`] this is.
    pub kind: &'static str,
}

/// Everything one removal resolved to.
#[derive(Debug, Default)]
pub struct Selection {
    /// What will be removed, in removal order.
    pub items: Vec<Item>,
    /// How many objects were examined to produce it.
    ///
    /// Carried so an empty result can be worded correctly: "there was nothing
    /// here" and "nothing survived your filters" send a user to two different
    /// places, and a removal that could not tell them apart would be its own
    /// least trustworthy corner.
    pub considered: usize,
}

/// Resolve `operation` against the store into the exact set it will remove.
///
/// # Errors
/// - [`ExitCode::FileNotFound`] when `deletefile` names nothing.
/// - [`ExitCode::DirNotFound`] when `rmdir` or `purge` names a path the remote
///   does not hold.
/// - [`ExitCode::Usage`] when `deletefile` names a directory, or when `rmdir`
///   is given a directory that is not empty.
/// - Whatever the listing itself reported.
///
/// `filter` is already compiled and validated — [`super::flow`] builds it before
/// the destructive gate, so a malformed `--include` is refused before anybody is
/// asked to confirm anything. It is [`Filter::default`] for the verbs that
/// document themselves as ignoring filters, and those verbs never consult it.
/// Takes a [`Scoped`] rather than a [`Target`], because selecting addresses
/// inside a store the remote has already named — see [`Scoped`] for what the two
/// mean and what swapping them costs.
pub async fn select(
    medium: &Medium,
    scoped: &Scoped,
    operation: &Operation,
    filter: &Filter,
) -> Result<Selection> {
    let target = scoped.inside();
    // `cleanup` addresses provider keys, not logical paths, so there is nothing
    // for this module to select. It is an explicit arm rather than a fallthrough
    // so that a seventh verb cannot silently inherit "selects nothing".
    if operation.is_cleanup() {
        return Ok(Selection::default());
    }

    let entries = medium.list(&target.path).await?;
    let considered = entries.len();
    let structure = Directories::from_paths(entries.iter().map(|entry| entry.path.as_str()));

    let items = match operation {
        Operation::Delete { rmdirs } => delete(filter, target, entries, &structure, *rmdirs),
        Operation::DeleteFile => delete_file(target, entries)?,
        Operation::Purge => purge(target, entries, &structure)?,
        Operation::Rmdir => rmdir(target, &structure)?,
        Operation::Rmdirs { leave_root } => rmdirs(target, &structure, *leave_root),
        Operation::Cleanup { .. } => Vec::new(),
    };

    Ok(Selection { items, considered })
}

/// `delete`: the objects the filters select, and optionally the directories that
/// removing them empties.
///
/// Directory markers are never candidates for the object half. A marker is what
/// *declares* a directory, so removing one while promising to leave the
/// structure standing would be a contradiction — and it is the difference
/// between `delete` and `purge` that the whole family is organised around.
fn delete(
    filter: &Filter,
    target: &Target,
    entries: Vec<Entry>,
    before: &Directories,
    rmdirs: bool,
) -> Vec<Item> {
    let mut removed: Vec<Item> = Vec::new();
    let mut surviving: Vec<String> = Vec::new();

    for entry in entries {
        if dirs::is_marker(&entry.path) {
            surviving.push(entry.path);
            continue;
        }
        let size = entry.size;
        let path = entry.path.clone();
        // The listing family's matcher, not a second one. A `--exclude` that
        // selected differently for `dctl ls` and for `dctl delete` would make the
        // listing a user reads before deleting a lie about what they are about
        // to lose.
        if filter.matches(&Matchable::from_source(entry, &target.path)) {
            removed.push(Item {
                path,
                size,
                kind: REMOVAL_KIND_OBJECT,
            });
        } else {
            surviving.push(path);
        }
    }

    if !rmdirs {
        return removed;
    }

    // Only the directories *this* deletion emptied. One that was already empty
    // before the run is somebody's deliberate `mkdir`, and sweeping it away
    // because a delete happened to pass overhead would be removing something the
    // command was never pointed at.
    let after = Directories::from_paths(surviving.iter().map(String::as_str));
    for directory in after.declared_at_or_below(&target.path) {
        // Never the target root: `delete vault:photos --rmdirs` is asked to
        // empty `photos`, not to remove it.
        if directory == target.path {
            continue;
        }
        if after.is_empty(directory) && before.holds_object(directory) {
            removed.push(marker_item(directory));
        }
    }

    removed
}

/// `deletefile`: exactly the one object named, or a refusal that says why not.
fn delete_file(target: &Target, entries: Vec<Entry>) -> Result<Vec<Item>> {
    let Some(exact) = entries.iter().find(|entry| entry.path == target.path) else {
        // A path that addresses *something* but not an object is a directory.
        // Saying so — rather than "not found" — is what stops a user retrying the
        // same command with a trailing slash and getting the same unhelpful
        // answer.
        if entries.is_empty() {
            return Err(CliError::new(
                ExitCode::FileNotFound,
                format!("'{target}' does not exist"),
            )
            .with_hint("Check the path with `dctl ls`, then name the object exactly."));
        }
        return Err(
            CliError::usage(format!("'{target}' is a directory, not an object")).with_hint(
                "Use `dctl rmdir` for an empty directory, or `dctl purge` to \
                 remove a directory and everything in it.",
            ),
        );
    };

    Ok(vec![Item {
        path: exact.path.clone(),
        size: exact.size,
        // Removing a marker by name is a legitimate thing to want — it is how a
        // directory created by mistake is un-declared — so the kind is reported
        // truthfully rather than the command refusing to name it.
        kind: kind_of(&exact.path),
    }])
}

/// `purge`: the target and everything beneath it, markers included.
fn purge(target: &Target, entries: Vec<Entry>, structure: &Directories) -> Result<Vec<Item>> {
    if entries.is_empty() && !target.is_root() {
        return Err(
            CliError::new(ExitCode::DirNotFound, format!("'{target}' does not exist")).with_hint(
                "There is nothing stored under this path, so there is nothing to purge.",
            ),
        );
    }

    let mut items: Vec<Item> = entries
        .into_iter()
        .filter(|entry| !dirs::is_marker(&entry.path))
        .map(|entry| Item {
            path: entry.path,
            size: entry.size,
            kind: REMOVAL_KIND_OBJECT,
        })
        .collect();

    // Markers last and deepest first, so an interrupted purge never undeclares a
    // directory whose contents are still there. See the module documentation.
    items.extend(
        structure
            .declared_at_or_below(&target.path)
            .into_iter()
            .map(marker_item),
    );
    Ok(items)
}

/// `rmdir`: one directory, and only if it is already empty.
///
/// The three refusals are the command's entire value. A `rmdir` that fell back
/// to removing contents would be a synonym for `purge`, and the reason a script
/// can use one is that the other one stops.
fn rmdir(target: &Target, structure: &Directories) -> Result<Vec<Item>> {
    if !structure.exists(&target.path) {
        return Err(
            CliError::new(ExitCode::DirNotFound, format!("'{target}' does not exist")).with_hint(
                "A directory holding no objects is not stored anywhere, so a vault \
             cannot tell it from one that was never created. `dctl mkdir` is \
             what makes an empty directory exist.",
            ),
        );
    }

    if let Some(occupant) = structure.first_object_under(&target.path) {
        return Err(
            CliError::usage(format!("'{target}' is not empty: it holds '{occupant}'"))
                .with_hint(REMOVAL_NOT_EMPTY_HINT),
        );
    }

    if let Some(child) = structure.subdirectories(&target.path).first() {
        return Err(
            CliError::usage(format!("'{target}' is not empty: it holds '{child}'")).with_hint(
                "Remove the directories inside it first, or use `dctl rmdirs` to \
                 sweep every empty directory under a path.",
            ),
        );
    }

    // Existing, empty, childless — so it is declared, and its marker is the one
    // object that stands for it. The `if` is not defensive padding: a caller
    // could hand this an empty structure, and returning nothing is the honest
    // answer to "remove a directory that nothing records".
    Ok(if structure.is_declared(&target.path) {
        vec![marker_item(&target.path)]
    } else {
        Vec::new()
    })
}

/// `rmdirs`: every declared, empty directory under the target, deepest first.
///
/// A directory that still holds an object is skipped rather than refused —
/// unlike `rmdir`, the user named a region here, not a victim.
fn rmdirs(target: &Target, structure: &Directories, leave_root: bool) -> Vec<Item> {
    structure
        .declared_at_or_below(&target.path)
        .into_iter()
        .filter(|directory| !(leave_root && *directory == target.path))
        .filter(|directory| structure.is_empty(directory))
        .map(marker_item)
        .collect()
}

/// The removal item that stands for a directory.
fn marker_item(directory: &str) -> Item {
    Item {
        path: dirs::marker_path(directory),
        // A marker is a zero-byte object by construction, so this is measured
        // rather than assumed: `mkdir` writes nothing into it.
        // A directory marker carries no bytes of its own, and that is a
        // measurement rather than an absence of one.
        size: Some(0),
        kind: REMOVAL_KIND_DIRECTORY,
    }
}

/// Which kind a path is, read from the path itself.
fn kind_of(path: &str) -> &'static str {
    if dirs::is_marker(path) {
        REMOVAL_KIND_DIRECTORY
    } else {
        REMOVAL_KIND_OBJECT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::globals::GlobalArgs;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    /// The compiled matcher for a set of flags, exactly as `flow` builds it.
    fn filter(args: &[&str]) -> Filter {
        Filter::from_globals(
            &Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals,
        )
        .expect("the flags compile")
    }

    fn target(spec: &str) -> Target {
        Target::parse(spec).expect("a well-formed target")
    }

    fn listing(paths: &[(&str, u64)]) -> Vec<Entry> {
        paths
            .iter()
            .map(|(path, size)| Entry::new(*path, *size))
            .collect()
    }

    fn structure(entries: &[Entry]) -> Directories {
        Directories::from_paths(entries.iter().map(|entry| entry.path.as_str()))
    }

    fn paths(items: &[Item]) -> Vec<&str> {
        items.iter().map(|item| item.path.as_str()).collect()
    }

    fn marker(directory: &str) -> String {
        dirs::marker_path(directory)
    }

    #[test]
    fn delete_takes_the_objects_and_leaves_the_structure_standing() {
        // The defining behaviour of the verb, in one assertion: the marker
        // survives a delete that removes everything it declared.
        let entries = listing(&[("photos/a.jpg", 3), (&marker("photos"), 0)]);
        let before = structure(&entries);
        let items = delete(
            &filter(&[]),
            &target("vault:photos"),
            entries,
            &before,
            false,
        );
        assert_eq!(paths(&items), ["photos/a.jpg"]);
    }

    #[test]
    fn delete_honours_the_filters() {
        let entries = listing(&[("photos/a.jpg", 3), ("photos/b.tmp", 1)]);
        let before = structure(&entries);
        let items = delete(
            &filter(&["--include", "*.tmp"]),
            &target("vault:photos"),
            entries,
            &before,
            false,
        );
        assert_eq!(paths(&items), ["photos/b.tmp"]);
    }

    #[test]
    fn delete_matches_filters_relative_to_the_target() {
        // `--max-depth 1` on `vault:photos` must mean one level below `photos`,
        // exactly as it does for a listing rooted there.
        let entries = listing(&[("photos/a.jpg", 1), ("photos/2024/b.jpg", 1)]);
        let before = structure(&entries);
        let items = delete(
            &filter(&["--max-depth", "1"]),
            &target("vault:photos"),
            entries,
            &before,
            false,
        );
        assert_eq!(paths(&items), ["photos/a.jpg"]);
    }

    #[test]
    fn a_rule_file_is_refused_when_the_matcher_is_built() {
        // A dropped `--filter-from` on a listing shows too many files; on a
        // delete it removes them. The refusal happens where the matcher is
        // compiled, which `flow` does before the destructive gate.
        let globals = Harness::parse_from(["dctl", "--filter-from", "rules.txt"]).globals;
        let error = Filter::from_globals(&globals).expect_err("a rule file must be refused");
        assert_ne!(error.code(), ExitCode::Success);
        assert!(error.hint().is_some());
    }

    #[test]
    fn rmdirs_sweeps_only_the_directories_the_delete_emptied() {
        // `photos/2024` is emptied by this run and goes; `photos/empty` was
        // already empty and is somebody's deliberate `mkdir`, so it stays.
        let entries = listing(&[
            ("photos/2024/a.jpg", 3),
            (&marker("photos/2024"), 0),
            (&marker("photos/empty"), 0),
        ]);
        let before = structure(&entries);
        let items = delete(
            &filter(&[]),
            &target("vault:photos"),
            entries,
            &before,
            true,
        );
        assert_eq!(paths(&items), ["photos/2024/a.jpg", &marker("photos/2024")]);
    }

    #[test]
    fn rmdirs_never_removes_the_target_root() {
        // The tree a scheduled job writes into has to still be there tomorrow.
        let entries = listing(&[("photos/a.jpg", 3), (&marker("photos"), 0)]);
        let before = structure(&entries);
        let items = delete(
            &filter(&[]),
            &target("vault:photos"),
            entries,
            &before,
            true,
        );
        assert_eq!(paths(&items), ["photos/a.jpg"]);
    }

    #[test]
    fn a_directory_a_filtered_delete_did_not_empty_survives_rmdirs() {
        let entries = listing(&[
            ("photos/2024/a.jpg", 3),
            ("photos/2024/b.tmp", 1),
            (&marker("photos/2024"), 0),
        ]);
        let before = structure(&entries);
        let items = delete(
            &filter(&["--include", "*.tmp"]),
            &target("vault:photos"),
            entries,
            &before,
            true,
        );
        assert_eq!(paths(&items), ["photos/2024/b.tmp"]);
    }

    #[test]
    fn deletefile_takes_exactly_the_object_named() {
        let entries = listing(&[("a.jpg", 5), ("a.jpg.bak", 9)]);
        let items = delete_file(&target("vault:a.jpg"), entries).unwrap();
        assert_eq!(paths(&items), ["a.jpg"]);
        assert_eq!(items[0].size, Some(5));
    }

    #[test]
    fn deletefile_refuses_a_directory_rather_than_recursing() {
        // The mistake that costs a decade of photographs.
        let entries = listing(&[("photos/a.jpg", 1)]);
        let error = delete_file(&target("vault:photos"), entries).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().unwrap_or_default().contains("purge"));
    }

    #[test]
    fn deletefile_reports_a_missing_object_as_missing() {
        let error = delete_file(&target("vault:nope.jpg"), Vec::new()).unwrap_err();
        assert_eq!(error.code(), ExitCode::FileNotFound);
    }

    #[test]
    fn purge_takes_everything_with_the_markers_last_and_deepest_first() {
        let entries = listing(&[
            ("old/a.jpg", 1),
            ("old/deep/b.jpg", 2),
            (&marker("old"), 0),
            (&marker("old/deep"), 0),
        ]);
        let structure = structure(&entries);
        let items = purge(&target("vault:old"), entries, &structure).unwrap();
        assert_eq!(
            paths(&items),
            [
                "old/a.jpg",
                "old/deep/b.jpg",
                &marker("old/deep"),
                &marker("old"),
            ]
        );
    }

    #[test]
    fn purge_ignores_the_filters_entirely() {
        // Not a call to the filter at all: `purge` takes no matcher, so there is
        // no code path through which a pattern could narrow it.
        let entries = listing(&[("old/a.jpg", 1), ("old/b.tmp", 1)]);
        let structure = structure(&entries);
        let items = purge(&target("vault:old"), entries, &structure).unwrap();
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn purging_a_path_that_holds_nothing_is_reported_as_missing() {
        let error = purge(&target("vault:gone"), Vec::new(), &Directories::default()).unwrap_err();
        assert_eq!(error.code(), ExitCode::DirNotFound);
    }

    #[test]
    fn purging_an_empty_remote_is_not_an_error() {
        // The root always exists — it is the vault — so an empty one is an
        // empty success rather than a missing directory.
        let items = purge(&target("vault:"), Vec::new(), &Directories::default()).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn rmdir_removes_the_marker_of_an_empty_directory() {
        let entries = listing(&[(&marker("photos/2024"), 0)]);
        let items = rmdir(&target("vault:photos/2024"), &structure(&entries)).unwrap();
        assert_eq!(paths(&items), [marker("photos/2024")]);
        assert_eq!(items[0].kind, REMOVAL_KIND_DIRECTORY);
    }

    #[test]
    fn rmdir_refuses_a_directory_that_holds_an_object_and_names_it() {
        let entries = listing(&[("photos/a.jpg", 1)]);
        let error = rmdir(&target("vault:photos"), &structure(&entries)).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(
            error.message().contains("photos/a.jpg"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn rmdir_refuses_a_directory_that_holds_a_subdirectory() {
        // The POSIX promise, preserved: `rmdir` is not recursive, and an empty
        // child is still a child.
        let entries = listing(&[(&marker("a"), 0), (&marker("a/b"), 0)]);
        let error = rmdir(&target("vault:a"), &structure(&entries)).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("a/b"), "{}", error.message());
    }

    #[test]
    fn rmdir_reports_a_directory_that_was_never_created_as_missing() {
        // A vault stores no empty directories, so this is genuinely absent —
        // and reporting it as an empty success would make a typo look like work.
        let error = rmdir(&target("vault:nowhere"), &Directories::default()).unwrap_err();
        assert_eq!(error.code(), ExitCode::DirNotFound);
        assert!(error.hint().unwrap_or_default().contains("mkdir"));
    }

    #[test]
    fn rmdirs_sweeps_deepest_first_and_skips_what_is_occupied() {
        let entries = listing(&[
            (&marker("a"), 0),
            (&marker("a/b"), 0),
            (&marker("a/b/c"), 0),
            (&marker("kept"), 0),
            ("kept/file.txt", 4),
        ]);
        let items = rmdirs(&target("vault:"), &structure(&entries), false);
        assert_eq!(paths(&items), [marker("a/b/c"), marker("a/b"), marker("a")]);
    }

    #[test]
    fn leave_root_keeps_the_directory_the_sweep_was_pointed_at() {
        let entries = listing(&[(&marker("a"), 0), (&marker("a/b"), 0)]);
        let structure = structure(&entries);
        assert_eq!(
            paths(&rmdirs(&target("vault:a"), &structure, true)),
            [marker("a/b")]
        );
        assert_eq!(
            paths(&rmdirs(&target("vault:a"), &structure, false)),
            [marker("a/b"), marker("a")]
        );
    }
}
