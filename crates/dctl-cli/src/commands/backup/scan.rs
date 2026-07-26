//! Walking a local tree into the set of files a backup would store.
//!
//! Three properties this walk is written for, in order of how much they matter.
//!
//! **It never stops on one bad entry.** A directory that cannot be read, a
//! filename that is not valid UTF-8, a file that vanished between the listing
//! and the `stat` — each is recorded and the walk continues. A backup that
//! aborts on the first unreadable directory backs up nothing; one that reports
//! four problems and 200 000 files gives its operator something to act on. The
//! problems are returned, never swallowed: the caller counts them as errors and
//! the run's exit code reflects it (`PLAN.md` §7).
//!
//! **It cannot loop.** Following symlinks is opt-in, and when it is on the walk
//! remembers the canonical path of every directory it enters. A symlink pointing
//! at its own ancestor is the oldest way to make a backup tool run until the
//! disk fills.
//!
//! **It is deterministic.** Entries are sorted, so two scans of an unchanged
//! tree produce byte-identical output and a plan can be diffed between runs.
//!
//! The walk is synchronous [`std::fs`] rather than `tokio::fs`. It runs to
//! completion before any network work is scheduled — there is nothing for it to
//! block — and an iterative walk with an explicit stack avoids both the boxing
//! that recursive `async fn` needs and the stack overflow that deep recursion
//! risks on a pathological tree.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::commands::recovery::Selection;
use crate::platform::path as logical;

/// One file the backup would store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScannedFile {
    /// Canonical logical path, relative to the scan root.
    pub logical: String,
    /// Where it lives on this machine.
    pub native: PathBuf,
    /// Size in bytes at the time of the scan.
    pub size: u64,
}

/// Something the walk could not do, kept rather than swallowed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Problem {
    /// The path involved, rendered for display.
    pub path: String,
    /// What went wrong, in a form a person can act on.
    pub detail: String,
}

/// The result of one walk.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Scan {
    /// Files that passed every filter, sorted by logical path.
    pub files: Vec<ScannedFile>,
    /// Symbolic links that were not followed, sorted.
    pub skipped_links: Vec<String>,
    /// Files excluded by `--min-size`, `--max-size`, `--max-depth` or
    /// `--files-from`. A count rather than a list: on a partial backup this is
    /// the *majority* of the tree, and listing it would bury the plan.
    pub filtered: usize,
    /// Everything that could not be read or represented.
    pub problems: Vec<Problem>,
}

impl Scan {
    /// Total size of everything that would be stored.
    ///
    /// Saturating rather than wrapping: a scan over a multi-petabyte tree must
    /// report a wrong-but-huge number rather than a small, believable one.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.files
            .iter()
            .fold(0_u64, |total, file| total.saturating_add(file.size))
    }

    /// The logical paths, in scan order — the input to the name pre-flight.
    #[must_use]
    pub fn logical_paths(&self) -> Vec<String> {
        self.files.iter().map(|file| file.logical.clone()).collect()
    }
}

/// Walk `root`, honouring `selection`.
///
/// A root that is a single file scans as a one-entry tree, so
/// `dctl backup notes.txt vault:` behaves the way it reads.
#[must_use]
pub fn walk(root: &Path, selection: &Selection, follow_links: bool) -> Scan {
    let mut scan = Scan::default();

    match std::fs::symlink_metadata(root) {
        Err(error) => {
            scan.problems.push(Problem {
                path: root.display().to_string(),
                detail: error.to_string(),
            });
            return scan;
        }
        Ok(metadata) if metadata.is_file() => {
            // A single file is its own logical path: the name, nothing else —
            // through the same gate as every name the walk below produces.
            match root.file_name().map(logical::to_logical_component) {
                Some(Ok(name)) => consider(
                    &mut scan,
                    selection,
                    ScannedFile {
                        logical: name,
                        native: root.to_path_buf(),
                        size: metadata.len(),
                    },
                    1,
                ),
                Some(Err(issue)) => scan.problems.push(not_representable(root, issue)),
                // A path with no final component (`..`, or a bare root) names no
                // file, whatever `symlink_metadata` just said about it.
                None => scan
                    .problems
                    .push(not_representable(root, logical::Unrepresentable::ParentDir)),
            }
            return scan;
        }
        Ok(_) => {}
    }

    // (directory, depth of its children)
    let mut stack: Vec<(PathBuf, i32)> = vec![(root.to_path_buf(), 1)];
    let mut visited: HashSet<PathBuf> = HashSet::new();

    while let Some((directory, depth)) = stack.pop() {
        if follow_links && !remember(&mut visited, &directory) {
            // Already walked through this directory by another route: a symlink
            // loop, or two links to the same tree. Either way, walking it twice
            // would at best duplicate work and at worst never finish.
            continue;
        }

        let entries = match read_sorted(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                scan.problems.push(Problem {
                    path: directory.display().to_string(),
                    detail: error.to_string(),
                });
                continue;
            }
        };

        for entry in entries {
            let relative = match logical::to_logical(entry.strip_prefix(root).unwrap_or(&entry)) {
                Ok(relative) => relative,
                Err(issue) => {
                    scan.problems.push(not_representable(&entry, issue));
                    continue;
                }
            };

            let metadata = match std::fs::symlink_metadata(&entry) {
                Ok(metadata) => metadata,
                Err(error) => {
                    scan.problems.push(Problem {
                        path: entry.display().to_string(),
                        detail: error.to_string(),
                    });
                    continue;
                }
            };

            if metadata.is_symlink() && !follow_links {
                scan.skipped_links.push(relative);
                continue;
            }

            // Following a link means asking about its target instead.
            let resolved = if metadata.is_symlink() {
                match std::fs::metadata(&entry) {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        scan.problems.push(Problem {
                            path: entry.display().to_string(),
                            detail: format!("symlink target: {error}"),
                        });
                        continue;
                    }
                }
            } else {
                metadata
            };

            if resolved.is_dir() {
                if selection.admits_depth(depth) {
                    stack.push((entry, depth + 1));
                } else {
                    scan.filtered += 1;
                }
                continue;
            }

            consider(
                &mut scan,
                selection,
                ScannedFile {
                    logical: relative,
                    native: entry,
                    size: resolved.len(),
                },
                depth,
            );
        }
    }

    scan.files.sort_by(|a, b| a.logical.cmp(&b.logical));
    scan.skipped_links.sort();
    scan.problems.sort_by(|a, b| a.path.cmp(&b.path));
    scan
}

/// Apply the filters to one candidate file.
fn consider(scan: &mut Scan, selection: &Selection, file: ScannedFile, depth: i32) {
    if selection.admits_depth(depth)
        && selection.admits_size(file.size)
        && selection.admits_path(&file.logical)
    {
        scan.files.push(file);
    } else {
        scan.filtered += 1;
    }
}

/// A name this platform holds but the vault cannot address.
///
/// Logical paths are UTF-8, and free of any character another platform reads as
/// a separator, because the index key is a hash of their bytes and a vault has
/// to be readable — and addressable — from every platform. Such a name is
/// reported rather than lossily converted: storing `photo?.jpg`, or splitting
/// `a\b.txt` into two components, would break the promise that a restore
/// reproduces exactly what was backed up.
///
/// The reason comes from [`logical::to_logical`] rather than being guessed
/// here, so the operator is told which rule actually fired.
fn not_representable(path: &Path, issue: logical::Unrepresentable) -> Problem {
    Problem {
        path: path.display().to_string(),
        detail: issue.to_string(),
    }
}

/// List a directory's children, sorted, so the walk is reproducible.
fn read_sorted(directory: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(directory)?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .collect();
    entries.sort();
    Ok(entries)
}

/// Record that a directory has been entered; `false` if it already had been.
///
/// Canonicalised, because two different paths reaching the same directory is
/// exactly the case worth catching. If canonicalisation fails the path itself is
/// used, which is conservative in the right direction: a directory is walked
/// once more rather than skipped.
fn remember(visited: &mut HashSet<PathBuf>, directory: &Path) -> bool {
    let key = std::fs::canonicalize(directory).unwrap_or_else(|_| directory.to_path_buf());
    visited.insert(key)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::cli::globals::GlobalArgs;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn selection(args: &[&str]) -> Selection {
        let globals =
            Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals;
        Selection::resolve(&globals).unwrap()
    }

    /// A small tree: two files at the top, one nested two levels down.
    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("a.txt"), "aaaa").unwrap();
        std::fs::write(root.join("b.txt"), "bb").unwrap();
        std::fs::create_dir_all(root.join("nested/deep")).unwrap();
        std::fs::write(root.join("nested/c.txt"), "cccccc").unwrap();
        std::fs::write(root.join("nested/deep/d.txt"), "d").unwrap();
        dir
    }

    fn paths(scan: &Scan) -> Vec<String> {
        scan.files.iter().map(|file| file.logical.clone()).collect()
    }

    #[test]
    fn a_whole_tree_is_walked_in_a_stable_order() {
        let dir = tree();
        let scan = walk(dir.path(), &selection(&[]), false);
        assert_eq!(
            paths(&scan),
            vec!["a.txt", "b.txt", "nested/c.txt", "nested/deep/d.txt"]
        );
        assert_eq!(scan.total_bytes(), 4 + 2 + 6 + 1);
        assert!(scan.problems.is_empty());
    }

    #[test]
    fn a_single_file_root_scans_as_a_one_entry_tree() {
        let dir = tree();
        let scan = walk(&dir.path().join("a.txt"), &selection(&[]), false);
        assert_eq!(paths(&scan), vec!["a.txt"]);
        assert_eq!(scan.total_bytes(), 4);
    }

    #[test]
    fn a_missing_root_is_a_problem_not_a_panic() {
        let scan = walk(Path::new("/nonexistent/tree"), &selection(&[]), false);
        assert!(scan.files.is_empty());
        assert_eq!(scan.problems.len(), 1);
    }

    #[test]
    fn depth_one_keeps_only_the_top_level() {
        let dir = tree();
        let scan = walk(dir.path(), &selection(&["--max-depth", "1"]), false);
        assert_eq!(paths(&scan), vec!["a.txt", "b.txt"]);
        assert!(scan.filtered > 0, "the rest must be counted, not vanish");
    }

    #[test]
    fn size_bounds_exclude_without_losing_the_count() {
        let dir = tree();
        let scan = walk(dir.path(), &selection(&["--min-size", "3"]), false);
        assert_eq!(paths(&scan), vec!["a.txt", "nested/c.txt"]);
        assert_eq!(scan.filtered, 2);
    }

    #[test]
    fn an_explicit_path_list_selects_exactly_those_files() {
        let dir = tree();
        let list = dir.path().join("wanted.txt");
        std::fs::write(&list, "nested/c.txt\n").unwrap();
        let list_arg = list.display().to_string();

        let scan = walk(
            dir.path(),
            &selection(&["--files-from", list_arg.as_str()]),
            false,
        );
        assert_eq!(paths(&scan), vec!["nested/c.txt"]);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_skipped_by_default_and_reported() {
        let dir = tree();
        std::os::unix::fs::symlink(dir.path().join("a.txt"), dir.path().join("link.txt")).unwrap();

        let scan = walk(dir.path(), &selection(&[]), false);
        assert_eq!(scan.skipped_links, vec!["link.txt"]);
        assert!(!paths(&scan).contains(&"link.txt".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn following_symlinks_includes_the_target() {
        let dir = tree();
        std::os::unix::fs::symlink(dir.path().join("a.txt"), dir.path().join("link.txt")).unwrap();

        let scan = walk(dir.path(), &selection(&[]), true);
        assert!(scan.skipped_links.is_empty());
        assert!(paths(&scan).contains(&"link.txt".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_loop_terminates() {
        // The oldest way to make a backup tool run until the disk fills.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir(root.join("inner")).unwrap();
        std::fs::write(root.join("inner/a.txt"), "a").unwrap();
        std::os::unix::fs::symlink(root, root.join("inner/loop")).unwrap();

        let scan = walk(root, &selection(&[]), true);
        assert!(
            scan.files.len() < 10,
            "the walk should not have revisited the tree: {:?}",
            paths(&scan)
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_broken_symlink_is_a_problem_rather_than_a_stop() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("real.txt"), "r").unwrap();
        std::os::unix::fs::symlink(dir.path().join("gone.txt"), dir.path().join("dangling.txt"))
            .unwrap();

        let scan = walk(dir.path(), &selection(&[]), true);
        // The good file is still found.
        assert!(paths(&scan).contains(&"real.txt".to_string()));
        assert_eq!(scan.problems.len(), 1);
        assert!(scan.problems[0].path.contains("dangling.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn a_backslash_in_a_name_is_a_problem_rather_than_an_ambiguous_key() {
        // Legal on this platform, a separator on Windows: the name has no single
        // logical spelling, so it is reported instead of stored under a key that
        // a spec naming the same file would never produce.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(r"a\b.txt"), "x").unwrap();
        std::fs::write(dir.path().join("clean.txt"), "y").unwrap();

        let scan = walk(dir.path(), &selection(&[]), false);
        assert_eq!(paths(&scan), vec!["clean.txt"]);
        assert_eq!(scan.problems.len(), 1);
        assert!(
            scan.problems[0].detail.contains('\\'),
            "the reason must name the offending character: {}",
            scan.problems[0].detail
        );
    }

    #[test]
    fn an_empty_tree_scans_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let scan = walk(dir.path(), &selection(&[]), false);
        assert!(scan.files.is_empty());
        assert!(scan.problems.is_empty());
        assert_eq!(scan.total_bytes(), 0);
    }

    #[test]
    fn logical_paths_feed_the_preflight_directly() {
        let dir = tree();
        let scan = walk(dir.path(), &selection(&[]), false);
        assert_eq!(scan.logical_paths(), paths(&scan));
    }

    #[test]
    fn an_absurd_total_saturates() {
        let mut scan = Scan::default();
        for logical in ["a", "b"] {
            scan.files.push(ScannedFile {
                logical: logical.into(),
                native: PathBuf::from(logical),
                size: u64::MAX,
            });
        }
        assert_eq!(scan.total_bytes(), u64::MAX);
    }
}
