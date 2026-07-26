//! Directories, inferred from the objects beneath them.
//!
//! An object store has no directories. `photos/2024/a.jpg` is one key with two
//! slashes in it, and every directory `lsd` or `tree` shows is something DCTL
//! decided existed because a path implied it. That inference has to happen
//! somewhere, and doing it once here is what keeps `lsd` and `tree` from
//! disagreeing about whether an empty prefix is a directory.
//!
//! ## Streaming, given sorted input
//!
//! The source contract (see [`super::source`]) is that entries arrive in
//! ascending path order, which means a directory's entire subtree is
//! *contiguous*. So a directory can be closed the moment the path leaves it,
//! and the aggregator only ever holds the chain of directories on the current
//! path — depth, not width, and certainly not the file list.
//!
//! ## The one thing that has to be buffered
//!
//! A directory's totals are only known once its subtree has been read, but
//! parents must print before their children or the output is not a listing of
//! anything recognisable. So a closed child waits in its parent's buffer until
//! the parent itself closes. That buffer holds *directories*, never objects, and
//! only those inside the top-level subtree currently open — at `lsd`'s default
//! depth of one it is always empty, and even under `--recursive` it is bounded
//! by the number of directories in one branch rather than by the size of the
//! vault.
//!
//! ## Totals are recursive
//!
//! `photos` reports every byte under it, including those in `photos/2024`, which
//! is what a user asking "how big is this directory" means. Each object is added
//! to every directory on the open chain, so the arithmetic costs O(depth) per
//! object and needs no second pass.

use crate::error::Result;

use super::entry::Entry;
use super::target::join;

/// One inferred directory and the totals of everything beneath it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Directory {
    path: String,
    /// Byte length of the listing root, so [`Directory::to_entry`] can re-root
    /// without every directory carrying its own copy of the prefix string.
    root_len: usize,
    bytes: u64,
    objects: u64,
}

impl Directory {
    /// Total bytes of every object beneath it, at any depth.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Number of objects beneath it, at any depth.
    #[must_use]
    pub const fn objects(&self) -> u64 {
        self.objects
    }

    /// The same directory as a listing [`Entry`], for the renderers and the
    /// JSON shape that do not care where an entry came from.
    #[must_use]
    pub fn to_entry(&self) -> Entry {
        Entry::directory(
            self.path.clone(),
            self.path.get(..self.root_len).unwrap_or_default(),
            self.bytes,
        )
    }
}

/// A directory currently open on the path being walked.
struct Open {
    /// This directory's own name, compared against the incoming path.
    name: String,
    /// Its full logical path.
    path: String,
    bytes: u64,
    objects: u64,
    /// Descendants that have already closed, in the order they must print.
    buffered: Vec<Directory>,
}

/// Turns a stream of objects into a stream of directories.
pub struct Aggregator {
    root: String,
    max_depth: Option<usize>,
    stack: Vec<Open>,
}

impl Aggregator {
    /// Aggregate objects below `root`, reporting directories no deeper than
    /// `max_depth` below it.
    ///
    /// `max_depth` bounds what is *reported*, not what is counted: objects
    /// deeper than the limit still contribute their bytes to the deepest
    /// directory that is shown, because "how big is this directory" has only one
    /// honest answer.
    #[must_use]
    pub fn new(root: impl Into<String>, max_depth: Option<usize>) -> Self {
        Self {
            root: root.into(),
            max_depth,
            stack: Vec::new(),
        }
    }

    /// Account for one object, emitting any directory it closed.
    ///
    /// # Errors
    /// Whatever `emit` returned.
    pub fn push(
        &mut self,
        entry: &Entry,
        emit: &mut dyn FnMut(&Directory) -> Result<()>,
    ) -> Result<()> {
        let components = entry.parent_components();
        let tracked = components.len().min(self.max_depth.unwrap_or(usize::MAX));

        // How much of the open chain this object still belongs to.
        let mut shared = 0usize;
        while shared < tracked {
            match (self.stack.get(shared), components.get(shared)) {
                (Some(open), Some(name)) if open.name == *name => shared += 1,
                _ => break,
            }
        }

        self.close_below(shared, emit)?;

        for index in shared..tracked {
            let Some(name) = components.get(index) else {
                break;
            };
            let path = {
                let parent = self
                    .stack
                    .last()
                    .map_or(self.root.as_str(), |open| open.path.as_str());
                join(parent, name)
            };
            self.stack.push(Open {
                name: (*name).to_string(),
                path,
                bytes: 0,
                objects: 0,
                buffered: Vec::new(),
            });
        }

        // Every open directory contains this object, so every one of them counts
        // it. Costs O(depth), which is what makes the totals recursive for free.
        for open in &mut self.stack {
            open.bytes = open.bytes.saturating_add(entry.size());
            open.objects = open.objects.saturating_add(1);
        }

        Ok(())
    }

    /// Close every remaining directory.
    ///
    /// # Errors
    /// Whatever `emit` returned.
    pub fn finish(mut self, emit: &mut dyn FnMut(&Directory) -> Result<()>) -> Result<()> {
        self.close_below(0, emit)
    }

    /// Close open directories until only `depth` remain.
    fn close_below(
        &mut self,
        depth: usize,
        emit: &mut dyn FnMut(&Directory) -> Result<()>,
    ) -> Result<()> {
        while self.stack.len() > depth {
            let Some(done) = self.stack.pop() else {
                break;
            };
            let summary = Directory {
                root_len: self.root.len(),
                path: done.path,
                bytes: done.bytes,
                objects: done.objects,
            };

            match self.stack.last_mut() {
                // The parent has not printed yet, so this subtree waits for it.
                Some(parent) => {
                    parent.buffered.push(summary);
                    parent.buffered.extend(done.buffered);
                }
                // Nothing above: this is a top-level directory and everything it
                // was holding can go out now, parent first.
                None => {
                    emit(&summary)?;
                    for child in &done.buffered {
                        emit(child)?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::listing::tests_support::entry;
    use crate::error::CliError;
    use crate::exit::ExitCode;

    /// Run the aggregator over a sorted set of paths and collect what it emits.
    fn aggregate(root: &str, max_depth: Option<usize>, paths: &[(&str, u64)]) -> Vec<Directory> {
        let mut collected = Vec::new();
        let mut aggregator = Aggregator::new(root, max_depth);
        {
            let mut emit = |dir: &Directory| -> Result<()> {
                collected.push(dir.clone());
                Ok(())
            };
            for (path, size) in paths {
                aggregator
                    .push(&entry(root, path, *size), &mut emit)
                    .expect("collecting cannot fail");
            }
            aggregator
                .finish(&mut emit)
                .expect("collecting cannot fail");
        }
        collected
    }

    fn rows(dirs: &[Directory]) -> Vec<(String, u64, u64)> {
        dirs.iter()
            .map(|d| (d.to_entry().path().to_string(), d.bytes(), d.objects()))
            .collect()
    }

    /// The expected shape of a row, spelled the way the assertions read.
    fn row(path: &str, bytes: u64, objects: u64) -> (String, u64, u64) {
        (path.to_string(), bytes, objects)
    }

    #[test]
    fn one_level_is_the_default_shape_of_lsd() {
        let dirs = aggregate(
            "",
            Some(1),
            &[
                ("docs/a.txt", 10),
                ("photos/2024/a.jpg", 100),
                ("photos/2024/b.jpg", 200),
                ("photos/c.jpg", 1),
            ],
        );
        assert_eq!(rows(&dirs), vec![row("docs", 10, 1), row("photos", 301, 3)]);
    }

    #[test]
    fn totals_include_everything_beneath_a_directory() {
        // The question a size column answers is "how big is this tree", not
        // "how big are the files sitting directly in it".
        let dirs = aggregate("", None, &[("a/b/c/deep.bin", 4096)]);
        assert_eq!(
            rows(&dirs),
            vec![
                row("a", 4096, 1),
                row("a/b", 4096, 1),
                row("a/b/c", 4096, 1)
            ]
        );
    }

    #[test]
    fn parents_print_before_their_children() {
        // Totals are only known when a directory closes, which is *after* its
        // children close; the output order must not show that.
        let dirs = aggregate(
            "",
            None,
            &[("a/x/1.bin", 1), ("a/y/2.bin", 2), ("b/3.bin", 4)],
        );
        assert_eq!(
            rows(&dirs),
            vec![
                row("a", 3, 2),
                row("a/x", 1, 1),
                row("a/y", 2, 1),
                row("b", 4, 1)
            ]
        );
    }

    #[test]
    fn objects_deeper_than_the_limit_still_count_towards_what_is_shown() {
        // Truncating the report must not truncate the arithmetic, or a top-level
        // directory full of nested files reports as empty.
        let dirs = aggregate("", Some(1), &[("a/b/c/d.bin", 999)]);
        assert_eq!(rows(&dirs), vec![row("a", 999, 1)]);
    }

    #[test]
    fn objects_in_the_root_imply_no_directory() {
        assert!(aggregate("", None, &[("a.txt", 1), ("b.txt", 2)]).is_empty());
    }

    #[test]
    fn directories_are_reported_relative_to_the_listing_root() {
        let dirs = aggregate("photos", Some(1), &[("photos/2024/a.jpg", 5)]);
        assert_eq!(rows(&dirs), vec![row("photos/2024", 5, 1)]);
        // And convert to an entry whose relative path drops the root again.
        let entry = dirs.first().expect("one directory").to_entry();
        assert_eq!(entry.relative(), "2024");
        assert!(entry.is_dir());
        assert_eq!(entry.size(), 5);
    }

    #[test]
    fn a_sibling_that_shares_a_name_prefix_is_a_different_directory() {
        // `photos` and `photos-backup` sort adjacently and must not merge.
        let dirs = aggregate(
            "",
            Some(1),
            &[("photos-backup/a.jpg", 2), ("photos/a.jpg", 1)],
        );
        assert_eq!(
            rows(&dirs),
            vec![row("photos-backup", 2, 1), row("photos", 1, 1)]
        );
    }

    #[test]
    fn a_deep_chain_costs_only_its_own_depth() {
        // Ten thousand objects in one directory must not accumulate ten thousand
        // buffered rows.
        let paths: Vec<(String, u64)> = (0..10_000)
            .map(|n| (format!("bulk/f{n:05}.bin"), 1))
            .collect();
        let borrowed: Vec<(&str, u64)> = paths.iter().map(|(p, s)| (p.as_str(), *s)).collect();
        let dirs = aggregate("", None, &borrowed);
        assert_eq!(rows(&dirs), vec![row("bulk", 10_000, 10_000)]);
    }

    #[test]
    fn an_emit_failure_stops_the_aggregation() {
        let mut aggregator = Aggregator::new("", Some(1));
        let mut emit = |_: &Directory| -> Result<()> {
            Err(CliError::new(ExitCode::Uncategorised, "stdout gone"))
        };
        aggregator
            .push(&entry("", "a/1.bin", 1), &mut emit)
            .expect("nothing closes yet");
        // `b` closes `a`, which is the first thing to reach the sink.
        let error = aggregator
            .push(&entry("", "b/1.bin", 1), &mut emit)
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Uncategorised);
    }

    #[test]
    fn an_empty_listing_produces_no_directories() {
        assert!(aggregate("", None, &[]).is_empty());
    }

    #[test]
    fn a_zero_depth_limit_reports_nothing() {
        // `--max-depth 0` asks for the levels above the top one, of which there
        // are none. Reporting the top level anyway would ignore the flag.
        assert!(aggregate("", Some(0), &[("a/b.txt", 1)]).is_empty());
    }
}
