//! The tree itself: building it from paths, and drawing it.
//!
//! ## Why this one command holds a structure in memory
//!
//! Every other listing verb streams in constant memory, and `PLAN.md` §16.2 is
//! why. `tree` cannot, and the reason is inherent to the output rather than to
//! the implementation: the connector drawn beside a node depends on whether that
//! node has any **later siblings**, and a directory's later siblings are only
//! known once its entire subtree has been read. Drawing `├──` where `└──`
//! belonged is not a rounding error — it is a picture of a different tree.
//!
//! What is held is therefore the *drawing*, bounded by `--level`, and never the
//! objects: one name and one `u64` per node, no hashes, no timestamps, no
//! records. A ten-million-object vault drawn with `--dirs-only --level 2` costs
//! the directories at two levels and nothing else. The honest framing is that a
//! tree of ten million objects is not a readable artefact under any
//! implementation — [`ls`](super::super::ls) and [`size`](super::super::size) are
//! the commands for that scale, and they stream.
//!
//! Drawing itself *is* O(depth): the indent prefix is one buffer that grows and
//! shrinks as the walk descends and returns, rather than a copy per node, so a
//! pathologically deep path costs its own length and not its length squared.
//!
//! ## Insertion assumes sorted input, and does not require it
//!
//! Entries arrive in ascending path order (see
//! [`listing::source`](super::super::listing::source)), which means the child
//! being inserted is almost always the *last* child of the directory being
//! inserted into. Checking that first turns insertion into one comparison per
//! component. A source that broke the ordering contract would fall back to a
//! linear scan and still build the correct tree — slower, never wrong.

use crate::constants::{LISTING_DIR_SUFFIX, PATH_SEPARATOR};
use crate::error::Result;

use super::glyphs::Glyphs;

/// Index of the root inside [`Tree::nodes`].
const ROOT: usize = 0;

/// One node: a directory, a file, or the root.
struct Node {
    /// Final path component, or the root label.
    name: String,
    /// Whether anything can hang below it.
    is_dir: bool,
    /// Total bytes beneath it; for a file, its own size. [`None`] once anything
    /// with no recorded size has landed in it — see [`Tree::total_bytes`].
    size: Option<u64>,
    /// Child indices, in insertion order.
    children: Vec<usize>,
}

/// How many directories and files a rendering covered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Directories drawn.
    pub directories: u64,
    /// Objects drawn. Zero under `--dirs-only`, which draws none.
    pub files: u64,
}

/// One step of the drawing walk.
enum Step {
    /// Draw this node, then descend into it.
    Draw { node: usize, last: bool },
    /// Cut the indent prefix back to this byte length, having finished a
    /// directory. The reason the prefix can be one buffer instead of a copy per
    /// node.
    Unwind(usize),
}

/// A tree assembled from logical paths.
pub struct Tree {
    nodes: Vec<Node>,
    /// Deepest level that is kept; `None` for unlimited.
    level: Option<usize>,
}

impl Tree {
    /// An empty tree whose root prints as `label`.
    #[must_use]
    pub fn new(label: impl Into<String>, level: Option<usize>) -> Self {
        Self {
            nodes: vec![Node {
                name: label.into(),
                is_dir: true,
                // A known zero: a node with nothing under it yet holds nothing.
                size: Some(0),
                children: Vec::new(),
            }],
            level,
        }
    }

    /// Add one object at `relative` — a path below the tree's root.
    ///
    /// A path with more components than `level` allows contributes its size to
    /// the deepest node that is kept, and that node is drawn as a directory:
    /// truncating the *picture* must not truncate the arithmetic, or a pruned
    /// branch reports as empty.
    pub fn insert(&mut self, relative: &str, size: Option<u64>) {
        let components: Vec<&str> = relative
            .split(PATH_SEPARATOR)
            .filter(|part| !part.is_empty())
            .collect();
        let kept = components.len().min(self.level.unwrap_or(usize::MAX));

        let mut current = ROOT;
        self.add_size(current, size);

        for (index, name) in components.iter().take(kept).enumerate() {
            // Anything that is not the object's final component is a directory,
            // and so is a component that only survives because of the level cut.
            let is_dir = index + 1 < components.len();
            current = self.child(current, name, is_dir);
            self.add_size(current, size);
        }
    }

    /// Total bytes beneath the root, including objects pruned by `--level` — or
    /// [`None`] when any object in the tree had no recorded size.
    ///
    /// Absorbing rather than partial. A vault whose index was rebuilt from
    /// object headers records no sizes at all, and a footer reading
    /// `3 files, 0 B` under a drawing of three real files is the same confident
    /// zero this whole change exists to remove. A sum that quietly omitted the
    /// unmeasured files would be the same lie with better manners.
    #[must_use]
    pub fn total_bytes(&self) -> Option<u64> {
        self.nodes.get(ROOT).and_then(|root| root.size)
    }

    /// Whether anything at all was added.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes
            .get(ROOT)
            .is_none_or(|root| root.children.is_empty())
    }

    /// Draw the tree, one line per node, root label first.
    ///
    /// # Errors
    /// Whatever `emit` returned — in practice a stdout write failure.
    pub fn render(
        &self,
        glyphs: Glyphs,
        dirs_only: bool,
        emit: &mut dyn FnMut(&str) -> Result<()>,
    ) -> Result<Counts> {
        let mut counts = Counts::default();

        let Some(root) = self.nodes.get(ROOT) else {
            return Ok(counts);
        };
        emit(&root.name)?;

        // An explicit stack rather than recursion: path depth is bounded only by
        // what a user typed, and overflowing the call stack part-way through a
        // listing would be a crash, which this crate does not do.
        let mut prefix = String::new();
        let mut stack: Vec<Step> = Vec::new();
        // The root's own children start flush against the left margin, so the
        // root contributes no indent and needs nothing unwound.
        queue(&mut stack, &self.visible_children(ROOT, dirs_only));

        while let Some(step) = stack.pop() {
            let (node, last) = match step {
                Step::Unwind(length) => {
                    prefix.truncate(length);
                    continue;
                }
                Step::Draw { node, last } => (node, last),
            };

            let Some(current) = self.nodes.get(node) else {
                continue;
            };
            let suffix = if current.is_dir {
                counts.directories += 1;
                LISTING_DIR_SUFFIX.to_string()
            } else {
                counts.files += 1;
                String::new()
            };
            emit(&format!(
                "{prefix}{}{}{suffix}",
                glyphs.connector(last),
                current.name
            ))?;

            let children = self.visible_children(node, dirs_only);
            if !children.is_empty() {
                // Pushed before the children so it pops after them, restoring
                // the prefix for the next sibling.
                stack.push(Step::Unwind(prefix.len()));
                prefix.push_str(glyphs.continuation(last));
                queue(&mut stack, &children);
            }
        }

        Ok(counts)
    }

    /// Find or create the child of `parent` named `name`.
    fn child(&mut self, parent: usize, name: &str, is_dir: bool) -> usize {
        // Sorted input means the answer is nearly always the most recent child.
        let recent = self
            .nodes
            .get(parent)
            .and_then(|node| node.children.last().copied())
            .filter(|last| self.nodes.get(*last).is_some_and(|n| n.name == name));
        if let Some(last) = recent {
            return last;
        }

        let existing = self.nodes.get(parent).and_then(|node| {
            node.children
                .iter()
                .copied()
                .find(|index| self.nodes.get(*index).is_some_and(|n| n.name == name))
        });
        if let Some(index) = existing {
            return index;
        }

        let index = self.nodes.len();
        self.nodes.push(Node {
            name: name.to_string(),
            is_dir,
            size: Some(0),
            children: Vec::new(),
        });
        if let Some(node) = self.nodes.get_mut(parent) {
            node.children.push(index);
        }
        index
    }

    /// Add `size` to a node's running total, or make that total unknown.
    fn add_size(&mut self, node: usize, size: Option<u64>) {
        if let Some(node) = self.nodes.get_mut(node) {
            node.size = node
                .size
                .zip(size)
                .map(|(total, added)| total.saturating_add(added));
        }
    }

    /// The children of `node` that will be drawn, sorted by name.
    fn visible_children(&self, node: usize, dirs_only: bool) -> Vec<usize> {
        let Some(parent) = self.nodes.get(node) else {
            return Vec::new();
        };
        let mut children: Vec<usize> = parent
            .children
            .iter()
            .copied()
            .filter(|index| !dirs_only || self.nodes.get(*index).is_some_and(|c| c.is_dir))
            .collect();
        // Sorted by name rather than left in insertion order: path order puts
        // `b.txt` before `b/` (`.` sorts below `/`), which reads as a mistake in
        // a tree even though it is a faithful echo of the index.
        children.sort_by(|left, right| self.name_of(*left).cmp(self.name_of(*right)));
        children
    }

    /// A node's name, or the empty string if the index is stale.
    fn name_of(&self, node: usize) -> &str {
        self.nodes.get(node).map_or("", |n| n.name.as_str())
    }
}

/// Push `children` so they pop in order, flagging the last one.
///
/// Reversed on the way in because a stack pops backwards, and the last child is
/// the one that gets the corner connector.
fn queue(stack: &mut Vec<Step>, children: &[usize]) {
    let Some(final_position) = children.len().checked_sub(1) else {
        return;
    };
    for (position, child) in children.iter().copied().enumerate().rev() {
        stack.push(Step::Draw {
            node: child,
            last: position == final_position,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CliError;
    use crate::exit::ExitCode;

    /// Build a tree and draw it, returning the lines.
    fn draw(paths: &[&str], level: Option<usize>, dirs_only: bool, glyphs: Glyphs) -> Vec<String> {
        let mut tree = Tree::new(".", level);
        for path in paths {
            tree.insert(path, Some(1));
        }
        let mut lines = Vec::new();
        {
            let mut emit = |line: &str| -> Result<()> {
                lines.push(line.to_string());
                Ok(())
            };
            tree.render(glyphs, dirs_only, &mut emit)
                .expect("collecting cannot fail");
        }
        lines
    }

    fn counts(paths: &[&str], dirs_only: bool) -> Counts {
        let mut tree = Tree::new(".", None);
        for path in paths {
            tree.insert(path, Some(1));
        }
        let mut sink = |_: &str| -> Result<()> { Ok(()) };
        tree.render(Glyphs::UNICODE, dirs_only, &mut sink)
            .expect("collecting cannot fail")
    }

    #[test]
    fn a_tree_nests_and_marks_the_last_child_of_every_directory() {
        let lines = draw(
            &["a/b/1.txt", "a/b/2.txt", "a/c/3.txt", "d/4.txt"],
            None,
            false,
            Glyphs::UNICODE,
        );
        assert_eq!(
            lines,
            vec![
                ".",
                "├── a/",
                "│   ├── b/",
                "│   │   ├── 1.txt",
                "│   │   └── 2.txt",
                "│   └── c/",
                "│       └── 3.txt",
                "└── d/",
                "    └── 4.txt",
            ]
        );
    }

    #[test]
    fn the_ascii_fallback_has_the_same_shape() {
        // Same tree, same indentation, different characters — which is what
        // makes `--ascii` a fallback rather than a different command.
        let unicode = draw(&["a/b/1.txt", "c.txt"], None, false, Glyphs::UNICODE);
        let ascii = draw(&["a/b/1.txt", "c.txt"], None, false, Glyphs::ASCII);
        assert_eq!(unicode.len(), ascii.len());
        for (left, right) in unicode.iter().zip(&ascii) {
            assert_eq!(
                left.chars().count(),
                right.chars().count(),
                "{left} / {right}"
            );
        }
        assert!(ascii.iter().all(|line| line.is_ascii()));
        assert_eq!(ascii[1], "|-- a/");
        assert_eq!(ascii[2], "|   `-- b/");
    }

    #[test]
    fn a_level_limit_prunes_the_picture_but_not_the_arithmetic() {
        let mut tree = Tree::new(".", Some(2));
        tree.insert("a/b/c/deep.bin", Some(1000));
        tree.insert("a/x.bin", Some(1));
        let mut lines = Vec::new();
        {
            let mut emit = |line: &str| -> Result<()> {
                lines.push(line.to_string());
                Ok(())
            };
            tree.render(Glyphs::UNICODE, false, &mut emit).unwrap();
        }
        assert_eq!(lines, vec![".", "└── a/", "    ├── b/", "    └── x.bin"]);
        // The pruned object still counts towards the total.
        assert_eq!(tree.total_bytes(), Some(1001));
    }

    #[test]
    fn a_pruned_node_is_drawn_as_a_directory() {
        // `b` only survives the cut because there is more below it; drawing it
        // as a file would claim the tree ends there.
        let lines = draw(&["a/b/c/d.bin"], Some(2), false, Glyphs::UNICODE);
        assert!(
            lines.last().is_some_and(|line| line.ends_with("b/")),
            "{lines:?}"
        );
    }

    #[test]
    fn dirs_only_drops_the_leaves() {
        let lines = draw(
            &["a/b/1.txt", "a/2.txt", "c.txt"],
            None,
            true,
            Glyphs::UNICODE,
        );
        assert_eq!(lines, vec![".", "└── a/", "    └── b/"]);
    }

    #[test]
    fn children_are_ordered_by_name_not_by_arrival() {
        // Path order puts `b.txt` before `b/` because '.' sorts below '/'; a
        // tree that echoed it would look broken.
        let lines = draw(&["b.txt", "b/inner.txt"], None, false, Glyphs::UNICODE);
        assert_eq!(lines, vec![".", "├── b/", "│   └── inner.txt", "└── b.txt"]);
    }

    #[test]
    fn an_empty_tree_is_just_its_root() {
        let mut tree = Tree::new("vault:", None);
        assert!(tree.is_empty());
        assert_eq!(draw(&[], None, false, Glyphs::UNICODE), vec!["."]);
        tree.insert("a.txt", Some(1));
        assert!(!tree.is_empty());
    }

    #[test]
    fn the_counts_separate_directories_from_files() {
        assert_eq!(
            counts(&["a/b/1.txt", "a/2.txt", "c.txt"], false),
            Counts {
                directories: 2,
                files: 3,
            }
        );
    }

    #[test]
    fn dirs_only_counts_only_directories() {
        let counts = counts(&["a/b/1.txt"], true);
        assert_eq!(counts.files, 0);
        assert_eq!(counts.directories, 2);
    }

    #[test]
    fn a_deep_path_neither_recurses_nor_copies_its_indent_per_level() {
        // A recursive renderer overflows here, and one that cloned the prefix
        // for every node would do quadratic work getting to the leaf.
        let depth = 5_000;
        let deep: Vec<&str> = std::iter::repeat_n("d", depth).collect();
        let path = format!("{}/leaf.bin", deep.join("/"));
        let lines = draw(&[&path], None, false, Glyphs::ASCII);
        assert_eq!(
            lines.len(),
            depth + 2,
            "root + {depth} directories + one leaf"
        );
        assert!(
            lines.last().is_some_and(|line| line.ends_with("leaf.bin")),
            "the walk did not reach the leaf"
        );
    }

    #[test]
    fn an_emit_failure_stops_the_drawing() {
        let mut tree = Tree::new(".", None);
        tree.insert("a/b.txt", Some(1));
        let mut failing = |_: &str| -> Result<()> {
            Err(CliError::new(ExitCode::Uncategorised, "stdout closed"))
        };
        let error = tree
            .render(Glyphs::UNICODE, false, &mut failing)
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Uncategorised);
    }

    #[test]
    fn an_unsorted_source_still_builds_the_right_tree() {
        // The fast path assumes sorted input; correctness must not.
        let sorted = draw(
            &["a/1.txt", "a/2.txt", "b/3.txt"],
            None,
            false,
            Glyphs::ASCII,
        );
        let shuffled = draw(
            &["b/3.txt", "a/2.txt", "a/1.txt"],
            None,
            false,
            Glyphs::ASCII,
        );
        assert_eq!(sorted, shuffled);
    }

    #[test]
    fn a_repeated_directory_is_one_node() {
        // Every object under `a` must attach to the same `a`, or the tree grows
        // one branch per file.
        let lines = draw(&["a/1", "a/2", "a/3"], None, true, Glyphs::ASCII);
        assert_eq!(lines, vec![".", "`-- a/"]);
    }
}
