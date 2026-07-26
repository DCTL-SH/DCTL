//! The pattern-filter engine: one implementation, shared by every command.
//!
//! `--include`, `--exclude`, `--filter-from`, `--files-from`, `--min-size`,
//! `--max-size` and `--max-depth` are documented global flags, and they decide
//! *which files exist* as far as a run is concerned. That makes them the one
//! setting three separate implementations must never be allowed to disagree
//! about: a file that a listing shows and the copy that follows omits is a
//! reporting bug, and a file that a listing hides and a `sync` then treats as an
//! extra is a deletion. So there is one engine, built here, and the commands
//! consult it rather than each interpreting the flags for themselves.
//!
//! ## Rules are evaluated in order, and the first match wins
//!
//! Not "all the excludes, then all the includes". rclone's rule, because
//! rclone's patterns are the ones users bring, and because it is the only
//! ordering that makes the common shape expressible at all:
//!
//! ```text
//! - /work/**/target/     # not the build output
//! + /work/**             # but everything else under work/
//! - **                   # and nothing anywhere else
//! ```
//!
//! Read top to bottom, that is exactly what it says. Under an "excludes first"
//! reading the narrow exception could never be written, because the broad
//! inclusion below it would have no way to lose.
//!
//! ## The asymmetry that surprises people
//!
//! **Using `--include` at all changes what happens to files that match nothing.**
//!
//! With no `--include` anywhere, an unmatched file is *kept*: `--exclude '*.tmp'`
//! means "everything except the temporary files", which is what everyone
//! expects. The moment a single `--include` appears, DCTL appends an implicit
//! `--exclude '**'` to the end of the rule list — so an unmatched file is
//! *dropped*, and `--include '*.jpg'` means "the JPEGs and nothing else".
//!
//! This catches people out in its mixed form. `--include '*.jpg' --exclude
//! '*.png'` does **not** mean "everything except PNGs, plus the JPEGs". It means
//! "the JPEGs only" — the `--exclude` is redundant, and the `.txt` files nobody
//! mentioned are gone. That is rclone's behaviour, and DCTL matches it rather
//! than inventing a kinder one, because the kinder rule would silently transfer
//! files a script written for rclone was relied upon to leave behind.
//!
//! The implicit exclusion comes from the **flag**, not from a rule file. A
//! `--filter-from` file that contains only `+ *.jpg` still keeps everything else,
//! because a rule file is an ordered program whose author is expected to write
//! their own final `- **`. Again: rclone's split, kept deliberately.
//!
//! ## `--files-from` is not a pattern
//!
//! It is an exact list of logical paths, and it *disables traversal*: nothing is
//! walked, nothing is globbed, and each named path is looked up directly. A
//! caller must therefore ask [`FilterSet::disables_traversal`] before deciding
//! how to enumerate, or it will do a full walk and then throw almost all of it
//! away — which is not merely slow, it is a different set of side effects
//! (every directory read, every remote page fetched) than the operator asked for.
//!
//! ## Everything is matched against the logical path
//!
//! Always `/`-separated, always NFC, on every platform
//! ([`crate::platform::path`]). A Windows operator's `--include` therefore
//! behaves identically to a Linux operator's, and a rule typed on a Mac matches
//! the accented directory it was written for rather than silently missing it.
//!
//! ## Order of evaluation
//!
//! For one candidate, in this order: the `--files-from` list, then `--max-depth`,
//! then the size bounds, then the pattern rules. The cheap, total tests come
//! first, and the size bounds are applied to files only — a directory's size is
//! an aggregate, and excluding a directory because its total exceeded
//! `--max-size` would hide every small file inside a large tree.

// This module is complete and tested but not yet wired into the three call
// sites that currently refuse these flags (`commands/transfer/compare.rs`,
// `commands/listing/filter.rs`, `commands/recovery/selection.rs`). Building the
// engine first and connecting it in a separate step is what keeps the three
// from being given three subtly different implementations; until that step
// lands, every item here is unreachable from `main` and the compiler is right
// to say so.
#![allow(dead_code)]

mod depth;
mod glob;
mod parse;
mod rule;
mod size;

// Only the types a call site has to name are re-exported. A pattern failure and
// a rule-file failure are both turned into a [`CliError`] before they leave this
// module — classification is the one thing a command must never have to redo —
// so their own types stay internal.
pub use depth::{DepthLimit, depth_of};
pub use parse::{Directive, FileProblem};
pub use rule::{Action, Rule};
pub use size::SizeBounds;

use depth::DepthProblem;
use size::SizeProblem;

use std::collections::BTreeSet;
use std::path::Path;

use crate::cli::globals::GlobalArgs;
use crate::constants::{
    FILTER_FLAG_EXCLUDE, FILTER_FLAG_FILES_FROM, FILTER_FLAG_FILTER_FROM, FILTER_FLAG_INCLUDE,
    GLOB_RECURSIVE_SEQUENCE, PATH_SEPARATOR,
};
use crate::error::{CliError, Result};

// ─────────────────────────────────────────────────────────────────────────────
// What is being filtered
// ─────────────────────────────────────────────────────────────────────────────

/// One entry offered to the filter.
///
/// Borrows its path rather than owning it because a walk offers thousands per
/// second and none of them outlive the question being asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate<'a> {
    path: &'a str,
    size: u64,
    is_dir: bool,
}

impl<'a> Candidate<'a> {
    /// A file at `path`, of `size` bytes.
    pub const fn file(path: &'a str, size: u64) -> Self {
        Self {
            path,
            size,
            is_dir: false,
        }
    }

    /// A directory at `path`.
    ///
    /// Carries no size: a directory's size is the total beneath it, and letting
    /// that number reach the size bounds would hide every small file in a large
    /// tree.
    pub const fn directory(path: &'a str) -> Self {
        Self {
            path,
            size: 0,
            is_dir: true,
        }
    }

    /// The root-relative logical path.
    pub const fn path(&self) -> &'a str {
        self.path
    }

    /// The size in bytes; always zero for a directory.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Whether this entry is a directory.
    pub const fn is_dir(&self) -> bool {
        self.is_dir
    }

    /// How many components below the transfer root this entry sits.
    pub fn depth(&self) -> usize {
        depth_of(self.path)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Why
// ─────────────────────────────────────────────────────────────────────────────

/// What decided a candidate's fate.
///
/// Carried rather than collapsed into a bare boolean so `--dump filters` can say
/// *which* rule dropped a file. "3,000 files skipped" is a shrug; "excluded by
/// `- **` (rule 3)" is something an operator can fix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason<'a> {
    /// No filter is in force.
    Unfiltered,
    /// A `--files-from` list was given and does not name this path.
    NotListed,
    /// Deeper than `--max-depth`.
    TooDeep { depth: usize, limit: usize },
    /// Smaller than `--min-size`.
    TooSmall { size: u64, limit: u64 },
    /// Larger than `--max-size`.
    TooLarge { size: u64, limit: u64 },
    /// The first rule that matched, and its position in the list.
    Matched { rule: &'a Rule, position: usize },
    /// No rule matched, so the default applied. See the asymmetry described in
    /// the module documentation.
    Unmatched,
}

/// A verdict and the reason for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision<'a> {
    action: Action,
    reason: Reason<'a>,
}

impl<'a> Decision<'a> {
    const fn new(action: Action, reason: Reason<'a>) -> Self {
        Self { action, reason }
    }

    /// Whether the candidate is in scope.
    pub const fn admits(&self) -> bool {
        self.action.admits()
    }

    /// The verdict.
    pub const fn action(&self) -> Action {
        self.action
    }

    /// Why.
    pub const fn reason(&self) -> Reason<'a> {
        self.reason
    }

    /// One line for a log or a `--dump filters` trace.
    pub fn describe(&self) -> String {
        let verdict = self.action.describe();
        match self.reason {
            Reason::Unfiltered => format!("{verdict}: no filter is in force"),
            Reason::NotListed => {
                format!("{verdict}: not named by {FILTER_FLAG_FILES_FROM}")
            }
            Reason::TooDeep { depth, limit } => {
                format!("{verdict}: depth {depth} is past the limit of {limit}")
            }
            Reason::TooSmall { size, limit } => {
                format!("{verdict}: {size} bytes is below the minimum of {limit}")
            }
            Reason::TooLarge { size, limit } => {
                format!("{verdict}: {size} bytes is above the maximum of {limit}")
            }
            Reason::Matched { rule, position } => format!(
                "{verdict}: rule {} '{} {}'",
                position + 1,
                rule.action().marker(),
                rule.pattern()
            ),
            Reason::Unmatched => format!("{verdict}: no rule matched, so the default applied"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The engine
// ─────────────────────────────────────────────────────────────────────────────

/// The complete set of filters one run is subject to.
#[derive(Clone, Debug)]
pub struct FilterSet {
    rules: Vec<Rule>,
    /// What happens to a candidate no rule matched. See the asymmetry in the
    /// module documentation.
    default_action: Action,
    sizes: SizeBounds,
    depth: DepthLimit,
    /// The exact paths named by `--files-from`, if any.
    only: Option<BTreeSet<String>>,
}

impl Default for FilterSet {
    fn default() -> Self {
        Self::everything()
    }
}

impl FilterSet {
    /// A filter that admits everything.
    pub const fn everything() -> Self {
        Self {
            rules: Vec::new(),
            default_action: Action::Include,
            sizes: SizeBounds::open(),
            depth: DepthLimit::unlimited(),
            only: None,
        }
    }

    /// Start building a filter, in rule order.
    pub fn builder() -> Builder {
        Builder::new()
    }

    /// Build the filter from the global flags.
    ///
    /// # Ordering
    ///
    /// The engine evaluates rules in the order it is given them, and rclone
    /// orders them by their position on the command line. `clap`'s derive hands
    /// back `--include` and `--exclude` as two separate `Vec<String>`, which
    /// discards that interleaving before this function is reached, so the order
    /// applied here is a deterministic reconstruction rather than the literal
    /// command line:
    ///
    /// 1. every `--exclude`, in the order given;
    /// 2. every `--filter-from` file, in the order given, lines in file order;
    /// 3. every `--include`, in the order given;
    /// 4. an implicit `- **` if any `--include` was used.
    ///
    /// Exclusions lead because they are the rules whose failure is
    /// unrecoverable. Of the two ways a reconstruction can be wrong, "showed or
    /// copied less than asked" is fixed by re-running, while "copied a file the
    /// operator told us to leave behind" cannot be taken back — and during a
    /// `sync` the same mistake deletes at the destination. A rule *file* keeps
    /// its internal order exactly, because that order is the whole reason the
    /// form exists.
    ///
    /// Recovering the true command-line order needs the flag layer to record it
    /// — a `clap` value parser that stamps each pattern with its argument index,
    /// after which [`FilterSet::builder`] can be fed the merged sequence and
    /// this reconstruction disappears. The builder is already the engine's real
    /// interface for exactly that reason.
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::Usage`] for a malformed pattern, size or depth,
    /// or for a filter file that cannot be read or understood.
    pub fn from_globals(globals: &GlobalArgs) -> Result<Self> {
        let mut builder = Builder::new();

        for pattern in &globals.exclude {
            builder = builder.exclude(pattern)?;
        }
        for source in &globals.filter_from {
            builder = builder.rules_from(source)?;
        }
        for pattern in &globals.include {
            builder = builder.include(pattern)?;
        }

        for source in &globals.files_from {
            builder = builder.only_from(source)?;
        }

        builder = builder
            .sizes(SizeBounds::parse(
                globals.min_size.as_deref(),
                globals.max_size.as_deref(),
            )?)
            .depth(DepthLimit::from_flag(globals.max_depth)?);

        Ok(builder.build())
    }

    /// Decide a candidate's fate, with the reason.
    pub fn decide<'a>(&'a self, candidate: &Candidate<'_>) -> Decision<'a> {
        if !self.is_restricting() {
            return Decision::new(Action::Include, Reason::Unfiltered);
        }

        if let Some(only) = &self.only {
            let listed = if candidate.is_dir() {
                is_under_any(only, candidate.path())
            } else {
                only.contains(candidate.path())
            };
            if !listed {
                return Decision::new(Action::Exclude, Reason::NotListed);
            }
        }

        let depth = candidate.depth();
        if let Some(limit) = self.depth.limit() {
            if depth > limit {
                return Decision::new(Action::Exclude, Reason::TooDeep { depth, limit });
            }
        }

        // Files only: see the note on `Candidate::directory`.
        if !candidate.is_dir() {
            let size = candidate.size();
            if let Some(limit) = self.sizes.min() {
                if size < limit {
                    return Decision::new(Action::Exclude, Reason::TooSmall { size, limit });
                }
            }
            if let Some(limit) = self.sizes.max() {
                if size > limit {
                    return Decision::new(Action::Exclude, Reason::TooLarge { size, limit });
                }
            }
        }

        for (position, rule) in self.rules.iter().enumerate() {
            if rule.matches(candidate) {
                return Decision::new(rule.action(), Reason::Matched { rule, position });
            }
        }

        Decision::new(self.default_action, Reason::Unmatched)
    }

    /// Whether a candidate is in scope.
    pub fn admits(&self, candidate: &Candidate<'_>) -> bool {
        self.decide(candidate).admits()
    }

    /// Whether a file is in scope.
    pub fn admits_file(&self, path: &str, size: u64) -> bool {
        self.admits(&Candidate::file(path, size))
    }

    /// Whether a directory is in scope.
    pub fn admits_dir(&self, path: &str) -> bool {
        self.admits(&Candidate::directory(path))
    }

    /// Whether a walk may descend into this directory.
    ///
    /// Distinct from [`FilterSet::admits_dir`] on purpose. A directory that is
    /// itself out of scope must still be entered when the limit that refused it
    /// was `--max-depth`, because the depth of a *directory* says nothing about
    /// whether the paths inside it were named by `--files-from`. Conflating the
    /// two is how a walk reports a directory as empty that is not.
    pub fn may_descend(&self, path: &str) -> bool {
        if !self.depth.may_descend(depth_of(path)) {
            return false;
        }
        if let Some(only) = &self.only {
            return is_under_any(only, path);
        }
        // A pattern rule may not prune a directory unless it names directories:
        // `--exclude '*.tmp'` says nothing about the tree, and refusing to enter
        // a directory whose *name* happened to match would drop everything under
        // it. A trailing-slash rule is the form that does mean "not this tree".
        !self
            .rules
            .iter()
            .any(|rule| rule.directories_only() && rule.matches(&Candidate::directory(path)))
    }

    /// Whether `--files-from` was given, which replaces traversal with lookups.
    pub const fn disables_traversal(&self) -> bool {
        self.only.is_some()
    }

    /// The exact path list, if one was given.
    pub fn explicit_paths(&self) -> Option<&BTreeSet<String>> {
        self.only.as_ref()
    }

    /// The compiled rules, in evaluation order.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The size bounds in force.
    pub const fn sizes(&self) -> SizeBounds {
        self.sizes
    }

    /// The depth limit in force.
    pub const fn depth(&self) -> DepthLimit {
        self.depth
    }

    /// Replace the depth limit; see [`DepthLimit::replaced_with`].
    pub fn with_depth_limit(mut self, limit: Option<usize>) -> Self {
        self.depth = self.depth.replaced_with(limit);
        self
    }

    /// Whether any restriction at all is in force.
    ///
    /// Used to word an empty result. "Nothing here" and "nothing survived your
    /// filters" are different answers, and reporting the first when the second
    /// is true sends the operator looking for data that was never missing.
    pub fn is_restricting(&self) -> bool {
        !self.rules.is_empty()
            || self.only.is_some()
            || self.sizes.is_limited()
            || self.depth.is_limited()
    }
}

/// Whether the set holds `path` itself or anything beneath it.
///
/// Public because a walk needs the question phrased about a directory before it
/// decides whether to open it, and the answer has to be the same one
/// [`FilterSet::decide`] will give afterwards.
///
/// A range query rather than a scan: a walk asks this once per directory, and a
/// linear pass over the list would make the walk quadratic in the size of a
/// `--files-from` manifest, which is exactly the input that tends to be large.
/// Comparison is component-aligned — `a/bb` is not an ancestor of `a/b/c.txt` —
/// for the same reason [`crate::platform::path::is_under`] is.
pub fn is_under_any(paths: &BTreeSet<String>, path: &str) -> bool {
    if path.is_empty() {
        return !paths.is_empty();
    }
    if paths.contains(path) {
        return true;
    }
    let prefix = format!("{path}{PATH_SEPARATOR}");
    paths
        .range(prefix.clone()..)
        .next()
        .is_some_and(|first| first.starts_with(&prefix))
}

// ─────────────────────────────────────────────────────────────────────────────
// Construction
// ─────────────────────────────────────────────────────────────────────────────

/// Accumulates rules in evaluation order.
///
/// The engine's real interface: rules go in the order they are to be tried, and
/// the caller — not this module — decides what that order is. Every method
/// returns a `Result` so a malformed pattern surfaces at the position it was
/// written rather than at the end of a batch, where a report could only name the
/// batch.
#[derive(Debug, Default)]
pub struct Builder {
    rules: Vec<Rule>,
    /// Set by [`Builder::include`] only. See the asymmetry in the module
    /// documentation: the implicit exclusion comes from the flag, never from a
    /// rule file.
    implicit_exclude: bool,
    sizes: SizeBounds,
    depth: DepthLimit,
    only: Option<BTreeSet<String>>,
}

impl Builder {
    fn new() -> Self {
        Self::default()
    }

    /// Append an `--include` rule, and arm the implicit trailing exclusion.
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::Usage`] for a malformed pattern.
    pub fn include(mut self, pattern: &str) -> Result<Self> {
        self.rules
            .push(compile(Action::Include, pattern, FILTER_FLAG_INCLUDE)?);
        self.implicit_exclude = true;
        Ok(self)
    }

    /// Append an `--exclude` rule.
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::Usage`] for a malformed pattern.
    pub fn exclude(mut self, pattern: &str) -> Result<Self> {
        self.rules
            .push(compile(Action::Exclude, pattern, FILTER_FLAG_EXCLUDE)?);
        Ok(self)
    }

    /// Append the rules in a `--filter-from` file, in file order.
    ///
    /// A `!` line in the file discards everything accumulated so far, including
    /// rules added before this call — that is what the directive means, and
    /// scoping it to the file would make it a different, quieter thing.
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::Usage`] if the file cannot be read, holds a line
    /// that is not a rule, or holds a malformed pattern. Each failure names the
    /// file and the line.
    pub fn rules_from(mut self, source: &Path) -> Result<Self> {
        for directive in parse::rules_from_file(source).map_err(from_file_problem)? {
            match directive {
                Directive::Clear { .. } => self.rules.clear(),
                Directive::Rule {
                    action,
                    pattern,
                    line,
                } => {
                    let origin = format!("{}:{line}", source.display());
                    self.rules.push(compile(action, &pattern, &origin)?);
                }
            }
        }
        Ok(self)
    }

    /// Append one rule with an explicit action, attributing failures to `origin`.
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::Usage`] for a malformed pattern.
    pub fn rule(mut self, action: Action, pattern: &str, origin: &str) -> Result<Self> {
        self.rules.push(compile(action, pattern, origin)?);
        if action == Action::Include {
            self.implicit_exclude = true;
        }
        Ok(self)
    }

    /// Merge a `--files-from` list into the exact path set.
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::Usage`] if the file cannot be read or holds a
    /// path that escapes the transfer root.
    pub fn only_from(mut self, source: &Path) -> Result<Self> {
        let paths = parse::paths_from_file(source).map_err(from_file_problem)?;
        self.only.get_or_insert_with(BTreeSet::new).extend(paths);
        Ok(self)
    }

    /// Set the exact path set outright.
    pub fn only(mut self, paths: BTreeSet<String>) -> Self {
        self.only = Some(paths);
        self
    }

    /// Set the size bounds.
    pub fn sizes(mut self, sizes: SizeBounds) -> Self {
        self.sizes = sizes;
        self
    }

    /// Set the depth limit.
    pub fn depth(mut self, depth: DepthLimit) -> Self {
        self.depth = depth;
        self
    }

    /// Finish, appending the implicit exclusion if `--include` was used.
    pub fn build(mut self) -> FilterSet {
        let default_action = if self.implicit_exclude {
            // Appended as a real, visible rule rather than left as a hidden
            // default, so `--dump filters` can name the thing that dropped a
            // file. "Excluded by rule 4, '- **'" is a sentence an operator can
            // act on; "excluded by an implicit default" is not.
            if let Ok(rule) = Rule::compile(Action::Exclude, GLOB_RECURSIVE_SEQUENCE) {
                self.rules.push(rule);
            }
            Action::Exclude
        } else {
            Action::Include
        };

        FilterSet {
            rules: self.rules,
            default_action,
            sizes: self.sizes,
            depth: self.depth,
            only: self.only,
        }
    }
}

/// Compile one rule, turning a pattern failure into a usage error that names
/// where the pattern came from.
fn compile(action: Action, pattern: &str, origin: &str) -> Result<Rule> {
    Rule::compile(action, pattern)
        .map_err(|error| CliError::usage(format!("{origin}: {error}")).with_hint(error.hint()))
}

/// Turn a filter-file failure into a usage error.
fn from_file_problem(problem: FileProblem) -> CliError {
    CliError::usage(format!(
        "{FILTER_FLAG_FILTER_FROM}/{FILTER_FLAG_FILES_FROM}: {problem}"
    ))
    .with_hint(problem.hint())
}

impl From<SizeProblem> for CliError {
    fn from(problem: SizeProblem) -> Self {
        Self::usage(problem.to_string()).with_hint(problem.hint())
    }
}

impl From<DepthProblem> for CliError {
    fn from(problem: DepthProblem) -> Self {
        Self::usage(problem.to_string()).with_hint(problem.hint())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::ExitCode;
    use clap::Parser;

    /// Minimal harness so the global block can be parsed in isolation.
    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn globals(args: &[&str]) -> GlobalArgs {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals
    }

    fn filters(args: &[&str]) -> FilterSet {
        FilterSet::from_globals(&globals(args)).expect("the flags should compile")
    }

    fn refuses(args: &[&str]) -> CliError {
        FilterSet::from_globals(&globals(args)).expect_err("the flags should be refused")
    }

    fn shows(set: &FilterSet, path: &str) -> bool {
        set.admits_file(path, 1024)
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("dctl-filter-{}-{}", std::process::id(), name));
        std::fs::create_dir_all(&dir).expect("temporary directory");
        dir
    }

    fn write(dir: &Path, name: &str, contents: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).expect("write the filter file");
        path
    }

    // ── The default ──────────────────────────────────────────────────────

    #[test]
    fn an_empty_filter_admits_everything() {
        let set = filters(&[]);
        assert!(!set.is_restricting());
        assert!(shows(&set, "a/b/c.txt"));
        assert!(set.admits_dir("anything"));
        assert!(!set.disables_traversal());
        assert_eq!(
            set.decide(&Candidate::file("a", 0)).reason(),
            Reason::Unfiltered
        );
        assert!(FilterSet::everything().admits_file("x", u64::MAX));
        assert!(FilterSet::default().admits_file("x", u64::MAX));
    }

    // ── Precedence ───────────────────────────────────────────────────────

    #[test]
    fn the_first_matching_rule_wins() {
        // The whole point of an ordered list: a narrow exception above a broad
        // rule, which "all excludes then all includes" could never express.
        let set = FilterSet::builder()
            .exclude("/work/**/target/**")
            .expect("rule 1")
            .include("/work/**")
            .expect("rule 2")
            .build();

        assert!(shows(&set, "work/src/main.rs"));
        assert!(!shows(&set, "work/src/target/debug/x"));
        // The implicit exclusion armed by `include` handles everything else.
        assert!(!shows(&set, "elsewhere/a.txt"));
    }

    #[test]
    fn reversing_the_order_reverses_the_answer() {
        // Proof that order really is the mechanism, not a coincidence of the
        // patterns above.
        let narrow_first = FilterSet::builder()
            .exclude("secret.txt")
            .expect("rule 1")
            .include("*.txt")
            .expect("rule 2")
            .build();
        let broad_first = FilterSet::builder()
            .include("*.txt")
            .expect("rule 1")
            .exclude("secret.txt")
            .expect("rule 2")
            .build();

        assert!(!shows(&narrow_first, "secret.txt"));
        assert!(shows(&broad_first, "secret.txt"));
        assert!(shows(&narrow_first, "notes.txt"));
        assert!(shows(&broad_first, "notes.txt"));
    }

    // ── The asymmetry ────────────────────────────────────────────────────

    #[test]
    fn an_include_with_no_exclude_drops_everything_else() {
        // The documented surprise, stated as a test so it cannot regress into
        // the kinder-but-wrong reading.
        let set = filters(&["--include", "*.jpg"]);
        assert!(shows(&set, "holiday/a.jpg"));
        assert!(!shows(&set, "holiday/a.raw"));
        assert!(!shows(&set, "notes.txt"));
    }

    #[test]
    fn mixing_include_and_exclude_still_drops_what_neither_names() {
        // `--include '*.jpg' --exclude '*.png'` is NOT "everything but PNGs
        // plus the JPEGs". It is "the JPEGs". rclone's behaviour, kept because
        // the kinder rule would silently transfer files a script written for
        // rclone relied on being left behind.
        let set = filters(&["--include", "*.jpg", "--exclude", "*.png"]);
        assert!(shows(&set, "a.jpg"));
        assert!(!shows(&set, "a.png"));
        assert!(!shows(&set, "a.txt"), "the unmentioned file is dropped too");
    }

    #[test]
    fn an_exclude_alone_keeps_everything_else() {
        let set = filters(&["--exclude", "*.tmp"]);
        assert!(!shows(&set, "a.tmp"));
        assert!(shows(&set, "a.txt"));
        assert!(shows(&set, "deep/tree/b.bin"));
    }

    #[test]
    fn several_includes_are_a_union() {
        let set = filters(&["--include", "*.jpg", "--include", "*.raw"]);
        assert!(shows(&set, "a.jpg"));
        assert!(shows(&set, "a.raw"));
        assert!(!shows(&set, "a.txt"));
    }

    #[test]
    fn the_implicit_exclusion_is_a_visible_rule() {
        // So `--dump filters` can name the thing that dropped a file, rather
        // than blaming an invisible default nobody can grep for.
        let set = filters(&["--include", "*.jpg"]);
        let decision = set.decide(&Candidate::file("a.txt", 1));
        assert!(!decision.admits());
        match decision.reason() {
            Reason::Matched { rule, .. } => {
                assert_eq!(rule.pattern(), GLOB_RECURSIVE_SEQUENCE);
                assert_eq!(rule.action(), Action::Exclude);
            }
            other => panic!("expected the implicit rule to decide, got {other:?}"),
        }
        assert!(decision.describe().contains("excluded"));
    }

    #[test]
    fn a_rule_file_carries_no_implicit_exclusion() {
        // rclone's split, kept deliberately: a rule file is an ordered program
        // whose author writes their own final `- **`.
        let dir = scratch("rulefile-default");
        let path = write(&dir, "only-includes.txt", "+ *.jpg\n");
        let set = FilterSet::builder()
            .rules_from(&path)
            .expect("the file should parse")
            .build();

        assert!(shows(&set, "a.jpg"));
        assert!(shows(&set, "a.txt"), "everything else is still kept");
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── Anchoring, wildcards, classes, alternation ────────────────────────

    #[test]
    fn a_bare_pattern_matches_the_name_at_any_depth() {
        let set = filters(&["--include", "*.jpg"]);
        assert!(shows(&set, "a.jpg"));
        assert!(shows(&set, "photos/2024/a.jpg"));
    }

    #[test]
    fn a_leading_slash_anchors_at_the_transfer_root() {
        let set = filters(&["--exclude", "/tmp/**"]);
        assert!(!shows(&set, "tmp/a"));
        assert!(shows(&set, "photos/tmp/a"));
    }

    #[test]
    fn one_star_stays_inside_a_component_and_two_cross_it() {
        let single = filters(&["--exclude", "tmp/*"]);
        assert!(!shows(&single, "tmp/a"));
        assert!(shows(&single, "tmp/a/b"));

        let double = filters(&["--exclude", "tmp/**"]);
        assert!(!shows(&double, "tmp/a"));
        assert!(!shows(&double, "tmp/a/b"));
    }

    #[test]
    fn classes_and_alternation_reach_the_engine() {
        let set = filters(&["--include", "img[0-9][0-9].{jpg,raw}"]);
        assert!(shows(&set, "a/img07.jpg"));
        assert!(shows(&set, "a/img07.raw"));
        assert!(!shows(&set, "a/imgAB.jpg"));
        assert!(!shows(&set, "a/img07.png"));
    }

    // ── Size and depth ───────────────────────────────────────────────────

    #[test]
    fn size_bounds_are_inclusive_at_both_ends() {
        let set = filters(&["--min-size", "1K", "--max-size", "10K"]);
        assert!(!set.admits_file("a", 1023));
        assert!(set.admits_file("a", 1024));
        assert!(set.admits_file("a", 10 * 1024));
        assert!(!set.admits_file("a", 10 * 1024 + 1));
    }

    #[test]
    fn size_bounds_do_not_apply_to_directories() {
        // A directory's size is the total beneath it; refusing it would hide
        // every small file inside a large tree.
        let set = filters(&["--max-size", "1K"]);
        assert!(set.admits_dir("big"));
        assert!(!set.admits_file("big/a", 1 << 20));
    }

    #[test]
    fn max_depth_counts_from_the_transfer_root() {
        let set = filters(&["--max-depth", "1"]);
        assert!(shows(&set, "a.txt"));
        assert!(!shows(&set, "a/b.txt"));
        assert!(
            set.may_descend(""),
            "the root must still be entered to reach depth 1"
        );
        assert!(!set.may_descend("a"));
    }

    #[test]
    fn a_bad_size_or_depth_is_a_usage_error_naming_its_flag() {
        let error = refuses(&["--max-size", "banana"]);
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("--max-size"));
        assert!(error.hint().is_some());

        let error = refuses(&["--min-size", "10G", "--max-size", "1G"]);
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("--min-size"));

        // Written with `=` because a bare `-7` is read by clap as a flag rather
        // than as a value; the depth itself is what is under test here.
        let error = refuses(&["--max-depth=-7"]);
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("--max-depth"));
        assert!(error.hint().is_some());
    }

    // ── Malformed patterns ───────────────────────────────────────────────

    #[test]
    fn a_malformed_pattern_names_the_flag_the_pattern_and_the_position() {
        let error = refuses(&["--include", "[abc"]);
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("--include"));
        assert!(error.message().contains("[abc"));
        assert!(error.message().contains("position"));
        assert!(error.hint().is_some_and(|hint| hint.contains("Quote")));

        let error = refuses(&["--exclude", "{a,b"]);
        assert!(error.message().contains("--exclude"));
    }

    // ── Rule files ───────────────────────────────────────────────────────

    #[test]
    fn a_rule_file_with_comments_and_blank_lines_is_honoured_in_order() {
        let dir = scratch("rulefile-order");
        let path = write(
            &dir,
            "rules.txt",
            "# keep the sources, drop the build output\n\
             ;  a second comment spelling\n\
             \n\
             - /work/**/target/**\n\
             + /work/**\n\
             - **\n",
        );
        let set = FilterSet::builder()
            .rules_from(&path)
            .expect("the file should parse")
            .build();

        assert!(shows(&set, "work/src/main.rs"));
        assert!(!shows(&set, "work/src/target/debug/x"));
        assert!(!shows(&set, "notes.txt"));
        assert_eq!(set.rules().len(), 3, "comments and blanks are not rules");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_bang_line_discards_the_rules_accumulated_so_far() {
        let dir = scratch("rulefile-clear");
        let path = write(&dir, "rules.txt", "!\n+ *.jpg\n- **\n");
        let set = FilterSet::builder()
            .exclude("*.jpg")
            .expect("a rule the file then discards")
            .rules_from(&path)
            .expect("the file should parse")
            .build();

        assert!(shows(&set, "a.jpg"), "the earlier exclusion was cleared");
        assert_eq!(set.rules().len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_rule_file_line_that_is_not_a_rule_is_refused() {
        let dir = scratch("rulefile-malformed");
        let path = write(&dir, "rules.txt", "# fine\n*.jpg\n");
        let error = FilterSet::builder()
            .rules_from(&path)
            .expect_err("a bare pattern is not a rule");
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("rules.txt:2"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_malformed_pattern_in_a_rule_file_names_the_line() {
        let dir = scratch("rulefile-badpattern");
        let path = write(&dir, "rules.txt", "+ ok\n- [abc\n");
        let error = FilterSet::builder()
            .rules_from(&path)
            .expect_err("the pattern is malformed");
        assert!(error.message().contains("rules.txt:2"));
        assert!(error.message().contains("[abc"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_rule_file_is_refused_rather_than_ignored() {
        // Silently continuing would leave a run believing a filter is in force
        // that is not — the failure this whole module exists to prevent.
        let error = FilterSet::builder()
            .rules_from(Path::new("no/such/rules.txt"))
            .expect_err("the file does not exist");
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("rules.txt"));
    }

    // ── Path lists ───────────────────────────────────────────────────────

    #[test]
    fn a_files_from_list_is_an_exact_set_that_disables_traversal() {
        let dir = scratch("files-from");
        let path = write(
            &dir,
            "list.txt",
            "# what the upstream job changed\n\
             photos/2024/a.jpg\n\
             \n\
             notes/todo.md\n",
        );
        let set = FilterSet::builder()
            .only_from(&path)
            .expect("the list should parse")
            .build();

        assert!(set.disables_traversal());
        assert!(set.is_restricting());
        assert!(shows(&set, "photos/2024/a.jpg"));
        assert!(shows(&set, "notes/todo.md"));
        assert!(!shows(&set, "photos/2024/b.jpg"));
        // No globbing: the list is a lookup, not a search.
        assert!(!shows(&set, "photos/2024/a.jpg.bak"));

        assert_eq!(
            set.explicit_paths().map(|paths| paths.len()),
            Some(2),
            "comments and blank lines are not paths"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_walk_may_still_descend_into_the_ancestors_of_a_listed_path() {
        // Otherwise a `--files-from` run would refuse to open the very
        // directories the listed files live in.
        let mut listed = BTreeSet::new();
        listed.insert("photos/2024/a.jpg".to_string());
        let set = FilterSet::builder().only(listed).build();

        assert!(set.may_descend(""));
        assert!(set.may_descend("photos"));
        assert!(set.may_descend("photos/2024"));
        assert!(!set.may_descend("music"));
        // And the ancestor directories are themselves in scope, so a listing
        // that shows containers shows the right ones.
        assert!(set.admits_dir("photos/2024"));
        assert!(!set.admits_dir("photos-old"));
    }

    #[test]
    fn several_files_from_lists_merge_into_one_set() {
        let dir = scratch("files-from-merge");
        let first = write(&dir, "one.txt", "a.txt\n");
        let second = write(&dir, "two.txt", "b.txt\n");
        let set = FilterSet::builder()
            .only_from(&first)
            .expect("first list")
            .only_from(&second)
            .expect("second list")
            .build();

        assert!(shows(&set, "a.txt"));
        assert!(shows(&set, "b.txt"));
        assert!(!shows(&set, "c.txt"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_list_path_that_escapes_the_root_is_refused() {
        let dir = scratch("files-from-escape");
        let path = write(&dir, "list.txt", "../../etc/passwd\n");
        let error = FilterSet::builder()
            .only_from(&path)
            .expect_err("the path escapes the root");
        assert_eq!(error.code(), ExitCode::Usage);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_list_written_on_another_platform_selects_the_same_files() {
        let dir = scratch("files-from-platform");
        let path = write(&dir, "list.txt", "photos\\cafe\u{301}\\a.jpg\n");
        let set = FilterSet::builder()
            .only_from(&path)
            .expect("the list should parse")
            .build();

        // Stored logical paths are `/`-separated and NFC; the Windows-flavoured,
        // decomposed line must still name this file.
        assert!(shows(&set, "photos/caf\u{e9}/a.jpg"));
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── Traversal pruning ────────────────────────────────────────────────

    #[test]
    fn only_a_directory_rule_prunes_a_tree() {
        // `--exclude '*.tmp'` says nothing about the tree: refusing to enter a
        // directory whose *name* matched would drop everything under it.
        let by_name = filters(&["--exclude", "build"]);
        assert!(!by_name.admits_dir("a/build"));
        assert!(by_name.may_descend("a/build"), "the rule names files too");

        let by_directory = filters(&["--exclude", "build/"]);
        assert!(!by_directory.admits_dir("a/build"));
        assert!(!by_directory.may_descend("a/build"));
        assert!(by_directory.may_descend("a/src"));
    }

    // ── Reporting ────────────────────────────────────────────────────────

    #[test]
    fn every_decision_can_explain_itself() {
        // These lines reach an operator through `--dump filters`. A blank or
        // generic one is a file that vanished for a reason nobody can act on.
        let dir = scratch("describe");
        let list = write(&dir, "list.txt", "kept.txt\n");
        let set = FilterSet::builder()
            .exclude("*.tmp")
            .expect("a rule")
            .only_from(&list)
            .expect("a list")
            .sizes(SizeBounds::parse(Some("1K"), Some("2K")).expect("bounds"))
            .depth(DepthLimit::from_flag(3).expect("a depth"))
            .build();

        for candidate in [
            Candidate::file("kept.txt", 1500),
            Candidate::file("unlisted.txt", 1500),
            Candidate::file("kept.txt", 1),
            Candidate::file("kept.txt", u64::MAX),
        ] {
            let text = set.decide(&candidate).describe();
            assert!(text.len() > 15, "unhelpful decision: {text}");
        }

        let deep = FilterSet::builder()
            .depth(DepthLimit::from_flag(1).expect("a depth"))
            .build();
        assert!(
            deep.decide(&Candidate::file("a/b.txt", 1))
                .describe()
                .contains("depth")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_reason_identifies_the_rule_that_decided() {
        let set = FilterSet::builder()
            .exclude("*.a")
            .expect("rule 1")
            .exclude("*.b")
            .expect("rule 2")
            .build();

        match set.decide(&Candidate::file("x.b", 1)).reason() {
            Reason::Matched { rule, position } => {
                assert_eq!(position, 1, "positions are zero-based within the list");
                assert_eq!(rule.pattern(), "*.b");
            }
            other => panic!("expected a rule to decide, got {other:?}"),
        }
    }

    // ── Composition ──────────────────────────────────────────────────────

    #[test]
    fn from_globals_applies_exclusions_before_the_reconstructed_includes() {
        // The documented reconstruction: `clap` discards the command-line
        // interleaving, and of the two ways to be wrong, keeping a file the
        // operator excluded is the one that cannot be taken back.
        let set = filters(&["--include", "**", "--exclude", "secret/**"]);
        assert!(!shows(&set, "secret/a.txt"));
        assert!(shows(&set, "public/a.txt"));
    }

    #[test]
    fn every_dial_is_reported_as_a_restriction() {
        for args in [
            vec!["--include", "*.jpg"],
            vec!["--exclude", "*.tmp"],
            vec!["--min-size", "1K"],
            vec!["--max-size", "1K"],
            vec!["--max-depth", "2"],
        ] {
            assert!(
                filters(&args).is_restricting(),
                "{args:?} should count as a restriction"
            );
        }
        assert!(!filters(&["--max-size", "off"]).is_restricting());
    }

    #[test]
    fn the_depth_limit_can_be_moved_to_the_directory_layer() {
        // `lsd` and `tree` derive directories from the objects beneath them, so
        // they must see objects the operator's `--max-depth` would have hidden.
        let set = filters(&["--max-depth", "1"]);
        assert!(!shows(&set, "a/b/c.txt"));
        assert!(shows(&set.clone().with_depth_limit(None), "a/b/c.txt"));
    }

    #[test]
    fn the_exact_path_helper_answers_for_a_whole_subtree() {
        let mut paths = BTreeSet::new();
        paths.insert("a/b/c.txt".to_string());
        assert!(is_under_any(&paths, ""));
        assert!(is_under_any(&paths, "a"));
        assert!(is_under_any(&paths, "a/b"));
        assert!(is_under_any(&paths, "a/b/c.txt"));
        // Component-aligned: `a/bb` is not an ancestor of `a/b/c.txt`.
        assert!(!is_under_any(&paths, "a/bb"));
        assert!(!is_under_any(&BTreeSet::new(), ""));
    }

    #[test]
    fn filters_compose_without_one_dial_masking_another() {
        // Everything at once, which is how a real run arrives.
        let set = filters(&[
            "--include",
            "*.jpg",
            "--exclude",
            "thumbs/**",
            "--min-size",
            "1K",
            "--max-depth",
            "3",
        ]);
        assert!(set.admits_file("a/b/photo.jpg", 4096));
        assert!(!set.admits_file("a/b/photo.jpg", 100), "below --min-size");
        assert!(
            !set.admits_file("a/b/c/photo.jpg", 4096),
            "past --max-depth"
        );
        assert!(!set.admits_file("thumbs/photo.jpg", 4096), "excluded");
        assert!(!set.admits_file("a/b/photo.raw", 4096), "not included");
    }
}
