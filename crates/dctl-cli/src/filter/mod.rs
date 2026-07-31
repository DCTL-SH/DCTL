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

// All three call sites are connected: the transfer family
// (`commands/transfer/listing.rs`), the recovery family
// (`commands/recovery/selection.rs`) and the listing family
// (`commands/listing/filter.rs`, which every listing verb, `check`, `scrub`,
// `hashsum`, `verify` and the removal verbs reach the engine through).
//
// What remains unreachable from `main` is the reporting surface — `Reason`,
// `Decision::describe`, `Rule::pattern` and the accessors behind them — which
// exists for `--dump filters`, the flag that answers "why did this file
// disappear". It is kept, with the tests that pin its wording, because a rule
// that drops a file for a reason nobody can name is the failure this module was
// written to prevent, and a diagnostic that first appears on the day it is
// needed is a diagnostic nobody reviewed.
#![allow(dead_code)]

pub(crate) mod age;
mod depth;
mod glob;
mod parse;
mod rule;
mod size;

// Only the types a call site has to name are re-exported. A pattern failure and
// a rule-file failure are both turned into a [`CliError`] before they leave this
// module — classification is the one thing a command must never have to redo —
// so their own types stay internal.
pub use age::{AgeBounds, parse_age};
pub use depth::{DepthLimit, depth_of};
pub use parse::{Directive, FileProblem};
pub use rule::{Action, Rule};
pub use size::SizeBounds;

use age::AgeProblem;
use depth::DepthProblem;
use size::SizeProblem;

use std::collections::BTreeSet;
use std::path::Path;

use crate::cli::globals::GlobalArgs;
use crate::constants::{
    FILTER_FLAG_EXCLUDE, FILTER_FLAG_EXCLUDE_FROM, FILTER_FLAG_FILES_FROM, FILTER_FLAG_FILTER,
    FILTER_FLAG_FILTER_FROM, FILTER_FLAG_INCLUDE, FILTER_FLAG_INCLUDE_FROM, FILTER_FLAG_MAX_AGE,
    FILTER_FLAG_MIN_AGE, GLOB_RECURSIVE_SEQUENCE, PATH_SEPARATOR,
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
    size: Option<u64>,
    /// Last modification, in unix seconds, when the side that offered this
    /// entry knows one.
    ///
    /// [`None`] is "nobody measured it", never "the epoch". The age bounds
    /// then do not apply — see [`super::age`] for the whole argument, which is
    /// the same one `size` makes and has to be, or `dctl ls --max-age` and the
    /// `copy` after it would select different files out of one rebuilt index.
    modified: Option<i64>,
    is_dir: bool,
}

impl<'a> Candidate<'a> {
    /// A file at `path`, of `size` bytes, whose modification time is unknown.
    ///
    /// Use [`Candidate::at`] to attach one. Kept as a separate step rather than
    /// a fourth parameter because most call sites in the test suite are about
    /// patterns and sizes, and a `None` typed a thousand times is a `None` that
    /// eventually gets typed where a real time was available.
    pub const fn file(path: &'a str, size: u64) -> Self {
        Self {
            path,
            size: Some(size),
            modified: None,
            is_dir: false,
        }
    }

    /// The same candidate, carrying the modification time its side reported.
    #[must_use]
    pub const fn at(mut self, modified: Option<i64>) -> Self {
        self.modified = modified;
        self
    }

    /// A file whose size nothing has measured.
    ///
    /// Reached only from a listing over a vault whose index was rebuilt: that
    /// pass records object names without reading their bodies, so the rows it
    /// writes carry no size until each file is next read (see
    /// [`crate::source::Entry::size`]).
    ///
    /// The size bounds are then **not applied**, rather than applied to a zero.
    /// Both alternatives are wrong in the same direction and one of them is
    /// silent: `--max-size 1K` over a rebuilt index would have admitted every
    /// object in the vault, and `--min-size 1K` would have hidden all of them —
    /// including a forty-terabyte file that plainly qualifies. Showing the row
    /// and letting the size column say `-` puts the uncertainty where the user
    /// can see it, which matters most in the listing somebody reads before
    /// deciding what to delete. Every other rule — globs, path lists, depth —
    /// still applies untouched.
    pub const fn unmeasured_file(path: &'a str) -> Self {
        Self {
            path,
            size: None,
            modified: None,
            is_dir: false,
        }
    }

    /// A directory at `path`.
    ///
    /// Carries no size: a directory's size is the total beneath it, and letting
    /// that number reach the size bounds would hide every small file in a large
    /// tree.
    ///
    /// Carries no time either. A directory's modification time is a property of
    /// the local filesystem rather than of the data, and it changes whenever a
    /// child is added — so letting `--max-age` see it would keep a directory of
    /// year-old files because one new file landed in it, and drop one whose
    /// files are new because nothing was added to it recently.
    pub const fn directory(path: &'a str) -> Self {
        Self {
            path,
            size: None,
            modified: None,
            is_dir: true,
        }
    }

    /// The root-relative logical path.
    pub const fn path(&self) -> &'a str {
        self.path
    }

    /// The size in bytes; always absent for a directory, and for a file whose
    /// size was never measured.
    pub const fn size(&self) -> Option<u64> {
        self.size
    }

    /// The last modification time in unix seconds, when one is known.
    pub const fn modified(&self) -> Option<i64> {
        self.modified
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
    /// Modified before the floor `--max-age` set.
    TooOld { modified: i64, floor: i64 },
    /// Modified after the ceiling `--min-age` set.
    TooNew { modified: i64, ceiling: i64 },
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
            Reason::TooOld { modified, floor } => format!(
                "{verdict}: modified at {modified}, before the {FILTER_FLAG_MAX_AGE} floor of {floor}"
            ),
            Reason::TooNew { modified, ceiling } => format!(
                "{verdict}: modified at {modified}, after the {FILTER_FLAG_MIN_AGE} ceiling of {ceiling}"
            ),
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
    ages: AgeBounds,
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
            ages: AgeBounds::open(),
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
    /// The engine evaluates rules in the order it is given them, and it is given
    /// them in **rclone's** order — which is *not* the order they appear on the
    /// command line, and this module used to say it was. rclone's `parseRules`
    /// (`fs/filter/rules.go:212`) walks the flags by kind:
    ///
    /// 1. every `--include`, then every `--include-from`;
    /// 2. every `--exclude`, then every `--exclude-from`;
    /// 3. every `--filter`, then every `--filter-from`;
    /// 4. an implicit `- **` if any inclusion was used, from any of those flags.
    ///
    /// This matters, and not subtly. Under rclone's order `--include '*.jpg'
    /// --exclude 'private/**'` **keeps** `private/a.jpg`, because the inclusion
    /// is tried first and first match wins. DCTL used to lead with the
    /// exclusions and dropped it. Neither answer is obviously right — rclone's
    /// own code logs "using --filter is recommended instead of both --include
    /// and --exclude as the order they are parsed in is indeterminate"
    /// (`fs/filter/rules.go:250`) — but a migrating script must get the answer
    /// it was written against, and only one of the two is that answer.
    ///
    /// `clap`'s derive hands back each flag as its own `Vec`, which discards the
    /// interleaving. That costs nothing here, because rclone discards it too.
    /// A rule *file* keeps its internal order exactly, because that order is the
    /// whole reason the form exists.
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::Usage`] for a malformed pattern, size, age or
    /// depth, or for a filter file that cannot be read or understood.
    pub fn from_globals(globals: &GlobalArgs) -> Result<Self> {
        Self::from_globals_at(globals, now_unix())
    }

    /// [`FilterSet::from_globals`] with the clock supplied.
    ///
    /// `--min-age` and `--max-age` are relative to a single instant, fixed here
    /// for the whole run (see [`age`]). Injecting it is what makes the age
    /// window assertable: a test that read the real clock could only check that
    /// the window moved, never that it landed where rclone puts it.
    ///
    /// # Errors
    /// As [`FilterSet::from_globals`].
    pub fn from_globals_at(globals: &GlobalArgs, now: i64) -> Result<Self> {
        let mut builder = Builder::new();

        for pattern in &globals.include {
            builder = builder.include(pattern)?;
        }
        for source in &globals.include_from {
            builder = builder.patterns_from(source, Action::Include)?;
        }
        for pattern in &globals.exclude {
            builder = builder.exclude(pattern)?;
        }
        for source in &globals.exclude_from {
            builder = builder.patterns_from(source, Action::Exclude)?;
        }
        for line in &globals.filter {
            builder = builder.filter_line(line)?;
        }
        for source in &globals.filter_from {
            builder = builder.rules_from(source)?;
        }

        for source in &globals.files_from {
            builder = builder.only_from(source)?;
        }

        builder = builder
            .sizes(SizeBounds::parse(
                globals.min_size.as_deref(),
                globals.max_size.as_deref(),
            )?)
            .ages(AgeBounds::parse(
                globals.min_age.as_deref(),
                globals.max_age.as_deref(),
                now,
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

        // Files only, and only files whose time somebody recorded: see the
        // notes on `Candidate::directory` and `super::age`.
        if let Some(modified) = candidate.modified() {
            if let Some(floor) = self.ages.from()
                && modified < floor
            {
                return Decision::new(Action::Exclude, Reason::TooOld { modified, floor });
            }
            if let Some(ceiling) = self.ages.to()
                && modified > ceiling
            {
                return Decision::new(Action::Exclude, Reason::TooNew { modified, ceiling });
            }
        }

        // Files only, and only files somebody has measured: see the notes on
        // `Candidate::directory` and `Candidate::unmeasured_file`.
        if let Some(size) = candidate.size() {
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
    ///
    /// The rules alone, with no account of the tree the candidate sits in. A
    /// caller that walks a directory structure wants this, because it has
    /// already refused to enter the directories [`FilterSet::may_descend`]
    /// pruned. A caller reading a *flat* enumeration wants
    /// [`FilterSet::admits_enumerated`] instead — see there.
    pub fn admits(&self, candidate: &Candidate<'_>) -> bool {
        self.decide(candidate).admits()
    }

    /// Whether a candidate is in scope for a caller that has no walk to prune.
    ///
    /// An index range scan and a provider listing both hand back a flat, already
    /// complete set of paths. There is no recursion in them for
    /// [`FilterSet::may_descend`] to stop, so the pruning a walking caller gets
    /// for free has to be applied explicitly here — by asking of every ancestor
    /// directory the same question the walk would have asked before opening it.
    ///
    /// Without this, `--exclude 'cache/'` means two different things depending
    /// on how the caller happens to enumerate: a local walk never opens `cache`
    /// and transfers nothing from it, while a listing of the same tree in a
    /// vault shows `cache/a.o` because a directories-only rule cannot match a
    /// file. That is not a cosmetic difference. A person reads `dctl ls
    /// --exclude 'cache/'`, sees the file, and concludes it was stored — then
    /// deletes their copy. The two must give one answer, and this is where a
    /// caller that cannot prune gets it.
    ///
    /// It is deliberately not folded into [`FilterSet::admits`]. A walking
    /// caller asking this would re-walk every ancestor of every file, turning a
    /// linear walk into a quadratic one for an answer it has already computed.
    pub fn admits_enumerated(&self, candidate: &Candidate<'_>) -> bool {
        self.admits(candidate) && ancestors(candidate.path()).all(|dir| self.may_descend(dir))
    }

    /// Whether a flat enumeration should show this file.
    pub fn admits_enumerated_file(&self, path: &str, size: u64) -> bool {
        self.admits_enumerated(&Candidate::file(path, size))
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
        //
        // And only an *exclusion* prunes. `+ photos/` says the directory is
        // wanted; treating it as a reason not to open it would make the rule
        // hide precisely the tree it was written to keep — which is not a
        // reading of `+` that anybody has.
        !self.rules.iter().any(|rule| {
            rule.action() == Action::Exclude
                && rule.directories_only()
                && rule.matches(&Candidate::directory(path))
        })
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

    /// The modification-time window in force.
    pub const fn ages(&self) -> AgeBounds {
        self.ages
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
            || self.ages.is_limited()
            || self.depth.is_limited()
    }
}

/// Every proper ancestor directory of `path`, shallowest first.
///
/// `a/b/c.txt` yields `""` (the transfer root), `a`, then `a/b`. The root is
/// always included: `--max-depth 0` and a `--files-from` list that names nothing
/// both refuse it, and a caller that started at `a` would never learn that the
/// walk it is imitating would not have begun at all.
///
/// Shallowest first because the rule that prunes is usually near the top, and
/// the caller is an `all()` that stops at the first `false`.
fn ancestors(path: &str) -> impl Iterator<Item = &str> {
    std::iter::once("").chain(
        path.match_indices(PATH_SEPARATOR)
            .filter_map(move |(index, _)| path.get(..index)),
    )
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
    ages: AgeBounds,
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

    /// Append one `--filter` line, in rclone's `+ pattern` / `- pattern` / `!`
    /// grammar.
    ///
    /// The flag rclone's own diagnostics recommend over `--include` and
    /// `--exclude` (`fs/filter/rules.go:250`), because it is the only one whose
    /// order is written down by the person using it rather than reconstructed.
    /// The grammar is exactly a rule file's, one line at a time, so a rule that
    /// works in a `--filter-from` file works as a `--filter` argument unchanged.
    ///
    /// A `!` clears every rule accumulated so far, including rules added by
    /// earlier flags — that is what the directive means, and scoping it to this
    /// one argument would make it a quieter, different thing. It does **not**
    /// disarm the implicit trailing exclusion; see [`Builder::rules_from`].
    ///
    /// A `+` here does **not** arm that exclusion either, and the asymmetry is
    /// rclone's rather than an oversight: `addImplicitExclude` is set only by
    /// the `--include` and `--include-from` loops (`fs/filter/rules.go:216,223`),
    /// while `--filter` lines go through `addRule` and set nothing. So
    /// `--filter '+ *.jpg'` on its own keeps everything, exactly as a
    /// `--filter-from` file containing only `+ *.jpg` does — a rule list is an
    /// ordered program whose author writes their own final `- **`, and that is
    /// the whole reason to prefer this flag when the order matters.
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::Usage`] for a line that is not a rule, or a rule
    /// whose pattern will not compile.
    pub fn filter_line(mut self, line: &str) -> Result<Self> {
        let origin = std::path::Path::new(FILTER_FLAG_FILTER);
        for directive in parse::rules_in(line, origin).map_err(from_file_problem)? {
            match directive {
                Directive::Clear { .. } => self.rules.clear(),
                Directive::Rule {
                    action, pattern, ..
                } => self
                    .rules
                    .push(compile(action, &pattern, FILTER_FLAG_FILTER)?),
            }
        }
        Ok(self)
    }

    /// Append every pattern in an `--include-from` or `--exclude-from` file.
    ///
    /// The lines are bare patterns, not `+`/`-` rules: the flag supplies the
    /// action, which is rclone's split (`fs/filter/rules.go:216,232` call `add`
    /// with a fixed `Include`, while `--filter-from` goes through `addRule`).
    /// Comments and blank lines are skipped as they are everywhere else.
    ///
    /// An `--include-from` file arms the implicit trailing exclusion exactly as
    /// `--include` does, even when the file turns out to be empty — rclone sets
    /// `addImplicitExclude` from the *flag*, before reading a line, and a file
    /// that happened to hold only comments must not silently turn a whitelist
    /// into "everything".
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::Usage`] if the file cannot be read or holds a
    /// pattern that will not compile.
    pub fn patterns_from(mut self, source: &Path, action: Action) -> Result<Self> {
        let flag = match action {
            Action::Include => FILTER_FLAG_INCLUDE_FROM,
            Action::Exclude => FILTER_FLAG_EXCLUDE_FROM,
        };
        let text = std::fs::read_to_string(source).map_err(|error| {
            from_file_problem(FileProblem::Unreadable {
                source: source.to_path_buf(),
                detail: error.to_string(),
            })
        })?;
        for (offset, raw) in text.lines().enumerate() {
            let pattern = raw.trim();
            if pattern.is_empty() || pattern.starts_with(crate::constants::FILTER_COMMENT_MARKERS) {
                continue;
            }
            let origin = format!("{flag} {}:{}", source.display(), offset + 1);
            self.rules.push(compile(action, pattern, &origin)?);
        }
        if action == Action::Include {
            self.implicit_exclude = true;
        }
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
                // The rules go, the implicit exclusion does not. rclone sets
                // `addImplicitExclude` from the *flag* (`fs/filter/rules.go:216`)
                // and appends `- /**` after every `Clear`, so `--include '*.jpg'
                // --filter-from f` where `f` begins `!` selects nothing there.
                // Disarming it here would make the same pair select everything —
                // the widest possible disagreement about one command line.
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

    /// Set the modification-time window.
    pub fn ages(mut self, ages: AgeBounds) -> Self {
        self.ages = ages;
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
            ages: self.ages,
            depth: self.depth,
            only: self.only,
        }
    }
}

/// The wall clock, in unix seconds, read once per run.
///
/// Lives here rather than in [`age`] so that module stays pure and testable
/// without a clock; the one place that needs the real time is the one place a
/// filter is built from flags.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
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

impl From<AgeProblem> for CliError {
    fn from(problem: AgeProblem) -> Self {
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

    /// A filter built from a `--filter-from` file holding `text`.
    ///
    /// Lets a test assert that a `--filter` argument and the same line in a rule
    /// file mean the same thing, which is the property the flag exists for.
    fn rules_file_set(text: &str) -> FilterSet {
        let dir = scratch("rules-file");
        let path = dir.join("rules.txt");
        std::fs::write(&path, text).expect("write the rule file");
        filters(&["--filter-from", path.to_str().expect("path")])
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

    #[test]
    fn an_inclusion_never_prunes_the_tree_it_names() {
        // `+ photos/` says the directory is wanted. Treating a directories-only
        // rule as a reason not to open it, whichever way it pointed, would make
        // the rule hide precisely the tree it was written to keep.
        let set = FilterSet::builder()
            .rule(Action::Include, "photos/", "test")
            .expect("a directory inclusion")
            .build();
        assert!(set.may_descend("a/photos"));
        assert!(set.admits_dir("a/photos"));
    }

    // ── Flat enumerations, which have no walk to prune ────────────────────

    #[test]
    fn a_directory_rule_reaches_the_contents_of_a_flat_enumeration() {
        // The divergence this method exists to close: a local walk never opens
        // `cache` and transfers nothing from it, while an index range scan hands
        // back `cache/a.o` — which a directories-only rule cannot match. One
        // rule has to mean one thing, or a person reads `ls --exclude 'cache/'`,
        // sees the file, concludes it was stored, and deletes their copy.
        let set = filters(&["--exclude", "cache/"]);

        // The rules alone cannot see it...
        assert!(set.admits_file("a/cache/x.o", 1));
        // ...and the question a flat caller has to ask can.
        assert!(!set.admits_enumerated_file("a/cache/x.o", 1));
        assert!(!set.admits_enumerated_file("cache/deep/x.o", 1));
        assert!(set.admits_enumerated_file("a/src/x.rs", 1));
    }

    #[test]
    fn a_files_from_list_reaches_a_flat_enumeration_the_same_way() {
        let mut listed = BTreeSet::new();
        listed.insert("photos/2024/a.jpg".to_string());
        let set = FilterSet::builder().only(listed).build();

        assert!(set.admits_enumerated_file("photos/2024/a.jpg", 1));
        assert!(!set.admits_enumerated_file("photos/2024/b.jpg", 1));
        assert!(!set.admits_enumerated_file("music/x.mp3", 1));
    }

    #[test]
    fn the_flat_and_walking_answers_agree_wherever_a_walk_could_have_pruned() {
        // The equivalence being claimed: "the walk never entered it" and "no
        // path under it is admitted" have to be the same statement, or the two
        // enumerations are two policies.
        let set = filters(&["--exclude", "cache/", "--max-depth", "3"]);
        for path in [
            "a.txt",
            "a/b.txt",
            "a/b/c.txt",
            "a/cache/c.txt",
            "cache/c.txt",
            "a/b/c/d.txt",
        ] {
            let walked =
                ancestors(path).all(|dir| set.may_descend(dir)) && set.admits_file(path, 1);
            assert_eq!(
                walked,
                set.admits_enumerated_file(path, 1),
                "the two enumerations disagree about {path}"
            );
        }
    }

    #[test]
    fn ancestors_start_at_the_root_and_stop_before_the_name() {
        assert_eq!(
            ancestors("a/b/c.txt").collect::<Vec<_>>(),
            vec!["", "a", "a/b"]
        );
        // A file in the root still has one ancestor: the root, which
        // `--max-depth 0` and an empty `--files-from` both refuse.
        assert_eq!(ancestors("c.txt").collect::<Vec<_>>(), vec![""]);
        assert_eq!(ancestors("").collect::<Vec<_>>(), vec![""]);
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
    fn from_globals_orders_the_flags_the_way_rclone_orders_them() {
        // The correction this pass made, and the one with teeth: rclone's
        // `parseRules` (`fs/filter/rules.go:212`) adds every `--include` before
        // any `--exclude`, so first-match-wins keeps `secret/a.txt`. DCTL led
        // with the exclusions and dropped it — a migrating `sync` would have
        // deleted at the destination exactly the files rclone had been keeping.
        let set = filters(&["--include", "**", "--exclude", "secret/**"]);
        assert!(shows(&set, "secret/a.txt"), "rclone keeps this one");
        assert!(shows(&set, "public/a.txt"));

        // …and the flag rclone recommends instead expresses the other reading,
        // because its order is the order it was written in.
        let ordered = filters(&["--filter", "- secret/**", "--filter", "+ **"]);
        assert!(!shows(&ordered, "secret/a.txt"));
        assert!(shows(&ordered, "public/a.txt"));
    }

    #[test]
    fn a_filter_flag_is_read_as_one_line_of_a_rule_file() {
        // Same grammar as a `--filter-from` file, and the same standing: a `+`
        // here does **not** arm the implicit `- **`, because rclone arms that
        // from the `--include` flags alone (`fs/filter/rules.go:216,223`) and a
        // rule list is an ordered program whose author writes their own final
        // rule. `--filter '+ *.jpg'` therefore keeps the `.txt` files too.
        let set = filters(&["--filter", "+ *.jpg"]);
        assert!(shows(&set, "a.jpg"));
        assert!(shows(&set, "a.txt"), "a '+' rule does not arm '- **'");
        // …which is exactly what a rule *file* holding the same line does.
        assert_eq!(
            shows(&set, "a.txt"),
            shows(&rules_file_set("+ *.jpg\n"), "a.txt")
        );

        let cleared = filters(&["--exclude", "*.jpg", "--filter", "!", "--filter", "+ *.jpg"]);
        assert!(shows(&cleared, "a.jpg"), "'!' discarded the exclusion");

        // A line that is not a rule is a usage error, not a silently ignored
        // argument — the same standard a rule file is held to.
        assert!(FilterSet::from_globals(&globals(&["--filter", "*.jpg"])).is_err());
    }

    #[test]
    fn a_clear_directive_discards_the_rules_and_keeps_the_implicit_exclusion() {
        // The widest disagreement one command line can produce, and the one this
        // nearly shipped. rclone appends `- /**` after every `Clear` because the
        // flag armed it, not the rules — so `--include '*.jpg'` followed by a
        // `!` selects **nothing** there. Disarming it here would have selected
        // **everything**: not a near miss, the opposite answer.
        let dir = scratch("clear-rules");
        let bang = dir.join("bang.txt");
        std::fs::write(&bang, "!\n").expect("write the rule file");
        let from_file = filters(&[
            "--include",
            "*.jpg",
            "--filter-from",
            bang.to_str().expect("path"),
        ]);

        // Both flags that can carry a `!` — the argument form and the file form
        // — have to answer the same way, or one of them is a quieter version of
        // the other.
        for cleared in [
            filters(&["--include", "*.jpg", "--filter", "!"]),
            filters(&["--include", "*.jpg", "--filter", "!", "--filter", "+ *.raw"]),
            from_file,
        ] {
            assert!(!shows(&cleared, "a.txt"), "the implicit '- **' survives");
            assert!(!shows(&cleared, "a.jpg"), "the include itself was cleared");
        }
        // The `+` after the clear is still a rule, and still wins over the
        // implicit exclusion that follows it.
        assert!(shows(
            &filters(&["--include", "*.jpg", "--filter", "!", "--filter", "+ *.raw"]),
            "a.raw"
        ));
        // With no inclusion flag anywhere there is nothing to survive, so a
        // cleared list keeps everything.
        assert!(shows(
            &filters(&["--exclude", "*.jpg", "--filter", "!"]),
            "a.jpg"
        ));
    }

    #[test]
    fn the_age_window_reaches_the_engine_from_the_flags() {
        // `--min-age`/`--max-age` parsed and then never consulted is the exact
        // shape of the eleven inert flags (§13). The clock is injected so the
        // window is asserted rather than merely observed to have moved.
        const NOW: i64 = 1_700_000_000;
        let set = FilterSet::from_globals_at(&globals(&["--max-age", "7d"]), NOW).unwrap();
        assert!(set.is_restricting());
        assert!(set.admits(&Candidate::file("new.txt", 1).at(Some(NOW - 86_400))));
        assert!(!set.admits(&Candidate::file("old.txt", 1).at(Some(NOW - 30 * 86_400))));
        // A file whose time nobody recorded is admitted rather than guessed at.
        assert!(set.admits(&Candidate::file("unknown.txt", 1)));

        let floor = FilterSet::from_globals_at(&globals(&["--min-age", "7d"]), NOW).unwrap();
        assert!(!floor.admits(&Candidate::file("new.txt", 1).at(Some(NOW - 86_400))));
        assert!(floor.admits(&Candidate::file("old.txt", 1).at(Some(NOW - 30 * 86_400))));

        // And a crossed pair is refused rather than selecting nothing.
        assert!(
            FilterSet::from_globals_at(&globals(&["--min-age", "30d", "--max-age", "7d"]), NOW)
                .is_err()
        );
    }

    #[test]
    fn include_from_and_exclude_from_read_bare_patterns_from_a_file() {
        // rclone's split: `--filter-from` lines carry their own `+`/`-`, while
        // these two take the action from the flag (`fs/filter/rules.go:216,232`).
        let dir = tempfile::tempdir().expect("temp dir");
        let includes = dir.path().join("in.txt");
        std::fs::write(
            &includes,
            "# only the photographs
*.jpg

*.raw
",
        )
        .expect("write");
        let excludes = dir.path().join("out.txt");
        std::fs::write(
            &excludes,
            "thumbs/**
",
        )
        .expect("write");

        let set = filters(&[
            "--include-from",
            includes.to_str().expect("path"),
            "--exclude-from",
            excludes.to_str().expect("path"),
        ]);
        assert!(shows(&set, "a.jpg"));
        assert!(shows(&set, "a.raw"));
        assert!(
            !shows(&set, "a.txt"),
            "an include-from arms the implicit '- **'"
        );
        // rclone's order again: the inclusion is tried first, so a `.jpg` under
        // `thumbs/` survives the exclusion below it.
        assert!(shows(&set, "thumbs/a.jpg"));
        assert!(!shows(&set, "thumbs/a.txt"));

        // A file holding only comments still arms the implicit exclusion,
        // because rclone arms it from the *flag* before reading a line — a
        // whitelist that silently became "everything" is the worst outcome here.
        let empty = dir.path().join("empty.txt");
        std::fs::write(
            &empty,
            "# nothing yet
",
        )
        .expect("write");
        let armed = filters(&["--include-from", empty.to_str().expect("path")]);
        assert!(!shows(&armed, "a.jpg"));
    }

    #[test]
    fn every_dial_is_reported_as_a_restriction() {
        for args in [
            vec!["--include", "*.jpg"],
            vec!["--exclude", "*.tmp"],
            vec!["--min-size", "1K"],
            vec!["--max-size", "1K"],
            vec!["--min-age", "1d"],
            vec!["--max-age", "1d"],
            vec!["--max-depth", "2"],
            vec!["--filter", "- *.tmp"],
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
        // Under rclone's order the inclusion is tried first, so a `.jpg` here
        // survives the exclusion — that is the behaviour a migrating script was
        // written against, and `--filter` is how the other reading is written.
        assert!(set.admits_file("thumbs/photo.jpg", 4096));
        assert!(!set.admits_file("a/b/photo.raw", 4096), "not included");
    }
}
