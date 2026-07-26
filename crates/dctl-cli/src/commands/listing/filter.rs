//! Which entries a listing is allowed to show.
//!
//! Built once per invocation from the global filtering flags and then consulted
//! per entry, so that all six listing verbs agree about scope. The alternative —
//! each command interpreting `--exclude` for itself — produces a tool where
//! `dctl size` and `dctl ls` report different vaults and neither is wrong.
//!
//! ## Anchoring
//!
//! rclone's rule, because rclone's patterns are the ones users bring:
//!
//! * A pattern beginning with `/` is **anchored** at the listing root and is
//!   matched against the whole root-relative path. `/tmp/*` matches `tmp/a` but
//!   never `photos/tmp/a`.
//! * A pattern containing no `/` at all is matched against the **file name**, at
//!   any depth. `*.jpg` means what everyone assumes it means.
//! * Anything else is matched against the root-relative path **and against every
//!   suffix of it that starts on a component boundary**, so `tmp/*` finds
//!   `photos/tmp/a` as well as `tmp/a`.
//!
//! ## Precedence
//!
//! `--exclude` wins. An entry that matches any exclusion is gone regardless of
//! what it also matches, and `--include` then narrows whatever survived. This is
//! the conservative reading: the two flags can be combined into a contradiction,
//! and of the two possible answers, "show less than asked" is recoverable by
//! re-running while "show a file the user told us to hide" is not.
//!
//! ## Refusals
//!
//! `--filter-from` and `--files-from` parse but are not honoured, so they are a
//! hard error rather than a shrug. A silently-dropped rule file makes a listing
//! *look* complete, and listings are what people read before deciding what to
//! delete.

use crate::cli::globals::GlobalArgs;
use crate::constants::{MAX_DEPTH_UNLIMITED, PATH_SEPARATOR, RULE_FILE_FEATURE, RULE_FILE_HINT};
use crate::error::{CliError, Result};
use crate::output::size::parse_size;

use super::entry::Entry;
use super::glob::Glob;

/// Where a pattern is allowed to match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Anchor {
    /// Against the whole root-relative path only.
    Root,
    /// Against the final path component, at any depth.
    Name,
    /// Against the root-relative path or any component-aligned suffix of it.
    Suffix,
}

/// One `--include` or `--exclude` rule.
#[derive(Clone, Debug)]
struct Rule {
    glob: Glob,
    anchor: Anchor,
}

impl Rule {
    /// Compile a rule, deciding its anchoring from its shape.
    fn compile(pattern: &str, flag: &str) -> Result<Self> {
        let (anchor, body) = match pattern.strip_prefix(PATH_SEPARATOR) {
            Some(rest) => (Anchor::Root, rest),
            None if pattern.contains(PATH_SEPARATOR) => (Anchor::Suffix, pattern),
            None => (Anchor::Name, pattern),
        };

        let glob = Glob::compile(body).map_err(|reason| {
            CliError::usage(format!("{flag}: {reason}")).with_hint(
                "Patterns use '*' within a path component, '**' across them, \
                 '?' for one character and '[a-z]' for a class.",
            )
        })?;

        Ok(Self { glob, anchor })
    }

    /// Whether this rule selects `entry`.
    fn matches(&self, entry: &Entry) -> bool {
        match self.anchor {
            Anchor::Root => self.glob.matches(entry.relative()),
            Anchor::Name => self.glob.matches(entry.name()),
            Anchor::Suffix => {
                component_suffixes(entry.relative()).any(|suffix| self.glob.matches(suffix))
            }
        }
    }
}

/// Every suffix of `path` that begins on a component boundary, longest first.
///
/// `a/b/c` yields `a/b/c`, `b/c`, `c`. Longest first because the common case is
/// a rule that matches the whole path, and a matcher that finds it on the first
/// try does no allocation and no backtracking.
fn component_suffixes(path: &str) -> impl Iterator<Item = &str> {
    std::iter::once(path).chain(
        path.match_indices(PATH_SEPARATOR)
            .filter_map(move |(index, _)| path.get(index + PATH_SEPARATOR.len_utf8()..)),
    )
}

/// The scope of one listing.
#[derive(Clone, Debug, Default)]
pub struct Filter {
    include: Vec<Rule>,
    exclude: Vec<Rule>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    max_depth: Option<usize>,
}

impl Filter {
    /// Build the filter from the global flags.
    ///
    /// # Errors
    /// [`ExitCode::Usage`](crate::exit::ExitCode::Usage) for a malformed pattern
    /// or size, and [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError)
    /// for a rule file, which is refused rather than ignored — see the module
    /// docs.
    pub fn from_globals(globals: &GlobalArgs) -> Result<Self> {
        if !globals.filter_from.is_empty() || !globals.files_from.is_empty() {
            return Err(CliError::unimplemented(RULE_FILE_FEATURE).with_hint(RULE_FILE_HINT));
        }

        let include = compile_all(&globals.include, "--include")?;
        let exclude = compile_all(&globals.exclude, "--exclude")?;

        Ok(Self {
            include,
            exclude,
            min_size: parse_limit(globals.min_size.as_deref(), "--min-size")?,
            max_size: parse_limit(globals.max_size.as_deref(), "--max-size")?,
            max_depth: depth_from_flag(globals.max_depth),
        })
    }

    /// Replace the depth limit.
    ///
    /// `lsd` and `tree` derive directories from the objects beneath them, so
    /// they must see objects the user's `--max-depth` would have hidden and
    /// apply the limit to the *directories* they synthesise instead. Without
    /// this, `dctl lsd --max-depth 1` would report a top-level directory as
    /// empty because every object in it sits at depth 2.
    #[must_use]
    pub fn with_depth_limit(mut self, depth: Option<usize>) -> Self {
        self.max_depth = depth;
        self
    }

    /// Whether `entry` is in scope.
    #[must_use]
    pub fn matches(&self, entry: &Entry) -> bool {
        if self.max_depth.is_some_and(|limit| entry.depth() > limit) {
            return false;
        }

        // Size limits apply to objects. A directory's size is an aggregate, and
        // excluding a directory because its total exceeds `--max-size` would
        // hide every small file inside it.
        if !entry.is_dir() {
            if self.min_size.is_some_and(|min| entry.size() < min) {
                return false;
            }
            if self.max_size.is_some_and(|max| entry.size() > max) {
                return false;
            }
        }

        if self.exclude.iter().any(|rule| rule.matches(entry)) {
            return false;
        }

        self.include.is_empty() || self.include.iter().any(|rule| rule.matches(entry))
    }

    /// Whether any pattern, size or depth restriction is in force.
    ///
    /// Used by the commands to word an empty result: "nothing here" and
    /// "nothing survived your filters" are different answers, and reporting the
    /// first when the second is true sends the user looking for missing data.
    #[must_use]
    pub fn is_restricting(&self) -> bool {
        !self.include.is_empty()
            || !self.exclude.is_empty()
            || self.min_size.is_some()
            || self.max_size.is_some()
            || self.max_depth.is_some()
    }
}

/// Compile every pattern given to one flag.
fn compile_all(patterns: &[String], flag: &str) -> Result<Vec<Rule>> {
    patterns
        .iter()
        .map(|pattern| Rule::compile(pattern, flag))
        .collect()
}

/// Parse one size limit, naming the flag in any failure.
fn parse_limit(value: Option<&str>, flag: &str) -> Result<Option<u64>> {
    match value {
        None => Ok(None),
        Some(text) => {
            parse_size(text).map_err(|reason| CliError::usage(format!("{flag}: {reason}")))
        }
    }
}

/// Turn the `--max-depth` sentinel into an optional limit.
fn depth_from_flag(value: i32) -> Option<usize> {
    if value <= MAX_DEPTH_UNLIMITED {
        None
    } else {
        usize::try_from(value).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::listing::tests_support::{ctx, entry};
    use crate::exit::ExitCode;

    fn filter(args: &[&str]) -> Filter {
        Filter::from_globals(&ctx(args).globals).expect("flags should compile")
    }

    fn shows(filter: &Filter, path: &str) -> bool {
        filter.matches(&entry("", path, 1024))
    }

    #[test]
    fn an_empty_filter_shows_everything() {
        let filter = filter(&[]);
        assert!(!filter.is_restricting());
        assert!(shows(&filter, "a/b/c.txt"));
        assert!(shows(&filter, "x.jpg"));
    }

    #[test]
    fn a_bare_pattern_matches_the_name_at_any_depth() {
        let filter = filter(&["--include", "*.jpg"]);
        assert!(shows(&filter, "a.jpg"));
        assert!(shows(&filter, "photos/2024/a.jpg"));
        assert!(!shows(&filter, "photos/2024/a.raw"));
    }

    #[test]
    fn a_leading_slash_anchors_at_the_listing_root() {
        let filter = filter(&["--include", "/tmp/*"]);
        assert!(shows(&filter, "tmp/a"));
        // Anchored: a `tmp` further down is a different directory.
        assert!(!shows(&filter, "photos/tmp/a"));
    }

    #[test]
    fn an_unanchored_path_pattern_matches_any_component_suffix() {
        let filter = filter(&["--exclude", "tmp/*"]);
        assert!(!shows(&filter, "tmp/a"));
        assert!(!shows(&filter, "photos/tmp/a"));
        assert!(shows(&filter, "photos/a"));
        // `*` does not cross a separator, so a deeper file survives the rule.
        assert!(shows(&filter, "tmp/a/b"));
    }

    #[test]
    fn a_component_suffix_never_starts_mid_component() {
        // The bug a naive `contains` would have: `photos-tmp/a` is not under a
        // directory called `tmp`.
        let filter = filter(&["--exclude", "tmp/*"]);
        assert!(shows(&filter, "photos-tmp/a"));
    }

    #[test]
    fn exclusion_beats_inclusion() {
        let filter = filter(&["--include", "*.jpg", "--exclude", "private/**"]);
        assert!(shows(&filter, "holiday/a.jpg"));
        assert!(!shows(&filter, "private/a.jpg"));
    }

    #[test]
    fn several_includes_are_a_union() {
        let filter = filter(&["--include", "*.jpg", "--include", "*.raw"]);
        assert!(shows(&filter, "a.jpg"));
        assert!(shows(&filter, "a.raw"));
        assert!(!shows(&filter, "a.txt"));
    }

    #[test]
    fn size_limits_bound_both_ends() {
        let filter = filter(&["--min-size", "1K", "--max-size", "10K"]);
        assert!(filter.matches(&entry("", "a", 1024)));
        assert!(filter.matches(&entry("", "a", 10 * 1024)));
        assert!(!filter.matches(&entry("", "a", 1023)));
        assert!(!filter.matches(&entry("", "a", 10 * 1024 + 1)));
    }

    #[test]
    fn size_limits_do_not_apply_to_directories() {
        // A directory's size is the total beneath it; excluding it would hide
        // every small file inside a large tree.
        let filter = filter(&["--max-size", "1K"]);
        let dir = Entry::directory("big".into(), "", 1 << 30);
        assert!(filter.matches(&dir));
    }

    #[test]
    fn max_depth_counts_from_the_listing_root() {
        let filter = filter(&["--max-depth", "1"]);
        assert!(shows(&filter, "a.txt"));
        assert!(!shows(&filter, "a/b.txt"));
    }

    #[test]
    fn the_unlimited_sentinel_means_no_limit() {
        assert!(shows(&filter(&[]), "a/b/c/d/e.txt"));
        assert_eq!(depth_from_flag(MAX_DEPTH_UNLIMITED), None);
        assert_eq!(depth_from_flag(-7), None);
        assert_eq!(depth_from_flag(3), Some(3));
    }

    #[test]
    fn the_depth_limit_can_be_moved_to_the_directory_layer() {
        // `lsd` must still see deep objects in order to know the directory
        // exists at all.
        let filter = filter(&["--max-depth", "1"]).with_depth_limit(None);
        assert!(shows(&filter, "a/b/c.txt"));
        // And back again, so the dial is a real setter rather than a reset.
        assert!(!shows(
            &filter.clone().with_depth_limit(Some(1)),
            "a/b/c.txt"
        ));
    }

    #[test]
    fn a_rule_file_is_refused_rather_than_ignored() {
        // The failure mode this prevents: a listing that looks complete while
        // silently ignoring the rules that were meant to shape it.
        let error =
            Filter::from_globals(&ctx(&["--filter-from", "rules.txt"]).globals).unwrap_err();
        assert_ne!(error.code(), ExitCode::Success);
        assert!(error.hint().is_some());

        let error = Filter::from_globals(&ctx(&["--files-from", "list.txt"]).globals).unwrap_err();
        assert_ne!(error.code(), ExitCode::Success);
    }

    #[test]
    fn a_malformed_pattern_names_its_flag() {
        let error = Filter::from_globals(&ctx(&["--include", "[abc"]).globals).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("--include"));
    }

    #[test]
    fn a_malformed_size_names_its_flag() {
        let error = Filter::from_globals(&ctx(&["--max-size", "banana"]).globals).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("--max-size"));
    }

    #[test]
    fn off_disables_a_size_limit_rather_than_setting_it_to_zero() {
        let filter = filter(&["--max-size", "off"]);
        assert!(filter.matches(&entry("", "a", u64::MAX)));
        assert!(!filter.is_restricting());
    }

    #[test]
    fn component_suffixes_are_component_aligned_and_longest_first() {
        let suffixes: Vec<&str> = component_suffixes("a/b/c").collect();
        assert_eq!(suffixes, vec!["a/b/c", "b/c", "c"]);
        assert_eq!(component_suffixes("solo").collect::<Vec<_>>(), vec!["solo"]);
    }

    #[test]
    fn restriction_is_reported_whenever_any_dial_is_turned() {
        assert!(filter(&["--include", "*.jpg"]).is_restricting());
        assert!(filter(&["--exclude", "*.tmp"]).is_restricting());
        assert!(filter(&["--min-size", "1K"]).is_restricting());
        assert!(filter(&["--max-depth", "2"]).is_restricting());
    }
}
