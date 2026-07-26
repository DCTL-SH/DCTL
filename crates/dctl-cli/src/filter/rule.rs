//! One include/exclude rule: what it matches, and where it is allowed to match.
//!
//! [`super::glob`] answers "does this pattern match this string". A rule answers
//! the question a user actually asked, which is "does this pattern match this
//! *file*" — and the gap between the two is anchoring, the part of rclone's
//! dialect that surprises people most often.
//!
//! ## Anchoring
//!
//! The shape of the pattern decides which string it is offered, exactly as in
//! rclone:
//!
//! * A pattern beginning with `/` is **anchored** at the transfer root and is
//!   matched against the whole root-relative path. `/tmp/*` matches `tmp/a` and
//!   never `photos/tmp/a`.
//! * A pattern containing no `/` at all is matched against the **file name**, at
//!   any depth. `*.jpg` means what everyone assumes it means.
//! * Anything else is matched against the root-relative path **and against every
//!   suffix of it that begins on a component boundary**, so `tmp/*` finds
//!   `photos/tmp/a` as well as `tmp/a` — but never `photos-tmp/a`, because a
//!   suffix that started mid-component would make `tmp` match a directory that
//!   merely ends in it.
//!
//! ## A trailing `/` means directories only
//!
//! `--exclude 'cache/'` matches the directory `cache` and no file, ever. Its
//! effect on the files *inside* comes from the walk: a directory a filter
//! refuses is not descended into, so nothing under it is ever offered. That
//! separation is deliberate. It keeps this module a pure predicate, and it means
//! the same rule set prunes a local walk and post-filters a remote listing
//! without either one re-deriving the policy.
//!
//! To exclude a directory *and* its contents by pattern alone, write both — or
//! write `cache/**`, which is the form that names the contents.
//!
//! ## Normalisation
//!
//! A pattern is NFC-normalised on the way in, because the paths it is matched
//! against always are ([`crate::platform::path`]). Without it, a rule typed on a
//! Mac (`cafe` + combining acute) would silently fail to match the very file it
//! was written for, whose logical path is the composed spelling. The two are
//! indistinguishable on screen, so the operator would have no way to see why.

use crate::constants::PATH_SEPARATOR;
use crate::platform::path as logical;

use super::Candidate;
use super::glob::{Glob, PatternError};

/// What a matching rule does to the path it matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// The path is in scope.
    Include,
    /// The path is out of scope.
    Exclude,
}

impl Action {
    /// The marker this action is written with in a `--filter-from` file.
    pub const fn marker(self) -> char {
        match self {
            Self::Include => crate::constants::FILTER_RULE_INCLUDE,
            Self::Exclude => crate::constants::FILTER_RULE_EXCLUDE,
        }
    }

    /// The word used when reporting a decision.
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Include => "included",
            Self::Exclude => "excluded",
        }
    }

    /// Whether this action admits the path.
    pub const fn admits(self) -> bool {
        matches!(self, Self::Include)
    }
}

/// Which string a pattern is offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Anchor {
    /// The whole root-relative path only.
    Root,
    /// The final path component, at any depth.
    Name,
    /// The root-relative path, or any component-aligned suffix of it.
    Suffix,
}

/// One compiled include/exclude rule.
#[derive(Clone, Debug)]
pub struct Rule {
    action: Action,
    glob: Glob,
    anchor: Anchor,
    directories_only: bool,
    /// The pattern exactly as the operator wrote it.
    ///
    /// Kept so a decision can be reported in the user's own spelling — the
    /// normalised, de-anchored form the matcher holds is not a string anybody
    /// typed, and showing it back would look like DCTL had rewritten the rule.
    source: String,
}

impl Rule {
    /// Compile one rule.
    ///
    /// # Errors
    /// A [`PatternError`] naming the pattern and the position of the problem.
    pub fn compile(action: Action, pattern: &str) -> Result<Self, PatternError> {
        let source = pattern.to_string();
        let normalised = logical::normalize_unicode(pattern);

        // Order matters: the trailing separator is the directory marker and the
        // leading one is the anchor, and both have to come off before the rest
        // is read as a pattern.
        let (body, directories_only) = match normalised.strip_suffix(PATH_SEPARATOR) {
            Some(trimmed) => (trimmed.to_string(), true),
            None => (normalised, false),
        };

        let (anchor, body) = match body.strip_prefix(PATH_SEPARATOR) {
            Some(rest) => (Anchor::Root, rest.to_string()),
            None if body.contains(PATH_SEPARATOR) => (Anchor::Suffix, body),
            None => (Anchor::Name, body),
        };

        // `/` on its own de-anchors to nothing and names the root itself, which
        // no candidate path spells; the empty pattern is refused by the matcher
        // with a message that says so.
        let glob = Glob::compile(&body)?;

        Ok(Self {
            action,
            glob,
            anchor,
            directories_only,
            source,
        })
    }

    /// What this rule does when it matches.
    pub const fn action(&self) -> Action {
        self.action
    }

    /// The pattern as written.
    pub fn pattern(&self) -> &str {
        &self.source
    }

    /// Whether this rule can only ever match a directory.
    pub const fn directories_only(&self) -> bool {
        self.directories_only
    }

    /// Whether this rule matches `candidate`.
    pub fn matches(&self, candidate: &Candidate<'_>) -> bool {
        if self.directories_only && !candidate.is_dir() {
            return false;
        }

        let path = candidate.path();
        match self.anchor {
            Anchor::Root => self.glob.matches(path),
            Anchor::Name => self.glob.matches(logical::file_name(path)),
            Anchor::Suffix => component_suffixes(path).any(|suffix| self.glob.matches(suffix)),
        }
    }
}

/// Every suffix of `path` that begins on a component boundary, longest first.
///
/// `a/b/c` yields `a/b/c`, `b/c`, `c`. Longest first because the common case is
/// a rule that matches the whole path, and finding it on the first try is one
/// comparison rather than one per component.
fn component_suffixes(path: &str) -> impl Iterator<Item = &str> {
    std::iter::once(path).chain(
        path.match_indices(PATH_SEPARATOR)
            .filter_map(move |(index, _)| path.get(index + PATH_SEPARATOR.len_utf8()..)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str) -> Rule {
        Rule::compile(Action::Include, pattern)
            .unwrap_or_else(|e| panic!("{pattern} did not compile: {e}"))
    }

    fn hits(pattern: &str, path: &str) -> bool {
        rule(pattern).matches(&Candidate::file(path, 0))
    }

    fn hits_dir(pattern: &str, path: &str) -> bool {
        rule(pattern).matches(&Candidate::directory(path))
    }

    #[test]
    fn a_bare_pattern_matches_the_name_at_any_depth() {
        assert!(hits("*.jpg", "a.jpg"));
        assert!(hits("*.jpg", "photos/2024/a.jpg"));
        assert!(!hits("*.jpg", "photos/2024/a.raw"));
        assert!(hits("thumbs.db", "a/b/thumbs.db"));
    }

    #[test]
    fn a_leading_slash_anchors_at_the_transfer_root() {
        assert!(hits("/tmp/*", "tmp/a"));
        // Anchored: a `tmp` further down is a different directory.
        assert!(!hits("/tmp/*", "photos/tmp/a"));
        assert!(hits("/a.txt", "a.txt"));
        assert!(!hits("/a.txt", "b/a.txt"));
    }

    #[test]
    fn an_unanchored_path_pattern_matches_any_component_suffix() {
        assert!(hits("tmp/*", "tmp/a"));
        assert!(hits("tmp/*", "photos/tmp/a"));
        assert!(!hits("tmp/*", "photos/a"));
        // `*` does not cross a separator, so a deeper file survives this rule.
        assert!(!hits("tmp/*", "tmp/a/b"));
        assert!(hits("tmp/**", "tmp/a/b"));
    }

    #[test]
    fn a_component_suffix_never_starts_mid_component() {
        // The bug a naive `contains` would have: `photos-tmp/a` is not under a
        // directory called `tmp`, and treating it as one would exclude a tree
        // the operator never named.
        assert!(!hits("tmp/*", "photos-tmp/a"));
        assert!(!hits("tmp/*", "xtmp/a"));
    }

    #[test]
    fn a_trailing_slash_matches_directories_only() {
        assert!(rule("cache/").directories_only());
        assert!(hits_dir("cache/", "cache"));
        assert!(hits_dir("cache/", "src/cache"));
        // The directory's *contents* are not matched by the rule itself; the
        // walk stops descending instead. See the module documentation.
        assert!(!hits("cache/", "cache"));
        assert!(!hits("cache/", "cache/a.o"));
    }

    #[test]
    fn a_directory_rule_can_be_anchored_too() {
        let anchored = rule("/build/");
        assert!(anchored.matches(&Candidate::directory("build")));
        assert!(!anchored.matches(&Candidate::directory("src/build")));
    }

    #[test]
    fn a_file_rule_matches_a_directory_of_the_same_name() {
        // Without a trailing slash a rule is about the *path*, not about the
        // kind of thing at it — so `--exclude node_modules` prunes the
        // directory, which is what the person meant.
        assert!(hits_dir("node_modules", "a/node_modules"));
        assert!(hits("node_modules", "a/node_modules"));
    }

    #[test]
    fn the_pattern_is_reported_as_the_operator_wrote_it() {
        // Not as the de-anchored, normalised string the matcher holds — that
        // would read as though DCTL had rewritten the rule.
        assert_eq!(rule("/tmp/**").pattern(), "/tmp/**");
        assert_eq!(rule("cache/").pattern(), "cache/");
    }

    #[test]
    fn nfc_equivalent_spellings_match_the_same_pattern() {
        // macOS hands back decomposed names, Linux and Windows composed ones.
        // Both display identically, so a rule that matched only one spelling
        // would look like it had been ignored.
        let decomposed = "cafe\u{301}/photo.jpg";
        let composed = "caf\u{e9}/photo.jpg";
        assert_ne!(decomposed, composed, "the inputs really do differ");

        let stored = logical::normalize_unicode(decomposed);
        // A rule typed in either spelling matches the stored (composed) path.
        assert!(Rule::compile(Action::Exclude, "cafe\u{301}/*")
            .expect("decomposed pattern")
            .matches(&Candidate::file(&stored, 0)));
        assert!(Rule::compile(Action::Exclude, "caf\u{e9}/*")
            .expect("composed pattern")
            .matches(&Candidate::file(&stored, 0)));
        assert!(Rule::compile(Action::Exclude, "caf\u{e9}\u{301}*")
            .is_ok_and(|r| !r.matches(&Candidate::file(&stored, 0))));
    }

    #[test]
    fn alternation_and_classes_survive_anchoring() {
        assert!(hits("*.{jpg,png}", "holiday/a.png"));
        assert!(!hits("*.{jpg,png}", "holiday/a.txt"));
        assert!(hits("/raw/img[0-9][0-9].dng", "raw/img07.dng"));
        assert!(!hits("/raw/img[0-9][0-9].dng", "raw/imgAB.dng"));
    }

    #[test]
    fn a_malformed_pattern_is_refused_rather_than_matching_nothing() {
        let error = Rule::compile(Action::Include, "[abc").expect_err("unclosed class");
        assert_eq!(error.pattern(), "[abc");
        assert!(error.position() >= 1);
    }

    #[test]
    fn component_suffixes_are_component_aligned_and_longest_first() {
        let suffixes: Vec<&str> = component_suffixes("a/b/c").collect();
        assert_eq!(suffixes, vec!["a/b/c", "b/c", "c"]);
        assert_eq!(component_suffixes("solo").collect::<Vec<_>>(), vec!["solo"]);
        // A trailing separator yields the empty suffix, which matches nothing
        // any real pattern can name, and must not be skipped silently.
        assert_eq!(component_suffixes("a/").collect::<Vec<_>>(), vec!["a/", ""]);
    }

    #[test]
    fn the_two_actions_are_distinguishable_everywhere_they_are_shown() {
        assert!(Action::Include.admits());
        assert!(!Action::Exclude.admits());
        assert_ne!(Action::Include.marker(), Action::Exclude.marker());
        assert_ne!(Action::Include.describe(), Action::Exclude.describe());
    }
}
