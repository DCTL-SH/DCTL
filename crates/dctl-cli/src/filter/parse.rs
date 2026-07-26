//! Reading `--filter-from` rule files and `--files-from` path lists.
//!
//! Two file formats, deliberately kept apart, because they answer different
//! questions and confusing them is expensive.
//!
//! ## A rule file is an ordered program
//!
//! ```text
//! # everything under work/, but not its build output
//! - /work/**/target/
//! + /work/**
//! - **
//! ```
//!
//! Each line is `+ pattern` or `- pattern`, rclone's spelling, so a rule file
//! copied out of an existing rclone setup keeps working. Blank lines are
//! ignored, and a line starting with `#` or `;` is a comment — both spellings,
//! because both are muscle memory (`#` from `.gitignore` and every shell, `;`
//! from INI files and from rclone's own filter files).
//!
//! Order is the whole point: the rules are evaluated top to bottom and the
//! **first** one that matches decides. That is why a rule file needs no
//! precedence rule of its own and why the example above works — the narrow
//! exclusion is written above the broad inclusion, exactly as it reads.
//!
//! A line that is neither a comment nor a rule is a usage error naming the file
//! and the line number. It is not skipped: a rule file with a typo'd marker is a
//! rule file whose author believes a rule is in force, and a filter believed to
//! be in force but silently absent is how a `sync` deletes what it was written
//! to protect.
//!
//! A lone `!` discards every rule accumulated so far. It exists so a file can
//! start from a known state regardless of what a wrapper script put in front of
//! it — the one thing a first-match-wins list cannot otherwise express.
//!
//! ### Whitespace
//!
//! Each line is trimmed at both ends before it is read, matching rclone. A
//! consequence worth stating: a pattern cannot end in a literal space, because
//! the trim removes it before the escape could protect it. Name such a file with
//! a trailing `?` instead.
//!
//! ## A path list is not a pattern
//!
//! `--files-from` names files exactly — no globbing, no anchoring, no
//! precedence. Each line goes through [`logical::clean_logical`], so a list
//! written on Windows with backslashes, or on a Mac with decomposed accents,
//! selects the same objects as one written on Linux. That is the same
//! normalisation the index key itself uses, which is what makes the list a
//! lookup rather than a search.
//!
//! A `..` component is refused rather than resolved. The list is relative to the
//! transfer root, and a line that climbs out of it is either a mistake or an
//! attempt to reach somewhere the operator did not name.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::constants::{
    FILTER_COMMENT_MARKERS, FILTER_RULE_CLEAR, FILTER_RULE_EXCLUDE, FILTER_RULE_INCLUDE,
};
use crate::platform::path as logical;

use super::rule::Action;

/// What is wrong with one line of a filter file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineProblem {
    /// Neither a comment, a rule, nor the clear directive.
    MissingMarker,
    /// A `+` or `-` with nothing after it.
    MissingPattern,
    /// A path that climbs above the transfer root.
    EscapesRoot,
}

impl fmt::Display for LineProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMarker => write!(
                f,
                "a rule must begin with '{FILTER_RULE_INCLUDE} ' or '{FILTER_RULE_EXCLUDE} '"
            ),
            Self::MissingPattern => write!(f, "the rule marker is not followed by a pattern"),
            Self::EscapesRoot => write!(f, "the path escapes the transfer root with '..'"),
        }
    }
}

/// Why a filter file could not be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileProblem {
    /// The file could not be read at all.
    Unreadable { source: PathBuf, detail: String },
    /// One line could not be understood.
    Malformed {
        source: PathBuf,
        line: usize,
        text: String,
        problem: LineProblem,
    },
}

impl FileProblem {
    /// Advice for the reader.
    pub fn hint(&self) -> String {
        match self {
            Self::Unreadable { .. } => {
                "The path is read relative to the working directory of the dctl process, \
                 which is not always the directory you launched it from."
                    .to_string()
            }
            Self::Malformed { problem, .. } => match problem {
                LineProblem::MissingMarker | LineProblem::MissingPattern => format!(
                    "Rules are written '{FILTER_RULE_INCLUDE} pattern' or \
                     '{FILTER_RULE_EXCLUDE} pattern', one per line. Blank lines and lines \
                     starting with {} are ignored. A line was refused rather than skipped \
                     because a rule you believe is in force but is not is how a filter \
                     silently stops protecting anything.",
                    describe_comment_markers()
                ),
                LineProblem::EscapesRoot =>
                    "Paths in a list are relative to the transfer root and may not contain \
                     '..' components."
                        .to_string(),
            },
        }
    }
}

impl fmt::Display for FileProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { source, detail } => {
                write!(f, "cannot read {}: {detail}", source.display())
            }
            Self::Malformed {
                source,
                line,
                text,
                problem,
            } => write!(f, "{}:{line}: '{text}': {problem}", source.display()),
        }
    }
}

impl std::error::Error for FileProblem {}

/// The comment markers, spelled for a message.
fn describe_comment_markers() -> String {
    FILTER_COMMENT_MARKERS
        .iter()
        .map(|marker| format!("'{marker}'"))
        .collect::<Vec<_>>()
        .join(" or ")
}

/// One directive read from a rule file.
///
/// Carries the line it came from so a decision can be traced back to the exact
/// line of the exact file that made it — which is the only way to debug a rule
/// file long enough to be worth writing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Directive {
    /// Add a rule to the end of the list.
    Rule {
        action: Action,
        pattern: String,
        line: usize,
    },
    /// Discard every rule accumulated so far.
    Clear { line: usize },
}

/// Parse the text of a rule file.
///
/// `origin` is used only for diagnostics.
///
/// # Errors
/// [`FileProblem::Malformed`] naming the file, the line number and the line.
pub fn rules_in(text: &str, origin: &Path) -> Result<Vec<Directive>, FileProblem> {
    let mut directives = Vec::new();

    for (offset, raw) in text.lines().enumerate() {
        let line = offset + 1;
        let trimmed = raw.trim();

        if trimmed.is_empty() || starts_a_comment(trimmed) {
            continue;
        }

        if trimmed == FILTER_RULE_CLEAR {
            directives.push(Directive::Clear { line });
            continue;
        }

        let action = match first_char(trimmed) {
            Some(FILTER_RULE_INCLUDE) => Action::Include,
            Some(FILTER_RULE_EXCLUDE) => Action::Exclude,
            _ => return Err(malformed(origin, line, trimmed, LineProblem::MissingMarker)),
        };

        // The marker has to be a word of its own: without the separating space
        // `-file.txt` would read as an exclusion of `file.txt` rather than as
        // the pattern for a file whose name begins with a dash.
        let rest = trimmed.get(action.marker().len_utf8()..).unwrap_or_default();
        if !rest.starts_with(char::is_whitespace) {
            return Err(malformed(origin, line, trimmed, LineProblem::MissingMarker));
        }

        let pattern = rest.trim();
        if pattern.is_empty() {
            return Err(malformed(origin, line, trimmed, LineProblem::MissingPattern));
        }

        directives.push(Directive::Rule {
            action,
            pattern: pattern.to_string(),
            line,
        });
    }

    Ok(directives)
}

/// Read a `--filter-from` file.
///
/// # Errors
/// [`FileProblem::Unreadable`] if the file cannot be read, or
/// [`FileProblem::Malformed`] for a line that is not a rule.
pub fn rules_from_file(source: &Path) -> Result<Vec<Directive>, FileProblem> {
    rules_in(&read(source)?, source)
}

/// Parse the text of a `--files-from` list into canonical logical paths.
///
/// # Errors
/// [`FileProblem::Malformed`] for a line that climbs above the transfer root.
pub fn paths_in(text: &str, origin: &Path) -> Result<BTreeSet<String>, FileProblem> {
    let mut paths = BTreeSet::new();

    for (offset, raw) in text.lines().enumerate() {
        let line = offset + 1;
        let trimmed = raw.trim();

        if trimmed.is_empty() || starts_a_comment(trimmed) {
            continue;
        }

        let Some(cleaned) = logical::clean_logical(trimmed) else {
            return Err(malformed(origin, line, trimmed, LineProblem::EscapesRoot));
        };

        // `.` and `./` clean away to nothing. They name the transfer root, which
        // is not a file anybody can be asked to copy, so they are dropped rather
        // than silently inserted as an empty key.
        if !cleaned.is_empty() {
            paths.insert(cleaned);
        }
    }

    Ok(paths)
}

/// Read a `--files-from` list.
///
/// # Errors
/// [`FileProblem::Unreadable`] if the file cannot be read, or
/// [`FileProblem::Malformed`] for a line that escapes the root.
pub fn paths_from_file(source: &Path) -> Result<BTreeSet<String>, FileProblem> {
    paths_in(&read(source)?, source)
}

/// Read a whole filter file, attributing an I/O failure to its path.
fn read(source: &Path) -> Result<String, FileProblem> {
    std::fs::read_to_string(source).map_err(|error| FileProblem::Unreadable {
        source: source.to_path_buf(),
        detail: error.to_string(),
    })
}

fn starts_a_comment(line: &str) -> bool {
    first_char(line).is_some_and(|c| FILTER_COMMENT_MARKERS.contains(&c))
}

fn first_char(line: &str) -> Option<char> {
    line.chars().next()
}

fn malformed(source: &Path, line: usize, text: &str, problem: LineProblem) -> FileProblem {
    FileProblem::Malformed {
        source: source.to_path_buf(),
        line,
        text: text.to_string(),
        problem,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> &'static Path {
        Path::new("rules.txt")
    }

    fn rules(text: &str) -> Vec<Directive> {
        rules_in(text, origin()).expect("the rule file should parse")
    }

    fn patterns(text: &str) -> Vec<(Action, String)> {
        rules(text)
            .into_iter()
            .filter_map(|directive| match directive {
                Directive::Rule {
                    action, pattern, ..
                } => Some((action, pattern)),
                Directive::Clear { .. } => None,
            })
            .collect()
    }

    #[test]
    fn a_rule_file_keeps_comments_blank_lines_and_order() {
        let text = "\
# photos, but never the raw sidecars
;  a second comment spelling

  - /photos/**/*.xmp
  + /photos/**

- **
";
        assert_eq!(
            patterns(text),
            vec![
                (Action::Exclude, "/photos/**/*.xmp".to_string()),
                (Action::Include, "/photos/**".to_string()),
                (Action::Exclude, "**".to_string()),
            ],
            "order is the meaning of a rule file and must survive parsing"
        );
    }

    #[test]
    fn the_line_number_reported_is_the_line_in_the_file() {
        // Counted over every line, comments and blanks included, or a report
        // would point at the wrong line of the operator's own file.
        let directives = rules("# one\n\n+ *.jpg\n");
        assert_eq!(
            directives,
            vec![Directive::Rule {
                action: Action::Include,
                pattern: "*.jpg".to_string(),
                line: 3,
            }]
        );
    }

    #[test]
    fn extra_whitespace_around_a_rule_is_ignored() {
        assert_eq!(
            patterns("\t+   *.jpg   \n"),
            vec![(Action::Include, "*.jpg".to_string())]
        );
    }

    #[test]
    fn a_lone_bang_clears_the_rules_so_far() {
        let directives = rules("+ a\n!\n- b\n");
        assert_eq!(
            directives,
            vec![
                Directive::Rule {
                    action: Action::Include,
                    pattern: "a".to_string(),
                    line: 1,
                },
                Directive::Clear { line: 2 },
                Directive::Rule {
                    action: Action::Exclude,
                    pattern: "b".to_string(),
                    line: 3,
                },
            ]
        );
    }

    #[test]
    fn a_line_with_no_marker_is_refused_rather_than_skipped() {
        // The failure this prevents: an author who believes a rule is in force
        // when it silently is not.
        let error = rules_in("*.jpg\n", origin()).expect_err("a bare pattern is not a rule");
        assert_eq!(
            error,
            FileProblem::Malformed {
                source: origin().to_path_buf(),
                line: 1,
                text: "*.jpg".to_string(),
                problem: LineProblem::MissingMarker,
            }
        );
        assert!(error.to_string().contains("rules.txt:1"));
        assert!(!error.hint().is_empty());
    }

    #[test]
    fn a_marker_must_be_a_word_of_its_own() {
        // Otherwise `-file.txt` would read as an exclusion of `file.txt` rather
        // than as the pattern for a file whose name starts with a dash.
        let error = rules_in("-file.txt\n", origin()).expect_err("no separating space");
        assert!(matches!(
            error,
            FileProblem::Malformed {
                problem: LineProblem::MissingMarker,
                ..
            }
        ));
        assert_eq!(
            patterns("- -file.txt\n"),
            vec![(Action::Exclude, "-file.txt".to_string())]
        );
    }

    #[test]
    fn a_marker_with_no_pattern_is_refused() {
        let error = rules_in("+ \n", origin()).expect_err("nothing to include");
        assert!(matches!(
            error,
            FileProblem::Malformed {
                problem: LineProblem::MissingPattern,
                ..
            }
        ));
    }

    #[test]
    fn every_line_problem_explains_itself() {
        for problem in [
            LineProblem::MissingMarker,
            LineProblem::MissingPattern,
            LineProblem::EscapesRoot,
        ] {
            assert!(problem.to_string().len() > 20, "{problem:?}");
        }
    }

    #[test]
    fn a_path_list_is_cleaned_deduplicated_and_sorted() {
        let text = "\
# the manifest an upstream job produced
photos/2024/a.jpg

./photos/2024/b.jpg
photos/2024/a.jpg
";
        let paths = paths_in(text, origin()).expect("the list should parse");
        assert_eq!(
            paths.into_iter().collect::<Vec<_>>(),
            vec!["photos/2024/a.jpg", "photos/2024/b.jpg"]
        );
    }

    #[test]
    fn a_path_list_reads_the_same_on_every_platform() {
        // A list written on Windows and a list written on a Mac must select the
        // same objects as one written on Linux, or a restore run from a
        // different machine quietly pulls back a different set of files.
        let windows = paths_in(r"photos\2024\a.jpg", origin()).expect("backslashes");
        let unix = paths_in("photos/2024/a.jpg", origin()).expect("forward slashes");
        assert_eq!(windows, unix);

        let decomposed = paths_in("cafe\u{301}/a.jpg", origin()).expect("decomposed");
        let composed = paths_in("caf\u{e9}/a.jpg", origin()).expect("composed");
        assert_eq!(decomposed, composed);
    }

    #[test]
    fn a_path_that_escapes_the_root_is_refused() {
        let error = paths_in("../../etc/passwd\n", origin()).expect_err("escaping path");
        assert!(matches!(
            error,
            FileProblem::Malformed {
                problem: LineProblem::EscapesRoot,
                ..
            }
        ));
        assert!(error.hint().contains(".."));
    }

    #[test]
    fn a_line_naming_only_the_root_is_dropped() {
        // `.` cleans away to nothing; inserting it would put an empty key in a
        // set that is otherwise a set of files.
        let paths = paths_in(".\n./\na.txt\n", origin()).expect("the list should parse");
        assert_eq!(paths.into_iter().collect::<Vec<_>>(), vec!["a.txt"]);
    }

    #[test]
    fn an_unreadable_file_names_itself() {
        let missing = Path::new("no/such/filter/file.txt");
        let error = rules_from_file(missing).expect_err("the file does not exist");
        assert!(error.to_string().contains("file.txt"));
        assert!(!error.hint().is_empty());
        assert!(paths_from_file(missing).is_err());
    }

    #[test]
    fn a_real_file_round_trips_through_the_filesystem() {
        let dir = std::env::temp_dir().join(format!("dctl-filter-parse-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temporary directory");

        let rules_path = dir.join("rules.txt");
        std::fs::write(&rules_path, "# a comment\n+ *.jpg\n- **\n").expect("write rules");
        let directives = rules_from_file(&rules_path).expect("read rules");
        assert_eq!(directives.len(), 2);

        let list_path = dir.join("list.txt");
        std::fs::write(&list_path, "a.txt\n# skip\nb/c.txt\n").expect("write list");
        let paths = paths_from_file(&list_path).expect("read list");
        assert_eq!(paths.into_iter().collect::<Vec<_>>(), vec!["a.txt", "b/c.txt"]);

        std::fs::remove_dir_all(&dir).ok();
    }
}
