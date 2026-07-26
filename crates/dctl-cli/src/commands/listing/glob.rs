//! The glob dialect `--include` and `--exclude` are written in.
//!
//! Hand-written rather than pulled from a crate, for the same reason
//! [`crate::output::table`] is: the dialect has to be *rclone's*, because the
//! patterns users arrive with were written for rclone, and no general-purpose
//! glob crate implements rclone's one distinctive rule — that `*` stops at a
//! path separator while `**` crosses it. A crate that got that subtly wrong
//! would make `--exclude "tmp/*"` match `tmp/a/b`, and the mistake would only
//! ever be noticed as missing files in a listing.
//!
//! ## The dialect
//!
//! | Pattern | Matches                                                |
//! |---------|--------------------------------------------------------|
//! | `*`     | any run of characters within one path component         |
//! | `**`    | any run of characters, crossing `/`                     |
//! | `?`     | exactly one character, never `/`                        |
//! | `[a-z]` | one character from the class                            |
//! | `[!ab]` | one character not in the class (`^` also negates)       |
//! | `\*`    | a literal `*`                                           |
//!
//! Anchoring is *not* decided here. This module answers "does this pattern
//! match this string"; [`super::filter`] decides which string a pattern is
//! offered — the name, the relative path, or a suffix of it — because that is a
//! policy question and this is a matcher.
//!
//! ## Cost
//!
//! Matching is backtracking, so a pattern like `**a**a**a**` against a long
//! path is exponential in the worst case. That is acceptable here and would not
//! be in a server: the patterns come from the command line of the process doing
//! the matching, so the only person who can construct the pathological case is
//! the one paying for it, and every realistic pattern has at most one or two
//! wildcards.

use crate::constants::{
    GLOB_ANY_CHAR, GLOB_ANY_SEQUENCE, GLOB_CLASS_CLOSE, GLOB_CLASS_NEGATE, GLOB_CLASS_OPEN,
    GLOB_CLASS_RANGE, GLOB_ESCAPE, GLOB_RECURSIVE_SEQUENCE, PATH_SEPARATOR,
};

/// One element of a compiled pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    /// A character that must appear exactly.
    Literal(char),
    /// Exactly one character other than [`PATH_SEPARATOR`].
    AnyChar,
    /// Any run of characters, stopping at [`PATH_SEPARATOR`].
    AnySequence,
    /// Any run of characters, crossing [`PATH_SEPARATOR`].
    Recursive,
    /// One character from (or, when negated, not from) a set.
    Class {
        negated: bool,
        items: Vec<ClassItem>,
    },
}

/// A member of a character class.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ClassItem {
    Char(char),
    Range(char, char),
}

impl ClassItem {
    fn contains(&self, candidate: char) -> bool {
        match self {
            Self::Char(c) => *c == candidate,
            Self::Range(low, high) => (*low..=*high).contains(&candidate),
        }
    }
}

/// A compiled glob pattern.
///
/// Holds only the token stream. The pattern text itself stays with the caller,
/// which is where the diagnostics are written: [`super::filter`] quotes the
/// user's own spelling, including the flag it came from, and a second copy here
/// would only be able to say less.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Glob {
    tokens: Vec<Token>,
}

impl Glob {
    /// Compile a pattern.
    ///
    /// # Errors
    /// Returns a message naming the problem and the pattern it was found in,
    /// suitable for a usage error. The only way to fail is an unterminated
    /// character class or a trailing escape — both of which almost always mean
    /// the shell ate a quote, so the message says so.
    pub fn compile(pattern: &str) -> Result<Self, String> {
        let chars: Vec<char> = pattern.chars().collect();
        let mut tokens = Vec::with_capacity(chars.len());
        let mut index = 0usize;

        while let Some(&current) = chars.get(index) {
            match current {
                GLOB_ESCAPE => {
                    let Some(&escaped) = chars.get(index + 1) else {
                        return Err(format!(
                            "pattern '{pattern}' ends with a lone '{GLOB_ESCAPE}'"
                        ));
                    };
                    tokens.push(Token::Literal(escaped));
                    index += 2;
                }
                GLOB_ANY_SEQUENCE => {
                    // `**` is one token, not two: two `AnySequence`s in a row
                    // would each stop at a separator and could never cross one.
                    if chars.get(index + 1) == Some(&GLOB_ANY_SEQUENCE) {
                        tokens.push(Token::Recursive);
                        index += GLOB_RECURSIVE_SEQUENCE.chars().count();
                    } else {
                        tokens.push(Token::AnySequence);
                        index += 1;
                    }
                }
                GLOB_ANY_CHAR => {
                    tokens.push(Token::AnyChar);
                    index += 1;
                }
                GLOB_CLASS_OPEN => {
                    let (token, next) = compile_class(&chars, index, pattern)?;
                    tokens.push(token);
                    index = next;
                }
                other => {
                    tokens.push(Token::Literal(other));
                    index += 1;
                }
            }
        }

        Ok(Self { tokens })
    }

    /// Whether the pattern matches the whole of `text`.
    #[must_use]
    pub fn matches(&self, text: &str) -> bool {
        let chars: Vec<char> = text.chars().collect();
        matches_from(&self.tokens, &chars)
    }
}

/// Parse a character class starting at `open`, returning the token and the
/// index just past the closing bracket.
fn compile_class(chars: &[char], open: usize, pattern: &str) -> Result<(Token, usize), String> {
    let mut index = open + 1;
    let negated = matches!(chars.get(index), Some(c) if GLOB_CLASS_NEGATE.contains(c));
    if negated {
        index += 1;
    }

    let mut items = Vec::new();
    // A `]` in the first position is a literal, which is how POSIX lets a class
    // contain one at all.
    let mut first = true;

    loop {
        let Some(&current) = chars.get(index) else {
            return Err(format!(
                "pattern '{pattern}' has an unclosed '{GLOB_CLASS_OPEN}'; \
                 quote the pattern so the shell does not consume it"
            ));
        };

        if current == GLOB_CLASS_CLOSE && !first {
            return Ok((Token::Class { negated, items }, index + 1));
        }
        first = false;

        let value = if current == GLOB_ESCAPE {
            index += 1;
            match chars.get(index) {
                Some(&escaped) => escaped,
                None => {
                    return Err(format!(
                        "pattern '{pattern}' ends with a lone '{GLOB_ESCAPE}'"
                    ));
                }
            }
        } else {
            current
        };

        // A `-` that is not the last member of the class opens a range.
        let is_range = chars.get(index + 1) == Some(&GLOB_CLASS_RANGE)
            && chars.get(index + 2).is_some_and(|c| *c != GLOB_CLASS_CLOSE);

        if is_range {
            let Some(&high) = chars.get(index + 2) else {
                return Err(format!("pattern '{pattern}' has an incomplete range"));
            };
            items.push(ClassItem::Range(value, high));
            index += 3;
        } else {
            items.push(ClassItem::Char(value));
            index += 1;
        }
    }
}

/// Whether `tokens` matches the whole of `text`.
fn matches_from(tokens: &[Token], text: &[char]) -> bool {
    let Some((token, rest)) = tokens.split_first() else {
        // Pattern exhausted: only a match if the text is too.
        return text.is_empty();
    };

    match token {
        Token::Literal(expected) => match text.split_first() {
            Some((actual, tail)) if actual == expected => matches_from(rest, tail),
            _ => false,
        },

        Token::AnyChar => match text.split_first() {
            Some((actual, tail)) if *actual != PATH_SEPARATOR => matches_from(rest, tail),
            _ => false,
        },

        Token::Class { negated, items } => match text.split_first() {
            Some((actual, tail)) => {
                let inside = items.iter().any(|item| item.contains(*actual));
                // A class never matches a separator, negated or not: `[!a]`
                // asking for "any non-a" must not silently cross a directory
                // boundary the way `**` deliberately does.
                inside != *negated && *actual != PATH_SEPARATOR && matches_from(rest, tail)
            }
            None => false,
        },

        Token::AnySequence => {
            let mut consumed = 0usize;
            loop {
                if text
                    .get(consumed..)
                    .is_some_and(|tail| matches_from(rest, tail))
                {
                    return true;
                }
                match text.get(consumed) {
                    Some(c) if *c != PATH_SEPARATOR => consumed += 1,
                    _ => return false,
                }
            }
        }

        Token::Recursive => (0..=text.len()).any(|consumed| {
            text.get(consumed..)
                .is_some_and(|tail| matches_from(rest, tail))
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(pattern: &str, text: &str) -> bool {
        Glob::compile(pattern)
            .unwrap_or_else(|e| panic!("{pattern} did not compile: {e}"))
            .matches(text)
    }

    #[test]
    fn a_literal_pattern_matches_only_itself() {
        assert!(matches("a.txt", "a.txt"));
        assert!(!matches("a.txt", "a.txtx"));
        assert!(!matches("a.txt", "b.txt"));
    }

    #[test]
    fn a_single_star_stays_within_one_component() {
        // The rule the whole module exists for.
        assert!(matches("*.jpg", "photo.jpg"));
        assert!(matches("tmp/*", "tmp/a"));
        assert!(!matches("tmp/*", "tmp/a/b"));
        assert!(!matches("*.jpg", "2024/photo.jpg"));
    }

    #[test]
    fn a_double_star_crosses_separators() {
        assert!(matches("**/*.jpg", "a/b/photo.jpg"));
        assert!(matches("tmp/**", "tmp/a/b/c"));
        assert!(matches("**", "anything/at/all"));
        // `**` also matches nothing at all, so a trailing one is not a
        // requirement that something follows.
        assert!(matches("tmp/**", "tmp/"));
    }

    #[test]
    fn a_question_mark_is_exactly_one_non_separator() {
        assert!(matches("a?c", "abc"));
        assert!(!matches("a?c", "ac"));
        assert!(!matches("a?c", "abbc"));
        assert!(!matches("a?c", "a/c"));
    }

    #[test]
    fn character_classes_and_ranges_work() {
        assert!(matches("[abc].txt", "b.txt"));
        assert!(!matches("[abc].txt", "d.txt"));
        assert!(matches("img[0-9][0-9].raw", "img42.raw"));
        assert!(!matches("img[0-9][0-9].raw", "imgxy.raw"));
    }

    #[test]
    fn a_negated_class_excludes_its_members() {
        for negate in GLOB_CLASS_NEGATE {
            let pattern = format!("[{negate}abc].txt");
            assert!(matches(&pattern, "d.txt"), "{pattern}");
            assert!(!matches(&pattern, "a.txt"), "{pattern}");
        }
    }

    #[test]
    fn a_negated_class_still_refuses_to_cross_a_separator() {
        // Otherwise `[!x]` would quietly do what only `**` is allowed to do.
        assert!(!matches("a[!x]c", "a/c"));
    }

    #[test]
    fn a_closing_bracket_may_be_the_first_class_member() {
        assert!(matches("[]a].txt", "].txt"));
        assert!(matches("[]a].txt", "a.txt"));
    }

    #[test]
    fn a_trailing_dash_in_a_class_is_a_literal() {
        assert!(matches("[a-].txt", "-.txt"));
        assert!(matches("[a-].txt", "a.txt"));
    }

    #[test]
    fn escaping_removes_a_metacharacter_s_meaning() {
        assert!(matches(r"a\*b", "a*b"));
        assert!(!matches(r"a\*b", "axxb"));
        assert!(matches(r"a\[b", "a[b"));
    }

    #[test]
    fn malformed_patterns_are_rejected_with_a_reason() {
        for pattern in ["[abc", r"trailing\"] {
            let error = Glob::compile(pattern).unwrap_err();
            assert!(error.contains(pattern), "{pattern}: {error}");
        }
        // The likeliest real cause gets named in the message.
        assert!(Glob::compile("[abc").unwrap_err().contains("quote"));
    }

    #[test]
    fn matching_is_case_sensitive_and_unicode_aware() {
        // Logical paths are NFC UTF-8 and the index keys the exact bytes, so a
        // case-folding matcher would claim files the vault does not hold.
        assert!(!matches("*.jpg", "PHOTO.JPG"));
        assert!(matches("caf\u{e9}/*", "caf\u{e9}/a"));
        assert!(matches("?.txt", "\u{e9}.txt"));
    }

    #[test]
    fn an_empty_pattern_matches_only_the_empty_string() {
        assert!(matches("", ""));
        assert!(!matches("", "a"));
    }

    #[test]
    fn adjacent_wildcards_do_not_multiply_the_dialect() {
        // `***` is `**` followed by `*`, and must still behave as "everything".
        assert!(matches("***", "a/b/c"));
    }
}
