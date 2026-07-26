//! The glob dialect every DCTL filter is written in.
//!
//! Hand-written rather than taken from a crate, because the dialect has to be
//! *rclone's*: the patterns users arrive with were written for rclone, and no
//! general-purpose glob crate implements rclone's distinctive rule — that `*`
//! stops at a path separator while `**` crosses it. A crate that got that subtly
//! wrong would make `--exclude 'tmp/*'` match `tmp/a/b`, and the mistake would
//! only ever be noticed as files missing from a listing, or present in a backup
//! that was supposed to omit them.
//!
//! This module answers exactly one question: *does this pattern match this
//! string*. Which string a pattern is offered — the whole path, the file name,
//! or a suffix — is anchoring policy and lives in [`super::rule`].
//!
//! ## The dialect
//!
//! | Pattern   | Matches                                              |
//! |-----------|------------------------------------------------------|
//! | `*`       | any run of characters *within* one path component    |
//! | `**`      | any run of characters, crossing `/`                  |
//! | `?`       | exactly one character, never `/`                     |
//! | `[a-z]`   | one character from the class, never `/`              |
//! | `[!a-z]`  | one character not in the class (`^` also negates)    |
//! | `{a,b}`   | either alternative; nests                            |
//! | `\*`      | a literal `*`; `\` escapes any metacharacter         |
//!
//! `]` outside a class and `}` outside an alternation are ordinary literals,
//! which is what every shell does and what lets `--include 'a}b'` name the file
//! a person actually has.
//!
//! ## `\` is an escape, never a separator
//!
//! Worth stating because it is the one place a pattern and a *path* are read
//! differently. [`crate::platform::path::clean_logical`] splits a path a person
//! typed on `\` as well as `/`, so a Windows-flavoured `--files-from` line works
//! everywhere. A pattern does not: `\` is the escape character, so
//! `--exclude 'photos\*.jpg'` asks for a file literally called `photos*.jpg`,
//! not for JPEGs under `photos`. Both readings cannot be had at once, and the
//! escape is the one rclone commits to, so DCTL does too. Patterns are therefore
//! written with `/` on every platform — which is also what makes a pattern mean
//! the same thing on Windows and on a Linux build agent.
//!
//! ## Cost: bounded by construction, not by hope
//!
//! Matching is an NFA simulation over the whole live state set at once (a Pike
//! VM without captures), not a backtracking search. That choice is the answer to
//! catastrophic backtracking: a pattern such as `**a**a**a**a**` costs a
//! backtracker exponential time and costs this matcher nothing extra, because
//! every alternative is explored in the same pass rather than one after another.
//!
//! The bound is exact and worth writing down: **one match costs at most
//! `characters in the path × instructions in the program` character tests.**
//! The program is capped at [`GLOB_MAX_INSTRUCTIONS`], the pattern that produces
//! it at [`GLOB_MAX_PATTERN_CHARS`], and brace nesting at
//! [`GLOB_MAX_NESTING_DEPTH`] — which is also the parser's and the emitter's
//! recursion depth, so neither can run away. Exceeding any of the three is a
//! usage error naming the pattern and the position, never a silent no-match.

use std::fmt;

use crate::constants::{
    GLOB_ALTERNATION_CLOSE, GLOB_ALTERNATION_OPEN, GLOB_ALTERNATION_SEPARATOR, GLOB_ANY_CHAR,
    GLOB_ANY_SEQUENCE, GLOB_CLASS_CLOSE, GLOB_CLASS_NEGATE, GLOB_CLASS_OPEN, GLOB_CLASS_RANGE,
    GLOB_ESCAPE, GLOB_MAX_INSTRUCTIONS, GLOB_MAX_NESTING_DEPTH, GLOB_MAX_PATTERN_CHARS,
    GLOB_PATTERN_HINT, PATH_SEPARATOR,
};

// ─────────────────────────────────────────────────────────────────────────────
// Failure
// ─────────────────────────────────────────────────────────────────────────────

/// What is wrong with a pattern.
///
/// Carried as a value rather than a formatted string so the tests can assert on
/// the *kind* of failure, which is what keeps "unclosed bracket" from quietly
/// degrading into "some parse error" as the parser changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatternProblem {
    /// Nothing to match. An empty `--include` would select nothing at all, and
    /// silently selecting nothing is the failure this whole module exists to
    /// avoid.
    Empty,
    /// A `[` with no `]` after it.
    UnclosedClass,
    /// A `{` with no `}` after it.
    UnclosedAlternation,
    /// A `\` as the final character, escaping nothing.
    TrailingEscape,
    /// A class range whose ends are the wrong way round, such as `[z-a]`. It can
    /// never match, so it is a typo rather than a selection.
    ReversedRange { low: char, high: char },
    /// Longer than [`GLOB_MAX_PATTERN_CHARS`].
    TooLong { limit: usize },
    /// Braces nested deeper than [`GLOB_MAX_NESTING_DEPTH`].
    TooDeep { limit: usize },
    /// Compiles to more than [`GLOB_MAX_INSTRUCTIONS`] steps.
    TooComplex { limit: usize },
}

impl fmt::Display for PatternProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "the pattern is empty and would select nothing"),
            Self::UnclosedClass => write!(f, "'{GLOB_CLASS_OPEN}' is never closed"),
            Self::UnclosedAlternation => write!(f, "'{GLOB_ALTERNATION_OPEN}' is never closed"),
            Self::TrailingEscape => write!(f, "the pattern ends with a lone '{GLOB_ESCAPE}'"),
            Self::ReversedRange { low, high } => write!(
                f,
                "the range '{low}{GLOB_CLASS_RANGE}{high}' runs backwards, so it can never match"
            ),
            Self::TooLong { limit } => {
                write!(f, "the pattern is longer than {limit} characters")
            }
            Self::TooDeep { limit } => write!(
                f,
                "'{GLOB_ALTERNATION_OPEN}' is nested more than {limit} deep"
            ),
            Self::TooComplex { limit } => {
                write!(f, "the pattern needs more than {limit} matching steps")
            }
        }
    }
}

/// A pattern that could not be compiled, and where it went wrong.
///
/// Both the pattern and the position are carried because the caller cannot
/// reconstruct either: by the time a rule reaches the engine it may have come
/// from a file rather than a flag, and a report that said only "malformed
/// pattern" would leave the operator grepping their own rule file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatternError {
    pattern: String,
    /// Zero-based character offset; rendered one-based, because that is how
    /// people count columns.
    position: usize,
    problem: PatternProblem,
}

impl PatternError {
    /// The pattern exactly as it was written.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// The one-based character position the problem was found at.
    pub const fn position(&self) -> usize {
        self.position + 1
    }

    /// What is wrong.
    pub const fn problem(&self) -> PatternProblem {
        self.problem
    }

    /// Advice for the reader. Always present: a pattern error is very often the
    /// shell's doing rather than the user's, and saying so is the fix.
    pub const fn hint(&self) -> &'static str {
        GLOB_PATTERN_HINT
    }
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "pattern '{}': {} at position {}",
            self.pattern,
            self.problem,
            self.position()
        )
    }
}

impl std::error::Error for PatternError {}

// ─────────────────────────────────────────────────────────────────────────────
// Syntax tree
// ─────────────────────────────────────────────────────────────────────────────

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

/// One element of a parsed pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Node {
    /// A character that must appear exactly.
    Literal(char),
    /// Exactly one character other than [`PATH_SEPARATOR`].
    AnyChar,
    /// Any run of characters, stopping at [`PATH_SEPARATOR`].
    Star,
    /// Any run of characters, crossing [`PATH_SEPARATOR`].
    Globstar,
    /// One character from (or, negated, not from) a set.
    Class {
        negated: bool,
        items: Vec<ClassItem>,
    },
    /// Any one of several alternatives.
    Alternation(Vec<Vec<Node>>),
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser
// ─────────────────────────────────────────────────────────────────────────────

/// Recursive-descent parser over the pattern's characters.
///
/// Works on a `Vec<char>` rather than byte offsets so that a position in an
/// error message counts characters, which is what a person sees. Patterns are
/// capped at [`GLOB_MAX_PATTERN_CHARS`], so the allocation is bounded.
struct Parser<'a> {
    pattern: &'a str,
    chars: Vec<char>,
    index: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn new(pattern: &'a str) -> Result<Self, PatternError> {
        let chars: Vec<char> = pattern.chars().collect();
        if chars.is_empty() {
            return Err(PatternError {
                pattern: pattern.to_string(),
                position: 0,
                problem: PatternProblem::Empty,
            });
        }
        if chars.len() > GLOB_MAX_PATTERN_CHARS {
            return Err(PatternError {
                pattern: pattern.to_string(),
                position: GLOB_MAX_PATTERN_CHARS,
                problem: PatternProblem::TooLong {
                    limit: GLOB_MAX_PATTERN_CHARS,
                },
            });
        }
        Ok(Self {
            pattern,
            chars,
            index: 0,
            depth: 0,
        })
    }

    fn fail<T>(&self, position: usize, problem: PatternProblem) -> Result<T, PatternError> {
        Err(PatternError {
            pattern: self.pattern.to_string(),
            position,
            problem,
        })
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.index).copied()
    }

    fn at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.index + offset).copied()
    }

    /// Parse until the end of the pattern, or — inside an alternation — until
    /// the `,` or `}` that ends this branch.
    fn sequence(&mut self, inside_alternation: bool) -> Result<Vec<Node>, PatternError> {
        let mut nodes = Vec::new();

        while let Some(current) = self.peek() {
            if inside_alternation
                && (current == GLOB_ALTERNATION_SEPARATOR || current == GLOB_ALTERNATION_CLOSE)
            {
                break;
            }

            match current {
                GLOB_ESCAPE => {
                    let Some(escaped) = self.at(1) else {
                        return self.fail(self.index, PatternProblem::TrailingEscape);
                    };
                    nodes.push(Node::Literal(escaped));
                    self.index += 2;
                }

                GLOB_ANY_SEQUENCE => {
                    // `**` is one node, not two: two `Star`s in a row would each
                    // stop at a separator and so could never cross one.
                    if self.at(1) == Some(GLOB_ANY_SEQUENCE) {
                        nodes.push(Node::Globstar);
                        self.index += 2;
                    } else {
                        nodes.push(Node::Star);
                        self.index += 1;
                    }
                }

                GLOB_ANY_CHAR => {
                    nodes.push(Node::AnyChar);
                    self.index += 1;
                }

                GLOB_CLASS_OPEN => nodes.push(self.class()?),

                GLOB_ALTERNATION_OPEN => nodes.push(self.alternation()?),

                // An unmatched `}` is a literal, exactly as an unmatched `]` is.
                other => {
                    nodes.push(Node::Literal(other));
                    self.index += 1;
                }
            }
        }

        Ok(nodes)
    }

    /// Parse `{a,b,c}`, positioned on the opening brace.
    fn alternation(&mut self) -> Result<Node, PatternError> {
        let open = self.index;
        if self.depth + 1 > GLOB_MAX_NESTING_DEPTH {
            return self.fail(
                open,
                PatternProblem::TooDeep {
                    limit: GLOB_MAX_NESTING_DEPTH,
                },
            );
        }

        self.index += 1;
        self.depth += 1;
        let mut branches = Vec::new();

        loop {
            branches.push(self.sequence(true)?);
            match self.peek() {
                Some(GLOB_ALTERNATION_SEPARATOR) => self.index += 1,
                Some(GLOB_ALTERNATION_CLOSE) => {
                    self.index += 1;
                    break;
                }
                // Only the end of the pattern can get here: `sequence` returns
                // on either of the two characters above and on nothing else.
                _ => return self.fail(open, PatternProblem::UnclosedAlternation),
            }
        }

        self.depth -= 1;
        Ok(Node::Alternation(branches))
    }

    /// Parse `[abc]`, positioned on the opening bracket.
    fn class(&mut self) -> Result<Node, PatternError> {
        let open = self.index;
        self.index += 1;

        let negated = self.peek().is_some_and(|c| GLOB_CLASS_NEGATE.contains(&c));
        if negated {
            self.index += 1;
        }

        let mut items = Vec::new();
        // A `]` in the first position is a literal — the POSIX trick that lets a
        // class contain one at all.
        let mut first = true;

        loop {
            let Some(current) = self.peek() else {
                return self.fail(open, PatternProblem::UnclosedClass);
            };

            if current == GLOB_CLASS_CLOSE && !first {
                self.index += 1;
                return Ok(Node::Class { negated, items });
            }
            first = false;

            let low = if current == GLOB_ESCAPE {
                let Some(escaped) = self.at(1) else {
                    return self.fail(self.index, PatternProblem::TrailingEscape);
                };
                self.index += 1;
                escaped
            } else {
                current
            };

            // A `-` opens a range only when something other than the closing
            // bracket follows it; a trailing `-` is an ordinary member.
            let opens_range = self.at(1) == Some(GLOB_CLASS_RANGE)
                && self.at(2).is_some_and(|c| c != GLOB_CLASS_CLOSE);

            if opens_range {
                let position = self.index;
                let Some(high) = self.at(2) else {
                    return self.fail(open, PatternProblem::UnclosedClass);
                };
                // `[z-a]` matches nothing. Accepting it would make a rule that
                // silently selects no files look like a rule that works.
                if high < low {
                    return self.fail(position, PatternProblem::ReversedRange { low, high });
                }
                items.push(ClassItem::Range(low, high));
                self.index += 3;
            } else {
                items.push(ClassItem::Char(low));
                self.index += 1;
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Program
// ─────────────────────────────────────────────────────────────────────────────

/// The test one instruction applies to one character.
#[derive(Clone, Debug, PartialEq, Eq)]
enum CharTest {
    Exact(char),
    /// `?` and the body of `*`: anything that is not a separator.
    WithinComponent,
    /// The body of `**`: anything at all.
    AcrossComponents,
    Class {
        negated: bool,
        items: Vec<ClassItem>,
    },
}

impl CharTest {
    fn admits(&self, candidate: char) -> bool {
        match self {
            Self::Exact(expected) => *expected == candidate,
            Self::WithinComponent => candidate != PATH_SEPARATOR,
            Self::AcrossComponents => true,
            // A class never matches a separator, negated or not: `[!a]` asking
            // for "any non-a" must not quietly cross a directory boundary the
            // way only `**` is allowed to.
            Self::Class { negated, items } => {
                candidate != PATH_SEPARATOR
                    && (items.iter().any(|item| item.contains(candidate)) != *negated)
            }
        }
    }
}

/// One step of the compiled matcher.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Inst {
    /// Consume one character if it passes the test, then continue at `pc + 1`.
    Consume(CharTest),
    /// Continue at both targets. The engine explores them in the same pass, so
    /// this is a fork rather than a choice to be backtracked over.
    Split(usize, usize),
    /// Continue at the target.
    Jump(usize),
    /// The whole pattern has been matched.
    Match,
}

/// The instruction list under construction.
///
/// Wraps the `Vec` only to make backpatching safe: [`Program::push`] hands back
/// the slot it filled and [`Program::patch`] is the only writer, so a target can
/// never be a made-up index.
#[derive(Debug, Default)]
struct Program {
    insts: Vec<Inst>,
}

impl Program {
    fn push(&mut self, inst: Inst) -> usize {
        self.insts.push(inst);
        self.insts.len().saturating_sub(1)
    }

    fn here(&self) -> usize {
        self.insts.len()
    }

    /// Overwrite a placeholder pushed earlier.
    ///
    /// `at` always comes from [`Program::push`], so the slot exists by
    /// construction; `get_mut` rather than indexing keeps the emitter free of a
    /// panic path that no argument could ever reach.
    fn patch(&mut self, at: usize, inst: Inst) {
        if let Some(slot) = self.insts.get_mut(at) {
            *slot = inst;
        }
    }
}

/// Emit the instructions for a run of nodes.
///
/// Recursion follows brace nesting only, which the parser has already capped at
/// [`GLOB_MAX_NESTING_DEPTH`].
fn emit(nodes: &[Node], program: &mut Program) {
    for node in nodes {
        match node {
            Node::Literal(c) => {
                program.push(Inst::Consume(CharTest::Exact(*c)));
            }
            Node::AnyChar => {
                program.push(Inst::Consume(CharTest::WithinComponent));
            }
            Node::Class { negated, items } => {
                program.push(Inst::Consume(CharTest::Class {
                    negated: *negated,
                    items: items.clone(),
                }));
            }
            Node::Star => emit_repeat(CharTest::WithinComponent, program),
            Node::Globstar => emit_repeat(CharTest::AcrossComponents, program),
            Node::Alternation(branches) => emit_alternation(branches, program),
        }
    }
}

/// Emit "zero or more characters passing `test`".
fn emit_repeat(test: CharTest, program: &mut Program) {
    let split = program.push(Inst::Jump(0));
    let body = program.push(Inst::Consume(test));
    program.push(Inst::Jump(split));
    let after = program.here();
    program.patch(split, Inst::Split(body, after));
}

/// Emit a chain of two-way splits, one per alternative.
///
/// Written as a loop rather than as recursion over the branch list so that the
/// only recursion in the emitter is the one that mirrors brace *nesting*, which
/// is bounded. A pattern may otherwise carry as many branches as it likes.
fn emit_alternation(branches: &[Vec<Node>], program: &mut Program) {
    // `{}` has no alternatives at all and matches the empty string, which is
    // what emitting nothing already means.
    let Some((last, leading)) = branches.split_last() else {
        return;
    };

    let mut escapes = Vec::with_capacity(leading.len());
    for branch in leading {
        let split = program.push(Inst::Jump(0));
        let start = program.here();
        emit(branch, program);
        escapes.push(program.push(Inst::Jump(0)));
        let next = program.here();
        program.patch(split, Inst::Split(start, next));
    }
    emit(last, program);

    let end = program.here();
    for escape in escapes {
        program.patch(escape, Inst::Jump(end));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Matcher
// ─────────────────────────────────────────────────────────────────────────────

/// A compiled glob pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Glob {
    program: Vec<Inst>,
}

impl Glob {
    /// Compile a pattern.
    ///
    /// # Errors
    /// A [`PatternError`] naming the pattern, the position and the problem. The
    /// pattern is never accepted-and-ignored: every shape this cannot match is
    /// reported here, at parse time, rather than turning into a rule that
    /// silently selects nothing.
    pub fn compile(pattern: &str) -> Result<Self, PatternError> {
        let mut parser = Parser::new(pattern)?;
        let nodes = parser.sequence(false)?;

        // Unreachable today: at the top level `sequence` stops only when the
        // pattern runs out, because `,` and `}` are literals outside a brace.
        // It is checked anyway so that a future parser change surfaces as a
        // refusal rather than as a pattern silently compiled from its prefix —
        // which would match files the operator never asked for.
        if parser.index < parser.chars.len() {
            return parser.fail(parser.index, PatternProblem::UnclosedAlternation);
        }

        let mut program = Program::default();
        emit(&nodes, &mut program);
        program.push(Inst::Match);

        if program.here() > GLOB_MAX_INSTRUCTIONS {
            return Err(PatternError {
                pattern: pattern.to_string(),
                position: 0,
                problem: PatternProblem::TooComplex {
                    limit: GLOB_MAX_INSTRUCTIONS,
                },
            });
        }

        Ok(Self {
            program: program.insts,
        })
    }

    /// Whether the pattern matches the whole of `text`.
    ///
    /// Runs every live alternative in one pass over `text`, so the cost is
    /// `text.chars().count() × self.program.len()` character tests at the very
    /// worst, with no input able to do better or worse by more than a constant.
    /// See the module documentation for why that guarantee, rather than a
    /// timeout, is the defence against a pathological pattern.
    pub fn matches(&self, text: &str) -> bool {
        let width = self.program.len();
        let mut live: Vec<usize> = Vec::with_capacity(width);
        let mut next: Vec<usize> = Vec::with_capacity(width);
        let mut seen_live = vec![false; width];
        let mut seen_next = vec![false; width];

        self.spawn(0, &mut live, &mut seen_live);

        for character in text.chars() {
            if live.is_empty() {
                return false;
            }

            next.clear();
            seen_next.iter_mut().for_each(|flag| *flag = false);

            for pc in &live {
                if matches!(self.program.get(*pc), Some(Inst::Consume(test)) if test.admits(character))
                {
                    self.spawn(pc + 1, &mut next, &mut seen_next);
                }
            }

            std::mem::swap(&mut live, &mut next);
            std::mem::swap(&mut seen_live, &mut seen_next);
        }

        live.iter()
            .any(|pc| matches!(self.program.get(*pc), Some(Inst::Match)))
    }

    /// Follow every epsilon step from `start`, collecting the instructions that
    /// actually consume a character (plus [`Inst::Match`]).
    ///
    /// `seen` makes each instruction join the set at most once, which both keeps
    /// the state set at most one instruction wide and makes a cyclic jump
    /// impossible to loop on.
    fn spawn(&self, start: usize, list: &mut Vec<usize>, seen: &mut [bool]) {
        let mut pending = vec![start];

        while let Some(pc) = pending.pop() {
            match seen.get_mut(pc) {
                Some(flag) if !*flag => *flag = true,
                // Already live, or past the end of the program.
                _ => continue,
            }

            match self.program.get(pc) {
                Some(Inst::Jump(target)) => pending.push(*target),
                Some(Inst::Split(first, second)) => {
                    pending.push(*second);
                    pending.push(*first);
                }
                Some(Inst::Consume(_) | Inst::Match) => list.push(pc),
                None => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn glob(pattern: &str) -> Glob {
        Glob::compile(pattern).unwrap_or_else(|e| panic!("{pattern} did not compile: {e}"))
    }

    fn matches(pattern: &str, text: &str) -> bool {
        glob(pattern).matches(text)
    }

    fn problem(pattern: &str) -> PatternProblem {
        Glob::compile(pattern)
            .expect_err("pattern should have been rejected")
            .problem()
    }

    #[test]
    fn a_literal_pattern_matches_only_itself() {
        assert!(matches("a.txt", "a.txt"));
        assert!(!matches("a.txt", "a.txtx"));
        assert!(!matches("a.txt", "xa.txt"));
        assert!(!matches("a.txt", "b.txt"));
    }

    #[test]
    fn a_single_star_stays_within_one_component() {
        // The rule the whole module exists for.
        assert!(matches("*.jpg", "photo.jpg"));
        assert!(matches("tmp/*", "tmp/a"));
        assert!(!matches("tmp/*", "tmp/a/b"));
        assert!(!matches("*.jpg", "2024/photo.jpg"));
        // A star also matches nothing at all.
        assert!(matches("a*b", "ab"));
    }

    #[test]
    fn a_double_star_crosses_separators() {
        assert!(matches("**/*.jpg", "a/b/photo.jpg"));
        assert!(matches("tmp/**", "tmp/a/b/c"));
        assert!(matches("**", "anything/at/all"));
        // `**` matches the empty run too, so a trailing one is not a
        // requirement that something follows.
        assert!(matches("tmp/**", "tmp/"));
        assert!(matches("**.jpg", "a/b/photo.jpg"));
    }

    #[test]
    fn the_star_and_globstar_distinction_survives_adjacency() {
        // `***` parses as `**` then `*`, and must still mean "everything".
        assert!(matches("***", "a/b/c"));
        // Two separate stars either side of a literal still each stop at `/`.
        assert!(!matches("*x*", "a/xb"));
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
        assert!(matches("[a-z0-9_].bin", "_.bin"));
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
    fn alternation_accepts_any_branch() {
        assert!(matches("*.{jpg,png,gif}", "a.jpg"));
        assert!(matches("*.{jpg,png,gif}", "a.png"));
        assert!(matches("*.{jpg,png,gif}", "a.gif"));
        assert!(!matches("*.{jpg,png,gif}", "a.txt"));
    }

    #[test]
    fn alternation_nests_and_may_hold_wildcards() {
        assert!(matches("{src,test}/**/*.{rs,toml}", "src/a/b.rs"));
        assert!(matches("{src,test}/**/*.{rs,toml}", "test/a/Cargo.toml"));
        assert!(!matches("{src,test}/**/*.{rs,toml}", "docs/a/b.rs"));
        assert!(matches("a{b,{c,d}}e", "ade"));
        assert!(!matches("a{b,{c,d}}e", "aee"));
    }

    #[test]
    fn an_empty_alternation_branch_matches_nothing_at_all() {
        // `{a,}` is the idiom for "optionally", and dropping the empty branch
        // would silently turn it into a requirement.
        assert!(matches("photo{s,}", "photos"));
        assert!(matches("photo{s,}", "photo"));
        assert!(matches("a{}b", "ab"));
    }

    #[test]
    fn a_single_branch_alternation_is_just_its_contents() {
        assert!(matches("a{b}c", "abc"));
        assert!(!matches("a{b}c", "ac"));
    }

    #[test]
    fn escaping_removes_a_metacharacter_s_meaning() {
        assert!(matches(r"a\*b", "a*b"));
        assert!(!matches(r"a\*b", "axxb"));
        assert!(matches(r"a\[b", "a[b"));
        assert!(matches(r"a\{b", "a{b"));
        assert!(matches(r"a\\b", r"a\b"));
        // And inside a class.
        assert!(matches(r"[\]].txt", "].txt"));
    }

    #[test]
    fn an_unmatched_close_is_an_ordinary_literal() {
        // Exactly what a shell does, and what lets a pattern name a file that
        // really is called this.
        assert!(matches("a}b", "a}b"));
        assert!(matches("a]b", "a]b"));
    }

    #[test]
    fn malformed_patterns_are_named_positioned_and_explained() {
        // Never a silent no-match: each of these is a usage error that quotes
        // the pattern back and points at the character.
        let error = Glob::compile("a[bc").expect_err("unclosed class");
        assert_eq!(error.problem(), PatternProblem::UnclosedClass);
        assert_eq!(error.position(), 2, "the '[' is the second character");
        assert_eq!(error.pattern(), "a[bc");
        assert!(error.to_string().contains("a[bc"));
        assert!(error.to_string().contains("position 2"));
        assert!(!error.hint().is_empty());

        let error = Glob::compile("x{a,b").expect_err("unclosed alternation");
        assert_eq!(error.problem(), PatternProblem::UnclosedAlternation);
        assert_eq!(error.position(), 2);

        let error = Glob::compile(r"done\").expect_err("trailing escape");
        assert_eq!(error.problem(), PatternProblem::TrailingEscape);
        assert_eq!(error.position(), 5);

        assert_eq!(problem(""), PatternProblem::Empty);
    }

    #[test]
    fn a_backwards_range_is_a_typo_not_a_selection() {
        // `[z-a]` can never match. Accepting it would produce a rule that
        // silently selects nothing, which is the one outcome a filter must
        // never produce quietly.
        let error = Glob::compile("[z-a].txt").expect_err("reversed range");
        assert_eq!(
            error.problem(),
            PatternProblem::ReversedRange {
                low: 'z',
                high: 'a'
            }
        );
        assert!(error.to_string().contains("backwards"));
        // The degenerate single-character range is still legal.
        assert!(matches("[a-a].txt", "a.txt"));
    }

    #[test]
    fn every_problem_explains_itself_in_words() {
        // These strings reach an operator verbatim. A generic one is a rule
        // that failed for a reason nobody can act on.
        for problem in [
            PatternProblem::Empty,
            PatternProblem::UnclosedClass,
            PatternProblem::UnclosedAlternation,
            PatternProblem::TrailingEscape,
            PatternProblem::ReversedRange {
                low: 'z',
                high: 'a',
            },
            PatternProblem::TooLong { limit: 8 },
            PatternProblem::TooDeep { limit: 8 },
            PatternProblem::TooComplex { limit: 8 },
        ] {
            let text = problem.to_string();
            assert!(text.len() > 15, "unhelpful reason: {text}");
        }
    }

    #[test]
    fn the_pattern_length_ceiling_is_a_refusal_not_a_truncation() {
        let longest = "a".repeat(GLOB_MAX_PATTERN_CHARS);
        assert!(Glob::compile(&longest).is_ok(), "the limit is inclusive");

        let over = "a".repeat(GLOB_MAX_PATTERN_CHARS + 1);
        assert_eq!(
            problem(&over),
            PatternProblem::TooLong {
                limit: GLOB_MAX_PATTERN_CHARS
            }
        );
    }

    #[test]
    fn the_nesting_ceiling_is_enforced() {
        let ok = format!(
            "{}a{}",
            GLOB_ALTERNATION_OPEN.to_string().repeat(GLOB_MAX_NESTING_DEPTH),
            GLOB_ALTERNATION_CLOSE
                .to_string()
                .repeat(GLOB_MAX_NESTING_DEPTH)
        );
        assert!(matches(&ok, "a"));

        let deep = format!(
            "{}a{}",
            GLOB_ALTERNATION_OPEN
                .to_string()
                .repeat(GLOB_MAX_NESTING_DEPTH + 1),
            GLOB_ALTERNATION_CLOSE
                .to_string()
                .repeat(GLOB_MAX_NESTING_DEPTH + 1)
        );
        assert_eq!(
            problem(&deep),
            PatternProblem::TooDeep {
                limit: GLOB_MAX_NESTING_DEPTH
            }
        );
    }

    #[test]
    fn the_emitted_program_stays_inside_its_ceiling() {
        // The instruction ceiling is the backstop behind the length ceiling, so
        // the worst pattern the length ceiling admits must still fit under it.
        // If an emitter change ever breaks that, this fails rather than the
        // ceiling quietly becoming the thing that rejects legal patterns.
        let worst = "{a,b}".repeat(GLOB_MAX_PATTERN_CHARS / 5);
        let compiled = Glob::compile(&worst).expect("the longest brace pattern must compile");
        assert!(
            compiled.program.len() <= GLOB_MAX_INSTRUCTIONS,
            "{} instructions from {} characters",
            compiled.program.len(),
            worst.chars().count()
        );
    }

    #[test]
    fn a_pattern_built_to_cause_catastrophic_backtracking_is_linear() {
        // The classic exponential case for a backtracking matcher. Here every
        // alternative advances in the same pass, so this returns immediately;
        // a backtracker would still be running when the heat death arrives.
        let pattern = "**a".repeat(20);
        let text = "a".repeat(2000);
        let compiled = glob(&pattern);

        let started = std::time::Instant::now();
        let outcome = compiled.matches(&text);
        let elapsed = started.elapsed();

        assert!(outcome, "the text really does match");
        // Generous by three orders of magnitude: the point is that the answer
        // does not depend on luck, not that the machine is fast.
        assert!(elapsed.as_secs() < 5, "took {elapsed:?}");
    }

    #[test]
    fn matching_is_case_sensitive_and_unicode_aware() {
        // Logical paths are NFC UTF-8 and the index keys their exact bytes, so a
        // case-folding matcher would claim files the vault does not hold.
        assert!(!matches("*.jpg", "PHOTO.JPG"));
        assert!(matches("caf\u{e9}/*", "caf\u{e9}/a"));
        // One `?` is one *character*, not one byte.
        assert!(matches("?.txt", "\u{e9}.txt"));
    }

    #[test]
    fn an_exhausted_state_set_stops_the_scan() {
        // A long path that diverges immediately must not be walked to the end.
        assert!(!matches("zzz*", &format!("a{}", "b".repeat(10_000))));
    }
}
