//! Every `dctl …` this crate writes down must name a command that exists.
//!
//! This module is a test and nothing else. It earns its place because the
//! failure it detects has now happened four times in this codebase, each time
//! in the same shape: a message tells the user to run something, and the thing
//! does not exist.
//!
//! * A refusal named `archive:` before that spelling was addressable.
//! * A hint named `dctl index rebuild` before the verb existed — recorded in
//!   [`crate::commands::index`], which was written to close it.
//! * [`crate::error`]'s unlock hint named `dctl vault recover` alongside a
//!   "BIP39 phrase", when neither the command nor the phrase existed in any
//!   build. Both exist now — [`crate::commands::vault`] holds the verb and
//!   `dctl init` issues the phrase — so the hint names them again, truthfully
//!   this time. That this scan would have caught the original *and* passes the
//!   replacement is the whole design: it checks the claim against the command
//!   tree, not against a list of forbidden words.
//! * `dctl --help` itself told every reader to run `dctl help exitcodes`.
//!
//! A wrong hint is worse than no hint. It is read at the moment the user is
//! least able to evaluate it — the unlock hint is read by somebody who believes
//! their vault may be lost — and it spends the one instruction they will follow
//! on a command that answers `error: unrecognized subcommand`. That converts a
//! recoverable situation into a belief that the tool is broken.
//!
//! ## Why this is checked mechanically rather than by review
//!
//! Every one of the four got through review. They read perfectly: the prose is
//! plausible, the verb is plausible, and nothing about the surrounding code
//! looks wrong. The only reliable reader is the argument parser, so the parser
//! is what this asks — [`Cli`] itself, not a hand-maintained list of verb names
//! that would drift from the command tree exactly the way the hints drifted
//! from the commands.
//!
//! ## What counts as a mention
//!
//! A delimited span — backticks in a doc comment, single quotes in help text —
//! whose first word is `dctl`. Both delimiters are read because the two
//! historical instances used different ones: the unlock hint is in backticks,
//! and `dctl --help`'s exit-code pointer was in single quotes inside
//! [`super::LONG_ABOUT`]. Checking only the delimiter that happened to be in
//! front of you is how a scan of the same class misses half of it.
//!
//! Spans are found line by line, so a mention wrapped across two lines is not
//! seen. That is a real limit rather than a hidden one, which is why
//! [`tests::the_scan_actually_reaches_the_corpus_it_claims_to`] pins a floor on
//! how much this finds: a scanner that quietly matched nothing would let every
//! future instance through while reporting success, which is the exact shape of
//! the bug this module exists to prevent.
//!
//! ## The exemption list is the point, not a loophole
//!
//! Prose legitimately names commands that do not exist — a design alternative
//! that was rejected, a verb that is planned. [`EXEMPT`] holds those, each with
//! the reason it is not an instruction. It is deliberately a chore: adding to it
//! is a visible, reviewable decision that a reader has to justify, which is a far
//! higher bar than typing a plausible verb into a hint. Stale entries are
//! rejected too — [`tests::no_exemption_outlives_the_reason_for_it`] fails if a
//! listed mention has since become a real command, so the list cannot rot into a
//! blanket allow.

use std::path::{Path, PathBuf};

use clap::Parser;
use clap::error::ErrorKind;

use super::Cli;

/// Mentions that deliberately name something the command tree does not hold.
///
/// Each entry is a mention that is *about* a command rather than an instruction
/// to run one. The reason is carried beside it so that a later reader can tell
/// a considered exception from an accumulated one.
const EXEMPT: &[(&str, &str)] = &[
    (
        "dctl rebuild-index",
        "Names the flat spelling `dctl index rebuild` was deliberately not \
         given, in the module that explains the choice. Making it real would \
         create the second spelling the prose exists to reject.",
    ),
    (
        "dctl index verify",
        "Named as a future verb, and marked as one in the sentence that uses \
         it. `PLAN.md` §13.5 lists it; this build ships `rebuild` only.",
    ),
];

/// Stand-ins for "some command", which name no verb and assert nothing.
///
/// `dctl … | ffplay -` is prose about the shape of a pipeline, not an
/// instruction, and there is no subcommand for a parser to confirm.
const ELISION: &[&str] = &["…", "..."];

/// The scanner modules' own paths, which are excluded from the scan.
///
/// They have to be. The documentation in each names every command that has ever
/// been wrongly promised — that list *is* the explanation — so a scanner that
/// read it would report each of them forever. [`super::doc_mentions`] is on the
/// list for the same reason and earned its place the same way: it was written,
/// and this test immediately reported eleven findings in its prose, every one of
/// them a string the module exists to talk about.
///
/// Excluding these two files is sound because neither contains an instruction to
/// a user: both are `#[cfg(test)]` and nothing in either is printed by the
/// binary. That is the whole of the justification, and it is why the list must
/// not grow to a file that ships. Exempting those mentions *globally* instead
/// would be the dangerous fix, since it would also excuse the next
/// plausible-looking verb somebody puts into a hint.
const SCANNER_PATHS: &[&str] = &["cli/mentions.rs", "cli/doc_mentions.rs"];

/// Whether `mention` parses as far as naming a real command.
///
/// Only [`ErrorKind::InvalidSubcommand`] counts as a failure. Everything else a
/// parse can report — a missing positional, an unknown flag, a shell pipe that
/// followed the command in the same span — means the *verb* was found, which is
/// the only claim a mention makes. Demanding a fully valid command line would
/// force every example in the documentation to be a runnable one, and the
/// examples are illustrations: `dctl copy SOURCE DEST` should stay legible.
fn names_a_real_command(mention: &str) -> bool {
    names_a_real_command_argv(&mention.split_whitespace().collect::<Vec<_>>())
}

/// The same question asked of an already-split command line.
///
/// [`super::doc_mentions`] has to strip metavariables and shell pipelines before
/// it can ask, so it arrives holding words rather than a string. Splitting them
/// back into one and re-splitting would be a round trip that could only lose
/// information — a documented path containing a space would become two
/// arguments — so the parser is reached directly.
pub(super) fn names_a_real_command_argv<S: AsRef<str>>(argv: &[S]) -> bool {
    match Cli::try_parse_from(argv.iter().map(AsRef::as_ref)) {
        Ok(_) => true,
        Err(error) => error.kind() != ErrorKind::InvalidSubcommand,
    }
}

/// Every delimited `dctl …` span on one line, with its delimiters removed.
///
/// Returns the mention text starting at `dctl`. A span whose first word is not
/// exactly `dctl` is not a mention: `dctl_core::Vault` and `dctl-store` are Rust
/// paths and crate names, and treating them as command lines would bury the
/// real findings in noise.
pub(super) fn mentions_on(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    for delimiter in ['`', '\''] {
        let mut rest = line;
        // Take spans pairwise. An unpaired trailing delimiter closes nothing
        // and is dropped, which is what keeps an apostrophe in prose from
        // swallowing the remainder of the line.
        while let Some((_, after_open)) = rest.split_once(delimiter) {
            let Some((span, after_close)) = after_open.split_once(delimiter) else {
                break;
            };
            rest = after_close;

            let span = span.trim();
            let mut words = span.split_whitespace();
            if words.next() != Some("dctl") {
                continue;
            }
            // A bare `dctl` names the binary, and `dctl …` stands in for "some
            // command" in prose about the family as a whole. Neither claims a
            // verb, so neither has anything to check.
            let Some(verb) = words.next() else {
                continue;
            };
            if ELISION.contains(&verb) {
                continue;
            }
            found.push(span.to_string());
        }
    }
    found
}

/// Every `.rs` file under `root`, recursively.
fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files.extend(rust_files(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    files
}

/// Every mention in the crate's source, paired with where it was written.
///
/// Reads the source from `CARGO_MANIFEST_DIR` rather than from a macro over the
/// current file, because the point is to cover files nobody remembered to add
/// to a list — which is every file that has carried one of these so far.
fn every_mention() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    for file in rust_files(&root) {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let shown = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .display()
            .to_string()
            .replace('\\', "/");
        if SCANNER_PATHS.contains(&shown.as_str()) {
            continue;
        }
        for (number, line) in text.lines().enumerate() {
            for mention in mentions_on(line) {
                found.push((mention, format!("src/{shown}:{}", number + 1)));
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::{EXEMPT, every_mention, mentions_on, names_a_real_command};

    /// How many mentions the crate is known to carry, rounded down.
    ///
    /// A floor rather than an exact count so ordinary edits do not fail the
    /// suite, and a floor rather than nothing so that a scanner which stopped
    /// matching — a delimiter changed, a path moved — fails loudly instead of
    /// passing over an empty corpus. The suite that stayed green through a live
    /// plaintext write did so because its list stopped one entry short; a scan
    /// with no floor is the same failure with no entries at all.
    ///
    /// Set at roughly two thirds of the 647 found when this was written. Wide
    /// enough that removing a documentation paragraph does not fail the build,
    /// tight enough that losing a third of the corpus does — a floor with so
    /// much slack that a half-broken scan still clears it is not a floor.
    const KNOWN_MENTIONS: usize = 430;

    /// How many distinct files are known to carry one.
    ///
    /// Checked separately because the two ways this scan can quietly shrink are
    /// different failures. A drop in mentions means the matcher stopped
    /// matching; a drop in *files* means the walk stopped descending, which one
    /// large well-documented module could hide from the count above entirely.
    const KNOWN_FILES: usize = 110;

    #[test]
    fn every_command_this_crate_names_is_a_command_that_exists() {
        let mut broken = Vec::new();
        for (mention, at) in every_mention() {
            if EXEMPT.iter().any(|(exempt, _)| *exempt == mention) {
                continue;
            }
            if !names_a_real_command(&mention) {
                broken.push(format!("  {at}: `{mention}`"));
            }
        }

        assert!(
            broken.is_empty(),
            "these name a subcommand that does not exist. A hint the user \
             cannot follow is worse than no hint — implement the command, or \
             name one that is real. If the mention is prose *about* a command \
             rather than an instruction, add it to `EXEMPT` with the reason:\n{}",
            broken.join("\n")
        );
    }

    #[test]
    fn the_scan_actually_reaches_the_corpus_it_claims_to() {
        let mentions = every_mention();
        assert!(
            mentions.len() >= KNOWN_MENTIONS,
            "the scan found only {} mentions, below the known floor of \
             {KNOWN_MENTIONS}. A scan that matches nothing passes every other \
             test in this file while checking nothing at all.",
            mentions.len()
        );

        // The walk has to descend. Counting distinct files catches a recursion
        // that stopped at the crate root, which the mention count alone could
        // miss if one heavily documented module happened to survive.
        let mut files: Vec<&str> = mentions
            .iter()
            .filter_map(|(_, at)| at.rsplit_once(':').map(|(file, _)| file))
            .collect();
        files.sort_unstable();
        files.dedup();
        assert!(
            files.len() >= KNOWN_FILES,
            "the scan reached only {} files, below the known floor of \
             {KNOWN_FILES}. The walk has stopped descending into subdirectories.",
            files.len()
        );

        // A nested verb must be reachable, because the second historical
        // instance of this defect was a nested one (`dctl index rebuild`).
        assert!(
            mentions
                .iter()
                .any(|(mention, _)| mention.starts_with("dctl index rebuild")),
            "the scan must see nested subcommands, not just top-level verbs"
        );
    }

    #[test]
    fn no_exemption_outlives_the_reason_for_it() {
        for (mention, reason) in EXEMPT {
            assert!(
                !names_a_real_command(mention),
                "`{mention}` is exempted as not-a-command, but the command tree \
                 now holds it. Delete the exemption: a list that keeps entries \
                 after they stop being true becomes a blanket allow, which is \
                 how the check it guards stops checking. Recorded reason: \
                 {reason}"
            );
            assert!(
                !reason.trim().is_empty(),
                "`{mention}` is exempted without a reason"
            );
        }
    }

    #[test]
    fn a_command_that_does_not_exist_is_actually_detected() {
        // The check's own smoke test. Every assertion above is worthless if
        // `names_a_real_command` answers "fine" to everything — which is
        // exactly what a mis-set `ErrorKind` comparison would do.
        // All of these were live in this crate's hints and help text until this
        // check read them back. Two are nested, which is the shape a
        // top-level-verb-only check would have missed entirely.
        assert!(!names_a_real_command("dctl help exitcodes"));
        assert!(!names_a_real_command("dctl index verify"));
        assert!(!names_a_real_command("dctl config set b2prod bucket=films"));
        // A near-miss of a verb that now exists: `dctl vault recover` was the
        // most damaging of the historical instances, and the failure mode that
        // replaces it is a hint naming a plausible *sibling* of a real verb.
        assert!(!names_a_real_command("dctl vault restore"));

        // ...and equally worthless if it answers "broken" to everything.
        assert!(names_a_real_command("dctl index rebuild"));
        // The verb that closed the worst of the four. It is real now, and the
        // unlock hint names it again — this is the assertion that would fail if
        // it were ever removed while that hint still pointed at it.
        assert!(names_a_real_command("dctl vault recover archive:"));
        assert!(names_a_real_command("dctl scrub archive:"));
        assert!(names_a_real_command("dctl --json size archive:"));
        // An illustration with placeholders still names a real verb.
        assert!(names_a_real_command("dctl copy SOURCE DEST"));
        // As does one trailed by a shell pipeline inside the same span.
        assert!(names_a_real_command("dctl ls vault: | head -5"));
    }

    #[test]
    fn both_delimiters_are_read_and_rust_paths_are_not_mistaken_for_commands() {
        assert_eq!(
            mentions_on("/// Try `dctl index rebuild` first."),
            vec!["dctl index rebuild".to_string()]
        );
        assert_eq!(
            mentions_on("Run 'dctl scrub archive:' nightly."),
            vec!["dctl scrub archive:".to_string()]
        );
        // A crate path, a bare binary name and an unpaired delimiter are all
        // silence rather than findings.
        assert!(mentions_on("`dctl_core::Vault` and `dctl-store`").is_empty());
        assert!(mentions_on("the `dctl` binary").is_empty());
        assert!(mentions_on("a lone ` backtick and dctl ls").is_empty());
    }
}
