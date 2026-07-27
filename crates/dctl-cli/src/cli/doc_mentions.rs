//! Every `dctl …` the *documentation* writes down must name a command that
//! exists.
//!
//! [`super::mentions`] does this for the crate's own source, and the reason it
//! exists applies at least as strongly here. A hint printed by the binary is
//! read by one user at one moment; a page in `docs/` is read by everybody, is
//! what a new user is pointed at first, and is the artefact most likely to be
//! copied into a runbook and run months later without being re-read.
//!
//! The sweep that added this module found four live instances, and their shape
//! is worth recording because it is not the shape the source scanner catches:
//!
//! * `docs/EXIT_CODES.md` named `dctl help exitcodes` and `dctl vault recover`.
//!   Both were *corrections* — prose explaining that an earlier revision had
//!   promised a command that did not exist. The explanation reintroduced the
//!   string, and one of the two (`vault recover`) has since become real, which
//!   is precisely why an exemption list has to be re-checked rather than
//!   accumulated.
//! * `docs/GUIDE.md` named `dctl share …` in a capability table.
//! * `docs/PLAIN_STORAGE_PLAN.md` and `docs/PROJECT_STATUS.md` name
//!   `dctl serve`, a command scheduled by the plan they are part of.
//!
//! ## Why this is not the same scan pointed at a different directory
//!
//! Source carries mentions in one form: a delimited span inside a doc comment or
//! a string literal. Markdown carries them in two, and the second is the one
//! that matters — a fenced block of shell:
//!
//! ```text
//! $ dctl copy ./src vault:photos
//! ```
//!
//! Nothing there is delimited, so [`super::mentions::mentions_on`] sees none of
//! it. A scan that read only backticks would pass over every worked example in
//! the documentation while reporting that it had checked the documentation,
//! which is the failure this whole family of checks exists to prevent.
//!
//! ## Illustrations are not instructions
//!
//! Documentation legitimately writes command lines that no parser could accept,
//! because it is describing a *grammar* rather than issuing an instruction:
//! `dctl [GLOBAL OPTIONS] <COMMAND> [ARGS]`, `dctl config <subcommand> [args]`,
//! `dctl <command> --help`. Putting each of those in an exemption list would
//! bury the real findings and would make the list itself unreadable.
//!
//! [`command_line_of`] handles them structurally instead: a metavariable —
//! anything in `<>` or `[]` — ends the command line, because everything after it
//! is a description of a shape rather than a word somebody typed. `dctl config
//! <subcommand>` therefore asks the parser about `dctl config`, which is exactly
//! the claim the prose is making, and `dctl <command> --help` asks about nothing
//! at all. The same truncation is what keeps a shell pipeline (`| head -5`) from
//! being read as arguments.
//!
//! A fenced block also holds *output*, not only commands. `dctl 0.0.1` is what
//! `dctl --version` prints, and it opens with the binary's own name. It is
//! rejected by requiring the candidate verb to be verb-shaped — lowercase ASCII,
//! starting with a letter — so a version number, a path or a table row can never
//! be mistaken for a promise.

use std::path::{Path, PathBuf};

/// Mentions in `docs/` that deliberately name something the command tree does
/// not hold.
///
/// Kept separate from [`super::mentions::EXEMPT`] because the two corpora fail
/// differently. Source exemptions are almost always a rejected design; doc
/// exemptions are almost always a *roadmap* — a command the plan schedules and
/// the build has not reached. Merging them would let a planning document's
/// vocabulary quietly excuse a hint printed by the binary.
///
/// Each entry carries the reason it is not an instruction, and
/// [`tests::no_doc_exemption_outlives_the_reason_for_it`] deletes it for you the
/// moment it becomes a real command.
const DOC_EXEMPT: &[(&str, &str)] = &[
    (
        "dctl help exitcodes",
        "Named by `docs/EXIT_CODES.md` in the sentence that exists to say it is \
         not a subcommand — `dctl --help` used to point every reader at it. The \
         string has to appear for the correction to be legible.",
    ),
    (
        "dctl cop",
        "Named by `docs/commands/dctl.md` as the worked example of an \
         *ambiguous* abbreviation: `cop` prefixes both `copy` and `copyto`, so \
         it names neither. The page previously offered it as an abbreviation \
         that works, and the transcript of its failure is the correction.",
    ),
    (
        "dctl share",
        "Named by `docs/GUIDE.md`'s capability table in the row that marks it \
         **not present in this build**. Sharing exists at the library level in \
         `dctl-core`/`dctl-crypto` and has no CLI verb.",
    ),
    (
        "dctl serve",
        "Scheduled by `docs/PLAIN_STORAGE_PLAN.md` (§E.3, M10) and tracked as \
         not-started in `docs/PROJECT_STATUS.md`. A roadmap naming its own \
         future verb is the one place that is not a broken instruction.",
    ),
];

/// Stand-ins for "some command", which name no verb and assert nothing.
const ELISION: &[&str] = &["…", "..."];

/// Whether `word` could be a subcommand name at all.
///
/// Command names are lowercase ASCII words. Requiring the shape before asking
/// the parser is what lets a fenced block hold program *output* — `dctl 0.0.1`,
/// a version line that opens with the binary's name — without every such line
/// being reported as a command that does not exist.
fn is_verb_shaped(word: &str) -> bool {
    !word.is_empty()
        && word.starts_with(|c: char| c.is_ascii_lowercase())
        && word
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Where a written command line stops being a command line.
///
/// A metavariable (`<COMMAND>`, `[flags]`) is documentation describing a shape;
/// a shell metacharacter hands the rest of the line to another program; and an
/// elision is the author saying "and whatever else you need". All three end the
/// argv that this mention is claiming exists.
///
/// The elision has to be a *terminator* rather than only a first-word check.
/// `dctl share …` names a verb and then trails off, so a scan that stopped
/// looking after the verb would hand the parser `share …` and report the
/// ellipsis as part of the claim — which is how this rule was written the first
/// time, and what the exemption for `dctl share` failed to match until it was
/// fixed.
fn ends_the_command_line(word: &str) -> bool {
    word.starts_with('<')
        || word.starts_with('[')
        || ELISION.contains(&word)
        || matches!(
            word,
            "|" | ">" | ">>" | "<" | "&&" | "||" | ";" | "2>" | "#"
        )
}

/// The argv a mention actually claims, or `None` if it claims no verb.
///
/// Returns the words from `dctl` up to the first metavariable or shell
/// metacharacter. `None` means there is nothing for a parser to confirm: the
/// mention named only flags, only a metavariable, or something that is not
/// verb-shaped.
pub(crate) fn command_line_of(mention: &str) -> Option<Vec<String>> {
    let mut words = mention.split_whitespace();
    if words.next() != Some("dctl") {
        return None;
    }

    let mut argv = vec!["dctl".to_string()];
    let mut named_a_verb = false;
    for word in words {
        if ends_the_command_line(word) {
            break;
        }
        if word.starts_with('-') {
            argv.push(word.to_string());
            continue;
        }
        // The first non-flag word is the claim. If it is not verb-shaped the
        // mention is output or prose, not an instruction.
        if !named_a_verb {
            if !is_verb_shaped(word) {
                return None;
            }
            named_a_verb = true;
        }
        argv.push(word.to_string());
    }

    named_a_verb.then_some(argv)
}

/// Every `dctl …` a markdown line claims, from both of the forms docs use.
///
/// A delimited span is read by [`super::mentions::mentions_on`]; a shell line
/// inside a fenced block is read here. `in_fence` is threaded by the caller
/// because a fence is a property of the file, not of the line.
fn doc_mentions_on(line: &str, in_fence: bool) -> Vec<String> {
    if in_fence {
        // A transcript prompt is not part of the command.
        let bare = line.trim().strip_prefix("$ ").unwrap_or(line.trim());
        if bare == "dctl" || bare.starts_with("dctl ") {
            return vec![bare.to_string()];
        }
        return Vec::new();
    }
    super::mentions::mentions_on(line)
}

/// Every `.md` file under `root`, recursively.
fn markdown_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files.extend(markdown_files(&path));
        } else if path.extension().is_some_and(|ext| ext == "md") {
            files.push(path);
        }
    }
    files
}

/// The repository's `docs/` directory, relative to this crate.
fn docs_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs")
}

/// Every mention in `docs/`, paired with where it was written.
fn every_doc_mention() -> Vec<(String, String)> {
    let root = docs_root();
    let mut found = Vec::new();
    for file in markdown_files(&root) {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let shown = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .display()
            .to_string()
            .replace('\\', "/");
        let mut in_fence = false;
        for (number, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("```") {
                in_fence = !in_fence;
                continue;
            }
            for mention in doc_mentions_on(line, in_fence) {
                found.push((mention, format!("docs/{shown}:{}", number + 1)));
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::{DOC_EXEMPT, command_line_of, every_doc_mention};
    use crate::cli::mentions::names_a_real_command_argv;

    /// How many mentions `docs/` is known to carry, rounded down.
    ///
    /// A floor, for the reason [`crate::cli::mentions`] gives: a scan that
    /// quietly stopped matching would pass every other assertion here while
    /// checking an empty corpus. Set at roughly two thirds of the 744 found when
    /// this was written, so deleting a page does not fail the build but losing
    /// the fenced-block reader does.
    const KNOWN_DOC_MENTIONS: usize = 490;

    /// How many documentation files are known to carry one.
    ///
    /// Checked separately because a walk that stopped descending into
    /// `docs/commands/` would still clear the count above on the strength of the
    /// top-level pages alone.
    const KNOWN_DOC_FILES: usize = 32;

    #[test]
    fn every_command_the_docs_name_is_a_command_that_exists() {
        let mut broken = Vec::new();
        for (mention, at) in every_doc_mention() {
            let Some(argv) = command_line_of(&mention) else {
                continue;
            };
            if DOC_EXEMPT
                .iter()
                .any(|(exempt, _)| *exempt == argv.join(" "))
            {
                continue;
            }
            if !names_a_real_command_argv(&argv) {
                broken.push(format!("  {at}: `{mention}`"));
            }
        }

        assert!(
            broken.is_empty(),
            "these documentation lines name a subcommand that does not exist. A \
             page is copied into a runbook and run months later without being \
             re-read, so a wrong command line here outlives the person who \
             wrote it. Implement the command, or name one that is real. If the \
             mention is prose *about* a command rather than an instruction, add \
             it to `DOC_EXEMPT` with the reason:\n{}",
            broken.join("\n")
        );
    }

    #[test]
    fn the_doc_scan_actually_reaches_the_corpus_it_claims_to() {
        let mentions = every_doc_mention();
        assert!(
            mentions.len() >= KNOWN_DOC_MENTIONS,
            "the documentation scan found only {} mentions, below the known \
             floor of {KNOWN_DOC_MENTIONS}. A scan that matches nothing passes \
             every other test in this file while checking nothing at all.",
            mentions.len()
        );

        let mut files: Vec<&str> = mentions
            .iter()
            .filter_map(|(_, at)| at.rsplit_once(':').map(|(file, _)| file))
            .collect();
        files.sort_unstable();
        files.dedup();
        assert!(
            files.len() >= KNOWN_DOC_FILES,
            "the documentation scan reached only {} files, below the known \
             floor of {KNOWN_DOC_FILES}. The walk has stopped descending into \
             docs/commands/.",
            files.len()
        );

        // The fenced-block reader is the half that `mentions_on` cannot do, and
        // the half every worked example lives in. If it stops working the scan
        // still finds hundreds of backticked mentions and looks healthy.
        assert!(
            mentions
                .iter()
                .any(|(mention, at)| mention.starts_with("dctl ")
                    && at.starts_with("docs/commands/")
                    && !mention.contains('`')),
            "the scan must read `$ dctl …` lines inside fenced code blocks, not \
             only backticked spans"
        );
    }

    #[test]
    fn no_doc_exemption_outlives_the_reason_for_it() {
        for (mention, reason) in DOC_EXEMPT {
            let argv = command_line_of(mention)
                .unwrap_or_else(|| panic!("`{mention}` is exempted but names no verb to check"));
            assert!(
                !names_a_real_command_argv(&argv),
                "`{mention}` is exempted as not-a-command, but the command tree \
                 now holds it. Delete the exemption and check the page that \
                 carries it — prose explaining that a command does not exist is \
                 worse than useless once it does. Recorded reason: {reason}"
            );
            assert!(
                !reason.trim().is_empty(),
                "`{mention}` is exempted without a reason"
            );
        }
    }

    #[test]
    fn illustrations_and_output_are_not_read_as_instructions() {
        // A grammar, not an instruction: everything from the metavariable on is
        // a description of a shape.
        assert!(command_line_of("dctl [GLOBAL OPTIONS] <COMMAND> [ARGS]").is_none());
        assert!(command_line_of("dctl <command> --help").is_none());
        assert_eq!(
            command_line_of("dctl config <subcommand> [args] [flags]"),
            Some(vec!["dctl".to_string(), "config".to_string()])
        );

        // Program output that happens to open with the binary's own name.
        assert!(command_line_of("dctl 0.0.1").is_none());

        // Prose about the family as a whole.
        assert!(command_line_of("dctl …").is_none());
        assert!(command_line_of("dctl -v …").is_none());

        // A pipeline: the claim is about `dctl ls`, not about `head`.
        assert_eq!(
            command_line_of("dctl ls vault: | head -5"),
            Some(vec![
                "dctl".to_string(),
                "ls".to_string(),
                "vault:".to_string()
            ])
        );

        // ...and a real instruction still reaches the parser intact.
        assert_eq!(
            command_line_of("dctl index rebuild vault:"),
            Some(vec![
                "dctl".to_string(),
                "index".to_string(),
                "rebuild".to_string(),
                "vault:".to_string()
            ])
        );
    }

    #[test]
    fn a_documented_command_that_does_not_exist_is_actually_detected() {
        // The check's own smoke test. Every assertion above is worthless if the
        // parser answers "fine" to everything.
        let bad = command_line_of("dctl serve http").expect("names a verb");
        assert!(!names_a_real_command_argv(&bad));

        let good = command_line_of("dctl vault recover archive:").expect("names a verb");
        assert!(names_a_real_command_argv(&good));
    }
}
