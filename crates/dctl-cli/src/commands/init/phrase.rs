//! Showing the recovery phrase, once.
//!
//! This is the single most important thing DCTL ever prints. Everything else the
//! tool writes can be produced again by running the command again; these
//! twenty-four words cannot, by design. They are generated inside `Vault::init`,
//! wrapped into the envelope's mnemonic slot, and then dropped — DCTL stores
//! them nowhere it can read, because a phrase the tool could reprint is a phrase
//! an attacker holding the envelope could reprint, and the envelope lives on
//! somebody else's disk.
//!
//! So the block below is built around one question: *will the person watching
//! this actually write it down?*
//!
//! ## stderr, never stdout
//!
//! stdout is the **result** stream ([the plan](https://doc.dctl.sh/project/plan) §7): `dctl init --json | jq -r
//! .vault_remote` is a supported pipeline, and so is `dctl init … | tee
//! provisioning.log`. A phrase on stdout therefore lands in a log file, a CI
//! artefact, or a provisioning transcript — and a phrase in a log file is a
//! compromised vault that **stays** compromised, because unlike a password it
//! cannot be rotated away. It goes to stderr, where it reaches the human at the
//! terminal and no pipeline.
//!
//! The consequence is deliberate: piping `dctl init` still shows the phrase on
//! the screen, and redirecting *stderr* to a file is the one way to capture it —
//! which is an explicit act, not an accident of using `tee`.
//!
//! ## `--json` prints it too, and never inside the JSON
//!
//! A machine-readable init must not carry the phrase in its document — see
//! [`crate::constants::INIT_FIELD_RECOVERY_PHRASE_ISSUED`], which reports only
//! *that* one was issued. But suppressing the block under `--json` would be
//! worse than either: the vault would have a second key nobody has ever seen,
//! which is the same as having no second key while believing otherwise. So the
//! words are written to stderr under every format.
//!
//! `--quiet` does not suppress it either, for the same reason [`Out::error`]
//! ignores `--quiet`: silence about something irreversible is not a courtesy.
//!
//! ## Why it looks the way it does
//!
//! * **Numbered words in a fixed grid.** Transcription is the failure mode —
//!   a dropped or transposed word produces a phrase that fails BIP-39's checksum
//!   months later, with nothing to compare against. Numbers let someone check
//!   their paper against the screen line by line, and make "I have 23 words"
//!   visible immediately.
//! * **ASCII rules.** The one message whose legibility must not depend on a
//!   terminal's encoding. Box-drawing glyphs render as mojibake often enough,
//!   and mojibake around a recovery phrase makes it look like a rendering bug
//!   rather than the thing to act on.
//! * **No colour.** The block is framed, not styled: it has to survive being
//!   `2>` redirected into a file and read back in a plain editor.

use zeroize::Zeroizing;

use crate::constants::{
    RECOVERY_PHRASE_COLUMNS, RECOVERY_PHRASE_RULE_CHAR, RECOVERY_PHRASE_RULE_WIDTH,
};
use crate::ctx::Ctx;

/// Headline of the block.
///
/// Names the action, not the object. "RECOVERY PHRASE" alone is a label somebody
/// scrolls past; an imperative with a deadline in it is an instruction.
const HEADING: &str = "RECOVERY PHRASE - WRITE THESE WORDS DOWN ON PAPER, NOW";

/// The sentence that stops somebody planning to come back to it later.
///
/// The single most important line in the block, because the natural reaction to
/// a wall of words is *"I will copy that out of the scrollback in a minute"*,
/// and the scrollback is not a plan. It says both halves of why that fails: it
/// is shown once, and nothing can reproduce it.
const ONLY_SHOWING: &str = "Shown once, here. DCTL stores it nowhere it can read, so nothing can \
     print it again - not this machine, not the provider, not a support request.";

/// What the phrase is *for*, in the words the reader already has.
const WHAT_IT_IS: &str = "It is the second, independent key to this vault: it opens the vault with \
     no password at all, which is what makes a forgotten password survivable.";

/// The security consequence, stated as plainly as the benefit.
///
/// Present because the previous line is an argument for keeping the phrase
/// somewhere convenient, and convenient is usually the same laptop the vault is
/// on. Someone who reads only one warning should read this one.
const WHO_CAN_USE_IT: &str = "Anyone holding these words can read every file in the vault. Keep the \
     paper where you would keep a passport - not in a file on this machine.";

/// The relationship between the phrase and the password.
///
/// Answers the question that decides whether the paper ever gets thrown away.
/// Someone who changes their password and assumes the old phrase died with it
/// will discard the backup; someone who assumes the opposite without being told
/// is guessing. Both are avoidable with one sentence.
const SURVIVES_A_PASSWORD_CHANGE: &str = "Changing the vault password does NOT change these words, and they will keep \
     working after every password change.";

/// Print the recovery phrase block on stderr.
///
/// Takes the phrase by reference and never returns, stores or logs it: the
/// caller owns the only copy, inside a `Zeroizing<String>` that wipes it.
pub fn show(ctx: &Ctx, vault_name: &str, phrase: &Zeroizing<String>) {
    for line in render(vault_name, phrase) {
        ctx.out.notice(&line);
    }
}

/// Build the block, line by line.
///
/// A pure function returning the exact lines stderr receives, so the wording,
/// the numbering and the "no phrase on stdout" rule are all assertable from a
/// unit test without running a process or capturing a stream.
#[must_use]
pub fn render(vault_name: &str, phrase: &str) -> Vec<String> {
    let rule: String =
        std::iter::repeat_n(RECOVERY_PHRASE_RULE_CHAR, RECOVERY_PHRASE_RULE_WIDTH).collect();
    let words: Vec<&str> = phrase.split_whitespace().collect();

    let mut lines = vec![
        String::new(),
        rule.clone(),
        format!("  {HEADING}"),
        format!("  Vault: {vault_name}    Words: {}", words.len()),
        rule.clone(),
        String::new(),
    ];

    // The widest BIP-39 word is eight characters; padding every column to that
    // keeps the grid rectangular, which is what makes a missing word visible.
    // Measured in `chars`, not bytes, because that is what the `{:<width$}`
    // formatter counts — the two agree for the English word list and would
    // silently disagree for any other, producing a grid that looks ragged in
    // exactly the block where raggedness reads as an error.
    let widest = words
        .iter()
        .map(|word| word.chars().count())
        .max()
        .unwrap_or(0);
    // Row-major: the numbers run left to right along each line, which is how a
    // phrase is read aloud and written down. A column-major grid is transcribed
    // wrongly by everyone who does not notice it is column-major, and the order
    // of the words *is* the phrase.
    for (row, chunk) in words.chunks(RECOVERY_PHRASE_COLUMNS).enumerate() {
        let mut line = String::from(" ");
        for (column, word) in chunk.iter().enumerate() {
            let number = row * RECOVERY_PHRASE_COLUMNS + column + 1;
            line.push_str(&format!("  {number:>2} {word:<widest$}"));
        }
        lines.push(line.trim_end().to_string());
    }

    lines.push(String::new());
    for paragraph in [
        ONLY_SHOWING,
        WHAT_IT_IS,
        WHO_CAN_USE_IT,
        SURVIVES_A_PASSWORD_CHANGE,
    ] {
        lines.extend(wrap(paragraph));
        lines.push(String::new());
    }
    lines.push(rule);
    lines.push(String::new());
    lines
}

/// Wrap a paragraph to the block's width, indented to match the word grid.
///
/// Wrapped here rather than left to the terminal because the block's frame is
/// the thing that makes it look unlike ordinary output, and a paragraph that
/// overflows the rules destroys the frame on exactly the narrow terminals where
/// this is hardest to read.
fn wrap(text: &str) -> Vec<String> {
    const INDENT: &str = "  ";
    let limit = RECOVERY_PHRASE_RULE_WIDTH - INDENT.len();

    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.len() + 1 + word.len() > limit {
            lines.push(format!("{INDENT}{current}"));
            current = String::new();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(format!("{INDENT}{current}"));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The BIP-39 specification's own 24-word test vector. Guards no data.
    const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank \
                          year wave sausage worth useful legal winner thank year wave sausage \
                          worth title";

    fn block() -> String {
        render("archive", PHRASE).join("\n")
    }

    #[test]
    fn every_word_appears_exactly_where_its_number_says() {
        // Transcription is the failure mode, so the numbering is the feature.
        // Asserted per word rather than by counting, because "24 numbers are
        // present" would also pass for a grid that had shuffled them.
        let rendered = block();
        for (index, word) in PHRASE.split_whitespace().enumerate() {
            let expected = format!("{:>2} {word}", index + 1);
            assert!(
                rendered.contains(&expected),
                "word {} is not numbered {}: \n{rendered}",
                index + 1,
                index + 1
            );
        }
    }

    #[test]
    fn the_words_are_in_reading_order_across_the_row() {
        // A column-major grid is transcribed wrongly by everyone who does not
        // notice it is column-major, and BIP-39 order is the whole phrase.
        let rendered = block();
        let first_row = rendered
            .lines()
            .find(|line| line.contains(" 1 legal"))
            .expect("a grid row");
        for word in ["legal", "winner", "thank", "year"] {
            assert!(first_row.contains(word), "row was: {first_row}");
        }
        assert!(
            !first_row.contains("wave"),
            "the fifth word belongs on the second row: {first_row}"
        );
    }

    #[test]
    fn the_grid_holds_every_word_and_no_others() {
        let rendered = block();
        let count = PHRASE
            .split_whitespace()
            .filter(|word| rendered.contains(*word))
            .count();
        assert_eq!(count, PHRASE.split_whitespace().count());
    }

    #[test]
    fn the_block_says_it_will_never_be_shown_again() {
        // The line that decides whether the phrase is written down now or
        // "later, from the scrollback".
        let rendered = block().to_lowercase();
        assert!(rendered.contains("shown once"), "{rendered}");
        assert!(rendered.contains("print it again"), "{rendered}");
    }

    #[test]
    fn the_block_says_a_password_change_keeps_it_working() {
        // Without this someone rotates their password, assumes the paper is
        // stale, and throws away the only other key to their data.
        assert!(block().contains("does NOT change these words"));
    }

    #[test]
    fn the_block_says_who_can_use_it() {
        let rendered = block();
        assert!(rendered.contains("read every file"), "{rendered}");
    }

    #[test]
    fn the_block_names_the_vault_and_the_word_count() {
        // Someone provisioning several vaults in one session has several of
        // these on screen, and a phrase filed against the wrong vault is a lost
        // vault. The count is the fastest check against a truncated paste.
        let rendered = block();
        assert!(rendered.contains("Vault: archive"), "{rendered}");
        assert!(rendered.contains("Words: 24"), "{rendered}");
    }

    #[test]
    fn nothing_in_the_block_is_wider_than_the_rule() {
        // The frame is what makes this look unlike ordinary output. A paragraph
        // that overflows it wraps at the terminal margin and the frame is gone
        // — on exactly the narrow terminals where the block is hardest to read.
        for line in render("archive", PHRASE) {
            assert!(
                line.chars().count() <= RECOVERY_PHRASE_RULE_WIDTH,
                "{} chars: {line}",
                line.chars().count()
            );
        }
    }

    #[test]
    fn a_long_vault_name_does_not_break_the_frame() {
        let name = "a".repeat(RECOVERY_PHRASE_RULE_WIDTH * 2);
        let rendered = render(&name, PHRASE);
        assert!(
            rendered.iter().any(|line| line.contains(&name)),
            "the vault must still be named"
        );
        // Only the name line may exceed the rule, and it does so because
        // truncating the name would be worse: the reader has to be able to tell
        // which vault these words open.
        let over: Vec<&String> = rendered
            .iter()
            .filter(|line| line.chars().count() > RECOVERY_PHRASE_RULE_WIDTH)
            .collect();
        assert_eq!(over.len(), 1, "{over:?}");
        assert!(over[0].contains("Vault:"));
    }

    #[test]
    fn the_rules_are_ascii_only() {
        // Mojibake around a recovery phrase reads as a rendering bug rather than
        // as the thing to act on.
        assert!(block().is_ascii(), "the block must survive any encoding");
    }
}
