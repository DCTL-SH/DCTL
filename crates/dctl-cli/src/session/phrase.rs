//! Acquiring the BIP-39 recovery phrase.
//!
//! Sibling of [`crate::session::password`], and deliberately not a branch inside
//! it: the two secrets are read differently, and the differences all come from
//! one fact — a phrase is copied off a sheet of paper by somebody who has
//! already had a bad day.
//!
//! * **The whole file is read, not its first line.** Twenty-four words get
//!   written across several lines on paper and typed back the same way. A
//!   first-line rule would reject a correct phrase, and the person reading that
//!   refusal has no way to tell it from "your phrase is wrong". BIP-39 splits on
//!   whitespace and derives its seed from the *word indices*, so line breaks,
//!   double spaces and a trailing newline all produce the identical key — the
//!   property is proved in `dctl_crypto::kdf::mnemonic`.
//! * **A malformed phrase is diagnosed before any unlock is attempted.**
//!   BIP-39 carries a checksum, so "you mistyped a word" and "this phrase is not
//!   for this vault" are distinguishable — and they have opposite remedies. An
//!   unlock attempt cannot tell them apart, because both end as "no slot
//!   opened", so the check happens here where it can still say something useful.
//!   The validator is `dctl-core`'s re-export of the same parser the KDF uses,
//!   never a second word list: a host that accepted a phrase the engine rejects
//!   would tell somebody holding a correct phrase that it is wrong.
//! * **There is no `--no-ask-password` special case.** That flag is about the
//!   password, and a recovery run that was given `--recovery-phrase-file` has
//!   already named its source; the prompt is reached only when a phrase was
//!   asked for with no source to read it from.

use std::path::Path;

use zeroize::Zeroizing;

use crate::cli::GlobalArgs;
use crate::constants::{ENV_RECOVERY_PHRASE, RECOVERY_PHRASE_PROMPT};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

/// Where a recovery phrase came from. Reported at `-v` so an operator debugging
/// a failed recovery can see which source actually answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// `--recovery-phrase` on the command line.
    Flag,
    /// The `DCTL_RECOVERY_PHRASE` environment variable.
    Environment,
    /// `--recovery-phrase-file`, read whole.
    File,
    /// Typed at a terminal.
    Prompt,
}

impl Source {
    /// Human description used in log and `-v` output.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Flag => "--recovery-phrase",
            Self::Environment => "the DCTL_RECOVERY_PHRASE environment variable",
            Self::File => "--recovery-phrase-file",
            Self::Prompt => "an interactive prompt",
        }
    }
}

/// A validated recovery phrase, wiped on drop.
pub struct RecoveryPhrase {
    value: Zeroizing<String>,
    source: Source,
}

impl RecoveryPhrase {
    /// The phrase itself. Never log the result.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.value
    }

    #[must_use]
    pub const fn source(&self) -> Source {
        self.source
    }
}

impl std::fmt::Debug for RecoveryPhrase {
    /// Redacted by hand, so a `{:?}` on a struct holding one cannot print the
    /// words. A leaked phrase is worse than a leaked password: changing the
    /// password does not revoke it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryPhrase")
            .field("value", &crate::logging::redact::REDACTED)
            .field("source", &self.source)
            .finish()
    }
}

/// Acquire the recovery phrase this run was told to use, if it was told to.
///
/// Returns `Ok(None)` only when **no** phrase source was named — the ordinary
/// password run. A named source that cannot be read is an error, never a silent
/// fall back to the password: a restore drill that quietly used the password
/// would report that the recovery path works without ever exercising it.
///
/// # Errors
/// [`ExitCode::VaultLocked`] when a named source is unreadable, empty, or holds
/// something BIP-39 rejects.
pub fn acquire(globals: &GlobalArgs) -> Result<Option<RecoveryPhrase>> {
    if let Some(value) = &globals.recovery_phrase {
        // Reachable from the flag *or* the variable, since clap fills the field
        // from either. Distinguished so `-v` names the real source.
        let source = if std::env::var_os(dctl_meta::env_var(ENV_RECOVERY_PHRASE)).is_some() {
            Source::Environment
        } else {
            Source::Flag
        };
        return finish(value, source).map(Some);
    }

    if let Some(path) = &globals.recovery_phrase_file {
        return from_file(path).map(Some);
    }

    Ok(None)
}

/// Acquire a phrase for a command whose entire purpose is the recovery path,
/// prompting when no source was named.
///
/// The prompt exists here and not in [`acquire`] because the two questions are
/// different. `dctl ls` must never stop and ask for a recovery phrase — the user
/// did not ask to recover — whereas `dctl vault recover` with no source is a
/// user who meant to type one and did not know the flag.
///
/// # Errors
/// Whatever [`acquire`] reports, or [`ExitCode::VaultLocked`] when there is no
/// terminal to prompt on (an unattended run must fail immediately rather than
/// block on a prompt nobody will answer,
/// [the plan](https://doc.dctl.sh/project/plan) §14).
pub fn acquire_required(globals: &GlobalArgs) -> Result<RecoveryPhrase> {
    if let Some(phrase) = acquire(globals)? {
        return Ok(phrase);
    }
    if globals.no_ask_password {
        return Err(CliError::new(
            ExitCode::VaultLocked,
            "no recovery phrase available and --no-ask-password forbids prompting",
        )
        .with_hint(
            "Supply one with --recovery-phrase-file, or set DCTL_RECOVERY_PHRASE. \
             Nothing was changed.",
        ));
    }
    from_prompt()
}

/// Read a phrase from a file, whole.
fn from_file(path: &Path) -> Result<RecoveryPhrase> {
    let contents = std::fs::read_to_string(path).map_err(|error| {
        CliError::new(
            ExitCode::VaultLocked,
            format!(
                "cannot read --recovery-phrase-file {}: {error}",
                path.display()
            ),
        )
    })?;
    finish(&contents, Source::File)
}

/// Prompt on the terminal, with echo off.
fn from_prompt() -> Result<RecoveryPhrase> {
    let value = rpassword::prompt_password(RECOVERY_PHRASE_PROMPT).map_err(|error| {
        CliError::new(
            ExitCode::VaultLocked,
            format!("cannot read a recovery phrase from the terminal: {error}"),
        )
        .with_hint(
            "There is no terminal to prompt on. Use --recovery-phrase-file or \
             DCTL_RECOVERY_PHRASE for unattended runs.",
        )
    })?;
    finish(&value, Source::Prompt)
}

/// Normalise the whitespace and check the phrase against BIP-39.
///
/// Normalising here rather than relying on the parser's own tolerance is what
/// makes the *stored* value predictable for everything downstream — the phrase
/// that reaches `dctl-core` is the canonical single-line spelling, so a
/// `-v` note or a future diagnostic cannot vary with how the file was wrapped.
/// The words themselves are never altered: case and spelling belong to BIP-39,
/// and "helpfully" lower-casing a word here would be this crate quietly
/// disagreeing with the engine's word list.
fn finish(raw: &str, source: Source) -> Result<RecoveryPhrase> {
    let value = Zeroizing::new(raw.split_whitespace().collect::<Vec<_>>().join(" "));

    if value.is_empty() {
        return Err(CliError::new(
            ExitCode::VaultLocked,
            format!("{} produced an empty recovery phrase", source.describe()),
        )
        .with_hint("A recovery phrase is the list of words `dctl init` printed once."));
    }

    dctl_core::validate_recovery_phrase(&value).map_err(|error| {
        CliError::new(
            ExitCode::VaultLocked,
            format!(
                "{} is not a valid recovery phrase: {error}",
                source.describe()
            ),
        )
        .with_hint(
            "Check the words against the paper: BIP-39 has a checksum, so this \
             refusal means a word is misspelled, missing, or in the wrong place \
             — not that the phrase belongs to another vault. Nothing was read \
             or written.",
        )
    })?;

    Ok(RecoveryPhrase { value, source })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn globals(args: &[&str]) -> GlobalArgs {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals
    }

    /// A real 24-word phrase with a valid checksum. Fixed rather than generated
    /// so the tests below assert on an exact string, and harmless because it
    /// guards no data — it is the BIP-39 specification's own test vector.
    const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank \
                          year wave sausage worth useful legal winner thank year wave sausage \
                          worth title";

    #[test]
    fn no_phrase_source_is_not_an_error() {
        // The ordinary password run must be untouched by this module.
        assert!(acquire(&globals(&[])).unwrap().is_none());
    }

    #[test]
    fn the_flag_supplies_a_phrase() {
        let phrase = acquire(&globals(&["--recovery-phrase", PHRASE]))
            .unwrap()
            .expect("a phrase was named");
        assert_eq!(phrase.expose(), PHRASE);
        assert_eq!(phrase.source(), Source::Flag);
    }

    #[test]
    fn a_phrase_file_is_read_whole_and_line_breaks_are_ignored() {
        // The transcription case this module exists for. `--password-file`'s
        // first-line rule would reject this, and the refusal would be
        // indistinguishable from "your phrase is wrong".
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("phrase.txt");
        let wrapped = PHRASE
            .split_whitespace()
            .collect::<Vec<_>>()
            .chunks(4)
            .map(|line| line.join(" "))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, format!("{wrapped}\n")).unwrap();

        let phrase = acquire(&globals(&[
            "--recovery-phrase-file",
            path.to_str().unwrap(),
        ]))
        .unwrap()
        .expect("a phrase was named");
        assert_eq!(
            phrase.expose(),
            PHRASE,
            "a wrapped phrase must normalise to the canonical one line"
        );
        assert_eq!(phrase.source(), Source::File);
    }

    #[test]
    fn a_mistyped_word_is_refused_here_rather_than_becoming_unlock_failed() {
        // BIP-39's checksum is the whole reason this check is worth making: the
        // last word depends on all the others, so a single transposition is
        // caught. Without this the operator is told their vault did not open.
        let mangled = PHRASE.replacen("legal", "zoo", 1);
        let error = acquire(&globals(&["--recovery-phrase", &mangled])).unwrap_err();
        assert_eq!(error.code(), ExitCode::VaultLocked);
        assert!(
            error.message().contains("not a valid recovery phrase"),
            "{}",
            error.message()
        );
        let hint = error.hint().unwrap_or_default();
        assert!(
            hint.contains("checksum"),
            "the hint must say why this is not 'wrong vault': {hint}"
        );
    }

    #[test]
    fn a_word_outside_the_bip39_list_is_refused() {
        let mangled = PHRASE.replacen("legal", "notaword", 1);
        assert!(acquire(&globals(&["--recovery-phrase", &mangled])).is_err());
    }

    #[test]
    fn an_empty_phrase_is_refused_rather_than_attempted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("phrase.txt");
        std::fs::write(&path, "   \n\n").unwrap();
        let error = acquire(&globals(&[
            "--recovery-phrase-file",
            path.to_str().unwrap(),
        ]))
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::VaultLocked);
    }

    #[test]
    fn a_missing_phrase_file_fails_instead_of_falling_back_to_the_password() {
        // The dangerous alternative: a restore drill that silently used the
        // password would report the recovery path as working while never having
        // run it.
        let error = acquire(&globals(&[
            "--recovery-phrase-file",
            "/nonexistent/phrase.txt",
            "--password",
            "correct horse battery staple",
        ]))
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::VaultLocked);
        assert!(error.message().contains("cannot read"));
    }

    #[test]
    fn an_unattended_recovery_with_no_source_fails_rather_than_blocking() {
        let error = acquire_required(&globals(&["--no-ask-password"])).unwrap_err();
        assert_eq!(error.code(), ExitCode::VaultLocked);
        assert!(error.hint().is_some());
    }

    #[test]
    fn the_debug_rendering_never_shows_the_words() {
        let phrase = acquire(&globals(&["--recovery-phrase", PHRASE]))
            .unwrap()
            .unwrap();
        let rendered = format!("{phrase:?}");
        assert!(!rendered.contains("sausage"), "leaked: {rendered}");
    }

    #[test]
    fn every_source_describes_itself() {
        for source in [
            Source::Flag,
            Source::Environment,
            Source::File,
            Source::Prompt,
        ] {
            assert!(!source.describe().is_empty());
        }
    }
}
