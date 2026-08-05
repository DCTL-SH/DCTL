//! Acquiring the password for a **new** vault.
//!
//! Creating a vault is the one moment where a mistyped password is
//! unrecoverable: the root key is wrapped under whatever was typed, and nothing
//! anywhere records what that was. Every other command can survive a typo by
//! asking again — `init` cannot, because the damage is a vault nobody can open.
//!
//! That single fact drives the whole module:
//!
//! * When the password comes from a terminal it is typed **twice** and the two
//!   readings must agree ([`constants::PASSWORD_CONFIRM_PROMPT`]).
//! * When it comes from a flag, a file or a command there is nothing to confirm
//!   against — a second read of the same source is not a check — so the
//!   confirmation is skipped rather than faked.
//! * A run that cannot obtain a password **fails**. It never falls back to an
//!   empty one, and under `--no-ask-password` it never blocks a headless job on a
//!   prompt nobody will answer ([the plan](https://doc.dctl.sh/project/plan)
//!   §14).
//!
//! The password is wrapped in [`Secret`] the moment it exists, so it cannot
//! reach a log by accident.

use std::io::IsTerminal;
use std::path::Path;
use std::process::Command;

use crate::cli::GlobalArgs;
use crate::constants;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::logging::Secret;

/// Where a password came from.
///
/// Reported in `--json` and at `-v` so an operator debugging an unattended run
/// can see *which* mechanism answered, without the answer itself appearing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    /// `--password`, or the `DCTL_PASSWORD` environment variable behind it.
    Flag,
    /// Standard output of `--password-command`.
    Command,
    /// First line of `--password-file`.
    File,
    /// Typed at the terminal, twice.
    Prompt,
}

impl Source {
    /// Human-readable name used in the `-v` note.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Flag => "--password",
            Self::Command => "--password-command",
            Self::File => "--password-file",
            Self::Prompt => "terminal prompt",
        }
    }
}

/// A new vault password and the mechanism that produced it.
///
/// `Debug` is derived deliberately: [`Secret`]'s own implementation prints
/// `<redacted>`, so a stray `{:?}` on this type in a future log line cannot
/// reveal the password. Omitting the derive would only push callers towards
/// unwrapping it by hand.
#[derive(Debug)]
pub struct NewPassword {
    secret: Secret<String>,
    source: Source,
}

impl NewPassword {
    /// The password itself.
    ///
    /// Named to make the call site auditable — this is the only place the value
    /// leaves the wrapper, and it is handed straight to `Vault::init`.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.secret.expose()
    }

    #[must_use]
    pub const fn source(&self) -> Source {
        self.source
    }
}

/// Obtain the password for a vault that is about to be created.
///
/// Sources are tried in the order a user would expect to override them:
/// explicit flag, then a command, then a file, then the terminal. Clap has
/// already folded `DCTL_PASSWORD` into [`GlobalArgs::password`], so the
/// environment is not consulted a second time here — resolving it twice is how
/// a flag and its variable start disagreeing.
///
/// # Errors
/// * [`ExitCode::Usage`] when no source is available and prompting is
///   impossible, when the two typed passwords disagree, or when the result is
///   shorter than [`constants::MIN_VAULT_PASSWORD_LEN`].
/// * [`ExitCode::FatalError`] when `--password-command` fails or produces
///   nothing.
pub fn acquire_new(globals: &GlobalArgs) -> Result<NewPassword> {
    if let Some(password) = &globals.password {
        return accept(password.clone(), Source::Flag);
    }
    if let Some(command) = &globals.password_command {
        return accept(run_password_command(command)?, Source::Command);
    }
    if let Some(path) = &globals.password_file {
        return accept(read_password_file(path)?, Source::File);
    }

    if globals.no_ask_password {
        return Err(CliError::new(
            ExitCode::Usage,
            "no password available and --no-ask-password forbids prompting",
        )
        .with_hint(
            "Supply --password-command, --password-file, or set DCTL_PASSWORD. \
             Nothing was created.",
        ));
    }

    if !std::io::stdin().is_terminal() {
        return Err(CliError::new(
            ExitCode::Usage,
            "no terminal available to type a new vault password",
        )
        .with_hint(
            "Run this interactively, or supply --password-command / \
             --password-file. Nothing was created.",
        ));
    }

    accept(prompt_twice()?, Source::Prompt)
}

/// Read the password twice from the terminal and require the two to agree.
///
/// Reads via `rpassword`, which opens the controlling terminal directly rather
/// than reading stdin, so echo stays off even when stdin has been redirected and
/// the typed characters never appear in a scrollback buffer.
fn prompt_twice() -> Result<String> {
    let first = rpassword::prompt_password(constants::PASSWORD_PROMPT)?;
    let second = rpassword::prompt_password(constants::PASSWORD_CONFIRM_PROMPT)?;
    confirm_match(&first, &second)?;
    Ok(first)
}

/// Require two typed readings to be identical.
///
/// A plain comparison, not a constant-time one: both sides are the same user's
/// own keystrokes seconds apart, so there is no secret here to leak by timing.
///
/// # Errors
/// [`ExitCode::Usage`] when they differ. The message says explicitly that nothing
/// was written, because the alternative reading — "it half-worked" — is exactly
/// the ambiguity [the plan](https://doc.dctl.sh/project/plan) §6 exists to
/// remove.
fn confirm_match(first: &str, second: &str) -> Result<()> {
    if first == second {
        return Ok(());
    }
    Err(
        CliError::new(ExitCode::Usage, "the two passwords did not match").with_hint(
            "Nothing was created. Run the command again; a vault whose password \
             was mistyped could never be opened.",
        ),
    )
}

/// Apply the new-vault password policy and wrap the result.
///
/// The length floor applies **only** to creation. It is deliberately not
/// enforced on unlock, where imposing today's rule on an older vault would lock
/// someone out of their own data.
fn accept(password: String, source: Source) -> Result<NewPassword> {
    let length = password.chars().count();
    if length < constants::MIN_VAULT_PASSWORD_LEN {
        return Err(CliError::new(
            ExitCode::Usage,
            format!(
                "a new vault password must be at least {} characters",
                constants::MIN_VAULT_PASSWORD_LEN
            ),
        )
        .with_hint(
            "The root key is random and strong; the password is the only part an \
             attacker who obtains the envelope can attack cheaply. Nothing was \
             created.",
        ));
    }

    Ok(NewPassword {
        secret: Secret::new(password),
        source,
    })
}

/// Run `--password-command` and take its output as the password.
///
/// Executed through a shell ([`constants::PASSWORD_COMMAND_SHELL`]) because the
/// flag exists to delegate to an existing secret manager, and those invocations
/// are pipelines far more often than they are single programs.
///
/// Only the first line is used, and its trailing newline is stripped: helpers
/// print a line, and a password silently carrying a `\n` would produce a vault
/// that no re-typed password could ever open.
fn run_password_command(command: &str) -> Result<String> {
    let output = Command::new(constants::PASSWORD_COMMAND_SHELL)
        .arg(constants::PASSWORD_COMMAND_SHELL_FLAG)
        .arg(command)
        .output()
        .map_err(|error| {
            CliError::new(
                ExitCode::FatalError,
                format!("could not run --password-command: {error}"),
            )
        })?;

    if !output.status.success() {
        // The command's own stderr is not echoed: a failing secret helper
        // frequently prints the secret it was trying to fetch.
        return Err(CliError::new(
            ExitCode::FatalError,
            format!("--password-command exited with status {}", output.status),
        )
        .with_hint("Nothing was created. Run the command by hand to see why it failed."));
    }

    first_line(&String::from_utf8_lossy(&output.stdout)).ok_or_else(|| {
        CliError::new(
            ExitCode::FatalError,
            "--password-command produced no output",
        )
        .with_hint("Nothing was created.")
    })
}

/// Read the password from the first line of a file.
///
/// # Errors
/// The underlying I/O failure, classified by
/// [`From<std::io::Error>`](crate::error::CliError) — a missing file becomes
/// [`ExitCode::FileNotFound`], so a typo in the path is distinguishable from a
/// permission problem.
fn read_password_file(path: &Path) -> Result<String> {
    let contents = std::fs::read_to_string(path)?;
    first_line(&contents).ok_or_else(|| {
        CliError::new(
            ExitCode::Usage,
            format!("password file {} is empty", path.display()),
        )
        .with_hint("Nothing was created.")
    })
}

/// The first line of some text, with its line ending removed, or `None` when
/// there is no non-empty first line.
///
/// Trailing `\r` is stripped as well as `\n`: a password file written on Windows
/// and read on Linux would otherwise carry an invisible carriage return into the
/// KDF.
fn first_line(text: &str) -> Option<String> {
    let line = text.split('\n').next()?.trim_end_matches('\r');
    (!line.is_empty()).then(|| line.to_string())
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

    /// A password comfortably over the policy floor, so length is never the
    /// thing a test is accidentally asserting.
    const LONG_ENOUGH: &str = "correct horse battery staple";

    #[test]
    fn the_flag_is_the_first_source_consulted() {
        let password = acquire_new(&globals(&["--password", LONG_ENOUGH])).unwrap();
        assert_eq!(password.expose(), LONG_ENOUGH);
        assert_eq!(password.source(), Source::Flag);
    }

    #[test]
    fn a_password_file_supplies_its_first_line_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw");
        std::fs::write(&path, format!("{LONG_ENOUGH}\nsecond line\n")).unwrap();

        let password =
            acquire_new(&globals(&["--password-file", &path.to_string_lossy()])).unwrap();
        assert_eq!(password.expose(), LONG_ENOUGH);
        assert_eq!(password.source(), Source::File);
    }

    #[test]
    fn a_missing_password_file_is_a_file_not_found() {
        let error = acquire_new(&globals(&["--password-file", "/nonexistent/pw"])).unwrap_err();
        assert_eq!(error.code(), ExitCode::FileNotFound);
    }

    #[test]
    fn an_empty_password_file_is_rejected_rather_than_used() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw");
        std::fs::write(&path, "\n").unwrap();
        let error =
            acquire_new(&globals(&["--password-file", &path.to_string_lossy()])).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[cfg(not(windows))]
    #[test]
    fn a_password_command_is_run_through_a_shell() {
        // A pipeline, because that is what real secret helpers look like.
        let password = acquire_new(&globals(&[
            "--password-command",
            "printf '%s\\nignored\\n' 'correct horse battery staple'",
        ]))
        .unwrap();
        assert_eq!(password.expose(), LONG_ENOUGH);
        assert_eq!(password.source(), Source::Command);
    }

    #[cfg(not(windows))]
    #[test]
    fn a_failing_password_command_is_fatal_and_creates_nothing() {
        let error = acquire_new(&globals(&["--password-command", "exit 3"])).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
    }

    #[cfg(not(windows))]
    #[test]
    fn a_silent_password_command_is_not_treated_as_an_empty_password() {
        // The failure mode this guards: a helper that prints nothing must not
        // wrap the root key under "".
        let error = acquire_new(&globals(&["--password-command", "true"])).unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
    }

    #[test]
    fn no_ask_password_fails_instead_of_blocking_a_headless_run() {
        let error = acquire_new(&globals(&["--no-ask-password"])).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        let hint = error.hint().unwrap_or_default();
        assert!(hint.contains("DCTL_PASSWORD"), "got hint: {hint}");
    }

    #[test]
    fn a_short_password_is_refused_at_creation_time() {
        let error = acquire_new(&globals(&["--password", "short"])).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(
            error
                .message()
                .contains(&constants::MIN_VAULT_PASSWORD_LEN.to_string())
        );
    }

    #[test]
    fn the_length_floor_counts_characters_not_bytes() {
        // Seven multi-byte characters are seven characters, not fourteen bytes'
        // worth of strength.
        let seven = "ααααααα";
        assert_eq!(seven.chars().count(), 7);
        assert!(acquire_new(&globals(&["--password", seven])).is_err());
    }

    #[test]
    fn mismatched_confirmations_are_rejected_and_say_nothing_was_created() {
        let error = confirm_match("first-attempt", "second-attempt").unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        let hint = error.hint().unwrap_or_default();
        assert!(hint.contains("Nothing was created"), "got hint: {hint}");
    }

    #[test]
    fn matching_confirmations_are_accepted() {
        assert!(confirm_match(LONG_ENOUGH, LONG_ENOUGH).is_ok());
        // Whitespace is part of a password, so it must not be trimmed away.
        assert!(confirm_match(" padded ", "padded").is_err());
    }

    #[test]
    fn line_endings_never_reach_the_key_derivation() {
        assert_eq!(first_line("secret\r\nmore").as_deref(), Some("secret"));
        assert_eq!(first_line("secret\n").as_deref(), Some("secret"));
        assert_eq!(first_line("secret").as_deref(), Some("secret"));
        assert_eq!(first_line(""), None);
        assert_eq!(first_line("\n"), None);
        // Interior spaces are content, not padding.
        assert_eq!(first_line("a b \n").as_deref(), Some("a b "));
    }

    #[test]
    fn the_password_never_renders_itself() {
        // The whole point of wrapping it: a stray `{:?}` in a future log line
        // must not print the value.
        let password = acquire_new(&globals(&["--password", LONG_ENOUGH])).unwrap();
        assert_eq!(
            format!("{:?}", password.secret),
            crate::logging::redact::REDACTED
        );
    }

    #[test]
    fn every_source_names_itself() {
        for source in [Source::Flag, Source::Command, Source::File, Source::Prompt] {
            assert!(!source.describe().is_empty());
        }
        // The serialised spelling is what a machine consumer branches on.
        assert_eq!(
            serde_json::to_value(Source::Prompt).unwrap(),
            serde_json::json!("prompt")
        );
    }
}
