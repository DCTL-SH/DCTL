//! Acquiring the password for an **existing** vault.
//!
//! Distinct from [`crate::commands::init::password`], which acquires a password
//! for a vault being created. The difference is not cosmetic: creating a vault
//! demands the password twice, because a typo would encrypt data under a secret
//! nobody knows. Unlocking one needs it once — a typo simply fails to unwrap the
//! envelope, loudly and harmlessly.
//!
//! Sources are tried in a fixed order, most explicit first, so a scripted run is
//! never surprised by an interactive prompt it did not ask for.

use std::process::Command;

use zeroize::Zeroizing;

use crate::cli::GlobalArgs;
use crate::constants::PASSWORD_PROMPT;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

/// Where a password came from. Reported at `-v` so an operator debugging a
/// failed unlock can see which source was actually used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// `--password` on the command line.
    Flag,
    /// The `DCTL_PASSWORD` environment variable.
    Environment,
    /// `--password-command`, whose stdout is the password.
    CommandOutput,
    /// `--password-file`, whose first line is the password.
    File,
    /// Typed at a terminal.
    Prompt,
}

impl Source {
    /// Human description used in log and `-v` output.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Flag => "--password",
            Self::Environment => "the DCTL_PASSWORD environment variable",
            Self::CommandOutput => "--password-command",
            Self::File => "--password-file",
            Self::Prompt => "an interactive prompt",
        }
    }
}

/// A password for an existing vault, wiped on drop.
pub struct Password {
    value: Zeroizing<String>,
    source: Source,
}

impl Password {
    /// The secret. Never log the result.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.value
    }

    #[must_use]
    pub const fn source(&self) -> Source {
        self.source
    }
}

impl std::fmt::Debug for Password {
    /// Redacted, so a `{:?}` on a struct holding one cannot leak it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Password")
            .field("value", &crate::logging::redact::REDACTED)
            .field("source", &self.source)
            .finish()
    }
}

/// Acquire the password for an existing vault.
///
/// # Errors
/// [`ExitCode::VaultLocked`] when no source yields one — including the case
/// where a prompt would be needed but `--no-ask-password` forbids it, or there
/// is no terminal to prompt on. Failing is deliberate: an unattended job that
/// would otherwise block forever on an invisible prompt is worse than one that
/// stops immediately and says why.
pub fn acquire(globals: &GlobalArgs) -> Result<Password> {
    if let Some(value) = &globals.password {
        // Reachable from `--password` *or* `DCTL_PASSWORD`, since clap fills the
        // field from either. Distinguished so `-v` names the real source.
        let source =
            if std::env::var_os(dctl_meta::env_var(crate::constants::ENV_PASSWORD)).is_some() {
                Source::Environment
            } else {
                Source::Flag
            };
        return Ok(Password {
            value: Zeroizing::new(value.clone()),
            source,
        });
    }

    if let Some(command) = &globals.password_command {
        return from_command(command);
    }

    if let Some(path) = &globals.password_file {
        return from_file(path);
    }

    if globals.no_ask_password {
        return Err(CliError::new(
            ExitCode::VaultLocked,
            "no password available and --no-ask-password forbids prompting",
        )
        .with_hint(
            "Supply one with --password-command, --password-file, or the \
             DCTL_PASSWORD environment variable.",
        ));
    }

    from_prompt()
}

/// Run a command and take its stdout as the password.
fn from_command(command: &str) -> Result<Password> {
    let output = shell(command).map_err(|error| {
        CliError::new(
            ExitCode::VaultLocked,
            format!("--password-command failed to run: {error}"),
        )
    })?;

    if !output.status.success() {
        // The command's own stderr is not echoed: it is attacker-influenced
        // text on a credential path, and a helper that prints the password on
        // failure would leak it into our logs.
        return Err(CliError::new(
            ExitCode::VaultLocked,
            format!(
                "--password-command exited with status {}",
                output
                    .status
                    .code()
                    .map_or_else(|| "unknown".to_string(), |code| code.to_string())
            ),
        )
        .with_hint("The command must print the password on stdout and exit 0."));
    }

    // Lossy, matching `dctl init`. Rejecting non-UTF-8 here while `init`
    // accepted it would be the same unrecoverable split as the first-line rule:
    // a helper emitting one stray byte would create a vault keyed on U+FFFD that
    // this function then refuses to reproduce.
    let value = String::from_utf8_lossy(&output.stdout).into_owned();

    finish(&value, Source::CommandOutput)
}

/// Spawn `command` through the platform shell.
///
/// Windows has no `sh`, so the two are genuinely different invocations rather
/// than one with a different binary name.
fn shell(command: &str) -> std::io::Result<std::process::Output> {
    if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", command]).output()
    } else {
        Command::new("sh").args(["-c", command]).output()
    }
}

/// Read the first line of a file as the password.
fn from_file(path: &std::path::Path) -> Result<Password> {
    let contents = std::fs::read_to_string(path).map_err(|error| {
        CliError::new(
            ExitCode::VaultLocked,
            format!("cannot read --password-file {}: {error}", path.display()),
        )
    })?;
    finish(&contents, Source::File)
}

/// Prompt on the terminal.
fn from_prompt() -> Result<Password> {
    let value = rpassword::prompt_password(PASSWORD_PROMPT).map_err(|error| {
        CliError::new(
            ExitCode::VaultLocked,
            format!("cannot read a password from the terminal: {error}"),
        )
        .with_hint(
            "There is no terminal to prompt on. Use --password-command, \
             --password-file, or DCTL_PASSWORD for unattended runs.",
        )
    })?;
    finish(&value, Source::Prompt)
}

/// Take the **first line** as the password, and reject an empty result.
///
/// First line, not the whole text, and this is load-bearing. `dctl init` uses
/// exactly this rule (`commands::init::password::first_line`), so a source that
/// yields more than one line — a password file with a trailing comment, a
/// CRLF-terminated file with a blank last line, or a `pass show` helper that
/// prints metadata after the secret — must be read here the same way it was read
/// when the vault was created.
///
/// Reading the whole text instead produces a vault that can **never** be
/// reopened: `init` derives the KEK from line one, every later unlock derives it
/// from line one plus the remainder, and the envelope refuses both the password
/// the user thinks they set and every variation they will try. There is no
/// recovery path from that state, which makes agreeing on one rule far more
/// important than which rule is chosen.
///
/// Within the line, leading and interior whitespace is preserved: it can
/// legitimately be part of a passphrase, and trimming it would break a correct
/// password against the vault it created — the same failure in miniature.
fn finish(raw: &str, source: Source) -> Result<Password> {
    let line = raw.split('\n').next().unwrap_or("").trim_end_matches('\r');
    let value = Zeroizing::new(line.to_string());

    if value.is_empty() {
        return Err(CliError::new(
            ExitCode::VaultLocked,
            format!("{} produced an empty password", source.describe()),
        )
        .with_hint("The first line of the file or command output is the password."));
    }
    Ok(Password { value, source })
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

    #[test]
    fn an_explicit_flag_wins() {
        let password = acquire(&globals(&["--password", "hunter2"])).unwrap();
        assert_eq!(password.expose(), "hunter2");
    }

    #[test]
    fn a_password_file_is_read_and_its_newline_stripped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw");
        std::fs::write(&path, "from-a-file\n").unwrap();

        let password = acquire(&globals(&["--password-file", path.to_str().unwrap()])).unwrap();
        assert_eq!(password.expose(), "from-a-file");
        assert_eq!(password.source(), Source::File);
    }

    #[test]
    fn interior_and_leading_whitespace_survive() {
        // A passphrase may legitimately contain spaces. Trimming them would
        // make a correct password fail against the vault it created.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw");
        std::fs::write(&path, "  correct horse battery staple \n").unwrap();

        let password = acquire(&globals(&["--password-file", path.to_str().unwrap()])).unwrap();
        assert_eq!(password.expose(), "  correct horse battery staple ");
    }

    #[test]
    fn only_the_first_line_of_a_file_is_the_password() {
        // The catastrophic case: `dctl init` reads line one, so unlocking must
        // too. Reading the whole file produces a vault nothing can reopen.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw");
        std::fs::write(&path, "correct horse battery staple\n# comment line\n").unwrap();

        let password = acquire(&globals(&["--password-file", path.to_str().unwrap()])).unwrap();
        assert_eq!(password.expose(), "correct horse battery staple");
    }

    #[test]
    fn crlf_line_endings_do_not_change_the_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw");
        std::fs::write(&path, "secret\r\nmore\r\n").unwrap();

        let password = acquire(&globals(&["--password-file", path.to_str().unwrap()])).unwrap();
        assert_eq!(password.expose(), "secret");
    }

    #[test]
    fn this_agrees_with_how_init_reads_the_same_file() {
        // Pinned against the other implementation rather than restated, because
        // a silent divergence between the two is unrecoverable data loss.
        for raw in [
            "pw\n",
            "pw\n\n",
            "pw\r\n",
            "pw\nignored second line\n",
            "  spaced  pw  \ntrailing\n",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("pw");
            std::fs::write(&path, raw).unwrap();

            let unlock = acquire(&globals(&["--password-file", path.to_str().unwrap()])).unwrap();
            let create = crate::commands::init::password::acquire_new(&globals(&[
                "--password-file",
                path.to_str().unwrap(),
            ]));

            if let Ok(create) = create {
                assert_eq!(
                    unlock.expose(),
                    create.expose(),
                    "init and unlock disagree for {raw:?}"
                );
            }
        }
    }

    #[test]
    fn an_empty_password_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw");
        std::fs::write(&path, "\n").unwrap();

        let error = acquire(&globals(&["--password-file", path.to_str().unwrap()])).unwrap_err();
        assert_eq!(error.code(), ExitCode::VaultLocked);
    }

    #[test]
    fn a_missing_password_file_fails_with_the_vault_locked_code() {
        let error = acquire(&globals(&["--password-file", "/nonexistent/pw"])).unwrap_err();
        assert_eq!(error.code(), ExitCode::VaultLocked);
        assert!(error.message().contains("cannot read"));
    }

    #[test]
    fn no_ask_password_refuses_rather_than_blocking() {
        // The unattended case: failing immediately beats hanging on a prompt
        // nobody can see.
        let error = acquire(&globals(&["--no-ask-password"])).unwrap_err();
        assert_eq!(error.code(), ExitCode::VaultLocked);
        assert!(error.hint().is_some());
    }

    #[test]
    #[cfg(unix)]
    fn a_password_command_supplies_its_stdout() {
        let password =
            acquire(&globals(&["--password-command", "printf 'from-a-command'"])).unwrap();
        assert_eq!(password.expose(), "from-a-command");
        assert_eq!(password.source(), Source::CommandOutput);
    }

    #[test]
    #[cfg(unix)]
    fn a_failing_password_command_is_an_error_not_an_empty_password() {
        let error = acquire(&globals(&["--password-command", "exit 3"])).unwrap_err();
        assert_eq!(error.code(), ExitCode::VaultLocked);
        assert!(error.message().contains("status 3"), "{}", error.message());
    }

    #[test]
    fn the_debug_rendering_never_shows_the_secret() {
        let password = acquire(&globals(&["--password", "hunter2"])).unwrap();
        let rendered = format!("{password:?}");
        assert!(!rendered.contains("hunter2"), "leaked: {rendered}");
    }

    #[test]
    fn every_source_describes_itself() {
        for source in [
            Source::Flag,
            Source::Environment,
            Source::CommandOutput,
            Source::File,
            Source::Prompt,
        ] {
            assert!(!source.describe().is_empty());
        }
    }
}
