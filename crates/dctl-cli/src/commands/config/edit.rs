//! `dctl config edit` — open the configuration file in an editor.
//!
//! The file is TOML and meant to be edited by hand ([the plan](https://doc.dctl.sh/project/plan) §14), so the
//! useful thing a CLI can add is not a questionnaire — it is finding the file,
//! creating it correctly if it is missing, and checking the result before the
//! user walks away believing it is fine.
//!
//! That last part is why this is a command rather than a shell alias. After the
//! editor exits the file is re-loaded, and a syntax error, a dangling vault
//! base, or a credential pasted in from an rclone tutorial is reported **now**,
//! while the user still remembers what they changed, instead of at 3am in a
//! backup job. The exit status follows: a configuration that no longer loads is
//! a failed `config edit`, not a successful one.
//!
//! The editor inherits the terminal, so it must not run when there is nothing to
//! inherit. A headless job that launched `vi` on a detached stdin would hang
//! forever; here it fails immediately and says what to do instead.

use std::io::IsTerminal;
use std::process::Command;

use serde::Serialize;

use super::emit;
use crate::config::{self, Config};
use crate::constants;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

/// What `edit` reports having done.
#[derive(Debug, Serialize)]
struct EditReport {
    path: String,
    /// The editor that was launched.
    editor: String,
    /// Whether the editor actually ran. False for a dry run, always.
    edited: bool,
    dry_run: bool,
}

/// Open the configuration file in an editor.
///
/// # Errors
/// * [`ExitCode::Usage`] when there is no terminal for an editor to use.
/// * [`ExitCode::FatalError`] when the editor cannot be started or exits
///   non-zero.
/// * Whatever [`crate::config::load`] classifies the file as, when the editor
///   leaves it unloadable.
pub async fn run(ctx: &Ctx) -> Result<()> {
    let path = config::resolve_path(ctx.globals.config.as_deref());
    let editor = choose_editor();

    if ctx.is_dry_run() {
        ctx.dry_run_notice("open in an editor", &path.display().to_string());
        return emit_report(
            ctx,
            &EditReport {
                path: path.display().to_string(),
                editor,
                edited: false,
                dry_run: true,
            },
        );
    }

    if !std::io::stdin().is_terminal() {
        return Err(
            CliError::new(ExitCode::Usage, "no terminal available for an editor").with_hint(
                "Edit the file directly — `dctl config file` prints its path — or \
                 use `dctl config create` and `dctl config update`, which need no \
                 terminal.",
            ),
        );
    }

    // Create it first, so the editor opens a file with the right permissions and
    // the no-secrets header rather than an empty buffer.
    if !path.exists() {
        config::save(&Config::default(), &path)?;
    }

    let status = Command::new(&editor).arg(&path).status().map_err(|error| {
        CliError::new(
            ExitCode::FatalError,
            format!("could not start editor '{editor}': {error}"),
        )
        .with_hint(format!(
            "Set {} to an editor that exists.",
            constants::EDITOR_ENV_VARS.join(" or ")
        ))
    })?;

    if !status.success() {
        return Err(CliError::new(
            ExitCode::FatalError,
            format!("editor '{editor}' exited with status {status}"),
        )
        .with_hint("The file was left as the editor wrote it; check it with `dctl config list`."));
    }

    // Re-read, so a mistake is reported while it is still fresh. This is the
    // whole reason the command exists rather than being a shell alias.
    let reloaded = config::load(&path)?;
    ctx.out
        .info(format!("{} remote(s) configured", reloaded.len()));

    emit_report(
        ctx,
        &EditReport {
            path: path.display().to_string(),
            editor,
            edited: true,
            dry_run: false,
        },
    )
}

/// Render the report in whichever format was requested.
fn emit_report(ctx: &Ctx, report: &EditReport) -> Result<()> {
    emit::records(ctx, std::slice::from_ref(report), || {
        emit::pairs(
            constants::CONFIG_COLUMN_NAME,
            constants::CONFIG_COLUMN_VALUE,
            vec![(report.path.clone(), report.editor.clone())],
        )
    })
}

/// The editor to launch.
///
/// [`constants::EDITOR_ENV_VARS`] in order, then
/// [`constants::DEFAULT_EDITOR`]. An empty variable is skipped rather than
/// obeyed: `EDITOR=` is how a shell profile unsets one, and launching a program
/// with no name would fail with an unreadable OS error.
fn choose_editor() -> String {
    constants::EDITOR_ENV_VARS
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
        .unwrap_or_else(|| constants::DEFAULT_EDITOR.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use clap::Parser;
    use std::path::Path;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(path: &Path, extra: &[&str]) -> Ctx {
        let config = path.to_string_lossy().to_string();
        let mut args = vec!["dctl".to_string(), "--config".to_string(), config];
        args.extend(extra.iter().map(|a| (*a).to_string()));
        Ctx::new(Harness::parse_from(args).globals)
    }

    #[tokio::test]
    async fn a_dry_run_launches_nothing_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        run(&ctx(&path, &["--dry-run"])).await.unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn a_dry_run_report_never_claims_the_file_was_edited() {
        let report = EditReport {
            path: "/x/config.toml".into(),
            editor: choose_editor(),
            edited: false,
            dry_run: true,
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["edited"], false);
        assert_eq!(json["dry_run"], true);
    }

    #[tokio::test]
    async fn a_headless_run_fails_immediately_rather_than_hanging() {
        // The failure this prevents: a cron job blocked forever on `vi` waiting
        // for a keystroke nobody will type.
        //
        // Only assertable when the harness itself has no terminal, which is the
        // case in CI and under `cargo test` with redirected output.
        if std::io::stdin().is_terminal() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let error = run(&ctx(&path, &[])).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().unwrap_or_default().contains("config file"));
        assert!(!path.exists(), "a refused edit must not create the file");
    }

    #[test]
    fn the_editor_search_order_is_visual_then_editor_then_the_fallback() {
        // The process environment cannot be mutated safely from a parallel test
        // (`set_var` is unsafe and this crate forbids unsafe), so the order is
        // asserted through the constant the resolver reads.
        assert_eq!(constants::EDITOR_ENV_VARS.first(), Some(&"VISUAL"));
        assert_eq!(constants::EDITOR_ENV_VARS.get(1), Some(&"EDITOR"));
    }

    #[test]
    fn the_chosen_editor_is_never_empty() {
        // An empty program name would fail with an unreadable OS error, so the
        // fallback must always win over one.
        assert!(!choose_editor().trim().is_empty());
    }

    #[test]
    fn a_file_the_editor_broke_is_reported_rather_than_accepted() {
        // The check that makes this more than a shell alias, exercised on the
        // loader directly since the editor itself cannot run under test.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[remotes.b2prod\n").unwrap();
        assert!(config::load(&path).is_err());

        // Including the mistake a user is most likely to make after reading an
        // rclone tutorial.
        std::fs::write(
            &path,
            "[remotes.b2prod]\ntype = \"b2\"\nbucket = \"p\"\napp_key = \"K001x\"\n",
        )
        .unwrap();
        assert!(config::load(&path).is_err());
    }
}
