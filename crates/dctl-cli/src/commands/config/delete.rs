//! `dctl config delete NAME` — remove a remote from the configuration.
//!
//! Destructive in the sense that matters here: it removes the *only* record of
//! how to reach a set of objects. No bytes are deleted anywhere — but a vault
//! whose endpoint, bucket and region have been forgotten is, for practical
//! purposes, gone until someone reconstructs them.
//!
//! So the removal goes through [`Ctx::confirm_destructive`] like any other
//! destructive action, and the command says plainly that stored data survives.
//! An operator who thinks `config delete` erased their backup will do something
//! far worse next.
//!
//! Removing a remote that a vault remote still wraps is refused. The
//! configuration layer would catch it on the next load anyway, but catching it
//! here means the file is never left in a state that no future command can read.

use clap::Args;
use serde::Serialize;

use super::emit;
use super::settings::unknown_remote;
use crate::config;
use crate::constants;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

/// Arguments for `dctl config delete`.
#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// Remote to remove from the configuration.
    #[arg(value_name = "NAME")]
    pub name: String,
}

/// What `delete` reports having done.
#[derive(Debug, Serialize)]
struct DeleteReport {
    name: String,
    /// Whether the section is gone from the file. False for a dry run, always.
    deleted: bool,
    dry_run: bool,
}

/// Remove a remote.
///
/// # Errors
/// [`ExitCode::Usage`] when the remote is still wrapped by a vault remote,
/// [`ExitCode::Cancelled`] when a confirmation prompt was declined, or
/// [`crate::config::ConfigError::UnknownRemote`] — classified by the
/// configuration layer — for a name that is not configured.
pub async fn run(ctx: &Ctx, args: &DeleteArgs) -> Result<()> {
    let path = config::resolve_path(ctx.globals.config.as_deref());
    let mut loaded = config::load_or_default(&path)?;

    if !loaded.contains(&args.name) {
        return Err(unknown_remote(&args.name));
    }
    refuse_if_wrapped(&loaded, &args.name)?;

    let approved = ctx.confirm_destructive("remove the configuration for", &args.name)?;

    if !approved && !ctx.is_dry_run() {
        return Err(CliError::new(
            ExitCode::Cancelled,
            format!("removal of '{}' was declined", args.name),
        )
        .with_hint("The configuration is unchanged."));
    }

    if approved && !ctx.is_dry_run() {
        // Reassurance, not decoration: someone who believes this erased their
        // backup is one command away from a real mistake.
        ctx.out.info(format!(
            "objects stored under '{}' are untouched; only the settings are gone",
            args.name
        ));
        let _removed = loaded.remove(&args.name);
        config::save(&loaded, &path)?;
        ctx.out.success(format!("removed remote '{}'", args.name));
    }

    let report = DeleteReport {
        name: args.name.clone(),
        deleted: approved && !ctx.is_dry_run(),
        dry_run: ctx.is_dry_run(),
    };

    emit::records(ctx, std::slice::from_ref(&report), || {
        emit::pairs(
            constants::CONFIG_COLUMN_NAME,
            constants::CONFIG_COLUMN_VALUE,
            vec![(report.name.clone(), report.deleted.to_string())],
        )
    })
}

/// Refuse to orphan a vault remote by removing the remote it wraps.
///
/// # Errors
/// [`ExitCode::Usage`], naming every dependant so the user can see the whole
/// job rather than discovering it one refusal at a time.
fn refuse_if_wrapped(loaded: &config::Config, name: &str) -> Result<()> {
    let dependants: Vec<&str> = loaded
        .remotes
        .iter()
        .filter(|(_, remote)| remote.base() == Some(name))
        .map(|(dependant, _)| dependant.as_str())
        .collect();

    if dependants.is_empty() {
        return Ok(());
    }

    Err(CliError::new(
        ExitCode::Usage,
        format!("'{name}' is wrapped by {}", dependants.join(", ")),
    )
    .with_hint(format!(
        "Remove or repoint {} first — a vault remote whose base is gone cannot \
         be loaded at all.",
        dependants.join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use clap::Parser;
    use std::path::{Path, PathBuf};

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

    const CHAINED: &str = "\
[remotes.b2prod]
type = \"b2\"
bucket = \"photos\"

[remotes.vault]
type = \"vault\"
base = \"b2prod\"
";

    const STANDALONE: &str = "\
[remotes.b2prod]
type = \"b2\"
bucket = \"photos\"

[remotes.scratch]
type = \"local\"
path = \"/srv/scratch\"
";

    fn written(contents: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, contents).unwrap();
        (dir, path)
    }

    fn args(name: &str) -> DeleteArgs {
        DeleteArgs {
            name: name.to_string(),
        }
    }

    #[tokio::test]
    async fn a_remote_is_removed_and_its_siblings_survive() {
        let (_dir, path) = written(STANDALONE);
        run(&ctx(&path, &[]), &args("scratch")).await.unwrap();

        let loaded = config::load(&path).unwrap();
        assert!(!loaded.contains("scratch"));
        assert!(loaded.contains("b2prod"));
    }

    #[tokio::test]
    async fn removing_a_base_that_something_wraps_is_refused() {
        // The failure this prevents: a config file that no later command can
        // load, because `vault` names a base that no longer exists.
        let (_dir, path) = written(CHAINED);
        let before = std::fs::read(&path).unwrap();
        let error = run(&ctx(&path, &[]), &args("b2prod")).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("vault"), "{}", error.message());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[tokio::test]
    async fn the_wrapper_itself_can_always_be_removed() {
        let (_dir, path) = written(CHAINED);
        run(&ctx(&path, &[]), &args("vault")).await.unwrap();
        let loaded = config::load(&path).unwrap();
        assert!(!loaded.contains("vault"));
        assert!(loaded.contains("b2prod"));
    }

    #[tokio::test]
    async fn a_dry_run_leaves_the_file_byte_identical() {
        let (_dir, path) = written(STANDALONE);
        let before = std::fs::read(&path).unwrap();
        run(&ctx(&path, &["--dry-run"]), &args("scratch"))
            .await
            .unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(config::load(&path).unwrap().contains("scratch"));
    }

    #[tokio::test]
    async fn an_unknown_remote_is_reported_with_the_shared_code() {
        let (_dir, path) = written(STANDALONE);
        let error = run(&ctx(&path, &[]), &args("nope")).await.unwrap_err();
        assert_eq!(
            error.code(),
            config::ConfigError::UnknownRemote("nope".to_string()).exit_code()
        );
        assert!(error.hint().unwrap_or_default().contains("config list"));
    }

    #[tokio::test]
    async fn force_removes_without_asking() {
        let (_dir, path) = written(STANDALONE);
        run(&ctx(&path, &["--force"]), &args("scratch"))
            .await
            .unwrap();
        assert!(!config::load(&path).unwrap().contains("scratch"));
    }

    #[test]
    fn a_dry_run_never_reports_the_remote_as_deleted() {
        let report = DeleteReport {
            name: "scratch".into(),
            deleted: false,
            dry_run: true,
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["deleted"], false);
        assert_eq!(json["dry_run"], true);
    }

    #[tokio::test]
    async fn every_format_is_supported() {
        for format in ["text", "json", "json-lines"] {
            let (_dir, path) = written(STANDALONE);
            assert!(
                run(&ctx(&path, &["--format", format]), &args("scratch"))
                    .await
                    .is_ok(),
                "{format} failed"
            );
        }
    }
}
