//! `dctl config update NAME [key=value ...]` — change settings on an existing
//! remote.
//!
//! The difference from [`super::create`] is the whole reason both exist:
//! `create` writes a section, `update` **merges into** one. Keys the caller does
//! not mention keep their values, which is what makes it safe to run from
//! configuration management that only knows about the two settings it owns.
//!
//! An empty value removes a key (`dctl config update s3west region=`). That is
//! the only way to unset a setting without opening an editor, and it is spelled
//! the way a shell user expects.
//!
//! Two things this refuses to do. It never *creates* a remote — a typo in the
//! name would otherwise leave behind a plausible-looking remote that points
//! nowhere and is used by nothing. And it never writes a merge result that would
//! not load again: the merged settings are turned back into a real
//! [`RemoteDef`](crate::config::RemoteDef) first, so removing a required setting
//! fails here rather than producing a file the next command cannot read.

use clap::Args;
use serde::Serialize;

use super::emit;
use super::settings::{self, unknown_remote};
use crate::config;
use crate::constants;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

/// Arguments for `dctl config update`.
#[derive(Args, Debug)]
pub struct UpdateArgs {
    /// Remote to change.
    #[arg(value_name = "NAME")]
    pub name: String,

    /// Settings, written 'key=value'. An empty value removes the key.
    #[arg(value_name = "KEY=VALUE")]
    pub settings: Vec<String>,
}

/// What `update` reports having done.
#[derive(Debug, Serialize)]
struct UpdateReport {
    name: String,
    /// Keys whose value was set. Keys only — see [`super::create`] for why a
    /// value typed on a command line is not echoed back.
    set: Vec<String>,
    /// Keys that were removed.
    removed: Vec<String>,
    /// Whether the file was rewritten. False for a dry run, always.
    updated: bool,
    dry_run: bool,
}

/// Change an existing remote's settings.
///
/// # Errors
/// [`ExitCode::Usage`] when no settings were given, when an argument is not
/// `key=value`, or when the merged result would not be a usable remote. A name
/// that is not configured is reported as
/// [`crate::config::ConfigError::UnknownRemote`], classified by the
/// configuration layer rather than by this command.
pub async fn run(ctx: &Ctx, args: &UpdateArgs) -> Result<()> {
    if args.settings.is_empty() {
        return Err(
            CliError::new(ExitCode::Usage, "no settings given").with_hint(
                "Write them as 'key=value', for example \
             `dctl config update b2prod bucket=films`.",
            ),
        );
    }

    let assignments = settings::parse_assignments(&args.settings)?;

    // Split before the write, so the report describes what was asked for even
    // when the write is the part a dry run skips.
    let set: Vec<String> = assignments
        .iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(key, _)| key.clone())
        .collect();
    let removed: Vec<String> = assignments
        .iter()
        .filter(|(_, value)| value.is_empty())
        .map(|(key, _)| key.clone())
        .collect();

    let path = config::resolve_path(ctx.globals.config.as_deref());
    let mut loaded = config::load_or_default(&path)?;
    let existing = loaded
        .get(&args.name)
        .ok_or_else(|| unknown_remote(&args.name))?;

    // Built before the dry-run gate on purpose: a dry run that reported success
    // for a merge that could never be saved would be worse than useless.
    let merged = settings::merge(existing, &assignments)?;

    let report = UpdateReport {
        name: args.name.clone(),
        set,
        removed,
        updated: !ctx.is_dry_run(),
        dry_run: ctx.is_dry_run(),
    };

    if ctx.is_dry_run() {
        ctx.dry_run_notice("update remote", &args.name);
    } else {
        let _displaced = loaded.insert(args.name.clone(), merged);
        config::save(&loaded, &path)?;
        ctx.out.success(format!("updated remote '{}'", args.name));
    }

    emit::records(ctx, std::slice::from_ref(&report), || {
        emit::pairs(
            constants::CONFIG_COLUMN_NAME,
            constants::CONFIG_COLUMN_KEY,
            report
                .set
                .iter()
                .chain(report.removed.iter())
                .map(|key| (report.name.clone(), key.clone()))
                .collect(),
        )
    })
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

    const SAMPLE: &str = "\
[remotes.s3west]
type = \"s3\"
bucket = \"archive\"
region = \"eu-central-1\"
";

    fn written() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, SAMPLE).unwrap();
        (dir, path)
    }

    fn args(name: &str, settings: &[&str]) -> UpdateArgs {
        UpdateArgs {
            name: name.to_string(),
            settings: settings.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    fn flat(path: &Path, name: &str) -> Vec<(String, String)> {
        let loaded = config::load(path).unwrap();
        settings::flatten(loaded.get(name).unwrap())
    }

    #[tokio::test]
    async fn an_update_merges_rather_than_replaces() {
        // The property that makes this safe to run from configuration
        // management: untouched keys survive.
        let (_dir, path) = written();
        run(&ctx(&path, &[]), &args("s3west", &["bucket=cold"]))
            .await
            .unwrap();

        let flat = flat(&path, "s3west");
        assert!(flat.contains(&("bucket".into(), "cold".into())));
        assert!(flat.contains(&("region".into(), "eu-central-1".into())));
        assert!(flat.contains(&("type".into(), "s3".into())));
    }

    #[tokio::test]
    async fn an_empty_value_removes_an_optional_key() {
        let (_dir, path) = written();
        run(&ctx(&path, &[]), &args("s3west", &["region="]))
            .await
            .unwrap();

        let flat = flat(&path, "s3west");
        assert!(!flat.iter().any(|(key, _)| key == "region"));
        assert!(flat.iter().any(|(key, _)| key == "bucket"));
    }

    #[tokio::test]
    async fn removing_a_required_setting_leaves_the_file_untouched() {
        // The failure this prevents: a remote written without its bucket, which
        // no later command could load.
        let (_dir, path) = written();
        let before = std::fs::read(&path).unwrap();
        let error = run(&ctx(&path, &[]), &args("s3west", &["bucket="]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[tokio::test]
    async fn a_numeric_setting_is_stored_as_a_number() {
        // `chunk_size=4194304` arrives from the shell as text and must not be
        // written as a quoted string the loader would then reject.
        let (_dir, path) = written();
        run(&ctx(&path, &[]), &args("s3west", &["chunk_size=4194304"]))
            .await
            .unwrap();
        assert_eq!(
            config::load(&path)
                .unwrap()
                .get("s3west")
                .unwrap()
                .chunk_size(),
            Some(4_194_304)
        );
    }

    #[tokio::test]
    async fn a_dry_run_leaves_the_file_byte_identical() {
        let (_dir, path) = written();
        let before = std::fs::read(&path).unwrap();
        run(
            &ctx(&path, &["--dry-run"]),
            &args("s3west", &["bucket=cold"]),
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[tokio::test]
    async fn an_unknown_remote_is_never_created_by_accident() {
        let (_dir, path) = written();
        let error = run(&ctx(&path, &[]), &args("s3wesr", &["bucket=cold"]))
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            config::ConfigError::UnknownRemote("s3wesr".to_string()).exit_code()
        );
        assert!(!config::load(&path).unwrap().contains("s3wesr"));
    }

    #[tokio::test]
    async fn an_update_with_nothing_to_do_is_a_usage_error() {
        // Silently succeeding would make a scripted typo look like a change.
        let (_dir, path) = written();
        let error = run(&ctx(&path, &[]), &args("s3west", &[]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some());
    }

    #[tokio::test]
    async fn a_malformed_setting_changes_nothing() {
        let (_dir, path) = written();
        let before = std::fs::read(&path).unwrap();
        assert!(
            run(&ctx(&path, &[]), &args("s3west", &["bucket"]))
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[tokio::test]
    async fn an_update_may_not_move_a_plain_remote_onto_a_vaults_object_store() {
        // The other half of the `require_vault` rule. `create` refuses a new
        // plain remote at a guarded location; `update` has to refuse *moving*
        // one there, or the rule is one command away from being routed around.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[remotes.archive-store]\ntype = \"local\"\npath = \"/srv/vault\"\n\
             require_vault = true\n\
             [remotes.archive]\ntype = \"vault\"\nbase = \"archive-store\"\n\
             [remotes.scratch]\ntype = \"local\"\npath = \"/srv/other\"\n",
        )
        .unwrap();
        let before = std::fs::read(&path).unwrap();

        let error = run(&ctx(&path, &[]), &args("scratch", &["path=/srv/vault"]))
            .await
            .unwrap_err();

        assert!(error.message().contains("scratch"), "{}", error.message());
        assert!(
            error.message().contains("archive-store"),
            "the refusal must name the remote that guards the location: {}",
            error.message()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[tokio::test]
    async fn a_credential_offered_as_a_setting_is_refused() {
        let (_dir, path) = written();
        let before = std::fs::read(&path).unwrap();
        let error = run(&ctx(&path, &[]), &args("s3west", &["secret_key=wJalrX"]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(!error.message().contains("wJalrX"), "{}", error.message());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn the_report_separates_settings_that_were_removed() {
        // A caller diffing configuration needs to know which keys went, not
        // just that something changed.
        let report = UpdateReport {
            name: "s3west".into(),
            set: vec!["bucket".into()],
            removed: vec!["region".into()],
            updated: true,
            dry_run: false,
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["set"][0], "bucket");
        assert_eq!(json["removed"][0], "region");
        assert_eq!(json["updated"], true);
    }

    #[test]
    fn a_dry_run_report_never_claims_the_file_was_written() {
        let report = UpdateReport {
            name: "s3west".into(),
            set: vec!["bucket".into()],
            removed: Vec::new(),
            updated: false,
            dry_run: true,
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["updated"], false);
        assert_eq!(json["dry_run"], true);
    }

    #[tokio::test]
    async fn every_format_is_supported() {
        for format in ["text", "json", "json-lines"] {
            let (_dir, path) = written();
            assert!(
                run(
                    &ctx(&path, &["--format", format]),
                    &args("s3west", &["bucket=cold"])
                )
                .await
                .is_ok(),
                "{format} failed"
            );
        }
    }
}
