//! `dctl config create NAME TYPE [key=value ...]` — add a remote.
//!
//! Non-interactive by design. rclone's `config` is a questionnaire, which is
//! excellent on a laptop and useless in a provisioning script;
//! [the plan](https://doc.dctl.sh/project/plan) §14 requires DCTL to be
//! configurable with no interactive step at all, so a remote is created in one
//! command whose arguments a configuration-management tool can generate.
//!
//! Two refusals are worth their inconvenience:
//!
//! * An existing remote of the same name is **not** silently replaced without
//!   `--force`. Rewriting `vault` because a script re-ran would repoint every
//!   path in every other script that mentions it.
//! * A remote that would not load again is rejected before anything is written.
//!   The settings are turned into a real [`RemoteDef`](crate::config::RemoteDef)
//!   first, so a missing `bucket` or a setting the provider does not define
//!   fails here rather than at 3am in a backup job.
//!
//! Credentials are not accepted as settings and would not work if they were: the
//! configuration model has no field that could hold one, so `app_key=…` is
//! refused with the offending key named
//! ([the plan](https://doc.dctl.sh/project/plan) §14).

use clap::Args;
use serde::Serialize;

use super::emit;
use super::settings;
use crate::config;
use crate::constants;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

/// Arguments for `dctl config create`.
#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Name for the new remote, as used in 'NAME:PATH'.
    #[arg(value_name = "NAME")]
    pub name: String,

    /// Provider type. See `dctl config providers`.
    #[arg(value_name = "TYPE")]
    pub remote_type: String,

    /// Settings, written 'key=value'. Repeatable.
    #[arg(value_name = "KEY=VALUE")]
    pub settings: Vec<String>,
}

/// What `create` reports having done.
#[derive(Debug, Serialize)]
struct CreateReport {
    name: String,
    #[serde(rename = "type")]
    kind: &'static str,
    /// Setting keys written. **Keys only.** A value typed on a command line is
    /// already visible to every process on the machine; echoing it into a JSON
    /// record would spread it into logs as well.
    keys: Vec<String>,
    /// Whether the remote now exists. False for a dry run, always.
    created: bool,
    dry_run: bool,
}

/// Create a remote.
///
/// # Errors
/// [`ExitCode::Usage`] for a bad name, an unknown type, a malformed
/// `key=value`, a set of settings that is not a usable remote, or a name that
/// is already taken without `--force`.
pub async fn run(ctx: &Ctx, args: &CreateArgs) -> Result<()> {
    // Name rules come from the configuration layer, not from here: a second
    // copy would drift from what the file itself accepts on load.
    config::validate_remote_name(&args.name)?;
    refuse_drive_letter(&args.name)?;

    let assignments = settings::parse_assignments(&args.settings)?;
    let remote = settings::build(&args.remote_type, &assignments)?;

    let path = config::resolve_path(ctx.globals.config.as_deref());
    let mut loaded = config::load_or_default(&path)?;

    if loaded.contains(&args.name) && !ctx.globals.force {
        return Err(CliError::new(
            ExitCode::Usage,
            format!("remote '{}' already exists", args.name),
        )
        .with_hint(
            "Change one setting with `dctl config update`, or pass --force to \
             replace the whole section.",
        ));
    }

    let report = CreateReport {
        name: args.name.clone(),
        kind: remote.type_name(),
        keys: settings::flatten(&remote)
            .into_iter()
            .map(|(key, _)| key)
            .collect(),
        created: !ctx.is_dry_run(),
        dry_run: ctx.is_dry_run(),
    };

    if ctx.is_dry_run() {
        ctx.dry_run_notice("create remote", &args.name);
    } else {
        let _displaced = loaded.insert(args.name.clone(), remote);
        config::save(&loaded, &path)?;
        ctx.out.success(format!("created remote '{}'", args.name));
    }

    emit::records(ctx, std::slice::from_ref(&report), || {
        emit::pairs(
            constants::CONFIG_COLUMN_NAME,
            constants::CONFIG_COLUMN_TYPE,
            vec![(report.name.clone(), report.kind.to_string())],
        )
    })
}

/// Refuse a name that this machine's own path syntax would take away.
///
/// The one platform-dependent rule in the naming layer, and it lives at
/// *creation* rather than at load so a configuration stays portable: a file
/// written on Linux with a remote called `r` opens on Windows, is listed, and
/// can be repaired — it simply cannot be reached as `r:`, because there `r:` is
/// the R: drive. rclone draws the line in the same place, and this is the
/// non-interactive equivalent.
///
/// # Errors
/// [`ExitCode::Usage`] naming the drive the name would collide with.
fn refuse_drive_letter(name: &str) -> Result<()> {
    refuse_drive_letter_on(name, constants::DRIVE_LETTERS_EXIST)
}

/// [`refuse_drive_letter`], with the platform stated rather than compiled in.
///
/// # Errors
/// [`ExitCode::Usage`] naming the drive the name would collide with.
fn refuse_drive_letter_on(name: &str, drive_letters: bool) -> Result<()> {
    if !config::drive_letter_conflict(name, drive_letters) {
        return Ok(());
    }
    Err(CliError::new(
        ExitCode::Usage,
        format!(
            "'{name}' is a drive letter on this platform, so a remote called \
                 '{name}' could never be addressed"
        ),
    )
    .with_hint(format!(
        "'{name}{}' names the {}{} drive before any configuration is consulted. \
             Choose a longer name. A configuration written on a platform without \
             drive letters may still contain this name and will load here.",
        constants::REMOTE_SEPARATOR,
        name.to_ascii_uppercase(),
        constants::REMOTE_SEPARATOR,
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

    fn empty() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        (dir, path)
    }

    fn args(name: &str, remote_type: &str, settings: &[&str]) -> CreateArgs {
        CreateArgs {
            name: name.to_string(),
            remote_type: remote_type.to_string(),
            settings: settings.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[tokio::test]
    async fn a_remote_is_written_and_loads_back() {
        let (_dir, path) = empty();
        let ctx = ctx(&path, &[]);
        run(&ctx, &args("b2prod", "b2", &["bucket=photos"]))
            .await
            .unwrap();

        let loaded = config::load(&path).unwrap();
        let remote = loaded.get("b2prod").unwrap();
        assert_eq!(remote.type_name(), "b2");
        assert!(settings::flatten(remote).contains(&("bucket".into(), "photos".into())));
    }

    #[tokio::test]
    async fn a_vault_remote_can_wrap_one_that_already_exists() {
        // The worked example from [the plan](https://doc.dctl.sh/project/plan)
        // §14, built one command at a time.
        let (_dir, path) = empty();
        let ctx = ctx(&path, &[]);
        run(&ctx, &args("b2prod", "b2", &["bucket=photos"]))
            .await
            .unwrap();
        run(&ctx, &args("vault", "vault", &["base=b2prod"]))
            .await
            .unwrap();

        let loaded = config::load(&path).unwrap();
        assert_eq!(
            config::vault_chain(&loaded, "vault").unwrap(),
            ["vault", "b2prod"]
        );
    }

    #[tokio::test]
    async fn a_vault_remote_naming_a_base_that_does_not_exist_is_refused() {
        // Validation runs before save, so the dangling reference never reaches
        // the file — and the next command does not fail on somebody else's typo.
        let (_dir, path) = empty();
        let ctx = ctx(&path, &[]);
        assert!(
            run(&ctx, &args("vault", "vault", &["base=nope"]))
                .await
                .is_err()
        );
        assert!(!path.exists() || config::load_or_default(&path).unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_dry_run_writes_nothing_at_all() {
        let (_dir, path) = empty();
        let ctx = ctx(&path, &["--dry-run"]);
        run(&ctx, &args("b2prod", "b2", &["bucket=photos"]))
            .await
            .unwrap();
        assert!(!path.exists(), "--dry-run must not create the config file");
    }

    #[test]
    fn a_dry_run_never_reports_the_remote_as_created() {
        // The report is what a script reads; it must not claim work that a dry
        // run deliberately skipped.
        let report = CreateReport {
            name: "b2prod".into(),
            kind: "b2",
            keys: vec!["bucket".into(), "type".into()],
            created: false,
            dry_run: true,
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["created"], false);
        assert_eq!(json["dry_run"], true);
    }

    #[tokio::test]
    async fn an_existing_name_is_not_silently_replaced() {
        let (_dir, path) = empty();
        let ctx = ctx(&path, &[]);
        run(&ctx, &args("b2prod", "b2", &["bucket=photos"]))
            .await
            .unwrap();

        let error = run(&ctx, &args("b2prod", "b2", &["bucket=films"]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);

        // The original survives the refusal.
        let loaded = config::load(&path).unwrap();
        assert!(
            settings::flatten(loaded.get("b2prod").unwrap())
                .contains(&("bucket".into(), "photos".into()))
        );
    }

    #[tokio::test]
    async fn force_replaces_the_whole_section() {
        let (_dir, path) = empty();
        run(
            &ctx(&path, &[]),
            &args("s3west", "s3", &["bucket=archive", "region=eu-central-1"]),
        )
        .await
        .unwrap();
        run(
            &ctx(&path, &["--force"]),
            &args("s3west", "s3", &["bucket=cold"]),
        )
        .await
        .unwrap();

        let loaded = config::load(&path).unwrap();
        let flat = settings::flatten(loaded.get("s3west").unwrap());
        assert!(flat.contains(&("bucket".into(), "cold".into())));
        // Replaced, not merged: the region the first command set is gone.
        assert!(!flat.iter().any(|(key, _)| key == "region"));
    }

    #[tokio::test]
    async fn an_unknown_type_is_caught_before_anything_is_written() {
        let (_dir, path) = empty();
        let ctx = ctx(&path, &[]);
        let error = run(&ctx, &args("b2prod", "dropbux", &[]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().unwrap_or_default().contains("b2"));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn an_unusable_name_is_rejected_before_anything_is_written() {
        let (_dir, path) = empty();
        let ctx = ctx(&path, &[]);
        for name in ["b2:prod", "a/b", "my remote", ".hidden"] {
            assert!(
                run(&ctx, &args(name, "b2", &["bucket=x"])).await.is_err(),
                "'{name}' was accepted"
            );
        }
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn a_one_character_name_is_created_where_no_drive_could_shadow_it() {
        // rclone accepts the name and addresses it off Windows; refusing it here
        // was the whole of the gap. The Windows half is asserted below through
        // the stated-platform entry point, because this suite runs on Linux.
        let (_dir, path) = empty();
        let ctx = ctx(&path, &[]);
        let outcome = run(&ctx, &args("r", "b2", &["bucket=x"])).await;
        if config::drive_letter_conflict("r", constants::DRIVE_LETTERS_EXIST) {
            let error = outcome.expect_err("a drive letter must be refused where drives exist");
            assert_eq!(error.code(), ExitCode::Usage);
            assert!(error.hint().unwrap_or_default().contains("drive"));
        } else {
            outcome.expect("a one-character remote must be creatable off Windows");
            assert!(config::load(&path).unwrap().get("r").is_some());
        }
    }

    #[test]
    fn the_drive_letter_refusal_names_the_drive_and_the_way_out() {
        // Asserted through the rule rather than through `run`, so the Windows
        // behaviour is exercised by a test run on any machine — the failure mode
        // of a cfg-gated rule is that only one half is ever executed.
        assert!(config::drive_letter_conflict("r", true));
        assert!(!config::drive_letter_conflict("r2", true));
        let error = refuse_drive_letter_on("r", true).expect_err("must be refused");
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("drive letter"), "{error}");
        let hint = error.hint().unwrap_or_default();
        assert!(hint.contains("R:"), "the hint must name the drive: {hint}");
        assert!(hint.contains("longer name"), "{hint}");
        // Off Windows the same name passes untouched.
        assert!(refuse_drive_letter_on("r", false).is_ok());
    }

    #[tokio::test]
    async fn a_malformed_setting_is_rejected_before_anything_is_written() {
        let (_dir, path) = empty();
        let ctx = ctx(&path, &[]);
        let error = run(&ctx, &args("b2prod", "b2", &["bucket"]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn a_credential_offered_as_a_setting_is_refused_by_name() {
        // The rclone habit [the plan](https://doc.dctl.sh/project/plan) §14
        // exists to break, attempted through the command line rather than through
        // the file.
        let (_dir, path) = empty();
        let ctx = ctx(&path, &[]);
        let error = run(
            &ctx,
            &args("b2prod", "b2", &["bucket=photos", "app_key=K001secret"]),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("app_key"), "{}", error.message());
        assert!(!path.exists());
        // And the value itself must not be echoed back in the failure.
        assert!(
            !error.message().contains("K001secret"),
            "{}",
            error.message()
        );
    }

    #[tokio::test]
    async fn a_plain_remote_may_not_be_created_at_a_vaults_object_store() {
        // `require_vault` enforced at the earliest possible moment: when the
        // configuration naming the second remote is written, not hours later
        // when a transfer reaches it. Two readings of one directory is how
        // plaintext ends up sitting beside the ciphertext it should have become.
        let (_dir, path) = empty();
        let ctx = ctx(&path, &[]);
        run(
            &ctx,
            &args(
                "archive-store",
                "local",
                &["path=/srv/vault", "require_vault=true"],
            ),
        )
        .await
        .unwrap();
        let before = std::fs::read(&path).unwrap();

        let error = run(&ctx, &args("scratch", "local", &["path=/srv/vault"]))
            .await
            .unwrap_err();

        assert!(
            error.message().contains("archive-store"),
            "{}",
            error.message()
        );
        assert!(
            error.message().contains("/srv/vault"),
            "{}",
            error.message()
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "a refused create must leave the file byte-identical"
        );

        // A *different* location is untouched by the rule, and a vault remote
        // over the store is exactly what the declaration invites.
        assert!(
            run(&ctx, &args("scratch", "local", &["path=/srv/other"]))
                .await
                .is_ok()
        );
        assert!(
            run(&ctx, &args("archive", "vault", &["base=archive-store"]))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_remote_missing_a_required_setting_is_refused() {
        let (_dir, path) = empty();
        let ctx = ctx(&path, &[]);
        assert!(run(&ctx, &args("b2prod", "b2", &[])).await.is_err());
        assert!(!path.exists());
    }

    #[test]
    fn the_report_carries_setting_keys_but_never_their_values() {
        let report = CreateReport {
            name: "b2prod".into(),
            kind: "b2",
            keys: vec!["bucket".into(), "type".into()],
            created: true,
            dry_run: false,
        };
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(encoded.contains("bucket"));
        assert!(!encoded.contains("photos"));
    }

    #[tokio::test]
    async fn every_format_is_supported() {
        for format in ["text", "json", "json-lines"] {
            let (_dir, path) = empty();
            let ctx = ctx(&path, &["--format", format]);
            assert!(
                run(&ctx, &args("b2prod", "b2", &["bucket=photos"]))
                    .await
                    .is_ok(),
                "{format} failed"
            );
        }
    }
}
