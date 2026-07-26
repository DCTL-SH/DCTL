//! `dctl config redact` — the whole configuration, safe to share.
//!
//! The command to run before pasting a configuration into a bug report, a
//! support ticket or a chat message. [`super::show`] applies the same rules to
//! one remote; this applies them to every remote at once, which is what someone
//! diagnosing "my sync stopped working" actually needs to see.
//!
//! It is deliberately **not** a TOML dump. Reproducing the file's own syntax
//! would invite pasting the output back over a working config, and a
//! configuration in which four values have been replaced by `<redacted>` is
//! worse than none at all. The output is a listing — remote, key, value —
//! obviously a report rather than a file.
//!
//! Same guarantee as `show`, for the same reason: every value goes through
//! [`super::secrets::render`], so there is no path through this command that can
//! print a credential.

use serde::Serialize;

use super::emit;
use super::secrets::{self, Reason};
use super::settings;
use crate::config;
use crate::constants;
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::{Align, Border, Column, Table};

/// One setting from anywhere in the configuration, as it may be printed.
#[derive(Debug, Serialize)]
struct RedactedRow {
    remote: String,
    key: String,
    /// The rendered value. As in [`super::show`], there is no field on this type
    /// carrying the original.
    value: String,
    redacted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<Reason>,
}

/// Print the whole configuration with every secret-shaped value withheld.
///
/// # Errors
/// A [`crate::config::ConfigError`] for an unusable file, or a stdout failure
/// other than a broken pipe.
pub async fn run(ctx: &Ctx) -> Result<()> {
    let path = config::resolve_path(ctx.globals.config.as_deref());
    let loaded = config::load_or_default(&path)?;
    let rows = render_rows(&loaded);

    // Keys and reasons only, never a value: the warning is *about* a secret, so
    // it is the one line most at risk of printing one.
    let hidden: Vec<String> = rows
        .iter()
        .filter_map(|row| {
            row.reason
                .map(|reason| format!("{}.{} ({})", row.remote, row.key, reason.describe()))
        })
        .collect();

    if !hidden.is_empty() {
        ctx.out.warn(format!(
            "{} value(s) were withheld from this report: {}. They do not belong \
             in {} — treat them as exposed",
            hidden.len(),
            hidden.join(", "),
            path.display()
        ));
    } else {
        // Worth saying explicitly: the point of the command is the reassurance,
        // and silence would leave the user guessing whether it had checked.
        ctx.out.info(format!(
            "{} contains nothing secret-shaped; this report is safe to share",
            path.display()
        ));
    }

    emit::records(ctx, &rows, || {
        let mut table = Table::new(vec![
            Column::new(constants::CONFIG_COLUMN_NAME, Align::Left),
            Column::new(constants::CONFIG_COLUMN_KEY, Align::Left),
            Column::new(constants::CONFIG_COLUMN_VALUE, Align::Left),
        ])
        .with_border(Border::None);

        for row in &rows {
            table.push(vec![row.remote.clone(), row.key.clone(), row.value.clone()]);
        }
        table
    })
}

/// Flatten every remote and run every value through the redaction policy.
///
/// The single path from a loaded configuration to something printable, so no
/// format can acquire its own unredacted route.
fn render_rows(loaded: &config::Config) -> Vec<RedactedRow> {
    loaded
        .remotes
        .iter()
        .flat_map(|(name, remote)| {
            settings::flatten(remote)
                .into_iter()
                .map(move |(key, value)| {
                    let rendered = secrets::render(&key, &value);
                    RedactedRow {
                        remote: name.clone(),
                        key,
                        redacted: rendered.is_redacted(),
                        reason: rendered.reason,
                        value: rendered.text,
                    }
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::config::{Config, R2Def, RemoteDef, S3Def, VaultDef};
    use crate::logging::redact::REDACTED;
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

    /// A configuration that is entirely *legal* — every value sits in a field
    /// the model defines — and still carries two things that must never be
    /// printed, in two different sections.
    fn leaky() -> Config {
        let mut config = Config::default();
        config.insert(
            "s3west",
            RemoteDef::S3(S3Def {
                bucket: "archive".into(),
                endpoint: Some("https://root:letmein@minio.internal:9000".into()),
                region: Some("eu-central-1".into()),
                chunk_size: None,
                verify: None,
                require_vault: false,
            }),
        );
        config.insert(
            "r2cold",
            RemoteDef::R2(R2Def {
                bucket: "cold".into(),
                account: Some("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY".into()),
                endpoint: None,
                chunk_size: None,
                verify: None,
                require_vault: false,
            }),
        );
        config
    }

    /// The strings planted in [`leaky`], as they appear in the file.
    const PLANTED: &[&str] = &["letmein", "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"];

    #[test]
    fn no_secret_survives_into_any_rendering() {
        // The reason this command exists: its output is pasted into places its
        // author does not control.
        let rows = render_rows(&leaky());

        let text: String = rows
            .iter()
            .map(|row| format!("{} {} {}\n", row.remote, row.key, row.value))
            .collect();
        let json = serde_json::to_string(&rows).unwrap();

        for secret in PLANTED {
            assert!(!text.contains(secret), "text output leaked '{secret}'");
            assert!(!json.contains(secret), "json output leaked '{secret}'");
        }
    }

    #[test]
    fn redaction_applies_across_every_remote_not_just_the_first() {
        let rows = render_rows(&leaky());
        let hidden: Vec<&RedactedRow> = rows.iter().filter(|row| row.redacted).collect();
        let remotes: Vec<&str> = hidden.iter().map(|row| row.remote.as_str()).collect();

        assert!(remotes.contains(&"s3west"), "got: {remotes:?}");
        assert!(remotes.contains(&"r2cold"), "got: {remotes:?}");
        assert!(hidden.iter().all(|row| row.value == REDACTED));
    }

    #[test]
    fn ordinary_settings_are_still_readable() {
        // A report in which everything is <redacted> helps nobody diagnose
        // anything, so over-redaction has a limit too.
        let rows = render_rows(&leaky());
        let region = rows
            .iter()
            .find(|row| row.remote == "s3west" && row.key == "region")
            .unwrap();
        assert!(!region.redacted);
        assert_eq!(region.value, "eu-central-1");

        let bucket = rows
            .iter()
            .find(|row| row.remote == "r2cold" && row.key == "bucket")
            .unwrap();
        assert_eq!(bucket.value, "cold");
    }

    #[test]
    fn every_row_names_the_remote_it_came_from() {
        // Without it a JSON Lines stream would be a pile of unattributed keys.
        for row in render_rows(&leaky()) {
            assert!(!row.remote.is_empty());
            assert!(!row.key.is_empty());
        }
    }

    #[test]
    fn a_vault_remote_reports_its_base_in_the_clear() {
        // A base is a remote *name*, never a credential, and hiding it would
        // make the report useless for exactly the problem it is run on.
        let mut config = Config::default();
        config.insert(
            "vault",
            RemoteDef::Vault(VaultDef {
                base: "s3west".into(),
                base_path: None,
                chunk_size: None,
                verify: None,
            }),
        );
        let rows = render_rows(&config);
        let base = rows.iter().find(|row| row.key == "base").unwrap();
        assert!(!base.redacted);
        assert_eq!(base.value, "s3west");
    }

    #[tokio::test]
    async fn an_absent_configuration_reports_nothing_and_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            run(&ctx(&dir.path().join("absent.toml"), &[]))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn every_format_is_supported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        config::save(&leaky(), &path).unwrap();

        for format in ["text", "json", "json-lines"] {
            assert!(
                run(&ctx(&path, &["--format", format])).await.is_ok(),
                "{format} failed"
            );
        }
    }

    #[tokio::test]
    async fn the_report_never_changes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        config::save(&leaky(), &path).unwrap();
        let before = std::fs::read(&path).unwrap();

        run(&ctx(&path, &[])).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
