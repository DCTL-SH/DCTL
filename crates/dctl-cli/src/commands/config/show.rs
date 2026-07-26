//! `dctl config show NAME` — one remote's settings.
//!
//! **This command must never print a secret** (`PLAN.md` §14). It is the one a
//! user runs when something is wrong, and therefore the one whose output ends up
//! in a screenshot, a chat message or an issue tracker.
//!
//! [`crate::config`] already makes a credential in the file impossible to load:
//! there is no field on a [`RemoteDef`](crate::config::RemoteDef) that could
//! hold one, and a pasted-in `secret_key` is refused rather than ignored. This
//! command does **not** rely on that. Every value still goes through
//! [`super::secrets::render`] on its way out, because the two guarantees fail in
//! different ways: the loader protects the file's *schema*, and this protects
//! the *rendering* — including of a value that is perfectly legal in a legal
//! field, such as an endpoint someone wrote with a password in its authority.
//!
//! Defence in depth is the point. If either layer is weakened by a later change,
//! the other still holds.

use clap::Args;
use serde::Serialize;

use super::emit;
use super::secrets::{self, Reason};
use super::settings::{self, unknown_remote};
use crate::config;
use crate::constants;
use crate::ctx::Ctx;
use crate::error::Result;

/// Arguments for `dctl config show`.
#[derive(Args, Debug)]
pub struct ShowArgs {
    /// Remote to show.
    #[arg(value_name = "NAME")]
    pub name: String,
}

/// One setting, as it may be printed.
///
/// [`SettingRow::value`] is the *rendered* value. There is deliberately no field
/// on this type carrying the original, so no future change to the serialisation
/// can leak one.
#[derive(Debug, Serialize)]
struct SettingRow {
    remote: String,
    key: String,
    value: String,
    /// Whether [`SettingRow::value`] stands in for something withheld.
    redacted: bool,
    /// Which rule hid it. Absent when nothing was hidden.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<Reason>,
}

/// Show one remote's settings, with anything secret-shaped withheld.
///
/// # Errors
/// [`crate::config::ConfigError::UnknownRemote`] when the remote is not
/// configured — classified by the configuration layer, not by this command — a
/// [`crate::config::ConfigError`] for an unusable file, or a stdout failure
/// other than a broken pipe.
pub async fn run(ctx: &Ctx, args: &ShowArgs) -> Result<()> {
    let path = config::resolve_path(ctx.globals.config.as_deref());
    let loaded = config::load_or_default(&path)?;
    let remote = loaded
        .get(&args.name)
        .ok_or_else(|| unknown_remote(&args.name))?;

    let rows = render_rows(&args.name, remote);

    // Loud, because a credential in the config file is a real finding: the value
    // is safe on screen but it is not safe on disk. Naming the rule that fired
    // matters as much as the count — someone who believes the value is harmless
    // needs to know whether it was the key's name or the value's shape that
    // triggered it, or they will conclude the tool is simply broken.
    let hidden = withheld(&rows);
    if !hidden.is_empty() {
        ctx.out.warn(format!(
            "{} value(s) in '{}' were withheld: {}. They do not belong in {} — \
             treat them as exposed and rotate them",
            hidden.len(),
            args.name,
            hidden.join(", "),
            path.display()
        ));
    }

    emit::records(ctx, &rows, || {
        emit::pairs(
            constants::CONFIG_COLUMN_KEY,
            constants::CONFIG_COLUMN_VALUE,
            rows.iter()
                .map(|row| (row.key.clone(), row.value.clone()))
                .collect(),
        )
    })
}

/// The keys that were withheld, each with the rule that hid it.
///
/// Keys and reasons only — never a value, not even a truncated one. The whole
/// point of the warning is that the thing it is about must not be printed.
fn withheld(rows: &[SettingRow]) -> Vec<String> {
    rows.iter()
        .filter_map(|row| {
            row.reason
                .map(|reason| format!("{} ({})", row.key, reason.describe()))
        })
        .collect()
}

/// Flatten a remote and run every value through the redaction policy.
///
/// The single path from a configured remote to something printable. Kept as one
/// function so no format can acquire its own, unredacted, route.
fn render_rows(name: &str, remote: &config::RemoteDef) -> Vec<SettingRow> {
    settings::flatten(remote)
        .into_iter()
        .map(|(key, value)| {
            let rendered = secrets::render(&key, &value);
            SettingRow {
                remote: name.to_string(),
                key,
                redacted: rendered.is_redacted(),
                reason: rendered.reason,
                value: rendered.text,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::config::{B2Def, RemoteDef, S3Def};
    use crate::exit::ExitCode;
    use crate::logging::redact::REDACTED;
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

    fn written(contents: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, contents).unwrap();
        (dir, path)
    }

    const SAMPLE: &str = "\
[remotes.b2prod]
type = \"b2\"
bucket = \"photos\"
";

    /// Everything a *legal* configuration can still carry that must not be
    /// printed. The loader stops a `secret_key` field from existing at all, so
    /// these are the cases that reach this command in practice: a credential
    /// written into an endpoint, and a value that is indistinguishable from a
    /// generated token.
    fn leaky_remote() -> RemoteDef {
        RemoteDef::S3(S3Def {
            bucket: "archive".into(),
            endpoint: Some("https://admin:s3cr3t@minio.internal:9000".into()),
            region: Some("aG9yc2ViYXR0ZXJ5U3RhcGxlMTIzNDU2Nzg5".into()),
            chunk_size: None,
            verify: None,
            require_vault: false,
        })
    }

    /// The strings planted in [`leaky_remote`], as they appear in the file.
    const PLANTED: &[&str] = &["s3cr3t", "aG9yc2ViYXR0ZXJ5U3RhcGxlMTIzNDU2Nzg5"];

    #[test]
    fn a_secret_shaped_value_never_renders_in_any_format() {
        // PLAN.md §14's hard requirement, asserted against both renderings at
        // once: whatever the format, the original text must not survive.
        let rows = render_rows("s3west", &leaky_remote());

        let text: String = rows
            .iter()
            .map(|row| format!("{} {}\n", row.key, row.value))
            .collect();
        let json = serde_json::to_string(&rows).unwrap();

        for secret in PLANTED {
            assert!(!text.contains(secret), "text output leaked '{secret}'");
            assert!(!json.contains(secret), "json output leaked '{secret}'");
        }
    }

    #[test]
    fn a_secret_shaped_key_never_renders_its_value() {
        // The key-name rule, exercised directly: even if a future field were
        // named like a credential, this command would not print its value.
        for key in [
            "password",
            "secret_key",
            "app_key",
            "token",
            "authorization",
        ] {
            let rendered = secrets::render(key, "hunter2");
            assert!(rendered.is_redacted(), "'{key}' was printed in the clear");
            assert_eq!(rendered.text, REDACTED);
        }
    }

    #[test]
    fn the_withheld_values_are_replaced_not_omitted() {
        // Dropping the row would hide the mistake from the person who has to
        // fix it; the key must still be visible.
        let rows = render_rows("s3west", &leaky_remote());
        let endpoint = rows.iter().find(|row| row.key == "endpoint").unwrap();
        assert!(endpoint.redacted);
        assert_eq!(endpoint.value, REDACTED);
        assert_eq!(endpoint.reason, Some(Reason::CredentialUrl));
    }

    #[test]
    fn ordinary_settings_are_shown_in_full() {
        // Over-redaction is the safe failure, but a listing nobody can read is
        // not usable either.
        let rows = render_rows("s3west", &leaky_remote());
        let bucket = rows.iter().find(|row| row.key == "bucket").unwrap();
        assert!(!bucket.redacted);
        assert_eq!(bucket.value, "archive");
        assert!(bucket.reason.is_none());

        let kind = rows.iter().find(|row| row.key == "type").unwrap();
        assert_eq!(kind.value, "s3");
    }

    #[test]
    fn the_warning_names_the_keys_and_the_rules_but_never_a_value() {
        // The warning is *about* a secret, so it is the one line most at risk of
        // printing one.
        let rows = render_rows("s3west", &leaky_remote());
        let notice = withheld(&rows).join(", ");

        assert!(notice.contains("endpoint"), "got: {notice}");
        assert!(
            notice.contains(Reason::CredentialUrl.describe()),
            "got: {notice}"
        );
        for secret in PLANTED {
            assert!(!notice.contains(secret), "the warning leaked '{secret}'");
        }
        // Nothing that was not withheld belongs in it either.
        assert!(!notice.contains("archive"), "got: {notice}");
    }

    #[test]
    fn a_clean_remote_produces_no_warning_at_all() {
        let remote = RemoteDef::B2(B2Def {
            bucket: "photos".into(),
            endpoint: None,
            chunk_size: None,
            verify: None,
            require_vault: false,
        });
        assert!(withheld(&render_rows("b2prod", &remote)).is_empty());
    }

    #[test]
    fn the_row_type_carries_no_field_that_could_hold_the_original() {
        // Structural, not behavioural: a future field named `raw` would defeat
        // every other test here, so the shape is pinned.
        let rows = render_rows("s3west", &leaky_remote());
        let json = serde_json::to_value(&rows[0]).unwrap();
        for field in json.as_object().unwrap().keys() {
            assert!(
                ["remote", "key", "value", "redacted", "reason"].contains(&field.as_str()),
                "unexpected field '{field}' on a rendered setting"
            );
        }
    }

    #[tokio::test]
    async fn a_configured_remote_is_shown() {
        let (_dir, path) = written(SAMPLE);
        let ctx = ctx(&path, &[]);
        assert!(
            run(
                &ctx,
                &ShowArgs {
                    name: "b2prod".into()
                }
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn an_unknown_remote_is_reported_with_the_shared_code_and_a_way_forward() {
        let (_dir, path) = written(SAMPLE);
        let ctx = ctx(&path, &[]);
        let error = run(
            &ctx,
            &ShowArgs {
                name: "nope".into(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.code(),
            config::ConfigError::UnknownRemote("nope".to_string()).exit_code()
        );
        assert_ne!(error.code(), ExitCode::Success);
        assert!(error.hint().unwrap_or_default().contains("config list"));
    }

    #[tokio::test]
    async fn every_format_is_supported() {
        let (_dir, path) = written(SAMPLE);
        for format in ["text", "json", "json-lines"] {
            let ctx = ctx(&path, &["--format", format]);
            assert!(
                run(
                    &ctx,
                    &ShowArgs {
                        name: "b2prod".into()
                    }
                )
                .await
                .is_ok(),
                "{format} failed"
            );
        }
    }

    #[test]
    fn showing_a_remote_does_not_change_the_file() {
        // `dctl config show` writing to the file it displays would be a serious
        // surprise, and this is the cheapest possible guard against it.
        let (_dir, path) = written(SAMPLE);
        let before = std::fs::read(&path).unwrap();
        let loaded = config::load_or_default(&path).unwrap();
        let _ = render_rows("b2prod", loaded.get("b2prod").unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn a_plain_remote_shows_only_the_settings_it_actually_has() {
        // Absent optional settings stay absent rather than printing a
        // placeholder that implies a decision nobody made.
        let remote = RemoteDef::B2(B2Def {
            bucket: "photos".into(),
            endpoint: None,
            chunk_size: None,
            verify: None,
            require_vault: false,
        });
        let keys: Vec<String> = render_rows("b2prod", &remote)
            .into_iter()
            .map(|row| row.key)
            .collect();
        assert!(keys.contains(&"type".to_string()));
        assert!(keys.contains(&"bucket".to_string()));
        assert!(!keys.contains(&"endpoint".to_string()));
    }

    #[test]
    fn the_path_type_is_used_rather_than_reimplemented() {
        // `--config` resolution lives in crate::config; a second copy here
        // would drift from DCTL_CONFIG's precedence rules.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("elsewhere.toml");
        let ctx = ctx(&path, &[]);
        assert_eq!(
            config::resolve_path(ctx.globals.config.as_deref()),
            PathBuf::from(&path)
        );
    }
}
