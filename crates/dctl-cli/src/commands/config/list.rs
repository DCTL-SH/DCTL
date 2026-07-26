//! `dctl config list` — the configured remotes, one per line.
//!
//! Deliberately two narrow columns: the name and the type. A listing is what a
//! script greps and what a person scans, so the settings behind a name are
//! [`super::show`]'s job, where the redaction rules apply.
//!
//! Prints nothing at all when nothing is configured, rather than a header with
//! no rows under it — an empty table reads as a malfunction. The count goes to
//! stderr, where it cannot reach a pipeline.
//!
//! A vault remote also reports what it wraps, because "which of these actually
//! encrypts, and over what" is the question a listing is usually being asked.

use serde::Serialize;

use super::emit;
use crate::config;
use crate::constants;
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::{Align, Border, Column, Table};

/// One configured remote.
#[derive(Debug, Serialize)]
struct RemoteRow {
    name: String,
    #[serde(rename = "type")]
    kind: &'static str,
    /// The remote this one wraps, for a vault remote. `None` for anything that
    /// stores bytes itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    base: Option<String>,
}

/// List the configured remotes.
///
/// # Errors
/// A damaged or credential-bearing configuration file, or a stdout failure
/// other than a broken pipe.
pub async fn run(ctx: &Ctx) -> Result<()> {
    let path = config::resolve_path(ctx.globals.config.as_deref());
    let loaded = config::load_or_default(&path)?;

    let rows: Vec<RemoteRow> = loaded
        .remotes
        .iter()
        .map(|(name, remote)| RemoteRow {
            name: name.clone(),
            kind: remote.type_name(),
            base: remote.base().map(str::to_string),
        })
        .collect();

    if rows.is_empty() {
        // On stderr: a fresh installation is not an error, and this note must
        // not appear in a pipeline that expected only remote names.
        ctx.out
            .info(format!("no remotes configured in {}", path.display()));
    }

    emit::records(ctx, &rows, || {
        let mut table = Table::new(vec![
            Column::new(constants::CONFIG_COLUMN_NAME, Align::Left),
            Column::new(constants::CONFIG_COLUMN_TYPE, Align::Left),
            Column::new(constants::CONFIG_KEY_BASE, Align::Left),
        ])
        .with_border(Border::None);

        for row in &rows {
            table.push(vec![
                row.name.clone(),
                row.kind.to_string(),
                row.base
                    .clone()
                    .unwrap_or_else(|| constants::UNKNOWN_VALUE.to_string()),
            ]);
        }
        table
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::config::RemoteDef;
    use crate::exit::ExitCode;
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

[remotes.vault]
type = \"vault\"
base = \"b2prod\"
";

    #[tokio::test]
    async fn an_absent_configuration_lists_nothing_and_succeeds() {
        // A fresh machine has no config file. PLAN.md §14 makes that supported,
        // not broken.
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx(&dir.path().join("absent.toml"), &[]);
        assert!(run(&ctx).await.is_ok());
    }

    #[tokio::test]
    async fn remotes_are_listed_in_every_format() {
        let (_dir, path) = written(SAMPLE);
        for format in ["text", "json", "json-lines"] {
            assert!(
                run(&ctx(&path, &["--format", format])).await.is_ok(),
                "{format} failed"
            );
        }
    }

    #[tokio::test]
    async fn a_damaged_configuration_fails_loudly_rather_than_listing_nothing() {
        // The failure this prevents: every remote silently disappearing because
        // one line of TOML is malformed.
        let (_dir, path) = written("[remotes.b2prod\n");
        let error = run(&ctx(&path, &[])).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
    }

    #[tokio::test]
    async fn a_credential_in_the_file_stops_the_listing() {
        // Not this command's rule, but it must not route around it: a config
        // holding a secret is refused at load, wherever it is loaded from.
        let (_dir, path) =
            written("[remotes.b2prod]\ntype = \"b2\"\nbucket = \"photos\"\napp_key = \"K001x\"\n");
        assert!(run(&ctx(&path, &[])).await.is_err());
    }

    #[test]
    fn rows_are_built_in_the_files_own_order() {
        // The order the file is written in is the order it is listed in, so a
        // user can follow one against the other.
        let (_dir, path) = written(SAMPLE);
        let loaded = config::load_or_default(&path).unwrap();
        let names: Vec<&str> = loaded.names().collect();
        assert_eq!(names, ["b2prod", "vault"]);
    }

    #[test]
    fn a_vault_remote_reports_what_it_wraps() {
        let (_dir, path) = written(SAMPLE);
        let loaded = config::load_or_default(&path).unwrap();
        let vault = loaded.get("vault").unwrap();
        let row = RemoteRow {
            name: "vault".into(),
            kind: vault.type_name(),
            base: vault.base().map(str::to_string),
        };
        assert_eq!(row.kind, "vault");
        assert_eq!(row.base.as_deref(), Some("b2prod"));
    }

    #[test]
    fn the_json_field_is_spelled_type_not_kind() {
        // `type` is a Rust keyword but it is the config file's own vocabulary,
        // and a JSON consumer must see the word it typed.
        let row = RemoteRow {
            name: "b2prod".into(),
            kind: "b2",
            base: None,
        };
        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(json["type"], "b2");
        assert!(json.get("kind").is_none());
        // A plain remote wraps nothing, and says so by omission rather than by
        // a null a consumer has to special-case.
        assert!(json.get("base").is_none());
    }

    #[test]
    fn a_remote_def_always_has_a_type() {
        // Unlike a hand-parsed document, a loaded RemoteDef cannot be missing
        // its type — the parser refuses a section without one — so the listing
        // never has to print a placeholder for it.
        for remote in [
            RemoteDef::Local(crate::config::LocalDef {
                path: PathBuf::from("/srv"),
                verify: None,
                require_vault: false,
            }),
            RemoteDef::Vault(crate::config::VaultDef {
                base: "b2prod".into(),
                base_path: None,
                chunk_size: None,
                verify: None,
            }),
        ] {
            assert!(!remote.type_name().is_empty());
        }
    }
}
