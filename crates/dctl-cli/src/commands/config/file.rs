//! `dctl config file` — print the path of the configuration file.
//!
//! Exists to be substituted into other commands: `$(dctl config file)` is how a
//! script, a dotfile installer or a support request finds the file without
//! hard-coding a path and getting it wrong when `DCTL_HOME` is set, or when one of
//! them wrong.
//!
//! Because it is meant for substitution, the path is the **only** thing on
//! stdout — one line, no label, no decoration. Whether the file exists, and
//! whether its permissions are too loose, are notes on stderr, where they cannot
//! end up inside the command substitution.

use serde::Serialize;

use super::emit;
use crate::config;
use crate::ctx::Ctx;
use crate::error::Result;

/// Where the configuration lives, and what state it is in.
#[derive(Debug, Serialize)]
struct FileReport {
    path: String,
    exists: bool,
    /// Permission bits that let somebody other than the owner read it, as an
    /// octal string. Absent when the file is owner-only, missing, or on a
    /// platform where access is an ACL rather than a mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    exposed_mode: Option<String>,
}

/// Print the configuration file path.
///
/// # Errors
/// A stdout failure other than a broken pipe.
pub async fn run(ctx: &Ctx) -> Result<()> {
    let path = config::resolve_path(ctx.globals.config.as_deref());
    let exists = path.exists();
    let exposed = config::exposed_permission_bits(&path);

    let report = FileReport {
        path: path.display().to_string(),
        exists,
        exposed_mode: exposed.map(|bits| format!("{bits:04o}")),
    };

    // Both notes go to stderr: neither may end up inside `$(dctl config file)`.
    if !exists {
        ctx.out.info(format!(
            "{} does not exist yet; `dctl config touch` creates it",
            report.path
        ));
    } else if let Some(bits) = &report.exposed_mode {
        ctx.out.warn(format!(
            "{} is readable beyond its owner (extra bits {bits}); it names your \
             buckets and endpoints",
            report.path
        ));
    }

    emit::one(ctx, &report, || report.path.clone())
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

    #[tokio::test]
    async fn a_missing_file_is_reported_without_failing() {
        // The command answers "where would it be", which has an answer whether
        // or not the file exists.
        let dir = tempfile::tempdir().unwrap();
        assert!(
            run(&ctx(&dir.path().join("absent.toml"), &[]))
                .await
                .is_ok()
        );
    }

    #[test]
    fn the_reported_path_is_the_one_the_flag_named() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("elsewhere.toml");
        let ctx = ctx(&path, &[]);
        assert_eq!(
            config::resolve_path(ctx.globals.config.as_deref()),
            PathBuf::from(&path)
        );
    }

    #[test]
    fn the_default_path_comes_from_the_platform_not_this_crate() {
        // Hard-coding ~/.config here would be wrong on macOS and Windows both.
        let globals = Harness::parse_from(["dctl"]).globals;
        let ctx = Ctx::new(globals);
        assert_eq!(
            config::resolve_path(ctx.globals.config.as_deref()),
            dctl_meta::paths::config_file()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_world_readable_file_is_flagged_without_failing() {
        // A warning, not a refusal: the file holds no secrets by design, so
        // refusing to print its path would be a false alarm dressed as an error.
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert!(config::exposed_permission_bits(&path).is_some());
        assert!(run(&ctx(&path, &[])).await.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn an_owner_only_file_is_not_flagged() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(config::exposed_permission_bits(&path).is_none());
    }

    #[test]
    fn the_exposed_mode_is_reported_in_octal_or_not_at_all() {
        // `0644` is the spelling a user would type into `chmod`; a decimal 420
        // would be unusable advice.
        let report = FileReport {
            path: "/x/config.toml".into(),
            exists: true,
            exposed_mode: Some(format!("{:04o}", 0o044)),
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["exposed_mode"], "0044");

        let clean = FileReport {
            path: "/x/config.toml".into(),
            exists: true,
            exposed_mode: None,
        };
        assert!(
            serde_json::to_value(&clean)
                .unwrap()
                .get("exposed_mode")
                .is_none()
        );
    }

    #[tokio::test]
    async fn every_format_is_supported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "").unwrap();
        for format in ["text", "json", "json-lines"] {
            assert!(
                run(&ctx(&path, &["--format", format])).await.is_ok(),
                "{format} failed"
            );
        }
    }
}
