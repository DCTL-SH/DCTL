//! `dctl config touch` — create the configuration file if it is missing.
//!
//! Two jobs, neither of which sounds like much until the alternative is
//! considered.
//!
//! It **creates the file with the right permissions from the start**. A user who
//! runs `mkdir -p ~/.dctl && $EDITOR ~/.dctl/config.toml` gets whatever their
//! umask says, which on plenty of systems is world-readable; the file then names
//! their buckets and endpoints to every account on the machine. Going through
//! [`crate::config::save`] means owner-only from the first byte rather than
//! after the first `dctl config create`.
//!
//! And it **writes the no-secrets header**, which is the one place a user
//! reliably reads the rule: they are looking at it at the exact moment they are
//! about to paste an application key in (`PLAN.md` §14).
//!
//! Idempotent. An existing file is never rewritten, because doing so would
//! discard comments and formatting that a human put there deliberately.

use serde::Serialize;

use super::emit;
use crate::config::{self, Config};
use crate::constants;
use crate::ctx::Ctx;
use crate::error::Result;

/// What `touch` reports having done.
#[derive(Debug, Serialize)]
struct TouchReport {
    path: String,
    /// Whether *this run* created the file. False when it was already there, so
    /// a provisioning script can tell a fresh install from a re-run.
    created: bool,
    dry_run: bool,
}

/// Create the configuration file if it does not exist.
///
/// # Errors
/// A [`crate::config::ConfigError`] for any filesystem failure along the way.
/// Nothing is left half-written: the file is staged and renamed into place.
pub async fn run(ctx: &Ctx) -> Result<()> {
    let path = config::resolve_path(ctx.globals.config.as_deref());
    let existed = path.exists();

    if existed {
        ctx.out.info(format!(
            "{} already exists; leaving it alone",
            path.display()
        ));
    } else if ctx.is_dry_run() {
        ctx.dry_run_notice("create", &path.display().to_string());
    } else {
        // An empty configuration, saved: the same path every other write takes,
        // so the header and the permissions cannot differ between the two.
        config::save(&Config::default(), &path)?;
        ctx.out.success(format!("created {}", path.display()));
    }

    let report = TouchReport {
        path: path.display().to_string(),
        created: !existed && !ctx.is_dry_run(),
        dry_run: ctx.is_dry_run(),
    };

    emit::records(ctx, std::slice::from_ref(&report), || {
        emit::pairs(
            constants::CONFIG_COLUMN_NAME,
            constants::CONFIG_COLUMN_VALUE,
            vec![(report.path.clone(), report.created.to_string())],
        )
    })
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
    async fn a_missing_file_is_created_along_with_its_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("config.toml");
        run(&ctx(&path, &[])).await.unwrap();
        assert!(path.exists());
    }

    #[tokio::test]
    async fn the_created_file_explains_that_secrets_do_not_belong_in_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        run(&ctx(&path, &[])).await.unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("NON-SECRET"), "got: {text}");
    }

    #[tokio::test]
    async fn the_created_file_loads_back_as_an_empty_configuration() {
        // A file that cannot be read by the next command would be worse than no
        // file at all.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        run(&ctx(&path, &[])).await.unwrap();
        assert!(config::load(&path).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_created_file_is_owner_only_from_the_first_byte() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        run(&ctx(&path, &[])).await.unwrap();
        assert!(
            config::exposed_permission_bits(&path).is_none(),
            "a freshly created config must not be readable by anyone else"
        );
    }

    #[tokio::test]
    async fn an_existing_file_is_never_rewritten() {
        // Comments and formatting are things a human put there on purpose.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let original = "# my notes\n[remotes.b2prod]\ntype = \"b2\"\nbucket = \"photos\"\n";
        std::fs::write(&path, original).unwrap();

        run(&ctx(&path, &[])).await.unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    #[tokio::test]
    async fn a_dry_run_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        run(&ctx(&path, &["--dry-run"])).await.unwrap();
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn touching_twice_is_harmless() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        run(&ctx(&path, &[])).await.unwrap();
        let first = std::fs::read(&path).unwrap();
        run(&ctx(&path, &[])).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), first);
    }

    #[test]
    fn created_describes_this_run_not_the_files_existence() {
        let report = TouchReport {
            path: "/x/config.toml".into(),
            created: false,
            dry_run: false,
        };
        assert_eq!(serde_json::to_value(&report).unwrap()["created"], false);
    }

    #[tokio::test]
    async fn every_format_is_supported() {
        for format in ["text", "json", "json-lines"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("config.toml");
            assert!(
                run(&ctx(&path, &["--format", format])).await.is_ok(),
                "{format} failed"
            );
        }
    }
}
