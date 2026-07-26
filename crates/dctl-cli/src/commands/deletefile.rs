//! `dctl deletefile` — remove exactly one named object.
//!
//! The narrowest command in the removal family, and the only one whose blast
//! radius is a single object no matter what the filters say. Filters are
//! ignored here for the same reason `cp file dest` ignores them: the user
//! named the thing, so there is nothing left to select. It is also the
//! deprecated `dctl rm` alias, which is why it takes no options at all — the
//! prototype's spelling has to keep meaning what it meant.
//!
//! **A directory is an error, not a recursion.** `deletefile vault:photos`
//! must never quietly become a tree removal: that is [`purge`](super::purge)'s
//! job, and confusing the two is how a user loses a decade of photographs
//! meaning to remove one file. The syntactic half of that check runs now — a
//! target written with a trailing separator names a directory, and a bare
//! `REMOTE:` names the root — while the index half (is this path a directory
//! *in the vault*?) needs a listing the engine does not expose yet.
//!
//! ## What runs today
//!
//! Everything except the removal: argument parsing, target resolution, the
//! directory refusal above, the destructive gate and the `--dry-run` plan.
//! `Vault::delete_file` exists, but [`Ctx`] carries no vault handle to call it
//! on, so the command fails with a real exit code rather than reporting a
//! deletion that never happened. See [`super::removal::engine`].

use clap::Args;

use crate::constants::{PATH_SEPARATOR, REMOTE_PATH_VALUE_NAME, REMOVAL_ACTION_DELETE};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};

use super::removal::{NoOptions, Removal, Target, execute};

/// Stable command name. Must match `Command::name()` in `cli/mod.rs`.
const COMMAND: &str = "deletefile";

/// The engine capability this command is waiting on.
const CAPABILITY: &str = "removing a named object from a vault";

/// `dctl deletefile REMOTE:PATH`
#[derive(Args, Debug)]
pub struct DeletefileArgs {
    /// The single object to delete, written REMOTE:PATH. Filters do not apply.
    #[arg(value_name = REMOTE_PATH_VALUE_NAME)]
    pub path: String,
}

/// Run `dctl deletefile`.
///
/// # Errors
/// [`crate::exit::ExitCode::Usage`] for a malformed target or one that names a
/// directory; [`crate::exit::ExitCode::Cancelled`] if the user declines;
/// otherwise the unimplemented refusal described above.
pub async fn run(ctx: &Ctx, args: &DeletefileArgs) -> Result<()> {
    let target = Target::parse(&args.path)?;
    refuse_directories(&args.path, &target)?;

    let removal = Removal {
        command: COMMAND,
        action: REMOVAL_ACTION_DELETE,
        target,
        // Filters cannot narrow a target the user named exactly.
        filters: None,
        options: NoOptions {},
        capability: CAPABILITY,
    };

    execute(ctx, &removal)
}

/// Refuse anything that is syntactically a directory rather than an object.
///
/// The check reads the *raw* argument, not the cleaned target: canonicalisation
/// strips the trailing separator that carries the user's intent, so by the time
/// the path is canonical `vault:photos/` and `vault:photos` are the same string.
fn refuse_directories(raw: &str, target: &Target) -> Result<()> {
    if target.is_root() {
        return Err(
            CliError::usage(format!("'{target}' is a remote, not an object"))
                .with_hint("Name the object to delete, for example 'vault:photos/a.jpg'."),
        );
    }

    if raw.ends_with(PATH_SEPARATOR) || raw.ends_with('\\') {
        return Err(
            CliError::usage(format!("'{raw}' names a directory, not an object")).with_hint(
                "Use `dctl rmdir` for an empty directory, or `dctl purge` to \
                 remove a directory and everything in it.",
            ),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::globals::GlobalArgs;
    use crate::exit::ExitCode;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
        #[command(flatten)]
        args: DeletefileArgs,
    }

    fn parse(args: &[&str]) -> Harness {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()))
    }

    async fn run_with(args: &[&str]) -> Result<()> {
        let parsed = parse(args);
        run(&Ctx::new(parsed.globals), &parsed.args).await
    }

    #[test]
    fn the_object_is_the_only_argument() {
        assert_eq!(parse(&["vault:a.jpg"]).args.path, "vault:a.jpg");
        assert!(Harness::try_parse_from(["dctl"]).is_err());
        // No options: the deprecated `rm` alias must keep its exact shape.
        assert!(Harness::try_parse_from(["dctl", "vault:a.jpg", "--rmdirs"]).is_err());
    }

    #[tokio::test]
    async fn a_trailing_separator_is_refused_as_a_directory() {
        // The check that stops `deletefile` becoming an accidental `purge`.
        for spec in ["vault:photos/", r"vault:photos\"] {
            let error = run_with(&[spec, "--force"]).await.unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "accepted '{spec}'");
            assert!(error.hint().unwrap_or_default().contains("purge"));
        }
    }

    #[tokio::test]
    async fn a_bare_remote_is_refused() {
        let error = run_with(&["vault:", "--force"]).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_local_path_is_refused() {
        let error = run_with(&[r"C:\Users\me\a.jpg", "--force"])
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_dry_run_never_reports_a_deletion() {
        let error = run_with(&["vault:a.jpg", "--dry-run", "--quiet"])
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
    }

    #[tokio::test]
    async fn a_real_run_never_reports_a_deletion_either() {
        let error = run_with(&["vault:a.jpg", "--force", "--quiet"])
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
    }

    #[tokio::test]
    async fn every_output_format_is_supported() {
        for format in [vec!["--json"], vec!["--format", "json-lines"], vec![]] {
            let mut args = vec!["vault:a.jpg", "--dry-run", "--quiet"];
            args.extend(format.iter().copied());
            assert!(run_with(&args).await.is_err(), "{format:?}");
        }
    }

    #[test]
    fn the_json_plan_omits_filters_because_the_object_was_named() {
        let target = Target::parse("vault:a.jpg").unwrap();
        let options = NoOptions {};
        let plan =
            crate::commands::removal::plan::Plan::new(COMMAND, &target, true, None, &options);
        let value = serde_json::to_value(&plan).unwrap();
        assert_eq!(value["command"], COMMAND);
        assert_eq!(value["target"]["path"], "a.jpg");
        assert!(value.get("filters").is_none());
    }
}
