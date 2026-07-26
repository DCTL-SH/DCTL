//! `dctl rmdir` — remove one directory, and only if it is already empty.
//!
//! The safe member of the removal family, and deliberately the timid one: it
//! removes a container, never contents. If the directory still holds anything
//! the command is an **error**, not a recursion — falling back to removing the
//! contents would make `rmdir` a synonym for [`purge`](super::purge), and the
//! whole point of a command that refuses is that a script can rely on the
//! refusal. `mkdir` is its exact inverse (see `commands::mkdir`).
//!
//! Two things follow from "one directory":
//!
//! * The vault root is not a directory anyone may remove. `dctl rmdir vault:`
//!   is a usage error, not an empty success.
//! * Filters are ignored. A filter selects objects; this command does not act
//!   on objects at all. Use [`rmdirs`](super::rmdirs) to sweep many empty
//!   directories under a path.
//!
//! ## What runs today
//!
//! Argument parsing, target resolution, the root refusal, the destructive gate
//! and the `--dry-run` plan. The emptiness check and the removal both need
//! directory enumeration, which the vault does not expose — and [`Ctx`] carries
//! no vault handle to ask — so the command fails with a real exit code rather
//! than reporting a removal that never happened. See
//! [`super::removal::engine`].

use clap::Args;

use crate::constants::{REMOTE_PATH_VALUE_NAME, REMOVAL_ACTION_REMOVE_DIR};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};

use super::removal::{NoOptions, Removal, Target, execute};

/// Stable command name. Must match `Command::name()` in `cli/mod.rs`.
const COMMAND: &str = "rmdir";

/// The engine capability this command is waiting on.
const CAPABILITY: &str = "checking that a directory is empty and removing it";

/// `dctl rmdir REMOTE:PATH`
#[derive(Args, Debug)]
pub struct RmdirArgs {
    /// The empty directory to remove, written REMOTE:PATH.
    #[arg(value_name = REMOTE_PATH_VALUE_NAME)]
    pub path: String,
}

/// Run `dctl rmdir`.
///
/// # Errors
/// [`crate::exit::ExitCode::Usage`] for a malformed target or the vault root;
/// [`crate::exit::ExitCode::Cancelled`] if the user declines; otherwise the
/// unimplemented refusal described above. Once the engine can enumerate, a
/// non-empty directory joins this list as a failure — never as a recursion.
pub async fn run(ctx: &Ctx, args: &RmdirArgs) -> Result<()> {
    let target = Target::parse(&args.path)?;
    refuse_the_root(&target)?;

    let removal = Removal {
        command: COMMAND,
        action: REMOVAL_ACTION_REMOVE_DIR,
        target,
        // A filter selects objects; this command removes a container.
        filters: None,
        options: NoOptions {},
        capability: CAPABILITY,
    };

    execute(ctx, &removal)
}

/// Refuse `dctl rmdir vault:`.
///
/// The root is the vault itself, not a directory inside it; removing it is a
/// different operation with a different name (`dctl config delete`), and
/// silently succeeding here would suggest the vault had been dismantled.
fn refuse_the_root(target: &Target) -> Result<()> {
    if target.is_root() {
        return Err(
            CliError::usage(format!("'{target}' is the vault root, not a directory")).with_hint(
                "Name a directory inside the remote, for example \
                 'vault:photos/2024'.",
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
        args: RmdirArgs,
    }

    fn parse(args: &[&str]) -> Harness {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()))
    }

    async fn run_with(args: &[&str]) -> Result<()> {
        let parsed = parse(args);
        run(&Ctx::new(parsed.globals), &parsed.args).await
    }

    #[test]
    fn the_directory_is_the_only_argument() {
        assert_eq!(parse(&["vault:photos/2024"]).args.path, "vault:photos/2024");
        assert!(Harness::try_parse_from(["dctl"]).is_err());
    }

    #[test]
    fn a_trailing_separator_is_accepted_because_it_is_a_directory() {
        // The opposite of `deletefile`, where a trailing separator is refused.
        let target = Target::parse("vault:photos/2024/").unwrap();
        assert_eq!(target.path, "photos/2024");
    }

    #[tokio::test]
    async fn the_vault_root_is_refused() {
        let error = run_with(&["vault:", "--force"]).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some());
    }

    #[tokio::test]
    async fn a_malformed_target_is_refused() {
        let error = run_with(&["not-a-remote", "--force"]).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_dry_run_never_reports_a_removal() {
        let error = run_with(&["vault:photos/2024", "--dry-run", "--quiet"])
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
    }

    #[tokio::test]
    async fn a_real_run_never_reports_a_removal_either() {
        // Especially important here: an empty-directory removal is the kind of
        // no-op a tool is tempted to report as success.
        let error = run_with(&["vault:photos/2024", "--force", "--quiet"])
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
    }

    #[tokio::test]
    async fn every_output_format_is_supported() {
        for format in [vec!["--json"], vec!["--format", "json-lines"], vec![]] {
            let mut args = vec!["vault:photos/2024", "--dry-run", "--quiet"];
            args.extend(format.iter().copied());
            assert!(run_with(&args).await.is_err(), "{format:?}");
        }
    }

    #[test]
    fn the_json_plan_names_the_directory() {
        let target = Target::parse("vault:photos/2024").unwrap();
        let options = NoOptions {};
        let plan =
            crate::commands::removal::plan::Plan::new(COMMAND, &target, true, None, &options);
        let value = serde_json::to_value(&plan).unwrap();
        assert_eq!(value["command"], COMMAND);
        assert_eq!(value["target"]["path"], "photos/2024");
        assert!(value.get("filters").is_none());
    }
}
