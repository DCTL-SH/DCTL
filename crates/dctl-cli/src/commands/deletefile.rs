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
//! meaning to remove one file. The check has two halves and both run: the
//! syntactic one here — a target written with a trailing separator names a
//! directory, and a bare `REMOTE:` names the root — and the factual one in
//! [`super::removal::selection`], which refuses a path the remote holds objects
//! *under* rather than *at*.

use clap::Args;

use crate::constants::{PATH_SEPARATOR, REMOTE_PATH_VALUE_NAME, REMOVAL_ACTION_DELETE};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};

use super::removal::{NoOptions, Operation, Removal, Target, execute};

/// Stable command name. Must match `Command::name()` in `cli/mod.rs`.
const COMMAND: &str = "deletefile";

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
/// directory; [`crate::exit::ExitCode::FileNotFound`] when the remote holds no
/// such object; [`crate::exit::ExitCode::Cancelled`] if the user declines.
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
        operation: Operation::DeleteFile,
    };

    execute(ctx, &removal).await
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
        // A bare path has no colon at all, so it is a local path on every
        // platform and there is nothing platform-conditional to reason about.
        let error = run_with(&["/home/me/a.jpg", "--force"]).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);

        // A drive specifier is a path only where drives exist. Off Windows it
        // is a reference to the remote `C`, which is not configured here — a
        // hard failure by name, never a file quietly deleted somewhere else.
        let error = run_with(&[r"C:\Users\me\a.jpg", "--force"])
            .await
            .unwrap_err();
        if crate::constants::DRIVE_LETTERS_EXIST {
            assert_eq!(error.code(), ExitCode::Usage);
        } else {
            assert_eq!(error.code(), ExitCode::FatalError);
            assert!(error.message().contains('C'), "{}", error.message());
        }
    }

    #[tokio::test]
    async fn the_directory_refusal_runs_before_any_store_is_opened() {
        // The syntactic half of the check. It must not need a remote to exist,
        // because the mistake it catches is worst on a remote that does.
        let error = run_with(&["vault:photos/", "--force", "--quiet", "--no-ask-password"])
            .await
            .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
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
