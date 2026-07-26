//! `dctl verify REMOTE:PATH` — prove that stored objects still decrypt and
//! still match the hashes recorded when they were written.
//!
//! This is the read-side half of the verified-write contract (`PLAN.md` §6). A
//! write refuses to commit unless the destination's checksum matches ours; a
//! `verify` asks the same question again later, on demand, and answers it with
//! whatever strength the global `--verify` flag selects:
//!
//! * `checksum` — compare the provider's stored checksum with ours. No egress.
//! * `sample` — additionally range-read and decrypt `--verify-samples` chunks.
//! * `strict` — read every object back in full and confirm its whole-file
//!   BLAKE3.
//!
//! The report always states which of those produced it, because "1,204 objects
//! verified" means three different things depending on the answer and the
//! strongest reading is the one people assume.
//!
//! **Failure is loud.** An object whose bytes fail authentication ends the
//! process with [`ExitCode::IntegrityFailure`](crate::exit::ExitCode::IntegrityFailure)
//! (21) and a message saying, in words, that the data was not served. It is
//! never rolled up into a generic error, and a run that found damage never exits
//! zero.
//!
//! ## What this build can do
//!
//! Argument parsing, target resolution, the report shape in all three output
//! formats, the verdict-to-exit-code mapping and the failure wording are all
//! implemented and tested here. The step that actually reads and authenticates
//! an object is not: `dctl_core::Vault` currently exposes `verify_file` for a
//! single path but no way to enumerate and verify a prefix under a chosen
//! strength, and `Ctx` does not yet carry an unlocked vault. Rather than print a
//! success message for work that did not happen, `run` validates everything it
//! can and then returns [`CliError::unimplemented`], which is an error with a
//! real exit code.

pub mod report;

use clap::Args;

use crate::commands::integrity::{Target, command_name, mode};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};

/// The verb this module implements, used in messages that name the command.
const VERB: &str = "verify";

/// Arguments to `dctl verify`.
///
/// Deliberately small: strength, sampling depth and path filtering are all
/// global flags already, and duplicating them here would create two spellings of
/// one setting.
#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Object or prefix to verify.
    #[arg(value_name = "REMOTE:PATH")]
    pub target: String,

    /// Stop at the first object that fails instead of checking the rest.
    ///
    /// Off by default: the most useful thing a verify run can tell you is *how
    /// much* is damaged, and stopping at the first bad object hides that.
    #[arg(long)]
    pub fail_fast: bool,
}

/// Verify stored objects against their recorded hashes.
///
/// # Errors
/// [`CliError::usage`] for a malformed or local target; the integrity family's
/// classified failure when objects do not verify; and
/// [`CliError::unimplemented`] until the engine can read objects back — see the
/// module documentation.
pub async fn run(ctx: &Ctx, args: &VerifyArgs) -> Result<()> {
    let command = command_name(VERB);
    let target = Target::parse(&args.target)?;
    // Verification compares stored bytes against the hash the vault recorded for
    // them. A local path has no such record, so there is nothing to compare and
    // saying so now beats reporting "0 objects verified" after doing nothing.
    target.require_remote(&command)?;

    let strength = ctx.verify_mode();
    ctx.out.info(format!(
        "{command}: {target} at --verify={} — {}",
        mode::slug(strength),
        mode::describe(strength)
    ));
    if mode::reads_object_bytes(strength) && target.is_tree() {
        // The one surprise worth a warning: a strict verify of a whole vault
        // downloads the whole vault, and the bill arrives later than the run.
        ctx.out.warn(format!(
            "--verify={} reads object bytes back, so verifying the tree '{target}' \
             will download every object it contains",
            mode::slug(strength)
        ));
    }

    // `verify` mutates nothing, so --dry-run has nothing to suppress. It must
    // still not be treated as permission to claim the work was done.
    Err(CliError::unimplemented(command))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use crate::exit::ExitCode;
    use clap::Parser;

    /// Parse a full command line and hand back the context plus the arguments.
    fn parse(args: &[&str]) -> (Ctx, VerifyArgs) {
        let cli = Cli::try_parse_from(std::iter::once("dctl").chain(args.iter().copied()))
            .expect("arguments should parse");
        let Command::Verify(verify) = cli.command else {
            panic!("expected the verify subcommand");
        };
        (Ctx::new(cli.globals), verify)
    }

    #[tokio::test]
    async fn a_target_is_required() {
        assert!(Cli::try_parse_from(["dctl", "verify"]).is_err());
    }

    #[tokio::test]
    async fn the_target_and_fail_fast_flag_parse() {
        let (_, args) = parse(&["verify", "vault:photos"]);
        assert_eq!(args.target, "vault:photos");
        assert!(!args.fail_fast);

        let (_, args) = parse(&["verify", "vault:photos", "--fail-fast"]);
        assert!(args.fail_fast);
    }

    #[tokio::test]
    async fn the_global_verify_mode_is_reachable_without_a_local_flag() {
        // Strength is a global dial; a per-command copy would be a second
        // spelling of one setting.
        let (ctx, _) = parse(&["verify", "vault:x", "--verify", "strict"]);
        assert_eq!(ctx.verify_mode(), crate::cli::VerifyMode::Strict);
    }

    #[tokio::test]
    async fn a_local_target_is_a_usage_error() {
        let (ctx, args) = parse(&["verify", "./photos"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains(VERB));
    }

    #[tokio::test]
    async fn an_escaping_path_is_rejected_before_any_work() {
        let (ctx, args) = parse(&["verify", "vault:../../etc"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn unimplemented_work_is_an_error_not_a_success() {
        // `PLAN.md` §6: never report work as done when it did not happen.
        let (ctx, args) = parse(&["verify", "vault:photos"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains(&command_name(VERB)));
    }

    #[tokio::test]
    async fn dry_run_does_not_turn_missing_work_into_success() {
        // --dry-run suppresses mutations; verify has none, and it must never be
        // read as permission to claim a verification that never ran.
        let (ctx, args) = parse(&["verify", "vault:photos", "--dry-run"]);
        assert!(ctx.is_dry_run());
        assert!(run(&ctx, &args).await.is_err());
    }

    #[tokio::test]
    async fn every_output_format_is_accepted() {
        for format in [&["--json"][..], &["--format", "json-lines"][..], &[][..]] {
            let mut argv = vec!["verify", "vault:photos"];
            argv.extend_from_slice(format);
            let (ctx, args) = parse(&argv);
            // The format must never change the classification of the failure.
            assert_eq!(
                run(&ctx, &args).await.unwrap_err().code(),
                ExitCode::FatalError
            );
        }
    }
}
