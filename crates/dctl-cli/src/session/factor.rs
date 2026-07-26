//! The `--key-file` second factor, and why every path refuses it.
//!
//! `PLAN.md` §8 defines the second factor as `KDF_input = password ‖ H(factor)`:
//! something you *have*, folded into the key-encryption key beside something you
//! *know*, so a stolen password alone does not open the vault.
//!
//! `dctl_core::Vault::init` and `dctl_core::Vault::unlock` accept a password and
//! nothing else. There is no parameter for a factor, so the CLI cannot supply
//! one — not by any arrangement of the code on this side of the boundary.
//!
//! That leaves exactly two behaviours, and only one of them is honest:
//!
//! * Accept the flag and unlock with the password alone. The command succeeds,
//!   exits 0, and the operator believes their vault needs two factors when it
//!   needs one. This is the failure `PLAN.md` §6 forbids, in its most damaging
//!   form: the thing misreported is a security property, and the misreport is
//!   silent and repeats on every single run.
//! * Refuse, name the flag, and say plainly that this build cannot apply it.
//!   The operator loses the run and learns something true.
//!
//! So this module refuses. It exists as its own file because both `dctl init`
//! and every vault unlock must refuse *identically* — a build where creating a
//! vault rejects the factor but opening one ignores it would be worse than
//! either behaviour applied consistently.

use crate::cli::GlobalArgs;
use crate::constants::KEY_FILE_UNSUPPORTED_REASON;
use crate::error::{CliError, Result};

/// Refuse the run if `--key-file` was given.
///
/// `operation` names the thing being refused and is quoted back to the user, so
/// it must contain the literal flag — the reader has to be able to map the
/// message onto the command line they typed. `consequence` states what did
/// *not* happen as a result, because "refused" alone leaves open whether a
/// half-finished vault or a partial transfer was left behind.
///
/// # Errors
/// [`ExitCode::FatalError`] when `--key-file` is present. A configuration the
/// engine cannot satisfy is fatal rather than temporary: no retry, no backoff
/// and no other remote makes it work.
///
/// [`ExitCode::FatalError`]: crate::exit::ExitCode::FatalError
pub fn refuse_if_present(globals: &GlobalArgs, operation: &str, consequence: &str) -> Result<()> {
    if globals.key_file.is_some() {
        return Err(CliError::unimplemented(operation)
            .with_hint(format!("{KEY_FILE_UNSUPPORTED_REASON} {consequence}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::ExitCode;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn globals(args: &[&str]) -> GlobalArgs {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals
    }

    #[test]
    fn a_run_without_the_flag_is_untouched() {
        refuse_if_present(&globals(&[]), "dctl copy --key-file", "Nothing was copied.").unwrap();
    }

    #[test]
    fn the_flag_is_refused_with_a_fatal_code() {
        let error = refuse_if_present(
            &globals(&["--key-file", "/dev/null"]),
            "dctl copy --key-file",
            "Nothing was copied.",
        )
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert_ne!(error.code(), ExitCode::Success);
    }

    #[test]
    fn the_refusal_names_the_flag_and_says_what_did_not_happen() {
        let error = refuse_if_present(
            &globals(&["--key-file", "/dev/null"]),
            "dctl copy --key-file",
            "Nothing was copied.",
        )
        .unwrap_err();
        assert!(
            error.message().contains("--key-file"),
            "{}",
            error.message()
        );

        let hint = error.hint().expect("a refusal must explain itself");
        assert!(
            hint.contains(KEY_FILE_UNSUPPORTED_REASON),
            "the reason must be the shared one: {hint}"
        );
        assert!(hint.contains("Nothing was copied."), "{hint}");
    }

    #[test]
    fn a_missing_keyfile_is_refused_the_same_way_as_a_present_one() {
        // The file is never opened, so its existence is irrelevant and must not
        // change the diagnosis. A "no such file" error here would suggest the
        // factor would have worked had the path been right.
        let error = refuse_if_present(
            &globals(&["--key-file", "/nonexistent/kf.bin"]),
            "dctl copy --key-file",
            "Nothing was copied.",
        )
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains("--key-file"),
            "{}",
            error.message()
        );
    }
}
