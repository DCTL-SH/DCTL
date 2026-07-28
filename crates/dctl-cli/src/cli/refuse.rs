//! The chokepoint that refuses a flag this build cannot honour.
//!
//! One call, in `main.rs`, before any command body runs and before anything is
//! read, written or unlocked. That placement is the whole design and it is
//! copied deliberately from [`crate::session::factor`], which learned it the
//! expensive way: the `--key-file` refusal used to live inside the vault-unlock
//! path, which a local-to-local transfer never calls, so
//! `dctl copy ./src ./dst --key-file kf` accepted the flag, ignored it and
//! exited 0. A guard that some routes reach is worse than none, because the
//! operator cannot tell which of their runs was protected.
//!
//! So there is exactly one gate, every command passes through it, and a command
//! added tomorrow passes through it without its author doing anything.
//!
//! ## What it refuses, and what decides
//!
//! [`crate::cli::reach::FLAGS`] does. This file holds no list: it walks the
//! table, asks each [`Reach::Refused`] row's predicate whether *this* run asked
//! for the thing, and turns the first yes into an error. Keeping the table
//! somewhere else is not indirection for its own sake — the table is what the
//! standing guard checks against clap, and a second list here would be the
//! second list that drifts.
//!
//! ## The shape of the message
//!
//! Identical to the `--key-file` refusal, because a user who meets two of these
//! should not have to learn two formats:
//!
//! * the **message** names what they were doing and which flag stopped it, so it
//!   maps onto the command line they typed;
//! * the **hint** carries the reason — which layer owes the capability, and what
//!   this build does instead — followed by what did *not* happen, because
//!   "refused" alone leaves open whether a half-finished transfer was left
//!   behind.
//!
//! The exit code is [`ExitCode::FatalError`], not [`ExitCode::Usage`]. The
//! command line was well-formed; the configuration is one the engine cannot
//! satisfy, and no retry, no backoff and no other remote makes it work.

use crate::cli::GlobalArgs;
use crate::cli::reach::{FLAGS, Reach};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::session;

/// Refuse the run if it asked for anything this build cannot do.
///
/// `operation` names **what the user was doing** — `dctl copy` — and is quoted
/// back to them. `consequence` states what did not happen as a result.
///
/// `--key-file` is refused first, through [`crate::session::factor`], which owns
/// that message and its tests: the second factor is a security property rather
/// than a tuning knob, and the sentence explaining it was written for somebody
/// who believes their vault needs two factors. Everything else is refused from
/// the table.
///
/// # Errors
/// [`ExitCode::FatalError`] naming the first flag this build cannot honour.
///
/// [`ExitCode::FatalError`]: crate::exit::ExitCode::FatalError
/// [`ExitCode::Usage`]: crate::exit::ExitCode::Usage
pub fn refuse_if_present(globals: &GlobalArgs, operation: &str, consequence: &str) -> Result<()> {
    session::factor::refuse_if_present(globals, operation, consequence)?;

    for flag in FLAGS {
        let Reach::Refused { reason, asked } = flag.reach else {
            continue;
        };
        if asked(globals) {
            // Built with `CliError::new` rather than `CliError::unimplemented`,
            // and the difference is not stylistic. `unimplemented` appends "is
            // not implemented in this build" to whatever it is handed, which is
            // right for `--key-file` — the subject there is a *feature* — and
            // produced "--timeout is not honoured in this build is not
            // implemented in this build" here, caught on the release binary
            // rather than by any test. Two claims in one sentence, one of them
            // ungrammatical and the other false: the flag is implemented as far
            // as parsing goes, and what it is not is *honoured*.
            return Err(CliError::new(
                ExitCode::FatalError,
                format!("{operation}: {} is not honoured in this build", flag.long),
            )
            .with_hint(format!("{reason} {consequence}")));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::reach::FLAGS;
    use crate::constants::{KEY_FILE_UNSUPPORTED_REASON, TIMEOUT_UNSUPPORTED_REASON};
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
    fn an_ordinary_run_passes_straight_through() {
        refuse_if_present(&globals(&[]), "dctl copy", "Nothing was copied.").unwrap();
    }

    #[test]
    fn the_refusal_names_the_flag_the_operation_and_what_did_not_happen() {
        let error = refuse_if_present(
            &globals(&["--timeout", "30"]),
            "dctl sync",
            "Nothing was transferred.",
        )
        .unwrap_err();

        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("--timeout"), "{}", error.message());
        assert!(error.message().contains("dctl sync"), "{}", error.message());
        assert!(
            !error.message().starts_with("dctl sync is not"),
            "`sync` is implemented; only the flag is not: {}",
            error.message()
        );

        let hint = error.hint().expect("a refusal must explain itself");
        assert!(hint.contains(TIMEOUT_UNSUPPORTED_REASON), "{hint}");
        assert!(hint.contains("Nothing was transferred."), "{hint}");
    }

    #[test]
    fn a_refusal_makes_exactly_one_claim_about_what_is_missing() {
        // Caught on the release binary, not by a test, which is why there is now
        // a test. The first version of this module built its error with
        // `CliError::unimplemented`, which appends "is not implemented in this
        // build" to whatever it is given — so the refusal read:
        //
        //     --timeout is not honoured in this build is not implemented in this build
        //
        // Two claims, one ungrammatical and the other false. Every refused flag
        // is checked, because the one that was wrong looked exactly like the six
        // that were not.
        for flag in FLAGS {
            let Reach::Refused { asked, .. } = flag.reach else {
                continue;
            };
            let argv: Vec<&str> = match flag.long {
                "--transfers" | "--checkers" => vec![flag.long, "2"],
                "--verify-samples" | "--low-level-retries" => vec![flag.long, "4"],
                "--timeout" | "--contimeout" => vec![flag.long, "30"],
                "--dump" => vec![flag.long, "headers"],
                "--key-file" => vec![flag.long, "/dev/null"],
                other => vec![other],
            };
            let parsed = globals(&argv);
            assert!(asked(&parsed), "{}", flag.long);

            let message = refuse_if_present(&parsed, "dctl copy", "Nothing.")
                .expect_err(flag.long)
                .message()
                .to_string();
            assert_eq!(
                message.matches("in this build").count(),
                1,
                "one refusal, one claim: {message}"
            );
        }
    }

    #[test]
    fn the_key_file_refusal_still_comes_from_its_own_module() {
        // Folding it into the table would have been tidier and wrong: the
        // second factor is a security property, and the sentence that explains
        // it was written for somebody who believes their vault needs two.
        let error = refuse_if_present(
            &globals(&["--key-file", "/dev/null"]),
            "dctl copy",
            "Nothing was copied.",
        )
        .unwrap_err();
        let hint = error.hint().unwrap_or_default();
        assert!(hint.contains(KEY_FILE_UNSUPPORTED_REASON), "{hint}");
    }

    #[test]
    fn the_second_factor_outranks_a_tuning_knob() {
        // Both are refused; only one of them is about whether the vault is
        // protected the way the operator thinks it is, so that is the one the
        // message must be about when a run asks for both.
        let error = refuse_if_present(
            &globals(&["--timeout", "30", "--key-file", "/dev/null"]),
            "dctl copy",
            "Nothing was copied.",
        )
        .unwrap_err();
        assert!(
            error.message().contains("--key-file"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn the_honest_value_of_a_partly_refused_flag_is_accepted() {
        // `--transfers 1` describes this executor exactly. Refusing it would be
        // refusing a correct statement.
        refuse_if_present(&globals(&["--transfers", "1"]), "dctl copy", "Nothing.").unwrap();
        let error = refuse_if_present(&globals(&["--transfers", "2"]), "dctl copy", "Nothing.")
            .unwrap_err();
        assert!(
            error.message().contains("--transfers"),
            "{}",
            error.message()
        );
    }
}
