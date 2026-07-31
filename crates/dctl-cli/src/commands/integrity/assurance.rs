//! The claim a run has to be able to make before it is allowed to start.
//!
//! `dctl verify` and `dctl scrub` exist to detect rot. On a remote that records
//! no digest of its own they cannot: every byte comes back, nothing disagrees
//! with anything, and the run prints `ok`. Measured on the shipped binary, on
//! `local:` and over a real `sshd`: a byte flipped in place and a 4 KiB object
//! truncated to 100 bytes produced `ok` in the table and **exit 0** on all four.
//!
//! An operator running that nightly is being told nothing while believing they
//! are being told everything. That is the shape of failure `PLAN.md` §6 forbids
//! — silent, and in the direction that loses data.
//!
//! ## So the run refuses, and the operator can say otherwise
//!
//! Both commands ask their source what a pass would prove
//! ([`Source::assurance`](crate::source::Source::assurance)) and stop **before**
//! reading anything if the answer cannot detect a changed byte. Exit
//! [`ExitCode::VerificationNotPossible`] (27): not 0, which is the defect, and
//! not 21, which would claim damage nobody has shown.
//!
//! [`AssuranceArgs::allow_read_back`] is how an operator says they want the
//! weaker check anyway — and it is worth having, because that check is exactly
//! what notices a replica quietly losing objects. What it is not is a rot check,
//! and the flag's name is the sentence the operator is agreeing to.
//!
//! ## Why this is one module and not two copies of an `if`
//!
//! `verify` and `scrub` share their verdicts, their exit codes and their
//! wording, and a claim only one of them enforced would be a claim nobody could
//! rely on — which is the exact history of the `assurance` field itself, which
//! `scrub` published and `verify` spent on a stderr warning (`HANDOVER.md` §11).
//! One gate, flattened into both argument structs, so the flag has one spelling
//! and the refusal has one wording.

use clap::Args;

use crate::constants::{ASSURANCE_REFUSED_HINT, ASSURANCE_REFUSED_NOTICE};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::source::Assurance;

/// The assurance an integrity run will accept, as the operator states it.
///
/// Flattened into both `VerifyArgs` and `ScrubArgs` rather than declared twice,
/// and deliberately **not** a global flag: eleven flags reached `dctl --help`
/// and did nothing because they were global and only some commands read them
/// (`HANDOVER.md` §13). This one is on exactly the two commands that honour it.
#[derive(Args, Debug, Default)]
pub struct AssuranceArgs {
    /// Run against a remote that cannot detect a changed byte, and check only
    /// that every object is still there and still readable.
    ///
    /// Off by default, and the default is a refusal: a plain `local:` or `sftp:`
    /// remote records no digest of what was written, so a run over one cannot
    /// tell a rotted object from an intact one and must not print `ok` as though
    /// it had. This flag asks for the check that *can* be made — every byte
    /// re-read — which is how a replica quietly losing objects is caught, and
    /// which is not a rot check.
    #[arg(long)]
    pub allow_read_back: bool,
}

/// Refuse a run whose source cannot make the claim the command exists to make.
///
/// Called before the walk starts, so a remote that cannot be certified costs
/// nothing to find out about — rather than an hour of egress followed by a
/// caveat.
///
/// # Errors
/// [`ExitCode::VerificationNotPossible`] when `assurance` cannot detect
/// corruption and the operator has not accepted that with
/// [`AssuranceArgs::allow_read_back`].
pub fn require(
    command: &str,
    target: &str,
    assurance: Assurance,
    args: &AssuranceArgs,
) -> Result<()> {
    if assurance.detects_corruption() || args.allow_read_back {
        return Ok(());
    }
    Err(CliError::new(
        ExitCode::VerificationNotPossible,
        format!(
            "'{target}' {ASSURANCE_REFUSED_NOTICE} — {}, so `{command}` {}",
            assurance.describe(),
            "cannot tell a changed byte from an unchanged one here",
        ),
    )
    .with_hint(ASSURANCE_REFUSED_HINT))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepting() -> AssuranceArgs {
        AssuranceArgs {
            allow_read_back: true,
        }
    }

    #[test]
    fn a_remote_that_cannot_detect_a_changed_byte_is_refused_by_default() {
        // The whole point. This is the run that used to print `ok` over a store
        // holding a flipped byte and exit 0.
        let error = require(
            "dctl verify",
            "pl:",
            Assurance::ReadBack,
            &AssuranceArgs::default(),
        )
        .expect_err("a remote that records nothing must be refused");
        assert_eq!(error.code(), ExitCode::VerificationNotPossible);
        assert_eq!(error.code().as_i32(), 27);
        assert!(error.message().contains("pl:"), "{}", error.message());
        assert!(error.hint().is_some(), "an operator needs a next action");
    }

    #[test]
    fn the_refusal_is_not_a_claim_that_anything_is_damaged() {
        // The over-correction this code is kept apart from: 21 means the bytes
        // were checked and failed.
        let error = require(
            "dctl scrub",
            "ps:",
            Assurance::ReadBack,
            &AssuranceArgs::default(),
        )
        .expect_err("refused");
        assert_ne!(error.code(), ExitCode::IntegrityFailure);
        assert!(
            !error.message().to_lowercase().contains("corrupt"),
            "nothing has been shown to be damaged: {}",
            error.message()
        );
    }

    #[test]
    fn a_remote_that_records_a_digest_is_allowed_through() {
        for level in [Assurance::Authenticated, Assurance::ProviderChecksum] {
            require("dctl verify", "archive:", level, &AssuranceArgs::default())
                .expect("a source that can detect corruption needs no permission");
        }
    }

    #[test]
    fn the_operator_can_ask_for_the_weaker_check_and_then_gets_it() {
        // The flag has to actually do something, or it is one of the eleven.
        require("dctl verify", "pl:", Assurance::ReadBack, &accepting())
            .expect("the operator said so");
    }
}
