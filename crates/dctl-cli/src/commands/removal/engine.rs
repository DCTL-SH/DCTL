//! The one place the removal family admits what it cannot yet do.
//!
//! `dctl-core::Vault` exposes `put_file`, `get_file`, `verify_file`, `list` and
//! `delete_file`, and nothing else. Two things are therefore missing before any
//! of these commands can remove a single object:
//!
//! 1. **A vault handle.** [`Ctx`](crate::ctx::Ctx) resolves configuration,
//!    output and safety flags, but carries no unlocked vault — and a command
//!    may not reach around it to build one, because that would re-derive the
//!    remote, the index path and the password that the context exists to settle
//!    exactly once.
//! 2. **The capability itself.** Directory enumeration, emptiness checks,
//!    multipart-upload listing and object versions have no API at all yet.
//!
//! Until both land, every removal validates its input, shows its plan, and then
//! fails **loudly** — `PLAN.md` §6's core promise is that DCTL never reports
//! work it did not do, and a command that quietly exited 0 having deleted
//! nothing would break it more thoroughly than any crash. Centralising the
//! refusal here means the day the engine arrives, this file is the boundary
//! that moves: the call sites already carry the command name and the capability
//! each one needs.

use crate::constants::{REMOVAL_ENGINE_HINT, REMOVAL_ENGINE_MISSING};
use crate::error::CliError;
use crate::exit::ExitCode;

/// The error a removal returns instead of pretending to have run.
///
/// `capability` names the missing engine feature in the user's vocabulary, not
/// the implementer's: the reader wants to know which operation is unavailable,
/// not which trait is unimplemented.
#[must_use]
pub fn unavailable(command: &str, capability: &str) -> CliError {
    CliError::unimplemented(format!("{} {command}", dctl_meta::BINARY_NAME)).with_hint(format!(
        "{REMOVAL_ENGINE_MISSING} {capability}. {REMOVAL_ENGINE_HINT}"
    ))
}

/// The error a removal returns when the user declines the confirmation.
///
/// Not a success and not a failure of the command: the operation was
/// cancelled, which has its own exit code so a script can tell "you said no"
/// apart from "it went wrong".
#[must_use]
pub fn declined(action: &str, target: &str) -> CliError {
    CliError::new(
        ExitCode::Cancelled,
        format!("cancelled: '{action}' on '{target}' was not confirmed"),
    )
    .with_hint(format!(
        "Type '{}' at the prompt to confirm, or pass --force to approve \
         destructive actions without being asked.",
        crate::constants::DESTRUCTIVE_CONFIRMATION
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unavailable_capability_is_an_error_never_a_success() {
        // The rule this module exists to enforce.
        let error = unavailable("delete", "removing objects from a vault");
        assert_ne!(error.code(), ExitCode::Success);
        assert_eq!(error.code(), ExitCode::FatalError);
    }

    #[test]
    fn the_message_names_the_command_and_the_missing_capability() {
        let error = unavailable("purge", "removing a whole tree");
        assert!(error.message().contains("purge"), "{}", error.message());
        let hint = error.hint().unwrap_or_default();
        assert!(hint.contains("removing a whole tree"), "{hint}");
        assert!(hint.contains(REMOVAL_ENGINE_HINT), "{hint}");
    }

    #[test]
    fn a_declined_confirmation_is_cancelled_not_failed() {
        let error = declined("purge", "vault:old");
        assert_eq!(error.code(), ExitCode::Cancelled);
        assert!(error.message().contains("vault:old"));
        assert!(
            error
                .hint()
                .unwrap_or_default()
                .contains(crate::constants::DESTRUCTIVE_CONFIRMATION)
        );
    }
}
