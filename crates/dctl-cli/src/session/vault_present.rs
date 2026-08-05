//! Refusing to unlock a location that holds no vault.
//!
//! One question, asked once, before any secret is: **is there a vault here at
//! all?** It is separate from [`super::open`] because it is a fact about the
//! *location*, not about the password, and conflating the two is what produced
//! this:
//!
//! ```text
//! $ dctl index rebuild plainstore:
//! error: unlock failed: wrong password or corrupted envelope
//! warning: Check the password … the envelope itself may be damaged; it is
//!          stored as 'system/envelope.bin' in the object store, and restoring
//!          that one object from a replica of the store is the repair.
//! ```
//!
//! `plainstore` is a plain object store. It has no envelope, because a plain
//! store is not a vault; there is nothing at `system/envelope.bin` to restore
//! and no replica that would have one. The operator was told to check a password
//! that was never involved and to repair a file that cannot exist. A wrong
//! diagnosis costs more than none — this one sends somebody to hunt a corrupted
//! vault they do not have.
//!
//! ## Declared first, then demonstrated
//!
//! Exactly the order [`crate::commands::replicate::target`] uses, and for the
//! same reason: a store `dctl init` registered is *declared* a vault's store in
//! the configuration (`type = "vault"` on the sealed remote, `require_vault =
//! true` on the store), and taking the operator's word for it costs nothing. Only
//! an undeclared location is probed, and the probe is
//! [`crate::remote::envelope`]'s key-free ranged read of the envelope header —
//! one small request, no password, no body.
//!
//! ## Absence is a claim, and a failed look is not absence
//!
//! [`Verdict::Absent`] is returned only when the store answered "no such
//! object". A permission error, a timeout or a wrong endpoint is propagated as
//! itself. Reporting "this is not a vault" because nobody could look would be
//! the same class of mistake one layer along: an answer invented from a failure
//! to get one.

use std::sync::Arc;

use dctl_core::CoreError;
use dctl_store::Backend;

use crate::constants::VAULT_ENVELOPE_OBJECT_KEY;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::remote::RemoteSpec;
use crate::remote::envelope::{self, Verdict};

/// Refuse `spec` unless a vault is stored at it.
///
/// `declared` is the configuration's own statement, computed where the
/// configuration was already loaded. `not_a_vault` is an optional sentence the
/// calling command adds to the refusal, saying what *it* means for a plain
/// remote — the generic message can say there is no envelope, but only
/// `index rebuild` can say that a plain remote has no index to rebuild.
///
/// # Errors
/// [`ExitCode::FatalError`] when the store holds no envelope, carrying
/// [`CoreError::NoVault`]'s wording so the same finding reads the same way
/// wherever it is reached from. Whatever the probe failed with otherwise.
///
/// [`ExitCode::FatalError`]: crate::exit::ExitCode::FatalError
pub async fn require(
    ctx: &Ctx,
    backend: &Arc<dyn Backend>,
    spec: &RemoteSpec,
    declared: bool,
    not_a_vault: Option<&str>,
) -> Result<()> {
    if declared {
        tracing::debug!(remote = %spec, "vault declared in the configuration; not probing");
        return Ok(());
    }

    match envelope::probe(backend).await? {
        // A vault this build cannot parse is still a vault, and the unlock is
        // the right place to say so: it can name the version byte, and this
        // check cannot tell an old envelope from a damaged one.
        Verdict::Vault { .. } | Verdict::Foreign { .. } => Ok(()),
        Verdict::Absent => {
            ctx.out.info(format!(
                "no vault envelope at '{spec}'; nothing was unlocked"
            ));
            Err(refusal(spec, not_a_vault))
        }
    }
}

/// The refusal, built from [`CoreError::NoVault`] so that a location with no
/// envelope reads identically whether it was caught here or by the unlock
/// itself.
///
/// One finding, one sentence. Writing a second wording here is how a tool ends
/// up describing the same state two ways and teaching its users that the two are
/// different problems.
fn refusal(spec: &RemoteSpec, not_a_vault: Option<&str>) -> CliError {
    let base = CliError::from(CoreError::NoVault(VAULT_ENVELOPE_OBJECT_KEY.to_string()));
    let message = format!("'{spec}' is not a vault: {}", base.message());
    let hint = match not_a_vault {
        Some(extra) => format!("{extra} {}", base.hint().unwrap_or_default()),
        None => base.hint().unwrap_or_default().to_string(),
    };
    CliError::new(base.code(), message).with_hint(hint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::ExitCode;

    fn spec() -> RemoteSpec {
        RemoteSpec::parse("plainstore:").expect("a well-formed spec")
    }

    #[test]
    fn the_refusal_says_it_is_not_a_vault_and_never_blames_a_password() {
        // §16.2, as one assertion. The old message was "unlock failed: wrong
        // password or corrupted envelope" with a hint telling the reader to
        // restore `system/envelope.bin` from a replica — for a remote that
        // cannot have one.
        let error = refusal(&spec(), None);
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains("not a vault"),
            "{}",
            error.message()
        );
        assert!(
            !error.message().contains("password"),
            "no password is involved: {}",
            error.message()
        );

        let hint = error.hint().unwrap_or_default();
        assert!(
            !hint.contains("Check the password"),
            "the reader must not be sent to check a secret that cannot help: {hint}"
        );
        assert!(
            hint.contains("plain object store"),
            "the hint must say what this location actually is: {hint}"
        );
        assert!(
            hint.contains("no password is involved"),
            "and say so explicitly, because the old message did the opposite: {hint}"
        );
    }

    #[test]
    fn the_caller_can_say_what_its_own_verb_means_for_a_plain_remote() {
        let error = refusal(&spec(), Some("A plain remote has no index."));
        let hint = error.hint().unwrap_or_default();
        assert!(hint.starts_with("A plain remote has no index."), "{hint}");
        // And the shared explanation is still there behind it.
        assert!(hint.contains(VAULT_ENVELOPE_OBJECT_KEY), "{hint}");
    }

    #[test]
    fn the_refusal_names_the_remote_the_operator_typed() {
        let error = refusal(&spec(), None);
        assert!(
            error.message().contains("plainstore"),
            "{}",
            error.message()
        );
    }
}
