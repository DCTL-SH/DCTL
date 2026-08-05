//! Which secret this run opens the vault with.
//!
//! One decision, made once, so that no two commands can answer it differently.
//! DCTL now has two independent ways into a vault — the password and the recovery
//! phrase (`crates/dctl-decode/FORMAT.md` §2,
//! [the plan](https://doc.dctl.sh/project/plan) §13.2) — and the moment two call
//! sites choose between them separately is the moment one of them forgets the
//! phrase exists.
//!
//! ## The precedence rule, and why it is not a conflict
//!
//! **A named recovery phrase wins outright.** Not "is preferred": if a phrase
//! source was given, the password is not consulted at all, and a phrase source
//! that cannot be read is a failure rather than a fall back.
//!
//! Clap could have been told the two flags conflict, and that would be the wrong
//! shape. `--password` is filled from `DCTL_PASSWORD` as well as the flag, so a
//! maintainer with the variable exported in their shell — which is the *normal*
//! way to use this tool — would find `dctl --recovery-phrase … ls archive:`
//! refused for a conflict they did not create, at the moment they are least able
//! to reason about it. Precedence lets the recovery path work in an environment
//! that is already configured for the ordinary one, which is exactly the
//! environment a recovery happens in.
//!
//! The choice is never silent: [`Secret::describe`] names the mechanism that
//! answered, and every unlock reports it at `-v`.

use dctl_core::UnlockKey;

use crate::cli::GlobalArgs;
use crate::error::Result;

use super::{password, phrase};

/// The unlock secret one invocation resolved to.
pub enum Secret {
    /// A password, for the `slot_type = 1` slot.
    Password(password::Password),
    /// A recovery phrase, for the `slot_type = 2` slot.
    Phrase(phrase::RecoveryPhrase),
}

// Never derive Debug: both variants hold a secret. Their own `Debug`
// implementations redact, but a derive here would print the variant name plus
// whatever a future field carried, and this type exists on the path where a
// mistake is a disclosed key.

impl Secret {
    /// The typed key `dctl-core` unlocks with.
    ///
    /// Borrowing rather than cloning keeps exactly one copy of the secret in
    /// memory, the one inside the `Zeroizing` wrapper that will wipe it.
    #[must_use]
    pub fn key(&self) -> UnlockKey<'_> {
        match self {
            Self::Password(password) => UnlockKey::Password(password.expose()),
            Self::Phrase(phrase) => UnlockKey::RecoveryPhrase(phrase.expose()),
        }
    }

    /// How this secret reached DCTL, for the `-v` note.
    ///
    /// Names the *kind* as well as the mechanism. "read from --password-file"
    /// leaves an operator debugging a failed recovery unable to tell whether the
    /// phrase they passed was used at all, and that is precisely the run where
    /// they need to know.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Password(password) => {
                format!("password read from {}", password.source().describe())
            }
            Self::Phrase(phrase) => format!(
                "recovery phrase read from {} (the password is not being used)",
                phrase.source().describe()
            ),
        }
    }

    /// Whether this run is using the recovery path.
    ///
    /// Read by callers that must behave differently on a recovery — nothing
    /// should, except in what it *says*, which is why this reports rather than
    /// decides.
    #[must_use]
    pub const fn is_recovery(&self) -> bool {
        matches!(self, Self::Phrase(_))
    }
}

/// Resolve the secret this invocation should unlock with.
///
/// # Errors
/// Whatever the chosen acquirer reports: an unreadable or invalid phrase, or a
/// missing password — both [`ExitCode::VaultLocked`], because in both cases the
/// vault stayed shut.
///
/// [`ExitCode::VaultLocked`]: crate::exit::ExitCode::VaultLocked
pub fn acquire(globals: &GlobalArgs) -> Result<Secret> {
    if let Some(phrase) = phrase::acquire(globals)? {
        return Ok(Secret::Phrase(phrase));
    }
    Ok(Secret::Password(password::acquire(globals)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn globals(args: &[&str]) -> GlobalArgs {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals
    }

    /// The BIP-39 specification's own 24-word test vector. Guards nothing.
    const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank \
                          year wave sausage worth useful legal winner thank year wave sausage \
                          worth title";

    #[test]
    fn a_password_run_resolves_to_a_password() {
        let secret = acquire(&globals(&["--password", "correct horse battery"])).unwrap();
        assert!(!secret.is_recovery());
        assert!(matches!(secret.key(), UnlockKey::Password(_)));
        assert!(secret.describe().contains("password"));
    }

    #[test]
    fn a_named_phrase_wins_over_an_exported_password() {
        // The environment a recovery actually happens in: DCTL_PASSWORD is
        // already set from ordinary use, and the operator adds a phrase. A
        // conflict error here would refuse the run; using the password would
        // exercise the wrong path and report success.
        let secret = acquire(&globals(&[
            "--recovery-phrase",
            PHRASE,
            "--password",
            "the password they have forgotten",
        ]))
        .unwrap();
        assert!(secret.is_recovery());
        assert!(matches!(secret.key(), UnlockKey::RecoveryPhrase(_)));
    }

    #[test]
    fn the_note_says_plainly_that_the_password_is_unused() {
        let secret = acquire(&globals(&["--recovery-phrase", PHRASE])).unwrap();
        let note = secret.describe();
        assert!(note.contains("recovery phrase"), "{note}");
        assert!(
            note.contains("not being used"),
            "an operator debugging a recovery must be told which secret ran: {note}"
        );
    }

    #[test]
    fn an_unreadable_phrase_never_falls_back_to_the_password() {
        // The failure this ordering exists to prevent: a restore drill that
        // silently used the password would report the recovery path as working
        // without ever having exercised it.
        //
        // `unwrap_err` is not available here: `Secret` has no `Debug`, on
        // purpose — both variants hold a plaintext key, and a derive would put
        // one `{:?}` away from any struct that ever contains one.
        let Err(error) = acquire(&globals(&[
            "--recovery-phrase-file",
            "/nonexistent/phrase.txt",
            "--password",
            "correct horse battery",
        ])) else {
            panic!("an unreadable phrase file must not resolve to a secret");
        };
        assert_eq!(error.code(), crate::exit::ExitCode::VaultLocked);
    }

    #[test]
    fn the_key_borrows_rather_than_copies_the_secret() {
        // Asserted through behaviour: the exposed bytes must be the ones the
        // acquirer read, not a re-derived or truncated copy.
        let secret = acquire(&globals(&["--recovery-phrase", PHRASE])).unwrap();
        let UnlockKey::RecoveryPhrase(words) = secret.key() else {
            panic!("a phrase run must yield a phrase key");
        };
        assert_eq!(words, PHRASE);
    }
}
