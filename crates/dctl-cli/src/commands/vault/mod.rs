//! `dctl vault` — operations on a vault's key material.
//!
//! Everything here acts on the **envelope**, not on the data: the small object
//! holding the wrapped root key that every byte in the vault depends on
//! (`crates/dctl-decode/FORMAT.md` §2). That is why it is its own command group
//! rather than a flag on `init` or a mode of `config`. Losing an object loses a
//! file; losing the envelope loses the dataset, and the operations that touch
//! it deserve a name an operator can find under stress.
//!
//! ## Why `recover` exists first
//!
//! [The plan](https://doc.dctl.sh/project/plan) §13.2 calls key survival the #1
//! risk of a twenty-year tool and promises several independent unwrap paths.
//! `dctl init` now issues one — a BIP-39 recovery phrase alongside the password
//! — and a phrase is only worth having if there is a documented way to *use*
//! it, named in the message somebody reads when their vault will not open.
//!
//! There are two halves to using it, and they are one command because doing
//! only the first leaves the operator no better off:
//!
//! 1. **Open the vault with the phrase.** This works everywhere, not only here:
//!    `--recovery-phrase` is a global, so `ls`, `cat`, `copy` and `restore` all
//!    accept one (see [`crate::session::secret`]). A `recover` verb that only
//!    proved the phrase works would be a demonstration, not a recovery.
//! 2. **Set a working password again.** Which is the actual request behind
//!    "I lost my password": not "read my files once through an awkward flag",
//!    but "give me my vault back". `Vault::change_password` rewrites the one
//!    password slot and leaves every other slot — the phrase's above all —
//!    byte-identical, so the paper backup keeps working afterwards.
//!
//! ## Layout
//!
//! One file per verb, plus the report they share. [`recover`] holds the
//! arguments and the run body; [`report`] holds the result in all three output
//! formats, so the machine-readable contract is unit-testable without a vault.

pub mod recover;
pub mod report;

use clap::{Args, Subcommand};

use crate::ctx::Ctx;
use crate::error::Result;

/// Arguments for `dctl vault`.
#[derive(Args, Debug)]
pub struct VaultArgs {
    #[command(subcommand)]
    pub action: Action,
}

/// What to do to the vault's key material.
#[derive(Subcommand, Debug)]
pub enum Action {
    /// Open a vault with its recovery phrase and set a new password.
    Recover(recover::RecoverArgs),
}

impl Action {
    /// Stable name for logs, audit records and documentation.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Recover(_) => "recover",
        }
    }

    /// Whether this action rewrites the envelope.
    ///
    /// The distinction `--dry-run` has to suppress, and the one that decides
    /// whether an audit record is written. A future read-only verb — one that
    /// reported which slot types an envelope holds, say — would answer `false`;
    /// `recover` replaces a key slot, so it answers `true`.
    #[must_use]
    pub const fn is_mutating(&self) -> bool {
        matches!(self, Self::Recover(_))
    }
}

/// Route a `dctl vault` invocation to its subcommand.
///
/// # Errors
/// Whatever the subcommand classifies its failure as. Nothing is classified
/// here: a router that invented its own codes would make the same failure look
/// different depending on which verb produced it.
pub async fn run(ctx: &Ctx, args: &VaultArgs) -> Result<()> {
    tracing::debug!(
        action = args.action.name(),
        mutating = args.action.is_mutating(),
        "vault"
    );

    match &args.action {
        Action::Recover(args) => recover::run(ctx, args).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use clap::Parser;

    fn action(argv: &[&str]) -> Action {
        let cli = Cli::try_parse_from(std::iter::once("dctl").chain(argv.iter().copied()))
            .unwrap_or_else(|error| panic!("{argv:?} did not parse: {error}"));
        match cli.command {
            Command::Vault(vault) => vault.action,
            other => panic!("{argv:?} parsed as {other:?}, not vault"),
        }
    }

    #[test]
    fn the_verb_the_unlock_hint_names_is_the_verb_that_parses() {
        // The whole reason this command exists in this shape: `dctl vault
        // recover` is quoted in the hint somebody reads when they believe their
        // vault is lost, so it has to be typeable exactly as written there.
        // `crate::cli::mentions` enforces that across the crate; this pins the
        // spelling at the source.
        let parsed = action(&["vault", "recover", "archive:"]);
        assert_eq!(parsed.name(), "recover");
        let Action::Recover(args) = parsed;
        assert_eq!(args.target, "archive:");
    }

    #[test]
    fn recovering_is_classified_as_rewriting_the_envelope() {
        assert!(action(&["vault", "recover", "archive:"]).is_mutating());
    }

    #[test]
    fn the_group_requires_a_verb() {
        // `dctl vault` alone must not pick a default that rewrites key material.
        assert!(Cli::try_parse_from(["dctl", "vault"]).is_err());
    }
}
