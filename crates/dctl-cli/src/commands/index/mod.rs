//! `dctl index` — operations on the local index database.
//!
//! The index is a **cache and a privacy layer, never a single point of failure**
//! (`PLAN.md` §13.5). Every fact it holds is derivable from the backend: the
//! path→object mapping lives in the encrypted `n/*` name records, and each object
//! carries its own DEK and metadata. It exists because deriving those facts on
//! demand would mean a network round trip per path, and because keeping the
//! mapping local is what stops a provider from learning the shape of the dataset
//! it is holding.
//!
//! That makes "the index" a thing an operator sometimes has to act on directly,
//! which is what this command group is for — and why it is a group with one verb
//! rather than a bare `dctl rebuild-index`. Snapshotting, verifying and
//! reporting on the index are all named in §13.5 and will land here; `rebuild`
//! is the one that recovers a machine, so it is the one that exists first.
//!
//! ## Why `rebuild` had to exist now
//!
//! Three of this binary's error hints already tell the user to run
//! `dctl index rebuild`: an index-layer failure ([`crate::error`]), an object
//! that is recorded but absent at the provider
//! ([`crate::commands::integrity::failure`]), and a `cat` of a file written on
//! another machine ([`crate::commands::cat`]). A hint naming a command that does
//! not exist is the same defect class as a refusal naming a remote that cannot
//! be addressed: the tool's own suggested fix does not work, which is worse than
//! no suggestion at all. The capability was real — `dctl_core::Vault` has
//! exposed `rebuild_index` throughout — so the honest resolution was to give it
//! a name a user can type.
//!
//! ## Layout
//!
//! One file per verb, plus the report shape they share. [`rebuild`] holds the
//! arguments and the run body; [`report`] holds the result in all three output
//! formats, so the machine-readable contract is unit-testable without a vault.

pub mod rebuild;
pub mod report;

use clap::{Args, Subcommand};

use crate::ctx::Ctx;
use crate::error::Result;

/// Arguments for `dctl index`.
#[derive(Args, Debug)]
pub struct IndexArgs {
    #[command(subcommand)]
    pub action: Action,
}

/// What to do to the index.
#[derive(Subcommand, Debug)]
pub enum Action {
    /// Rebuild the index by rescanning the backend's object records.
    Rebuild(rebuild::RebuildArgs),
}

impl Action {
    /// Stable name for logs and documentation.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Rebuild(_) => "rebuild",
        }
    }

    /// Whether this action writes to the index database.
    ///
    /// Used by the dispatcher's log record and by the tests that hold the
    /// read-only actions to being read-only. A rebuild writes; a future
    /// `dctl index verify` will not, and the distinction is what `--dry-run` has
    /// to suppress.
    #[must_use]
    pub const fn is_mutating(&self) -> bool {
        matches!(self, Self::Rebuild(_))
    }
}

/// Route a `dctl index` invocation to its subcommand.
///
/// # Errors
/// Whatever the subcommand classifies its failure as. Nothing is classified
/// here: a router that invented its own error codes would make the same failure
/// look different depending on which verb produced it.
pub async fn run(ctx: &Ctx, args: &IndexArgs) -> Result<()> {
    tracing::debug!(
        action = args.action.name(),
        mutating = args.action.is_mutating(),
        "index"
    );

    match &args.action {
        Action::Rebuild(args) => rebuild::run(ctx, args).await,
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
            Command::Index(index) => index.action,
            other => panic!("{argv:?} parsed as {other:?}, not index"),
        }
    }

    #[test]
    fn the_verb_the_error_hints_name_is_the_verb_that_parses() {
        // The whole reason this command exists: `dctl index rebuild` is quoted
        // in three of the binary's hints, so it has to be typeable exactly as
        // written there.
        let parsed = action(&["index", "rebuild", "archive:"]);
        assert_eq!(parsed.name(), "rebuild");
        let Action::Rebuild(args) = parsed;
        assert_eq!(args.target, "archive:");
    }

    #[test]
    fn a_rebuild_is_classified_as_writing_to_the_index() {
        assert!(action(&["index", "rebuild", "archive:"]).is_mutating());
    }

    #[test]
    fn the_group_requires_a_verb() {
        // `dctl index` on its own does nothing and must say so rather than
        // picking a default that writes.
        assert!(Cli::try_parse_from(["dctl", "index"]).is_err());
    }
}
