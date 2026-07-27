//! `dctl audit` — inspect and verify the tamper-evident log (`PLAN.md` §7).
//!
//! The log is an append-only, hash-chained record of every operation: each entry
//! carries the previous entry's hash, so the sequence can be extended but not
//! rewritten. Editing one entry orphans the next; deleting one leaves a gap in
//! the indices; reordering breaks both. What the chain buys is the ability to
//! *prove* what happened, and to detect an attempt to change the story.
//!
//! Three verbs, one rule between them:
//!
//! * [`verify`] — walk the chain and report the exact record where it fails.
//! * [`list`] — show what the log says happened, with filters.
//! * [`export`] — hand the chain to someone else, byte-for-byte re-verifiable.
//!
//! **Every one of them walks the whole chain, and every one of them exits 24 if
//! it is broken.** A `list` that prints forged rows and exits 0 would put those
//! rows on screen with an implicit clean bill of health; an `export` that
//! silently copied a broken chain into an evidence bundle would be worse. The
//! output is still produced — an investigator needs it — and the exit code says
//! what it is.
//!
//! ## The format is not defined here
//!
//! [`chain`] and [`record`] are re-exported from [`crate::audit`], the home the
//! reader shares with the writer. They are shared rather than restated because
//! both halves have to agree exactly and forever: two definitions of a format
//! that must round-trip is how a log becomes unverifiable — the day they drift,
//! every record written after the drift reads as a forgery, and neither half is
//! wrong enough to notice.
//!
//! ## What these verbs read
//!
//! A real log. Every operation that changes stored data — the transfer family,
//! the removal family, `rcat`, `replicate`, `init` and `index rebuild` — appends
//! a chained record through [`crate::audit::sink`] after its durable commit, so
//! the chain these verbs walk is the account of what this machine actually did.
//!
//! An **empty** log verifies, and says so: the claim "nothing has been appended"
//! is a real answer. An **absent** one is an error, because it far more often
//! means the reader was pointed somewhere the writer never wrote than that
//! nothing ever happened — see [`source`].

pub use crate::audit::{chain, record};

pub mod export;
pub mod list;
pub mod source;
pub mod verify;

use clap::{Args, Subcommand};

use crate::ctx::Ctx;
use crate::error::Result;

/// Arguments for `dctl audit`.
#[derive(Args, Debug)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommand,
}

/// The audit verbs.
///
/// A subcommand is required rather than defaulting to `verify`: the three do
/// very different things, and a bare `dctl audit` that silently *verified*
/// would be a command whose most important behaviour is invisible in the
/// scripts that call it.
#[derive(Subcommand, Debug)]
pub enum AuditCommand {
    /// Walk the hash chain and report where it breaks. Exits 24 on a break.
    Verify(verify::VerifyArgs),

    /// Show recorded operations, newest last.
    List(list::ListArgs),

    /// Write the chain out in its canonical, re-verifiable form.
    Export(export::ExportArgs),
}

pub async fn run(ctx: &Ctx, args: &AuditArgs) -> Result<()> {
    match &args.command {
        AuditCommand::Verify(args) => verify::run(ctx, args).await,
        AuditCommand::List(args) => list::run(ctx, args).await,
        AuditCommand::Export(args) => export::run(ctx, args).await,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use clap::{CommandFactory, Parser};

    #[derive(Parser, Debug)]
    #[command(name = "dctl")]
    struct Harness {
        #[command(subcommand)]
        audit: Wrapper,
    }

    #[derive(Subcommand, Debug)]
    enum Wrapper {
        Audit(AuditArgs),
    }

    fn parse(args: &[&str]) -> Harness {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()))
    }

    #[test]
    fn the_subcommand_tree_is_internally_consistent() {
        // clap's own invariant checker: duplicate flags, conflicting shorts,
        // malformed help across the whole audit subtree.
        Harness::command().debug_assert();
    }

    #[test]
    fn each_verb_parses_to_its_own_arguments() {
        let Wrapper::Audit(args) = parse(&["audit", "verify"]).audit;
        assert!(matches!(args.command, AuditCommand::Verify(_)));

        let Wrapper::Audit(args) = parse(&["audit", "list", "--op", "copy"]).audit;
        let AuditCommand::List(list) = args.command else {
            panic!("expected list");
        };
        assert_eq!(list.op.as_deref(), Some("copy"));

        let Wrapper::Audit(args) = parse(&["audit", "export", "--output", "/tmp/a.jsonl"]).audit;
        let AuditCommand::Export(export) = args.command else {
            panic!("expected export");
        };
        assert_eq!(
            export.output.as_deref(),
            Some(std::path::Path::new("/tmp/a.jsonl"))
        );
    }

    #[test]
    fn a_bare_audit_is_a_usage_error() {
        // Defaulting to `verify` would hide the most important behaviour of the
        // command from the scripts that call it.
        assert!(Harness::try_parse_from(["dctl", "audit"]).is_err());
    }

    #[test]
    fn every_verb_accepts_an_explicit_log_path() {
        // Verification has to work on a chain written somewhere else — that is
        // how a mirrored copy gets checked.
        for verb in ["verify", "list", "export"] {
            assert!(
                Harness::try_parse_from(["dctl", "audit", verb, "--audit-log", "/tmp/a.jsonl"])
                    .is_ok(),
                "{verb} should accept --audit-log"
            );
        }
    }
}
