//! The claims a run has to be able to make before it is allowed to start.
//!
//! `dctl verify` and `dctl scrub` exist to detect two different losses, and a
//! remote can be unable to detect either one independently of the other:
//!
//! | | the question | what a remote needs to answer it |
//! |---|---|---|
//! | **rot** | are these the bytes that were written? | a digest recorded at write time ([`Assurance`]) |
//! | **loss** | is everything that was written still here? | a list of what was written ([`Inventory`]) |
//!
//! ## Rot: measured, and refused since `HANDOVER.md` §34
//!
//! On a remote that records no digest of its own, `verify` cannot detect a
//! changed byte: every byte comes back, nothing disagrees with anything, and the
//! run prints `ok`. Measured on the shipped binary, on `local:` and over a real
//! `sshd`: a byte flipped in place and a 4 KiB object truncated to 100 bytes
//! produced `ok` in the table and **exit 0** on all four.
//!
//! ## Loss: measured, and refused since `HANDOVER.md` §36
//!
//! On **every** plain remote — including one whose provider does record digests
//! — `verify` enumerates the remote and then checks the keys the remote just
//! reported. Both sides of that comparison are one source, so they agree by
//! construction. Measured on the shipped binary, a plain `local:` remote holding
//! three objects with `--allow-read-back` set: **one object deleted outright**
//! gave `OK  2 objects examined` and **exit 0**. The same deletion inside a vault
//! is caught at exit 4, because a vault walks an index row per object and a plain
//! remote has no such row.
//!
//! That one was worse than a silent limitation. The flag's own `--help` said the
//! read-back "is how a replica quietly losing objects is caught" — the single
//! damage it was measured **not** to catch. See [`Inventory`] for where a plain
//! manifest would have to live, and why DCTL ships a vault instead of one.
//!
//! ## So the run refuses, and the operator can accept each limit by name
//!
//! Both commands ask their source what a pass would prove ([`Claims::of`]) and
//! stop **before** reading anything if either claim cannot be made. Exit
//! [`ExitCode::VerificationNotPossible`] (27): not 0, which is the defect, and
//! not 21 or 4, which would claim damage nobody has shown.
//!
//! **Two limits, two flags, and deliberately not one.**
//! [`AssuranceArgs::allow_read_back`] accepts the first,
//! [`AssuranceArgs::allow_listing_as_inventory`] accepts the second, and a
//! remote that fails both is told both at once rather than one per run. A single
//! flag meaning "accept whatever this remote cannot prove" would make a B2
//! operator accept a rot caveat that does not apply to their remote, would make
//! a `local:` operator unable to accept one limit without the other — and, worse,
//! is the shape that lets a limitation discovered later be swallowed silently by
//! a flag somebody put in a cron entry years ago. That is how the sentence this
//! module exists to retire came to be shipped. One flag, one sentence, and the
//! flag's name is the sentence being agreed to.
//!
//! ## Why this is one module and not two copies of an `if`
//!
//! `verify` and `scrub` share their verdicts, their exit codes and their
//! wording, and a claim only one of them enforced would be a claim nobody could
//! rely on — which is the exact history of the `assurance` field itself, which
//! `scrub` published and `verify` spent on a stderr warning (`HANDOVER.md` §11).
//! One gate, flattened into both argument structs, so the flags have one
//! spelling and the refusal has one wording.

use clap::Args;

use crate::constants::{
    ASSURANCE_REFUSED_CONSEQUENCE, ASSURANCE_REFUSED_HINT, ASSURANCE_REFUSED_NOTICE,
    INTEGRITY_REFUSED_JOIN, INVENTORY_FLAG, INVENTORY_REFUSED_CONSEQUENCE, INVENTORY_REFUSED_HINT,
    INVENTORY_REFUSED_NOTICE, READ_BACK_FLAG,
};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::source::Claims;

/// The claims an integrity run will accept, as the operator states them.
///
/// Flattened into both `VerifyArgs` and `ScrubArgs` rather than declared twice,
/// and deliberately **not** global flags: eleven flags reached `dctl --help` and
/// did nothing because they were global and only some commands read them
/// (`HANDOVER.md` §13). These are on exactly the two commands that honour them.
#[derive(Args, Debug, Default)]
pub struct AssuranceArgs {
    /// Run against a remote that cannot detect a changed byte, and accept that
    /// a rotted object will read back as `ok`.
    ///
    /// Off by default, and the default is a refusal: a plain `local:` or `sftp:`
    /// remote records no digest of what was written, so a run over one cannot
    /// tell a rotted object from an intact one and must not print `ok` as though
    /// it had. What this flag buys is the check that *can* be made — every byte
    /// of every listed object re-read in full, which proves those objects are
    /// still retrievable and proves nothing about whether they changed.
    ///
    /// It says nothing about an object that is **gone**; see
    /// `--allow-listing-as-inventory`, which is the other half and is a
    /// separate decision.
    #[arg(long)]
    pub allow_read_back: bool,

    /// Treat this remote's own listing as the record of what it should hold, and
    /// accept that an object deleted from it will not be reported.
    ///
    /// Off by default, and the default is a refusal. Nothing on a plain remote
    /// records what was written there, so a run can only examine the keys the
    /// remote reports — and an object that is gone is not missing from that
    /// list, it is simply absent from it. A store that quietly lost half its
    /// objects would report the other half and exit 0.
    ///
    /// A vault records an index row per object outside the remote, so a lost
    /// object is reported missing at exit 4 and this flag is neither needed nor
    /// accepted as a substitute for one. `dctl check SOURCE REMOTE:` compares a
    /// replica against the tree it replicates, which is the only independent
    /// record a plain replica has.
    #[arg(long)]
    pub allow_listing_as_inventory: bool,
}

/// One claim the command makes that the remote in hand cannot support.
///
/// A struct rather than two parallel `Vec`s, so a notice can never be joined to
/// another limit's hint — which is the failure mode of a refusal that names the
/// wrong next action, and `HANDOVER.md` §16 records three of those.
struct Unmet {
    /// What the remote does not have, phrased as a predicate on the remote.
    notice: &'static str,
    /// What follows for the operator, in the words of the damage they will not
    /// be told about.
    consequence: &'static str,
    /// The flag that accepts exactly this limit and no other.
    flag: &'static str,
    /// What to do instead of accepting it.
    hint: &'static str,
}

/// Refuse a run whose source cannot make a claim the command exists to make.
///
/// Called before the walk starts, so a remote that cannot be certified costs
/// nothing to find out about — rather than an hour of egress followed by a
/// caveat.
///
/// Both limits are reported in **one** refusal. A gate that named the rot limit,
/// accepted a flag for it and then named the loss limit on the next run would
/// train an operator to add flags until the command went quiet, which is the
/// opposite of what a refusal is for.
///
/// # Errors
/// [`ExitCode::VerificationNotPossible`] when `claims` cannot support a claim
/// the command publishes and the operator has not accepted that limit by name.
pub fn require(command: &str, target: &str, claims: Claims, args: &AssuranceArgs) -> Result<()> {
    let mut unmet: Vec<Unmet> = Vec::new();
    if !claims.assurance.detects_corruption() && !args.allow_read_back {
        unmet.push(Unmet {
            notice: ASSURANCE_REFUSED_NOTICE,
            consequence: ASSURANCE_REFUSED_CONSEQUENCE,
            flag: READ_BACK_FLAG,
            hint: ASSURANCE_REFUSED_HINT,
        });
    }
    if !claims.inventory.detects_loss() && !args.allow_listing_as_inventory {
        unmet.push(Unmet {
            notice: INVENTORY_REFUSED_NOTICE,
            consequence: INVENTORY_REFUSED_CONSEQUENCE,
            flag: INVENTORY_FLAG,
            hint: INVENTORY_REFUSED_HINT,
        });
    }
    if unmet.is_empty() {
        return Ok(());
    }

    let findings = unmet
        .iter()
        .map(|claim| {
            format!(
                "it {}, so {} ({} accepts that)",
                claim.notice, claim.consequence, claim.flag
            )
        })
        .collect::<Vec<_>>()
        .join(INTEGRITY_REFUSED_JOIN);
    let hint = unmet
        .iter()
        .map(|claim| claim.hint)
        .collect::<Vec<_>>()
        .join(" ");

    Err(CliError::new(
        ExitCode::VerificationNotPossible,
        format!("'{target}' cannot support what `{command}` reports: {findings}"),
    )
    .with_hint(hint))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{Assurance, Inventory};

    /// A plain filesystem remote: no digest, and its listing is the only list.
    const fn plain_filesystem() -> Claims {
        Claims::new(Assurance::ReadBack, Inventory::SelfReported)
    }

    /// A plain remote whose provider records a per-object digest — live B2. It
    /// detects a changed byte and it still cannot detect a deleted object.
    const fn plain_with_digests() -> Claims {
        Claims::new(Assurance::ProviderChecksum, Inventory::SelfReported)
    }

    /// A sealed vault: both claims available.
    const fn vault() -> Claims {
        Claims::new(Assurance::Authenticated, Inventory::Recorded)
    }

    fn accepting_read_back() -> AssuranceArgs {
        AssuranceArgs {
            allow_read_back: true,
            allow_listing_as_inventory: false,
        }
    }

    fn accepting_listing() -> AssuranceArgs {
        AssuranceArgs {
            allow_read_back: false,
            allow_listing_as_inventory: true,
        }
    }

    fn accepting_both() -> AssuranceArgs {
        AssuranceArgs {
            allow_read_back: true,
            allow_listing_as_inventory: true,
        }
    }

    #[test]
    fn a_remote_that_cannot_detect_a_changed_byte_is_refused_by_default() {
        // The whole point. This is the run that used to print `ok` over a store
        // holding a flipped byte and exit 0.
        let error = require(
            "dctl verify",
            "pl:",
            plain_filesystem(),
            &AssuranceArgs::default(),
        )
        .expect_err("a remote that records nothing must be refused");
        assert_eq!(error.code(), ExitCode::VerificationNotPossible);
        assert_eq!(error.code().as_i32(), 27);
        assert!(error.message().contains("pl:"), "{}", error.message());
        assert!(error.hint().is_some(), "an operator needs a next action");
    }

    #[test]
    fn a_remote_whose_listing_is_its_own_record_is_refused_by_default() {
        // The defect this axis exists for, and the reason it is not folded into
        // the assurance: this remote *can* detect a changed byte — live B2
        // records a per-object digest — and the gate let it straight through
        // while a deleted object exited 0.
        assert!(
            plain_with_digests().assurance.detects_corruption(),
            "the pairing only means something if the byte axis is satisfied"
        );
        let error = require(
            "dctl verify",
            "pb:",
            plain_with_digests(),
            &AssuranceArgs::default(),
        )
        .expect_err("a remote with no record of what it holds must be refused");
        assert_eq!(error.code(), ExitCode::VerificationNotPossible);
        assert_eq!(error.code().as_i32(), 27);
        assert!(
            error.message().contains(INVENTORY_FLAG),
            "the refusal must name the flag that accepts it: {}",
            error.message()
        );
    }

    #[test]
    fn accepting_the_read_back_does_not_accept_a_listing_as_a_record() {
        // Exactly the command line that was measured reporting `OK 2 objects
        // examined` and exit 0 over three objects one of which had been deleted.
        let error = require(
            "dctl verify",
            "pl:",
            plain_filesystem(),
            &accepting_read_back(),
        )
        .expect_err("the read-back proves nothing about an object that is gone");
        assert_eq!(error.code(), ExitCode::VerificationNotPossible);
        assert!(
            error.message().contains(INVENTORY_FLAG),
            "{}",
            error.message()
        );
        assert!(
            !error.message().contains(READ_BACK_FLAG),
            "the limit the operator already accepted must not be re-raised: {}",
            error.message()
        );
    }

    #[test]
    fn accepting_the_listing_does_not_accept_a_remote_that_cannot_detect_rot() {
        // The other direction, and it has to hold too, or the second flag would
        // be a way to switch the first one off.
        let error = require(
            "dctl verify",
            "pl:",
            plain_filesystem(),
            &accepting_listing(),
        )
        .expect_err("a listing accepted as a record says nothing about the bytes");
        assert_eq!(error.code(), ExitCode::VerificationNotPossible);
        assert!(
            error.message().contains(READ_BACK_FLAG),
            "{}",
            error.message()
        );
        assert!(
            !error.message().contains(INVENTORY_FLAG),
            "{}",
            error.message()
        );
    }

    #[test]
    fn a_remote_that_can_answer_neither_is_told_both_at_once() {
        // A gate that named one limit per run would train an operator to add
        // flags until the command went quiet.
        let error = require(
            "dctl verify",
            "pl:",
            plain_filesystem(),
            &AssuranceArgs::default(),
        )
        .expect_err("refused");
        assert!(
            error.message().contains(READ_BACK_FLAG) && error.message().contains(INVENTORY_FLAG),
            "one refusal must name both limits and both flags: {}",
            error.message()
        );
        let hint = error.hint().expect("a next action");
        assert!(
            hint.contains("dctl init") && hint.contains("dctl check"),
            "the hint must name what actually detects each loss: {hint}"
        );
    }

    #[test]
    fn the_refusal_is_not_a_claim_that_anything_is_damaged_or_gone() {
        // The over-correction this code is kept apart from: 21 means the bytes
        // were checked and failed, and 4 means an object was looked for and was
        // not there. Neither has been shown.
        let error = require(
            "dctl scrub",
            "ps:",
            plain_filesystem(),
            &AssuranceArgs::default(),
        )
        .expect_err("refused");
        assert_ne!(error.code(), ExitCode::IntegrityFailure);
        assert_ne!(error.code(), ExitCode::FileNotFound);
        assert!(
            !error.message().to_lowercase().contains("corrupt"),
            "nothing has been shown to be damaged: {}",
            error.message()
        );
    }

    #[test]
    fn a_vault_needs_no_permission_for_either_claim() {
        require(
            "dctl verify",
            "archive:",
            vault(),
            &AssuranceArgs::default(),
        )
        .expect("a source that can answer both questions needs no permission");
    }

    #[test]
    fn the_operator_can_ask_for_the_weaker_run_and_then_gets_it() {
        // The flags have to actually do something, or they are two of the
        // eleven (`HANDOVER.md` §13).
        require("dctl verify", "pl:", plain_filesystem(), &accepting_both())
            .expect("the operator accepted both limits by name");
        require(
            "dctl verify",
            "pb:",
            plain_with_digests(),
            &accepting_listing(),
        )
        .expect("a B2 remote is short of one claim, not two");
    }

    #[test]
    fn the_flags_the_refusal_names_are_the_flags_that_exist() {
        // A refusal naming a flag `clap` does not define sends an operator to
        // `error: unexpected argument`, which is a worse failure than the one
        // being reported. Asked of the parser rather than asserted against a
        // literal, so a rename cannot leave the message behind.
        use clap::CommandFactory;
        let cli = crate::cli::Cli::command();
        for name in ["verify", "scrub"] {
            let rendered = cli
                .clone()
                .find_subcommand_mut(name)
                .expect("the subcommand exists")
                .render_long_help()
                .to_string();
            for flag in [READ_BACK_FLAG, INVENTORY_FLAG] {
                assert!(
                    rendered.contains(flag),
                    "the help for the {name} subcommand does not offer {flag}"
                );
            }
        }
    }

    #[test]
    fn the_help_does_not_promise_the_check_that_was_measured_missing() {
        // The defect in the place the operator actually meets it. The flag's
        // help said the read-back "is how a replica quietly losing objects is
        // caught", which is the one damage it was measured not to catch.
        use clap::CommandFactory;
        let cli = crate::cli::Cli::command();
        for name in ["verify", "scrub"] {
            let rendered = cli
                .clone()
                .find_subcommand_mut(name)
                .expect("the subcommand exists")
                .render_long_help()
                .to_string()
                .to_lowercase();
            assert!(
                !rendered.contains("losing objects is caught"),
                "the help for the {name} subcommand still claims the read-back catches a \
                 lost object"
            );
        }
    }
}
