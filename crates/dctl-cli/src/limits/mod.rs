//! The two cost controls, resolved once and shared by the whole run.
//!
//! `--bwlimit` and `--max-transfer` are not tuning knobs. They are the flags an
//! operator sets so that a job which goes wrong cannot generate a bill, and
//! before this module existed both of them parsed, appeared in `dctl --help`,
//! and did nothing at all: `--bwlimit 1k` moved 10 MiB at 32.9 MiB/s, and
//! `--max-transfer 1M` moved the whole 10 MiB and exited **0**, which made exit
//! code 8 unreachable in any build.
//!
//! They live together because they are charged from the same place with the
//! same number — the bytes [`StageDriver::upload`] measured leaving — and
//! because a run where the two disagreed about what had moved would be worse
//! than a run with neither. One structure, built once, on [`crate::ctx::Ctx`].
//!
//! ## Where they are applied
//!
//! [`crate::commands::transfer::pipeline`], which is the single path every
//! transfer verb goes through: `copy`, `move`, `sync`, `copyto` and `moveto` all
//! reach it, and `sync`'s interleaved `--delete-during` loop calls the same
//! entry point. The budget is asked *before* a file starts and the bandwidth
//! charged *after* it finishes; each module documents why its side is the right
//! one.
//!
//! ## What is deliberately not capped
//!
//! `replicate`, `restore` and `cat` do not pass through that pipeline and are
//! therefore uncapped in this build. That is a gap rather than a decision, and
//! it is named here rather than left for someone to discover: the honest fix is
//! for those paths to share the pipeline, not for three more call sites to grow
//! their own charge points and drift.
//!
//! [`StageDriver::upload`]: crate::commands::transfer::pipeline::StageDriver::upload

pub mod bandwidth;
pub mod budget;
pub mod quantity;

use std::sync::Arc;

use crate::cli::GlobalArgs;

pub use bandwidth::Bandwidth;
pub use budget::Budget;
pub use quantity::ByteLimit;

/// The cost controls in force for one run.
#[derive(Debug)]
pub struct Limits {
    /// The pace, from `--bwlimit`.
    pub bandwidth: Arc<Bandwidth>,
    /// The ceiling, from `--max-transfer`.
    pub budget: Budget,
}

impl Limits {
    /// This run's pace, as the storage layer's [`Meter`](dctl_store::Meter).
    ///
    /// One limiter shared by every backend a command opens, because "do not use
    /// more than 1 MB/s of my uplink" is a statement about the uplink and not
    /// about each destination separately. A command that opens two remotes and
    /// got two limiters would move at twice the rate the operator asked for.
    #[must_use]
    pub fn meter(&self) -> Arc<dyn dctl_store::Meter> {
        Arc::clone(&self.bandwidth) as Arc<dyn dctl_store::Meter>
    }

    /// Resolve both from the parsed flags.
    ///
    /// Infallible, and that is a property of the types rather than an omission:
    /// [`ByteLimit`] parses at the command line, so a malformed `--bwlimit` is
    /// a usage error before any command body runs and nothing downstream can
    /// hold a value it has not validated.
    #[must_use]
    pub fn resolve(globals: &GlobalArgs) -> Self {
        Self {
            bandwidth: Arc::new(Bandwidth::new(globals.bwlimit.unwrap_or_default())),
            budget: Budget::new(globals.max_transfer.unwrap_or_default()),
        }
    }
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

    fn limits(args: &[&str]) -> Limits {
        let parsed = Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()));
        Limits::resolve(&parsed.globals)
    }

    #[test]
    fn a_run_with_neither_flag_is_uncapped() {
        let limits = limits(&[]);
        assert!(!limits.bandwidth.is_limited());
        limits
            .budget
            .afford(u64::MAX, "x", crate::output::Units::Binary)
            .unwrap();
    }

    #[test]
    fn both_flags_reach_their_limiters() {
        let limits = limits(&["--bwlimit", "1M", "--max-transfer", "10M"]);
        assert!(limits.bandwidth.is_limited());
        assert!(
            limits
                .budget
                .afford(11 * 1024 * 1024, "x", crate::output::Units::Binary)
                .is_err()
        );
    }

    #[test]
    fn off_is_the_same_as_absent() {
        let limits = limits(&["--bwlimit", "off", "--max-transfer", "off"]);
        assert!(!limits.bandwidth.is_limited());
        limits
            .budget
            .afford(u64::MAX, "x", crate::output::Units::Binary)
            .unwrap();
    }

    #[test]
    fn a_malformed_limit_is_refused_by_the_parser() {
        // The whole reason `ByteLimit` is a clap type: this must fail here, at
        // parse time, and not become a silently unlimited run.
        assert!(Harness::try_parse_from(["dctl", "--bwlimit", "10Q"]).is_err());
        assert!(Harness::try_parse_from(["dctl", "--max-transfer", "wat"]).is_err());
    }
}
