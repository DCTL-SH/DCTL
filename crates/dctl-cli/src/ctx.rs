//! The runtime context handed to every command.
//!
//! Commands receive a fully-resolved [`Ctx`] and never reach for global state,
//! parse a flag, or read an environment variable themselves. Everything
//! ambiguous — which config file, which remote, what the password is, whether
//! colour is on — is decided once, here, before any command body runs.
//!
//! That single-resolution rule is what makes commands testable: a test
//! constructs a `Ctx` pointing at a temporary directory and drives the command
//! directly, with no process environment involved.

use std::sync::Arc;

use crate::audit::sink::Sink;
use crate::cli::globals::{GlobalArgs, VerifyMode};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::limits::Limits;
use crate::output::{Out, Progress, Stats};

/// How a command body ended, as far as the end-of-run summary is concerned.
///
/// Two states rather than a bool so the call sites read as what happened rather
/// than as a flag whose polarity has to be remembered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ran {
    /// The body returned, whatever its per-file counters say.
    Completed,
    /// The body returned an error.
    Failed,
}

/// Resolved state for one command invocation.
pub struct Ctx {
    /// Fully-parsed global flags.
    pub globals: GlobalArgs,
    /// The output sink (stdout for data, stderr for everything else).
    pub out: Out,
    /// Live counters, shared with the progress renderer and worker tasks.
    pub stats: Arc<Stats>,
    /// The progress display.
    pub progress: Arc<Progress>,
    /// The two cost controls in force for this run — `--bwlimit` and
    /// `--max-transfer`.
    ///
    /// On the context rather than threaded through each command for the reason
    /// the counters are: they are *per run*, not per file or per destination,
    /// and "do not move more than 10 GB" is a statement about the whole
    /// invocation. A command that had to construct its own would be a command
    /// that could forget to, which is how eleven flags came to do nothing.
    pub limits: Limits,

    /// The tamper-evident log every data-changing operation appends to
    /// (`PLAN.md` §7).
    ///
    /// Resolved here with everything else ambiguous, and opened lazily by the
    /// first record, so a read-only command leaves no evidence file behind. It
    /// lives on the context rather than being threaded through each command for
    /// the same reason the counters do: a million-file run must pay the open
    /// once, and a command that had to remember to construct one is a command
    /// that can forget.
    pub audit: Sink,
}

impl Ctx {
    /// Build a context from parsed globals.
    #[must_use]
    pub fn new(globals: GlobalArgs) -> Self {
        let audit = Sink::new(&globals);
        let limits = Limits::resolve(&globals);
        let out = Out::new(
            globals.effective_format(),
            globals.color,
            globals.units,
            globals.quiet,
            globals.verbose,
        );
        let stats = Stats::shared();
        let progress = Arc::new(Progress::new(
            crate::output::ProgressMode::resolve(
                globals.progress,
                globals.quiet || out.is_json(),
                Out::stderr_is_terminal(),
            ),
            globals.units,
            globals.ascii,
            Arc::clone(&stats),
        ));

        Self {
            globals,
            out,
            stats,
            progress,
            limits,
            audit,
        }
    }

    /// Whether this run must not modify anything.
    #[must_use]
    pub const fn is_dry_run(&self) -> bool {
        self.globals.dry_run
    }

    /// The configured verification strength.
    #[must_use]
    pub const fn verify_mode(&self) -> VerifyMode {
        self.globals.verify
    }

    /// Announce an action that a dry run is skipping.
    ///
    /// Centralised so every command words it identically, and so `--dry-run`
    /// output is greppable: each line starts with the same marker.
    pub fn dry_run_notice(&self, action: &str, target: &str) {
        self.out
            .warn(format!("{DRY_RUN_MARKER} would {action}: {target}"));
    }

    /// Ask the user to confirm a destructive action.
    ///
    /// Returns `Ok(true)` when the action may proceed. `--force` approves
    /// without asking; `--dry-run` always declines; otherwise the user must
    /// type the confirmation word exactly.
    ///
    /// Refuses rather than assumes when there is no terminal to ask: an
    /// unattended job that would otherwise hang must fail loudly instead.
    pub fn confirm_destructive(&self, action: &str, target: &str) -> Result<bool> {
        if self.globals.dry_run {
            self.dry_run_notice(action, target);
            return Ok(false);
        }
        if self.globals.force {
            return Ok(true);
        }
        if !self.globals.interactive {
            return Ok(true);
        }

        if !Out::stderr_is_terminal() {
            return Err(CliError::new(
                ExitCode::Usage,
                format!("cannot confirm '{action}' on '{target}': no terminal available"),
            )
            .with_hint("Pass --force to approve destructive actions non-interactively."));
        }

        // Clear the bars so the prompt is not overdrawn mid-render.
        let answer = self.progress.suspend(|| {
            eprint!(
                "{} {action} '{target}'? Type '{}' to confirm: ",
                crate::constants::CONFIRM_PROMPT_PREFIX,
                crate::constants::DESTRUCTIVE_CONFIRMATION
            );
            use std::io::Write as _;
            let _ = std::io::stderr().flush();

            let mut line = String::new();
            match std::io::stdin().read_line(&mut line) {
                Ok(_) => line.trim().to_string(),
                Err(_) => String::new(),
            }
        });

        Ok(answer == crate::constants::DESTRUCTIVE_CONFIRMATION)
    }

    /// Emit the end-of-run summary, if this command should have one.
    pub fn finish(&self, show_summary: bool) {
        self.finish_with(show_summary, Ran::Completed);
    }

    /// Emit the end-of-run summary, unless the run failed having done nothing.
    ///
    /// The exception is narrow on purpose. A `copy` that moved nine hundred of a
    /// thousand files and then failed needs its summary — that is the only
    /// record of what did land. A run that refused before it started has no such
    /// record, and printing one anyway put `Errors: 0` in a table directly above
    /// `error: …`, which is not noise but a contradiction. See
    /// [`Snapshot::attempted_nothing`](crate::output::stats::Snapshot::attempted_nothing).
    pub fn finish_with(&self, show_summary: bool, ran: Ran) {
        self.progress.finish();
        if !show_summary {
            return;
        }
        let snapshot = self.stats.snapshot();
        if ran == Ran::Failed && snapshot.attempted_nothing() {
            return;
        }
        self.out.summary(&snapshot);
    }

    /// The exit code implied by the counters.
    ///
    /// `PLAN.md` §7 forbids rolling a partial failure up into success, so any
    /// recorded error downgrades the result even when the command body returned
    /// `Ok`.
    #[must_use]
    pub fn outcome(&self) -> ExitCode {
        let snapshot = self.stats.snapshot();
        if snapshot.checksum_mismatches > 0 {
            ExitCode::ChecksumMismatch
        } else if snapshot.errors > 0 {
            ExitCode::PartialFailure
        } else {
            ExitCode::Success
        }
    }
}

/// Marker prefixed to every `--dry-run` line, so the output can be filtered.
const DRY_RUN_MARKER: &str = "[dry-run]";

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        let parsed = Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()));
        Ctx::new(parsed.globals)
    }

    #[test]
    fn json_output_disables_the_progress_display() {
        // Bars on stderr would not corrupt JSON on stdout, but a machine
        // consumer running under a TTY should still get a clean run.
        let ctx = ctx(&["--json"]);
        assert!(ctx.out.is_json());
        assert_eq!(ctx.progress.mode(), crate::output::ProgressMode::Quiet);
    }

    #[test]
    fn dry_run_declines_every_destructive_action() {
        let ctx = ctx(&["--dry-run", "--force"]);
        assert!(ctx.is_dry_run());
        // --dry-run must win over --force.
        assert!(!ctx.confirm_destructive("delete", "vault:x").unwrap());
    }

    #[test]
    fn force_approves_without_prompting() {
        let ctx = ctx(&["--force"]);
        assert!(ctx.confirm_destructive("purge", "vault:old").unwrap());
    }

    #[test]
    fn non_interactive_runs_do_not_prompt() {
        // Without --interactive the caller has already accepted the risk by
        // typing the command; prompting would break every script.
        let ctx = ctx(&[]);
        assert!(ctx.confirm_destructive("delete", "vault:x").unwrap());
    }

    #[test]
    fn errors_downgrade_a_successful_return() {
        let ctx = ctx(&[]);
        assert_eq!(ctx.outcome(), ExitCode::Success);
        ctx.stats.error();
        assert_eq!(ctx.outcome(), ExitCode::PartialFailure);
    }

    #[test]
    fn a_checksum_mismatch_outranks_a_generic_error() {
        let ctx = ctx(&[]);
        ctx.stats.error();
        ctx.stats.checksum_mismatch();
        assert_eq!(ctx.outcome(), ExitCode::ChecksumMismatch);
    }

    #[test]
    fn verify_mode_defaults_to_checksum() {
        assert_eq!(ctx(&[]).verify_mode(), VerifyMode::Checksum);
        assert_eq!(
            ctx(&["--verify", "strict"]).verify_mode(),
            VerifyMode::Strict
        );
    }

    #[test]
    fn quiet_silences_the_progress_display() {
        assert_eq!(
            ctx(&["--quiet"]).progress.mode(),
            crate::output::ProgressMode::Quiet
        );
    }
}
