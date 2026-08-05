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
use crate::constants::{MAX_DURATION_HINT, MAX_DURATION_REACHED};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use dctl_store::Deadlines;

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

    /// How long this run waits — `--contimeout` to reach a host, `--timeout` for
    /// one that has gone quiet, and `--max-duration` for the run itself.
    ///
    /// On the context for the same reason [`Ctx::limits`] is: patience is a
    /// property of the *invocation*, not of each destination, and an operator
    /// who said "my backup window is thirty seconds" means it about the run. A
    /// command that had to construct its own is a command that could forget to,
    /// which is the failure that put eleven flags on `cli::reach`'s list.
    ///
    /// The third of the three is read from the clock **here**, once, when the
    /// context is built. That is what makes it a bound on the run rather than a
    /// bound on each thing the run does: a deadline computed wherever it was
    /// needed would give every file, every request and every retry the whole
    /// window over again — which is precisely the arithmetic behind the run in
    /// which `--timeout 30` fired exactly on time and the command carried on for
    /// 943.6 s.
    pub deadlines: Deadlines,

    /// The tamper-evident log every data-changing operation appends to
    /// ([the plan](https://doc.dctl.sh/project/plan) §7).
    ///
    /// Resolved here with everything else ambiguous, and opened lazily by the
    /// first record, so a read-only command leaves no evidence file behind. It
    /// lives on the context rather than being threaded through each command for
    /// the same reason the counters do: a million-file run must pay the open
    /// once, and a command that had to remember to construct one is a command
    /// that can forget.
    /// `Arc` so the mount can share it: the session record is appended by the
    /// command and the first-read records by the filesystem, which outlives
    /// the call that started it. Every other call site reaches it by method
    /// syntax and is unaffected.
    pub audit: Arc<Sink>,
}

impl Ctx {
    /// Build a context from parsed globals.
    #[must_use]
    pub fn new(globals: GlobalArgs) -> Self {
        let audit = Arc::new(Sink::new(&globals));
        let limits = Limits::resolve(&globals);
        let deadlines = Deadlines::from_seconds(globals.contimeout, globals.timeout).within(
            dctl_store::RunDeadline::starting_now(globals.max_duration.unwrap_or_default().get()),
        );
        let out = Out::new(
            globals.effective_format(),
            globals.color,
            globals.units,
            globals.quiet,
            globals.verbose,
        );
        let stats = Stats::shared();
        let progress = Arc::new(Progress::new(
            // `--json` and `--quiet` are handed over separately, and the
            // difference is what `-P` acts on: silence is absolute, machine
            // output is only a default. See `ProgressMode::resolve`.
            crate::output::ProgressMode::resolve(
                globals.progress,
                globals.quiet,
                out.is_json(),
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
            deadlines,
            audit,
        }
    }

    /// Whether this run must not modify anything.
    #[must_use]
    pub const fn is_dry_run(&self) -> bool {
        self.globals.dry_run
    }

    /// Refuse to start more work when the run's `--max-duration` has passed.
    ///
    /// The counterpart of [`crate::limits::Budget::afford`], and asked in the
    /// same place for the same reason: a ceiling that is only noticed *after*
    /// the work is a ceiling that has already been exceeded. `subject` names the
    /// file that would have been started, so the last line of a run that ran out
    /// of time says where it stopped rather than merely that it did.
    ///
    /// This is the *tidy* half of the bound. The hard half is in `main`, which
    /// races the whole command against the same instant — because a file that is
    /// already in flight cannot be stopped by a check between files, and a run
    /// that has one enormous object left has to end too. Both are needed; see
    /// `dctl_store::deadline::run` for the three depths and what each covers.
    ///
    /// # Errors
    /// [`ExitCode::DurationLimitExceeded`] — exit 10 — naming the window the
    /// operator set and the file the run declined to start. The message says
    /// what *did* happen, because a run stopped at its deadline is a success up
    /// to that point and the operator's next question is where to resume.
    pub fn within_deadline(&self, subject: &str) -> Result<()> {
        let Some(exceeded) = self.deadlines.run.exceeded() else {
            return Ok(());
        };
        Err(CliError::new(
            ExitCode::DurationLimitExceeded,
            format!("{MAX_DURATION_REACHED}: '{subject}' was not started ({exceeded})"),
        )
        .with_hint(MAX_DURATION_HINT))
    }

    /// The verification strength a run addressed to `spec` applies.
    ///
    /// It used to be `verify_mode(&self)` — a function of the flag and nothing
    /// else — and that signature *was* the defect. `verify` is declared on all
    /// six providers, accepted by `dctl config create` and printed by
    /// `dctl config show`, and no caller could have honoured it because no
    /// caller was given a remote to ask about. Taking the destination is what
    /// makes forgetting it a compile error rather than a silent `checksum`.
    ///
    /// The rule and the precedence live in
    /// [`crate::remote::resolve::verify_policy`]; this is the seam that supplies
    /// it the configuration, on the same pattern as [`crate::remote::place::Place::of`].
    ///
    /// Not called per file. The transfer pipeline asks its driver
    /// ([`crate::commands::transfer::pipeline::StageDriver::verify_mode`]),
    /// which resolved this once when it connected — a million-file run must not
    /// re-read the configuration a million times.
    ///
    /// # Errors
    /// [`ExitCode::FatalError`] for an unreadable configuration or a `verify`
    /// value that is not one of the modes, naming the remote and the value.
    pub fn verify_mode_for(&self, spec: &crate::remote::RemoteSpec) -> Result<VerifyMode> {
        let path = crate::config::resolve_path(self.globals.config.as_deref());
        let configured = crate::config::load_or_default(&path)?;
        crate::remote::resolve::verify_policy(
            self.globals.verify,
            spec,
            &crate::commands::config::settings::catalog(&configured),
        )
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

    /// Emit the end-of-run summary, unless the run failed having landed
    /// nothing.
    ///
    /// The exception is narrow on purpose. A `copy` that moved nine hundred of a
    /// thousand files and then failed needs its summary — that is the only
    /// record of what did land. A run that refused has no such record — even
    /// when the planner had already listed the source and counted its skips
    /// before the refusal fired, as every remote-to-remote transfer does —
    /// and printing one anyway put `Errors: 0` in a table directly above
    /// `error: …`, which is not noise but a contradiction. See
    /// [`Snapshot::nothing_landed`](crate::output::stats::Snapshot::nothing_landed).
    pub fn finish_with(&self, show_summary: bool, ran: Ran) {
        self.progress.finish();
        if !show_summary {
            return;
        }
        let snapshot = self.stats.snapshot();
        if ran == Ran::Failed && snapshot.nothing_landed() {
            return;
        }
        self.out.summary(&snapshot);
    }

    /// The exit code implied by the counters.
    ///
    /// [The plan](https://doc.dctl.sh/project/plan) §7 forbids rolling a partial failure up into success, so any
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
    fn verify_mode_defaults_to_checksum_and_the_flag_still_wins() {
        // A bare path names no remote, so there is no policy to state and the
        // compiled default applies. The flag overrides it, which is the half
        // that has always worked.
        let bare = crate::remote::RemoteSpec::Local(std::path::PathBuf::from("/srv/x"));
        assert_eq!(
            ctx(&[]).verify_mode_for(&bare).expect("resolves"),
            VerifyMode::Checksum
        );
        assert_eq!(
            ctx(&["--verify", "strict"])
                .verify_mode_for(&bare)
                .expect("resolves"),
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
