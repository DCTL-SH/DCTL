//! DCTL — encrypted, verified, metadata-private cloud storage.
//!
//! This file owns *process* concerns only: parsing, installing logging, running
//! the command, and converting the outcome into an exit status. Routing lives in
//! [`dispatch`], and every command lives in its own module under [`commands`].
//!
//! ## The exit-status contract
//!
//! `main` never returns `Result`. Rust's default `Termination` for an `Err`
//! prints a `Debug` representation and exits 1, which would collapse DCTL's
//! entire taxonomy — a checksum mismatch and a typo in a flag would be
//! indistinguishable to a script. Instead every path ends at
//! [`std::process::exit`] with a code from [`exit::ExitCode`].
//!
//! Two rules follow from [the plan](https://doc.dctl.sh/project/plan) §7 and are enforced here rather than trusted
//! to each command:
//!
//! * A command that returns `Ok` but recorded errors still exits non-zero —
//!   partial failure is never rolled up into success.
//! * Cancellation is not success. Ctrl-C exits 25, so a wrapper script can tell
//!   "the operator stopped it" from "it finished".

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Inline unit tests may use unwrap/expect; command and library code may not.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod addressing;
mod audit;
mod cli;
mod commands;
mod config;
mod constants;
mod ctx;
mod dispatch;
mod error;
mod exit;
mod filter;
mod limits;
mod links;
mod logging;
// The read-only FUSE filesystem, on the two platforms that have a FUSE layer.
// Target-gated in one place rather than inside every file it contains: on
// Windows there is no kernel interface to compile against, and `commands::mount`
// answers that with a refusal naming WinFSP ([the plan](https://doc.dctl.sh/project/plan) §15) rather than with a
// module full of `#[cfg]`s that could not work if they compiled.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod mount;
mod output;
mod platform;
mod remote;
mod session;
mod source;
mod specials;

use clap::Parser;

use cli::Cli;
use ctx::Ctx;
use error::CliError;
use exit::ExitCode;
use logging::{LogConfig, fields};

fn main() {
    // Parse first: a usage error must be reported before anything else is set
    // up, and clap already renders those well.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            // clap reports `--help` and `--version` through `Err` too, but they
            // are not failures: exiting non-zero would break `dctl --help` in
            // any script running under `set -e`.
            let _ = error.print();
            let code = if error.use_stderr() {
                ExitCode::Usage
            } else {
                ExitCode::Success
            };
            std::process::exit(code.as_i32());
        }
    };

    let code = run(cli);
    std::process::exit(code.as_i32());
}

/// Set up the runtime and execute the command, returning its exit status.
fn run(cli: Cli) -> ExitCode {
    // Logging first, so that failures during setup are themselves logged.
    if let Err(error) = install_logging(&cli) {
        eprintln!("{} {error}", constants::ERROR_PREFIX);
        return ExitCode::FatalError;
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!(
                "{} cannot start async runtime: {error}",
                constants::ERROR_PREFIX
            );
            return ExitCode::FatalError;
        }
    };

    let (code, ending) = runtime.block_on(execute(cli));

    // A run that was **stopped** does not then wait for the work it stopped.
    //
    // This is the last place `--max-duration` could have failed to be a bound,
    // and it did: measured live, a `--max-duration 3s` copy of 8 MiB at
    // `--bwlimit 64k` into a configured `local:` remote printed its deadline on
    // time and exited **126 s** later. The report was right and the process was
    // still there — the same defect with a new cause: a deadline that reports
    // on time and does not end the run.
    //
    // The cause is that `spawn_blocking` work cannot be cancelled. `local:`
    // copies inside one and paces there with a real `std::thread::sleep`
    // (`dctl_store::meter::charge_blocking`, which is correct for what it is);
    // dropping the command future detaches that task rather than ending it, and
    // `Runtime::drop` then waits for the blocking pool to drain — all 128
    // seconds of pacing for bytes nobody will ever look at.
    //
    // `shutdown_background` is the documented way to say "do not wait", and it
    // is applied **only** to the endings that abandoned something. A run that
    // finished normally has awaited everything it spawned, so there is nothing
    // to abandon and today's behaviour is kept: the difference matters because
    // the durability contract is that what was *reported* as stored is durable,
    // and nothing here may weaken it. On the abandoned path nothing was
    // reported as stored — the file in flight is not counted — so there is no
    // claim to protect.
    if ending == Ending::Abandoned {
        runtime.shutdown_background();
    }
    code
}

/// What the process must do about work that outlived the run.
///
/// Two states rather than a bool so the call sites read as what happened rather
/// than as a flag whose polarity has to be remembered — the same reason
/// [`ctx::Ran`] has two.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ending {
    /// The command returned. Anything it spawned, it also awaited.
    Completed,
    /// The command was stopped where it stood — `--max-duration` or a signal —
    /// and whatever it had in flight was left running.
    Abandoned,
}

/// Told to the user when a flag this build cannot honour is refused before a
/// command begins.
///
/// The refusal happens before anything is read, written or unlocked, so this is
/// the complete account of the run's effects. Saying it explicitly stops the
/// reader wondering whether a partial change needs cleaning up.
const NOTHING_ATTEMPTED: &str = "No command was run and nothing was read or written.";

/// What happened to the command future.
enum Outcome {
    Finished(error::Result<()>),
    Cancelled,
    /// The run reached the deadline `--max-duration` gave it.
    ///
    /// A third state rather than a `Finished(Err(...))`, because it is not
    /// something the command *returned*: the command future was dropped where
    /// it stood. Folding it into either of the other two would lose the one
    /// fact a wrapper script needs — that the window closed, rather than that
    /// the work failed or that somebody pressed Ctrl-C.
    OutOfTime(std::time::Duration),
}

/// Run the command, racing it against an interrupt and against the run's own
/// deadline.
///
/// Returns the exit status **and** whether anything was left running, because
/// the caller owns the runtime and is the only place that can decide not to
/// wait for it. See [`run`].
async fn execute(cli: Cli) -> (ExitCode, Ending) {
    let show_summary = cli.command.is_transfer();
    // Resolved before the globals are moved into the context, and resolved once:
    // `--progress` shortens the cadence and `--stats 0` turns it off, and a
    // second place deciding that is a second place for them to disagree.
    let record_interval =
        output::progress::ticker::interval(cli.globals.progress, cli.globals.stats);
    let context = Ctx::new(cli.globals);

    tracing::debug!(
        { fields::OP } = cli.command.name(),
        dry_run = context.is_dry_run(),
        "starting"
    );

    // Refused here, once, for every command — not inside the vault-unlock path.
    //
    // The `--key-file` half lived in `session::open`, which a local-to-local
    // transfer never calls, so `dctl copy ./src ./dst --key-file kf` accepted
    // the flag, ignored it and exited 0. A second factor that is silently
    // dropped on some routes and honoured on others is worse than one that is
    // never honoured at all: the operator cannot tell which run protected them.
    // One chokepoint every command passes through is the only arrangement that
    // cannot be bypassed by adding a new command later.
    //
    // The same gate now carries the rest of the flags this build cannot honour
    // (`cli::reach`), for the same reason and against a worse history: eleven of
    // them parsed, appeared in `--help`, and did nothing at all. `--bwlimit 1k`
    // moved 10 MiB at 32.9 MiB/s. Whatever else is true of a refusal, it is not
    // that.
    //
    // What is passed is the *operation*, and only the operation: the flag and
    // the missing capability are appended by `refuse_if_present` itself. That
    // split exists because of what this exact line used to produce. It handed
    // over `dctl init` as the whole subject, so the refusal read "dctl init is
    // not implemented in this build" — a false statement about a command that is
    // entirely implemented, shown to somebody whose only mistake was asking for
    // a second factor. Every other call site spelled the flag out by hand and
    // read correctly, which is why nothing noticed.
    if let Err(error) = cli::refuse::refuse_if_present(
        &context.globals,
        &format!("dctl {}", cli.command.name()),
        NOTHING_ATTEMPTED,
    ) {
        report(&context, &error);
        return (error.code(), Ending::Completed);
    }

    // An interrupted run must never be reported as success: in-flight work is
    // either resumable or rolled back, and the index commit that would make it
    // count as stored never happened ([the plan](https://doc.dctl.sh/project/plan) §6 step 6).
    //
    // The periodic status line lives and dies inside this block. A redirected
    // run draws no bars, so it is the only thing that reports movement while the
    // command is running — and the scope is what guarantees it stops before the
    // summary below is printed. A status line emitted after the final report
    // would show smaller numbers than the report it follows, which reads as
    // though the run had gone backwards.
    let outcome = {
        let _ticker = output::progress::ticker::spawn(
            &context.progress,
            &context.stats,
            record_interval,
            output::progress::ticker::Style::resolve(context.globals.stats_one_line),
        );

        tokio::select! {
            result = dispatch::dispatch(&context, &cli.command) => Outcome::Finished(result),
            _ = tokio::signal::ctrl_c() => Outcome::Cancelled,
            // The run's own deadline, and the reason it is *here* as well as in
            // every layer below. The layers below make the ending orderly — the
            // request is cancelled by name, the retry loop is not re-entered, no
            // further file is started — and none of them can promise the wall
            // clock, because none of them owns the work that no future owns: a
            // blocking read inside `spawn_blocking`, an `ssh` child, a
            // filesystem call in uninterruptible sleep. Dropping the command
            // future is what makes `--max-duration` a bound rather than a
            // request, and it is exactly what rclone's default
            // `--cutoff-mode hard` does with a cancelled context.
            //
            // Nothing is left half-written by it. A verified write commits only
            // when the stored bytes match, so an abandoned object was never an
            // object; the debris is a staging file or an unfinished multipart
            // upload, and the hint on the way out names the command that
            // reclaims them.
            limit = out_of_time(&context) => Outcome::OutOfTime(limit),
        }
    };

    match outcome {
        Outcome::OutOfTime(limit) => {
            // The summary is shown, not suppressed. A run stopped at its
            // deadline is a success up to that point, and the counters are the
            // only record of how far it got — which is the first thing an
            // operator sizing tomorrow's window needs to know.
            context.finish(show_summary);
            let error = CliError::new(
                ExitCode::DurationLimitExceeded,
                format!(
                    "{}: the run was stopped after {}s with work still in flight",
                    constants::MAX_DURATION_REACHED,
                    limit.as_secs()
                ),
            )
            .with_hint(constants::MAX_DURATION_HINT);
            report(&context, &error);
            // Abandoned by construction: the command future was dropped where
            // it stood, so whatever it had spawned is still running.
            (ExitCode::DurationLimitExceeded, Ending::Abandoned)
        }

        Outcome::Cancelled => {
            context.finish(false);
            context
                .out
                .error("cancelled — no partial work was reported as stored");
            tracing::warn!(
                { fields::ERROR_CODE } = ExitCode::Cancelled.slug(),
                "cancelled"
            );
            // The same shape as the deadline: dropped where it stood. This
            // ending had the identical defect and had it before
            // `--max-duration` existed — a Ctrl-C on a paced `local:` copy sat
            // there for the rest of the pacing.
            (ExitCode::Cancelled, Ending::Abandoned)
        }

        Outcome::Finished(Ok(())) => {
            context.finish(show_summary);
            // A command can return Ok while individual files failed; the
            // counters, not the return value, decide the exit status.
            let code = context.outcome();
            if code != ExitCode::Success {
                tracing::warn!(
                    { fields::ERROR_CODE } = code.slug(),
                    "completed with errors"
                );
            }
            (code, Ending::Completed)
        }

        Outcome::Finished(Err(error)) => {
            // `Ran::Failed` suppresses the summary when nothing was attempted.
            // A partial run keeps it — the counters are the only record of what
            // did land — but a refusal has nothing to report, and printing
            // `Errors: 0` in a table immediately above `error: …` contradicted
            // the line it introduced.
            context.finish_with(show_summary, ctx::Ran::Failed);
            report(&context, &error);
            (error.code(), Ending::Completed)
        }
    }
}

/// Resolve when this run's `--max-duration` has passed, and never otherwise.
///
/// Written as a future rather than as a `tokio::time::timeout` around the
/// dispatch so the `select!` above reads as the three things that can end a run,
/// side by side. An unbounded run gets [`std::future::pending`]: no timer, no
/// wakeups, and no arithmetic that could one day overflow into one — the same
/// rule `dctl_store::deadline` follows for the other two deadlines.
async fn out_of_time(context: &Ctx) -> std::time::Duration {
    let Some(limit) = context.deadlines.run.limit() else {
        return std::future::pending().await;
    };
    match context.deadlines.run.left() {
        dctl_store::Left::Unbounded => std::future::pending().await,
        dctl_store::Left::Remaining(left) => tokio::time::sleep(left).await,
        // Already gone before the command started, which a `--max-duration`
        // shorter than the vault unlock can produce. Nothing is awaited: the
        // run is over, and sleeping for zero to say so would only add a wakeup.
        dctl_store::Left::Spent => {}
    }
    limit
}

/// Report a failure to both sinks.
///
/// The human gets a message and a remediation hint on stderr; the log pipeline
/// gets the stable slug it can alert on.
fn report(context: &Ctx, error: &CliError) {
    tracing::error!(
        { fields::ERROR_CODE } = error.code().slug(),
        exit_code = error.code().as_i32(),
        "{}",
        error.message()
    );

    context.out.error(error.message());
    if let Some(hint) = error.hint() {
        context.out.warn(hint);
    }
}

/// Build the logging configuration from the flags and install it.
fn install_logging(cli: &Cli) -> Result<(), logging::LogInitError> {
    let globals = &cli.globals;
    logging::init(&LogConfig {
        level: globals.effective_log_level(),
        format: globals.log_format,
        file: globals.log_file.clone(),
        show_source: globals.log_source,
        // Logs share stderr with the progress display, so they follow the same
        // colour decision the user made for everything else.
        color: globals.color.resolve(output::Out::stderr_is_terminal()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_and_version_are_reported_as_success() {
        for flag in ["--help", "--version"] {
            let error = Cli::try_parse_from(["dctl", flag]).unwrap_err();
            assert!(
                !error.use_stderr(),
                "{flag} must exit 0, not as a usage error"
            );
        }
    }

    #[test]
    fn bad_input_is_a_usage_error() {
        for args in [
            vec!["dctl", "--not-a-real-flag"],
            vec!["dctl", "frobnicate"],
            vec!["dctl"], // no subcommand
        ] {
            let error = Cli::try_parse_from(args.clone()).unwrap_err();
            assert!(error.use_stderr(), "{args:?} should be a usage error");
        }
    }

    #[test]
    fn transfer_commands_request_a_summary() {
        let copy = Cli::try_parse_from(["dctl", "copy", "a", "vault:b"]).unwrap();
        assert!(copy.command.is_transfer());
        let ls = Cli::try_parse_from(["dctl", "ls", "vault:"]).unwrap();
        assert!(!ls.command.is_transfer());
    }
}
