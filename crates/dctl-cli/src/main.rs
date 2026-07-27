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
//! Two rules follow from `PLAN.md` §7 and are enforced here rather than trusted
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
mod logging;
// The read-only FUSE filesystem, on the two platforms that have a FUSE layer.
// Target-gated in one place rather than inside every file it contains: on
// Windows there is no kernel interface to compile against, and `commands::mount`
// answers that with a refusal naming WinFSP (`PLAN.md` §15) rather than with a
// module full of `#[cfg]`s that could not work if they compiled.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod mount;
mod output;
mod platform;
mod remote;
mod session;
mod source;

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

    runtime.block_on(execute(cli))
}

/// Told to the user when `--key-file` is refused before a command begins.
///
/// The refusal happens before anything is read, written or unlocked, so this is
/// the complete account of the run's effects. Saying it explicitly stops the
/// reader wondering whether a partial change needs cleaning up.
const NOTHING_ATTEMPTED: &str = "No command was run and nothing was read or written.";

/// What happened to the command future.
enum Outcome {
    Finished(error::Result<()>),
    Cancelled,
}

/// Run the command, racing it against an interrupt.
async fn execute(cli: Cli) -> ExitCode {
    let show_summary = cli.command.is_transfer();
    let stats_interval = cli.globals.stats;
    let context = Ctx::new(cli.globals);

    tracing::debug!(
        { fields::OP } = cli.command.name(),
        dry_run = context.is_dry_run(),
        "starting"
    );

    // Refused here, once, for every command — not inside the vault-unlock path.
    //
    // It lived in `session::open`, which a local-to-local transfer never calls,
    // so `dctl copy ./src ./dst --key-file kf` accepted the flag, ignored it and
    // exited 0. A second factor that is silently dropped on some routes and
    // honoured on others is worse than one that is never honoured at all: the
    // operator cannot tell which run protected them. One chokepoint every
    // command passes through is the only arrangement that cannot be bypassed by
    // adding a new command later.
    //
    // What is passed is the *operation*, and only the operation: the flag and
    // the missing capability are appended by `refuse_if_present` itself. That
    // split exists because of what this exact line used to produce. It handed
    // over `dctl init` as the whole subject, so the refusal read "dctl init is
    // not implemented in this build" — a false statement about a command that is
    // entirely implemented, shown to somebody whose only mistake was asking for
    // a second factor. Every other call site spelled the flag out by hand and
    // read correctly, which is why nothing noticed.
    if let Err(error) = session::factor::refuse_if_present(
        &context.globals,
        &format!("dctl {}", cli.command.name()),
        NOTHING_ATTEMPTED,
    ) {
        report(&context, &error);
        return error.code();
    }

    // An interrupted run must never be reported as success: in-flight work is
    // either resumable or rolled back, and the index commit that would make it
    // count as stored never happened (`PLAN.md` §6 step 6).
    //
    // The periodic status line lives and dies inside this block. A redirected
    // run draws no bars, so it is the only thing that reports movement while the
    // command is running — and the scope is what guarantees it stops before the
    // summary below is printed. A status line emitted after the final report
    // would show smaller numbers than the report it follows, which reads as
    // though the run had gone backwards.
    let outcome = {
        let _ticker =
            output::progress::ticker::spawn(&context.progress, &context.stats, stats_interval);

        tokio::select! {
            result = dispatch::dispatch(&context, &cli.command) => Outcome::Finished(result),
            _ = tokio::signal::ctrl_c() => Outcome::Cancelled,
        }
    };

    match outcome {
        Outcome::Cancelled => {
            context.finish(false);
            context
                .out
                .error("cancelled — no partial work was reported as stored");
            tracing::warn!(
                { fields::ERROR_CODE } = ExitCode::Cancelled.slug(),
                "cancelled"
            );
            ExitCode::Cancelled
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
            code
        }

        Outcome::Finished(Err(error)) => {
            context.finish(show_summary);
            report(&context, &error);
            error.code()
        }
    }
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
