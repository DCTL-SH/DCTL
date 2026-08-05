//! Command dispatch.
//!
//! One place where a parsed [`Command`] becomes a call into its module. Kept
//! separate from `main.rs` so the entry point stays about process concerns
//! (logging, signals, exit codes) and this stays about routing.
//!
//! Every arm opens a `tracing` span carrying the command name, so every record
//! emitted anywhere beneath it is attributable to the operation that caused it
//! ([the plan](https://doc.dctl.sh/project/plan) §7).

use tracing::Instrument as _;

use crate::cli::Command;
use crate::commands;
use crate::ctx::Ctx;
use crate::error::Result;
use crate::logging::fields;

/// Route a parsed command to its implementation.
///
/// The span is opened here rather than inside each command so no command can
/// forget it, and so the field name is guaranteed consistent across all of them.
pub async fn dispatch(ctx: &Ctx, command: &Command) -> Result<()> {
    let span = tracing::info_span!("command", { fields::OP } = command.name());
    run_inner(ctx, command).instrument(span).await
}

async fn run_inner(ctx: &Ctx, command: &Command) -> Result<()> {
    match command {
        // ── Setup ────────────────────────────────────────────────────────
        Command::Config(args) => commands::config::run(ctx, args).await,
        Command::Init(args) => commands::init::run(ctx, args).await,

        // ── Listing ──────────────────────────────────────────────────────
        Command::Ls(args) => commands::ls::run(ctx, args).await,
        Command::Lsd(args) => commands::lsd::run(ctx, args).await,
        Command::Lsl(args) => commands::lsl::run(ctx, args).await,
        Command::Lsjson(args) => commands::lsjson::run(ctx, args).await,
        Command::Tree(args) => commands::tree::run(ctx, args).await,
        Command::Size(args) => commands::size::run(ctx, args).await,

        // ── Transfer ─────────────────────────────────────────────────────
        Command::Copy(args) | Command::Put(args) | Command::Get(args) => {
            commands::copy::run(ctx, args).await
        }
        Command::Move(args) => commands::mv::run(ctx, args).await,
        Command::Sync(args) => commands::sync::run(ctx, args).await,
        Command::Copyto(args) => commands::copyto::run(ctx, args).await,
        Command::Moveto(args) => commands::moveto::run(ctx, args).await,

        // ── Replication ──────────────────────────────────────────────────
        // The one transfer arm that never reaches `session::open`: it moves
        // ciphertext between two object stores and holds no key
        // (https://doc.dctl.sh/project/plan §13.3).
        Command::Replicate(args) => commands::replicate::run(ctx, args).await,

        // ── Content ──────────────────────────────────────────────────────
        Command::Cat(args) => commands::cat::run(ctx, args).await,
        Command::Rcat(args) => commands::rcat::run(ctx, args).await,

        // ── Removal ──────────────────────────────────────────────────────
        Command::Delete(args) => commands::delete::run(ctx, args).await,
        Command::Deletefile(args) | Command::Rm(args) => commands::deletefile::run(ctx, args).await,
        Command::Purge(args) => commands::purge::run(ctx, args).await,
        Command::Rmdir(args) => commands::rmdir::run(ctx, args).await,
        Command::Rmdirs(args) => commands::rmdirs::run(ctx, args).await,
        Command::Cleanup(args) => commands::cleanup::run(ctx, args).await,

        // ── Directories ──────────────────────────────────────────────────
        Command::Mkdir(args) => commands::mkdir::run(ctx, args).await,
        Command::Touch(args) => commands::touch::run(ctx, args).await,

        // ── Integrity ────────────────────────────────────────────────────
        Command::Verify(args) => commands::verify::run(ctx, args).await,
        Command::Check(args) => commands::check::run(ctx, args).await,
        Command::Scrub(args) => commands::scrub::run(ctx, args).await,
        Command::Hashsum(args) => commands::hashsum::run(ctx, args).await,
        Command::Index(args) => commands::index::run(ctx, args).await,

        // ── Audit & recovery ─────────────────────────────────────────────
        Command::Vault(args) => commands::vault::run(ctx, args).await,
        Command::Audit(args) => commands::audit::run(ctx, args).await,
        Command::Backup(args) => commands::backup::run(ctx, args).await,
        Command::Restore(args) => commands::restore::run(ctx, args).await,

        // ── Mount ────────────────────────────────────────────────────────
        Command::Mount(args) => commands::mount::run(ctx, args).await,

        // ── Utility ──────────────────────────────────────────────────────
        Command::About(args) => commands::about::run(ctx, args).await,
        Command::Home(args) => commands::home::run(ctx, args),
        Command::Version(args) => commands::version::run(ctx, args).await,
        Command::Completion(args) => commands::completion::run(ctx, args).await,
    }
}

#[cfg(test)]
mod tests {
    use crate::cli::Cli;
    use clap::Parser;

    #[test]
    fn deprecated_aliases_route_to_their_modern_command() {
        // `put`/`get` both carry CopyArgs and reach the copy implementation;
        // `rm` carries DeletefileArgs. This is compile-checked by the match
        // arms above, so the test asserts the parse side of the contract.
        let put = Cli::try_parse_from(["dctl", "put", "a.txt", "vault:a.txt"]).unwrap();
        assert_eq!(put.command.name(), "put");

        let rm = Cli::try_parse_from(["dctl", "rm", "vault:a.txt"]).unwrap();
        assert_eq!(rm.command.name(), "rm");
        assert!(rm.command.is_destructive());
    }
}
