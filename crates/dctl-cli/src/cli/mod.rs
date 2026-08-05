//! The command tree.
//!
//! Structure and vocabulary deliberately track rclone's, because that is the
//! muscle memory of the people this tool is for: `copy` skips identical files,
//! `sync` makes the destination match the source (and therefore deletes),
//! `purge` removes a tree, `lsd` lists directories. A script written against
//! rclone should port with edits to the remote names and little else.
//!
//! Where DCTL adds commands, they exist because the plan promises guarantees
//! rclone does not make: [`Command::Verify`] and [`Command::Scrub`] back the
//! durability contract ([the plan](https://doc.dctl.sh/project/plan) §6, §13.4), and [`Command::Audit`] backs the
//! tamper-evident log (§7).
//!
//! Each subcommand's arguments and implementation live in their own module
//! under [`crate::commands`] — this file only wires them together.

pub mod globals;
pub mod reach;
pub mod refuse;
pub mod window;

// Tests and nothing else. `mentions` reads this crate's own source and
// `doc_mentions` reads `docs/`, and both ask the parser below whether every
// `dctl …` they find names a command that exists. Four hints and four
// documentation lines have not. See the modules for why that is checked
// mechanically rather than by review.
#[cfg(test)]
#[cfg(test)]
mod mentions;

use clap::{Parser, Subcommand};

use crate::commands;

pub use globals::{GlobalArgs, VerifyMode};

/// Long description shown by `dctl --help`.
const ABOUT: &str = "Encrypted, verified, metadata-private cloud storage.";

const LONG_ABOUT: &str = "\
Transfer, back up, encrypt and stream data across cloud providers.

DCTL never reports a file as stored until its bytes have been checksum-verified
at the destination and durably committed to the index. Encryption is optional
and per-remote: a remote is either plain or vault-wrapped, and the durability
contract applies to both.

Paths are written as REMOTE:PATH, for example 'vault:photos/2024'. A bare path,
a Windows drive path such as C:\\data, and a UNC path are all treated as local.

See docs/EXIT_CODES.md for the exit-code contract, or docs/commands/ for
per-command documentation.";

/// Top-level parsed command line.
#[derive(Parser, Debug)]
#[command(
    name = "dctl",
    version,
    about = ABOUT,
    long_about = LONG_ABOUT,
    propagate_version = true,
    disable_help_subcommand = false,
    infer_subcommands = true,
    max_term_width = 100
)]
pub struct Cli {
    #[command(flatten)]
    pub globals: GlobalArgs,

    #[command(subcommand)]
    pub command: Command,
}

/// Every subcommand.
///
/// Ordered by workflow rather than alphabetically, so `dctl --help` reads as a
/// tour of the tool: set it up, look at it, move data, remove data, prove the
/// data is intact, mount it.
#[derive(Subcommand, Debug)]
pub enum Command {
    // ── Setup ────────────────────────────────────────────────────────────
    /// Create and manage configuration and remotes.
    Config(commands::config::ConfigArgs),

    /// Create a vault and register both of its remotes.
    Init(commands::init::InitArgs),

    // ── Listing ──────────────────────────────────────────────────────────
    /// List objects with size and path.
    Ls(commands::ls::LsArgs),

    /// List directories only.
    Lsd(commands::lsd::LsdArgs),

    /// List objects with size, modification time and path.
    Lsl(commands::lsl::LslArgs),

    /// List objects as JSON, one document per object.
    Lsjson(commands::lsjson::LsjsonArgs),

    /// Show the object tree.
    Tree(commands::tree::TreeArgs),

    /// Show total size and object count.
    Size(commands::size::SizeArgs),

    // ── Transfer ─────────────────────────────────────────────────────────
    /// Copy files from source to destination, skipping identical files.
    Copy(commands::copy::CopyArgs),

    /// Move files, deleting the source only after a verified, durable commit.
    #[command(name = "move")]
    Move(commands::mv::MoveArgs),

    /// Make the destination identical to the source. Deletes from destination.
    Sync(commands::sync::SyncArgs),

    /// Copy a single file or directory to an exact destination name.
    Copyto(commands::copyto::CopytoArgs),

    /// Move a single file or directory to an exact destination name.
    Moveto(commands::moveto::MovetoArgs),

    // ── Replication ──────────────────────────────────────────────────────
    /// Replicate a vault's ciphertext objects to a second store. No password.
    Replicate(commands::replicate::ReplicateArgs),

    // ── Content ──────────────────────────────────────────────────────────
    /// Write object contents to standard output.
    Cat(commands::cat::CatArgs),

    /// Read standard input and write it to an object.
    Rcat(commands::rcat::RcatArgs),

    // ── Removal ──────────────────────────────────────────────────────────
    /// Delete objects in a path, honouring filters.
    Delete(commands::delete::DeleteArgs),

    /// Delete a single named object.
    Deletefile(commands::deletefile::DeletefileArgs),

    /// Remove a path and all of its contents.
    Purge(commands::purge::PurgeArgs),

    /// Remove an empty directory.
    Rmdir(commands::rmdir::RmdirArgs),

    /// Remove empty directories under a path.
    Rmdirs(commands::rmdirs::RmdirsArgs),

    /// Clean up a remote: abandoned uploads, stale temporary objects, old
    /// versions.
    Cleanup(commands::cleanup::CleanupArgs),

    // ── Directories ──────────────────────────────────────────────────────
    /// Create a directory.
    Mkdir(commands::mkdir::MkdirArgs),

    /// Create an object, or update its modification time.
    Touch(commands::touch::TouchArgs),

    // ── Integrity ────────────────────────────────────────────────────────
    /// Verify that stored objects decrypt and match their recorded hashes.
    Verify(commands::verify::VerifyArgs),

    /// Compare source and destination without transferring.
    Check(commands::check::CheckArgs),

    /// Re-read and verify the whole dataset, reporting its health.
    Scrub(commands::scrub::ScrubArgs),

    /// Print content hashes for objects.
    Hashsum(commands::hashsum::HashsumArgs),

    /// Operate on the local index: rebuild it from the backend.
    ///
    /// Grouped with the integrity verbs because the index is what they read, and
    /// because `dctl index rebuild` is the remedy the `missing`-verdict and
    /// index-error hints already name.
    Index(commands::index::IndexArgs),

    // ── Audit & recovery ─────────────────────────────────────────────────
    /// Operate on a vault's key material: recover one with its recovery phrase.
    ///
    /// Grouped with the recovery verbs because that is what it is for, and named
    /// as a group rather than a bare verb because the envelope has more
    /// operations coming ([the plan](https://doc.dctl.sh/project/plan) §13.2's Shamir shares, device slots) and all
    /// of them act on the same object. `dctl vault recover` is also the command
    /// [`crate::error`]'s unlock hint names, which makes its spelling a
    /// published contract rather than a preference.
    Vault(commands::vault::VaultArgs),

    /// Inspect and verify the tamper-evident audit log.
    Audit(commands::audit::AuditArgs),

    /// Back up a local tree into a vault.
    Backup(commands::backup::BackupArgs),

    /// Restore a vault, or part of one, to a local tree.
    Restore(commands::restore::RestoreArgs),

    // ── Mount ────────────────────────────────────────────────────────────
    /// Mount a remote as a filesystem.
    Mount(commands::mount::MountArgs),

    // ── Utility ──────────────────────────────────────────────────────────
    /// Show remote usage, quota and capability information.
    About(commands::about::AboutArgs),

    /// Show where DCTL keeps everything on this machine, and whether it is well.
    Home(commands::home::HomeArgs),

    /// Show version and build information.
    Version(commands::version::VersionArgs),

    /// Generate a shell completion script.
    Completion(commands::completion::CompletionArgs),

    // ── Compatibility aliases ────────────────────────────────────────────
    // The prototype CLI shipped these names and scripts already use them.
    // Kept working, hidden from help, and delegating to the modern command.
    /// Deprecated alias for `copy` from a local file into a vault.
    #[command(hide = true)]
    Put(commands::copy::CopyArgs),

    /// Deprecated alias for `copy` from a vault to a local file.
    #[command(hide = true)]
    Get(commands::copy::CopyArgs),

    /// Deprecated alias for `deletefile`.
    #[command(hide = true)]
    Rm(commands::deletefile::DeletefileArgs),
}

impl Command {
    /// Stable command name, used as the `op` field in log spans and in the
    /// audit record for the operation.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Config(_) => "config",
            Self::Init(_) => "init",
            Self::Ls(_) => "ls",
            Self::Lsd(_) => "lsd",
            Self::Lsl(_) => "lsl",
            Self::Lsjson(_) => "lsjson",
            Self::Tree(_) => "tree",
            Self::Size(_) => "size",
            Self::Copy(_) => "copy",
            Self::Move(_) => "move",
            Self::Sync(_) => "sync",
            Self::Copyto(_) => "copyto",
            Self::Moveto(_) => "moveto",
            Self::Replicate(_) => "replicate",
            Self::Cat(_) => "cat",
            Self::Rcat(_) => "rcat",
            Self::Delete(_) => "delete",
            Self::Deletefile(_) => "deletefile",
            Self::Purge(_) => "purge",
            Self::Rmdir(_) => "rmdir",
            Self::Rmdirs(_) => "rmdirs",
            Self::Cleanup(_) => "cleanup",
            Self::Mkdir(_) => "mkdir",
            Self::Touch(_) => "touch",
            Self::Verify(_) => "verify",
            Self::Check(_) => "check",
            Self::Scrub(_) => "scrub",
            Self::Hashsum(_) => "hashsum",
            Self::Index(_) => "index",
            Self::Vault(_) => "vault",
            Self::Audit(_) => "audit",
            Self::Backup(_) => "backup",
            Self::Restore(_) => "restore",
            Self::Mount(_) => "mount",
            Self::About(_) => "about",
            Self::Home(_) => "home",
            Self::Version(_) => "version",
            Self::Completion(_) => "completion",
            Self::Put(_) => "put",
            Self::Get(_) => "get",
            Self::Rm(_) => "rm",
        }
    }

    // The two classifiers below are `cfg(test)`. Both state a policy that is
    // *enforced structurally* rather than by consulting them: a destructive
    // command passes its target through `Ctx::confirm_destructive`, and a
    // command that needs a vault is a command that calls `session::open`. Asking
    // an enum instead would be a second, weaker enforcement — one that a new
    // subcommand joins by being added to a list somebody has to remember.
    //
    // They are kept because `about`, `version` and `dispatch` each assert their
    // own claim against them, and that assertion is the only thing standing
    // between "`dctl version` never prompts for a password" being a documented
    // promise and being a documented hope.

    /// Whether this command can destroy data.
    #[cfg(test)]
    #[must_use]
    pub const fn is_destructive(&self) -> bool {
        matches!(
            self,
            Self::Move(_)
                | Self::Sync(_)
                | Self::Moveto(_)
                | Self::Delete(_)
                | Self::Deletefile(_)
                | Self::Purge(_)
                | Self::Rmdir(_)
                | Self::Rmdirs(_)
                | Self::Cleanup(_)
                | Self::Rm(_)
        )
    }

    /// Whether this command needs an unlocked vault.
    ///
    /// The commands that do not — `config`, `version`, `completion` — must run
    /// without ever prompting for a password.
    ///
    /// `about` used to be in that list and no longer is. Its usage report
    /// measures how much a remote holds by enumerating it, and for a sealed
    /// remote that means opening the vault, so the claim stopped being true the
    /// moment the report started being real. `dctl about --capabilities` still
    /// answers offline — that promise is asserted in `commands::about` against
    /// `--no-ask-password`, which is where a per-mode claim belongs — but this
    /// classifier describes a whole command, and a command that can prompt must
    /// not be listed here. A documented promise nobody can rely on is worse than
    /// no promise.
    ///
    /// `replicate` joins them, and for a reason worth more than the others put
    /// together: it moves a vault's opaque ciphertext objects between two object
    /// stores, so a backup operator can satisfy 3-2-1 without ever holding
    /// decryption capability ([the plan](https://doc.dctl.sh/project/plan) §13.3). Separation of duties is a
    /// structural property of the command, not a policy applied to it.
    #[cfg(test)]
    #[must_use]
    pub const fn requires_vault(&self) -> bool {
        !matches!(
            self,
            Self::Config(_)
                | Self::Home(_)
                | Self::Version(_)
                | Self::Completion(_)
                | Self::Replicate(_)
        )
    }

    /// Whether this command writes bulk data and should therefore show
    /// transfer progress and an end-of-run summary.
    #[must_use]
    pub const fn is_transfer(&self) -> bool {
        matches!(
            self,
            Self::Copy(_)
                | Self::Move(_)
                | Self::Sync(_)
                | Self::Copyto(_)
                | Self::Moveto(_)
                | Self::Backup(_)
                | Self::Restore(_)
                | Self::Rcat(_)
                | Self::Replicate(_)
                | Self::Put(_)
                | Self::Get(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_tree_is_internally_consistent() {
        // clap's own invariant checker: catches duplicate flags, bad defaults,
        // conflicting short options, and malformed help across the whole tree.
        Cli::command().debug_assert();
    }

    #[test]
    fn every_command_has_a_distinct_stable_name() {
        // Names appear in audit records, so a collision would make two
        // different operations indistinguishable after the fact.
        let cmd = Cli::command();
        let names: Vec<String> = cmd
            .get_subcommands()
            .map(|s| s.get_name().to_string())
            .collect();
        let mut unique = names.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), names.len(), "duplicate subcommand name");
    }

    #[test]
    fn destructive_commands_are_correctly_classified() {
        let sync = Cli::try_parse_from(["dctl", "sync", "a", "b"]).unwrap();
        assert!(sync.command.is_destructive());
        assert!(sync.command.is_transfer());

        let ls = Cli::try_parse_from(["dctl", "ls", "vault:"]).unwrap();
        assert!(!ls.command.is_destructive());
        assert!(!ls.command.is_transfer());
    }

    #[test]
    fn config_and_version_never_need_a_password() {
        let version = Cli::try_parse_from(["dctl", "version"]).unwrap();
        assert!(!version.command.requires_vault());
        let ls = Cli::try_parse_from(["dctl", "ls", "vault:"]).unwrap();
        assert!(ls.command.requires_vault());
    }

    #[test]
    fn deprecated_aliases_still_parse() {
        // The prototype CLI's verbs must keep working for existing scripts.
        assert!(Cli::try_parse_from(["dctl", "put", "a.txt", "vault:a.txt"]).is_ok());
        assert!(Cli::try_parse_from(["dctl", "get", "vault:a.txt", "a.txt"]).is_ok());
        assert!(Cli::try_parse_from(["dctl", "rm", "vault:a.txt"]).is_ok());
    }

    #[test]
    fn move_is_spelled_move_not_mv() {
        // The module is `mv` because `move` is a Rust keyword, but the
        // user-facing verb must match rclone's.
        assert!(Cli::try_parse_from(["dctl", "move", "a", "b"]).is_ok());
    }

    #[test]
    fn globals_are_accepted_after_the_subcommand() {
        // Users type `dctl copy a b --progress`, not `dctl --progress copy a b`.
        let cli = Cli::try_parse_from(["dctl", "copy", "a", "b", "--progress", "-vv"]).unwrap();
        assert!(cli.globals.progress);
        assert_eq!(cli.globals.verbose, 2);
    }

    #[test]
    fn command_names_match_the_parsed_subcommand() {
        let cli = Cli::try_parse_from(["dctl", "purge", "vault:old"]).unwrap();
        assert_eq!(cli.command.name(), "purge");
    }
}
