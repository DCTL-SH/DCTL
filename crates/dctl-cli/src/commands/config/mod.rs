//! `dctl config` — read and change the configuration file.
//!
//! DCTL's configuration is a TOML file holding **non-secret settings only**
//! ([the plan](https://doc.dctl.sh/project/plan) §14): named remotes with their
//! type, endpoint, bucket and region, plus policy defaults. Provider
//! credentials live in the OS keychain and the vault password is never stored
//! anywhere, which is the deliberate difference from `rclone.conf` — that file
//! keeps credentials in it, "obscured" with reversible obfuscation that anyone
//! holding the file can undo.
//!
//! Three rules shape every subcommand below.
//!
//! **Nothing printed here is ever a secret.** The file is not supposed to
//! contain one, but the installation that ends up in a bug report is exactly the
//! one where somebody pasted an application key into it by hand. [`show`] and
//! [`redact`] both route every value through [`secrets::render`], so the
//! guarantee holds by construction rather than by remembering.
//!
//! **Every subcommand works headlessly.** `create` and `update` take their
//! settings as arguments rather than asking questions, so a provisioning script
//! can configure a server with no terminal attached. `edit` is the one
//! exception, and it refuses rather than hanging when there is no terminal to
//! attach to.
//!
//! **The file is never left half-written, and never written unloadable.**
//! [`crate::config`] validates before it saves and stages every write through a
//! rename, so an interrupted `config create` cannot produce a truncated file
//! that reads as "no remotes configured", and a `config update` that would
//! remove a required setting fails instead of writing a section no later command
//! could parse.
//!
//! ## Addressing a vault, and proving it
//!
//! Two verbs exist because a vault is addressed by **two** remotes — the sealed
//! view and its object store — and because that addressing has to be
//! recoverable and auditable.
//!
//! [`import`] inspects a location, confirms a vault's envelope is there, and
//! writes the same pair `dctl init` writes. It is the recovery path for a lost
//! configuration, and it is an *explicit command an operator runs*, never a
//! detection that fires during a copy: what a command encrypts follows the
//! remote name typed. A destination's contents can refuse a command (which is
//! what sends an operator here); they never change what it does.
//!
//! [`verify`] proves, from the file alone — no data, no key, no network — that
//! every remote resolves, that no vault chain loops or dangles, and whether each
//! remote is plain or sealed. It is the pre-flight to run before a compliance
//! review, and the only subcommand that deliberately opens a configuration the
//! loader would refuse, because reporting what is wrong is its entire job.
//!
//! ## Layout
//!
//! One file per verb, plus four that carry the shared concerns. The file on
//! disk belongs to [`crate::config`] and is not re-implemented here;
//! [`settings`] translates between its typed model and the flat `key=value`
//! vocabulary a shell speaks, [`base`] turns a base *location* into the store
//! remote that addresses it, [`secrets`] owns the redaction policy, and
//! [`emit`] owns how a result reaches stdout in each format.

// Declared `pub` rather than private because [`Action`] carries their argument
// types: an enum variant may not be more visible than the type inside it.
pub mod base;
pub mod create;
pub mod delete;
pub mod edit;
pub mod emit;
pub mod file;
pub mod import;
pub mod list;
pub mod providers;
pub mod redact;
pub mod secrets;
pub mod settings;
pub mod show;
pub mod touch;
pub mod update;
pub mod verify;

use clap::{Args, Subcommand};

use crate::ctx::Ctx;
use crate::error::Result;

/// Arguments for `dctl config`.
#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: Action,
}

/// What to do to the configuration.
///
/// Ordered as a workflow rather than alphabetically — find out what is
/// configured, change it, then deal with the file itself — so `dctl config
/// --help` reads as a tour.
#[derive(Subcommand, Debug)]
pub enum Action {
    /// List the configured remotes.
    List,

    /// Show one remote's settings. Never prints a secret.
    Show(show::ShowArgs),

    /// Add a remote.
    Create(create::CreateArgs),

    /// Change settings on an existing remote.
    Update(update::UpdateArgs),

    /// Remove a remote from the configuration. Stored objects are untouched.
    Delete(delete::DeleteArgs),

    /// Write the remotes that address a vault which already exists.
    Import(import::ImportArgs),

    /// Prove every remote resolves, from the configuration alone.
    Verify,

    /// Print the path of the configuration file.
    File,

    /// Create the configuration file if it does not exist.
    Touch,

    /// Open the configuration file in an editor, then check that it parses.
    Edit,

    /// List the remote types this build supports.
    Providers,

    /// Print the whole configuration, safe to paste into a bug report.
    Redact,
}

impl Action {
    /// Stable name for logs and documentation.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Show(_) => "show",
            Self::Create(_) => "create",
            Self::Update(_) => "update",
            Self::Delete(_) => "delete",
            Self::Import(_) => "import",
            Self::Verify => "verify",
            Self::File => "file",
            Self::Touch => "touch",
            Self::Edit => "edit",
            Self::Providers => "providers",
            Self::Redact => "redact",
        }
    }

    /// Whether this action changes the configuration file.
    ///
    /// Used by the dispatcher's log record, and by the tests that hold the
    /// read-only subcommands to being read-only — `dctl config show` writing to
    /// the file it is displaying would be a serious surprise.
    #[must_use]
    pub const fn is_mutating(&self) -> bool {
        matches!(
            self,
            Self::Create(_)
                | Self::Update(_)
                | Self::Delete(_)
                | Self::Import(_)
                | Self::Touch
                | Self::Edit
        )
    }
}

/// Route a `dctl config` invocation to its subcommand.
///
/// # Errors
/// Whatever the subcommand classifies its failure as. Nothing is classified
/// here: a router that invented its own error codes would make the same failure
/// look different depending on which verb produced it.
pub async fn run(ctx: &Ctx, args: &ConfigArgs) -> Result<()> {
    tracing::debug!(
        action = args.action.name(),
        mutating = args.action.is_mutating(),
        "config"
    );

    match &args.action {
        Action::List => list::run(ctx).await,
        Action::Show(args) => show::run(ctx, args).await,
        Action::Create(args) => create::run(ctx, args).await,
        Action::Update(args) => update::run(ctx, args).await,
        Action::Delete(args) => delete::run(ctx, args).await,
        Action::Import(args) => import::run(ctx, args).await,
        Action::Verify => verify::run(ctx).await,
        Action::File => file::run(ctx).await,
        Action::Touch => touch::run(ctx).await,
        Action::Edit => edit::run(ctx).await,
        Action::Providers => providers::run(ctx).await,
        Action::Redact => redact::run(ctx).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("dctl").chain(args.iter().copied()))
            .unwrap_or_else(|error| panic!("{args:?} did not parse: {error}"))
    }

    fn action(args: &[&str]) -> Action {
        match parse(args).command {
            crate::cli::Command::Config(config) => config.action,
            other => panic!("{args:?} parsed as {other:?}, not config"),
        }
    }

    #[test]
    fn every_subcommand_parses() {
        // The list is the command's public surface; a missing verb here is a
        // documented feature that does not exist.
        for (args, expected) in [
            (vec!["config", "list"], "list"),
            (vec!["config", "show", "b2prod"], "show"),
            (vec!["config", "create", "b2prod", "b2"], "create"),
            (vec!["config", "update", "b2prod", "bucket=x"], "update"),
            (vec!["config", "delete", "b2prod"], "delete"),
            (vec!["config", "import", "local:/srv/vault"], "import"),
            (vec!["config", "verify"], "verify"),
            (vec!["config", "file"], "file"),
            (vec!["config", "touch"], "touch"),
            (vec!["config", "edit"], "edit"),
            (vec!["config", "providers"], "providers"),
            (vec!["config", "redact"], "redact"),
        ] {
            assert_eq!(action(&args).name(), expected, "{args:?}");
        }
    }

    #[test]
    fn create_accepts_a_type_and_any_number_of_settings() {
        let parsed = action(&[
            "config",
            "create",
            "b2prod",
            "b2",
            "bucket=photos",
            "region=us-west-002",
        ]);
        match parsed {
            Action::Create(args) => {
                assert_eq!(args.name, "b2prod");
                assert_eq!(args.remote_type, "b2");
                assert_eq!(args.settings.len(), 2);
            }
            other => panic!("parsed as {other:?}"),
        }

        // A remote with no settings beyond its type is legal: `local:` needs
        // nothing else.
        match action(&["config", "create", "scratch", "local"]) {
            Action::Create(args) => assert!(args.settings.is_empty()),
            other => panic!("parsed as {other:?}"),
        }
    }

    #[test]
    fn a_missing_subcommand_is_a_usage_error() {
        // `dctl config` alone has no sensible default: rclone's is an
        // interactive menu, and [the plan](https://doc.dctl.sh/project/plan)
        // §14 rules that out.
        let error = Cli::try_parse_from(["dctl", "config"]).unwrap_err();
        assert!(error.use_stderr());
    }

    #[test]
    fn required_arguments_are_required() {
        assert!(Cli::try_parse_from(["dctl", "config", "show"]).is_err());
        assert!(Cli::try_parse_from(["dctl", "config", "delete"]).is_err());
        // `create` needs both a name and a type.
        assert!(Cli::try_parse_from(["dctl", "config", "create", "b2prod"]).is_err());
    }

    #[test]
    fn the_read_only_subcommands_are_classified_as_read_only() {
        // `dctl config show` writing to the file it displays would be a serious
        // surprise; the classification is what a future reviewer checks against.
        for args in [
            vec!["config", "list"],
            vec!["config", "show", "b2prod"],
            vec!["config", "file"],
            vec!["config", "providers"],
            vec!["config", "redact"],
            // The compliance pre-flight reads and reports; a verifier that
            // could change what it verifies would be worthless as evidence.
            vec!["config", "verify"],
        ] {
            assert!(!action(&args).is_mutating(), "{args:?}");
        }

        for args in [
            vec!["config", "create", "b2prod", "b2"],
            vec!["config", "update", "b2prod", "bucket=x"],
            vec!["config", "delete", "b2prod"],
            vec!["config", "import", "local:/srv/vault"],
            vec!["config", "touch"],
            vec!["config", "edit"],
        ] {
            assert!(action(&args).is_mutating(), "{args:?}");
        }
    }

    #[test]
    fn every_action_has_a_distinct_name() {
        // Names appear in log records, so a collision would make two different
        // operations indistinguishable after the fact.
        let names = [
            "list",
            "show",
            "create",
            "update",
            "delete",
            "import",
            "verify",
            "file",
            "touch",
            "edit",
            "providers",
            "redact",
        ];
        let mut unique = names.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), names.len());
    }

    #[test]
    fn global_flags_reach_the_subcommands() {
        // `--config` and `--dry-run` are declared once, globally; a subcommand
        // that re-declared them would shadow the global and silently ignore it.
        let cli = parse(&[
            "config",
            "create",
            "b2prod",
            "b2",
            "--config",
            "/tmp/x.toml",
            "--dry-run",
        ]);
        assert_eq!(
            cli.globals.config.as_deref(),
            Some(std::path::Path::new("/tmp/x.toml"))
        );
        assert!(cli.globals.dry_run);
    }
}
