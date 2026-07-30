//! Typed failures of the configuration layer.
//!
//! `PLAN.md` §16.5 asks for a `thiserror` taxonomy per concern rather than a
//! stringly-typed `anyhow` chain, and configuration is the concern with the most
//! *distinguishable* ways to go wrong: a name a user typed, a base remote that
//! does not exist, a cycle between vault remotes, a file that cannot be read,
//! and — the one this whole layer exists to prevent — a credential pasted into
//! the file.
//!
//! Keeping them apart buys three things. Tests assert *which* rule fired instead
//! of grepping a message. Each variant carries its own remediation hint, so the
//! user is told the fix and not just the fault. And the split between "the user
//! mistyped an argument" (exit 1) and "the file on disk is wrong" (exit 7) is
//! made once, here, rather than guessed at each call site.

use std::path::PathBuf;

use thiserror::Error;

use crate::constants::{CONFIG_CHAIN_ARROW, CONFIG_KEY_PATH_SEPARATOR};
use crate::error::CliError;
use crate::exit::ExitCode;

/// A configuration failure, classified by what went wrong.
///
/// Split into two families that the [`ConfigError::exit_code`] mapping keeps
/// apart: everything from [`ConfigError::NameEmpty`] to
/// [`ConfigError::ReservedName`] is a *name a caller supplied*, and everything
/// else describes the state of the file on disk.
#[derive(Debug, Error)]
pub enum ConfigError {
    // ── The file ─────────────────────────────────────────────────────────────
    /// The file was named explicitly (`--config`, `DCTL_CONFIG`) but is absent.
    ///
    /// Distinct from "no config at all": a *default* path that does not exist is
    /// a fresh installation and is answered with an empty [`super::Config`],
    /// while a path the user chose and got wrong must never be silently ignored.
    #[error("configuration file '{0}' does not exist")]
    Missing(PathBuf),

    /// The file exists but could not be read.
    #[error("configuration file '{path}' could not be read: {source}")]
    Read {
        /// The file that could not be read.
        path: PathBuf,
        /// The underlying operating-system error.
        #[source]
        source: std::io::Error,
    },

    /// The file could not be written, or the write could not be made durable.
    #[error("configuration file '{path}' could not be written: {source}")]
    Write {
        /// The file, directory, or staging file the write failed on.
        path: PathBuf,
        /// The underlying operating-system error.
        #[source]
        source: std::io::Error,
    },

    /// The file is not valid TOML, or does not match the expected shape.
    #[error("configuration file '{path}' is not valid: {source}")]
    Parse {
        /// The file that failed to parse.
        path: PathBuf,
        /// The parser's own error, which carries the line and column.
        #[source]
        source: toml::de::Error,
    },

    /// The in-memory configuration could not be rendered as TOML.
    ///
    /// In practice this means a value TOML cannot represent — most plausibly a
    /// local remote whose path is not valid UTF-8.
    #[error("configuration could not be serialised as TOML: {0}")]
    Serialize(#[from] toml::ser::Error),

    /// A key whose name looks like a credential was found in the file.
    ///
    /// The loudest error in this enum on purpose. `PLAN.md` §14 rejects
    /// rclone's model of keeping reversibly-obscured secrets in the config, and
    /// a tool that merely *ignored* an unexpected `secret_key` would leave it
    /// sitting on disk, in a backup, and in the next bug report.
    #[error(
        "configuration key '{key}' looks like a credential, and credentials are never stored in the configuration file"
    )]
    SecretInConfig {
        /// Dotted path to the offending key, e.g. `remotes.b2prod.secret_key`.
        key: String,
    },

    // ── Names a caller supplied ──────────────────────────────────────────────
    /// A remote was given an empty name.
    #[error("a remote name cannot be empty")]
    NameEmpty,

    /// A remote name is shorter than [`crate::constants::MIN_REMOTE_NAME_LEN`].
    #[error("remote name '{name}' is shorter than {min} characters")]
    NameTooShort {
        /// The rejected name.
        name: String,
        /// The floor it fell below.
        min: usize,
    },

    /// A remote name is longer than [`crate::constants::MAX_REMOTE_NAME_LEN`].
    #[error("remote name '{name}' is longer than {max} characters")]
    NameTooLong {
        /// The rejected name.
        name: String,
        /// The ceiling it exceeded.
        max: usize,
    },

    /// A remote name contains a character that is not allowed in one.
    #[error("remote name '{name}' contains '{offender}', which is not allowed in a remote name")]
    NameCharset {
        /// The rejected name.
        name: String,
        /// The first offending character, so the message points at one thing.
        offender: char,
    },

    /// A remote name starts with something other than an ASCII letter or digit.
    #[error("remote name '{name}' must start with a letter or a digit")]
    NameStart {
        /// The rejected name.
        name: String,
    },

    /// A remote was named after a provider type.
    ///
    /// `crate::remote` reads the scheme of a spec as a provider type, so a
    /// remote called `b2` would make `b2:bucket` mean two different things.
    #[error("'{name}' is a provider type and cannot also be a remote name")]
    ReservedName {
        /// The rejected name.
        name: String,
    },

    /// Two remotes differ only in letter case.
    ///
    /// Always a typo in practice, and an ambiguity in every case-insensitive
    /// context a name passes through — a shell completion, a Windows path, a
    /// human reading a table.
    #[error("remotes '{first}' and '{second}' differ only in case")]
    DuplicateNameCase {
        /// The name encountered first, in the file's own ordering.
        first: String,
        /// The name that collided with it.
        second: String,
    },

    // ── The remote graph ─────────────────────────────────────────────────────
    /// A remote was asked for that the configuration does not define.
    #[error("no remote named '{0}' is configured")]
    UnknownRemote(String),

    /// A vault remote names a base remote that does not exist.
    #[error("vault remote '{remote}' wraps '{base}', which is not configured")]
    UnknownBase {
        /// The vault remote carrying the dangling reference.
        remote: String,
        /// The base it names.
        base: String,
    },

    /// A vault remote's base chain loops back on itself.
    ///
    /// Carries the whole walk, ending on the repeated name, because "there is a
    /// cycle" is not actionable and "vault -> inner -> vault" is.
    #[error("vault remotes form a cycle: {}", .chain.join(CONFIG_CHAIN_ARROW))]
    VaultCycle {
        /// The walk that closed the loop, first link first.
        chain: Vec<String>,
    },

    /// A vault remote's base chain is longer than
    /// [`crate::constants::MAX_VAULT_CHAIN_DEPTH`].
    #[error("vault remote '{remote}' wraps more than {max} remotes deep")]
    ChainTooDeep {
        /// The remote whose chain was walked.
        remote: String,
        /// The bound it exceeded.
        max: usize,
    },

    /// A plain remote addresses a location another remote declared vault-only.
    ///
    /// Invariant I2 caught at the earliest moment it can be: a location holding
    /// a vault's opaque objects must not also be addressable as an ordinary
    /// place to put files, because the two readings of one directory are how
    /// plaintext ends up sitting beside the ciphertext it was supposed to
    /// become.
    #[error(
        "remote '{plain}' addresses '{location}', which remote '{guard}' declares is a vault's object store"
    )]
    PlainRemoteAtVaultLocation {
        /// The plain remote that would address the location.
        plain: String,
        /// The remote carrying [`crate::constants::CONFIG_KEY_REQUIRE_VAULT`].
        guard: String,
        /// The place both of them name.
        location: String,
    },

    /// A remote carries a setting this build cannot apply.
    ///
    /// The one today is a vault's `base_path`: a vault occupies the **root** of
    /// the store it wraps, and the setting was accepted by `dctl config create`,
    /// written to the file, printed back by `dctl config show`, and reached
    /// nothing. A file written by an older build may still carry one, and the
    /// objects are at the root regardless of what it says.
    ///
    /// Diagnosed on load for the reason
    /// [`ConfigError::PlainRemoteAtVaultLocation`] is: a rule enforced by one
    /// command is a rule the file can be hand-edited around. The classification
    /// itself is `crate::config::reach`'s, so this variant carries the reason
    /// rather than restating it.
    ///
    /// Nothing has to move to fix it, and the hint says so — this is the one
    /// diagnosis in this enum whose remedy is deleting a line.
    #[error("remote '{remote}' has a {key} of '{written}', which nothing honours")]
    SettingNotHonoured {
        /// The remote carrying it.
        remote: String,
        /// The setting's key, as the file spells it.
        key: String,
        /// The value as written, so the operator can find the line.
        written: String,
        /// Why it cannot be honoured, from `crate::config::reach::refusal`.
        reason: &'static str,
    },

    /// A name a caller asked to create is already in use.
    ///
    /// Distinct from [`ConfigError::DuplicateNameCase`], which is about a file
    /// that already contains two colliding names: this is a *request* to add
    /// one, refused before anything is written.
    #[error("remote '{name}' already exists")]
    NameTaken {
        /// The name that is already spoken for.
        name: String,
    },
}

impl ConfigError {
    /// The process exit status this failure should produce.
    ///
    /// The split follows `PLAN.md` §7: a *fatal* error is one where the state of
    /// the machine is wrong (exit 7 — the file is missing, unreadable, malformed,
    /// or describes an impossible remote graph), while a *usage* error is one
    /// where the invocation was wrong (exit 1 — the caller supplied a name that
    /// is not a legal remote name). Scripts branch on these, so a bad `--name`
    /// argument must not look like a corrupted installation.
    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        match self {
            Self::NameEmpty
            | Self::NameTooShort { .. }
            | Self::NameTooLong { .. }
            | Self::NameCharset { .. }
            | Self::NameStart { .. }
            | Self::ReservedName { .. }
            // A name the caller asked for and cannot have is the same kind of
            // event as a name they misspelled: the invocation was wrong, the
            // installation is fine, and a script must be able to tell those
            // apart.
            | Self::NameTaken { .. } => ExitCode::Usage,

            Self::PlainRemoteAtVaultLocation { .. }
            | Self::SettingNotHonoured { .. }
            | Self::Missing(_)
            | Self::Read { .. }
            | Self::Write { .. }
            | Self::Parse { .. }
            | Self::Serialize(_)
            | Self::SecretInConfig { .. }
            | Self::DuplicateNameCase { .. }
            | Self::UnknownRemote(_)
            | Self::UnknownBase { .. }
            | Self::VaultCycle { .. }
            | Self::ChainTooDeep { .. } => ExitCode::FatalError,
        }
    }

    /// The remediation hint shown beneath the message.
    ///
    /// Every variant that has a *specific* next step gets one; the rest return
    /// `None` rather than padding the output with a restatement of the error,
    /// which trains people to stop reading hints.
    #[must_use]
    pub fn hint(&self) -> Option<String> {
        match self {
            Self::Missing(path) => Some(format!(
                "Create it with `dctl config create`, or point --config at an \
                 existing file. Expected: {}",
                path.display()
            )),

            Self::Read { .. } => Some(
                "Check that the file is readable by the user running DCTL. The \
                 configuration is kept owner-only on purpose, so a file created \
                 by another account will not be readable."
                    .to_string(),
            ),

            Self::Write { .. } => Some(
                "Check that the configuration directory exists and is writable. \
                 Nothing was changed: the new configuration is written to a \
                 staging file and only renamed into place once it is complete."
                    .to_string(),
            ),

            Self::Parse { .. } => Some(
                "Fix the file by hand, or move it aside and re-create the \
                 remotes with `dctl config create`."
                    .to_string(),
            ),

            Self::SecretInConfig { .. } => Some(
                "Delete that line. Provider credentials are read from the \
                 environment, and the vault password is prompted for or produced \
                 by --password-command — DCTL never stores either in the \
                 configuration file (PLAN.md §14). Treat the credential as \
                 exposed and rotate it."
                    .to_string(),
            ),

            Self::NameTooShort { .. } => Some(
                "A one-character name could not be told apart from a Windows \
                 drive letter: `c:\\data` must always be a path."
                    .to_string(),
            ),

            Self::NameCharset { .. } | Self::NameStart { .. } => Some(
                "Remote names may contain letters, digits, '-' and '_', and must \
                 start with a letter or a digit — anything else could not be told \
                 apart from a path in `remote:path`."
                    .to_string(),
            ),

            Self::ReservedName { name } => Some(format!(
                "`{name}:` already means \"the {name} backend\" when no such \
                 remote is configured, so the two would be indistinguishable. \
                 Pick another name."
            )),

            Self::UnknownBase { base, .. } => Some(format!(
                "Define '{base}' first, or point the vault remote's `base` at an \
                 existing remote. `dctl config list` shows what is configured."
            )),

            Self::VaultCycle { .. } => Some(
                "A vault remote must eventually resolve to a remote that stores \
                 bytes. Break the loop by pointing one link's `base` at a plain \
                 remote."
                    .to_string(),
            ),

            Self::PlainRemoteAtVaultLocation { guard, .. } => Some(format!(
                "Writing plaintext into a vault's object store would leave it \
                 sitting beside the ciphertext it should have become. Address \
                 the vault remote that wraps '{guard}' instead — everything \
                 through it is sealed. To replicate the stored objects as they \
                 are, without a password, address '{guard}' itself."
            )),

            Self::SettingNotHonoured {
                remote,
                key,
                reason,
                ..
            } => Some(format!(
                "Nothing has to move: the setting has never been applied, so \
                 this remote already addresses what it addressed before. Delete \
                 the line, or run `dctl config update {remote} {key}=` to clear \
                 it. {reason}"
            )),

            Self::NameTaken { name } => Some(format!(
                "Pick another name, or pass --force to replace '{name}'. \
                 `dctl config list` shows what is configured."
            )),

            Self::NameEmpty
            | Self::NameTooLong { .. }
            | Self::DuplicateNameCase { .. }
            | Self::UnknownRemote(_)
            | Self::ChainTooDeep { .. }
            | Self::Serialize(_) => None,
        }
    }

    /// Build the dotted path a [`ConfigError::SecretInConfig`] reports.
    ///
    /// Lives here rather than at the detection site so the spelling of a key
    /// path — the thing a user greps their file for — is defined once.
    #[must_use]
    pub fn key_path(segments: &[&str]) -> String {
        segments.join(&CONFIG_KEY_PATH_SEPARATOR.to_string())
    }
}

/// Fold a configuration failure into the CLI's error type.
///
/// The classification and the hint both come from the variant itself, so a new
/// variant cannot be added without deciding what it means to a script and what
/// the user should do about it.
impl From<ConfigError> for CliError {
    fn from(error: ConfigError) -> Self {
        let code = error.exit_code();
        let hint = error.hint();
        let cli = Self::new(code, error.to_string());
        match hint {
            Some(hint) => cli.with_hint(hint),
            None => cli,
        }
    }
}

/// Result alias for the configuration layer.
pub type Result<T> = std::result::Result<T, ConfigError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mistyped_name_is_a_usage_error_and_a_broken_file_is_fatal() {
        // Scripts branch on these. A bad argument must not be reported the same
        // way as a corrupted installation.
        assert_eq!(
            ConfigError::NameEmpty.exit_code(),
            ExitCode::Usage,
            "a name the caller typed is a usage error"
        );
        assert_eq!(
            ConfigError::ReservedName { name: "b2".into() }.exit_code(),
            ExitCode::Usage
        );
        assert_eq!(
            ConfigError::Missing(PathBuf::from("/nope")).exit_code(),
            ExitCode::FatalError
        );
        assert_eq!(
            ConfigError::VaultCycle {
                chain: vec!["a".into(), "b".into(), "a".into()]
            }
            .exit_code(),
            ExitCode::FatalError
        );
    }

    #[test]
    fn a_cycle_names_the_whole_walk() {
        // "there is a cycle" is not actionable; the walk is.
        let error = ConfigError::VaultCycle {
            chain: vec!["vault".into(), "inner".into(), "vault".into()],
        };
        let message = error.to_string();
        assert!(
            message.contains("vault -> inner -> vault"),
            "got: {message}"
        );
    }

    #[test]
    fn a_secret_in_the_config_says_where_it_is_and_to_rotate_it() {
        let error = ConfigError::SecretInConfig {
            key: ConfigError::key_path(&["remotes", "b2prod", "secret_key"]),
        };
        assert!(error.to_string().contains("remotes.b2prod.secret_key"));
        let hint = error.hint().unwrap_or_default();
        assert!(hint.contains("rotate"), "an exposed key must be rotated");
        assert!(hint.contains("§14"));
    }

    #[test]
    fn key_paths_are_dotted_like_toml_itself() {
        assert_eq!(ConfigError::key_path(&["a", "b", "c"]), "a.b.c");
        assert_eq!(ConfigError::key_path(&["solo"]), "solo");
        assert_eq!(ConfigError::key_path(&[]), "");
    }

    #[test]
    fn every_variant_carries_its_classification_into_the_cli_error() {
        let cli = CliError::from(ConfigError::UnknownBase {
            remote: "vault".into(),
            base: "gone".into(),
        });
        assert_eq!(cli.code(), ExitCode::FatalError);
        assert!(cli.message().contains("vault"));
        assert!(
            cli.hint().unwrap_or_default().contains("gone"),
            "the hint must name the missing base"
        );
    }

    #[test]
    fn hints_never_restate_the_message() {
        // A hint that adds nothing trains people to stop reading hints, so the
        // variants with no specific next step deliberately have none.
        assert!(ConfigError::NameEmpty.hint().is_none());
        assert!(
            ConfigError::UnknownRemote("nope".into()).hint().is_none(),
            "the message already says which remote is missing"
        );
    }

    #[test]
    fn the_drive_letter_rule_is_explained_where_it_bites() {
        let hint = ConfigError::NameTooShort {
            name: "c".into(),
            min: 2,
        }
        .hint()
        .unwrap_or_default();
        assert!(hint.contains("drive letter"), "got: {hint}");
    }
}
