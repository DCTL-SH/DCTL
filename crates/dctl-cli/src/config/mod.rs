//! The configuration layer — `config.toml` and the rules that govern it.
//!
//! `PLAN.md` §14 defines this file by what it deliberately is *not*. rclone's
//! `rclone.conf` keeps provider credentials and vault passwords next to the
//! settings, "obscured" with reversible obfuscation that anyone holding the file
//! can undo — which means a config in a backup, a dotfiles repository, or a bug
//! report is a credential in a backup, a dotfiles repository, or a bug report.
//! DCTL's config holds **non-secret settings only**: which remotes exist, what
//! type each is, which bucket or endpoint or region it names, how it is chunked,
//! how hard writes are verified. Credentials come from the OS keychain or the
//! environment; the vault password is prompted for or produced by
//! `--password-command`.
//!
//! That prohibition is enforced, not merely stated. There is no field in
//! [`RemoteDef`] that could hold a credential (a test walks the serialised form
//! of every variant to keep it that way), unknown keys are refused rather than
//! ignored, and a refused key whose *name* looks like a credential gets its own
//! error telling the user to delete the line and rotate the secret.
//!
//! # Layout
//!
//! One concern per file, in the order a configuration passes through them:
//!
//! * [`model`] — the shape of the file: [`Config`], [`RemoteDef`] and the
//!   per-provider settings each variant carries. Inert; it knows nothing about
//!   filesystems or rules.
//! * [`location`] — where a remote's bytes physically land, as a comparable
//!   value, so two names for one bucket can be recognised as one place.
//! * [`namespace`] — whether a destination belongs to a vault's object
//!   namespace, so a plain write into one can be refused by name rather than by
//!   inspecting what the destination currently holds.
//! * [`load`] — which file this invocation uses (`--config`, then `DCTL_CONFIG`,
//!   then the platform config directory), reading it, and warning when it is
//!   readable beyond its owner.
//! * [`validate`] — the rules: remote-name spelling, case collisions,
//!   credential-shaped keys, vault chains that loop or dangle, and a plain
//!   remote pointing into a vault's object store.
//! * [`pair`] — the two remotes that address one vault, assembled so that a
//!   single save writes both or neither.
//! * [`save`] — writing it back atomically and owner-only.
//! * [`error`] — the typed failures all of the above produce, and their mapping
//!   onto exit codes and remediation hints.
//!
//! Validation runs at exactly two moments — on load and before save — so a
//! [`Config`] that any other part of the CLI is holding has already been proven
//! consistent, and nothing downstream has to defend itself against a cycle, a
//! dangling base, or a name that cannot be typed.
//!
//! # Typical use
//!
//! ```ignore
//! let path = config::resolve_path(ctx.globals.config.as_deref());
//! let config = config::load_or_default(&path)?;
//! let chain = config::vault_chain(&config, "vault")?;   // ["vault", "b2prod"]
//! ```

mod error;
mod load;
mod location;
mod model;
mod namespace;
mod pair;
mod save;
mod validate;

pub mod catalog;

pub use error::ConfigError;
pub use load::{exposed_permission_bits, load, load_for_diagnosis, load_or_default, resolve_path};
pub use model::{Config, RemoteDef};
pub use namespace::VaultNamespace;
pub use pair::VaultPair;
pub use save::save;
pub use validate::{validate, validate_remote_name, vault_chain, vault_only_locations};

/// The parts of the layer only its tests reach for.
///
/// Nothing in a running command constructs a provider's settings struct by
/// hand, renders a document without writing it, or parses one that did not come
/// from a file: a remote is built by round-tripping TOML (see
/// [`crate::commands::config::settings`]), which is what keeps the file format
/// the single definition of the schema. Tests need to assemble a [`Config`] and
/// inspect its serialised form without touching a filesystem, so these stay
/// re-exported for them rather than forcing a test to reach into a private
/// module — but they are `cfg(test)` so that a *command* that starts wanting
/// one is a compile error and a design conversation, not a quiet second path
/// into the model.
#[cfg(test)]
pub use load::{absent_path, parse};
#[cfg(test)]
pub use model::{B2Def, LocalDef, R2Def, S3Def, VaultDef};
#[cfg(test)]
pub use save::render;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The worked example from `PLAN.md` §14: a plain B2 remote, and a vault
    /// remote wrapping it, both usable in the same run.
    fn plan_example() -> Config {
        let mut config = Config::default();
        config.insert(
            "b2prod",
            RemoteDef::B2(B2Def {
                bucket: "photos".into(),
                endpoint: None,
                chunk_size: None,
                verify: None,
                require_vault: false,
            }),
        );
        config.insert(
            "vault",
            RemoteDef::Vault(VaultDef {
                base: "b2prod".into(),
                base_path: None,
                chunk_size: Some(4 * 1024 * 1024),
                verify: None,
            }),
        );
        config
    }

    #[test]
    fn a_configuration_survives_a_full_save_and_load_cycle() {
        // The end-to-end contract the layer exists to provide: what goes in
        // comes back out, through the real file, with the real rules applied.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        let original = plan_example();

        save(&original, &path).expect("must save");
        let reloaded = load(&path).expect("must load");

        assert_eq!(reloaded, original);
        assert_eq!(
            vault_chain(&reloaded, "vault").expect("must resolve"),
            ["vault", "b2prod"]
        );
    }

    #[test]
    fn the_file_a_user_would_open_contains_no_credentials_and_says_so() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        save(&plan_example(), &path).expect("must save");

        let text = std::fs::read_to_string(&path).expect("must read");
        assert!(
            text.contains("NON-SECRET"),
            "the header is the documentation"
        );

        // Everything below the header is the configuration proper. The header
        // itself talks *about* passwords and credentials, which is the point of
        // it, so the audit starts where the settings do.
        let body = text
            .strip_prefix(crate::constants::CONFIG_FILE_HEADER)
            .unwrap_or(&text)
            .to_ascii_lowercase();
        for forbidden in ["password", "secret", "app_key", "token", "obscure"] {
            assert!(
                !body.contains(forbidden),
                "'{forbidden}' appears in a saved configuration:\n{body}"
            );
        }
    }

    #[test]
    fn a_hand_edited_credential_is_refused_on_the_next_load() {
        // The realistic failure: someone follows an rclone tutorial and pastes a
        // key in. The next command must refuse and say why, not ignore it —
        // an ignored secret is still a secret sitting on disk.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        save(&plan_example(), &path).expect("must save");

        let mut text = std::fs::read_to_string(&path).expect("must read");
        text.push_str(
            "\n[remotes.leaky]\ntype = \"s3\"\nbucket = \"x\"\nsecret_key = \"leaked\"\n",
        );
        std::fs::write(&path, text).expect("must write");

        let error = load(&path).expect_err("must be refused");
        match error {
            ConfigError::SecretInConfig { ref key } => {
                assert_eq!(key, "remotes.leaky.secret_key");
                assert!(
                    error.hint().unwrap_or_default().contains("rotate"),
                    "an exposed credential must be reported as exposed"
                );
            }
            other => panic!("expected the credential to be refused, got {other}"),
        }
    }

    #[test]
    fn a_saved_configuration_is_stable_across_saves() {
        // Byte-for-byte stability is what makes the file worth committing to
        // version control, which §14 explicitly wants.
        let config = plan_example();
        let first = render(&config).expect("must render");
        let second = render(&config).expect("must render");
        assert_eq!(first, second);
    }

    #[test]
    fn every_public_entry_point_agrees_on_what_is_valid() {
        // The same configuration must be acceptable to the validator, the
        // renderer and the parser — a rule enforced by only one of the three
        // would be a rule a user could route around.
        let config = plan_example();
        assert!(validate(&config).is_ok());
        let text = render(&config).expect("must render");
        assert_eq!(
            parse(&text, &PathBuf::from("config.toml")).expect("must parse"),
            config
        );
        assert!(validate_remote_name("b2prod").is_ok());
        assert!(validate_remote_name("c").is_err());
    }
}
