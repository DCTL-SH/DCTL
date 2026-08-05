//! The rules a configuration must satisfy to be usable.
//!
//! Four unrelated things can be wrong with a syntactically valid config, and all
//! four are cheap to detect and expensive to discover later:
//!
//! 1. **A name that cannot be used.** `remote:path` is ambiguous unless remote
//!    names are constrained, and the constraint has to be enforced when a name
//!    is *written* — by the time `c:\data` reaches an argument parser it is too
//!    late to ask which of the two readings was meant.
//! 2. **A vault remote whose base chain loops.** `vault` wrapping `inner`
//!    wrapping `vault` parses perfectly and would hang or blow the stack the
//!    first time anything tried to resolve it.
//! 3. **A credential in the file.** [The plan](https://doc.dctl.sh/project/plan)
//!    §14's central prohibition. The model has no field that could hold one, so
//!    the only way a secret arrives is as an unexpected key — and an unexpected
//!    key that looks like a credential deserves a louder answer than "unknown
//!    field".
//! 4. **A plain remote pointing into a vault's object store.** A location
//!    marked `require_vault` holds a vault's opaque objects. A second, plain
//!    remote addressing the same place is one mistyped command away from
//!    writing unencrypted files next to them, so it is refused here rather than
//!    at the moment the bytes are already moving.
//!
//! Validation runs at exactly two moments: when a configuration is loaded, and
//! before one is written. Nothing invalid is therefore ever read *or* stored,
//! and no other code has to defend itself against a cycle.

use std::collections::{BTreeMap, BTreeSet};

use crate::constants::{
    MAX_REMOTE_NAME_LEN, MAX_VAULT_CHAIN_DEPTH, MIN_REMOTE_NAME_LEN, REMOTE_NAME_EXTRA_CHARS,
    REMOTE_PROVIDER_TYPES,
};
use crate::logging::redact::is_sensitive_key;
use crate::platform::path::is_drive_letter;

use super::error::{ConfigError, Result};
use super::location::Location;
use super::model::{Config, RemoteDef};

/// Check one remote name against every naming rule.
///
/// The rules exist to keep `remote:path` unambiguous, in this order of
/// importance: a name is at least [`MIN_REMOTE_NAME_LEN`] characters, which is
/// one, matching rclone's own minimum; it contains only ASCII letters, digits
/// and [`REMOTE_NAME_EXTRA_CHARS`], so it can never be read as a path or need
/// shell quoting; it starts with a letter or a digit, so it can never be read as
/// a flag; and it is not the name of a provider type, so `b2:` cannot mean both
/// "the remote called b2" and "the b2 backend".
///
/// **Platform-independent, deliberately.** A config file is carried between
/// machines, so what it may contain cannot depend on where it is read. The one
/// rule that *is* platform-dependent — that a Windows machine must not create a
/// remote a drive letter would shadow — lives in [`drive_letter_conflict`] and
/// applies when a name is chosen, not when a file is loaded.
///
/// # Errors
/// One of [`ConfigError::NameEmpty`], [`ConfigError::NameTooShort`],
/// [`ConfigError::NameTooLong`], [`ConfigError::NameCharset`],
/// [`ConfigError::NameStart`] or [`ConfigError::ReservedName`], naming the first
/// rule the name broke.
pub fn validate_remote_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(ConfigError::NameEmpty);
    }

    // Count characters, not bytes: the length rules are about how a name reads,
    // and a name is rejected as non-ASCII below anyway.
    let length = name.chars().count();
    if length < MIN_REMOTE_NAME_LEN {
        return Err(ConfigError::NameTooShort {
            name: name.to_string(),
            min: MIN_REMOTE_NAME_LEN,
        });
    }
    if length > MAX_REMOTE_NAME_LEN {
        return Err(ConfigError::NameTooLong {
            name: name.to_string(),
            max: MAX_REMOTE_NAME_LEN,
        });
    }

    if let Some(offender) = name.chars().find(|c| !is_name_char(*c)) {
        return Err(ConfigError::NameCharset {
            name: name.to_string(),
            offender,
        });
    }

    // Checked after the charset so a name starting with an illegal character is
    // reported as an illegal character rather than as a bad first letter.
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return Err(ConfigError::NameStart {
            name: name.to_string(),
        });
    }

    if is_reserved(name) {
        return Err(ConfigError::ReservedName {
            name: name.to_string(),
        });
    }

    Ok(())
}

/// Whether a character may appear inside a remote name.
fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || REMOTE_NAME_EXTRA_CHARS.contains(&c)
}

/// Whether creating a remote called `name` on **this** machine would produce a
/// remote nothing on this machine could address.
///
/// rclone refuses a drive-letter name outright when a remote is created, and for
/// the reason that matters here: on Windows `c:` is the C: drive before any
/// configuration is consulted, so a remote called `c` could be listed and
/// repaired by name but never reached through `c:path`. Off Windows there is no
/// drive to be shadowed by and the name is ordinary — which is why this is asked
/// at creation time, on the machine doing the creating, and never on load.
///
/// A config carried from Linux to Windows may therefore contain such a name.
/// That is rclone's position too, and `dctl config list` still shows it; what
/// this prevents is a Windows operator *choosing* a name their own shell will
/// take away from them.
///
/// `drive_letters` is [`crate::constants::DRIVE_LETTERS_EXIST`] in production and
/// is a parameter
/// for the same reason [`crate::remote::RemoteSpec::classify`]'s is: the failure
/// mode of a `cfg`-gated rule is that only one half of it is ever executed, and
/// the half nobody runs here is the one that decides what a Windows operator may
/// call their vault.
#[must_use]
pub fn drive_letter_conflict(name: &str, drive_letters: bool) -> bool {
    drive_letters && is_drive_letter(name)
}

/// Whether a name is already taken by a provider type.
///
/// Compared case-insensitively because the collision is about how a human reads
/// `B2:bucket`, not about how a map looks it up.
///
/// [`PROVIDER_VAULT`] is deliberately **not** reserved, and that is the whole
/// reason this checks [`REMOTE_PROVIDER_TYPES`] rather than every legal `type`
/// value. A name is reserved when it already means a backend on the left of a
/// colon: `b2:bucket` cannot be allowed to mean both "the remote called b2" and
/// "the b2 backend". `vault:` has no such second reading — a vault remote is
/// absent from [`REMOTE_PROVIDER_TYPES`] precisely because it stores nothing and
/// therefore has no shorthand form — so there is no ambiguity to prevent, and
/// reserving it would forbid the one name a vault is most likely to be given.
fn is_reserved(name: &str) -> bool {
    REMOTE_PROVIDER_TYPES
        .iter()
        .any(|(provider, _)| name.eq_ignore_ascii_case(provider))
}

/// Check a whole configuration.
///
/// Runs the name rules over every remote, refuses two names that differ only in
/// case, and resolves every vault remote's base chain — so a configuration that
/// passes this can be walked by the rest of the CLI without any of it having to
/// consider a missing base or an infinite loop.
///
/// # Errors
/// Anything [`validate_remote_name`] or [`vault_chain`] produces, plus
/// [`ConfigError::DuplicateNameCase`] when two names differ only in case.
pub fn validate(config: &Config) -> Result<()> {
    let mut folded: BTreeMap<String, &str> = BTreeMap::new();

    for name in config.names() {
        validate_remote_name(name)?;

        // Two names differing only in case are always a typo, and an ambiguity
        // everywhere a name passes through something case-insensitive: a shell
        // completion, a Windows filename, a person reading a table.
        if let Some(first) = folded.insert(name.to_ascii_lowercase(), name) {
            return Err(ConfigError::DuplicateNameCase {
                first: first.to_string(),
                second: name.to_string(),
            });
        }
    }

    for name in config.names() {
        if config.get(name).is_some_and(RemoteDef::is_vault) {
            vault_chain(config, name)?;
        }
    }

    vault_only_locations(config)?;
    settings_nothing_honours(config)?;

    Ok(())
}

/// Refuse a remote carrying a setting [`crate::config::reach`] says this build
/// cannot apply.
///
/// `dctl config create` refuses one before it is written, but a file created by
/// an earlier build still carries it — and carried it *silently*, because the
/// value round-tripped through the file faithfully and reached nothing. So the
/// setting is diagnosed on the way in as well, which is the same conclusion
/// reached about the sftp base and for the same reason: a rule enforced by
/// one command is a rule the file can be hand-edited around.
///
/// Table-driven, and asked of the serialised form, so the next refused setting
/// needs no edit here. One refusal exists today — a vault's `base_path` — and
/// its remedy costs nothing, which the hint says: because the setting was never
/// applied, the vault's objects are already at the root of the store it wraps,
/// so deleting the line changes where nothing is addressed. That is what makes
/// refusing an existing file safe rather than hostile, and it is the opposite of
/// the sftp base, where the same shape of fault meant two different directories.
///
/// # Errors
/// [`ConfigError::SettingNotHonoured`], naming the remote, the key and the value
/// as written, so the operator can find the line.
fn settings_nothing_honours(config: &Config) -> Result<()> {
    for name in config.names() {
        let Some(remote) = config.get(name) else {
            continue;
        };
        let Ok(toml::Value::Table(table)) = toml::Value::try_from(remote) else {
            continue;
        };
        for (key, value) in &table {
            // An empty value is unset, the same rule every other setting
            // follows, and what an update assigning nothing writes on its way
            // to removing one.
            if value.as_str() == Some("") {
                continue;
            }
            if let Some(reason) = crate::config::reach::refusal(remote.type_name(), key) {
                return Err(ConfigError::SettingNotHonoured {
                    remote: name.to_string(),
                    key: key.clone(),
                    written: crate::commands::config::settings::scalar_text(value),
                    reason,
                });
            }
        }
    }
    Ok(())
}

/// Refuse a plain remote pointing at a location declared vault-only.
///
/// The config-level half of invariant I2 (`require_vault`). It lives in
/// [`validate`] rather than inside `dctl config create` for the same reason
/// every other rule here does: a rule enforced by one command is a rule the file
/// can be hand-edited around, and the failure it prevents — plaintext written
/// into a vault's object store — is not one worth leaving a door open on.
///
/// Enforcing it on **load** as well as on save is deliberate and is the
/// aggressive reading. A configuration that names both a vault store and a plain
/// remote at the same place is not merely untidy; it is a configuration in which
/// one mistyped command writes unencrypted data next to the ciphertext. Refusing
/// to open it, with a message that names both remotes and the place they share,
/// is a better outcome than opening it and hoping the right one gets typed.
///
/// Public because `dctl config verify` reports this fault alongside the others
/// it finds, and a compliance pre-flight that re-derived the rule would sooner
/// or later disagree with the loader about what the file means.
///
/// # Errors
/// [`ConfigError::PlainRemoteAtVaultLocation`], naming the plain remote, the
/// remote that declared the location, and the location itself.
pub fn vault_only_locations(config: &Config) -> Result<()> {
    // Collected first so the answer does not depend on which remote the walk
    // happens to reach first: whether a location is vault-only is a property of
    // the file, not of the iteration order.
    let mut guarded: BTreeMap<Location, &str> = BTreeMap::new();
    for name in config.names() {
        if let Some(remote) = config.get(name)
            && remote.require_vault()
            && let Some(location) = Location::of(remote)
        {
            guarded.entry(location).or_insert(name);
        }
    }

    if guarded.is_empty() {
        return Ok(());
    }

    for name in config.names() {
        let Some(remote) = config.get(name) else {
            continue;
        };
        // A remote that declares the location is the remote the rule exists to
        // protect; it is not in violation of itself.
        if remote.require_vault() {
            continue;
        }
        let Some(location) = Location::of(remote) else {
            continue;
        };
        if let Some(guard) = guarded.get(&location) {
            return Err(ConfigError::PlainRemoteAtVaultLocation {
                plain: name.to_string(),
                guard: (*guard).to_string(),
                location: location.to_string(),
            });
        }
    }

    Ok(())
}

/// Resolve a remote to the chain of remotes it stores through.
///
/// Returns the walk from `name` down to the first remote that stores bytes
/// itself, so `["vault", "b2prod"]` for a vault remote over a B2 bucket and
/// `["b2prod"]` for the bucket alone. That chain is what a caller needs in order
/// to build a backend, and producing it is also the only honest way to prove
/// there is no cycle.
///
/// Fails with [`ConfigError::VaultCycle`] on a loop, [`ConfigError::UnknownBase`]
/// on a dangling reference, and [`ConfigError::ChainTooDeep`] on a chain longer
/// than [`MAX_VAULT_CHAIN_DEPTH`]. The visited set makes the first of those
/// exact; the depth bound catches the merely absurd.
///
/// # Errors
/// [`ConfigError::UnknownRemote`] when `name` itself is not configured,
/// [`ConfigError::UnknownBase`] when a link names a base that is not,
/// [`ConfigError::VaultCycle`] on a loop, and [`ConfigError::ChainTooDeep`]
/// beyond [`MAX_VAULT_CHAIN_DEPTH`] links.
pub fn vault_chain<'a>(config: &'a Config, name: &'a str) -> Result<Vec<&'a str>> {
    let mut chain: Vec<&str> = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut current = name;

    loop {
        if !seen.insert(current) {
            // Push the repeat so the reported walk closes visibly:
            // `vault -> inner -> vault`.
            chain.push(current);
            return Err(ConfigError::VaultCycle {
                chain: chain.iter().map(|link| (*link).to_string()).collect(),
            });
        }
        chain.push(current);

        if chain.len() > MAX_VAULT_CHAIN_DEPTH {
            return Err(ConfigError::ChainTooDeep {
                remote: name.to_string(),
                max: MAX_VAULT_CHAIN_DEPTH,
            });
        }

        let Some(remote) = config.get(current) else {
            // The head of the chain is a remote the caller asked for; anything
            // deeper is a base some vault remote named.
            return Err(match chain.len() {
                1 => ConfigError::UnknownRemote(current.to_string()),
                length => ConfigError::UnknownBase {
                    remote: chain[length - 2].to_string(),
                    base: current.to_string(),
                },
            });
        };

        match remote.base() {
            Some(base) => current = base,
            None => return Ok(chain),
        }
    }
}

/// Refuse a parsed TOML document that contains a credential-shaped key.
///
/// Runs against the raw document, before it is deserialised, so the message can
/// name the key's full path and say what to do about it — `deny_unknown_fields`
/// alone would report "unknown field `secret_key`", which reads like a typo
/// rather than like the security event it is.
///
/// Only keys holding a *value* are checked. A key whose value is a table is a
/// user-chosen remote name, and `my-secret-vault` is a perfectly reasonable thing
/// to call a vault; the prohibition in
/// [the plan](https://doc.dctl.sh/project/plan) §14 is about storing credentials,
/// not about the words people name things with.
///
/// # Errors
/// [`ConfigError::SecretInConfig`], carrying the dotted path of the first
/// offending key.
pub fn reject_secret_keys(document: &toml::Table) -> Result<()> {
    let mut path: Vec<&str> = Vec::new();
    walk_for_secrets(document, &mut path)
}

/// Depth-first walk behind [`reject_secret_keys`].
fn walk_for_secrets<'a>(table: &'a toml::Table, path: &mut Vec<&'a str>) -> Result<()> {
    for (key, value) in table {
        match value.as_table() {
            Some(child) => {
                path.push(key.as_str());
                walk_for_secrets(child, path)?;
                path.pop();
            }
            None => {
                if is_sensitive_key(key) {
                    path.push(key.as_str());
                    let reported = ConfigError::key_path(path);
                    path.pop();
                    return Err(ConfigError::SecretInConfig { key: reported });
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{B2Def, LocalDef, RemoteDef, VaultDef};
    use crate::constants::DRIVE_LETTERS_EXIST;
    use crate::constants::PROVIDER_VAULT;
    use std::path::PathBuf;

    fn local() -> RemoteDef {
        RemoteDef::Local(LocalDef {
            path: PathBuf::from("/srv"),
            verify: None,
            require_vault: false,
        })
    }

    fn local_at(path: &str, require_vault: bool) -> RemoteDef {
        RemoteDef::Local(LocalDef {
            path: PathBuf::from(path),
            verify: None,
            require_vault,
        })
    }

    fn bucket() -> RemoteDef {
        RemoteDef::B2(B2Def {
            bucket: "photos".into(),
            endpoint: None,
            chunk_size: None,
            verify: None,
            require_vault: false,
        })
    }

    fn bucket_named(name: &str, require_vault: bool) -> RemoteDef {
        RemoteDef::B2(B2Def {
            bucket: name.into(),
            endpoint: None,
            chunk_size: None,
            verify: None,
            require_vault,
        })
    }

    fn vault(base: &str) -> RemoteDef {
        RemoteDef::Vault(VaultDef {
            base: base.to_string(),
            base_path: None,
            chunk_size: None,
            verify: None,
        })
    }

    fn config_of(pairs: &[(&str, RemoteDef)]) -> Config {
        let mut config = Config::default();
        for (name, remote) in pairs {
            config.insert(*name, remote.clone());
        }
        config
    }

    #[test]
    fn ordinary_names_are_accepted() {
        for name in [
            "b2prod",
            "vault",
            "cold-storage",
            "vault_2024",
            "vault.old",
            "a1",
            "x9",
        ] {
            assert!(
                validate_remote_name(name).is_ok(),
                "'{name}' should be a legal remote name"
            );
        }
    }

    #[test]
    fn a_one_character_name_is_legal_because_rclone_makes_one_legal() {
        // rclone accepts a single-character name and applies that rule on every
        // platform, so a config being migrated can already contain one.
        // Refusing it here made the import, not the data, the thing that
        // failed.
        for name in ["r", "c", "1", "x"] {
            assert!(
                validate_remote_name(name).is_ok(),
                "'{name}' must be declarable"
            );
        }
        // Empty is still nothing at all.
        assert!(matches!(
            validate_remote_name(""),
            Err(ConfigError::NameEmpty)
        ));
    }

    #[test]
    fn a_drive_letter_name_is_refused_only_where_drives_exist() {
        // rclone's rule, and the reason the length rule above could safely be
        // dropped: on Windows `c:` is the C: drive before any config is read,
        // so choosing `c` there gives you a remote your own shell hides.
        assert!(drive_letter_conflict("c", true));
        assert!(drive_letter_conflict("Z", true));
        assert!(!drive_letter_conflict("c", false));
        // Not every one-character name is a drive: rclone requires a single
        // ASCII letter, so a digit is a perfectly reachable remote on Windows.
        assert!(!drive_letter_conflict("1", true));
        assert!(!drive_letter_conflict("cd", true));
        // And this platform's own answer is one of the two, never a third.
        assert_eq!(
            drive_letter_conflict("c", DRIVE_LETTERS_EXIST),
            DRIVE_LETTERS_EXIST
        );
    }

    #[test]
    fn names_that_could_be_paths_are_rejected() {
        // Each of these would make `name:path` ambiguous or need shell quoting.
        for name in [
            "my/remote",
            r"my\remote",
            "my:remote",
            "my remote",
            "remote!",
            "remote*",
            "café",
            "remote\n",
        ] {
            let error = validate_remote_name(name)
                .expect_err(&format!("'{name}' should have been rejected"));
            assert!(
                matches!(error, ConfigError::NameCharset { .. }),
                "'{name}' gave {error}"
            );
        }
    }

    #[test]
    fn a_name_that_reads_as_a_flag_or_a_path_is_rejected() {
        // `--exclude -old` and `dctl ls -old:` are already hard enough to read
        // without a remote actually being called `-old`. A leading dot is the
        // same rule doing the other half of its job: `.` and `..` are paths on
        // every platform, so `..:backup` must never resolve as a remote — which
        // is why `.` is legal *inside* a name (`vault.old`) but not at the front.
        for name in ["-old", "_tmp", ".hidden", "..", ".."] {
            let error = validate_remote_name(name).expect_err("must be rejected");
            assert!(matches!(error, ConfigError::NameStart { .. }), "{error}");
        }
    }

    #[test]
    fn a_name_may_not_be_longer_than_the_ceiling() {
        let long = "a".repeat(MAX_REMOTE_NAME_LEN + 1);
        assert!(matches!(
            validate_remote_name(&long),
            Err(ConfigError::NameTooLong { .. })
        ));
        // Exactly at the ceiling is fine — the bound is inclusive.
        assert!(validate_remote_name(&"a".repeat(MAX_REMOTE_NAME_LEN)).is_ok());
    }

    #[test]
    fn provider_types_cannot_be_reused_as_remote_names() {
        // `b2:bucket` must mean one thing. It already means "the b2 backend".
        for (provider, _) in REMOTE_PROVIDER_TYPES {
            assert!(
                matches!(
                    validate_remote_name(provider),
                    Err(ConfigError::ReservedName { .. })
                ),
                "'{provider}' should be reserved"
            );
        }
        // Case does not rescue it: a person reading `B2:` reads "b2".
        assert!(matches!(
            validate_remote_name("B2"),
            Err(ConfigError::ReservedName { .. })
        ));
        // A name that merely *contains* a provider type is fine.
        assert!(validate_remote_name("b2prod").is_ok());
    }

    #[test]
    fn vault_is_a_legal_remote_name_because_it_is_not_a_backend() {
        // The exclusion of `vault` from REMOTE_PROVIDER_TYPES is load-bearing, not
        // an oversight in the table. Every documented example spells a vault
        // `vault:photos/2024`, so the moment `vault` became reserved the docs
        // would describe a configuration the loader refuses to accept.
        assert!(
            !REMOTE_PROVIDER_TYPES
                .iter()
                .any(|(provider, _)| provider.eq_ignore_ascii_case(PROVIDER_VAULT)),
            "a vault stores nothing, so it must never be offered as a destination"
        );
        assert!(
            validate_remote_name(PROVIDER_VAULT).is_ok(),
            "'{PROVIDER_VAULT}' must remain usable as a remote name"
        );
        // And in the shape a config actually takes: a vault named `vault`.
        let config = config_of(&[("b2prod", bucket()), (PROVIDER_VAULT, vault("b2prod"))]);
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn a_valid_configuration_validates() {
        let config = config_of(&[("b2prod", bucket()), ("vault", vault("b2prod"))]);
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn an_empty_configuration_is_valid() {
        // A machine driven entirely by flags and environment variables never
        // writes a config, and [the plan](https://doc.dctl.sh/project/plan) §14
        // says that must keep working.
        assert!(validate(&Config::default()).is_ok());
    }

    #[test]
    fn a_self_referential_vault_remote_is_a_cycle() {
        let config = config_of(&[("vault", vault("vault"))]);
        let error = validate(&config).expect_err("must be rejected");
        match error {
            ConfigError::VaultCycle { chain } => assert_eq!(chain, ["vault", "vault"]),
            other => panic!("expected a cycle, got {other}"),
        }
    }

    #[test]
    fn a_two_step_cycle_is_reported_with_the_whole_walk() {
        let config = config_of(&[("vault", vault("inner")), ("inner", vault("vault"))]);
        let error = validate(&config).expect_err("must be rejected");
        match error {
            ConfigError::VaultCycle { chain } => {
                // The walk closes on the repeat, so the loop is readable.
                assert_eq!(
                    chain.first().map(String::as_str),
                    chain.last().map(String::as_str)
                );
                assert_eq!(chain.len(), 3);
            }
            other => panic!("expected a cycle, got {other}"),
        }
    }

    #[test]
    fn a_long_cycle_is_still_caught() {
        // Three links, to prove the visited set and not merely a self-check.
        let config = config_of(&[
            ("one", vault("two")),
            ("two", vault("three")),
            ("three", vault("one")),
        ]);
        assert!(matches!(
            validate(&config),
            Err(ConfigError::VaultCycle { .. })
        ));
    }

    #[test]
    fn a_dangling_base_names_both_ends() {
        let config = config_of(&[("vault", vault("gone"))]);
        let error = validate(&config).expect_err("must be rejected");
        match error {
            ConfigError::UnknownBase { remote, base } => {
                assert_eq!(remote, "vault");
                assert_eq!(base, "gone");
            }
            other => panic!("expected a dangling base, got {other}"),
        }
    }

    #[test]
    fn asking_for_a_remote_that_does_not_exist_is_its_own_error() {
        // Distinct from a dangling base: nobody pointed at it, the caller did.
        let config = config_of(&[("b2prod", bucket())]);
        assert!(matches!(
            vault_chain(&config, "nope"),
            Err(ConfigError::UnknownRemote(_))
        ));
    }

    #[test]
    fn a_chain_resolves_to_the_remote_that_actually_stores_bytes() {
        let config = config_of(&[
            ("b2prod", bucket()),
            ("inner", vault("b2prod")),
            ("vault", vault("inner")),
        ]);
        assert_eq!(
            vault_chain(&config, "vault").expect("must resolve"),
            ["vault", "inner", "b2prod"]
        );
        // A plain remote is a chain of one — the terminal case, not a special one.
        assert_eq!(
            vault_chain(&config, "b2prod").expect("must resolve"),
            ["b2prod"]
        );
    }

    #[test]
    fn an_absurdly_deep_chain_is_refused_before_it_is_walked_further() {
        // One more link than the bound allows, all distinct, so this is the depth
        // rule firing and not the cycle detector.
        let mut config = Config::default();
        let depth = MAX_VAULT_CHAIN_DEPTH + 1;
        for step in 0..depth {
            config.insert(format!("w{step}"), vault(&format!("w{}", step + 1)));
        }
        config.insert(format!("w{depth}"), local());

        assert!(matches!(
            vault_chain(&config, "w0"),
            Err(ConfigError::ChainTooDeep { .. })
        ));
        // And a chain exactly at the bound still resolves.
        let mut shallow = Config::default();
        for step in 0..MAX_VAULT_CHAIN_DEPTH - 1 {
            shallow.insert(format!("w{step}"), vault(&format!("w{}", step + 1)));
        }
        shallow.insert(format!("w{}", MAX_VAULT_CHAIN_DEPTH - 1), local());
        assert!(vault_chain(&shallow, "w0").is_ok());
    }

    #[test]
    fn names_differing_only_in_case_are_refused() {
        let config = config_of(&[("vault", bucket()), ("Vault", bucket())]);
        assert!(matches!(
            validate(&config),
            Err(ConfigError::DuplicateNameCase { .. })
        ));
    }

    #[test]
    fn a_bad_name_in_the_file_is_caught_by_whole_config_validation() {
        // A name too long is the shape that survives: the floor is one character
        // now, so shortness is no longer a fault a file can have.
        let config = config_of(&[(&"a".repeat(MAX_REMOTE_NAME_LEN + 1), local())]);
        assert!(matches!(
            validate(&config),
            Err(ConfigError::NameTooLong { .. })
        ));
        // And a one-character section loads, on every platform, which is the
        // point of the change: a Linux-authored config opens on Windows too.
        assert!(validate(&config_of(&[("r", local())])).is_ok());
    }

    #[test]
    fn the_pair_dctl_init_writes_is_valid() {
        // The shape everything else in this section is measured against: a store
        // remote that declares its location vault-only, and the vault remote
        // that wraps it. Nothing about that is a violation — the store is the
        // remote the rule protects, not one it catches.
        let config = config_of(&[
            ("archive-store", local_at("/srv/vault", true)),
            ("archive", vault("archive-store")),
        ]);
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn a_plain_remote_at_a_vault_store_is_refused_and_named() {
        // The failure this rule exists for: a second remote addressing the same
        // directory as an ordinary place to put files. One mistyped destination
        // and plaintext is sitting beside the ciphertext.
        let config = config_of(&[
            ("archive-store", local_at("/srv/vault", true)),
            ("archive", vault("archive-store")),
            ("scratch", local_at("/srv/vault", false)),
        ]);
        let error = validate(&config).expect_err("must be refused");
        match error {
            ConfigError::PlainRemoteAtVaultLocation {
                ref plain,
                ref guard,
                ref location,
            } => {
                assert_eq!(plain, "scratch");
                assert_eq!(guard, "archive-store");
                assert!(location.contains("/srv/vault"), "got: {location}");
                // The remediation has to point at the two ways the location can
                // legitimately be addressed, or the user's only option is to
                // delete the guard.
                let hint = error.hint().unwrap_or_default();
                assert!(hint.contains("archive-store"), "got hint: {hint}");
            }
            other => panic!("expected the plain remote to be refused, got {other}"),
        }
    }

    #[test]
    fn the_rule_follows_the_place_and_not_the_provider_or_the_name() {
        // A bucket is a place too, and the collision is between *locations*: two
        // sections naming one bucket collide however differently they are named.
        let colliding = config_of(&[
            ("archive-store", bucket_named("sealed", true)),
            ("archive", vault("archive-store")),
            ("legacy", bucket_named("sealed", false)),
        ]);
        assert!(matches!(
            validate(&colliding),
            Err(ConfigError::PlainRemoteAtVaultLocation { .. })
        ));

        // A different bucket is a different place, and must not be caught.
        let separate = config_of(&[
            ("archive-store", bucket_named("sealed", true)),
            ("archive", vault("archive-store")),
            ("legacy", bucket_named("elsewhere", false)),
        ]);
        assert!(validate(&separate).is_ok());
    }

    #[test]
    fn a_configuration_with_no_vault_only_location_is_unaffected() {
        // The rule must cost nothing to the overwhelming majority of configs,
        // which never mark a location at all.
        let config = config_of(&[
            ("b2prod", bucket()),
            ("scratch", local()),
            ("vault", vault("b2prod")),
        ]);
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn two_stores_may_both_declare_the_same_location() {
        // Not a collision worth refusing: both agree the place is a vault store,
        // which is the claim the rule enforces. Refusing here would break the
        // legitimate case of an operator renaming a store by adding the new
        // section before removing the old one.
        let config = config_of(&[
            ("archive-store", local_at("/srv/vault", true)),
            ("archive-store2", local_at("/srv/vault", true)),
            ("archive", vault("archive-store")),
        ]);
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn a_credential_key_is_found_wherever_it_hides() {
        for (text, expected) in [
            ("password = \"x\"\n", "password"),
            (
                "[remotes.b2prod]\ntype = \"b2\"\napp_key = \"x\"\n",
                "remotes.b2prod.app_key",
            ),
            (
                "[remotes.v]\ntype = \"s3\"\nsecret_key = \"x\"\n",
                "remotes.v.secret_key",
            ),
            (
                "[remotes.v]\ntype = \"s3\"\nAuthorization = \"x\"\n",
                "remotes.v.Authorization",
            ),
        ] {
            let document: toml::Table = toml::from_str(text).expect("must parse as TOML");
            match reject_secret_keys(&document) {
                Err(ConfigError::SecretInConfig { key }) => assert_eq!(key, expected),
                other => panic!("expected '{expected}' to be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_remote_may_still_be_called_something_with_secret_in_it() {
        // The false positive that would make the rule unusable: the prohibition
        // is on storing credentials, not on the words people name things with.
        let document: toml::Table =
            toml::from_str("[remotes.my-secret-vault]\ntype = \"b2\"\nbucket = \"x\"\n")
                .expect("must parse as TOML");
        assert!(reject_secret_keys(&document).is_ok());
    }

    #[test]
    fn an_ordinary_configuration_has_nothing_to_refuse() {
        let document: toml::Table = toml::from_str(
            "[remotes.b2prod]\ntype = \"b2\"\nbucket = \"photos\"\nendpoint = \"https://x\"\n\
             [remotes.vault]\ntype = \"vault\"\nbase = \"b2prod\"\nchunk_size = 4194304\n",
        )
        .expect("must parse as TOML");
        assert!(reject_secret_keys(&document).is_ok());
    }

    #[test]
    fn a_vault_base_path_written_by_an_older_build_is_diagnosed_on_the_way_in() {
        // `dctl config create` refuses it now, but a file that already carries
        // one is the case that matters: the setting round-tripped faithfully and
        // reached nothing, so an operator has a subdirectory in their config and
        // their objects at the root.
        let mut config = Config::default();
        config.insert(
            "archive-store",
            RemoteDef::Local(LocalDef {
                path: PathBuf::from("/srv/v"),
                verify: None,
                require_vault: true,
            }),
        );
        config.insert(
            "archive",
            RemoteDef::Vault(VaultDef {
                base: "archive-store".into(),
                base_path: Some("vaults/a".into()),
                chunk_size: None,
                verify: None,
            }),
        );
        let error = validate(&config).expect_err("a subdirectory must be diagnosed");
        assert_eq!(
            error.exit_code(),
            crate::exit::ExitCode::FatalError,
            "a configuration that cannot be honoured is a configuration error"
        );
        assert!(error.to_string().contains("archive"), "{error}");
        assert!(error.to_string().contains("vaults/a"), "{error}");
        // The remedy is deleting a line and nothing moves, which is the whole
        // reason refusing an existing file is safe here.
        let hint = error.hint().unwrap_or_default();
        assert!(hint.contains("Nothing has to move"), "{hint}");
        assert!(hint.contains("base_path="), "{hint}");

        // Cleared, the same configuration is fine — so the rule refuses the
        // setting rather than the vault.
        if let Some(RemoteDef::Vault(def)) = config.remotes.get_mut("archive") {
            def.base_path = None;
        }
        assert!(validate(&config).is_ok());

        // And an empty value is unset, which is what `config update v
        // base_path=` writes on the way to removing it.
        if let Some(RemoteDef::Vault(def)) = config.remotes.get_mut("archive") {
            def.base_path = Some(String::new());
        }
        assert!(validate(&config).is_ok());
    }
}
