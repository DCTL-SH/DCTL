//! Translation between a typed [`RemoteDef`] and the flat `key=value`
//! vocabulary a command line speaks.
//!
//! [`crate::config`] models a remote as a tagged enum with a different set of
//! fields per provider, which is what makes an impossible configuration
//! unrepresentable and a pasted-in credential a parse error. A shell, though,
//! has words: `dctl config create b2prod b2 bucket=photos`. Something has to
//! sit between the two, and putting it here rather than in each subcommand means
//! `create`, `update` and `show` cannot disagree about what a setting is called
//! or how a value is spelled.
//!
//! The conversion goes through TOML in both directions rather than through a
//! hand-written match per provider. That is deliberate: the file format *is* the
//! vocabulary, so a field added to [`RemoteDef`] tomorrow becomes settable and
//! displayable with no edit here, and a field that does not exist is rejected by
//! the same `deny_unknown_fields` that rejects it in the file. A hand-written
//! mapping would be a second definition of the schema, and second definitions
//! drift.

use std::collections::BTreeMap;

use toml::Value;

use crate::config::{ConfigError, RemoteDef};
use crate::constants;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::remote::resolve::RemoteEntry;

/// Every `type` a config section may declare.
///
/// [`constants::REMOTE_PROVIDER_TYPES`] plus [`constants::PROVIDER_VAULT`]. The
/// vault wrapper is legal in the file but is not a *destination*, which is why
/// the shared table leaves it out and this list puts it back: `dctl config
/// providers` answers "where can bytes go", while `dctl config create` has to
/// accept everything the file accepts.
#[must_use]
pub fn known_types() -> Vec<&'static str> {
    constants::REMOTE_PROVIDER_TYPES
        .iter()
        .map(|(name, _)| *name)
        .chain(std::iter::once(constants::PROVIDER_VAULT))
        .collect()
}

/// Reject a provider type this build has no model for.
///
/// Deserialising would reject it too, but as a serde message about an unknown
/// variant. Checking first means the error names the typo and lists what would
/// have worked.
///
/// # Errors
/// [`ExitCode::Usage`], listing the accepted types.
pub fn validate_type(remote_type: &str) -> Result<()> {
    let known = known_types();
    if known.contains(&remote_type) {
        return Ok(());
    }

    Err(CliError::new(
        ExitCode::Usage,
        format!("unknown remote type '{remote_type}'"),
    )
    .with_hint(format!(
        "Known types: {}. See `dctl config providers`.",
        known.join(", ")
    )))
}

/// Flatten a remote into the settings a user would see in the file.
///
/// Sorted by key, `type` included, values spelled as they are written in TOML —
/// minus the quotes on a string, which belong to the format rather than to the
/// value. Absent optional settings do not appear, because the file does not
/// write them either: showing `chunk_size -` would imply a decision that has
/// deliberately not been made.
#[must_use]
pub fn flatten(remote: &RemoteDef) -> Vec<(String, String)> {
    let Ok(Value::Table(table)) = Value::try_from(remote) else {
        // Unreachable for a `RemoteDef`, which is a plain struct of scalars.
        // Returning nothing beats inventing a value that was never configured.
        return Vec::new();
    };

    let mut settings: Vec<(String, String)> = table
        .into_iter()
        .map(|(key, value)| (key, scalar_to_string(&value)))
        .collect();
    settings.sort_by(|a, b| a.0.cmp(&b.0));
    settings
}

/// The whole configuration, in the vocabulary [`crate::remote::resolve`] reads.
///
/// [`crate::remote::resolve`] takes its remotes through the
/// [`RemoteCatalog`](crate::remote::resolve::RemoteCatalog) trait so that
/// resolution stays a pure function of (spec, catalog) — which leaves somebody
/// having to translate a typed [`crate::config::Config`] into that vocabulary.
/// It happens here, once, by the same [`flatten`] round trip `dctl config show`
/// makes, so what a command resolves is exactly what the file says rather than a
/// second reading of it. A second translation living next to whichever command
/// needed one first is how two commands come to disagree about which bucket a
/// remote names.
///
/// The `type` key is dropped from the settings map because
/// [`RemoteEntry::provider`] already carries it; leaving it in both places would
/// let a hand-edited section contradict itself.
#[must_use]
pub fn catalog(config: &crate::config::Config) -> BTreeMap<String, RemoteEntry> {
    config
        .remotes
        .iter()
        .map(|(name, remote)| {
            let settings = flatten(remote)
                .into_iter()
                .filter(|(key, _)| key != constants::CONFIG_REMOTE_TYPE_KEY)
                .collect();
            (
                name.clone(),
                RemoteEntry {
                    provider: remote.type_name().to_string(),
                    settings,
                },
            )
        })
        .collect()
}

/// Build a remote from a declared type and a set of assignments.
///
/// # Errors
/// [`ExitCode::Usage`] when the type is unknown, a required setting is missing,
/// or a setting does not belong to this provider — all three surface as the
/// deserialiser's own message, which names the offending key.
pub fn build(remote_type: &str, assignments: &BTreeMap<String, String>) -> Result<RemoteDef> {
    validate_type(remote_type)?;

    let mut table = toml::Table::new();
    for (key, value) in assignments {
        // An empty value means "unset", and a setting that is being unset before
        // it exists is simply absent.
        if !value.is_empty() {
            table.insert(key.clone(), coerce(value));
        }
    }
    // Written last so it always wins: `config create x b2 type=s3` is
    // contradictory, and the positional argument is the documented one.
    table.insert(
        constants::CONFIG_REMOTE_TYPE_KEY.to_string(),
        Value::String(remote_type.to_string()),
    );

    deserialize(table)
}

/// Apply assignments on top of an existing remote.
///
/// Keys not mentioned keep their values, and an **empty value removes a key** —
/// the only way to unset a setting without opening an editor. The result is
/// re-deserialised rather than patched in place, so removing a required setting
/// fails here instead of writing a remote that cannot be loaded again.
///
/// # Errors
/// [`ExitCode::Usage`] when the merged result is not a valid remote.
pub fn merge(existing: &RemoteDef, assignments: &BTreeMap<String, String>) -> Result<RemoteDef> {
    let Ok(Value::Table(mut table)) = Value::try_from(existing) else {
        return Err(CliError::new(
            ExitCode::FatalError,
            "the configured remote could not be read back",
        ));
    };

    for (key, value) in assignments {
        if value.is_empty() {
            table.remove(key);
        } else {
            table.insert(key.clone(), coerce(value));
        }
    }

    deserialize(table)
}

/// Turn a raw TOML table into a remote, reporting failure the way the file
/// format would.
fn deserialize(table: toml::Table) -> Result<RemoteDef> {
    let remote: RemoteDef = Value::Table(table)
        .try_into()
        .map_err(|error: toml::de::Error| {
            CliError::new(ExitCode::Usage, format!("not a usable remote: {error}")).with_hint(
                format!(
                    "Only the settings a provider defines are accepted, and '{}' is \
             required. See `dctl config show` on a working remote for the \
             vocabulary.",
                    constants::CONFIG_REMOTE_TYPE_KEY
                ),
            )
        })?;
    canonicalise(remote)
}

/// Put a remote's settings into the spelling the file should carry, and refuse
/// the ones this build cannot honour.
///
/// Two providers need something here, for two different reasons.
///
/// **sftp `base`.** Written as a bare relative path it meant `$HOME/…` here and
/// `/…` through `dctl init --base sftp:HOST/…` — one spelling, two different
/// destinations — so the one rule ([`crate::remote::sftp_base`]) is applied at
/// the moment the value is written rather than at the moment it is used. Two
/// things follow: the file always says which of the two it means, and a remote
/// that cannot say is refused *before* it exists instead of after somebody has
/// pointed a backup at it.
///
/// **vault `base_path`.** A vault occupies the root of the store it wraps, and
/// `dctl init --base local:/srv/v/sub` has always said so. This door did not:
/// it accepted the key, wrote it to the file, printed it back from
/// `dctl config show`, and addressed the root anyway — the exact shape
/// `crate::config::reach` exists to make impossible. Refused here rather than at
/// resolve time so the value never reaches the file, because a setting that
/// fails only when a transfer runs is a setting that fails at 02:00.
fn canonicalise(remote: RemoteDef) -> Result<RemoteDef> {
    match remote {
        RemoteDef::Sftp(mut def) => {
            def.base = crate::remote::sftp_base::from_setting(&def.base)?;
            Ok(RemoteDef::Sftp(def))
        }
        other => {
            refuse_unhonourable(&other)?;
            Ok(other)
        }
    }
}

/// Refuse any setting [`crate::config::reach`] says this provider cannot honour.
///
/// Table-driven rather than a match per provider, and that is the point: the one
/// refusal in the table today is a vault's `base_path`, and the next one must not
/// need a second place to be remembered. A setting whose row says `Refused` is
/// refused here, at the door that writes the file, and again by
/// [`crate::config::validate`] for a file that already carries one.
///
/// Asked of the *serialised* form so the question is (provider, key) — the same
/// pair the table is keyed on — rather than a field access that would have to be
/// written out per variant.
fn refuse_unhonourable(remote: &RemoteDef) -> Result<()> {
    let Ok(Value::Table(table)) = Value::try_from(remote) else {
        return Ok(());
    };
    for (key, value) in &table {
        // An empty value is unset, the rule every other setting follows, and the
        // way an update assigning nothing clears one an older build wrote.
        if value.as_str() == Some("") {
            continue;
        }
        if let Some(reason) = crate::config::reach::refusal(remote.type_name(), key) {
            return Err(CliError::new(
                ExitCode::Usage,
                format!(
                    "'{key}' is not a setting a {} remote can honour",
                    remote.type_name()
                ),
            )
            .with_hint(reason));
        }
    }
    Ok(())
}

/// Interpret a command-line value as the TOML scalar a user meant.
///
/// `chunk_size=4194304` must become an integer, not the string `"4194304"`, or
/// the deserialiser rejects it — and quoting rules on a command line are exactly
/// the kind of detail that turns a two-word command into a support question.
/// Integers and booleans are recognised; everything else is a string, which is
/// the right default because every other setting a provider defines is one.
///
/// A number is only taken as a number when it round-trips exactly. `007` and
/// `+5` parse as integers but do not spell themselves that way, so they are
/// identifiers a user typed deliberately — silently rewriting one into `7` would
/// change a value the file then reports back differently from how it was set.
fn coerce(value: &str) -> Value {
    if let Ok(number) = value.parse::<i64>() {
        if number.to_string() == value {
            return Value::Integer(number);
        }
    }
    if let Ok(flag) = value.parse::<bool>() {
        return Value::Boolean(flag);
    }
    Value::String(value.to_string())
}

/// Render a TOML scalar the way DCTL prints it.
///
/// Strings lose their quotes — someone reading `bucket photos` does not want
/// `bucket "photos"` — while every other type keeps the spelling that would have
/// to be typed back into the file.
///
/// Re-exported as [`scalar_text`] because `crate::config::validate` quotes a
/// refused setting's value back at the operator, and it has to be the *same*
/// spelling `dctl config show` used or they will be hunting for a line that
/// reads differently from the message.
pub fn scalar_text(value: &Value) -> String {
    scalar_to_string(value)
}

/// See [`scalar_text`].
fn scalar_to_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// Split a `key=value` argument.
///
/// Splits on the **first** separator only, so a value may itself contain `=` —
/// an endpoint carrying a query string, a base64 blob — with no quoting.
///
/// # Errors
/// [`ExitCode::Usage`] when there is no separator, or the key side is empty.
pub fn parse_assignment(argument: &str) -> Result<(String, String)> {
    let malformed = |message: String| {
        CliError::new(ExitCode::Usage, message)
            .with_hint("Settings are written 'key=value', for example 'bucket=my-photos'.")
    };

    let Some((key, value)) = argument.split_once(constants::CONFIG_ASSIGNMENT_SEPARATOR) else {
        return Err(malformed(format!("'{argument}' is not key=value")));
    };

    let key = key.trim();
    if key.is_empty() {
        return Err(malformed(format!("'{argument}' has an empty key")));
    }

    Ok((key.to_string(), value.to_string()))
}

/// Collect `key=value` arguments into a sorted map.
///
/// # Errors
/// The first malformed assignment, so the message names the argument to fix
/// rather than a count of how many were wrong.
pub fn parse_assignments(arguments: &[String]) -> Result<BTreeMap<String, String>> {
    arguments.iter().map(|a| parse_assignment(a)).collect()
}

/// The error every subcommand raises for a name that is not configured.
///
/// Built from [`ConfigError::UnknownRemote`] rather than from a fresh
/// [`CliError`], so both the wording *and the exit code* come from the
/// configuration layer. That matters more than it looks: whether "no such
/// remote" is a usage error or a configuration error is a decision scripts
/// branch on, and `dctl config show` answering it differently from `dctl ls`
/// would make the code useless. All this adds is the remediation the bare
/// variant does not carry.
#[must_use]
pub fn unknown_remote(name: &str) -> CliError {
    CliError::from(ConfigError::UnknownRemote(name.to_string()))
        .with_hint("Run `dctl config list` to see the configured remotes.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{B2Def, LocalDef, RemoteDef, VaultDef};
    use std::path::PathBuf;

    fn assignments(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn a_remote_flattens_into_the_words_the_file_uses() {
        let remote = RemoteDef::B2(B2Def {
            bucket: "photos".into(),
            endpoint: None,
            chunk_size: Some(4_194_304),
            verify: None,
            require_vault: false,
        });
        let settings = flatten(&remote);

        assert!(settings.contains(&("type".to_string(), "b2".to_string())));
        assert!(settings.contains(&("bucket".to_string(), "photos".to_string())));
        assert!(settings.contains(&("chunk_size".to_string(), "4194304".to_string())));
        // Absent optional settings stay absent: showing them would imply a
        // decision that was deliberately not made.
        assert!(!settings.iter().any(|(key, _)| key == "endpoint"));
        assert!(!settings.iter().any(|(key, _)| key == "verify"));
    }

    #[test]
    fn flattened_strings_lose_the_quotes_that_belong_to_toml() {
        let remote = RemoteDef::Local(LocalDef {
            path: PathBuf::from("/srv/data"),
            verify: None,
            require_vault: false,
        });
        let settings = flatten(&remote);
        assert!(settings.iter().all(|(_, value)| !value.contains('"')));
        assert!(settings.contains(&("path".to_string(), "/srv/data".to_string())));
    }

    #[test]
    fn flattening_is_sorted_so_output_is_stable() {
        let remote = RemoteDef::S3(crate::config::S3Def {
            bucket: "archive".into(),
            endpoint: Some("https://s3.example.com".into()),
            region: Some("eu-central-1".into()),
            chunk_size: None,
            verify: None,
            require_vault: false,
        });
        let keys: Vec<String> = flatten(&remote).into_iter().map(|(key, _)| key).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn a_remote_is_built_from_a_type_and_assignments() {
        let remote = build("b2", &assignments(&[("bucket", "photos")])).unwrap();
        assert_eq!(remote.type_name(), "b2");
        assert!(matches!(remote, RemoteDef::B2(def) if def.bucket == "photos"));
    }

    #[test]
    fn numeric_settings_are_not_written_as_strings() {
        // The failure this prevents: `chunk_size=4194304` rejected because the
        // shell handed it over as text.
        let remote = build(
            "b2",
            &assignments(&[("bucket", "photos"), ("chunk_size", "4194304")]),
        )
        .unwrap();
        assert_eq!(remote.chunk_size(), Some(4_194_304));
    }

    #[test]
    fn the_positional_type_wins_over_a_type_assignment() {
        // `config create x b2 type=s3` is contradictory; the documented
        // argument decides.
        let remote = build("b2", &assignments(&[("bucket", "photos"), ("type", "s3")])).unwrap();
        assert_eq!(remote.type_name(), "b2");
    }

    #[test]
    fn a_missing_required_setting_is_refused() {
        // A b2 remote with no bucket cannot be used, so it must not be written.
        let error = build("b2", &BTreeMap::new()).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some());
    }

    #[test]
    fn a_setting_the_provider_does_not_define_is_refused() {
        // `deny_unknown_fields` is what keeps a credential out of the file, and
        // it has to bite on the command line too or the command line becomes the
        // way around it.
        let error = build(
            "b2",
            &assignments(&[("bucket", "photos"), ("app_key", "K001secret")]),
        )
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("app_key"), "{}", error.message());
    }

    #[test]
    fn merging_keeps_the_settings_that_were_not_mentioned() {
        let remote = RemoteDef::S3(crate::config::S3Def {
            bucket: "archive".into(),
            endpoint: Some("https://s3.example.com".into()),
            region: Some("eu-central-1".into()),
            chunk_size: None,
            verify: None,
            require_vault: false,
        });
        let merged = merge(&remote, &assignments(&[("bucket", "cold")])).unwrap();
        let settings = flatten(&merged);
        assert!(settings.contains(&("bucket".to_string(), "cold".to_string())));
        assert!(settings.contains(&("region".to_string(), "eu-central-1".to_string())));
    }

    #[test]
    fn an_empty_value_removes_an_optional_setting() {
        let remote = RemoteDef::S3(crate::config::S3Def {
            bucket: "archive".into(),
            endpoint: None,
            region: Some("eu-central-1".into()),
            chunk_size: None,
            verify: None,
            require_vault: false,
        });
        let merged = merge(&remote, &assignments(&[("region", "")])).unwrap();
        assert!(!flatten(&merged).iter().any(|(key, _)| key == "region"));
    }

    #[test]
    fn removing_a_required_setting_fails_instead_of_writing_a_broken_remote() {
        // The whole reason `merge` re-deserialises rather than patching: a b2
        // remote with no bucket would be written and then never load again.
        let remote = RemoteDef::B2(B2Def {
            bucket: "photos".into(),
            endpoint: None,
            chunk_size: None,
            verify: None,
            require_vault: false,
        });
        let error = merge(&remote, &assignments(&[("bucket", "")])).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[test]
    fn a_vault_remote_can_be_built_even_though_it_is_not_a_provider() {
        // `vault` stores no bytes, so `config providers` does not offer it — but
        // it is a legal section type and must be creatable.
        let remote = build("vault", &assignments(&[("base", "b2prod")])).unwrap();
        assert!(remote.is_vault());
        assert_eq!(remote.base(), Some("b2prod"));
        assert!(
            !constants::REMOTE_PROVIDER_TYPES
                .iter()
                .any(|(name, _)| *name == constants::PROVIDER_VAULT)
        );
    }

    #[test]
    fn every_advertised_provider_is_a_type_create_accepts() {
        for (name, _) in constants::REMOTE_PROVIDER_TYPES {
            assert!(validate_type(name).is_ok(), "'{name}' was rejected");
        }
        assert!(validate_type(constants::PROVIDER_VAULT).is_ok());
    }

    #[test]
    fn an_unknown_type_names_what_would_have_worked() {
        let error = validate_type("dropbux").unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        let hint = error.hint().unwrap_or_default();
        assert!(hint.contains(constants::PROVIDER_B2), "got hint: {hint}");
        // Types are lower-case; the upper-case spelling is a real mistake.
        assert!(validate_type("B2").is_err());
        assert!(validate_type("").is_err());
    }

    #[test]
    fn assignments_split_on_the_first_separator_only() {
        assert_eq!(
            parse_assignment("bucket=my-photos").unwrap(),
            ("bucket".to_string(), "my-photos".to_string())
        );
        // The case that forces the rule: a value containing '='.
        assert_eq!(
            parse_assignment("endpoint=https://x.example.com/?a=b").unwrap(),
            (
                "endpoint".to_string(),
                "https://x.example.com/?a=b".to_string()
            )
        );
        // An empty value is meaningful — it unsets a key.
        assert_eq!(
            parse_assignment("region=").unwrap(),
            ("region".to_string(), String::new())
        );
    }

    #[test]
    fn malformed_assignments_name_the_argument_at_fault() {
        for argument in ["bucket", "=orphan", " =x"] {
            let error = parse_assignment(argument).unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage);
            assert!(
                error.message().contains(argument),
                "got: {}",
                error.message()
            );
            assert!(error.hint().is_some());
        }
    }

    #[test]
    fn assignments_collect_into_a_sorted_map_and_stop_at_the_first_bad_one() {
        let parsed =
            parse_assignments(&["type=b2".to_string(), "bucket=photos".to_string()]).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.get("type").map(String::as_str), Some("b2"));
        assert!(parse_assignments(&["broken".to_string()]).is_err());
    }

    #[test]
    fn values_are_coerced_to_the_type_the_file_expects() {
        assert_eq!(coerce("4194304"), Value::Integer(4_194_304));
        assert_eq!(coerce("true"), Value::Boolean(true));
        assert_eq!(coerce("photos"), Value::String("photos".into()));
        // A bucket that happens to look like a word must stay a string.
        assert_eq!(coerce("us-west-2"), Value::String("us-west-2".into()));
        // Leading zeros are an identifier, not a number: rewriting `007` into
        // `7` would report a value back differently from how it was set.
        assert_eq!(coerce("007"), Value::String("007".into()));
        assert_eq!(coerce("+5"), Value::String("+5".into()));
        assert_eq!(coerce("-1"), Value::Integer(-1));
    }

    #[test]
    fn the_unknown_remote_error_defers_to_the_configuration_layer() {
        // The classification is not this module's to invent: a script that
        // branches on "no such remote" must see the same code whichever command
        // reported it.
        let error = unknown_remote("nope");
        assert_eq!(
            error.code(),
            ConfigError::UnknownRemote("nope".to_string()).exit_code()
        );
        assert!(error.message().contains("nope"));
        // What this adds on top: somewhere to go next.
        assert!(error.hint().unwrap_or_default().contains("config list"));
    }

    #[test]
    fn an_sftp_remote_round_trips_through_the_flat_vocabulary() {
        // The `dctl config create NAME sftp host=… base=…` path: host and base are
        // the two required settings, and both must survive flatten → build
        // unchanged, with require_vault riding along so a store declares itself.
        let remote = RemoteDef::Sftp(crate::config::SftpDef {
            host: "backup.example.com".into(),
            base: "~/dctl-store".into(),
            chunk_size: None,
            verify: None,
            require_vault: true,
        });
        let settings = flatten(&remote);
        assert!(settings.contains(&("type".to_string(), "sftp".to_string())));
        assert!(settings.contains(&("host".to_string(), "backup.example.com".to_string())));
        assert!(settings.contains(&("base".to_string(), "~/dctl-store".to_string())));

        let rebuilt = build(
            constants::PROVIDER_SFTP,
            &settings
                .into_iter()
                .filter(|(key, _)| key != constants::CONFIG_REMOTE_TYPE_KEY)
                .collect(),
        )
        .unwrap();
        assert_eq!(rebuilt, remote);
    }

    #[test]
    fn an_sftp_remote_rejects_a_setting_it_does_not_define() {
        // `deny_unknown_fields` has to bite on the command line too: a bucket is
        // not an sftp setting, and accepting it would silently write a remote the
        // loader then refuses.
        let error = build(
            constants::PROVIDER_SFTP,
            &assignments(&[
                ("host", "backup.example.com"),
                ("base", "store"),
                ("bucket", "nope"),
            ]),
        )
        .unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("bucket"), "{}", error.message());
    }

    #[test]
    fn a_vault_chain_setting_round_trips_through_the_flat_vocabulary() {
        // `base_path` is deliberately absent. It used to be in this fixture, and
        // the fixture passing was the whole problem: the round trip was faithful
        // and the value reached nothing, which is exactly what `config::reach`
        // now forbids. The settings that remain are the ones a vault honours.
        let remote = RemoteDef::Vault(VaultDef {
            base: "b2prod".into(),
            base_path: None,
            chunk_size: Some(4 * 1024 * 1024),
            verify: Some(crate::cli::VerifyMode::Strict),
        });
        let settings = flatten(&remote);
        let rebuilt = build(
            constants::PROVIDER_VAULT,
            &settings
                .into_iter()
                .filter(|(key, _)| key != constants::CONFIG_REMOTE_TYPE_KEY)
                .collect(),
        )
        .unwrap();
        assert_eq!(rebuilt, remote);
    }

    #[test]
    fn a_vault_subdirectory_is_refused_at_the_door_that_used_to_accept_it() {
        // The documented rule has always been that a vault occupies the root of
        // the store it wraps, and `dctl init --base local:/srv/v/sub` has always
        // said so out loud. This door did not: it took the key, wrote it to the
        // file, showed it back through `dctl config show`, and addressed the
        // root — a setting the operator could see, could not remove by observing
        // anything, and that moved no data.
        let error = build(
            constants::PROVIDER_VAULT,
            &assignments(&[("base", "b2prod"), ("base_path", "vaults/a")]),
        )
        .expect_err("a subdirectory must be refused rather than ignored");
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(
            error.message().contains(constants::CONFIG_KEY_BASE_PATH),
            "the refusal must name the setting: {}",
            error.message()
        );
        // And say what to do instead, which is the whole difference between a
        // refusal and a wall.
        let hint = error.hint().unwrap_or_default();
        assert!(hint.contains("own container"), "{hint}");

        // The same remote without it is still perfectly creatable, or the
        // refusal is refusing vaults rather than subdirectories.
        assert!(
            build(
                constants::PROVIDER_VAULT,
                &assignments(&[("base", "b2prod")])
            )
            .is_ok()
        );

        // An *empty* value is unset, not a subdirectory — the same rule every
        // other setting follows, and the way `dctl config update v base_path=`
        // clears one written by an older build.
        assert!(
            build(
                constants::PROVIDER_VAULT,
                &assignments(&[("base", "b2prod"), ("base_path", "")])
            )
            .is_ok()
        );
    }
}
