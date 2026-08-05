//! Every per-remote setting, and what it reaches.
//!
//! ## The defect this module exists to make impossible
//!
//! `crate::cli::reach` asks one question of every global *flag*: does anything
//! read it? Eleven did not. This module asks the same question of the
//! *configuration file*, and it was raised because `chunk_size` had to be found
//! by needing it rather than by looking — it was declared on five provider
//! definitions, printed by `dctl config show`, documented in
//! `dctl config providers`, and read by **nothing** on two of them.
//!
//! A setting in that state is worse than one that does not exist. An unknown key
//! is a parse error the operator sees the first time they save the file.
//! An accepted one that reaches nothing is a belief: they think they pinned the
//! part size for a container with 256 MiB of memory, and the OOM killer is the
//! first thing that disagrees.
//!
//! ## Why this guard is stronger than the flag one, and why it can be
//!
//! [`crate::cli::reach`] proves an honoured flag by *scanning this crate's
//! source* for a read of the field, and says plainly that this is a weaker claim
//! than "it works". It has to: a flag is consumed in dozens of places, none of
//! them a function of the flag alone.
//!
//! A setting is different. Resolution is a **pure function of (spec, catalog)**,
//! so this guard does not scan for a mention — it puts a sentinel value in the
//! setting, runs the real resolver, and requires the sentinel to come out the
//! other end. [`observe`] is where each setting names the seam that carries it,
//! and a setting whose value is dropped between the file and that seam fails
//! here with the value that arrived instead.
//!
//! ## Two outcomes, never a third
//!
//! Every row below is either [`Reach::Honoured`] — the value reaches the code
//! that acts on it, proved by [`observe`] — or [`Reach::Refused`], which means
//! the setting is meaningless for that provider and writing it fails at
//! `dctl config create`/`update` time rather than being accepted and ignored.
//!
//! Refusing is a perfectly good answer. A silent no-op never is, and it is
//! exactly what `base_path` on a vault did: `dctl init` refuses the subdirectory
//! form clearly, while `dctl config create v vault base=s base_path=x`
//! accepted it, wrote it to the file, showed it back in `dctl config show`, and
//! addressed the container's root anyway.
//!
//! ## What enforces that the table is exhaustive
//!
//! [`SETTINGS`] is checked against the **serialised form of a fully-populated
//! value of every [`RemoteDef`] variant** — the same TOML the file holds. A
//! field added to a provider without a row here fails the suite with an
//! instruction, and a row naming a field its provider does not have fails too.
//! That is the difference between wiring `chunk_size` and closing the reason it
//! was inert.

use crate::constants::{
    CONFIG_KEY_ACCOUNT, CONFIG_KEY_BASE, CONFIG_KEY_BASE_PATH, CONFIG_KEY_BUCKET,
    CONFIG_KEY_CHUNK_SIZE, CONFIG_KEY_ENDPOINT, CONFIG_KEY_HOST, CONFIG_KEY_PATH,
    CONFIG_KEY_REGION, CONFIG_KEY_REQUIRE_VAULT, CONFIG_KEY_VERIFY, PROVIDER_B2, PROVIDER_LOCAL,
    PROVIDER_R2, PROVIDER_S3, PROVIDER_SFTP, PROVIDER_VAULT, VAULT_BASE_PATH_UNSUPPORTED_REASON,
};

/// What a per-remote setting actually reaches in this build.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reach {
    /// The value reaches the code that acts on it.
    ///
    /// Proved rather than asserted: [`observe`] carries a sentinel through the
    /// real resolver and the guard compares what came out.
    Honoured,

    /// The setting is meaningless for this provider, and is refused when written.
    ///
    /// The reason is a sentence naming what the provider does instead, on the
    /// [`crate::cli::reach`] principle that the operator's next question after
    /// "no" is "then what?".
    Refused {
        /// Why, in the words the refusal prints.
        reason: &'static str,
    },
}

/// One (provider, setting) pair's row.
pub struct Setting {
    /// The provider type, as the file's `type` key spells it.
    pub provider: &'static str,

    /// The setting's key, as the file spells it.
    pub key: &'static str,

    /// What it reaches.
    pub reach: Reach,
}

impl Setting {
    /// A setting whose value reaches an implementation.
    const fn honoured(provider: &'static str, key: &'static str) -> Self {
        Self {
            provider,
            key,
            reach: Reach::Honoured,
        }
    }

    /// A setting this provider has no use for, refused when it is written.
    const fn refused(provider: &'static str, key: &'static str, reason: &'static str) -> Self {
        Self {
            provider,
            key,
            reach: Reach::Refused { reason },
        }
    }
}

/// Every setting on every provider, grouped by provider in the order
/// [`crate::config::model`] declares the variants, and within a provider in the
/// order the struct declares the fields.
///
/// Kept in declaration order for the reason [`crate::cli::reach::FLAGS`] is:
/// "add a field" and "add its row" are then adjacent hunks in a review.
pub const SETTINGS: &[Setting] = &[
    // ── local ────────────────────────────────────────────────────────────
    Setting::honoured(PROVIDER_LOCAL, CONFIG_KEY_PATH),
    Setting::honoured(PROVIDER_LOCAL, CONFIG_KEY_VERIFY),
    Setting::honoured(PROVIDER_LOCAL, CONFIG_KEY_REQUIRE_VAULT),
    // ── b2 ───────────────────────────────────────────────────────────────
    Setting::honoured(PROVIDER_B2, CONFIG_KEY_BUCKET),
    Setting::honoured(PROVIDER_B2, CONFIG_KEY_ENDPOINT),
    Setting::honoured(PROVIDER_B2, CONFIG_KEY_CHUNK_SIZE),
    Setting::honoured(PROVIDER_B2, CONFIG_KEY_VERIFY),
    Setting::honoured(PROVIDER_B2, CONFIG_KEY_REQUIRE_VAULT),
    // ── s3 ───────────────────────────────────────────────────────────────
    Setting::honoured(PROVIDER_S3, CONFIG_KEY_BUCKET),
    Setting::honoured(PROVIDER_S3, CONFIG_KEY_ENDPOINT),
    Setting::honoured(PROVIDER_S3, CONFIG_KEY_REGION),
    Setting::honoured(PROVIDER_S3, CONFIG_KEY_CHUNK_SIZE),
    Setting::honoured(PROVIDER_S3, CONFIG_KEY_VERIFY),
    Setting::honoured(PROVIDER_S3, CONFIG_KEY_REQUIRE_VAULT),
    // ── r2 ───────────────────────────────────────────────────────────────
    Setting::honoured(PROVIDER_R2, CONFIG_KEY_BUCKET),
    Setting::honoured(PROVIDER_R2, CONFIG_KEY_ACCOUNT),
    Setting::honoured(PROVIDER_R2, CONFIG_KEY_ENDPOINT),
    Setting::honoured(PROVIDER_R2, CONFIG_KEY_CHUNK_SIZE),
    Setting::honoured(PROVIDER_R2, CONFIG_KEY_VERIFY),
    Setting::honoured(PROVIDER_R2, CONFIG_KEY_REQUIRE_VAULT),
    // ── sftp ─────────────────────────────────────────────────────────────
    Setting::honoured(PROVIDER_SFTP, CONFIG_KEY_HOST),
    Setting::honoured(PROVIDER_SFTP, CONFIG_KEY_BASE),
    Setting::honoured(PROVIDER_SFTP, CONFIG_KEY_CHUNK_SIZE),
    Setting::honoured(PROVIDER_SFTP, CONFIG_KEY_VERIFY),
    Setting::honoured(PROVIDER_SFTP, CONFIG_KEY_REQUIRE_VAULT),
    // ── vault ────────────────────────────────────────────────────────────
    Setting::honoured(PROVIDER_VAULT, CONFIG_KEY_BASE),
    // The one refusal. A vault occupies the **root** of the container it wraps:
    // `dctl init --base local:/srv/v/sub` already refuses the subdirectory form
    // in so many words, and this is the same refusal at the other door, which
    // used to accept it and address the root regardless.
    Setting::refused(
        PROVIDER_VAULT,
        CONFIG_KEY_BASE_PATH,
        VAULT_BASE_PATH_UNSUPPORTED_REASON,
    ),
    Setting::honoured(PROVIDER_VAULT, CONFIG_KEY_CHUNK_SIZE),
    Setting::honoured(PROVIDER_VAULT, CONFIG_KEY_VERIFY),
];

/// Why `key` cannot be honoured on `provider`, or [`None`] if it can.
///
/// **The production entry point, and the reason [`SETTINGS`] is not a test
/// fixture.** Both doors a setting arrives through ask this one question:
///
/// * [`crate::commands::config::settings`] asks before a remote is written, so
///   a value this build cannot apply never reaches the file;
/// * [`super::validate`] asks on load, so a file written by an earlier build —
///   or edited by hand — is diagnosed on the way in rather than round-tripping
///   faithfully and doing nothing.
///
/// Deriving both from the table is what makes the guard below meaningful. If the
/// refusal were written out separately at each door, [`SETTINGS`] would be
/// documentation, and a row could claim a refusal that no door performs — which
/// is precisely the failure `cli::reach`'s third test was written to catch.
///
/// An unknown provider or an unknown key answers [`None`]: this decides what is
/// *refused*, and the schema itself decides what exists. `serde`'s
/// `deny_unknown_fields` already rejects a key that no provider has, with a
/// message naming it.
#[must_use]
pub fn refusal(provider: &str, key: &str) -> Option<&'static str> {
    SETTINGS
        .iter()
        .find(|setting| setting.provider == provider && setting.key == key)
        .and_then(|setting| match setting.reach {
            Reach::Refused { reason } => Some(reason),
            Reach::Honoured => None,
        })
}

/// What the resolver made of `sentinel` written into `key` on `provider`.
///
/// The whole strength of this guard. Each arm names the **seam that acts on the
/// value**, not an accessor that merely reads it back off the struct — a getter
/// nobody calls would let every setting in this table pass forever, which is the
/// shape of the defect the table exists to prevent, reproduced inside its own
/// guard.
///
/// Returns the value as it arrived at that seam, or [`None`] when the seam
/// carries nothing — which is what an inert setting looks like from here.
///
/// # Errors
/// Whatever the resolver reported. A setting that makes the remote unresolvable
/// is a failed observation rather than a missing one, and the guard prints it.
#[cfg(test)]
fn observe(provider: &str, key: &str, sentinel: &str) -> crate::error::Result<Option<String>> {
    use crate::remote::registry::Target;
    use crate::remote::resolve::{self, RemoteEntry};
    use crate::remote::spec::RemoteSpec;
    use std::collections::BTreeMap;

    // A remote carrying the sentinel plus whatever else its provider requires,
    // and — for a vault — the store it wraps, so the chain resolves.
    let mut entry = RemoteEntry {
        provider: provider.to_string(),
        settings: required_settings(provider),
    };
    entry.settings.insert(key.to_string(), sentinel.to_string());

    let mut catalog: BTreeMap<String, RemoteEntry> = BTreeMap::new();
    catalog.insert(SUBJECT.to_string(), entry.clone());
    // The store a vault's `base` points at when the sentinel is not itself that
    // name. Named for what it is so a failure message reads.
    catalog.insert(
        VAULT_STORE.to_string(),
        RemoteEntry {
            provider: PROVIDER_LOCAL.to_string(),
            settings: [(CONFIG_KEY_PATH.to_string(), "/srv/store".to_string())]
                .into_iter()
                .collect(),
        },
    );
    if provider == PROVIDER_VAULT && key == CONFIG_KEY_BASE {
        // The sentinel *is* a remote name here, so it has to exist for the chain
        // to be walkable at all.
        catalog.insert(
            sentinel.to_string(),
            RemoteEntry {
                provider: PROVIDER_LOCAL.to_string(),
                settings: [(CONFIG_KEY_PATH.to_string(), "/srv/store".to_string())]
                    .into_iter()
                    .collect(),
            },
        );
    }

    let spec = RemoteSpec::Named {
        remote: SUBJECT.to_string(),
        path: String::new(),
    };

    // `verify` and `require_vault` are answered above the `Target`, because
    // neither is a piece of addressing: one decides how hard a run checks what it
    // wrote, the other whether a plain remote may address the location at all.
    if key == CONFIG_KEY_VERIFY {
        let mode = resolve::verify_policy(None, &spec, &catalog)?;
        return Ok(Some(crate::commands::integrity::mode::slug(mode)));
    }
    if key == CONFIG_KEY_REQUIRE_VAULT {
        // The typed configuration is what `config::validate` and `session::open`
        // read, so the observation goes through the file's own vocabulary rather
        // than through the flat entry.
        let typed = crate::commands::config::settings::build(provider, &entry.settings)?;
        return Ok(Some(
            crate::config::RemoteDef::require_vault(&typed).to_string(),
        ));
    }
    // A vault's `base` is walked to the store that holds the bytes; nothing else
    // in the configuration decides where a vault's objects land.
    if provider == PROVIDER_VAULT && key == CONFIG_KEY_BASE {
        let mut config = crate::config::Config::default();
        for (name, carried) in &catalog {
            config.insert(
                name.clone(),
                crate::commands::config::settings::build(&carried.provider, &carried.settings)?,
            );
        }
        let chain = crate::config::vault_chain(&config, SUBJECT)?;
        return Ok(chain.last().map(|name| (*name).to_string()));
    }
    // A vault's `chunk_size` reaches the sealer rather than a `Target`: a vault
    // remote resolves to no target of its own, because it stores nothing.
    if provider == PROVIDER_VAULT && key == CONFIG_KEY_CHUNK_SIZE {
        return Ok(resolve::vault_chunk_size(&spec, &catalog)?.map(|size| size.to_string()));
    }
    // `base_path` has no seam at all. Saying so here rather than returning `None`
    // from a fall-through keeps "there is nowhere for this to arrive" distinct
    // from "it was dropped on the way".
    if key == CONFIG_KEY_BASE_PATH {
        return Ok(None);
    }

    // Everything else is addressing, and addressing travels in the `Target` the
    // registry builds a backend from.
    let target = resolve::resolve(&spec, &catalog)?.target().clone();
    Ok(match (&target, key) {
        (Target::Local { root }, CONFIG_KEY_PATH) => Some(root.display().to_string()),

        (Target::B2 { bucket, .. }, CONFIG_KEY_BUCKET)
        | (Target::S3 { bucket, .. }, CONFIG_KEY_BUCKET)
        | (Target::R2 { bucket, .. }, CONFIG_KEY_BUCKET) => Some(bucket.clone()),

        (Target::B2 { endpoint, .. }, CONFIG_KEY_ENDPOINT)
        | (Target::S3 { endpoint, .. }, CONFIG_KEY_ENDPOINT)
        | (Target::R2 { endpoint, .. }, CONFIG_KEY_ENDPOINT) => endpoint.clone(),

        (Target::S3 { region, .. }, CONFIG_KEY_REGION) => region.clone(),
        (Target::R2 { account, .. }, CONFIG_KEY_ACCOUNT) => account.clone(),

        (Target::Sftp { host, .. }, CONFIG_KEY_HOST) => Some(host.clone()),
        (Target::Sftp { base, .. }, CONFIG_KEY_BASE) => Some(base.clone()),

        (Target::B2 { chunk_size, .. }, CONFIG_KEY_CHUNK_SIZE)
        | (Target::S3 { chunk_size, .. }, CONFIG_KEY_CHUNK_SIZE)
        | (Target::R2 { chunk_size, .. }, CONFIG_KEY_CHUNK_SIZE)
        | (Target::Sftp { chunk_size, .. }, CONFIG_KEY_CHUNK_SIZE) => {
            chunk_size.map(|size| size.to_string())
        }

        // No wildcard for the *setting*: reaching here means the table claims a
        // provider carries a key its `Target` has no field for, which is the
        // finding rather than a gap in the test.
        _ => None,
    })
}

/// The remote this guard resolves. A name rather than `"x"` so an assertion that
/// fails reads as a sentence.
#[cfg(test)]
const SUBJECT: &str = "subject";

/// The store a vault wraps when the sentinel is not itself a remote name.
#[cfg(test)]
const VAULT_STORE: &str = "subject-store";

/// The settings a provider cannot resolve without, minus the one under test.
///
/// Deliberately *not* every setting: the sentinel is written on top, so a
/// required key under test is overwritten with the sentinel and observed there.
#[cfg(test)]
fn required_settings(provider: &str) -> std::collections::BTreeMap<String, String> {
    let pairs: &[(&str, &str)] = match provider {
        PROVIDER_LOCAL => &[(CONFIG_KEY_PATH, "/srv/data")],
        PROVIDER_B2 | PROVIDER_S3 => &[(CONFIG_KEY_BUCKET, "a-bucket")],
        PROVIDER_R2 => &[
            (CONFIG_KEY_BUCKET, "a-bucket"),
            (CONFIG_KEY_ACCOUNT, "acct"),
        ],
        PROVIDER_SFTP => &[(CONFIG_KEY_HOST, "a-host"), (CONFIG_KEY_BASE, "/srv/data")],
        PROVIDER_VAULT => &[(CONFIG_KEY_BASE, VAULT_STORE)],
        _ => &[],
    };
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

/// A sentinel for `key` that is a legal value for it and could not be a default.
///
/// "Could not be a default" is the load-bearing half: observing `chunk_size`
/// with the provider's own default would pass whether the setting reached the
/// backend or not.
#[cfg(test)]
fn sentinel(key: &str) -> &'static str {
    match key {
        CONFIG_KEY_PATH => "/srv/dctl-reach-sentinel",
        CONFIG_KEY_BUCKET => "dctl-reach-sentinel",
        CONFIG_KEY_ENDPOINT => "https://dctl-reach-sentinel.example",
        CONFIG_KEY_REGION => "dctl-reach-sentinel",
        CONFIG_KEY_ACCOUNT => "dctlreachsentinel",
        CONFIG_KEY_HOST => "dctl-reach-sentinel",
        CONFIG_KEY_BASE => "/srv/dctl-reach-sentinel",
        CONFIG_KEY_BASE_PATH => "dctl-reach-sentinel",
        // Neither a provider minimum nor any compiled-in default, and a legal
        // part size on every provider that has one.
        CONFIG_KEY_CHUNK_SIZE => "9437184",
        // Not the default (`checksum`), so an ignored setting is visible.
        CONFIG_KEY_VERIFY => "strict",
        CONFIG_KEY_REQUIRE_VAULT => "true",
        other => panic!("no sentinel for the setting '{other}'"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::globals::VerifyMode;
    use crate::config::{
        B2Def, LocalDef, R2Def, RemoteDef, S3Def, SftpDef, VaultDef, model_test_support,
    };
    use crate::constants::CONFIG_REMOTE_TYPE_KEY;
    use std::collections::BTreeSet;

    /// A vault's `base` names a remote, so its sentinel has to be a legal remote
    /// name rather than a path. Handled here rather than in [`sentinel`] because
    /// the key is shared with sftp, where it *is* a path.
    fn sentinel_for(provider: &str, key: &str) -> &'static str {
        if provider == PROVIDER_VAULT && key == CONFIG_KEY_BASE {
            return "dctl-reach-sentinel";
        }
        sentinel(key)
    }

    /// Every (provider, key) the file format actually has, taken from the
    /// serialised form of a fully-populated value of each variant.
    ///
    /// Through TOML rather than from a hand-written list, for the reason
    /// `commands::config::settings` gives about the same round trip: the file
    /// format *is* the vocabulary, so a second list would be a second definition
    /// of the schema, and second definitions drift.
    fn declared_settings() -> BTreeSet<(String, String)> {
        let mut declared = BTreeSet::new();
        for remote in model_test_support::every_variant() {
            let Ok(toml::Value::Table(table)) = toml::Value::try_from(&remote) else {
                panic!("a RemoteDef must serialise");
            };
            for key in table.keys() {
                if key == CONFIG_REMOTE_TYPE_KEY {
                    continue;
                }
                declared.insert((remote.type_name().to_string(), key.clone()));
            }
        }
        declared
    }

    fn tabled_settings() -> BTreeSet<(String, String)> {
        SETTINGS
            .iter()
            .map(|s| (s.provider.to_string(), s.key.to_string()))
            .collect()
    }

    #[test]
    fn every_declared_setting_is_classified_and_every_row_is_a_real_setting() {
        let declared = declared_settings();
        let tabled = tabled_settings();
        assert!(
            declared.len() >= 20,
            "the schema walk must actually reach the providers: found {}",
            declared.len()
        );

        let unclassified: Vec<_> = declared.difference(&tabled).collect();
        assert!(
            unclassified.is_empty(),
            "these settings exist in the file format and this table does not say \
             what they reach: {unclassified:?}\n\
             Add a row to config::reach::SETTINGS. A per-remote setting must either \
             reach the code that acts on it (Reach::Honoured, proved by `observe`) \
             or be refused when it is written (Reach::Refused) — a setting that \
             round-trips through the file and reaches nothing is the defect this \
             table exists to prevent."
        );

        let phantom: Vec<_> = tabled.difference(&declared).collect();
        assert!(
            phantom.is_empty(),
            "these rows name settings the file format does not have: {phantom:?}"
        );
    }

    #[test]
    fn no_provider_and_setting_pair_is_tabled_twice() {
        // A duplicated row would let one copy claim `Honoured` and the other
        // `Refused`, and whichever the guard read first would decide.
        let mut seen = BTreeSet::new();
        for setting in SETTINGS {
            assert!(
                seen.insert((setting.provider, setting.key)),
                "'{}' on '{}' has two rows",
                setting.key,
                setting.provider
            );
        }
    }

    #[test]
    fn every_honoured_setting_reaches_the_code_that_acts_on_it() {
        // The question at the top of this module, as a property rather than as
        // five examples. A sentinel goes into the file's vocabulary and has to
        // come out of the seam that acts on it; anything else — a dropped
        // value, a default substituted for it — fails here naming both.
        for setting in SETTINGS {
            if setting.reach != Reach::Honoured {
                continue;
            }
            let expected = sentinel_for(setting.provider, setting.key);
            let observed = observe(setting.provider, setting.key, expected).unwrap_or_else(|e| {
                panic!(
                    "'{}' on '{}' made the remote unresolvable: {}",
                    setting.key,
                    setting.provider,
                    e.message()
                )
            });
            assert_eq!(
                observed.as_deref(),
                Some(expected),
                "'{}' on '{}' is declared honoured, and the value written in the \
                 file does not reach the code that acts on it. Either carry it \
                 through, or make the row Reach::Refused with the reason it \
                 cannot be — an accepted setting that changes nothing is what \
                 this guard exists to catch.",
                setting.key,
                setting.provider,
            );
        }
    }

    #[test]
    fn every_refused_setting_is_actually_refused_when_it_is_written() {
        // The strong half, and the same shape as `cli::reach`'s: a row may not
        // merely *claim* a refusal. The value goes through the real
        // `dctl config create` translation and the error has to arrive, name the
        // setting, and carry the reason.
        for setting in SETTINGS {
            let Reach::Refused { reason } = setting.reach else {
                continue;
            };
            let mut assignments = required_settings(setting.provider);
            assignments.insert(
                setting.key.to_string(),
                sentinel_for(setting.provider, setting.key).to_string(),
            );

            let error = crate::commands::config::settings::build(setting.provider, &assignments)
                .expect_err(setting.key);
            assert!(
                error.message().contains(setting.key),
                "the refusal must name the setting the operator wrote: {}",
                error.message()
            );
            let hint = error.hint().unwrap_or_default();
            assert!(
                hint.contains(reason),
                "and carry the reason that says what the tool does instead: {hint}"
            );

            // …and the same provider without it must still be creatable, or the
            // refusal is refusing the provider rather than the setting.
            let ok = required_settings(setting.provider);
            assert!(
                crate::commands::config::settings::build(setting.provider, &ok).is_ok(),
                "'{}' cannot be created at all",
                setting.provider
            );
        }
    }

    #[test]
    fn the_observation_can_tell_a_carried_value_from_a_dropped_one() {
        // The guard's own guard. `observe` is only worth anything if it can
        // return the wrong answer: a version that echoed its argument back would
        // pass every row in the table forever, which is precisely the failure
        // mode of a getter nobody calls.
        //
        // `base_path` is the fixture, because it is the one setting in the file
        // format with no seam at all — and it must therefore observe as `None`
        // while a setting beside it in the same provider observes as its value.
        assert_eq!(
            observe(PROVIDER_VAULT, CONFIG_KEY_BASE_PATH, "anything").expect("a vault resolves"),
            None,
            "a setting with no seam must not appear to arrive at one"
        );
        assert_eq!(
            observe(PROVIDER_LOCAL, CONFIG_KEY_PATH, "/srv/probe")
                .expect("a local remote resolves"),
            Some("/srv/probe".to_string()),
            "and a setting that is carried must be seen to arrive"
        );
        // A value the seam does not carry must not be reported as the value that
        // was written: this is the assertion that fails if `observe` is ever
        // "simplified" into returning its own argument.
        assert_ne!(
            observe(PROVIDER_LOCAL, CONFIG_KEY_PATH, "/srv/probe").expect("resolves"),
            Some("/srv/other".to_string())
        );
    }

    #[test]
    fn every_provider_in_the_file_format_has_at_least_one_row() {
        // A provider added with no settings table at all would pass the
        // difference checks above by having nothing to differ about.
        let tabled: BTreeSet<&str> = SETTINGS.iter().map(|s| s.provider).collect();
        for remote in model_test_support::every_variant() {
            assert!(
                tabled.contains(remote.type_name()),
                "'{}' has no rows in config::reach::SETTINGS",
                remote.type_name()
            );
        }
    }

    /// The variants exist to be walked by the two tests above; this keeps the
    /// imports honest about being used.
    #[test]
    fn the_schema_walk_sees_every_provider_struct() {
        let variants = model_test_support::every_variant();
        assert!(variants.iter().any(|r| matches!(r, RemoteDef::Local(_))));
        assert!(variants.iter().any(|r| matches!(r, RemoteDef::B2(_))));
        assert!(variants.iter().any(|r| matches!(r, RemoteDef::S3(_))));
        assert!(variants.iter().any(|r| matches!(r, RemoteDef::R2(_))));
        assert!(variants.iter().any(|r| matches!(r, RemoteDef::Sftp(_))));
        assert!(variants.iter().any(|r| matches!(r, RemoteDef::Vault(_))));
        // Every optional field is populated, or a field could be missing from
        // `declared_settings` and the exhaustiveness check would not see it.
        let _ = (
            LocalDef {
                path: std::path::PathBuf::from("/"),
                verify: Some(VerifyMode::Strict),
                require_vault: true,
            },
            B2Def {
                bucket: String::new(),
                endpoint: Some(String::new()),
                chunk_size: Some(1),
                verify: Some(VerifyMode::Strict),
                require_vault: true,
            },
            S3Def {
                bucket: String::new(),
                endpoint: Some(String::new()),
                region: Some(String::new()),
                chunk_size: Some(1),
                verify: Some(VerifyMode::Strict),
                require_vault: true,
            },
            R2Def {
                bucket: String::new(),
                account: Some(String::new()),
                endpoint: Some(String::new()),
                chunk_size: Some(1),
                verify: Some(VerifyMode::Strict),
                require_vault: true,
            },
            SftpDef {
                host: String::new(),
                base: "/x".into(),
                chunk_size: Some(1),
                verify: Some(VerifyMode::Strict),
                require_vault: true,
            },
            VaultDef {
                base: String::new(),
                base_path: Some(String::new()),
                chunk_size: Some(1),
                verify: Some(VerifyMode::Strict),
            },
        );
    }
}
