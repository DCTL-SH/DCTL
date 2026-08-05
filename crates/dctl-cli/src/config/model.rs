//! The shape of `config.toml`.
//!
//! These types are the *only* definition of what may appear in the file: the
//! parser accepts nothing they do not describe, and the writer emits nothing
//! they do not contain. That symmetry is what lets `PLAN.md` §14's central
//! promise be enforced rather than merely documented — there is no field here
//! that could hold a credential, so there is no code path that could write one.
//!
//! The module is deliberately inert. It knows how to *be* a configuration, not
//! how to find one ([`super::load`]), how to persist one ([`super::save`]), or
//! whether one makes sense ([`super::validate`]). Keeping the rules out of the
//! data means the rules can be applied at exactly one place — the moment a
//! configuration is read or written — instead of being re-litigated by every
//! constructor.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::cli::globals::VerifyMode;
use crate::constants::{
    PROVIDER_B2, PROVIDER_LOCAL, PROVIDER_R2, PROVIDER_S3, PROVIDER_SFTP, PROVIDER_VAULT,
};

/// A whole configuration file.
///
/// `remotes` is a [`BTreeMap`] rather than a `HashMap` because the ordering is
/// user-visible twice over: it is the order `dctl config list` prints, and it is
/// the order the file is written in. A hash map would reshuffle the file on
/// every save, turning a one-line edit into an unreadable diff and making the
/// file useless in version control — which §14 explicitly wants it to be good at.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Named remotes, keyed by the name typed before the `:` in a spec.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub remotes: BTreeMap<String, RemoteDef>,
}

impl Config {
    /// Look a remote up by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&RemoteDef> {
        self.remotes.get(name)
    }

    /// Whether a remote of this name is configured.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.remotes.contains_key(name)
    }

    /// Every configured remote name, in the file's own order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.remotes.keys().map(String::as_str)
    }

    /// How many remotes are configured.
    #[must_use]
    pub fn len(&self) -> usize {
        self.remotes.len()
    }

    /// Whether no remotes are configured.
    ///
    /// The state a fresh installation is in, and not an error: `PLAN.md` §14
    /// requires DCTL to run fully headless from flags and environment variables
    /// alone, so a machine that never runs `dctl config` is a supported machine.
    ///
    /// Uncalled today, and kept anyway: a type that answers [`Config::len`] and
    /// cannot answer "is it empty" is one `clippy::len_without_is_empty` would
    /// object to, and rightly — the caller who has to write `len() == 0` is the
    /// caller who writes `len() > 0` next to it and means something else.
    #[allow(dead_code)]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remotes.is_empty()
    }

    /// Add or replace a remote, returning what it displaced.
    ///
    /// Deliberately does not validate. Rules live in [`super::validate`] and are
    /// applied when a configuration is loaded or saved, so a caller building one
    /// up in several steps is never forced through a transiently-invalid state —
    /// defining a vault remote before its base is a normal thing to do.
    pub fn insert(&mut self, name: impl Into<String>, remote: RemoteDef) -> Option<RemoteDef> {
        self.remotes.insert(name.into(), remote)
    }

    /// Remove a remote, returning it if it was there.
    #[must_use = "the removed remote is returned so a caller can undo or report it"]
    pub fn remove(&mut self, name: &str) -> Option<RemoteDef> {
        self.remotes.remove(name)
    }
}

/// One named remote.
///
/// # No credentials, ever
///
/// **Every field below is non-secret, and that is a hard invariant, not a
/// default.** `PLAN.md` §14 rejects rclone's model outright: `rclone.conf`
/// stores provider keys and vault passwords in the file, "obscured" with
/// reversible obfuscation that anyone holding the file can undo. DCTL stores
/// buckets, endpoints, regions, account ids, chunk sizes and verify policy —
/// facts about *where* data lives, never about *who may read it*.
///
/// Credentials arrive from the OS keychain or the environment
/// (`DCTL_B2_APP_KEY` and friends), and the vault password is prompted for or
/// produced by `--password-command`. A key whose name looks like a credential is
/// **refused** on load rather than ignored, because an ignored secret is still a
/// secret sitting on disk, in a backup, and in the next bug report.
///
/// Adding a field here is therefore a security decision. The test
/// `no_field_is_named_like_a_secret` in this module walks the serialised form of
/// every variant and fails if any key trips
/// [`crate::logging::redact::is_sensitive_key`] — the same list that redacts
/// HTTP headers — so the invariant is checked by the build and not by review.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RemoteDef {
    /// A directory on this machine's filesystem.
    Local(LocalDef),
    /// A Backblaze B2 bucket, over B2's native API.
    B2(B2Def),
    /// An Amazon S3 bucket, or any S3-compatible endpoint.
    S3(S3Def),
    /// A Cloudflare R2 bucket.
    R2(R2Def),
    /// An SSH host reached over SFTP, driven by the system `ssh`.
    Sftp(SftpDef),
    /// A vault wrapper over another configured remote.
    Vault(VaultDef),
}

impl RemoteDef {
    /// The `type` value this remote serialises as.
    ///
    /// Returns the shared constants rather than the variant's own name so the
    /// serde tag, the provider table in [`crate::constants`], and the backend
    /// registry in `crate::remote` cannot drift apart. A test asserts the
    /// serialiser really emits these strings.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Local(_) => PROVIDER_LOCAL,
            Self::B2(_) => PROVIDER_B2,
            Self::S3(_) => PROVIDER_S3,
            Self::R2(_) => PROVIDER_R2,
            Self::Sftp(_) => PROVIDER_SFTP,
            Self::Vault(_) => PROVIDER_VAULT,
        }
    }

    /// The remote this one wraps, or `None` if it stores bytes itself.
    ///
    /// The single edge of the remote graph, which is what makes cycle detection
    /// in [`super::validate`] a walk over one accessor rather than a match on
    /// every variant.
    #[must_use]
    pub fn base(&self) -> Option<&str> {
        match self {
            Self::Vault(vault) => Some(vault.base.as_str()),
            _ => None,
        }
    }

    /// Whether this remote encrypts on the way through.
    #[must_use]
    pub const fn is_vault(&self) -> bool {
        matches!(self, Self::Vault(_))
    }

    /// Whether this remote's location is declared vault-only.
    ///
    /// True on the store remote `dctl init` registers, and the config-level
    /// half of invariant I2: the location holds a vault's opaque objects, so no
    /// *plain* remote may address it. A vault remote never carries the flag —
    /// it stores nothing itself, and a wrapper claiming a location it does not
    /// own would make the rule impossible to reason about.
    ///
    /// See [`crate::constants::CONFIG_KEY_REQUIRE_VAULT`] for why this is a
    /// declaration and not a lock.
    #[must_use]
    pub const fn require_vault(&self) -> bool {
        match self {
            Self::Local(def) => def.require_vault,
            Self::B2(def) => def.require_vault,
            Self::S3(def) => def.require_vault,
            Self::R2(def) => def.require_vault,
            Self::Sftp(def) => def.require_vault,
            Self::Vault(_) => false,
        }
    }

    /// The configured chunk size, if the file pins one.
    ///
    /// `None` means "use the profile default", which is the right answer for
    /// almost every config: a size written down today would otherwise freeze a
    /// tuning decision that a later release improves.
    ///
    /// Not yet read by anything: [`crate::remote::resolve`] turns a remote into
    /// a `Target` that has no field to carry it, so the setting round-trips
    /// through the file faithfully and then stops. That is a gap, and this
    /// accessor is where it closes — one fold over every variant, so the day a
    /// `Target` grows the field there is no per-provider match to write and
    /// forget one arm of.
    #[allow(dead_code)]
    #[must_use]
    pub const fn chunk_size(&self) -> Option<u64> {
        match self {
            Self::Local(_) => None,
            Self::B2(def) => def.chunk_size,
            Self::S3(def) => def.chunk_size,
            Self::R2(def) => def.chunk_size,
            Self::Sftp(def) => def.chunk_size,
            Self::Vault(def) => def.chunk_size,
        }
    }

    /// The configured default verification strength, if the file pins one.
    ///
    /// `--verify` on the command line still wins: the file states a policy for
    /// this destination, the flag states an intent for this run.
    ///
    /// Uncalled for the same reason as [`RemoteDef::chunk_size`]: nothing
    /// between the config and [`crate::ctx::Ctx::verify_mode`] carries a
    /// per-remote default yet. Until it does, every run verifies at whatever the
    /// flag says — which is the safe direction to be wrong in, because the
    /// default flag value is already the checksum comparison `PLAN.md` §6
    /// mandates.
    #[allow(dead_code)]
    #[must_use]
    pub const fn verify(&self) -> Option<VerifyMode> {
        match self {
            Self::Local(def) => def.verify,
            Self::B2(def) => def.verify,
            Self::S3(def) => def.verify,
            Self::R2(def) => def.verify,
            Self::Sftp(def) => def.verify,
            Self::Vault(def) => def.verify,
        }
    }
}

/// Settings for a `local` remote.
///
/// Two fields and no credentials, because a local remote's access control is the
/// filesystem's job and DCTL has nothing to add to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalDef {
    /// Root directory that logical vault paths resolve beneath.
    ///
    /// A [`PathBuf`] rather than a `String` because it is a *native* path — the
    /// one place in the configuration where platform spelling is correct, since
    /// a local remote is by definition not portable to another machine.
    pub path: PathBuf,

    /// Default verification strength for writes to this remote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<VerifyMode>,

    /// Whether this directory is a vault's object store.
    #[serde(default, skip_serializing_if = "is_unset")]
    pub require_vault: bool,
}

/// Settings for a `b2` remote, spoken over B2's native API.
///
/// The key id and application key are **not** here; they arrive as
/// `DCTL_B2_KEY_ID` and `DCTL_B2_APP_KEY`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B2Def {
    /// Bucket objects are stored in.
    pub bucket: String,

    /// Override for B2's API host.
    ///
    /// Present for private deployments and for test doubles; unset means B2's
    /// published endpoint, which is what every real installation wants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// Multipart part size, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u64>,

    /// Default verification strength for writes to this remote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<VerifyMode>,

    /// Whether this bucket is a vault's object store.
    #[serde(default, skip_serializing_if = "is_unset")]
    pub require_vault: bool,
}

/// Settings for an `s3` remote.
///
/// The access key and secret key are **not** here; they arrive as
/// `DCTL_S3_ACCESS_KEY` and `DCTL_S3_SECRET_KEY`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3Def {
    /// Bucket objects are stored in.
    pub bucket: String,

    /// Endpoint URL.
    ///
    /// Required for every S3 deployment that is not AWS — Wasabi, MinIO, B2's S3
    /// gateway — which is why it is a per-remote setting and not a compiled-in
    /// default that could quietly point somebody's data at the wrong provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// SigV4 region requests are signed for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// Multipart part size, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u64>,

    /// Default verification strength for writes to this remote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<VerifyMode>,

    /// Whether this bucket is a vault's object store.
    #[serde(default, skip_serializing_if = "is_unset")]
    pub require_vault: bool,
}

/// Settings for an `r2` remote.
///
/// Separate from [`S3Def`] even though R2 speaks the S3 protocol: R2 *derives*
/// its endpoint from an account id and pins the signing region, so the two need
/// different things from the user and sharing a struct would mean accepting
/// settings that cannot apply.
///
/// The access key and secret key are **not** here; they arrive as
/// `DCTL_R2_ACCESS_KEY` and `DCTL_R2_SECRET_KEY`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct R2Def {
    /// Bucket objects are stored in.
    pub bucket: String,

    /// Cloudflare account id the bucket belongs to.
    ///
    /// An identifier, not a credential: it appears in the endpoint hostname of
    /// every request R2 serves, so it is no more secret than the bucket name.
    /// It is here rather than in the environment because it is the R2 equivalent
    /// of [`S3Def::endpoint`] — the thing that says *which* deployment to talk
    /// to — and losing it would make the remote unusable rather than insecure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,

    /// Explicit endpoint URL, overriding the one derived from `account`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// Multipart part size, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u64>,

    /// Default verification strength for writes to this remote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<VerifyMode>,

    /// Whether this bucket is a vault's object store.
    #[serde(default, skip_serializing_if = "is_unset")]
    pub require_vault: bool,
}

/// Settings for an `sftp` remote — an SSH host reached over SFTP.
///
/// The two required fields are both non-secret, and deliberately so. [`host`] is
/// a destination `ssh` understands (a `~/.ssh/config` `Host` alias, or
/// `user@host[:port]`); every other connection parameter — the user, the port,
/// the identity file, any `ProxyCommand` — is resolved by `ssh` from the user's
/// own config and is therefore neither DCTL's to store nor a credential. There
/// is nothing here to arrive from the environment, because the transport's
/// authentication is `ssh`'s and not DCTL's: this is the one provider that keeps
/// its whole configuration in the file precisely because none of it is secret.
///
/// [`host`]: SftpDef::host
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SftpDef {
    /// SSH destination, as `ssh` resolves it: a `~/.ssh/config` `Host` alias
    /// (e.g. `backup.example.com`) or `user@host[:port]`.
    ///
    /// An IPv6 literal that also names a port must bracket the address —
    /// `[fe80::1]:2222` — because an unbracketed literal ends in a colon and a
    /// number of its own. Written without a port it is passed to `ssh`
    /// untouched, brackets or not.
    pub host: String,

    /// Remote base directory the objects live under. `~/…` is home-relative and
    /// a bare relative path is resolved against the SFTP session's start
    /// directory (the login home); `/…` is absolute.
    pub base: String,

    /// Transfer chunk size, in bytes.
    ///
    /// Carried for parity with the other providers and so a future tuning knob
    /// round-trips through the file; the backend streams in a fixed-size window
    /// today and does not yet read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u64>,

    /// Default verification strength for writes to this remote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<VerifyMode>,

    /// Whether this directory is a vault's object store.
    #[serde(default, skip_serializing_if = "is_unset")]
    pub require_vault: bool,
}

/// Whether a boolean setting is still at its default and may be left unwritten.
///
/// The same reasoning as every `Option::is_none` above: a default written into
/// the file states a decision that was never made. `require_vault = false` in a
/// section would read as "somebody considered this location and decided it was
/// not a vault store", which is a different and much stronger claim than "this
/// is an ordinary remote".
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_unset(flag: &bool) -> bool {
    !*flag
}

/// Settings for a `vault` remote — the wrapper described in `PLAN.md` §14.
///
/// A vault remote stores nothing itself. It names a **base** remote and
/// encrypts everything on the way through, so `vault:` can be a vault over
/// `b2prod` while `b2prod:` stays usable as a plain remote in the same run.
/// (`vault` rather than rclone's `crypt`, for the reason recorded on
/// [`crate::constants::PROVIDER_VAULT`]: this is an object with identity, not a
/// stateless transformation over a base remote.)
///
/// The encryption key is **not** here, and neither is anything derived from it.
/// A vault remote is a statement about *where* ciphertext goes, never about how
/// to decrypt it — the vault password is prompted for, read from
/// `--password-command`, or held by the unlock agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultDef {
    /// Name of the remote this one wraps.
    ///
    /// A bare **name**, never a `name:path` spec. A spec here would reintroduce
    /// exactly the ambiguity `MIN_REMOTE_NAME_LEN` exists to prevent —
    /// `base = "c:/data"` is unreadable as either — so the subdirectory is a
    /// separate field with one unambiguous meaning.
    pub base: String,

    /// Subdirectory of the base remote this vault remote occupies.
    ///
    /// A *logical* path: `/`-separated on every platform, no `..`, no leading
    /// slash. Unset means the base remote's root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_path: Option<String>,

    /// AEAD chunk size, in bytes.
    ///
    /// The seek granularity of the format (`PLAN.md` §3): playing from the
    /// middle of a video fetches whole chunks, so a larger value trades seek
    /// latency for fewer round trips. Unset means the media profile default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u64>,

    /// Default verification strength for writes through this remote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<VerifyMode>,
}

/// The schema walk both this module's tests and [`super::reach`] are built on.
///
/// A separate module rather than a function inside `mod tests` because two
/// guards need it and they check different things about the same set: the audit
/// below proves no field is named like a credential, and
/// [`super::reach::SETTINGS`] proves every field reaches an implementation.
/// Sharing the one definition is what stops a provider being added to one walk
/// and forgotten by the other.
#[cfg(test)]
pub mod model_test_support {
    use super::{B2Def, LocalDef, PathBuf, R2Def, RemoteDef, S3Def, SftpDef, VaultDef, VerifyMode};

    /// One fully-populated value of every variant.
    ///
    /// Every optional field is `Some` on purpose: a field that is `None` does
    /// not appear in the serialised form, so a sample built from defaults would
    /// let a secret-shaped field slip past the audit unnoticed, and would let a
    /// setting stay out of the reach table without failing its exhaustiveness
    /// check. The same reasoning sets every flag, which is skipped when `false`.
    #[must_use]
    pub fn every_variant() -> Vec<RemoteDef> {
        vec![
            RemoteDef::Local(LocalDef {
                path: PathBuf::from("/srv/data"),
                verify: Some(VerifyMode::Strict),
                require_vault: true,
            }),
            RemoteDef::B2(B2Def {
                bucket: "photos".into(),
                endpoint: Some("https://api.backblazeb2.com".into()),
                chunk_size: Some(64 * 1024 * 1024),
                verify: Some(VerifyMode::Checksum),
                require_vault: true,
            }),
            RemoteDef::S3(S3Def {
                bucket: "archive".into(),
                endpoint: Some("https://s3.example.com".into()),
                region: Some("eu-central-1".into()),
                chunk_size: Some(16 * 1024 * 1024),
                verify: Some(VerifyMode::Sample),
                require_vault: true,
            }),
            RemoteDef::R2(R2Def {
                bucket: "cold".into(),
                account: Some("0123456789abcdef".into()),
                endpoint: Some("https://acct.r2.cloudflarestorage.com".into()),
                chunk_size: Some(8 * 1024 * 1024),
                verify: Some(VerifyMode::Checksum),
                require_vault: true,
            }),
            RemoteDef::Sftp(SftpDef {
                host: "backup.example.com".into(),
                base: "~/dctl-store".into(),
                chunk_size: Some(4 * 1024 * 1024),
                verify: Some(VerifyMode::Strict),
                require_vault: true,
            }),
            RemoteDef::Vault(VaultDef {
                base: "b2prod".into(),
                base_path: Some("vault".into()),
                chunk_size: Some(4 * 1024 * 1024),
                verify: Some(VerifyMode::Strict),
            }),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        CONFIG_KEY_BASE, CONFIG_KEY_BUCKET, CONFIG_KEY_REMOTES, CONFIG_KEY_REQUIRE_VAULT,
        CONFIG_REMOTE_TYPE_KEY,
    };
    use crate::logging::redact::is_sensitive_key;
    use model_test_support::every_variant;

    fn sample_config() -> Config {
        let mut config = Config::default();
        for remote in every_variant() {
            config.insert(format!("{}remote", remote.type_name()), remote);
        }
        config
    }

    /// Collect every key in a TOML tree, dotted, for auditing.
    fn collect_keys(value: &toml::Value, prefix: &str, into: &mut Vec<(String, bool)>) {
        if let Some(table) = value.as_table() {
            for (key, child) in table {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                into.push((path.clone(), child.is_table()));
                collect_keys(child, &path, into);
            }
        }
    }

    #[test]
    fn no_field_is_named_like_a_secret() {
        // The invariant PLAN.md §14 rests on, checked by the build rather than by
        // review: adding a `secret_key` or `password` field to any RemoteDef
        // fails here. The list is the same one that redacts HTTP headers, so the
        // two definitions of "looks like a credential" cannot drift.
        let mut keys = Vec::new();
        collect_keys(
            &toml::Value::try_from(sample_config()).expect("the sample must serialise"),
            "",
            &mut keys,
        );
        assert!(!keys.is_empty(), "the audit must actually see some keys");

        for (path, is_table) in keys {
            // Table keys under `remotes` are user-chosen remote *names*, and
            // `my-secret-vault` is a perfectly good name for a vault. The rule
            // targets settings, which are the things that hold values.
            if is_table {
                continue;
            }
            let leaf = path.rsplit('.').next().unwrap_or(&path);
            assert!(
                !is_sensitive_key(leaf),
                "'{path}' is named like a credential; PLAN.md §14 forbids one in the config file"
            );
        }
    }

    #[test]
    fn a_populated_config_round_trips_through_toml() {
        let original = sample_config();
        let text = toml::to_string_pretty(&original).expect("must serialise");
        let parsed: Config = toml::from_str(&text).expect("must parse back");
        assert_eq!(parsed, original, "round trip changed the configuration");
    }

    #[test]
    fn an_empty_config_round_trips_and_writes_nothing() {
        let empty = Config::default();
        assert!(empty.is_empty());
        let text = toml::to_string_pretty(&empty).expect("must serialise");
        assert!(
            text.trim().is_empty(),
            "an empty config must not invent a table: {text:?}"
        );
        assert_eq!(toml::from_str::<Config>(&text).expect("must parse"), empty);
    }

    #[test]
    fn the_type_tag_is_spelled_from_the_shared_constants() {
        // serde's `rename_all` and the provider constants are two independent
        // definitions of the same word. If they ever disagree, a config file
        // written by one release stops parsing in the next.
        for remote in every_variant() {
            let value = toml::Value::try_from(&remote).expect("must serialise");
            let tag = value
                .get(CONFIG_REMOTE_TYPE_KEY)
                .and_then(toml::Value::as_str)
                .unwrap_or_default();
            assert_eq!(
                tag,
                remote.type_name(),
                "serde tag and type_name() disagree for {remote:?}"
            );
        }
    }

    #[test]
    fn the_remotes_table_is_spelled_from_the_shared_constant() {
        let value = toml::Value::try_from(sample_config()).expect("must serialise");
        assert!(
            value.get(CONFIG_KEY_REMOTES).is_some(),
            "the top-level table must be '{CONFIG_KEY_REMOTES}'"
        );
    }

    #[test]
    fn a_hand_written_file_parses_into_the_expected_shape() {
        // The file as a human would actually type it, which is the only form
        // that proves the TOML spelling is usable rather than merely reversible.
        let text = format!(
            "[remotes.b2prod]\n\
             {CONFIG_REMOTE_TYPE_KEY} = \"b2\"\n\
             {CONFIG_KEY_BUCKET} = \"photos\"\n\
             \n\
             [remotes.vault]\n\
             {CONFIG_REMOTE_TYPE_KEY} = \"vault\"\n\
             {CONFIG_KEY_BASE} = \"b2prod\"\n"
        );
        let config: Config = toml::from_str(&text).expect("must parse");
        assert_eq!(config.len(), 2);
        assert_eq!(
            config.get("b2prod").map(RemoteDef::type_name),
            Some(PROVIDER_B2)
        );
        assert_eq!(
            config.get("vault").and_then(RemoteDef::base),
            Some("b2prod")
        );
        assert!(config.get("vault").is_some_and(RemoteDef::is_vault));
        assert!(!config.get("b2prod").is_some_and(RemoteDef::is_vault));
    }

    #[test]
    fn a_credential_pasted_into_the_file_is_refused_not_ignored() {
        // The rclone habit PLAN.md §14 exists to break. Silently dropping the key
        // would leave it on disk; `deny_unknown_fields` makes the parse fail.
        let text = "[remotes.b2prod]\ntype = \"b2\"\nbucket = \"photos\"\n\
                    app_key = \"K000ffffffffffffffffffffffff\"\n";
        let error = toml::from_str::<Config>(text).expect_err("must not be accepted");
        assert!(
            error.to_string().contains("app_key"),
            "the error must name the offending key: {error}"
        );
    }

    #[test]
    fn unknown_top_level_keys_are_refused() {
        let error =
            toml::from_str::<Config>("password = \"hunter2\"\n").expect_err("must not be accepted");
        assert!(error.to_string().contains("password"), "got: {error}");
    }

    #[test]
    fn a_remote_without_a_type_is_not_a_remote() {
        let error = toml::from_str::<Config>("[remotes.b2prod]\nbucket = \"photos\"\n")
            .expect_err("a section with no type is not a remote");
        assert!(!error.to_string().is_empty());
    }

    #[test]
    fn an_unknown_provider_type_is_named_in_the_error() {
        let error = toml::from_str::<Config>("[remotes.x]\ntype = \"dropbox\"\n")
            .expect_err("dropbox is not a provider this build has");
        assert!(error.to_string().contains("dropbox"), "got: {error}");
    }

    #[test]
    fn verify_policy_uses_the_same_words_as_the_flag() {
        // `--verify strict` and `verify = "strict"` must be the same word, or the
        // documentation for one is wrong for the other.
        let text = "[remotes.disk]\ntype = \"local\"\npath = \"/srv\"\nverify = \"strict\"\n";
        let config: Config = toml::from_str(text).expect("must parse");
        assert_eq!(
            config.get("disk").and_then(RemoteDef::verify),
            Some(VerifyMode::Strict)
        );
        assert!(
            toml::from_str::<Config>(
                "[remotes.disk]\ntype = \"local\"\npath = \"/srv\"\nverify = \"Strict\"\n"
            )
            .is_err(),
            "only the lower-case spelling is accepted, matching the flag"
        );
    }

    #[test]
    fn absent_tuning_stays_absent_rather_than_being_written_as_a_default() {
        // A default written into the file would freeze today's tuning decision
        // for a config that outlives the release that wrote it.
        let mut config = Config::default();
        config.insert(
            "disk",
            RemoteDef::Local(LocalDef {
                path: PathBuf::from("/srv"),
                verify: None,
                require_vault: false,
            }),
        );
        let text = toml::to_string_pretty(&config).expect("must serialise");
        assert!(!text.contains("verify"), "got: {text}");
        assert!(!text.contains("chunk_size"), "got: {text}");
    }

    #[test]
    fn a_vault_only_location_is_declared_by_the_remote_that_stores_the_bytes() {
        // The flag belongs to the store, not to the wrapper: the wrapper stores
        // nothing, so a claim from it would be a claim about somebody else's
        // location. Every variant that *does* hold bytes can carry it.
        for remote in every_variant() {
            assert_eq!(
                remote.require_vault(),
                !remote.is_vault(),
                "{remote:?} disagrees about who owns the location"
            );
        }
    }

    #[test]
    fn the_vault_only_flag_survives_the_file_and_stays_out_of_it_when_unset() {
        let text = "[remotes.archive-store]\ntype = \"local\"\npath = \"/srv/vault\"\n\
                    require_vault = true\n";
        let config: Config = toml::from_str(text).expect("must parse");
        assert!(
            config
                .get("archive-store")
                .is_some_and(RemoteDef::require_vault)
        );

        // Unset is the overwhelming majority of remotes, and an unset flag must
        // not be written back: `require_vault = false` would read as a decision
        // somebody made about the location rather than as an ordinary remote.
        let mut plain = Config::default();
        plain.insert(
            "scratch",
            RemoteDef::Local(LocalDef {
                path: PathBuf::from("/srv"),
                verify: None,
                require_vault: false,
            }),
        );
        let rendered = toml::to_string_pretty(&plain).expect("must serialise");
        assert!(
            !rendered.contains(CONFIG_KEY_REQUIRE_VAULT),
            "got: {rendered}"
        );
    }

    #[test]
    fn only_vault_remotes_have_a_base() {
        for remote in every_variant() {
            assert_eq!(
                remote.base().is_some(),
                remote.is_vault(),
                "{remote:?} disagrees with itself about being a wrapper"
            );
        }
    }

    #[test]
    fn every_variant_reports_a_distinct_type_name() {
        let names: Vec<&str> = every_variant().iter().map(RemoteDef::type_name).collect();
        for (index, name) in names.iter().enumerate() {
            assert!(!name.is_empty());
            assert!(!names[index + 1..].contains(name), "'{name}' is duplicated");
        }
        assert!(names.contains(&PROVIDER_VAULT));
    }

    #[test]
    fn remotes_keep_their_file_order_across_a_save() {
        // The reason `remotes` is a BTreeMap: a reshuffled file turns a one-line
        // edit into an unreadable diff.
        let mut config = Config::default();
        for name in ["zulu", "alpha", "mike"] {
            config.insert(
                name,
                RemoteDef::Local(LocalDef {
                    path: PathBuf::from("/srv"),
                    verify: None,
                    require_vault: false,
                }),
            );
        }
        assert_eq!(
            config.names().collect::<Vec<_>>(),
            ["alpha", "mike", "zulu"]
        );
        let text = toml::to_string_pretty(&config).expect("must serialise");
        let alpha = text.find("alpha").unwrap_or_default();
        let mike = text.find("mike").unwrap_or_default();
        let zulu = text.find("zulu").unwrap_or_default();
        assert!(alpha < mike && mike < zulu, "file order is not sorted");
    }

    #[test]
    fn insert_replaces_and_remove_returns_what_it_took() {
        let mut config = Config::default();
        let first = RemoteDef::Local(LocalDef {
            path: PathBuf::from("/one"),
            verify: None,
            require_vault: false,
        });
        let second = RemoteDef::Local(LocalDef {
            path: PathBuf::from("/two"),
            verify: None,
            require_vault: false,
        });
        assert!(config.insert("disk", first.clone()).is_none());
        assert_eq!(config.insert("disk", second), Some(first));
        assert_eq!(config.len(), 1);
        assert!(config.remove("disk").is_some());
        assert!(config.is_empty());
        assert!(config.remove("disk").is_none());
        assert!(!config.contains("disk"));
    }
}
