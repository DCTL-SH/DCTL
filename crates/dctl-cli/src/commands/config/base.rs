//! Turning a base **location** into the store remote that addresses it.
//!
//! `dctl init --base local:/srv/vault` and `dctl config import b2:media` say the
//! same kind of thing in the same words: *here is a place*. Both then have to
//! write a configuration section describing it, and this is the one translation
//! between the two vocabularies.
//!
//! ## A location, deliberately not a remote name
//!
//! `--base` never accepts the name of a remote that already exists, and the
//! refusal is a design decision rather than a missing feature. `dctl init`
//! promises to register **both** views of a vault — the sealed one and the
//! object one — and a base that resolved to an existing section would make that
//! promise conditional: sometimes two remotes appear, sometimes one, depending
//! on what the file happened to contain. A user reading the command could not
//! tell which. Wrapping a remote that already exists is a real thing to want and
//! has its own spelling: `dctl config create NAME vault base=EXISTING`.
//!
//! Because provider types are reserved as remote names
//! ([`crate::config::validate_remote_name`]), the two readings can never
//! collide: `b2:` is always the provider shorthand and never a configured
//! remote, so no configuration can change what a base spec means.
//!
//! ## The subdirectory refusal
//!
//! A base may name a container and a prefix inside it — `s3:archive/vaults/a` —
//! and [`BaseLocation`] carries that prefix as the vault's `base_path`. It is
//! then **refused**, because `dctl_core::Vault::init` writes the envelope to a
//! fixed object key and honours no prefix: accepting the spec would create a
//! vault at the bucket root while the configuration said it was in a
//! subdirectory, and every later command would look in the place the file
//! named and find nothing. Refusing is the `PLAN.md` §6 answer — say what did
//! not happen, rather than report a vault at an address it is not at.

use std::path::Path;

use crate::config::RemoteDef;
use crate::constants::{
    CONFIG_KEY_BUCKET, CONFIG_KEY_PATH, PATH_SEPARATOR, PROVIDER_B2, PROVIDER_LOCAL, PROVIDER_R2,
    PROVIDER_S3, PROVIDER_SFTP, REMOTE_SEPARATOR,
};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::remote::RemoteSpec;

use super::settings;

/// A place to put a vault's objects, parsed and ready to be written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseLocation {
    /// The spec exactly as the user typed it, for messages and reports.
    ///
    /// Kept verbatim rather than re-rendered, because the whole value of an
    /// error at this stage is that the operator recognises their own argument
    /// in it.
    pub spec: String,

    /// The store remote's definition, before it is marked as a vault store.
    pub store: RemoteDef,

    /// Subdirectory of the store the vault would occupy, if the spec named one.
    ///
    /// Always refused by [`BaseLocation::refuse_subdirectory`] in this build;
    /// carried anyway so the refusal can name it and so the field is already
    /// right the day the engine honours it.
    pub base_path: Option<String>,

    /// The container's own name — the bucket, or the directory's last component.
    ///
    /// The one part of a location that reads like a name a human chose, and
    /// therefore the only defensible default for `dctl config import`.
    pub container: String,
}

impl BaseLocation {
    /// Parse a base spec into the store remote that addresses it.
    ///
    /// # Errors
    /// [`ExitCode::Usage`] for a spec that addresses nothing, one that names a
    /// configured remote rather than a location, a provider shorthand with no
    /// container, or a local path that is not valid UTF-8 and therefore could
    /// not be written into the configuration file.
    pub fn parse(spec: &str) -> Result<Self> {
        match RemoteSpec::parse(spec)? {
            RemoteSpec::Local(path) => Self::local(spec, &path),
            RemoteSpec::Named { remote, path } => Self::named(spec, &remote, &path),
        }
    }

    /// A directory on this machine.
    fn local(spec: &str, path: &Path) -> Result<Self> {
        // The configuration file is UTF-8 TOML, so a path that is not valid
        // UTF-8 cannot be written into it. Caught here, where the message can
        // name the argument, rather than as a serialisation failure after a
        // vault has already been created.
        let text = path.to_str().ok_or_else(|| {
            CliError::new(
                ExitCode::Usage,
                format!("'{spec}' is not valid UTF-8 and cannot be written to the configuration"),
            )
            .with_hint(
                "The configuration file is UTF-8. Address the directory through \
                 a path that is, or create it somewhere that is.",
            )
        })?;

        Ok(Self {
            spec: spec.to_string(),
            store: settings::build(
                PROVIDER_LOCAL,
                &[(CONFIG_KEY_PATH.to_string(), text.to_string())]
                    .into_iter()
                    .collect(),
            )?,
            base_path: None,
            container: container_of_path(path),
        })
    }

    /// A provider shorthand: `b2:bucket`, `s3:bucket/prefix`, `r2:bucket`, or an
    /// sftp host `sftp:host/base-dir`.
    fn named(spec: &str, remote: &str, path: &str) -> Result<Self> {
        // sftp is a place, but not a bucket: its tail is a base directory rather
        // than a container-plus-prefix, so it has its own parse below.
        if remote == PROVIDER_SFTP {
            return Self::sftp(spec, path);
        }

        if !matches!(remote, PROVIDER_B2 | PROVIDER_S3 | PROVIDER_R2) {
            return Err(CliError::new(
                ExitCode::Usage,
                format!("'{remote}' is not a provider type, so '{spec}' does not name a location"),
            )
            .with_hint(format!(
                "A base is a *place*, written as \
                 'provider{REMOTE_SEPARATOR}container' — for example \
                 'b2{REMOTE_SEPARATOR}my-bucket', \
                 'sftp{REMOTE_SEPARATOR}lsx-001/dctl-store' or \
                 'local{REMOTE_SEPARATOR}/srv/vault'. To wrap a remote that is \
                 already configured, use `dctl config create NAME vault \
                 base={remote}` instead."
            )));
        }

        let (container, prefix) = path.split_once(PATH_SEPARATOR).unwrap_or((path, ""));
        if container.is_empty() {
            return Err(CliError::new(
                ExitCode::Usage,
                format!("'{spec}' names no container to store the vault in"),
            )
            .with_hint(format!(
                "Write it as '{remote}{REMOTE_SEPARATOR}BUCKET'. The bucket must \
                 already exist; DCTL stores objects in it, it does not create it."
            )));
        }

        Ok(Self {
            spec: spec.to_string(),
            store: settings::build(
                remote,
                &[(CONFIG_KEY_BUCKET.to_string(), container.to_string())]
                    .into_iter()
                    .collect(),
            )?,
            base_path: (!prefix.is_empty()).then(|| prefix.to_string()),
            container: container.to_string(),
        })
    }

    /// An sftp host: `sftp:host/base-dir`.
    ///
    /// The first path component is the ssh destination and the whole remainder is
    /// the base directory the vault's objects go under. Unlike a bucket prefix
    /// there is no subdirectory to refuse: the tail *is* the store's root, and the
    /// vault's envelope is written at the root of exactly that directory — so
    /// [`BaseLocation::base_path`] stays `None` and [`refuse_subdirectory`] has
    /// nothing to catch.
    ///
    /// The split is [`crate::remote::sftp_base`]'s, and that is the fix for
    /// `docs/HANDOVER.md` §16.3. This function used to do its own
    /// `split_once('/')`, which threw the separator away — so `--base
    /// sftp:h/srv/vault` wrote `base = "srv/vault"`, the backend resolved it
    /// against the SSH login directory, and the vault was created in
    /// `$HOME/srv/vault` while this command reported it on `sftp:h/srv/vault`.
    /// `dctl config create NAME sftp host=h base=/srv/vault` meant the other one.
    ///
    /// [`refuse_subdirectory`]: BaseLocation::refuse_subdirectory
    fn sftp(spec: &str, path: &str) -> Result<Self> {
        let (host, base) = crate::remote::sftp_base::from_spec(spec, path)?;

        Ok(Self {
            spec: spec.to_string(),
            store: settings::build(
                PROVIDER_SFTP,
                &crate::remote::sftp_base::settings(&host, &base),
            )?,
            base_path: None,
            container: host.clone(),
        })
    }

    /// Refuse a base that names a subdirectory of its container.
    ///
    /// See the module docs: the engine writes the envelope to a fixed key, so a
    /// configuration claiming the vault lives in a prefix would be addressing a
    /// vault that is somewhere else.
    ///
    /// # Errors
    /// [`ExitCode::Usage`] when [`BaseLocation::base_path`] is set.
    pub fn refuse_subdirectory(&self) -> Result<()> {
        let Some(prefix) = &self.base_path else {
            return Ok(());
        };

        Err(CliError::new(
            ExitCode::Usage,
            format!(
                "'{}' puts the vault in the subdirectory '{prefix}', which this \
                 build cannot address",
                self.spec
            ),
        )
        .with_hint(format!(
            "The engine writes a vault's envelope to a fixed key at the root of \
             its store, so a vault in a subdirectory would be created somewhere \
             other than where the configuration said it was. Address the \
             container itself ('{}'), or give the vault a container of its own.",
            self.container
        )))
    }
}

/// The last component of a local path, as a candidate remote name.
///
/// Lossy on purpose: this feeds a *suggestion*, and a name derived from it is
/// put through [`crate::config::validate_remote_name`] before it is used, so an
/// unusable candidate becomes "pass --name" rather than a bad remote.
fn container_of_path(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The native path a local store remote addresses.
    ///
    /// Test-only, and deliberately so: production never reads a store's path
    /// back out, because the only thing it does with a `BaseLocation` is hand
    /// the whole definition to [`crate::config::VaultPair`]. The tests need it
    /// to assert that a spec became the *directory the user typed* rather than
    /// something a parser rewrote, which is the one property of this module that
    /// silently sends data to the wrong place when it is wrong.
    fn local_path_of(store: &RemoteDef) -> Option<PathBuf> {
        match store {
            RemoteDef::Local(def) => Some(def.path.clone()),
            _ => None,
        }
    }

    fn parsed(spec: &str) -> BaseLocation {
        BaseLocation::parse(spec).unwrap_or_else(|error| panic!("'{spec}': {}", error.message()))
    }

    #[test]
    fn a_local_directory_becomes_a_local_store() {
        for spec in ["local:/srv/vault", "/srv/vault"] {
            let base = parsed(spec);
            assert_eq!(base.store.type_name(), PROVIDER_LOCAL);
            assert_eq!(
                local_path_of(&base.store),
                Some(PathBuf::from("/srv/vault"))
            );
            assert_eq!(base.base_path, None);
            assert_eq!(base.container, "vault");
            assert_eq!(base.spec, spec, "the argument must survive verbatim");
        }
    }

    #[test]
    fn a_windows_path_is_never_a_bucket_called_c() {
        // The shared spec rule, not a second copy of it: `dctl init` must not
        // disagree with `dctl copy` about what `C:\vaults` means. Which of the
        // two truthful readings applies depends on the platform — a directory
        // where drives exist, a reference to the undeclarable remote `C`
        // elsewhere — and `crate::remote::spec` asserts both on either machine.
        // What this pins is that `dctl init` gets the *same* reading, and that
        // neither of them is a provider.
        match BaseLocation::parse(r"C:\vaults\main") {
            Ok(base) => {
                assert_eq!(base.store.type_name(), PROVIDER_LOCAL);
                assert_eq!(
                    local_path_of(&base.store),
                    Some(PathBuf::from(r"C:\vaults\main"))
                );
            }
            Err(error) => assert!(error.message().contains('C'), "{}", error.message()),
        }
    }

    #[test]
    fn a_provider_shorthand_becomes_a_bucket() {
        let base = parsed("b2:media-archive");
        assert_eq!(base.store.type_name(), PROVIDER_B2);
        assert_eq!(base.container, "media-archive");
        assert_eq!(base.base_path, None);
        assert!(base.refuse_subdirectory().is_ok());

        assert_eq!(parsed("s3:archive").store.type_name(), PROVIDER_S3);
        assert_eq!(parsed("r2:cold").store.type_name(), PROVIDER_R2);
    }

    #[test]
    fn a_prefix_is_carried_and_then_refused() {
        // Carried, so the refusal can name it and so the field is already right
        // for the day the engine honours it. Refused, because accepting it would
        // create a vault somewhere other than where the config says it is.
        let base = parsed("s3:archive/vaults/a");
        assert_eq!(base.container, "archive");
        assert_eq!(base.base_path.as_deref(), Some("vaults/a"));

        let error = base.refuse_subdirectory().unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("vaults/a"), "{}", error.message());
        // The remediation has to say what *would* work.
        assert!(
            error.hint().unwrap_or_default().contains("archive"),
            "the hint must name the container"
        );
    }

    #[test]
    fn a_name_that_is_not_a_provider_is_not_a_location() {
        // The design decision: `--base` never resolves a configured remote, so
        // `dctl init` always registers exactly two sections.
        let error = BaseLocation::parse("b2prod:").unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("b2prod"), "{}", error.message());
        // And it has to point at the command that does wrap an existing remote.
        let hint = error.hint().unwrap_or_default();
        assert!(hint.contains("vault base=b2prod"), "got hint: {hint}");
    }

    #[test]
    fn a_shorthand_with_no_container_is_refused() {
        // `b2:` says "some bucket" and means nothing; a store remote written
        // from it would address a bucket named the empty string.
        let error = BaseLocation::parse("b2:").unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some(), "the refusal needs a remediation");

        // A leading separator is not a missing container: the shared spec parser
        // canonicalises the logical path, so `s3:/archive` is the bucket
        // `archive` — the same reading `dctl ls s3:/archive` already has, and
        // disagreeing with it here would be worse than being strict.
        assert_eq!(parsed("s3:/archive").container, "archive");
    }

    #[test]
    fn a_spec_that_addresses_nothing_is_refused_by_the_shared_parser() {
        for spec in ["", "b2:../escape"] {
            let error = BaseLocation::parse(spec).unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "'{spec}'");
        }
    }

    #[test]
    fn the_container_of_a_root_directory_is_not_a_usable_name() {
        // `/` has no last component. The empty candidate must simply fail the
        // name rules later rather than produce a remote called "".
        assert!(container_of_path(Path::new("/")).is_empty());
        assert!(crate::config::validate_remote_name("").is_err());
    }
}
