//! Where a remote's bytes physically land, as a comparable value.
//!
//! Two remotes can be spelled completely differently and still be the same
//! place. `archive-store` and `b2prod` are two names, two sections and two sets
//! of settings; if both say `bucket = "photos"` they are one bucket, and a rule
//! about "this location is a vault's object store" is worthless unless it can
//! notice that.
//!
//! So a [`Location`] is the identity of a *place*, derived from the settings
//! that decide which place it is and from nothing else. A bucket and the
//! endpoint it lives behind decide a place; a signing region, a chunk size and a
//! verification policy decide how DCTL talks to it, and two remotes that differ
//! only in those are still pointed at the same objects. Including them would let
//! `region = "us-east-1"` be the difference between a refusal and a silent
//! plaintext write into a vault.
//!
//! ## What this is not
//!
//! It is not a *reachability* claim. Nothing here opens a connection, expands a
//! symlink or canonicalises a path against a filesystem — the config layer is
//! pure by design, and a rule that needed I/O to decide could not be enforced
//! when the file is written on one machine and read on another. Two spellings of
//! one directory (`/srv/vault` and `/srv/../srv/vault`) are therefore two
//! locations here, and the vault-only rule does not catch the second.
//!
//! That is the honest trade and worth stating plainly: this catches the mistake
//! people actually make — pointing a second, plain remote at a store they can
//! see in `dctl config list` — and does not pretend to be a sandbox. The
//! invariant that has no gaps is the one on the write path, where a vault remote
//! always seals and a plain write into a store is refused by inspecting the
//! bytes that are really there.

use std::fmt;
use std::path::Path;

use crate::constants::{LOCATION_FIELD_SEPARATOR, PROVIDER_LOCAL, REMOTE_SEPARATOR};

use super::model::RemoteDef;

/// The physical place a remote addresses.
///
/// Compared by value, so a `BTreeMap<Location, _>` groups every remote that
/// lands on one bucket. Rendered as `provider:field|field` — readable enough to
/// print in the refusal that names it, which matters because the whole value of
/// the check is telling an operator *which two remotes collided and where*.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Location(String);

impl Location {
    /// The place `remote` addresses, or `None` when it addresses none.
    ///
    /// A vault remote returns `None`, and that is the point rather than an
    /// omission: it stores nothing itself, so it has no location of its own to
    /// collide with. Its base does, and the base is a remote in the same file.
    #[must_use]
    pub fn of(remote: &RemoteDef) -> Option<Self> {
        let fields: Vec<String> = match remote {
            // A native path, kept exactly as the file spells it. Not
            // canonicalised: see the module docs on why this stays pure.
            RemoteDef::Local(def) => vec![def.path.display().to_string()],

            // B2's native API addresses a bucket inside one account, and the
            // account is decided by the credentials rather than by the config,
            // so the bucket is the whole of the identity available here.
            RemoteDef::B2(def) => vec![def.bucket.clone()],

            // The endpoint is part of the identity: `archive` on MinIO and
            // `archive` on AWS are different buckets that happen to share a
            // name, and treating them as one would refuse a legitimate remote.
            RemoteDef::S3(def) => {
                vec![def.bucket.clone(), def.endpoint.clone().unwrap_or_default()]
            }

            // The account plays the endpoint's role for R2, which derives its
            // host from it.
            RemoteDef::R2(def) => {
                vec![def.bucket.clone(), def.account.clone().unwrap_or_default()]
            }

            RemoteDef::Vault(_) => return None,
        };

        Some(Self(format!(
            "{}{REMOTE_SEPARATOR}{}",
            remote.type_name(),
            fields.join(&LOCATION_FIELD_SEPARATOR.to_string())
        )))
    }

    /// The place a **bare filesystem path** addresses.
    ///
    /// The counterpart of [`Location::of`] for a destination the user typed
    /// rather than a section the file declares, and the reason it is a
    /// constructor here rather than a comparison at the call site: deciding
    /// whether `/srv/vault/photos` lands in the same place as
    /// `path = "/srv/vault"` is the identity question this type owns. A caller
    /// that compared the two as strings would be writing a second definition of
    /// "the same place", and the two would eventually disagree — at which point
    /// a plain write into a vault's object store stops being refused.
    ///
    /// Kept as pure as everything else here: no canonicalisation, no symlink
    /// expansion, no filesystem access at all. A path is taken exactly as it is
    /// spelled, which is the trade the module documentation states.
    #[must_use]
    pub fn of_path(path: &Path) -> Self {
        Self(format!(
            "{PROVIDER_LOCAL}{REMOTE_SEPARATOR}{}",
            path.display()
        ))
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{B2Def, LocalDef, R2Def, S3Def, VaultDef};
    use std::path::PathBuf;

    fn local(path: &str) -> RemoteDef {
        RemoteDef::Local(LocalDef {
            path: PathBuf::from(path),
            verify: None,
            require_vault: false,
        })
    }

    fn b2(bucket: &str) -> RemoteDef {
        RemoteDef::B2(B2Def {
            bucket: bucket.into(),
            endpoint: None,
            chunk_size: None,
            verify: None,
            require_vault: false,
        })
    }

    fn s3(bucket: &str, endpoint: Option<&str>, region: Option<&str>) -> RemoteDef {
        RemoteDef::S3(S3Def {
            bucket: bucket.into(),
            endpoint: endpoint.map(str::to_string),
            region: region.map(str::to_string),
            chunk_size: None,
            verify: None,
            require_vault: false,
        })
    }

    #[test]
    fn two_remotes_naming_one_bucket_are_one_location() {
        // The whole reason this type exists: `archive-store` and `b2prod` are
        // two sections and one bucket, and the vault-only rule has to see that.
        assert_eq!(Location::of(&b2("photos")), Location::of(&b2("photos")));
        assert_ne!(Location::of(&b2("photos")), Location::of(&b2("films")));
    }

    #[test]
    fn settings_that_only_change_how_we_talk_are_not_part_of_the_place() {
        // A region is a signing detail. If it split the identity, adding one to
        // a section would be enough to slip a plain remote past the rule.
        let with_region = s3("archive", Some("https://s3.example.com"), Some("eu-west-1"));
        let without = s3("archive", Some("https://s3.example.com"), None);
        assert_eq!(Location::of(&with_region), Location::of(&without));

        let mut chunked = without.clone();
        if let RemoteDef::S3(def) = &mut chunked {
            def.chunk_size = Some(8 * 1024 * 1024);
            def.require_vault = true;
        }
        assert_eq!(Location::of(&chunked), Location::of(&without));
    }

    #[test]
    fn the_endpoint_distinguishes_two_buckets_that_share_a_name() {
        // `archive` on MinIO is not `archive` on AWS, and refusing the second
        // because of the first would be a false alarm on a real configuration.
        assert_ne!(
            Location::of(&s3("archive", Some("https://minio.internal"), None)),
            Location::of(&s3("archive", Some("https://s3.amazonaws.com"), None))
        );
        assert_ne!(
            Location::of(&s3("archive", None, None)),
            Location::of(&s3("archive", Some("https://minio.internal"), None))
        );
    }

    #[test]
    fn the_account_plays_that_role_for_r2() {
        let one = RemoteDef::R2(R2Def {
            bucket: "cold".into(),
            account: Some("aaaa".into()),
            endpoint: None,
            chunk_size: None,
            verify: None,
            require_vault: false,
        });
        let mut other = one.clone();
        if let RemoteDef::R2(def) = &mut other {
            def.account = Some("bbbb".into());
        }
        assert_ne!(Location::of(&one), Location::of(&other));
    }

    #[test]
    fn two_providers_never_share_a_location() {
        // A bucket called `photos` and a directory called `photos` are not the
        // same place, however similarly they render.
        assert_ne!(Location::of(&b2("photos")), Location::of(&local("photos")));
        assert_ne!(
            Location::of(&b2("photos")),
            Location::of(&s3("photos", None, None))
        );
    }

    #[test]
    fn a_vault_remote_has_no_location_of_its_own() {
        // It stores nothing, so it cannot collide with anything. Its base can.
        let vault = RemoteDef::Vault(VaultDef {
            base: "archive-store".into(),
            base_path: None,
            chunk_size: None,
            verify: None,
        });
        assert_eq!(Location::of(&vault), None);
    }

    #[test]
    fn a_location_renders_readably_enough_to_put_in_a_refusal() {
        // The message that names it is the only thing the operator has to work
        // out which two remotes collided, so it has to say where.
        let rendered = Location::of(&local("/srv/vault"))
            .map(|location| location.to_string())
            .unwrap_or_default();
        assert!(rendered.contains("/srv/vault"), "got: {rendered}");
        assert!(rendered.starts_with("local"), "got: {rendered}");
    }

    #[test]
    fn a_typed_path_and_a_configured_one_are_the_same_place() {
        // The two constructors have to agree, or the namespace rule would ask
        // "is this directory a vault's object store" of a value that could never
        // equal any location the file declares — and would answer no, always.
        assert_eq!(
            Location::of(&local("/srv/vault")),
            Some(Location::of_path(std::path::Path::new("/srv/vault")))
        );
        assert_ne!(
            Location::of(&local("/srv/vault")),
            Some(Location::of_path(std::path::Path::new("/srv/other")))
        );
        // A bucket is not a directory, whatever the two are named.
        assert_ne!(
            Location::of(&b2("photos")),
            Some(Location::of_path(std::path::Path::new("photos")))
        );
    }

    #[test]
    fn a_path_is_taken_as_the_file_spells_it() {
        // Documented limitation, asserted so it cannot be assumed away: nothing
        // here touches a filesystem, so two spellings of one directory are two
        // locations. The write-path guard is what closes that gap.
        assert_ne!(
            Location::of(&local("/srv/vault")),
            Location::of(&local("/srv/../srv/vault"))
        );
    }
}
