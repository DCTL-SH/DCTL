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
//! locations *here*, and config validation does not catch the second.
//!
//! That purity is right for validation and would be wrong on the write path, so
//! the write path does not rely on it. [`super::namespace`] compares each
//! [`Location`] twice — as the file spells it and as
//! [`crate::platform::resolve`] resolves it — precisely so a destination cannot
//! escape the vault-only rule by being typed differently. This module used to
//! carry a paragraph excusing the gap on the grounds that the write path closed
//! it by "inspecting the bytes that are really there". That excuse was wrong
//! twice over, and both halves are worth recording so they are not reintroduced:
//!
//! * It was **factually wrong**. Inspecting bytes is the *fallback* for a
//!   location no remote describes. For a configured store the decision is made
//!   from the file alone, so a spelling this type failed to recognise was not
//!   rescued by anything downstream — it was a plaintext write into a vault.
//! * It described the **wrong shape of guarantee**. Invariant I4 (see
//!   [`crate::addressing`]) says contents may only ever cause a refusal, never a
//!   change in what a command does. A guard justified by what it reads off the
//!   disk is a guard whose behaviour is a function of the disk, which is the
//!   property the model exists to deny.
//!
//! What remains true, and is the honest limit of this type on its own: it
//! catches the mistake people actually make — pointing a second, plain remote at
//! a store they can see in `dctl config list` — and it does not pretend to be a
//! sandbox.

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

            // The host and the base directory together decide the place: the
            // same directory on two hosts is two locations, and two bases on one
            // host are two. Kept verbatim, like a local path — this type stays
            // pure, so `~/store` and `store` are two spellings it does not unify.
            RemoteDef::Sftp(def) => vec![def.host.clone(), def.base.clone()],

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
    /// expansion, no filesystem access at all. But *purity is not the same as
    /// literalness*, and conflating the two cost this module its whole purpose.
    ///
    /// The identity was previously `path.display()` — a raw string — so
    /// `/srv/store/` and `/srv/store` were two different places. They are one
    /// directory spelled two ways, and a trailing slash is what shell
    /// tab-completion produces. The consequence was not cosmetic:
    /// `dctl copy ./src /srv/store/` wrote plaintext *into* a vault's object
    /// store and exited 0, and `dctl sync ./src /srv/store/` deleted the
    /// ciphertext objects already there.
    ///
    /// So the identity is built from the path's **components**, which is a pure,
    /// I/O-free normalisation: it collapses `/`, `//`, `/.` and a trailing
    /// separator, and leaves everything that genuinely distinguishes two places
    /// alone. `..` is deliberately NOT resolved — that needs the filesystem to be
    /// correct in the presence of symlinks, and guessing would be worse than the
    /// resolved-path pass [`super::namespace`] already performs.
    #[must_use]
    pub fn of_path(path: &Path) -> Self {
        use std::path::Component;

        let mut identity = String::new();
        for component in path.components() {
            match component {
                Component::RootDir => identity.push('/'),
                Component::CurDir => {}
                Component::Prefix(prefix) => {
                    identity.push_str(&prefix.as_os_str().to_string_lossy());
                }
                Component::ParentDir => {
                    if !identity.is_empty() && !identity.ends_with('/') {
                        identity.push('/');
                    }
                    identity.push_str("..");
                }
                Component::Normal(part) => {
                    if !identity.is_empty() && !identity.ends_with('/') {
                        identity.push('/');
                    }
                    identity.push_str(&part.to_string_lossy());
                }
            }
        }

        Self(format!("{PROVIDER_LOCAL}{REMOTE_SEPARATOR}{identity}"))
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
        // locations. `super::namespace` closes that gap by resolving both sides
        // before it compares them; this type stays pure so validation can run on
        // a machine that has never seen the paths in the file.
        assert_ne!(
            Location::of(&local("/srv/vault")),
            Location::of(&local("/srv/../srv/vault"))
        );
    }
}
