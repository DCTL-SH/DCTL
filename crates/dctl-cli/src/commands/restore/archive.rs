//! The vault a restore reads from: one unlock, one listing, streamed reads.
//!
//! ## Why this is not `crate::source`
//!
//! [`crate::source`] is the binary's one *read* abstraction and every listing
//! verb goes through it, including the transfer family's enumeration of a vault
//! source. A restore cannot, and the reason is specific rather than a matter of
//! taste.
//!
//! A restore has to move a fifty-gigabyte file onto a disk without holding it.
//! The call that does that is
//! [`Vault::get_file_to_path`](dctl_core::Vault::get_file_to_path), which
//! decrypts chunk by chunk straight into a temporary sibling of the destination
//! and renames it into place only after the whole object authenticates.
//! `Source::read` returns a whole `Zeroizing<Vec<u8>>` — that is the shape of
//! `Vault::get_file`, not a limitation of the trait's callers — so routing a
//! restore through it would make peak memory O(object) and break `PLAN.md`
//! §16.2 precisely on the verb most likely to meet the largest file anybody
//! owns.
//!
//! The alternative — enumerate through `crate::source` and open a *second*
//! session for the reads — costs a second unlock, which for an interactive
//! operator means being asked for the same password twice in one command. So
//! this module holds one [`Session`] and answers both questions from it. The
//! listing rule below is deliberately the same one [`crate::source::vault`]
//! applies — the index matches a prefix by bytes, so `photos` would otherwise
//! report `photos-backup` — and it is expressed through [`Target::covers`], the
//! recovery family's own statement of that rule, rather than re-written here.
//!
//! When `dctl-core` grows a streaming read on the `Source` trait, this module
//! collapses into a `crate::source::open` call and nothing above it changes.
//!
//! ## What a fetch proves
//!
//! `get_file_to_path` verifies every chunk's authentication tag and the object
//! footer, folds a streaming BLAKE3 over the emitted plaintext, and compares it
//! to the object's own DEK-authenticated `content_blake3`. A mismatch removes
//! the temporary file and returns an integrity error, so **no destination file
//! exists** for an object that did not authenticate — not a partial one, not a
//! stale one. That is the claim a restore needs: what landed is what was stored.
//!
//! On top of that, [`Archive::fetch`] cross-checks the length of what landed
//! against the length the index recorded, where the index recorded one. The core
//! compares the object against *itself*; this compares the object against the
//! catalogue, which is the disagreement a corrupted or half-rebuilt index would
//! produce.

use std::path::Path;

use dctl_core::{Modified, Record};

use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::platform::times;
use crate::remote::RemoteSpec;
use crate::session::{self, Session};

use crate::commands::recovery::Target;

/// One stored object, as the index describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    /// Full logical path inside the vault.
    pub logical: String,
    /// Plaintext size the index recorded.
    pub size: u64,
    /// Whether that size was ever actually measured.
    ///
    /// [`Vault::rebuild_index`](dctl_core::Vault::rebuild_index) recovers a
    /// machine from the backend alone by listing and decrypting the §5 name
    /// records. That is a list-only pass by design — it must not cost a full
    /// read of the dataset — so the rows it writes carry `size: 0` and an
    /// *empty* content hash.
    ///
    /// The two together are what make the case identifiable: a file written
    /// through the ordinary path always has a 32-byte BLAKE3 recorded, and that
    /// is true of a genuinely empty file too, because `blake3::hash(b"")` is a
    /// full digest rather than nothing. So `size == 0` with *no* hash cannot be
    /// an empty file; it can only be a row nobody has measured.
    ///
    /// Distinguishing them matters twice over: a plan that reported the zero as
    /// fact would understate what a restore is about to write, and the
    /// length cross-check in [`Archive::fetch`] would refuse every such object.
    /// The same distinction is drawn, for the same reason, in
    /// [`crate::source::vault`].
    pub measured: bool,
    /// When the file this object was made from was last modified.
    ///
    /// Carried through the restore so the tree that lands is the tree that was
    /// backed up — dates and all. A restore that returned the right bytes under
    /// the right names with every timestamp set to the moment of the restore has
    /// not reproduced the tree; it has produced a tree that *looks* entirely
    /// rewritten to every tool that sorts, compares or syncs by date, including
    /// this one.
    ///
    /// [`Modified::Unknown`] for a row `dctl index rebuild` wrote, which recovers
    /// from a list-only pass and records no time — the same reason `measured` has
    /// to exist.
    pub modified: Modified,
}

impl Object {
    /// Describe one index record.
    fn from_record(record: &Record) -> Self {
        Self {
            logical: record.path.clone(),
            size: record.size,
            measured: !(record.size == 0 && record.content_hash.is_empty()),
            modified: record.modified_unix.map_or(Modified::Unknown, Modified::At),
        }
    }
}

/// An unlocked vault, scoped to the tree a restore was pointed at.
pub struct Archive {
    session: Session,
    /// The tree the operand named. Held whole rather than reduced to its prefix
    /// string because the scope rule ([`Target::covers`]) is a method on it, and
    /// a second spelling of that rule is how a restore comes to write
    /// `photos-backup` into a directory prepared for `photos`.
    target: Target,
}

impl std::fmt::Debug for Archive {
    /// Written by hand so the unlocked vault cannot be rendered; see
    /// [`Session`]'s own implementation for why that matters.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Archive")
            .field("remote", &self.session.remote)
            .field("target", &self.target)
            .finish()
    }
}

impl Archive {
    /// Unlock the vault the operand names.
    ///
    /// Once per run, before anything is listed, so a missing password costs one
    /// error rather than one per file.
    ///
    /// # Errors
    /// Whatever [`session::open`] reported: an unresolvable remote
    /// ([`ExitCode::FatalError`]), a missing password
    /// ([`ExitCode::VaultLocked`]), or an envelope that will not unwrap.
    pub async fn open(ctx: &Ctx, target: &Target) -> Result<Self> {
        // The whole spec, never the remote's name on its own: a bare name has
        // no colon and would be re-read as a relative directory of that name.
        let spec = RemoteSpec::Named {
            remote: target.remote.clone(),
            path: target.path.clone(),
        };
        Ok(Self {
            session: session::open(ctx, &spec).await?,
            target: target.clone(),
        })
    }

    /// The vault's name as the audit log spells it.
    ///
    /// The trailing separator is stripped so one remote has one spelling in the
    /// log. A [`Session`] carries the spec as it was typed (`archive:`) while the
    /// removal family carries the parsed name (`archive`), and a compliance query
    /// filtering `remote == archive` must not silently exclude every restore.
    #[must_use]
    pub fn remote(&self) -> &str {
        self.session
            .remote
            .trim_end_matches(crate::constants::REMOTE_SEPARATOR)
    }

    /// Every object under the tree that was named, in path order.
    ///
    /// # Errors
    /// Whatever the index reported while scanning.
    pub fn contents(&self) -> Result<Vec<Object>> {
        let records = self.session.vault.list(&self.target.path)?;
        Ok(records
            .iter()
            // The index matches a prefix by bytes, so listing `photos` also sees
            // `photos-backup`. Comparing whole components is what stops a
            // restore of `photos` from writing a neighbouring tree into the
            // destination the operator prepared for one of them.
            .filter(|record| self.target.covers(&record.path))
            .map(Object::from_record)
            .collect())
    }

    /// Write one object to `destination`, streaming and verified.
    ///
    /// The parent directories are created first, because a vault has no
    /// directories: they exist only as prefixes of object paths, so every one
    /// the destination needs has to be materialised on the way past.
    ///
    /// The recorded modification time is applied **after** the length check, so a
    /// file that failed it is removed rather than stamped. Stamping is the last
    /// thing that happens to a restored file, and it happens to every file that
    /// survives — a restore that returned the bytes but not the dates would hand
    /// back a tree that every later `dctl check` or `dctl copy` reads as entirely
    /// rewritten.
    ///
    /// # Errors
    /// [`ExitCode::IntegrityFailure`] when the object does not authenticate, or
    /// when what landed is not the length the index recorded; whatever the
    /// filesystem reported when a directory could not be created or a timestamp
    /// could not be set; and whatever the provider reported when the object could
    /// not be fetched.
    pub async fn fetch(&self, object: &Object, destination: &Path) -> Result<()> {
        if let Some(parent) = destination.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|error| {
                CliError::from(error)
                    .with_hint(format!("creating {} for the restore", parent.display()))
            })?;
        }

        self.session
            .vault
            .get_file_to_path(&object.logical, destination)
            .await?;

        self.confirm_length(object, destination).await?;
        times::stamp(destination, object.modified).await
    }

    /// Compare what landed against what the catalogue said it would be.
    ///
    /// The core has already proved the object is internally consistent — every
    /// chunk tag, the footer, and the plaintext hash the object carries. What it
    /// cannot prove is that the *index* agrees, and an index that disagrees with
    /// its objects is exactly what a partial rebuild or a restored-from-backup
    /// database looks like. A length mismatch is the cheapest signal of it: it
    /// costs one `stat` and no re-read.
    ///
    /// Rows the index never measured are exempt rather than refused — see
    /// [`Object::measured`]. Refusing them would make `dctl index rebuild`
    /// followed by a restore fail on every single file.
    async fn confirm_length(&self, object: &Object, destination: &Path) -> Result<()> {
        if !object.measured {
            return Ok(());
        }
        let landed = tokio::fs::metadata(destination).await?.len();
        if landed == object.size {
            return Ok(());
        }
        // The file is removed: leaving it would put a wrong-length object under
        // the right name, which is the one outcome worse than failing.
        let _ = tokio::fs::remove_file(destination).await;
        Err(CliError::new(
            ExitCode::IntegrityFailure,
            format!(
                "'{}' restored as {landed} bytes but the index records {}",
                object.logical, object.size
            ),
        )
        .with_hint(
            "The object authenticated against itself, so the index and the store \
             disagree. Run 'dctl index rebuild' against this vault before trusting \
             the restore; nothing was left at the destination for this file.",
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn record(path: &str, size: u64, hash: Vec<u8>) -> Record {
        Record {
            path: path.to_string(),
            object_key: "o/deadbeef".to_string(),
            size,
            modified_unix: None,
            content_hash: hash,
        }
    }

    #[test]
    fn a_written_row_is_measured_even_when_the_file_was_empty() {
        // `blake3::hash(b"")` is a full digest, so an empty file written through
        // the ordinary path is distinguishable from a row nobody measured.
        let empty = Object::from_record(&record(
            "empty.txt",
            0,
            blake3::hash(b"").as_bytes().to_vec(),
        ));
        assert!(empty.measured);
        assert_eq!(empty.size, 0);
    }

    #[test]
    fn a_rebuilt_row_is_not_mistaken_for_an_empty_file() {
        // `dctl index rebuild` writes size 0 and an empty hash. Treating that as
        // fact would make a plan understate the restore and the length check
        // refuse every object.
        let rebuilt = Object::from_record(&record("a.txt", 0, Vec::new()));
        assert!(!rebuilt.measured);
    }

    #[test]
    fn an_ordinary_row_carries_its_recorded_size() {
        let object = Object::from_record(&record(
            "photos/a.jpg",
            4096,
            blake3::hash(b"x").as_bytes().to_vec(),
        ));
        assert_eq!(object.logical, "photos/a.jpg");
        assert_eq!(object.size, 4096);
        assert!(object.measured);
    }
}
