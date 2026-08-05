//! Asking a store, without a key, whether it already holds a vault.
//!
//! One question, two callers, and both of them need the answer *before* they do
//! anything irreversible:
//!
//! * `dctl init` must not write an envelope over one that is already there.
//!   Replacing an envelope replaces the root key, and every object stored under
//!   the old one becomes permanently unreadable while the provider keeps billing
//!   for the bytes. That is the single most expensive mistake this CLI can make,
//!   and until this module existed the command could only *warn* that it had not
//!   checked.
//! * `dctl config import` must confirm that the location it is being asked to
//!   address really is a vault's store. Writing a plausible-looking pair of
//!   remotes for an empty bucket would hand an operator addressing for data that
//!   is not there — the exact "reported as done when it did not happen" failure
//!   [the plan](https://doc.dctl.sh/project/plan) §6 forbids, in the one command people reach for when something
//!   has already gone wrong.
//!
//! ## Key-free by construction
//!
//! Nothing here can decrypt anything, and that is what makes it usable at these
//! two moments: both run before any password exists. Recognition reads the first
//! [`VAULT_ENVELOPE_HEADER_LEN`] bytes of the envelope object — magic, version
//! and slot count, the fields `crates/dctl-decode/FORMAT.md` §2 freezes — and stops. The
//! wrapped root key sits a few bytes further on and is never fetched, never held
//! and never logged.
//!
//! The read is a **ranged** GET, not a whole-object one. Against a cloud
//! provider that is one small request rather than a download of every key slot,
//! and it is the same primitive the streaming-seek path depends on, so a backend
//! that gets it wrong is caught here rather than in the middle of a restore.
//!
//! ## Absence is a claim, and claims can fail
//!
//! [`Verdict::Absent`] is only ever returned for a store that answered "there is
//! no such object". A permission error, a timeout or a misconfigured endpoint is
//! propagated, never folded into "no vault here": a probe that reported absence
//! because it could not look would send `dctl init` straight into overwriting
//! the envelope it failed to see.

use std::sync::Arc;

use dctl_store::{Backend, ByteRange, ObjectKey, StoreError};

use crate::constants::{
    VAULT_ENVELOPE_HEADER_LEN, VAULT_ENVELOPE_MAGIC, VAULT_ENVELOPE_MAX_SLOTS,
    VAULT_ENVELOPE_MIN_SLOTS, VAULT_ENVELOPE_OBJECT_KEY, VAULT_ENVELOPE_SLOT_COUNT_OFFSET,
    VAULT_ENVELOPE_VERSION,
};
use crate::error::{CliError, Result};

/// What a store said when asked whether it holds a vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// A `DKE1` envelope of a version this build understands.
    Vault {
        /// Number of key slots the envelope declares.
        ///
        /// Reported rather than merely checked because it is the one fact about
        /// a vault that is both useful and free: it says how many ways there are
        /// to unlock this store — a password, a recovery mnemonic, a device key
        /// — which is what an operator staring at a store they have just found
        /// wants to know first.
        slots: u16,
    },

    /// An envelope object exists, but this build cannot read its version.
    ///
    /// Kept apart from [`Verdict::Absent`] on purpose. "There is a vault here
    /// that I am too old to address" and "there is nothing here" lead to
    /// opposite actions, and conflating them would let an upgrade-shaped problem
    /// end as an overwritten envelope.
    Foreign {
        /// The version byte found, so the message can name it.
        version: u8,
    },

    /// The envelope object is not there.
    Absent,
}

impl Verdict {
    /// Whether a vault occupies this store in any form this build must respect.
    ///
    /// True for [`Verdict::Foreign`] as well as [`Verdict::Vault`]: the guard
    /// this answers for is "would writing here destroy something", and an
    /// envelope DCTL cannot parse is still an envelope somebody's data hangs
    /// off.
    #[must_use]
    pub const fn is_occupied(self) -> bool {
        matches!(self, Self::Vault { .. } | Self::Foreign { .. })
    }
}

/// Ask `backend` whether a vault's envelope sits at the store's root.
///
/// The root, and only the root, because that is where every vault this build
/// creates puts its envelope: `dctl_core::Vault::init` writes to the fixed key
/// and honours no prefix, so `dctl init` and `dctl config import` both refuse a
/// base spec carrying one. The day the engine grows subdirectory support, this
/// signature grows the prefix with it — asking about a place no vault can be is
/// not generality, it is a check that would always answer the same way.
///
/// # Errors
/// Any backend failure other than "no such object", which is
/// [`Verdict::Absent`]. A store that cannot be read is reported as unreadable,
/// because the alternative is claiming a vault is not there when nobody looked.
pub async fn probe(backend: &Arc<dyn Backend>) -> Result<Verdict> {
    let key = ObjectKey::new(VAULT_ENVELOPE_OBJECT_KEY);
    let range = ByteRange::new(0, Some(VAULT_ENVELOPE_HEADER_LEN));

    match backend.get_range(&key, range).await {
        Ok(header) => Ok(classify(&header)),
        Err(StoreError::NotFound(_)) => Ok(Verdict::Absent),
        Err(source) => Err(CliError::from(source).with_hint(format!(
            "DCTL could not read '{VAULT_ENVELOPE_OBJECT_KEY}', so it cannot \
             tell whether a vault is already stored here. Nothing was changed. \
             Check the credentials and the endpoint for this location, then run \
             the command again."
        ))),
    }
}

/// Read a fetched header as a verdict.
///
/// Pure, so the recognition rules — which are the part that can be got wrong —
/// are testable without a backend, a network or a temporary directory.
///
/// A short read is [`Verdict::Absent`] rather than an error. An object at this
/// key too small to hold a header is not an envelope by any reading, and the
/// only thing DCTL could usefully say about it is that there is no vault here.
#[must_use]
fn classify(header: &[u8]) -> Verdict {
    if header.len() < VAULT_ENVELOPE_HEADER_LEN as usize {
        return Verdict::Absent;
    }
    if !header.starts_with(VAULT_ENVELOPE_MAGIC) {
        return Verdict::Absent;
    }

    let version = header[VAULT_ENVELOPE_MAGIC.len()];
    if version != VAULT_ENVELOPE_VERSION {
        return Verdict::Foreign { version };
    }

    // Little-endian: `crates/dctl-decode/FORMAT.md` states it once, at the top, for every
    // multi-byte integer in the format, and the envelope's `slot_count` is no
    // exception. Reading it the other way round turns one slot into 256 and
    // sends the count out of the frozen bounds, so a real vault would be
    // reported as no vault at all — which is exactly the answer that lets
    // `dctl init` overwrite one.
    let slots = u16::from_le_bytes([
        header[VAULT_ENVELOPE_SLOT_COUNT_OFFSET],
        header[VAULT_ENVELOPE_SLOT_COUNT_OFFSET + 1],
    ]);

    // A slot count outside the frozen bounds means the bytes are not an
    // envelope, whatever the first five of them said. Treating one as a vault
    // would have `dctl config import` write addressing for something that can
    // never be unlocked.
    if !(VAULT_ENVELOPE_MIN_SLOTS..=VAULT_ENVELOPE_MAX_SLOTS).contains(&slots) {
        return Verdict::Absent;
    }

    Verdict::Vault { slots }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header as `crates/dctl-decode/FORMAT.md` §2 lays one out.
    fn header(magic: &[u8], version: u8, slots: u16) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(VAULT_ENVELOPE_HEADER_LEN as usize);
        bytes.extend_from_slice(magic);
        bytes.push(version);
        bytes.extend_from_slice(&[0x11; 16]); // vault_id
        bytes.extend_from_slice(&slots.to_le_bytes());
        bytes
    }

    #[test]
    fn a_real_header_is_recognised_and_reports_its_slots() {
        assert_eq!(
            classify(&header(VAULT_ENVELOPE_MAGIC, VAULT_ENVELOPE_VERSION, 3)),
            Verdict::Vault { slots: 3 }
        );
        assert_eq!(
            classify(&header(
                VAULT_ENVELOPE_MAGIC,
                VAULT_ENVELOPE_VERSION,
                VAULT_ENVELOPE_MAX_SLOTS
            )),
            Verdict::Vault {
                slots: VAULT_ENVELOPE_MAX_SLOTS
            }
        );
    }

    #[test]
    fn something_that_is_not_an_envelope_is_not_a_vault() {
        // A file that happens to sit at the envelope's key. Recognising it as a
        // vault would make `config import` write addressing for nothing.
        assert_eq!(classify(&header(b"ZIP0", 1, 1)), Verdict::Absent);
        assert_eq!(classify(b""), Verdict::Absent);
        assert_eq!(
            classify(b"DKE1"),
            Verdict::Absent,
            "a short read is not one"
        );
    }

    #[test]
    fn a_slot_count_outside_the_frozen_bounds_is_rejected() {
        // The bound is what separates "four plausible bytes" from an envelope.
        assert_eq!(
            classify(&header(VAULT_ENVELOPE_MAGIC, VAULT_ENVELOPE_VERSION, 0)),
            Verdict::Absent
        );
        assert_eq!(
            classify(&header(
                VAULT_ENVELOPE_MAGIC,
                VAULT_ENVELOPE_VERSION,
                VAULT_ENVELOPE_MAX_SLOTS + 1
            )),
            Verdict::Absent
        );
    }

    #[test]
    fn a_newer_envelope_is_a_vault_this_build_cannot_address() {
        // The distinction that keeps an upgrade problem from becoming a data
        // loss: `Foreign` still counts as occupied.
        let verdict = classify(&header(VAULT_ENVELOPE_MAGIC, VAULT_ENVELOPE_VERSION + 1, 1));
        assert_eq!(
            verdict,
            Verdict::Foreign {
                version: VAULT_ENVELOPE_VERSION + 1
            }
        );
        assert!(verdict.is_occupied());
        assert!(Verdict::Vault { slots: 1 }.is_occupied());
        assert!(!Verdict::Absent.is_occupied());
    }

    #[tokio::test]
    async fn a_real_store_on_disk_answers_both_ways() {
        // End to end against the one backend a test can build without
        // credentials: an empty directory holds no vault, and one holding an
        // envelope does. This is the assertion that catches a probe looking
        // under the wrong key, which no amount of `classify` testing would.
        let dir = tempfile::tempdir().expect("temp dir");
        let backend: Arc<dyn Backend> =
            Arc::new(dctl_store::LocalFs::new(dir.path().to_path_buf()));

        assert_eq!(
            probe(&backend).await.expect("an empty store must answer"),
            Verdict::Absent
        );

        let system = dir.path().join("system");
        std::fs::create_dir_all(&system).expect("system dir");
        std::fs::write(
            system.join("envelope.bin"),
            header(VAULT_ENVELOPE_MAGIC, VAULT_ENVELOPE_VERSION, 2),
        )
        .expect("envelope");

        assert_eq!(
            probe(&backend).await.expect("a store with a vault"),
            Verdict::Vault { slots: 2 }
        );
    }
}
