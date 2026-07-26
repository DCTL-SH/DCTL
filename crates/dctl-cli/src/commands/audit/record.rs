//! One entry in the tamper-evident audit log, and the bytes its hash covers.
//!
//! `PLAN.md` §7 requires an append-only, hash-chained record of every operation:
//! timestamp, files, plaintext and ciphertext hashes, sizes, provider, result,
//! each entry carrying the previous entry's hash. This module is the CLI's
//! reader for that record — the shape it expects on disk, and the exact byte
//! string a record's own hash is computed over.
//!
//! ## The canonical form is the contract
//!
//! A chain is only evidence if two implementations agree, byte for byte, on what
//! is hashed. Serialising the JSON and hashing *that* would not do: JSON object
//! key order, whitespace and number formatting are all free choices, so a
//! re-serialisation could differ from what the writer hashed and every record
//! would look forged. So the hash covers an explicit, ordered, separator-joined
//! string built by [`AuditRecord::canonical`] — one field per position, always
//! the same order, joined by a control character no field is allowed to contain
//! ([`AUDIT_HASH_FIELD_SEPARATOR`]).
//!
//! That separator choice is the anti-forgery property. If a path could contain
//! the separator, a record with path `a` and op `b` would hash identically to
//! one with path `a␟b` and an empty op — and an attacker who can choose a
//! filename could rewrite history without breaking the chain. Control characters
//! are rejected everywhere by [`crate::platform::names`], so no field value can
//! reach across a boundary.
//!
//! ## What this cannot detect
//!
//! Truncation of the tail. Removing the last *n* records leaves a chain that
//! verifies perfectly, because nothing inside the log attests to its own length.
//! Detecting that needs an anchor kept somewhere the writer cannot reach — the
//! encrypted remote mirror §7 mentions, or a periodically published head hash.
//! Saying so here is deliberate: an evidence tool that overstates what it proves
//! is worse than one that proves less.

use serde::{Deserialize, Serialize};

use crate::constants::{AUDIT_HASH_DISPLAY_LEN, AUDIT_HASH_FIELD_SEPARATOR, HASH_HEX_LEN_BLAKE3};

/// One append-only audit entry.
///
/// Optional fields default rather than failing to parse: an operation with no
/// path (`dctl init`) or no plaintext hash (a delete) is a perfectly ordinary
/// record, and a reader that refused it could not verify a real log.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct AuditRecord {
    /// Position in the chain, dense and ascending from
    /// [`crate::constants::AUDIT_CHAIN_FIRST_INDEX`].
    pub index: u64,
    /// When the operation completed, RFC 3339 in UTC.
    pub time: String,
    /// The command that ran, using [`crate::cli::Command::name`]'s vocabulary.
    pub op: String,
    /// How it ended: the slug from [`crate::exit::ExitCode`].
    pub result: String,
    /// Logical vault path the operation touched.
    #[serde(default)]
    pub path: String,
    /// Plaintext size in bytes.
    #[serde(default)]
    pub size: u64,
    /// BLAKE3 of the plaintext, hex.
    #[serde(default)]
    pub plaintext_hash: String,
    /// BLAKE3 of the stored ciphertext, hex.
    #[serde(default)]
    pub ciphertext_hash: String,
    /// Remote the operation was against.
    #[serde(default)]
    pub remote: String,
    /// Hash of the *previous* record — the link that makes the log a chain.
    pub prev: String,
    /// This record's own hash, over [`AuditRecord::canonical`].
    pub hash: String,
}

impl AuditRecord {
    /// The exact byte string this record's hash covers.
    ///
    /// `prev` is included, which is what chains the records: changing any
    /// earlier record changes its hash, which changes this record's `prev`,
    /// which changes this record's hash, all the way to the head. An attacker
    /// who edits one entry has to re-derive every entry after it.
    #[must_use]
    pub fn canonical(&self) -> String {
        // Built as an explicit ordered list rather than a format string: the
        // order *is* the contract, and a list makes an accidental reordering or
        // omission visible at a glance.
        let index = self.index.to_string();
        let size = self.size.to_string();
        let separator = AUDIT_HASH_FIELD_SEPARATOR.to_string();

        [
            self.prev.as_str(),
            index.as_str(),
            self.time.as_str(),
            self.op.as_str(),
            self.result.as_str(),
            self.path.as_str(),
            size.as_str(),
            self.plaintext_hash.as_str(),
            self.ciphertext_hash.as_str(),
            self.remote.as_str(),
        ]
        .join(separator.as_str())
    }

    /// The hash this record *should* carry, recomputed from its content.
    #[must_use]
    pub fn computed_hash(&self) -> String {
        blake3::hash(self.canonical().as_bytes())
            .to_hex()
            .to_string()
    }

    /// The leading characters of the stored hash, for a listing.
    ///
    /// A prefix, never the whole value: a listing has not verified anything, and
    /// showing a full-width hash would invite a reader to believe it had.
    #[must_use]
    pub fn short_hash(&self) -> &str {
        let end = self
            .hash
            .char_indices()
            .nth(AUDIT_HASH_DISPLAY_LEN)
            .map_or(self.hash.len(), |(index, _)| index);
        &self.hash[..end]
    }
}

/// Whether a string is a well-formed chain hash.
///
/// Length is checked as well as the alphabet. A truncated hash must be reported
/// as a malformed record rather than compared: a prefix comparison would let
/// `"aa"` pass as equal to a hash starting `aa`, which is exactly the forgery
/// the chain exists to prevent.
#[must_use]
pub fn is_well_formed_hash(value: &str) -> bool {
    value.len() == HASH_HEX_LEN_BLAKE3 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::constants::AUDIT_CHAIN_GENESIS_PREV;

    fn record() -> AuditRecord {
        AuditRecord {
            index: 0,
            time: "2026-07-26T14:30:00Z".into(),
            op: "copy".into(),
            result: "success".into(),
            path: "photos/2024/a.jpg".into(),
            size: 1024,
            plaintext_hash: "aa".repeat(32),
            ciphertext_hash: "bb".repeat(32),
            remote: "vault".into(),
            prev: AUDIT_CHAIN_GENESIS_PREV.into(),
            hash: String::new(),
        }
    }

    fn sealed() -> AuditRecord {
        let mut record = record();
        record.hash = record.computed_hash();
        record
    }

    /// A single-field edit, used to prove the hash covers that field.
    type Mutation = Box<dyn Fn(&mut AuditRecord)>;

    #[test]
    fn a_records_hash_covers_every_field() {
        // Any change to any field must change the hash, or that field could be
        // rewritten without breaking the chain.
        let baseline = record().computed_hash();

        let mutations: Vec<Mutation> = vec![
            Box::new(|r| r.index += 1),
            Box::new(|r| r.time.push('!')),
            Box::new(|r| r.op = "delete".into()),
            Box::new(|r| r.result = "partial_failure".into()),
            Box::new(|r| r.path = "photos/2024/b.jpg".into()),
            Box::new(|r| r.size += 1),
            Box::new(|r| r.plaintext_hash = "cc".repeat(32)),
            Box::new(|r| r.ciphertext_hash = "dd".repeat(32)),
            Box::new(|r| r.remote = "backup".into()),
            Box::new(|r| r.prev = "ee".repeat(32)),
        ];

        for (position, mutate) in mutations.iter().enumerate() {
            let mut mutated = record();
            mutate(&mut mutated);
            assert_ne!(
                mutated.computed_hash(),
                baseline,
                "field {position} is outside the hash"
            );
        }
    }

    #[test]
    fn the_hash_is_stable_across_recomputation() {
        let record = record();
        assert_eq!(record.computed_hash(), record.computed_hash());
        assert_eq!(record.computed_hash().len(), HASH_HEX_LEN_BLAKE3);
        assert!(is_well_formed_hash(&record.computed_hash()));
    }

    #[test]
    fn a_field_cannot_reach_across_a_separator() {
        // The forgery this blocks: moving text from one field into the next so
        // two different records serialise to the same bytes.
        let mut shifted = record();
        shifted.op = format!("copy{AUDIT_HASH_FIELD_SEPARATOR}success");
        shifted.result = String::new();
        assert_ne!(shifted.computed_hash(), record().computed_hash());
        // And the separator itself is a character no legal path may contain.
        assert!(AUDIT_HASH_FIELD_SEPARATOR.is_control());
    }

    #[test]
    fn the_canonical_form_lists_every_field_once() {
        let canonical = record().canonical();
        let fields: Vec<&str> = canonical.split(AUDIT_HASH_FIELD_SEPARATOR).collect();
        assert_eq!(fields.len(), 10, "prev + 9 record fields");
        assert_eq!(fields[0], AUDIT_CHAIN_GENESIS_PREV);
        assert_eq!(fields[1], "0");
        assert_eq!(fields.last(), Some(&"vault"));
    }

    #[test]
    fn a_short_hash_is_a_prefix_and_never_the_whole_thing() {
        let sealed = sealed();
        assert_eq!(sealed.short_hash().len(), AUDIT_HASH_DISPLAY_LEN);
        assert!(sealed.hash.starts_with(sealed.short_hash()));
        assert!(sealed.short_hash().len() < HASH_HEX_LEN_BLAKE3);
    }

    #[test]
    fn a_short_hash_of_a_truncated_value_does_not_panic() {
        // A malformed log must produce a report, never a crash.
        let mut broken = record();
        broken.hash = "abc".into();
        assert_eq!(broken.short_hash(), "abc");
        broken.hash = String::new();
        assert_eq!(broken.short_hash(), "");
    }

    #[test]
    fn malformed_hashes_are_rejected_by_shape() {
        assert!(is_well_formed_hash(&"0".repeat(HASH_HEX_LEN_BLAKE3)));
        assert!(is_well_formed_hash(AUDIT_CHAIN_GENESIS_PREV));
        // Too short: a prefix must never be accepted as a hash.
        assert!(!is_well_formed_hash("aa"));
        // Too long, and non-hex.
        assert!(!is_well_formed_hash(&"0".repeat(HASH_HEX_LEN_BLAKE3 + 1)));
        assert!(!is_well_formed_hash(&"z".repeat(HASH_HEX_LEN_BLAKE3)));
        assert!(!is_well_formed_hash(""));
    }

    #[test]
    fn optional_fields_default_rather_than_failing_to_parse() {
        // `dctl init` touches no path and hashes no plaintext; a reader that
        // refused such a record could not verify a real log.
        let json = r#"{"index":0,"time":"t","op":"init","result":"success",
                       "prev":"00","hash":"11"}"#;
        let record: AuditRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.path, "");
        assert_eq!(record.size, 0);
        assert_eq!(record.op, "init");
    }

    #[test]
    fn a_record_round_trips_through_json() {
        let sealed = sealed();
        let json = serde_json::to_string(&sealed).unwrap();
        let parsed: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, sealed);
        assert_eq!(parsed.computed_hash(), sealed.hash);
    }
}
