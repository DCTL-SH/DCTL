//! Walking the hash chain, and saying exactly where it breaks.
//!
//! This is the evidence half of `PLAN.md` §7. Every record carries the previous
//! record's hash, so the log can only be appended to: editing an entry changes
//! its hash, which orphans the entry after it, and re-deriving the rest of the
//! chain is the work an attacker would have to do — and would still leave the
//! head hash different from whatever was published or mirrored.
//!
//! **A break is a security event, not a parse error.** The walk therefore stops
//! at the first one and reports the *exact position*: which record, what was
//! expected, what was found, and which of the four ways a chain can fail it was.
//! "The audit log is corrupt" is not an answer anybody can investigate; "record
//! 4 991 links to a hash no record produces" is.
//!
//! The walk stops rather than continuing because everything after a break is
//! unattested: once one link is wrong, the records beyond it prove nothing about
//! themselves, and listing them as "also broken" would bury the one position
//! that matters under thousands that do not.
//!
//! Four failure modes, checked in a deliberate order per record:
//!
//! 1. **Malformed** — a hash that is not a full-width hex value. Checked first,
//!    because comparing a truncated hash could accidentally succeed.
//! 2. **Index discontinuity** — a gap or a repeat, which is what a *deleted*
//!    record leaves behind even if someone re-linked the survivors.
//! 3. **Broken link** — `prev` does not match the previous record's hash: a
//!    record was removed, reordered, or inserted.
//! 4. **Content mismatch** — the record's own hash does not match its content:
//!    a field was edited in place.
//!
//! Link before content, because a removal is the more precise diagnosis: a
//! re-hashed forgery shows up as a link break at the *following* record, and
//! reporting "record 42's content was edited" when the truth is "record 41 was
//! deleted" would send an investigator to the wrong place.

use std::fmt;

use serde::Serialize;

use crate::constants::{AUDIT_CHAIN_FIRST_INDEX, AUDIT_CHAIN_GENESIS_PREV};

use super::record::{AuditRecord, is_well_formed_hash};

/// Names of the two hash-bearing fields, spelled exactly as the record spells
/// them, so a `MalformedHash` report can be matched against the file by eye.
const FIELD_PREV: &str = "prev";
/// See [`FIELD_PREV`].
const FIELD_HASH: &str = "hash";

/// How a chain failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BreakKind {
    /// A hash field is not a full-width hex value.
    MalformedHash {
        /// Which field: `hash` or `prev`.
        field: &'static str,
        /// What was stored there.
        value: String,
    },
    /// The record's position in the chain is not the one its index claims.
    IndexDiscontinuity { expected: u64, found: u64 },
    /// `prev` does not name the preceding record's hash.
    BrokenLink { expected: String, found: String },
    /// The record's own hash does not match its content.
    ContentMismatch { expected: String, found: String },
}

impl fmt::Display for BreakKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedHash { field, value } => write!(
                f,
                "the '{field}' field is not a chain hash (found '{value}')"
            ),
            Self::IndexDiscontinuity { expected, found } => write!(
                f,
                "expected index {expected}, found {found} — a record was removed or reordered"
            ),
            Self::BrokenLink { expected, found } => write!(
                f,
                "links to {found}, but the preceding record hashes to {expected} — \
                 a record was removed, reordered or inserted"
            ),
            Self::ContentMismatch { expected, found } => write!(
                f,
                "carries hash {found}, but its content hashes to {expected} — \
                 the record was edited in place"
            ),
        }
    }
}

/// Where and how the chain failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Break {
    /// Zero-based position in the chain. **This is the number to investigate**;
    /// it is the position in the file, not a value the log itself supplied, so a
    /// forged index cannot move it.
    pub position: usize,
    /// One-based line in the log file, since the log is one record per line and
    /// that is what an editor will show.
    pub line: usize,
    /// The index the record claims for itself, which may be part of the forgery.
    pub claimed_index: u64,
    /// What went wrong.
    #[serde(flatten)]
    pub kind: BreakKind,
}

impl fmt::Display for Break {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "audit chain broken at record {} (line {}): {}",
            self.position, self.line, self.kind
        )
    }
}

/// A chain that verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Verified {
    /// How many records were walked.
    pub records: usize,
    /// The hash of the last record — the value to compare against an anchor
    /// kept outside the log, which is the only way to detect truncation.
    pub head: String,
}

/// Walk the chain.
///
/// # Errors
/// Returns the first [`Break`]. An empty log verifies: it is a log to which
/// nothing has been appended, which is a different claim from "nothing
/// happened" — see the truncation note in [`super::record`].
pub fn verify(records: &[AuditRecord]) -> Result<Verified, Break> {
    let mut previous_hash = AUDIT_CHAIN_GENESIS_PREV.to_string();

    for (position, record) in records.iter().enumerate() {
        let at = |kind| Break {
            position,
            line: position + 1,
            claimed_index: record.index,
            kind,
        };

        // 1. Shape first: a truncated hash must never reach a comparison.
        for (field, value) in [(FIELD_PREV, &record.prev), (FIELD_HASH, &record.hash)] {
            if !is_well_formed_hash(value) {
                return Err(at(BreakKind::MalformedHash {
                    field,
                    value: value.clone(),
                }));
            }
        }

        // 2. A deleted record leaves a gap even when the survivors are re-linked.
        let expected_index = AUDIT_CHAIN_FIRST_INDEX.saturating_add(position as u64);
        if record.index != expected_index {
            return Err(at(BreakKind::IndexDiscontinuity {
                expected: expected_index,
                found: record.index,
            }));
        }

        // 3. The link itself.
        if !record.prev.eq_ignore_ascii_case(&previous_hash) {
            return Err(at(BreakKind::BrokenLink {
                expected: previous_hash,
                found: record.prev.clone(),
            }));
        }

        // 4. And finally the content the hash claims to cover.
        let computed = record.computed_hash();
        if !record.hash.eq_ignore_ascii_case(&computed) {
            return Err(at(BreakKind::ContentMismatch {
                expected: computed,
                found: record.hash.clone(),
            }));
        }

        previous_hash = record.hash.clone();
    }

    Ok(Verified {
        records: records.len(),
        head: previous_hash,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::constants::HASH_HEX_LEN_BLAKE3;

    /// Build a sealed chain of `count` records, each correctly linked.
    ///
    /// `upper` writes the hex in upper case, which a conforming writer is
    /// entitled to do — note that it seals each record over the upper-case
    /// `prev` it actually stores, because the hash covers the stored bytes.
    fn chain_with(count: u64, upper: bool) -> Vec<AuditRecord> {
        let mut records = Vec::new();
        let mut previous = AUDIT_CHAIN_GENESIS_PREV.to_string();

        for index in 0..count {
            let mut record = AuditRecord {
                index,
                time: format!("2026-07-26T00:00:{index:02}Z"),
                op: "copy".into(),
                result: "success".into(),
                path: format!("photos/{index}.jpg"),
                size: 1000 + index,
                plaintext_hash: "aa".repeat(32),
                ciphertext_hash: "bb".repeat(32),
                remote: "vault".into(),
                prev: previous.clone(),
                hash: String::new(),
            };
            record.hash = if upper {
                record.computed_hash().to_uppercase()
            } else {
                record.computed_hash()
            };
            previous.clone_from(&record.hash);
            records.push(record);
        }
        records
    }

    fn chain(count: u64) -> Vec<AuditRecord> {
        chain_with(count, false)
    }

    #[test]
    fn an_intact_chain_verifies_and_reports_its_head() {
        let records = chain(5);
        let verified = verify(&records).unwrap();
        assert_eq!(verified.records, 5);
        assert_eq!(verified.head, records[4].hash);
        assert_eq!(verified.head.len(), HASH_HEX_LEN_BLAKE3);
    }

    #[test]
    fn an_empty_chain_verifies_with_the_genesis_head() {
        // Nothing has been appended. That is a different claim from "nothing
        // happened", and the module docs say so out loud.
        let verified = verify(&[]).unwrap();
        assert_eq!(verified.records, 0);
        assert_eq!(verified.head, AUDIT_CHAIN_GENESIS_PREV);
    }

    #[test]
    fn the_first_record_must_link_to_the_genesis_value() {
        // A genesis record that links elsewhere is a chain with its head cut off.
        let mut records = chain(3);
        records[0].prev = "cc".repeat(32);
        records[0].hash = records[0].computed_hash();

        let broken = verify(&records).unwrap_err();
        assert_eq!(broken.position, 0);
        assert!(matches!(broken.kind, BreakKind::BrokenLink { .. }));
    }

    #[test]
    fn an_edited_record_is_reported_at_its_own_position() {
        let mut records = chain(6);
        // Someone changes what a copy claims to have copied, and does not
        // re-hash it.
        records[3].path = "photos/forged.jpg".into();

        let broken = verify(&records).unwrap_err();
        assert_eq!(broken.position, 3, "the exact record must be named");
        assert_eq!(broken.line, 4);
        assert_eq!(broken.claimed_index, 3);
        assert!(matches!(broken.kind, BreakKind::ContentMismatch { .. }));
        assert!(broken.to_string().contains("record 3"));
    }

    #[test]
    fn a_re_hashed_forgery_is_caught_at_the_following_record() {
        // The attacker edits record 2 *and* re-hashes it, which is what a naive
        // "does each record hash to its content" check would miss entirely.
        let mut records = chain(6);
        records[2].path = "photos/forged.jpg".into();
        records[2].hash = records[2].computed_hash();

        let broken = verify(&records).unwrap_err();
        assert_eq!(broken.position, 3, "the orphan is the evidence");
        assert!(matches!(broken.kind, BreakKind::BrokenLink { .. }));
    }

    #[test]
    fn a_deleted_record_is_reported_as_a_discontinuity() {
        // Removing an entry leaves a gap in the indices even before the link is
        // examined, and the gap is the more precise diagnosis.
        let mut records = chain(6);
        records.remove(2);

        let broken = verify(&records).unwrap_err();
        assert_eq!(broken.position, 2);
        assert_eq!(
            broken.kind,
            BreakKind::IndexDiscontinuity {
                expected: 2,
                found: 3
            }
        );
    }

    #[test]
    fn reordered_records_are_caught() {
        let mut records = chain(6);
        records.swap(1, 4);

        let broken = verify(&records).unwrap_err();
        assert_eq!(broken.position, 1);
        assert!(matches!(broken.kind, BreakKind::IndexDiscontinuity { .. }));
    }

    #[test]
    fn a_truncated_hash_is_malformed_rather_than_compared() {
        // The bug this prevents: a prefix comparison quietly succeeding.
        let mut records = chain(3);
        records[1].hash.truncate(8);

        let broken = verify(&records).unwrap_err();
        assert_eq!(broken.position, 1);
        assert!(matches!(
            broken.kind,
            BreakKind::MalformedHash { field: "hash", .. }
        ));
    }

    #[test]
    fn a_malformed_link_names_the_prev_field() {
        let mut records = chain(3);
        records[2].prev = "not-a-hash".into();

        let broken = verify(&records).unwrap_err();
        assert!(matches!(
            broken.kind,
            BreakKind::MalformedHash { field: "prev", .. }
        ));
    }

    #[test]
    fn hash_comparison_is_case_insensitive() {
        // Hex has two spellings and a writer may legitimately choose either;
        // rejecting upper case would report a break where there is none.
        let records = chain_with(4, true);
        let verified = verify(&records).unwrap();
        assert_eq!(verified.records, 4);
        assert_eq!(verified.head, records[3].hash);
        assert_eq!(verified.head, verified.head.to_uppercase());
    }

    #[test]
    fn the_walk_stops_at_the_first_break() {
        // Everything past a break is unattested; listing it would bury the one
        // position that matters.
        let mut records = chain(10);
        records[2].path = "forged".into();
        records[7].path = "also forged".into();

        let broken = verify(&records).unwrap_err();
        assert_eq!(broken.position, 2);
    }

    #[test]
    fn a_break_serialises_with_its_kind_inlined() {
        let mut records = chain(3);
        records[1].path = "forged".into();
        let broken = verify(&records).unwrap_err();

        let json = serde_json::to_string(&broken).unwrap();
        // A machine consumer must be able to branch on the kind and read the
        // position without unwrapping a nested object.
        assert!(json.contains("\"position\":1"), "{json}");
        assert!(json.contains("\"kind\":\"content-mismatch\""), "{json}");
    }
}
