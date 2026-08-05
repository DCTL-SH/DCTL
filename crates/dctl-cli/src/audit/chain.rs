//! The hash-chain rule: how an entry's hash is computed, and how a chain is
//! walked and verified.
//!
//! This is the evidence half of [the plan](https://doc.dctl.sh/project/plan) §7,
//! and the only place in DCTL that decides what a record's hash *means*. The
//! writer seals a record here and the reader checks it here, against the same
//! function — two implementations of a rule that must round-trip is how a log
//! becomes unverifiable.
//!
//! ## The canonical form is the contract
//!
//! A chain is only evidence if two implementations agree, byte for byte, on what
//! is hashed. Serialising the JSON and hashing *that* would not do: JSON object
//! key order, whitespace and number formatting are all free choices, so a
//! re-serialisation could differ from what the writer hashed and every record
//! would look forged. So the hash covers an explicit, ordered,
//! separator-joined string built by [`canonical`] — one field per position,
//! always the same order, joined by a control character no field is allowed to
//! contain ([`AUDIT_HASH_FIELD_SEPARATOR`]).
//!
//! That separator choice is the anti-forgery property. If a path could contain
//! the separator, a record with path `a` and op `b` would hash identically to
//! one with path `a␟b` and an empty op — and an attacker who can choose a
//! filename could rewrite history without breaking the chain. Control characters
//! are rejected by `crate::platform::names` and escaped unconditionally by
//! [`super::redaction`], so no field value can reach across a boundary.
//!
//! ## A break is a security event, not a parse error
//!
//! The walk stops at the first one and reports the *exact position*: which
//! record, what was expected, what was found, and which of the four ways a chain
//! can fail it was. "The audit log is corrupt" is not an answer anybody can
//! investigate; "record 4 991 links to a hash no record produces" is.
//!
//! The walk stops rather than continuing because everything after a break is
//! unattested: once one link is wrong, the records beyond it prove nothing about
//! themselves, and listing them as "also broken" would bury the one position
//! that matters under thousands that do not.
//!
//! Five failure modes, checked in a deliberate order per record:
//!
//! 1. **Malformed** — a hash that is not a full-width hex value. Checked first,
//!    because comparing a truncated hash could accidentally succeed.
//! 2. **Unsupported version** — a record from a schema this build does not know.
//!    Checked before anything is hashed, because the version *chooses* which
//!    bytes get hashed and guessing would report a perfectly good record as a
//!    forgery.
//! 3. **Index discontinuity** — a gap or a repeat, which is what a *deleted*
//!    record leaves behind even if someone re-linked the survivors.
//! 4. **Broken link** — `prev` does not match the previous record's hash: a
//!    record was removed, reordered, or inserted.
//! 5. **Content mismatch** — the record's own hash does not match its content:
//!    a field was edited in place.
//!
//! Link before content, because a removal is the more precise diagnosis: a
//! re-hashed forgery shows up as a link break at the *following* record, and
//! reporting "record 42's content was edited" when the truth is "record 41 was
//! deleted" would send an investigator to the wrong place.
//!
//! ## Two schemas, one chain
//!
//! A hash-chained log cannot be rewritten in place: changing one record's bytes
//! changes its hash and orphans everything after it. So when the record schema
//! grew a direction and a real byte count
//! ([the audit-log reference](https://doc.dctl.sh/reference/audit-log) §2.1),
//! the records already on disk stayed exactly as they were, and [`canonical`]
//! became a function of the record's **own** version rather than of the file's.
//! A log written across an upgrade holds v1 records followed by v2 records, links
//! across the boundary, and verifies end to end — which is the only acceptable
//! answer, because the alternative is a product that invalidates its customers'
//! evidence at every release.
//!
//! ## What this cannot detect, and the module that can
//!
//! Truncation of the tail. Removing the last *n* records leaves a chain that
//! verifies perfectly, because nothing inside the log attests to its own length
//! — and the records an attacker most wants gone are the most recent ones. No
//! amount of care in this module changes that: everything it checks lives inside
//! the file, and whoever can cut the tail can cut whatever the tail said about
//! itself.
//!
//! [`super::anchor`] is the half that closes it, by comparing the chain against
//! a value recorded somewhere the writer cannot reach. That is why [`Verified`]
//! reports the record count and the head rather than only a verdict: those two
//! numbers *are* the anchor. `dctl audit head` prints one and `dctl audit verify
//! --expect-head` checks one, at exit 26.
//!
//! Saying so here is deliberate: an evidence tool that overstates what it proves
//! is worse than one that proves less, and a `verify` with no anchor is making a
//! claim about content, not about length.

use std::fmt;

use serde::Serialize;

use crate::constants::{
    AUDIT_CHAIN_FIRST_INDEX, AUDIT_CHAIN_GENESIS_PREV, AUDIT_HASH_FIELD_SEPARATOR,
    AUDIT_RECORD_VERSION, AUDIT_RECORD_VERSION_LEGACY,
};

use super::record::{AuditRecord, Entry, is_well_formed_hash};

/// Names of the two hash-bearing fields, spelled exactly as the record spells
/// them, so a `MalformedHash` report can be matched against the file by eye.
const FIELD_PREV: &str = "prev";
/// See [`FIELD_PREV`].
const FIELD_HASH: &str = "hash";

/// The exact byte string a record's hash covers, chosen by the record's own
/// schema version.
///
/// `prev` is included, and comes first among the v1 fields, which is what chains
/// the records: changing any earlier record changes its hash, which changes this
/// record's `prev`, which changes this record's hash, all the way to the head. An
/// attacker who edits one entry has to re-derive every entry after it.
///
/// Both field orders are a **frozen wire contract** — they are specified in
/// [the audit-log reference](https://doc.dctl.sh/reference/audit-log) §3 so that
/// a chain can be verified in twenty years with a short script and no DCTL
/// binary. Reordering either, or inserting a field into either, would invalidate
/// every chain ever written.
///
/// The v2 form is the v1 form with the version in front of it and the three new
/// values behind it:
///
/// ```text
/// v1:            prev ␟ index ␟ … ␟ remote
/// v2:  v ␟ prev ␟ index ␟ … ␟ remote ␟ direction ␟ bytes ␟ objects
/// ```
///
/// The ten v1 values are byte-identical in the middle of the v2 string. That is
/// worth having: a reader can see at a glance that v2 did not *redefine* any v1
/// field, only bracket them — and `size` in particular still means exactly what
/// it always meant.
///
/// Including `v` in the preimage is what stops the version being switched. Strip
/// `v: 2` from a v2 record and a reader computes the v1 string, which hashes to
/// something else; add `v: 2` to a v1 record and the same happens in reverse.
/// Both are reported as a content mismatch, which is what they are.
///
/// A version this build does not know never reaches here — [`verify`] refuses it
/// first, because a canonical form guessed from the wrong schema would report a
/// perfectly good record as a forgery.
#[must_use]
pub fn canonical(record: &AuditRecord) -> String {
    // Built as explicit ordered lists rather than format strings: the order *is*
    // the contract, and a list makes an accidental reordering or omission visible
    // at a glance.
    let index = record.index.to_string();
    let size = record.size.to_string();
    let separator = AUDIT_HASH_FIELD_SEPARATOR.to_string();

    let v1 = [
        record.prev.as_str(),
        index.as_str(),
        record.time.as_str(),
        record.op.as_str(),
        record.result.as_str(),
        record.path.as_str(),
        size.as_str(),
        record.plaintext_hash.as_str(),
        record.ciphertext_hash.as_str(),
        record.remote.as_str(),
    ];

    if record.version() == AUDIT_RECORD_VERSION_LEGACY {
        return v1.join(separator.as_str());
    }

    let version = record.version().to_string();
    let bytes = record.bytes.to_string();
    let objects = record.objects.to_string();

    let mut fields: Vec<&str> = Vec::with_capacity(v1.len() + 4);
    fields.push(version.as_str());
    fields.extend_from_slice(&v1);
    fields.push(record.direction.as_str());
    fields.push(bytes.as_str());
    fields.push(objects.as_str());
    fields.join(separator.as_str())
}

/// The hash a record *should* carry, recomputed from its content.
///
/// Lower-case hex. A conforming writer may spell it either way — comparisons in
/// [`verify`] are case-insensitive — but DCTL writes one spelling so that two
/// records with identical content are byte-identical on disk.
#[must_use]
pub fn compute_hash(record: &AuditRecord) -> String {
    blake3::hash(canonical(record).as_bytes())
        .to_hex()
        .to_string()
}

/// Place an entry at `index`, link it to `previous`, and seal it.
///
/// This is the *only* way a record acquires its position and its hash. The
/// caller supplies what happened; the chain supplies where it happened and what
/// attests to it — see [`super::record::Entry`] for why those are kept apart.
/// Every record this build seals carries [`AUDIT_RECORD_VERSION`], because a
/// writer that could choose its own schema could write a record no reader knows
/// how to hash.
#[must_use]
pub fn seal(entry: &Entry, index: u64, previous: &str) -> AuditRecord {
    let mut record = AuditRecord {
        v: Some(AUDIT_RECORD_VERSION),
        index,
        time: entry.time_field().to_string(),
        op: entry.op_field().to_string(),
        result: entry.result_field().to_string(),
        direction: entry.direction_field().to_string(),
        path: entry.path_field().to_string(),
        size: entry.size_field(),
        bytes: entry.bytes_field(),
        objects: entry.objects_field(),
        plaintext_hash: entry.plaintext_hash_field().to_string(),
        ciphertext_hash: entry.ciphertext_hash_field().to_string(),
        remote: entry.remote_field().to_string(),
        prev: previous.to_string(),
        hash: String::new(),
    };
    record.hash = compute_hash(&record);
    record
}

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
    /// The record names a schema this build cannot hash.
    ///
    /// **Not a forgery**, and the message says so. A log written by a newer DCTL
    /// is perfectly good evidence that this build simply cannot check, and
    /// telling an operator their chain is broken when the remedy is an upgrade
    /// would send them hunting for an intruder.
    UnsupportedVersion {
        /// The version the record claims.
        version: u32,
        /// The newest version this build can verify.
        supported: u32,
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
            Self::UnsupportedVersion { version, supported } => write!(
                f,
                "the record is written in schema version {version}, and this build \
                 verifies up to {supported} — the chain is not proven forged, it is \
                 unproven; upgrade DCTL to check it"
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
/// happened" — see the truncation note in this module's documentation.
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

        // 2. Before anything is hashed: the version chooses *which bytes* are
        //    hashed, so a record from a schema this build does not know cannot be
        //    checked at all. Guessing a canonical form would report a good record
        //    as a forgery, which is the one mistake an evidence tool must not
        //    make.
        if !record.is_supported_version() {
            return Err(at(BreakKind::UnsupportedVersion {
                version: record.version(),
                supported: AUDIT_RECORD_VERSION,
            }));
        }

        // 3. A deleted record leaves a gap even when the survivors are re-linked.
        let expected_index = AUDIT_CHAIN_FIRST_INDEX.saturating_add(position as u64);
        if record.index != expected_index {
            return Err(at(BreakKind::IndexDiscontinuity {
                expected: expected_index,
                found: record.index,
            }));
        }

        // 4. The link itself.
        if !record.prev.eq_ignore_ascii_case(&previous_hash) {
            return Err(at(BreakKind::BrokenLink {
                expected: previous_hash,
                found: record.prev.clone(),
            }));
        }

        // 5. And finally the content the hash claims to cover.
        let computed = compute_hash(record);
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
    use crate::commands::touch::timestamp::Timestamp;
    use crate::constants::HASH_HEX_LEN_BLAKE3;
    use crate::exit::ExitCode;

    fn record() -> AuditRecord {
        AuditRecord {
            v: Some(AUDIT_RECORD_VERSION),
            index: 0,
            time: "2026-07-26T14:30:00Z".into(),
            op: "copy".into(),
            result: "success".into(),
            direction: crate::constants::AUDIT_DIRECTION_IN.into(),
            path: "photos/2024/a.jpg".into(),
            size: 1024,
            bytes: 1024,
            objects: 1,
            plaintext_hash: "aa".repeat(32),
            ciphertext_hash: "bb".repeat(32),
            remote: "vault".into(),
            prev: AUDIT_CHAIN_GENESIS_PREV.into(),
            hash: String::new(),
        }
    }

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
                path: format!("photos/{index}.jpg"),
                size: 1000 + index,
                bytes: 1000 + index,
                prev: previous.clone(),
                ..record()
            };
            record.hash = if upper {
                compute_hash(&record).to_uppercase()
            } else {
                compute_hash(&record)
            };
            previous.clone_from(&record.hash);
            records.push(record);
        }
        records
    }

    fn chain(count: u64) -> Vec<AuditRecord> {
        chain_with(count, false)
    }

    /// A single-field edit, used to prove the hash covers that field.
    type Mutation = Box<dyn Fn(&mut AuditRecord)>;

    #[test]
    fn a_records_hash_covers_every_field() {
        // Any change to any field must change the hash, or that field could be
        // rewritten without breaking the chain.
        let baseline = compute_hash(&record());

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
            // The v2 additions. A direction outside the hash would be the whole
            // defect back again: an upload could be re-labelled a download, or
            // an egress of 40 GB re-labelled as zero, without breaking a link.
            Box::new(|r| r.direction = crate::constants::AUDIT_DIRECTION_OUT.into()),
            Box::new(|r| r.bytes += 1),
            Box::new(|r| r.objects += 1),
            // And the version itself, which chooses *which* bytes are hashed.
            Box::new(|r| r.v = None),
        ];

        for (position, mutate) in mutations.iter().enumerate() {
            let mut mutated = record();
            mutate(&mut mutated);
            assert_ne!(
                compute_hash(&mutated),
                baseline,
                "field {position} is outside the hash"
            );
        }
    }

    #[test]
    fn the_hash_is_stable_across_recomputation() {
        let record = record();
        assert_eq!(compute_hash(&record), compute_hash(&record));
        assert_eq!(compute_hash(&record).len(), HASH_HEX_LEN_BLAKE3);
        assert!(is_well_formed_hash(&compute_hash(&record)));
        // One spelling on disk, so identical content is byte-identical.
        assert_eq!(compute_hash(&record), compute_hash(&record).to_lowercase());
    }

    #[test]
    fn a_field_cannot_reach_across_a_separator() {
        // The forgery this blocks: moving text from one field into the next so
        // two different records serialise to the same bytes.
        let mut shifted = record();
        shifted.op = format!("copy{AUDIT_HASH_FIELD_SEPARATOR}success");
        shifted.result = String::new();
        assert_ne!(compute_hash(&shifted), compute_hash(&record()));
        // And the separator itself is a character no legal field may contain.
        assert!(AUDIT_HASH_FIELD_SEPARATOR.is_control());
    }

    #[test]
    fn the_canonical_form_lists_every_field_once_in_a_frozen_order() {
        let canonical = canonical(&record());
        let fields: Vec<&str> = canonical.split(AUDIT_HASH_FIELD_SEPARATOR).collect();
        assert_eq!(fields.len(), 14, "version + prev + 12 record fields");
        // This order is documented in the audit-log reference
        // (https://doc.dctl.sh/reference/audit-log) §3 and is frozen: changing
        // it invalidates every chain ever written.
        assert_eq!(
            fields,
            vec![
                "2",
                AUDIT_CHAIN_GENESIS_PREV,
                "0",
                "2026-07-26T14:30:00Z",
                "copy",
                "success",
                "photos/2024/a.jpg",
                "1024",
                &"aa".repeat(32),
                &"bb".repeat(32),
                "vault",
                "in",
                "1024",
                "1",
            ]
        );
    }

    #[test]
    fn the_v1_preimage_survives_unaltered_inside_the_v2_one() {
        // The property the migration rests on: v2 *brackets* the v1 fields, it
        // does not redefine any of them. A reader can check that by eye, and a
        // v1 record's ten values still mean exactly what they always meant.
        let mut legacy = record();
        legacy.v = None;
        let v1 = canonical(&legacy);
        let v2 = canonical(&record());

        assert!(v2.contains(&v1), "v2 preimage:\n{v2:?}\nv1:\n{v1:?}");
        assert!(v2.starts_with(&format!("2{AUDIT_HASH_FIELD_SEPARATOR}")));
        assert_eq!(v1.split(AUDIT_HASH_FIELD_SEPARATOR).count(), 10);
    }

    /// The four records of the worked example in
    /// [the audit-log reference](https://doc.dctl.sh/reference/audit-log) §7 —
    /// two written by a v1 build, two by a v2 build, in one chain.
    ///
    /// The mixed chain is the specification's central claim, so it is the
    /// specification's example: a log that spans an upgrade must keep verifying,
    /// or every customer's evidence is invalidated by every release.
    fn documented_example() -> [AuditRecord; 4] {
        let first = AuditRecord {
            v: None,
            index: 0,
            time: "2026-07-26T14:30:00Z".into(),
            op: "copy".into(),
            result: "success".into(),
            direction: String::new(),
            path: "photos/2024/holiday.mov".into(),
            size: 4_294_967_296,
            bytes: 0,
            objects: 0,
            plaintext_hash: "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
                .into(),
            ciphertext_hash: "c12f1481789d50a4c549e15c42bda1759277bc954d2f4b62c0f4531937f2e990"
                .into(),
            remote: "vault".into(),
            prev: AUDIT_CHAIN_GENESIS_PREV.into(),
            hash: "82003870c5344e3adb90c5e5319c2d77ed90605a4cc09d6f4e313558e5fa8597".into(),
        };
        let second = AuditRecord {
            index: 1,
            time: "2026-07-26T14:31:07Z".into(),
            op: "delete".into(),
            result: "success".into(),
            path: "photos/2023/old.mov".into(),
            size: 0,
            plaintext_hash: String::new(),
            ciphertext_hash: String::new(),
            prev: first.hash.clone(),
            hash: "de169675b8da96a4892e92a98fd20b952f389d93fcfb0a38d95cf51bf4df1ccd".into(),
            ..first.clone()
        };
        // The upgrade happens here. Everything above stays byte-for-byte as the
        // older build wrote it.
        let third = AuditRecord {
            v: Some(AUDIT_RECORD_VERSION),
            index: 2,
            time: "2026-08-01T09:15:00Z".into(),
            op: "restore".into(),
            result: "success".into(),
            direction: "out".into(),
            path: "photos/2024/holiday.mov".into(),
            size: 4_294_967_296,
            bytes: 4_294_967_296,
            objects: 1,
            plaintext_hash: "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
                .into(),
            ciphertext_hash: String::new(),
            remote: "vault".into(),
            prev: second.hash.clone(),
            hash: "4c9d4e83a75f5df8e35de5a83378568e45fc26417fcd1749ca2b2cf7f8e036a8".into(),
        };
        let fourth = AuditRecord {
            index: 3,
            time: "2026-08-01T09:15:04Z".into(),
            op: "cleanup".into(),
            result: "success".into(),
            direction: String::new(),
            path: String::new(),
            size: 0,
            bytes: 0,
            objects: 12,
            plaintext_hash: String::new(),
            prev: third.hash.clone(),
            hash: "37b656508f9217e841bf0963e2fa72225506687d1f1ecb4b34af60e98a2b35c7".into(),
            ..third.clone()
        };
        [first, second, third, fourth]
    }

    #[test]
    fn the_worked_example_in_the_specification_is_the_one_this_code_produces() {
        // The audit-log reference (https://doc.dctl.sh/reference/audit-log)
        // promises a chain can be verified with a short script and no DCTL
        // binary. That promise is only worth something if the
        // numbers printed in it are the numbers this function computes, so they
        // are pinned here: a change to either canonical form fails this test
        // before it silently invalidates the specification.
        let records = documented_example();
        for record in &records {
            assert_eq!(
                compute_hash(record),
                record.hash,
                "the audit-log reference and chain::canonical have drifted at index {}",
                record.index
            );
        }
        let verified = verify(&records).unwrap();
        assert_eq!(verified.records, 4);
        assert_eq!(verified.head, records[3].hash);

        // The exact byte strings the document tells a third party to hash — one
        // from each side of the version boundary.
        assert_eq!(
            canonical(&records[1]),
            format!(
                "82003870c5344e3adb90c5e5319c2d77ed90605a4cc09d6f4e313558e5fa8597{s}1{s}\
                 2026-07-26T14:31:07Z{s}delete{s}success{s}photos/2023/old.mov{s}0{s}{s}{s}vault",
                s = AUDIT_HASH_FIELD_SEPARATOR
            )
        );
        assert_eq!(
            canonical(&records[3]),
            format!(
                "2{s}{prev}{s}3{s}2026-08-01T09:15:04Z{s}cleanup{s}success{s}{s}0{s}{s}{s}\
                 vault{s}{s}0{s}12",
                s = AUDIT_HASH_FIELD_SEPARATOR,
                prev = records[2].hash
            )
        );
    }

    #[test]
    fn a_chain_written_across_an_upgrade_still_verifies_end_to_end() {
        // The migration guarantee, asserted on its own rather than only as a
        // by-product of the worked example: records 0 and 1 have no `v` field
        // and are hashed by the ten-value rule, records 2 and 3 carry `v: 2` and
        // are hashed by the fourteen-value rule, and the links cross the
        // boundary untouched.
        let records = documented_example();
        assert_eq!(records[0].version(), 1);
        assert_eq!(records[1].version(), 1);
        assert_eq!(records[2].version(), 2);
        assert_eq!(records[2].prev, records[1].hash, "the link crosses");

        verify(&records).expect("a mixed-schema chain verifies");

        // And the old records are still hashed the *old* way: recomputing record
        // 0 under the v2 rule must give something else, which is exactly why the
        // version has to travel with the record.
        let mut upgraded = records[0].clone();
        upgraded.v = Some(AUDIT_RECORD_VERSION);
        assert_ne!(compute_hash(&upgraded), records[0].hash);
    }

    #[test]
    fn a_record_from_a_future_schema_is_unproven_rather_than_forged() {
        // A log written by a newer DCTL is good evidence this build cannot
        // check. Reporting it as tampering would send an operator hunting for an
        // intruder when the remedy is an upgrade.
        let mut records = chain(3);
        records[1].v = Some(AUDIT_RECORD_VERSION + 1);

        let broken = verify(&records).unwrap_err();
        assert_eq!(broken.position, 1);
        assert_eq!(
            broken.kind,
            BreakKind::UnsupportedVersion {
                version: AUDIT_RECORD_VERSION + 1,
                supported: AUDIT_RECORD_VERSION,
            }
        );
        let said = broken.to_string();
        assert!(said.contains("upgrade DCTL"), "{said}");
        assert!(said.contains("not proven forged"), "{said}");
    }

    #[test]
    fn a_version_of_zero_is_refused_rather_than_read_as_v1() {
        // `"v": 0` is not the absent field, and treating it as one would let a
        // forger pick which canonical form a record is measured against.
        let mut records = chain(2);
        records[0].v = Some(0);
        let broken = verify(&records).unwrap_err();
        assert!(matches!(
            broken.kind,
            BreakKind::UnsupportedVersion { version: 0, .. }
        ));
    }

    #[test]
    fn the_specification_pins_the_json_field_order_too() {
        // A verifier written from the document reads the fields by name, but a
        // human comparing a file against the worked example reads them in order.
        let example = documented_example();
        assert_eq!(
            serde_json::to_string(&example[0]).unwrap(),
            r#"{"index":0,"time":"2026-07-26T14:30:00Z","op":"copy","result":"success","direction":"","path":"photos/2024/holiday.mov","size":4294967296,"bytes":0,"objects":0,"plaintext_hash":"d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24","ciphertext_hash":"c12f1481789d50a4c549e15c42bda1759277bc954d2f4b62c0f4531937f2e990","remote":"vault","prev":"0000000000000000000000000000000000000000000000000000000000000000","hash":"82003870c5344e3adb90c5e5319c2d77ed90605a4cc09d6f4e313558e5fa8597"}"#
        );
        assert_eq!(
            serde_json::to_string(&example[2]).unwrap(),
            r#"{"v":2,"index":2,"time":"2026-08-01T09:15:00Z","op":"restore","result":"success","direction":"out","path":"photos/2024/holiday.mov","size":4294967296,"bytes":4294967296,"objects":1,"plaintext_hash":"d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24","ciphertext_hash":"","remote":"vault","prev":"de169675b8da96a4892e92a98fd20b952f389d93fcfb0a38d95cf51bf4df1ccd","hash":"4c9d4e83a75f5df8e35de5a83378568e45fc26417fcd1749ca2b2cf7f8e036a8"}"#
        );
    }

    #[test]
    fn a_sealed_record_carries_this_builds_schema_and_hashes_the_new_fields() {
        // The silent failure this catches. If `seal` regressed to writing v1
        // records, `direction`, `bytes` and `objects` would still appear in the
        // JSON — but *outside* the hash preimage, because the v1 canonical form
        // does not cover them. An egress of 40 GB could then be relabelled an
        // ingest of nothing without breaking a single link, and the chain would
        // verify perfectly while attesting to the opposite of what happened.
        //
        // That is worse than the v1 gap it replaced: v1 was silent, and this
        // would be confidently wrong.
        use super::super::record::Direction;

        let entry = Entry::at("copy", ExitCode::Success, Timestamp::parse("@0").unwrap())
            .path("q4.xlsx")
            .size(40_000_000_000)
            .moved(Direction::Out, 40_000_000_000)
            .objects(1);
        let sealed = seal(&entry, 0, AUDIT_CHAIN_GENESIS_PREV);

        assert_eq!(sealed.v, Some(AUDIT_RECORD_VERSION));
        assert_eq!(sealed.direction, "out");
        assert_eq!(sealed.bytes, 40_000_000_000);
        assert_eq!(sealed.objects, 1);
        verify(std::slice::from_ref(&sealed)).expect("a freshly sealed record verifies");

        // And the relabelling is caught — which is true only because the three
        // fields are inside the preimage.
        for tamper in [
            Box::new(|r: &mut AuditRecord| r.direction = "in".into()) as Mutation,
            Box::new(|r: &mut AuditRecord| r.bytes = 0),
            Box::new(|r: &mut AuditRecord| r.objects = 9),
        ] {
            let mut forged = sealed.clone();
            tamper(&mut forged);
            let broken = verify(&[forged]).unwrap_err();
            assert!(
                matches!(broken.kind, BreakKind::ContentMismatch { .. }),
                "{:?}",
                broken.kind
            );
        }
    }

    #[test]
    fn sealing_assigns_the_position_and_the_hash_the_caller_cannot_choose() {
        let entry = Entry::at("copy", ExitCode::Success, Timestamp::parse("@0").unwrap())
            .path("photos/a.jpg")
            .size(7)
            .remote("vault");

        let sealed = seal(&entry, 4, &"ab".repeat(32));
        assert_eq!(sealed.index, 4);
        assert_eq!(sealed.prev, "ab".repeat(32));
        assert_eq!(sealed.hash, compute_hash(&sealed));
        // And the content the caller *did* supply is carried through untouched.
        assert_eq!(sealed.op, "copy");
        assert_eq!(sealed.result, ExitCode::Success.slug());
        assert_eq!(sealed.time, "1970-01-01T00:00:00Z");
        assert_eq!(sealed.path, "photos/a.jpg");
        assert_eq!(sealed.size, 7);
        assert_eq!(sealed.remote, "vault");
    }

    #[test]
    fn a_sealed_run_of_entries_verifies_as_a_chain() {
        // The round trip that matters: what the writer seals is what the reader
        // accepts, checked against the same rule rather than a restatement.
        let mut records = Vec::new();
        let mut previous = AUDIT_CHAIN_GENESIS_PREV.to_string();
        for index in 0..5 {
            let entry = Entry::at("copy", ExitCode::Success, Timestamp::parse("@0").unwrap())
                .path(&format!("photos/{index}.jpg"))
                .size(index);
            let sealed = seal(&entry, index, &previous);
            previous.clone_from(&sealed.hash);
            records.push(sealed);
        }

        let verified = verify(&records).unwrap();
        assert_eq!(verified.records, 5);
        assert_eq!(verified.head, records[4].hash);
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
        records[0].hash = compute_hash(&records[0]);

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
        records[2].hash = compute_hash(&records[2]);

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
