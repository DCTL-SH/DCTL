//! One entry in the tamper-evident audit log, and the only safe way to build
//! one.
//!
//! `PLAN.md` §7 requires an append-only, hash-chained record of every operation:
//! timestamp, files, plaintext and ciphertext hashes, sizes, provider, result,
//! each entry carrying the previous entry's hash. Two types live here, and the
//! split between them is deliberate:
//!
//! * [`AuditRecord`] — what is *on disk*. Eleven fields, including the three the
//!   chain owns: `index`, `prev` and `hash`.
//! * [`Entry`] — what a *caller* supplies. The same record minus those three,
//!   because a caller that could choose its own index or its own `prev` could
//!   write a fork or a forgery without the chain noticing. Position is the
//!   writer's to assign ([`crate::audit::write`]) and the hash is the chain's to
//!   compute ([`crate::audit::chain`]).
//!
//! ## Every field is scrubbed on the way in
//!
//! `PLAN.md` §7 makes redaction mandatory, and a mandatory thing that has to be
//! remembered is optional. So there is no way to put a string into an entry that
//! does not pass through [`crate::audit::redaction`] first: the setters take the
//! raw value and store the scrubbed one. That buys two separate guarantees —
//! credentials never reach the log, and no field can contain
//! [`crate::constants::AUDIT_HASH_FIELD_SEPARATOR`], which is what stops one
//! field's contents from being read as another's.
//!
//! ## Where the clock comes from
//!
//! [`Timestamp`] is borrowed from `dctl touch` rather than re-derived here.
//! DCTL converts calendar dates itself instead of taking a datetime dependency
//! (`PLAN.md` §13.1), so there is exactly one proleptic-Gregorian
//! implementation in the crate — and a second copy of it is how the audit log
//! and the file listings would come to disagree about what `2028-02-29` means.
//!
//! ## Why the optional fields default rather than failing to parse
//!
//! An operation with no path (`dctl init`) or no plaintext hash (a delete) is a
//! perfectly ordinary record, and a reader that refused it could not verify a
//! real log. The chain-bearing fields — `index`, `prev`, `hash` — are *not*
//! optional: a record without them is not a record, and the reader says so.

use serde::{Deserialize, Serialize};

use crate::commands::touch::timestamp::Timestamp;
use crate::constants::{AUDIT_HASH_DISPLAY_LEN, HASH_HEX_LEN_BLAKE3};
use crate::exit::ExitCode;

use super::redaction;

/// One append-only audit entry, as it appears on disk.
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
    /// This record's own hash, over [`crate::audit::chain::canonical`].
    pub hash: String,
}

impl AuditRecord {
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

/// What happened, as the operation itself knows it — everything except where in
/// the chain it lands.
///
/// Built with a chained-setter style rather than a struct literal so that no
/// call site can bypass the scrub in [`crate::audit::redaction`], and so that
/// adding a field later cannot silently leave existing call sites constructing
/// a record with a stale idea of what belongs in one.
///
/// See the note on [`crate::audit::write`] for why nothing outside the tests
/// constructs one of these yet.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    time: String,
    op: String,
    result: String,
    path: String,
    size: u64,
    plaintext_hash: String,
    ciphertext_hash: String,
    remote: String,
}

#[allow(dead_code)]
impl Entry {
    /// An entry for `op` that ended in `outcome`, stamped with the current time.
    ///
    /// The outcome is an [`ExitCode`] rather than a string because the log has
    /// to be queryable years later: `result` is the field a compliance query
    /// filters on, and a free-form word would let one command write `"ok"` and
    /// the next `"success"` for the same thing. The slug is the same vocabulary
    /// the process exit status and the structured logs already use, so the three
    /// accounts of a run agree.
    #[must_use]
    pub fn new(op: &str, outcome: ExitCode) -> Self {
        Self::at(op, outcome, Timestamp::now())
    }

    /// [`Entry::new`] with the clock supplied.
    ///
    /// Exists so a test can assert on an exact record — and so a caller that
    /// already knows when the operation *completed* can record that instant
    /// rather than the slightly later one at which it got round to logging.
    #[must_use]
    pub fn at(op: &str, outcome: ExitCode, time: Timestamp) -> Self {
        Self {
            time: redaction::field(&time.to_rfc3339()),
            op: redaction::field(op),
            result: redaction::field(outcome.slug()),
            path: String::new(),
            size: 0,
            plaintext_hash: String::new(),
            ciphertext_hash: String::new(),
            remote: String::new(),
        }
    }

    /// The logical vault path the operation touched.
    #[must_use]
    pub fn path(mut self, path: &str) -> Self {
        self.path = redaction::field(path);
        self
    }

    /// Plaintext size in bytes.
    #[must_use]
    pub const fn size(mut self, bytes: u64) -> Self {
        self.size = bytes;
        self
    }

    /// BLAKE3 of the plaintext, hex.
    #[must_use]
    pub fn plaintext_hash(mut self, hash: &str) -> Self {
        self.plaintext_hash = redaction::field(hash);
        self
    }

    /// BLAKE3 of the stored ciphertext, hex.
    #[must_use]
    pub fn ciphertext_hash(mut self, hash: &str) -> Self {
        self.ciphertext_hash = redaction::field(hash);
        self
    }

    /// The remote the operation was against.
    ///
    /// Scrubbed harder than the other fields: a remote is usually a configured
    /// name (`vault`), but it can be a URL, and a URL is where a credential
    /// hides. See [`redaction::remote`].
    #[must_use]
    pub fn remote(mut self, remote: &str) -> Self {
        self.remote = redaction::remote(remote);
        self
    }

    /// When the operation completed, RFC 3339 in UTC.
    #[must_use]
    pub fn time_field(&self) -> &str {
        &self.time
    }

    /// The command that ran.
    #[must_use]
    pub fn op_field(&self) -> &str {
        &self.op
    }

    /// How it ended.
    #[must_use]
    pub fn result_field(&self) -> &str {
        &self.result
    }

    /// The logical path, or empty when the operation touched none.
    #[must_use]
    pub fn path_field(&self) -> &str {
        &self.path
    }

    /// Plaintext size in bytes.
    #[must_use]
    pub const fn size_field(&self) -> u64 {
        self.size
    }

    /// Plaintext hash, or empty when there was no plaintext.
    #[must_use]
    pub fn plaintext_hash_field(&self) -> &str {
        &self.plaintext_hash
    }

    /// Ciphertext hash, or empty on a plain remote.
    #[must_use]
    pub fn ciphertext_hash_field(&self) -> &str {
        &self.ciphertext_hash
    }

    /// The remote, scrubbed.
    #[must_use]
    pub fn remote_field(&self) -> &str {
        &self.remote
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
    use crate::constants::{AUDIT_CHAIN_GENESIS_PREV, AUDIT_HASH_FIELD_SEPARATOR};

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

    #[test]
    fn a_short_hash_is_a_prefix_and_never_the_whole_thing() {
        let mut sealed = record();
        sealed.hash = "ab".repeat(32);
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
        let mut sealed = record();
        sealed.hash = "cd".repeat(32);
        let json = serde_json::to_string(&sealed).unwrap();
        let parsed: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, sealed);
    }

    #[test]
    fn an_entry_takes_its_result_from_the_exit_code_vocabulary() {
        // The same word the process exit status and the structured log use, so
        // the three accounts of a run agree rather than nearly agree.
        let entry = Entry::new("copy", ExitCode::Success);
        assert_eq!(entry.result_field(), ExitCode::Success.slug());
        assert_eq!(entry.op_field(), "copy");

        let failed = Entry::new("copy", ExitCode::ChecksumMismatch);
        assert_eq!(failed.result_field(), "checksum_mismatch");
    }

    #[test]
    fn an_entry_is_stamped_in_rfc_3339_utc() {
        let entry = Entry::at("copy", ExitCode::Success, Timestamp::parse("@0").unwrap());
        assert_eq!(entry.time_field(), "1970-01-01T00:00:00Z");
        // And the live clock produces the same shape.
        assert!(
            Entry::new("copy", ExitCode::Success)
                .time_field()
                .ends_with('Z')
        );
    }

    #[test]
    fn the_optional_fields_start_empty_and_are_set_by_name() {
        let entry = Entry::at("copy", ExitCode::Success, Timestamp::parse("@0").unwrap());
        assert_eq!(entry.path_field(), "");
        assert_eq!(entry.size_field(), 0);
        assert_eq!(entry.plaintext_hash_field(), "");
        assert_eq!(entry.ciphertext_hash_field(), "");
        assert_eq!(entry.remote_field(), "");

        let filled = entry
            .path("photos/a.jpg")
            .size(1024)
            .plaintext_hash(&"aa".repeat(32))
            .ciphertext_hash(&"bb".repeat(32))
            .remote("vault");
        assert_eq!(filled.path_field(), "photos/a.jpg");
        assert_eq!(filled.size_field(), 1024);
        assert_eq!(filled.plaintext_hash_field(), "aa".repeat(32));
        assert_eq!(filled.ciphertext_hash_field(), "bb".repeat(32));
        assert_eq!(filled.remote_field(), "vault");
    }

    #[test]
    fn no_field_can_carry_the_hash_separator() {
        // The forgery this blocks: a path that closes its own field and opens
        // the next, so two different records produce the same canonical bytes.
        let entry = Entry::at("copy", ExitCode::Success, Timestamp::parse("@0").unwrap())
            .path(&format!("a{AUDIT_HASH_FIELD_SEPARATOR}b"))
            .remote(&format!("v{AUDIT_HASH_FIELD_SEPARATOR}w"));

        for field in [entry.path_field(), entry.remote_field(), entry.op_field()] {
            assert!(
                !field.contains(AUDIT_HASH_FIELD_SEPARATOR),
                "separator survived into {field:?}"
            );
        }
        assert_eq!(entry.path_field(), "a\\u001fb");
    }
}
