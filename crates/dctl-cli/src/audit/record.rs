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
//!
//! ## Version 2: which way did the bytes go, and how many were there
//!
//! A v1 record said an operation happened. It could not say whether data went
//! **into** the vault or came **out** of it, and its `size` was the object's
//! declared size rather than a measurement — so `dctl copy vault:tree /out`,
//! which is data leaving, recorded `size: 0` and was indistinguishable from the
//! upload that put it there. For a tool sold on an audit story, "who took data
//! out" is the question the log exists to answer, and v1 could not answer it.
//!
//! Version 2 adds three fields — [`AuditRecord::direction`],
//! [`AuditRecord::bytes`] and [`AuditRecord::objects`] — and one that says which
//! schema a record is written in, [`AuditRecord::version`]. The rule for reading
//! old records is stated normatively in `docs/AUDIT_LOG.md` §2.1 and implemented
//! in [`crate::audit::chain::canonical`]: **the version travels with the record,
//! never with the file**, because a hash-chained log cannot be rewritten in place
//! — rewriting one record breaks every link after it. A v1 record therefore stays
//! byte-for-byte as it was written and keeps verifying under the v1 rule forever.
//!
//! [`Entry::moved`] is the reason `bytes` cannot be recorded without a direction:
//! there is no setter for one without the other, so an operation that moves bytes
//! and forgets to say which way will not compile.

use serde::{Deserialize, Serialize};

use crate::commands::touch::timestamp::Timestamp;
use crate::constants::{
    AUDIT_DIRECTION_IN, AUDIT_DIRECTION_INTERNAL, AUDIT_DIRECTION_NONE_DISPLAY,
    AUDIT_DIRECTION_OUT, AUDIT_HASH_DISPLAY_LEN, AUDIT_RECORD_VERSION, AUDIT_RECORD_VERSION_LEGACY,
    HASH_HEX_LEN_BLAKE3,
};
use crate::exit::ExitCode;

use super::redaction;

/// Which way object bytes crossed the boundary of the remote a record names.
///
/// A closed enum rather than a string, because the whole point of the field is
/// that a compliance query can filter on it in ten years: a log in which one
/// command wrote `out` and another wrote `download` answers nothing. The absence
/// of a variant for "no bytes" is deliberate — see [`Entry::moved`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Bytes entered the remote: an upload, a `backup`, an `rcat`, the
    /// destination side of a `replicate`.
    In,
    /// Bytes left it: a download, a `restore`, a `cat`. **This is the direction
    /// the log exists to record.**
    Out,
    /// Bytes never crossed the boundary — both ends are the same remote, or
    /// neither end is one (a filesystem-to-filesystem copy).
    Internal,
}

impl Direction {
    /// The stable slug written to the record and matched by a query.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::In => AUDIT_DIRECTION_IN,
            Self::Out => AUDIT_DIRECTION_OUT,
            Self::Internal => AUDIT_DIRECTION_INTERNAL,
        }
    }
}

/// One append-only audit entry, as it appears on disk.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct AuditRecord {
    /// Which record schema this entry is written in.
    ///
    /// Spelled `v` on disk — it is on every line of a file people read with
    /// `grep`, and the shortest name that cannot be mistaken for anything else is
    /// the right one there. **Absent means 1**, because v1 predates the field;
    /// [`version`](AuditRecord::version) resolves that so no reader has to
    /// remember it.
    #[serde(rename = "v", default, skip_serializing_if = "Option::is_none")]
    pub v: Option<u32>,
    /// Position in the chain, dense and ascending from
    /// [`crate::constants::AUDIT_CHAIN_FIRST_INDEX`].
    pub index: u64,
    /// When the operation completed, RFC 3339 in UTC.
    pub time: String,
    /// The command that ran, using [`crate::cli::Command::name`]'s vocabulary.
    pub op: String,
    /// How it ended: the slug from [`crate::exit::ExitCode`].
    pub result: String,
    /// Which way the bytes went: `in`, `out`, `internal`, or empty when the
    /// operation moved no object bytes at all.
    #[serde(default)]
    pub direction: String,
    /// Logical vault path the operation touched.
    #[serde(default)]
    pub path: String,
    /// Plaintext size in bytes of the object the operation *concerned*.
    ///
    /// Not a claim that these bytes moved — [`bytes`](AuditRecord::bytes) is that
    /// claim. Keeping both is what lets a failure record still answer "what were
    /// you moving?" while answering "nothing landed" at the same time.
    #[serde(default)]
    pub size: u64,
    /// Object bytes this operation actually moved, measured rather than planned.
    ///
    /// Zero on a failure, because nothing was proven to have landed; zero for an
    /// operation that moves no bytes at all, such as a delete.
    #[serde(default)]
    pub bytes: u64,
    /// How many objects this record accounts for.
    ///
    /// One for a per-file record. A run-level record — `cleanup`, `index
    /// rebuild`, a `scrub` — carries the whole count, so a chain of a hundred
    /// records still totals correctly.
    #[serde(default)]
    pub objects: u64,
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
    /// The schema this record is written in, with the absent-means-v1 rule
    /// applied.
    ///
    /// One function so the rule has one implementation. A reader that inlined
    /// `unwrap_or(1)` in three places is three chances for one of them to become
    /// `unwrap_or(2)` and start hashing every historical record the wrong way.
    #[must_use]
    pub const fn version(&self) -> u32 {
        match self.v {
            Some(version) => version,
            None => AUDIT_RECORD_VERSION_LEGACY,
        }
    }

    /// Whether this build knows how to compute this record's hash.
    ///
    /// A record from a *future* schema is not a forgery and must not be reported
    /// as one: this build simply cannot attest to it. See
    /// [`crate::audit::chain::BreakKind::UnsupportedVersion`].
    #[must_use]
    pub const fn is_supported_version(&self) -> bool {
        self.version() >= AUDIT_RECORD_VERSION_LEGACY && self.version() <= AUDIT_RECORD_VERSION
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

    /// What a listing shows in the direction column.
    ///
    /// A dash for "no bytes moved" and for every v1 record, which could not state
    /// one. An empty cell would read as missing data.
    #[must_use]
    pub fn direction_display(&self) -> &str {
        if self.direction.is_empty() {
            AUDIT_DIRECTION_NONE_DISPLAY
        } else {
            &self.direction
        }
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
/// Constructed by every command that changes stored data, through
/// [`crate::audit::sink::Sink::record`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    time: String,
    op: String,
    result: String,
    direction: String,
    path: String,
    size: u64,
    bytes: u64,
    objects: u64,
    plaintext_hash: String,
    ciphertext_hash: String,
    remote: String,
}

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
            direction: String::new(),
            path: String::new(),
            size: 0,
            bytes: 0,
            objects: 0,
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

    /// Plaintext size in bytes of the object the operation concerned.
    ///
    /// Deliberately **not** a claim that the bytes moved: that is
    /// [`Entry::moved`]. A failed transfer records the size it was attempting and
    /// zero bytes moved, which is what makes a failure record investigable.
    #[must_use]
    pub const fn size(mut self, bytes: u64) -> Self {
        self.size = bytes;
        self
    }

    /// Object bytes that actually moved, and which way they went.
    ///
    /// **One setter for both, on purpose.** A byte count with no direction is the
    /// v1 defect this schema exists to close — a read that looks exactly like a
    /// write — so there is no way to record one without the other, and an
    /// operation that moves bytes and forgets to say which way will not compile.
    ///
    /// Call it with the *measured* count, after the operation concluded. A
    /// failure records nothing moved, because nothing was proven to have landed.
    #[must_use]
    pub fn moved(mut self, direction: Direction, bytes: u64) -> Self {
        self.direction = redaction::field(direction.slug());
        self.bytes = bytes;
        self
    }

    /// How many objects this record accounts for.
    ///
    /// One for a per-file record; the whole count for a run-level one. Set
    /// explicitly rather than defaulted to 1, because a record that accounts for
    /// no object at all — `dctl init`, a `cleanup` that found nothing — is a real
    /// record and must not claim to have touched one.
    #[must_use]
    pub const fn objects(mut self, count: u64) -> Self {
        self.objects = count;
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

    /// The direction slug, or empty when the operation moved no object bytes.
    #[must_use]
    pub fn direction_field(&self) -> &str {
        &self.direction
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

    /// Object bytes that actually moved.
    #[must_use]
    pub const fn bytes_field(&self) -> u64 {
        self.bytes
    }

    /// How many objects this record accounts for.
    #[must_use]
    pub const fn objects_field(&self) -> u64 {
        self.objects
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
            v: Some(AUDIT_RECORD_VERSION),
            index: 0,
            time: "2026-07-26T14:30:00Z".into(),
            op: "copy".into(),
            result: "success".into(),
            direction: AUDIT_DIRECTION_IN.into(),
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
    fn a_record_with_no_version_field_is_read_as_v1() {
        // The whole migration rule, in one assertion. Every record ever written
        // by a v1 build lacks the field, and reading it as anything else would
        // hash it the wrong way and report the customer's evidence as forged.
        let json = r#"{"index":0,"time":"t","op":"copy","result":"success",
                       "prev":"00","hash":"11"}"#;
        let legacy: AuditRecord = serde_json::from_str(json).unwrap();
        assert_eq!(legacy.v, None);
        assert_eq!(legacy.version(), AUDIT_RECORD_VERSION_LEGACY);
        assert!(legacy.is_supported_version());

        // And a v1 record round-trips without acquiring one: re-serialising a
        // record must never change the bytes its hash covers.
        assert!(!serde_json::to_string(&legacy).unwrap().contains("\"v\""));
    }

    #[test]
    fn a_version_this_build_does_not_know_is_reported_rather_than_guessed() {
        let mut future = record();
        future.v = Some(AUDIT_RECORD_VERSION + 1);
        assert!(!future.is_supported_version());

        // Zero is not "absent": a reader that treated it as v1 would let a
        // forger choose which canonical form a record is measured against.
        let mut zero = record();
        zero.v = Some(0);
        assert!(!zero.is_supported_version());
    }

    #[test]
    fn a_direction_column_never_renders_an_empty_cell() {
        // "This operation moved no bytes" is a fact. A blank cell reads as
        // missing data, which is a different and much worse claim.
        let mut moved = record();
        assert_eq!(moved.direction_display(), AUDIT_DIRECTION_IN);
        moved.direction = String::new();
        assert_eq!(
            moved.direction_display(),
            crate::constants::AUDIT_DIRECTION_NONE_DISPLAY
        );
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
        assert_eq!(entry.direction_field(), "");
        assert_eq!(entry.bytes_field(), 0);
        assert_eq!(entry.objects_field(), 0);
        assert_eq!(entry.plaintext_hash_field(), "");
        assert_eq!(entry.ciphertext_hash_field(), "");
        assert_eq!(entry.remote_field(), "");

        let filled = entry
            .path("photos/a.jpg")
            .size(1024)
            .moved(Direction::Out, 1024)
            .objects(1)
            .plaintext_hash(&"aa".repeat(32))
            .ciphertext_hash(&"bb".repeat(32))
            .remote("vault");
        assert_eq!(filled.path_field(), "photos/a.jpg");
        assert_eq!(filled.size_field(), 1024);
        assert_eq!(filled.direction_field(), AUDIT_DIRECTION_OUT);
        assert_eq!(filled.bytes_field(), 1024);
        assert_eq!(filled.objects_field(), 1);
        assert_eq!(filled.plaintext_hash_field(), "aa".repeat(32));
        assert_eq!(filled.ciphertext_hash_field(), "bb".repeat(32));
        assert_eq!(filled.remote_field(), "vault");
    }

    #[test]
    fn bytes_cannot_be_recorded_without_saying_which_way_they_went() {
        // The v1 defect, closed at the type level: there is no setter for a byte
        // count on its own, so `moved` is the only route to a non-zero `bytes`
        // and it takes the direction in the same call. A read that looked like a
        // write is what made the log unable to answer "who took data out".
        let entry = Entry::at("copy", ExitCode::Success, Timestamp::parse("@0").unwrap());
        assert_eq!(entry.bytes_field(), 0);
        assert_eq!(entry.direction_field(), "");

        for (direction, slug) in [
            (Direction::In, AUDIT_DIRECTION_IN),
            (Direction::Out, AUDIT_DIRECTION_OUT),
            (
                Direction::Internal,
                crate::constants::AUDIT_DIRECTION_INTERNAL,
            ),
        ] {
            let moved = entry.clone().moved(direction, 7);
            assert_eq!(moved.bytes_field(), 7);
            assert_eq!(moved.direction_field(), slug);
            assert_eq!(direction.slug(), slug);
        }
    }

    #[test]
    fn the_three_direction_slugs_are_distinct_and_stable() {
        // A compliance query filters on these years later; two spellings of one
        // direction, or a collision between two, is a log nobody can query.
        let slugs: Vec<&str> = [Direction::In, Direction::Out, Direction::Internal]
            .into_iter()
            .map(Direction::slug)
            .collect();
        let mut unique = slugs.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), slugs.len());
        assert!(slugs.iter().all(|slug| !slug.is_empty()));
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
