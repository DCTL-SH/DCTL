//! Every forgery anybody has thought of, run against the shipped `dctl` binary.
//!
//! ## Why this file exists, and why it is not a unit test
//!
//! An adversarial pass tried eleven forgeries against the tamper-evident log.
//! Ten were refused with the right diagnosis. The eleventh — **dropping the last
//! two records** — reported `intact` and exited **0**. That is the classic and
//! complete break of a hash chain: every record links to its predecessor, so
//! lopping records off the *end* leaves a shorter chain in which every link
//! still holds, and the records an attacker most wants gone are the most recent
//! ones. An audit log that cannot detect truncation does not do the one job it
//! exists for.
//!
//! The eleven live here, together, at the level a buyer's security reviewer will
//! test them at: a real process, a real file, a real exit status. A unit test
//! proving `chain::verify` returns `Err` cannot prove the binary exits 24, and
//! the whole value of these codes is that a script branches on them.
//!
//! ## The fixture is a second implementation on purpose
//!
//! [`canonical`] and [`seal`] below build records from
//! [the audit-log reference](https://doc.dctl.sh/reference/audit-log) §3 rather
//! than by calling DCTL's own code — `dctl-cli` is a binary crate, so there is
//! nothing to link against, and that constraint is worth keeping even if there
//! were. The specification promises a chain can be verified from the
//! document alone, with nothing but a JSON parser and a BLAKE3 implementation.
//! These tests *are* that verifier: if the shipped canonical form ever drifts
//! from the published one, every case below stops agreeing with the binary and
//! says so.
//!
//! It is also what makes the hard forgeries possible. Re-sealing an edited
//! record, or appending a record with a correctly recomputed chain, needs a
//! writer the attacker controls — which is exactly what an attacker has.

use std::path::PathBuf;

use assert_cmd::Command;
use tempfile::TempDir;

/// Field separator of the canonical hash string: U+001F,
/// [the audit-log reference](https://doc.dctl.sh/reference/audit-log) §3.1.
/// Spelled here rather than imported, so a change to DCTL's constant cannot
/// silently change what this file checks against.
const US: char = '\u{1f}';

/// The `prev` of the first record: sixty-four `0`s (§2).
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Exit codes this file asserts on. The published contract of
/// [the exit-code reference](https://doc.dctl.sh/reference/exit-codes), written
/// as literals because that is what a customer's script contains.
const EXIT_OK: i32 = 0;
const EXIT_CHAIN_BROKEN: i32 = 24;
const EXIT_HEAD_MISMATCH: i32 = 26;

/// Environment that would redirect a run away from its sandbox.
const INHERITED_ENV: &[&str] = &[
    "DCTL_CONFIG",
    "DCTL_INDEX",
    "DCTL_REMOTE",
    "DCTL_PASSWORD",
    "DCTL_PASSWORD_COMMAND",
    "DCTL_LOG_LEVEL",
    "DCTL_LOG_FORMAT",
];

// ── The record, and the chain rule: https://doc.dctl.sh/reference/audit-log ──

/// One audit record, as JSON Lines carries it.
///
/// A struct of owned strings rather than a `serde` type, because a forgery has
/// to be able to produce a record DCTL's own type would refuse to represent —
/// `"v": 99`, or a v2 record with its version stripped.
#[derive(Clone, Debug)]
struct Record {
    /// `None` spells version 1: the field predates nothing, so its absence *is*
    /// the v1 spelling (§2.1).
    v: Option<u32>,
    index: u64,
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
    prev: String,
    hash: String,
}

impl Record {
    /// A v2 record with everything that is not interesting left empty.
    fn new(index: u64, op: &str, path: &str) -> Self {
        Self {
            v: Some(2),
            index,
            time: format!("2026-07-26T00:{:02}:00Z", index % 60),
            op: op.to_string(),
            result: "success".to_string(),
            direction: String::new(),
            path: path.to_string(),
            size: 0,
            bytes: 0,
            objects: 1,
            plaintext_hash: String::new(),
            ciphertext_hash: String::new(),
            remote: "vault".to_string(),
            prev: GENESIS.to_string(),
            hash: String::new(),
        }
    }

    /// Bytes moved, and which way — the egress question of §2.2.
    fn moved(mut self, direction: &str, bytes: u64) -> Self {
        self.direction = direction.to_string();
        self.bytes = bytes;
        self.size = bytes;
        self
    }

    /// The record as one line of JSON, field order per §2.
    fn to_json(&self) -> String {
        let mut fields = Vec::new();
        if let Some(v) = self.v {
            fields.push(format!("\"v\":{v}"));
        }
        fields.push(format!("\"index\":{}", self.index));
        fields.push(format!("\"time\":\"{}\"", self.time));
        fields.push(format!("\"op\":\"{}\"", self.op));
        fields.push(format!("\"result\":\"{}\"", self.result));
        fields.push(format!("\"direction\":\"{}\"", self.direction));
        fields.push(format!("\"path\":\"{}\"", self.path));
        fields.push(format!("\"size\":{}", self.size));
        fields.push(format!("\"bytes\":{}", self.bytes));
        fields.push(format!("\"objects\":{}", self.objects));
        fields.push(format!("\"plaintext_hash\":\"{}\"", self.plaintext_hash));
        fields.push(format!("\"ciphertext_hash\":\"{}\"", self.ciphertext_hash));
        fields.push(format!("\"remote\":\"{}\"", self.remote));
        fields.push(format!("\"prev\":\"{}\"", self.prev));
        fields.push(format!("\"hash\":\"{}\"", self.hash));
        format!("{{{}}}", fields.join(","))
    }
}

/// The exact byte string a record's hash covers, per §3.1.
///
/// Ten values for version 1; fourteen for version 2, which is the v1 ten with
/// the version in front and `direction`, `bytes`, `objects` behind.
fn canonical(record: &Record) -> String {
    let v1 = [
        record.prev.clone(),
        record.index.to_string(),
        record.time.clone(),
        record.op.clone(),
        record.result.clone(),
        record.path.clone(),
        record.size.to_string(),
        record.plaintext_hash.clone(),
        record.ciphertext_hash.clone(),
        record.remote.clone(),
    ];

    match record.v {
        None | Some(1) => v1.join(&US.to_string()),
        Some(version) => {
            let mut fields = vec![version.to_string()];
            fields.extend(v1);
            fields.push(record.direction.clone());
            fields.push(record.bytes.to_string());
            fields.push(record.objects.to_string());
            fields.join(&US.to_string())
        }
    }
}

/// `hash = lowercase_hex(BLAKE3-256(canonical))`, per §3.2.
fn digest(record: &Record) -> String {
    blake3::hash(canonical(record).as_bytes())
        .to_hex()
        .to_string()
}

/// Link every record to its predecessor and seal it.
///
/// This is what an attacker who has read the specification can do, and it is why
/// the chain alone cannot answer a truncation: re-sealing costs nothing.
fn seal(records: &mut [Record]) {
    let mut previous = GENESIS.to_string();
    for record in records.iter_mut() {
        record.prev.clone_from(&previous);
        record.hash = digest(record);
        previous.clone_from(&record.hash);
    }
}

/// The chain every test starts from: nine records, one of them a real egress.
fn honest_chain() -> Vec<Record> {
    let mut records = vec![
        Record::new(0, "init", ""),
        Record::new(1, "copy", "photos/2024/a.jpg").moved("in", 1024),
        Record::new(2, "copy", "photos/2024/b.jpg").moved("in", 2048),
        Record::new(3, "delete", "photos/2023/old.mov"),
        Record::new(4, "copy", "finance/q4.xlsx").moved("in", 4096),
        Record::new(5, "cleanup", ""),
        // The record an attacker wants gone: 4 MiB left the vault.
        Record::new(6, "restore", "finance/q4.xlsx").moved("out", 4 * 1024 * 1024),
        Record::new(7, "cat", "finance/q4-draft.xlsx").moved("out", 12_700),
        Record::new(8, "copy", "photos/2024/c.jpg").moved("in", 8192),
    ];
    seal(&mut records);
    records
}

fn body(records: &[Record]) -> String {
    let mut text = String::new();
    for record in records {
        text.push_str(&record.to_json());
        text.push('\n');
    }
    text
}

// ── Driving the binary ───────────────────────────────────────────────────────

/// An isolated log, and the invocations that read it.
struct Fixture {
    root: TempDir,
    log: PathBuf,
}

/// What one invocation produced.
struct Ran {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Ran {
    /// The single word `verify` writes to stdout, with its newline removed.
    fn verdict(&self) -> &str {
        self.stdout.trim()
    }

    fn says(&self, needle: &str) -> bool {
        self.stderr.contains(needle)
    }
}

impl Fixture {
    fn with(records: &[Record]) -> Self {
        let root = TempDir::new().expect("a temporary directory");
        let log = root.path().join("audit.jsonl");
        std::fs::write(&log, body(records)).expect("write the log");
        Self { root, log }
    }

    /// Overwrite the log with a different set of records — the forgery step.
    fn forge(&self, records: &[Record]) {
        std::fs::write(&self.log, body(records)).expect("rewrite the log");
    }

    /// Overwrite the log with raw bytes, for a forgery that is not a record.
    fn forge_raw(&self, text: &str) {
        std::fs::write(&self.log, text).expect("rewrite the log");
    }

    fn dctl(&self) -> Command {
        let mut command = Command::cargo_bin("dctl").expect("the dctl binary is built");
        for key in INHERITED_ENV {
            command.env_remove(key);
        }
        command
            .current_dir(self.root.path())
            .arg("--config")
            .arg(self.root.path().join("dctl.toml"))
            .arg("--index")
            .arg(self.root.path().join("index.redb"))
            .arg("--color")
            .arg("never");
        command
    }

    fn run(&self, args: &[&str]) -> Ran {
        let output = self
            .dctl()
            .args(args)
            .arg("--audit-log")
            .arg(&self.log)
            .output()
            .expect("dctl ran");
        Ran {
            code: output.status.code().expect("a process exit code"),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    /// `dctl audit head`, and the anchor it printed.
    fn anchor(&self) -> String {
        let ran = self.run(&["audit", "head"]);
        assert_eq!(ran.code, EXIT_OK, "audit head failed: {}", ran.stderr);
        ran.stdout.trim().to_string()
    }

    fn verify(&self) -> Ran {
        self.run(&["audit", "verify"])
    }

    fn verify_against(&self, anchor: &str) -> Ran {
        self.run(&["audit", "verify", "--expect-head", anchor])
    }
}

/// Assert that a chain-internal forgery is refused at exit 24, with `naming` in
/// the diagnosis.
///
/// Used for the ten forgeries the chain already caught, so a regression in any
/// of them fails here rather than in a customer's log.
fn refused_as_broken(fixture: &Fixture, naming: &str, what: &str) {
    let ran = fixture.verify();
    assert_eq!(ran.code, EXIT_CHAIN_BROKEN, "{what}: exit {}", ran.code);
    assert_eq!(ran.verdict(), "broken", "{what}");
    assert!(ran.says(naming), "{what}: stderr said {:?}", ran.stderr);
}

// ── The pristine chain ───────────────────────────────────────────────────────

#[test]
fn an_honest_chain_verifies_and_yields_an_anchor_that_matches_it() {
    let fixture = Fixture::with(&honest_chain());

    let ran = fixture.verify();
    assert_eq!(ran.code, EXIT_OK);
    assert_eq!(ran.verdict(), "intact");

    // The anchor is one token, and it names both numbers.
    let anchor = fixture.anchor();
    let (records, head) = anchor
        .split_once(':')
        .expect("an anchor is <records>:<head>");
    assert_eq!(records, "9");
    assert_eq!(head, honest_chain()[8].hash);
    assert_eq!(head.len(), 64);

    // And it satisfies the flag it exists for.
    let ran = fixture.verify_against(&anchor);
    assert_eq!(ran.code, EXIT_OK, "{}", ran.stderr);
    assert_eq!(ran.verdict(), "intact");

    // A bare head hash is the other accepted spelling.
    assert_eq!(fixture.verify_against(head).code, EXIT_OK);
}

#[test]
fn the_fixture_and_the_binary_agree_on_the_canonical_form() {
    // The guard that keeps every other test in this file honest. These records
    // are hashed here from the audit-log reference
    // (https://doc.dctl.sh/reference/audit-log) §3 alone; if DCTL's own
    // canonical form drifted from the document, the binary would call this
    // pristine chain broken and every forgery below would "pass" for the wrong
    // reason.
    let fixture = Fixture::with(&honest_chain());
    let ran = fixture.verify();
    assert_eq!(
        ran.code, EXIT_OK,
        "the specification and the binary have drifted: {}",
        ran.stderr
    );

    // Belt and braces on the mixed-schema rule: a v1 record (no `v`) hashed by
    // the ten-value form links into v2 records hashed by the fourteen-value one.
    let mut mixed = honest_chain();
    mixed[0].v = None;
    mixed[1].v = None;
    seal(&mut mixed);
    let fixture = Fixture::with(&mixed);
    assert_eq!(
        fixture.verify().code,
        EXIT_OK,
        "a chain that spans an upgrade"
    );
}

// ── The eleventh forgery: truncation, at every depth ─────────────────────────

#[test]
fn dropping_the_last_two_records_no_longer_reports_intact() {
    // THE break. Verbatim from the finding: "dropping the last two records
    // reports `intact`, exit 0."
    let records = honest_chain();
    let fixture = Fixture::with(&records);
    let anchor = fixture.anchor();

    fixture.forge(&records[..7]);

    // Unanchored the shorter chain is still internally sound, and saying so is
    // honest — the links really do hold. That is precisely why the anchor is
    // needed, and the note printed at `-v` says so rather than leaving the
    // operator to infer it.
    let ran = fixture.verify();
    assert_eq!(ran.code, EXIT_OK);
    assert_eq!(ran.verdict(), "intact");

    // Anchored, it is caught, named and counted.
    let ran = fixture.verify_against(&anchor);
    assert_eq!(ran.code, EXIT_HEAD_MISMATCH, "{}", ran.stderr);
    assert_ne!(ran.verdict(), "intact", "a truncated log reported `intact`");
    assert_eq!(ran.verdict(), "head-mismatch");
    assert!(ran.says("TRUNCATION"), "{}", ran.stderr);
    assert!(ran.says("2 records have been removed"), "{}", ran.stderr);
}

#[test]
fn every_depth_of_truncation_is_counted_exactly() {
    // One record, two, all but one, and the whole log. A count that was right at
    // one depth and wrong at another would be worse than no count at all.
    let records = honest_chain();

    for (kept, gone) in [
        (8_usize, "1 record has"),
        (7, "2 records have"),
        (1, "8 records have"),
        (0, "9 records have"),
    ] {
        let fixture = Fixture::with(&records);
        let anchor = fixture.anchor();
        fixture.forge(&records[..kept]);

        let ran = fixture.verify_against(&anchor);
        assert_eq!(
            ran.code, EXIT_HEAD_MISMATCH,
            "truncated to {kept} records: exit {} — {}",
            ran.code, ran.stderr
        );
        assert_ne!(ran.verdict(), "intact", "truncated to {kept} records");
        assert!(
            ran.says(&format!("{gone} been removed")),
            "truncated to {kept}: {}",
            ran.stderr
        );
    }
}

#[test]
fn the_whole_log_being_wiped_is_a_finding_and_not_an_empty_success() {
    // `> audit.jsonl`. An empty log verifies on its own — "nothing has been
    // appended" is a real answer — so without an anchor this is the quietest
    // possible attack.
    let records = honest_chain();
    let fixture = Fixture::with(&records);
    let anchor = fixture.anchor();

    fixture.forge_raw("");
    assert_eq!(fixture.verify().code, EXIT_OK, "an empty chain is sound");

    let ran = fixture.verify_against(&anchor);
    assert_eq!(ran.code, EXIT_HEAD_MISMATCH);
    assert!(ran.says("9 records have been removed"), "{}", ran.stderr);
}

#[test]
fn a_bare_hash_anchor_still_catches_truncation_and_says_it_cannot_count() {
    // The weaker anchor an operator gets from `verify --json | jq -r .head`.
    // It must still refuse, and it must be honest that the number is unknowable
    // rather than inventing one.
    let records = honest_chain();
    let fixture = Fixture::with(&records);
    let head = records[8].hash.clone();

    fixture.forge(&records[..7]);

    let ran = fixture.verify_against(&head);
    assert_eq!(ran.code, EXIT_HEAD_MISMATCH, "{}", ran.stderr);
    assert!(ran.says("TRUNCATION OR DIVERGENCE"), "{}", ran.stderr);
    assert!(ran.says("cannot be known"), "{}", ran.stderr);
}

#[test]
fn a_log_that_grew_honestly_is_reported_as_stale_and_not_as_an_attack() {
    // The case that decides whether anybody keeps passing the flag. A vault in
    // service appends records between anchors, and reporting that as tampering
    // would train operators to drop the check.
    let records = honest_chain();
    let fixture = Fixture::with(&records[..5]);
    let anchor = fixture.anchor();

    fixture.forge(&records);

    let ran = fixture.verify_against(&anchor);
    assert_eq!(ran.code, EXIT_HEAD_MISMATCH, "{}", ran.stderr);
    assert!(ran.says("4 records were appended"), "{}", ran.stderr);
    assert!(ran.says("Nothing was removed"), "{}", ran.stderr);
    assert!(!ran.says("TRUNCATION"), "{}", ran.stderr);
    // And the remedy offered is to re-anchor, not to call an incident.
    assert!(ran.says("No records were removed"), "{}", ran.stderr);
}

#[test]
fn a_truncation_hidden_under_fresh_appends_is_still_caught() {
    // The realistic version of the attack: remove the two records that show the
    // egress, then let the vault keep working so the log is longer than it was
    // when the anchor was taken. Length alone proves nothing; the anchored head
    // is what does.
    let records = honest_chain();
    let fixture = Fixture::with(&records);
    let anchor = fixture.anchor();

    let mut doctored: Vec<Record> = records[..7].to_vec();
    doctored.push(Record::new(7, "copy", "photos/2024/d.jpg").moved("in", 512));
    doctored.push(Record::new(8, "copy", "photos/2024/e.jpg").moved("in", 512));
    doctored.push(Record::new(9, "copy", "photos/2024/f.jpg").moved("in", 512));
    seal(&mut doctored);

    // The doctored chain verifies perfectly and is *longer* than the original.
    let ran = fixture.run(&["audit", "verify"]);
    assert_eq!(ran.code, EXIT_OK);
    fixture.forge(&doctored);
    assert_eq!(
        fixture.verify().code,
        EXIT_OK,
        "the rewritten chain is sound"
    );

    let ran = fixture.verify_against(&anchor);
    assert_eq!(ran.code, EXIT_HEAD_MISMATCH, "{}", ran.stderr);
    assert!(ran.says("DIVERGENCE"), "{}", ran.stderr);
    assert!(ran.says("rewritten"), "{}", ran.stderr);
}

#[test]
fn an_anchor_from_one_vault_does_not_clear_another_vaults_log() {
    let mine = honest_chain();
    let theirs = {
        let mut other = honest_chain();
        for record in &mut other {
            record.remote = "somewhere-else".to_string();
        }
        seal(&mut other);
        other
    };

    let fixture = Fixture::with(&mine);
    let anchor = fixture.anchor();
    fixture.forge(&theirs);

    let ran = fixture.verify_against(&anchor);
    assert_eq!(ran.code, EXIT_HEAD_MISMATCH, "{}", ran.stderr);
    assert!(ran.says("DIVERGENCE"), "{}", ran.stderr);
}

#[test]
fn a_broken_chain_yields_no_anchor_to_keep() {
    // `head` refuses rather than handing out a value taken from a forgery.
    // Unlike `list` and `export`, there is nothing here an investigator needs to
    // read — only a number somebody would later trust.
    let mut records = honest_chain();
    records[4].path = "finance/forged.xlsx".to_string();
    let fixture = Fixture::with(&records);

    let ran = fixture.run(&["audit", "head"]);
    assert_eq!(ran.code, EXIT_CHAIN_BROKEN, "{}", ran.stderr);
    assert!(ran.stdout.trim().is_empty(), "stdout: {:?}", ran.stdout);
    assert!(ran.says("record 4"), "{}", ran.stderr);
}

#[test]
fn a_broken_chain_outranks_the_anchor_it_also_fails() {
    // Both findings at once. 24 is the more specific and more serious of the
    // two, and it names a record position that 26 cannot.
    let records = honest_chain();
    let fixture = Fixture::with(&records);
    let anchor = fixture.anchor();

    let mut forged = records[..7].to_vec();
    forged[3].path = "photos/forged.jpg".to_string();
    fixture.forge(&forged);

    let ran = fixture.verify_against(&anchor);
    assert_eq!(ran.code, EXIT_CHAIN_BROKEN, "{}", ran.stderr);
    assert_eq!(ran.verdict(), "broken");
}

#[test]
fn an_unreadable_anchor_is_a_usage_error_rather_than_a_silent_pass() {
    // The failure that would be worst: a value the flag could not read being
    // ignored, so the command verifies the chain, prints `intact`, exits 0 and
    // compares nothing at all.
    let fixture = Fixture::with(&honest_chain());
    for bad in ["intact", "abc", "9:", "9:zz", &"ab".repeat(16)] {
        let ran = fixture.verify_against(bad);
        assert_ne!(ran.code, EXIT_OK, "--expect-head {bad:?} was accepted");
        assert_ne!(ran.verdict(), "intact", "--expect-head {bad:?}");
    }
}

// ── The ten forgeries that were already refused: none may regress ────────────

#[test]
fn an_egress_cannot_be_relabelled_an_ingress() {
    let mut records = honest_chain();
    records[6].direction = "in".to_string();
    let fixture = Fixture::with(&records);
    refused_as_broken(&fixture, "edited in place", "relabelled egress");
}

#[test]
fn a_four_megabyte_egress_cannot_be_rewritten_as_one_byte() {
    let mut records = honest_chain();
    records[6].bytes = 1;
    let fixture = Fixture::with(&records);
    refused_as_broken(&fixture, "edited in place", "rewritten byte count");
}

#[test]
fn an_edited_record_that_is_re_hashed_is_caught_at_the_following_record() {
    // The forgery a naive "does each record hash to its content" check misses
    // entirely. The orphan is the evidence, and it must be reported at record 7
    // rather than at record 6.
    let mut records = honest_chain();
    records[6].direction = "in".to_string();
    records[6].bytes = 0;
    records[6].hash = digest(&records[6]);

    let fixture = Fixture::with(&records);
    let ran = fixture.verify();
    assert_eq!(ran.code, EXIT_CHAIN_BROKEN);
    assert!(ran.says("record 7"), "{}", ran.stderr);
    assert!(ran.says("removed, reordered or inserted"), "{}", ran.stderr);
}

#[test]
fn a_record_removed_from_the_middle_is_a_discontinuity() {
    let mut records = honest_chain();
    records.remove(4);
    let fixture = Fixture::with(&records);
    refused_as_broken(&fixture, "expected index 4, found 5", "removed record");
}

#[test]
fn two_swapped_records_are_caught() {
    let mut records = honest_chain();
    records.swap(2, 6);
    let fixture = Fixture::with(&records);
    refused_as_broken(&fixture, "audit chain broken", "swapped records");
}

#[test]
fn a_duplicated_record_is_caught() {
    let mut records = honest_chain();
    let replay = records[6].clone();
    records.insert(7, replay);
    let fixture = Fixture::with(&records);
    refused_as_broken(&fixture, "audit chain broken", "replayed record");
}

#[test]
fn the_last_record_appended_again_is_caught() {
    let mut records = honest_chain();
    let replay = records[8].clone();
    records.push(replay);
    let fixture = Fixture::with(&records);
    refused_as_broken(&fixture, "audit chain broken", "tail replay");
}

#[test]
fn stripping_the_version_from_a_v2_record_is_caught() {
    // Removing `"v":2` makes a reader compute the ten-value string, which hashes
    // to something else — which is what stops the version being switched to move
    // `direction` and `bytes` outside the preimage.
    let mut records = honest_chain();
    records[6].v = None;
    let fixture = Fixture::with(&records);
    refused_as_broken(&fixture, "edited in place", "version stripped");
}

#[test]
fn a_record_claiming_a_future_schema_is_unproven_rather_than_forged() {
    // Not a forgery report. A log written by a newer DCTL is good evidence this
    // build cannot check, and telling an operator to hunt for an intruder when
    // the remedy is an upgrade is the one mistake an evidence tool must not
    // make.
    let mut records = honest_chain();
    records[6].v = Some(99);
    let fixture = Fixture::with(&records);

    let ran = fixture.verify();
    assert_eq!(ran.code, EXIT_CHAIN_BROKEN);
    assert!(ran.says("not proven forged"), "{}", ran.stderr);
    assert!(ran.says("upgrade DCTL"), "{}", ran.stderr);
}

#[test]
fn a_line_that_is_not_a_record_is_reported_with_its_line_number() {
    let records = honest_chain();
    let fixture = Fixture::with(&records);
    let mut text = body(&records);
    text.push_str("{ not json\n");
    fixture.forge_raw(&text);

    let ran = fixture.verify();
    assert_eq!(ran.code, EXIT_CHAIN_BROKEN);
    assert!(ran.says("line 10"), "{}", ran.stderr);
}

#[test]
fn a_forged_record_appended_with_a_recomputed_chain_is_visible_only_to_the_anchor() {
    // The honest statement of what the chain does and does not prove. Anybody
    // who can write the file can append a correctly linked record, and the walk
    // has no way to object — so `verify` alone says `intact`, and it is right
    // to. Only the anchor notices that the log is no longer the one that was
    // recorded.
    let records = honest_chain();
    let fixture = Fixture::with(&records);
    let anchor = fixture.anchor();

    let mut extended = records.clone();
    extended.push(Record::new(9, "delete", "finance/q4.xlsx"));
    seal(&mut extended);
    fixture.forge(&extended);

    assert_eq!(fixture.verify().code, EXIT_OK, "an append breaks no link");

    let ran = fixture.verify_against(&anchor);
    assert_eq!(ran.code, EXIT_HEAD_MISMATCH, "{}", ran.stderr);
    assert!(ran.says("1 record was appended"), "{}", ran.stderr);
}

// ── The machine channel ──────────────────────────────────────────────────────

#[test]
fn the_json_verdict_carries_the_kind_and_the_counts() {
    // A log pipeline branches on this rather than on prose. `head-mismatch`
    // alone is not enough — a stale anchor and a truncation need different
    // responses, and the `kind` is what separates them.
    let records = honest_chain();
    let fixture = Fixture::with(&records);
    let anchor = fixture.anchor();
    fixture.forge(&records[..7]);

    let ran = fixture.run(&["audit", "verify", "--json", "--expect-head", &anchor]);
    assert_eq!(ran.code, EXIT_HEAD_MISMATCH);

    let document: serde_json::Value =
        serde_json::from_str(&ran.stdout).expect("--json emits one document");
    assert_eq!(document["verdict"], "head-mismatch");
    assert_eq!(document["head_mismatch"]["kind"], "truncated");
    assert_eq!(document["head_mismatch"]["missing"], 2);
    assert_eq!(document["head_mismatch"]["anchored_records"], 9);
    assert_eq!(document["head_mismatch"]["records"], 7);
    assert_eq!(document["records"], 7);
    // The head the log has *now* stays in the document: it is what an operator
    // needs in order to see where the chain ends before deciding anything.
    assert_eq!(document["head"], records[6].hash);
    assert_eq!(document["expected_head"], anchor);
}

#[test]
fn the_json_anchor_carries_its_parts_as_well_as_its_whole() {
    let records = honest_chain();
    let fixture = Fixture::with(&records);

    let ran = fixture.run(&["audit", "head", "--json"]);
    assert_eq!(ran.code, EXIT_OK, "{}", ran.stderr);

    let document: serde_json::Value =
        serde_json::from_str(&ran.stdout).expect("--json emits one document");
    assert_eq!(document["records"], 9);
    assert_eq!(document["head"], records[8].hash);
    assert_eq!(document["anchor"], format!("9:{}", records[8].hash));
    assert_eq!(
        document["log"],
        fixture.log.display().to_string(),
        "the document names the file it walked"
    );
}

#[test]
fn an_unanchored_verify_says_out_loud_what_it_did_not_prove() {
    // `intact` on its own is a claim about content, never about length. An
    // operator who reads the one word as both has exactly the belief this whole
    // mechanism exists to prevent, so the limit is stated where the verdict is.
    let fixture = Fixture::with(&honest_chain());
    let ran = fixture.run(&["audit", "verify", "-v"]);
    assert_eq!(ran.code, EXIT_OK);
    assert!(ran.says("not its length"), "{}", ran.stderr);
    assert!(ran.says("dctl audit head"), "{}", ran.stderr);

    // And it is not repeated once an anchor *was* given: the note would then be
    // false.
    let anchor = fixture.anchor();
    let ran = fixture.run(&["audit", "verify", "-v", "--expect-head", &anchor]);
    assert!(!ran.says("not its length"), "{}", ran.stderr);
}

// ── The documented procedure, run end to end ─────────────────────────────────

#[test]
fn the_operating_procedure_in_the_documentation_actually_runs() {
    // The audit-log reference (https://doc.dctl.sh/reference/audit-log) §10
    // tells an operator to keep the anchor in a file and check against its last
    // line. A procedure nobody tested is a procedure that works until somebody
    // needs it.
    let records = honest_chain();
    let fixture = Fixture::with(&records);

    let anchors = fixture.root.path().join("anchors.txt");
    std::fs::write(
        &anchors,
        format!("2026-07-26T00:00:00Z {}\n", fixture.anchor()),
    )
    .expect("write the anchor file");

    let last = std::fs::read_to_string(&anchors).expect("read it back");
    let anchor = last
        .lines()
        .next_back()
        .and_then(|line| line.split_whitespace().next_back())
        .expect("the last field of the last line");

    assert_eq!(fixture.verify_against(anchor).code, EXIT_OK);

    fixture.forge(&records[..8]);
    let ran = fixture.verify_against(anchor);
    assert_eq!(ran.code, EXIT_HEAD_MISMATCH, "{}", ran.stderr);
    assert!(ran.says("1 record has been removed"), "{}", ran.stderr);
}
