//! The anchor: a head hash kept **outside** the log, and what comparing one
//! against a chain does and does not prove.
//!
//! ## The break this closes
//!
//! A hash chain detects every edit made *inside* it and none made to its *end*.
//! Drop the last two records and what remains is a shorter chain that verifies
//! perfectly — every link still holds, every index is still dense — because
//! nothing inside a log attests to how many records it should have. The records
//! an attacker most wants gone are the most recent ones, which is exactly the
//! region the chain cannot defend. `docs/AUDIT_LOG.md` §1 has always said so;
//! this module is the mechanism that does something about it.
//!
//! The only thing that can attest to a chain's length is a value recorded
//! somewhere the writer cannot reach. That value is the **anchor**, and
//! comparing it against the log is the whole defence. `dctl audit head` produces
//! one, `dctl audit verify --expect-head` checks one, and
//! `docs/AUDIT_LOG.md` §10 is the operating procedure for keeping one — because
//! a defence nobody knows how to operate is not a defence.
//!
//! ## Why an anchor carries a record count
//!
//! A bare head hash answers "does the log still end here?" and nothing else.
//! When it does not, the hash alone cannot say whether two records were removed
//! or two thousand — it carries no length, so there is nothing to subtract.
//!
//! An anchor spelled `<records>`[`AUDIT_ANCHOR_SEPARATOR`]`<head>` carries both,
//! and the difference is the difference between "something is wrong" and
//! "**seventeen records have been removed from the end**", which is the sentence
//! an investigator actually needs. It is still one token, still copy-pasteable
//! into a ticket, still `diff`-able by a script. So that is what `dctl audit
//! head` prints.
//!
//! A bare hash is accepted too, and produces the weaker diagnosis honestly
//! rather than guessing: an operator who pasted the `head` field out of
//! `dctl audit verify --json`, or out of a third-party verifier's output, must
//! not be told their anchor is malformed.
//!
//! ## Four outcomes, because four different things go wrong
//!
//! [`Mismatch`] separates them because the remedies are not the same, and
//! collapsing them would train an operator to ignore the one that matters:
//!
//! * [`Mismatch::Advanced`] — the anchored head is **still in the chain**, and
//!   records were appended after it. Nothing was removed; the anchor is simply
//!   older than the log. This is what a stale anchor looks like, and calling it
//!   tampering would make the check unusable on a log that is still in service.
//! * [`Mismatch::Truncated`] — the chain is **shorter** than the anchor says it
//!   was. This is the attack, counted exactly.
//! * [`Mismatch::Diverged`] — the chain has a record where the anchor points and
//!   it is not the anchored one: history at or before the anchor was rewritten,
//!   or this is a different chain altogether.
//! * [`Mismatch::Absent`] — the anchored head is nowhere in the chain and the
//!   anchor carried no count, so truncation and divergence cannot be told apart
//!   and the number of missing records is not knowable. Said plainly rather than
//!   guessed.
//!
//! All four exit [`crate::exit::ExitCode::AuditHeadMismatch`] (26), which is a
//! *different* code from a broken chain (24) on purpose. The chain being sound
//! and the chain not ending where you left it are different findings with
//! different remedies, and `docs/EXIT_CODES.md`'s own rule is that a new
//! condition gets a new number rather than re-scoping a published one.
//!
//! ## What an anchor still does not prove
//!
//! Authorship. The chain is unkeyed, so anybody who can write the file can
//! append records to it with correct links — that was always true and the anchor
//! does not change it. What an anchor proves is that nothing **before** it was
//! removed or rewritten. Detecting forged *appends* needs a signature, which is
//! a different mechanism and is not claimed here.

use std::fmt;

use serde::Serialize;

use crate::constants::{AUDIT_ANCHOR_SEPARATOR, AUDIT_CHAIN_GENESIS_PREV};

use super::chain::Verified;
use super::record::{AuditRecord, is_well_formed_hash};

/// A head hash recorded outside the log, optionally with the number of records
/// the chain held when it was taken.
///
/// Cloneable and `'static` because `clap` stores it in the parsed arguments;
/// constructed only through [`Anchor::parse`] and [`Anchor::of`], so a value of
/// this type always holds a well-formed hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    /// Records the chain held when the anchor was taken, when the anchor says.
    records: Option<usize>,
    /// The head hash at that point, as written. Compared case-insensitively —
    /// a conforming writer may spell hex either way — but kept verbatim so a
    /// message can quote back exactly what the operator supplied.
    head: String,
}

impl Anchor {
    /// The anchor for a chain that has just verified.
    ///
    /// Always the counted form: this is the value DCTL hands an operator to keep,
    /// and handing out the weaker of the two spellings would throw away the
    /// count that makes a truncation countable.
    #[must_use]
    pub fn of(records: usize, head: &str) -> Self {
        Self {
            records: Some(records),
            head: head.to_string(),
        }
    }

    /// Read an anchor an operator supplied.
    ///
    /// Accepts `<head>` and `<records>:<head>`, and surrounding whitespace,
    /// because the value arrives pasted out of a ticket or read from a file with
    /// `$(cat …)` and a trailing newline is not a typo worth a usage error.
    ///
    /// # Errors
    /// A message naming both accepted forms. Returned as a `String` so `clap`
    /// renders it as an ordinary usage error against the flag that carried it.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();

        let (records, head) = match trimmed.split_once(AUDIT_ANCHOR_SEPARATOR) {
            None => (None, trimmed),
            Some((count, head)) => {
                let parsed = count
                    .parse::<usize>()
                    .map_err(|_| format!("'{count}' is not a record count — {}", Self::EXPECTED))?;
                (Some(parsed), head)
            }
        };

        if !is_well_formed_hash(head) {
            return Err(format!("'{head}' is not a chain hash — {}", Self::EXPECTED));
        }

        Ok(Self {
            records,
            head: head.to_string(),
        })
    }

    /// The shape both spellings are described by, so one wording serves every
    /// parse failure.
    const EXPECTED: &'static str = "an anchor is the 64-hex head hash, \
         optionally prefixed with the record count and a colon, exactly as \
         `dctl audit head` prints it";

    /// The head hash on its own, without the count.
    ///
    /// There is deliberately no matching accessor for the count. Nothing outside
    /// this module needs to branch on whether an anchor is counted — [`compare`]
    /// is the only thing the difference changes, and it owns that decision. A
    /// getter nobody calls is a second way to ask a question that already has an
    /// answer here.
    #[must_use]
    pub fn head(&self) -> &str {
        &self.head
    }
}

impl fmt::Display for Anchor {
    /// The one-token form: `<records>:<head>`, or the bare hash for an anchor
    /// that never carried a count.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.records {
            Some(records) => write!(f, "{records}{AUDIT_ANCHOR_SEPARATOR}{}", self.head),
            None => f.write_str(&self.head),
        }
    }
}

impl Serialize for Anchor {
    /// One string, the same one [`fmt::Display`] renders, so a machine consumer
    /// reads back exactly the token a human would paste.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

/// How a chain failed to end where an anchor said it would.
///
/// The tag is `kind`, flattened into the verdict document, exactly as
/// [`super::chain::BreakKind`] is: a machine consumer branches on the kind and
/// reads the counts without unwrapping a nested object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Mismatch {
    /// The anchored head is still in the chain, with records appended after it.
    ///
    /// **Not tampering.** Nothing was removed; the anchor is older than the log.
    Advanced {
        /// Records the chain held at the anchored head.
        anchored_records: usize,
        /// Records it holds now.
        records: usize,
        /// How many were appended since — the ones the anchor does not cover.
        appended: usize,
    },

    /// The chain is shorter than the anchor says it was. **This is truncation.**
    Truncated {
        /// Records the anchor says the chain held.
        anchored_records: usize,
        /// Records it holds now.
        records: usize,
        /// The difference: how many were removed from the end.
        missing: usize,
    },

    /// The chain has a record at the anchored position, and it is not the
    /// anchored one: history at or before the anchor was rewritten, or this is a
    /// different chain.
    Diverged {
        /// Records the anchor says the chain held.
        anchored_records: usize,
        /// The head the anchor names.
        expected: String,
        /// The head the chain actually has after that many records.
        found: String,
    },

    /// The anchored head is nowhere in the chain, and the anchor carried no
    /// count — so truncation and divergence cannot be told apart, and how many
    /// records are missing is **not knowable**.
    Absent {
        /// The head the anchor names.
        expected: String,
        /// Records the chain holds now.
        records: usize,
    },
}

impl Mismatch {
    /// What to do about it.
    ///
    /// Carried by the kind rather than by the call site, because the remedies
    /// genuinely differ: [`Mismatch::Advanced`] is an anchor to refresh and the
    /// other three are an incident. One hint for all four would either cry wolf
    /// on the benign case or whisper on the dangerous ones.
    #[must_use]
    pub const fn hint(&self) -> &'static str {
        match self {
            Self::Advanced { .. } => {
                "No records were removed: the chain still contains the head you \
                 anchored. If the appended records are your own runs, take a \
                 fresh anchor with `dctl audit head` and keep it where this \
                 machine cannot rewrite it. If they are not, read them with \
                 `dctl audit list` before you re-anchor — an anchor taken now \
                 attests to whatever is in the log now."
            }
            Self::Truncated { .. } | Self::Diverged { .. } | Self::Absent { .. } => {
                "Records this log once held are not in it now. Do not delete \
                 this copy and do not re-anchor it: keep it as evidence, compare \
                 it against any mirrored or offline copy, and treat every \
                 operation it no longer accounts for as unattested. A chain that \
                 verifies is not a chain that is complete."
            }
        }
    }
}

/// `1 record has` / `n records have` — subject and verb together.
///
/// Agreement is not decoration here. These sentences are read by somebody
/// deciding whether they are looking at an incident, and a tool that says
/// "1 records have been removed" invites the reader to wonder what else it got
/// approximately right.
fn records_have(count: usize) -> String {
    if count == 1 {
        "1 record has".to_string()
    } else {
        format!("{count} records have")
    }
}

/// `1 record was` / `n records were`. See [`records_have`].
fn records_were(count: usize) -> String {
    if count == 1 {
        "1 record was".to_string()
    } else {
        format!("{count} records were")
    }
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Advanced {
                anchored_records,
                records,
                appended,
            } => write!(
                f,
                "the chain does not end at the anchored head — it still contains \
                 it, after {anchored_records} records, and has grown to {records}: \
                 {} appended since the anchor was taken. Nothing was removed; the \
                 anchor is stale",
                records_were(*appended)
            ),
            Self::Truncated {
                anchored_records,
                records,
                missing,
            } => write!(
                f,
                "TRUNCATION: the anchor says this chain held {anchored_records} \
                 records; it holds {records}. {} been removed from the end",
                records_have(*missing)
            ),
            Self::Diverged {
                anchored_records,
                expected,
                found,
            } => write!(
                f,
                "DIVERGENCE: after {anchored_records} records this chain heads at \
                 {found}, not the anchored {expected} — history at or before that \
                 point was rewritten, or this is a different chain"
            ),
            Self::Absent { expected, records } => write!(
                f,
                "TRUNCATION OR DIVERGENCE: the anchored head {expected} appears \
                 nowhere in this chain's {records} records — records were removed \
                 from the end, or this is a different chain. How many are missing \
                 cannot be known from a head hash alone; anchor the counted form \
                 `<records>:<hash>` that `dctl audit head` prints and the next \
                 answer will carry the number"
            ),
        }
    }
}

/// The head a chain has after `count` records.
///
/// The genesis link for none, because "nothing has been appended" is a real
/// state with a real head — and an anchor taken from a fresh vault names it.
/// `None` when the chain is not that long, which is the truncation signal.
fn head_after(records: &[AuditRecord], count: usize) -> Option<&str> {
    match count {
        0 => Some(AUDIT_CHAIN_GENESIS_PREV),
        _ => records.get(count - 1).map(|record| record.hash.as_str()),
    }
}

/// Check that a chain ends where an anchor says it should.
///
/// `verified` is taken rather than inferred so that this cannot be called on a
/// chain nobody walked: an anchor comparison against records whose own links
/// were never checked would report "intact" for a log that is forged in the
/// middle, which is a worse answer than either check alone.
///
/// # Errors
/// The single [`Mismatch`] that describes the difference. Ordering matters: a
/// counted anchor is answered from its count, which is `O(1)` and gives the
/// exact figure; a bare one falls back to a scan, which can only ever say "still
/// present" or "gone".
pub fn compare(
    anchor: &Anchor,
    verified: &Verified,
    records: &[AuditRecord],
) -> Result<(), Mismatch> {
    // The head is the evidence, so it decides the verdict. A count that
    // disagreed with a matching head could only come from a mistyped anchor or a
    // BLAKE3 collision, and neither is worth failing a log that ends exactly
    // where the operator said it would.
    if anchor.head.eq_ignore_ascii_case(&verified.head) {
        return Ok(());
    }

    // Counted from the records themselves rather than from `verified.records`,
    // which is the same number. Taking it from the slice the positions are
    // looked up in is what makes it impossible for the count in a message and
    // the position it was derived from to disagree.
    let now = records.len();

    if let Some(anchored_records) = anchor.records {
        return Err(match head_after(records, anchored_records) {
            // The chain never reaches the anchored position: the records that
            // used to be there are gone, and the count says how many.
            None => Mismatch::Truncated {
                anchored_records,
                records: now,
                missing: anchored_records.saturating_sub(now),
            },
            // The anchored history is intact and the log has moved on. The head
            // already failed to match above, so this is strictly shorter than
            // the chain and `appended` is at least one.
            Some(found) if anchor.head.eq_ignore_ascii_case(found) => Mismatch::Advanced {
                anchored_records,
                records: now,
                appended: now.saturating_sub(anchored_records),
            },
            // Something else is at the anchored position.
            Some(found) => Mismatch::Diverged {
                anchored_records,
                expected: anchor.head.clone(),
                found: found.to_string(),
            },
        });
    }

    // A bare hash. Search backwards: an anchor is usually recent, so the match
    // is usually near the end, and the genesis link at `0` is the last thing
    // tried rather than the first.
    for anchored_records in (0..now).rev() {
        if head_after(records, anchored_records)
            .is_some_and(|found| anchor.head.eq_ignore_ascii_case(found))
        {
            return Err(Mismatch::Advanced {
                anchored_records,
                records: now,
                appended: now - anchored_records,
            });
        }
    }

    Err(Mismatch::Absent {
        expected: anchor.head.clone(),
        records: now,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::audit::chain;
    use crate::constants::{AUDIT_RECORD_VERSION, HASH_HEX_LEN_BLAKE3};

    /// A sealed chain of `count` correctly linked records.
    fn chain(count: u64) -> Vec<AuditRecord> {
        let mut records = Vec::new();
        let mut previous = AUDIT_CHAIN_GENESIS_PREV.to_string();
        for index in 0..count {
            let mut record = AuditRecord {
                v: Some(AUDIT_RECORD_VERSION),
                index,
                time: format!("2026-07-26T00:00:{index:02}Z"),
                op: "copy".into(),
                result: "success".into(),
                path: format!("photos/{index}.jpg"),
                size: 1000 + index,
                prev: previous.clone(),
                ..AuditRecord::default()
            };
            record.hash = chain::compute_hash(&record);
            previous.clone_from(&record.hash);
            records.push(record);
        }
        records
    }

    /// Verify a chain and compare an anchor against it, the way the command does.
    fn check(anchor: &str, records: &[AuditRecord]) -> Result<(), Mismatch> {
        let verified = chain::verify(records).expect("the fixture chain verifies");
        compare(
            &Anchor::parse(anchor).expect("a well-formed anchor"),
            &verified,
            records,
        )
    }

    #[test]
    fn an_anchor_is_one_copy_pasteable_token_carrying_both_numbers() {
        let anchor = Anchor::of(4, &"ab".repeat(32));
        assert_eq!(anchor.to_string(), format!("4:{}", "ab".repeat(32)));
        // Round trip: what the command prints is what the flag accepts, count
        // and all — equality is over both fields, so a count lost in the parse
        // fails here.
        assert_eq!(Anchor::parse(&anchor.to_string()).unwrap(), anchor);
        assert_eq!(anchor.head(), "ab".repeat(32));
    }

    #[test]
    fn a_bare_head_hash_is_accepted_and_stays_uncounted() {
        // An operator who pasted the `head` field out of `--json`, or out of a
        // third-party verifier, must not be told their anchor is malformed.
        let bare = Anchor::parse(&"cd".repeat(32)).unwrap();
        assert_eq!(bare.to_string(), "cd".repeat(32));
        // And it is *not* the counted anchor for the same hash: the two carry
        // different evidence and compare differently.
        assert_ne!(bare, Anchor::of(1, &"cd".repeat(32)));
    }

    #[test]
    fn surrounding_whitespace_is_not_a_usage_error() {
        // `--expect-head "$(cat anchor.txt)"` carries a trailing newline.
        let anchor = Anchor::parse(&format!("  7:{}\n", "ef".repeat(32))).unwrap();
        assert_eq!(anchor, Anchor::of(7, &"ef".repeat(32)));
    }

    #[test]
    fn a_malformed_anchor_is_refused_with_both_spellings_named() {
        for bad in [
            "",
            "not-a-hash",
            // Truncated: the exact forgery a width check exists to stop.
            &"ab".repeat(16),
            &format!("x:{}", "ab".repeat(32)),
            &format!("-1:{}", "ab".repeat(32)),
            &format!("4:{}", "zz".repeat(32)),
        ] {
            let error = Anchor::parse(bad).unwrap_err();
            assert!(
                error.contains("dctl audit head"),
                "{bad:?} produced an unhelpful message: {error}"
            );
        }
    }

    #[test]
    fn a_chain_that_ends_at_the_anchor_matches() {
        let records = chain(5);
        let head = records[4].hash.clone();
        check(&format!("5:{head}"), &records).expect("counted anchor");
        check(&head, &records).expect("bare anchor");
        // Hex has two spellings and a conforming writer may choose either.
        check(&head.to_uppercase(), &records).expect("upper-case anchor");
    }

    #[test]
    fn an_empty_chain_matches_a_genesis_anchor() {
        // "Nothing has been appended" is a real state with a real head, and a
        // fresh vault's anchor names it.
        check(&format!("0:{AUDIT_CHAIN_GENESIS_PREV}"), &[]).expect("counted");
        check(AUDIT_CHAIN_GENESIS_PREV, &[]).expect("bare");
    }

    #[test]
    fn dropping_the_last_two_records_is_reported_as_truncation_with_the_count() {
        // THE break this module exists for. Before it, this exact forgery
        // reported `intact` and exited 0.
        let full = chain(9);
        let anchor = Anchor::of(9, &full[8].hash).to_string();

        let mut truncated = full.clone();
        truncated.truncate(7);

        assert_eq!(
            check(&anchor, &truncated).unwrap_err(),
            Mismatch::Truncated {
                anchored_records: 9,
                records: 7,
                missing: 2,
            }
        );
    }

    #[test]
    fn every_depth_of_truncation_is_counted_exactly() {
        // One record, all but one, and the whole log. A count that was right for
        // one depth and wrong for another would be worse than no count.
        let full = chain(6);
        let anchor = Anchor::of(6, &full[5].hash).to_string();

        for (kept, missing) in [(5, 1), (4, 2), (1, 5), (0, 6)] {
            let mut short = full.clone();
            short.truncate(kept);
            assert_eq!(
                check(&anchor, &short).unwrap_err(),
                Mismatch::Truncated {
                    anchored_records: 6,
                    records: kept,
                    missing,
                },
                "truncating to {kept} records"
            );
        }
    }

    #[test]
    fn a_truncation_says_the_word_and_names_the_number() {
        // The message is the product here: an exit code alone does not tell an
        // investigator what happened or how much of it.
        let full = chain(9);
        let mut truncated = full.clone();
        truncated.truncate(7);
        let said = check(&Anchor::of(9, &full[8].hash).to_string(), &truncated)
            .unwrap_err()
            .to_string();

        assert!(said.contains("TRUNCATION"), "{said}");
        assert!(said.contains("2 records have been removed"), "{said}");
        assert!(said.contains("from the end"), "{said}");
    }

    #[test]
    fn a_bare_anchor_reports_truncation_it_cannot_count() {
        // Honest about the limit rather than guessing a number: a head hash
        // carries no length, so there is nothing to subtract.
        let full = chain(9);
        let mut truncated = full.clone();
        truncated.truncate(7);

        let mismatch = check(&full[8].hash, &truncated).unwrap_err();
        assert_eq!(
            mismatch,
            Mismatch::Absent {
                expected: full[8].hash.clone(),
                records: 7,
            }
        );
        let said = mismatch.to_string();
        assert!(said.contains("TRUNCATION OR DIVERGENCE"), "{said}");
        assert!(said.contains("cannot be known"), "{said}");
        // And it names the remedy for next time.
        assert!(said.contains("<records>:<hash>"), "{said}");
    }

    #[test]
    fn a_log_that_grew_since_the_anchor_is_stale_and_not_tampering() {
        // The case that decides whether the flag is usable on a live vault. A
        // chain that legitimately grew must not be reported as an attack, or
        // operators will stop passing the flag — and a defence nobody runs is
        // not a defence.
        let full = chain(10);

        for anchored in [0_usize, 1, 7, 9] {
            let head = head_after(&full, anchored).unwrap().to_string();
            assert_eq!(
                check(&format!("{anchored}:{head}"), &full).unwrap_err(),
                Mismatch::Advanced {
                    anchored_records: anchored,
                    records: 10,
                    appended: 10 - anchored,
                },
                "an anchor taken at {anchored} records"
            );
            // And the same conclusion from a bare hash, by scanning.
            assert_eq!(
                check(&head, &full).unwrap_err(),
                Mismatch::Advanced {
                    anchored_records: anchored,
                    records: 10,
                    appended: 10 - anchored,
                }
            );
        }
    }

    #[test]
    fn a_stale_anchor_says_nothing_was_removed() {
        let full = chain(10);
        let mismatch = check(&Anchor::of(6, &full[5].hash).to_string(), &full).unwrap_err();
        let said = mismatch.to_string();
        assert!(said.contains("4 records were appended"), "{said}");
        assert!(said.contains("Nothing was removed"), "{said}");
        assert!(!said.contains("TRUNCATION"), "{said}");
        assert!(mismatch.hint().contains("No records were removed"));
    }

    #[test]
    fn a_rewritten_history_is_divergence_rather_than_truncation() {
        // Same length, different content: the anchored position holds a record
        // that is not the one that was anchored.
        let mine = chain(6);
        let mut theirs = chain(6);
        theirs[3].path = "photos/forged.jpg".into();
        // Re-seal from the edit forward, so the chain itself still verifies —
        // which is precisely the forgery an anchor is the only defence against.
        let mut previous = theirs[2].hash.clone();
        for record in theirs.iter_mut().skip(3) {
            record.prev.clone_from(&previous);
            record.hash = chain::compute_hash(record);
            previous.clone_from(&record.hash);
        }

        let mismatch = check(&Anchor::of(6, &mine[5].hash).to_string(), &theirs).unwrap_err();
        assert!(
            matches!(
                mismatch,
                Mismatch::Diverged {
                    anchored_records: 6,
                    ..
                }
            ),
            "{mismatch:?}"
        );
        let said = mismatch.to_string();
        assert!(said.contains("DIVERGENCE"), "{said}");
        assert!(said.contains("rewritten"), "{said}");
    }

    #[test]
    fn a_wholly_different_chain_is_not_read_as_a_stale_anchor() {
        // The scan must not find a foreign head by accident, and a counted
        // anchor must not report "advanced" for a log it was never taken from.
        let mine = chain(4);
        let theirs = {
            let mut other = chain(4);
            let mut previous = AUDIT_CHAIN_GENESIS_PREV.to_string();
            for record in &mut other {
                record.remote = "somewhere-else".into();
                record.prev.clone_from(&previous);
                record.hash = chain::compute_hash(record);
                previous.clone_from(&record.hash);
            }
            other
        };

        assert!(matches!(
            check(&mine[3].hash, &theirs).unwrap_err(),
            Mismatch::Absent { .. }
        ));
        assert!(matches!(
            check(&Anchor::of(4, &mine[3].hash).to_string(), &theirs).unwrap_err(),
            Mismatch::Diverged { .. }
        ));
    }

    #[test]
    fn a_wiped_log_is_reported_against_both_spellings() {
        // `> audit.jsonl`. The counted anchor gives the exact loss; the bare one
        // says it cannot count and why.
        let full = chain(12);

        assert_eq!(
            check(&Anchor::of(12, &full[11].hash).to_string(), &[]).unwrap_err(),
            Mismatch::Truncated {
                anchored_records: 12,
                records: 0,
                missing: 12,
            }
        );
        assert!(matches!(
            check(&full[11].hash, &[]).unwrap_err(),
            Mismatch::Absent { records: 0, .. }
        ));
    }

    #[test]
    fn a_replayed_tail_is_not_mistaken_for_growth() {
        // Appending a copy of the last record forks the index sequence, so the
        // chain itself fails first — but if it did not, the anchor would still
        // see a head it does not know.
        let mut records = chain(5);
        let anchor = Anchor::of(5, &records[4].hash).to_string();
        let replay = records[4].clone();
        records.push(replay);

        // The chain is what catches this one; assert that rather than pretending
        // the anchor did it.
        let broken = chain::verify(&records).unwrap_err();
        assert!(matches!(
            broken.kind,
            chain::BreakKind::IndexDiscontinuity { .. }
        ));

        // And with the duplicate re-indexed and re-sealed — a chain that *does*
        // verify — the anchor still refuses it as growth it did not authorise.
        records[5].index = 5;
        records[5].prev = records[4].hash.clone();
        records[5].hash = chain::compute_hash(&records[5]);
        assert_eq!(
            check(&anchor, &records).unwrap_err(),
            Mismatch::Advanced {
                anchored_records: 5,
                records: 6,
                appended: 1,
            }
        );
    }

    #[test]
    fn the_mismatch_serialises_with_its_kind_inlined_and_its_counts_readable() {
        let full = chain(9);
        let mut truncated = full.clone();
        truncated.truncate(7);
        let mismatch = check(&Anchor::of(9, &full[8].hash).to_string(), &truncated).unwrap_err();

        let json = serde_json::to_string(&mismatch).unwrap();
        assert!(json.contains("\"kind\":\"truncated\""), "{json}");
        assert!(json.contains("\"missing\":2"), "{json}");
        assert!(json.contains("\"anchored_records\":9"), "{json}");
    }

    #[test]
    fn an_anchor_serialises_as_the_token_it_prints() {
        let anchor = Anchor::of(3, &"1a".repeat(32));
        assert_eq!(
            serde_json::to_string(&anchor).unwrap(),
            format!("\"3:{}\"", "1a".repeat(32))
        );
    }

    #[test]
    fn a_count_of_one_reads_as_english() {
        // A tool that says "1 records have been removed" invites the reader to
        // wonder what else it got approximately right.
        let full = chain(6);
        let anchor = Anchor::of(6, &full[5].hash).to_string();

        let said = check(&anchor, &full[..5]).unwrap_err().to_string();
        assert!(said.contains("1 record has been removed"), "{said}");

        // `chain(7)` extends `chain(6)` record for record, so the anchor taken
        // at six is exactly one record behind it.
        let said = check(&anchor, &chain(7)).unwrap_err().to_string();
        assert!(said.contains("1 record was appended"), "{said}");
    }

    #[test]
    fn the_two_dangerous_kinds_and_the_benign_one_give_different_advice() {
        // A single hint for all four would either cry wolf on a stale anchor or
        // whisper on a truncation.
        let benign = Mismatch::Advanced {
            anchored_records: 1,
            records: 2,
            appended: 1,
        };
        let attack = Mismatch::Truncated {
            anchored_records: 2,
            records: 1,
            missing: 1,
        };
        assert_ne!(benign.hint(), attack.hint());
        assert!(attack.hint().contains("Do not delete"));
        assert!(attack.hint().contains("evidence"));
    }

    #[test]
    fn the_head_after_a_count_is_the_genesis_link_for_none() {
        let records = chain(3);
        assert_eq!(head_after(&records, 0), Some(AUDIT_CHAIN_GENESIS_PREV));
        assert_eq!(head_after(&records, 1), Some(records[0].hash.as_str()));
        assert_eq!(head_after(&records, 3), Some(records[2].hash.as_str()));
        assert_eq!(head_after(&records, 4), None);
        assert_eq!(AUDIT_CHAIN_GENESIS_PREV.len(), HASH_HEX_LEN_BLAKE3);
    }
}
