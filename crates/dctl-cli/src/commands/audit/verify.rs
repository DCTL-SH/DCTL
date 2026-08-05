//! `dctl audit verify` — walk the chain and say whether it holds.
//!
//! The verdict is **data**, so it goes to stdout: a cron job's whole test is
//! `[ "$(dctl audit verify)" = intact ]`, and a machine reading `--json` gets a
//! document carrying the head hash or the exact break position. The exit code
//! carries the same answer for anything that branches on `$?`:
//! [`ExitCode::AuditChainBroken`] (24) and nothing else means the log failed.
//!
//! On a break the document is written **before** the error is returned. A
//! consumer that only gets a non-zero exit knows something is wrong; one that
//! also gets the record position knows where to look, and losing that because
//! the command failed would be exactly the wrong trade for a security event.
//!
//! ## `--expect-head`: the half the chain cannot do
//!
//! A walk proves that nothing was altered *inside* the log. It cannot prove that
//! nothing was removed from the **end** — drop the last two records and what
//! remains is a shorter chain whose every link still holds. The records an
//! attacker most wants gone are the most recent ones, so that is not a corner
//! case, it is the case.
//!
//! `--expect-head` takes the anchor `dctl audit head` printed, and asserts that
//! the chain **still ends there**. A disagreement is
//! [`ExitCode::AuditHeadMismatch`] (26) and the verdict word
//! [`AUDIT_VERDICT_HEAD_MISMATCH`] — never `intact`, which is the whole point:
//! a log with its tail cut off must not report the same word as a whole one.
//!
//! The two codes stay separate because the two findings are. 24 says the links
//! failed; 26 says the links held and this is not the chain you left. They call
//! for different first moves, and a script that pages on 24 should not be woken
//! by an anchor that is merely older than the log — which is one of the four
//! shapes [`crate::audit::anchor::Mismatch`] separates, and the one that keeps
//! the flag usable on a vault still in service.
//!
//! ## `proves`: one word, three claims, and the one that is never made
//!
//! `intact` has to be a single shell-comparable token, and a single token cannot
//! say which of several separate things it established. It establishes that no
//! record was **edited** and that none was **removed, reordered or inserted**;
//! with a matching `--expect-head` it also establishes that none was removed
//! from the **end**; and it never establishes **who wrote any of them**.
//!
//! The `--json` document therefore carries `proves` — the claims as separate
//! tokens, so a consumer branches on a list rather than on a word's reputation.
//! `authorship` is not in that vocabulary and there is no arm of this function
//! that can put it there. The chain is unkeyed BLAKE3 over public values, so
//! any process that can append a line to the log can append a correctly linked
//! one; [the audit-log reference](https://doc.dctl.sh/reference/audit-log) §11
//! is the argument for why DCTL cannot close that with a key it must itself be
//! able to use unattended, and what the operator does instead.
//! [`AUDIT_PROVES_AUTHORSHIP_NOTE`] says the same on the human stream,
//! unconditionally, because unlike length there is no flag that closes it.

use std::path::PathBuf;

use clap::Args;
use serde::Serialize;

use crate::audit::anchor::{self, Anchor, Mismatch};
use crate::constants::{
    AUDIT_PROVES_AUTHORSHIP_NOTE, AUDIT_PROVES_INTEGRITY, AUDIT_PROVES_LENGTH, AUDIT_PROVES_ORDER,
    AUDIT_VERDICT_BROKEN, AUDIT_VERDICT_HEAD_MISMATCH, AUDIT_VERDICT_INTACT,
    AUDIT_WITHOUT_ANCHOR_NOTE,
};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::output::Format;

use super::chain::{self, Break, Verified};
use super::source::{self, Log};

/// Arguments for `dctl audit verify`.
#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Chain to verify. Defaults to the log beside the configured index.
    #[arg(long, value_name = "PATH")]
    pub audit_log: Option<PathBuf>,

    /// Anchor the chain must end at, as `dctl audit head` printed it.
    ///
    /// Without this the chain is checked for edits and **not** for length: a
    /// truncated log passes, because nothing inside a log attests to its own
    /// size. Takes `<records>:<hash>` or a bare `<hash>`.
    #[arg(long, value_name = "ANCHOR", value_parser = Anchor::parse)]
    pub expect_head: Option<Anchor>,
}

/// The verdict, in the shape a machine consumer reads.
#[derive(Debug, Serialize)]
struct Verdict<'a> {
    /// [`AUDIT_VERDICT_INTACT`], [`AUDIT_VERDICT_BROKEN`] or
    /// [`AUDIT_VERDICT_HEAD_MISMATCH`].
    verdict: &'static str,
    /// Exactly which claims this verdict establishes, as separate tokens.
    ///
    /// `intact` is one word doing three jobs, and the three are not always all
    /// true: content and order always are, length only with a matching anchor,
    /// and **authorship never** — so the vocabulary
    /// ([`AUDIT_PROVES_INTEGRITY`], [`AUDIT_PROVES_ORDER`],
    /// [`AUDIT_PROVES_LENGTH`]) has no token for it and cannot acquire one by
    /// accident. A consumer that treats `verdict == "intact"` as "authentic" is
    /// making a claim this document declines to make, and now has a field to
    /// read instead of a manual to have read.
    ///
    /// Empty on a break: a chain that failed proves nothing.
    proves: &'static [&'static str],
    /// The file that was walked.
    log: String,
    /// How many records were read.
    records: usize,
    /// Head hash, present whenever the chain itself held — including on a head
    /// mismatch, where it is the value the caller needs in order to see what the
    /// log ends at now.
    #[serde(skip_serializing_if = "Option::is_none")]
    head: Option<&'a str>,
    /// The anchor the caller asserted, present only when one was given.
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_head: Option<&'a Anchor>,
    /// Where the chain failed, present only when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    broken_at: Option<&'a Break>,
    /// How the head differed from the anchor, present only when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    head_mismatch: Option<&'a Mismatch>,
}

/// What a chain that verified proves when nothing anchored its length.
///
/// Authorship is absent from all three of these lists, and there is no fourth
/// list that has it — see [`AUDIT_PROVES_AUTHORSHIP_NOTE`].
const PROVES_UNANCHORED: &[&str] = &[AUDIT_PROVES_INTEGRITY, AUDIT_PROVES_ORDER];

/// The same, and the length the matching anchor closed.
const PROVES_ANCHORED: &[&str] = &[
    AUDIT_PROVES_INTEGRITY,
    AUDIT_PROVES_ORDER,
    AUDIT_PROVES_LENGTH,
];

/// A chain that failed proves nothing at all — not even about the records
/// before the break, because a walk that stopped never reached the rest.
const PROVES_NOTHING: &[&str] = &[];

pub async fn run(ctx: &Ctx, args: &VerifyArgs) -> Result<()> {
    let log = source::load(&ctx.globals, args.audit_log.as_deref())?;
    report(
        ctx,
        &log,
        chain::verify(&log.records),
        args.expect_head.as_ref(),
    )
}

/// Emit the verdict, then fail if it was a failure.
fn report(
    ctx: &Ctx,
    log: &Log,
    outcome: std::result::Result<Verified, Break>,
    expected: Option<&Anchor>,
) -> Result<()> {
    let verified = match outcome {
        Err(broken) => {
            emit(
                ctx,
                &Verdict {
                    verdict: AUDIT_VERDICT_BROKEN,
                    proves: PROVES_NOTHING,
                    log: log.path.display().to_string(),
                    records: log.records.len(),
                    head: None,
                    expected_head: expected,
                    broken_at: Some(&broken),
                    head_mismatch: None,
                },
            )?;
            return Err(break_error(log, &broken));
        }
        Ok(verified) => verified,
    };

    // The links held. Whether the chain is the *whole* chain is a separate
    // question, and one only an anchor can answer.
    let mismatch = expected.and_then(|anchor| {
        anchor::compare(anchor, &verified, &log.records)
            .err()
            .map(|mismatch| (anchor, mismatch))
    });

    let Some((anchor, mismatch)) = mismatch else {
        emit(
            ctx,
            &Verdict {
                verdict: AUDIT_VERDICT_INTACT,
                // The anchor is what adds `length`, so the list is chosen by
                // whether one was given — and, because this arm is only reached
                // when `compare` found no mismatch, by whether it *held*.
                proves: if expected.is_some() {
                    PROVES_ANCHORED
                } else {
                    PROVES_UNANCHORED
                },
                log: log.path.display().to_string(),
                records: verified.records,
                head: Some(verified.head.as_str()),
                expected_head: expected,
                broken_at: None,
                head_mismatch: None,
            },
        )?;
        ctx.out.info(format!(
            "{} records verified, head {}",
            verified.records, verified.head
        ));
        if expected.is_none() {
            // Said out loud rather than left to the manual. `intact` without an
            // anchor is a claim about content, not about length, and an operator
            // who reads it as both has the one belief this command must not
            // create.
            ctx.out.info(AUDIT_WITHOUT_ANCHOR_NOTE);
        }
        // Unconditional, where the note above is conditional: an anchor closes
        // length and nothing closes authorship, so there is no flag whose
        // presence would make this one stop being true.
        ctx.out.info(AUDIT_PROVES_AUTHORSHIP_NOTE);
        return Ok(());
    };

    emit(
        ctx,
        &Verdict {
            verdict: AUDIT_VERDICT_HEAD_MISMATCH,
            // The links held, so content and order stand; the anchor did not, so
            // `length` must not be in the list. This is the arm where a
            // consumer reading only `verdict` would most easily go wrong, and
            // the one where the field earns its place.
            proves: PROVES_UNANCHORED,
            log: log.path.display().to_string(),
            records: verified.records,
            head: Some(verified.head.as_str()),
            expected_head: Some(anchor),
            broken_at: None,
            head_mismatch: Some(&mismatch),
        },
    )?;
    Err(head_mismatch_error(log, anchor, &verified, &mismatch))
}

/// The one place a chain break becomes an error, so its code and its wording
/// cannot drift between callers.
///
/// Shared with `head`, `list` and `export`: whichever subcommand notices a break
/// must exit 24, because a listing of a forged log that exits 0 is worse than no
/// listing at all.
pub fn break_error(log: &Log, broken: &Break) -> CliError {
    CliError::new(
        ExitCode::AuditChainBroken,
        format!("{}: {broken}", log.path.display()),
    )
    .with_hint(
        "The audit log no longer proves what it claims. Do not delete it: keep \
         this copy, compare it against any mirrored or offline copy, and treat \
         every operation recorded after the break as unattested.",
    )
}

/// The chain held; it is not the chain the caller anchored.
///
/// Names the file, what the anchor said, what the log says now, and what the
/// difference is in plain words — `TRUNCATION`, `DIVERGENCE`, or a stale anchor
/// — because an exit code alone tells an investigator nothing about how much
/// history is gone.
fn head_mismatch_error(
    log: &Log,
    anchor: &Anchor,
    verified: &Verified,
    mismatch: &Mismatch,
) -> CliError {
    CliError::new(
        ExitCode::AuditHeadMismatch,
        format!(
            "{}: {mismatch}. Anchored {anchor}; the chain verifies and now ends \
             at {}:{}",
            log.path.display(),
            verified.records,
            verified.head
        ),
    )
    .with_hint(mismatch.hint())
}

/// Write the verdict in whichever format was asked for.
///
/// Text gets the bare word, because that is what a shell test compares; both
/// JSON formats get the whole document, since a machine that asked for structure
/// wants the head hash and the break or mismatch detail too.
fn emit(ctx: &Ctx, verdict: &Verdict<'_>) -> Result<()> {
    match ctx.out.format() {
        Format::Text => ctx.out.line(verdict.verdict)?,
        Format::Json | Format::JsonLines => ctx.out.json(verdict)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::super::record::AuditRecord;
    use super::*;
    use crate::cli::globals::GlobalArgs;
    use crate::constants::AUDIT_CHAIN_GENESIS_PREV;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        Ctx::new(Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals)
    }

    fn sealed_chain(count: u64) -> Vec<AuditRecord> {
        let mut records = Vec::new();
        let mut previous = AUDIT_CHAIN_GENESIS_PREV.to_string();
        for index in 0..count {
            let mut record = AuditRecord {
                index,
                time: "2026-07-26T00:00:00Z".into(),
                op: "copy".into(),
                result: "success".into(),
                prev: previous.clone(),
                ..AuditRecord::default()
            };
            record.hash = chain::compute_hash(&record);
            previous.clone_from(&record.hash);
            records.push(record);
        }
        records
    }

    fn log(records: Vec<AuditRecord>) -> Log {
        Log {
            path: PathBuf::from("/tmp/audit.jsonl"),
            records,
        }
    }

    /// Run the whole report path over a chain, the way `run` does.
    fn check(records: Vec<AuditRecord>, expected: Option<&str>) -> Result<()> {
        let log = log(records);
        let outcome = chain::verify(&log.records);
        let anchor = expected.map(|raw| Anchor::parse(raw).expect("a well-formed anchor"));
        report(&ctx(&[]), &log, outcome, anchor.as_ref())
    }

    #[test]
    fn an_intact_chain_succeeds_in_every_format() {
        for args in [vec![], vec!["--json"], vec!["--format", "json-lines"]] {
            let ctx = ctx(&args);
            let log = log(sealed_chain(3));
            let outcome = chain::verify(&log.records);
            assert!(report(&ctx, &log, outcome, None).is_ok(), "{args:?}");
        }
    }

    #[test]
    fn a_broken_chain_exits_twenty_four() {
        // The exit code is a published contract; scripts branch on 24.
        let mut records = sealed_chain(4);
        records[2].op = "forged".into();

        let error = check(records, None).unwrap_err();
        assert_eq!(error.code(), ExitCode::AuditChainBroken);
        assert_eq!(error.code().as_i32(), 24);
    }

    #[test]
    fn the_error_names_the_exact_record_and_the_file() {
        let mut records = sealed_chain(6);
        records[4].path = "forged.jpg".into();
        let log = log(records);
        let broken = chain::verify(&log.records).unwrap_err();

        let error = break_error(&log, &broken);
        assert!(error.message().contains("record 4"), "{}", error.message());
        assert!(error.message().contains("audit.jsonl"));
        // The hint must tell an operator what *not* to do first.
        assert!(error.hint().unwrap().contains("Do not delete"));
    }

    #[test]
    fn dropping_the_last_two_records_no_longer_reports_intact() {
        // THE defect. Before `--expect-head` this exact forgery — the classic
        // and complete break of a hash chain — verified perfectly and exited 0.
        let full = sealed_chain(9);
        let anchor = format!("9:{}", full[8].hash);

        // Unanchored, it still passes, and that is honest: the links do hold.
        check(full[..7].to_vec(), None).expect("the shorter chain is internally sound");

        // Anchored, it is caught, counted and refused.
        let error = check(full[..7].to_vec(), Some(&anchor)).unwrap_err();
        assert_eq!(error.code(), ExitCode::AuditHeadMismatch);
        assert_eq!(error.code().as_i32(), 26);
        assert!(
            error.message().contains("TRUNCATION"),
            "{}",
            error.message()
        );
        assert!(
            error.message().contains("2 records have been removed"),
            "{}",
            error.message()
        );
        assert!(error.hint().unwrap().contains("Do not delete"));
    }

    #[test]
    fn a_matching_anchor_verifies_and_exits_zero() {
        let records = sealed_chain(5);
        let head = records[4].hash.clone();
        check(records.clone(), Some(&format!("5:{head}"))).expect("counted anchor");
        check(records, Some(&head)).expect("bare anchor");
    }

    #[test]
    fn a_stale_anchor_is_refused_but_says_nothing_was_removed() {
        // The case that decides whether operators keep passing the flag. It must
        // not read as an attack, and it must not be silent either: records the
        // anchor does not cover were appended, and that is worth knowing.
        let records = sealed_chain(9);
        let error = check(records.clone(), Some(&format!("6:{}", records[5].hash))).unwrap_err();

        assert_eq!(error.code(), ExitCode::AuditHeadMismatch);
        assert!(
            error.message().contains("Nothing was removed"),
            "{}",
            error.message()
        );
        assert!(
            !error.message().contains("TRUNCATION"),
            "{}",
            error.message()
        );
        assert!(error.hint().unwrap().contains("No records were removed"));
    }

    #[test]
    fn a_head_mismatch_is_never_the_word_intact() {
        // The title of the defect, asserted on the bytes that reach stdout
        // rather than on an exit code: a cron whose whole test is
        // `[ "$(dctl audit verify …)" = intact ]` must fail on a truncated log.
        let full = sealed_chain(9);
        let verified = chain::verify(&full[..7]).unwrap();
        let anchor = Anchor::parse(&format!("9:{}", full[8].hash)).unwrap();
        let mismatch = anchor::compare(&anchor, &verified, &full[..7]).unwrap_err();

        let verdict = Verdict {
            verdict: AUDIT_VERDICT_HEAD_MISMATCH,
            proves: PROVES_UNANCHORED,
            log: "/tmp/a.jsonl".into(),
            records: 7,
            head: Some(&verified.head),
            expected_head: Some(&anchor),
            broken_at: None,
            head_mismatch: Some(&mismatch),
        };
        assert_ne!(verdict.verdict, AUDIT_VERDICT_INTACT);

        let json = serde_json::to_string(&verdict).unwrap();
        assert!(json.contains("\"verdict\":\"head-mismatch\""), "{json}");
        assert!(json.contains("\"kind\":\"truncated\""), "{json}");
        assert!(json.contains("\"missing\":2"), "{json}");
        // The head the log has *now* stays in the document: an operator needs it
        // to see what the chain ends at before deciding anything.
        assert!(json.contains("\"head\""), "{json}");
        assert!(json.contains("\"expected_head\":\"9:"), "{json}");
    }

    #[test]
    fn no_verdict_this_command_can_produce_claims_authorship() {
        // Pinned as a property of the code rather than as a sentence in a
        // document nobody diffs. The chain is unkeyed — its hash is BLAKE3 over
        // values anyone can read — so a correctly linked *append* is available
        // to anybody who can write the file, and there is no state of this
        // command in which that stops being so.
        //
        // Two properties, and together they are what makes the claim structural
        // rather than a spot check. **The vocabulary has no authorship token**,
        // and **every list is drawn from the vocabulary** — so no list can spell
        // a claim the vocabulary does not have.
        const VOCABULARY: &[&str] = &[
            AUDIT_PROVES_INTEGRITY,
            AUDIT_PROVES_ORDER,
            AUDIT_PROVES_LENGTH,
        ];
        for token in VOCABULARY {
            assert_ne!(*token, "authorship", "the vocabulary grew the claim");
        }
        for list in [PROVES_NOTHING, PROVES_UNANCHORED, PROVES_ANCHORED] {
            for token in list {
                assert!(
                    VOCABULARY.contains(token),
                    "a verdict list holds a token the vocabulary does not: {token}"
                );
            }
        }

        // What this cannot enforce, said rather than implied: nothing makes the
        // compiler notice a **fourth** list added for a future keyed mode and
        // left out of the loop above. Rust has no reflection over consts and
        // there is no enum to be exhaustive about. The guard against that is
        // this test's name and
        // [the audit-log reference](https://doc.dctl.sh/reference/audit-log)
        // §11's normative statement, not the type system — so a pass that adds
        // one has to come here on purpose.
    }

    #[test]
    fn length_is_claimed_only_when_an_anchor_was_given_and_held() {
        // The three states of the same chain, and the field that separates
        // them. `intact` is one word for the first two, which is exactly why a
        // machine consumer needs the list instead.
        let records = sealed_chain(9);
        let head = records[8].hash.clone();

        // No anchor: content and order, and deliberately not length.
        assert_eq!(
            PROVES_UNANCHORED,
            [AUDIT_PROVES_INTEGRITY, AUDIT_PROVES_ORDER]
        );
        assert!(!PROVES_UNANCHORED.contains(&AUDIT_PROVES_LENGTH));
        check(records.clone(), None).expect("the chain holds");

        // A matching anchor: length as well.
        assert!(PROVES_ANCHORED.contains(&AUDIT_PROVES_LENGTH));
        check(records.clone(), Some(&format!("9:{head}"))).expect("and it ends where it was left");

        // An anchor that does not hold reaches the mismatch arm, whose list is
        // the *unanchored* one — the links held, the length did not. A verdict
        // that kept `length` here would be a claim to have proved something
        // this run did not.
        let error = check(records, Some(&format!("11:{}", "ab".repeat(32)))).unwrap_err();
        assert_eq!(error.code(), ExitCode::AuditHeadMismatch);
    }

    #[test]
    fn the_authorship_note_never_reaches_the_word_a_script_compares() {
        // The note is a claim about scope, so it belongs on stderr beside the
        // record count — not in the one token
        // `[ "$(dctl audit verify)" = intact ]` reads. Pinned because moving it
        // to `line` would break every operator's cron and would look like a
        // documentation improvement while doing it.
        assert!(
            !AUDIT_PROVES_AUTHORSHIP_NOTE.contains(AUDIT_VERDICT_INTACT),
            "the note must not contain the verdict word: {AUDIT_PROVES_AUTHORSHIP_NOTE}"
        );
        assert!(
            AUDIT_PROVES_AUTHORSHIP_NOTE.contains("unkeyed"),
            "the note has to say *why*, or it is a disclaimer rather than a fact: \
             {AUDIT_PROVES_AUTHORSHIP_NOTE}"
        );
        assert!(
            AUDIT_PROVES_AUTHORSHIP_NOTE.contains("doc.dctl.sh/reference/audit-log"),
            "and where the argument is: {AUDIT_PROVES_AUTHORSHIP_NOTE}"
        );
    }

    #[test]
    fn a_broken_chain_outranks_a_head_mismatch() {
        // Both are wrong at once: the anchor cannot match a chain whose links
        // failed. 24 is the more specific and more serious finding, and it names
        // a record position that 26 cannot.
        let mut records = sealed_chain(6);
        records[2].path = "forged.jpg".into();
        let error = check(records, Some(&format!("6:{}", "ab".repeat(32)))).unwrap_err();
        assert_eq!(error.code(), ExitCode::AuditChainBroken);
    }

    #[test]
    fn the_flag_takes_both_spellings_and_refuses_a_third() {
        // The parser is the flag's contract: what `dctl audit head` prints, and
        // the bare hash somebody pasted out of `--json`.
        assert!(Anchor::parse(&"ab".repeat(32)).is_ok());
        assert!(Anchor::parse(&format!("12:{}", "ab".repeat(32))).is_ok());

        let error = Anchor::parse("head").unwrap_err();
        assert!(error.contains("dctl audit head"), "{error}");
    }

    #[test]
    fn the_verdict_document_carries_the_head_or_the_break_but_never_both() {
        let intact = Verdict {
            verdict: AUDIT_VERDICT_INTACT,
            proves: PROVES_UNANCHORED,
            log: "/tmp/a.jsonl".into(),
            records: 2,
            head: Some("ab"),
            expected_head: None,
            broken_at: None,
            head_mismatch: None,
        };
        let json = serde_json::to_string(&intact).unwrap();
        assert!(json.contains("\"verdict\":\"intact\""), "{json}");
        assert!(json.contains("\"head\":\"ab\""), "{json}");
        assert!(!json.contains("broken_at"), "{json}");
        assert!(!json.contains("expected_head"), "{json}");
        assert!(!json.contains("head_mismatch"), "{json}");

        let mut records = sealed_chain(3);
        records[1].size += 1;
        let broken = chain::verify(&records).unwrap_err();
        let failed = Verdict {
            verdict: AUDIT_VERDICT_BROKEN,
            proves: PROVES_NOTHING,
            log: "/tmp/a.jsonl".into(),
            records: 3,
            head: None,
            expected_head: None,
            broken_at: Some(&broken),
            head_mismatch: None,
        };
        let json = serde_json::to_string(&failed).unwrap();
        assert!(json.contains("\"verdict\":\"broken\""), "{json}");
        assert!(json.contains("\"position\":1"), "{json}");
        assert!(!json.contains("\"head\""), "{json}");
    }

    #[test]
    fn an_empty_chain_is_reported_as_intact_with_no_records() {
        // Honest: nothing has been appended. The module docs are explicit that
        // this is not a claim that nothing happened — and a genesis anchor is
        // what turns it into a claim about length too.
        let log = log(Vec::new());
        let verified = chain::verify(&log.records).unwrap();
        assert_eq!(verified.records, 0);

        check(Vec::new(), Some(AUDIT_CHAIN_GENESIS_PREV))
            .expect("a fresh vault anchors at genesis");

        // And a wiped log is caught against an anchor that covered records.
        let records = sealed_chain(12);
        let error = check(Vec::new(), Some(&format!("12:{}", records[11].hash))).unwrap_err();
        assert_eq!(error.code(), ExitCode::AuditHeadMismatch);
        assert!(
            error.message().contains("12 records have been removed"),
            "{}",
            error.message()
        );
    }
}
