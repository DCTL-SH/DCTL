//! The on-disk encoding: one JSON object per line, and the framing rules that
//! make a half-written record detectable.
//!
//! ## Why JSON Lines
//!
//! An append-only chain has to outlive the tool that wrote it. One
//! self-describing record per line is greppable, diffable, safely appendable,
//! and readable by any language's standard library in twenty years — the same
//! reasoning that governs the object format (`PLAN.md` §13.1). A database would
//! be faster to query and unreadable the day its file format is orphaned; an
//! auditor with `grep` and a hash tool is the design target.
//!
//! ## The terminator is the commit point
//!
//! A record counts if and only if its [`AUDIT_LOG_LINE_TERMINATOR`] is on the
//! medium. That single rule is what makes an append atomic in the only sense
//! that matters: a run that dies part-way through writing a record leaves bytes
//! after the last terminator, and those bytes are unambiguously *not a record* —
//! never "a record that might be short". The chain up to the last terminator is
//! untouched and still verifies, which is the guarantee `PLAN.md` §6 demands of
//! every durable write: no partial state is ever surfaced as success.
//!
//! [`frame`] is the pure half of that rule, over a byte slice, so the framing
//! can be tested exhaustively without a filesystem. [`super::write`] does the
//! seeking and the repair.
//!
//! ## Why the encoder cannot emit a raw terminator
//!
//! `serde_json` escapes every control character inside a string, so no field
//! value can put a bare newline into the middle of a line even if one somehow
//! survived [`super::redaction`]. The two defences are independent on purpose:
//! the redaction protects the *hash*, this protects the *framing*, and neither
//! is allowed to depend on the other being correct.

use crate::constants::AUDIT_LOG_LINE_TERMINATOR;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

use super::record::AuditRecord;

/// Encode one record as the bytes of its line, terminator included.
///
/// # Errors
/// [`ExitCode::Uncategorised`] if the record cannot be serialised. Serialising
/// a struct of strings and integers cannot fail in practice, but "cannot fail in
/// practice" is not a reason to `unwrap` in the one code path whose whole job is
/// to be trustworthy after a crash.
pub fn encode_line(record: &AuditRecord) -> Result<Vec<u8>> {
    let mut line = serde_json::to_vec(record).map_err(|error| {
        CliError::new(
            ExitCode::Uncategorised,
            format!("cannot encode an audit record: {error}"),
        )
        .with_hint(
            "The operation itself may have completed; its audit record did not. \
             Treat the log as incomplete from this point.",
        )
    })?;
    line.push(AUDIT_LOG_LINE_TERMINATOR);
    Ok(line)
}

/// Decode one record from the bytes of a line, terminator excluded.
///
/// # Errors
/// The `serde_json` failure, for the caller to classify. A line that will not
/// parse is treated as tampering rather than as a formatting inconvenience —
/// see `crate::commands::audit::source` for why the two are indistinguishable.
pub fn decode(line: &[u8]) -> std::result::Result<AuditRecord, serde_json::Error> {
    serde_json::from_slice(line)
}

/// Whether a line carries a record, as opposed to being blank.
///
/// A trailing newline is normal and a blank line is evidence of nothing, so both
/// are skipped rather than reported. This is the same rule the reader applies,
/// stated once so the two cannot drift.
#[must_use]
pub fn is_blank(line: &[u8]) -> bool {
    line.iter().all(u8::is_ascii_whitespace)
}

/// What the end of a log looks like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tail<'a> {
    /// The last complete, non-blank record line, without its terminator.
    ///
    /// `None` means the log holds no complete record at all — either it is
    /// empty, or every byte in it is part of an unterminated fragment.
    pub last: Option<&'a [u8]>,
    /// Bytes after the final terminator.
    ///
    /// **Non-empty means a torn write**: a previous run died between starting
    /// the append and completing it, so this is a partial record that was never
    /// acknowledged to anybody.
    pub fragment: &'a [u8],
}

/// The result of framing a window onto the end of a log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing<'a> {
    /// The window was wide enough to answer the question.
    Resolved(Tail<'a>),
    /// The last record starts before the window does; widen it and try again.
    ///
    /// Returned rather than guessing, because a line whose beginning is outside
    /// the window would decode as a truncated record — and a truncated record
    /// read as the chain's head is how a writer would link the next record to a
    /// hash that never existed.
    NeedMore,
}

/// Frame the end of a log from a window onto its final bytes.
///
/// `anchored` says the window starts at file offset 0, which is what makes a
/// negative answer final: only then is "no complete record before this point"
/// the same statement as "no complete record at all".
///
/// The scan is backwards because the writer needs exactly two facts — the head
/// hash and the next index — and both live in the final record. Walking the file
/// forwards would make every append cost the whole history (`PLAN.md` §D10).
#[must_use]
pub fn frame(window: &[u8], anchored: bool) -> Framing<'_> {
    let terminator = window
        .iter()
        .rposition(|byte| *byte == AUDIT_LOG_LINE_TERMINATOR);

    let (body, fragment) = match terminator {
        // `body` keeps its final terminator, so every segment inside it is a
        // complete line by construction.
        Some(position) => window.split_at(position + 1),
        None => (&window[..0], window),
    };

    if body.is_empty() {
        // Nothing is terminated inside the window. Either the log holds no
        // record at all, or the record we want starts further back.
        return if anchored {
            Framing::Resolved(Tail {
                last: None,
                fragment,
            })
        } else {
            Framing::NeedMore
        };
    }

    // Walk backwards over the terminated lines, skipping blank ones, until a
    // line with content is found — and only accept it if its *start* is inside
    // the window too.
    let mut end = body.len() - 1;
    loop {
        let start = body[..end]
            .iter()
            .rposition(|byte| *byte == AUDIT_LOG_LINE_TERMINATOR)
            .map_or(0, |position| position + 1);
        let line = &body[start..end];

        if !is_blank(line) {
            return if start == 0 && !anchored {
                // The line may be a suffix of a longer one that began before
                // the window.
                Framing::NeedMore
            } else {
                Framing::Resolved(Tail {
                    last: Some(line),
                    fragment,
                })
            };
        }

        if start == 0 {
            return if anchored {
                Framing::Resolved(Tail {
                    last: None,
                    fragment,
                })
            } else {
                Framing::NeedMore
            };
        }
        // Step over the terminator that ended the line before this one.
        end = start - 1;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::constants::AUDIT_CHAIN_GENESIS_PREV;

    fn record() -> AuditRecord {
        AuditRecord {
            v: Some(crate::constants::AUDIT_RECORD_VERSION),
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
            hash: "cc".repeat(32),
        }
    }

    fn resolved(window: &[u8], anchored: bool) -> Tail<'_> {
        match frame(window, anchored) {
            Framing::Resolved(tail) => tail,
            Framing::NeedMore => panic!("expected the window to resolve"),
        }
    }

    #[test]
    fn a_line_is_one_record_and_one_terminator() {
        let line = encode_line(&record()).unwrap();
        assert_eq!(line.last(), Some(&AUDIT_LOG_LINE_TERMINATOR));
        assert_eq!(
            line.iter()
                .filter(|byte| **byte == AUDIT_LOG_LINE_TERMINATOR)
                .count(),
            1,
            "a record must never span two lines"
        );
    }

    #[test]
    fn a_record_round_trips_through_the_encoding() {
        let line = encode_line(&record()).unwrap();
        let decoded = decode(&line[..line.len() - 1]).unwrap();
        assert_eq!(decoded, record());
    }

    #[test]
    fn a_field_holding_a_terminator_cannot_break_the_framing() {
        // Redaction should have escaped this already; the encoder must not rely
        // on that having happened.
        let mut awkward = record();
        awkward.path = "a\nb".into();
        let line = encode_line(&awkward).unwrap();
        assert_eq!(
            line.iter()
                .filter(|byte| **byte == AUDIT_LOG_LINE_TERMINATOR)
                .count(),
            1
        );
        assert_eq!(decode(&line[..line.len() - 1]).unwrap().path, "a\nb");
    }

    #[test]
    fn an_empty_log_has_no_record_and_no_fragment() {
        let tail = resolved(b"", true);
        assert_eq!(tail.last, None);
        assert!(tail.fragment.is_empty());
    }

    #[test]
    fn the_last_terminated_line_is_the_head() {
        let tail = resolved(b"one\ntwo\nthree\n", true);
        assert_eq!(tail.last, Some(&b"three"[..]));
        assert!(tail.fragment.is_empty());
    }

    #[test]
    fn bytes_after_the_last_terminator_are_a_torn_write() {
        // The crash signature: the terminator of the final record never landed,
        // so the record was never acknowledged to anybody.
        let tail = resolved(b"one\ntwo\n{\"index\":2,\"tim", true);
        assert_eq!(tail.last, Some(&b"two"[..]));
        assert_eq!(tail.fragment, b"{\"index\":2,\"tim");
    }

    #[test]
    fn a_log_that_is_nothing_but_a_fragment_has_no_head() {
        // A crash during the very first append. The chain has to start from
        // genesis, not from whatever the fragment happens to parse as.
        let tail = resolved(b"{\"index\":0", true);
        assert_eq!(tail.last, None);
        assert_eq!(tail.fragment, b"{\"index\":0");
    }

    #[test]
    fn trailing_blank_lines_are_skipped_to_reach_the_real_head() {
        let tail = resolved(b"one\ntwo\n\n   \n", true);
        assert_eq!(tail.last, Some(&b"two"[..]));
        assert!(tail.fragment.is_empty());
    }

    #[test]
    fn a_log_of_only_blank_lines_has_no_head() {
        let tail = resolved(b"\n \n\t\n", true);
        assert_eq!(tail.last, None);
    }

    #[test]
    fn an_unanchored_window_that_may_cut_a_line_asks_for_more() {
        // "ee\n" could be the tail of "three\n". Guessing would hand the writer
        // a truncated record as the chain's head.
        assert_eq!(frame(b"ee\n", false), Framing::NeedMore);
        // With one more terminator in view, the line's start is proven.
        assert_eq!(resolved(b"\nthree\n", false).last, Some(&b"three"[..]));
    }

    #[test]
    fn an_unanchored_window_of_blank_lines_asks_for_more() {
        // The real head may be further back than the blanks.
        assert_eq!(frame(b"\n\n", false), Framing::NeedMore);
        assert_eq!(frame(b"no terminator at all", false), Framing::NeedMore);
    }

    #[test]
    fn the_same_window_anchored_and_unanchored_differ_only_at_the_boundary() {
        // Anchoring is what makes a negative answer final.
        assert_eq!(resolved(b"three\n", true).last, Some(&b"three"[..]));
        assert_eq!(frame(b"three\n", false), Framing::NeedMore);
    }
}
