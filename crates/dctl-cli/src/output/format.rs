//! The serialisation format chosen for one command invocation.
//!
//! `--format` is what makes DCTL scriptable
//! ([the plan](https://doc.dctl.sh/project/plan) §16.3): the same command
//! either prints aligned columns for a human or emits machine-readable JSON, and
//! nothing about the *work* changes between the two. Keeping the choice in one
//! small enum — rather than a pair of booleans threaded through the writers —
//! means a new format is a new variant plus the matches the compiler then
//! demands, never a forgotten branch that silently prints text into a JSON
//! stream.

use clap::ValueEnum;
use serde::Serialize;

/// How structured results are serialised.
///
/// Parsed straight from `--format` by clap, so the variant names *are* the
/// user-facing spellings (`text`, `json`, `json-lines`) and cannot drift from a
/// hand-written parser.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Human-readable, aligned columns.
    #[default]
    Text,
    /// One JSON document for the whole result.
    Json,
    /// One JSON object per line (JSON Lines) — streams without buffering the
    /// entire result set, so it works on a ten-million-file listing.
    JsonLines,
}

impl Format {
    /// Whether this format is meant for a machine rather than a person.
    ///
    /// Callers use it to suppress anything a parser would choke on: the
    /// end-of-run summary, decorative separators, and human-oriented notes.
    #[must_use]
    pub const fn is_json(self) -> bool {
        matches!(self, Self::Json | Self::JsonLines)
    }

    /// Whether ANSI styling may be emitted in this format.
    ///
    /// Only [`Format::Text`] may be coloured. Escape sequences inside a JSON
    /// document are not merely ugly — they land inside string values and break
    /// every downstream parser, so `--color always --format json` must still
    /// produce clean JSON. This is the single place that rule is expressed.
    #[must_use]
    pub const fn permits_color(self) -> bool {
        matches!(self, Self::Text)
    }

    /// Whether each record must occupy exactly one line.
    ///
    /// True only for [`Format::JsonLines`], where the newline *is* the record
    /// separator: a consumer reads one line, parses it, and drops it, which is
    /// what keeps memory flat on a listing far larger than RAM.
    #[must_use]
    pub const fn is_line_delimited(self) -> bool {
        matches!(self, Self::JsonLines)
    }

    /// Serialise a value the way this format wants it on the wire.
    ///
    /// [`Format::JsonLines`] gets compact output because a pretty-printed record
    /// spanning several lines would destroy the one-record-per-line contract.
    /// Everything else gets indented output, including [`Format::Text`]: commands
    /// such as `lsjson` emit JSON whatever the global format is, and when a human
    /// asked for text they are reading the result themselves.
    ///
    /// # Errors
    /// Propagates any `serde_json` failure, which for a well-formed type means a
    /// non-string map key or a custom `Serialize` impl that itself failed.
    pub fn encode<T: Serialize + ?Sized>(self, value: &T) -> serde_json::Result<String> {
        if self.is_line_delimited() {
            serde_json::to_string(value)
        } else {
            serde_json::to_string_pretty(value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Format, ValueEnum};

    #[test]
    fn the_command_line_spellings_are_stable() {
        // These strings are in every script and CI job that calls DCTL;
        // renaming a variant must not silently rename a flag value.
        let spellings: Vec<String> = Format::value_variants()
            .iter()
            .filter_map(ValueEnum::to_possible_value)
            .map(|value| value.get_name().to_owned())
            .collect();
        assert_eq!(spellings, ["text", "json", "json-lines"]);
    }

    #[test]
    fn text_is_the_default() {
        // A user who passes no --format must get the human view.
        assert_eq!(Format::default(), Format::Text);
    }

    #[test]
    fn both_json_variants_are_machine_formats() {
        assert!(Format::Json.is_json());
        assert!(Format::JsonLines.is_json());
        assert!(!Format::Text.is_json());
    }

    #[test]
    fn only_text_may_be_coloured() {
        assert!(Format::Text.permits_color());
        assert!(!Format::Json.permits_color());
        assert!(!Format::JsonLines.permits_color());
    }

    #[test]
    fn json_lines_records_never_contain_a_newline() {
        // The newline is the record separator; a multi-line record would make
        // the stream unparseable one line at a time.
        let value = serde_json::json!({"path": "a/b.txt", "size": 12, "nested": {"k": 1}});
        let encoded = Format::JsonLines.encode(&value).unwrap();
        assert!(!encoded.contains('\n'), "got: {encoded}");
    }

    #[test]
    fn whole_document_formats_are_indented_for_reading() {
        let value = serde_json::json!({"path": "a/b.txt", "size": 12});
        for format in [Format::Json, Format::Text] {
            let encoded = format.encode(&value).unwrap();
            assert!(encoded.contains('\n'), "{format:?} produced: {encoded}");
        }
    }

    #[test]
    fn every_format_round_trips_through_a_parser() {
        let value = serde_json::json!({"unicode": "café", "quote": "a\"b"});
        for format in [Format::Text, Format::Json, Format::JsonLines] {
            let encoded = format.encode(&value).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&encoded).unwrap();
            assert_eq!(parsed, value, "{format:?} did not round-trip");
        }
    }
}
