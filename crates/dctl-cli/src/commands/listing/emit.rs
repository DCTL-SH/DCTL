//! Writing a JSON document that is longer than memory.
//!
//! `serde_json::to_string(&all_the_entries)` is the obvious way to emit a
//! listing and the one thing `PLAN.md` §16.2 rules out: it needs the whole
//! result set in a `Vec` *and* the whole document in a `String` before the first
//! byte reaches the pipe. On a ten-million-object vault that is two copies of
//! the listing in RAM in exchange for output that could have started
//! immediately.
//!
//! So the brackets are written by hand around individually-encoded elements.
//! The result is byte-identical to what `serde_json`'s pretty printer would have
//! produced for the whole array — the indent is the same two spaces — while
//! memory stays at one element.
//!
//! Under [`Format::JsonLines`] there are no brackets at all: each element is one
//! compact line, which is the format that actually scales, and the one to reach
//! for when a listing is going into a pipeline rather than onto a screen.
//!
//! ## The empty case
//!
//! An empty listing must still be a valid document, so a run that pushed nothing
//! closes as `[]`. Emitting nothing at all would leave `jq` reading an empty
//! stream and reporting a parse error, which a script would then have to
//! distinguish from a real failure.

use serde::Serialize;

use crate::constants::{
    JSON_ARRAY_CLOSE, JSON_ARRAY_OPEN, JSON_ARRAY_SEPARATOR, JSON_EMPTY_ARRAY, JSON_INDENT,
};
use crate::error::Result;
use crate::output::{Format, Out};

/// Record separator inside a streamed document.
///
/// Always LF, never CRLF, on every platform: a JSON Lines consumer splits on LF
/// and would be handed a trailing `\r` on each record, and DCTL's output is
/// parsed far more often than it is read in Notepad.
const NEWLINE: char = '\n';

/// A JSON array or JSON Lines stream, written as it is produced.
pub struct Emitter<'a> {
    out: &'a Out,
    format: Format,
    written: u64,
}

impl<'a> Emitter<'a> {
    /// Start a document on `out`, in whichever format the run selected.
    #[must_use]
    pub fn new(out: &'a Out) -> Self {
        Self {
            format: out.format(),
            out,
            written: 0,
        }
    }

    /// Append one element.
    ///
    /// # Errors
    /// A stdout write failure other than a broken pipe, or a serialisation
    /// failure — which for these shapes means a `Serialize` impl changed
    /// underneath the listing.
    pub fn push<T: Serialize>(&mut self, value: &T) -> Result<()> {
        let chunk = element(self.format, value, self.written == 0)?;
        self.out.write(chunk)?;
        self.written += 1;
        Ok(())
    }

    /// Close the document.
    ///
    /// # Errors
    /// A stdout write failure other than a broken pipe.
    pub fn finish(self) -> Result<()> {
        self.out.write(closing(self.format, self.written))?;
        Ok(())
    }
}

/// Render one element, including whatever punctuation must precede it.
///
/// Pure, so the exact bytes are testable without a terminal: this is the part
/// that has to be right, and it is the part a `String`-returning function can be
/// held to.
fn element<T: Serialize>(format: Format, value: &T, first: bool) -> Result<String> {
    let encoded = format.encode(value).map_err(std::io::Error::other)?;

    if format.is_line_delimited() {
        return Ok(format!("{encoded}{NEWLINE}"));
    }

    let opener = if first {
        JSON_ARRAY_OPEN
    } else {
        JSON_ARRAY_SEPARATOR
    };
    Ok(format!("{opener}{NEWLINE}{}", indent(&encoded)))
}

/// Render the document's closing punctuation.
fn closing(format: Format, written: u64) -> String {
    if format.is_line_delimited() {
        return String::new();
    }
    if written == 0 {
        return format!("{JSON_EMPTY_ARRAY}{NEWLINE}");
    }
    format!("{NEWLINE}{JSON_ARRAY_CLOSE}{NEWLINE}")
}

/// Indent every line of an encoded element to array-member depth.
fn indent(encoded: &str) -> String {
    let mut out = String::with_capacity(encoded.len() + JSON_INDENT.len());
    for (index, line) in encoded.lines().enumerate() {
        if index > 0 {
            out.push(NEWLINE);
        }
        out.push_str(JSON_INDENT);
        out.push_str(line);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    /// Assemble a whole document the way [`Emitter`] would, so the test asserts
    /// on the bytes a consumer actually receives.
    fn document(format: Format, values: &[Value]) -> String {
        let mut out = String::new();
        for (index, value) in values.iter().enumerate() {
            out.push_str(&element(format, value, index == 0).expect("json values encode"));
        }
        out.push_str(&closing(format, values.len() as u64));
        out
    }

    #[test]
    fn an_array_document_parses_back_as_the_values_that_went_in() {
        let values = vec![
            json!({"Path": "a.txt", "Size": 1}),
            json!({"Path": "b/c", "Size": 2}),
        ];
        for format in [Format::Text, Format::Json] {
            let rendered = document(format, &values);
            let parsed: Value = serde_json::from_str(&rendered).expect("valid JSON");
            assert_eq!(parsed, Value::Array(values.clone()), "{format:?}");
        }
    }

    #[test]
    fn json_lines_emits_one_parseable_record_per_line() {
        let values = vec![json!({"Path": "a"}), json!({"Path": "b"})];
        let rendered = document(Format::JsonLines, &values);
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 2);
        for (line, expected) in lines.iter().zip(&values) {
            let parsed: Value = serde_json::from_str(line).expect("valid JSON per line");
            assert_eq!(&parsed, expected);
        }
    }

    #[test]
    fn an_empty_listing_is_still_a_valid_document() {
        // A consumer must be able to tell "no matches" from "the command
        // produced nothing because it crashed".
        let parsed: Value = serde_json::from_str(&document(Format::Json, &[])).unwrap();
        assert_eq!(parsed, Value::Array(Vec::new()));
        // JSON Lines has nothing to say about an empty stream, and says it.
        assert_eq!(document(Format::JsonLines, &[]), "");
    }

    #[test]
    fn a_single_element_array_closes_correctly() {
        let parsed: Value =
            serde_json::from_str(&document(Format::Json, &[json!({"a": 1})])).unwrap();
        assert_eq!(parsed, json!([{"a": 1}]));
    }

    #[test]
    fn the_streamed_array_matches_what_serde_would_have_produced_whole() {
        // The claim in the module docs, tested: streaming is an optimisation,
        // not a different output format.
        let values = vec![
            json!({"Path": "a", "Size": 1}),
            json!({"Path": "b", "Size": 2}),
        ];
        let whole = serde_json::to_string_pretty(&values).unwrap();
        assert_eq!(document(Format::Json, &values), format!("{whole}\n"));
    }

    #[test]
    fn no_record_of_a_line_delimited_stream_contains_a_newline() {
        // The newline *is* the record separator; a pretty-printed record would
        // make the stream unparseable one line at a time.
        let nested = json!({"Hashes": {"blake3": "ab"}, "Path": "a"});
        let rendered = element(Format::JsonLines, &nested, true).unwrap();
        assert_eq!(rendered.matches(NEWLINE).count(), 1);
        assert!(rendered.ends_with(NEWLINE));
    }

    #[test]
    fn indentation_reaches_every_line_of_a_nested_element() {
        let indented = indent("{\n  \"a\": 1\n}");
        for line in indented.lines() {
            assert!(line.starts_with(JSON_INDENT), "unindented line: {line:?}");
        }
    }

    #[test]
    fn unicode_and_quotes_survive_every_format() {
        let value = json!({"Path": "caf\u{e9}/a\"b.txt"});
        for format in [Format::Text, Format::Json, Format::JsonLines] {
            let rendered = document(format, std::slice::from_ref(&value));
            let text = rendered.trim();
            let parsed: Value = serde_json::from_str(text)
                .unwrap_or_else(|e| panic!("{format:?} produced invalid JSON: {e}\n{text}"));
            let first = match parsed {
                Value::Array(mut items) => items.pop().expect("one element"),
                other => other,
            };
            assert_eq!(first, value, "{format:?}");
        }
    }
}
