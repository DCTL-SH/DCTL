//! The shape of a `hashsum` result.
//!
//! The odd one out in the integrity family: its text form is **not** a table.
//! `dctl hashsum sha256 vault: > SUMS` has to produce a file `sha256sum -c` can
//! read, so stdout carries nothing but a digest, the
//! [two-space separator](crate::constants::HASHSUM_FIELD_SEPARATOR) and a path —
//! no header, no rule, no aligned columns, no summary. Every word of commentary
//! belongs on stderr.
//!
//! The JSON forms exist for consumers that would rather not parse a checksum
//! file, and they carry the algorithm alongside every digest: a bare hex string
//! with no algorithm attached is ambiguous between BLAKE3 and SHA-256, which
//! share a width.

// Some of what follows is not reachable from this build's `run` body: the engine
// has no entry point yet for the step that would call it (see the command's
// module documentation). It is written and unit-tested now, with the tests that
// pin its contract, rather than left until the engine lands — a machine-readable
// output format that first appears on the day it is needed is a format nobody
// reviewed.
#![allow(dead_code)]

use serde::Serialize;

use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::output::{Format, Out};

use super::algo::{Algorithm, format_line};

/// One object's hash.
#[derive(Clone, Debug, Serialize)]
pub struct Record {
    /// The algorithm this digest came from. Repeated on every record because a
    /// 64-character hex string alone does not say whether it is BLAKE3 or
    /// SHA-256, and a JSON Lines consumer sees records one at a time with no
    /// document-level context to fall back on.
    pub algorithm: String,
    /// Lower-case hex digest.
    pub hash: String,
    /// Logical vault path.
    pub path: String,
}

impl Record {
    #[must_use]
    pub fn new(algorithm: Algorithm, hash: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            algorithm: algorithm.slug(),
            hash: hash.into(),
            path: path.into(),
        }
    }
}

/// The whole result of one `hashsum` run.
#[derive(Clone, Debug)]
pub struct Report {
    algorithm: Algorithm,
    binary: bool,
    records: Vec<Record>,
}

impl Report {
    /// An empty report.
    #[must_use]
    pub const fn new(algorithm: Algorithm, binary: bool) -> Self {
        Self {
            algorithm,
            binary,
            records: Vec::new(),
        }
    }

    /// Add one object's hash.
    pub fn push(&mut self, record: Record) {
        self.records.push(record);
    }

    /// How many objects were hashed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether nothing was hashed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Render exactly the bytes stdout should receive.
    ///
    /// # Errors
    /// Only if serialisation fails, which is reported rather than swallowed.
    pub fn render(&self, out: &Out) -> Result<String> {
        match out.format() {
            // Deliberately not a table: this output is consumed by `sha256sum -c`.
            Format::Text => {
                let mut rendered = String::new();
                for record in &self.records {
                    rendered.push_str(&format_line(&record.hash, &record.path, self.binary));
                    rendered.push('\n');
                }
                Ok(rendered)
            }
            Format::Json => encode(Format::Json, &self.records).map(|json| format!("{json}\n")),
            Format::JsonLines => {
                let mut rendered = String::new();
                for record in &self.records {
                    rendered.push_str(&encode(Format::JsonLines, record)?);
                    rendered.push('\n');
                }
                Ok(rendered)
            }
        }
    }

    /// Write the report to stdout.
    ///
    /// # Errors
    /// Propagates a stdout write failure other than a broken pipe.
    pub fn emit(&self, out: &Out) -> Result<()> {
        let rendered = self.render(out)?;
        out.write(rendered)?;
        Ok(())
    }

    /// Whether every digest is the right shape for the algorithm.
    ///
    /// A guard against emitting a checksum file that cannot be checked: a
    /// truncated digest would make `sha256sum -c` report a mismatch, sending
    /// somebody hunting for corruption that never happened.
    #[must_use]
    pub fn digests_are_well_formed(&self) -> bool {
        self.records
            .iter()
            .all(|record| self.algorithm.is_well_formed(&record.hash))
    }
}

/// Serialise a value, turning a serde failure into a classified CLI error.
fn encode<T: Serialize + ?Sized>(format: Format, value: &T) -> Result<String> {
    format.encode(value).map_err(|error| {
        CliError::new(
            ExitCode::Uncategorised,
            format!("cannot serialise the hashsum report: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::HASHSUM_FIELD_SEPARATOR;
    use crate::output::{ColorChoice, Units};

    const EMPTY_BLAKE3: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    const OTHER_BLAKE3: &str = "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213";

    fn out(format: Format) -> Out {
        Out::new(format, ColorChoice::Never, Units::Binary, false, 0)
    }

    fn sample(binary: bool) -> Report {
        let mut report = Report::new(Algorithm::Blake3, binary);
        report.push(Record::new(Algorithm::Blake3, EMPTY_BLAKE3, "photos/a.jpg"));
        report.push(Record::new(
            Algorithm::Blake3,
            OTHER_BLAKE3,
            "photos/b b.jpg",
        ));
        report
    }

    #[test]
    fn text_output_is_a_checksum_file_and_nothing_else() {
        // No header, no rule, no summary — anything extra makes the file
        // unusable by `sha256sum -c`.
        let rendered = sample(false).render(&Out::plain()).unwrap();
        assert_eq!(
            rendered,
            format!("{EMPTY_BLAKE3}  photos/a.jpg\n{OTHER_BLAKE3}  photos/b b.jpg\n")
        );
        assert_eq!(rendered.lines().count(), 2);
    }

    #[test]
    fn every_text_line_splits_into_a_digest_and_a_path() {
        // The exact operation a checker performs on each line.
        let rendered = sample(false).render(&Out::plain()).unwrap();
        for line in rendered.lines() {
            let (digest, path) = line.split_once(HASHSUM_FIELD_SEPARATOR).unwrap();
            assert!(Algorithm::Blake3.is_well_formed(digest));
            assert!(!path.is_empty());
        }
    }

    #[test]
    fn binary_mode_marks_every_path() {
        let rendered = sample(true).render(&Out::plain()).unwrap();
        for line in rendered.lines() {
            assert!(line.contains(" *"), "not binary mode: {line}");
        }
    }

    #[test]
    fn json_names_the_algorithm_on_every_record() {
        // A 64-character hex string is ambiguous between BLAKE3 and SHA-256, and
        // a JSON Lines consumer sees one record at a time.
        let rendered = sample(false).render(&out(Format::Json)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed[0]["algorithm"], "blake3");
        assert_eq!(parsed[0]["hash"], EMPTY_BLAKE3);
        assert_eq!(parsed[0]["path"], "photos/a.jpg");

        let rendered = sample(false).render(&out(Format::JsonLines)).unwrap();
        assert_eq!(rendered.lines().count(), 2);
        for line in rendered.lines() {
            let record: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(record["algorithm"], "blake3");
        }
    }

    #[test]
    fn a_paths_spaces_survive_the_round_trip() {
        // Only the *first* double space separates the fields, so a path
        // containing spaces must come back intact.
        let rendered = sample(false).render(&Out::plain()).unwrap();
        let last = rendered.lines().last().unwrap();
        let (_, path) = last.split_once(HASHSUM_FIELD_SEPARATOR).unwrap();
        assert_eq!(path, "photos/b b.jpg");
    }

    #[test]
    fn a_malformed_digest_is_caught_before_the_file_is_written() {
        let mut report = Report::new(Algorithm::Sha1, false);
        report.push(Record::new(Algorithm::Sha1, EMPTY_BLAKE3, "a.txt"));
        assert!(
            !report.digests_are_well_formed(),
            "a 64-character digest is not a SHA-1"
        );
        assert!(sample(false).digests_are_well_formed());
    }

    #[test]
    fn an_empty_report_renders_empty_in_every_line_format() {
        // Notably *not* an error here — the caller decides whether "no objects"
        // is acceptable; the renderer must not invent a line.
        let report = Report::new(Algorithm::Sha256, false);
        assert!(report.is_empty());
        assert_eq!(report.len(), 0);
        assert_eq!(report.render(&Out::plain()).unwrap(), "");
        assert_eq!(report.render(&out(Format::JsonLines)).unwrap(), "");
        assert_eq!(report.render(&out(Format::Json)).unwrap().trim(), "[]");
    }
}
