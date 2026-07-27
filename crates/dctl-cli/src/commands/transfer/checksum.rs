//! Producing the content hash `--checksum` compares, for a side that has to
//! compute one.
//!
//! Two sides of a transfer answer "what does this file hash to?" in two
//! completely different ways, and the whole point of this file is that they
//! answer with the *same* value.
//!
//! A vault already knows. It recorded a BLAKE3 of the plaintext at write time,
//! under the same verified-write contract that refused to commit unless the
//! stored bytes matched, and that digest is on every [`Record`](dctl_core::Record)
//! the index hands back. Nothing is read to obtain it.
//!
//! A plain local file knows nothing, so it has to be read. That is expensive —
//! `--checksum` over two local trees costs a full pass over both — and it is
//! exactly the cost the flag exists to buy: the user asked for content equality
//! rather than a metadata guess, and `PLAN.md` §6 forbids answering a cheaper
//! question and calling it the one that was asked.
//!
//! ## Why BLAKE3, and why hex
//!
//! BLAKE3 because that is what the vault recorded; any other algorithm would
//! make the two sides incomparable, and a comparison that cannot be made must be
//! refused rather than approximated. Lower-case hex because
//! [`crate::output::hex`] already fixes that spelling as this program's wire
//! format, so the value in a plan, in `lsjson` and in this comparison are one
//! string rather than three that have to be normalised at every meeting point.
//!
//! ## Memory
//!
//! The file is streamed through a fixed buffer, never read whole. `PLAN.md`
//! §16.2 caps memory at O(concurrency), and a `--checksum` that materialised a
//! fifty-gigabyte file in order to *decide whether to copy it* would be the most
//! absurd possible way to break that rule.

use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use crate::constants::CHECKSUM_STREAM_BUFFER_BYTES;
use crate::error::{CliError, Result};
use crate::output::hex;

/// The hash a vault already recorded, in this program's spelling.
///
/// Takes the raw digest from a [`crate::source::Entry`] and renders it, so the
/// vault side and the local side below produce values that can be compared with
/// `==` rather than with a conversion nobody remembers to apply.
#[must_use]
pub fn encode(digest: &[u8]) -> String {
    hex::encode(digest)
}

/// Hash a local file, streaming.
///
/// # Errors
/// Whatever opening or reading the file reported, with the path attached: a
/// `--checksum` run that cannot read one file has to say which, because the
/// alternative is a comparison silently made on incomplete information.
pub fn of_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)
        .map_err(|error| CliError::from(error).with_hint(format!("hashing {}", path.display())))?;

    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; CHECKSUM_STREAM_BUFFER_BYTES];

    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            CliError::from(error).with_hint(format!("hashing {}", path.display()))
        })?;
        if read == 0 {
            break;
        }
        // `read` never exceeds the buffer's length, so the slice is always in
        // range; the fallback keeps this file free of an indexing panic.
        match buffer.get(..read) {
            Some(chunk) => hasher.update(chunk),
            None => &mut hasher,
        };
    }

    Ok(hex::encode(hasher.finalize().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn a_recorded_digest_renders_the_way_the_rest_of_the_program_spells_one() {
        let digest = blake3::hash(b"hello").as_bytes().to_vec();
        assert_eq!(encode(&digest), blake3::hash(b"hello").to_hex().to_string());
    }

    #[test]
    fn a_local_file_hashes_to_the_value_the_vault_would_have_recorded() {
        // The property the whole file exists for: a vault stores BLAKE3 of the
        // plaintext, so a local file of the same bytes must produce the same
        // string or `--checksum` would report every file as differing.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.bin");
        std::fs::write(&path, b"hello").unwrap();

        assert_eq!(
            of_file(&path).unwrap(),
            encode(blake3::hash(b"hello").as_bytes())
        );
    }

    #[test]
    fn a_file_larger_than_the_buffer_hashes_correctly() {
        // The loop, not the one-shot: a file that spans several reads must
        // produce the same digest as hashing it whole, or every large file would
        // compare as different.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.bin");
        let bytes: Vec<u8> = (0..CHECKSUM_STREAM_BUFFER_BYTES * 3 + 7)
            .map(|i| (i % 251) as u8)
            .collect();
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&bytes).unwrap();
        drop(file);

        assert_eq!(
            of_file(&path).unwrap(),
            encode(blake3::hash(&bytes).as_bytes())
        );
    }

    #[test]
    fn an_empty_file_hashes_rather_than_reporting_nothing() {
        // `blake3::hash(b"")` is a full digest. Answering with an empty string
        // would make two unrelated empty files "unknown" instead of identical.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        std::fs::write(&path, b"").unwrap();
        assert_eq!(
            of_file(&path).unwrap(),
            encode(blake3::hash(b"").as_bytes())
        );
    }

    #[test]
    fn a_missing_file_is_reported_with_its_path() {
        let error = of_file(Path::new("/definitely/not/here.bin")).unwrap_err();
        assert_eq!(error.code(), crate::exit::ExitCode::FileNotFound);
        assert!(error.hint().is_some_and(|hint| hint.contains("here.bin")));
    }
}
