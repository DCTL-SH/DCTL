//! §5 path normalization + validation.
//!
//! Paths are NFC-normalized then checked against the frozen §5 rules before they feed
//! a name/index key or are materialized to disk (reader-side re-validation). Naming is
//! case-sensitive; case-folding is never applied.
//!
//! **Follow-up (documented):** the §5 "assigned code points only / Unicode-15.1
//! repertoire" check requires a pinned UCD-15.1 assignment table and is not yet
//! enforced here; every other §5 rule is. Surrogates cannot occur in a Rust `&str`,
//! so that part of the rule is satisfied structurally.

use unicode_normalization::UnicodeNormalization;

use crate::constants::{MAX_PATH_BYTES, MAX_PATH_SEGMENT_BYTES};
use crate::error::{CryptoError, Result};

/// NFC-normalize `raw` and validate it per §5; returns the normalized path.
pub fn normalize(raw: &str) -> Result<String> {
    let nfc: String = raw.nfc().collect();
    validate(&nfc)?;
    Ok(nfc)
}

/// Validate an already-NFC path per §5. Also the reader-side re-validation (§5/§6):
/// a decrypted `path_hint` is only DEK-authenticated, so it MUST pass this before use.
pub fn validate(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(err("empty path"));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(err("path exceeds 4096 bytes"));
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err(err("leading/trailing '/'"));
    }
    for ch in path.chars() {
        if is_banned_control(ch) {
            return Err(err("C0/DEL/C1 control code point"));
        }
        if ch == '\\' {
            return Err(err("backslash not allowed"));
        }
        if is_noncharacter(ch) {
            return Err(err("noncharacter code point"));
        }
    }
    // Windows drive-letter prefix (e.g. "C:...") on the first segment.
    let first = path.split('/').next().unwrap_or("");
    let fb = first.as_bytes();
    if fb.len() >= 2 && fb[0].is_ascii_alphabetic() && fb[1] == b':' {
        return Err(err("drive-letter prefix"));
    }
    for seg in path.split('/') {
        if seg.is_empty() {
            return Err(err("empty segment ('a//b')"));
        }
        if seg == "." || seg == ".." {
            return Err(err("'.'/'..' segment"));
        }
        if seg.len() > MAX_PATH_SEGMENT_BYTES {
            return Err(err("segment exceeds 255 bytes"));
        }
    }
    Ok(())
}

/// C0 (`U+0000..=U+001F`), DEL (`U+007F`), C1 (`U+0080..=U+009F`).
fn is_banned_control(ch: char) -> bool {
    let c = ch as u32;
    c <= 0x1F || c == 0x7F || (0x80..=0x9F).contains(&c)
}

/// Unicode noncharacters: `U+FDD0..=U+FDEF` and any `U+nFFFE`/`U+nFFFF`.
fn is_noncharacter(ch: char) -> bool {
    let c = ch as u32;
    (0xFDD0..=0xFDEF).contains(&c) || (c & 0xFFFE) == 0xFFFE
}

fn err(msg: &str) -> CryptoError {
    CryptoError::Format(format!("invalid path: {msg}"))
}
