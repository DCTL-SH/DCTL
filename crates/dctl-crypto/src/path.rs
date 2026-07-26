//! §5 path normalization + validation.
//!
//! Paths are NFC-normalized then checked against the frozen §5 rules before they feed
//! a name/index key or are materialized to disk (reader-side re-validation). Naming is
//! case-sensitive; case-folding is never applied.
//!
//! **Assigned-code-points-only / repertoire pin (§5, FROZEN).** By Unicode's
//! Normalization Stability Policy the NFC image of any string made only of code points
//! assigned as of **UCD 15.1.0** is byte-identical under every UCD ≥ 15.1. A code point
//! first assigned in Unicode 16.0 or later can NFC-normalize *differently* under
//! different UCD versions, which would produce a different `BLAKE3_keyed` name-record /
//! index key — the object becomes unfindable on another device, or two logically
//! distinct paths collide. So we reject any code point not assigned as of 15.1
//! ([`is_assigned_15_1`]). The repertoire is pinned to `unicode-properties` `=0.1.2`
//! (UCD 15.1.0 exactly); [`UCD_ASSIGNED_VERSION`] plus the compile-time guard below fail
//! loudly if a dependency bump ever shifts it. Surrogates cannot occur in a Rust `&str`,
//! so that leg of the §5 rule is satisfied structurally.

use unicode_normalization::UnicodeNormalization;
use unicode_properties::{GeneralCategory, UnicodeGeneralCategory};

use crate::constants::{MAX_PATH_BYTES, MAX_PATH_SEGMENT_BYTES};
use crate::error::{CryptoError, Result};

/// UCD version whose assigned-repertoire table [`is_assigned_15_1`] relies on.
/// FROZEN at 15.1.0 (§5); re-exported so tests can pin it.
pub const UCD_ASSIGNED_VERSION: (u64, u64, u64) = unicode_properties::UNICODE_VERSION;

// Compile-time guard: the assigned-code-points table MUST be UCD 15.1.0 (§5 FROZEN).
// A caret bump of `unicode-properties` (0.1.3 → 16.0.0, 0.1.4 → 17.0.0, …) would
// silently shift the frozen repertoire; this makes the build fail instead. Written as
// an array-length check rather than `assert!` so it stays clear of the crate's
// `deny(clippy::panic)` lint. Length is 1 when the version matches, 0 otherwise —
// a mismatch fails to unify with the declared `[(); 1]` type.
const _UCD_VERSION_GUARD: [(); 1] = [(); (UCD_ASSIGNED_VERSION.0 == 15
    && UCD_ASSIGNED_VERSION.1 == 1
    && UCD_ASSIGNED_VERSION.2 == 0) as usize];

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
        if !is_assigned_15_1(ch) {
            return Err(err(
                "unassigned code point (outside the Unicode 15.1 repertoire)",
            ));
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

/// True iff `c` had an assigned General_Category as of **UCD 15.1.0** — i.e. its
/// category is anything other than `Cn` (Unassigned). This is exactly the §5
/// "assigned code points only" leg: code points first assigned in Unicode 16.0+
/// are `Cn` in the pinned 15.1 table and thus rejected, closing the NFC-stability /
/// name-key hole. Private-use code points map to `Co` (not `Cn`) and so are allowed
/// (PUA is permanently assigned). Noncharacters/surrogates also read as `Cn`, but
/// those are caught earlier with clearer messages — a harmless overlap.
fn is_assigned_15_1(c: char) -> bool {
    c.general_category() != GeneralCategory::Unassigned
}

fn err(msg: &str) -> CryptoError {
    CryptoError::Format(format!("invalid path: {msg}"))
}
