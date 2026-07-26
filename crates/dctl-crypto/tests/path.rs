//! §5 path normalization + validation.

use dctl_crypto::path;

#[test]
fn nfc_normalization() {
    // "café": NFD (e + U+0301) normalizes to NFC (U+00E9), so both forms key identically.
    let out = path::normalize("cafe\u{0301}/file").unwrap();
    assert_eq!(out, "caf\u{00e9}/file");
}

#[test]
fn accepts_valid_paths() {
    for p in [
        "a",
        "dir/file.txt",
        "a/b/c/d",
        "photos/2026/img.heic",
        "r\u{00e9}sum\u{00e9}.pdf",
    ] {
        assert!(path::normalize(p).is_ok(), "should accept {p}");
    }
}

#[test]
fn rejects_invalid_paths() {
    let bad = [
        "",           // empty
        "/leading",   // leading slash
        "trailing/",  // trailing slash
        "a//b",       // empty segment
        "a/./b",      // '.'
        "a/../b",     // '..'
        "a\\b",       // backslash
        "C:/win",     // drive letter
        "a\u{0000}b", // NUL (C0)
        "a\u{0007}b", // BEL (C0)
        "a\u{007F}b", // DEL
        "a\u{0085}b", // NEL (C1)
        "a\u{FDD0}b", // noncharacter
        "a\u{FFFE}b", // noncharacter
    ];
    for p in bad {
        assert!(path::normalize(p).is_err(), "should reject {p:?}");
    }
}

#[test]
fn accepts_15_1_repertoire() {
    // Ordinary code points assigned as of UCD 15.1 must pass the "assigned only" gate.
    for p in [
        "hello_world.txt",                     // ASCII
        "caf\u{00e9}",                         // café, NFC (U+00E9 assigned since forever)
        "\u{4e2d}\u{6587}/\u{65e5}\u{672c}",   // CJK: 中文/日本
        "party\u{1f600}.txt",                  // 😀 U+1F600, present since Unicode 6.1 (≤15.1)
        "vault/\u{e000}",                      // U+E000: Private Use (Co) — permanently assigned
    ] {
        assert!(path::normalize(p).is_ok(), "should accept {p:?}");
    }
}

#[test]
fn rejects_unicode_16_code_points() {
    // U+105C0 = TODHRI LETTER A. The Todhri block (U+105C0..U+105FF) was FIRST assigned
    // in Unicode 16.0, so it is Unassigned (Cn) in the pinned UCD 15.1 table and must be
    // rejected: a ≥16.0 code point can NFC-normalize differently under different UCD
    // versions → an unstable BLAKE3-keyed name/index key across devices (§5).
    assert!(
        path::normalize("dir/\u{105c0}").is_err(),
        "must reject a code point first assigned in Unicode 16.0 (U+105C0 Todhri)"
    );
    assert!(
        path::validate("dir/\u{105c0}").is_err(),
        "reader-side re-validation must also reject the 16.0 code point"
    );
}

#[test]
fn ucd_repertoire_pinned_to_15_1() {
    // Version guard: the assigned-code-points predicate MUST rely on UCD 15.1.0 exactly.
    // If a dependency bump shifts the repertoire (e.g. to 16.0/17.0), this fails loudly
    // instead of silently changing which paths are accepted (§5 FROZEN).
    assert_eq!(
        path::UCD_ASSIGNED_VERSION,
        (15, 1, 0),
        "§5 assigned-repertoire table must be pinned to Unicode 15.1.0"
    );
}

#[test]
fn rejects_oversized() {
    assert!(
        path::normalize(&"x".repeat(256)).is_err(),
        "segment > 255 bytes"
    );
    let long = vec!["a"; 3000].join("/"); // ~5999 bytes total
    assert!(path::normalize(&long).is_err(), "path > 4096 bytes");
}
