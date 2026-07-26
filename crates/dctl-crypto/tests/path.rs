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
fn rejects_oversized() {
    assert!(
        path::normalize(&"x".repeat(256)).is_err(),
        "segment > 255 bytes"
    );
    let long = vec!["a"; 3000].join("/"); // ~5999 bytes total
    assert!(path::normalize(&long).is_err(), "path > 4096 bytes");
}
