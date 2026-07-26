//! Mandatory secret redaction.
//!
//! `PLAN.md` §7 makes this non-negotiable: **keys and tokens are never logged**,
//! and secrets appear only as BLAKE3 fingerprints. That requirement is what
//! makes it safe to hand a `--log-level=trace` capture to a vendor, attach it to
//! a support ticket, or ship it to a log aggregator.
//!
//! The design principle here is that redaction must be *impossible to forget*.
//! A raw `String` password can be logged by accident; a [`Secret<String>`]
//! cannot, because its `Debug` and `Display` implementations do not reveal the
//! value. Anything sensitive should be wrapped at the point it is created, not
//! at the point it is logged.

use std::fmt;

// ── Fingerprints, and why they are compiled but not yet called ───────────────
//
// [`fingerprint`] and the two constants below have no caller in this build.
// They are the rendering half of `logging::fields::DEK_FINGERPRINT`, and the
// records that will carry that field are written where a key exists — inside
// `dctl-core`'s vault — not here. What lives here is the *format*: `blake3:`
// plus exactly eight hex characters, which is a wire contract, because a log
// pipeline correlating "which key was this?" across a million records matches
// on that string. The tests at the bottom of this file pin it.
//
// Deleting them would not remove a fingerprint from a log — nothing emits one
// yet — it would remove the agreed spelling, and the first record that needed
// one would invent a second. So the `dead_code` allows are deliberate and
// scoped to these four items; the rest of the module warns normally, and a
// redaction helper that stops being called is a redaction that stopped
// happening.

/// Length of a fingerprint's hex prefix.
///
/// Eight hex characters is 32 bits — ample to tell two keys apart in a log while
/// being far too little to help an attacker who obtains the log.
#[allow(dead_code)]
const FINGERPRINT_HEX_LEN: usize = 8;

/// Prefix marking a value as a fingerprint rather than the value itself.
#[allow(dead_code)]
const FINGERPRINT_PREFIX: &str = "blake3:";

/// Text substituted for a redacted value.
pub const REDACTED: &str = "<redacted>";

/// Query-string and header names whose values must never be logged.
///
/// Matched case-insensitively against the whole name.
const SENSITIVE_KEYS: &[&str] = &[
    "authorization",
    "x-bz-file-info-src_last_modified_millis",
    "password",
    "passphrase",
    "secret",
    "token",
    "access_key",
    "secret_key",
    "app_key",
    "api_key",
    "apikey",
    "credential",
    "signature",
    "x-amz-security-token",
    "set-cookie",
    "cookie",
];

/// A value that must never appear in output.
///
/// Wrapping a secret at creation makes leaking it a compile-time-visible act:
/// you have to call [`Secret::expose`] on purpose, and that call is greppable in
/// review.
#[derive(Clone)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    /// Wrap a value as secret.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Deliberately read the underlying value.
    ///
    /// Every call site is an auditable decision. Never pass the result to a
    /// logging macro.
    pub const fn expose(&self) -> &T {
        &self.0
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T: AsRef<[u8]>> Secret<T> {
    /// A stable, non-reversible identifier for this secret.
    ///
    /// Two log records mentioning the same fingerprint refer to the same key,
    /// which is exactly what is needed to debug "which DEK was used here?"
    /// without ever exposing the DEK.
    ///
    /// See the note above [`FINGERPRINT_HEX_LEN`] for why this is compiled
    /// without a caller.
    #[allow(dead_code)]
    #[must_use]
    pub fn fingerprint(&self) -> String {
        fingerprint(self.0.as_ref())
    }
}

/// Fingerprint arbitrary bytes for logging: `blake3:1a2b3c4d`.
///
/// See the note above [`FINGERPRINT_HEX_LEN`] for why this is compiled without
/// a caller.
#[allow(dead_code)]
#[must_use]
pub fn fingerprint(bytes: &[u8]) -> String {
    let hash = blake3::hash(bytes);
    let hex = hash.to_hex();
    format!("{FINGERPRINT_PREFIX}{}", &hex[..FINGERPRINT_HEX_LEN])
}

/// Whether a header or parameter name carries a secret value.
#[must_use]
pub fn is_sensitive_key(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_KEYS
        .iter()
        .any(|sensitive| lower == *sensitive || lower.contains(sensitive))
}

/// Redact a header value if its name is sensitive; otherwise pass it through.
///
/// The safety half of `--dump headers`. The flag parses and the protocol
/// tracing layer it feeds is not written, so nothing calls this yet — but the
/// order matters: the redaction exists *before* the capture does, so the layer
/// that eventually emits headers has a safe renderer already sitting there
/// rather than a deadline and a `format!`. `PLAN.md` §7 makes redaction
/// mandatory, and a mandatory thing that has to be remembered is optional.
#[allow(dead_code)]
#[must_use]
pub fn redact_header(name: &str, value: &str) -> String {
    if is_sensitive_key(name) {
        REDACTED.to_string()
    } else {
        value.to_string()
    }
}

/// Strip credential-bearing query parameters from a URL before logging it.
///
/// Pre-signed S3 URLs carry the signature in the query string, so logging a raw
/// download URL would leak a working credential with a real time window.
#[must_use]
pub fn redact_url(url: &str) -> String {
    let Some((base, query)) = url.split_once('?') else {
        return url.to_string();
    };

    let redacted: Vec<String> = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, _)) if is_sensitive_key(key) => format!("{key}={REDACTED}"),
            _ => pair.to_string(),
        })
        .collect();

    format!("{base}?{}", redacted.join("&"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_never_render_their_value() {
        let secret = Secret::new("hunter2".to_string());
        assert_eq!(format!("{secret}"), REDACTED);
        assert_eq!(format!("{secret:?}"), REDACTED);
        // The formatted forms must not contain the value anywhere.
        assert!(!format!("{secret:?}").contains("hunter2"));
    }

    #[test]
    fn secrets_can_be_exposed_deliberately() {
        let secret = Secret::new("hunter2".to_string());
        assert_eq!(secret.expose(), "hunter2");
    }

    #[test]
    fn fingerprints_are_stable_short_and_non_reversible() {
        let a = fingerprint(b"key-material");
        let b = fingerprint(b"key-material");
        assert_eq!(a, b, "same input must fingerprint identically");
        assert!(a.starts_with(FINGERPRINT_PREFIX));
        assert_eq!(a.len(), FINGERPRINT_PREFIX.len() + FINGERPRINT_HEX_LEN);
        assert!(!a.contains("key-material"));
    }

    #[test]
    fn different_secrets_fingerprint_differently() {
        assert_ne!(fingerprint(b"key-a"), fingerprint(b"key-b"));
    }

    #[test]
    fn secret_fingerprint_matches_the_free_function() {
        let secret = Secret::new(b"abc".to_vec());
        assert_eq!(secret.fingerprint(), fingerprint(b"abc"));
    }

    #[test]
    fn sensitive_header_names_are_detected_case_insensitively() {
        assert!(is_sensitive_key("Authorization"));
        assert!(is_sensitive_key("AUTHORIZATION"));
        assert!(is_sensitive_key("X-Amz-Security-Token"));
        assert!(is_sensitive_key("app_key"));
        assert!(!is_sensitive_key("Content-Length"));
        assert!(!is_sensitive_key("X-Bz-File-Name"));
    }

    #[test]
    fn headers_are_redacted_by_name() {
        assert_eq!(redact_header("Authorization", "Bearer abc"), REDACTED);
        assert_eq!(redact_header("Content-Type", "text/plain"), "text/plain");
    }

    #[test]
    fn presigned_url_signatures_are_stripped() {
        let url = "https://s3.example.com/bucket/key?X-Amz-Algorithm=AWS4&X-Amz-Signature=deadbeef";
        let redacted = redact_url(url);
        assert!(!redacted.contains("deadbeef"), "got: {redacted}");
        assert!(redacted.contains("X-Amz-Algorithm=AWS4"), "got: {redacted}");
    }

    #[test]
    fn urls_without_a_query_are_untouched() {
        let url = "https://s3.example.com/bucket/key";
        assert_eq!(redact_url(url), url);
    }

    #[test]
    fn malformed_query_pairs_do_not_panic() {
        let url = "https://example.com/x?novalue&=empty&a=b";
        let redacted = redact_url(url);
        assert!(redacted.starts_with("https://example.com/x?"));
    }
}
