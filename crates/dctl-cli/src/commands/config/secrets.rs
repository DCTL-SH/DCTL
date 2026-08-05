//! The rule the whole command is built around: **a rendered configuration never
//! contains a secret** ([the plan](https://doc.dctl.sh/project/plan) §14).
//!
//! DCTL's config file is designed to hold no credentials — provider keys live in
//! the OS keychain, and the vault password is never stored anywhere. So in a
//! correct installation nothing here ever fires.
//!
//! It exists for the incorrect one. A user who does not know the design adds
//! `secret_key = …` to a section by hand; then, debugging something unrelated,
//! pastes `dctl config show b2prod` into an issue tracker. Redaction lives at
//! the *render* boundary rather than at the parse boundary so that no future
//! subcommand can bypass it by reading the document a different way: everything
//! that prints a value calls [`render`], and [`render`] cannot be persuaded to
//! print a credential.
//!
//! The policy is deliberately biased towards over-redaction. A bucket name shown
//! as `<redacted>` is a five-second annoyance with an obvious remedy (open the
//! file). A printed application key is a credential rotation.

use crate::constants;
use crate::logging::redact::{REDACTED, is_sensitive_key, redact_url};

/// Why a value was hidden.
///
/// Kept as a type rather than a bool so `--json` can say *which* rule fired: a
/// user seeing `<redacted>` on a value they believe is harmless needs to know
/// whether it was the key's name or the value's shape that triggered it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// The key is one of [`crate::logging::redact`]'s sensitive names.
    SensitiveKey,
    /// The value carries a credential marker such as PEM armour.
    CredentialMarker,
    /// The value is a URL with a password embedded in its authority.
    CredentialUrl,
    /// The value is a long, high-entropy opaque token.
    OpaqueToken,
}

impl Reason {
    /// One-line explanation shown beside a redacted value in text output.
    ///
    /// Phrased as advice, because every one of these is a mistake the user can
    /// fix: the config file is not where any of this belongs.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::SensitiveKey => "the key names a credential",
            Self::CredentialMarker => "the value looks like key material",
            Self::CredentialUrl => "the URL carries a password",
            Self::OpaqueToken => "the value looks like a generated token",
        }
    }
}

/// The outcome of rendering one key/value pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    /// What may be printed.
    pub text: String,
    /// The rule that hid the real value, if one did.
    pub reason: Option<Reason>,
}

impl Rendered {
    /// Whether anything was withheld.
    #[must_use]
    pub const fn is_redacted(&self) -> bool {
        self.reason.is_some()
    }
}

/// Render a configuration value for display.
///
/// Returns [`crate::logging::redact::REDACTED`] in place of anything that could
/// be a credential; otherwise returns the value with any signed URL query
/// parameters stripped, because a pre-signed URL sitting in a config file is a
/// working credential with a real time window.
#[must_use]
pub fn render(key: &str, value: &str) -> Rendered {
    if let Some(reason) = classify(key, value) {
        return Rendered {
            text: REDACTED.to_string(),
            reason: Some(reason),
        };
    }
    Rendered {
        // Safe by construction: `classify` has already rejected any URL whose
        // authority carries a password, so this only strips signatures.
        text: redact_url(value),
        reason: None,
    }
}

/// Decide whether a key/value pair must be withheld, and under which rule.
///
/// Rules are ordered cheapest-first, and the first match wins — the reported
/// reason is therefore the most specific *available* explanation, not
/// necessarily the only one that applies.
#[must_use]
fn classify(key: &str, value: &str) -> Option<Reason> {
    if is_sensitive_key(key) {
        return Some(Reason::SensitiveKey);
    }
    if constants::SECRET_VALUE_MARKERS
        .iter()
        .any(|marker| value.contains(marker))
    {
        return Some(Reason::CredentialMarker);
    }
    if has_embedded_credentials(value) {
        return Some(Reason::CredentialUrl);
    }
    if looks_like_opaque_token(value) {
        return Some(Reason::OpaqueToken);
    }
    None
}

/// Whether a URL carries `user:password@` in its authority.
///
/// Only the authority is examined — the span between `://` and the first `/`
/// after it. A password may not appear anywhere else in a URL, and scanning the
/// whole string would redact every path containing an `@`.
fn has_embedded_credentials(value: &str) -> bool {
    let Some((_scheme, rest)) = value.split_once(constants::URL_SCHEME_SEPARATOR) else {
        return false;
    };
    let authority = rest
        .split_once(constants::PATH_SEPARATOR)
        .map_or(rest, |(authority, _path)| authority);
    authority.contains(constants::URL_USERINFO_SEPARATOR)
}

/// Whether a value is a long, opaque, high-entropy token.
///
/// Three conditions together, because any one alone has too many false
/// positives to be usable:
///
/// 1. At least [`constants::SECRET_VALUE_MIN_LEN`] characters.
/// 2. Drawn entirely from the base64/hex alphabet plus
///    [`constants::SECRET_VALUE_EXTRA_CHARS`] — so a hostname, a path, or any
///    value with a space or a dot in it is structured text, not a token.
/// 3. Mixed case *and* at least one digit. This is what separates a generated
///    credential from a long human-chosen identifier: S3 bucket names are
///    lower-case by rule, and `my-company-backups-production` reads as a name
///    rather than as entropy.
fn looks_like_opaque_token(value: &str) -> bool {
    if value.chars().count() < constants::SECRET_VALUE_MIN_LEN {
        return false;
    }

    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;

    for character in value.chars() {
        if character.is_ascii_uppercase() {
            has_upper = true;
        } else if character.is_ascii_lowercase() {
            has_lower = true;
        } else if character.is_ascii_digit() {
            has_digit = true;
        } else if !constants::SECRET_VALUE_EXTRA_CHARS.contains(&character) {
            return false;
        }
    }

    has_upper && has_lower && has_digit
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The assertion this module exists for. Every other test is a refinement
    /// of it: whatever the rule, the original text must not survive rendering.
    fn assert_hidden(key: &str, value: &str) {
        let rendered = render(key, value);
        assert!(
            rendered.is_redacted(),
            "'{key}' = '{value}' was rendered in the clear"
        );
        assert_eq!(rendered.text, REDACTED);
        assert!(
            !rendered.text.contains(value),
            "'{key}' leaked its value: {}",
            rendered.text
        );
    }

    #[test]
    fn a_secret_shaped_key_never_renders_its_value() {
        // [The plan](https://doc.dctl.sh/project/plan) §14's hard requirement,
        // stated as a test.
        for key in [
            "password",
            "Password",
            "secret_key",
            "SECRET_KEY",
            "app_key",
            "api_key",
            "token",
            "authorization",
            "credential",
            "b2_app_key",
            "aws_secret_access_key",
        ] {
            assert_hidden(key, "hunter2");
        }
    }

    #[test]
    fn the_reason_names_the_rule_that_fired() {
        assert_eq!(render("password", "x").reason, Some(Reason::SensitiveKey));
        assert_eq!(
            render("cert", "-----BEGIN PRIVATE KEY-----").reason,
            Some(Reason::CredentialMarker)
        );
        assert_eq!(
            render("endpoint", "https://user:pw@s3.example.com").reason,
            Some(Reason::CredentialUrl)
        );
        assert_eq!(
            render("blob", "aG9yc2ViYXR0ZXJ5U3RhcGxlMTIzNDU2Nzg5").reason,
            Some(Reason::OpaqueToken)
        );
    }

    #[test]
    fn ordinary_settings_render_unchanged() {
        // Over-redaction is the safe failure, but a config nobody can read is
        // not usable either — the ordinary keys must survive.
        for (key, value) in [
            ("type", "b2"),
            ("bucket", "my-photos"),
            ("region", "us-west-002"),
            ("endpoint", "https://s3.us-west-002.backblazeb2.com"),
            ("chunk_size", "4MiB"),
            ("verify", "checksum"),
            ("bucket", "my-company-backups-production"),
        ] {
            let rendered = render(key, value);
            assert!(!rendered.is_redacted(), "'{key}' = '{value}' was redacted");
            assert_eq!(rendered.text, value);
        }
    }

    #[test]
    fn credential_markers_are_caught_whatever_the_key_is_called() {
        assert_hidden("anything", "-----BEGIN OPENSSH PRIVATE KEY-----");
        assert_hidden("header", "Bearer ya29.a0AfH6SMBx");
        assert_hidden("id", "AKIAIOSFODNN7EXAMPLE");
        assert_hidden("id", "ASIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn a_url_with_an_embedded_password_is_hidden_whole() {
        // Partial redaction would still publish the username and the host, and
        // half a credential in a bug report is a credential in a bug report.
        assert_hidden("endpoint", "https://admin:s3cr3t@minio.internal:9000");
        assert_hidden("proxy", "socks5://user:pass@10.0.0.1:1080");
    }

    #[test]
    fn an_at_sign_outside_the_authority_is_not_a_credential() {
        // The false positive the authority-only scan exists to avoid.
        let value = "https://example.com/buckets/team@example.com/data";
        assert!(!render("endpoint", value).is_redacted());
    }

    #[test]
    fn a_signed_url_loses_its_signature_but_keeps_its_shape() {
        // Not a redaction — the URL is still useful to read — but the working
        // credential inside it must not survive.
        let value = "https://s3.example.com/b/k?X-Amz-Algorithm=AWS4&X-Amz-Signature=deadbeef";
        let rendered = render("endpoint", value);
        assert!(!rendered.is_redacted());
        assert!(
            !rendered.text.contains("deadbeef"),
            "got: {}",
            rendered.text
        );
        assert!(rendered.text.contains("s3.example.com"));
    }

    #[test]
    fn opaque_tokens_are_recognised_by_length_alphabet_and_entropy() {
        // Long, mixed-case, digit-bearing, alphabet-clean: a generated secret.
        assert!(looks_like_opaque_token("K001abcDEF234ghiJKL567mno89"));
        assert!(looks_like_opaque_token(
            "aG9yc2ViYXR0ZXJ5U3RhcGxlMTIzNDU2Nzg5"
        ));

        // Too short to be a credential worth having.
        assert!(!looks_like_opaque_token("Ab1"));
        // Structured text: the dots make it a hostname.
        assert!(!looks_like_opaque_token("s3.us-west-002.backblazeb2.com"));
        // Lower-case only: an identifier a person chose, not entropy.
        assert!(!looks_like_opaque_token(
            "my-company-backups-production-2024"
        ));
        // No digits: prose, however long.
        assert!(!looks_like_opaque_token(
            "ThisIsAVeryLongHumanReadableLabel"
        ));
        // A space means it is not a token at all.
        assert!(!looks_like_opaque_token("K001abcDEF234 ghiJKL567mno89"));
    }

    #[test]
    fn the_length_floor_counts_characters_not_bytes() {
        // A multi-byte value could otherwise sneak past a byte-length check —
        // or, worse, a short one could be redacted for no reason.
        let value = "ααααααααααααααααααααααα";
        assert_eq!(value.chars().count(), 23);
        assert!(!looks_like_opaque_token(value));
    }

    #[test]
    fn every_reason_names_itself_for_both_audiences() {
        // A human needs the sentence; a machine consumer branches on the slug.
        for reason in [
            Reason::SensitiveKey,
            Reason::CredentialMarker,
            Reason::CredentialUrl,
            Reason::OpaqueToken,
        ] {
            assert!(!reason.describe().is_empty());
        }
        assert_eq!(
            serde_json::to_value(Reason::SensitiveKey).unwrap(),
            serde_json::json!("sensitive_key")
        );
    }

    #[test]
    fn redaction_is_decided_per_pair_not_per_document() {
        // A section holding one secret must not blank out its siblings.
        let secret = render("app_key", "K001abcDEF234ghiJKL567mno89");
        let plain = render("bucket", "photos");
        assert!(secret.is_redacted());
        assert!(!plain.is_redacted());
        assert_eq!(plain.text, "photos");
    }
}
