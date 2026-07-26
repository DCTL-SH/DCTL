//! The mandatory scrub every value passes through before it can enter a record.
//!
//! `PLAN.md` §7 is unambiguous: keys and tokens are never logged, and secrets
//! appear only as BLAKE3 fingerprints. The audit log is the *most* exposed thing
//! DCTL writes — its whole purpose is to be handed to an auditor, an insurer or
//! a client — so a credential that leaked into it would leak to exactly the
//! audience least entitled to it, and would do so in a file nobody is allowed to
//! edit afterwards. There is no "redact it later" for an append-only log.
//!
//! Two scrubs, applied by [`super::record::Entry`]'s setters so that no call
//! site can skip them:
//!
//! * [`field`] — escapes control characters. This is the *integrity* half, not
//!   the secrecy half: the canonical byte string a record's hash covers joins
//!   fields with [`AUDIT_HASH_FIELD_SEPARATOR`], so a value containing that byte
//!   could forge a field boundary and make two different records hash
//!   identically. `crate::platform::names` already rejects control characters in
//!   paths, but "already rejected somewhere else" is not a property the hash can
//!   rely on.
//! * [`remote`] — strips credentials out of a remote that was spelled as a URL,
//!   then applies [`field`].
//!
//! ## What this can and cannot promise
//!
//! It can promise that the shapes DCTL actually produces are safe: a configured
//! remote name, a URL with userinfo, a pre-signed URL carrying a signature in
//! its query string. It cannot promise anything about a caller that hands a bare
//! secret to [`super::record::Entry::path`] — no scrub can tell a password from
//! a filename once the context is gone. That is why the builder has typed,
//! purpose-named setters and no free-form "extra" field: the defence is that
//! there is nowhere for an unclassified string to go.
//!
//! ## Why nothing outside the tests calls this yet
//!
//! It is called by [`super::record::Entry`], which is itself called only by the
//! tests until the writer is wired into the transfer and removal families. See
//! the note at the top of [`super::write`] — the same reasoning applies, and the
//! `dead_code` allow comes off with the same commit that wires it up.

#![allow(dead_code)]

use crate::constants::{
    AUDIT_CONTROL_ESCAPE_PREFIX, AUDIT_CONTROL_ESCAPE_WIDTH, URL_SCHEME_SEPARATOR,
};
use crate::logging::redact;

/// Characters that end a URL's authority component.
///
/// Userinfo can only appear inside the authority, so the search for an `@` has
/// to stop here — otherwise a path or query containing `@` (an email address in
/// a filename is ordinary) would be mistaken for a credential boundary and the
/// host would be replaced by a fingerprint.
const AUTHORITY_TERMINATORS: [char; 3] = ['/', '?', '#'];

/// Make a value safe to place in a record field.
///
/// Every control character becomes [`AUDIT_CONTROL_ESCAPE_PREFIX`] plus
/// [`AUDIT_CONTROL_ESCAPE_WIDTH`] lower-case hex digits. Escaped rather than
/// dropped, because an audit record is evidence: a path that really did contain
/// a strange byte should be recorded as it was, and dropping the byte would make
/// two different paths record identically — the very collision the escape
/// exists to prevent.
#[must_use]
pub fn field(value: &str) -> String {
    // The common case is a value with nothing to escape, and a record is built
    // once per file transferred; scanning first avoids a second allocation for
    // every path in a million-file run.
    if !value.chars().any(char::is_control) {
        return value.to_string();
    }

    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            let width = AUDIT_CONTROL_ESCAPE_WIDTH;
            let code = character as u32;
            escaped.push_str(AUDIT_CONTROL_ESCAPE_PREFIX);
            escaped.push_str(&format!("{code:0width$x}"));
        } else {
            escaped.push(character);
        }
    }
    escaped
}

/// Make a remote safe to place in a record field.
///
/// A remote is normally a configured name (`vault`, `b2prod`) and passes through
/// untouched. When it is a URL it can carry two kinds of credential, and both
/// are removed:
///
/// * **Userinfo** — `s3://ACCESS:SECRET@bucket/…`. The whole userinfo is
///   replaced by [`redact::fingerprint`] of itself, not by a fixed placeholder,
///   so two records made with the same credential still correlate — which is the
///   question an investigator actually asks — while neither half is recoverable.
/// * **Query parameters** — a pre-signed URL carries a working signature in its
///   query string, so logging one raw would put a live credential with a real
///   time window into the permanent record. [`redact::redact_url`] removes them.
#[must_use]
pub fn remote(value: &str) -> String {
    field(&redact::redact_url(&strip_userinfo(value)))
}

/// Replace a URL's userinfo with a fingerprint of it.
///
/// Returns the input unchanged when there is no scheme, no authority, or no
/// userinfo — which covers every configured remote name.
fn strip_userinfo(value: &str) -> String {
    let Some((scheme, rest)) = value.split_once(URL_SCHEME_SEPARATOR) else {
        return value.to_string();
    };

    let authority_end = rest.find(AUTHORITY_TERMINATORS).unwrap_or(rest.len());
    let authority = &rest[..authority_end];

    // The *last* `@`, because userinfo may legally contain a percent-encoded
    // one; the host may not.
    let Some(boundary) = authority.rfind('@') else {
        return value.to_string();
    };

    let (userinfo, host) = authority.split_at(boundary);
    format!(
        "{scheme}{URL_SCHEME_SEPARATOR}{}{host}{}",
        redact::fingerprint(userinfo.as_bytes()),
        &rest[authority_end..]
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::constants::AUDIT_HASH_FIELD_SEPARATOR;

    #[test]
    fn an_ordinary_value_is_returned_unchanged() {
        for value in ["photos/2024/a.jpg", "vault", "", "naïve — dash.mov"] {
            assert_eq!(field(value), value);
        }
    }

    #[test]
    fn the_hash_separator_cannot_survive_into_a_field() {
        // The forgery this blocks: a value that closes its own field.
        let scrubbed = field(&format!("a{AUDIT_HASH_FIELD_SEPARATOR}b"));
        assert!(!scrubbed.contains(AUDIT_HASH_FIELD_SEPARATOR));
        assert_eq!(scrubbed, "a\\u001fb");
    }

    #[test]
    fn every_control_character_is_escaped_to_a_fixed_width() {
        // Fixed width is what makes the escape unambiguous to split back apart.
        // Unicode defines no control character above U+009F, so four hex digits
        // is enough forever.
        for code in (0u32..=0x1f).chain(0x7f..=0x9f) {
            let character = char::from_u32(code).unwrap();
            let escaped = field(&character.to_string());
            assert_eq!(
                escaped.len(),
                AUDIT_CONTROL_ESCAPE_PREFIX.len() + AUDIT_CONTROL_ESCAPE_WIDTH,
                "U+{code:04X} escaped to {escaped:?}"
            );
            assert!(!escaped.chars().any(char::is_control));
        }
    }

    #[test]
    fn escaping_does_not_collapse_two_different_values_into_one() {
        // Dropping the byte instead of escaping it would make these equal, which
        // is exactly the collision the escape exists to prevent.
        assert_ne!(field("a\u{1f}b"), field("ab"));
        assert_ne!(field("a\u{1f}b"), field("a\u{1e}b"));
    }

    #[test]
    fn a_configured_remote_name_passes_through() {
        for name in ["vault", "b2prod", "local", ""] {
            assert_eq!(remote(name), name);
        }
    }

    #[test]
    fn url_userinfo_becomes_a_fingerprint_and_the_host_survives() {
        let scrubbed = remote("s3://AKIAEXAMPLE:wJalrXUtnFEMI@bucket.example.com/prefix");
        assert!(!scrubbed.contains("wJalrXUtnFEMI"), "{scrubbed}");
        assert!(!scrubbed.contains("AKIAEXAMPLE"), "{scrubbed}");
        assert!(scrubbed.contains("bucket.example.com/prefix"), "{scrubbed}");
        // A fingerprint, not a placeholder: two records made with the same
        // credential must still be recognisable as the same credential.
        assert!(scrubbed.contains("blake3:"), "{scrubbed}");
        assert_eq!(
            scrubbed,
            remote("s3://AKIAEXAMPLE:wJalrXUtnFEMI@bucket.example.com/prefix")
        );
    }

    #[test]
    fn different_credentials_fingerprint_differently() {
        assert_ne!(
            remote("s3://user:one@host/x"),
            remote("s3://user:two@host/x")
        );
    }

    #[test]
    fn a_presigned_signature_never_reaches_the_record() {
        let scrubbed =
            remote("https://s3.example.com/b/k?X-Amz-Algorithm=AWS4&X-Amz-Signature=deadbeef");
        assert!(!scrubbed.contains("deadbeef"), "{scrubbed}");
        assert!(scrubbed.contains("X-Amz-Algorithm=AWS4"), "{scrubbed}");
    }

    #[test]
    fn an_at_sign_outside_the_authority_is_not_a_credential() {
        // An email address in a filename is ordinary; mistaking it for userinfo
        // would replace the host with a fingerprint and make the record wrong.
        let url = "https://host.example.com/mail/a@b.com.eml";
        assert_eq!(remote(url), url);
    }

    #[test]
    fn a_url_with_no_userinfo_is_untouched() {
        for url in [
            "https://host.example.com/path",
            "s3://bucket/prefix",
            "file:///var/data",
        ] {
            assert_eq!(remote(url), url);
        }
    }
}
