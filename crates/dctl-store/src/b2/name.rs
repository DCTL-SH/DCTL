//! B2 `X-Bz-File-Name` percent-encoding.
//!
//! B2 requires the file name header to be percent-encoded, leaving unescaped only
//! `A-Z a-z 0-9` and the set `._-/~!$'()*;=:@`; every other byte becomes `%XX`
//! (uppercase hex, over the UTF-8 bytes).

/// Bytes that must NOT be percent-encoded (besides ASCII alphanumerics).
const UNRESERVED_EXTRA: &[u8] = b"._-/~!$'()*;=:@";

/// Percent-encode `name` for the `X-Bz-File-Name` header.
pub(super) fn encode_file_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for &byte in name.as_bytes() {
        if byte.is_ascii_alphanumeric() || UNRESERVED_EXTRA.contains(&byte) {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(hex_upper(byte >> 4));
            out.push(hex_upper(byte & 0x0f));
        }
    }
    out
}

/// Map a 0..=15 nibble to an uppercase hex digit.
fn hex_upper(nibble: u8) -> char {
    if nibble < 10 {
        (b'0' + nibble) as char
    } else {
        (b'A' + (nibble - 10)) as char
    }
}

#[cfg(test)]
mod tests {
    use super::encode_file_name;

    #[test]
    fn leaves_safe_characters_untouched() {
        assert_eq!(
            encode_file_name("photos/2020/img_001.jpg"),
            "photos/2020/img_001.jpg"
        );
        assert_eq!(encode_file_name("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn encodes_spaces_and_specials() {
        assert_eq!(encode_file_name("a b"), "a%20b");
        assert_eq!(encode_file_name("100%"), "100%25");
        assert_eq!(encode_file_name("a+b&c"), "a%2Bb%26c");
    }

    #[test]
    fn encodes_utf8_bytes() {
        // "é" is U+00E9 → UTF-8 0xC3 0xA9.
        assert_eq!(encode_file_name("é"), "%C3%A9");
    }
}
