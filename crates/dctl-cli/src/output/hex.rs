//! Rendering a digest as the text other tools expect.
//!
//! Content hashes cross this program's boundary constantly — a checksum column
//! in `lsjson`, a `hashsum` line a `sha256sum -c` has to parse, the two values
//! `check --checksum` compares — and every one of those consumers reads
//! **lower-case hex**. That spelling is therefore a wire format, not a display
//! preference, and it lives in one place so two commands cannot disagree about
//! the case of the same digest and report a false difference.
//!
//! Lower case specifically because that is what `blake3`, `sha256sum` and
//! `b2 ls` all emit; a comparison that had to be case-insensitive to work would
//! be papering over a spelling this program controls on both sides.

use crate::constants::HEX_DIGITS;

/// Lower-case hex encoding of `bytes`.
///
/// Infallible and allocation-exact: the output is always twice the input, so the
/// buffer is sized once rather than grown a nibble at a time on a path that runs
/// per object in a ten-million-object listing.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // The index is a nibble, so it is always inside the table; the fallback
        // exists only because this crate may not panic outside its tests.
        out.push(char::from(
            HEX_DIGITS
                .get(usize::from(byte >> 4))
                .copied()
                .unwrap_or(b'?'),
        ));
        out.push(char::from(
            HEX_DIGITS
                .get(usize::from(byte & 0x0f))
                .copied()
                .unwrap_or(b'?'),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_byte_becomes_two_lower_case_digits() {
        assert_eq!(encode(&[0x00, 0x0f, 0xf0, 0xff]), "000ff0ff");
        assert_eq!(encode(&[0xab, 0xcd]), "abcd");
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn the_encoding_is_what_other_checksum_tools_print() {
        // The property that makes a DCTL digest paste-compatible with the rest
        // of the world: same algorithm, same spelling.
        assert_eq!(
            encode(blake3::hash(b"hello world").as_bytes()),
            blake3::hash(b"hello world").to_hex().to_string()
        );
    }
}
