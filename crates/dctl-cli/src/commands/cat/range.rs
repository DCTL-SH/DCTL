//! Byte-range arithmetic for `dctl cat`.
//!
//! `--head`, `--tail`, `--offset` and `--count` are four spellings of a single
//! question — *which slice of this object does the caller want?* — so they are
//! folded into one [`Span`] here and nowhere else. The command body then handles
//! exactly one shape, and these rules are testable without a vault, a file, or a
//! terminal.
//!
//! The distinction that carries its weight is **when the object's size is
//! needed**. A [`Span`] is what the flags mean on their own; a [`Slice`] is what
//! they mean for an object of a known size. Keeping the two apart is what lets
//! the read stay cheap: the size comes from a stat or an index record, and the
//! resulting slice becomes a range request for exactly the stored chunks that
//! cover it. Seeking 40 GB into a film is one ranged read, not 40 GB of egress —
//! which is the entire point of a seekable format.

use crate::constants::SIZE_LIMIT_OFF;
use crate::error::{CliError, Result};
use crate::output::size::parse_size;

/// Which end of the object an offset is measured from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Anchor {
    /// Counted forwards from byte zero.
    Start,
    /// Counted backwards from the end — what `--tail` and a negative `--offset`
    /// ask for. Resolvable only once the size is known, which is why it survives
    /// as an anchor rather than being turned into a number too early.
    End,
}

/// What the range flags asked for, before any object is looked at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    anchor: Anchor,
    offset: u64,
    /// `None` means "to the end of the object".
    length: Option<u64>,
}

/// A resolved byte range within an object of a known size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slice {
    /// First byte to read.
    pub start: u64,
    /// Number of bytes to read. Always within the object.
    pub length: u64,
}

impl Slice {
    /// One past the last byte read.
    ///
    /// Cannot overflow: both fields come from [`Span::resolve`], which clamps
    /// them to a real object size.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.start + self.length
    }

    /// Whether the range selects nothing — an empty object, or an offset past
    /// the end.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.length == 0
    }
}

impl Span {
    /// The whole object, from the first byte to the last.
    pub const WHOLE: Self = Self {
        anchor: Anchor::Start,
        offset: 0,
        length: None,
    };

    /// Fold the four range flags into one span.
    ///
    /// clap already rejects the combinations that conflict, but the rules are
    /// re-stated here so they can be tested directly and so a future flag added
    /// without the matching `conflicts_with` cannot silently produce a range
    /// nobody asked for.
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::Usage`] when the flags contradict each other.
    pub fn from_flags(
        head: Option<u64>,
        tail: Option<u64>,
        offset: Option<i64>,
        count: Option<u64>,
    ) -> Result<Self> {
        if head.is_some() && tail.is_some() {
            return Err(
                CliError::usage("--head and --tail ask for opposite ends of the object")
                    .with_hint("Pick one, or use --offset with --count for an arbitrary range."),
            );
        }

        if let Some(length) = head {
            if offset.is_some() || count.is_some() {
                return Err(
                    CliError::usage("--head cannot be combined with --offset or --count")
                        .with_hint("--head N is shorthand for --offset 0 --count N."),
                );
            }
            return Ok(Self {
                anchor: Anchor::Start,
                offset: 0,
                length: Some(length),
            });
        }

        if let Some(length) = tail {
            if offset.is_some() || count.is_some() {
                return Err(
                    CliError::usage("--tail cannot be combined with --offset or --count")
                        .with_hint("--tail N is shorthand for --offset -N."),
                );
            }
            // Deliberately open-ended rather than `Some(length)`: starting N
            // bytes from the end and reading to the end is the same range, and
            // leaving the length unset keeps one representation of it.
            return Ok(Self {
                anchor: Anchor::End,
                offset: length,
                length: None,
            });
        }

        let (anchor, offset) = match offset {
            // A negative offset counts back from the end, matching rclone and
            // `tail -c`: `--offset -1M` is the last mebibyte.
            Some(value) if value < 0 => (Anchor::End, value.unsigned_abs()),
            Some(value) => (Anchor::Start, value.unsigned_abs()),
            // No offset at all: the whole object, narrowed by --count if given.
            None => return Ok(Self::WHOLE.taking(count)),
        };

        Ok(Self {
            anchor,
            offset,
            length: count,
        })
    }

    /// This span with its length replaced.
    #[must_use]
    const fn taking(self, length: Option<u64>) -> Self {
        Self {
            anchor: self.anchor,
            offset: self.offset,
            length,
        }
    }

    /// Resolve the span against an object of `size` bytes.
    ///
    /// Everything is clamped rather than refused. An offset past the end yields
    /// an empty slice, and a length longer than what remains is truncated — the
    /// same behaviour as `dd`, `tail -c` and every other tool that takes a byte
    /// range, and the behaviour a script depends on when it asks for the last
    /// megabyte of a file that turns out to be smaller than one.
    #[must_use]
    pub const fn resolve(self, size: u64) -> Slice {
        let start = match self.anchor {
            Anchor::Start if self.offset > size => size,
            Anchor::Start => self.offset,
            Anchor::End => size.saturating_sub(self.offset),
        };

        let available = size - start;
        let length = match self.length {
            Some(wanted) if wanted < available => wanted,
            Some(_) | None => available,
        };

        Slice { start, length }
    }
}

/// Parse a byte count for `--head`, `--tail` and `--count`.
///
/// Delegates to [`parse_size`] so `1M` means the same thing here as it does in
/// `--max-size`, then folds its "no limit" answer back into a plain zero. That
/// fold is the interesting part: for a *filter* threshold, `0` sensibly means
/// "unlimited", but for a *length* it means zero bytes, and `--head 0` must write
/// nothing rather than dump the whole object. The `off` spelling is refused
/// outright — a length has no "off".
///
/// # Errors
/// Returns a message suitable for a clap validation failure.
pub fn byte_count(input: &str) -> std::result::Result<u64, String> {
    if input.trim().eq_ignore_ascii_case(SIZE_LIMIT_OFF) {
        return Err(format!(
            "'{input}' is not a byte count; a length is a number, optionally with a \
             size suffix such as 1M"
        ));
    }
    Ok(parse_size(input)?.unwrap_or(0))
}

/// Parse a signed byte offset for `--offset`.
///
/// A negative value counts back from the end of the object, so `--offset -4K`
/// selects the last four kibibytes. Accepts the same size suffixes as
/// [`byte_count`], because an offset and a length are quoted in the same units
/// and having only one of them understand `1M` would be a trap.
///
/// # Errors
/// Returns a message suitable for a clap validation failure.
pub fn byte_offset(input: &str) -> std::result::Result<i64, String> {
    let (negative, magnitude) = match input.trim().strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, input.trim().trim_start_matches('+')),
    };

    let value = byte_count(magnitude)?;
    let signed =
        i64::try_from(value).map_err(|_| format!("'{input}' is too large to be a byte offset"))?;

    Ok(if negative { -signed } else { signed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::ExitCode;

    const SIZE: u64 = 1000;

    fn span(head: Option<u64>, tail: Option<u64>, offset: Option<i64>, count: Option<u64>) -> Span {
        Span::from_flags(head, tail, offset, count).unwrap()
    }

    #[test]
    fn no_flags_selects_the_whole_object() {
        let span = span(None, None, None, None);
        assert_eq!(span, Span::WHOLE);
        assert_eq!(
            span.resolve(SIZE),
            Slice {
                start: 0,
                length: SIZE
            }
        );
        assert_eq!(
            span.resolve(0),
            Slice {
                start: 0,
                length: 0
            }
        );
    }

    #[test]
    fn head_reads_from_the_front() {
        let slice = span(Some(10), None, None, None).resolve(SIZE);
        assert_eq!(
            slice,
            Slice {
                start: 0,
                length: 10
            }
        );
        assert_eq!(slice.end(), 10);
    }

    #[test]
    fn tail_reads_from_the_back() {
        let slice = span(None, Some(10), None, None).resolve(SIZE);
        assert_eq!(
            slice,
            Slice {
                start: 990,
                length: 10
            }
        );
        assert_eq!(slice.end(), SIZE);
    }

    #[test]
    fn a_negative_offset_counts_back_from_the_end() {
        // `--offset -100 --count 10` is "ten bytes, starting a hundred from the
        // end" — not the last ten.
        let slice = span(None, None, Some(-100), Some(10)).resolve(SIZE);
        assert_eq!(
            slice,
            Slice {
                start: 900,
                length: 10
            }
        );
    }

    #[test]
    fn offset_and_count_select_an_arbitrary_window() {
        let slice = span(None, None, Some(400), Some(100)).resolve(SIZE);
        assert_eq!(
            slice,
            Slice {
                start: 400,
                length: 100
            }
        );
    }

    #[test]
    fn an_offset_with_no_count_runs_to_the_end() {
        let slice = span(None, None, Some(400), None).resolve(SIZE);
        assert_eq!(
            slice,
            Slice {
                start: 400,
                length: 600
            }
        );
    }

    #[test]
    fn a_range_longer_than_the_object_is_truncated_not_refused() {
        // The case that matters: asking for the last megabyte of a file smaller
        // than a megabyte must yield the whole file, exactly as `tail -c` does.
        assert_eq!(
            span(None, Some(1_000_000), None, None).resolve(SIZE),
            Slice {
                start: 0,
                length: SIZE
            }
        );
        assert_eq!(
            span(Some(1_000_000), None, None, None).resolve(SIZE),
            Slice {
                start: 0,
                length: SIZE
            }
        );
        assert_eq!(
            span(None, None, Some(900), Some(1_000_000)).resolve(SIZE),
            Slice {
                start: 900,
                length: 100
            }
        );
    }

    #[test]
    fn an_offset_past_the_end_selects_nothing() {
        let slice = span(None, None, Some(5000), None).resolve(SIZE);
        assert!(slice.is_empty());
        assert_eq!(slice.start, SIZE);
    }

    #[test]
    fn a_zero_length_selects_nothing() {
        // `--head 0` must write nothing. Reading it as "no limit" — which is what
        // a bare 0 means to a size *filter* — would dump the whole object.
        assert!(span(Some(0), None, None, None).resolve(SIZE).is_empty());
        assert!(span(None, None, None, Some(0)).resolve(SIZE).is_empty());
    }

    #[test]
    fn contradictory_flags_are_refused_with_advice() {
        for flags in [
            (Some(1), Some(1), None, None),
            (Some(1), None, Some(1), None),
            (Some(1), None, None, Some(1)),
            (None, Some(1), Some(1), None),
            (None, Some(1), None, Some(1)),
        ] {
            let error = Span::from_flags(flags.0, flags.1, flags.2, flags.3).unwrap_err();
            assert_eq!(error.code(), ExitCode::Usage, "accepted {flags:?}");
            assert!(error.hint().is_some(), "{flags:?} failed without advice");
        }
    }

    #[test]
    fn byte_counts_accept_size_suffixes() {
        assert_eq!(byte_count("1024"), Ok(1024));
        assert_eq!(byte_count("1K"), Ok(1024));
        assert_eq!(byte_count("1kB"), Ok(1000));
        assert_eq!(byte_count("1.5M"), Ok(1024 * 1024 * 3 / 2));
    }

    #[test]
    fn a_zero_byte_count_is_zero_bytes_not_unlimited() {
        assert_eq!(byte_count("0"), Ok(0));
        // 'off' is a filter word, not a length; accepting it would silently mean
        // "no limit" where the user asked for a size.
        assert!(byte_count("off").is_err());
        assert!(byte_count("banana").is_err());
    }

    #[test]
    fn offsets_carry_a_sign_and_a_suffix() {
        assert_eq!(byte_offset("100"), Ok(100));
        assert_eq!(byte_offset("+100"), Ok(100));
        assert_eq!(byte_offset("-1M"), Ok(-1024 * 1024));
        assert_eq!(byte_offset("0"), Ok(0));
        assert!(byte_offset("-off").is_err());
    }

    #[test]
    fn an_offset_beyond_the_signed_range_is_refused() {
        // Rather than wrapping into a negative offset, which would silently read
        // from the wrong end of the object.
        assert!(byte_offset("8192P").is_err());
    }

    #[test]
    fn resolving_never_produces_a_range_outside_the_object() {
        // Property-ish sweep: whatever the flags, the slice stays inside.
        for size in [0_u64, 1, 7, SIZE] {
            for span in [
                Span::WHOLE,
                span(Some(3), None, None, None),
                span(None, Some(3), None, None),
                span(None, None, Some(-3), Some(9)),
                span(None, None, Some(5), Some(9)),
                span(None, None, Some(-9_000), None),
            ] {
                let slice = span.resolve(size);
                assert!(slice.start <= size, "start {} > size {size}", slice.start);
                assert!(slice.end() <= size, "end {} > size {size}", slice.end());
            }
        }
    }
}
