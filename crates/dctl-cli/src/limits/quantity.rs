//! A byte quantity typed on the command line, with `off` for "no limit".
//!
//! `--bwlimit 10M` and `--max-transfer 100G` both take one, and both are
//! **cost controls** rather than tuning knobs: they are what an operator sets so
//! a runaway job cannot generate a bill. That is why they are parsed here, by
//! clap, rather than in the command body like `--min-size` is.
//!
//! The difference matters. A `--min-size` that fails to parse costs a run. A
//! `--bwlimit` that fails to parse and is then *ignored* costs money, and the
//! shape of the failure — accepted, silent, no effect — is exactly the one this
//! whole change exists to remove. Giving the flag a type means the parser
//! refuses `--bwlimit 10Q` as a usage error before any command body starts, and
//! means no code path downstream can hold a value it has not validated.
//!
//! `off` and `0` are one meaning — no limit — and are represented as `None`
//! rather than as `Some(0)`, so "unlimited" can never be confused with "nothing
//! is allowed through".

use std::str::FromStr;

use crate::output::size::parse_size;

/// A limit in bytes, or no limit at all.
///
/// A newtype rather than a bare `Option<u64>` so the `off` spelling has exactly
/// one implementation, and so a function taking a limit cannot be handed a
/// count of bytes by mistake.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ByteLimit(Option<u64>);

impl ByteLimit {
    /// No limit — what `off`, `0` and an absent flag all mean.
    #[must_use]
    pub const fn none() -> Self {
        Self(None)
    }

    /// A limit of exactly this many bytes.
    ///
    /// Zero is normalised to [`ByteLimit::none`] rather than kept, because the
    /// two spellings a user has for "unlimited" must not produce two different
    /// values downstream.
    #[must_use]
    pub const fn bytes(value: u64) -> Self {
        if value == 0 {
            Self(None)
        } else {
            Self(Some(value))
        }
    }

    /// The limit in bytes, or `None` when there is none.
    #[must_use]
    pub const fn get(self) -> Option<u64> {
        self.0
    }
}

impl FromStr for ByteLimit {
    /// A message, because that is what clap renders for a bad value.
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_size(input).map(|parsed| parsed.map_or_else(Self::none, Self::bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_off_spellings_all_mean_no_limit() {
        for spelling in ["off", "OFF", "0"] {
            assert_eq!(
                spelling.parse::<ByteLimit>().unwrap().get(),
                None,
                "'{spelling}' must mean unlimited"
            );
        }
    }

    #[test]
    fn a_size_parses_with_the_same_suffixes_a_listing_prints() {
        assert_eq!("1k".parse::<ByteLimit>().unwrap().get(), Some(1024));
        assert_eq!("1kB".parse::<ByteLimit>().unwrap().get(), Some(1000));
        assert_eq!(
            "10M".parse::<ByteLimit>().unwrap().get(),
            Some(10 * 1024 * 1024)
        );
    }

    #[test]
    fn a_malformed_limit_is_a_message_not_a_silent_zero() {
        // The failure this type exists to prevent: `--bwlimit 10Q` accepted,
        // parsed to nothing, and the run proceeding at full speed.
        let error = "10Q".parse::<ByteLimit>().unwrap_err();
        assert!(error.contains("10Q"), "{error}");
        assert!("-5".parse::<ByteLimit>().is_err());
        assert!("nonsense".parse::<ByteLimit>().is_err());
    }

    #[test]
    fn zero_bytes_is_no_limit_not_an_impassable_one() {
        assert_eq!(ByteLimit::bytes(0), ByteLimit::none());
        assert_eq!(ByteLimit::bytes(1).get(), Some(1));
    }
}
