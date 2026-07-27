//! Human-readable sizes, rates, durations and counts.
//!
//! Two conventions are supported because both are load-bearing: storage
//! providers bill in **decimal** units (a "1 TB" bucket is 10^12 bytes) while
//! operating systems report **binary** units (Windows' "1 TB" is 2^40). DCTL
//! shows binary by default — matching what the OS shows for the same file — and
//! `--units decimal` switches over for reconciling an invoice.
//!
//! The four formatters live in their own files because they answer four
//! unrelated questions — how big, how fast, how long, how many — and only
//! [`bytes()`] and [`rate()`] share the [`Units`] choice defined here.
//! [`parse_size()`] is the inverse of [`bytes()`] and is kept beside it so the
//! accepted spellings and the printed ones stay in step.

mod bytes;
mod count;
mod duration;
mod parse;

pub use bytes::{bytes, bytes_or_unknown, rate};
pub use count::count;
pub use duration::{duration, eta};
pub use parse::parse_size;

use clap::ValueEnum;

use crate::constants::{
    BINARY_DIVISOR, BINARY_UNIT_SUFFIXES, DECIMAL_DIVISOR, DECIMAL_UNIT_SUFFIXES,
};

/// Which unit convention to display.
///
/// Chosen once on the command line and carried on the output sink rather than
/// passed per call site, so a single `--units` decides every number one command
/// prints. A run that mixed the two would be worse than either, because the
/// reader could not tell which convention any one figure used.
///
/// Derives [`ValueEnum`] for the same reason `ColorChoice` does: the flag's
/// accepted values and its `--help` text are then generated from this
/// definition, so a new convention can never be added to the enum and forgotten
/// in the parser.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum Units {
    /// Powers of 1024 with IEC suffixes (KiB, MiB, …). Matches the OS.
    #[default]
    Binary,
    /// Powers of 1000 with SI suffixes (kB, MB, …). Matches provider billing.
    Decimal,
}

impl Units {
    /// The value one unit step is worth.
    ///
    /// Deliberately not public — the divisor and the suffix table are only
    /// correct together, and exposing either alone invites a caller to pair 1024
    /// with `kB`. The formatters in this module's children reach it as
    /// descendants; nothing outside can.
    const fn divisor(self) -> f64 {
        match self {
            Self::Binary => BINARY_DIVISOR,
            Self::Decimal => DECIMAL_DIVISOR,
        }
    }

    /// Unit suffixes in ascending order, starting with the bare byte. Paired
    /// with [`Units::divisor`]; see the note there.
    const fn suffixes(self) -> &'static [&'static str] {
        match self {
            Self::Binary => BINARY_UNIT_SUFFIXES,
            Self::Decimal => DECIMAL_UNIT_SUFFIXES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_is_the_default_convention() {
        // Matching the OS is the less surprising default: a user comparing a
        // listing against Finder or Explorer sees the same number.
        assert_eq!(Units::default(), Units::Binary);
    }

    #[test]
    fn each_convention_pairs_its_own_divisor_with_its_own_suffixes() {
        assert!((Units::Binary.divisor() - 1024.0).abs() < f64::EPSILON);
        assert!((Units::Decimal.divisor() - 1000.0).abs() < f64::EPSILON);
        assert_eq!(Units::Binary.suffixes()[1], "KiB");
        assert_eq!(Units::Decimal.suffixes()[1], "kB");
    }

    #[test]
    fn the_flag_spellings_are_lower_case_and_complete() {
        // `--units Binary` is not a spelling anyone types, and a variant with no
        // possible value would be unreachable from the command line.
        let spellings: Vec<String> = Units::value_variants()
            .iter()
            .filter_map(|variant| variant.to_possible_value())
            .map(|value| value.get_name().to_string())
            .collect();
        assert_eq!(spellings, ["binary", "decimal"]);
    }

    #[test]
    fn both_suffix_tables_start_at_the_bare_byte() {
        // `bytes` prints counts below the divisor with the first suffix, so a
        // table that started at "KiB" would label 512 bytes as kibibytes.
        assert_eq!(Units::Binary.suffixes().first(), Some(&"B"));
        assert_eq!(Units::Decimal.suffixes().first(), Some(&"B"));
    }
}
