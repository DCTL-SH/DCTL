//! The tunables `dctl mount` accepts, and how they are read off the command
//! line.
//!
//! Every value here is validated by clap **before** the command body runs, so a
//! typo in `--dir-cache-time` is a usage error (exit 1) with a message naming
//! the accepted spellings, not a surprise three layers into a mount attempt.
//! That matters more than usual for this command: the flags are published in
//! `--help`, in the generated shell completions and in the documentation from
//! the moment this ships, and phase 2 must be able to wire an engine underneath
//! them without changing a single spelling.

use std::time::Duration;

use clap::ValueEnum;

use crate::constants::{
    DURATION_PARSE_EXAMPLES, DURATION_SUFFIX_MULTIPLIERS_MS, MOUNT_SIZE_DISABLED,
};
use crate::output::size::parse_size;

/// How much of a file the VFS keeps on local disk.
///
/// The four modes are rclone's, because a user reaching for `--vfs-cache-mode`
/// has read rclone's documentation for it, and a fifth spelling of the same four
/// behaviours would help nobody. `PLAN.md` §15 makes the encrypted on-disk cache
/// the second tier beneath the in-RAM one; this flag decides how much of it a
/// mount is allowed to use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum VfsCacheMode {
    /// Stream everything; keep nothing on disk. Reads only, no rewrites.
    #[default]
    Off,
    /// Cache only what an application opens for writing.
    Minimal,
    /// Cache written data so a re-read after a write is served locally.
    Writes,
    /// Cache read and written data. The only mode where seeking backwards in a
    /// large file is free the second time.
    Full,
}

impl VfsCacheMode {
    /// Stable slug for logs and, later, for the mount's own status output.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Minimal => "minimal",
            Self::Writes => "writes",
            Self::Full => "full",
        }
    }
}

/// Parse a duration written the way a human writes one: `5m`, `1s`, `500ms`,
/// or a bare number of seconds.
///
/// The inverse of [`crate::output::size::duration`], and deliberately shaped
/// like [`parse_size`] so the two flag families behave the same way: a bare
/// number takes the natural unit, a suffix is matched case-insensitively, and a
/// failure quotes the input and the accepted spellings.
///
/// # Errors
/// A message suitable for a clap validation failure.
pub fn parse_duration(input: &str) -> Result<Duration, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "a duration is required (try {DURATION_PARSE_EXAMPLES})"
        ));
    }

    // The suffix starts at the first letter; everything before it is the number.
    let split = trimmed
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(trimmed.len());
    let (number, suffix) = trimmed.split_at(split);

    let value: f64 = number.trim().parse().map_err(|_| {
        format!("'{input}' is not a valid duration (try {DURATION_PARSE_EXAMPLES})")
    })?;
    if value < 0.0 {
        return Err(format!("'{input}' is negative"));
    }
    if !value.is_finite() {
        return Err(format!("'{input}' is not a finite duration"));
    }

    let suffix = suffix.trim();
    let key = suffix.to_ascii_lowercase();
    let multiplier = DURATION_SUFFIX_MULTIPLIERS_MS
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, multiplier)| *multiplier)
        // The message quotes the suffix as typed, not as folded, so the user can
        // see their own input in the error.
        .ok_or_else(|| format!("unknown duration suffix '{suffix}' in '{input}'"))?;

    Ok(Duration::from_millis((value * multiplier as f64) as u64))
}

/// Parse a byte size for a mount buffer, where "no limit" means "no buffer".
///
/// [`parse_size`] returns `None` for `0` and `off` because for a *filter* those
/// mean "unlimited". For a buffer they mean the opposite — allocate nothing —
/// so the mapping is made explicit here rather than left for each flag to guess.
///
/// # Errors
/// A message suitable for a clap validation failure.
pub fn parse_buffer_size(input: &str) -> Result<u64, String> {
    Ok(parse_size(input)?.unwrap_or(MOUNT_SIZE_DISABLED))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_numbers_are_seconds() {
        // Matching --timeout and every other bare number of time in the tool.
        assert_eq!(parse_duration("90"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("0"), Ok(Duration::ZERO));
    }

    #[test]
    fn every_suffix_on_the_ladder_resolves() {
        assert_eq!(parse_duration("500ms"), Ok(Duration::from_millis(500)));
        assert_eq!(parse_duration("5s"), Ok(Duration::from_secs(5)));
        assert_eq!(parse_duration("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(parse_duration("2h"), Ok(Duration::from_secs(7_200)));
        assert_eq!(parse_duration("1d"), Ok(Duration::from_secs(86_400)));
    }

    #[test]
    fn suffixes_are_case_insensitive_and_space_tolerant() {
        // Users copy values out of documentation, and documentation is not
        // consistent about either.
        assert_eq!(parse_duration("5M"), parse_duration("5m"));
        assert_eq!(parse_duration("  5 m  "), parse_duration("5m"));
    }

    #[test]
    fn fractions_are_accepted_and_land_on_the_millisecond() {
        assert_eq!(parse_duration("1.5s"), Ok(Duration::from_millis(1_500)));
        assert_eq!(parse_duration("0.5m"), Ok(Duration::from_secs(30)));
    }

    #[test]
    fn malformed_durations_name_the_accepted_spellings() {
        for input in ["", "  ", "soon", "5x", "-1s", "s"] {
            let error = parse_duration(input).unwrap_err();
            assert!(!error.is_empty(), "silent failure for '{input}'");
        }
        assert!(parse_duration("soon").unwrap_err().contains("500ms"));
    }

    #[test]
    fn every_ladder_row_is_reachable_and_lower_case() {
        // A row nobody can spell is dead weight; lookup folds the user's suffix
        // to lower case, so an upper-case key here would never match.
        for (suffix, millis) in DURATION_SUFFIX_MULTIPLIERS_MS {
            assert_eq!(*suffix, suffix.to_ascii_lowercase(), "'{suffix}'");
            let written = format!("1{suffix}");
            assert_eq!(
                parse_duration(&written),
                Ok(Duration::from_millis(*millis)),
                "'{written}' did not resolve to its own multiplier"
            );
        }
    }

    #[test]
    fn the_ladder_has_no_duplicate_rows() {
        for (index, (suffix, _)) in DURATION_SUFFIX_MULTIPLIERS_MS.iter().enumerate() {
            for (other, _) in &DURATION_SUFFIX_MULTIPLIERS_MS[index + 1..] {
                assert_ne!(suffix, other, "'{suffix}' is listed twice");
            }
        }
    }

    #[test]
    fn a_disabled_buffer_is_zero_bytes_not_unlimited() {
        // The inversion this wrapper exists for: for a filter, 0 means "no
        // limit"; for a buffer it means "allocate nothing".
        assert_eq!(parse_buffer_size("0"), Ok(MOUNT_SIZE_DISABLED));
        assert_eq!(parse_buffer_size("off"), Ok(MOUNT_SIZE_DISABLED));
    }

    #[test]
    fn buffer_sizes_use_the_same_ladder_as_every_other_size_flag() {
        assert_eq!(parse_buffer_size("16M"), Ok(16 * 1024 * 1024));
        assert_eq!(parse_buffer_size("1MB"), Ok(1_000_000));
        assert!(parse_buffer_size("banana").is_err());
    }

    #[test]
    fn the_cache_mode_spellings_are_stable() {
        // They are in every mount script and systemd unit that calls DCTL;
        // renaming a variant must not silently rename a flag value.
        let spellings: Vec<String> = VfsCacheMode::value_variants()
            .iter()
            .filter_map(ValueEnum::to_possible_value)
            .map(|value| value.get_name().to_owned())
            .collect();
        assert_eq!(spellings, ["off", "minimal", "writes", "full"]);
    }

    #[test]
    fn each_cache_mode_slug_matches_its_flag_spelling() {
        // The slug lands in a log record; a mismatch would make a query for
        // `vfs_cache_mode=full` miss the runs that used --vfs-cache-mode full.
        for mode in VfsCacheMode::value_variants() {
            let spelling = mode
                .to_possible_value()
                .map(|value| value.get_name().to_owned());
            assert_eq!(spelling.as_deref(), Some(mode.slug()));
        }
    }

    #[test]
    fn caching_nothing_is_the_default() {
        // A mount that silently filled a disk cache on first use would be a
        // surprise; the expensive modes are opt-in.
        assert_eq!(VfsCacheMode::default(), VfsCacheMode::Off);
    }
}
