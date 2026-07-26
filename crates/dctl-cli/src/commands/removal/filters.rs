//! The filter set a removal will honour, resolved and validated up front.
//!
//! `delete` honours filters; `purge` ignores them. That difference is the whole
//! reason both commands exist, so the filter set is a first-class value here
//! rather than a handful of flags read at the point of use — a command either
//! resolves one and shows it, or documents that it does not.
//!
//! Validation happens *before* the destructive gate, deliberately. A
//! `--max-size` that does not parse is a typo, and a typo in a size limit on a
//! `delete` is exactly the kind of mistake that removes far more than intended.
//! Failing at parse time costs a second; failing after the first object is gone
//! costs a restore.

use serde::Serialize;

use crate::cli::globals::GlobalArgs;
use crate::constants::{
    MAX_DEPTH_UNLIMITED, REMOVAL_LABEL_EXCLUDE, REMOVAL_LABEL_FILES_FROM,
    REMOVAL_LABEL_FILTER_FROM, REMOVAL_LABEL_INCLUDE, REMOVAL_LABEL_MAX_DEPTH,
    REMOVAL_LABEL_MAX_SIZE, REMOVAL_LABEL_MIN_SIZE, REMOVAL_LIST_SEPARATOR, SIZE_PARSE_EXAMPLES,
};
use crate::error::{CliError, Result};
use crate::output::size::{self, Units};

use super::plan::Row;

/// The active filter set for one removal.
///
/// Every field is omitted from the JSON when it is unset, so a machine consumer
/// can distinguish "no size limit" from "a limit of zero" without a sentinel.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Filters {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub filter_from: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files_from: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
    /// Recursion limit, or `None` for unlimited. Never carries the `-1`
    /// sentinel: "no limit" is the absence of a value, not a negative one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<i32>,
}

impl Filters {
    /// Read and validate the global filter flags.
    ///
    /// # Errors
    /// [`crate::exit::ExitCode::Usage`] when a size does not parse, when the
    /// two size bounds cross (no object could ever match, so the command would
    /// silently do nothing), or when `--max-depth` is negative but is not the
    /// documented "unlimited" sentinel.
    pub fn resolve(globals: &GlobalArgs) -> Result<Self> {
        let min_size = parse_bound(globals.min_size.as_deref(), REMOVAL_LABEL_MIN_SIZE)?;
        let max_size = parse_bound(globals.max_size.as_deref(), REMOVAL_LABEL_MAX_SIZE)?;

        if let (Some(min), Some(max)) = (min_size, max_size) {
            if min > max {
                return Err(CliError::usage(format!(
                    "--min-size ({min}) is larger than --max-size ({max})"
                ))
                .with_hint(
                    "No object can satisfy both bounds, so the command would remove \
                     nothing. Swap them, or drop one.",
                ));
            }
        }

        let max_depth = match globals.max_depth {
            MAX_DEPTH_UNLIMITED => None,
            depth if depth < MAX_DEPTH_UNLIMITED => {
                return Err(
                    CliError::usage(format!("--max-depth {depth} is not a depth")).with_hint(
                        format!("Use a depth of 0 or more, or {MAX_DEPTH_UNLIMITED} for no limit."),
                    ),
                );
            }
            depth => Some(depth),
        };

        Ok(Self {
            include: globals.include.clone(),
            exclude: globals.exclude.clone(),
            filter_from: to_strings(&globals.filter_from),
            files_from: to_strings(&globals.files_from),
            min_size,
            max_size,
            max_depth,
        })
    }

    /// Label/value rows describing the set, for the text rendering of a plan.
    ///
    /// Sizes are rendered in the caller's chosen [`Units`] so the plan quotes
    /// limits the same way a listing quotes the objects they will match.
    #[must_use]
    pub fn rows(&self, units: Units) -> Vec<Row> {
        let mut rows = Vec::new();
        push_list(&mut rows, REMOVAL_LABEL_INCLUDE, &self.include);
        push_list(&mut rows, REMOVAL_LABEL_EXCLUDE, &self.exclude);
        push_list(&mut rows, REMOVAL_LABEL_FILTER_FROM, &self.filter_from);
        push_list(&mut rows, REMOVAL_LABEL_FILES_FROM, &self.files_from);
        if let Some(min) = self.min_size {
            rows.push((REMOVAL_LABEL_MIN_SIZE, size::bytes(min, units)));
        }
        if let Some(max) = self.max_size {
            rows.push((REMOVAL_LABEL_MAX_SIZE, size::bytes(max, units)));
        }
        if let Some(depth) = self.max_depth {
            rows.push((REMOVAL_LABEL_MAX_DEPTH, depth.to_string()));
        }
        rows
    }
}

/// Parse one size bound, naming the flag in any failure.
fn parse_bound(value: Option<&str>, label: &str) -> Result<Option<u64>> {
    match value {
        None => Ok(None),
        Some(raw) => size::parse_size(raw).map_err(|message| {
            CliError::usage(format!("{label}: {message}"))
                .with_hint(format!("Sizes are written as {SIZE_PARSE_EXAMPLES}."))
        }),
    }
}

/// Render paths for display and serialisation.
///
/// Lossy on purpose: a `--filter-from` path that is not valid UTF-8 is still
/// worth quoting back to the user in a plan, and a plan is not a place where a
/// mangled byte can do damage.
fn to_strings(paths: &[std::path::PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect()
}

/// Append a row for a repeatable flag, unless it was never given.
fn push_list(rows: &mut Vec<Row>, label: &'static str, values: &[String]) {
    if !values.is_empty() {
        rows.push((label, values.join(REMOVAL_LIST_SEPARATOR)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::ExitCode;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn globals(args: &[&str]) -> GlobalArgs {
        Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals
    }

    fn resolve(args: &[&str]) -> Result<Filters> {
        Filters::resolve(&globals(args))
    }

    #[test]
    fn no_flags_means_no_narrowing() {
        let filters = resolve(&[]).unwrap();
        assert!(filters.rows(Units::Binary).is_empty());
    }

    #[test]
    fn repeatable_patterns_are_carried_through_in_order() {
        let filters = resolve(&["--include", "*.jpg", "--include", "*.raw"]).unwrap();
        assert_eq!(filters.include, ["*.jpg", "*.raw"]);
        assert!(!filters.rows(Units::Binary).is_empty());
    }

    #[test]
    fn sizes_are_parsed_with_the_same_spellings_a_listing_prints() {
        let filters = resolve(&["--min-size", "1k", "--max-size", "1M"]).unwrap();
        assert_eq!(filters.min_size, Some(1024));
        assert_eq!(filters.max_size, Some(1024 * 1024));
    }

    #[test]
    fn an_unparseable_size_fails_before_anything_is_removed() {
        let error = resolve(&["--max-size", "banana"]).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some());
    }

    #[test]
    fn crossed_size_bounds_are_refused_rather_than_matching_nothing() {
        // Silently removing nothing would look like success; it is a typo.
        let error = resolve(&["--min-size", "10M", "--max-size", "1M"]).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[test]
    fn the_unlimited_depth_sentinel_becomes_an_absent_value() {
        assert_eq!(resolve(&[]).unwrap().max_depth, None);
        assert_eq!(resolve(&["--max-depth", "2"]).unwrap().max_depth, Some(2));
    }

    #[test]
    fn a_nonsense_depth_is_a_usage_error() {
        // Written with `=` because clap reads a bare `-7` as a flag; the
        // sentinel is the only negative depth the resolver accepts.
        let error = resolve(&["--max-depth=-7"]).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(resolve(&["--max-depth=-1"]).is_ok());
    }

    #[test]
    fn unset_filters_are_absent_from_the_json_not_null() {
        let value = serde_json::to_value(resolve(&[]).unwrap()).unwrap();
        assert_eq!(value, serde_json::json!({}));
    }

    #[test]
    fn the_json_shape_names_every_flag_that_was_given() {
        let filters = resolve(&[
            "--exclude",
            "tmp/**",
            "--min-size",
            "1k",
            "--max-depth",
            "3",
        ])
        .unwrap();
        let value = serde_json::to_value(&filters).unwrap();
        assert_eq!(value["exclude"][0], "tmp/**");
        assert_eq!(value["min_size"], 1024);
        assert_eq!(value["max_depth"], 3);
        assert!(value.get("include").is_none());
    }

    #[test]
    fn rows_quote_sizes_in_the_requested_units() {
        let filters = resolve(&["--min-size", "1k"]).unwrap();
        let binary = filters.rows(Units::Binary);
        let decimal = filters.rows(Units::Decimal);
        assert_eq!(binary.len(), 1);
        assert_ne!(binary[0].1, decimal[0].1, "units must reach the plan");
    }
}
