//! What `dctl about` prints.
//!
//! Two tables in text, one document in JSON, and the same facts in both. The
//! summary says which remote was addressed, what is really on the far end of it,
//! and — unless `--capabilities` asked for the offline half alone — how much is
//! stored there; the matrix says what that provider's backend can do. Both go to
//! **stdout**, because they are the command's result (`PLAN.md` §7), and
//! `dctl about vault: --json | jq '.bytes'` is a working pipeline.
//!
//! ## Every fact is in both renderings, including the absences
//!
//! `total_bytes` and `free_bytes` are always present in the JSON and always
//! `null`, with [`ABOUT_LIMITS_NOTE`] beside them saying exactly why nothing in
//! this build can measure them. A key that vanished when the answer was unknown
//! would make a consumer's `.total_bytes` silently `undefined`; a `0` would be
//! believed. The text table shows the same two rows carrying
//! [`ABOUT_LIMIT_NOT_REPORTED`], so a person reading the table and a script
//! reading the document reach the same conclusion.
//!
//! The `capabilities` array carries a real boolean per row rather than the
//! `yes`/`no` words the text table shows: a machine consumer must never have to
//! parse a human rendering, and a script that branched on the string would break
//! the first time somebody translated it.

use serde::Serialize;

use crate::constants::{
    ABOUT_CAPABILITIES_NOTICE, ABOUT_COLUMN_CAPABILITY, ABOUT_COLUMN_DESCRIPTION,
    ABOUT_COLUMN_SETTING, ABOUT_COLUMN_SUPPORTED, ABOUT_COLUMN_VALUE, ABOUT_FIELD_BYTES,
    ABOUT_FIELD_CHAIN, ABOUT_FIELD_ENCRYPTED, ABOUT_FIELD_FREE_BYTES, ABOUT_FIELD_LIMITS_NOTE,
    ABOUT_FIELD_OBJECTS, ABOUT_FIELD_PROVIDER, ABOUT_FIELD_REMOTE, ABOUT_FIELD_SIZES,
    ABOUT_FIELD_STORAGE_PROVIDER, ABOUT_FIELD_TOTAL_BYTES, ABOUT_FIELD_UNMEASURED,
    ABOUT_LIMIT_NOT_REPORTED, ABOUT_LIMITS_NOTE, ABOUT_USAGE_NOTICE, CONFIG_CHAIN_ARROW,
    SIZE_REPORT_EXACT_UNIT, SIZE_REPORT_LOWER_BOUND,
};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::size::{bytes as human_bytes, count};
use crate::output::{Align, Border, Column, Table};
use crate::source::Sizes;

use super::capabilities::{self, Capability};
use super::target::Described;
use super::usage::Usage;

/// The result of one `dctl about --capabilities` invocation.
///
/// Field names are the JSON keys *and* the text row labels, following the
/// convention [`crate::constants::ABOUT_FIELD_REMOTE`] documents.
#[derive(Debug, Serialize)]
pub struct AboutReport {
    /// The remote as it was understood, not as it was typed.
    pub remote: String,
    /// The named remote's own provider type.
    pub provider: &'static str,
    /// The provider that actually stores bytes — the far end of a vault chain,
    /// and the one the capability rows describe.
    pub storage_provider: &'static str,
    /// Whether anything in the chain encrypts on the way through.
    pub encrypted: bool,
    /// The remote names walked, nearest first. Empty for a filesystem path.
    pub chain: Vec<String>,
    /// Objects found under the remote's root, or [`None`] when
    /// `--capabilities` asked for the offline half of the report and nothing was
    /// enumerated. `null` here means "not measured", never "none".
    pub objects: Option<u64>,
    /// Their total size, on the basis named by `sizes`.
    ///
    /// `null` for two different reasons, told apart by `objects`: nothing was
    /// enumerated at all (`objects` is null too — the `--capabilities` case), or
    /// the enumeration met objects with no recorded size and therefore cannot
    /// total itself (`objects` is a number and `unmeasured` is non-zero). Both
    /// are honest absences and neither may be rendered as `0`, which in a
    /// capacity report gets believed and then gets acted on.
    pub bytes: Option<u64>,
    /// Total of the objects that did carry a recorded size — the lower bound
    /// behind a null `bytes`. `null` only when nothing was enumerated.
    pub measured_bytes: Option<u64>,
    /// How many enumerated objects carried no recorded size. `null` only when
    /// nothing was enumerated.
    pub unmeasured: Option<u64>,
    /// Which basis that was.
    pub sizes: Option<Sizes>,
    /// The allowance this remote is subject to. Always [`None`]: see
    /// [`ABOUT_LIMITS_NOTE`].
    pub total_bytes: Option<u64>,
    /// What is left of it. Always [`None`], for the same reason.
    pub free_bytes: Option<u64>,
    /// Why the two above are `null`, carried in the document rather than left to
    /// the documentation — a script's author reads this, not the manual.
    pub limits_note: &'static str,
    /// Every capability, supported or not. See
    /// [`super::capabilities::for_provider`] for why the unsupported rows are
    /// included.
    pub capabilities: Vec<Capability>,
}

impl AboutReport {
    /// Build the record for a resolved remote.
    ///
    /// `usage` is [`None`] for `--capabilities`, which deliberately enumerates
    /// nothing: that mode answers offline, without credentials and without a
    /// password, and a listing would cost all three.
    #[must_use]
    pub fn new(described: &Described, usage: Option<Usage>) -> Self {
        Self {
            remote: described.remote.clone(),
            provider: described.provider,
            storage_provider: described.storage_provider,
            encrypted: described.encrypted,
            chain: described.chain.clone(),
            objects: usage.map(|usage| usage.objects),
            bytes: usage.and_then(|usage| usage.bytes),
            measured_bytes: usage.map(|usage| usage.measured_bytes),
            unmeasured: usage.map(|usage| usage.unmeasured),
            sizes: usage.map(|usage| usage.sizes),
            // Not a placeholder waiting to be filled in by a later branch: there
            // is no code path in this build that can produce either number, and
            // the note beside them says why in full.
            total_bytes: None,
            free_bytes: None,
            limits_note: ABOUT_LIMITS_NOTE,
            capabilities: capabilities::for_provider(described.storage_provider),
        }
    }

    /// The rows of the summary table, in the order a person reads them: what was
    /// addressed, what it is, what is really behind it, whether it is encrypted
    /// on the way through, how much is in it, and what the allowance is.
    ///
    /// The chain row is omitted for a filesystem path, which is not a named
    /// remote and therefore has no chain — an empty cell there would read as a
    /// missing value rather than an inapplicable one. The usage rows are omitted
    /// under `--capabilities`, which measured nothing, for the same reason: a
    /// `0` there would be read as an empty remote.
    ///
    /// Every label is the JSON field name it corresponds to, so the two
    /// renderings can be read against each other without a legend.
    ///
    /// `units` decides how the byte total is rounded for the human column; the
    /// exact figure travels beside it, because a rounded number loses up to five
    /// per cent of what somebody is about to subtract from a quota.
    pub fn rows(&self, units: crate::output::Units) -> Vec<(&'static str, String)> {
        let mut rows = vec![
            (ABOUT_FIELD_REMOTE, self.remote.clone()),
            (ABOUT_FIELD_PROVIDER, self.provider.to_string()),
            (
                ABOUT_FIELD_STORAGE_PROVIDER,
                self.storage_provider.to_string(),
            ),
            (ABOUT_FIELD_ENCRYPTED, self.encrypted.to_string()),
        ];
        if !self.chain.is_empty() {
            rows.push((ABOUT_FIELD_CHAIN, self.chain.join(CONFIG_CHAIN_ARROW)));
        }

        // Gated on `objects` and `sizes`, not on `bytes`: a remote that was
        // measured but could not be totalled still has rows worth printing, and
        // dropping them would hide the object count as well as the byte one.
        if let (Some(objects), Some(sizes)) = (self.objects, self.sizes) {
            let measured = self.measured_bytes.unwrap_or_default();
            rows.push((ABOUT_FIELD_OBJECTS, count(objects)));
            rows.push((
                ABOUT_FIELD_BYTES,
                format!(
                    "{}{} ({measured} {SIZE_REPORT_EXACT_UNIT})",
                    if self.bytes.is_some() {
                        String::new()
                    } else {
                        format!("{SIZE_REPORT_LOWER_BOUND} ")
                    },
                    human_bytes(measured, units)
                ),
            ));
            if self.unmeasured.is_some_and(|count| count > 0) {
                rows.push((
                    ABOUT_FIELD_UNMEASURED,
                    count(self.unmeasured.unwrap_or_default()),
                ));
            }
            // The basis is a row of its own rather than a suffix on the figure:
            // it is a JSON field, and the label/field correspondence is what
            // lets a reader move between the two renderings.
            rows.push((ABOUT_FIELD_SIZES, sizes.label().to_string()));
            rows.push((ABOUT_FIELD_TOTAL_BYTES, ABOUT_LIMIT_NOT_REPORTED.into()));
            rows.push((ABOUT_FIELD_FREE_BYTES, ABOUT_LIMIT_NOT_REPORTED.into()));
            rows.push((ABOUT_FIELD_LIMITS_NOTE, self.limits_note.to_string()));
        }

        rows
    }

    /// Write the report to stdout in the active format.
    ///
    /// # Errors
    /// Any stdout failure other than a broken pipe, which
    /// [`crate::output::Out`] deliberately tolerates.
    pub fn emit(&self, ctx: &Ctx) -> Result<()> {
        // Said on stderr, so they can never corrupt a pipe, and at -v so the
        // default output stays clean: the capability rows describe the backend
        // in this binary rather than an answer from the provider, and the usage
        // figures are what DCTL counted rather than what the provider bills for.
        ctx.out.info(ABOUT_CAPABILITIES_NOTICE);
        if self.objects.is_some() {
            ctx.out.info(ABOUT_USAGE_NOTICE);
        }

        if ctx.out.format().is_json() {
            ctx.out.json(self)?;
            return Ok(());
        }

        ctx.out.table(&self.summary_table(ctx.out.units()))?;
        // A blank line between two tables, so the second reads as a second table
        // rather than as more rows of the first.
        ctx.out.line("")?;
        ctx.out.table(&self.capability_table())?;
        Ok(())
    }

    /// The remote summary, borderless so it stays greppable.
    fn summary_table(&self, units: crate::output::Units) -> Table {
        let mut table = Table::new(vec![
            Column::new(ABOUT_COLUMN_SETTING, Align::Left),
            Column::new(ABOUT_COLUMN_VALUE, Align::Left),
        ])
        .with_border(Border::None);
        for (label, value) in self.rows(units) {
            table.push(vec![label.to_string(), value]);
        }
        table
    }

    /// The capability matrix, headed because it is a report rather than a
    /// listing and the third column needs naming to be readable.
    fn capability_table(&self) -> Table {
        let mut table = Table::new(vec![
            Column::new(ABOUT_COLUMN_CAPABILITY, Align::Left),
            Column::new(ABOUT_COLUMN_SUPPORTED, Align::Left),
            Column::new(ABOUT_COLUMN_DESCRIPTION, Align::Left),
        ])
        .with_border(Border::Header);

        for capability in &self.capabilities {
            table.push(vec![
                capability.name.to_string(),
                capability.supported_label().to_string(),
                capability.description.to_string(),
            ]);
        }
        table
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::constants::{
        ABOUT_FIELD_CAPABILITIES, ABOUT_SUPPORTED_NO, ABOUT_SUPPORTED_YES,
        CAPABILITY_QUOTA_REPORTING, CAPABILITY_USAGE_REPORTING, PROVIDER_B2, PROVIDER_LOCAL,
        PROVIDER_VAULT,
    };
    use crate::output::Units;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        let parsed = Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied()));
        Ctx::new(parsed.globals)
    }

    fn local() -> Described {
        Described {
            spec: crate::remote::RemoteSpec::Local(std::path::PathBuf::from("/srv/data")),
            remote: "/srv/data".into(),
            provider: PROVIDER_LOCAL,
            storage_provider: PROVIDER_LOCAL,
            encrypted: false,
            chain: Vec::new(),
        }
    }

    fn vault_over_b2() -> Described {
        Described {
            spec: crate::remote::RemoteSpec::Named {
                remote: "vault".into(),
                path: "2024".into(),
            },
            remote: "vault:2024".into(),
            provider: PROVIDER_VAULT,
            storage_provider: PROVIDER_B2,
            encrypted: true,
            chain: vec!["vault".into(), "b2prod".into()],
        }
    }

    /// A measured usage figure, as a sealed remote produces one.
    fn measured() -> Usage {
        Usage {
            objects: 3,
            bytes: Some(6150),
            measured_bytes: 6150,
            unmeasured: 0,
            sizes: Sizes::Plaintext,
        }
    }

    #[test]
    fn text_row_labels_are_the_json_field_names() {
        let report = AboutReport::new(&vault_over_b2(), Some(measured()));
        let json = serde_json::to_value(&report).unwrap();
        for (label, _) in report.rows(Units::Binary) {
            assert!(
                json.get(label).is_some(),
                "text row '{label}' has no matching JSON field"
            );
        }
    }

    #[test]
    fn the_capabilities_reported_are_the_storage_providers_not_the_wrappers() {
        // The whole reason the chain is followed: a vault remote stores nothing,
        // so reporting its capabilities would describe the wrong thing.
        let report = AboutReport::new(&vault_over_b2(), None);
        assert_eq!(report.provider, PROVIDER_VAULT);
        assert_eq!(report.storage_provider, PROVIDER_B2);
        assert_eq!(
            report.capabilities,
            capabilities::for_provider(PROVIDER_B2),
            "the wrapper's capabilities were reported"
        );
    }

    #[test]
    fn usage_and_quota_are_reported_as_unsupported_everywhere() {
        // Consistency with the `unimplemented` gate in the command: the table
        // and the error must tell the same story.
        for described in [local(), vault_over_b2()] {
            let report = AboutReport::new(&described, None);
            for name in [CAPABILITY_USAGE_REPORTING, CAPABILITY_QUOTA_REPORTING] {
                let row = report
                    .capabilities
                    .iter()
                    .find(|entry| entry.name == name)
                    .expect("the row is in the matrix");
                assert!(!row.supported, "{name} claimed support");
                assert_eq!(row.supported_label(), ABOUT_SUPPORTED_NO);
            }
        }
    }

    #[test]
    fn the_json_carries_booleans_and_never_the_human_words() {
        // A consumer must branch on `true`, not on the string `yes`, or it
        // breaks the moment the words change.
        let report = AboutReport::new(&local(), None);
        let json = serde_json::to_value(&report).unwrap();
        let capabilities = json[ABOUT_FIELD_CAPABILITIES].as_array().unwrap();
        assert!(!capabilities.is_empty());
        for entry in capabilities {
            assert!(entry["supported"].is_boolean(), "got {entry}");
            assert_ne!(entry["supported"], ABOUT_SUPPORTED_YES);
            assert_ne!(entry["supported"], ABOUT_SUPPORTED_NO);
        }
    }

    #[test]
    fn a_filesystem_path_has_no_chain_row() {
        // An empty cell would read as "unknown"; a path simply has no chain.
        let report = AboutReport::new(&local(), None);
        assert!(
            !report
                .rows(Units::Binary)
                .iter()
                .any(|(label, _)| *label == ABOUT_FIELD_CHAIN),
            "a path was given a chain row"
        );
        // The JSON keeps the key, as an empty array — a machine consumer reads
        // the shape once and must not have it change between remotes.
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json[ABOUT_FIELD_CHAIN], serde_json::json!([]));
    }

    #[test]
    fn a_vault_chain_is_rendered_with_the_shared_arrow() {
        let report = AboutReport::new(&vault_over_b2(), None);
        let rendered = report
            .rows(Units::Binary)
            .into_iter()
            .find(|(label, _)| *label == ABOUT_FIELD_CHAIN)
            .map(|(_, value)| value);
        assert_eq!(
            rendered.as_deref(),
            Some(format!("vault{CONFIG_CHAIN_ARROW}b2prod").as_str())
        );
    }

    #[test]
    fn every_format_emits_without_error() {
        for format in ["text", "json", "json-lines"] {
            let ctx = ctx(&["--format", format]);
            assert!(
                AboutReport::new(&vault_over_b2(), Some(measured()))
                    .emit(&ctx)
                    .is_ok(),
                "{format} failed"
            );
        }
    }

    #[test]
    fn the_json_lines_rendering_is_one_line() {
        let report = AboutReport::new(&vault_over_b2(), None);
        let encoded = crate::output::Format::JsonLines
            .encode(&report)
            .expect("the report serialises");
        assert!(!encoded.contains('\n'), "got: {encoded}");
    }

    #[test]
    fn an_allowance_is_reported_as_unknown_with_the_reason_beside_it() {
        // The rule the whole command is built on: no number is better than an
        // invented one, and an invented one gets used to decide whether a backup
        // fits. `null` plus a stated reason is the honest shape.
        let report = AboutReport::new(&vault_over_b2(), Some(measured()));
        let json = serde_json::to_value(&report).unwrap();

        assert_eq!(json[ABOUT_FIELD_TOTAL_BYTES], serde_json::Value::Null);
        assert_eq!(json[ABOUT_FIELD_FREE_BYTES], serde_json::Value::Null);
        assert_ne!(json[ABOUT_FIELD_TOTAL_BYTES], 0);
        // The reason is in the document, not only in the manual.
        let note = json[ABOUT_FIELD_LIMITS_NOTE].as_str().unwrap_or_default();
        assert!(note.contains("Backend"), "got: {note}");
        assert!(note.contains("statvfs"), "got: {note}");

        // And a person reading the table is told the same thing.
        let rows = report.rows(Units::Binary);
        for field in [ABOUT_FIELD_TOTAL_BYTES, ABOUT_FIELD_FREE_BYTES] {
            let value = rows
                .iter()
                .find(|(label, _)| *label == field)
                .map(|(_, value)| value.as_str())
                .unwrap_or_default();
            assert_eq!(value, ABOUT_LIMIT_NOT_REPORTED);
        }
    }

    #[test]
    fn the_measured_figures_carry_the_basis_they_were_measured_on() {
        // A plaintext total and a stored total are both true and not equal; a
        // reader reconciling one against an invoice has to know which they hold.
        let report = AboutReport::new(&vault_over_b2(), Some(measured()));
        let json = serde_json::to_value(&report).unwrap();

        assert_eq!(json[ABOUT_FIELD_OBJECTS], 3);
        assert_eq!(json[ABOUT_FIELD_BYTES], 6150);
        assert_eq!(json[ABOUT_FIELD_SIZES], Sizes::Plaintext.label());

        let rows = report.rows(Units::Binary);
        let bytes = rows
            .iter()
            .find(|(label, _)| *label == ABOUT_FIELD_BYTES)
            .map(|(_, value)| value.clone())
            .unwrap_or_default();
        // Rounded for a person and exact for arithmetic, on one line.
        assert!(bytes.contains("6150 bytes"), "got: {bytes}");
        assert!(bytes.contains("KiB"), "got: {bytes}");
    }

    #[test]
    fn a_capability_only_report_measures_nothing_and_claims_nothing() {
        // `null` here means "not measured". A zero would be read as an empty
        // remote by the same script that reads the sealed figure.
        let report = AboutReport::new(&vault_over_b2(), None);
        let json = serde_json::to_value(&report).unwrap();

        assert_eq!(json[ABOUT_FIELD_OBJECTS], serde_json::Value::Null);
        assert_eq!(json[ABOUT_FIELD_BYTES], serde_json::Value::Null);
        assert_eq!(json[ABOUT_FIELD_SIZES], serde_json::Value::Null);
        // The keys stay present, so a consumer parses one shape.
        assert!(json.get(ABOUT_FIELD_OBJECTS).is_some());
        assert!(
            !report
                .rows(Units::Binary)
                .iter()
                .any(|(label, _)| *label == ABOUT_FIELD_OBJECTS),
            "an unmeasured remote was given a usage row"
        );
    }
}
