//! What `dctl about --capabilities` prints.
//!
//! Two tables in text, one document in JSON, and the same facts in both. The
//! summary says which remote was addressed and what is really on the far end of
//! it; the matrix says what that provider's backend can do. Both go to
//! **stdout**, because they are the command's result (`PLAN.md` §7), and
//! `dctl about --capabilities vault: --json | jq '.storage_provider'` is a
//! working pipeline.
//!
//! The `capabilities` array carries a real boolean per row rather than the
//! `yes`/`no` words the text table shows: a machine consumer must never have to
//! parse a human rendering, and a script that branched on the string would break
//! the first time somebody translated it.

use serde::Serialize;

use crate::constants::{
    ABOUT_CAPABILITIES_NOTICE, ABOUT_COLUMN_CAPABILITY, ABOUT_COLUMN_DESCRIPTION,
    ABOUT_COLUMN_SETTING, ABOUT_COLUMN_SUPPORTED, ABOUT_COLUMN_VALUE, ABOUT_FIELD_CHAIN,
    ABOUT_FIELD_ENCRYPTED, ABOUT_FIELD_PROVIDER, ABOUT_FIELD_REMOTE, ABOUT_FIELD_STORAGE_PROVIDER,
    CONFIG_CHAIN_ARROW,
};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::{Align, Border, Column, Table};

use super::capabilities::{self, Capability};
use super::target::Described;

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
    /// Every capability, supported or not. See
    /// [`super::capabilities::for_provider`] for why the unsupported rows are
    /// included.
    pub capabilities: Vec<Capability>,
}

impl AboutReport {
    /// Build the record for a resolved remote.
    #[must_use]
    pub fn new(described: &Described) -> Self {
        Self {
            remote: described.remote.clone(),
            provider: described.provider,
            storage_provider: described.storage_provider,
            encrypted: described.encrypted,
            chain: described.chain.clone(),
            capabilities: capabilities::for_provider(described.storage_provider),
        }
    }

    /// The rows of the summary table, in the order a person reads them: what was
    /// addressed, what it is, what is really behind it, and whether it is
    /// encrypted on the way through.
    ///
    /// The chain row is omitted for a filesystem path, which is not a named
    /// remote and therefore has no chain — an empty cell there would read as a
    /// missing value rather than an inapplicable one.
    pub fn rows(&self) -> Vec<(&'static str, String)> {
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
        rows
    }

    /// Write the report to stdout in the active format.
    ///
    /// # Errors
    /// Any stdout failure other than a broken pipe, which
    /// [`crate::output::Out`] deliberately tolerates.
    pub fn emit(&self, ctx: &Ctx) -> Result<()> {
        // Said on stderr, so it can never corrupt a pipe, and at -v so the
        // default output stays clean: these rows describe the backend in this
        // binary, not an answer from the provider.
        ctx.out.info(ABOUT_CAPABILITIES_NOTICE);

        if ctx.out.format().is_json() {
            ctx.out.json(self)?;
            return Ok(());
        }

        ctx.out.table(&self.summary_table())?;
        // A blank line between two tables, so the second reads as a second table
        // rather than as more rows of the first.
        ctx.out.line("")?;
        ctx.out.table(&self.capability_table())?;
        Ok(())
    }

    /// The remote summary, borderless so it stays greppable.
    fn summary_table(&self) -> Table {
        let mut table = Table::new(vec![
            Column::new(ABOUT_COLUMN_SETTING, Align::Left),
            Column::new(ABOUT_COLUMN_VALUE, Align::Left),
        ])
        .with_border(Border::None);
        for (label, value) in self.rows() {
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
            remote: "/srv/data".into(),
            provider: PROVIDER_LOCAL,
            storage_provider: PROVIDER_LOCAL,
            encrypted: false,
            chain: Vec::new(),
        }
    }

    fn vault_over_b2() -> Described {
        Described {
            remote: "vault:2024".into(),
            provider: PROVIDER_VAULT,
            storage_provider: PROVIDER_B2,
            encrypted: true,
            chain: vec!["vault".into(), "b2prod".into()],
        }
    }

    #[test]
    fn text_row_labels_are_the_json_field_names() {
        let report = AboutReport::new(&vault_over_b2());
        let json = serde_json::to_value(&report).unwrap();
        for (label, _) in report.rows() {
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
        let report = AboutReport::new(&vault_over_b2());
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
            let report = AboutReport::new(&described);
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
        let report = AboutReport::new(&local());
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
        let report = AboutReport::new(&local());
        assert!(
            !report
                .rows()
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
        let report = AboutReport::new(&vault_over_b2());
        let rendered = report
            .rows()
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
                AboutReport::new(&vault_over_b2()).emit(&ctx).is_ok(),
                "{format} failed"
            );
        }
    }

    #[test]
    fn the_json_lines_rendering_is_one_line() {
        let report = AboutReport::new(&vault_over_b2());
        let encoded = crate::output::Format::JsonLines
            .encode(&report)
            .expect("the report serialises");
        assert!(!encoded.contains('\n'), "got: {encoded}");
    }
}
