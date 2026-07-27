//! `dctl config verify` — prove the configuration is sound, from the file alone.
//!
//! The compliance pre-flight. It answers three questions without reading a byte
//! of stored data, without a password, and without touching the network:
//!
//! 1. **Does every remote resolve?** Names that can be typed, settings complete
//!    enough to build a backend from, no two names differing only in case.
//! 2. **Is the remote graph sound?** Every vault chain ends at a remote that
//!    actually stores bytes — no loops, no dangling bases, nothing absurdly
//!    deep.
//! 3. **What does each remote do to the bytes?** `plain` or `sealed`, per
//!    remote, stated outright.
//!
//! That third answer is only possible because of invariant I4: what a remote
//! encrypts is determined solely by the **name**, fixed when the remote was
//! defined. Contents can withhold permission from a command; they cannot change
//! what it does, so `plain` and `sealed` are properties of the file being read
//! here and not of any place it points at. A tool that decided by inspection
//! could not tell you what a command *will* do, only what it would have done a
//! moment ago. This one can put it in a report, before the run, and be right.
//!
//! ## Why it opens files the loader refuses
//!
//! Every other command reads the configuration through [`crate::config::load`],
//! which validates and refuses. That is right for them and useless here: an
//! operator whose file has a dangling base would get the same one-line refusal
//! from `verify` as from `dctl ls`, and still not know what else is wrong. So
//! this one command reads through [`crate::config::load_for_diagnosis`] and
//! applies the rules itself, collecting **every** finding rather than stopping
//! at the first — a pre-flight that reports one problem per run is a pre-flight
//! nobody runs twice.
//!
//! The rules are not re-implemented. Each check calls the same function the
//! loader calls, so `verify` cannot come to a different conclusion about a file
//! than the command that will read it next.

use std::collections::BTreeMap;

use serde::Serialize;

use super::settings;
use crate::config::{self, Config, ConfigError, RemoteDef};
use crate::constants;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::output::{Align, Border, Column, Table};
use crate::remote::resolve::{RemoteEntry, resolve};
use crate::remote::spec::RemoteSpec;

/// One remote, as the pre-flight sees it.
#[derive(Debug, Serialize)]
struct RemoteRow {
    /// The name typed before the `:`.
    name: String,
    /// The provider type, as the file spells it.
    #[serde(rename = "type")]
    kind: &'static str,
    /// `sealed` or `plain` — what this remote does to bytes passing through it.
    mode: &'static str,
    /// The remote at the end of this one's chain: where the bytes really land.
    store: String,
    /// The full chain, sealed view first.
    chain: Vec<String>,
    /// Whether this remote's location is declared vault-only.
    require_vault: bool,
    /// `ok`, or the slug of the first finding against this remote.
    status: &'static str,
}

/// One thing wrong with the configuration.
#[derive(Debug, Serialize)]
struct Finding {
    /// The remote the finding is about; empty for a file-wide one.
    remote: String,
    /// A stable slug — see [`constants::CONFIG_FINDING_UNKNOWN_BASE`].
    finding: &'static str,
    /// The typed error's own message, so the report says what, not just which.
    detail: String,
}

/// The whole pre-flight result.
#[derive(Debug, Serialize)]
struct VerifyReport {
    /// Every configured remote, in the file's own order.
    remotes: Vec<RemoteRow>,
    /// Everything wrong, in the order it was found. Empty when the file is
    /// sound.
    findings: Vec<Finding>,
    /// Whether the configuration is usable as it stands.
    ok: bool,
}

/// Check the configuration and report.
///
/// # Errors
/// [`ExitCode::FatalError`] when the file cannot be read or parsed at all, or
/// when the pre-flight found something. A configuration that is merely empty is
/// sound and exits zero: a machine driven entirely by flags and environment
/// variables never writes one (`PLAN.md` §14).
pub async fn run(ctx: &Ctx) -> Result<()> {
    let path = config::resolve_path(ctx.globals.config.as_deref());

    // `load_or_default` is the wrong door — it validates — and a plain read is
    // the wrong one too, since a missing default config is a fresh install
    // rather than a fault.
    let loaded = match config::load_for_diagnosis(&path) {
        Ok(loaded) => loaded,
        Err(ConfigError::Missing(_)) => Config::default(),
        Err(other) => return Err(other.into()),
    };

    let report = inspect(&loaded);
    emit_report(ctx, &report)?;

    if report.ok {
        ctx.out.success(format!(
            "{} remote(s) in {} verified",
            report.remotes.len(),
            path.display()
        ));
        return Ok(());
    }

    Err(CliError::new(
        ExitCode::FatalError,
        format!("{} problem(s) in {}", report.findings.len(), path.display()),
    )
    .with_hint(
        "Every problem above is reachable from the configuration alone, so all \
         of them can be fixed before any command touches stored data. \
         `dctl config show NAME` prints one remote's settings.",
    ))
}

/// Apply every rule to `config` and collect what they say.
///
/// Pure, and the whole of the command's logic: driven directly by tests, with no
/// filesystem, no terminal and no output involved.
fn inspect(config: &Config) -> VerifyReport {
    let mut findings = Vec::new();

    // A file-wide rule, checked once. It is about a *pair* of remotes, so
    // attributing it to one of them would be arbitrary.
    if let Err(error) = config::vault_only_locations(config) {
        findings.push(Finding {
            remote: String::new(),
            finding: constants::CONFIG_FINDING_PLAIN_AT_VAULT_LOCATION,
            detail: error.to_string(),
        });
    }

    // Two names differing only in case are an ambiguity in every
    // case-insensitive context a name travels through, so the fold is done once
    // and consulted per remote.
    let mut folded: BTreeMap<String, String> = BTreeMap::new();
    let catalog = settings::catalog(config);
    let mut remotes = Vec::with_capacity(config.len());

    for name in config.names() {
        let Some(remote) = config.get(name) else {
            continue;
        };

        // Collected per remote, then folded into the report. A local list rather
        // than pushing straight through keeps "the first finding decides the
        // row's status" in one obvious place.
        let mut against: Vec<(&'static str, String)> = Vec::new();

        if let Err(error) = config::validate_remote_name(name) {
            against.push((constants::CONFIG_FINDING_ILLEGAL_NAME, error.to_string()));
        }

        if let Some(first) = folded.insert(name.to_ascii_lowercase(), name.to_string()) {
            against.push((
                constants::CONFIG_FINDING_CASE_COLLISION,
                ConfigError::DuplicateNameCase {
                    first,
                    second: name.to_string(),
                }
                .to_string(),
            ));
        }

        // The chain is what proves there is a remote at the end of this one that
        // actually stores bytes, and producing it is the only honest way to show
        // there is no cycle.
        let chain = match config::vault_chain(config, name) {
            Ok(chain) => chain.into_iter().map(str::to_string).collect::<Vec<_>>(),
            Err(error) => {
                against.push((chain_slug(&error), error.to_string()));
                Vec::new()
            }
        };

        // Only the terminal link is resolved: a vault remote stores nothing, so
        // asking the registry to build one is a question with no answer.
        let store = chain.last().cloned().unwrap_or_default();
        if !store.is_empty()
            && let Err(error) = resolve_terminal(&catalog, &store)
        {
            against.push((
                constants::CONFIG_FINDING_INCOMPLETE_SETTINGS,
                error.message().to_string(),
            ));
        }

        let status = against
            .first()
            .map_or(constants::CONFIG_VERIFY_STATUS_OK, |(slug, _)| *slug);
        findings.extend(against.into_iter().map(|(slug, detail)| Finding {
            remote: name.to_string(),
            finding: slug,
            detail,
        }));

        remotes.push(RemoteRow {
            name: name.to_string(),
            kind: remote.type_name(),
            mode: mode_of(remote),
            store,
            chain,
            require_vault: remote.require_vault(),
            status,
        });
    }

    VerifyReport {
        ok: findings.is_empty(),
        remotes,
        findings,
    }
}

/// The word for what a remote does to bytes passing through it.
///
/// Invariant I4 in one function: it reads the remote's *definition* and nothing
/// else — not the destination, not its contents, not whether an envelope happens
/// to be there.
const fn mode_of(remote: &RemoteDef) -> &'static str {
    if remote.is_vault() {
        constants::CONFIG_MODE_SEALED
    } else {
        constants::CONFIG_MODE_PLAIN
    }
}

/// Which slug a chain failure reports as.
const fn chain_slug(error: &ConfigError) -> &'static str {
    match error {
        ConfigError::VaultCycle { .. } => constants::CONFIG_FINDING_CHAIN_CYCLE,
        ConfigError::ChainTooDeep { .. } => constants::CONFIG_FINDING_CHAIN_TOO_DEEP,
        // `UnknownRemote` cannot occur here — the name came from the file — so
        // everything else a chain walk produces is a base that is not there.
        _ => constants::CONFIG_FINDING_UNKNOWN_BASE,
    }
}

// The configuration is turned into the resolver's vocabulary by
// [`settings::catalog`] rather than here. `dctl replicate` needs the same
// translation to resolve a store remote, and two flattenings of one file are two
// answers to "which bucket does this remote name" waiting to diverge.

/// Prove a terminal remote has the settings its provider cannot work without.
///
/// Resolution only — never [`crate::remote::registry::build`], which reads
/// credentials from the environment and opens connections. A pre-flight that
/// demanded credentials could not be run by the person auditing the file.
fn resolve_terminal(catalog: &BTreeMap<String, RemoteEntry>, name: &str) -> Result<()> {
    let spec = RemoteSpec::Named {
        remote: name.to_string(),
        path: String::new(),
    };
    resolve(&spec, catalog)?;
    Ok(())
}

/// Write the report in whichever format was asked for.
///
/// JSON gets one document carrying both lists, because a consumer deciding
/// whether to fail a release needs the findings and the modes together. Text
/// gets the table on stdout — it is the result — and the findings on stderr,
/// where a warning belongs and cannot pollute a pipeline.
fn emit_report(ctx: &Ctx, report: &VerifyReport) -> Result<()> {
    if ctx.out.format().is_json() {
        ctx.out.json(report)?;
        return Ok(());
    }

    if !report.remotes.is_empty() {
        let mut table = Table::new(vec![
            Column::new(constants::CONFIG_COLUMN_NAME, Align::Left),
            Column::new(constants::CONFIG_COLUMN_TYPE, Align::Left),
            Column::new(constants::CONFIG_COLUMN_MODE, Align::Left),
            Column::new(constants::CONFIG_COLUMN_STORE, Align::Left),
            Column::new(constants::CONFIG_COLUMN_STATUS, Align::Left),
        ])
        .with_border(Border::None);

        for row in &report.remotes {
            table.push(vec![
                row.name.clone(),
                row.kind.to_string(),
                row.mode.to_string(),
                if row.store.is_empty() {
                    constants::UNKNOWN_VALUE.to_string()
                } else {
                    row.store.clone()
                },
                row.status.to_string(),
            ]);
        }
        ctx.out.table(&table)?;
    }

    for finding in &report.findings {
        ctx.out
            .error(format!("{}: {}", finding.finding, finding.detail));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::config::{B2Def, LocalDef, RemoteDef, VaultDef};
    use clap::Parser;
    use std::path::{Path, PathBuf};

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(config: &Path, extra: &[&str]) -> Ctx {
        let mut args = vec![
            "dctl".to_string(),
            "--config".to_string(),
            config.to_string_lossy().into_owned(),
        ];
        args.extend(extra.iter().map(|a| (*a).to_string()));
        Ctx::new(Harness::parse_from(args).globals)
    }

    fn store(path: &str, require_vault: bool) -> RemoteDef {
        RemoteDef::Local(LocalDef {
            path: PathBuf::from(path),
            verify: None,
            require_vault,
        })
    }

    fn vault(base: &str) -> RemoteDef {
        RemoteDef::Vault(VaultDef {
            base: base.to_string(),
            base_path: None,
            chunk_size: None,
            verify: None,
        })
    }

    fn sound() -> Config {
        let mut config = Config::default();
        config.insert("archive-store", store("/srv/vault", true));
        config.insert("archive", vault("archive-store"));
        config
    }

    #[test]
    fn a_sound_configuration_reports_every_remote_and_no_findings() {
        let report = inspect(&sound());
        assert!(report.ok);
        assert!(report.findings.is_empty());
        assert_eq!(report.remotes.len(), 2);
        for row in &report.remotes {
            assert_eq!(row.status, constants::CONFIG_VERIFY_STATUS_OK);
        }
    }

    #[test]
    fn each_remote_is_reported_as_plain_or_sealed() {
        // The answer only possible because what a remote encrypts follows the
        // name typed; contents can refuse a command but never change what it
        // does (invariant I4), so this column is never contingent.
        let report = inspect(&sound());
        let modes: BTreeMap<&str, &str> = report
            .remotes
            .iter()
            .map(|row| (row.name.as_str(), row.mode))
            .collect();
        assert_eq!(modes.get("archive"), Some(&constants::CONFIG_MODE_SEALED));
        assert_eq!(
            modes.get("archive-store"),
            Some(&constants::CONFIG_MODE_PLAIN)
        );
    }

    #[test]
    fn every_remote_names_the_store_its_bytes_really_land_in() {
        let report = inspect(&sound());
        for row in &report.remotes {
            assert_eq!(
                row.store, "archive-store",
                "'{}' must resolve to the remote that stores bytes",
                row.name
            );
        }
        let sealed = report
            .remotes
            .iter()
            .find(|row| row.name == "archive")
            .expect("the vault remote");
        assert_eq!(sealed.chain, ["archive", "archive-store"]);
    }

    #[test]
    fn a_dangling_base_is_caught_and_named() {
        // The finding this command exists for: a vault remote pointing at a
        // store that is not in the file. Every other command answers this with a
        // refusal to open the file at all.
        let mut config = Config::default();
        config.insert("archive", vault("gone"));

        let report = inspect(&config);
        assert!(!report.ok);
        let finding = report.findings.first().expect("a finding");
        assert_eq!(finding.finding, constants::CONFIG_FINDING_UNKNOWN_BASE);
        assert_eq!(finding.remote, "archive");
        assert!(finding.detail.contains("gone"), "got: {}", finding.detail);

        // And the row still appears, marked, rather than vanishing from the
        // report: an operator counting remotes must see all of them.
        let row = report.remotes.first().expect("a row");
        assert_eq!(row.status, constants::CONFIG_FINDING_UNKNOWN_BASE);
        assert!(row.store.is_empty());
    }

    #[test]
    fn a_cycle_and_a_dangling_base_are_told_apart() {
        let mut config = Config::default();
        config.insert("one", vault("two"));
        config.insert("two", vault("one"));

        let report = inspect(&config);
        assert!(!report.ok);
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.finding == constants::CONFIG_FINDING_CHAIN_CYCLE),
            "got: {:?}",
            report.findings
        );
    }

    #[test]
    fn a_remote_missing_a_required_setting_is_reported_without_credentials() {
        // Resolution only, never a backend build: an auditor reading the file
        // must not need the provider's keys to run the pre-flight.
        let mut config = Config::default();
        config.insert(
            "b2prod",
            RemoteDef::B2(B2Def {
                bucket: String::new(),
                endpoint: None,
                chunk_size: None,
                verify: None,
                require_vault: false,
            }),
        );

        let report = inspect(&config);
        assert!(!report.ok);
        assert_eq!(
            report.findings.first().map(|finding| finding.finding),
            Some(constants::CONFIG_FINDING_INCOMPLETE_SETTINGS)
        );
    }

    #[test]
    fn a_plain_remote_at_a_vault_store_is_a_file_wide_finding() {
        let mut config = sound();
        config.insert("scratch", store("/srv/vault", false));

        let report = inspect(&config);
        assert!(!report.ok);
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.finding == constants::CONFIG_FINDING_PLAIN_AT_VAULT_LOCATION)
            .expect("the location rule must fire");
        assert!(
            finding.remote.is_empty(),
            "the fault is a pair of remotes, so it belongs to neither"
        );
        assert!(
            finding.detail.contains("scratch"),
            "got: {}",
            finding.detail
        );
    }

    #[test]
    fn every_problem_is_reported_rather_than_only_the_first() {
        // A pre-flight that stops at one problem is a pre-flight run once per
        // problem, which is the opposite of what it is for.
        let mut config = Config::default();
        config.insert("archive", vault("gone"));
        config.insert("backup", vault("also-gone"));

        let report = inspect(&config);
        assert_eq!(report.findings.len(), 2, "got: {:?}", report.findings);
    }

    #[test]
    fn an_empty_configuration_is_sound() {
        // A machine driven entirely by flags and environment variables never
        // writes a config, and that must not be reported as a compliance
        // failure.
        let report = inspect(&Config::default());
        assert!(report.ok);
        assert!(report.remotes.is_empty());
    }

    #[tokio::test]
    async fn a_broken_file_is_reported_rather_than_refused() {
        // The reason this command reads through the diagnostic door: every other
        // command answers a dangling base by refusing to open the file, which
        // tells an operator nothing about the rest of it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[remotes.archive]\ntype = \"vault\"\nbase = \"gone\"\n\
             [remotes.disk]\ntype = \"local\"\npath = \"/srv\"\n",
        )
        .unwrap();

        // The strict door refuses outright.
        assert!(config::load(&path).is_err());

        let error = run(&ctx(&path, &[])).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("problem"), "{}", error.message());
    }

    #[tokio::test]
    async fn a_sound_file_verifies_in_every_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        config::save(&sound(), &path).unwrap();

        for format in ["text", "json", "json-lines"] {
            assert!(
                run(&ctx(&path, &["--format", format])).await.is_ok(),
                "{format} failed"
            );
        }
    }

    #[tokio::test]
    async fn a_missing_configuration_file_is_not_a_compliance_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.toml");
        assert!(run(&ctx(&path, &[])).await.is_ok());
    }

    #[tokio::test]
    async fn a_credential_in_the_file_is_still_refused_by_the_pre_flight() {
        // Leniency is only ever about the remote graph. A key sitting in the
        // file is not a finding to report politely (PLAN.md §14).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[remotes.b2prod]\ntype = \"b2\"\nbucket = \"x\"\napp_key = \"K00…\"\n",
        )
        .unwrap();

        let error = run(&ctx(&path, &[])).await.unwrap_err();
        assert!(error.message().contains("app_key"), "{}", error.message());
    }

    #[test]
    fn the_report_serialises_with_stable_field_names() {
        let json = serde_json::to_value(inspect(&sound())).unwrap();
        assert_eq!(json["ok"], true);
        assert!(json["remotes"].is_array());
        assert!(json["findings"].is_array());
        assert_eq!(json["remotes"][0]["name"], "archive");
        assert_eq!(json["remotes"][0]["mode"], constants::CONFIG_MODE_SEALED);
    }
}
