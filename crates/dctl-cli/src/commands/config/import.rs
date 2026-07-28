//! `dctl config import LOCATION [--name NAME]` — address a vault that already
//! exists.
//!
//! The recovery path for a configuration that was lost, and the one command in
//! DCTL whose whole job is to write addressing for data somebody else already
//! stored. It reads no secret, unwraps no key, and moves no bytes: it inspects
//! the location, confirms an envelope is there, and writes the same two entries
//! `dctl init` writes.
//!
//! **The data was never at risk.** A vault's envelope lives on its own store
//! (`PLAN.md` §13.1 — objects are self-describing), so losing `config.toml`
//! loses only the names. That is worth stating plainly, because the operator
//! running this command usually believes something much worse has happened.
//!
//! ## Why this is a command and not a detection
//!
//! DCTL could notice an envelope during a copy and quietly start encrypting.
//! It must not, and invariant I4 is the reason: what a command encrypts is
//! determined solely by the **remote name typed**, fixed when the remote was
//! defined. A destination's contents may cause DCTL to *refuse* — that is the
//! fallback this command is the remedy for — but never to change what it does. A
//! tool that switched to encrypting because it found a file would have
//! encryption semantics that changed under a running backup job, and no operator
//! could state, from a script, what that script does.
//!
//! That is the whole difference between this command and auto-detection, and it
//! is a difference in kind rather than in politeness. Auto-detection *changes
//! behaviour*; the refusal only ever *stops*. So the inspection is explicit,
//! deliberate, and produces *configuration* — after which every later command
//! behaves exactly as it would have if `dctl init` had written it, and stops
//! consulting the destination at all.
//!
//! ## Naming
//!
//! `--name` is optional here and required by `dctl init`, and the asymmetry is
//! deliberate. `init` creates something that did not exist, and its name is a
//! permanent choice nobody else can make. `import` is *re*-addressing a store
//! that is already there, and the store's own container — the bucket, the
//! directory — is a name the operator did choose, at creation time, in the
//! provider's console. Defaulting to it re-uses a decision rather than inventing
//! one, and the moment it is not a legal remote name the command asks instead of
//! guessing.

use clap::Args;
use serde::Serialize;

use super::base::BaseLocation;
use super::emit;
use crate::config::{self, VaultPair};
use crate::constants;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::remote::envelope::{self, Verdict};

/// Arguments for `dctl config import`.
#[derive(Args, Debug)]
pub struct ImportArgs {
    /// Location holding the vault, e.g. 'local:/srv/vault' or 'b2:my-bucket'.
    #[arg(value_name = "LOCATION")]
    pub location: String,

    /// Name for the sealed view. Defaults to the container's own name.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// Name for the object store remote. Defaults to '<NAME>-store'.
    #[arg(long, value_name = "NAME")]
    pub store_name: Option<String>,
}

/// What `import` reports having done.
#[derive(Debug, Serialize)]
struct ImportReport {
    /// The sealed view's name: everything through it is encrypted.
    vault_remote: String,
    /// The object view's name: opaque ciphertext, replicable without a password.
    store_remote: String,
    /// The location, as it was typed.
    base: String,
    /// How many unlock slots the envelope declares. Absent when the envelope's
    /// format version is one this build cannot read.
    #[serde(skip_serializing_if = "Option::is_none")]
    slots: Option<u16>,
    /// Whether the configuration now names both remotes. False for a dry run.
    imported: bool,
    dry_run: bool,
}

/// Write the two remotes that address an existing vault.
///
/// # Errors
/// [`ExitCode::Usage`] for a location that names no place, a name that cannot
/// be used, or a name already taken. [`ExitCode::FatalError`] when the location
/// holds no vault envelope, or when it cannot be read at all.
pub async fn run(ctx: &Ctx, args: &ImportArgs) -> Result<()> {
    let location = BaseLocation::parse(&args.location)?;
    location.refuse_subdirectory()?;

    let vault_name = match &args.name {
        Some(chosen) => chosen.clone(),
        None => derive_name(&location)?,
    };
    let store_name = match &args.store_name {
        Some(chosen) => chosen.clone(),
        None => format!("{vault_name}{}", constants::INIT_STORE_NAME_SUFFIX),
    };

    let pair = VaultPair::new(&vault_name, &store_name, location.store.clone(), None)?;

    let path = config::resolve_path(ctx.globals.config.as_deref());
    let mut configured = config::load_or_default(&path)?;

    // Rehearsed against a copy before the store is contacted, so a name
    // collision costs nothing and is reported as a name collision.
    let mut rehearsal = configured.clone();
    pair.apply(&mut rehearsal, ctx.globals.force)?;
    config::validate(&rehearsal)?;

    if ctx.is_dry_run() {
        ctx.dry_run_notice(
            "import the vault at",
            &format!("{} as '{vault_name}'", args.location),
        );
        return report(
            ctx,
            &ImportReport {
                vault_remote: vault_name,
                store_remote: store_name,
                base: args.location.clone(),
                slots: None,
                imported: false,
                dry_run: true,
            },
        );
    }

    let backend = crate::remote::build_backend(&args.location, ctx.globals.links)?;
    let slots = confirm_vault_present(ctx, &args.location, envelope::probe(&backend).await?)?;

    pair.apply(&mut configured, ctx.globals.force)?;
    config::save(&configured, &path)?;

    ctx.out.success(format!(
        "imported the vault at '{}' as '{vault_name}'; its objects are \
         addressable as '{store_name}'",
        args.location
    ));

    report(
        ctx,
        &ImportReport {
            vault_remote: vault_name,
            store_remote: store_name,
            base: args.location.clone(),
            slots,
            imported: true,
            dry_run: false,
        },
    )
}

/// Refuse a location that holds no vault, and report what was found.
///
/// The check that keeps this command honest. Writing addressing for an empty
/// bucket would hand an operator a configuration that looks exactly like a
/// working one and fails at the first unlock — in the command people reach for
/// precisely when something has already gone wrong.
///
/// A [`Verdict::Foreign`] envelope is imported with a warning rather than
/// refused. The *addressing* is correct whatever the format version says, and it
/// is what the operator asked for; being unable to read the envelope is an
/// upgrade problem, and refusing to write two harmless configuration lines would
/// not fix it.
///
/// # Errors
/// [`ExitCode::FatalError`] when no envelope is there.
fn confirm_vault_present(ctx: &Ctx, location: &str, verdict: Verdict) -> Result<Option<u16>> {
    match verdict {
        Verdict::Vault { slots } => Ok(Some(slots)),

        Verdict::Foreign { version } => {
            ctx.out.warn(format!(
                "'{location}' holds a vault of format version {version}, which \
                 this build cannot read. The addressing has been written, but \
                 unlocking it needs a newer DCTL."
            ));
            Ok(None)
        }

        Verdict::Absent => Err(CliError::new(
            ExitCode::FatalError,
            format!("'{location}' does not hold a vault"),
        )
        .with_hint(format!(
            "`dctl config import` addresses a vault that already exists; it \
             looks for the envelope at '{}'. If this is where the vault should \
             be, check that the location and its credentials are the ones the \
             vault was created with. To create a new vault here instead, run \
             `dctl init --name NAME --base {location}`.",
            constants::VAULT_ENVELOPE_OBJECT_KEY
        ))),
    }
}

/// The default name for an imported vault: its container's own name.
///
/// See the module docs on why a default is defensible here and not in
/// `dctl init`. When the container's name is not a legal remote name — a bucket
/// with a dot-leading name, a directory called `x`, a path with no last
/// component — the command asks rather than mangling it into something typeable,
/// because a silently-adjusted name is a name the operator will not recognise in
/// their own configuration.
fn derive_name(location: &BaseLocation) -> Result<String> {
    config::validate_remote_name(&location.container).map_err(|error| {
        CliError::new(
            ExitCode::Usage,
            format!(
                "'{}' does not suggest a usable remote name: {error}",
                location.spec
            ),
        )
        .with_hint(format!(
            "Give one with --name, for example `dctl config import {} --name \
             archive`.",
            location.spec
        ))
    })?;
    Ok(location.container.clone())
}

/// Emit the record in whichever format was asked for.
fn report(ctx: &Ctx, record: &ImportReport) -> Result<()> {
    emit::records(ctx, std::slice::from_ref(record), || {
        emit::pairs(
            constants::CONFIG_COLUMN_NAME,
            constants::CONFIG_COLUMN_TYPE,
            vec![
                (
                    record.vault_remote.clone(),
                    constants::CONFIG_MODE_SEALED.to_string(),
                ),
                (
                    record.store_remote.clone(),
                    constants::CONFIG_MODE_PLAIN.to_string(),
                ),
            ],
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::config::RemoteDef;
    use crate::constants::{VAULT_ENVELOPE_MAGIC, VAULT_ENVELOPE_VERSION};
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

    fn workspace() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        (dir, config)
    }

    /// A directory holding a plausible `DKE1` envelope.
    fn store_with_vault(root: &Path, slots: u16) {
        let system = root.join("system");
        std::fs::create_dir_all(&system).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(VAULT_ENVELOPE_MAGIC);
        bytes.push(VAULT_ENVELOPE_VERSION);
        bytes.extend_from_slice(&[7; 16]);
        bytes.extend_from_slice(&slots.to_le_bytes());
        bytes.extend_from_slice(&[0; 64]); // slot bytes we never read
        std::fs::write(system.join("envelope.bin"), bytes).unwrap();
    }

    fn args(location: &str, name: Option<&str>) -> ImportArgs {
        ImportArgs {
            location: location.to_string(),
            name: name.map(str::to_string),
            store_name: None,
        }
    }

    #[tokio::test]
    async fn a_vault_round_trips_from_init_through_a_lost_configuration() {
        // The recovery story end to end: create a vault, throw the configuration
        // away, and get the same two remotes back by inspecting the store.
        let (dir, config) = workspace();
        let store = dir.path().join("store");
        let index = dir.path().join("vault.redb");
        let base = format!("local:{}", store.display());

        crate::commands::init::run(
            &ctx(
                &config,
                &[
                    "--index",
                    &index.to_string_lossy(),
                    "--password",
                    "correct horse battery staple",
                ],
            ),
            &crate::commands::init::InitArgs {
                legacy_location: None,
                name: Some("archive".into()),
                base: Some(base.clone()),
                store_name: None,
            },
        )
        .await
        .unwrap();

        let original = config::load(&config).unwrap();
        std::fs::remove_file(&config).unwrap();

        run(&ctx(&config, &[]), &args(&base, Some("archive")))
            .await
            .unwrap();

        let recovered = config::load(&config).unwrap();
        assert_eq!(
            recovered, original,
            "import must reproduce exactly what init wrote"
        );
    }

    #[tokio::test]
    async fn the_container_supplies_a_default_name() {
        let (dir, config) = workspace();
        let store = dir.path().join("archive");
        store_with_vault(&store, 2);

        run(
            &ctx(&config, &[]),
            &args(&format!("local:{}", store.display()), None),
        )
        .await
        .unwrap();

        let written = config::load(&config).unwrap();
        assert!(written.get("archive").is_some_and(RemoteDef::is_vault));
        assert!(
            written
                .get("archive-store")
                .is_some_and(RemoteDef::require_vault)
        );
    }

    #[tokio::test]
    async fn a_container_whose_name_cannot_be_a_remote_asks_instead_of_mangling() {
        // A silently-adjusted name is one the operator will not recognise in
        // their own configuration.
        let (dir, config) = workspace();
        // A directory whose name is not a legal remote name. One character is
        // legal now (rclone accepts it), so the case has to be a real one: a
        // name that starts with a dot could never come out of a config file.
        let store = dir.path().join(".vault");
        store_with_vault(&store, 1);

        let error = run(
            &ctx(&config, &[]),
            &args(&format!("local:{}", store.display()), None),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), ExitCode::Usage);
        assert!(
            error.hint().unwrap_or_default().contains("--name"),
            "the remediation must be the flag that fixes it"
        );
        assert!(!config.exists());
    }

    #[tokio::test]
    async fn a_location_with_no_vault_is_refused_rather_than_addressed() {
        // Writing addressing for an empty bucket would produce a configuration
        // that looks correct and fails at the first unlock.
        let (dir, config) = workspace();
        let empty = dir.path().join("nothing-here");
        std::fs::create_dir_all(&empty).unwrap();

        let error = run(
            &ctx(&config, &[]),
            &args(&format!("local:{}", empty.display()), Some("archive")),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(
            error.message().contains("does not hold a vault"),
            "{}",
            error.message()
        );
        // And it must point at the command that would create one.
        assert!(
            error
                .hint()
                .unwrap_or_default()
                .contains("dctl init --name"),
            "got hint: {:?}",
            error.hint()
        );
        assert!(!config.exists(), "nothing may be written");
    }

    #[tokio::test]
    async fn a_file_that_is_not_an_envelope_is_not_a_vault() {
        // Four plausible bytes at the right key are not an envelope; treating
        // one as a vault would write addressing for something unopenable.
        let (dir, config) = workspace();
        let store = dir.path().join("decoy");
        std::fs::create_dir_all(store.join("system")).unwrap();
        std::fs::write(
            store.join("system").join("envelope.bin"),
            b"not a vault at all",
        )
        .unwrap();

        assert!(
            run(
                &ctx(&config, &[]),
                &args(&format!("local:{}", store.display()), Some("archive"))
            )
            .await
            .is_err()
        );
        assert!(!config.exists());
    }

    #[tokio::test]
    async fn a_name_already_taken_is_refused_before_the_store_is_contacted() {
        let (dir, config) = workspace();
        let store = dir.path().join("archive");
        store_with_vault(&store, 1);

        let mut existing = config::Config::default();
        existing.insert(
            "archive",
            RemoteDef::Local(config::LocalDef {
                path: PathBuf::from("/elsewhere"),
                verify: None,
                require_vault: false,
            }),
        );
        config::save(&existing, &config).unwrap();
        let before = std::fs::read(&config).unwrap();

        let error = run(
            &ctx(&config, &[]),
            &args(&format!("local:{}", store.display()), Some("archive")),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), ExitCode::Usage);
        assert_eq!(std::fs::read(&config).unwrap(), before);
    }

    #[tokio::test]
    async fn a_dry_run_contacts_nothing_and_writes_nothing() {
        let (dir, config) = workspace();
        let store = dir.path().join("archive");
        // Deliberately absent: a dry run must not need the store to exist.
        let error_free = run(
            &ctx(&config, &["--dry-run"]),
            &args(&format!("local:{}", store.display()), Some("archive")),
        )
        .await;

        assert!(error_free.is_ok(), "a dry run must not need a real vault");
        assert!(!config.exists());
    }

    #[tokio::test]
    async fn every_format_is_supported() {
        for format in ["text", "json", "json-lines"] {
            let (dir, config) = workspace();
            let store = dir.path().join("archive");
            store_with_vault(&store, 3);
            assert!(
                run(
                    &ctx(&config, &["--format", format]),
                    &args(&format!("local:{}", store.display()), Some("archive"))
                )
                .await
                .is_ok(),
                "{format} failed"
            );
        }
    }

    #[test]
    fn a_dry_run_report_never_claims_the_vault_was_imported() {
        let record = ImportReport {
            vault_remote: "archive".into(),
            store_remote: "archive-store".into(),
            base: "local:/srv/vault".into(),
            slots: None,
            imported: false,
            dry_run: true,
        };
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["imported"], false);
        assert_eq!(json["dry_run"], true);
        assert!(json.get("slots").is_none(), "nothing was inspected");
    }
}
