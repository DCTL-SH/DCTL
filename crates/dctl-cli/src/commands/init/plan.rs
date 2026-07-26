//! What `dctl init` is about to do, worked out before anything is touched.
//!
//! Splitting the decision from the action buys two things the command needs.
//! `--dry-run` gets something real to print rather than a hand-written guess at
//! what the action *would* have done, and every rule about which names, base
//! specs and index paths are acceptable becomes testable without a network, a
//! password, or a backend.
//!
//! Nothing in this file writes: [`InitPlan::resolve`] reads flags and `stat`s
//! the index path, and [`InitPlan::preflight`] answers "would the configuration
//! this run produces be a valid one?" against a **copy**. Creating directories
//! and saving the file are the caller's job, after the dry-run gate.
//!
//! ## Why the configuration is rehearsed here
//!
//! Saving already validates — [`crate::config::save`] refuses to write a file
//! that could not be loaded again. But `dctl init` writes the configuration
//! *after* it has created a vault, and a name collision discovered at that point
//! would leave a real vault on a real store with no way to address it. So the
//! whole consequence of the run is rehearsed first, against a clone of the
//! loaded configuration: both names free, no plain remote already sitting on the
//! store's location, no chain that would not resolve. If the rehearsal fails,
//! nothing has been created and the message is about a name, not a recovery.

use std::path::PathBuf;

use serde::Serialize;

use crate::commands::config::base::BaseLocation;
use crate::config::{self, Config, VaultPair};
use crate::constants;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

/// The resolved intent of one `dctl init` invocation.
#[derive(Debug, Serialize)]
pub struct InitPlan {
    /// Name of the sealed view — everything addressed through it is encrypted.
    pub vault_name: String,

    /// Name of the object view — the opaque ciphertext objects.
    ///
    /// Named rather than anonymous so an offsite replication job can be
    /// addressed at it and run with no vault password at all (`PLAN.md` §13.3).
    pub store_name: String,

    /// The base spec exactly as it was typed, for reports and messages.
    pub base: String,

    /// Local encrypted index database this vault will use.
    pub index: PathBuf,

    /// Whether an index database is already sitting at [`InitPlan::index`].
    pub index_exists: bool,

    /// The configuration file this run will write to.
    pub config_path: PathBuf,

    /// The two entries that will be written, in one save.
    #[serde(skip)]
    pub pair: VaultPair,
}

impl InitPlan {
    /// Work out what would be initialised, without touching anything.
    ///
    /// # Errors
    /// [`ExitCode::Usage`] when the old positional form was used, when `--name`
    /// is missing, when no base was given anywhere, or when the base does not
    /// name a location this build can put a vault in. Any naming rule
    /// [`crate::config::validate_remote_name`] enforces, for either name.
    pub fn resolve(ctx: &Ctx, args: &super::InitArgs) -> Result<Self> {
        refuse_positional_form(args)?;

        let vault_name = args.name.clone().ok_or_else(missing_name)?;

        // `--remote` remains a fallback so a headless deployment that already
        // exports DCTL_REMOTE keeps working; the *name*, which is a permanent
        // choice, has no fallback at all.
        let base_spec = args
            .base
            .clone()
            .or_else(|| ctx.globals.remote.clone())
            .ok_or_else(missing_base)?;

        let location = BaseLocation::parse(&base_spec)?;
        location.refuse_subdirectory()?;

        let store_name = match &args.store_name {
            Some(chosen) => chosen.clone(),
            None => format!("{vault_name}{}", constants::INIT_STORE_NAME_SUFFIX),
        };

        // `base_path` is `None` because the subdirectory form is refused above.
        // Passing the location's own value would write addressing this build
        // cannot honour.
        let pair = VaultPair::new(&vault_name, &store_name, location.store.clone(), None)?;

        let index = resolve_index_path(ctx);
        let index_exists = index.exists();

        Ok(Self {
            vault_name,
            store_name,
            base: base_spec,
            index,
            index_exists,
            config_path: config::resolve_path(ctx.globals.config.as_deref()),
            pair,
        })
    }

    /// Refuse to run when initialising would destroy or misaddress something.
    ///
    /// Two checks, both answerable without contacting the store:
    ///
    /// * **The local index** is a file DCTL can `stat`, so an existing one is a
    ///   hard refusal without `--force`. Re-initialising over it writes records
    ///   under a new root key and leaves the old ones unreadable.
    /// * **The configuration this run would produce** is assembled against a
    ///   clone and validated. A name already taken, or a plain remote already
    ///   pointing at the store's location, is reported now — while nothing has
    ///   been created — instead of after a vault exists.
    ///
    /// The third thing that could be clobbered, an envelope already on the
    /// store, is not visible from here: it needs a backend and credentials. The
    /// command probes for it separately, and refuses on the same terms.
    ///
    /// # Errors
    /// [`ExitCode::FatalError`] when an index already exists and `--force` was
    /// not given, and whatever [`crate::config::validate`] or
    /// [`VaultPair::apply`] classify their failures as.
    pub fn preflight(&self, ctx: &Ctx, config: &Config) -> Result<()> {
        if self.index_exists && !ctx.globals.force {
            return Err(CliError::new(
                ExitCode::FatalError,
                format!(
                    "refusing to initialise: an index already exists at {}",
                    self.index.display()
                ),
            )
            .with_hint(
                "That index belongs to a vault. Re-initialising generates a new \
                 root key and makes everything already stored unreadable. Point \
                 --index somewhere else, or pass --force if you are certain.",
            ));
        }

        // The whole consequence, rehearsed. A clone rather than the real value,
        // so a failure here cannot leave a half-built configuration behind for
        // the caller to notice or forget to discard.
        let mut rehearsal = config.clone();
        self.pair.apply(&mut rehearsal, ctx.globals.force)?;
        config::validate(&rehearsal)?;
        Ok(())
    }

    /// Write both entries into `config`, ready for a single save.
    ///
    /// # Errors
    /// [`crate::config::ConfigError::NameTaken`] for either name when `force` is
    /// not set. Already reported by [`InitPlan::preflight`], and re-checked here
    /// because this is the call that actually mutates: a guard that only ran in
    /// the rehearsal is a guard a refactor can drop without failing a test.
    pub fn register(&self, config: &mut Config, force: bool) -> Result<()> {
        self.pair.apply(config, force)?;
        Ok(())
    }

    /// Create the directory the index will live in.
    ///
    /// Separate from [`InitPlan::resolve`] because it is the first thing in the
    /// command that writes, and therefore the first thing `--dry-run` must skip.
    ///
    /// # Errors
    /// Any filesystem failure, classified by
    /// [`From<std::io::Error>`](crate::error::CliError).
    pub fn ensure_index_directory(&self) -> Result<()> {
        if let Some(parent) = self.index.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        Ok(())
    }
}

/// Refuse `dctl init LOCATION`, naming the command that replaces it.
///
/// The old form took a location and nothing else, which meant nobody chose how
/// the vault would be addressed — and every later command had to spell the
/// location out again. The new form requires a name.
///
/// The message carries the **exact replacement command**, built from what the
/// user typed, so it can be copy-pasted with one edit. The one thing it does not
/// do is guess: `NAME` stays a placeholder, because a name invented here would
/// appear in every future command and in every script written against it, and
/// nobody would have chosen it.
fn refuse_positional_form(args: &super::InitArgs) -> Result<()> {
    let Some(spec) = &args.legacy_location else {
        return Ok(());
    };

    Err(CliError::new(
        ExitCode::Usage,
        format!("`dctl init {spec}` no longer names a vault"),
    )
    .with_hint(format!(
        "A vault now has two remotes: the sealed view you write through, and the \
         object store that holds its ciphertext. Both get names, and the name is \
         yours to choose. Run:\n\n    dctl init --name NAME --base {spec}\n\n\
         replacing NAME with what you want to type on every later command; the \
         store is then called NAME{}.",
        constants::INIT_STORE_NAME_SUFFIX
    )))
}

/// The failure for a run with no `--name`.
///
/// Its own function so the reasoning is stated once, where it is enforced. A
/// generated name would be a name nobody chose appearing in every future command
/// and in every script written against it, and unlike a bucket it cannot be
/// changed later without editing every one of them. So there is no default — and
/// clap does not mark the flag required either, because that would make the old
/// positional form fail with clap's generic "the following required arguments
/// were not provided" instead of the message that says exactly what to run.
fn missing_name() -> CliError {
    CliError::new(ExitCode::Usage, "no --name given for the vault").with_hint(format!(
        "Choose the name you will type on every later command, for example \
         `--name archive`. DCTL will not invent one: it would appear in every \
         script written against this vault, and nobody would have picked it. \
         The object store is named after it ('archive{}') unless --store-name \
         says otherwise.",
        constants::INIT_STORE_NAME_SUFFIX
    ))
}

/// The failure for a run with no `--base` and no `--remote`.
fn missing_base() -> CliError {
    CliError::new(ExitCode::Usage, "no --base given for the vault").with_hint(format!(
        "Name the place the ciphertext objects go, for example \
         `--base local:/srv/vault` or `--base b2:my-bucket`. A default remote \
         set with --remote or {} is used when --base is absent.",
        dctl_meta::env_var(constants::ENV_REMOTE)
    ))
}

/// Where the index database lives: `--index` if given, otherwise the platform
/// data directory.
///
/// Reads `ctx.globals` rather than the environment because `DCTL_INDEX` has
/// already been folded into the flag by clap — resolving it twice is how the
/// flag and the variable start disagreeing.
fn resolve_index_path(ctx: &Ctx) -> PathBuf {
    ctx.globals
        .index
        .clone()
        .unwrap_or_else(|| dctl_meta::paths::data_dir().join(constants::INDEX_FILE_NAME))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::commands::init::InitArgs;
    use crate::config::{B2Def, LocalDef, RemoteDef};
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

    fn args(name: Option<&str>, base: Option<&str>) -> InitArgs {
        InitArgs {
            legacy_location: None,
            name: name.map(str::to_string),
            base: base.map(str::to_string),
            store_name: None,
        }
    }

    fn plan(ctx: &Ctx, name: &str, base: &str) -> InitPlan {
        InitPlan::resolve(ctx, &args(Some(name), Some(base))).expect("a legal plan")
    }

    fn unrelated_bucket() -> RemoteDef {
        RemoteDef::B2(B2Def {
            bucket: "unrelated".into(),
            endpoint: None,
            chunk_size: None,
            verify: None,
            require_vault: false,
        })
    }

    fn local_at(path: &str) -> RemoteDef {
        RemoteDef::Local(LocalDef {
            path: PathBuf::from(path),
            verify: None,
            require_vault: false,
        })
    }

    #[test]
    fn a_plan_names_both_views_of_the_vault() {
        let ctx = ctx(&["--index", "/tmp/dctl-test.redb"]);
        let plan = plan(&ctx, "archive", "local:/srv/vault");
        assert_eq!(plan.vault_name, "archive");
        assert_eq!(plan.store_name, "archive-store");
        assert_eq!(plan.base, "local:/srv/vault");
        assert_eq!(plan.pair.vault.base(), Some("archive-store"));
        assert!(plan.pair.store.require_vault());
    }

    #[test]
    fn the_store_name_can_be_chosen_outright() {
        let ctx = ctx(&["--index", "/tmp/dctl-test.redb"]);
        let mut raw = args(Some("archive"), Some("local:/srv/vault"));
        raw.store_name = Some("cold-objects".into());
        let plan = InitPlan::resolve(&ctx, &raw).expect("a legal plan");
        assert_eq!(plan.store_name, "cold-objects");
        assert_eq!(plan.pair.vault.base(), Some("cold-objects"));
    }

    #[test]
    fn the_old_positional_form_says_exactly_what_to_run() {
        // The whole point of the refusal: a copy-pasteable command carrying the
        // location the user already typed, and a placeholder where the name goes
        // — never a guess.
        let ctx = ctx(&[]);
        let raw = InitArgs {
            legacy_location: Some("local:/srv/vault".into()),
            name: None,
            base: None,
            store_name: None,
        };
        let error = InitPlan::resolve(&ctx, &raw).expect_err("must be refused");
        assert_eq!(error.code(), ExitCode::Usage);

        let hint = error.hint().unwrap_or_default();
        assert!(
            hint.contains("dctl init --name NAME --base local:/srv/vault"),
            "the replacement command must be copy-pasteable: {hint}"
        );
        assert!(
            hint.contains("NAME"),
            "the name must stay a placeholder: {hint}"
        );
    }

    #[test]
    fn the_old_form_is_refused_even_when_the_new_flags_are_also_present() {
        // Otherwise a half-ported command would silently ignore the positional
        // and initialise somewhere the user also named.
        let ctx = ctx(&[]);
        let raw = InitArgs {
            legacy_location: Some("local:/elsewhere".into()),
            name: Some("archive".into()),
            base: Some("local:/srv/vault".into()),
            store_name: None,
        };
        assert!(InitPlan::resolve(&ctx, &raw).is_err());
    }

    #[test]
    fn a_missing_name_explains_why_there_is_no_default() {
        let ctx = ctx(&[]);
        let error =
            InitPlan::resolve(&ctx, &args(None, Some("local:/srv/vault"))).expect_err("refused");
        assert_eq!(error.code(), ExitCode::Usage);
        let hint = error.hint().unwrap_or_default();
        assert!(hint.contains("--name archive"), "got hint: {hint}");
        assert!(
            hint.contains("store"),
            "the derived store name must be shown"
        );
    }

    #[test]
    fn a_missing_base_names_the_environment_variable_that_would_supply_one() {
        let ctx = ctx(&[]);
        let error = InitPlan::resolve(&ctx, &args(Some("archive"), None)).expect_err("refused");
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(
            error.hint().unwrap_or_default().contains("DCTL_REMOTE"),
            "the headless path has to stay discoverable"
        );
    }

    #[test]
    fn the_default_remote_still_supplies_a_base() {
        // The headless deployment that exports DCTL_REMOTE once keeps working;
        // only the name became mandatory.
        let ctx = ctx(&["--remote", "b2:media", "--index", "/tmp/dctl-test.redb"]);
        let plan = InitPlan::resolve(&ctx, &args(Some("archive"), None)).expect("a legal plan");
        assert_eq!(plan.base, "b2:media");
    }

    #[test]
    fn an_unusable_name_is_refused_before_anything_happens() {
        let ctx = ctx(&["--index", "/tmp/dctl-test.redb"]);
        for name in ["c", "b2", "my remote"] {
            assert!(
                InitPlan::resolve(&ctx, &args(Some(name), Some("local:/srv/vault"))).is_err(),
                "'{name}' was accepted"
            );
        }
    }

    #[test]
    fn a_base_in_a_subdirectory_is_refused_rather_than_misaddressed() {
        let ctx = ctx(&["--index", "/tmp/dctl-test.redb"]);
        let error = InitPlan::resolve(&ctx, &args(Some("archive"), Some("s3:bucket/vaults/a")))
            .expect_err("must be refused");
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.message().contains("vaults/a"), "{}", error.message());
    }

    #[test]
    fn a_name_already_in_use_is_refused_by_the_rehearsal() {
        // Discovering this after the vault exists would leave a real vault on a
        // real store with no way to address it, so it is discovered before.
        let dir = tempfile::tempdir().unwrap();
        let index = dir.path().join("vault.redb");
        let ctx = ctx(&["--index", &index.to_string_lossy()]);
        let plan = plan(&ctx, "archive", "local:/srv/vault");
        assert!(plan.preflight(&ctx, &Config::default()).is_ok());

        for taken in ["archive", "archive-store"] {
            let mut config = Config::default();
            config.insert(taken, unrelated_bucket());
            let error = plan
                .preflight(&ctx, &config)
                .expect_err("the taken name must be refused");
            assert_eq!(error.code(), ExitCode::Usage, "'{taken}'");
            assert!(error.message().contains(taken), "{}", error.message());
        }
    }

    #[test]
    fn a_plain_remote_already_on_the_store_is_refused_by_the_rehearsal() {
        // The `require_vault` rule reached through init: the store this run
        // would create declares the location vault-only, and an existing plain
        // remote there is exactly what that declaration forbids.
        let dir = tempfile::tempdir().unwrap();
        let index = dir.path().join("vault.redb");
        let ctx = ctx(&["--index", &index.to_string_lossy()]);
        let plan = plan(&ctx, "archive", "local:/srv/vault");

        let mut config = Config::default();
        config.insert("scratch", local_at("/srv/vault"));
        let error = plan.preflight(&ctx, &config).expect_err("must be refused");
        assert!(error.message().contains("scratch"), "{}", error.message());
    }

    #[test]
    fn an_existing_index_blocks_initialisation_until_forced() {
        let dir = tempfile::tempdir().unwrap();
        let index = dir.path().join("vault.redb");
        std::fs::write(&index, b"pretend index").unwrap();
        let index = index.to_string_lossy().to_string();

        let guarded = ctx(&["--index", &index]);
        let guarded_plan = plan(&guarded, "archive", "local:/srv/vault");
        assert!(guarded_plan.index_exists);

        let error = guarded_plan
            .preflight(&guarded, &Config::default())
            .expect_err("must be refused");
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.hint().is_some());

        let forced = ctx(&["--index", &index, "--force"]);
        let forced_plan = plan(&forced, "archive", "local:/srv/vault");
        assert!(forced_plan.preflight(&forced, &Config::default()).is_ok());
    }

    #[test]
    fn a_fresh_index_path_passes_preflight_and_its_parent_is_made_on_demand() {
        let dir = tempfile::tempdir().unwrap();
        let index = dir.path().join("nested").join("vault.redb");
        let ctx = ctx(&["--index", &index.to_string_lossy()]);
        let plan = plan(&ctx, "archive", "local:/srv/vault");
        assert!(!plan.index_exists);
        assert!(plan.preflight(&ctx, &Config::default()).is_ok());

        assert!(!index.parent().unwrap().exists());
        plan.ensure_index_directory().unwrap();
        assert!(index.parent().unwrap().exists());
    }

    #[test]
    fn registering_writes_both_entries_and_nothing_else() {
        let ctx = ctx(&["--index", "/tmp/dctl-test.redb"]);
        let plan = plan(&ctx, "archive", "local:/srv/vault");
        let mut config = Config::default();
        plan.register(&mut config, false).expect("must register");

        assert_eq!(config.len(), 2);
        assert!(config.get("archive").is_some_and(RemoteDef::is_vault));
        assert!(
            config
                .get("archive-store")
                .is_some_and(RemoteDef::require_vault)
        );
        assert!(config::validate(&config).is_ok());
    }

    #[test]
    fn the_plan_serialises_with_stable_field_names() {
        let ctx = ctx(&["--index", "/tmp/dctl-test.redb"]);
        let json = serde_json::to_value(plan(&ctx, "archive", "local:/srv/vault")).unwrap();
        assert_eq!(json["vault_name"], "archive");
        assert_eq!(json["store_name"], "archive-store");
        assert_eq!(json["base"], "local:/srv/vault");
        assert_eq!(json["index_exists"], false);
    }
}
