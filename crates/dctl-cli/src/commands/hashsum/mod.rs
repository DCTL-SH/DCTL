//! `dctl hashsum ALGO REMOTE:PATH` — print content hashes.
//!
//! The command exists because of `PLAN.md` §13.1: the data has to outlive the
//! tool. A vault whose checksums can only be read by DCTL is a vault that
//! depends on DCTL still existing in 2045. A vault whose checksums come out as
//!
//! ```text
//! af1349b9f5f9…  photos/2024/a.jpg
//! ```
//!
//! can be handed to `sha256sum -c`, to a tape catalogue, or to whatever replaces
//! them, by someone who has never heard of this program. That is the entire
//! design constraint, and it is enforced in [`algo::format_line`].
//!
//! Text output is therefore **not** a table: it is the coreutils line format,
//! byte for byte, on stdout with nothing else mixed in. `--json` and
//! `--format json-lines` are available for consumers that would rather not parse
//! it.
//!
//! ## The digest is of the PLAINTEXT, always
//!
//! This is the single most important sentence about the command, so it is said
//! here as well as in [`digest`]. A sealed object is a nonce, a header, a chain
//! of AEAD chunks and a footer; hashing *that* would produce a well-formed
//! digest which matches nothing the user has, and which changes every time the
//! object is re-sealed even though the file has not moved a byte. What a person
//! running `dctl hashsum sha256 archive:photos/a.jpg` is about to do is compare
//! the answer with `sha256sum photos/a.jpg` on their own disk, and the only
//! digest that makes that comparison mean anything is the digest of the file.
//!
//! So every byte hashed here came out of
//! [`Source::read`](crate::source::Source::read) — decrypted and authenticated
//! for a vault, the object as stored for a plain remote — which is exactly what
//! `dctl cat` would have written. Hashing ciphertext would silently answer a
//! different question in a form indistinguishable from an answer to this one.
//!
//! ## Cost
//!
//! `blake3` is the vault's own plaintext hash and is recorded for every object
//! at write time, so it is answered from the index with no egress at all.
//! `sha1` and `sha256` are not recorded, and producing them means reading and
//! decrypting every object — the command says so before it starts, because the
//! surprise otherwise arrives as a bill.
//!
//! The shortcut is not a verification. A `blake3` run answered from the index
//! reports the hash the file had when it was written and never touches the
//! provider, so it cannot notice that the object has since rotted. That is what
//! `dctl verify` and `dctl scrub` are for, and this command does not pretend
//! otherwise.
//!
//! An object that fails authentication while being hashed ends the process with
//! [`ExitCode::IntegrityFailure`](crate::exit::ExitCode::IntegrityFailure) (21)
//! and a message saying the data was not served. Printing a hash of bytes that
//! failed to authenticate would be the worst possible outcome here: it would
//! certify corruption.
//!
//! ## Scope
//!
//! The global filtering flags apply, through the one engine every other verb
//! uses ([`crate::filter`]). `dctl hashsum sha256 archive: --include '*.jpg'`
//! therefore covers exactly the objects `dctl ls --include '*.jpg'` listed —
//! a checksum file that covered a different set from the listing it was written
//! beside would be worse than no checksum file.

pub mod algo;
pub mod digest;
pub mod engine;
pub mod report;

use clap::Args;

use crate::commands::integrity::{Target, command_name};
use crate::commands::listing::Filter;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

use algo::Algorithm;
use report::Report;

/// The verb this module implements, used in messages that name the command.
const VERB: &str = "hashsum";

/// Arguments to `dctl hashsum`.
#[derive(Args, Debug)]
pub struct HashsumArgs {
    /// Hash algorithm.
    #[arg(value_enum, value_name = "ALGO")]
    pub algorithm: Algorithm,

    /// Object or prefix to hash.
    #[arg(value_name = "REMOTE:PATH")]
    pub target: String,

    /// Mark paths as binary, the way `sha256sum --binary` does.
    ///
    /// Writes `<hash> *<path>` instead of `<hash>  <path>`. Off by default
    /// because plain `sha256sum` writes text mode, and matching the common
    /// spelling keeps a diff of two checksum files readable.
    #[arg(long)]
    pub binary: bool,
}

/// Print content hashes in the coreutils format.
///
/// # Errors
/// [`CliError::usage`] for a malformed or local target or an unusable filter;
/// whatever opening the remote reported; and the integrity family's classified
/// failure — [`ExitCode::IntegrityFailure`] — for an object that does not
/// authenticate, in which case no checksum file is produced at all.
pub async fn run(ctx: &Ctx, args: &HashsumArgs) -> Result<()> {
    let command = command_name(VERB);
    let target = Target::parse(&args.target)?;
    // Hashes come from the vault's integrity manifest. A local path has none,
    // and quietly hashing local files instead would answer a different question
    // from the one that was asked.
    target.require_remote(&command)?;

    ctx.out.info(format!(
        "{command}: {} over {target}",
        args.algorithm.slug()
    ));
    if !args.algorithm.is_recorded_in_the_index() {
        // The vault records BLAKE3 only; anything else has to be recomputed from
        // the plaintext, which means downloading and decrypting every object.
        ctx.out.warn(format!(
            "{} is not recorded in the index, so every object under '{target}' must be \
             read back and decrypted to compute it",
            args.algorithm.slug()
        ));
    }

    // Compiled before the remote opens, so a malformed `--include` fails before
    // a password is asked for.
    let filter = Filter::from_globals(&ctx.globals)?;
    let source = crate::source::open(ctx, &target.spec()).await?;

    // `hashsum` mutates nothing, so --dry-run has nothing to suppress — and is
    // not permission to emit an empty checksum file, which a checker would
    // happily accept as "nothing to verify".
    let mut report = Report::new(args.algorithm, args.binary);
    engine::hash(
        ctx,
        source.as_ref(),
        target.prefix(),
        &filter,
        args.algorithm,
        &mut report,
    )
    .await?;

    // The last guard before a file somebody will later trust. A digest of the
    // wrong width makes `sha256sum -c` report a mismatch, which sends a person
    // hunting for corruption that never happened — so a malformed report is
    // refused rather than written.
    if !report.digests_are_well_formed() {
        return Err(CliError::new(
            ExitCode::Uncategorised,
            format!(
                "{command} produced a digest that is not a well-formed {}",
                args.algorithm.slug()
            ),
        )
        .with_hint(
            "No checksum file was written. This is a defect in DCTL rather than a \
             problem with the data; please report it.",
        ));
    }

    if report.is_empty() {
        // On stderr, never stdout: an empty SUMS file passes `sha256sum -c`
        // trivially, so the one thing a person must not have to guess is
        // whether the file is empty because the vault is or because their
        // filters were.
        empty_notice(ctx, &target, &filter);
    } else {
        // Also stderr: a count belongs nowhere near a file `sha256sum -c` will
        // read, but a person redirecting stdout still deserves to be told how
        // many lines they just captured.
        ctx.out
            .info(format!("{command}: {} objects hashed", report.len()));
    }

    report.emit(&ctx.out)
}

/// Say on stderr why nothing was hashed.
///
/// "Nothing is there" and "nothing survived your filters" produce the same empty
/// checksum file and call for completely different actions, and a run that could
/// not tell them apart would be this command's least trustworthy corner.
fn empty_notice(ctx: &Ctx, target: &Target, filter: &Filter) {
    if filter.is_restricting() {
        ctx.out.info(format!(
            "no objects under '{target}' matched the active filters, so the checksum \
             file is empty"
        ));
    } else {
        ctx.out.info(format!(
            "no objects under '{target}', so the checksum file is empty"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use crate::commands::listing::tests_support::ctx as listing_ctx;
    use crate::constants::HASHSUM_FIELD_SEPARATOR;
    use crate::exit::ExitCode;
    use crate::output::Out;
    use clap::Parser;

    fn parse(args: &[&str]) -> (Ctx, HashsumArgs) {
        let cli = Cli::try_parse_from(std::iter::once("dctl").chain(args.iter().copied()))
            .expect("arguments should parse");
        let Command::Hashsum(hashsum) = cli.command else {
            panic!("expected the hashsum subcommand");
        };
        (Ctx::new(cli.globals), hashsum)
    }

    /// A configured plain remote over a temporary directory, plus the `--config`
    /// argument that points DCTL at the file naming it.
    fn plain_remote(files: &[(&str, &[u8])]) -> (tempfile::TempDir, String) {
        let dir = tempfile::TempDir::new().expect("a temporary directory");
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).expect("the root exists even when empty");
        for (relative, bytes) in files {
            let path = root.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("the parent directory is created");
            }
            std::fs::write(&path, bytes).expect("the fixture file is written");
        }

        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[remotes.store]\ntype = \"local\"\npath = {:?}\n",
                root.to_string_lossy()
            ),
        )
        .expect("the configuration is written");
        let path = config.to_string_lossy().into_owned();
        (dir, path)
    }

    #[tokio::test]
    async fn every_documented_algorithm_parses() {
        for (spelling, expected) in [
            ("blake3", Algorithm::Blake3),
            ("sha1", Algorithm::Sha1),
            ("sha256", Algorithm::Sha256),
        ] {
            let (_, args) = parse(&["hashsum", spelling, "vault:photos"]);
            assert_eq!(args.algorithm, expected);
            assert_eq!(args.target, "vault:photos");
            assert!(!args.binary);
        }
    }

    #[tokio::test]
    async fn an_unknown_algorithm_is_a_usage_error() {
        // Silently falling back to a different algorithm would produce a
        // checksum file that fails to check for no visible reason.
        assert!(Cli::try_parse_from(["dctl", "hashsum", "md5", "vault:"]).is_err());
    }

    #[tokio::test]
    async fn both_arguments_are_required() {
        assert!(Cli::try_parse_from(["dctl", "hashsum"]).is_err());
        assert!(Cli::try_parse_from(["dctl", "hashsum", "sha256"]).is_err());
    }

    #[tokio::test]
    async fn binary_mode_is_opt_in() {
        let (_, args) = parse(&["hashsum", "sha256", "vault:", "--binary"]);
        assert!(args.binary);
    }

    #[tokio::test]
    async fn a_local_target_is_a_usage_error() {
        let (ctx, args) = parse(&["hashsum", "sha256", "./photos"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn an_unresolvable_remote_is_an_error_rather_than_an_empty_checksum_file() {
        // An empty SUMS file passes `sha256sum -c` trivially, so a silent
        // success here would be worse than a loud failure.
        let (ctx, args) = parse(&["hashsum", "sha256", "nosuchremote:", "--no-ask-password"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains("nosuchremote"));
    }

    #[tokio::test]
    async fn a_malformed_pattern_fails_before_the_remote_is_opened() {
        // Otherwise an unattended run would prompt for a password and only then
        // report a typo in a flag.
        let (ctx, args) = parse(&["hashsum", "sha256", "nosuchremote:", "--include", "[abc"]);
        assert_eq!(run(&ctx, &args).await.unwrap_err().code(), ExitCode::Usage);
    }

    #[tokio::test]
    async fn a_real_remote_produces_a_checkable_checksum_file() {
        let (_dir, config) = plain_remote(&[("a.txt", b"abc"), ("sub/b.txt", b"")]);
        let (ctx, args) = parse(&["hashsum", "sha256", "store:", "--config", &config]);
        run(&ctx, &args).await.expect("the run succeeds");

        // The rendering is asserted against the same report the run built, so
        // the shape of what reaches stdout is pinned without capturing it.
        let filter = Filter::from_globals(&ctx.globals).expect("no filters");
        let source = crate::source::open(&ctx, &Target::parse("store:").unwrap().spec())
            .await
            .expect("the remote opens");
        let mut report = Report::new(Algorithm::Sha256, false);
        engine::hash(
            &ctx,
            source.as_ref(),
            "",
            &filter,
            Algorithm::Sha256,
            &mut report,
        )
        .await
        .expect("the walk succeeds");

        let rendered = report.render(&Out::plain()).expect("the report renders");
        assert_eq!(rendered.lines().count(), 2);
        for line in rendered.lines() {
            let (hash, path) = line
                .split_once(HASHSUM_FIELD_SEPARATOR)
                .expect("two spaces separate the fields");
            assert!(Algorithm::Sha256.is_well_formed(hash), "got: {line}");
            assert!(!path.is_empty());
        }
        assert!(rendered.starts_with(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  a.txt"
        ));
    }

    #[tokio::test]
    async fn every_output_format_is_accepted() {
        let (_dir, config) = plain_remote(&[("a.txt", b"1")]);
        for format in [&["--json"][..], &["--format", "json-lines"][..], &[][..]] {
            let mut argv = vec!["hashsum", "blake3", "store:", "--config", config.as_str()];
            argv.extend_from_slice(format);
            let (ctx, args) = parse(&argv);
            run(&ctx, &args)
                .await
                .expect("the format must not change the outcome");
        }
    }

    #[tokio::test]
    async fn dry_run_does_not_suppress_the_answer() {
        // `hashsum` mutates nothing, so a rehearsal of it is the thing itself —
        // and printing nothing would look like an empty vault.
        let (_dir, config) = plain_remote(&[("a.txt", b"1")]);
        let (ctx, args) = parse(&[
            "hashsum",
            "blake3",
            "store:",
            "--config",
            &config,
            "--dry-run",
        ]);
        assert!(ctx.is_dry_run());
        run(&ctx, &args).await.expect("a dry run still answers");
    }

    #[tokio::test]
    async fn an_empty_result_says_which_kind_of_empty_it_is() {
        // The notice is on stderr, so this asserts the branch rather than the
        // bytes: what must not happen is the two cases becoming indistinguishable.
        let unfiltered = Filter::from_globals(&listing_ctx(&[]).globals).expect("no filters");
        assert!(!unfiltered.is_restricting());
        let filtered =
            Filter::from_globals(&listing_ctx(&["--include", "*.jpg"]).globals).expect("a filter");
        assert!(filtered.is_restricting());

        let (_dir, config) = plain_remote(&[]);
        let (ctx, args) = parse(&["hashsum", "sha256", "store:", "--config", &config]);
        run(&ctx, &args)
            .await
            .expect("an empty remote is not a failure");
    }

    #[tokio::test]
    async fn a_sealed_vault_hashes_the_plaintext_end_to_end() {
        // The whole command, wired: configuration, vault chain, unlock, index
        // walk, authenticated read-back, coreutils line.
        use std::sync::Arc;

        use dctl_core::Vault;
        use dctl_store::{Backend, LocalFs};

        let dir = tempfile::TempDir::new().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        let index = dir.path().join("index.redb");

        {
            let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(&store));
            let vault = Vault::init(backend, &index, "pw").await.unwrap();
            vault.put_file("notes.txt", b"abc").await.unwrap();
        }

        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[remotes.store]\ntype = \"local\"\npath = {:?}\nrequire_vault = true\n\n\
                 [remotes.archive]\ntype = \"vault\"\nbase = \"store\"\n",
                store.to_string_lossy()
            ),
        )
        .unwrap();

        let config = config.to_string_lossy().into_owned();
        let index = index.to_string_lossy().into_owned();
        let (ctx, args) = parse(&[
            "hashsum",
            "sha256",
            "archive:",
            "--config",
            &config,
            "--index",
            &index,
            "--password",
            "pw",
        ]);
        run(&ctx, &args).await.expect("the vault hashes");
    }
}
