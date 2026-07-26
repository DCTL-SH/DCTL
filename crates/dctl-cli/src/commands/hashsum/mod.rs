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
//! ## Cost
//!
//! `blake3` is the vault's own plaintext hash and is recorded for every object
//! at write time, so it is answered from the index with no egress at all.
//! `sha1` and `sha256` are not recorded, and producing them means reading and
//! decrypting every object — the command says so before it starts, because the
//! surprise otherwise arrives as a bill.
//!
//! An object that fails authentication while being hashed ends the process with
//! [`ExitCode::IntegrityFailure`](crate::exit::ExitCode::IntegrityFailure) (21)
//! and a message saying the data was not served. Printing a hash of bytes that
//! failed to authenticate would be the worst possible outcome here: it would
//! certify corruption.
//!
//! ## What this build can do
//!
//! Argument parsing, target resolution, the algorithm table, the coreutils line
//! format and the report shape in all three formats are implemented and tested
//! here. Reading hashes out of a vault is not: `Ctx` does not yet carry an
//! unlocked vault and `dctl_core::Vault` exposes no way to fetch a recorded
//! content hash without also fetching the object. `run` therefore validates and
//! then returns [`CliError::unimplemented`] rather than printing an empty
//! checksum file, which a script would happily accept as "nothing to check".

pub mod algo;
pub mod report;

use clap::Args;

use crate::commands::integrity::{Target, command_name};
use crate::ctx::Ctx;
use crate::error::{CliError, Result};

use algo::Algorithm;

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
/// [`CliError::usage`] for a malformed or local target; an integrity failure for
/// an object that does not authenticate; and [`CliError::unimplemented`] until
/// the engine can supply hashes — see the module documentation.
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

    // `hashsum` mutates nothing, so --dry-run has nothing to suppress — and is
    // not permission to emit an empty checksum file, which a checker would
    // happily accept as "nothing to verify".
    Err(CliError::unimplemented(command))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use crate::exit::ExitCode;
    use clap::Parser;

    fn parse(args: &[&str]) -> (Ctx, HashsumArgs) {
        let cli = Cli::try_parse_from(std::iter::once("dctl").chain(args.iter().copied()))
            .expect("arguments should parse");
        let Command::Hashsum(hashsum) = cli.command else {
            panic!("expected the hashsum subcommand");
        };
        (Ctx::new(cli.globals), hashsum)
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
    async fn unimplemented_work_never_emits_an_empty_checksum_file() {
        // An empty SUMS file passes `sha256sum -c` trivially, so a silent
        // success here would be worse than a loud failure.
        let (ctx, args) = parse(&["hashsum", "sha256", "vault:photos"]);
        let error = run(&ctx, &args).await.unwrap_err();
        assert_eq!(error.code(), ExitCode::FatalError);
        assert!(error.message().contains(&command_name(VERB)));
    }

    #[tokio::test]
    async fn every_output_format_is_accepted() {
        for format in [&["--json"][..], &["--format", "json-lines"][..], &[][..]] {
            let mut argv = vec!["hashsum", "blake3", "vault:"];
            argv.extend_from_slice(format);
            let (ctx, args) = parse(&argv);
            assert_eq!(
                run(&ctx, &args).await.unwrap_err().code(),
                ExitCode::FatalError
            );
        }
    }
}
