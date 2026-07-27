//! Storing a stream into a vault.
//!
//! The three steps are ordered by what a pipe cannot survive:
//!
//! 1. **Open the vault first.** A refusal has to happen before the producer's
//!    output is consumed — a pipe cannot be rewound, so a run that read the
//!    stream and *then* discovered it could not store it would have destroyed
//!    data that exists nowhere else. Unlocking is also where `--immutable` and
//!    `--interactive` get their answer, because both are questions about an
//!    object that may already be there.
//! 2. **Spool, then seal.** [`super::spool`] captures the stream on disk and
//!    `Vault::put_file_from_path` seals it straight from there in
//!    `O(chunk_size)` memory — the reason `rcat` has no size limit while the
//!    transfer engine still does.
//! 3. **Report what the vault recorded**, not what was sent. The byte count
//!    comes back from the spool, and success is only claimed after the core has
//!    completed its verified write *and* committed the index record, which is
//!    one operation and therefore has no window in which bytes are stored but
//!    uncommitted.
//!
//! ## Why the existence check is a listing and not a read
//!
//! `--immutable` and the destructive-replacement prompt both need to know
//! whether the object is there. `Vault::get_file` would answer by downloading
//! and decrypting the whole thing; the index answers from a local lookup. For a
//! command whose next act is to upload, paying an egress charge to find out
//! whether it may would be an odd way to protect the data.

use dctl_core::Vault;

use crate::commands::directory::Target;
use crate::commands::pipeline::ObjectSpec;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::session;

use super::spool;

/// What a resolved sealed destination allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Read the stream and store it.
    Store,
    /// The operator declined the replacement; read nothing.
    Decline,
}

/// Store standard input as one sealed object.
///
/// Returns the number of bytes stored, or [`None`] when the operator declined a
/// replacement — in which case standard input was never read.
///
/// # Errors
/// [`ExitCode::Usage`] when `--immutable` forbids replacing what is there;
/// [`ExitCode::VaultLocked`] when the vault will not unlock; and whatever the
/// spool, the seal or the provider reported. Every one of them happens either
/// before the stream is read or after it is complete, so a failure never leaves
/// a truncated object.
pub async fn store(
    ctx: &Ctx,
    spec: &ObjectSpec,
    target: &Target,
    reader: &mut impl std::io::Read,
) -> Result<Option<u64>> {
    // Opened before a byte is read, so every refusal below costs the producer
    // nothing.
    let session = session::open(ctx, &target.spec()).await?;

    if decide(ctx, &session.vault, spec)? == Decision::Decline {
        return Ok(None);
    }

    let spooled = spool::capture(ctx, reader)?;

    // The seal, the verified write and the durable index commit are one
    // operation in `dctl-core`: when this returns `Ok`, the object is stored and
    // recorded, and when it returns an error nothing was committed.
    session
        .vault
        .put_file_from_path(&target.path, spooled.path())
        .await?;

    ctx.stats.file_done();
    Ok(Some(spooled.bytes()))
}

/// Decide whether an existing object may be replaced.
///
/// Split out so the decision table is testable against a real vault without a
/// pipe: this is where data is destroyed, and "does `--immutable` actually stop
/// it?" must be answerable by a test rather than by reading the call site.
///
/// # Errors
/// [`ExitCode::Usage`] under `--immutable`, and whatever the index reported.
pub fn decide(ctx: &Ctx, vault: &Vault, spec: &ObjectSpec) -> Result<Decision> {
    if !exists(vault, spec.path())? {
        return Ok(Decision::Store);
    }

    if ctx.globals.immutable {
        return Err(CliError::new(
            ExitCode::Usage,
            format!("'{spec}' already exists and --immutable was given"),
        )
        .with_hint("--immutable refuses to modify anything that already exists."));
    }

    // Replacing an object is destructive, so `--interactive` gets to ask.
    if ctx.confirm_destructive("replace", spec.display())? {
        Ok(Decision::Store)
    } else {
        Ok(Decision::Decline)
    }
}

/// Whether the vault already holds `path`.
///
/// `Vault::list` matches by byte prefix, so `db.sql` would also report
/// `db.sql.bak`; the exact comparison is what makes this a lookup rather than a
/// search, and getting it wrong would make `--immutable` refuse a write it
/// should allow.
fn exists(vault: &Vault, path: &str) -> Result<bool> {
    Ok(vault.list(path)?.iter().any(|record| record.path == path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use clap::Parser;
    use dctl_store::{Backend, LocalFs};
    use std::sync::Arc;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        let argv = std::iter::once("dctl")
            .chain(args.iter().copied())
            .chain(std::iter::once("--quiet"));
        Ctx::new(Harness::parse_from(argv).globals)
    }

    /// A real vault over a temporary directory, holding `notes.txt`.
    ///
    /// Built through `Vault::init` rather than mocked: the question these tests
    /// ask — "is this object already there?" — is answered by the index, and an
    /// index that is not the real one answers a different question.
    async fn vault_with(files: &[(&str, &[u8])]) -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).expect("the store directory");

        let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(&store));
        let vault = Vault::init(
            backend,
            &dir.path().join("index.db"),
            "correct horse battery",
        )
        .await
        .expect("a fresh vault initialises");

        for (path, bytes) in files {
            vault.put_file(path, bytes).await.expect("a verified write");
        }
        (dir, vault)
    }

    fn spec(text: &str) -> ObjectSpec {
        ObjectSpec::parse(text).expect("a valid spec")
    }

    #[tokio::test]
    async fn an_absent_object_is_stored_without_a_question() {
        let (_dir, vault) = vault_with(&[]).await;
        assert_eq!(
            decide(&ctx(&[]), &vault, &spec("archive:new.txt")).unwrap(),
            Decision::Store
        );
    }

    #[tokio::test]
    async fn immutable_refuses_to_replace_an_object_the_vault_holds() {
        // And it refuses *before* the stream is read, which is why this decision
        // is made from the index rather than from the upload's result.
        let (_dir, vault) = vault_with(&[("notes.txt", b"original")]).await;
        let error = decide(&ctx(&["--immutable"]), &vault, &spec("archive:notes.txt"))
            .expect_err("--immutable forbids replacing");

        assert_eq!(error.code(), ExitCode::Usage);
        assert_eq!(
            vault.get_file("notes.txt").await.unwrap().as_slice(),
            b"original",
            "the refusal must not have touched anything"
        );
    }

    #[tokio::test]
    async fn a_dry_run_declines_a_replacement_rather_than_performing_it() {
        // `confirm_destructive` answers `false` under --dry-run, and the caller
        // must treat that as "read nothing".
        let (_dir, vault) = vault_with(&[("notes.txt", b"original")]).await;
        assert_eq!(
            decide(
                &ctx(&["--dry-run", "--interactive"]),
                &vault,
                &spec("archive:notes.txt")
            )
            .unwrap(),
            Decision::Decline
        );
    }

    #[tokio::test]
    async fn a_neighbouring_name_is_not_the_object() {
        // `Vault::list` matches by prefix: without the exact comparison,
        // `--immutable` would refuse to create `db.sql` because `db.sql.bak`
        // happens to exist.
        let (_dir, vault) = vault_with(&[("db.sql.bak", b"older")]).await;
        assert!(!exists(&vault, "db.sql").unwrap());
        assert!(exists(&vault, "db.sql.bak").unwrap());
    }

    #[tokio::test]
    async fn a_stream_round_trips_through_the_vault_byte_for_byte() {
        // The end-to-end claim: what the pipe produced is what `cat` gives back.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).expect("the store directory");
        let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(&store));
        let vault = Vault::init(
            backend,
            &dir.path().join("index.db"),
            "correct horse battery",
        )
        .await
        .expect("a fresh vault initialises");

        let payload: Vec<u8> = (0..=255_u8).cycle().take(200_000).collect();
        let spooled = spool::capture(&ctx(&[]), &mut payload.as_slice()).expect("the spool");
        vault
            .put_file_from_path("dump.bin", spooled.path())
            .await
            .expect("the sealed write");

        assert_eq!(
            vault.get_file("dump.bin").await.unwrap().as_slice(),
            payload.as_slice()
        );
    }
}
