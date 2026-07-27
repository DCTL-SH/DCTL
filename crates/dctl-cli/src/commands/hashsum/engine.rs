//! The walk: enumerate, hash, record.
//!
//! ## The shortcut, and its exact boundary
//!
//! A vault records the plaintext BLAKE3 of every object at write time, under the
//! same verified-write contract that refused to commit unless the stored bytes
//! matched. `dctl hashsum blake3` therefore answers from the index, and a
//! whole-vault run costs one index scan and no egress at all.
//!
//! The shortcut applies **only** when the algorithm is BLAKE3 *and* the entry
//! actually carries a hash. Both halves matter:
//!
//! * a plain object store knows no plaintext hash and reports [`None`], so the
//!   object is read and hashed like any other;
//! * a vault row written by `dctl index rebuild` also reports [`None`], because
//!   that pass lists object headers without reading bodies. Treating the absence
//!   as "hashes to nothing" — which an empty `Vec` would have made easy — would
//!   put the digest of the empty string next to a file that is plainly not
//!   empty.
//!
//! Everything else is read back through [`Source::read`], which for a vault
//! means decrypted and authenticated **plaintext**. That is the whole cost of
//! the command for `sha1` and `sha256`, and the command warns before it starts.
//!
//! ## Failure is loud, and the line is never written
//!
//! An object whose bytes do not authenticate ends the run immediately with
//! [`ExitCode::IntegrityFailure`](crate::exit::ExitCode::IntegrityFailure) (21)
//! and nothing on stdout. This is the one command in the family where continuing
//! would be actively dangerous: a checksum file is a *certificate*, and a line
//! computed from bytes that failed authentication would certify the corruption
//! as though it were the file. Unlike `scrub`, which is asked "how much is
//! damaged" and therefore keeps going, `hashsum` is asked "what is the hash of
//! this data", and once any of it will not authenticate the honest answer to
//! that question is no answer at all.
//!
//! ## Memory
//!
//! One entry at a time from the cursor, and one object's plaintext at a time
//! while it is being hashed — that second buffer is [`Source::read`]'s shape and
//! is documented there. `blake3` over a vault never allocates it, which is the
//! difference between hashing a 50 TB dataset and reading one.

use zeroize::Zeroizing;

use crate::commands::integrity::failure::{self, classify};
use crate::commands::listing::{self, Filter};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::hex;
use crate::source::Source;

use super::algo::Algorithm;
use super::digest;
use super::report::{Record, Report};

/// Hash everything under `prefix` that `filter` admits, into `report`.
///
/// # Errors
/// Whatever enumerating the source reported, and — as a hard stop —
/// [`ExitCode::IntegrityFailure`](crate::exit::ExitCode::IntegrityFailure) for
/// an object that did not authenticate, in which case no line for it, and no
/// line after it, is produced.
pub async fn hash(
    ctx: &Ctx,
    source: &dyn Source,
    prefix: &str,
    filter: &Filter,
    algorithm: Algorithm,
    report: &mut Report,
) -> Result<()> {
    let mut entries = source.enumerate(prefix).await?;

    while let Some(entry) = entries.next().await? {
        // Building the listing view costs a clone, so it is skipped entirely
        // when no filter is in force — which is every run that does not ask for
        // one.
        if filter.is_restricting()
            && !filter.matches(&listing::Entry::from_source(entry.clone(), prefix))
        {
            continue;
        }

        let hash = match recorded(algorithm, entry.content_hash.as_deref()) {
            Some(digest) => digest,
            None => digest::of(algorithm, &read(ctx, source, &entry.path).await?),
        };
        report.push(Record::new(algorithm, hash, entry.path));
    }

    Ok(())
}

/// The digest the source already knows, when it is the one that was asked for.
///
/// Split out and kept pure so the boundary of the shortcut — see the module
/// documentation — is one testable function rather than a condition buried in
/// the loop, where a later edit could widen it to "any algorithm" and silently
/// print BLAKE3 digests under a `sha256` heading.
fn recorded(algorithm: Algorithm, content_hash: Option<&[u8]>) -> Option<String> {
    if !algorithm.is_recorded_in_the_index() {
        return None;
    }
    content_hash.map(hex::encode)
}

/// Read one object's plaintext, turning a failed read into the family's own
/// classified failure.
///
/// The translation is the point. [`Source::read`] reports a provider's wording
/// and an exit code; what a person needs to see here is the sentence that says
/// the data was **not** served, in the same words `verify`, `scrub` and `cat`
/// use — which is [`failure::object_failure`], and which is why the error is not
/// simply propagated.
async fn read(ctx: &Ctx, source: &dyn Source, path: &str) -> Result<Zeroizing<Vec<u8>>> {
    source.read(path).await.map_err(|error| {
        let verdict = classify(&error);
        // The provider's own wording on stderr, then the family's classified
        // failure as the run's outcome: the first says what went wrong at the
        // remote, the second says what it means for the data.
        ctx.out
            .warn(format!("{}: {}", verdict.slug(), error.message()));
        failure::object_failure(path, verdict)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::exit::ExitCode;
    use crate::session::Session;
    use crate::source::plain::PlainSource;
    use crate::source::vault::VaultSource;
    use clap::Parser;
    use dctl_core::Vault;
    use dctl_store::{Backend, LocalFs};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::TempDir;

    /// The published SHA digests of `abc`, from FIPS 180-4's own worked
    /// examples. Hard-coded rather than computed so the walk is checked against
    /// the outside world and not against this crate's own hasher.
    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ABC_SHA1: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(args: &[&str]) -> Ctx {
        Ctx::new(Harness::parse_from(std::iter::once("dctl").chain(args.iter().copied())).globals)
    }

    /// A real directory behind a real backend, so the read path under test is
    /// the production one.
    fn store(files: &[(&str, &[u8])]) -> (TempDir, PlainSource) {
        let root = TempDir::new().expect("a temporary directory");
        for (relative, bytes) in files {
            let path = root.path().join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("the parent directory is created");
            }
            std::fs::write(&path, bytes).expect("the fixture file is written");
        }
        let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(root.path()));
        (root, PlainSource::new(backend))
    }

    /// A real sealed vault over temporary directories, with `files` written
    /// through the ordinary verified write.
    ///
    /// Handed back unwrapped so a test can act on the vault itself — rebuilding
    /// its index — before it disappears into a [`Session`].
    async fn sealed(files: &[(&str, &[u8])]) -> (TempDir, TempDir, PathBuf, Vault) {
        let store = TempDir::new().expect("a temporary store");
        let index = TempDir::new().expect("a temporary index");
        let index_path = index.path().join("index.redb");
        let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(store.path()));

        let vault = Vault::init(backend, &index_path, "pw")
            .await
            .expect("a fresh vault initialises")
            .vault;
        for (path, bytes) in files {
            vault
                .put_file(path, bytes, dctl_core::Modified::Now)
                .await
                .expect("a verified write");
        }
        (store, index, index_path, vault)
    }

    /// The sealed source reading `vault`.
    fn source_for(vault: Vault, index: PathBuf) -> VaultSource {
        VaultSource::new(Session {
            vault,
            remote: "archive:".to_string(),
            index,
        })
    }

    /// Overwrite every sealed object with garbage of the same length, reaching
    /// past DCTL entirely — the only way to prove the command detects what it
    /// exists to detect.
    fn damage_objects(store: &std::path::Path) {
        for entry in std::fs::read_dir(store.join("o")).expect("the object directory exists") {
            let path = entry.expect("a directory entry").path();
            if !path.is_file() {
                continue;
            }
            let length = std::fs::metadata(&path).expect("readable").len();
            std::fs::write(&path, vec![0xA5; length as usize]).expect("overwritten");
        }
    }

    /// Run the walk and reduce it to the `(path, digest)` pairs it produced.
    ///
    /// Read back out of the *rendered* checksum file rather than out of the
    /// report's fields, so every assertion below is about the bytes a
    /// `sha256sum -c` would be handed and not about an intermediate a user never
    /// sees.
    async fn run(
        source: &dyn Source,
        algorithm: Algorithm,
        flags: &[&str],
    ) -> Result<Vec<(String, String)>> {
        let context = ctx(flags);
        let filter = Filter::from_globals(&context.globals).expect("the flags compile");
        let mut report = Report::new(algorithm, false);
        hash(&context, source, "", &filter, algorithm, &mut report).await?;

        let rendered = report
            .render(&crate::output::Out::plain())
            .expect("the report renders");
        Ok(rendered
            .lines()
            .map(|line| {
                let (hash, path) = line
                    .split_once(crate::constants::HASHSUM_FIELD_SEPARATOR)
                    .expect("every line is a digest, two spaces and a path");
                (path.to_string(), hash.to_string())
            })
            .collect())
    }

    #[tokio::test]
    async fn a_plain_store_is_read_and_hashed_for_every_algorithm() {
        let (_root, source) = store(&[("a.txt", b"abc"), ("sub/b.txt", b"")]);

        for (algorithm, first) in [
            (Algorithm::Sha256, ABC_SHA256.to_string()),
            (Algorithm::Sha1, ABC_SHA1.to_string()),
            (Algorithm::Blake3, digest::of(Algorithm::Blake3, b"abc")),
        ] {
            let lines = run(&source, algorithm, &[])
                .await
                .expect("the walk succeeds");
            assert_eq!(
                lines,
                vec![
                    ("a.txt".to_string(), first),
                    ("sub/b.txt".to_string(), digest::of(algorithm, b"")),
                ],
                "wrong digests for {}",
                algorithm.slug()
            );
        }
    }

    #[tokio::test]
    async fn a_vault_hashes_the_plaintext_and_never_the_stored_object() {
        // The property the whole command turns on: the answer has to be what
        // `sha256sum` prints for the file the user put in, not for the sealed
        // bytes the provider is holding.
        let (_store, _index, path, vault) = sealed(&[("notes.txt", b"abc")]).await;
        let source = source_for(vault, path);

        for (algorithm, expected) in [(Algorithm::Sha256, ABC_SHA256), (Algorithm::Sha1, ABC_SHA1)]
        {
            let lines = run(&source, algorithm, &[])
                .await
                .expect("the walk succeeds");
            assert_eq!(lines, vec![("notes.txt".to_string(), expected.to_string())]);
        }
    }

    #[tokio::test]
    async fn blake3_over_a_vault_is_answered_from_the_index() {
        // Same digest reading and re-hashing would produce — which is the only
        // reason the shortcut is allowed to exist.
        let (_store, _index, path, vault) = sealed(&[("a.txt", b"hello world")]).await;
        let source = source_for(vault, path);

        let lines = run(&source, Algorithm::Blake3, &[])
            .await
            .expect("the walk succeeds");
        assert_eq!(
            lines,
            vec![(
                "a.txt".to_string(),
                digest::of(Algorithm::Blake3, b"hello world")
            )]
        );
    }

    #[tokio::test]
    async fn a_row_with_no_recorded_hash_is_read_rather_than_reported_as_empty() {
        // `dctl index rebuild` lists object headers without reading bodies, so
        // its rows carry no plaintext hash. Believing the absence would print
        // the digest of the empty string beside a file that is not empty.
        let (_store, _index, path, vault) = sealed(&[("a.txt", b"hello world")]).await;
        vault
            .rebuild_index()
            .await
            .expect("the index rebuilds from the backend");
        let source = source_for(vault, path);

        let lines = run(&source, Algorithm::Blake3, &[])
            .await
            .expect("the walk succeeds");
        assert_eq!(
            lines,
            vec![(
                "a.txt".to_string(),
                digest::of(Algorithm::Blake3, b"hello world")
            )],
            "a rebuilt row must be read, not reported as hashing to nothing"
        );
        assert_ne!(lines[0].1, digest::of(Algorithm::Blake3, b""));
    }

    #[test]
    fn the_shortcut_is_exactly_blake3_with_a_recorded_hash() {
        assert_eq!(
            recorded(Algorithm::Blake3, Some(&[0xab, 0xcd])),
            Some("abcd".to_string())
        );
        assert_eq!(recorded(Algorithm::Blake3, None), None);
        // Never for another algorithm: a BLAKE3 digest printed under a `sha256`
        // heading is a checksum file that fails to check for no visible reason.
        assert_eq!(recorded(Algorithm::Sha256, Some(&[0xab, 0xcd])), None);
        assert_eq!(recorded(Algorithm::Sha1, Some(&[0xab, 0xcd])), None);
    }

    #[tokio::test]
    async fn a_corrupt_object_stops_the_run_and_certifies_nothing() {
        // A checksum line computed from bytes that failed authentication would
        // certify the corruption as though it were the file.
        let (store, _index, path, vault) = sealed(&[("a.txt", b"one"), ("b.txt", b"two")]).await;
        damage_objects(store.path());
        let source = source_for(vault, path);

        let error = run(&source, Algorithm::Sha256, &[])
            .await
            .expect_err("damaged objects must not be hashed");
        assert_eq!(error.code(), ExitCode::IntegrityFailure);
        assert_eq!(error.code().as_i32(), 21);
        assert!(
            error.message().contains("NOT served"),
            "got: {}",
            error.message()
        );
        assert!(error.message().contains("a.txt"), "the object is named");
    }

    #[tokio::test]
    async fn blake3_from_the_index_is_not_a_substitute_for_authentication() {
        // The cost of the shortcut, stated as a test rather than left for a user
        // to discover: `hashsum blake3` over a vault answers from the index and
        // therefore reports the hash of a damaged object without noticing. That
        // is not a lie — the recorded hash *is* the file's hash — but it is why
        // `dctl verify` exists and why this command does not claim to verify.
        let (store, _index, path, vault) = sealed(&[("a.txt", b"one")]).await;
        damage_objects(store.path());
        let source = source_for(vault, path);

        let lines = run(&source, Algorithm::Blake3, &[])
            .await
            .expect("the index still answers");
        assert_eq!(lines[0].1, digest::of(Algorithm::Blake3, b"one"));

        // Asking for an algorithm the index does not hold reads the object, and
        // then the damage is found.
        assert_eq!(
            run(&source, Algorithm::Sha256, &[])
                .await
                .expect_err("the read authenticates")
                .code(),
            ExitCode::IntegrityFailure
        );
    }

    #[tokio::test]
    async fn filters_narrow_what_is_hashed() {
        // `dctl hashsum sha256 vault: --include '*.jpg' > SUMS` has to cover the
        // same objects `dctl ls --include '*.jpg'` listed.
        let (_root, source) = store(&[("a.jpg", b"1"), ("b.txt", b"22")]);
        let lines = run(&source, Algorithm::Sha256, &["--include", "*.jpg"])
            .await
            .expect("the walk succeeds");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].0, "a.jpg");
    }

    #[tokio::test]
    async fn an_empty_prefix_produces_an_empty_report_rather_than_a_failure() {
        // "There is nothing here" is an answer; the command decides whether an
        // empty checksum file is acceptable, not this walk.
        let (_root, source) = store(&[]);
        assert!(
            run(&source, Algorithm::Sha256, &[])
                .await
                .expect("an empty listing still succeeds")
                .is_empty()
        );
    }
}
