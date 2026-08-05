//! Creating a directory, where there is one to create.
//!
//! The whole command reduces to a single question — *does this place have
//! directories?* — asked of [`Place`] and answered from the configuration alone.
//! Only one of the three answers involves doing anything.
//!
//! ## A filesystem remote: the ordinary case, with `mkdir(1)`'s division of
//! labour
//!
//! `create_dir` for one directory, `create_dir_all` for `--parents`, and the
//! difference between them is the difference the flag has always meant: without
//! it a missing parent is an error the operating system reports, with it the
//! chain is made. `--parents` additionally makes an existing directory a success
//! rather than an error, again matching `mkdir -p`, because a script that runs
//! twice must not fail the second time.
//!
//! ## A vault or an object store: nothing to create, said out loud
//!
//! Neither has directories. A path there is a shared prefix among keys, which
//! exists exactly while an object is stored under it — so there is no state to
//! establish, nothing is missing when the command returns, and the postcondition
//! the user wants (an object may now be stored at this path) already held before
//! they typed it. That is reported as [`Outcome::NotRequired`] with the reason
//! attached, never as `created`: a script checking for the word `created` must
//! not be told a directory was made when none was.
//!
//! The rejected alternatives are worth naming, because both look reasonable:
//!
//! * **Refusing.** `mkdir` would then fail on the one backend the tool exists
//!   for, breaking `mkdir && copy` for a condition that is not an error. A
//!   command that refuses when its postcondition already holds teaches its users
//!   to ignore its exit code.
//! * **Writing a marker object.** `<dir>/.dctl-dir` would put a file into the
//!   user's namespace that `ls`, `size`, `check`, `sync`, `hashsum` and every
//!   restore would carry as data. Fabricating a file to simulate a directory is
//!   a larger misreport than the absence it hides — see
//!   [`DIRECTORY_MARKER_NAME`](crate::constants::DIRECTORY_MARKER_NAME).
//!
//! ## Why a vault is not asked for a password
//!
//! Because the answer does not depend on its contents. Unlocking to discover
//! that there is nothing to do would put a password prompt in the middle of a
//! script for no result, and [the plan](https://doc.dctl.sh/project/plan)
//! §14's headless case would fail on a command that never needed a credential.

use std::path::Path;

use crate::commands::directory::{Outcome, Target};
use crate::constants::DIRECTORY_NOTHING_TO_CREATE;
use crate::ctx::Ctx;
use crate::error::{CliError, Result};
use crate::platform::path as logical;
use crate::remote::Place;

use super::chain::PlannedDirectory;

/// Create `chain` in `place`, reporting what actually happened.
///
/// The chain is applied in order, so every parent exists before its child; for a
/// place with no directories the chain is not walked at all, because walking it
/// would still create nothing and the report would be the same.
///
/// # Errors
/// [`ExitCode::FatalError`](crate::exit::ExitCode::FatalError) when the
/// configuration claims the destination for a vault's object store, and whatever
/// the operating system reported — a missing parent without `--parents`
/// ([`ExitCode::FileNotFound`](crate::exit::ExitCode::FileNotFound)), a
/// permission failure, or a file already occupying the name.
pub fn create(
    ctx: &Ctx,
    place: &Place,
    target: &Target,
    chain: &[PlannedDirectory],
    parents: bool,
) -> Result<Outcome> {
    // Matched exhaustively rather than tested with a predicate, so a kind of
    // place added later has to state its answer here instead of inheriting
    // whichever one this branch happened to have.
    let (root, path) = match place {
        // Nothing to do, and — importantly — nothing to open in order to find
        // that out. The caller reports it with the reason attached.
        Place::Sealed | Place::ObjectStore { .. } => return Ok(Outcome::NotRequired),
        Place::Filesystem { root, path } => (root, path),
    };

    // A directory inside a vault's object store is still something appearing in
    // a namespace that belongs to a vault, so the addressing rule applies to it
    // exactly as it applies to a file. Asked before anything is created, from
    // the configuration rather than from what the directory currently holds.
    let root_of_write = logical::from_logical(root, path);
    crate::addressing::refuse_plain_write_to_path(ctx, &root_of_write)?;

    // The chain's paths are relative to the *remote*, and `path` is where the
    // target sits inside it. Both are needed: a configured remote may address a
    // prefix, and joining only one of the two lands the directory in the wrong
    // tree.
    let prefix = trim_target_prefix(&target.path, path);

    let mut outcome = Outcome::Created;
    for directory in chain {
        let relative = logical::join(prefix, &directory.path);
        outcome = create_one(&logical::from_logical(root, &relative), parents)?;
    }
    Ok(outcome)
}

/// The part of a resolved path that precedes the target's own logical path.
///
/// For every remote the resolver produces today the two are equal (a configured
/// local remote's path *is* the target's path), so this is the empty string and
/// the join below is the identity. It is computed rather than assumed because
/// the day a remote carries a prefix of its own, silently dropping it would
/// create the directory one tree away from where the user named it — and that
/// failure is invisible until a restore.
fn trim_target_prefix<'a>(target_path: &str, resolved_path: &'a str) -> &'a str {
    match resolved_path.strip_suffix(target_path) {
        Some(prefix) => prefix.trim_end_matches(crate::constants::PATH_SEPARATOR),
        None => resolved_path,
    }
}

/// Create one directory, honouring `mkdir(1)`'s two behaviours.
fn create_one(path: &Path, parents: bool) -> Result<Outcome> {
    if parents {
        // `create_dir_all` is idempotent by design, which is what `-p` promises:
        // a script that runs twice succeeds twice.
        std::fs::create_dir_all(path).map_err(|error| at(path, error))?;
        return Ok(Outcome::Created);
    }

    match std::fs::create_dir(path) {
        Ok(()) => Ok(Outcome::Created),
        // Without `-p`, `mkdir(1)` fails on an existing directory. DCTL reports
        // it as a success with a distinct outcome instead: the caller asked for
        // the directory to exist, it does, and nothing was written — which is
        // more information than an error code and less noise than a failure a
        // runbook has to special-case. A *file* of that name is still an error,
        // because that postcondition genuinely does not hold.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if path.is_dir() {
                Ok(Outcome::AlreadyPresent)
            } else {
                Err(CliError::usage(format!(
                    "'{}' exists and is not a directory",
                    path.display()
                ))
                .with_hint("Remove it, or name a directory that mkdir may create."))
            }
        }
        Err(error) => Err(at(path, error)),
    }
}

/// Attach the offending path to an operating-system failure.
///
/// `create_dir` reports "No such file or directory" with no indication of
/// *which* one, and the answer a user needs is the parent that is missing.
fn at(path: &Path, error: std::io::Error) -> CliError {
    CliError::from(error).with_hint(format!("creating {}", path.display()))
}

/// The sentence explaining a [`Outcome::NotRequired`] result.
///
/// Built here rather than at the call site so `mkdir` says the same thing about
/// a vault and about a bucket — they are the same fact about keys and prefixes,
/// and two wordings would suggest two different situations.
#[must_use]
pub fn nothing_to_create(place: &Place) -> String {
    format!("{} {DIRECTORY_NOTHING_TO_CREATE}", place.label())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::directory::testing::ctx;
    use crate::exit::ExitCode;

    fn target(spec: &str) -> Target {
        Target::parse(spec, "directory").expect("a valid target")
    }

    /// A filesystem place rooted at a temporary directory, addressing `path`.
    fn filesystem(root: &Path, path: &str) -> Place {
        Place::Filesystem {
            root: root.to_path_buf(),
            path: path.to_string(),
        }
    }

    #[test]
    fn a_filesystem_directory_is_really_created() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let target = target("scratch:photos");
        let chain = super::super::chain::build(&target, false);

        let outcome = create(
            &ctx(&[]),
            &filesystem(root.path(), "photos"),
            &target,
            &chain,
            false,
        )
        .expect("the directory is created");

        assert_eq!(outcome, Outcome::Created);
        assert!(root.path().join("photos").is_dir(), "nothing was created");
    }

    #[test]
    fn parents_creates_the_whole_chain_and_repeats_cleanly() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let target = target("scratch:a/b/c");
        let chain = super::super::chain::build(&target, true);
        let place = filesystem(root.path(), "a/b/c");

        assert_eq!(
            create(&ctx(&[]), &place, &target, &chain, true).unwrap(),
            Outcome::Created
        );
        assert!(root.path().join("a/b/c").is_dir());
        // `-p` is idempotent: a runbook that runs twice must not fail the second
        // time.
        assert!(create(&ctx(&[]), &place, &target, &chain, true).is_ok());
    }

    #[test]
    fn a_missing_parent_without_the_flag_is_the_operating_systems_error() {
        // The division of labour `mkdir(1)` has always had: without `-p` the
        // chain is not made, and the failure names the path that could not be
        // created.
        let root = tempfile::tempdir().expect("a temporary directory");
        let target = target("scratch:a/b/c");
        let chain = super::super::chain::build(&target, false);

        let error = create(
            &ctx(&[]),
            &filesystem(root.path(), "a/b/c"),
            &target,
            &chain,
            false,
        )
        .expect_err("the parent does not exist");

        assert_eq!(error.code(), ExitCode::FileNotFound);
        assert!(error.hint().is_some_and(|hint| hint.contains("a/b/c")));
    }

    #[test]
    fn an_existing_directory_is_reported_as_present_rather_than_created() {
        // The two must be distinguishable: a script that counts creations would
        // otherwise count directories that were already there.
        let root = tempfile::tempdir().expect("a temporary directory");
        std::fs::create_dir(root.path().join("photos")).expect("the fixture");
        let target = target("scratch:photos");
        let chain = super::super::chain::build(&target, false);

        let outcome = create(
            &ctx(&[]),
            &filesystem(root.path(), "photos"),
            &target,
            &chain,
            false,
        )
        .unwrap();
        assert_eq!(outcome, Outcome::AlreadyPresent);
    }

    #[test]
    fn a_file_in_the_way_is_an_error_and_is_not_replaced() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let occupied = root.path().join("photos");
        std::fs::write(&occupied, b"a real file").expect("the fixture");
        let target = target("scratch:photos");
        let chain = super::super::chain::build(&target, false);

        let error = create(
            &ctx(&[]),
            &filesystem(root.path(), "photos"),
            &target,
            &chain,
            false,
        )
        .expect_err("a file is not a directory");

        assert_eq!(error.code(), ExitCode::Usage);
        assert_eq!(
            std::fs::read(&occupied).unwrap(),
            b"a real file",
            "the file must survive the refusal"
        );
    }

    #[tokio::test]
    async fn a_place_without_directories_creates_nothing_and_says_so() {
        // Both of them, and neither is reached through a backend: the answer is
        // a property of the place, so no password and no request is involved.
        let target = target("archive:photos/2024");
        let chain = super::super::chain::build(&target, true);

        for place in [
            Place::Sealed,
            Place::ObjectStore {
                provider: crate::constants::PROVIDER_B2,
            },
        ] {
            let outcome = create(&ctx(&[]), &place, &target, &chain, true).unwrap();
            assert_eq!(outcome, Outcome::NotRequired);
            assert_ne!(outcome, Outcome::Created, "nothing was created");
            assert!(nothing_to_create(&place).contains(place.label()));
        }
    }

    #[test]
    fn a_resolved_prefix_is_not_applied_twice() {
        // The resolver's path already contains the target's path for every
        // remote that exists today, so the join must be the identity — repeating
        // it would create `photos/photos`.
        assert_eq!(trim_target_prefix("photos/2024", "photos/2024"), "");
        assert_eq!(trim_target_prefix("2024", "photos/2024"), "photos");
        // An unrelated resolved path is used as given rather than guessed at.
        assert_eq!(trim_target_prefix("2024", "elsewhere"), "elsewhere");
    }
}
