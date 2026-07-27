//! What a stored copy can still tell you about the original it was made from.
//!
//! Every incremental verb in this tool — `copy`, `move`, `sync`, `check` — rests
//! on one question asked per file: *is what is over there already what is over
//! here?* The default answer is size plus modification time, because it costs
//! one metadata round trip and catches almost everything. It is also the answer
//! that quietly stops meaning anything the moment a destination cannot carry the
//! source's timestamp across.
//!
//! ## The case this module exists for, precisely
//!
//! A **sealed** vault cannot. `dctl_core::Vault::put_file(path, data)` takes a
//! logical path and the plaintext, and nothing else; the index record it commits
//! therefore stamps `now_unix()` as the modification time
//! (`dctl-core/src/vault/put.rs`). That value is a true statement about the
//! *write*, and it is not the source file's time and never was.
//!
//! The consequence was defect D5, and it was not subtle. `dctl copy ./src
//! archive:` stored three files and reported success; `dctl check ./src archive:`
//! immediately afterwards reported all three as differing; and the next `copy`
//! re-uploaded all three, forever, on every run. Nothing was broken in the
//! transfer — the bytes were correct on both sides — but the tool could not tell,
//! so it never skipped anything and never agreed with itself. An incremental
//! backup that is not incremental is a backup nobody runs twice.
//!
//! ## What is substituted, and why it is an upgrade rather than a fallback
//!
//! The same index record carries `content_hash`: the BLAKE3 of the plaintext,
//! taken at write time and stored for free. So a sealed side can answer the
//! *stronger* question — are the contents identical — even though it cannot
//! answer the weaker one. That is why this is not a downgrade dressed up: the
//! user asked "is this the same file?", the metadata comparison was one cheap way
//! to guess, and the vault happens to hold the definitive answer.
//!
//! It is not free. The other side is a local tree with no recorded hash, so it
//! has to be read end to end to produce one, which is roughly the cost of the
//! transfer this comparison exists to avoid. That is why the substitution is
//! announced rather than performed quietly
//! ([`WRITE_TIME_COMPARISON_NOTICE`](crate::constants::WRITE_TIME_COMPARISON_NOTICE)):
//! a user who asked for the cheap comparison must be told they are getting the
//! expensive one, and told which side forced it.
//!
//! ## What is *not* substituted
//!
//! `--size-only` and `--checksum` are left exactly alone. Both are explicit
//! instructions, and neither is broken by a write-time timestamp: sizes need no
//! clock, and `--checksum` already asks the question this module falls back to.
//! Only the unspoken default is changed, because only the unspoken default was
//! answering something other than what it appeared to.
//!
//! ## Deleting this module
//!
//! It is compensation for one missing parameter, and it should not outlive it.
//! When `Vault::put_file` grows a modification time — taken from the source's
//! metadata and recorded in the index instead of `now_unix()` — a sealed side
//! becomes comparable by time like any other, [`writes_its_own_timestamp`] can
//! return `false` for every place, and this file and its two call sites
//! ([`crate::commands::transfer::prepare`] and [`crate::commands::check`]) go
//! away together. The `content_hash` comparison would still be available under
//! `--checksum`, where it belongs, rather than as a default nobody asked for.
//!
//! ## Why the classification is asked of `Place`
//!
//! Because "is this side sealed?" already has exactly one answer in this binary
//! and it is [`Place::of`], which reads the configuration and consults
//! [`RemoteDef::is_vault`](crate::config::RemoteDef::is_vault). Defect D4 was two
//! spellings of that question disagreeing; a third one written here would be the
//! same defect with a different symptom. Nothing in this module connects, opens
//! or unlocks anything — the answer comes from the configuration file, so
//! choosing a comparison costs no password prompt.

use crate::ctx::Ctx;
use crate::error::Result;
use crate::remote::{Place, RemoteSpec};

/// Whether a modification time read back from this side describes the *write*
/// rather than the source file it was made from.
///
/// True only for a sealed vault, and for the reason in the module documentation:
/// the core's `put_file` has no parameter to carry a source timestamp, so the
/// index records the moment of the write. Every other place is answered `false`
/// — not as a promise that its timestamps are faithful, but as the statement
/// that nothing about the *place* substitutes one, which is the only claim this
/// function is entitled to make.
///
/// # Errors
/// Whatever [`Place::of`] reported: an unreadable configuration, an unknown
/// remote, or one whose settings are incomplete. Callers that are about to list
/// the same side anyway may prefer to let the listing produce that diagnosis —
/// see [`comparing_by_time_is_meaningless`], which does exactly that.
pub fn writes_its_own_timestamp(ctx: &Ctx, spec: &RemoteSpec) -> Result<bool> {
    Ok(Place::of(ctx, spec)? == Place::Sealed)
}

/// Which of two sides, if either, makes a modification-time comparison
/// meaningless — as the user spelled it, so a message can name it.
///
/// The source is offered before the destination only so that a run with a sealed
/// side on each end names one of them rather than both; either would do, because
/// one is enough to make the comparison unanswerable.
///
/// **A classification failure is reported as "no such side" rather than as an
/// error**, and that is deliberate. This decides which comparison to run, and a
/// side whose configuration cannot even be classified is a side that is about to
/// fail to open a moment later, with a far better diagnosis than "could not pick
/// a comparison". Nothing is suppressed by doing so: there is no route that
/// reaches a transfer or a check without opening both sides.
#[must_use]
pub fn comparing_by_time_is_meaningless<'a>(
    ctx: &Ctx,
    source: &'a RemoteSpec,
    dest: &'a RemoteSpec,
) -> Option<&'a RemoteSpec> {
    [source, dest]
        .into_iter()
        .find(|spec| writes_its_own_timestamp(ctx, spec).unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::config::{Config, LocalDef, RemoteDef, VaultDef};
    use clap::Parser;
    use std::path::PathBuf;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    /// A context whose `--config` points at a written-out fixture.
    fn ctx_with(config: &Config) -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("dctl.toml");
        crate::config::save(config, &path).expect("the fixture config is written");
        let ctx =
            Ctx::new(Harness::parse_from(["dctl", "--config", &path.to_string_lossy()]).globals);
        (dir, ctx)
    }

    /// The pair `dctl init --name archive --base /srv/v` registers, plus an
    /// ordinary local remote that is nobody's vault.
    fn config() -> Config {
        let mut config = Config::default();
        config.insert(
            "archive-store",
            RemoteDef::Local(LocalDef {
                path: PathBuf::from("/srv/v"),
                verify: None,
                require_vault: true,
            }),
        );
        config.insert(
            "archive",
            RemoteDef::Vault(VaultDef {
                base: "archive-store".into(),
                base_path: None,
                chunk_size: None,
                verify: None,
            }),
        );
        config.insert(
            "backup",
            RemoteDef::Local(LocalDef {
                path: PathBuf::from("/mnt/backup"),
                verify: None,
                require_vault: false,
            }),
        );
        config
    }

    fn named(remote: &str) -> RemoteSpec {
        RemoteSpec::Named {
            remote: remote.to_string(),
            path: String::new(),
        }
    }

    fn local() -> RemoteSpec {
        RemoteSpec::Local(PathBuf::from("/tmp/src"))
    }

    #[test]
    fn only_a_sealed_side_stamps_its_own_write_time() {
        // The whole rule, and both halves matter. A vault answering `false`
        // would put D5 straight back; a plain remote answering `true` would make
        // every ordinary `copy` read its source twice for nothing.
        let (_dir, ctx) = ctx_with(&config());
        assert!(writes_its_own_timestamp(&ctx, &named("archive")).unwrap());
        assert!(!writes_its_own_timestamp(&ctx, &named("backup")).unwrap());
        assert!(!writes_its_own_timestamp(&ctx, &named("archive-store")).unwrap());
        assert!(!writes_its_own_timestamp(&ctx, &local()).unwrap());
    }

    #[test]
    fn a_sealed_side_is_found_on_either_end_of_the_transfer() {
        // `copy ./src archive:` and `copy archive: ./out` are the same problem
        // seen from two directions: in both, one side's timestamps describe the
        // write. A rule that only looked at the destination would leave every
        // download re-fetching the whole vault on every run.
        let (_dir, ctx) = ctx_with(&config());
        // The side handed back is the one that forced it, so the notice can name
        // it — telling a user their *source* directory stamps write times would
        // send them looking in the wrong place.
        let sealed = named("archive");
        assert_eq!(
            comparing_by_time_is_meaningless(&ctx, &local(), &sealed),
            Some(&sealed)
        );
        assert!(comparing_by_time_is_meaningless(&ctx, &named("archive"), &local()).is_some());
        assert!(comparing_by_time_is_meaningless(&ctx, &local(), &named("backup")).is_none());
        assert!(comparing_by_time_is_meaningless(&ctx, &local(), &local()).is_none());
    }

    #[test]
    fn an_unclassifiable_side_leaves_the_diagnosis_to_whoever_opens_it() {
        // "Could not choose a comparison" is a useless thing to tell someone who
        // typoed a remote name. The listing that follows says "no remote named
        // 'archiv'", which is the message that gets them moving — so this
        // declines to be the first to fail.
        let (_dir, ctx) = ctx_with(&config());
        assert!(writes_its_own_timestamp(&ctx, &named("archiv")).is_err());
        assert!(comparing_by_time_is_meaningless(&ctx, &local(), &named("archiv")).is_none());
    }
}
