//! What a mounted vault writes into the tamper-evident chain.
//!
//! Every other verb that moves object content appends a record; a mount served
//! decrypted plaintext to anything that could read a filesystem and appended
//! nothing at all. `audit/coverage.rs` called that "the largest remaining hole
//! in the audit story" and kept its own table green with an `Exempt` row, which
//! is an honest note about a dishonest silence: an operator asking *what left
//! this vault* got an answer that omitted every byte a mount had handed out.
//!
//! ## Two records, and why not one per read
//!
//! A FUSE read is 128 KiB. A film is a hundred thousand of them, each costing
//! an `fsync` — the chain would become a write amplifier that made the mount
//! unusable and buried the interesting facts under its own noise. The shape
//! settled on instead:
//!
//! * **One session record**, when the filesystem attaches: this vault, this
//!   subtree, from now until it is unmounted. It moves nothing, so it carries
//!   no direction and no bytes.
//! * **One first-read record per object**, when a read of that object first
//!   returns bytes: direction `out`, and the window's length — exactly what
//!   `cat` records for a ranged read, and for the same reason. It is the
//!   answer to *which objects left*, which is the question the chain exists to
//!   answer; the byte total is a floor and says so.
//!
//! What that deliberately does not claim: the totals are not the mount's
//! egress. A reader that streams a whole film after its first window is
//! recorded once, for one window. Anything else costs an fsync per 128 KiB.
//!
//! ## Recorded before the bytes are served
//!
//! [`MountAudit::record_first_read`] appends *before* [`super::state`] hands
//! the window back, so an unwritable log fails the read (`EIO`) rather than
//! serving plaintext it could not account for. That is the sink's own policy —
//! if the log cannot be written, the command fails — applied to the one verb
//! that had been exempt from it, and it is strictly stronger than the
//! record-after-egress the other read verbs use.
//!
//! ## Where the fsync happens
//!
//! [`Sink::record`] is synchronous and ends in an `fsync`; the read path is a
//! Tokio task. Every append therefore goes through `spawn_blocking`, so no FUSE
//! read ever blocks a runtime worker on disk.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::audit::record::{Direction, Entry};
use crate::audit::sink::Sink;
use crate::constants::MOUNT_AUDIT_SEEN_MAX;
use crate::error::Result;

/// The verb every mount record is attributed to.
const VERB: &str = "mount";

/// The chain-writing half of a mount.
pub struct MountAudit {
    /// Shared with the command that built it, because the session record is
    /// appended by the command and the read records by the filesystem.
    audit: Arc<Sink>,
    /// The remote whose objects these are, as the operator named it.
    remote: String,
    /// The subtree the mount serves, for the session record's path.
    root: String,
    /// Objects already recorded this session, with the tick they were last
    /// touched at.
    seen: Mutex<Seen>,
    /// How many objects the set holds before it starts forgetting.
    capacity: usize,
}

/// The dedup set: which objects have been recorded, and how recently each was
/// used.
#[derive(Default)]
struct Seen {
    objects: HashMap<String, u64>,
    tick: u64,
}

impl MountAudit {
    /// The recorder for a mount of `root` inside `remote`.
    #[must_use]
    pub fn new(audit: Arc<Sink>, remote: impl Into<String>, root: impl Into<String>) -> Self {
        Self {
            audit,
            remote: remote.into(),
            root: root.into(),
            seen: Mutex::new(Seen::default()),
            capacity: MOUNT_AUDIT_SEEN_MAX,
        }
    }

    /// The same, forgetting after `capacity` objects.
    ///
    /// `cfg(test)` because the only reason to shrink it is to reach the
    /// eviction path without recording sixty-five thousand objects first.
    #[cfg(test)]
    #[must_use]
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity.max(1);
        self
    }

    /// Record that a filesystem is now serving this vault.
    ///
    /// Appended once, when the mount attaches. No direction and no bytes: the
    /// session has moved nothing, and `bytes` is a measurement rather than a
    /// plan ([the audit-log reference](https://doc.dctl.sh/reference/audit-log)
    /// §2.2).
    ///
    /// # Errors
    /// Whatever [`Sink::record`] refused. The caller drops the mount on the
    /// error, so a filesystem never serves a window the chain has no session
    /// record for.
    pub fn record_session(&self) -> Result<()> {
        self.audit.record(
            &Entry::new(VERB, crate::exit::ExitCode::Success)
                .path(&self.root)
                .remote(&self.remote),
        )
    }

    /// Record the first read of `path`, if it has not been recorded already.
    ///
    /// `bytes` is the window that was read — the honest answer to how much of
    /// the object left on the read that triggered the record, and a floor on
    /// what a reader went on to take.
    ///
    /// # Errors
    /// Whatever [`Sink::record`] refused. The reservation is released on
    /// failure, so the next read of the same object tries again rather than
    /// treating an unwritten record as written.
    pub async fn record_first_read(&self, path: &str, bytes: u64) -> Result<()> {
        if !self.reserve(path) {
            return Ok(());
        }

        let entry = Entry::new(VERB, crate::exit::ExitCode::Success)
            .path(path)
            .size(bytes)
            .moved(Direction::Out, bytes)
            .objects(1)
            .remote(&self.remote);

        let audit = Arc::clone(&self.audit);
        // The append is a write plus an fsync. On the blocking pool, never on
        // a runtime worker — the FUSE callback has already returned by the
        // time this runs, but the worker it runs on is still serving every
        // other read.
        let appended = tokio::task::spawn_blocking(move || audit.record(&entry)).await;

        match appended {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                self.release(path);
                Err(error)
            }
            Err(join) => {
                self.release(path);
                Err(crate::error::CliError::new(
                    crate::exit::ExitCode::FatalError,
                    format!("the audit record for '{path}' could not be written: {join}"),
                ))
            }
        }
    }

    /// Claim the first-read record for `path`, or report that somebody already
    /// has it. Evicts the least recently used entry when the set is full.
    ///
    /// Eviction can only cost a *duplicate* record for an object read again
    /// much later — an overcount in a log whose totals are already a floor —
    /// and never a missing one, which is the direction that would matter.
    fn reserve(&self, path: &str) -> bool {
        let mut seen = self.seen();
        seen.tick = seen.tick.wrapping_add(1);
        let tick = seen.tick;
        if let Some(used) = seen.objects.get_mut(path) {
            *used = tick;
            return false;
        }
        while seen.objects.len() >= self.capacity {
            let Some(oldest) = seen
                .objects
                .iter()
                .min_by_key(|(_, used)| **used)
                .map(|(path, _)| path.clone())
            else {
                break;
            };
            seen.objects.remove(&oldest);
        }
        seen.objects.insert(path.to_string(), tick);
        true
    }

    /// Give the claim back, so a failed append is retried rather than
    /// remembered as a success.
    fn release(&self, path: &str) {
        self.seen().objects.remove(path);
    }

    /// Lock the set, recovering from a poisoned mutex rather than failing.
    ///
    /// The same stance the mount's other locks take: nothing in a critical
    /// section here can panic, and turning a theoretical poisoning into a
    /// wedged filesystem would be the worse outcome.
    fn seen(&self) -> MutexGuard<'_, Seen> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::sink::Sink;
    use crate::cli::globals::GlobalArgs;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    /// A sink over a scratch chain — `Sink::new` is TempDir-backed under
    /// `cfg(test)`, so each of these gets a chain of its own.
    fn sink() -> Arc<Sink> {
        Arc::new(Sink::new(&Harness::parse_from(["dctl"]).globals))
    }

    /// A recorder over a scratch chain, plus the sink to read it back through.
    fn recorder() -> (Arc<Sink>, MountAudit) {
        let sink = sink();
        let audit = MountAudit::new(Arc::clone(&sink), "archive", "photos");
        (sink, audit)
    }

    /// The records the chain holds, as parsed JSON objects.
    fn records(sink: &Sink) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(sink.path()).expect("the chain reads");
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("a record"))
            .collect()
    }

    #[tokio::test]
    async fn a_session_record_says_which_vault_is_being_served_and_moves_nothing() {
        let (sink, audit) = recorder();
        audit.record_session().expect("the session records");

        let records = records(&sink);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["op"], "mount");
        assert_eq!(records[0]["path"], "photos");
        assert_eq!(records[0]["remote"], "archive");
        assert_eq!(
            records[0]["bytes"], 0,
            "a session has moved nothing yet, and bytes is a measurement"
        );
    }

    #[tokio::test]
    async fn the_first_read_of_an_object_is_recorded_and_the_rest_are_not() {
        let (sink, audit) = recorder();

        audit.record_first_read("a.mkv", 128 * 1024).await.unwrap();
        audit.record_first_read("a.mkv", 128 * 1024).await.unwrap();
        audit.record_first_read("a.mkv", 4096).await.unwrap();
        audit.record_first_read("b.jpg", 900).await.unwrap();

        let records = records(&sink);
        assert_eq!(
            records.len(),
            2,
            "one record per object, not one per 128 KiB window"
        );
        assert_eq!(records[0]["path"], "a.mkv");
        assert_eq!(records[0]["direction"], "out");
        assert_eq!(records[0]["bytes"], 128 * 1024);
        assert_eq!(records[0]["objects"], 1);
        assert_eq!(records[1]["path"], "b.jpg");
        assert_eq!(records[1]["bytes"], 900);
    }

    #[tokio::test]
    async fn a_record_that_could_not_be_written_is_retried_rather_than_assumed() {
        let sink = sink();
        let path = sink.path().to_path_buf();
        // A chain whose tail cannot be read is a chain nothing may be appended
        // to — the sink's own refusal, reached here on purpose.
        std::fs::write(&path, "{ not a record\n").expect("the corruption lands");
        let audit = MountAudit::new(Arc::clone(&sink), "archive", "photos");

        audit
            .record_first_read("a.mkv", 10)
            .await
            .expect_err("an unwritable chain fails the read");
        audit
            .record_first_read("a.mkv", 10)
            .await
            .expect_err("and the next read tries again rather than assuming");
    }

    #[tokio::test]
    async fn forgetting_an_object_costs_a_duplicate_and_never_a_silence() {
        let sink = sink();
        let audit = MountAudit::new(Arc::clone(&sink), "archive", "photos").with_capacity(1);

        audit.record_first_read("a.mkv", 1).await.unwrap();
        audit.record_first_read("b.jpg", 2).await.unwrap();
        // `a.mkv` was evicted to make room, so it is recorded again.
        audit.record_first_read("a.mkv", 3).await.unwrap();

        let records = records(&sink);
        assert_eq!(records.len(), 3);
        assert_eq!(records[2]["path"], "a.mkv");
    }
}
