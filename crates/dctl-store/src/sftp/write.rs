//! The verified staged write, in the order it happens, over [`RemoteFs`].
//!
//! One function per source shape — bytes already in hand ([`put_bytes`]) and a
//! stream of unknown size in memory terms ([`put_stream`]) — sharing one tail
//! ([`publish`]), because the tail is where the guarantees are:
//!
//! 1. nothing is written until the bytes are proven to match the caller's hash
//!    (for a stream, until the last chunk has gone past the hasher);
//! 2. everything is written to a **staging sibling**, never to the object's own
//!    name, so no reader can observe a partial object;
//! 3. the source's own modification time is applied to the staging path
//!    **before** the rename, so the object appears at its final name already
//!    carrying it and the next run's comparison finds it unchanged rather than
//!    re-uploading it forever;
//! 4. the rename is the commit, and it is last;
//! 5. every failure between (2) and (4) removes the staging file, so a failed
//!    write leaves nothing behind — not even a name.
//!
//! Written against the trait rather than the client so all five are provable
//! with no network in reach; see [`super::ops`] for why that mattered enough to
//! restructure the backend.

use std::time::SystemTime;

use tokio::io::{AsyncRead, AsyncReadExt as _};

use crate::checksum::{ContentHash, Hasher};
use crate::error::{Result, StoreError};
use crate::model::PutOutcome;
use crate::modified::SourceModified;

use super::ops::{RemoteFs, StagedFile, times};
use super::path::{chunk_spans, temp_path};

/// Store `data` at `remote`, verified, atomically, carrying `modified`.
///
/// The hash is checked **before** anything is opened: a caller whose declared
/// hash does not describe its own bytes has a defect that no amount of writing
/// will fix, and staging first would mean creating and then removing a file to
/// learn it.
pub(super) async fn put_bytes<F: RemoteFs>(
    fs: &F,
    remote: &str,
    data: &[u8],
    expected: &ContentHash,
    modified: SourceModified,
) -> Result<PutOutcome> {
    let computed = ContentHash::compute(expected.algo, data);
    if !computed.matches(expected) {
        return Err(StoreError::ChecksumMismatch {
            expected: expected.hex(),
            actual: computed.hex(),
        });
    }

    fs.mkdir_p(remote).await;
    let tmp = temp_path(remote);
    let mut file = fs.create(&tmp).await?;

    if let Err(e) = file.write_all(data).await {
        drop(file);
        fs.remove_quiet(&tmp).await;
        return Err(e);
    }

    publish(fs, file, &tmp, remote, modified).await?;
    Ok(PutOutcome {
        size: data.len() as u64,
        verified: computed,
    })
}

/// Store `total` bytes read from `source` at `remote`, verified, atomically,
/// carrying `modified`.
///
/// Peak memory is `O(chunk)` regardless of object size, which is the whole
/// reason this exists beside [`put_bytes`]. The hash is folded chunk by chunk
/// and compared before the flush, so a source that changed under the read is
/// caught with nothing committed.
pub(super) async fn put_stream<F, R>(
    fs: &F,
    remote: &str,
    source: &mut R,
    total: u64,
    chunk: u64,
    expected: &ContentHash,
    modified: SourceModified,
) -> Result<PutOutcome>
where
    F: RemoteFs,
    R: AsyncRead + Unpin + Send,
{
    fs.mkdir_p(remote).await;
    let tmp = temp_path(remote);
    let mut file = fs.create(&tmp).await?;

    let mut hasher = Hasher::new(expected.algo);
    let mut buf = vec![0u8; chunk.max(1) as usize];
    for span in chunk_spans(total, chunk) {
        let n = span.len as usize;
        if let Err(e) = source.read_exact(&mut buf[..n]).await {
            drop(file);
            fs.remove_quiet(&tmp).await;
            return Err(e.into());
        }
        hasher.update(&buf[..n]);
        if let Err(e) = file.write_all(&buf[..n]).await {
            drop(file);
            fs.remove_quiet(&tmp).await;
            return Err(e);
        }
    }

    let computed = hasher.finalize();
    if !computed.matches(expected) {
        drop(file);
        fs.remove_quiet(&tmp).await;
        return Err(StoreError::ChecksumMismatch {
            expected: expected.hex(),
            actual: computed.hex(),
        });
    }

    publish(fs, file, &tmp, remote, modified).await?;
    Ok(PutOutcome {
        size: total,
        verified: computed,
    })
}

/// Flush, close, stamp, rename — and remove the staging file if any of them
/// fails.
///
/// The stamp is not optional-in-spirit even though it is optional-in-fact: a
/// failure is reported rather than swallowed. The bytes are already correct at
/// this point, so publishing anyway is tempting — and it is exactly what makes
/// the next run find the object different, transfer it again, and go on doing
/// that forever with nothing on either stream to explain it. When the writer had
/// no representable time there is nothing to send and the call is skipped; see
/// [`times`] for which times those are.
async fn publish<F: RemoteFs>(
    fs: &F,
    mut file: F::File,
    tmp: &str,
    remote: &str,
    modified: SourceModified,
) -> Result<()> {
    if let Err(e) = file.sync().await {
        drop(file);
        fs.remove_quiet(tmp).await;
        return Err(e);
    }
    if let Err(e) = file.close().await {
        fs.remove_quiet(tmp).await;
        return Err(e);
    }

    if let Some(stamp) = times(modified, SystemTime::now()) {
        if let Err(e) = fs.set_times(tmp, stamp).await {
            fs.remove_quiet(tmp).await;
            return Err(e);
        }
    }

    if let Err(e) = fs.rename(tmp, remote).await {
        fs.remove_quiet(tmp).await;
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sftp::ops::Times;
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    /// 2020-01-01T00:00:00Z. Far from any clock these tests can run against, so
    /// a write that quietly stamped "now" cannot pass by accident.
    const AGED: i64 = 1_577_836_800;

    /// The object path every test writes to.
    const REMOTE: &str = "nested/dir/object.bin";

    /// One thing the write asked the remote filesystem to do.
    ///
    /// A recorded call rather than a resulting state, because the properties
    /// under test are about *order*: a `SetTimes` issued after the rename stamps
    /// the published object, and a snapshot taken at the end cannot tell that
    /// from a `SetTimes` issued before it. One of the two is observable by a
    /// concurrent reader and re-transferred by the next run; the other is not.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Call {
        MkdirP(String),
        Create(String),
        Write(usize),
        Sync,
        Close,
        SetTimes(String, u32),
        Rename(String, String),
        Remove(String),
    }

    /// Which operation the fake should fail, to exercise one cleanup path.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FailAt {
        Create,
        Write,
        Sync,
        Close,
        SetTimes,
        Rename,
    }

    /// The recorded sequence, shared between the filesystem and the handles it
    /// hands out so both appear in one list in the order they really happened.
    #[derive(Clone, Default)]
    struct Journal {
        calls: Arc<Mutex<Vec<Call>>>,
        fail_at: Option<FailAt>,
    }

    impl Journal {
        fn note(&self, call: Call) {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push(call);
            }
        }

        fn refuse(&self, op: FailAt) -> Result<()> {
            if self.fail_at == Some(op) {
                return Err(StoreError::Backend(format!("fake failure at {op:?}")));
            }
            Ok(())
        }
    }

    /// A remote filesystem that records what it was asked to do and touches
    /// nothing.
    #[derive(Clone, Default)]
    struct Fake {
        journal: Journal,
    }

    impl Fake {
        fn failing_at(op: FailAt) -> Self {
            Self {
                journal: Journal {
                    calls: Arc::default(),
                    fail_at: Some(op),
                },
            }
        }

        fn calls(&self) -> Vec<Call> {
            self.journal
                .calls
                .lock()
                .map(|calls| calls.clone())
                .unwrap_or_default()
        }

        /// The staging path this write used, taken from the call it made rather
        /// than recomputed — `temp_path` is unique per call, so a test that
        /// derived its own would be asserting against a different name.
        fn staging(&self) -> String {
            self.calls()
                .into_iter()
                .find_map(|call| match call {
                    Call::Create(path) => Some(path),
                    _ => None,
                })
                .expect("the write must have staged something")
        }

        fn published(&self) -> bool {
            self.calls()
                .iter()
                .any(|call| matches!(call, Call::Rename(_, to) if to == REMOTE))
        }

        fn removed(&self, path: &str) -> bool {
            self.calls()
                .iter()
                .any(|call| matches!(call, Call::Remove(p) if p == path))
        }
    }

    /// A staging handle onto the same journal, so writes and closes interleave
    /// with the directory operations rather than accumulating in a second list.
    struct FakeFile {
        journal: Journal,
    }

    #[async_trait]
    impl StagedFile for FakeFile {
        async fn write_all(&mut self, data: &[u8]) -> Result<()> {
            self.journal.note(Call::Write(data.len()));
            self.journal.refuse(FailAt::Write)
        }
        async fn sync(&mut self) -> Result<()> {
            self.journal.note(Call::Sync);
            self.journal.refuse(FailAt::Sync)
        }
        async fn close(self) -> Result<()> {
            self.journal.note(Call::Close);
            self.journal.refuse(FailAt::Close)
        }
    }

    #[async_trait]
    impl RemoteFs for Fake {
        type File = FakeFile;

        async fn mkdir_p(&self, remote_file: &str) {
            self.journal.note(Call::MkdirP(remote_file.to_string()));
        }

        async fn create(&self, remote: &str) -> Result<Self::File> {
            self.journal.note(Call::Create(remote.to_string()));
            self.journal.refuse(FailAt::Create)?;
            Ok(FakeFile {
                journal: self.journal.clone(),
            })
        }

        async fn set_times(&self, remote: &str, times: Times) -> Result<()> {
            self.journal
                .note(Call::SetTimes(remote.to_string(), times.modified));
            self.journal.refuse(FailAt::SetTimes)
        }

        /// Refuses *before* recording, unlike every other operation here, and
        /// the asymmetry is deliberate: a `Rename` in the journal is what
        /// [`Fake::published`] reads as "the object exists under its name". A
        /// rename that the server rejected published nothing, so recording it
        /// would make the failure test assert against a lie of its own making.
        async fn rename(&self, from: &str, to: &str) -> Result<()> {
            self.journal.refuse(FailAt::Rename)?;
            self.journal
                .note(Call::Rename(from.to_string(), to.to_string()));
            Ok(())
        }

        async fn remove_quiet(&self, remote: &str) {
            self.journal.note(Call::Remove(remote.to_string()));
        }
    }

    fn blake3(data: &[u8]) -> ContentHash {
        ContentHash::blake3(data)
    }

    /// The property `sync` is incremental because of, on the backend where the
    /// only previous witness needed an ssh host.
    ///
    /// A `SETSTAT` that never happened would leave the server's write time on
    /// every object, the next run would compare each one against its source,
    /// find a difference, and upload it again — forever, with nothing on either
    /// stream to say why. Deleting the `set_times` call, or the modification
    /// time inside it, turns this red in `cargo test --workspace`, which is
    /// exactly what `HANDOVER.md` §15.4 could not say before.
    #[tokio::test]
    async fn a_write_stamps_the_source_time_on_the_staging_path_before_the_rename() {
        let fake = Fake::default();
        let data = b"written now, modified in 2020";

        put_bytes(&fake, REMOTE, data, &blake3(data), SourceModified::at(AGED))
            .await
            .expect("the write succeeds");

        let tmp = fake.staging();
        assert_ne!(tmp, REMOTE, "the bytes must never be written to the name");
        assert_eq!(
            fake.calls(),
            vec![
                Call::MkdirP(REMOTE.to_string()),
                Call::Create(tmp.clone()),
                Call::Write(data.len()),
                Call::Sync,
                Call::Close,
                // On the staging path, and before the rename: the object
                // therefore appears at its final name already carrying the
                // source's time, and no listing can observe it carrying the
                // server's.
                Call::SetTimes(tmp.clone(), AGED as u32),
                Call::Rename(tmp, REMOTE.to_string()),
            ]
        );
    }

    /// The streaming path is separate code and is what a large file takes, so a
    /// stamp applied only on the buffered path would make exactly the big files
    /// re-upload every night.
    #[tokio::test]
    async fn a_streamed_write_stamps_the_source_time_too() {
        let fake = Fake::default();
        let data = b"a source read in chunks";
        let mut source = &data[..];

        put_stream(
            &fake,
            REMOTE,
            &mut source,
            data.len() as u64,
            8,
            &blake3(data),
            SourceModified::at(AGED),
        )
        .await
        .expect("the streamed write succeeds");

        let tmp = fake.staging();
        let stamp = fake
            .calls()
            .into_iter()
            .position(|call| call == Call::SetTimes(tmp.clone(), AGED as u32))
            .expect("the streamed write must stamp the source's time");
        let rename = fake
            .calls()
            .into_iter()
            .position(|call| matches!(call, Call::Rename(_, _)))
            .expect("and must publish");
        assert!(stamp < rename, "and must stamp before it publishes");
    }

    #[tokio::test]
    async fn a_streamed_write_never_holds_more_than_one_chunk() {
        // The reason this path exists at all. A single `Write` of the whole
        // total would still pass every other assertion here.
        let fake = Fake::default();
        let data: Vec<u8> = (0..=200u8).collect();
        let mut source = &data[..];

        put_stream(
            &fake,
            REMOTE,
            &mut source,
            data.len() as u64,
            32,
            &blake3(&data),
            SourceModified::unknown(),
        )
        .await
        .expect("the streamed write succeeds");

        let writes: Vec<usize> = fake
            .calls()
            .into_iter()
            .filter_map(|call| match call {
                Call::Write(n) => Some(n),
                _ => None,
            })
            .collect();
        assert!(writes.len() > 1, "got {writes:?}");
        assert!(writes.iter().all(|n| *n <= 32), "got {writes:?}");
        assert_eq!(writes.iter().sum::<usize>(), data.len());
    }

    #[tokio::test]
    async fn an_unknown_time_stamps_nothing_and_still_publishes() {
        // Substituting the epoch would date the object 1970, which makes it look
        // older than every local file and inverts `--update` over all of them.
        let fake = Fake::default();
        let data = b"no time to record";

        put_bytes(
            &fake,
            REMOTE,
            data,
            &blake3(data),
            SourceModified::unknown(),
        )
        .await
        .expect("the write succeeds");

        assert!(
            !fake
                .calls()
                .iter()
                .any(|call| matches!(call, Call::SetTimes(_, _))),
            "got {:?}",
            fake.calls()
        );
        assert!(fake.published());
    }

    #[tokio::test]
    async fn a_time_the_protocol_cannot_hold_publishes_without_a_stamp() {
        // Pre-1970 has no representation in SFTP v3's unsigned seconds. The
        // object keeps the server's time and is re-transferred next run — a
        // cost. A wrapped value would be a confident, fabricated date instead.
        let fake = Fake::default();
        let data = b"dated 1969";

        put_bytes(&fake, REMOTE, data, &blake3(data), SourceModified::at(-1))
            .await
            .expect("the write still succeeds");

        assert!(
            !fake
                .calls()
                .iter()
                .any(|call| matches!(call, Call::SetTimes(_, _)))
        );
        assert!(fake.published());
    }

    #[tokio::test]
    async fn bytes_that_do_not_match_their_declared_hash_are_never_opened() {
        let fake = Fake::default();
        let error = put_bytes(
            &fake,
            REMOTE,
            b"actual",
            &blake3(b"different"),
            SourceModified::at(AGED),
        )
        .await
        .expect_err("a mismatch must refuse");

        assert!(matches!(error, StoreError::ChecksumMismatch { .. }));
        assert!(
            fake.calls().is_empty(),
            "nothing may be created to learn this: {:?}",
            fake.calls()
        );
    }

    #[tokio::test]
    async fn a_stream_that_changed_under_the_read_is_removed_not_published() {
        // The source is hashed as it goes past, so bytes that do not add up to
        // the declared digest are caught with the staging file still unnamed.
        let fake = Fake::default();
        let data = b"what was actually read";
        let mut source = &data[..];

        let error = put_stream(
            &fake,
            REMOTE,
            &mut source,
            data.len() as u64,
            8,
            &blake3(b"what the caller declared"),
            SourceModified::at(AGED),
        )
        .await
        .expect_err("a mismatch must refuse");

        assert!(matches!(error, StoreError::ChecksumMismatch { .. }));
        assert!(!fake.published(), "nothing may be committed");
        assert!(fake.removed(&fake.staging()), "and nothing may be left");
    }

    #[tokio::test]
    async fn every_failure_removes_the_staging_file_and_publishes_nothing() {
        // Including the stamp. A failed `SETSTAT` used to be the tempting one to
        // ignore — the bytes are already correct by then — and ignoring it is
        // what makes the next run transfer the file again, and the run after
        // that, with nothing anywhere to explain it.
        for op in [
            FailAt::Create,
            FailAt::Write,
            FailAt::Sync,
            FailAt::Close,
            FailAt::SetTimes,
            FailAt::Rename,
        ] {
            let fake = Fake::failing_at(op);
            let data = b"a write that will not complete";

            let error = put_bytes(&fake, REMOTE, data, &blake3(data), SourceModified::at(AGED))
                .await
                .expect_err(&format!("{op:?} must fail the write"));
            assert!(matches!(error, StoreError::Backend(_)), "{op:?}");

            assert!(!fake.published(), "{op:?} published anyway");
            let tmp = fake.staging();
            if op == FailAt::Create {
                // Nothing was opened, so there is nothing to remove.
                assert!(!fake.removed(&tmp), "{op:?}");
            } else {
                assert!(fake.removed(&tmp), "{op:?} left {tmp} behind");
            }
        }
    }

    #[tokio::test]
    async fn the_write_reports_what_it_stored() {
        let fake = Fake::default();
        let data = b"seventeen bytes!!";
        let outcome = put_bytes(
            &fake,
            REMOTE,
            data,
            &blake3(data),
            SourceModified::unknown(),
        )
        .await
        .expect("the write succeeds");
        assert_eq!(outcome.size, data.len() as u64);
        assert!(outcome.verified.matches(&blake3(data)));
    }
}
