//! What a verified staged write asks of the remote filesystem — and nothing else.
//!
//! # Why this seam exists
//!
//! [`Backend::put`](crate::Backend::put) and `put_from_path` used to call
//! [`openssh_sftp_client`] directly, so the *order* of a staged write — create,
//! write, flush, close, stamp the source's own modification time, rename — could
//! only be observed by connecting to a real `sshd`. It was observed there, by
//! `tests/sftp_live.rs`; and because that test is `#[ignore]`d and needs
//! `DCTL_SFTP_HOST`, deleting the stamp left `cargo test --workspace` entirely
//! green. A guarantee whose only witness needs credentials is a guarantee the
//! stated gate does not hold, and the gate is what every report in this project
//! quotes as proof.
//!
//! So the write is expressed against these two traits and driven, in
//! [`super::write`]'s tests, by a fake that records every call. The sequence, the
//! `SETSTAT` on the staging path *before* the rename, and the cleanup on each
//! failure are all asserted with no network in reach.
//!
//! # What is deliberately not here
//!
//! Reads, listings and deletes stay on [`SftpBackend`] against the real client.
//! This trait is exactly the write path's surface: widening it to "the SFTP
//! operations" would grow a second, partial SFTP client that has to be kept in
//! step with the first, and the write path is where the §6 contract lives.

use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use openssh_sftp_client::file::File;
use openssh_sftp_client::metadata::MetaDataBuilder;
use openssh_sftp_client::{Error as SftpError, UnixTimeStamp};

use crate::deadline::IdleWatch;
use crate::error::{Result, StoreError};
use crate::modified::SourceModified;

use super::dial::Link;
use super::path::{ancestor_dirs_at_or_below, ancestor_dirs_below};
use super::{SftpBackend, map_sftp_err};

/// The access/modification pair a `SETSTAT` carries.
///
/// Both, always, because SFTP version 3 carries them as one
/// `SSH_FILEXFER_ATTR_ACMODTIME` attribute: an access time has to be supplied to
/// set a modification time at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Times {
    /// When the object was last read. The real clock, not a copy of `modified`:
    /// this run really did just write the file, and nothing in DCTL reads an
    /// access time, so the honest value costs nothing and the fabricated one
    /// buys nothing.
    pub accessed: u32,
    /// The source's own last-modified time — the whole point of the call.
    pub modified: u32,
}

/// The times to stamp on a freshly written object, or [`None`] when this
/// protocol cannot hold the one the writer gave.
///
/// Pure, and separated from the call that transmits it, because the rule it
/// encodes is the interesting part: SFTP version 3 stores both times as
/// **unsigned 32-bit seconds**, so a source modified before 1970 or after 2106
/// has no representation on the wire. Those are left unstamped and keep the
/// server's write time, which the next comparison reads as a difference and
/// re-transfers: a cost, never a wrong answer. Storing a wrapped value instead
/// would give the file a confident, fabricated date that every later run would
/// believe.
///
/// `now` is a parameter rather than read from the clock here so the whole
/// function is a total function of its inputs, testable at both ends of the
/// representable range. A `now` that is itself out of range (which happens in
/// 2106) falls back to the modification time rather than dropping the stamp: the
/// modification time is what the write exists to record.
pub(super) fn times(modified: SourceModified, now: SystemTime) -> Option<Times> {
    let modified = representable(modified.unix()?)?;
    let accessed = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|since| u32::try_from(since.as_secs()).ok())
        .unwrap_or(modified);
    Some(Times { accessed, modified })
}

/// Whole seconds as the wire can carry them, or [`None`] outside 1970–2106.
fn representable(unix_seconds: i64) -> Option<u32> {
    u32::try_from(unix_seconds).ok()
}

/// One staging file, open on the remote.
///
/// Taken by value at [`StagedFile::close`] because a handle is closed exactly
/// once: a second close on a published object would be a request the server
/// answers with an error nobody can act on.
#[async_trait]
pub(super) trait StagedFile: Send + Sized {
    /// Append `data` to the staging file.
    async fn write_all(&mut self, data: &[u8]) -> Result<()>;

    /// Force what has been written to the server's disk.
    ///
    /// May report that the server has no such capability without failing; see
    /// [`SftpBackend`]'s implementation for the one error this is allowed to
    /// tolerate and why every other one is fatal.
    async fn sync(&mut self) -> Result<()>;

    /// Close the handle, surfacing whatever the server reports.
    async fn close(self) -> Result<()>;
}

/// The remote directory operations a staged write needs.
#[async_trait]
pub(super) trait RemoteFs: Sync {
    /// The staging-file handle this filesystem hands out.
    type File: StagedFile;

    /// Realize `mkdir -p` for the parent of a remote **file** path, **below the
    /// configured base and never at or above it**.
    ///
    /// Infallible by design: an "already exists" on an intermediate directory is
    /// the ordinary case, and a genuinely un-writable parent surfaces when the
    /// subsequent create or rename fails, where the error can name what was
    /// being attempted. A base that is *not* there is one of those failures now,
    /// which is the point — see [`super::path::ancestor_dirs_below`].
    async fn mkdir_p(&self, remote_file: &str);

    /// Open a fresh remote file for writing (create + truncate).
    async fn create(&self, remote: &str) -> Result<Self::File>;

    /// Apply an access/modification pair to `remote`.
    async fn set_times(&self, remote: &str, times: Times) -> Result<()>;

    /// Atomically move `from` onto `to`.
    async fn rename(&self, from: &str, to: &str) -> Result<()>;

    /// Remove a path, ignoring any error — used to clean up a staging file on
    /// the failure paths, where the error that matters is the one already in
    /// hand.
    async fn remove_quiet(&self, remote: &str);
}

/// The staging handle over a live SFTP session.
pub(super) struct SftpStagedFile {
    file: File,
    /// The path, kept so an error names what failed rather than a file handle.
    remote: String,
    /// The conversation this handle was opened on.
    ///
    /// Held, and nothing reads it. An SFTP file handle is meaningful only to the
    /// session that issued it, so keeping the session alive for as long as the
    /// handle exists is what stops a re-dial elsewhere in the backend from
    /// closing the channel this writer is still streaming down. Dropping it here
    /// is what releases the last reference once the staging file is closed.
    #[allow(dead_code)]
    link: Arc<Link>,
    /// The inactivity deadline covering this object's whole write.
    ///
    /// One watch for the file rather than one per call, because an upload is one
    /// operation to the operator and a chunk landing is what proves it is still
    /// moving.
    ///
    /// Without it this path had **no deadline at all**. `RemoteFs::create`
    /// travelled through [`SftpBackend::on_link`] and every `write_all` after it
    /// did not, so a session that went quiet in the middle of an object hung for
    /// as long as TCP allowed — the one place in this backend where `--timeout`
    /// would have been a published claim reaching nothing. Found by asking where
    /// the bytes actually move rather than where the trait methods are.
    watch: IdleWatch,
}

/// What one step of a staged write does about its outcome.
///
/// Two things, and both are needed wherever bytes move. A step that succeeded is
/// progress, so the deadline starts again from full rather than from what is
/// left of this object's. A failure meaning the conversation has ended marks the
/// connection dead — and [`Link::mark_dead`] lives on the connection precisely so
/// this type can reach it: a staging file holds the link and not the backend, so
/// left unsaid the retry's `create` would open on the same dead session, fail,
/// and only then discard it. One attempt of six spent on bookkeeping.
fn note(watch: &IdleWatch, link: &Arc<Link>, outcome: &Result<()>) {
    match outcome {
        Ok(()) => watch.touch(),
        Err(StoreError::Transport { backend, .. }) if *backend == super::SFTP_BACKEND_NAME => {
            link.mark_dead();
        }
        Err(_) => {}
    }
}

/// Give a refusal a cause, where the far end will supply one.
///
/// A thin wrapper over [`super::space::diagnose`] so the write path reads as one
/// line per step, and so the `Ok` case never touches the module at all: a
/// healthy transfer must not pay a round trip per chunk for a diagnosis it does
/// not need.
///
/// Applied to the **write** operations only. A refused `read` or `stat` cannot
/// be a full disk, and asking `df` about one would spend a round trip to print a
/// sentence about free space beside a failure that has nothing to do with it.
async fn diagnosed(link: &Arc<Link>, remote: &str, outcome: Result<()>) -> Result<()> {
    match outcome {
        Ok(()) => Ok(()),
        Err(error) => Err(super::space::diagnose(link, remote, error).await),
    }
}

#[async_trait]
impl StagedFile for SftpStagedFile {
    async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        // Destructured so the future may borrow `file` mutably while the watch
        // is borrowed immutably; one borrow of `self` could not be both.
        let Self {
            file,
            remote,
            link,
            watch,
        } = self;
        let outcome = match watch.guard(file.write_all(data)).await {
            Ok(result) => result.map_err(|e| map_sftp_err(remote, e)),
            Err(expired) => Err(expired.into_store_error(super::SFTP_BACKEND_NAME)),
        };
        // The refused write, which is where a full disk actually lands: the
        // filesystem fills part-way through an object, not at the `open`. The
        // status code cannot say so (`super::status`), so the far end is asked.
        let outcome = diagnosed(link, remote, outcome).await;
        note(watch, link, &outcome);
        outcome
    }

    /// Durability where the server offers it: fsync the handle, tolerating only
    /// a server that does not implement `fsync@openssh.com`.
    ///
    /// The tolerance is for a **missing capability**, and nothing else. It used
    /// to swallow every error the fsync could return, `tracing::debug!` them and
    /// carry on to the rename — so a server whose filesystem filled up between
    /// the last write and the flush published the object anyway and DCTL
    /// reported a successful transfer. That is a success reported over a
    /// swallowed error, with the failure hidden one layer further down than
    /// usual: an I/O error that nothing read, and a verdict reached without it.
    ///
    /// "Best effort" is an honest description of doing less when the server
    /// cannot do more. It is not a licence to ignore the server saying no.
    async fn sync(&mut self) -> Result<()> {
        let Self {
            file,
            remote,
            link,
            watch,
        } = self;
        // Under the deadline like every other step. An `fsync` on a server whose
        // disk has stopped answering is exactly the quiet failure `--timeout`
        // bounds, and it is the last thing standing between a staging file and
        // the rename that publishes it.
        let outcome = match watch.guard(file.sync_all()).await {
            Ok(Ok(())) => Ok(()),
            // Server lacks the fsync extension — durability is best-effort here.
            Ok(Err(SftpError::UnsupportedExtension(_))) => {
                tracing::debug!("sftp server has no fsync extension; write is not forced to disk");
                Ok(())
            }
            Ok(Err(e)) => Err(map_sftp_err(remote, e)),
            Err(expired) => Err(expired.into_store_error(super::SFTP_BACKEND_NAME)),
        };
        // A filesystem that filled between the last write and the flush refuses
        // here instead, and it is the last step before the rename that would
        // publish the object.
        let outcome = diagnosed(link, remote, outcome).await;
        note(watch, link, &outcome);
        outcome
    }

    async fn close(self) -> Result<()> {
        let outcome = match self.watch.guard(self.file.close()).await {
            Ok(result) => result.map_err(|e| map_sftp_err(&self.remote, e)),
            Err(expired) => Err(expired.into_store_error(super::SFTP_BACKEND_NAME)),
        };
        let outcome = diagnosed(&self.link, &self.remote, outcome).await;
        note(&self.watch, &self.link, &outcome);
        outcome
    }
}

#[async_trait]
impl RemoteFs for SftpBackend {
    type File = SftpStagedFile;

    async fn mkdir_p(&self, remote_file: &str) {
        // Whether the base itself may be created was decided once, on the first
        // connection, and is not re-decided per write or per re-dial — see
        // [`SftpBackend::may_create_base`].
        let dirs = if self.may_create_base {
            ancestor_dirs_at_or_below(&self.base, remote_file)
        } else {
            ancestor_dirs_below(&self.base, remote_file)
        };
        // Errors are ignored here exactly as before — a directory that already
        // exists is the ordinary case — but the operation still travels through
        // `on_link`, so a session that has died is noticed and thrown away
        // rather than being carried into the `create` immediately after it.
        let _ = self
            .on_link(|link| async move {
                let mut fs = link.sftp.fs();
                for dir in dirs {
                    let _ = fs.create_dir(&dir).await;
                }
                Ok(())
            })
            .await;
    }

    async fn create(&self, remote: &str) -> Result<Self::File> {
        // The handle belongs to the conversation that opened it, so the staged
        // file holds the link alive for as long as it is being written to. A
        // re-dial underneath an open handle would leave the writer addressing a
        // file on a session nobody is listening to any more.
        let link = self.link().await?;
        let opened = self
            .on_link(|link| async move {
                link.sftp
                    .options()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(remote)
                    .await
                    .map_err(|e| map_sftp_err(remote, e))
            })
            .await;
        // A filesystem with no room for another inode refuses here, before a
        // single byte is offered — the other half of the full-disk case, and the
        // one that leaves nothing behind to look at.
        let file = match opened {
            Ok(file) => file,
            Err(error) => return Err(super::space::diagnose(&link, remote, error).await),
        };
        Ok(SftpStagedFile {
            file,
            remote: remote.to_string(),
            link,
            watch: self.watch(),
        })
    }

    async fn set_times(&self, remote: &str, times: Times) -> Result<()> {
        // `from_raw` is infallible for every value `times` produces — it rejects
        // exactly what a `u32` cannot hold, and `times` already refused that —
        // so this arm is unreachable rather than a silent skip. Reported as a
        // backend error if the two ever disagree, because a stamp that did not
        // happen is what makes the next run re-transfer the file.
        let (accessed, modified) = (
            UnixTimeStamp::from_raw(times.accessed),
            UnixTimeStamp::from_raw(times.modified),
        );
        let (Some(accessed), Some(modified)) = (accessed, modified) else {
            return Err(StoreError::Backend(format!(
                "sftp: modification time {} is outside the protocol's range",
                times.modified
            )));
        };
        let metadata = MetaDataBuilder::new().time(accessed, modified).create();
        self.on_link(|link| async move {
            link.sftp
                .fs()
                .set_metadata(remote, metadata)
                .await
                .map_err(|e| map_sftp_err(remote, e))
        })
        .await
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let outcome = self
            .on_link(|link| async move {
                link.sftp
                    .fs()
                    .rename(from, to)
                    .await
                    .map_err(|e| map_sftp_err(to, e))
            })
            .await;
        // The commit. A directory that cannot take another entry refuses here,
        // with every byte of the object already staged and correct — which is
        // the most confusing place to be told only `Failure`.
        match outcome {
            Ok(()) => Ok(()),
            Err(error) => {
                let link = self.link().await?;
                Err(super::space::diagnose(&link, to, error).await)
            }
        }
    }

    async fn remove_quiet(&self, remote: &str) {
        let _ = self
            .on_link(|link| async move {
                let _ = link.sftp.fs().remove_file(remote).await;
                Ok(())
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// 2020-01-01T00:00:00Z — a time no clock this test runs against can be.
    const AGED: i64 = 1_577_836_800;

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn a_known_time_becomes_the_modification_half_of_the_pair() {
        let stamp = times(SourceModified::at(AGED), at(1_800_000_000)).expect("representable");
        assert_eq!(stamp.modified, AGED as u32);
        assert_eq!(
            stamp.accessed, 1_800_000_000,
            "the access time is the clock, not a copy of the modification time"
        );
    }

    #[test]
    fn an_unknown_time_stamps_nothing() {
        // Not the epoch: an object dated 1970 looks older than every local file
        // and inverts `--update` over all of them.
        assert_eq!(times(SourceModified::unknown(), at(1_800_000_000)), None);
    }

    #[test]
    fn a_time_the_wire_cannot_hold_is_left_unstamped() {
        // SFTP v3 carries unsigned 32-bit seconds. Outside 1970–2106 the object
        // keeps the server's write time and is re-transferred next run — a cost.
        // A wrapped value would be a confident, fabricated date instead.
        assert_eq!(times(SourceModified::at(-1), at(0)), None);
        assert_eq!(
            times(SourceModified::at(i64::from(u32::MAX) + 1), at(0)),
            None
        );
        // …and both ends of the range are inside it.
        assert!(times(SourceModified::at(0), at(0)).is_some());
        assert!(times(SourceModified::at(i64::from(u32::MAX)), at(0)).is_some());
    }

    #[test]
    fn a_clock_the_wire_cannot_hold_still_records_the_modification_time() {
        // In 2106 `now` stops fitting. The access time is bookkeeping; the
        // modification time is the reason the call is made, so it survives.
        let far_future = at(u64::from(u32::MAX) + 1_000);
        let stamp = times(SourceModified::at(AGED), far_future).expect("still stamped");
        assert_eq!(stamp.modified, AGED as u32);
        assert_eq!(stamp.accessed, AGED as u32);
    }
}
