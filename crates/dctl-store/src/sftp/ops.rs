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
//! green (`HANDOVER.md` §15.4). A guarantee whose only witness needs credentials
//! is a guarantee the stated gate does not hold, and the gate is what every
//! report in this project quotes as proof.
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

use std::time::SystemTime;

use async_trait::async_trait;
use openssh_sftp_client::file::File;
use openssh_sftp_client::metadata::MetaDataBuilder;
use openssh_sftp_client::{Error as SftpError, UnixTimeStamp};

use crate::error::{Result, StoreError};
use crate::modified::SourceModified;

use super::path::ancestor_dirs;
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

    /// Realize `mkdir -p` for the parent of a remote **file** path.
    ///
    /// Infallible by design: an "already exists" on an intermediate directory is
    /// the ordinary case, and a genuinely un-writable parent surfaces when the
    /// subsequent create or rename fails, where the error can name what was
    /// being attempted.
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
}

#[async_trait]
impl StagedFile for SftpStagedFile {
    async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.file
            .write_all(data)
            .await
            .map_err(|e| map_sftp_err(&self.remote, e))
    }

    /// Durability where the server offers it: fsync the handle, tolerating only
    /// a server that does not implement `fsync@openssh.com`.
    ///
    /// The tolerance is for a **missing capability**, and nothing else. It used
    /// to swallow every error the fsync could return, `tracing::debug!` them and
    /// carry on to the rename — so a server whose filesystem filled up between
    /// the last write and the flush published the object anyway and DCTL
    /// reported a successful transfer. That is the same defect as
    /// `HANDOVER.md` §16.1 with the failure hidden one layer further down: an
    /// I/O error that nothing read, and a verdict reached without it.
    ///
    /// "Best effort" is an honest description of doing less when the server
    /// cannot do more. It is not a licence to ignore the server saying no.
    async fn sync(&mut self) -> Result<()> {
        match self.file.sync_all().await {
            Ok(()) => Ok(()),
            // Server lacks the fsync extension — durability is best-effort here.
            Err(SftpError::UnsupportedExtension(_)) => {
                tracing::debug!("sftp server has no fsync extension; write is not forced to disk");
                Ok(())
            }
            Err(e) => Err(map_sftp_err(&self.remote, e)),
        }
    }

    async fn close(self) -> Result<()> {
        let remote = self.remote;
        self.file
            .close()
            .await
            .map_err(|e| map_sftp_err(&remote, e))
    }
}

#[async_trait]
impl RemoteFs for SftpBackend {
    type File = SftpStagedFile;

    async fn mkdir_p(&self, remote_file: &str) {
        let mut fs = self.sftp.fs();
        for dir in ancestor_dirs(remote_file) {
            let _ = fs.create_dir(&dir).await;
        }
    }

    async fn create(&self, remote: &str) -> Result<Self::File> {
        let file = self
            .sftp
            .options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(remote)
            .await
            .map_err(|e| map_sftp_err(remote, e))?;
        Ok(SftpStagedFile {
            file,
            remote: remote.to_string(),
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
        self.sftp
            .fs()
            .set_metadata(remote, metadata)
            .await
            .map_err(|e| map_sftp_err(remote, e))
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.sftp
            .fs()
            .rename(from, to)
            .await
            .map_err(|e| map_sftp_err(to, e))
    }

    async fn remove_quiet(&self, remote: &str) {
        let mut fs = self.sftp.fs();
        let _ = fs.remove_file(remote).await;
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
