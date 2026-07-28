//! Finishing an async write so a failure is reported as the failure it was.
//!
//! One concern, one file, because getting it wrong does not look like a bug. It
//! looks like corruption.
//!
//! ## The mechanism
//!
//! [`tokio::fs::File`] is not a file handle; it is a queue in front of one.
//! `write_all` copies into an internal buffer, hands the buffer to the blocking
//! pool and returns `Ok` long before the kernel has been asked to store
//! anything. When that background write fails, the error is stashed in the
//! file's private `last_write_err` and delivered to whichever call looks for it
//! next.
//!
//! `poll_flush` looks for it — and `sync_all` does **not**. `sync_all` calls
//! `complete_inflight`, which polls the flush, and on an error takes the error
//! out and puts it straight back in the box:
//!
//! ```text
//! // tokio-1.53.1/src/fs/file.rs
//! fn poll_complete_inflight(&mut self, cx: &mut Context<'_>) -> Poll<()> {
//!     match self.poll_flush(cx) {
//!         Poll::Ready(Err(e)) => { self.last_write_err = Some(e.kind()); Poll::Ready(()) }
//!         ...
//! ```
//!
//! Then it fsyncs a file with nothing left to sync, which succeeds. So
//!
//! ```text
//! file.write_all(&data).await?;   // Ok — the write has not happened yet
//! file.sync_all().await?;         // Ok — the ENOSPC is swallowed here
//! ```
//!
//! reports a clean, durable write of a file that is empty on disk. The error is
//! never seen: the handle is dropped with it still inside.
//!
//! ## Why this earned a module instead of a `.flush()`
//!
//! Because a bare `file.flush()` sitting next to a `file.sync_all()` reads as
//! redundant, and the next person to tidy it up deletes it. It was already
//! written once, in the CLI's own download path, with the mechanism explained in
//! a comment — and the storage layer, doing the same thing three functions away,
//! did not have it. The consequence is `docs/HANDOVER.md` §16.1: a full disk was
//! reported to the operator as **`checksum mismatch`**, because the only thing
//! that ever noticed the failed write was the read-back hash comparison, and a
//! hash comparison can only ever say "these bytes are not those bytes".
//!
//! An operator told their backup tool found a checksum mismatch goes looking for
//! bit-rot. The fix was `df`.
//!
//! So the step has a name that says what it is for, one place to read why, and
//! no call site where it can be mistaken for noise.

/// Surface a write error that [`tokio::fs::File`] has deferred.
///
/// Call this after the final `write_all` and **before** anything reads the file
/// back, stamps it, renames it or syncs it. See the module docs: `sync_all`
/// consumes the deferred error without returning it, so a `sync_all` that has
/// not been preceded by this call cannot fail on a write that did.
///
/// # Errors
/// Whatever the deferred write failed with — `ENOSPC` for a full filesystem,
/// `EDQUOT` for an exhausted quota, `EFBIG` for a file-size rlimit, `EIO` for a
/// failing device.
pub async fn surface_write_errors(file: &mut tokio::fs::File) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt as _;
    file.flush().await
}

/// [`surface_write_errors`] and then `sync_all`, for the common case where
/// nothing happens to the handle between the two.
///
/// A caller that must touch the file in between — stamping a modification time
/// onto the open handle, for instance — calls the two steps itself, in this
/// order.
///
/// # Errors
/// The deferred write's error, or the fsync's.
pub async fn finish(file: &mut tokio::fs::File) -> std::io::Result<()> {
    surface_write_errors(file).await?;
    file.sync_all().await
}

/// Whether an I/O failure means the destination has nowhere to put the bytes.
///
/// The four kinds an operator fixes with `df`, `quota` or a remount rather than
/// by suspecting their data — grouped because DCTL's answer to all four is the
/// same sentence and the same exit code, and because [`ExitCode::FatalError`]'s
/// own definition names "disk full" as the thing it is for.
///
/// Deliberately not a catch-all for "I/O error". `EIO` on one file says nothing
/// about the next one; a full filesystem fails every remaining file in the run
/// identically, which is what makes it worth stopping for.
///
/// [`ExitCode::FatalError`]: https://docs.rs/dctl-cli
#[must_use]
pub fn is_out_of_space(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::StorageFull
            | std::io::ErrorKind::QuotaExceeded
            | std::io::ErrorKind::FileTooLarge
            | std::io::ErrorKind::ReadOnlyFilesystem
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt as _;

    #[tokio::test]
    async fn a_healthy_write_finishes_cleanly() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("f");
        let mut file = tokio::fs::File::create(&path).await.unwrap();
        file.write_all(b"hello").await.unwrap();
        finish(&mut file).await.unwrap();
        drop(file);
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
    }

    #[test]
    fn the_out_of_space_family_is_exactly_the_four_that_df_explains() {
        use std::io::{Error, ErrorKind};
        for kind in [
            ErrorKind::StorageFull,
            ErrorKind::QuotaExceeded,
            ErrorKind::FileTooLarge,
            ErrorKind::ReadOnlyFilesystem,
        ] {
            assert!(is_out_of_space(&Error::from(kind)), "{kind:?}");
        }
        // A device error, a permission problem or a closed connection are all
        // real I/O failures that `df` does not explain, and folding them in
        // would send an operator to check free space they have plenty of.
        for kind in [
            ErrorKind::Other,
            ErrorKind::PermissionDenied,
            ErrorKind::BrokenPipe,
            ErrorKind::NotFound,
        ] {
            assert!(!is_out_of_space(&Error::from(kind)), "{kind:?}");
        }
    }
}
