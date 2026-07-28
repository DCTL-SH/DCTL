//! What DCTL says when a write does not land: it must name the failure, not the
//! bytes.
//!
//! This is `docs/HANDOVER.md` §16.1 held in place. A `tokio::fs::File` reports a
//! successful `write_all` before the kernel has been asked to store anything and
//! `sync_all` consumes the resulting error without returning it
//! (`dctl_store::durable`), so a full filesystem used to be noticed for the first
//! time by the read-back hash comparison — and a hash comparison can only ever
//! say *"checksum mismatch: expected … got …"*. An operator reading that on a
//! backup tool concludes their data is corrupt. The fix was `df`.
//!
//! ## Its own binary, on purpose
//!
//! `RLIMIT_FSIZE` is a **process-wide** limit, and `cargo test` runs the tests in
//! one integration file as threads of one process. This file therefore contains
//! exactly one rlimit-setting test and nothing else: dropped into `local.rs` it
//! would cap every other test in that binary at 64 KiB and fail them for reasons
//! that have nothing to do with what they assert.
//!
//! ## Why an rlimit rather than a full disk
//!
//! Because it runs in the stated gate, on any machine, with no root and no
//! mount. `EFBIG` and `ENOSPC` travel the identical path — a blocking write that
//! fails after `write_all` has already returned `Ok` — so this proves the
//! mechanism. The real thing is proved separately by
//! [`a_full_filesystem_reports_no_space_left_on_device`], which needs a genuinely
//! full filesystem and says so rather than passing quietly without one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::Bytes;
use dctl_store::{Backend, ContentHash, LocalFs, ObjectKey, SourceModified, StoreError};

/// The file-size ceiling the rlimit test imposes, in bytes.
///
/// Small enough to be exceeded instantly and comfortably under `tokio`'s 2 MiB
/// write buffer, so the whole object is accepted by a single `write_all` that
/// returns `Ok` before the kernel has refused it — which is the exact shape of
/// the defect.
const FSIZE_CEILING: u64 = 64 * 1024;

/// Bytes offered to the backend: several times the ceiling, so the write cannot
/// succeed, and still one buffer's worth so it is deferred rather than reported
/// inline.
const OBJECT_LEN: usize = 256 * 1024;

/// The environment variable naming a directory on a filesystem with no free
/// space, for the live half of this file.
const FULL_FS_DIR: &str = "DCTL_FULL_FS_DIR";

/// Cap this process's file size and stop `SIGXFSZ` from killing it.
///
/// Ignoring the signal is what turns "the process dies" into "the write returns
/// `EFBIG`", which is the failure a full filesystem produces and the one under
/// test.
#[cfg(unix)]
fn cap_file_size(bytes: u64) {
    // SAFETY: both calls are plain libc with no memory involved. `signal` sets a
    // disposition and `setrlimit` reads one fully-initialised `rlimit`. This is
    // a test binary; the library itself is `#![forbid(unsafe_code)]`.
    unsafe {
        libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
        let limit = libc::rlimit {
            rlim_cur: bytes,
            rlim_max: bytes,
        };
        assert_eq!(
            libc::setrlimit(libc::RLIMIT_FSIZE, &raw const limit),
            0,
            "the test could not impose a file-size limit: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn a_write_the_filesystem_refuses_is_reported_as_that_refusal() {
    // RED before `dctl_store::durable`, and this test's exact shape is the
    // reason it is worth writing carefully. Its first draft accepted *either*
    // the errno or a `ShortWrite`, and it passed with the defect reinstated:
    // the length backstop caught the truncation and the assertion never saw
    // that the write path had said nothing. Only `StoreError::Io` proves the
    // failure was read from the write that failed rather than inferred from
    // what turned up on disk afterwards — with the defect in place this is
    // `ShortWrite`, and before the backstop existed it was
    // `ChecksumMismatch { expected: <hash of 256 KiB>, actual: <hash of 64 KiB> }`
    // under a hint blaming "the provider or the network path" for a local disk.
    let dir = tempfile::TempDir::new().unwrap();
    let fs = LocalFs::new(dir.path());
    let key = ObjectKey::new("big.bin");
    let data = Bytes::from(vec![0xA5u8; OBJECT_LEN]);
    let expected = ContentHash::blake3(&data);

    cap_file_size(FSIZE_CEILING);

    let error = fs
        .put(&key, data, &expected, SourceModified::unknown())
        .await
        .expect_err("a 256 KiB object cannot be written under a 64 KiB ceiling");

    match &error {
        StoreError::Io(source) => assert!(
            dctl_store::durable::is_out_of_space(source),
            "the errno must be one an operator can act on, got {source:?}"
        ),
        StoreError::ShortWrite { .. } => panic!(
            "the write path stayed silent and the failure was inferred from the \
             file afterwards: {error}. The refusal was there to be read."
        ),
        StoreError::ChecksumMismatch { .. } => panic!(
            "a refused write was diagnosed by comparing hashes: {error}. \
             That sentence sends an operator hunting bit-rot in undamaged data."
        ),
        other => panic!("unexpected classification of a refused write: {other}"),
    }

    // And nothing was published or left behind. A staging file that survived a
    // disk-full write holds exactly the space the retry needs — the failing
    // write used to leak one the size of the object it could not store.
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        leftovers.is_empty(),
        "a failed write left files behind: {leftovers:?}"
    );
}

/// The same claim against a genuinely full filesystem.
///
/// `#[ignore]` because it needs one, and **panics** rather than returning when
/// [`FULL_FS_DIR`] is unset or the directory it names has room: a test that
/// prints "skipping" and reports `ok` is `docs/HANDOVER.md` §11.3 item 2, and the
/// whole point of this file is that a failure must not be able to look like a
/// success.
///
/// Run with, for example:
///
/// ```text
/// mkfs.ext4 -F disk.img && mount -o loop disk.img /mnt/full
/// dd if=/dev/zero of=/mnt/full/ballast bs=1M 2>/dev/null
/// DCTL_FULL_FS_DIR=/mnt/full cargo test -p dctl-store --test write_failure -- --ignored
/// ```
#[tokio::test]
#[ignore = "needs a filesystem with no free space; set DCTL_FULL_FS_DIR"]
async fn a_full_filesystem_reports_no_space_left_on_device() {
    let root = std::env::var(FULL_FS_DIR).unwrap_or_else(|_| {
        panic!("{FULL_FS_DIR} is not set; this test cannot run and must not pass")
    });
    let root = std::path::PathBuf::from(root);
    assert!(
        root.is_dir(),
        "{FULL_FS_DIR}={} is not a directory",
        root.display()
    );

    let fs = LocalFs::new(root.join("dctl-enospc-probe"));
    let key = ObjectKey::new("big.bin");
    let data = Bytes::from(vec![0x5Au8; OBJECT_LEN]);
    let expected = ContentHash::blake3(&data);

    let error = fs
        .put(&key, data, &expected, SourceModified::unknown())
        .await
        .expect_err("a full filesystem cannot store an object; if it did, it was not full");

    match &error {
        StoreError::Io(source) => assert!(
            dctl_store::durable::is_out_of_space(source),
            "expected an out-of-space errno, got {source:?}"
        ),
        StoreError::ShortWrite { .. } => {}
        other => panic!("a full disk was diagnosed as: {other}"),
    }
}
