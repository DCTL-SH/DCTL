//! What a B2 upload costs in memory, measured rather than argued.
//!
//! `b2::constants` states the contract: peak ≈ `part_size × UPLOAD_PARTS_IN_FLIGHT`,
//! with no term in the object's size. [`B2Backend::upload_peak_bytes`] is the
//! program saying that number out loud, and this file is the only place that
//! holds it to it without a live bucket.
//!
//! ## What it caught
//!
//! The contract was false by a factor of two, in three places at once. A part was
//! read into a reusable buffer and then **copied again** for the request body —
//! `chunk.to_vec()` on the streaming path, `data.to_vec()` on the single-shot
//! one, `Bytes::copy_from_slice` on the in-memory one — so two whole parts were
//! live while one was on the wire. Measured on the release binary against a live
//! bucket inside a cgroup with `memory.max=512M`, that was **213 MiB of RSS for
//! every object from 128 MiB to 4 GiB**, and 218 MiB for a 99 MiB one. Flat, as
//! promised, and twice as large as it needed to be — which is why a flat number
//! is not by itself evidence of anything. The same runs afterwards are in
//! `HANDOVER.md` §25.
//!
//! ## Why it reads `/proc/self/status`
//!
//! `VmHWM` is the kernel's own high-water mark for this process's resident set:
//! the same quantity `/usr/bin/time -v` reports as *Maximum resident set size*
//! and the same one the cgroup measurements in `HANDOVER.md` are made of. Nothing
//! here simulates memory, and no global allocator is installed — this crate is
//! `#![forbid(unsafe_code)]` and a counting allocator needs `unsafe impl`.
//!
//! Two consequences, both deliberate:
//!
//! * **This file holds exactly one test.** `VmHWM` is a property of the process,
//!   and `cargo test` runs the tests of one binary in parallel threads, so a
//!   second test here would measure the first one's allocations as well as its
//!   own. A new memory claim about B2 gets a new file.
//! * **It is Linux-only.** `/proc` is where the number lives. The three gates run
//!   on Linux; on any other platform this file compiles to nothing and the claim
//!   rests on the live measurement in `HANDOVER.md` §25, which is where it rested
//!   entirely before this file existed.
//!
//! The measurement is bounded on **both** sides. An upper bound alone would be
//! satisfied by a test that never uploaded anything — `VmHWM` would not move and
//! the assertion would pass — so the lower bound asserts the part buffer was
//! visible in the number at all. An instrument that cannot fail is the fault this
//! project keeps finding in its own harnesses (`HANDOVER.md` §23.10).

#![cfg(target_os = "linux")]

mod support;

use dctl_store::Deadlines;
use std::io::Write as _;
use std::path::Path;

use dctl_store::b2::{B2Backend, B2Credentials};
use dctl_store::{Backend, ContentHash, HashAlgo, Hasher, ObjectKey, SourceModified};
use support::mock_b2::{APP_KEY, BUCKET, KEY_ID, MockB2};
use tempfile::TempDir;

/// Part size the upload runs at.
///
/// Large enough that one part dwarfs the noise floor of a `tokio` + `reqwest`
/// process (a few mebibytes), so the difference between holding one part and
/// holding two is unmistakable rather than statistical. Small enough that the
/// test writes and moves a hundred megabytes rather than a gigabyte.
///
/// Deliberately not `32 MiB`: glibc caps its dynamic `mmap` threshold at exactly
/// that, so a 32 MiB allocation lands on one side of the boundary the first time
/// and the other side afterwards, which is a needless variable in a measurement
/// about allocation.
const PART: u64 = 24 * 1024 * 1024;

/// Everything that is live during an upload and is not the part.
///
/// The response being parsed, `reqwest`'s per-connection buffers, the mock's own
/// 64 KiB read buffer and whatever the runtime has not handed back. Eight
/// mebibytes is roughly twenty times what those add up to and a third of a part,
/// so it leaves the assertion able to tell one part from two — which is the whole
/// discrimination this test exists to make.
const SLACK: u64 = 8 * 1024 * 1024;

/// The multipart object: three parts, the last one short.
///
/// A short final part is not decoration. It is the one part whose length differs
/// from every other, so a buffer sized once and reused would show up here as a
/// wrong `Content-Length` or a wrong SHA-1 rather than only as memory.
const MULTIPART_BYTES: u64 = PART * 2 + PART / 2;

#[tokio::test]
async fn an_upload_holds_one_part_however_large_the_object_and_however_often_it_retries() {
    let work = TempDir::new().expect("a temporary directory");
    let single = work.path().join("single.bin");
    let large = work.path().join("large.bin");
    write_pattern(&single, PART);
    write_pattern(&large, MULTIPART_BYTES);
    // Hashed by streaming, before the baseline is taken: reading either file
    // whole to hash it would put the object into the very number being measured.
    let single_hash = hash_file(&single);
    let large_hash = hash_file(&large);

    // `recommendedPartSize` is set to something the client must *not* use. B2
    // sends one, DCTL reads it, reports it and sizes nothing from it, because a
    // figure that is the process's peak memory must not arrive from the network.
    let mock = MockB2::start(7_000_000).await;
    let b2 = B2Backend::new(
        B2Credentials::new(KEY_ID, APP_KEY),
        BUCKET,
        Deadlines::default(),
    )
    .expect("the backend builds")
    .with_authorize_url(mock.authorize_url())
    .with_part_size(Some(PART));

    // Warm up: authorize, open a connection, let the runtime and the HTTP client
    // reach their steady state. Everything they allocate for their own sake
    // belongs below the baseline, not in the upload's bill.
    let warmup = work.path().join("warmup.bin");
    write_pattern(&warmup, 4096);
    b2.put_from_path(
        &ObjectKey::new("warmup"),
        &warmup,
        &hash_file(&warmup),
        SourceModified::unknown(),
    )
    .await
    .expect("the warm-up object stores");

    let before = peak_rss_bytes();

    // 1. The single-shot arm: an object of exactly one part.
    b2.put_from_path(
        &ObjectKey::new("o/single"),
        &single,
        &single_hash,
        SourceModified::unknown(),
    )
    .await
    .expect("a one-part object stores");

    // 2. The streaming arm: three parts through the large-file API.
    b2.put_from_path(
        &ObjectKey::new("o/large"),
        &large,
        &large_hash,
        SourceModified::unknown(),
    )
    .await
    .expect("a multi-part object stores");

    // 3. The same again, with one part refused once. A retried part must cost
    //    nothing: it is the same allocation sent a second time, not a second copy
    //    of it. `503 service_unavailable` is what B2 answers when the storage pod
    //    behind an upload URL is busy, and it took five of ten files out of the
    //    first live restore drill.
    mock.fail_next("/b2_upload_part/large-2", 503, "service_unavailable");
    b2.put_from_path(
        &ObjectKey::new("o/large-retried"),
        &large,
        &large_hash,
        SourceModified::unknown(),
    )
    .await
    .expect("a multi-part object stores through a refused part");

    let after = peak_rss_bytes();
    let grew = after.saturating_sub(before);

    // The bytes really arrived, or the memory figure is a figure about nothing.
    let state = mock.state();
    assert_eq!(
        state.singles.len(),
        2,
        "expected the warm-up and the one-part object on the single-shot path, got {:?}",
        state.singles
    );
    assert_eq!(
        state.singles[1].len as u64, PART,
        "the one-part object arrived the wrong size"
    );
    let finished: Vec<_> = state.large.iter().filter(|f| f.finished).collect();
    assert_eq!(
        finished.len(),
        2,
        "expected two finished large files, got {} ({:?})",
        finished.len(),
        state.large
    );
    for file in &finished {
        assert_eq!(
            file.parts.len(),
            3,
            "a {MULTIPART_BYTES}-byte object at a {PART}-byte part size is three parts"
        );
        let carried: u64 = file.parts.iter().map(|p| p.len as u64).sum();
        assert_eq!(
            carried, MULTIPART_BYTES,
            "the parts do not cover the object"
        );
        assert_eq!(
            file.parts[2].len as u64,
            PART / 2,
            "the last part carries the remainder"
        );
    }
    // The refusal really happened, so run 3 measured a retry rather than a
    // repeat of run 2.
    assert_eq!(
        state.count("/b2_upload_part/large-2"),
        4,
        "expected three parts plus one refused attempt on the retried upload"
    );

    // Bounded above: one part, plus what is not the part.
    let ceiling = b2.upload_peak_bytes() + SLACK;
    assert!(
        grew <= ceiling,
        "three uploads of at most {MULTIPART_BYTES} bytes grew the process's peak \
         resident set by {grew} bytes; the contract is {} bytes ({} × the part size) \
         plus {SLACK} of slack. Twice the part size means a part is being copied \
         for the request body instead of handed to it.",
        b2.upload_peak_bytes(),
        b2.upload_peak_bytes() / PART,
    );
    // Bounded below: the part buffer must be visible in the number, or this test
    // is measuring an upload that did not happen.
    assert!(
        grew >= PART / 2,
        "the process's peak resident set moved by only {grew} bytes across three \
         uploads at a {PART}-byte part size — this instrument is not seeing the \
         upload at all"
    );
}

/// This process's peak resident set, in bytes, as the kernel has recorded it.
fn peak_rss_bytes() -> u64 {
    let status =
        std::fs::read_to_string("/proc/self/status").expect("/proc/self/status is readable");
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|kib| kib.parse::<u64>().ok())
        .map(|kib| kib * 1024)
        .expect("/proc/self/status carries VmHWM")
}

/// Write `len` bytes of a repeating pattern, a mebibyte at a time.
///
/// A mebibyte at a time because building the whole file in memory first would put
/// the object into the measurement this file exists to make. A pattern rather
/// than zeroes so a wrongly-offset part is a hash mismatch rather than a silent
/// pass.
fn write_pattern(path: &Path, len: u64) {
    const BLOCK: usize = 1024 * 1024;
    let block: Vec<u8> = (0..BLOCK).map(|i| (i % 251) as u8).collect();
    let mut file = std::fs::File::create(path).expect("a source file");
    let mut written = 0u64;
    while written < len {
        let take = BLOCK.min((len - written) as usize);
        file.write_all(&block[..take]).expect("the source writes");
        written += take as u64;
    }
    file.sync_all().expect("the source is durable");
}

/// BLAKE3 of a file, streamed — the `expected` a verified write is held to.
///
/// Streamed rather than `ContentHash::blake3(&std::fs::read(path))` because that
/// second form would put the whole object into the very number this file
/// measures, and would do it before the baseline was taken.
fn hash_file(path: &Path) -> ContentHash {
    use std::io::Read as _;
    let mut hasher = Hasher::new(HashAlgo::Blake3);
    let mut file = std::fs::File::open(path).expect("the source is readable");
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buf).expect("the source reads");
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    hasher.finalize()
}
