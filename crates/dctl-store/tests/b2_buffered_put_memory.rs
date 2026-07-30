//! What [`Backend::put`] adds to the buffer it was handed: nothing.
//!
//! The buffered arm is the one place a B2 upload legitimately holds a whole
//! object — the caller passed it one. What it must not do is hold a *part* as
//! well, and it did: `Bytes::copy_from_slice(&data[start..end])` made a second
//! allocation of every part out of a buffer that was already in memory, so a
//! caller who handed over a gigabyte paid for a gigabyte and a hundred megabytes.
//!
//! This is a different contract from the one `b2_upload_memory.rs` measures, and
//! it needs its own file for the same reason that one does: `VmHWM` is a property
//! of the process, `cargo test` runs a binary's tests in parallel threads, and
//! two ceilings cannot share one high-water mark. See that file for why the
//! measurement is `/proc/self/status` and why it is Linux-only.
//!
//! The instrument here is sharper than a ratio, because the object is allocated
//! **before** the baseline is taken: whatever the process was holding when the
//! measurement started, the only thing this upload may add is the small change
//! that is not proportional to anything.

#![cfg(target_os = "linux")]

mod support;

use bytes::Bytes;
use dctl_store::Deadlines;
use dctl_store::b2::{B2Backend, B2Credentials};
use dctl_store::{Backend, ContentHash, HashAlgo, ObjectKey, SourceModified};
use support::mock_b2::{APP_KEY, BUCKET, KEY_ID, MockB2};

/// Part size the upload runs at. See `b2_upload_memory.rs` for why it is this.
const PART: u64 = 24 * 1024 * 1024;

/// Two whole parts, so the copy this test is about happens twice.
const OBJECT_BYTES: usize = (PART * 2) as usize;

/// Everything an upload may hold that is not proportional to the object.
///
/// Response bodies, `reqwest`'s per-connection buffers, the mock's 64 KiB reads.
/// Eight mebibytes is a third of a part, so the assertion can still tell "nothing
/// proportional" from "one part".
const SLACK: u64 = 8 * 1024 * 1024;

#[tokio::test]
async fn a_buffered_put_allocates_nothing_in_proportion_to_the_object_it_was_given() {
    let mock = MockB2::start(7_000_000).await;
    let b2 = B2Backend::new(
        B2Credentials::new(KEY_ID, APP_KEY),
        BUCKET,
        Deadlines::default(),
    )
    .expect("the backend builds")
    .with_authorize_url(mock.authorize_url())
    .with_part_size(Some(PART));

    // The caller's buffer, allocated and hashed before the baseline: it is the
    // cost of calling this API, not the cost of the upload, and the point of the
    // test is what the upload adds on top of it.
    let data: Vec<u8> = (0..OBJECT_BYTES).map(|i| (i % 251) as u8).collect();
    let expected = ContentHash::compute(HashAlgo::Blake3, &data);
    let body = Bytes::from(data);

    // Warm up so the runtime and the HTTP client are at their steady state.
    b2.put(
        &ObjectKey::new("warmup"),
        Bytes::from_static(b"warm"),
        &ContentHash::compute(HashAlgo::Blake3, b"warm"),
        SourceModified::unknown(),
    )
    .await
    .expect("the warm-up object stores");

    let before = peak_rss_bytes();
    b2.put(
        &ObjectKey::new("o/buffered"),
        body,
        &expected,
        SourceModified::unknown(),
    )
    .await
    .expect("the object stores");
    let grew = peak_rss_bytes().saturating_sub(before);

    // It really was uploaded, as two parts, or the number above is about nothing.
    let state = mock.state();
    let large = state.large.first().expect("a large file was started");
    assert!(large.finished, "the large file was never finished");
    assert_eq!(large.parts.len(), 2);
    assert_eq!(
        large.parts.iter().map(|p| p.len).sum::<usize>(),
        OBJECT_BYTES
    );

    assert!(
        grew <= SLACK,
        "putting a {OBJECT_BYTES}-byte buffer grew the process's peak resident set \
         by a further {grew} bytes. The caller's buffer was already resident before \
         the measurement started, so anything on this scale is a part being copied \
         out of it instead of being viewed."
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
