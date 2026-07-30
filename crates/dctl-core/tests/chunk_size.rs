//! `chunk_size` at the far end: the number a remote sets, read back out of the
//! object it sealed.
//!
//! §11.3 item 8's remaining half, and the **second** of the two ends that item
//! insists on. The resolver's end — that `chunk_size = 262144` on a `vault`
//! remote parses, is refused when it is nonsense, and is carried rather than
//! dropped — is asserted in `dctl_cli::remote::resolve`. This is the other one:
//! that the number then reaches the sealer and changes the framing of the bytes
//! that are actually stored.
//!
//! Between the two ends is the middle, and the middle is where this project has
//! lost a setting before — §21.7, a meter installed in one arm of
//! `registry::build` and silently dropped in the other four, and §13's eleven
//! flags that parsed, documented themselves, and reached nothing. A setting is
//! wired when both ends are pinned, not when either is.
//!
//! Every assertion below reads the framing out of the **stored object's own
//! head** rather than out of the [`Vault`] that wrote it. That `vault.chunk_size()`
//! returns what it was handed proves a builder assigned a field; it does not
//! prove one object was sealed with it — which is the fact an operator who
//! lowered the setting to fit a container is relying on, and the fact that would
//! still have been false if `with_chunk_size` had set a field nothing read.

use std::sync::Arc;

use dctl_core::{MIN_CHUNK_SIZE, Modified, UnlockKey, Vault};
use dctl_crypto::constants::{DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, OBJECT_HEAD_LEN};
use dctl_crypto::object::parse_head;
use dctl_store::{Backend, ByteRange, LocalFs, ObjectKey};
use tempfile::TempDir;

struct Env {
    _store: TempDir,
    _index: TempDir,
    backend: Arc<dyn Backend>,
    index_path: std::path::PathBuf,
}

fn env() -> Env {
    let store = TempDir::new().expect("a temp store");
    let index = TempDir::new().expect("a temp index");
    let backend: Arc<dyn Backend> = Arc::new(LocalFs::new(store.path()));
    let index_path = index.path().join("vault.redb");
    Env {
        _store: store,
        _index: index,
        backend,
        index_path,
    }
}

/// Deterministic bytes that do not compress into a special case.
fn pseudo_random(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    for b in out.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x & 0xFF) as u8;
    }
    out
}

/// The one object this vault stored, as the provider holds it.
///
/// Read through the backend rather than through the vault on purpose: the
/// subject is the bytes that were committed, and a reader that went back through
/// `Vault` would be asking the writer to confirm its own account of itself.
async fn sealed_head(backend: &Arc<dyn Backend>) -> dctl_crypto::object::Head {
    let page = backend
        .list_page("o/", None)
        .await
        .expect("the object listing works");
    assert_eq!(page.items.len(), 1, "expected exactly one object: {page:?}");
    let head = backend
        .get_range(
            &ObjectKey::new(page.items[0].key.as_str()),
            ByteRange::new(0, Some(OBJECT_HEAD_LEN as u64)),
        )
        .await
        .expect("the head reads back");
    parse_head(&head).expect("the head parses")
}

/// Seal `data` at `requested` through both write paths and return each object's
/// head, having first proved the object still reads back byte for byte.
///
/// Both paths, every time, because they are two different sealers:
/// `put_file` builds the object in memory and `put_file_from_path` streams it
/// into the backend's pipe. A `chunk_size` that reached one and not the other is
/// exactly the half-wired state this file exists to refuse, and it is not a
/// hypothetical shape — it is §13's, arriving in a new place.
async fn seal_both_ways(
    data: &[u8],
    requested: Option<u64>,
) -> (dctl_crypto::object::Head, dctl_crypto::object::Head) {
    let buffered = {
        let e = env();
        let vault = Vault::init(e.backend.clone(), &e.index_path, "pw")
            .await
            .expect("the vault initialises")
            .vault
            .with_chunk_size(requested);
        vault
            .put_file("clip.bin", data, Modified::Now)
            .await
            .expect("the buffered put stores");
        assert_eq!(
            vault
                .get_file("clip.bin")
                .await
                .expect("it reads back")
                .as_slice(),
            data,
            "a re-framed object must still decode to its plaintext"
        );
        sealed_head(&e.backend).await
    };

    let streamed = {
        let e = env();
        let src = TempDir::new().expect("a temp source");
        let src_path = src.path().join("clip.bin");
        std::fs::write(&src_path, data).expect("the source writes");
        let vault = Vault::init(e.backend.clone(), &e.index_path, "pw")
            .await
            .expect("the vault initialises")
            .vault
            .with_chunk_size(requested);
        vault
            .put_file_from_path("clip.bin", &src_path, Modified::Now)
            .await
            .expect("the streamed put stores");
        assert_eq!(
            vault
                .get_file("clip.bin")
                .await
                .expect("it reads back")
                .as_slice(),
            data,
            "a re-framed streamed object must still decode to its plaintext"
        );
        sealed_head(&e.backend).await
    };

    (buffered, streamed)
}

#[tokio::test]
async fn the_configured_chunk_size_is_the_one_the_object_is_sealed_with() {
    // 256 KiB is a quarter of the default, so an object of this size is framed
    // into four times as many chunks — a difference no amount of luck produces.
    let data = pseudo_random(1024 * 1024 + 7);
    let requested = 256 * 1024u64;

    let (buffered, streamed) = seal_both_ways(&data, Some(requested)).await;

    for (path, head) in [("put_file", &buffered), ("put_file_from_path", &streamed)] {
        assert_eq!(
            u64::from(head.chunk_size),
            requested,
            "{path} sealed at {} rather than the configured {requested}",
            head.chunk_size
        );
        assert_eq!(
            head.chunk_count,
            (data.len() as u64).div_ceil(requested),
            "{path}: the chunk count must follow the chunk size"
        );
        assert_eq!(head.plaintext_len, data.len() as u64, "{path}");
    }
}

#[tokio::test]
async fn an_unset_chunk_size_leaves_the_build_default() {
    // The setting is optional and most remotes will never carry it. `None` must
    // mean "the default", not "zero" and not "whatever was left in the field" —
    // and the default is the one number the whole existing corpus was sealed at.
    let data = pseudo_random(64 * 1024);
    let (buffered, streamed) = seal_both_ways(&data, None).await;
    assert_eq!(buffered.chunk_size, DEFAULT_CHUNK_SIZE);
    assert_eq!(streamed.chunk_size, DEFAULT_CHUNK_SIZE);
}

#[tokio::test]
async fn a_size_outside_the_envelope_seals_at_the_clamp_rather_than_failing() {
    // The clamp is only a real policy if the object that comes out is sealed at
    // the clamped value. A `with_chunk_size` that logged the clamp and then
    // stored the requested number would produce an object no reader could parse
    // — which is the failure clamping exists to prevent, caused by the clamp.
    let data = pseudo_random(96 * 1024);

    let (low_buffered, low_streamed) = seal_both_ways(&data, Some(1)).await;
    assert_eq!(low_buffered.chunk_size, MIN_CHUNK_SIZE);
    assert_eq!(low_streamed.chunk_size, MIN_CHUNK_SIZE);

    let (high_buffered, high_streamed) = seal_both_ways(&data, Some(u64::MAX)).await;
    assert_eq!(high_buffered.chunk_size, MAX_CHUNK_SIZE);
    assert_eq!(high_streamed.chunk_size, MAX_CHUNK_SIZE);
}

#[tokio::test]
async fn an_object_sealed_at_one_size_still_opens_after_the_setting_changes() {
    // The property that makes this safe to change on a live vault: `chunk_size`
    // is written into each object's head by whoever sealed it, and every reader
    // takes the object's own value. An operator who lowers the setting to fit a
    // container must not thereby lose everything sealed before they did.
    let e = env();
    let old = pseudo_random(512 * 1024 + 11);

    {
        let vault = Vault::init(e.backend.clone(), &e.index_path, "pw")
            .await
            .expect("the vault initialises")
            .vault
            .with_chunk_size(Some(u64::from(MIN_CHUNK_SIZE) * 2));
        vault
            .put_file("before.bin", &old, Modified::Now)
            .await
            .expect("the first object stores");
    }

    // Re-opened with a different setting, as a changed configuration file gives.
    let vault = Vault::unlock(e.backend.clone(), &e.index_path, UnlockKey::Password("pw"))
        .await
        .expect("the vault unlocks")
        .with_chunk_size(Some(1024 * 1024));
    let new = pseudo_random(300_000);
    vault
        .put_file("after.bin", &new, Modified::Now)
        .await
        .expect("the second object stores");

    assert_eq!(
        vault
            .get_file("before.bin")
            .await
            .expect("the old one opens")
            .as_slice(),
        old,
        "an object sealed at the previous chunk size must still open"
    );
    assert_eq!(
        vault
            .get_file("after.bin")
            .await
            .expect("the new one opens")
            .as_slice(),
        new
    );
}
