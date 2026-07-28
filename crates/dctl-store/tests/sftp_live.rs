//! Live SFTP round-trip test. Ignored by default; runs only against a real host.
//!
//! This targets an **ssh-config host**: `DCTL_SFTP_HOST` must be a destination the
//! system `ssh` can resolve from `~/.ssh/config` (or `user@host`). For DCTL's
//! `lsx-001` that means the config's `ProxyCommand cloudflared access ssh
//! --hostname %h` and `IdentityFile` are honored transparently — the test needs the
//! system `ssh` binary (and, for cloudflared hosts, a working `cloudflared access`).
//!
//! ```sh
//! DCTL_SFTP_HOST=lsx-001 cargo test -p dctl-store --test sftp_live -- --ignored --nocapture
//! ```
//!
//! Optional: `DCTL_SFTP_BASE` overrides the remote scratch directory
//! (default `~/dctl-sftp-livetest`). Everything the test creates lives under a
//! per-run subdirectory that is removed at the end.
//!
//! LIVE VERIFICATION STATUS: **run**, on 2026-07-27, against a real `sshd` +
//! `internal-sftp` subsystem on lsx-002 (`DCTL_SFTP_HOST=sftpprobe`). It still
//! never runs in CI — no `DCTL_SFTP_HOST` means it is skipped, and `#[ignore]`
//! keeps it out of the default run — so this line is the only record that it has
//! been exercised. Re-run it after any change to `sftp/`, and update the date.

use bytes::Bytes;
use dctl_store::{
    Backend, ByteRange, ContentHash, HashAlgo, Hasher, ObjectKey, SftpBackend, SftpConfig,
    SourceModified,
};

/// A multi-chunk source (> the backend's 4 MiB streaming chunk) so `put_from_path`
/// and `get_to_path` exercise the bounded, multi-iteration streaming path.
const STREAM_SOURCE_LEN: u64 = 5 * 1024 * 1024 + 123;

fn host_from_env() -> Option<String> {
    std::env::var("DCTL_SFTP_HOST")
        .ok()
        .filter(|s| !s.is_empty())
}

fn base_from_env() -> String {
    std::env::var("DCTL_SFTP_BASE").unwrap_or_else(|_| "~/dctl-sftp-livetest".to_string())
}

/// Write a deterministic `len`-byte pattern to `path` in fixed blocks, so the test
/// fixture itself never holds the whole file in memory.
fn write_pattern_file(path: &std::path::Path, len: u64) {
    use std::io::Write as _;
    let mut f = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    let block: Vec<u8> = (0u32..1_048_576).map(|i| (i % 251) as u8).collect();
    let mut written = 0u64;
    while written < len {
        let take = ((len - written) as usize).min(block.len());
        f.write_all(&block[..take]).unwrap();
        written += take as u64;
    }
    f.flush().unwrap();
}

/// Stream-hash a file under `algo` without holding it in memory.
fn hash_file(path: &std::path::Path, algo: HashAlgo) -> ContentHash {
    use std::io::Read as _;
    let mut f = std::fs::File::open(path).unwrap();
    let mut hasher = Hasher::new(algo);
    let mut buf = vec![0u8; 1_048_576];
    loop {
        let n = f.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    hasher.finalize()
}

fn blake3(data: &[u8]) -> ContentHash {
    ContentHash::blake3(data)
}

#[tokio::test]
#[ignore = "requires a live ssh-config host via DCTL_SFTP_HOST (needs system ssh + its ProxyCommand)"]
async fn sftp_full_round_trip() {
    let Some(host) = host_from_env() else {
        eprintln!("skipping sftp_full_round_trip: DCTL_SFTP_HOST not set");
        return;
    };
    // Per-run scratch subdirectory so parallel/repeated runs never collide, and so
    // cleanup can remove exactly what this run created.
    let run = format!("run-{}", std::process::id());
    let base = format!("{}/{run}", base_from_env());
    let sftp = SftpBackend::connect(SftpConfig::new(host.clone(), base.clone()))
        .await
        .expect("connect + open sftp");

    // ---- small object: put → verify → head/exists → get → range → list -------
    let small_key = ObjectKey::new("nested/dir/small.bin");
    let small = Bytes::from((0u8..=255).cycle().take(5000).collect::<Vec<u8>>());
    let small_hash = blake3(&small);

    let outcome = sftp
        .put(
            &small_key,
            small.clone(),
            &small_hash,
            SourceModified::unknown(),
        )
        .await
        .expect("put small");
    assert_eq!(outcome.size, small.len() as u64);
    assert!(outcome.verified.matches(&small_hash));

    assert!(sftp.exists(&small_key).await.unwrap());
    assert_eq!(
        sftp.head(&small_key).await.unwrap().size,
        small.len() as u64
    );

    // get: byte-exact.
    assert_eq!(sftp.get(&small_key).await.unwrap(), small);

    // get_range: a middle window, byte-exact and without fetching the whole object.
    let mid = sftp
        .get_range(&small_key, ByteRange::new(1000, Some(256)))
        .await
        .unwrap();
    assert_eq!(&mid[..], &small[1000..1256]);
    // A tail range clamps its length at EOF rather than erroring.
    let tail = sftp
        .get_range(
            &small_key,
            ByteRange::new(small.len() as u64 - 10, Some(999)),
        )
        .await
        .unwrap();
    assert_eq!(&tail[..], &small[small.len() - 10..]);

    // A second small object so listing has more than one item.
    let other_key = ObjectKey::new("nested/dir/other.bin");
    let other = Bytes::from_static(b"a second small object");
    sftp.put(
        &other_key,
        other.clone(),
        &blake3(&other),
        SourceModified::unknown(),
    )
    .await
    .unwrap();

    // Verified-write refuses a hash mismatch and commits nothing.
    let bad_key = ObjectKey::new("nested/dir/bad.bin");
    let err = sftp
        .put(
            &bad_key,
            Bytes::from_static(b"actual"),
            &blake3(b"different"),
            SourceModified::unknown(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        dctl_store::StoreError::ChecksumMismatch { .. }
    ));
    assert!(!sftp.exists(&bad_key).await.unwrap());

    // ---- streaming: put_from_path / get_to_path, byte-exact --------------------
    let tmp = tempfile::TempDir::new().unwrap();
    let src = tmp.path().join("source.bin");
    write_pattern_file(&src, STREAM_SOURCE_LEN);
    let src_hash = hash_file(&src, HashAlgo::Blake3);

    let stream_key = ObjectKey::new("stream/big.bin");
    let outcome = sftp
        .put_from_path(&stream_key, &src, &src_hash, SourceModified::unknown())
        .await
        .expect("streamed put_from_path");
    assert_eq!(outcome.size, STREAM_SOURCE_LEN);
    assert!(outcome.verified.matches(&src_hash));
    assert_eq!(
        sftp.head(&stream_key).await.unwrap().size,
        STREAM_SOURCE_LEN
    );

    // Streamed download reproduces the object byte-for-byte (compared via a
    // streamed hash so the test never buffers the whole object either).
    let dest = tmp.path().join("download.bin");
    sftp.get_to_path(&stream_key, &dest).await.unwrap();
    assert_eq!(std::fs::metadata(&dest).unwrap().len(), STREAM_SOURCE_LEN);
    assert!(hash_file(&dest, HashAlgo::Blake3).matches(&src_hash));

    // A middle range of the multi-chunk object, byte-exact.
    let win = sftp
        .get_range(
            &stream_key,
            ByteRange::new(4 * 1024 * 1024, Some(64 * 1024)),
        )
        .await
        .unwrap();
    let src_bytes = std::fs::read(&src).unwrap();
    assert_eq!(
        &win[..],
        &src_bytes[4 * 1024 * 1024..4 * 1024 * 1024 + 64 * 1024]
    );

    // ---- listing finds every object under the prefix ---------------------------
    let mut listed = Vec::new();
    let mut cursor = None;
    loop {
        let page = sftp.list_page("", cursor.clone()).await.unwrap();
        for item in &page.items {
            listed.push(item.key.as_str().to_string());
        }
        if page.next_cursor.is_none() {
            break;
        }
        cursor = page.next_cursor;
    }
    listed.sort();
    assert_eq!(
        listed,
        vec![
            "nested/dir/other.bin".to_string(),
            "nested/dir/small.bin".to_string(),
            "stream/big.bin".to_string(),
        ],
        "listing must find exactly the committed objects (no temp files)"
    );
    // Prefix filtering scopes the walk.
    let nested = sftp.list_page("nested/", None).await.unwrap();
    assert_eq!(nested.items.len(), 2);
    assert!(
        nested
            .items
            .iter()
            .all(|m| m.key.as_str().starts_with("nested/"))
    );

    // ---- a real file whose name looks temporary survives the round trip -------
    //
    // The data-loss defect this guards against, over a real sshd. The listing
    // walk used to skip any name containing `.tmp.`, so `report.tmp.2024.csv`
    // was stored, was readable by key, and was **absent from every listing** —
    // `dctl copy sfp: /restore` reported `Files: 5 / 5, Errors: 0` and left it
    // behind, `sync` never removed it from a destination, and `purge` reported
    // success over it.
    //
    // The 245-byte name is the other half: the old staging spelling appended a
    // suffix to the *filename*, so a name the server accepts as final exceeded
    // NAME_MAX as a staging file and the upload failed with `Bad message` — on
    // some nights only, because the suffix embedded the process id.
    let awkward: Vec<(ObjectKey, Bytes)> = vec![
        (
            ObjectKey::new("looks/report.tmp.2024.csv"),
            Bytes::from_static(b"IMPORTANT USER DATA"),
        ),
        (
            ObjectKey::new("looks/db.tmp.2024-07-27.sql"),
            Bytes::from_static(b"a database dump"),
        ),
        (
            ObjectKey::new(format!("looks/{}", "n".repeat(245))),
            Bytes::from_static(b"a name at the filesystem limit"),
        ),
    ];
    for (key, body) in &awkward {
        sftp.put(key, body.clone(), &blake3(body), SourceModified::unknown())
            .await
            .unwrap_or_else(|error| panic!("{key} must be storable: {error}"));
    }
    let looks = sftp.list_page("looks/", None).await.unwrap();
    let seen: Vec<String> = looks.items.iter().map(|m| m.key.to_string()).collect();
    for (key, body) in &awkward {
        assert!(
            seen.iter().any(|k| k == key.as_str()),
            "{key} was stored and is invisible to every listing: {seen:?}"
        );
        assert_eq!(&sftp.get(key).await.unwrap(), body);
    }
    assert_eq!(seen.len(), awkward.len());
    for (key, _) in &awkward {
        sftp.delete(key).await.unwrap();
    }

    // ---- the source's modification time survives the write ---------------------
    //
    // The property `sync` is incremental because of. A `SETSTAT` that never
    // happened would leave the server's write time, every later run would compare
    // the object against its source, find a difference, and upload it again —
    // forever, with nothing on either stream to say why. 2020-01-01T00:00:00Z is
    // far from any clock this test can run against, so a backend that stamped
    // "now" cannot pass by accident. Both read paths are asserted, because a
    // transfer compares against the *listing* and not against `head`.
    const AGED: i64 = 1_577_836_800;
    let aged_key = ObjectKey::new("aged/2020.bin");
    let aged = Bytes::from_static(b"written now, modified in 2020");
    sftp.put(
        &aged_key,
        aged.clone(),
        &blake3(&aged),
        SourceModified::at(AGED),
    )
    .await
    .expect("put aged");
    assert_eq!(
        sftp.head(&aged_key).await.unwrap().modified_unix,
        Some(AGED),
        "head must report the time the writer gave, not the time of the write"
    );
    let aged_page = sftp.list_page("aged/", None).await.unwrap();
    assert_eq!(
        aged_page.items.first().map(|item| item.modified_unix),
        Some(Some(AGED)),
        "a listing must report the same time head does"
    );
    // The streaming write is separate code and is what `backup` uses for a large
    // file, so a stamp applied only on the buffered path would make exactly the
    // big files re-upload every night.
    let aged_stream_key = ObjectKey::new("aged/streamed.bin");
    sftp.put_from_path(&aged_stream_key, &src, &src_hash, SourceModified::at(AGED))
        .await
        .expect("streaming put aged");
    assert_eq!(
        sftp.head(&aged_stream_key).await.unwrap().modified_unix,
        Some(AGED)
    );
    sftp.delete(&aged_key).await.unwrap();
    sftp.delete(&aged_stream_key).await.unwrap();

    // ---- delete is idempotent and really removes the object --------------------
    sftp.delete(&small_key).await.unwrap();
    assert!(!sftp.exists(&small_key).await.unwrap());
    assert!(matches!(
        sftp.get(&small_key).await.unwrap_err(),
        dctl_store::StoreError::NotFound(_)
    ));
    sftp.delete(&small_key).await.unwrap(); // deleting again is a no-op success

    // ---- clean up the whole per-run scratch subtree ----------------------------
    sftp.delete(&other_key).await.unwrap();
    sftp.delete(&stream_key).await.unwrap();
    drop(sftp); // close the mux session before the cleanup ssh

    // The backend deletes objects, not directories, so remove the now-empty
    // per-run subtree with a plain `ssh … rm -rf`. This rides the SAME
    // `~/.ssh/config` resolution (ProxyCommand/IdentityFile) as the backend, and
    // the remote login shell expands the leading `~` in `base`.
    let status = std::process::Command::new("ssh")
        .arg(&host)
        .arg(format!("rm -rf -- {base}"))
        .status()
        .expect("spawn cleanup ssh");
    assert!(status.success(), "remote scratch cleanup failed");

    eprintln!(
        "sftp_full_round_trip: OK ({} objects round-tripped)",
        listed.len()
    );
}
