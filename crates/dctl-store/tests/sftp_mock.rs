//! The SFTP backend against an SFTP server in this process: the three
//! guarantees that used to need `DCTL_SFTP_HOST`.
//!
//! `sftp_live.rs` needs a host, so until this file existed three of this
//! backend's promises rested on a test the plain gate does not run. All three
//! were re-attacked in `HANDOVER.md` §23.0 by deleting them from the source, and
//! all three came back **GREEN**:
//!
//! * `mtime-sftp-settimes` — the `SETSTAT` is never sent, so every object keeps
//!   the *server's* write time and the next `sync` transfers the whole tree
//!   again, and the one after that, forever.
//! * `sftp-recreates-base` — the write path re-creates the configured base. That
//!   is the defect that put seventeen of twenty-five objects into a directory
//!   nobody named, and reported all of them as stored and verified.
//! * `guard-store-identity-b2`'s SFTP counterpart — the base probe the store
//!   guard rests on, which is what notices the base has gone at all.
//!
//! What runs here is the **real** [`SftpBackend`], unchanged, over the real
//! client library and the real version-3 packet encoding, against
//! [`support::mock_sftp`] — which that module's documentation describes,
//! including what it deliberately does not prove.

mod support;

use dctl_store::guard::Strength;
use dctl_store::sftp::SftpBackend;
use dctl_store::{Backend, ContentHash, HashAlgo, LinkPolicy, ObjectKey, SourceModified};
use support::mock_sftp::{MockSftp, Seen};

/// 2020-01-01T00:00:00Z — a time no clock this test runs against can be, so a
/// write that quietly stamped "now" cannot pass by accident.
const AGED: i64 = 1_577_836_800;

/// A backend over a fresh in-process server, rooted at `base`, with `existing`
/// present on the server **before** the backend connects.
///
/// The ordering is the whole point and is why this is a parameter rather than
/// two lines in each test: `may_create_base` is decided once, by a `stat` during
/// the connect, and a directory made a moment later would flip the decision
/// without changing a single assertion. The first draft of this file did exactly
/// that and turned the vanished-base test green over a write that had re-created
/// the base and stored the object in it.
async fn backend(base: &str, existing: &[&str]) -> (MockSftp, SftpBackend) {
    let (mock, pipes) = support::mock_sftp::start();
    for directory in existing {
        std::fs::create_dir_all(mock.root().join(directory.trim_start_matches('/')))
            .expect("the fixture directory is created");
    }
    let backend = SftpBackend::over_stream(pipes.writes, pipes.reads, base, LinkPolicy::Skip)
        .await
        .expect("the sftp conversation opens over a pipe");
    (mock, backend)
}

fn blake3(data: &[u8]) -> ContentHash {
    ContentHash::compute(HashAlgo::Blake3, data)
}

/// The host-side path of a wire path, for reading back what really happened.
fn on_disk(mock: &MockSftp, wire: &str) -> std::path::PathBuf {
    mock.root().join(wire.trim_start_matches('/'))
}

#[tokio::test]
async fn a_write_really_sends_the_setstat_and_the_object_carries_the_source_time() {
    // The whole of why `sync` is incremental on this backend. Deleting the
    // `set_metadata` call leaves a backend that writes correct bytes, reports
    // success, and re-uploads every object on every run — which is a cost with
    // no error message anywhere, and which the plain gate could not see.
    let (mock, sftp) = backend("/srv/store", &["/srv/store"]).await;
    let data = b"written now, modified in 2020";

    sftp.put(
        &ObjectKey::new("o/object.bin"),
        bytes::Bytes::from_static(data),
        &blake3(data),
        SourceModified::at(AGED),
    )
    .await
    .expect("the write succeeds");

    // The request happened, carrying the source's time.
    let stamped = mock
        .seen()
        .iter()
        .filter(|seen| matches!(seen, Seen::Setstat(_, Some((_, m))) if *m == AGED as u32))
        .count();
    assert_eq!(
        stamped,
        1,
        "exactly one SETSTAT carrying the source's time: {:?}",
        mock.seen()
    );

    // And the file on the server really has it, read with `std::fs` rather than
    // taken from the server's own account of itself.
    let landed = on_disk(&mock, "/srv/store/o/object.bin");
    let modified = std::fs::metadata(&landed)
        .expect("the object is there")
        .modified()
        .expect("this filesystem records times")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    assert_eq!(modified, AGED as u64);

    // Read back through the backend too: the modification time is what a
    // listing compares, and a stamp the protocol could not report would leave
    // `sync` no better off.
    let head = sftp
        .head(&ObjectKey::new("o/object.bin"))
        .await
        .expect("the object heads");
    assert_eq!(head.modified_unix, Some(AGED));
    assert_eq!(head.size, data.len() as u64);
}

#[tokio::test]
async fn the_stamp_lands_on_the_staging_path_before_the_rename_and_never_after_it() {
    // An ordering claim, and only the request sequence can carry one: a
    // `SETSTAT` issued after the rename stamps the *published* object, which a
    // concurrent reader can observe carrying the server's time, and which a
    // snapshot of the finished file cannot tell from the correct order.
    let (mock, sftp) = backend("/srv/store", &["/srv/store"]).await;
    let data = b"order matters";

    sftp.put(
        &ObjectKey::new("obj.bin"),
        bytes::Bytes::from_static(data),
        &blake3(data),
        SourceModified::at(AGED),
    )
    .await
    .expect("the write succeeds");

    let seen = mock.seen();
    let stamp = seen
        .iter()
        .position(|s| matches!(s, Seen::Setstat(_, Some(_))))
        .expect("the write must stamp");
    let rename = seen
        .iter()
        .position(|s| matches!(s, Seen::Rename(_, _)))
        .expect("and must publish");
    assert!(stamp < rename, "{seen:?}");

    let Seen::Setstat(path, _) = &seen[stamp] else {
        unreachable!("selected by the pattern above")
    };
    assert!(
        !path.ends_with("obj.bin"),
        "the stamp must land on the staging sibling, not the object: {path}"
    );
    let Seen::Rename(from, to) = &seen[rename] else {
        unreachable!("selected by the pattern above")
    };
    assert_eq!(from, path, "and on the path that is then renamed");
    assert!(to.ends_with("obj.bin"));
}

#[tokio::test]
async fn a_write_never_creates_the_base_it_was_configured_with() {
    // The defect that destroyed data: a base renamed away mid-run was silently
    // re-created underneath the run, seventeen of twenty-five objects landed in
    // the replacement, and every one of them was reported as stored and
    // verified. The rule is decided once, at connect — the base was there, so no
    // write in this run may put it back — and until now the *decision* was
    // reachable only against a real host.
    let (mock, sftp) = backend("/srv/store", &["/srv/store"]).await;

    // The base goes away underneath the run, exactly as a rename would take it.
    std::fs::rename(
        mock.root().join("srv/store"),
        mock.root().join("srv/store.gone"),
    )
    .expect("the base is renamed away");

    let data = b"this must not land anywhere";
    let error = sftp
        .put(
            &ObjectKey::new("deep/dir/obj.bin"),
            bytes::Bytes::from_static(data),
            &blake3(data),
            SourceModified::unknown(),
        )
        .await
        .expect_err("a write into a base that is gone must fail");
    assert!(
        format!("{error}").to_lowercase().contains("no such file")
            || format!("{error}").to_lowercase().contains("not found"),
        "the failure must name the missing path: {error}"
    );

    // Nothing was put back — not the base, and not the directory above it.
    assert!(
        !mock.root().join("srv/store").exists(),
        "the base was re-created underneath the run"
    );
    // And the server was never even asked to.
    assert!(
        !mock.saw(|seen| matches!(seen, Seen::Mkdir(path) if path == "/srv/store")),
        "a MKDIR of the configured base reached the server: {:?}",
        mock.seen()
    );
    assert!(
        !mock.saw(|seen| matches!(seen, Seen::Mkdir(path) if path == "/srv")),
        "a MKDIR above the configured base reached the server: {:?}",
        mock.seen()
    );
}

#[tokio::test]
async fn a_base_that_was_not_there_at_connect_is_created_by_the_first_write() {
    // The other half of the same rule, and the reason it is a decision rather
    // than a blanket refusal: `dctl config create backup sftp host=… base=/srv/new`
    // names a directory the first copy through it legitimately creates, exactly
    // as `local:` creates a root that was never there. Refusing here would break
    // the ordinary case in order to catch the rare one.
    // The base is deliberately *not* in the fixture: it is the directory the
    // first write is allowed to make.
    let (mock, sftp) = backend("/srv/new", &["/srv"]).await;
    assert!(!mock.root().join("srv/new").exists());

    let data = b"the first write";
    sftp.put(
        &ObjectKey::new("a/obj.bin"),
        bytes::Bytes::from_static(data),
        &blake3(data),
        SourceModified::unknown(),
    )
    .await
    .expect("the first write creates the base it was given");

    assert!(mock.root().join("srv/new/a/obj.bin").is_file());
    assert!(
        mock.saw(|seen| matches!(seen, Seen::Mkdir(path) if path == "/srv/new")),
        "the base itself had to be created: {:?}",
        mock.seen()
    );
    // Still never anything above it: `/srv` is not DCTL's to make.
    assert!(
        !mock.saw(|seen| matches!(seen, Seen::Mkdir(path) if path == "/srv")),
        "{:?}",
        mock.seen()
    );
}

#[tokio::test]
async fn the_store_identity_sees_the_base_go_and_says_how_much_it_can_tell() {
    // What the guard rests on for this backend. Existence and nothing stronger,
    // because version 3's `SSH_FXP_STAT` carries no inode — and the value says
    // so, rather than handing back a token that looks like a comparison and
    // never is one.
    let (mock, sftp) = backend("/srv/store", &["/srv/store"]).await;

    let present = sftp
        .store_identity()
        .await
        .expect("the probe succeeds")
        .expect("the base is there");
    assert_eq!(present.strength(), Strength::ExistenceOnly);

    std::fs::rename(
        mock.root().join("srv/store"),
        mock.root().join("srv/store.gone"),
    )
    .expect("the base is renamed away");
    assert_eq!(
        sftp.store_identity()
            .await
            .expect("the probe still succeeds"),
        None,
        "a base that has been removed is an absence, not an error"
    );
    assert_eq!(
        dctl_store::guard::identity::verdict(Some(&present), None),
        dctl_store::guard::identity::Verdict::Gone
    );

    // A file where the store should be is not a store either, and the guard's
    // `Gone` is the right verdict for it.
    std::fs::write(mock.root().join("srv/store"), b"not a directory").expect("a file is written");
    assert_eq!(
        sftp.store_identity()
            .await
            .expect("the probe succeeds over a plain file"),
        None
    );
}

#[tokio::test]
async fn an_object_round_trips_over_the_wire_and_the_staging_file_is_gone() {
    // The end-to-end shape, so the assertions above are known to be about a
    // backend that really works rather than one that merely sends the packets
    // they look for.
    let (mock, sftp) = backend("/srv/store", &["/srv/store"]).await;
    let data: Vec<u8> = (0..40_000u32).map(|n| (n % 251) as u8).collect();
    let key = ObjectKey::new("o/big.bin");

    sftp.put(
        &key,
        bytes::Bytes::from(data.clone()),
        &blake3(&data),
        SourceModified::at(AGED),
    )
    .await
    .expect("the write succeeds");

    assert_eq!(sftp.get(&key).await.expect("the object reads back"), data);
    assert_eq!(
        sftp.get_range(&key, dctl_store::ByteRange::new(100, Some(16)))
            .await
            .expect("a window reads back"),
        data[100..116]
    );
    assert!(sftp.exists(&key).await.expect("the lookup succeeds"));

    let page = sftp.list_page("", None).await.expect("the listing walks");
    let keys: Vec<String> = page
        .items
        .iter()
        .map(|meta| meta.key.as_str().to_string())
        .collect();
    assert_eq!(keys, vec!["o/big.bin".to_string()]);

    // A committed write leaves no staging file — not even a name.
    let listed = std::fs::read_dir(mock.root().join("srv/store/o"))
        .expect("the object directory is there")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(listed, vec!["big.bin".to_string()]);

    sftp.delete(&key).await.expect("the object deletes");
    assert!(!sftp.exists(&key).await.expect("the lookup succeeds"));
}

#[tokio::test]
async fn a_second_write_of_one_object_publishes_over_the_first() {
    // The rename is the commit, and version 3's plain `SSH_FXP_RENAME` refuses a
    // destination that exists — which is why the client prefers
    // `posix-rename@openssh.com` and why the mock advertises it. Without this
    // row, a backend that had lost the preference would pass every other test
    // here and fail on the second night of every backup.
    // The handle is held rather than named: dropping it removes the served
    // directory, and this test reads the object back through the backend.
    let (_mock, sftp) = backend("/srv/store", &["/srv/store"]).await;
    let key = ObjectKey::new("o/twice.bin");

    for body in [b"first".as_slice(), b"second".as_slice()] {
        sftp.put(
            &key,
            bytes::Bytes::from_static(body),
            &blake3(body),
            SourceModified::unknown(),
        )
        .await
        .expect("both writes succeed");
    }

    assert_eq!(
        sftp.get(&key).await.expect("the object reads back"),
        b"second"[..]
    );
}
