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
//!
//! ## Three groups, and they answer different questions
//!
//! The file has grown past the three guarantees it started with, and the reason
//! to read it in groups is that each group needs a different thing from the
//! server.
//!
//! 1. **The three original guarantees, and the round trip around them.** These
//!    arrange a *directory* and watch the backend deal with it.
//! 2. **Re-dialling** (§28), which needs a server that can be killed and will
//!    answer a second conversation over the same directory.
//! 3. **The protocol layer's own refusals** (§30), which need a server that
//!    **answers wrongly** — no size where the protocol allows none, a permission
//!    denial, a read that stops before the length it declared, a write it will
//!    not accept. Ten guards across this backend and S3's were deletable with
//!    `cargo test --workspace` staying green before this group existed;
//!    `handover-scripts/protocol-2026-07-30/reinstate-before.txt` is that
//!    measurement.
//!
//! Every test here is named for the **consequence** rather than for the packet,
//! because that is what a failure at three in the morning has to communicate.

mod support;

use bytes::Bytes;
use dctl_store::guard::Strength;
use dctl_store::sftp::SftpBackend;
use dctl_store::{
    Backend, ContentHash, Deadlines, HashAlgo, LinkPolicy, ObjectKey, SourceModified,
};
use support::mock_sftp::{MockSftp, RedialableSftp, Seen};

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
    let backend = SftpBackend::over_stream(
        pipes.writes,
        pipes.reads,
        base,
        LinkPolicy::Skip,
        Deadlines::default(),
    )
    .await
    .expect("the sftp conversation opens over a pipe");
    (mock, backend)
}

fn blake3(data: &[u8]) -> ContentHash {
    ContentHash::compute(HashAlgo::Blake3, data)
}

/// The host-side path of a wire path, for reading back what really happened.
fn on_disk(root: &std::path::Path, wire: &str) -> std::path::PathBuf {
    root.join(wire.trim_start_matches('/'))
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
    let landed = on_disk(mock.root(), "/srv/store/o/object.bin");
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

// ── re-dialling a dead session ───────────────────────────────────────────────
//
// `HANDOVER.md` §11.2's last open entry: *"Re-dial a dead connection."* Every
// backend retried, and none could re-establish anything — which on sftp is not
// a small gap, because a dropped session invalidates every open handle. The
// entry recorded that DCTL classified a dead session as terminal and told the
// operator to run the command again, and that this was the honest report of a
// thing the tool would not do.
//
// These run the **real** `SftpBackend` over the real client library against
// `support::mock_sftp::RedialableSftp`, which answers as many conversations as
// it is asked for over one directory and can be told to drop the live one
// without warning.

/// A backend that re-dials, over a server rooted at `base`.
/// Two seconds of patience for the re-dial tests.
///
/// Short, and **not zero**, and the difference turned out to be the whole story.
/// The first draft of these tests used `Deadlines::none()` on the reasoning that
/// a session which has *died* should not need a clock to notice. It hung — for
/// as long as the test harness would allow — and that is the finding, not the
/// flake:
///
/// **`openssh_sftp_client` does not surface a severed session to a request that
/// is already waiting for a reply.** The request is written into a pipe whose
/// far end has gone, the reply never comes, and nothing below the deadline ever
/// reports anything. `map_sftp_err`'s "the session is no longer usable" arm is
/// reachable — a *later* request meets the closed channel — but the request that
/// was in flight when the wire died is not one of them.
///
/// So the two halves of this pass are not two features that happen to have
/// landed together. Without `--timeout` a dead sftp session is not a slow
/// failure, it is a hang, and the retry layer never gets a turn; without the
/// re-dial the timeout would fire six times into the same corpse. Each is what
/// makes the other worth having.
const REDIAL_DEADLINES: Deadlines = Deadlines::from_seconds(2, 2);

async fn redialable(base: &str) -> (RedialableSftp, SftpBackend) {
    let mock = RedialableSftp::start();
    std::fs::create_dir_all(mock.root().join(base.trim_start_matches('/')))
        .expect("the fixture directory is created");
    let backend = SftpBackend::over_dialer(mock.dialer(), base, LinkPolicy::Skip, REDIAL_DEADLINES)
        .await
        .expect("the first conversation opens");
    (mock, backend)
}

#[tokio::test]
async fn a_severed_session_is_re_dialled_and_the_write_lands() {
    // The entry, closed. The session dies between two writes and the second one
    // has to succeed anyway — on a new connection, with the bytes really on the
    // server's disk, read back with `std::fs` rather than taken from the
    // backend's own account of itself.
    let (mock, sftp) = redialable("/srv/store").await;

    sftp.put(
        &ObjectKey::new("first.bin"),
        Bytes::from_static(b"before"),
        &blake3(b"before"),
        SourceModified::unknown(),
    )
    .await
    .expect("the first write goes over the first conversation");
    assert_eq!(
        mock.dials(),
        1,
        "nothing has needed a second connection yet"
    );

    // The wire dies. No goodbye, no protocol shutdown — a connection dies
    // without warning or it does not die at all.
    mock.sever();

    // The retry layer is what turns a discarded connection into a recovered
    // transfer, and it is wrapped here exactly as `remote::registry::build`
    // wraps it in production. Without it this call returns the transport error
    // and the operator does the re-dialling by hand, which is the state this
    // test exists to leave behind.
    let retrying = dctl_store::Retrying::wrap(std::sync::Arc::new(sftp) as _);
    retrying
        .put(
            &ObjectKey::new("second.bin"),
            Bytes::from_static(b"after"),
            &blake3(b"after"),
            SourceModified::unknown(),
        )
        .await
        .expect("the second write survives the session dying under it");

    assert!(
        mock.dials() >= 2,
        "the recovery must have opened a new conversation, not reused the dead one"
    );
    assert_eq!(
        std::fs::read(on_disk(mock.root(), "/srv/store/second.bin"))
            .expect("the object is really on the server"),
        b"after",
        "a re-dial that reports success without the bytes landing is the failure \
         this whole entry is about"
    );
}

#[tokio::test]
async fn a_healthy_session_is_never_re_dialled() {
    // The control, and it is not a formality: a backend that dialled per request
    // would pass the test above and be a different, quieter defect — one ssh
    // handshake per object, which on a proxied host is seconds each and would
    // never show up as an error.
    let (mock, sftp) = redialable("/srv/store").await;

    for index in 0..5 {
        let body = format!("object {index}");
        sftp.put(
            &ObjectKey::new(format!("obj-{index}.bin")),
            Bytes::from(body.clone()),
            &blake3(body.as_bytes()),
            SourceModified::unknown(),
        )
        .await
        .expect("a write on a healthy session");
    }
    let _ = sftp.list_page("", None).await.expect("a listing too");

    assert_eq!(
        mock.dials(),
        1,
        "five writes and a listing on one live session must reuse it"
    );
}

#[tokio::test]
async fn a_dead_session_is_reported_as_transport_so_the_retry_layer_will_try_again() {
    // The classification the re-dial rests on, asserted on the error's *shape*
    // rather than on its words. It was `StoreError::Backend` — which
    // `retry::observed` reads as permanent — and that was the correct answer for
    // a backend that could not re-dial. Changing it without the capability would
    // have bought five attempts into a socket that is not there.
    let (mock, sftp) = redialable("/srv/store").await;
    mock.sever();

    let started = std::time::Instant::now();
    let error = sftp
        .head(&ObjectKey::new("anything.bin"))
        .await
        .expect_err("the request cannot be answered by a session that has gone");
    let took = started.elapsed();

    assert!(
        matches!(&error, dctl_store::StoreError::Transport { backend, .. } if *backend == "sftp"),
        "a dead session must be transport, or nothing above will try again: {error:?}"
    );
    assert!(
        dctl_store::retry::Observed::of(&error).transient,
        "and the retry layer has to agree, or the classification is decorative"
    );

    // Which mechanism produced it, recorded rather than assumed — see
    // `REDIAL_DEADLINES`. It is the deadline, and the elapsed time is what says
    // so: a client library that had reported the closed channel would have
    // failed in microseconds. Pinned here because the day that changes is the
    // day this test could pass for a different reason than it does now.
    assert!(
        took >= std::time::Duration::from_secs(1),
        "the failure arrived in {took:?}, which means something below the \
         deadline reported the dead session — good news, and a change worth \
         knowing about rather than absorbing silently"
    );
    assert!(
        error.to_string().contains("no data moved"),
        "and it is the idle deadline's own wording: {error}"
    );
}

#[tokio::test]
async fn a_missing_object_does_not_throw_the_session_away() {
    // The other side of the same predicate, and the expensive one to get wrong.
    // A `NoSuchFile` is the server *answering*, so the conversation is fine; a
    // backend that re-dialled on every absent object would open a connection per
    // miss, and `sync` asks about every file it is considering.
    let (mock, sftp) = redialable("/srv/store").await;

    // `head`, not `exists`: `exists` folds a missing object into `Ok(false)`
    // *inside* the operation, so it never hands `on_link` an error at all and
    // this test would pass against a backend that discarded on every failure.
    // It did, in the first draft — the reinstatement that should have turned it
    // red came back green, which is how the weakness was found rather than
    // shipped. `head` returns `Err(NotFound)` and puts the predicate under real
    // load.
    for index in 0..4 {
        let error = sftp
            .head(&ObjectKey::new(format!("absent-{index}.bin")))
            .await
            .expect_err("a missing object is reported as missing");
        assert!(
            matches!(error, dctl_store::StoreError::NotFound(_)),
            "{error:?}"
        );
    }

    assert_eq!(
        mock.dials(),
        1,
        "a protocol answer is not a dead connection: four misses must not cost \
         four ssh handshakes, and `sync` asks about every file it considers"
    );
}

#[tokio::test]
async fn the_base_decision_survives_a_re_dial() {
    // The vanished-base guard, re-asked against a fact that did not exist before
    // this pass. `may_create_base` is decided by one `stat` on the **first**
    // connection precisely so a base that disappears mid-run stays disappeared.
    // A re-dial that re-probed would answer the question again on a connection
    // opened *after* the base was renamed away, get "not there, so make it", and
    // re-create underneath the run the very directory the field protects — which
    // is the defect that once put seventeen of twenty-five objects into a
    // directory nobody named and reported every one of them as stored.
    let (mock, sftp) = redialable("/srv/store").await;

    // The base goes away, and then so does the connection.
    std::fs::remove_dir_all(mock.root().join("srv/store")).expect("the base is removed");
    mock.sever();

    let retrying = dctl_store::Retrying::wrap(std::sync::Arc::new(sftp) as _);
    let _ = retrying
        .put(
            &ObjectKey::new("orphan.bin"),
            Bytes::from_static(b"data"),
            &blake3(b"data"),
            SourceModified::unknown(),
        )
        .await;

    assert!(
        mock.dials() >= 2,
        "the write must have re-dialled, or this proves nothing about re-dialling"
    );
    assert!(
        !mock.root().join("srv/store").exists(),
        "a re-dial must not re-create the base the run was told had gone"
    );
}

#[tokio::test]
async fn a_write_to_a_server_that_stops_answering_is_given_up_on() {
    // The gap this pass found in its own work. `--timeout` reached the sftp
    // backend through `SftpBackend::on_link`, which every request went through —
    // except the ones that actually move an object's bytes. `RemoteFs::create`
    // was guarded; the `write_all`, `sync` and `close` after it were not. So a
    // server that opened the staging file and then went quiet hung for as long
    // as TCP allowed, and the flag was a published claim reaching nothing on the
    // one path an operator cares most about.
    //
    // The wire is deliberately left healthy here — see `go_silent_on_write`. A
    // severed connection is noticed by other means; a server that simply stops
    // replying is noticed by the deadline or not at all.
    let (mock, sftp) = redialable("/srv/store").await;
    mock.go_silent_on_write();

    let started = std::time::Instant::now();
    let error = sftp
        .put(
            &ObjectKey::new("stalled.bin"),
            Bytes::from(vec![9u8; 64 * 1024]),
            &blake3(&vec![9u8; 64 * 1024]),
            SourceModified::unknown(),
        )
        .await
        .expect_err("a write nobody answers must not report success");
    let took = started.elapsed();

    assert!(
        matches!(&error, dctl_store::StoreError::Transport { backend, .. } if *backend == "sftp"),
        "and it must be transport, so the layer above tries again: {error:?}"
    );
    assert!(
        error.to_string().contains("--timeout"),
        "naming the dial the operator would turn: {error}"
    );
    assert!(
        took >= std::time::Duration::from_secs(1) && took < std::time::Duration::from_secs(15),
        "bounded by the deadline it was given, not by TCP: {took:?}"
    );
    assert!(
        !on_disk(mock.root(), "/srv/store/stalled.bin").exists(),
        "and nothing may be published: the object was never written whole"
    );
}

// ── the protocol layer's own refusals ────────────────────────────────────────
//
// `HANDOVER.md` §11.3 item 10, and the entries in §11.2 it stands behind. What
// separates these from everything above is where the fault comes from: the tests
// so far arrange a *directory* and watch the backend deal with it, and these
// arrange a **server that answers wrongly**, which is the only way to reach the
// arms that exist because a server can.
//
// Every fault below is one a real server produces — `support::mock_sftp::Faults`
// says which, per knob, and why a fault nobody's `sshd` can make would be worth
// nothing.

#[tokio::test]
async fn a_server_that_reports_no_file_size_is_refused_rather_than_read_as_empty() {
    // Three copies of `sftp server did not return file size`, one per read path,
    // and all three were unreachable in the plain gate before this file could
    // make a server omit the attribute (measured: three GREEN reinstatements).
    //
    // The consequence of losing them is not an error, which is what makes them
    // worth a test: version 3's attribute block is a flags word followed by only
    // the fields it claims, so a missing size arrives as `None` and the obvious
    // repair is `unwrap_or(0)`. Every object then heads as zero-length, every
    // ranged read serves nothing, and a download writes an empty file over a
    // good local copy and reports success.
    let (mock, sftp) = backend("/srv/store", &["/srv/store"]).await;
    let data = b"forty-one bytes of perfectly good object..";
    let key = ObjectKey::new("o/sized.bin");

    sftp.put(
        &key,
        Bytes::from_static(data),
        &blake3(data),
        SourceModified::unknown(),
    )
    .await
    .expect("the write succeeds while the server is still honest");

    // The control: with sizes reported, all three paths agree on the length.
    assert_eq!(
        sftp.head(&key).await.expect("the object heads").size,
        data.len() as u64
    );

    mock.omit_size();

    // `head` — what a listing and every `--checksum` comparison reads.
    let error = sftp
        .head(&key)
        .await
        .expect_err("a size the server did not give must not be invented");
    assert!(
        format!("{error}").contains("did not return file size"),
        "the refusal must name what was missing: {error}"
    );

    // A ranged read — the mount's seek path.
    let error = sftp
        .get_range(&key, dctl_store::ByteRange::new(0, Some(8)))
        .await
        .expect_err("a window of an object whose length is unknown is not servable");
    assert!(
        format!("{error}").contains("did not return file size"),
        "{error}"
    );

    // And the download, which is the one that would overwrite a local file.
    let into = tempfile::TempDir::new().expect("a temporary directory");
    let dest = into.path().join("restored.bin");
    let error = sftp
        .get_to_path(&key, &dest)
        .await
        .expect_err("a download of an object of unknown length must not publish");
    assert!(
        format!("{error}").contains("did not return file size"),
        "{error}"
    );
    assert!(
        !dest.exists(),
        "and it must leave nothing behind: an empty file here is the defect, \
         because it is indistinguishable from a restored one"
    );
}

#[tokio::test]
async fn a_permission_denial_is_terminal_and_does_not_cost_the_session() {
    // The classification `map_sftp_err` draws, driven by a server that really
    // refuses rather than by constructing the error value directly — the point
    // being that the packet has to travel through the real client library for
    // the arm that reads it to be the arm production uses.
    //
    // Both halves matter and they pull in opposite directions. A denial is a
    // statement about the *request*, equally true next time, so retrying it
    // spends five attempts to be told the same thing five times. A severed
    // session is a statement about the *conversation*, so not retrying it turns
    // a recoverable drop into a failed backup. §28.4 moved one arm between these
    // two and this is the test that says the other one did not move with it.
    let (mock, sftp) = redialable("/srv/store").await;
    mock.deny("locked");

    let error = sftp
        .put(
            &ObjectKey::new("locked/obj.bin"),
            Bytes::from_static(b"data"),
            &blake3(b"data"),
            SourceModified::unknown(),
        )
        .await
        .expect_err("a write the server refuses must not report success");

    assert!(
        matches!(&error, dctl_store::StoreError::Backend(detail) if detail.contains("PermDenied")),
        "the server answered, so this is about the request and not the link: {error:?}"
    );
    assert!(
        !dctl_store::retry::Observed::of(&error).transient,
        "a refusal is equally true on the next attempt, so retrying it buys \
         nothing and costs the operator four more round trips: {error:?}"
    );

    // And the conversation is untouched: a refusal is the server working.
    assert_eq!(
        mock.dials(),
        1,
        "a denial must not be mistaken for a dead session and re-dialled"
    );
    mock.allow_everything();
    sftp.put(
        &ObjectKey::new("locked/obj.bin"),
        Bytes::from_static(b"data"),
        &blake3(b"data"),
        SourceModified::unknown(),
    )
    .await
    .expect("the same session still works once the permission is fixed");
    assert_eq!(mock.dials(), 1, "and still on the first connection");
}

#[tokio::test]
async fn a_server_that_stops_serving_bytes_never_publishes_a_short_object() {
    // The worst outcome this product has, in the shape sftp can produce it: a
    // server whose `stat` declares one length and whose reads end at another.
    // `SSH_FX_EOF` is not an error — to the client it is indistinguishable from
    // a file that really ended there — so nothing below DCTL's own comparison
    // against the declared length can notice, and what would land at `dest` is a
    // **prefix** of the object with no mark on it anywhere.
    //
    // A truncated restore that reports success is worse than a failed one,
    // because the failed one gets retried.
    let (mock, sftp) = backend("/srv/store", &["/srv/store"]).await;
    let data: Vec<u8> = (0..50_000u32).map(|n| (n % 251) as u8).collect();
    let key = ObjectKey::new("o/whole.bin");
    sftp.put(
        &key,
        Bytes::from(data.clone()),
        &blake3(&data),
        SourceModified::unknown(),
    )
    .await
    .expect("the object is stored whole");

    // The server keeps declaring 50 000 and stops handing bytes over at 4 096.
    mock.serve_at_most(4_096);

    let into = tempfile::TempDir::new().expect("a temporary directory");
    let dest = into.path().join("restored.bin");
    let error = sftp
        .get_to_path(&key, &dest)
        .await
        .expect_err("an object the server stopped serving must not be published");

    assert!(
        !dest.exists(),
        "the staging file must not be renamed into place: a 4 KiB file at the \
         name of a 50 KB object, with a successful exit, is the failure this \
         whole test exists to prevent"
    );
    // Nothing partial is left beside it either.
    let leftovers: Vec<String> = std::fs::read_dir(into.path())
        .expect("the destination directory is there")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        leftovers.is_empty(),
        "a failed download left debris behind: {leftovers:?}"
    );
    // The error names the transfer rather than the file's contents: nothing was
    // corrupt, the server simply stopped.
    let text = format!("{error}").to_lowercase();
    assert!(
        !text.contains("checksum"),
        "a server that stopped serving is not a checksum failure, and saying so \
         sends the operator to look at the wrong thing: {error}"
    );
}

#[tokio::test]
async fn a_directory_that_is_already_there_does_not_fail_the_write_that_needs_it() {
    // `mkdir_p` issues one `SSH_FXP_MKDIR` per ancestor and drops the result,
    // and the dropped result is load-bearing rather than lazy: after the first
    // object under a prefix, every later one meets `SSH_FX_FAILURE` /
    // `EEXIST` for every directory in its path. Propagating that would leave a
    // backend that stores the first file of every directory and refuses the
    // rest — a defect that needs a *second* write to appear, which is why an
    // end-to-end test that stores one object cannot see it.
    let (mock, sftp) = backend("/srv/store", &["/srv/store"]).await;

    for index in 0..3 {
        let body = format!("object {index}");
        sftp.put(
            &ObjectKey::new(format!("a/b/c/obj-{index}.bin")),
            Bytes::from(body.clone()),
            &blake3(body.as_bytes()),
            SourceModified::unknown(),
        )
        .await
        .expect("every write into an existing directory succeeds");
    }

    // The request really was re-sent and really was refused — otherwise this
    // passes against a backend that had learned to skip the `mkdir`, which is a
    // different (and fine) design that this test must not silently start
    // asserting.
    let asked = mock
        .seen()
        .iter()
        .filter(|seen| matches!(seen, Seen::Mkdir(path) if path == "/srv/store/a/b/c"))
        .count();
    assert!(
        asked >= 2,
        "the second write must have asked for the directory again: {:?}",
        mock.seen()
    );
    for index in 0..3 {
        assert!(
            mock.root()
                .join(format!("srv/store/a/b/c/obj-{index}.bin"))
                .is_file()
        );
    }
}

#[tokio::test]
async fn a_write_the_server_stops_accepting_leaves_no_staging_file_behind() {
    // The commonest real write failure on a shared host — a quota met or a
    // filesystem filled — and the only one that happens **part-way through an
    // object**. An `open` that fails leaves nothing; a write that fails at 60%
    // leaves 60% of an object under a staging name nobody looks at again, on
    // every retry, for as long as the disk stays full.
    //
    // `HANDOVER.md` §24.1 is what that debris costs and `cleanup` is what
    // reclaims it, but the cheaper answer is the write path not making any: the
    // `remove_quiet` in the loop's error arm. It could be deleted with the plain
    // gate staying green.
    let (mock, sftp) = backend("/srv/store", &["/srv/store"]).await;
    let data: Vec<u8> = (0..200_000u32).map(|n| (n % 251) as u8).collect();

    // Enough room for some of the object and not for all of it.
    mock.accept_at_most(64 * 1024);

    // All **three** writers, because each stages and each cleans up in its own
    // error arm — the same shape `HANDOVER.md` §26.1 found in `source::plain`'s
    // three truncation refusals, where two of the three had no witness. A test
    // that exercised only `put` would leave the two streaming writers, which are
    // the ones a large object actually takes, unwatched.
    let dir = tempfile::TempDir::new().expect("a temporary directory");
    let source = dir.path().join("big.bin");
    std::fs::write(&source, &data).expect("the source file is written");

    let buffered = sftp
        .put(
            &ObjectKey::new("o/buffered.bin"),
            Bytes::from(data.clone()),
            &blake3(&data),
            SourceModified::unknown(),
        )
        .await
        .expect_err("a write the server refused part-way must not report success");

    let from_file = sftp
        .put_from_path(
            &ObjectKey::new("o/from-file.bin"),
            &source,
            &blake3(&data),
            SourceModified::unknown(),
        )
        .await
        .expect_err("nor may the file-fed writer");

    // The producer hands over the **whole** object and closes cleanly, so the
    // only thing that can fail is the server. A producer that stopped would
    // fail one line earlier, in the window arm, and this test would be about
    // that instead — which is what
    // `a_producer_that_stops_mid_object_leaves_no_staging_file_behind` is for.
    // The object is well under the pipe's bound, so `finish` cannot block on a
    // consumer that has already given up.
    let (mut writer, stream) = dctl_store::object_stream(data.len() as u64, HashAlgo::Blake3);
    let owned = data.clone();
    let producing = tokio::task::spawn_blocking(move || {
        use std::io::Write as _;
        writer
            .write_all(&owned)
            .expect("the pipe takes the whole object");
        writer.finish().expect("and the end of it");
    });
    let from_producer = sftp
        .put_stream(
            &ObjectKey::new("o/from-producer.bin"),
            stream,
            SourceModified::unknown(),
        )
        .await
        .expect_err("nor may the producer-fed writer");
    producing.await.expect("the producer ran");

    // The server's own words reach the caller, through all three. A write that
    // failed for a reason the operator cannot read is a support ticket, and
    // `map_sftp_err`'s "the server answered, so the conversation is not what is
    // wrong" arm is what keeps the message rather than replacing it with a
    // transport error.
    for (writer, error) in [
        ("buffered", &buffered),
        ("from a file", &from_file),
        ("from a producer", &from_producer),
    ] {
        assert!(
            format!("{error}").contains("no space left on device"),
            "the {writer} writer lost the server's reason: {error}"
        );
    }

    // Nothing was published under any of the three names...
    for name in ["buffered.bin", "from-file.bin", "from-producer.bin"] {
        assert!(
            !mock.root().join(format!("srv/store/o/{name}")).exists(),
            "a partial object was published as {name}"
        );
    }
    // ...and no staging sibling was left behind. This is the assertion the three
    // `remove_quiet` calls exist for: without them the directory holds three
    // files under names no listing shows and no later run reuses, and every
    // retry adds three more.
    //
    // The budget is per **conversation** and all three writers share one, so the
    // first fails part-way through its object and the other two are refused at
    // their first window. Both matter and both leave debris: `create` opens the
    // staging file before any byte is written, so a writer refused immediately
    // has still made a file — an empty one, with a name that looks exactly like
    // an interrupted transfer's.
    let leftovers: Vec<String> = std::fs::read_dir(mock.root().join("srv/store/o"))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        leftovers.is_empty(),
        "the failed writes left staging debris on the server: {leftovers:?}"
    );
    // And the removals really were requested, rather than the directory being
    // empty because nothing was ever created there.
    let removed = mock
        .seen()
        .iter()
        .filter(|seen| matches!(seen, Seen::Remove(path) if path.contains(".dctl-staging")))
        .count();
    assert_eq!(removed, 3, "one REMOVE per writer: {:?}", mock.seen());
}

#[tokio::test]
async fn a_directory_the_server_refuses_fails_the_listing_rather_than_shrinking_it() {
    // The most expensive thing a walk can do quietly. `list_page` folds a
    // *missing* directory into an empty listing, which is correct — a prefix
    // with no objects under it is not an error. One arm away is the same
    // treatment for a directory the server **refused**, and the difference is
    // the difference between "there is nothing here" and "I was not allowed to
    // look".
    //
    // A listing that silently shrinks is what `sync --delete` reads as "these
    // objects are gone from the source", and the objects it then deletes at the
    // destination are the ones nobody could enumerate. The guard is
    // `tree.rs`'s `other => return Err(other)`, and it could be deleted with the
    // plain gate staying green.
    let (mock, sftp) = backend("/srv/store", &["/srv/store"]).await;

    for name in ["visible/a.bin", "restricted/b.bin"] {
        let body = name.as_bytes();
        sftp.put(
            &ObjectKey::new(name),
            Bytes::from_static(b"x"),
            &blake3(b"x"),
            SourceModified::unknown(),
        )
        .await
        .unwrap_or_else(|e| panic!("the fixture stores {name}: {e}"));
        let _ = body;
    }

    // The control: both are there while the server is willing to be read.
    let page = sftp.list_page("", None).await.expect("the listing walks");
    assert_eq!(page.items.len(), 2, "the fixture must hold two objects");

    mock.deny("restricted");

    let error = sftp
        .list_page("", None)
        .await
        .expect_err("a directory the walk could not read must not be reported as empty");
    assert!(
        !matches!(error, dctl_store::StoreError::NotFound(_)),
        "a refusal is not an absence, and reporting it as one is the defect: {error:?}"
    );
    assert!(
        format!("{error}").to_lowercase().contains("denied"),
        "the failure must name the refusal so an operator can fix the permission: {error}"
    );
}

#[tokio::test]
async fn a_producer_that_stops_mid_object_leaves_no_staging_file_behind() {
    // The other fault with the same consequence, and it needs its own test
    // because it fails one line earlier. Here the **server** is healthy and the
    // *producer* stops — a vault sealer that hit a read error on the source, a
    // `dctl rcat` whose pipe was closed, a killed upstream — so the failure
    // arrives from `ObjectStream::window` rather than from the write.
    //
    // Both arms clean up, and both had to be watched separately: a test that
    // covered one would leave the other's `remove_quiet` deletable with the
    // plain gate staying green, which is exactly how these three copies came to
    // be worth checking one at a time.
    let (mock, sftp) = backend("/srv/store", &["/srv/store"]).await;
    let declared = 400_000u64;

    let (mut writer, stream) = dctl_store::object_stream(declared, HashAlgo::Blake3);
    let producing = tokio::task::spawn_blocking(move || {
        use std::io::Write as _;
        // Half of what was declared, and then gone without `finish`.
        let part: Vec<u8> = (0..200_000u32).map(|n| (n % 251) as u8).collect();
        let _ = writer.write_all(&part);
        drop(writer);
    });
    let error = sftp
        .put_stream(
            &ObjectKey::new("o/abandoned.bin"),
            stream,
            SourceModified::unknown(),
        )
        .await
        .expect_err("an object its producer abandoned must not be published");
    producing.await.expect("the producer ran");

    assert!(
        format!("{error}").contains("stopped before it finished"),
        "the failure must name the producer rather than the server, or an          operator goes looking at the network: {error}"
    );
    assert!(
        !mock.root().join("srv/store/o/abandoned.bin").exists(),
        "half an object was published"
    );
    let leftovers: Vec<String> = std::fs::read_dir(mock.root().join("srv/store/o"))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        leftovers.is_empty(),
        "the abandoned write left staging debris on the server: {leftovers:?}"
    );
    assert!(
        mock.saw(|seen| matches!(seen, Seen::Remove(path) if path.contains(".dctl-staging"))),
        "no REMOVE of the staging path reached the server: {:?}",
        mock.seen()
    );

    // And the quieter shape of the same fault: a producer that stops short and
    // then says it is **done**. Nothing is broken — the stream ends cleanly, the
    // loop reaches its own `break`, and the object is simply not as long as it
    // was declared to be. That is caught one line further on, by `agreed`, whose
    // cleanup arm is a third copy of the same removal and needs the producer to
    // have closed properly to be reached at all.
    let (mut writer, stream) = dctl_store::object_stream(declared, HashAlgo::Blake3);
    let producing = tokio::task::spawn_blocking(move || {
        use std::io::Write as _;
        let part: Vec<u8> = (0..120_000u32).map(|n| (n % 251) as u8).collect();
        writer
            .write_all(&part)
            .expect("the pipe takes what there is");
        writer
            .finish()
            .expect("and the producer says it is finished");
    });
    let error = sftp
        .put_stream(
            &ObjectKey::new("o/short.bin"),
            stream,
            SourceModified::unknown(),
        )
        .await
        .expect_err("an object shorter than its declaration must not be published");
    producing.await.expect("the producer ran");

    assert!(
        matches!(error, dctl_store::StoreError::ShortWrite { .. }),
        "a short object is a write that stopped, not a checksum failure — the          two send an operator to different places: {error:?}"
    );
    assert!(!mock.root().join("srv/store/o/short.bin").exists());
    let leftovers: Vec<String> = std::fs::read_dir(mock.root().join("srv/store/o"))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    // Two assertions, and the order they are written in is the order to read a
    // failure in. `remove_quiet` is best-effort by design — it swallows its own
    // error, because the error worth reporting is the one already in hand — so
    // the **request** is the guarantee and the empty directory is the outcome.
    // A future failure of the second with the first intact is the server's
    // problem; a failure of the first is DCTL's.
    assert_eq!(
        mock.seen()
            .iter()
            .filter(|seen| matches!(seen, Seen::Remove(path) if path.contains(".dctl-staging")))
            .count(),
        2,
        "one REMOVE per failed write, and this is the second: {:?}",
        mock.seen()
    );
    assert!(
        leftovers.is_empty(),
        "the short write left staging debris on the server: {leftovers:?}"
    );
}
