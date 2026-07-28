//! What comes back where a symbolic link used to be.
//!
//! The question `HANDOVER.md` §11.2's last defect leaves behind once the link is
//! no longer dropped in silence: a followed link goes *in* as a directory tree
//! under the link's own name — does it come *out* as a link, or as a copy?
//!
//! **As a copy, and that is the whole answer.** A vault is keyed by logical
//! path. It has records for paths that hold bytes and no record type for "this
//! path is a link to that one" — rclone has one, `-l/--links`, which writes the
//! target into a `.rclonelink` file (`backend/local/local.go:110`), and DCTL
//! deliberately does not. So `srv/data -> /mnt/bigdisk/data` backed up with
//! `--links follow` restores as a real directory `srv/data` holding real files.
//! A skipped link restores as nothing at all, because nothing about it was ever
//! stored.
//!
//! Both halves are asserted here rather than written down, because "restores as
//! a copy" is exactly the kind of claim that is true when it is made and quietly
//! stops being true. The consequences an operator has to plan for follow from
//! it and are worth stating plainly:
//!
//! * A restore of a followed tree needs **space for the data**, not for a link.
//!   Two links to one 400 GB directory restore as 800 GB.
//! * The layout is not reproduced. A machine restored from `/srv` gets a real
//!   `/srv/data`, and if the operator wants the volume back on `/mnt/bigdisk`
//!   they re-create the link and move the data themselves.
//! * A tree backed up with the default policy has **no record of the link at
//!   all**. That is why the run says so at the time: the warning is the only
//!   notice there will ever be.
//!
//! This module is a drill and not a unit test for the reason the rest of the
//! suite is: the claim spans the walk, the vault, the index, a destroyed index,
//! a rebuild and a restore, and every one of those layers passes its own tests
//! while the sequence does not.

use crate::harness::{Backend, Sandbox, VAULT_REMOTE, init};

/// Bytes behind the link, distinctive enough that finding them proves which
/// file was restored rather than merely that a file was.
const BEHIND_THE_LINK: &[u8] = b"stored through a followed symbolic link\n";

/// Bytes of the ordinary file beside it, so a restore that dropped everything
/// can be told apart from one that dropped only the link.
const ON_THE_SYSTEM_DISK: &[u8] = b"an ordinary file on the small disk\n";

#[test]
fn a_followed_link_restores_as_a_copy_and_a_skipped_one_restores_as_nothing() {
    let sandbox = Sandbox::new();
    let backend = Backend::Local;
    let source = layout(&sandbox);
    let source_arg = source.to_str().expect("a UTF-8 sandbox path");
    init(&sandbox, &backend);

    // ── Backed up with the link followed ─────────────────────────────────
    sandbox
        .run_with_password(
            &backend,
            &[
                "backup",
                source_arg,
                &format!("{VAULT_REMOTE}:followed"),
                "--links",
                "follow",
            ],
        )
        .expect_success("backing up with links followed");

    // ── …and with the default, which passes over it ──────────────────────
    sandbox
        .run_with_password(
            &backend,
            &["backup", source_arg, &format!("{VAULT_REMOTE}:skipped")],
        )
        .expect_success("backing up with the default policy");

    let followed = sandbox.path("restored-followed");
    sandbox
        .run_with_password(
            &backend,
            &[
                "restore",
                &format!("{VAULT_REMOTE}:followed"),
                followed.to_str().expect("a UTF-8 sandbox path"),
            ],
        )
        .expect_success("restoring the followed backup");

    let skipped = sandbox.path("restored-skipped");
    sandbox
        .run_with_password(
            &backend,
            &[
                "restore",
                &format!("{VAULT_REMOTE}:skipped"),
                skipped.to_str().expect("a UTF-8 sandbox path"),
            ],
        )
        .expect_success("restoring the default backup");

    // The bytes came back, under the link's own name.
    let restored_target = followed.join("data/report.csv");
    assert_eq!(
        std::fs::read(&restored_target).unwrap_or_else(|error| panic!(
            "the followed link's target did not come back at {}: {error}",
            restored_target.display()
        )),
        BEHIND_THE_LINK
    );

    // And what came back is a **real directory**, not a link. This is the
    // assertion the module exists for: `symlink_metadata` does not traverse, so
    // it is the only call that can tell a restored copy from a restored link.
    let restored_dir =
        std::fs::symlink_metadata(followed.join("data")).expect("the restored path exists");
    assert!(
        !restored_dir.is_symlink(),
        "a followed link restored as a link; the vault stores bytes at a path and \
         has no record type that could have reproduced one"
    );
    assert!(restored_dir.is_dir(), "and it is a directory of real files");

    // The ordinary file is in both, so the difference below is about the link
    // and not about the backup having failed.
    for (name, root) in [("followed", &followed), ("skipped", &skipped)] {
        assert_eq!(
            std::fs::read(root.join("readme.txt")).expect("the ordinary file comes back"),
            ON_THE_SYSTEM_DISK,
            "the {name} restore lost a file that had nothing to do with links"
        );
    }

    // The skipped run stored no record of the link, so the restore produces
    // nothing there — not an empty directory, and not a dangling link.
    assert!(
        !skipped.join("data").exists(),
        "the default policy stored nothing about the link, so a restore must \
         produce nothing at that path"
    );
    assert!(
        std::fs::symlink_metadata(skipped.join("data")).is_err(),
        "and not a dangling link either"
    );
}

/// `/srv` with its data on another volume, linked into place.
///
/// Built with absolute paths inside the sandbox, so the link resolves without
/// depending on the process's working directory — which the drill's runner sets
/// to the sandbox root and which a future change could reasonably move.
fn layout(sandbox: &Sandbox) -> std::path::PathBuf {
    let bigdisk = sandbox.path("mnt/bigdisk/data");
    std::fs::create_dir_all(&bigdisk).expect("create the other volume");
    std::fs::write(bigdisk.join("report.csv"), BEHIND_THE_LINK).expect("write behind the link");

    let srv = sandbox.path("srv");
    std::fs::create_dir_all(&srv).expect("create the system disk tree");
    std::fs::write(srv.join("readme.txt"), ON_THE_SYSTEM_DISK).expect("write beside the link");
    std::os::unix::fs::symlink(&bigdisk, srv.join("data")).expect("link the volume into place");
    srv
}
