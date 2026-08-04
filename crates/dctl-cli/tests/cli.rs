//! End-to-end tests that drive the shipped `dctl` binary.
//!
//! These are deliberately *not* unit tests. Every assertion below is made
//! against a real process: its exit status, its two output streams, and the
//! bytes it left on a filesystem. That is the only level at which the promises
//! on the tin can be checked — a unit test can prove `Engine::upload` writes a
//! buffer, but only running the binary proves the argument parser, the plan, the
//! guards and the engine are wired to each other in the order the docs claim.
//!
//! ## What is asserted, and why each one earns its place
//!
//! * **Bytes, not counters.** A transfer is verified by reading the destination
//!   and comparing it to the source, never by a "Files: 1 / 1" line. A counter
//!   can be incremented by a stage that did nothing; a file on disk cannot.
//! * **Specific exit codes.** `ExitCode` is a published contract (`src/exit.rs`),
//!   so a test that merely asserts "failure" would pass while the code silently
//!   changed from 3 to 7 and broke every script branching on it.
//! * **The absence of plaintext.** [`copy_into_a_directory_holding_a_vault_is_refused`]
//!   is the most valuable test in this file. DCTL's entire promise is that data
//!   is sealed before it lands, so the failure mode worth pinning is not "the
//!   command errored" but "the unencrypted bytes are nowhere on disk".
//!
//! ## Isolation
//!
//! Each test owns a [`Sandbox`] — a fresh temporary directory — and every
//! invocation passes `--config` and `--index` explicitly. Nothing here may read
//! or write the developer's real configuration, index or data directory, so the
//! inherited `DCTL_*` environment is cleared on every command too: a maintainer
//! with `DCTL_REMOTE` exported must not see different results from CI.
//!
//! ## Both kinds of remote, end to end
//!
//! A named remote is now enumerated and written through for real, so the two
//! shapes that matter are asserted here rather than only in unit tests:
//! [`copy_into_a_plain_configured_remote_needs_no_password_and_lands_the_bytes`]
//! stores bytes through an ordinary remote with prompting switched off, and
//! [`copy_into_a_vault_remote_still_needs_the_key_and_still_seals`] proves the
//! sealed remote still refuses without a key and still writes nothing readable
//! when it has one. They are a pair on purpose: the defect they pin was one
//! answer being given to both questions.
//!
//! Also asserted end-to-end is the refusal
//! ([`copy_to_a_provider_shorthand_never_lands_in_a_directory_of_that_name`]):
//! a named remote must never quietly become a local directory, because that
//! failure looked exactly like a successful backup.
//!
//! ## Deliberately not covered
//!
//! Nothing here contacts a cloud provider. `b2:`, `s3:` and `r2:` appear only in
//! the tests that assert a *refusal*, and the inherited credentials are cleared
//! so a maintainer with real keys cannot have a test upload to somebody's
//! bucket.
//!
//! The addressing invariants themselves — including that no flag makes a vault
//! write land as plaintext even while the sealed path is unfinished — live in
//! `tests/invariant_i4/`, which asserts on the bytes under the store rather than
//! on today's exit codes.

use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

use assert_cmd::Command;
// `.not()` on a predicate: a refusal that must *not* appear is as much a
// property as one that must, and asserting its absence is how a reinstated
// "not implemented" would be caught rather than quietly passing.
use predicates::prelude::PredicateBooleanExt as _;
use tempfile::TempDir;

/// Environment variables that would silently redirect a run away from its
/// sandbox. Cleared before every invocation.
///
/// `--config` and `--index` are always passed explicitly, so these could only
/// change behaviour by accident — which is exactly the accident worth removing,
/// since `DCTL_PASSWORD` in a maintainer's shell would make a test that should
/// fail on a missing password quietly succeed.
/// The provider credentials belong on the list for the same reason: a
/// maintainer with real B2 keys exported would have
/// [`copy_to_a_provider_shorthand_never_lands_in_a_directory_of_that_name`]
/// attempt a live upload to somebody's bucket instead of failing on a missing
/// key, which is neither a passing test nor an acceptable side effect.
const INHERITED_ENV: &[&str] = &[
    "DCTL_CONFIG",
    "DCTL_INDEX",
    "DCTL_REMOTE",
    "DCTL_PASSWORD",
    "DCTL_PASSWORD_COMMAND",
    "DCTL_LOG_LEVEL",
    "DCTL_LOG_FORMAT",
    "DCTL_B2_KEY_ID",
    "DCTL_B2_APP_KEY",
];

/// A password long enough to satisfy `constants::MIN_VAULT_PASSWORD_LEN`.
const GOOD_PASSWORD: &str = "correct horse battery staple";

/// Shorter than the minimum, so `init` must refuse it.
const SHORT_PASSWORD: &str = "short";

/// The one file every vault has and no ordinary directory has by accident.
/// Mirrors `constants::VAULT_ENVELOPE_OBJECT_KEY`; spelled out here so the test
/// pins the on-disk layout rather than following the code that produced it.
/// Name given to the vault every test creates.
///
/// `dctl init` now registers two remotes — the sealed view and its object store
/// — and both need names, so the tests name the vault explicitly rather than
/// letting one be invented. The store is then `<VAULT_NAME>-store`.
const VAULT_NAME: &str = "archive";

const ENVELOPE: &str = "system/envelope.bin";

/// An isolated working area for one test.
struct Sandbox {
    root: TempDir,
}

impl Sandbox {
    fn new() -> Self {
        Self {
            root: TempDir::new().expect("a temporary directory"),
        }
    }

    /// An absolute path inside the sandbox. Nothing is created.
    fn path(&self, relative: &str) -> PathBuf {
        self.root.path().join(relative)
    }

    /// Create a directory (and its parents) inside the sandbox.
    fn dir(&self, relative: &str) -> PathBuf {
        let path = self.path(relative);
        std::fs::create_dir_all(&path).expect("create directory");
        path
    }

    /// Write a file inside the sandbox, creating parent directories.
    fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = self.path(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent directory");
        }
        std::fs::write(&path, bytes).expect("write file");
        path
    }

    /// Backdate a file's modification time by `seconds`.
    ///
    /// Not decoration. A source file written a moment ago and a destination
    /// written a moment later fall inside `DEFAULT_MODIFY_WINDOW_SECS`, so a
    /// comparison that is completely broken still *looks* right on a fixture
    /// built and copied inside one second. Ageing the source is what makes the
    /// difference between "the times agree" and "the times were never
    /// comparable" observable — which is the whole of defect D5.
    fn age(&self, relative: &str, seconds: u64) {
        let path = self.path(relative);
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(seconds);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open the file to backdate it")
            .set_modified(when)
            .expect("set the modification time");
    }

    /// Replace a file's contents while leaving its modification time exactly
    /// where it was.
    ///
    /// The edit a size-and-time comparison is blind to by construction, and the
    /// only thing `--checksum` can be tested against. Capturing and restoring the
    /// file's *own* timestamp rather than backdating it again from the clock:
    /// `now - A_DAY` computed a second time is a second later than the first, and
    /// a second is the modify window — so a test written that way passes or fails
    /// depending on how long the commands before it took, which is the kind of
    /// flake that gets a real failure dismissed as noise.
    fn edit_keeping_time(&self, relative: &str, bytes: &[u8]) {
        let path = self.path(relative);
        let when = std::fs::metadata(&path)
            .expect("the file exists")
            .modified()
            .expect("this platform reports modification times");
        std::fs::write(&path, bytes).expect("rewrite the file");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open the file to restore its time")
            .set_modified(when)
            .expect("restore the modification time");
    }

    fn read(&self, relative: &str) -> Vec<u8> {
        std::fs::read(self.path(relative)).expect("read file")
    }

    fn exists(&self, relative: &str) -> bool {
        self.path(relative).exists()
    }

    /// A `dctl` invocation wired to this sandbox.
    ///
    /// `--config` and `--index` are supplied on every call, even by tests that
    /// never touch either: the point is that no run can fall back to the
    /// platform config or data directory, and leaving them off "because this
    /// command does not need them" is how one eventually does.
    fn dctl(&self) -> Command {
        let mut cmd = Command::cargo_bin("dctl").expect("the dctl binary is built");
        for key in INHERITED_ENV {
            cmd.env_remove(key);
        }
        cmd.current_dir(self.root.path())
            .arg("--config")
            .arg(self.path("dctl.toml"))
            .arg("--index")
            .arg(self.path("index.redb"))
            // Styling would otherwise depend on whether a terminal is attached,
            // and every `contains` assertion below would become flaky under a
            // different test runner.
            .arg("--color")
            .arg("never");
        cmd
    }
}

/// Every regular file under `root`, recursively.
///
/// Used by the vault guard test, which has to prove a *negative* — that a
/// plaintext file is nowhere at all, not merely absent from the path it would
/// most obviously have been written to.
fn all_files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let Ok(children) = std::fs::read_dir(&directory) else {
            continue;
        };
        for child in children.flatten() {
            let path = child.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

/// Parse a command's stdout as a single JSON document.
///
/// Fails loudly with the offending text, because "the output did not parse" is
/// useless without seeing what was actually printed.
fn json(stdout: &[u8]) -> serde_json::Value {
    let text = String::from_utf8_lossy(stdout);
    serde_json::from_str(&text).unwrap_or_else(|error| {
        panic!("stdout is not valid JSON ({error}):\n{text}");
    })
}

// ── 1. copy ───────────────────────────────────────────────────────────────────

#[test]
fn copy_moves_real_bytes_and_leaves_the_source_alone() {
    // The regression that matters most for `copy`: reporting a transfer that
    // did not happen. Asserted on the destination's contents, and on the
    // source's continued existence — the single property that separates `copy`
    // from `move`.
    let sandbox = Sandbox::new();
    sandbox.write("src/a.txt", b"hello dctl");
    sandbox.write("src/nested/b.txt", b"a nested payload");
    sandbox.dir("dst");

    sandbox
        .dctl()
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(sandbox.path("dst"))
        .assert()
        .success();

    assert_eq!(sandbox.read("dst/a.txt"), b"hello dctl");
    assert_eq!(
        sandbox.read("dst/nested/b.txt"),
        b"a nested payload",
        "the tree's shape must survive the transfer"
    );
    assert_eq!(
        sandbox.read("src/a.txt"),
        b"hello dctl",
        "copy must never remove or alter a source file"
    );
    assert!(sandbox.exists("src/nested/b.txt"));
}

#[test]
fn copy_creates_a_destination_that_does_not_exist_yet() {
    // The ordinary first run. A destination that has to be created is not an
    // error, and the guard against writing into a vault must not make it one.
    let sandbox = Sandbox::new();
    sandbox.write("src/only.txt", b"first run");

    sandbox
        .dctl()
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(sandbox.path("brand-new"))
        .assert()
        .success();

    assert_eq!(sandbox.read("brand-new/only.txt"), b"first run");
}

// ── 2. move ───────────────────────────────────────────────────────────────────

#[test]
fn move_removes_the_source_only_once_the_destination_holds_it() {
    // `move` is the verb that can lose data. The ordering guarantee is the whole
    // point, so both halves are asserted together: the destination must hold the
    // exact bytes *and* the source must be gone. Either one alone would pass for
    // a broken implementation — a delete that never copied, or a copy that never
    // deleted.
    let sandbox = Sandbox::new();
    sandbox.write("src/moved.txt", b"bytes in flight");
    sandbox.write("src/deep/also.txt", b"and another");
    sandbox.dir("dst");

    sandbox
        .dctl()
        .arg("move")
        .arg(sandbox.path("src"))
        .arg(sandbox.path("dst"))
        .assert()
        .success();

    assert_eq!(sandbox.read("dst/moved.txt"), b"bytes in flight");
    assert_eq!(sandbox.read("dst/deep/also.txt"), b"and another");
    assert!(
        !sandbox.exists("src/moved.txt"),
        "the source must be gone once the destination is committed"
    );
    assert!(!sandbox.exists("src/deep/also.txt"));
}

// ── 3. sync ───────────────────────────────────────────────────────────────────

#[test]
fn sync_makes_the_destination_match_and_deletes_what_is_only_there() {
    // The deletion is what separates `sync` from `copy`, and it is the behaviour
    // that destroys data when it is wrong. Both directions are asserted: the
    // missing file arrives, the extra file goes, and the file present on both
    // sides ends up with the *source's* contents.
    let sandbox = Sandbox::new();
    sandbox.write("src/keep.txt", b"the new contents");
    sandbox.write("src/added.txt", b"freshly added");
    sandbox.write("dst/keep.txt", b"the old contents!!");
    sandbox.write("dst/stale.txt", b"present only at the destination");

    sandbox
        .dctl()
        .arg("sync")
        .arg(sandbox.path("src"))
        .arg(sandbox.path("dst"))
        .assert()
        .success();

    assert_eq!(sandbox.read("dst/keep.txt"), b"the new contents");
    assert_eq!(sandbox.read("dst/added.txt"), b"freshly added");
    assert!(
        !sandbox.exists("dst/stale.txt"),
        "sync must delete files the source does not have"
    );
    assert!(
        sandbox.exists("src/keep.txt") && sandbox.exists("src/added.txt"),
        "sync must never delete from the source"
    );
}

#[test]
fn copy_leaves_destination_only_files_where_sync_would_delete_them() {
    // The same fixture as the `sync` test, run through `copy`. Stating the
    // difference as an assertion is what stops the two verbs from converging:
    // a shared planner bug that made `copy` delete extras would pass every
    // `sync` test in this file.
    let sandbox = Sandbox::new();
    sandbox.write("src/a.txt", b"source side");
    sandbox.write("dst/stale.txt", b"present only at the destination");

    sandbox
        .dctl()
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(sandbox.path("dst"))
        .assert()
        .success();

    assert_eq!(
        sandbox.read("dst/stale.txt"),
        b"present only at the destination",
        "copy must never remove a destination-only file"
    );
}

#[test]
#[cfg(unix)]
fn a_source_root_reached_through_a_symlink_is_walked_rather_than_skipped() {
    // `/data -> /mnt/disk/data` is an ordinary layout, and the root is the one
    // path the operator typed. It used to list as an empty tree, because the
    // never-follow-symlinks rule — which exists to stop a walk wandering out of
    // the tree it was given — was applied to the walk's starting point as well.
    //
    // The result was a silent no-op: `copy` stored nothing and printed
    // `Files: 0 / 0  Errors: 0` with exit 0. `dctl ls`, `dctl size`, `dctl tree`
    // and `dctl check` all followed the same link, so the tree the operator was
    // shown was not the tree the transfer walked.
    let sandbox = Sandbox::new();
    sandbox.write("real/a.txt", b"through a link");
    sandbox.write("real/nested/b.txt", b"and a nested one");
    std::os::unix::fs::symlink(sandbox.path("real"), sandbox.path("link"))
        .expect("create the symlink to the source tree");

    sandbox
        .dctl()
        .arg("copy")
        .arg(sandbox.path("link"))
        .arg(sandbox.path("dst"))
        .assert()
        .success();

    assert_eq!(sandbox.read("dst/a.txt"), b"through a link");
    assert_eq!(sandbox.read("dst/nested/b.txt"), b"and a nested one");
}

#[test]
#[cfg(unix)]
fn a_symlink_inside_the_tree_is_still_never_followed() {
    // The other half of the rule, asserted beside it so that following the root
    // cannot be mistaken for permission to follow links found during the walk.
    // A link to an ancestor would loop forever, and a link out of the tree would
    // copy data the user never named.
    let sandbox = Sandbox::new();
    sandbox.write("real/a.txt", b"named by the walk");
    sandbox.write("outside/secret.txt", b"never named by the user");
    std::os::unix::fs::symlink(sandbox.path("outside"), sandbox.path("real/escape"))
        .expect("create the outward symlink");

    sandbox
        .dctl()
        .arg("copy")
        .arg(sandbox.path("real"))
        .arg(sandbox.path("dst"))
        .assert()
        .success();

    assert_eq!(sandbox.read("dst/a.txt"), b"named by the walk");
    assert!(
        !sandbox.exists("dst/escape"),
        "a link found during the walk must not carry data from outside the tree"
    );
}

#[test]
#[cfg(unix)]
fn sync_from_a_symlinked_source_root_does_not_empty_the_destination() {
    // The data-loss shape of the same defect, and the reason it is pinned end to
    // end rather than only in the walker's unit tests. A source root that listed
    // as empty made `sync --force` delete every file at the destination and exit
    // 0 with `Errors: 0` — `--force` being exactly how an unattended backup runs,
    // and the empty-source guard being the only thing between the two.
    let sandbox = Sandbox::new();
    sandbox.write("real/keep.txt", b"still here");
    sandbox.write("real/also.txt", b"also still here");
    sandbox.write("dst/keep.txt", b"still here");
    sandbox.write("dst/also.txt", b"also still here");
    std::os::unix::fs::symlink(sandbox.path("real"), sandbox.path("link"))
        .expect("create the symlink to the source tree");

    sandbox
        .dctl()
        .arg("sync")
        .arg("--force")
        .arg(sandbox.path("link"))
        .arg(sandbox.path("dst"))
        .assert()
        .success();

    assert_eq!(
        sandbox.read("dst/keep.txt"),
        b"still here",
        "a readable source must never be read as permission to empty the destination"
    );
    assert_eq!(sandbox.read("dst/also.txt"), b"also still here");
}

// ── 4. init ───────────────────────────────────────────────────────────────────

#[test]
fn init_creates_a_vault_envelope_and_an_index() {
    let sandbox = Sandbox::new();
    sandbox.dir("vault");

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .success();

    let envelope = sandbox.path("vault").join(ENVELOPE);
    assert!(
        envelope.is_file(),
        "init must write {ENVELOPE} — everything else depends on it"
    );
    assert!(
        std::fs::metadata(&envelope)
            .expect("envelope metadata")
            .len()
            > 0,
        "an empty envelope would be an unopenable vault reported as created"
    );
    assert!(
        sandbox.exists("index.redb"),
        "the index named by --index must be the one that was created"
    );
}

// ── 5. a password that is too short ───────────────────────────────────────────

#[test]
fn init_refuses_a_password_below_the_minimum_length() {
    // The root key is random and strong; the password is the only part an
    // attacker with the envelope can attack cheaply. A weak one must be refused
    // *before* anything is written, so the absence of the envelope is as much
    // the assertion as the exit code is.
    let sandbox = Sandbox::new();
    sandbox.dir("vault");

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", SHORT_PASSWORD)
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .code(1)
        .stderr(predicates::str::contains("at least 8 characters"));

    assert!(
        !sandbox.path("vault").join(ENVELOPE).exists(),
        "a refused init must create no vault"
    );
    assert!(
        !sandbox.exists("index.redb"),
        "a refused init must create no index"
    );
}

// ── 6. the guard against storing plaintext next to an envelope ────────────────

#[test]
fn copy_into_a_directory_holding_a_vault_is_refused() {
    // The most valuable test in this file.
    //
    // `dctl copy ./plain ./vault` addresses the vault's directory as an ordinary
    // filesystem path. Without the guard the copy succeeds, the plaintext lands
    // next to the envelope, and the run reports success — for a tool whose whole
    // promise is that data is sealed before it lands, that is the worst outcome
    // available, and it is silent.
    //
    // So the assertion is not "the command failed". It is that the secret bytes
    // are nowhere under the vault directory at all.
    const SECRET: &[u8] = b"PLAINTEXT-THAT-MUST-NEVER-BE-WRITTEN-UNSEALED";

    let sandbox = Sandbox::new();
    sandbox.dir("vault");
    sandbox.write("plain/secret.txt", SECRET);

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .success();

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(sandbox.path("plain"))
        .arg(sandbox.path("vault"))
        .assert()
        // FatalError: the run cannot continue, and nothing was written.
        .code(7)
        // The refusal names the configured remote and the remedy, rather than
        // describing the hazard in the abstract: an operator who hits this needs
        // to know what to type next, not what went wrong in principle.
        .stderr(predicates::str::contains("is the object store for remote"))
        .stderr(predicates::str::contains(VAULT_NAME))
        // And it states the invariant outright, because the whole point is that
        // DCTL never silently switches between sealed and plain.
        .stderr(predicates::str::contains(
            "decided by the remote name typed",
        ));

    let vault = sandbox.path("vault");
    let files = all_files(&vault);

    assert!(
        !vault.join("secret.txt").exists(),
        "the plaintext file must not appear in the vault directory"
    );
    for file in &files {
        let contents = std::fs::read(file).expect("read a file inside the vault");
        assert!(
            !contains(&contents, SECRET),
            "unsealed plaintext was written to {}",
            file.display()
        );
    }
    assert_eq!(
        files.len(),
        1,
        "the refused copy must leave the vault exactly as init made it: {files:?}"
    );
    assert!(vault.join(ENVELOPE).is_file(), "the envelope must survive");

    // …and the source is untouched, so the user has lost nothing by being
    // refused.
    assert_eq!(sandbox.read("plain/secret.txt"), SECRET);
}

/// Whether `haystack` contains `needle` as a contiguous byte run.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// ── 7. --dry-run ──────────────────────────────────────────────────────────────

#[test]
fn a_dry_run_prints_the_plan_and_changes_nothing() {
    // `--dry-run` is only worth having if it is trustworthy in both directions:
    // it must report the work (so a reviewer can approve it) and perform none of
    // it (so approving is safe). A `sync` fixture is used because it is the one
    // that would delete.
    let sandbox = Sandbox::new();
    sandbox.write("src/incoming.txt", b"would be copied");
    sandbox.write("dst/stale.txt", b"would be deleted");

    sandbox
        .dctl()
        .arg("--dry-run")
        .arg("sync")
        .arg(sandbox.path("src"))
        .arg(sandbox.path("dst"))
        .assert()
        .success()
        // The plan is data, so it goes to stdout where `grep` and `jq` can see it.
        .stdout(predicates::str::contains("incoming.txt"))
        .stdout(predicates::str::contains("stale.txt"))
        .stdout(predicates::str::contains("delete"));

    assert!(
        !sandbox.exists("dst/incoming.txt"),
        "a dry run must transfer nothing"
    );
    assert_eq!(
        sandbox.read("dst/stale.txt"),
        b"would be deleted",
        "a dry run must delete nothing"
    );
}

#[test]
fn a_dry_run_init_creates_neither_a_vault_nor_an_index() {
    // The destructive-confirmation path: a dry run declines it, and must then
    // stop rather than fall through to the write.
    let sandbox = Sandbox::new();
    sandbox.dir("vault");

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("--dry-run")
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .success();

    assert!(!sandbox.path("vault").join(ENVELOPE).exists());
    assert!(!sandbox.exists("index.redb"));
}

// ── 8. version ────────────────────────────────────────────────────────────────

#[test]
fn version_works_with_no_config_and_no_vault() {
    // The command a user runs first, and the one a bug report quotes. It must
    // not need a configuration file, an index, a vault or a password — and it
    // must not create any of them on the way.
    let sandbox = Sandbox::new();

    sandbox
        .dctl()
        .arg("version")
        .assert()
        .success()
        .stdout(predicates::str::contains("version"))
        .stdout(predicates::str::contains("dctl"));

    assert!(
        !sandbox.exists("dctl.toml"),
        "`version` must not materialise a configuration file"
    );
    assert!(
        !sandbox.exists("index.redb"),
        "`version` must not materialise an index"
    );
}

// ── 9. exit codes ─────────────────────────────────────────────────────────────

#[test]
fn a_missing_source_exits_with_dir_not_found() {
    // ExitCode::DirNotFound (3). Specifically *not* a generic failure: a script
    // that retries on a temporary error must be able to tell "you named
    // something that is not there" apart from "the network was down".
    let sandbox = Sandbox::new();
    sandbox.dir("dst");

    sandbox
        .dctl()
        .arg("copy")
        .arg(sandbox.path("definitely-not-here"))
        .arg(sandbox.path("dst"))
        .assert()
        .code(3)
        .stderr(predicates::str::contains("source not found"));
}

#[test]
fn missing_positional_arguments_exit_with_usage() {
    // ExitCode::Usage (1). `copy` takes an explicit DEST — the rclone-style
    // surface — so a one-argument invocation is a usage error and not a copy to
    // some implicit default remote.
    let sandbox = Sandbox::new();

    sandbox.dctl().arg("copy").assert().code(1);

    sandbox
        .dctl()
        .arg("copy")
        .arg(sandbox.path("src"))
        .assert()
        .code(1)
        .stderr(predicates::str::contains("DEST"));
}

#[test]
fn a_transfer_onto_itself_exits_with_usage() {
    // ExitCode::Usage (1). Under `sync` this would be a race between listing a
    // tree and deleting from it, so it is refused for the whole family.
    let sandbox = Sandbox::new();
    sandbox.write("both/a.txt", b"x");

    sandbox
        .dctl()
        .arg("copy")
        .arg(sandbox.path("both"))
        .arg(sandbox.path("both"))
        .assert()
        .code(1)
        .stderr(predicates::str::contains("same"));
}

#[test]
fn syncing_from_a_single_file_exits_with_usage() {
    // ExitCode::Usage (1). `dctl sync photo.jpg backups/` reads as "make
    // backups/ contain exactly photo.jpg", which means emptying it. Refusing is
    // the difference between a confusing command and a destroyed directory.
    let sandbox = Sandbox::new();
    sandbox.write("src/photo.jpg", b"pretend jpeg");
    sandbox.write("dst/other.txt", b"would have been deleted");

    sandbox
        .dctl()
        .arg("sync")
        .arg(sandbox.path("src/photo.jpg"))
        .arg(sandbox.path("dst"))
        .assert()
        .code(1);

    assert!(
        sandbox.exists("dst/other.txt"),
        "the refusal must happen before anything is removed"
    );
}

#[test]
fn re_initialising_over_an_existing_index_exits_with_a_fatal_error() {
    // ExitCode::FatalError (7). Re-initialising generates a new root key and
    // orphans everything already stored, so an existing index is a hard refusal
    // — and it happens before a password is ever read.
    let sandbox = Sandbox::new();
    sandbox.dir("vault");
    sandbox.write("index.redb", b"pretend index");

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .code(7)
        .stderr(predicates::str::contains("already exists"));

    assert!(!sandbox.path("vault").join(ENVELOPE).exists());
}

#[test]
fn an_unattended_run_with_no_password_exits_with_usage() {
    // ExitCode::Usage (1). `--no-ask-password` is what a cron job passes; the
    // failure has to be immediate and named, never a prompt on a stream nobody
    // is reading.
    let sandbox = Sandbox::new();
    sandbox.dir("vault");

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .code(1)
        .stderr(predicates::str::contains("no password available"));

    assert!(!sandbox.path("vault").join(ENVELOPE).exists());
}

#[test]
fn the_key_file_refusal_names_the_flag_and_never_calls_a_working_command_missing() {
    // The chokepoint in `main.rs` is the only `--key-file` check a user ever
    // reaches — the per-command ones behind it are defence in depth — and it
    // built its message from the command name alone. So `dctl init --key-file`
    // reported `dctl init is not implemented in this build`: a false statement
    // about a command that creates vaults perfectly well, made to somebody whose
    // only mistake was asking for two factors.
    //
    // The unit tests in `session::factor` all passed, because every one of them
    // hands `refuse_if_present` a subject with the flag already in it. Only a run
    // of the real binary goes through the call site that did not, which is why
    // this test lives here.
    let sandbox = Sandbox::new();
    sandbox.dir("vault");
    let keyfile = sandbox.write("kf.bin", b"not a real factor");

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("--key-file")
        .arg(&keyfile)
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .code(7)
        .stderr(predicates::str::contains("--key-file"))
        // The layer that owes the capability, so the reader knows the wait is
        // not this command's…
        .stderr(predicates::str::contains("dctl-core"))
        // …and the section that specifies it, so the wait has an address.
        .stderr(predicates::str::contains("§8"))
        // The sentence that must never come back.
        .stderr(predicates::str::contains("dctl init is not implemented").not());

    // And nothing was created — a refusal that left a one-factor vault behind
    // would be the exact failure the refusal exists to prevent.
    assert!(!sandbox.path("vault").join(ENVELOPE).exists());
}

// ── 10. --json ────────────────────────────────────────────────────────────────

#[test]
fn version_json_parses_and_names_the_binary() {
    let sandbox = Sandbox::new();

    let output = sandbox
        .dctl()
        .arg("--json")
        .arg("version")
        .assert()
        .success()
        .get_output()
        .clone();

    let document = json(&output.stdout);
    assert_eq!(document["binary"], "dctl");
    assert!(
        document["version"].is_string(),
        "a machine consumer branches on this field"
    );
}

#[test]
fn a_dry_run_plan_parses_as_json_and_describes_every_action() {
    // The contract behind `dctl sync --dry-run --json | jq '.actions[]'`: the
    // document has to be self-describing, so a plan pulled out of a CI log can
    // be reviewed after the fact without knowing the command line that made it.
    let sandbox = Sandbox::new();
    sandbox.write("src/incoming.txt", b"0123456789");
    sandbox.write("dst/stale.txt", b"gone");

    let output = sandbox
        .dctl()
        .arg("--json")
        .arg("--dry-run")
        .arg("sync")
        .arg(sandbox.path("src"))
        .arg(sandbox.path("dst"))
        .assert()
        .success()
        .get_output()
        .clone();

    let document = json(&output.stdout);
    assert_eq!(document["command"], "sync");
    assert_eq!(document["dry_run"], true);
    assert_eq!(document["summary"]["copy"], 1);
    assert_eq!(document["summary"]["delete"], 1);

    let actions = document["actions"]
        .as_array()
        .expect("actions is an array")
        .clone();
    assert_eq!(actions.len(), 2);

    let copy = actions
        .iter()
        .find(|action| action["action"] == "copy")
        .expect("a copy action");
    assert_eq!(copy["dest"], "incoming.txt");
    assert_eq!(copy["size"], 10);

    let delete = actions
        .iter()
        .find(|action| action["action"] == "delete")
        .expect("a delete action");
    assert_eq!(delete["dest"], "stale.txt");
    // The reason is a stable slug, not prose: scripts branch on it.
    assert!(delete["reason"].is_string());
}

#[test]
fn init_json_reports_what_it_created() {
    let sandbox = Sandbox::new();
    sandbox.dir("vault");

    let output = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("--json")
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .success()
        .get_output()
        .clone();

    let document = json(&output.stdout);
    assert_eq!(document["created"], true);
    assert_eq!(document["dry_run"], false);
    // The report must name the index it actually used, not the default one.
    assert_eq!(
        document["index"],
        sandbox.path("index.redb").to_string_lossy().as_ref()
    );
    assert!(sandbox.path("vault").join(ENVELOPE).is_file());
}

#[test]
fn config_providers_json_parses_as_a_list() {
    // The discovery command a wrapper script calls before writing a config file.
    let sandbox = Sandbox::new();

    let output = sandbox
        .dctl()
        .arg("--json")
        .arg("config")
        .arg("providers")
        .assert()
        .success()
        .get_output()
        .clone();

    let providers = json(&output.stdout);
    let providers = providers.as_array().expect("an array of providers");
    assert!(
        providers.iter().any(|provider| provider["type"] == "local"),
        "the local provider is always available"
    );
}

// ── 11. a named remote is never quietly a local directory ─────────────────────

#[test]
fn copy_to_a_provider_shorthand_never_lands_in_a_directory_of_that_name() {
    // S6, and the reason it earns an end-to-end test rather than a unit one: the
    // failure was silent *and* successful-looking. `dctl copy ./src b2:mybucket`
    // handed the bare name `b2` to the backend builder, which re-parsed it as a
    // spec — and a name with no colon in it is a relative path. A `./b2`
    // directory in the working tree therefore became the destination, the bucket
    // name was discarded, and the run printed "Files: 1 / 1" and exited 0.
    //
    // So the assertion is not "the command failed". It is that nothing new
    // appeared in `./b2`, which is the property a user's data depends on.
    let sandbox = Sandbox::new();
    sandbox.write("src/a.txt", b"payload bytes");
    sandbox.dir("b2");

    // A real vault in `./b2` is what made the old behaviour succeed instead of
    // erroring: the run unlocked it and stored the file there.
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("b2"))
        .assert()
        .success();

    let before = all_files(&sandbox.path("b2"));

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg("b2:mybucket")
        .arg("--no-traverse")
        .assert()
        // FatalError (7), and the message names the B2 credential that is not
        // exported. That is the *whole* remaining reason this run cannot
        // proceed, and pinning it is what keeps two regressions visible:
        //
        //  * it must not say "not implemented" — writing a plain object into a
        //    bucket is implemented, through `Backend::put`, and a refusal would
        //    mean the path had been closed again;
        //  * it must not ask for a vault password — `b2:mybucket` is a plain
        //    destination with no key, and demanding one is defect S6/D4, the
        //    behaviour that put this file's data in `./b2` in the first place.
        //
        // The password *is* on the environment for this run, deliberately: if
        // anything on the path still reached for a vault it would find one and
        // succeed, and the assertion below would catch it.
        .code(7)
        .stderr(predicates::str::contains("DCTL_B2_KEY_ID"))
        .stderr(predicates::str::contains("not implemented").not());

    assert_eq!(
        all_files(&sandbox.path("b2")).len(),
        before.len(),
        "the transfer must not have landed in the local './b2' directory"
    );
}

#[test]
fn copy_to_an_unconfigured_remote_names_the_remote_and_writes_nothing() {
    // The same defect from the other side, and the inconsistency S6 was really
    // about: `dctl about vault:` and `dctl init vault:` both reported "unknown
    // remote 'vault'", while `copy` quietly wrote into a directory called
    // `vault`. All three now resolve the same way, so all three agree.
    let sandbox = Sandbox::new();
    sandbox.write("src/a.txt", b"payload bytes");
    sandbox.dir("vault");

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg("vault:photos")
        .arg("--no-traverse")
        .assert()
        .code(7)
        .stderr(predicates::str::contains("unknown remote 'vault'"))
        .stderr(predicates::str::contains("config list"));

    assert!(
        all_files(&sandbox.path("vault")).is_empty(),
        "a refused transfer must leave the lookalike directory empty"
    );
}

// ── 12. a plain configured remote is a first-class destination ────────────────

/// The remote `dctl config create backup local path=…` registers in these tests.
const PLAIN_REMOTE: &str = "backup";

#[test]
fn copy_into_a_plain_configured_remote_needs_no_password_and_lands_the_bytes() {
    // D4, end to end. `dctl config create backup local path=/mnt/backup` makes
    // an ordinary remote — no vault wraps it, nothing about it is sealed — and
    // `dctl --no-ask-password copy ./src backup:` exited 22 demanding a vault
    // password, having written nothing. The engine decided from the argument's
    // *shape*: anything with a colon was a vault.
    //
    // Invariant I3 is that a write to an ordinary location is plaintext and
    // fully supported, so the assertion is the bytes under the remote's root,
    // not the exit code and not the "Files: 1 / 1" line — a counter can be
    // incremented by a stage that did nothing.
    const PAYLOAD: &[u8] = b"ordinary bytes for an ordinary remote";

    let sandbox = Sandbox::new();
    sandbox.write("src/a.txt", PAYLOAD);
    sandbox.write("src/sub/b.txt", b"nested");
    let root = sandbox.dir("store");

    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", root.display()))
        .assert()
        .success();

    sandbox
        .dctl()
        // No password on the environment *and* prompting forbidden: if anything
        // on this path still reaches for a key, the run cannot succeed.
        .arg("--no-ask-password")
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .success();

    assert_eq!(sandbox.read("store/a.txt"), PAYLOAD);
    assert_eq!(sandbox.read("store/sub/b.txt"), b"nested");
    // …and the source is untouched, because `copy` is not `move`.
    assert_eq!(sandbox.read("src/a.txt"), PAYLOAD);
}

#[test]
fn copy_into_a_plain_configured_remote_honours_the_prefix() {
    // `backup:photos` must land under `photos/`, which is where a listing of
    // `backup:photos` looks. Writing at the root instead would make every run
    // copy the same files again, for ever, and report success each time.
    let sandbox = Sandbox::new();
    sandbox.write("src/a.txt", b"prefixed");
    let root = sandbox.dir("store");

    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", root.display()))
        .assert()
        .success();

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{PLAIN_REMOTE}:photos"))
        .assert()
        .success();

    assert_eq!(sandbox.read("store/photos/a.txt"), b"prefixed");
    assert!(
        !sandbox.exists("store/a.txt"),
        "the prefix the user named must not be dropped"
    );
}

/// A sandbox holding a day-old three-file tree and a plain `local:` remote.
///
/// Backdating matters and is not decoration. A file copied a moment after it was
/// written falls inside the modify window whatever the destination records, so a
/// tree built and copied in the same second cannot tell a working incremental
/// transfer from a broken one. A day is what a real backup looks like.
fn aged_source_and_plain_remote() -> Sandbox {
    let sandbox = Sandbox::new();
    for (path, bytes) in AGED_TREE {
        sandbox.write(path, bytes);
        sandbox.age(path, A_DAY);
    }
    let root = sandbox.dir("store");
    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", root.display()))
        .assert()
        .success();
    sandbox
}

#[test]
fn a_second_copy_into_a_plain_remote_transfers_nothing() {
    // The defect this whole change exists for, at the level a user meets it.
    //
    // `Backend::put` used to store bytes under a key and carry no modification
    // time — there was no parameter for one — so a plain destination reported
    // the moment it was *written*, the default size-and-time comparison found
    // every file different, and the second run of a nightly backup re-uploaded
    // the entire dataset. This test asserted that behaviour, on the grounds that
    // a bucket stamps its own `Last-Modified`; the premise was wrong. A local
    // file's inode, an SFTP `SETSTAT` and B2's `src_last_modified_millis` all
    // hold the source's time perfectly well.
    //
    // Both halves are asserted, because the second run alone would pass on a
    // tool that never transferred anything at all.
    let sandbox = aged_source_and_plain_remote();

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 3 / 3"));

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 0 / 0"));
}

#[test]
fn sync_into_a_plain_remote_is_incremental_and_check_agrees_with_it() {
    // The property that makes `sync` worth putting in a cron job, and the one
    // `check` has to corroborate. Four runs, in the order an operator would hit
    // them:
    //
    //   1. everything transfers;
    //   2. nothing transfers, and `check` calls the tree identical;
    //   3. one file is touched and exactly one file transfers;
    //   4. one file's contents change without changing its size or its time —
    //      invisible to size-and-time by construction, which is what `--checksum`
    //      is for.
    //
    // Run 2 asserting `Files: 0 / 0` *and* `check` reporting `all match` is the
    // pair that matters: before this, the second sync moved `3 / 3` and `check`
    // answered `3 of 3 paths differ` over a copy it had just made byte-for-byte.
    let sandbox = aged_source_and_plain_remote();
    let sync = |extra: &[&str]| {
        let mut command = sandbox.dctl();
        command
            .arg("--no-ask-password")
            .arg("--force")
            .args(extra)
            .arg("sync")
            .arg(sandbox.path("src"))
            .arg(format!("{PLAIN_REMOTE}:"));
        command
    };

    sync(&[])
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 3 / 3"));

    sync(&[])
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 0 / 0"));

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("check")
        .arg(sandbox.path("src"))
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .success()
        .stderr(predicates::str::contains("all match"));

    // One file, moved well outside the modify window.
    sandbox.age("src/b.txt", A_DAY * 30);
    sync(&[])
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 1 / 1"));

    // Same length, same timestamp, different bytes: the documented blind spot of
    // a size-and-time comparison, and the reason `--checksum` exists.
    sandbox.edit_keeping_time("src/a.txt", b"FIRST");
    sync(&[])
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 0 / 0"));

    // `check --checksum` reads both sides and hashes them, so it sees the edit
    // the metadata comparison cannot.
    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("--checksum")
        .arg("check")
        .arg(sandbox.path("src"))
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .failure()
        .stdout(predicates::str::contains("differ  a.txt"));

    // …and so does `sync --checksum`, which used to exit **7** here with
    // `--checksum: no content hash for 'a.txt'` (`HANDOVER.md` §11.2). A plain
    // store holds the plaintext, so reading an object and hashing it is exactly
    // the digest the comparison needs; it costs a read, and the run says so
    // once.
    sync(&["--checksum"])
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 1 / 1"))
        .stderr(predicates::str::contains("has to read this side"));

    // The half that makes it a *nightly* job rather than a one-night one: with
    // both sides identical again, the very next `--checksum` run transfers
    // nothing. This is the assertion the old behaviour could not have made,
    // because there was no second run — the first repeat exited 7.
    sync(&["--checksum"])
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 0 / 0"));

    // And it still sees an edit that the default comparison cannot: same
    // length, same timestamp, different bytes. A `--checksum` that had quietly
    // fallen back to size-and-time would pass every assertion above and fail
    // this one.
    sandbox.edit_keeping_time("src/a.txt", b"THIRD");
    sync(&["--checksum"])
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 1 / 1"));

    // The warning is emitted once per run and not once per object, which is what
    // keeps it readable on a ten-thousand-file sync.
    let output = sync(&["--checksum"]).assert().success();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr).into_owned();
    assert_eq!(
        stderr.matches("has to read this side").count(),
        1,
        "the cost note must be said once, not per object:\n{stderr}"
    );
}

#[test]
fn sync_out_of_a_plain_remote_is_incremental_too() {
    // The other direction, and a separate code path. A download from a plain
    // store fetches bytes through `Backend::get`, which returns bytes and nothing
    // else — so the local file used to be stamped with the moment it was written,
    // and the next run compared it against the object it came from, found a
    // difference, and fetched it again. On a metered provider that is egress per
    // file per run, for a restore mirror nobody is changing.
    //
    // The source time now travels on the plan, taken from the same listing the
    // comparison read, so no extra round trip is paid to learn it.
    let sandbox = aged_source_and_plain_remote();
    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .success();

    let out = sandbox.dir("out");
    let down = || {
        let mut command = sandbox.dctl();
        command
            .arg("--no-ask-password")
            .arg("--force")
            .arg("sync")
            .arg(format!("{PLAIN_REMOTE}:"))
            .arg(&out);
        command
    };

    down()
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 3 / 3"));
    down()
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 0 / 0"));
}

#[test]
fn a_same_size_edit_is_caught_by_checksum_against_a_vault() {
    // The other half of the `--checksum` story, on the destination that can
    // answer it without reading anything back: a vault index records the
    // plaintext BLAKE3 of everything it holds, so content equality costs one
    // local read and no egress at all.
    //
    // Three runs: everything moves, nothing moves, then one file is edited in
    // place — same length, same timestamp — and is invisible to size-and-time
    // and caught by `--checksum`.
    let sandbox = aged_source_and_vault();
    let sync = |extra: &[&str]| {
        let mut command = sandbox.dctl();
        command
            .env("DCTL_PASSWORD", GOOD_PASSWORD)
            .arg("--force")
            .args(extra)
            .arg("sync")
            .arg(sandbox.path("src"))
            .arg(format!("{VAULT_NAME}:"));
        command
    };

    sync(&[])
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 3 / 3"));
    sync(&[])
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 0 / 0"));

    sandbox.edit_keeping_time("src/a.txt", b"FIRST");
    sync(&[])
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 0 / 0"));
    sync(&["--checksum"])
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 1 / 1"));
}

#[test]
fn a_modify_window_below_the_stored_resolution_is_refused_by_every_verb_that_reads_it() {
    // A flag that parses, appears in `--help` and does nothing is the defect this
    // codebase keeps finding in other tools. `--modify-window 0` cannot be
    // honoured — DCTL records whole seconds — so it is refused, by the transfer
    // family and by `check` alike, from the one function that decides it.
    let sandbox = aged_source_and_plain_remote();

    for verb in ["copy", "sync", "check"] {
        sandbox
            .dctl()
            .arg("--no-ask-password")
            .args(["--modify-window", "0"])
            .arg(verb)
            .arg(sandbox.path("src"))
            .arg(format!("{PLAIN_REMOTE}:"))
            .assert()
            .failure()
            .stderr(predicates::str::contains("whole"));
    }
}

#[test]
fn copy_out_of_a_plain_configured_remote_needs_no_password_either() {
    // The same defect in the read direction: `copy backup: ./out` also opened a
    // vault session and also failed at exit 22.
    const PAYLOAD: &[u8] = b"read back out of an ordinary remote";

    let sandbox = Sandbox::new();
    let root = sandbox.dir("store");
    sandbox.write("store/a.txt", PAYLOAD);

    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", root.display()))
        .assert()
        .success();

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("copy")
        .arg(format!("{PLAIN_REMOTE}:"))
        .arg(sandbox.path("out"))
        .assert()
        .success();

    assert_eq!(sandbox.read("out/a.txt"), PAYLOAD);
}

#[test]
fn copy_into_a_vault_remote_still_needs_the_key_and_still_seals() {
    // The control for all three above, and the half of invariant I1 that must
    // not move: a write through a vault remote is sealed, so it still needs the
    // key — refused at exit 22 without one — and when it does run, the plaintext
    // is nowhere under the store.
    //
    // Both halves are asserted in one test on purpose. "It refused" alone would
    // also pass if the sealed path were broken outright, and "it sealed" alone
    // would also pass if the password were being ignored.
    const SECRET: &[u8] = b"SEALED-PAYLOAD-THAT-MUST-NOT-APPEAR-IN-THE-CLEAR";

    let sandbox = Sandbox::new();
    sandbox.write("src/a.txt", SECRET);
    sandbox.dir("vault");

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .success();

    let after_init = all_files(&sandbox.path("vault"));

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        // VaultLocked (22) — the exact code the plain remote must *not* produce.
        .code(22);

    assert_eq!(
        all_files(&sandbox.path("vault")).len(),
        after_init.len(),
        "a refused sealed transfer must store nothing"
    );

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();

    let stored = all_files(&sandbox.path("vault"));
    assert!(
        stored.len() > after_init.len(),
        "the sealed transfer must have stored something"
    );
    for file in &stored {
        let contents = std::fs::read(file).expect("read a stored object");
        assert!(
            !contains(&contents, SECRET),
            "plaintext was written through a vault remote: {}",
            file.display()
        );
    }
}

// ── a vault destination is comparable against its source ──────────────────────

/// The tree the incremental-backup tests copy.
const AGED_TREE: &[(&str, &[u8])] = &[
    ("src/a.txt", b"first"),
    ("src/b.txt", b"second"),
    ("src/sub/c.txt", b"third"),
];

/// A day, in seconds — how far the fixture's files are backdated.
///
/// Any value comfortably outside the modify window would do; a day is chosen
/// because it is what a real backup looks like, where the source was written
/// long before the copy of it was.
const A_DAY: u64 = 86_400;

/// Build the sandbox `copy` → `check` → `copy` is exercised against.
fn aged_source_and_vault() -> Sandbox {
    let sandbox = Sandbox::new();
    for (path, bytes) in AGED_TREE {
        sandbox.write(path, bytes);
        sandbox.age(path, A_DAY);
    }
    sandbox.dir("vault");
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .success();
    sandbox
}

#[test]
fn a_second_copy_into_a_vault_skips_every_file_and_check_agrees() {
    // Defect D5. `dctl_core::Vault::put_file` took no modification time and
    // recorded `now_unix()` instead, so the index's time described the *write*
    // and never the source. Compared by size and time — the default — a vault
    // destination therefore never matched its source: `copy` re-uploaded the
    // whole dataset on every run, and `check` reported a tree it had just
    // written as entirely different.
    //
    // Four assertions, in the order a user meets them, because each one alone
    // has a way of passing while the product is broken:
    //
    //  * the first `copy` transferring everything proves the fixture is real and
    //    the skip below is not simply "nothing was ever stored";
    //  * `check` agreeing proves the comparison was fixed — and it must say it
    //    compared *size-and-modtime*, because a run that reached the same
    //    verdict by silently hashing both sides would be the old compensation
    //    wearing the new answer's clothes;
    //  * the second `copy` transferring nothing proves the same answer reached
    //    the planner, rather than the two commands being fixed apart;
    //  * one edited file, and only it, moving proves the skip is a comparison
    //    and not a tool that has stopped transferring.
    let sandbox = aged_source_and_vault();

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 3 / 3"));

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("check")
        .arg(sandbox.path("src"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success()
        // A health gate that is silent when healthy cannot be told apart from
        // one that did nothing, so the clean run states what it compared.
        .stderr(predicates::str::contains("3 paths compared"))
        .stderr(predicates::str::contains("size-and-modtime"))
        // …and says nothing on stdout, which is where a finding would go.
        .stdout("");

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 0 / 0"))
        .stderr(predicates::str::contains("Skipped: 3"));

    sandbox.write("src/sub/c.txt", b"third, edited");

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 1 / 1"));

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("cat")
        .arg(format!("{VAULT_NAME}:sub/c.txt"))
        .assert()
        .success()
        .stdout("third, edited");
}

#[test]
fn a_vault_copy_never_reads_the_source_to_compare_it() {
    // The cost half of the same defect, and the reason the compensation had to
    // go rather than stay as a belt-and-braces.
    //
    // While a vault could not be compared by time, `copy` answered the default
    // by content instead: correct, and paid for by reading and hashing every
    // byte of the other side on every run. On the nightly backup this tool is
    // for, that is the whole dataset read to discover nothing had changed.
    //
    // The run is required to say nothing about hashing, because the notice was
    // the substitution's only outward sign — and a silent return of it is the
    // failure this test exists to catch.
    let sandbox = aged_source_and_vault();

    for _ in 0..2 {
        sandbox
            .dctl()
            .env("DCTL_PASSWORD", GOOD_PASSWORD)
            .arg("copy")
            .arg(sandbox.path("src"))
            .arg(format!("{VAULT_NAME}:"))
            .assert()
            .success()
            .stderr(predicates::str::contains("compares contents").not())
            .stderr(predicates::str::contains("read and hashed").not());
    }
}

#[test]
fn a_vault_records_the_sources_modification_time_and_hands_it_back() {
    // What the index actually holds, read through the shipped binary rather than
    // through the core's own API: `lsl` prints the recorded time, and the file it
    // came from was backdated a day. A vault stamping the write would print
    // today, and the whole of D5 follows from that one number.
    //
    // The round trip is asserted too. Restoring the tree has to reproduce the
    // times as well as the bytes, or the copy back out is a fresh tree that the
    // *next* comparison finds entirely modified — the same defect, one direction
    // over.
    let sandbox = aged_source_and_vault();
    let source_modified = std::fs::metadata(sandbox.path("src/a.txt"))
        .expect("the fixture file")
        .modified()
        .expect("this platform reports modification times");

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();

    let listed = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("lsl")
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();
    let listed = String::from_utf8(listed.get_output().stdout.clone()).expect("utf-8 output");
    let today = chrono_free_date(std::time::SystemTime::now());
    assert!(
        !listed.contains(&today),
        "the index recorded the time of the write, not the source's: {listed}"
    );
    assert!(
        listed.contains(&chrono_free_date(source_modified)),
        "the source's own date is missing from the listing: {listed}"
    );

    // …and back out again, byte-for-byte and second-for-second.
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(format!("{VAULT_NAME}:"))
        .arg(sandbox.path("restored"))
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 3 / 3"));

    assert_eq!(sandbox.read("restored/a.txt"), b"first");
    assert_eq!(
        whole_seconds(
            std::fs::metadata(sandbox.path("restored/a.txt"))
                .expect("the restored file")
                .modified()
                .expect("a modification time")
        ),
        whole_seconds(source_modified),
        "a restored file must carry the time the vault recorded for it"
    );

    // Which is the property that makes the download incremental too.
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(format!("{VAULT_NAME}:"))
        .arg(sandbox.path("restored"))
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 0 / 0"));
}

/// A `SystemTime` as whole unix seconds — the resolution the index stores.
fn whole_seconds(time: std::time::SystemTime) -> u64 {
    time.duration_since(std::time::UNIX_EPOCH)
        .expect("a time after 1970")
        .as_secs()
}

/// The `YYYY-MM-DD` of a `SystemTime`, without a calendar dependency.
///
/// Only ever compared against another value produced the same way, and only to
/// tell "a day ago" from "today" — which is the whole distinction defect D5 was
/// invisible without. Civil-date arithmetic from the epoch day, valid for every
/// date this test can produce.
fn chrono_free_date(time: std::time::SystemTime) -> String {
    let days = i64::try_from(whole_seconds(time) / 86_400).expect("a representable day");

    // Howard Hinnant's `civil_from_days`, shifted to a March-based year so the
    // leap day lands at the end and no month table is needed.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = era * 400 + yoe + i64::from(month <= 2);

    format!("{year:04}-{month:02}-{day:02}")
}

#[test]
fn an_edited_file_is_still_re_uploaded_after_the_comparison_changed() {
    // The dangerous direction of the D5 fix. Making a vault destination compare
    // *equal* is only correct if it still compares unequal when the file
    // changes, and this pins the hardest version of that: an edit that changes
    // no byte of the size, only the contents and the clock.
    //
    // What catches it is the timestamp — editing a file moves it — and that is
    // exactly the claim being made. A same-size edit that also preserved the
    // modification time is invisible to size-and-modtime, which is the trade
    // every tool in this family makes and what `--checksum` is for; it is pinned
    // as a unit test in `commands/transfer/compare.rs`.
    let sandbox = aged_source_and_vault();

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();

    // Same length, different bytes — and the edit moves the modification time,
    // as every edit does.
    sandbox.write("src/a.txt", b"FIRST");

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("check")
        .arg(sandbox.path("src"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .code(6)
        .stdout(predicates::str::contains("a.txt"));

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 1 / 1"));

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("cat")
        .arg(format!("{VAULT_NAME}:a.txt"))
        .assert()
        .success()
        .stdout("FIRST");
}

#[test]
fn size_only_is_still_honoured_exactly_against_a_vault() {
    // Nothing may swallow a dial the user set deliberately. `--size-only` is a
    // request for the cheapest comparison there is, and it is the flag a
    // substituted comparison used to be most tempted to upgrade — which would
    // have spent the user's money answering a question they declined to ask.
    let sandbox = aged_source_and_vault();

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();

    // A same-size edit: invisible to --size-only, by definition.
    sandbox.write("src/a.txt", b"FIRST");
    sandbox.age("src/a.txt", A_DAY);

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("--size-only")
        .arg("check")
        .arg(sandbox.path("src"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success()
        .stderr(predicates::str::contains("size-only"));
}

#[test]
fn backup_and_restore_return_the_dates_as_well_as_the_bytes() {
    // `backup` and `restore` are the pair the whole tool is for, and they are a
    // separate code path from `copy` — `backup` streams through
    // `put_file_from_path` and `restore` writes through `get_file_to_path`, so a
    // fix applied to the transfer engine reaches neither of them.
    //
    // A restore that returns the right bytes under the right names with every
    // timestamp set to the moment of the restore has not reproduced the tree. It
    // has produced one that every tool sorting or syncing by date reads as
    // entirely rewritten — including this one, on the very next `dctl check`.
    let sandbox = aged_source_and_vault();
    let source_modified = whole_seconds(
        std::fs::metadata(sandbox.path("src/a.txt"))
            .expect("the fixture file")
            .modified()
            .expect("this platform reports modification times"),
    );

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("backup")
        .arg(sandbox.path("src"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("restore")
        .arg(format!("{VAULT_NAME}:"))
        .arg(sandbox.path("recovered"))
        .assert()
        .success();

    assert_eq!(sandbox.read("recovered/a.txt"), b"first");
    assert_eq!(
        whole_seconds(
            std::fs::metadata(sandbox.path("recovered/a.txt"))
                .expect("the restored file")
                .modified()
                .expect("a modification time")
        ),
        source_modified,
        "a restored file must carry the time it was backed up with"
    );

    // The property that makes it more than cosmetic: the restored tree compares
    // equal to the original, so it can be backed up again for nothing.
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("check")
        .arg(sandbox.path("recovered"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success()
        .stdout("");
}

#[test]
fn touch_stores_a_chosen_time_in_a_vault_and_still_refuses_to_move_one() {
    // The half of `--timestamp` that became possible, and the half that did not.
    //
    // Creating an object with a chosen time used to be refused because the write
    // took no timestamp; it takes one now, so the flag is honoured and `lsl`
    // prints the second that was asked for rather than the second of the write.
    // Re-stamping an object the vault already holds is a different gap — it needs
    // a call that edits an existing index row — and it still refuses, loudly, at
    // exit 7.
    let sandbox = aged_source_and_vault();

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("touch")
        .args(["-t", "2024-05-01T12:00:00Z"])
        .arg(format!("{VAULT_NAME}:dated"))
        .assert()
        .success();

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("lsl")
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success()
        .stdout(predicates::str::contains("2024-05-01T12:00:00Z dated"));

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("touch")
        .args(["-t", "2024-06-01T12:00:00Z"])
        .arg(format!("{VAULT_NAME}:dated"))
        .assert()
        .code(7)
        .stderr(predicates::str::contains("re-stamping"));

    // …and the refusal changed nothing, which is the part worth proving.
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("lsl")
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success()
        .stdout(predicates::str::contains("2024-05-01T12:00:00Z dated"));
}

// ── the harness itself ────────────────────────────────────────────────────────

#[test]
fn the_binary_under_test_is_the_one_that_was_built() {
    // A guard on the harness rather than on the product. If `cargo_bin` ever
    // resolved to something else — a stale install on `PATH`, say — every
    // assertion above would be testing the wrong program, and they would all
    // still pass.
    let path = assert_cmd::cargo::cargo_bin("dctl");
    assert!(path.is_file(), "{} is not a file", path.display());

    let output = StdCommand::new(&path)
        .arg("--version")
        .output()
        .expect("run the built binary");
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("dctl"),
        "unexpected --version output"
    );
}

// ── a scrub reports what it covered, and a rebuilt index reports what it does
//    not know ───────────────────────────────────────────────────────────────

/// The tree the scrub and unmeasured-size tests seal.
///
/// One genuinely empty file is in it on purpose. "The index recorded no size"
/// and "the file is zero bytes long" are the two cases a naive fix collapses,
/// and a fixture that held only non-empty files would let that collapse pass.
/// What a size column reads when nothing ever measured the object.
///
/// Mirrors `constants::UNKNOWN_VALUE`, spelled out here so the test pins the
/// rendered output rather than following the code that produced it.
const UNKNOWN_SIZE: &str = "-";

const SCRUBBED_TREE: &[(&str, &[u8])] = &[
    ("src/a.txt", b"hello world payload"),
    ("src/sub/b.txt", b"second file here"),
    ("src/empty.txt", b""),
];

/// A vault holding [`SCRUBBED_TREE`], sealed through the ordinary copy path.
fn a_sealed_vault_with_content() -> Sandbox {
    let sandbox = Sandbox::new();
    for (path, bytes) in SCRUBBED_TREE {
        sandbox.write(path, bytes);
    }
    sandbox.dir("vault");
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .success();
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();
    sandbox
}

#[test]
fn a_scrub_says_what_it_covered_without_being_asked_to() {
    // Defect D2. A clean scrub printed nothing at all on either stream at
    // default verbosity, so it was indistinguishable from a scrub that had
    // found nothing to read. The coverage is the report: a run that verified
    // three objects has to say so where the operator is already looking, not
    // only behind `--json` or `-v`.
    let sandbox = a_sealed_vault_with_content();

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .args(["--verify", "strict", "scrub"])
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success()
        .stderr(predicates::str::contains("3"))
        .stderr(predicates::str::contains("healthy"))
        .stderr(predicates::str::contains("authenticated"));
}

#[test]
fn a_scrub_that_verified_nothing_does_not_pass_for_a_clean_one() {
    // The dangerous half of D2, and the reason the exit code has to move: a
    // cron job wrapping `dctl scrub` stayed green while verifying nothing at
    // all, because scanning zero objects exited 0 and printed nothing.
    let sandbox = a_sealed_vault_with_content();

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .args(["--verify", "strict", "scrub"])
        .arg(format!("{VAULT_NAME}:nonexistent"))
        .assert()
        // NoFilesTransferred (9): the run succeeded and covered nothing.
        .code(9)
        .stderr(predicates::str::contains("nothing"));
}

#[test]
fn a_rebuilt_index_carries_the_sizes_and_hashes_its_objects_declare() {
    // Defect D3's other half. The rendering was fixed — an absent size stopped
    // printing as `0` — but the absence itself was the ordinary state of every
    // rebuilt row, so a recovered machine could not `check`, could not total its
    // own bytes, and re-uploaded the whole vault on the next `sync`. A rebuild
    // now describes each object from its own header, and this is that claim end
    // to end, through the shipped binary.
    let sandbox = a_sealed_vault_with_content();

    // What the vault held before the rebuild, to compare against.
    let before = json(
        &sandbox
            .dctl()
            .env("DCTL_PASSWORD", GOOD_PASSWORD)
            .args(["--json", "size"])
            .arg(format!("{VAULT_NAME}:"))
            .assert()
            .success()
            .get_output()
            .stdout,
    );

    let rebuild = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .args(["--json", "index", "rebuild"])
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();
    let rebuilt = json(&rebuild.get_output().stdout);
    assert_eq!(rebuilt["files"], 3);
    assert_eq!(rebuilt["measured"], 3);
    assert_eq!(
        rebuilt["unmeasured"], 0,
        "every object is describable from its own header: {rebuilt}"
    );

    // `ls` prints real byte counts, including a real zero for the empty file.
    let listing = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("ls")
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();
    let listed = String::from_utf8_lossy(&listing.get_output().stdout).into_owned();
    assert_eq!(listed.lines().count(), 3);
    assert!(
        listed
            .lines()
            .all(|line| line.split_whitespace().next() != Some(UNKNOWN_SIZE)),
        "no row may be unmeasured after a rebuild:\n{listed}"
    );

    // `size` reports the same total it did before the index was rebuilt, which
    // is the property a capacity monitor depends on.
    let sized = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .args(["--json", "size"])
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();
    let totals = json(&sized.get_output().stdout);
    assert_eq!(totals["count"], 3);
    assert_eq!(totals["unmeasured"], 0);
    assert_eq!(
        totals["bytes"], before["bytes"],
        "a rebuild must not change what the vault is said to hold: {totals} vs {before}"
    );

    // And `check` against the source tree matches, which it cannot do at all
    // over rows with no size and no hash.
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .args(["check", "--checksum"])
        .arg(sandbox.path("src"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();
}

#[test]
fn a_rebuild_over_missing_objects_says_so_and_does_not_exit_zero() {
    // The other side: the objects are gone at the provider and only the name
    // records remain. The paths are still mapped — that is the recovery story —
    // but nothing about them can be measured, and a rebuild that reported three
    // files and exited 0 would be a recovery calling itself complete.
    let sandbox = a_sealed_vault_with_content();
    std::fs::remove_dir_all(sandbox.path("vault").join("o")).expect("the object tree is removable");

    let rebuild = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .args(["--json", "index", "rebuild"])
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        // PartialFailure (6): the mapping is complete, the description is not.
        .code(6);
    let rebuilt = json(&rebuild.get_output().stdout);
    assert_eq!(rebuilt["files"], 3);
    assert_eq!(rebuilt["measured"], 0);
    assert_eq!(rebuilt["unmeasured"], 3);

    // And the unmeasured rows still refuse to render as measured zeroes.
    let listing = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("ls")
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();
    let listed = String::from_utf8_lossy(&listing.get_output().stdout).into_owned();
    assert!(
        !listed.contains("0 B"),
        "an unmeasured row must not render as a measured zero:\n{listed}"
    );
    assert!(
        listed
            .lines()
            .all(|line| line.split_whitespace().next() == Some(UNKNOWN_SIZE)),
        "every unmeasured row's size column must read as unknown:\n{listed}"
    );
}

#[test]
fn a_measured_vault_still_reports_its_real_sizes_and_a_real_zero() {
    // The control, and the trap the D3 fix must not fall into: an object that
    // genuinely is zero bytes long has a recorded size of zero, and rendering
    // *that* as unknown would be the same defect pointing the other way.
    let sandbox = a_sealed_vault_with_content();

    let listing = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("ls")
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();
    let listed = String::from_utf8_lossy(&listing.get_output().stdout).into_owned();
    assert!(
        listed.contains("0 B") && listed.contains("empty.txt"),
        "a real empty file still measures zero:\n{listed}"
    );
    assert!(
        listed
            .lines()
            .all(|line| line.split_whitespace().next() != Some(UNKNOWN_SIZE)),
        "nothing here is unmeasured:\n{listed}"
    );

    let sized = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .args(["--json", "size"])
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();
    let totals = json(&sized.get_output().stdout);
    assert_eq!(totals["count"], 3);
    assert_eq!(totals["bytes"], 35);
    assert_eq!(totals["measured_bytes"], 35);
    assert_eq!(totals["unmeasured"], 0);
}

// ── addressing one object still names it ──────────────────────────────────────

#[test]
fn a_listing_of_one_exact_object_still_names_that_object() {
    // Defect D7. Every listing verb resolves an entry's path against the root
    // the listing was opened at, and `dctl lsjson archive:a.txt` opens the
    // listing at the object's own full path — so the relative portion came out
    // empty. `lsjson` emitted `"Path": ""`, `ls` printed a blank path column,
    // and `tree` printed a header with nothing under it.
    //
    // The empty string is the dangerous part rather than the ugly part: a
    // script doing `lsjson ... | jq -r '.[0].Path'` reads it back and may go on
    // to write to `""`. rclone answers the same argument with the file's name,
    // and so must this.
    let sandbox = a_sealed_vault_with_content();

    // An object at the vault root has no parent to be relative to, so its whole
    // name is the answer.
    let top = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("lsjson")
        .arg(format!("{VAULT_NAME}:a.txt"))
        .assert()
        .success();
    let rows = json(&top.get_output().stdout);
    assert_eq!(rows.as_array().map(Vec::len), Some(1));
    assert_eq!(rows[0]["Path"], "a.txt");
    assert_eq!(rows[0]["Name"], "a.txt");

    // An object inside a directory is named relative to that directory, which
    // is the case that a fix hard-coding "just use the whole path" gets wrong.
    let nested = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("lsjson")
        .arg(format!("{VAULT_NAME}:sub/b.txt"))
        .assert()
        .success();
    let rows = json(&nested.get_output().stdout);
    assert_eq!(rows.as_array().map(Vec::len), Some(1));
    assert_eq!(rows[0]["Path"], "b.txt");

    // The same root reaches `ls`, which had been printing the size and then
    // nothing at all.
    let listed = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("ls")
        .arg(format!("{VAULT_NAME}:sub/b.txt"))
        .assert()
        .success();
    let text = String::from_utf8_lossy(&listed.get_output().stdout).into_owned();
    assert!(
        text.contains("b.txt"),
        "ls must name the object it listed:\n{text}"
    );

    // And `tree`, whose header is the argument and whose body was empty.
    let tree = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("tree")
        .arg(format!("{VAULT_NAME}:sub/b.txt"))
        .assert()
        .success();
    let drawn = String::from_utf8_lossy(&tree.get_output().stdout).into_owned();
    assert!(
        drawn.lines().skip(1).any(|line| line.contains("b.txt")),
        "tree must draw an entry beneath its header:\n{drawn}"
    );
}

#[test]
fn listing_a_directory_still_reports_paths_relative_to_it() {
    // The control for the test above. The fix changes how a root that *equals*
    // an entry's path resolves, and the way to get that wrong is to stop
    // stripping the root from entries genuinely beneath it — which would make
    // every ordinary listing print absolute paths and break every script that
    // joins them onto a destination.
    let sandbox = a_sealed_vault_with_content();

    let whole = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("lsjson")
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();
    let rows = json(&whole.get_output().stdout);
    let paths: Vec<&str> = rows
        .as_array()
        .expect("lsjson emits an array")
        .iter()
        .filter_map(|row| row["Path"].as_str())
        .collect();
    assert!(
        paths.contains(&"sub/b.txt"),
        "a listing of the whole vault keeps the subtree in the path: {paths:?}"
    );

    let subtree = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("lsjson")
        .arg(format!("{VAULT_NAME}:sub"))
        .assert()
        .success();
    let rows = json(&subtree.get_output().stdout);
    assert_eq!(rows.as_array().map(Vec::len), Some(1));
    assert_eq!(
        rows[0]["Path"], "b.txt",
        "listing a directory reports its children relative to it"
    );
}

// ── a windowed read of a sealed object moves the window, not the object ─────

/// A sealed object comfortably larger than any per-read buffer, so a window of it
/// cannot be served by accident from something that happened to be resident.
///
/// Sixty-four mebibytes was the threshold the old whole-object warning fired at,
/// kept here on purpose: this is the exact size that used to produce a 64 MiB
/// transfer to return four bytes.
const RANGED_READ_FIXTURE_BYTES: usize = 64 * 1024 * 1024;

#[test]
fn a_window_of_a_large_sealed_object_is_served_without_moving_the_object() {
    // Defect D8, closed. `dctl-core` had no ranged read, so a vault served a byte
    // window by fetching and decrypting the entire object: `--offset 0 --count 4`
    // against a 40 GB film was a 40 GB download that returned four bytes and
    // exited 0. The command warned about it, because warning was the only honest
    // thing available.
    //
    // It now reads only the chunks covering the window (`docs/FORMAT.md` §3), so
    // there are two things to assert and they are equally important: the bytes are
    // right, and the warning is *gone*. A warning about a cost that is no longer
    // paid is the kind an operator learns to filter out before the run that
    // mattered.
    let sandbox = Sandbox::new();
    sandbox.dir("vault");

    // A recognisable pattern rather than zeros: a window taken from the wrong
    // offset — or from a chunk cached under the wrong index — cannot compare equal
    // to the right one by luck.
    let bytes: Vec<u8> = (0..RANGED_READ_FIXTURE_BYTES)
        .map(|i| (i % 251) as u8)
        .collect();
    sandbox.write("src/huge.bin", &bytes);

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .success();
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();

    // A ten-byte window from deep inside the object — past any header, past the
    // first chunk, and nowhere near a boundary the arithmetic could stumble on.
    let offset = RANGED_READ_FIXTURE_BYTES / 2 + 12_345;
    let windowed = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("cat")
        .arg(format!("{VAULT_NAME}:huge.bin"))
        .args(["--offset", &offset.to_string(), "--count", "10"])
        .assert()
        .success();
    assert_eq!(
        windowed.get_output().stdout,
        bytes[offset..offset + 10],
        "a window of a sealed object must be exactly the plaintext at that offset"
    );

    let stderr = String::from_utf8_lossy(&windowed.get_output().stderr).into_owned();
    assert!(
        !stderr.contains("no ranged read"),
        "the whole-object warning must be gone, not merely quiet:\n{stderr}"
    );
    assert!(
        !stderr.contains("warning"),
        "a windowed read of a sealed object has nothing to warn about:\n{stderr}"
    );

    // The control that gives the assertions above their meaning: a plain store
    // has always served genuine ranges, and must return the identical bytes for
    // the identical window. Two different code paths, one answer.
    sandbox
        .dctl()
        .args(["config", "create", "plain", "local"])
        .arg(format!("path={}", sandbox.path("src").display()))
        .assert()
        .success();
    let plain = sandbox
        .dctl()
        .arg("cat")
        .arg("plain:huge.bin")
        .args(["--offset", &offset.to_string(), "--count", "10"])
        .arg("--no-ask-password")
        .assert()
        .success();
    assert_eq!(
        plain.get_output().stdout,
        windowed.get_output().stdout,
        "a sealed vault and a plain store must agree byte for byte on a window"
    );
}

// ── 20. a vault is recoverable without its password ───────────────────────────
//
// `PLAN.md` §13.2 calls key survival the #1 risk of a twenty-year tool. The
// tests below are the only place that claim is checked the way a user would
// check it: through the real binary, against the real bytes, with the password
// genuinely gone rather than merely unused.

/// Pull the recovery phrase out of what `dctl init` wrote to stderr.
///
/// Parses the numbered grid rather than looking for a run of words, because the
/// numbering is the property worth depending on: a block that renumbered or
/// reordered its words would still contain twenty-four valid BIP-39 words and
/// would still look right to a laxer parser, while producing a phrase that
/// opens nothing. Words are accepted only when their printed number is the next
/// one expected, so this reads the phrase exactly as a human transcribing the
/// block would.
fn recovery_phrase_from(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let mut words: Vec<String> = Vec::new();
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for pair in tokens.chunks(2) {
            let [number, word] = pair else { continue };
            if number.parse::<usize>() == Ok(words.len() + 1) {
                words.push((*word).to_string());
            }
        }
    }
    assert!(
        !words.is_empty(),
        "no recovery phrase was printed. stderr was:\n{text}"
    );
    words.join(" ")
}

/// Create a vault, seal one file into it, and return the recovery phrase.
///
/// The password is used here and *never again* by the callers below — that is
/// the point of the fixture.
fn vault_with_a_file_and_its_phrase(sandbox: &Sandbox, contents: &[u8]) -> String {
    sandbox.write("src/secret.txt", contents);
    sandbox.dir("vault");

    let init = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .success();
    let phrase = recovery_phrase_from(&init.get_output().stderr);

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();

    phrase
}

#[test]
fn a_vault_opens_with_its_phrase_after_the_password_is_gone() {
    // THE proof. A vault is created, a file is sealed into it, the password is
    // then discarded entirely — `--no-ask-password` makes a password
    // *impossible* to supply, and the harness already clears `DCTL_PASSWORD` —
    // and the file comes back byte-identical from the phrase alone.
    //
    // The index is deleted first, so this is a machine that has never seen the
    // vault: everything needed comes from the object store plus twenty-four
    // words on a piece of paper.
    const SECRET: &[u8] = b"the bytes a forgotten password must not destroy";

    let sandbox = Sandbox::new();
    let phrase = vault_with_a_file_and_its_phrase(&sandbox, SECRET);

    std::fs::remove_file(sandbox.path("index.redb")).expect("destroy the local index");

    // A phrase drives an ordinary command, not just a recovery-shaped one.
    sandbox
        .dctl()
        .arg("--no-ask-password")
        .args(["--recovery-phrase", &phrase])
        .args(["index", "rebuild", &format!("{VAULT_NAME}:")])
        .assert()
        .success();

    let read_back = sandbox
        .dctl()
        .arg("--no-ask-password")
        .args(["--recovery-phrase", &phrase])
        .arg("cat")
        .arg(format!("{VAULT_NAME}:secret.txt"))
        .assert()
        .success();

    assert_eq!(
        read_back.get_output().stdout,
        SECRET,
        "the phrase alone must return the exact bytes that were sealed"
    );
}

#[test]
fn the_phrase_is_printed_on_stderr_and_never_on_stdout() {
    // stdout is the result stream: `dctl init --json | tee provisioning.log` is
    // an ordinary thing to run, and a phrase in a log file is a vault that is
    // permanently compromised — unlike a password, it cannot be rotated away.
    // Asserted under `--json`, which is the shape a provisioning script uses.
    let sandbox = Sandbox::new();
    sandbox.dir("vault");

    let output = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("--json")
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .success()
        .get_output()
        .clone();

    let phrase = recovery_phrase_from(&output.stderr);
    assert_eq!(
        phrase.split_whitespace().count(),
        24,
        "a 256-bit phrase is 24 words: {phrase}"
    );

    // The document must say only *that* a phrase was issued.
    let document = json(&output.stdout);
    assert_eq!(document["recovery_phrase_issued"], true);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains(&phrase),
        "the whole phrase reached stdout:\n{stdout}"
    );

    // And no *pair* of consecutive phrase words may appear adjacent in stdout.
    //
    // Neither a substring scan nor a whole-word scan works here, and both
    // failures are worth recording because each looks correct until it runs.
    // `stdout.contains(word)` fires on the JSON field `password_source`, which
    // contains "sword" — a real BIP-39 word — so a passing run would depend on
    // which twenty-four words the CSPRNG happened to choose. Matching whole
    // words instead fails the other way: "index", "source", "run" and "create"
    // are all in the BIP-39 list *and* in this document legitimately, so that
    // check is flaky in the opposite direction.
    //
    // Adjacency is the property that actually distinguishes them, because the
    // phrase's *order* is the thing that cannot occur by accident. The count is
    // reported rather than a bare boolean for the one residual case: `dry` and
    // `run` are both BIP-39 words and appear adjacent in this document as
    // `"dry_run"`, so a phrase that happened to place them consecutively would
    // match once (roughly one run in 180 000). That is what the number is for —
    // a leak matches ~23 of the 23 pairs, a coincidence matches exactly one, and
    // the two must never be confused for each other by someone who sees this
    // fail and reaches for a weaker check.
    let printed = alphabetic_words(&stdout);
    let secret = alphabetic_words(&phrase);
    let leaked = |haystack: &[String]| {
        secret
            .windows(2)
            .filter(|pair| haystack.windows(2).any(|seen| seen == *pair))
            .count()
    };

    // The check's own smoke test, and it earns its place: an assertion that
    // never fires passes every run while proving nothing, which for *this*
    // property means shipping a build that prints recovery phrases into log
    // files. Both a bare phrase and the rendered numbered block must be caught.
    let pairs = secret.len() - 1;
    assert_eq!(
        leaked(&alphabetic_words(&format!(
            "{{\"recovery_phrase\":\"{phrase}\"}}"
        ))),
        pairs,
        "the leak detector does not detect a leaked phrase"
    );
    assert_eq!(
        leaked(&alphabetic_words(&recovery_block_lines(&phrase).join("\n"))),
        pairs,
        "the leak detector misses the rendered numbered block"
    );

    assert_eq!(
        leaked(&printed),
        0,
        "consecutive phrase words reached stdout. A count near {pairs} is a \
         leak; a count of exactly 1 may be the documented `dry_run` \
         coincidence — check the phrase before changing this test:\n{stdout}"
    );
}

/// The recovery block as `dctl init` renders it, rebuilt for the smoke test
/// above: numbered words in a grid, which is the *other* shape a leak takes.
fn recovery_block_lines(phrase: &str) -> Vec<String> {
    phrase
        .split_whitespace()
        .enumerate()
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|row| {
            row.iter()
                .map(|(index, word)| format!("{:>2} {word}", index + 1))
                .collect::<Vec<_>>()
                .join("   ")
        })
        .collect()
}

/// Every run of ASCII letters in `text`, lowercased, in order.
///
/// Numbers and punctuation are separators, so the recovery block's numbered
/// grid (`1 shiver     2 quantum`) reduces to the word sequence itself — which
/// is what makes the adjacency check above catch a leak of the rendered block
/// as readily as a leak of the bare phrase.
fn alphabetic_words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_ascii_alphabetic())
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect()
}

#[test]
fn quiet_does_not_suppress_the_phrase() {
    // `--quiet` asks for less noise, not for something irreversible to happen
    // silently. A vault whose second key was generated and never shown has no
    // second key at all, and nothing can print it afterwards.
    let sandbox = Sandbox::new();
    sandbox.dir("vault");

    let output = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("--quiet")
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .success()
        .get_output()
        .clone();

    assert_eq!(
        recovery_phrase_from(&output.stderr)
            .split_whitespace()
            .count(),
        24
    );
}

#[test]
fn recovering_sets_a_new_password_and_leaves_the_phrase_working() {
    // `PLAN.md` §13.2's independence promise, end to end: rotating one wrapper
    // of the root key must not disturb another. If it did, the first password
    // change would silently destroy the paper backup and nobody would find out
    // until the day they needed it.
    const NEW_PASSWORD: &str = "an entirely different secret";
    const SECRET: &[u8] = b"still readable after the password changed";

    let sandbox = Sandbox::new();
    let phrase = vault_with_a_file_and_its_phrase(&sandbox, SECRET);

    sandbox
        .dctl()
        .args(["--recovery-phrase", &phrase])
        .args(["--password", NEW_PASSWORD])
        .args(["vault", "recover", &format!("{VAULT_NAME}:")])
        .assert()
        .success()
        .stderr(predicates::str::contains("still opens this vault"));

    // The old password is gone: VaultLocked (22), not a success.
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("cat")
        .arg(format!("{VAULT_NAME}:secret.txt"))
        .assert()
        .code(22);

    // The new password works …
    let by_password = sandbox
        .dctl()
        .env("DCTL_PASSWORD", NEW_PASSWORD)
        .arg("cat")
        .arg(format!("{VAULT_NAME}:secret.txt"))
        .assert()
        .success();
    assert_eq!(by_password.get_output().stdout, SECRET);

    // … and so does the phrase that was issued before the change.
    let by_phrase = sandbox
        .dctl()
        .arg("--no-ask-password")
        .args(["--recovery-phrase", &phrase])
        .arg("cat")
        .arg(format!("{VAULT_NAME}:secret.txt"))
        .assert()
        .success();
    assert_eq!(
        by_phrase.get_output().stdout,
        SECRET,
        "a password change must never invalidate the recovery phrase"
    );
}

#[test]
fn a_restore_drill_proves_the_phrase_without_changing_the_vault() {
    // `PLAN.md` §13.6: a backup nobody restored is not a backup. Checking the
    // paper still works has to be a read-only act, or it will not be done
    // yearly — so `--keep-password` must leave the existing password in force.
    const SECRET: &[u8] = b"drill";

    let sandbox = Sandbox::new();
    let phrase = vault_with_a_file_and_its_phrase(&sandbox, SECRET);

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .args(["--recovery-phrase", &phrase])
        .args([
            "vault",
            "recover",
            &format!("{VAULT_NAME}:"),
            "--keep-password",
        ])
        .assert()
        .success();

    // Unchanged: the original password still opens the vault.
    let still = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("cat")
        .arg(format!("{VAULT_NAME}:secret.txt"))
        .assert()
        .success();
    assert_eq!(still.get_output().stdout, SECRET);
}

#[test]
fn a_mistyped_phrase_says_so_instead_of_blaming_the_vault() {
    // BIP-39 carries a checksum, so "you mistyped a word" is distinguishable
    // from "this phrase is for another vault" — and the two have opposite
    // remedies. Reporting the first as `unlock failed` sends someone holding a
    // correct sheet of paper looking for a damaged envelope.
    let sandbox = Sandbox::new();
    let _phrase = vault_with_a_file_and_its_phrase(&sandbox, b"x");

    // Every word is a real BIP-39 word, so only the checksum can reject it.
    // Derived from the canonical all-`abandon` vector (valid final word `art`)
    // with word 0 mistyped to `ability` — the same fixture dctl-crypto's own
    // mnemonic tests use, for the same reason: a *generated* phrase mangled at
    // random still passes the 8-bit checksum ~1/256 times, which made this
    // test flaky.
    const MISTYPED: &str = "ability abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon abandon art";
    dctl_core::validate_recovery_phrase(MISTYPED)
        .expect_err("fixture must fail the BIP-39 checksum, or this test proves nothing");

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .args(["--recovery-phrase", MISTYPED])
        .arg("cat")
        .arg(format!("{VAULT_NAME}:secret.txt"))
        .assert()
        .code(22)
        .stderr(predicates::str::contains("not a valid recovery phrase"));
}

#[test]
fn init_refuses_a_phrase_rather_than_ignoring_it() {
    // The trap: `--recovery-phrase` is global, so it parses on `init`, and
    // somebody who has read that a phrase opens a vault will try to supply one.
    // Ignoring it would generate a *different* phrase while the operator
    // believed theirs was in force.
    let sandbox = Sandbox::new();
    sandbox.dir("vault");

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .args(["--recovery-phrase", "legal winner thank year"])
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .code(1)
        .stderr(predicates::str::contains("generated, not chosen"));

    assert!(
        !sandbox.path("vault").join(ENVELOPE).exists(),
        "a refused init must create no vault"
    );
}

#[test]
fn the_unlock_failure_names_a_recovery_command_that_exists() {
    // The hint read by somebody who believes their vault is lost. It has named
    // a nonexistent command twice in this codebase's history; this asserts both
    // that it offers the route *and* that the route runs.
    let sandbox = Sandbox::new();
    sandbox.dir("vault");

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .success();

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", "not the password at all")
        .arg("cat")
        .arg(format!("{VAULT_NAME}:anything.txt"))
        .assert()
        .code(22)
        .stderr(predicates::str::contains("dctl vault recover"));

    // And the named command is real: it parses, resolves the vault, and reaches
    // its own refusal — no phrase was supplied — rather than clap's
    // "unrecognized subcommand". `--keep-password` is what makes the missing
    // *phrase* the thing reported: without it an unattended run is refused
    // earlier, for having no new password to set.
    sandbox
        .dctl()
        .arg("--no-ask-password")
        .args([
            "vault",
            "recover",
            &format!("{VAULT_NAME}:"),
            "--keep-password",
        ])
        .assert()
        .code(22)
        .stderr(predicates::str::contains("recovery phrase"));
}

// ── the modification time survives every kind of transfer ─────────────────────

#[test]
fn a_second_local_copy_skips_every_file_and_only_a_touched_one_moves() {
    // The plainest form of the defect, and the one no compensation ever covered:
    // `dctl copy ./src ./backup` re-copied the whole tree on every run, because
    // the destination file was created *now* and the source was modified
    // whenever it was modified. Nothing about a vault is involved — the
    // modification time simply was not carried across.
    //
    // Both halves are asserted, because the first alone would pass on a tool
    // that had stopped transferring anything at all.
    let sandbox = Sandbox::new();
    for (path, bytes) in AGED_TREE {
        sandbox.write(path, bytes);
        sandbox.age(path, A_DAY);
    }

    for expected in ["Files: 3 / 3", "Files: 0 / 0"] {
        sandbox
            .dctl()
            .arg("--no-ask-password")
            .arg("copy")
            .arg(sandbox.path("src"))
            .arg(sandbox.path("backup"))
            .assert()
            .success()
            .stderr(predicates::str::contains(expected));
    }

    // One file moves on: only it may be re-copied.
    sandbox.write("src/b.txt", b"second, edited");

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(sandbox.path("backup"))
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 1 / 1"));

    assert_eq!(sandbox.read("backup/b.txt"), b"second, edited");
    assert_eq!(sandbox.read("backup/a.txt"), b"first");
}

// ── 14. reports that must reach a default-verbosity reader ───────────────────

#[test]
fn an_empty_checksum_manifest_says_so_at_the_default_verbosity() {
    // An empty SUMS file passes `sha256sum -c` trivially, so the sentence that
    // stops a person mistaking an empty manifest for a verified one is the whole
    // safety of this command. It used to be an `Out::info`, suppressed below
    // `-v`, so a default run printed nothing on either stream and exited 0.
    let sandbox = Sandbox::new();
    let store = sandbox.dir("store");
    sandbox.write(
        "dctl.toml",
        format!(
            "[remotes.plain]\ntype = \"local\"\npath = {:?}\n",
            store.to_string_lossy()
        )
        .as_bytes(),
    );

    let assert = sandbox
        .dctl()
        .args(["hashsum", "blake3", "plain:"])
        .assert()
        .success();
    let output = assert.get_output();

    assert!(
        output.stdout.is_empty(),
        "an empty manifest has no lines: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("checksum file is empty"),
        "a default run must say the manifest is empty, on stderr: {stderr:?}"
    );

    // And it stays out of the file `sha256sum -c` would read.
    assert!(!stderr.is_empty() && output.stdout.is_empty());
}

#[test]
fn a_listing_of_an_unmounted_named_remote_refuses_rather_than_reporting_empty() {
    // The unmounted-volume scenario, on the spelling an operator actually
    // configures. `dctl ls backups:` used to print nothing on either stream and
    // exit 0 — the same answer as an empty tree, and what a retention job acts
    // on — while `dctl ls /the/same/path` exited 3.
    let sandbox = Sandbox::new();
    let absent = sandbox.path("not-mounted");
    sandbox.write(
        "dctl.toml",
        format!(
            "[remotes.backups]\ntype = \"local\"\npath = {:?}\n",
            absent.to_string_lossy()
        )
        .as_bytes(),
    );

    for target in ["backups:", "backups:2019"] {
        let assert = sandbox
            .dctl()
            .args(["ls", target])
            .assert()
            // 3 = dir_not_found, the same code every transfer verb
            // already gives this path (docs/EXIT_CODES.md).
            .code(3);
        let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
        assert!(
            stderr.contains("mounted"),
            "{target}: the operator has to be told what to check: {stderr:?}"
        );
    }

    // The same directory, once it exists, lists as empty — which is a real
    // answer and must stay one.
    std::fs::create_dir_all(&absent).expect("create the volume");
    sandbox
        .dctl()
        .args(["ls", "backups:"])
        .assert()
        .success()
        .stdout("");
}

#[test]
fn no_command_reports_zero_for_a_volume_that_is_not_mounted() {
    // The scenario, and the reason this is a table rather than one assertion:
    //
    //     dctl purge archive:2019 --force && record_purged 2019
    //
    // The archive volume did not mount. Every one of these commands used to
    // enumerate nothing, do nothing, and exit **0** — `OK removed: 0 object(s)`,
    // `Total objects: 0`, `objects 0 / bytes 0 B` — so 2019 was marked reclaimed
    // while the data sat untouched, and a monitor reading `dctl size backup:`
    // would page somebody to say the backup had been wiped.
    //
    // Every row here is a command whose output a script acts on.
    let sandbox = Sandbox::new();
    let absent = sandbox.path("not-mounted");
    sandbox.write(
        "dctl.toml",
        format!(
            "[remotes.archive]\ntype = \"local\"\npath = {:?}\n",
            absent.to_string_lossy()
        )
        .as_bytes(),
    );

    let commands: &[&[&str]] = &[
        &["ls", "archive:"],
        &["lsl", "archive:"],
        &["lsd", "archive:"],
        &["lsjson", "archive:"],
        &["tree", "archive:"],
        &["size", "archive:"],
        &["about", "archive:"],
        &["hashsum", "blake3", "archive:"],
        &["delete", "archive:2019"],
        &["deletefile", "archive:2019/a.bin"],
        &["purge", "archive:2019", "--force"],
        &["rmdirs", "archive:"],
    ];

    for argv in commands {
        let assert = sandbox.dctl().args(*argv).assert();
        let output = assert.get_output();
        let code = output.status.code();
        assert_ne!(
            code,
            Some(0),
            "{argv:?} reported success over an unmounted volume;              stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("mounted"),
            "{argv:?} must tell the operator what to check: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn json_on_a_real_transfer_is_a_document_and_not_zero_bytes() {
    // `dctl --json copy src dst | wc -c` printed **0**, on every real run. The
    // plan was rendered only under `--dry-run`, and the stderr statistics block
    // is suppressed in the JSON formats, so there was no output at all — while
    // `--dry-run --json` on the same command produced 427 bytes.
    //
    // A CI job running `dctl --json sync /srv/data backup: > run.json` and then
    // reading `run.json` to record what moved got an empty file every time,
    // including the runs where files failed.
    let sandbox = Sandbox::new();
    sandbox.write("src/a.txt", b"aaaa");
    sandbox.write("src/b.txt", b"bb");

    let assert = sandbox
        .dctl()
        .args(["--json", "copy", "src", "dst"])
        .assert()
        .success();
    let document = json(&assert.get_output().stdout);

    assert_eq!(document["command"], "copy");
    assert_eq!(document["dry_run"], false);
    // The counters are the executor's, not the plan's: `files` is files whose
    // durable commit returned.
    assert_eq!(document["result"]["files"], 2);
    assert_eq!(document["result"]["bytes"], 6);
    assert_eq!(document["result"]["errors"], 0);
    assert_eq!(
        document["actions"].as_array().map(Vec::len),
        Some(2),
        "the plan is still there: {document}"
    );

    // And the bytes really moved, which is the only assertion that cannot be
    // faked by a counter.
    assert_eq!(sandbox.read("dst/a.txt"), b"aaaa");

    // A dry run still claims nothing: the key is absent rather than zeroed.
    let rehearsal = sandbox
        .dctl()
        .args(["--json", "--dry-run", "copy", "src", "dst2"])
        .assert()
        .success();
    let planned = json(&rehearsal.get_output().stdout);
    assert_eq!(planned["dry_run"], true);
    assert!(planned["result"].is_null(), "{planned}");
    assert!(!sandbox.exists("dst2"));
}

#[test]
fn json_on_a_transfer_with_a_failure_still_reports_what_happened() {
    // The worse half of the same defect: with a real per-file failure the JSON
    // channel was *still* empty while the process exited 6, so the one run a
    // consumer most needs a record of produced no record at all.
    let sandbox = Sandbox::new();
    sandbox.write("src/ok.txt", b"fine");
    sandbox.write("src/blocked.txt", b"nope");
    // A directory where the destination file has to go, so that one entry fails
    // and the other succeeds.
    sandbox.dir("dst/blocked.txt");

    let assert = sandbox
        .dctl()
        .args(["--json", "copy", "src", "dst"])
        // 6 = partial_failure (docs/EXIT_CODES.md).
        .assert()
        .code(6);
    let document = json(&assert.get_output().stdout);

    assert_eq!(document["result"]["errors"], 1);
    assert_eq!(document["result"]["files"], 1);
    assert_eq!(sandbox.read("dst/ok.txt"), b"fine");
}

#[test]
fn a_run_that_refused_before_it_started_prints_no_statistics_block() {
    // `dctl replicate` against a location that is not a vault's object store
    // printed a full summary *above* its own error:
    //
    //      Transferred: 0 B / 0 B, -
    //            Files: 0 / 0
    //           Errors: 0
    //     error: SOURCE-STORE: 'pl:' is not a vault's object store …
    //
    // `Errors: 0` in a table is not noise there; it is a direct contradiction of
    // the line beneath it, printed first and with more formatting. The refusal
    // is the whole report a run like this has.
    let sandbox = Sandbox::new();
    sandbox.dir("plain");
    sandbox
        .dctl()
        .args(["config", "create", "plainloc", "local"])
        .arg(format!("path={}", sandbox.path("plain").display()))
        .assert()
        .success();

    let refused = sandbox
        .dctl()
        .args(["replicate", "plainloc:", "elsewhere:"])
        // 7 = fatal_error (docs/EXIT_CODES.md).
        .assert()
        .code(7);
    let stderr = String::from_utf8_lossy(&refused.get_output().stderr).into_owned();

    assert!(
        stderr.contains("is not a vault's object store"),
        "the refusal itself must still be reported:\n{stderr}"
    );
    for row in ["Transferred:", "Files:", "Errors:", "Elapsed:"] {
        assert!(
            !stderr.contains(row),
            "a run that attempted nothing must not print '{row}':\n{stderr}"
        );
    }
}

#[test]
fn a_run_that_failed_partway_still_prints_what_it_moved() {
    // The control, and the reason the rule is about *attempting nothing* rather
    // than about failing. A copy that moved one file of two and then failed has
    // a record nothing else carries: suppressing the summary here would lose the
    // only statement of what actually landed.
    let sandbox = Sandbox::new();
    sandbox.write("src/ok.txt", b"fine");
    sandbox.write("src/blocked.txt", b"nope");
    sandbox.dir("dst/blocked.txt");

    let partial = sandbox
        .dctl()
        .args(["copy", "src", "dst"])
        // 6 = partial_failure (docs/EXIT_CODES.md).
        .assert()
        .code(6);
    let stderr = String::from_utf8_lossy(&partial.get_output().stderr).into_owned();

    assert!(stderr.contains("Transferred:"), "{stderr}");
    assert!(stderr.contains("Errors:"), "{stderr}");
    assert!(
        stderr.contains("Files:"),
        "the file counters are the record of what landed:\n{stderr}"
    );
}

#[test]
fn a_remote_to_remote_refusal_prints_no_counter_lines() {
    // The harder case of the rule above: `moveto` between two remotes LISTS
    // its source and accounts its skips before `Engine::connect` refuses, so
    // planning-side counters have moved even though nothing landed. The old
    // every-counter predicate took that accounting as work and printed
    // `Checks: 1 / 1` and `Errors: 0` in a table above a refusal saying
    // nothing was done. Planning is an intention, not a record.
    let sandbox = Sandbox::new();
    sandbox.write("one/render.mov", b"frames");
    sandbox.dir("two");
    for (name, dir) in [("pl", "one"), ("p2", "two")] {
        sandbox
            .dctl()
            .args(["config", "create", name, "local"])
            .arg(format!("path={}", sandbox.path(dir).display()))
            .assert()
            .success();
    }

    let refused = sandbox
        .dctl()
        .arg("--force")
        .args(["moveto", "pl:render.mov", "p2:final.mov"])
        // 7 = fatal_error (docs/EXIT_CODES.md).
        .assert()
        .code(7);
    let output = refused.get_output();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();

    assert!(
        stderr.contains("not implemented in this build"),
        "the refusal itself must still be reported:\n{stderr}"
    );
    assert!(
        sandbox.path("one/render.mov").exists(),
        "a refused moveto must leave the source in place"
    );
    for row in ["Transferred:", "Files:", "Checks:", "Errors:", "Elapsed:"] {
        assert!(
            !stderr.contains(row) && !stdout.contains(row),
            "a refusal is the whole report; '{row}' must not appear above \
             it:\nstderr:\n{stderr}\nstdout:\n{stdout}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The flags that used to parse and do nothing
// ─────────────────────────────────────────────────────────────────────────────
//
// Eleven global flags were accepted, listed in `--help`, and had no effect on
// any run. The measurements that found them were made against this binary, so
// the tests that close them are made against this binary too: a unit test on a
// limiter proves the limiter, and only a process proves the flag reaches it.
//
// Each of the four implemented flags is asserted by its *effect* — elapsed time,
// an exit status, a byte count on disk, a line of output — never by a counter
// that a stage could increment without doing the work.

/// Bytes of test data that make a rate limit measurable without making the
/// suite slow: eight files of 32 KiB is 256 KiB, which at 128 KiB/s is about
/// two seconds of pacing.
const PACED_FILE_BYTES: usize = 32 * 1024;
const PACED_FILE_COUNT: usize = 8;

#[test]
fn bwlimit_paces_a_single_object_and_not_merely_the_gaps_between_files() {
    // The defect this closes, measured against this binary before the fix: the
    // limiter was charged once per *finished file*, so a run of one object was
    // not paced at all. 8 MiB as a single file at `--bwlimit 1M` took **47 ms**;
    // the same 8 MiB as eight files took **7051 ms**. The last file of every run
    // was unpaced for the same reason.
    //
    // One object is therefore the whole test. The same total moved as many files
    // was already paced correctly and proves nothing about the fix — which is
    // exactly why the defect survived a test suite that had a `--bwlimit` test
    // in it.
    let sandbox = Sandbox::new();
    let bytes = PACED_FILE_BYTES * PACED_FILE_COUNT;
    sandbox.write("src/one.bin", &vec![b'p'; bytes]);

    // Unpaced first, so that a slow fixture cannot be mistaken for a working
    // limiter. This is the number that was 47 ms.
    let started = std::time::Instant::now();
    sandbox
        .dctl()
        .args(["copy", "src", "dst-fast"])
        .assert()
        .success();
    let unpaced = started.elapsed();
    assert!(
        unpaced < std::time::Duration::from_secs(1),
        "the fixture must be fast when unpaced, took {unpaced:?}"
    );

    // 256 KiB at 128 KiB/s is two seconds of debt. The first window is free by
    // construction — the charge is made after bytes move — so the floor is set
    // at one second: far above the unpaced run, and far above what charging
    // once at the end of the single file could ever produce.
    let started = std::time::Instant::now();
    sandbox
        .dctl()
        .args(["--bwlimit", "128k", "copy", "src", "dst-slow"])
        .assert()
        .success();
    let paced = started.elapsed();

    assert!(
        paced >= std::time::Duration::from_secs(1),
        "--bwlimit 128k over one {} KiB object must take at least a second; took \
         {paced:?} against {unpaced:?} unpaced — the limiter is being charged \
         once for the whole file rather than per window",
        bytes / 1024
    );

    // And it moved every byte: a limiter that worked by transferring less would
    // pass the timing assertion and fail the product.
    assert_eq!(
        std::fs::read(sandbox.path("dst-slow/one.bin")).expect("the object arrived"),
        vec![b'p'; bytes]
    );
}

#[test]
fn bwlimit_actually_slows_the_run_down() {
    // The measurement that exposed the defect was a throughput one — `--bwlimit
    // 1k` moved 10 MiB at 32.9 MiB/s, about 34 000x the requested rate — so the
    // test that closes it is a throughput one. Nothing here inspects a field.
    //
    // The assertion is a *floor* on elapsed time, never a ceiling: a loaded CI
    // machine can always be slower, and a test that failed for being slow would
    // be turned off within a month.
    let sandbox = Sandbox::new();
    let payload = vec![b'p'; PACED_FILE_BYTES];
    for index in 0..PACED_FILE_COUNT {
        sandbox.write(&format!("src/f{index}.bin"), &payload);
    }

    // First, unpaced, to establish that the fixture itself is fast. If copying
    // 256 KiB locally took two seconds anyway, the paced run below would prove
    // nothing at all.
    let started = std::time::Instant::now();
    sandbox
        .dctl()
        .args(["copy", "src", "dst-fast"])
        .assert()
        .success();
    let unpaced = started.elapsed();
    assert!(
        unpaced < std::time::Duration::from_secs(2),
        "the fixture must be fast when unpaced, took {unpaced:?}"
    );

    // 128 KiB/s over 256 KiB is ~2 s of debt, of which the first file's share is
    // never waited for (see `limits::bandwidth`) — so the floor is set at 1 s,
    // comfortably above the unpaced run and comfortably below the ideal.
    let started = std::time::Instant::now();
    sandbox
        .dctl()
        .args(["--bwlimit", "128k", "copy", "src", "dst-slow"])
        .assert()
        .success();
    let paced = started.elapsed();

    assert!(
        paced >= std::time::Duration::from_secs(1),
        "--bwlimit 128k over {} KiB must take at least a second; took {paced:?} \
         against {unpaced:?} unpaced",
        (PACED_FILE_BYTES * PACED_FILE_COUNT) / 1024
    );

    // And it must still have moved every byte: a limiter that worked by
    // transferring less would pass a timing assertion and fail the product.
    for index in 0..PACED_FILE_COUNT {
        assert_eq!(
            sandbox.read(&format!("dst-slow/f{index}.bin")).len(),
            PACED_FILE_BYTES
        );
    }
}

#[test]
fn bwlimit_off_is_not_paced() {
    // The other half: `off` must mean off. A limiter that paced an unlimited run
    // would be a performance regression nobody could switch back.
    let sandbox = Sandbox::new();
    let payload = vec![b'p'; PACED_FILE_BYTES];
    for index in 0..PACED_FILE_COUNT {
        sandbox.write(&format!("src/f{index}.bin"), &payload);
    }

    let started = std::time::Instant::now();
    sandbox
        .dctl()
        .args(["--bwlimit", "off", "copy", "src", "dst"])
        .assert()
        .success();
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
}

#[test]
fn a_malformed_bandwidth_limit_is_a_usage_error_not_an_unlimited_run() {
    // The failure that makes a cost control worthless: a value that does not
    // parse, accepted, and the run proceeding at full speed.
    let sandbox = Sandbox::new();
    sandbox.write("src/a.txt", b"data");
    sandbox
        .dctl()
        .args(["--bwlimit", "10Q", "copy", "src", "dst"])
        // 1 = usage (docs/EXIT_CODES.md).
        .assert()
        .code(1);
    assert!(
        !sandbox.exists("dst/a.txt"),
        "a refused command line must transfer nothing"
    );
}

#[test]
fn max_transfer_stops_the_run_and_reaches_exit_8() {
    // Exit code 8 was unreachable in every build: `--max-transfer 1M` moved the
    // whole 10 MiB and exited 0. This is the test that makes the published
    // contract real.
    let sandbox = Sandbox::new();
    // Three files of 64 KiB against a 100 KiB ceiling: the first fits, the
    // second does not, and the run stops there.
    let payload = vec![b'm'; 64 * 1024];
    for name in ["a.bin", "b.bin", "c.bin"] {
        sandbox.write(&format!("src/{name}"), &payload);
    }

    let stopped = sandbox
        .dctl()
        .args(["--max-transfer", "100k", "copy", "src", "dst"])
        // 8 = transfer_limit_exceeded (docs/EXIT_CODES.md).
        .assert()
        .code(8);
    let stderr = String::from_utf8_lossy(&stopped.get_output().stderr).into_owned();
    assert!(
        stderr.contains("--max-transfer"),
        "the stop must name the flag that caused it:\n{stderr}"
    );

    // Cautious, not hard: the limit is not exceeded by a byte, and no
    // partially-written object is left behind. Exactly one file landed, whole.
    let landed: Vec<PathBuf> = all_files(&sandbox.path("dst"));
    assert_eq!(
        landed.len(),
        1,
        "one file fits under 100 KiB, got {landed:?}"
    );
    assert_eq!(
        std::fs::metadata(&landed[0])
            .expect("the file exists")
            .len(),
        64 * 1024,
        "what landed must be whole"
    );
}

#[test]
fn max_transfer_smaller_than_the_first_file_moves_nothing() {
    // The documented consequence of the cautious cutoff, pinned so nobody
    // "fixes" it into a partial write later: `--max-transfer 1M` against a
    // 10 MiB file transfers nothing rather than 1 MiB of it.
    let sandbox = Sandbox::new();
    sandbox.write("src/big.bin", &vec![b'x'; 256 * 1024]);

    sandbox
        .dctl()
        .args(["--max-transfer", "64k", "copy", "src", "dst"])
        .assert()
        .code(8);

    assert!(
        all_files(&sandbox.path("dst")).is_empty(),
        "a file that does not fit is never started, so nothing may be on disk"
    );
}

#[test]
fn max_duration_stops_the_run_and_reaches_exit_10() {
    // Exit code 10 was reserved and unreachable in every build, because
    // `--max-duration` did not exist — and its absence was the defect
    // `HANDOVER.md` §11.3 item 2 names: `--timeout` bounds one attempt, so a run
    // that met a dead network had no flag that bounded it at all, and one
    // measured against live B2 under `--timeout 30 --retries 1` was still going
    // **943.6 s** after the cut. This is the test that makes the published
    // contract real, against the real binary.
    //
    // The window is deliberately far too short rather than merely tight, so the
    // assertion is about the *stop* and not about a race with the machine's
    // load. A run that cannot start a file inside 1 ms is what "the window has
    // closed" looks like from the pipeline, and it is the same code path a
    // four-hour window reaches four hours in.
    let sandbox = Sandbox::new();
    for name in ["a.bin", "b.bin", "c.bin"] {
        sandbox.write(&format!("src/{name}"), &vec![b'm'; 64 * 1024]);
    }

    let stopped = sandbox
        .dctl()
        .args(["--max-duration", "1ms", "copy", "src", "dst"])
        // 10 = duration_limit_exceeded (docs/EXIT_CODES.md).
        .assert()
        .code(10);
    let stderr = String::from_utf8_lossy(&stopped.get_output().stderr).into_owned();
    assert!(
        stderr.contains("--max-duration"),
        "the stop must name the flag that caused it:\n{stderr}"
    );
    assert!(
        stderr.contains("cleanup"),
        "a hard cutoff leaves reclaimable debris and the hint must say so:\n{stderr}"
    );
    // Whatever landed, landed whole: a verified write commits nothing unless the
    // stored bytes match, so a cut run must never leave a short object.
    for file in all_files(&sandbox.path("dst")) {
        assert_eq!(
            std::fs::metadata(&file).expect("the file exists").len(),
            64 * 1024,
            "a run stopped at its deadline left a partial object: {file:?}"
        );
    }
}

#[test]
fn max_duration_ends_the_process_rather_than_merely_reporting_the_deadline() {
    // The half §32.9 is actually about. The deadline firing was never in doubt —
    // it fired at exactly 30 s, to the second — and the run carried on for
    // another fifteen minutes. So what is measured here is **wall time of the
    // whole process**, against a run that would otherwise take far longer than
    // its window: 2 MiB at 32 KiB/s is a minute of transfer, given two seconds.
    let sandbox = Sandbox::new();
    sandbox.write("src/big.bin", &vec![b'x'; 2 * 1024 * 1024]);

    let started = std::time::Instant::now();
    sandbox
        .dctl()
        .args([
            "--max-duration",
            "2s",
            "--bwlimit",
            "32k",
            "copy",
            "src",
            "dst",
        ])
        .assert()
        .code(10);
    let took = started.elapsed();

    assert!(
        took < std::time::Duration::from_secs(30),
        "the run outlived its own --max-duration by more than an order of \
         magnitude, which is the defect this flag exists to close: {took:?}"
    );
}

#[test]
fn max_duration_ends_the_process_even_when_the_work_it_stopped_cannot_be_cancelled() {
    // The last place `--max-duration` could have failed to be a bound, and it
    // did — found by the live proof and not by any test that existed at the
    // time, which is why this one is here.
    //
    // A configured `local:` remote copies inside `spawn_blocking` and paces
    // there with a real `std::thread::sleep`. `spawn_blocking` work cannot be
    // cancelled: dropping the command future detaches it, and dropping the
    // runtime then waits for the blocking pool to drain. Measured against the
    // release binary, `--max-duration 3s` on 8 MiB at `--bwlimit 64k` printed
    // its deadline on time and the process exited **126 seconds** later — the
    // whole of the pacing, for bytes nobody would ever look at. The report was
    // right and the run was still there, which is `HANDOVER.md` §32.9's
    // complaint with a new cause.
    //
    // The **bare-path** form of the same copy exits on time and always did, so
    // a test written against `copy src dst` — which is what the first spelling
    // of this suite's deadline tests used — passes while the defect is present.
    // The destination has to be a configured remote for the paced blocking path
    // to be the one under test.
    const WINDOW_SECS: u64 = 2;
    // Four mebibytes at 32 KiB/s is 128 seconds of pacing: two orders of
    // magnitude more than the window, so a process that waits for it cannot be
    // mistaken for one that was merely slow.
    let sandbox = Sandbox::new();
    sandbox.write("src/big.bin", &vec![b'p'; 4 * 1024 * 1024]);
    let root = sandbox.dir("store");
    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", root.display()))
        .assert()
        .success();

    let started = std::time::Instant::now();
    sandbox
        .dctl()
        .args([
            "--no-ask-password",
            "--bwlimit",
            "32k",
            "--max-duration",
            "2s",
            "copy",
            "src",
            &format!("{PLAIN_REMOTE}:"),
        ])
        // 10 = duration_limit_exceeded (docs/EXIT_CODES.md).
        .assert()
        .code(10);
    let took = started.elapsed();

    assert!(
        took < std::time::Duration::from_secs(30),
        "the run reported its deadline at {WINDOW_SECS}s and the process took \
         {took:?} to go away — a deadline the operator cannot observe is not a \
         bound"
    );
}

#[test]
fn max_duration_off_and_a_window_the_run_fits_inside_change_nothing() {
    // The direction that matters more, and the one this flag could have broken:
    // a deadline a run is comfortably inside must not touch it. An inactivity
    // deadline that behaved like a stopwatch would kill healthy large transfers,
    // which is worse than having no whole-run bound at all.
    let sandbox = Sandbox::new();
    for name in ["a.bin", "b.bin", "c.bin"] {
        sandbox.write(&format!("src/{name}"), &vec![b'm'; 64 * 1024]);
    }
    sandbox
        .dctl()
        .args(["--max-duration", "off", "copy", "src", "dst"])
        .assert()
        .success();
    assert_eq!(all_files(&sandbox.path("dst")).len(), 3);

    let generous = Sandbox::new();
    for name in ["a.bin", "b.bin", "c.bin"] {
        generous.write(&format!("src/{name}"), &vec![b'm'; 64 * 1024]);
    }
    generous
        .dctl()
        .args(["--max-duration", "1h", "copy", "src", "dst"])
        .assert()
        .success();
    assert_eq!(all_files(&generous.path("dst")).len(), 3);
}

#[test]
fn a_malformed_run_window_is_a_usage_error_not_an_unbounded_run() {
    // The same failure `--bwlimit 10Q` has: a value that does not parse,
    // accepted, and the bound silently absent. A backup window removed without
    // anybody being told is the one thing this flag may not do.
    let sandbox = Sandbox::new();
    sandbox.write("src/a.txt", b"data");
    sandbox
        .dctl()
        .args(["--max-duration", "4hrs", "copy", "src", "dst"])
        // 1 = usage (docs/EXIT_CODES.md).
        .assert()
        .code(1);
    assert!(
        !sandbox.exists("dst/a.txt"),
        "a refused command line must transfer nothing"
    );
}

#[test]
fn max_transfer_off_transfers_everything() {
    let sandbox = Sandbox::new();
    for name in ["a.bin", "b.bin", "c.bin"] {
        sandbox.write(&format!("src/{name}"), &vec![b'm'; 64 * 1024]);
    }
    sandbox
        .dctl()
        .args(["--max-transfer", "off", "copy", "src", "dst"])
        .assert()
        .success();
    assert_eq!(all_files(&sandbox.path("dst")).len(), 3);
}

#[test]
fn stats_one_line_condenses_a_record_that_is_otherwise_a_block() {
    // The flag was indistinguishable from its absence, because the periodic
    // record only ever had one shape. Both shapes are now asserted against the
    // real binary, from the same run length, so "it does something" is measured
    // rather than asserted.
    //
    // `--stats 1` with output redirected (which it always is here) is what makes
    // the ticker emit at all; the copy is slowed by `--bwlimit` so that at least
    // one interval elapses while it runs.
    let sandbox = Sandbox::new();
    let payload = vec![b's'; PACED_FILE_BYTES];
    for index in 0..PACED_FILE_COUNT {
        sandbox.write(&format!("src/f{index}.bin"), &payload);
    }

    let block = sandbox
        .dctl()
        .args(["--stats", "1", "--bwlimit", "128k", "copy", "src", "dst-a"])
        .assert()
        .success();
    let block = String::from_utf8_lossy(&block.get_output().stderr).into_owned();

    let condensed = sandbox
        .dctl()
        .args([
            "--stats",
            "1",
            "--stats-one-line",
            "--bwlimit",
            "128k",
            "copy",
            "src",
            "dst-b",
        ])
        .assert()
        .success();
    let condensed = String::from_utf8_lossy(&condensed.get_output().stderr).into_owned();

    // The condensed form carries `files` and a percentage on one line; the block
    // carries labelled rows. Counting `Errors:` occurrences separates them
    // without depending on how many intervals elapsed: the block emits one per
    // record *plus* the end-of-run summary, the condensed form only the summary.
    let block_rows = block.matches("Errors:").count();
    let condensed_rows = condensed.matches("Errors:").count();
    assert!(
        block_rows > condensed_rows,
        "the default record must be the block and --stats-one-line must not be:\n\
         block ({block_rows}):\n{block}\ncondensed ({condensed_rows}):\n{condensed}"
    );
    assert!(
        condensed.contains("files"),
        "the condensed record must still report progress:\n{condensed}"
    );
}

#[test]
fn every_inert_flag_is_now_refused_by_name_before_anything_runs() {
    // The five that cannot be honoured. Each must fail the run, name itself,
    // explain what the tool does instead, and leave the destination untouched —
    // the `--key-file` contract, applied to every one of them.
    //
    // Driven through the binary rather than through `cli::reach`'s unit guard on
    // purpose: the unit test proves the table refuses, and this proves the table
    // is *reached* by a real command line. Those are different claims, and the
    // second one is what `--key-file` got wrong for a whole release.
    //
    // It was seven. `--timeout` and `--contimeout` left this list because they
    // are honoured now, and the test directly below is the other half of that
    // move: a flag may only leave here by arriving there. `--verify-samples`
    // left the same way when the sampled read-back became real — its arrival
    // half is `a_sampled_read_back_is_accepted_and_the_file_arrives`.
    let cases: &[(&[&str], &str)] = &[
        (&["--transfers", "8"], "--transfers"),
        (&["--checkers", "16"], "--checkers"),
        (&["--low-level-retries", "5"], "--low-level-retries"),
        (&["--dump", "headers"], "--dump"),
    ];

    for (flag, name) in cases {
        let sandbox = Sandbox::new();
        sandbox.write("src/a.txt", b"data");

        let mut command = sandbox.dctl();
        command.args(*flag).args(["copy", "src", "dst"]);
        // 7 = fatal_error: a configuration the engine cannot satisfy.
        let refused = command.assert().code(7);
        let stderr = String::from_utf8_lossy(&refused.get_output().stderr).into_owned();

        assert!(
            stderr.contains(name),
            "the refusal must name {name}:\n{stderr}"
        );
        assert!(
            stderr.contains("dctl copy"),
            "and what the user was doing:\n{stderr}"
        );
        assert!(
            !sandbox.exists("dst/a.txt"),
            "{name} must be refused before anything is written"
        );
    }
}

#[test]
fn the_two_deadlines_are_accepted_and_a_healthy_transfer_is_untouched() {
    // The other half of the list above: these two used to be refused with exit
    // 7, so a run that named them transferred nothing at all. Now they are
    // honoured, which has to mean two things at once — the run is accepted, and
    // the data actually arrives.
    //
    // The second half is the one worth having. An idle deadline that fired on a
    // transfer which was progressing would be worse than no deadline: it would
    // destroy work that was succeeding, and it would do it silently on exactly
    // the large transfers that take longest to redo. A local copy is instant, so
    // this cannot catch a deadline that is merely too short — but it does catch
    // one that is armed wrongly, which is the failure that would land here.
    for flag in [
        vec!["--timeout", "30"],
        vec!["--contimeout", "10"],
        vec!["--timeout", "300", "--contimeout", "60"],
        // Zero is rclone's "wait forever" and must be a legal answer rather than
        // a deadline of no length at all.
        vec!["--timeout", "0", "--contimeout", "0"],
    ] {
        let sandbox = Sandbox::new();
        sandbox.write("src/a.txt", b"data");

        let mut command = sandbox.dctl();
        command.args(&flag).args(["copy", "src", "dst"]);
        command.assert().success();

        assert!(
            sandbox.exists("dst/a.txt"),
            "{flag:?} must transfer the file, not merely be accepted"
        );
    }
}

#[test]
fn a_sampled_read_back_is_accepted_and_the_file_arrives() {
    // `--verify-samples` left the refused list when the sampled read-back
    // became real. Accepted has to mean two things at once — the run is
    // accepted, and the data arrives having survived the sampled
    // authentication. Driven against a real vault so the sampled arm is the
    // code that actually runs, not merely parses.
    let sandbox = Sandbox::new();
    let _phrase = vault_with_a_file_and_its_phrase(&sandbox, b"seed");
    sandbox.write("src/a.txt", b"data worth spot checking");

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .args(["--verify", "sample", "--verify-samples", "4"])
        .args(["copy", "src", &format!("{VAULT_NAME}:sampled/")])
        .assert()
        .success();

    let out = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("cat")
        .arg(format!("{VAULT_NAME}:sampled/a.txt"))
        .assert()
        .success();
    assert_eq!(
        out.get_output().stdout,
        b"data worth spot checking",
        "the sampled write must land the same bytes"
    );

    // Zero is not a legal depth: head and tail are mandatory, and a depth of
    // nothing is a contradiction the parser refuses rather than reinterprets.
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .args(["--verify", "sample", "--verify-samples", "0"])
        .args(["copy", "src", &format!("{VAULT_NAME}:again/")])
        .assert()
        .failure();
}

#[test]
fn a_nightly_copy_repairs_a_destination_that_lost_an_object() {
    // BENCHMARKS §7.2 defect 1, High: delete one stored object behind the
    // tool's back and the nightly copy reported `Checks: 150/150, Skipped:
    // 150, Errors: 0` — the index rows still described the lost bytes as
    // live, nothing consulted the store, and the loss surfaced at restore.
    // The destination reconciliation makes the same run repair instead.
    let sandbox = Sandbox::new();
    sandbox.write("src/a.txt", b"alpha");
    sandbox.write("src/b.txt", b"bravo");
    sandbox.write("src/c.txt", b"charlie");
    sandbox.dir("vault");
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .success();
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();

    // The damage, exactly as the benchmark inflicted it.
    let objects: Vec<_> = std::fs::read_dir(sandbox.path("vault/o"))
        .expect("the object namespace exists")
        .map(|entry| entry.expect("a store entry").path())
        .collect();
    assert_eq!(objects.len(), 3, "three sealed objects before the damage");
    std::fs::remove_file(&objects[0]).expect("the damage lands");

    // The nightly. Success is required — but so is the repair.
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();
    let after = std::fs::read_dir(sandbox.path("vault/o"))
        .expect("the object namespace exists")
        .count();
    assert_eq!(
        after, 3,
        "the nightly must re-upload the lost object, not skip it as identical"
    );

    // The proof that matters: every byte restores.
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(format!("{VAULT_NAME}:"))
        .arg(sandbox.path("out"))
        .assert()
        .success();
    for (name, bytes) in [
        ("a.txt", &b"alpha"[..]),
        ("b.txt", &b"bravo"[..]),
        ("c.txt", &b"charlie"[..]),
    ] {
        assert_eq!(
            std::fs::read(sandbox.path(&format!("out/{name}"))).expect("the file restores"),
            bytes,
            "{name} must restore byte-identical after the repair"
        );
    }
}

#[test]
fn the_deadlines_publish_the_defaults_they_apply() {
    // A default is a published claim. `--timeout` printed `[default: 300]` for a
    // five-minute idle timeout no backend applied, which is why it carried no
    // default at all until this pass. It carries one again because it is true,
    // and `--help` is where an operator reads it.
    let sandbox = Sandbox::new();
    let mut command = sandbox.dctl();
    command.arg("--help");
    let shown = command.assert().success();
    let stdout = String::from_utf8_lossy(&shown.get_output().stdout).into_owned();

    assert!(stdout.contains("--timeout"), "{stdout}");
    assert!(stdout.contains("--contimeout"), "{stdout}");
    // rclone's own two numbers (`fs/config.go:115-123`), which is what makes a
    // migrating script's expectations hold.
    assert!(
        stdout.contains("[default: 300]"),
        "the idle deadline must publish its five minutes:\n{stdout}"
    );
    assert!(
        stdout.contains("[default: 60]"),
        "and the connect deadline its sixty seconds:\n{stdout}"
    );
}

#[test]
fn the_honest_value_of_a_sequential_engine_is_accepted() {
    // `--transfers 1` is a true statement about this executor, so it runs.
    // Refusing a request for the behaviour you already have would be a worse
    // tool, not a more honest one.
    let sandbox = Sandbox::new();
    sandbox.write("src/a.txt", b"data");
    sandbox
        .dctl()
        .args(["--transfers", "1", "--checkers", "1", "copy", "src", "dst"])
        .assert()
        .success();
    assert_eq!(sandbox.read("dst/a.txt"), b"data");
}

#[test]
fn a_single_letter_remote_is_a_remote_and_never_a_directory_named_r_colon() {
    // On Linux `dctl copy /srv/data r:` created a local directory literally
    // named `r:` and exited 0 — a backup landing somewhere nobody named. rclone
    // treats `r` as a remote everywhere except Windows.
    //
    // On Windows the same argument is a drive-relative path, which is a
    // different but equally non-silent answer; the assertion below is written to
    // hold on both, because what must never happen is the third outcome.
    let sandbox = Sandbox::new();
    sandbox.write("src/a.txt", b"data");

    let outcome = sandbox.dctl().args(["copy", "src", "r:"]).assert();
    let code = outcome.get_output().status.code().unwrap_or_default();
    assert_ne!(
        code, 0,
        "a reference to an undefined remote is not a success"
    );

    assert!(
        !sandbox.exists("r:"),
        "nothing may be created under a directory literally named 'r:'"
    );
}

/// A run that finds nothing to do must still say so in the format it was asked
/// for.
///
/// The hole: `copy`, `sync` and `move` return from their `plan.is_noop()` branch
/// *before* `report::outcome`, and the only thing that branch emits is
/// `ctx.out.info(...)`, which the JSON formats suppress. So a second, unchanged
/// run produced **zero bytes on stdout and zero on stderr** and exited 0:
///
/// ```text
/// $ dctl --json sync src dst | wc -c     # first run
/// 505
/// $ dctl --json sync src dst | wc -c     # second run, nothing to do
/// 0
/// ```
///
/// This was unreachable in practice until `sync` became incremental: before
/// that every run had work to do, so the empty branch was never the steady
/// state. Now it is the steady state — a nightly
/// `dctl --json sync ... > run.json` writes an empty file on every healthy
/// night, and a consumer cannot tell that from the binary failing to start.
/// "Nothing needed doing" is a result, and a result document is how this tool
/// reports one.
#[test]
fn a_no_op_transfer_still_renders_its_result_document_under_json() {
    for verb in ["copy", "sync", "move"] {
        let sandbox = Sandbox::new();
        sandbox.write("src/a.txt", b"contents");
        // First run: real work, and it is reported.
        sandbox
            .dctl()
            .args(["--json", "copy", "src", "dst"])
            .assert()
            .success();

        // Second run through the verb under test: nothing left to do.
        let quiet = sandbox
            .dctl()
            .args(["--json", verb, "src", "dst"])
            .assert()
            .success();
        let stdout = String::from_utf8_lossy(&quiet.get_output().stdout).into_owned();
        assert!(
            !stdout.trim().is_empty(),
            "dctl --json {verb} with nothing to do wrote nothing at all to stdout"
        );
        let document: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
            panic!(
                "{verb}: {error}
{stdout}"
            )
        });
        assert_eq!(
            document["result"]["files"], 0,
            "{verb}: the document must say that no file moved:
{stdout}"
        );
        assert_eq!(
            document["result"]["bytes"], 0,
            "{verb}: and that no bytes moved:
{stdout}"
        );
    }
}

/// A no-op run must not be silent in *any* format.
///
/// The stronger statement of the test above, and the one that matches
/// `PLAN.md` §7: whatever the format, a successful run says something. Text
/// already printed its statistics block; the JSON formats printed nothing at
/// all, which is the one outcome a tool that refuses to lie must never have.
#[test]
fn no_successful_transfer_exits_silently_on_both_streams() {
    for format in ["text", "json", "json-lines"] {
        let sandbox = Sandbox::new();
        sandbox.write("src/a.txt", b"contents");
        sandbox
            .dctl()
            .args(["--format", format, "sync", "src", "dst"])
            .assert()
            .success();
        let second = sandbox
            .dctl()
            .args(["--format", format, "sync", "src", "dst"])
            .assert()
            .success();
        let output = second.get_output();
        assert!(
            !output.stdout.is_empty() || !output.stderr.is_empty(),
            "--format={format}: exit 0 with nothing on either stream"
        );
    }
}

/// Bytes per file, and the rate the pacing tests below hold a run to.
///
/// Chosen together so a run lasts about two seconds: long enough for the
/// one-second periodic record to fire at least once, short enough that three of
/// these are not a noticeable part of the suite. The pacing is what buys the
/// time — a local copy of 400 KiB is otherwise instantaneous, and a flag about
/// *periodic* output cannot be observed in a run that does not last a period.
///
/// **Two** files, not one, and that is not arbitrary: `--bwlimit` charges a file
/// after it has moved and makes the *next* one wait, so a single-file run is
/// never delayed at all (`limits::bandwidth`). One file paced to any rate
/// whatsoever finishes instantly, which is how the first draft of this test
/// managed to prove nothing.
const PACED_BYTES: usize = 200 * 1024;
const PACED_RATE: &str = "100k";

/// Write the paced fixture: two files, each [`PACED_BYTES`] of `fill`.
fn paced_source(sandbox: &Sandbox, fill: u8) {
    sandbox.write("src/one.bin", &vec![fill; PACED_BYTES]);
    sandbox.write("src/two.bin", &vec![fill; PACED_BYTES]);
}

/// Status records on a stream, counted by the one thing only they carry.
///
/// `--stats-one-line` is passed by both callers so the periodic record is a
/// single line containing an ETA. The end-of-run summary renders the same
/// counters but has no ETA row — it is a report of what happened, not a
/// projection — so this counts periodic records and nothing else. Counting
/// `Errors` instead would count the final summary too and both runs would look
/// identical.
fn status_records(stderr: &[u8]) -> usize {
    String::from_utf8_lossy(stderr)
        .lines()
        .filter(|line| line.contains("ETA"))
        .count()
}

/// `-P` has to change what a run actually writes, or it is a belief rather than
/// a flag.
///
/// This is `HANDOVER.md` §11.2's fourth bullet, end to end: the flag was
/// accepted, documented, and produced byte-identical output in every
/// environment. Off a terminal the display is periodic records, and their
/// cadence is what `-P` selects — a minute by default, which is right for an
/// unattended nightly job and useless to somebody watching, against one second,
/// which is what asking to watch means.
///
/// Both runs are redirected, because `assert_cmd` captures the streams: that is
/// the environment the flag exists for and the one where the previous behaviour
/// was actively harmful.
#[test]
fn progress_changes_what_a_redirected_run_reports() {
    let sandbox = Sandbox::new();
    paced_source(&sandbox, 0x41);

    let quiet_run = sandbox
        .dctl()
        .args([
            "--bwlimit",
            PACED_RATE,
            "--stats-one-line",
            "copy",
            "src",
            "dst-plain",
        ])
        .assert()
        .success();
    let watched_run = sandbox
        .dctl()
        .args([
            "-P",
            "--bwlimit",
            PACED_RATE,
            "--stats-one-line",
            "copy",
            "src",
            "dst-watched",
        ])
        .assert()
        .success();

    let unwatched = status_records(&quiet_run.get_output().stderr);
    let watched = status_records(&watched_run.get_output().stderr);
    assert_eq!(
        unwatched,
        0,
        "a two-second run reports nothing at the default one-minute cadence, and \
         that is the behaviour -P exists to change. Got:\n{}",
        String::from_utf8_lossy(&quiet_run.get_output().stderr)
    );
    assert!(
        watched >= 1,
        "-P asked to watch a two-second run and got {watched} status records:\n{}",
        String::from_utf8_lossy(&watched_run.get_output().stderr)
    );

    // And the transfer itself is unaffected: a flag about output must not change
    // what lands.
    assert_eq!(
        std::fs::read(sandbox.path("dst-watched/two.bin")).expect("the copy landed"),
        vec![0x41; PACED_BYTES]
    );
}

/// `--json -P` gives the operator progress back without touching the JSON.
///
/// The other half of what `-P` does. `--json` silences the display because a
/// program is reading stdout — a courtesy, since progress goes to stderr and the
/// two cannot collide. For a four-hour run there is then nothing at all to watch,
/// so `-P` restores it, and this proves the restoration does not cost the machine
/// consumer anything: stdout still parses.
#[test]
fn progress_restores_the_display_under_json_without_polluting_it() {
    let sandbox = Sandbox::new();
    paced_source(&sandbox, 0x42);

    let run = sandbox
        .dctl()
        .args([
            "--json",
            "-P",
            "--bwlimit",
            PACED_RATE,
            "--stats-one-line",
            "copy",
            "src",
            "dst",
        ])
        .assert()
        .success();
    let output = run.get_output();

    assert!(
        status_records(&output.stderr) >= 1,
        "--json -P must still show progress on stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str::<serde_json::Value>(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout must still be one JSON document ({e}):\n{stdout}"));
}

#[test]
fn log_source_stamps_every_record_even_when_a_log_file_is_open() {
    // `--log-source` was honoured in exactly one configuration: an interactive
    // run with no `--log-file`. Adding the flag an unattended job always has —
    // the file it will actually be asked for when something goes wrong —
    // silently switched `--log-source` off on *both* streams, because the two
    // `Some(file)` arms of `logging::init` built their layers without
    // `.with_file()`/`.with_line_number()` at all.
    //
    // Measured on the release binary before the fix, over one `copy`:
    //
    //     --log-source                 : 1 record on stderr carries `.rs:LINE`
    //     --log-source --log-file X    : 0 on stderr, 0 in X
    //
    // No warning, no error. A support engineer asks for `--log-source
    // --log-file` and gets a file with no source locations in it, which is the
    // silent-partial-success class `PLAN.md` §7 forbids.
    //
    // The assertion is on the *records*, not on the flag being read: a flag
    // whose only witness is that some code mentions the field is exactly what
    // §13.3's guard admits it cannot catch.
    const PAYLOAD: &[u8] = b"a record worth locating in the source";

    let sandbox = Sandbox::new();
    sandbox.write("src/a.txt", PAYLOAD);
    let root = sandbox.dir("store");
    let log = sandbox.path("run.log");

    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", root.display()))
        .assert()
        .success();

    let run = sandbox
        .dctl()
        .args(["--log-level", "info", "--log-source", "--log-file"])
        .arg(&log)
        .arg("--no-ask-password")
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&run.get_output().stderr).into_owned();
    let file = String::from_utf8(sandbox.read("run.log")).expect("the log file is text");

    // The per-file INFO record has to be there at all, or the rest asserts
    // nothing: a log with no records trivially has no records missing a source
    // location.
    assert!(
        file.contains("file finished"),
        "the log file holds no per-file record to locate:\n{file}"
    );

    let located = |text: &str| text.lines().filter(|line| line.contains(".rs:")).count();
    assert!(
        located(&file) > 0,
        "--log-source stamped no record in --log-file:\n{file}"
    );
    assert!(
        located(&stderr) > 0,
        "--log-source stamped no record on stderr once --log-file was open:\n{stderr}"
    );

    // …and the flag is still what decides it: the same run without it carries
    // no source location anywhere, so the assertion above is not passing on
    // something the formatter prints unconditionally.
    let plain_log = sandbox.path("plain.log");
    sandbox
        .dctl()
        .args(["--log-level", "info", "--log-file"])
        .arg(&plain_log)
        .arg("--no-ask-password")
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{PLAIN_REMOTE}:again"))
        .assert()
        .success();
    let plain = String::from_utf8(sandbox.read("plain.log")).expect("the log file is text");
    assert!(
        plain.contains("file finished"),
        "the control run wrote no records:\n{plain}"
    );
    assert_eq!(
        located(&plain),
        0,
        "a record carried a source location without --log-source:\n{plain}"
    );
}

// ── 21. symbolic links: the canonical layout, end to end ──────────────────────

/// `/srv` with the data on another volume and linked into place.
///
/// Returns the sandbox and the path to stand in for `/srv`. Everything lives
/// inside the sandbox, so `data -> …/mnt/bigdisk/data` is an absolute link to a
/// directory the test owns and no real `/mnt` is involved.
#[cfg(unix)]
fn canonical_layout() -> (Sandbox, PathBuf) {
    let sandbox = Sandbox::new();
    sandbox.write("mnt/bigdisk/data/report.csv", b"rows,and,rows");
    sandbox.write("mnt/bigdisk/data/nested/deep.txt", b"deep");
    let srv = sandbox.dir("srv");
    sandbox.write("srv/readme.txt", b"on the system disk");
    std::os::unix::fs::symlink(sandbox.path("mnt/bigdisk/data"), srv.join("data"))
        .expect("create the canonical symlink");
    (sandbox, srv)
}

#[cfg(unix)]
#[test]
fn copying_a_tree_whose_data_is_a_symlink_says_so_instead_of_exiting_quietly() {
    // `HANDOVER.md` §11.2's last data-destroying defect, driven through the
    // shipped binary. `/srv/data -> /mnt/bigdisk/data` is the canonical layout
    // of every machine with a small system disk, and pointing DCTL at `/srv`
    // copied `readme.txt`, said `Errors: 0`, and exited 0 — the operator found
    // out on restore day.
    //
    // The default still does not follow the link. What it may never do again is
    // pass over it in silence, so the assertion is on *stderr*: the count, and
    // the flag that changes the answer.
    let (sandbox, srv) = canonical_layout();
    let store = sandbox.dir("store");
    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", store.display()))
        .assert()
        .success();

    let assertion = sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("copy")
        .arg(&srv)
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr).into_owned();

    assert!(
        stderr.contains("skipped 1 symbolic link"),
        "the run said nothing about the link that held the whole dataset:\n{stderr}"
    );
    assert!(
        stderr.contains("--links follow"),
        "the warning must name the flag that stores it:\n{stderr}"
    );
    // And the omission is real, so the warning is not decoration.
    assert!(sandbox.exists("store/readme.txt"));
    assert!(!sandbox.exists("store/data/report.csv"));
}

#[cfg(unix)]
#[test]
fn following_the_link_stores_the_tree_behind_it() {
    // The other half: the flag the warning names actually works, and the bytes
    // land under the link's own name — `data/report.csv`, which is where a
    // restore has to put them back.
    let (sandbox, srv) = canonical_layout();
    let store = sandbox.dir("store");
    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", store.display()))
        .assert()
        .success();

    sandbox
        .dctl()
        .args(["--no-ask-password", "--links", "follow"])
        .arg("copy")
        .arg(&srv)
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .success();

    assert_eq!(sandbox.read("store/data/report.csv"), b"rows,and,rows");
    assert_eq!(sandbox.read("store/data/nested/deep.txt"), b"deep");
    assert_eq!(sandbox.read("store/readme.txt"), b"on the system disk");
}

#[cfg(unix)]
#[test]
fn listing_the_same_tree_reports_the_same_link() {
    // The read-side half of the defect, and the reason it matters: an operator
    // checks with `ls` before deciding what is safe to delete from the source.
    // `dctl ls /srv` printed one file and nothing else — indistinguishable from
    // a tree that really does hold one file.
    let (sandbox, srv) = canonical_layout();

    let listing = sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("ls")
        .arg(&srv)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&listing.get_output().stdout).into_owned();
    let stderr = String::from_utf8_lossy(&listing.get_output().stderr).into_owned();

    assert!(stdout.contains("readme.txt"));
    assert!(
        !stdout.contains("report.csv"),
        "the default did not follow, so the target is not listed:\n{stdout}"
    );
    assert!(
        stderr.contains("skipped 1 symbolic link"),
        "`ls` must say what it passed over:\n{stderr}"
    );

    // …and `--links follow` shows the tree, on stdout, where a listing belongs.
    let followed = sandbox
        .dctl()
        .args(["--no-ask-password", "--links", "follow"])
        .arg("ls")
        .arg(&srv)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&followed.get_output().stdout).into_owned();
    assert!(stdout.contains("data/report.csv"), "{stdout}");
    assert!(stdout.contains("data/nested/deep.txt"), "{stdout}");
}

#[cfg(unix)]
#[test]
fn verbose_names_the_links_a_run_passed_over() {
    // "skipped 1" is enough to stop an operator; the name is what tells them
    // *which* directory is missing from the backup.
    let (sandbox, srv) = canonical_layout();

    let assertion = sandbox
        .dctl()
        .args(["--no-ask-password", "-v"])
        .arg("ls")
        .arg(&srv)
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr).into_owned();
    assert!(
        stderr.contains("data: not followed"),
        "-v must name the link and say what happened to it:\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_cycle_terminates_rather_than_filling_the_disk() {
    // `HANDOVER.md` §11.3 item 1 names loop protection as the reason this fix
    // had not been attempted. A link at its own ancestor is the oldest way to
    // make a backup tool run until the disk fills; the run must finish, list the
    // real file once, and say which link closed the loop.
    let sandbox = Sandbox::new();
    let root = sandbox.dir("tree");
    sandbox.write("tree/inner/a.txt", b"a");
    std::os::unix::fs::symlink(&root, root.join("inner/loop")).expect("create the loop");

    let assertion = sandbox
        .dctl()
        .args(["--no-ask-password", "--links", "follow", "-v"])
        .arg("ls")
        .arg(&root)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout).into_owned();
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr).into_owned();

    assert_eq!(
        stdout.lines().filter(|line| line.contains("a.txt")).count(),
        1,
        "the file must appear exactly once:\n{stdout}"
    );
    assert!(
        stderr.contains("points at a directory it is already inside"),
        "the cycle must be named, not merely survived:\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn a_link_out_of_the_tree_is_followed_or_refused_by_policy_and_never_in_silence() {
    // "An operator syncing /srv must not silently pull in /etc." Following one
    // is available, because the canonical layout *is* out of tree; doing it
    // quietly is not, and `--links in-tree` refuses it outright.
    let sandbox = Sandbox::new();
    sandbox.write("outside/passwd", b"root:x:0:0");
    let root = sandbox.dir("srv");
    std::os::unix::fs::symlink(sandbox.path("outside"), root.join("etc"))
        .expect("create the outward link");

    let followed = sandbox
        .dctl()
        .args(["--no-ask-password", "--links", "follow", "-v"])
        .arg("ls")
        .arg(&root)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&followed.get_output().stdout).into_owned();
    let stderr = String::from_utf8_lossy(&followed.get_output().stderr).into_owned();
    assert!(stdout.contains("etc/passwd"), "{stdout}");
    assert!(
        stderr.contains("etc: followed"),
        "a followed link must be named at -v, so pulling in /etc is never silent:\n{stderr}"
    );

    let confined = sandbox
        .dctl()
        .args(["--no-ask-password", "--links", "in-tree"])
        .arg("ls")
        .arg(&root)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&confined.get_output().stdout).into_owned();
    let stderr = String::from_utf8_lossy(&confined.get_output().stderr).into_owned();
    assert!(
        !stdout.contains("passwd"),
        "in-tree must not leave the tree:\n{stdout}"
    );
    assert!(stderr.contains("skipped 1 symbolic link"), "{stderr}");
}

#[cfg(unix)]
#[test]
fn a_broken_link_is_named_and_counted_without_stopping_the_run() {
    // A dangling link must not abort a backup of 200 000 other files. It must
    // also not pass unnoticed: the operator asked for it and did not get it, so
    // it is an error the exit code reflects — the same answer rclone gives
    // (`backend/local/local.go:741` fails the sync on one).
    let sandbox = Sandbox::new();
    let root = sandbox.dir("tree");
    sandbox.write("tree/good.txt", b"kept");
    std::os::unix::fs::symlink(sandbox.path("tree/gone.txt"), root.join("stale.txt"))
        .expect("create the dangling link");
    let store = sandbox.dir("store");
    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", store.display()))
        .assert()
        .success();

    let assertion = sandbox
        .dctl()
        .args(["--no-ask-password", "--links", "follow", "-v"])
        .arg("copy")
        .arg(&root)
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert();
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr).into_owned();

    // The rest of the tree still arrives — that is the "without stopping" half.
    assert_eq!(sandbox.read("store/good.txt"), b"kept");
    assert!(
        stderr.contains("point at nothing"),
        "the dangling link must be reported:\n{stderr}"
    );
    assert!(
        stderr.contains("stale.txt: points at nothing"),
        "-v must name it:\n{stderr}"
    );
    assert_ne!(
        assertion.get_output().status.code(),
        Some(0),
        "a file that was asked for and not stored is not a clean run"
    );
}

#[cfg(unix)]
#[test]
fn a_tree_with_no_links_says_nothing_about_them() {
    // The property that keeps the warning worth reading. A line printed on every
    // run is a line nobody reads on the run that has one.
    let sandbox = Sandbox::new();
    sandbox.write("tree/a.txt", b"a");

    let assertion = sandbox
        .dctl()
        .args(["--no-ask-password", "-v"])
        .arg("ls")
        .arg(sandbox.path("tree"))
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr).into_owned();
    assert!(
        !stderr.contains("symbolic link"),
        "an ordinary tree must produce no link report at all:\n{stderr}"
    );
}

// ── 22. the debris a killed write leaves, and the sweep that must see it ──────

/// A staging file exactly as an interrupted verified write leaves one.
///
/// Spelled out rather than taken from `dctl_store::staging_name()`: this file
/// pins the *observable* layout, and a test that asked the code under test what
/// it calls its own debris would keep passing if that answer changed to
/// something `cleanup` no longer recognised.
#[cfg(unix)]
fn plant_staging_file(directory: &Path, bytes: &[u8]) -> PathBuf {
    std::fs::create_dir_all(directory).expect("create the store directory");
    let path = directory.join(".dctl-staging.4711.0");
    std::fs::write(&path, bytes).expect("plant the staging file");
    path
}

#[cfg(unix)]
#[test]
fn cleanup_reclaims_the_staging_file_an_interrupted_write_left_in_a_plain_store() {
    // `HANDOVER.md` §11.2: a `SIGKILL` three seconds into a copy leaves
    // `o/.dctl-staging.<pid>.<seq>` in the store, and
    // `cleanup --class staging --min-age 0s` reported `OK removed: 0 object(s)`
    // with the file still there. A nightly backup over a flaky link leaks one
    // full-size staging file per interruption and is told every night that
    // there is nothing to reclaim.
    let sandbox = Sandbox::new();
    let store = sandbox.dir("store");
    sandbox.write("store/o/real.bin", b"a committed object");
    let debris = plant_staging_file(&store.join("o"), &vec![7u8; 4096]);

    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", store.display()))
        .assert()
        .success();

    let assertion = sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("cleanup")
        .arg(format!("{PLAIN_REMOTE}:"))
        .args(["--class", "staging", "--min-age", "0s"])
        .assert()
        .success();
    let output = assertion.get_output();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !debris.exists(),
        "the sweep reported on debris it left behind:\n{text}"
    );
    assert!(
        text.contains("removed: 1 object(s)"),
        "the count must be the debris actually removed:\n{text}"
    );
    assert!(
        sandbox.exists("store/o/real.bin"),
        "a committed object is not debris"
    );
}

#[cfg(unix)]
#[test]
fn cleanup_reclaims_the_staging_file_an_interrupted_write_left_in_a_vault() {
    // The same defect on the sealed view, which is the one an operator actually
    // runs: `dctl cleanup archive: --class staging`.
    let sandbox = Sandbox::new();
    sandbox.write("plain/note.txt", b"kept");
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .success();
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("copy")
        .arg(sandbox.path("plain"))
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();

    let debris = plant_staging_file(&sandbox.path("vault").join("o"), &vec![3u8; 2048]);

    let assertion = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("cleanup")
        .arg(format!("{VAULT_NAME}:"))
        .args(["--class", "staging", "--min-age", "0s"])
        .assert()
        .success();
    let output = assertion.get_output();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !debris.exists(),
        "the vault sweep gave a false all-clear:\n{text}"
    );
    assert!(
        text.contains("removed: 1 object(s)"),
        "the count must be the debris actually removed:\n{text}"
    );
    // And the vault is untouched: the file that was really stored still lists.
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("ls")
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success()
        .stdout(predicates::str::contains("note.txt"));
}

#[cfg(unix)]
#[test]
fn a_sweep_that_left_debris_because_it_was_young_says_so_rather_than_reporting_nothing() {
    // The defect this pass found live, on the release binary. A `SIGKILL` five
    // seconds into a copy leaves a 238 MiB staging file, and the sweep an
    // operator's nightly job actually runs — `dctl cleanup v: --class staging`,
    // with no `--min-age`, so the default day applies — answered:
    //
    //     no reclaimable debris found in 'v:'
    //     OK removed: 0 object(s), 0 B
    //
    // at every verbosity up to `-vvv`, with the file still on the store. Holding
    // a staging file younger than the default is *right*: it may belong to a
    // transfer still running, which is why `--min-age` is load-bearing rather
    // than a tuning knob. Saying "no reclaimable debris found" over it is not.
    // That sentence is the false all-clear this whole family spent a release
    // printing — the one `HANDOVER.md` §11.3 item 1 was closed to stop — moved
    // from the listing to the age filter rather than removed.
    let sandbox = Sandbox::new();
    let store = sandbox.dir("store");
    let debris = plant_staging_file(&store.join("o"), &vec![9u8; 8192]);

    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", store.display()))
        .assert()
        .success();

    let assertion = sandbox
        .dctl()
        .arg("--no-ask-password")
        // `-v`, and it is the whole reason this test can fail. The false
        // all-clear is emitted through `Out::info`, which is silent below
        // verbosity 1 — so this assertion used to be the absence of a sentence
        // the command would not have printed either way, and deleting the guard
        // that suppresses it left the gate green. Measured: `HANDOVER.md` §35.3.
        .arg("-v")
        .arg("cleanup")
        .arg(format!("{PLAIN_REMOTE}:"))
        .args(["--class", "staging"])
        .assert()
        .success();
    let output = assertion.get_output();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        debris.exists(),
        "the default sweep must not delete debris younger than --min-age:\n{text}"
    );
    assert!(
        !text.contains("no reclaimable debris found"),
        "the sweep found debris and left it; saying it found none is the false \
         all-clear this command exists not to print:\n{text}"
    );
    assert!(
        text.contains("held"),
        "what was seen and left has to be reported as held:\n{text}"
    );
    assert!(
        text.contains(".dctl-staging.4711.0"),
        "the object that was left has to be named, so an operator can decide \
         whether to lower --min-age:\n{text}"
    );
    assert!(
        text.contains("1 held"),
        "the summary has to carry the count, because that is the line a nightly \
         job's output gets grepped for:\n{text}"
    );
}

#[cfg(unix)]
#[test]
fn an_explicit_min_age_that_holds_everything_still_names_what_it_held() {
    // What this test is, and what it is not.
    //
    // It used to be called `debris_whose_age_cannot_be_established_is_held_and_
    // named_rather_than_passed_over`, and its comment said it drove the arm that
    // holds debris whose modification time the provider will not report. It does
    // not: `local:` reports a modification time for every file, so what a
    // 36-hour minimum over a file planted a moment ago exercises is the
    // *younger-than* arm — the same one the test above it drives, through a
    // different door. Deleting the unknown-age arm therefore left the gate
    // green, and the name said otherwise (`HANDOVER.md` §35.3).
    //
    // No shipped backend can be made to omit a modification time from a listing
    // on demand, so that arm is held where it can be held honestly: in
    // `removal::reclaim`'s own tests, against `Aging::verdict`, which is the one
    // place both call sites now make the decision.
    //
    // What is left here is worth keeping on its own account. It is the operator
    // path where **every** candidate is held: an explicit `--min-age` larger
    // than anything on the store, which is what a first sweep after an incident
    // looks like, and the run still has to name what it left and must not report
    // a clean store.
    let sandbox = Sandbox::new();
    let store = sandbox.dir("store");
    plant_staging_file(&store.join("o"), &vec![1u8; 512]);

    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", store.display()))
        .assert()
        .success();

    // A day and a half: the file cannot be `min_age` old however the clock is
    // read, so the hold does not depend on the test machine's clock resolution.
    let assertion = sandbox
        .dctl()
        .arg("--no-ask-password")
        // See the test above: below `-v` the sentence this asserts the absence
        // of is never printed, so the assertion could not fail.
        .arg("-v")
        .arg("cleanup")
        .arg(format!("{PLAIN_REMOTE}:"))
        .args(["--class", "staging", "--min-age", "36h"])
        .assert()
        .success();
    let output = assertion.get_output();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains("held") && text.contains(".dctl-staging.4711.0"),
        "a sweep that looked at debris and left it names it:\n{text}"
    );
    assert!(
        !text.contains("no reclaimable debris found"),
        "it did find some:\n{text}"
    );
}

#[cfg(unix)]
#[test]
fn a_cleanup_sweep_never_reclaims_a_users_file_that_merely_looks_temporary() {
    // The other direction, and the reason the sweep may not carry its own
    // opinion about which keys are DCTL's: a substring test on `.tmp.` is what
    // put a user's `report.tmp.2024.csv` in the bin.
    let sandbox = Sandbox::new();
    let store = sandbox.dir("store");
    sandbox.write("store/report.tmp.2024.csv", b"rows");
    sandbox.write("store/photo.jpg.tmp.4711.0", b"an older DCTL's spelling");
    let debris = plant_staging_file(&store, b"half a write");

    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", store.display()))
        .assert()
        .success();
    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("cleanup")
        .arg(format!("{PLAIN_REMOTE}:"))
        .args(["--class", "staging", "--min-age", "0s"])
        .assert()
        .success();

    assert!(!debris.exists(), "the debris was not reclaimed");
    assert!(
        sandbox.exists("store/report.tmp.2024.csv"),
        "a user's file was swept as debris"
    );
    assert!(
        sandbox.exists("store/photo.jpg.tmp.4711.0"),
        "an older DCTL's staging spelling is an ordinary file now"
    );
}

#[cfg(unix)]
#[test]
fn a_staging_file_younger_than_the_minimum_age_is_left_where_it_is() {
    // `--min-age` is load-bearing rather than a tuning knob: now that the sweep
    // can see staging debris it can also see *another run's live write*, and the
    // age bound is the only thing standing between the two.
    let sandbox = Sandbox::new();
    let store = sandbox.dir("store");
    let debris = plant_staging_file(&store, b"a write happening right now");

    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", store.display()))
        .assert()
        .success();
    let assertion = sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("cleanup")
        .arg(format!("{PLAIN_REMOTE}:"))
        .args(["--class", "staging", "--min-age", "1h"])
        .assert()
        .success();
    let output = assertion.get_output();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(debris.exists(), "a live write was deleted:\n{text}");
    assert!(
        text.contains("removed: 0 object(s)"),
        "and the run must say it removed nothing:\n{text}"
    );
}

// ── 23. a fifo, socket or device node is reported, never passed over silently ─

/// A tree holding one ordinary file and one of each special file that can be
/// created without privileges.
///
/// A device node needs `CAP_MKNOD`, so it is not made here: the classification
/// of every POSIX file type is asserted exhaustively and without a filesystem
/// in `dctl_store::specials`, and the device nodes themselves are exercised
/// against a real tree in the live verification.
#[cfg(unix)]
fn tree_with_special_files(sandbox: &Sandbox) -> PathBuf {
    let src = sandbox.dir("src");
    sandbox.write("src/keep.txt", b"ordinary");
    let made = std::process::Command::new("mkfifo")
        .arg(src.join("pipe"))
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "mkfifo failed — the case cannot be tested");
    std::os::unix::net::UnixListener::bind(src.join("sock")).expect("bind a unix socket");
    src
}

#[cfg(unix)]
#[test]
fn a_fifo_and_a_socket_in_the_source_are_counted_and_named_rather_than_passed_over() {
    // `HANDOVER.md` §11.2: a tree holding `real.txt` and a named pipe copied as
    // `Files: 1 / 1, Errors: 0`, exit 0, with the pipe appearing nowhere in
    // stdout, stderr or the log even at `-v`. Skipping is right and matches
    // rclone — but rclone logs `Can't transfer non file/directory`
    // (`backend/local/local.go:1301`), and DCTL's own source cites that very
    // line as its authority for skipping while omitting the half that speaks.
    let sandbox = Sandbox::new();
    let src = tree_with_special_files(&sandbox);
    let destination = sandbox.dir("dst");

    let assertion = sandbox
        .dctl()
        .args(["--no-ask-password", "-v"])
        .arg("copy")
        .arg(&src)
        .arg(&destination)
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr).into_owned();

    assert!(
        stderr.contains("skipped 2 special file(s)"),
        "the run said nothing about what it passed over:\n{stderr}"
    );
    assert!(
        stderr.contains("pipe: a named pipe"),
        "-v must name the fifo and say what it is:\n{stderr}"
    );
    assert!(
        stderr.contains("sock: a unix socket"),
        "-v must name the socket and say what it is:\n{stderr}"
    );
    // The skip itself is unchanged, and it is still not an error: rclone's
    // `Storable` returns false and logs, and raises no error count with it.
    assert!(sandbox.exists("dst/keep.txt"));
    assert!(!sandbox.exists("dst/pipe"));
    assert!(!sandbox.exists("dst/sock"));
}

#[cfg(unix)]
#[test]
fn a_listing_says_what_it_passed_over_just_as_a_transfer_does() {
    // The listing family and the transfer family must agree about a tree: a
    // `ls` that shows one file and a `copy` that stores one file, over a
    // directory holding four entries, is the same silence in two places.
    let sandbox = Sandbox::new();
    let src = tree_with_special_files(&sandbox);

    let assertion = sandbox
        .dctl()
        .args(["--no-ask-password", "-v"])
        .arg("ls")
        .arg(&src)
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr).into_owned();

    assert!(
        stderr.contains("skipped 2 special file(s)"),
        "`ls` must disclose what it did not list:\n{stderr}"
    );
    assert!(
        stderr.contains("pipe: a named pipe"),
        "-v must name it:\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn a_backup_never_offers_to_store_a_fifo_and_says_that_it_did_not() {
    // The backup walk was worse than silent: it planned to *store* the fifo,
    // the socket and every device node, counted them in `N files`, and then
    // blocked forever on the first `open` of the pipe — a backup of `/var` that
    // never returns. Skipping them is the fix; saying so is the other half.
    let sandbox = Sandbox::new();
    let src = tree_with_special_files(&sandbox);
    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("init")
        .args(["--name", VAULT_NAME, "--base"])
        .arg(sandbox.path("vault"))
        .assert()
        .success();

    let assertion = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .args(["--dry-run", "-v"])
        .arg("backup")
        .arg(&src)
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();
    let output = assertion.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert!(
        !stdout.contains("src/pipe") && !stdout.contains("src/sock"),
        "a plan that offers to store a fifo is a plan that hangs:\n{stdout}"
    );
    assert!(
        stdout.contains("keep.txt"),
        "the ordinary file must still be planned:\n{stdout}"
    );
    assert!(
        stderr.contains("skipped 2 special file(s)"),
        "the scan must disclose what it passed over:\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn a_tree_with_no_special_files_says_nothing_about_them() {
    // The property that keeps the warning worth reading, asserted for specials
    // exactly as it is for links: an ordinary tree produces no line at all.
    let sandbox = Sandbox::new();
    sandbox.write("tree/a.txt", b"a");

    let assertion = sandbox
        .dctl()
        .args(["--no-ask-password", "-v"])
        .arg("ls")
        .arg(sandbox.path("tree"))
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr).into_owned();
    assert!(
        !stderr.contains("special file"),
        "an ordinary tree must produce no special-file report at all:\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn a_scoped_sweep_reclaims_the_debris_under_the_path_it_was_given_and_no_other() {
    // `photos` is not the parent of `photos-backup`, and this command deletes
    // what it is handed. A backend matches a prefix the way a provider does —
    // by bytes — so the sweep applies the same whole-component containment the
    // object listing does, or `cleanup remote:photos` reclaims out of a
    // directory nobody named.
    let sandbox = Sandbox::new();
    let store = sandbox.dir("store");
    let named = plant_staging_file(&store.join("photos"), b"asked for");
    let neighbour = plant_staging_file(&store.join("photos-backup"), b"not asked for");

    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", store.display()))
        .assert()
        .success();
    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("cleanup")
        .arg(format!("{PLAIN_REMOTE}:photos"))
        .args(["--class", "staging", "--min-age", "0s"])
        .assert()
        .success();

    assert!(
        !named.exists(),
        "the debris that was asked for is still there"
    );
    assert!(
        neighbour.exists(),
        "a neighbouring directory was swept because its name starts the same way"
    );
}

// ── verify: what an `ok` proved, and where a machine can read it ─────────────

#[test]
fn a_verify_over_a_plain_remote_publishes_what_its_ok_actually_proved() {
    // The measurement behind this test: an 8 MiB object on a plain `local:`
    // remote was truncated to zero bytes on disk, and `dctl verify` printed
    // `ok`, exited 0, and emitted
    // `{"status":"ok", "verified":1, "failed":0, "verify_mode":"strict"}`
    // with nothing anywhere in the document saying that a plain remote records
    // no hash of its own and that the pass was therefore a retrievability check
    // rather than a statement about the bytes.
    //
    // `scrub` has carried exactly that distinction since it was written — its
    // report has an `assurance` field, its grade line names it, and
    // `a_grade_always_says_what_the_reading_could_prove` pins it. `verify`
    // computes the same value at the same point in `run` and spends it on a
    // stderr warning, which a redirected stdout and a cron job both discard. Two
    // sibling commands, one shared truth, and only one of them telling it.
    //
    // The assertion is on the document a monitor parses, because that is the
    // consumer that cannot see the warning.
    const PAYLOAD: &[u8] = b"bytes a plain remote keeps no hash of";

    let sandbox = Sandbox::new();
    sandbox.write("src/a.txt", PAYLOAD);
    let root = sandbox.dir("store");

    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", root.display()))
        .assert()
        .success();
    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .success();

    let report = json(
        &sandbox
            .dctl()
            .arg("--no-ask-password")
            .args(["--format", "json", "verify"])
            // Both limits have to be asked for by name now, because a remote
            // that records no digest cannot detect rot and one whose listing is
            // its only record cannot detect a loss — and `verify` refuses both
            // by default. This test is about what the document says once the
            // operator has accepted them.
            .arg("--allow-read-back")
            .arg("--allow-listing-as-inventory")
            .arg(format!("{PLAIN_REMOTE}:"))
            .assert()
            .success()
            .get_output()
            .stdout,
    );

    assert_eq!(report["summary"]["verified"], 1, "the run did examine it");
    assert_eq!(
        report["assurance"], "read-back",
        "a verify of a plain remote must publish that its `ok` is a \
         retrievability claim, not a statement about the bytes; got: {report}"
    );
    assert_eq!(
        report["inventory"], "self-reported",
        "and that the object list is the remote's own, so `verified: 1` is a \
         count of what the remote still admits to holding rather than of a \
         dataset; got: {report}"
    );
}

#[test]
fn a_verify_over_a_vault_publishes_the_stronger_claim_it_can_make() {
    // The other half, and the reason one field is enough: the two remotes must
    // not produce the same document. A vault authenticates every chunk against a
    // key and compares the object's own recorded content hash, so its `ok` means
    // *these are the bytes that were written* — and a consumer that cannot tell
    // the two apart has to treat both as the weaker one, which throws away the
    // guarantee the vault exists to provide.
    let sandbox = a_sealed_vault_with_content();

    let report = json(
        &sandbox
            .dctl()
            .env("DCTL_PASSWORD", GOOD_PASSWORD)
            .args(["--format", "json", "verify"])
            .arg(format!("{VAULT_NAME}:"))
            .assert()
            .success()
            .get_output()
            .stdout,
    );

    assert_eq!(
        report["assurance"], "authenticated",
        "a verify of a vault must publish the stronger claim it really made; got: {report}"
    );
}

#[test]
fn a_verify_says_what_it_covered_and_what_that_proved_without_being_asked() {
    // `verify`'s only text output was a table of rows: no count, no byte figure,
    // and no statement of what the rows proved. The assurance reached the
    // operator through one warning that fires only when the remote *cannot*
    // detect corruption, so a vault's verify never said what it had proved
    // either, and neither run left a sentence a ticket or a monitor could carry.
    //
    // The line goes to stderr, not stdout: stdout carries either the table or a
    // JSON document, and a prose sentence appended to the latter would corrupt
    // it. That is where `scrub` puts its coverage, for the same reason and with
    // the same argument (`a_scrub_says_what_it_covered_without_being_asked_to`).
    const PAYLOAD: &[u8] = b"a plain object";

    let sandbox = Sandbox::new();
    sandbox.write("src/a.txt", PAYLOAD);
    let root = sandbox.dir("store");
    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", root.display()))
        .assert()
        .success();
    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .success();

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("verify")
        // See the sibling test: both weaker claims are opt-in now.
        .arg("--allow-read-back")
        .arg("--allow-listing-as-inventory")
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .success()
        // How much was covered, what covering it proved, and where the list of
        // things to cover came from.
        .stderr(predicates::str::contains("1 object examined"))
        .stderr(predicates::str::contains("read-back"))
        .stderr(predicates::str::contains("self-reported"));
}

/// A plain `local:` remote holding one object, and the object's path on disk so
/// a test can reach past DCTL and damage what the provider is holding.
fn a_plain_remote_holding_one_object(payload: &[u8]) -> (Sandbox, std::path::PathBuf) {
    let sandbox = Sandbox::new();
    sandbox.write("src/a.txt", payload);
    let root = sandbox.dir("store");
    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", root.display()))
        .assert()
        .success();
    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .success();
    let stored = root.join("a.txt");
    (sandbox, stored)
}

#[test]
fn a_verify_of_a_remote_that_cannot_detect_rot_refuses_rather_than_reporting_ok() {
    // The defect, measured on the shipped binary before this existed: one byte
    // flipped in place on a plain `local:` remote produced `ok` in the table,
    // `"failed": 0` in the JSON and **exit 0**. An operator running this nightly
    // was being told nothing while believing they were being told everything.
    //
    // The refusal is what closes it, and it must come with the flag that accepts
    // the weaker check — otherwise the operator's only route back to a green
    // cron job is `|| true`.
    let (sandbox, stored) = a_plain_remote_holding_one_object(b"bytes that will be changed");

    let mut bytes = std::fs::read(&stored).expect("the stored object is readable");
    bytes[3] ^= 0xFF;
    std::fs::write(&stored, &bytes).expect("the stored object is rewritten");

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("verify")
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .code(27)
        .stderr(predicates::str::contains(PLAIN_REMOTE))
        .stderr(predicates::str::contains("--allow-read-back"));
}

#[test]
fn a_scrub_of_a_remote_that_cannot_detect_rot_refuses_rather_than_grading_it_healthy() {
    // The same defect one command over. `scrub` and `verify` share their
    // verdicts, their exit codes and their wording, and a claim only one of them
    // enforced would be a claim nobody could rely on.
    let (sandbox, _stored) = a_plain_remote_holding_one_object(b"bytes nothing here records");

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("scrub")
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .code(27)
        .stderr(predicates::str::contains("--allow-read-back"));
}

/// A plain `local:` remote holding three named objects, and the store root so a
/// test can reach past DCTL and take one away.
///
/// Three rather than one, deliberately: with one object a run that lost it
/// examines nothing and already fails with exit 9, which would pass a test of
/// this defect while proving nothing. The defect is a run that examines the
/// **survivors**, reports them all `ok` and exits 0.
fn a_plain_remote_holding_three_objects() -> (Sandbox, std::path::PathBuf) {
    let sandbox = Sandbox::new();
    sandbox.write("src/a.bin", b"the first object");
    sandbox.write("src/b.bin", b"the second object, which will be taken away");
    sandbox.write("src/c.bin", b"the third object");
    let root = sandbox.dir("store");
    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", root.display()))
        .assert()
        .success();
    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .success();
    (sandbox, root)
}

#[test]
fn a_verify_of_a_remote_that_lost_an_object_refuses_rather_than_reporting_ok() {
    // The defect, measured on the shipped binary before this existed, under the
    // flag whose own `--help` said this was exactly what it caught: three
    // objects stored, one deleted outright from the store, and the run printed
    // `OK  2 objects examined` and exited **0**.
    //
    // The cause is that both sides of the comparison were the same source. A
    // plain remote records nothing about what it should hold, so `verify`
    // enumerates the remote and then checks the keys the remote just reported —
    // and a deleted object is not missing from that list, it is absent from it.
    let (sandbox, root) = a_plain_remote_holding_three_objects();
    let gone = root.join("b.bin");
    std::fs::remove_file(&gone).expect("the object is removed from the store");
    assert!(!gone.exists(), "the damage must have landed");

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("verify")
        .arg("--allow-read-back")
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .code(27)
        .stderr(predicates::str::contains(PLAIN_REMOTE))
        .stderr(predicates::str::contains("--allow-listing-as-inventory"));
}

#[test]
fn a_scrub_of_a_remote_that_lost_an_object_refuses_rather_than_grading_it_healthy() {
    // The same defect one command over, and the command an operator actually
    // schedules to notice a replica losing objects. `scrub` and `verify` share
    // one gate; a claim only one of them enforced would be a claim nobody could
    // rely on.
    let (sandbox, root) = a_plain_remote_holding_three_objects();
    std::fs::remove_file(root.join("b.bin")).expect("the object is removed from the store");

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("scrub")
        .arg("--allow-read-back")
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .code(27)
        .stderr(predicates::str::contains("--allow-listing-as-inventory"));
}

#[test]
fn an_undamaged_plain_remote_still_passes_with_both_limits_accepted() {
    // The self-test the two above are worthless without: the same command over
    // an undamaged store, with both limits accepted by name, has to exit 0. A
    // gate that refused everything would pass both of them and would have made
    // the command useless.
    let (sandbox, _root) = a_plain_remote_holding_three_objects();

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("verify")
        .arg("--allow-read-back")
        .arg("--allow-listing-as-inventory")
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .success()
        .stderr(predicates::str::contains("3 objects examined"));
}

#[test]
fn the_read_backs_help_no_longer_promises_to_catch_a_lost_object() {
    // The defect in the place the operator meets it, asserted against the text
    // the shipped binary actually prints rather than against a doc comment. The
    // flag's help said the read-back "is how a replica quietly losing objects is
    // caught"; measured, that is the one damage it does not catch.
    let sandbox = Sandbox::new();
    for command in ["verify", "scrub"] {
        let help = String::from_utf8(
            sandbox
                .dctl()
                .arg(command)
                .arg("--help")
                .assert()
                .success()
                .get_output()
                .stdout
                .clone(),
        )
        .expect("help is utf-8");
        assert!(
            !help.contains("losing objects is caught"),
            "`dctl {command} --help` still claims the read-back catches a lost \
             object:\n{help}"
        );
        assert!(
            help.contains("--allow-listing-as-inventory"),
            "`dctl {command} --help` must offer the flag its refusal names:\n{help}"
        );
    }
}

#[test]
fn the_refusal_is_reached_before_anything_is_read() {
    // A remote that cannot be certified must cost nothing to find out about,
    // rather than an hour of egress followed by a caveat. The object is removed
    // from under the store first: if the run reached the walk it would report a
    // missing object (exit 4) instead of the refusal.
    let (sandbox, stored) = a_plain_remote_holding_one_object(b"about to disappear");
    std::fs::remove_file(&stored).expect("the object is removed");

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("verify")
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .code(27);
}

#[test]
fn accepting_the_weaker_check_still_says_what_it_did_and_did_not_prove() {
    // The flag is a concession, not an off switch: the run goes green and the
    // report still carries the claim it can support, so an `ok` here can never
    // be read as an `ok` over a vault.
    let (sandbox, _stored) = a_plain_remote_holding_one_object(b"retrievable, and that is all");

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("verify")
        .arg("--allow-read-back")
        .arg("--allow-listing-as-inventory")
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .success()
        .stderr(predicates::str::contains("read-back"))
        .stderr(predicates::str::contains("not that it is unchanged"))
        // And the second concession says its own sentence rather than being
        // folded into the first: they are different limits with different
        // remedies, and an operator who set one flag has not agreed to the
        // other.
        .stderr(predicates::str::contains(
            "keeps no record of what it should hold",
        ))
        .stderr(predicates::str::contains("is simply not listed"));
}

#[test]
fn a_coverage_line_about_damage_does_not_wear_a_success_mark() {
    // `Out::success` prefixes its line with a check glyph (`SUCCESS_MARK`, or
    // `OK` where ANSI is off). A coverage sentence that ends "1 of them did not
    // verify" carrying one would be the same misreport as an unqualified `ok`,
    // one line further down — so the emitter follows the verdict.
    //
    // Asserted through the shipped binary and on the real stream, because the
    // mark is added by the sink and a unit test of the report cannot see it.
    let sandbox = a_sealed_vault_with_content();

    // Damage every stored object, so the run cannot end clean.
    let store = sandbox.path("vault").join("o");
    for entry in std::fs::read_dir(&store).expect("the object directory exists") {
        let path = entry.expect("a readable entry").path();
        if path.is_file() {
            let mut bytes = std::fs::read(&path).expect("the object reads");
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
            std::fs::write(&path, &bytes).expect("the object writes back");
        }
    }

    let output = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .arg("verify")
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        // IntegrityFailure (21): the damage is what the run is for.
        .code(21)
        .get_output()
        .stderr
        .clone();
    let text = String::from_utf8_lossy(&output);

    let coverage = text
        .lines()
        .find(|line| line.contains("objects examined"))
        .unwrap_or_else(|| panic!("no coverage line on stderr:\n{text}"));
    assert!(
        coverage.contains("did not verify"),
        "the coverage line must say how many failed; got: {coverage}"
    );
    assert!(
        !coverage.contains("OK") && !coverage.contains('\u{2713}'),
        "a line about damage is wearing a success mark: {coverage}"
    );
}

// ── rcat: the directory it was asked to write into ──────────────────────────

#[test]
fn rcat_creates_the_directory_it_was_asked_to_write_into() {
    // Measured: `printf x | dctl rcat pl:2026-07-30/db.sql` exits 4 with
    // `.../2026-07-30/.dctl-staging.NNN.0: No such file or directory`, while
    // `dctl copyto file pl:2026-07-30/db.sql` — the same destination, the same
    // backend, the same staging rule — succeeds and creates the tree. Two
    // spellings of "write this stream to here", and only one of them makes the
    // directory.
    //
    // `Staging::create` in `commands::rcat::local` reaches straight for
    // `File::create` on the staging sibling; every other verified write in the
    // workspace calls `create_dir_all` on the parent first
    // (`dctl_store::local::verified_write`, three separate entry points). The
    // shape that meets it is the ordinary one: a nightly dump piped into a
    // dated directory, which fails on the first night of every month.
    const PAYLOAD: &[u8] = b"a stream bound for a directory that is not there yet";

    let sandbox = Sandbox::new();

    // The comparison first, so the test pins an asymmetry rather than a guess:
    // `copyto` into exactly this shape already works.
    sandbox.write("src.bin", PAYLOAD);
    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("copyto")
        .arg(sandbox.path("src.bin"))
        .arg(sandbox.path("by-copyto/2026-07-30/db.sql"))
        .assert()
        .success();
    assert_eq!(sandbox.read("by-copyto/2026-07-30/db.sql"), PAYLOAD);

    // ...and now the same destination shape through `rcat`.
    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("rcat")
        .arg(sandbox.path("by-rcat/2026-07-30/db.sql"))
        .write_stdin(PAYLOAD)
        .assert()
        .success();
    assert_eq!(sandbox.read("by-rcat/2026-07-30/db.sql"), PAYLOAD);
}

#[test]
fn rcat_creates_the_directory_under_a_plain_remote_too() {
    // The same defect reached through a configured `local:` remote, which is how
    // an operator addresses a backup target. Separate from the bare-path case
    // because the two go through different resolvers to reach one writer, and a
    // fix that only covered one would leave the other exactly as broken.
    const PAYLOAD: &[u8] = b"piped into a dated directory on a plain remote";

    let sandbox = Sandbox::new();
    let root = sandbox.dir("store");
    sandbox
        .dctl()
        .args(["config", "create", PLAIN_REMOTE, "local"])
        .arg(format!("path={}", root.display()))
        .assert()
        .success();

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("rcat")
        .arg(format!("{PLAIN_REMOTE}:2026-07-30/db.sql"))
        .write_stdin(PAYLOAD)
        .assert()
        .success();

    assert_eq!(sandbox.read("store/2026-07-30/db.sql"), PAYLOAD);
}
