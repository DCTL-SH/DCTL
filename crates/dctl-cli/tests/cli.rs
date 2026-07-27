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

#[test]
fn a_second_copy_into_a_plain_remote_re_transfers_and_size_only_is_the_way_out() {
    // A limitation, pinned deliberately rather than discovered on a bill.
    //
    // `Backend::put` stores bytes under a key and carries no modification time —
    // there is no parameter for one, and for a bucket there could not be: B2, S3
    // and R2 stamp `Last-Modified` themselves. So a plain destination reports the
    // time it was *written*, exactly as a sealed vault reports the time it was
    // sealed (defect D5), and the default size-and-time comparison finds every
    // file different on the next run.
    //
    // For a vault, `crate::fidelity` substitutes a content comparison, because
    // the index recorded a plaintext BLAKE3 at write time. A plain remote has no
    // such record: a store holds the object and nothing about it, and a bucket's
    // own checksum is SHA-1 or an ETag rather than a BLAKE3 of the plaintext. So
    // there is nothing to substitute, and the honest behaviour is the one
    // asserted here — re-transfer — with `--size-only` as the comparison that
    // needs no clock.
    //
    // Assert both halves, because the first alone would pass on a tool that
    // simply never skipped anything.
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

    for _ in 0..2 {
        sandbox
            .dctl()
            .arg("--no-ask-password")
            .arg("copy")
            .arg(sandbox.path("src"))
            .arg(format!("{PLAIN_REMOTE}:"))
            .assert()
            .success()
            .stderr(predicates::str::contains("Files: 3 / 3"));
    }

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .arg("--size-only")
        .arg("copy")
        .arg(sandbox.path("src"))
        .arg(format!("{PLAIN_REMOTE}:"))
        .assert()
        .success()
        .stderr(predicates::str::contains("Files: 0 / 0"));
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
fn a_rebuilt_index_reports_sizes_as_unknown_rather_than_as_zero() {
    // Defect D3. `index rebuild` is a list-only pass, so its rows carry no
    // size — and every reader downstream rendered that absence as the number
    // 0. A capacity monitor reading `--json size` after a disaster-recovery
    // rebuild was told a 40 TB vault held nothing.
    let sandbox = a_sealed_vault_with_content();

    sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .args(["index", "rebuild"])
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();

    // `ls` must not print a byte count it does not have.
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
    assert_eq!(listed.lines().count(), 3);
    assert!(
        listed
            .lines()
            .all(|line| line.split_whitespace().next() == Some(UNKNOWN_SIZE)),
        "every unmeasured row's size column must read as unknown:\n{listed}"
    );

    // `size` must not report a total it could not compute.
    let sized = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .args(["--json", "size"])
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();
    let totals = json(&sized.get_output().stdout);
    assert_eq!(totals["count"], 3);
    assert!(
        totals["bytes"].is_null(),
        "a total over unmeasured rows is not a number: {totals}"
    );
    assert_eq!(totals["unmeasured"], 3);
    assert_eq!(totals["measured_bytes"], 0);

    // And the same absence has to reach the audit trail a scrub writes.
    let scrubbed = sandbox
        .dctl()
        .env("DCTL_PASSWORD", GOOD_PASSWORD)
        .args(["--json", "scrub"])
        .arg(format!("{VAULT_NAME}:"))
        .assert()
        .success();
    let report = json(&scrubbed.get_output().stdout);
    assert_eq!(report["coverage"]["scanned"], 3);
    assert_eq!(report["coverage"]["unmeasured"], 3);
    assert!(
        report["coverage"]["bytes"].is_null(),
        "a scrub that cannot total its bytes must not publish a zero: {report}"
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
    let phrase = vault_with_a_file_and_its_phrase(&sandbox, b"x");

    let mut words: Vec<&str> = phrase.split_whitespace().collect();
    words[0] = "zoo";
    let mangled = words.join(" ");

    sandbox
        .dctl()
        .arg("--no-ask-password")
        .args(["--recovery-phrase", &mangled])
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
