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
//! ## Deliberately not covered
//!
//! There is no end-to-end vault upload or download. Reaching
//! `Direction::Upload`/`Download` needs a `RemoteSpec::Named` destination, and
//! in this build `crate::session::open` resolves one against the *empty* catalog
//! — so a remote defined in `--config` is rejected as unknown, and the only
//! names that do resolve (`b2:`, `s3:`, `r2:`) need real cloud credentials.
//! Enumerating a named remote is unimplemented besides. Those paths are covered
//! by the engine's own unit tests until the CLI can address a local vault by
//! name; asserting on them here would mean asserting on a shape the binary
//! cannot currently reach.
//!
//! What *is* asserted end-to-end is the refusal
//! ([`copy_to_a_provider_shorthand_never_lands_in_a_directory_of_that_name`]):
//! a named remote must never quietly become a local directory, because that
//! failure looked exactly like a successful backup.

use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

use assert_cmd::Command;
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
        // FatalError (7): with no B2 credentials exported the bucket cannot be
        // reached, and saying so is the only honest answer available.
        .code(7)
        .stderr(predicates::str::contains("DCTL_B2_KEY_ID"));

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
