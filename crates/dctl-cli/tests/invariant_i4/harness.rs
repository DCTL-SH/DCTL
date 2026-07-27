//! The sandbox every I4 test runs in, and the assertions they share.
//!
//! Three things live here, and each is shared because writing it twice is how
//! two tests come to disagree about what "no plaintext escaped" means:
//!
//! 1. A [`Sandbox`] — an isolated directory, an isolated configuration and an
//!    isolated index, with the inherited `DCTL_*` environment stripped so a
//!    maintainer's shell cannot change a result.
//! 2. The **matrix**: [`FLAG_SETS`] × [`Verb::ALL`]. I4 is a claim about *every*
//!    flag and *every* write verb, so the claim is only as good as the matrix.
//! 3. The **filesystem assertions**, which are the only kind this suite makes.

#![allow(dead_code)] // Each test module uses a different part of the harness.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use tempfile::TempDir;

/// Environment that would silently redirect a run away from its sandbox.
///
/// `--config` and `--index` are always passed explicitly, so these could only
/// take effect by accident — which is exactly the accident worth removing. A
/// maintainer with `DCTL_PASSWORD` exported must not see a different result from
/// CI, and one with real B2 keys must not have a test attempt an upload into
/// somebody's bucket.
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

/// The bytes every test follows through the filesystem.
///
/// Long and unmistakable on purpose: the assertions scan whole files for it, and
/// a short marker would match by coincidence inside a key, a hash or a length
/// field and turn a passing suite into a failing one for no reason.
pub const MARKER: &[u8] = b"I4-PLAINTEXT-MARKER-THAT-MUST-NEVER-BE-MISPLACED";

/// Long enough for `constants::MIN_VAULT_PASSWORD_LEN`.
///
/// Supplied to *every* invocation, not only to `init`. The point of the suite is
/// that DCTL declines to seal a bare-path write even when it is fully able to:
/// with the password withheld, "nothing was sealed" would prove only that a
/// locked vault stays locked.
pub const PASSWORD: &str = "correct horse battery staple";

/// The sealed view `dctl init` registers. Everything through it is encrypted.
pub const VAULT_REMOTE: &str = "archive";

/// The object view of the same vault: opaque ciphertext, no password needed.
pub const STORE_REMOTE: &str = "archive-store";

/// The one file every vault has and no ordinary directory has by accident.
///
/// Mirrors `constants::VAULT_ENVELOPE_OBJECT_KEY`, spelled out here so the tests
/// pin the on-disk layout rather than following the code that produced it.
pub const ENVELOPE: &str = "system/envelope.bin";

/// Magic at the head of a sealed DCTL object (`docs/FORMAT.md` §3).
///
/// Written out rather than imported for the same reason as [`ENVELOPE`]: this is
/// the *frozen format*, and a test that read the constant would keep passing if
/// the constant changed. A file starting with these four bytes at a destination
/// that was asked for plaintext is invariant I4 broken in the sealed direction.
pub const SEALED_OBJECT_MAGIC: &[u8] = b"DSF1";

/// Flag combinations crossed with every write verb.
///
/// I4 says no flag changes what a command encrypts, so a single invocation
/// proves nothing and this list *is* the claim. The entries are chosen because
/// each is a plausible reason someone might expect different behaviour:
///
/// * `--force`, `--interactive` — the safety dials, and the first thing reached
///   for when a command refuses.
/// * `--dry-run` — the rehearsal. It must reach the *same* decision as the real
///   run, or approving a plan means nothing.
/// * `--checksum`, `--size-only`, `--immutable` — the comparison and replacement
///   policy, which decides *whether* a file is written.
/// * `--verify strict`, `--verify sample` — the durability dial, the one flag
///   whose name most suggests it might involve the vault.
/// * `--remote archive` — a global that names a **vault remote**. If any input
///   other than the destination could switch a write to sealed, this is it.
/// * `--transfers`/`--checkers`, `--bwlimit` — concurrency and pacing, where a
///   race would show up as an intermittent wrong answer.
/// * `--json`, `--progress`, `-vv` — output shape, which must never be load
///   bearing.
/// * `--no-ask-password` — the headless path, where a prompt cannot be used to
///   ask the operator anything.
/// * the last entry — several at once, because guards are usually defeated by
///   combinations rather than by single flags.
///
/// `--include`/`--exclude`/`--files-from` are deliberately absent. Filtering
/// selects *which files* a command considers; it cannot change the destination's
/// address, which is the only input I4 is about — so a filtered row asks the
/// same question as an unfiltered one with fewer files. (When this suite was
/// written they were also refused outright as unimplemented, which would have
/// made those rows pass without exercising anything at all.)
pub const FLAG_SETS: &[&[&str]] = &[
    &[],
    &["--force"],
    &["--interactive"],
    &["--dry-run"],
    &["--checksum"],
    &["--size-only"],
    &["--immutable"],
    &["--verify", "strict"],
    &["--verify", "sample", "--verify-samples", "4"],
    &["--remote", VAULT_REMOTE],
    &["--transfers", "8", "--checkers", "8"],
    &["--bwlimit", "1M"],
    &["--json"],
    &["--progress", "--stats-one-line"],
    &["-vv"],
    &["--no-ask-password"],
    &[
        "--force",
        "--checksum",
        "--verify",
        "strict",
        "--remote",
        VAULT_REMOTE,
        "--transfers",
        "4",
        "--immutable",
    ],
];

/// Every command that can put bytes at a destination.
///
/// Enumerated as a type rather than left to each test to spell, because the
/// failure this suite exists to catch is *one* write path missing the rule. That
/// has happened: the guard lived inside the transfer engine, `dctl rcat` reached
/// the filesystem by another route, and plaintext streamed into a vault
/// directory and exited 0. A verb added to the CLI and not to [`Verb::ALL`] is
/// the same defect, so the two lists are meant to be reviewed together.
#[derive(Clone, Copy, Debug)]
pub enum Verb {
    Copy,
    Move,
    Sync,
    Copyto,
    Moveto,
    Rcat,
}

impl Verb {
    /// Every write verb the CLI exposes.
    pub const ALL: &'static [Self] = &[
        Self::Copy,
        Self::Move,
        Self::Sync,
        Self::Copyto,
        Self::Moveto,
        Self::Rcat,
    ];

    /// The subcommand as typed.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Copy => "copy",
            Self::Move => "move",
            Self::Sync => "sync",
            Self::Copyto => "copyto",
            Self::Moveto => "moveto",
            Self::Rcat => "rcat",
        }
    }

    /// The arguments after the subcommand, for a source tree and a destination.
    ///
    /// `source_dir` holds one file called `marker.txt`; the directory verbs are
    /// given the directory and the exact-name verbs are given the file, because
    /// that is what each verb means. `rcat` takes no source at all: its payload
    /// is [`Verb::stdin`].
    pub fn args(self, source_dir: &str, dest: &str) -> Vec<String> {
        let source_file = format!("{source_dir}/{}", MARKER_FILE);
        match self {
            Self::Copy | Self::Move | Self::Sync => {
                vec![source_dir.to_string(), dest.to_string()]
            }
            Self::Copyto | Self::Moveto => vec![source_file, self.landing(dest)],
            Self::Rcat => vec![self.landing(dest)],
        }
    }

    /// The bytes to feed the command's standard input.
    pub const fn stdin(self) -> &'static [u8] {
        match self {
            Self::Rcat => MARKER,
            _ => b"",
        }
    }

    /// Where the marker lands at `dest` if the write happens.
    ///
    /// A directory verb reproduces the source's own filename inside `dest`; an
    /// exact-name verb writes the name it was given. Both are spelled here so a
    /// test can allow exactly one path and treat the marker anywhere else in the
    /// sandbox as an escape.
    pub fn landing(self, dest: &str) -> String {
        match self {
            Self::Copy | Self::Move | Self::Sync => child(dest, MARKER_FILE),
            Self::Copyto | Self::Moveto => child(dest, "exact-name.txt"),
            Self::Rcat => child(dest, "piped.txt"),
        }
    }

    /// Whether this verb removes its source on success.
    ///
    /// The matrix re-creates the source before every invocation, so a verb that
    /// consumed it does not silently turn the next row into a no-op that passes.
    pub const fn consumes_the_source(self) -> bool {
        matches!(self, Self::Move | Self::Moveto)
    }
}

/// The file the marker is written to inside a source tree.
pub const MARKER_FILE: &str = "marker.txt";

/// `dest/name`, for a destination that may be a path or a remote spec.
///
/// `archive:` and `./out` compose differently — `archive:one.txt` has no
/// separator and `./out/one.txt` does — and getting that wrong would silently
/// address a *different* place, which is the class of bug the whole addressing
/// model exists to remove.
pub fn child(dest: &str, name: &str) -> String {
    if dest.ends_with(':') || dest.is_empty() {
        format!("{dest}{name}")
    } else {
        format!("{dest}/{name}")
    }
}

/// One process's observable behaviour.
#[derive(Debug)]
pub struct Outcome {
    /// Process exit status. `None` only if it was killed by a signal.
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

impl Outcome {
    /// The lines DCTL addressed to the operator: the failure and its remedy.
    ///
    /// The `tracing` sink also writes the error to stderr with a timestamp, and
    /// a timestamp differs between two runs by definition — so comparing raw
    /// stderr could never establish "identical behaviour". These lines carry the
    /// whole user-visible contract and nothing that varies with the clock.
    pub fn messages(&self) -> Vec<&str> {
        self.stderr
            .lines()
            .filter(|line| line.starts_with("error:") || line.starts_with("warning:"))
            .collect()
    }

    /// Stderr with the timestamped `tracing` lines removed.
    ///
    /// Every other line — the summary block, the messages, an `OK` — starts with
    /// a space or a letter, so dropping lines that begin with a digit removes
    /// exactly the clock-dependent ones and keeps the rest for comparison.
    pub fn stderr_without_timestamps(&self) -> Vec<&str> {
        self.stderr
            .lines()
            .filter(|line| !line.starts_with(|c: char| c.is_ascii_digit()))
            .collect()
    }

    /// Whether any message DCTL addressed to the operator contains `needle`.
    pub fn said(&self, needle: &str) -> bool {
        self.messages().iter().any(|line| line.contains(needle))
    }

    /// Everything printed, for a failure message worth reading.
    pub fn transcript(&self) -> String {
        format!(
            "exit {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.code,
            String::from_utf8_lossy(&self.stdout),
            self.stderr
        )
    }
}

/// An isolated working area for one test.
pub struct Sandbox {
    root: TempDir,
}

impl Sandbox {
    pub fn new() -> Self {
        Self {
            root: TempDir::new().expect("a temporary directory"),
        }
    }

    /// The sandbox root, resolved.
    ///
    /// Resolved because on macOS a temporary directory is reached through
    /// `/var` → `/private/var`, and a test that compared a path DCTL reported
    /// against an unresolved one would fail for a reason that has nothing to do
    /// with what it is testing.
    pub fn root(&self) -> PathBuf {
        self.root
            .path()
            .canonicalize()
            .expect("the sandbox root resolves")
    }

    /// An absolute path inside the sandbox. Nothing is created.
    pub fn path(&self, relative: &str) -> PathBuf {
        self.root().join(relative)
    }

    /// Create a directory and its parents.
    pub fn dir(&self, relative: &str) -> PathBuf {
        let path = self.path(relative);
        std::fs::create_dir_all(&path).expect("create directory");
        path
    }

    /// Write a file, creating parent directories.
    pub fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = self.path(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent directory");
        }
        std::fs::write(&path, bytes).expect("write file");
        path
    }

    pub fn exists(&self, relative: &str) -> bool {
        self.path(relative).exists()
    }

    pub fn read(&self, relative: &str) -> Vec<u8> {
        std::fs::read(self.path(relative)).expect("read file")
    }

    /// A source tree holding exactly one file, whose contents are [`MARKER`].
    ///
    /// Re-created before every row of the matrix, because `move` and `moveto`
    /// consume it and a missing source turns the next row into a no-op that
    /// passes without testing anything.
    pub fn fresh_source(&self, relative: &str) -> String {
        let _ = std::fs::remove_dir_all(self.path(relative));
        self.write(&format!("{relative}/{MARKER_FILE}"), MARKER);
        relative.to_string()
    }

    /// A `dctl` invocation wired to this sandbox.
    ///
    /// `--config` and `--index` are supplied on every call, even to commands
    /// that need neither: the point is that no run can fall back to the
    /// platform's real configuration or data directory, and leaving them off
    /// "because this command does not need them" is how one eventually does.
    pub fn dctl(&self) -> Command {
        self.dctl_using("dctl.toml", "index.redb")
    }

    /// A `dctl` invocation wired to a *different* configuration and index inside
    /// the same sandbox.
    ///
    /// Needed by exactly one fixture and worth a method rather than a
    /// hand-rolled `Command`: a vault created against a configuration the tests
    /// never read is how a real "my config.toml is gone" recovery looks, and
    /// building that by hand would drop the environment scrubbing that keeps a
    /// maintainer's shell out of the result.
    pub fn dctl_using(&self, config: &str, index: &str) -> Command {
        let mut cmd = Command::cargo_bin("dctl").expect("the dctl binary is built");
        for key in INHERITED_ENV {
            cmd.env_remove(key);
        }
        cmd.current_dir(self.root.path())
            .env("DCTL_PASSWORD", PASSWORD)
            .arg("--config")
            .arg(self.path(config))
            .arg("--index")
            .arg(self.path(index))
            // Styling would otherwise depend on whether a terminal is attached,
            // and every message assertion would become flaky under a different
            // test runner.
            .arg("--color")
            .arg("never");
        cmd
    }

    /// Run one invocation: global flags, then a subcommand and its arguments.
    pub fn run(&self, flags: &[&str], verb: &str, args: &[String], stdin: &[u8]) -> Outcome {
        let output = self
            .dctl()
            .args(flags)
            .arg(verb)
            .args(args)
            .write_stdin(stdin.to_vec())
            .output()
            .expect("the dctl binary runs");

        Outcome {
            code: output.status.code(),
            stdout: output.stdout,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    /// Create a real vault at `base` and register both of its remotes.
    ///
    /// A real one, with a real Argon2id-wrapped envelope, rather than a
    /// hand-written config and a file of nonsense: the tests below assert that a
    /// vault's presence changes nothing, and that claim is only worth making
    /// about a vault the tool itself would recognise, unlock and use.
    pub fn init_vault(&self, name: &str, base: &str) {
        self.dir(base);
        self.dctl()
            .arg("init")
            .args(["--name", name, "--base"])
            .arg(self.path(base))
            .assert()
            .success();
        assert!(
            self.exists(&format!("{base}/{ENVELOPE}")),
            "init must leave a real envelope behind, or this sandbox proves nothing"
        );
    }
}

/// Every regular file under `root`, recursively.
pub fn all_files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let Ok(children) = std::fs::read_dir(&directory) else {
            continue;
        };
        for child in children.flatten() {
            let path = child.path();
            // `symlink_metadata`, so a link into a directory already on the
            // stack cannot make this walk recurse forever.
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// Whether `haystack` contains `needle` as a contiguous byte run.
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Assert the marker appears nowhere in the sandbox except at `allowed`.
///
/// The whole sandbox rather than the destination, because the interesting
/// failures put the bytes somewhere nobody looked: a directory literally named
/// `archive:`, a staging file left behind by an aborted write, a temporary copy
/// beside the index. An allow-list makes the assertion say what it means — these
/// paths may hold the plaintext, and the existence of it anywhere else is the
/// bug.
pub fn assert_marker_confined(sandbox: &Sandbox, allowed: &[String], context: &str) {
    let permitted: Vec<PathBuf> = allowed.iter().map(|path| sandbox.path(path)).collect();
    let strays: Vec<PathBuf> = all_files(&sandbox.root())
        .into_iter()
        .filter(|file| !permitted.contains(file))
        .filter(|file| std::fs::read(file).is_ok_and(|bytes| contains(&bytes, MARKER)))
        .collect();

    assert!(
        strays.is_empty(),
        "{context}: plaintext escaped to {strays:?} (allowed: {permitted:?})"
    );
}

/// Assert nothing under `root` is a sealed DCTL object.
///
/// The other direction of I4, and the one nobody thinks to check: a guard that
/// helpfully encrypted a write to an ordinary directory would leave the operator
/// with a file their own tools cannot read, produced by a command that never
/// mentioned a vault.
pub fn assert_nothing_sealed_under(root: &Path, context: &str) {
    for file in all_files(root) {
        let Ok(bytes) = std::fs::read(&file) else {
            continue;
        };
        assert!(
            !bytes.starts_with(SEALED_OBJECT_MAGIC),
            "{context}: {} is a sealed object, but this destination was addressed \
             as an ordinary path",
            file.display()
        );
    }
}

/// A label naming the row of the matrix a failure came from.
pub fn row(verb: Verb, flags: &[&str]) -> String {
    format!("dctl {} {}", flags.join(" "), verb.name())
}
