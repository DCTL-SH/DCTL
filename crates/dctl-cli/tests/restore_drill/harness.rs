//! The machine the drill runs on, and the vault it runs against.
//!
//! Everything here exists so the six steps in [`super::drill`] can be written
//! once and run against any backend. A drill that only ever ran against a local
//! directory would prove that DCTL can copy files; the point of the exercise is
//! that the *same* six steps survive a real provider, and the only way to keep
//! them the same is for the backend to be one value the harness carries rather
//! than a branch inside every step.
//!
//! Three things are worth stating about how commands are run.
//!
//! **The binary, never the library.** Every step below spawns the shipped `dctl`
//! and reads its exit status and its two streams. A restore drill asserted
//! against `Vault::get_file` would prove the crypto works and nothing about
//! whether the *command* a person types on recovery day is wired to it — which
//! is precisely the failure this exercise exists to catch.
//!
//! **The inherited environment is scrubbed.** A maintainer with `DCTL_PASSWORD`
//! or `DCTL_INDEX` exported must not get a different result from CI, and one
//! with real provider keys must not have the local drill quietly reach the
//! network. The B2 credentials are the single exception, re-exported by
//! [`Backend::B2`] onto the invocations that need them, because there the
//! network *is* the test.
//!
//! **The recovery phrase is captured from stderr, by parsing the block a human
//! reads.** That is not a shortcut around a missing API: `dctl init` deliberately
//! keeps the words out of stdout and out of `--json`
//! (`crates/dctl-cli/src/commands/init/phrase.rs`), because a phrase in a log
//! file is a vault that is permanently compromised and cannot be rotated. Step 2
//! of the drill is therefore the same explicit act an operator performs —
//! redirecting stderr and reading the grid — and [`Init::phrase`] fails loudly if
//! the block ever stops being parseable, which would mean an operator could no
//! longer transcribe it either.

#![allow(dead_code)] // Each drill module uses a different part of the harness.

use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use tempfile::TempDir;

/// Environment that would silently redirect a run away from its sandbox.
///
/// `--config` and `--index` are passed explicitly on every invocation, so these
/// could only take effect by accident — which is the accident worth removing.
/// The provider credentials are on the list so the local drill cannot reach a
/// maintainer's bucket; [`Backend::B2`] puts back exactly the two it needs.
const INHERITED_ENV: &[&str] = &[
    "DCTL_CONFIG",
    "DCTL_INDEX",
    "DCTL_REMOTE",
    "DCTL_HOME",
    "DCTL_PASSWORD",
    "DCTL_PASSWORD_COMMAND",
    "DCTL_RECOVERY_PHRASE",
    "DCTL_LOG_LEVEL",
    "DCTL_LOG_FORMAT",
    "DCTL_B2_KEY_ID",
    "DCTL_B2_APP_KEY",
    "DCTL_S3_ACCESS_KEY",
    "DCTL_S3_SECRET_KEY",
];

/// The password the vault is created with.
///
/// Long enough for `constants::MIN_VAULT_PASSWORD_LEN`, and deliberately never
/// used again after step 2: the whole claim of step 5 is that the recovery
/// phrase alone opens the vault, and a drill that fell back to the password
/// would prove nothing about the phrase.
pub const PASSWORD: &str = "correct horse battery staple";

/// The sealed remote `dctl init` registers. Everything written through it is
/// encrypted.
pub const VAULT_REMOTE: &str = "drill";

/// Environment variable naming the bucket the B2 drill runs against.
///
/// Separate from the credentials on purpose. Credentials say *whether* the drill
/// can reach B2; this says *where* it is allowed to write, and the drill
/// re-initialises whatever it names. Requiring it to be spelled out is what
/// stops a maintainer who exported keys for something else from discovering that
/// a test suite reformatted a bucket.
pub const B2_BUCKET_ENV: &str = "DCTL_DRILL_B2_BUCKET";

/// Where a vault's ciphertext objects live for one run of the drill.
///
/// The drill is identical for both; only the `--base` spec and the credentials
/// differ. Keeping that difference in one enum is what makes "we ran it twice"
/// a true statement about the same procedure rather than about two procedures
/// that resemble each other.
pub enum Backend {
    /// A directory inside the sandbox. Costs nothing, reaches no network, and
    /// runs in the default test suite.
    Local,
    /// A real Backblaze B2 bucket, named by [`B2_BUCKET_ENV`], with credentials
    /// from the environment.
    ///
    /// The bucket is treated as scratch: the drill re-initialises it, which
    /// makes anything already stored there permanently unreadable. That is why
    /// the bucket has to be named explicitly and is never defaulted.
    B2 {
        bucket: String,
        key_id: String,
        app_key: String,
    },
}

impl Backend {
    /// Read the B2 configuration from the environment, or say what is missing.
    ///
    /// Returns the missing variable names rather than a bare `None` so the
    /// caller can fail with something an operator can act on. "Skipped" is not
    /// an acceptable outcome for a drill somebody explicitly asked to run.
    pub fn from_env() -> Result<Self, Vec<&'static str>> {
        const KEY_ID: &str = "DCTL_B2_KEY_ID";
        const APP_KEY: &str = "DCTL_B2_APP_KEY";

        let mut missing = Vec::new();
        for name in [KEY_ID, APP_KEY, B2_BUCKET_ENV] {
            if std::env::var(name).is_err() {
                missing.push(name);
            }
        }
        if !missing.is_empty() {
            return Err(missing);
        }

        Ok(Self::B2 {
            bucket: std::env::var(B2_BUCKET_ENV).unwrap_or_default(),
            key_id: std::env::var(KEY_ID).unwrap_or_default(),
            app_key: std::env::var(APP_KEY).unwrap_or_default(),
        })
    }

    /// How this backend is named to `dctl init --base`.
    fn base_spec(&self, sandbox: &Sandbox) -> String {
        match self {
            Self::Local => format!("local:{}", sandbox.path("store").display()),
            Self::B2 { bucket, .. } => format!("b2:{bucket}"),
        }
    }

    /// A one-line description for the drill's own transcript.
    pub fn describe(&self) -> String {
        match self {
            Self::Local => "local directory".to_string(),
            Self::B2 { bucket, .. } => format!("b2 bucket '{bucket}'"),
        }
    }

    /// Put back the credentials this backend needs, and nothing else.
    fn apply_credentials(&self, command: &mut Command) {
        if let Self::B2 {
            key_id, app_key, ..
        } = self
        {
            command.env("DCTL_B2_KEY_ID", key_id);
            command.env("DCTL_B2_APP_KEY", app_key);
        }
    }
}

/// One process's observable behaviour.
///
/// Kept whole rather than reduced to a boolean at the call site: when a drill
/// step fails, the transcript is the finding, and a test that asserted
/// `status.success()` would report that a restore failed without saying how.
pub struct Outcome {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Outcome {
    fn new(output: &Output) -> Self {
        Self {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    /// Everything the process printed, for a failure message worth reading.
    pub fn transcript(&self) -> String {
        format!(
            "exit {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.code, self.stdout, self.stderr
        )
    }

    /// Assert the run exited 0, showing the whole transcript if it did not.
    pub fn expect_success(self, step: &str) -> Self {
        assert_eq!(
            self.code,
            Some(0),
            "{step} did not succeed\n{}",
            self.transcript()
        );
        self
    }
}

/// An isolated working area holding one vault, its index, and its trees.
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
    /// `/var` → `/private/var`, and comparing a path DCTL reported against an
    /// unresolved one fails for a reason unrelated to what is being tested.
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

    /// Where the local index database lives.
    ///
    /// Inside its own directory, because **destroying that directory is step 3**
    /// and a machine that is gone did not leave the folder behind.
    pub fn index(&self) -> PathBuf {
        self.path("index/vault.redb")
    }

    /// Where the configuration lives.
    pub fn config(&self) -> PathBuf {
        self.path("config/dctl.toml")
    }

    /// A `dctl` invocation wired to this sandbox, with no secret supplied.
    ///
    /// Secrets are added per step, never here, so the one step that must run on
    /// the recovery phrase alone cannot inherit a password by accident. That is
    /// the difference between proving the phrase works and assuming it.
    pub fn dctl(&self, backend: &Backend) -> Command {
        let mut command = Command::cargo_bin("dctl").expect("the dctl binary is built");
        for key in INHERITED_ENV {
            command.env_remove(key);
        }
        backend.apply_credentials(&mut command);
        command
            .current_dir(self.root.path())
            .arg("--config")
            .arg(self.config())
            .arg("--index")
            .arg(self.index())
            // Styling would otherwise depend on whether a terminal is attached,
            // making every message assertion flaky under a different runner.
            .arg("--color")
            .arg("never");
        command
    }

    /// Run one invocation and capture everything it did.
    pub fn run(&self, backend: &Backend, args: &[&str]) -> Outcome {
        Outcome::new(&self.dctl(backend).args(args).output().expect("dctl runs"))
    }

    /// Run one invocation with the vault password supplied.
    pub fn run_with_password(&self, backend: &Backend, args: &[&str]) -> Outcome {
        Outcome::new(
            &self
                .dctl(backend)
                .env("DCTL_PASSWORD", PASSWORD)
                .args(args)
                .output()
                .expect("dctl runs"),
        )
    }

    /// Run one invocation with the recovery phrase supplied and **no password**.
    ///
    /// `--no-ask-password` is not passed, deliberately. If the phrase were not
    /// being used, the run would fall through to a password prompt, and a test
    /// process has no terminal — so it would fail rather than quietly succeed by
    /// some other route.
    pub fn run_with_phrase(&self, backend: &Backend, phrase: &str, args: &[&str]) -> Outcome {
        Outcome::new(
            &self
                .dctl(backend)
                .env("DCTL_RECOVERY_PHRASE", phrase)
                .args(args)
                .output()
                .expect("dctl runs"),
        )
    }
}

/// What `dctl init` produced, including the one thing it will never print again.
pub struct Init {
    pub outcome: Outcome,
    phrase: String,
}

impl Init {
    /// The 24 words, as they would be written on paper.
    pub fn phrase(&self) -> &str {
        &self.phrase
    }
}

/// Step 2: create the vault and capture the recovery phrase off stderr.
///
/// The `--base` spec is the only thing the backend changes here.
pub fn init(sandbox: &Sandbox, backend: &Backend) -> Init {
    let base = backend.base_spec(sandbox);
    let mut args = vec!["init", "--name", VAULT_REMOTE, "--base", base.as_str()];
    // A scratch bucket may already hold the envelope from a previous drill, and
    // `init` correctly refuses to overwrite a vault. Local runs start empty and
    // must not be given the flag, so a real refusal there would still be caught.
    if matches!(backend, Backend::B2 { .. }) {
        args.push("--force");
    }

    let outcome = sandbox
        .run_with_password(backend, &args)
        .expect_success("step 2: dctl init");
    let phrase = parse_phrase(&outcome.stderr);

    Init { outcome, phrase }
}

/// Read the recovery phrase out of the block `dctl init` writes to stderr.
///
/// Parsed from the numbered grid rather than from any machine-readable field,
/// because there is deliberately no such field: `--json` reports only
/// `recovery_phrase_issued`. The numbering is what makes this safe — a word is
/// only taken when it follows its own index, so a wrapped paragraph or a warning
/// line cannot contribute a word, and a grid that lost or transposed one is
/// caught here rather than months later at the moment it is needed.
fn parse_phrase(stderr: &str) -> String {
    const WORDS: usize = 24;

    let mut words: Vec<&str> = Vec::with_capacity(WORDS);
    let mut tokens = stderr.split_whitespace().peekable();
    while words.len() < WORDS {
        let Some(token) = tokens.next() else { break };
        if token.parse::<usize>() != Ok(words.len() + 1) {
            continue;
        }
        match tokens.peek() {
            Some(word) if word.chars().all(|c| c.is_ascii_lowercase()) => {
                words.push(word);
                tokens.next();
            }
            _ => {}
        }
    }

    assert_eq!(
        words.len(),
        WORDS,
        "the recovery phrase block is no longer transcribable: found {} of {WORDS} numbered \
         words. An operator reading this block could not write the phrase down either.\n{stderr}",
        words.len()
    );
    words.join(" ")
}

/// Remove a directory and prove it is gone.
///
/// Step 3 is the whole premise of the drill — the machine is gone, only the
/// store remains — so "the index was deleted" is asserted rather than assumed.
/// A drill whose disaster silently did not happen is a drill that proves the
/// index still works.
pub fn destroy(directory: &Path) {
    std::fs::remove_dir_all(directory).expect("the index directory is removable");
    assert!(
        !directory.exists(),
        "step 3 did not destroy {}",
        directory.display()
    );
}
