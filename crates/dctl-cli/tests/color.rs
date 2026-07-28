//! `--color`, asserted on the bytes each command actually writes.
//!
//! # Why this file exists
//!
//! `--color always` emitted **zero** escape sequences from `ls`, `lsl`, `lsd`,
//! `tree`, `check` and `size`. Only `about` coloured anything, so the flag was
//! *measurably* honoured — two sequences against zero for `--color never` — on
//! the one command nobody reaches for, and inert on every command an operator
//! reads (`HANDOVER.md` §11.2, §11.3 item 8).
//!
//! A flag that is honoured in one place and silently ignored in six is worse
//! than one that is missing: the user has evidence it works. So the assertion
//! here is not "the flag parses" but "these bytes contain ESC, and these do
//! not", per command, in all three modes.
//!
//! # The three modes, and why `auto` is asserted at all
//!
//! * `always` — colour survives a pipe. Every test below runs with stdout
//!   redirected into the harness, so a renderer that produced escapes and let
//!   `anstream` strip them again would fail this half rather than pass it.
//! * `never` — no escapes, whatever the terminal.
//! * `auto` — no escapes *here*, because stdout is a pipe. This is the case a
//!   `contains("OK")` assertion anywhere else in the suite depends on, and the
//!   one that breaks the moment a renderer writes escapes unconditionally.
//!
//! # Why the whole family and not one representative
//!
//! Because the defect was per command. Six renderers each decide for themselves
//! whether to ask the palette for a style, and five of them silently did not.
//! A test that checked `ls` alone would have passed over `tree` for exactly as
//! long as the last one did.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use assert_cmd::Command;
use tempfile::TempDir;

/// The one byte that decides every assertion in this file.
const ESC: u8 = 0x1b;

/// Environment that would redirect a run away from its sandbox, or decide
/// colour behind the flag's back.
///
/// `NO_COLOR`, `CLICOLOR_FORCE` and `TERM` are on the list for the second
/// reason: `ColorChoice::Auto` consults all three, so a maintainer running the
/// suite under `NO_COLOR=1` would otherwise see the `auto` case pass for the
/// wrong reason and the `always` case keep working — which is precisely the
/// half-honoured state this file exists to detect.
const CLEARED_ENV: &[&str] = &[
    "DCTL_CONFIG_DIR",
    "DCTL_CONFIG",
    "DCTL_INDEX",
    "DCTL_REMOTE",
    "DCTL_PASSWORD",
    "NO_COLOR",
    "CLICOLOR_FORCE",
    "TERM",
];

struct Sandbox {
    root: TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let root = TempDir::new().expect("temp dir");
        let left = root.path().join("left");
        let right = root.path().join("right");
        std::fs::create_dir_all(left.join("sub")).unwrap();
        std::fs::create_dir_all(&right).unwrap();
        std::fs::write(left.join("a.txt"), b"alpha").unwrap();
        std::fs::write(left.join("sub").join("b.txt"), b"beta").unwrap();
        std::fs::write(right.join("a.txt"), b"alpha-different").unwrap();
        Self { root }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.path().join(relative)
    }

    fn dctl(&self, color: &str) -> Command {
        let mut cmd = Command::cargo_bin("dctl").expect("the dctl binary is built");
        for key in CLEARED_ENV {
            cmd.env_remove(key);
        }
        cmd.current_dir(self.root.path())
            .arg("--config")
            .arg(self.path("dctl.toml"))
            .arg("--index")
            .arg(self.path("index.redb"))
            .arg("--color")
            .arg(color);
        cmd
    }
}

/// Run one command in one colour mode and hand back everything it wrote.
///
/// Both streams, concatenated, because colour is a property of the whole
/// rendering: `size` puts its totals on stdout and its basis note on stderr,
/// and a test that looked at one of them would give a different verdict per
/// command for reasons that have nothing to do with the flag.
fn output(sandbox: &Sandbox, color: &str, args: &[&str]) -> Vec<u8> {
    let assert = sandbox.dctl(color).args(args).assert();
    let out = assert.get_output();
    let mut bytes = out.stdout.clone();
    bytes.extend_from_slice(&out.stderr);
    bytes
}

fn escapes(bytes: &[u8]) -> usize {
    bytes.iter().filter(|byte| **byte == ESC).count()
}

/// Every command an operator reads output from, with arguments that produce
/// some.
///
/// `check` appears twice, and the pair is the point. Two trees that **differ**
/// render a table on stdout; two that **match** render one confirmation line on
/// stderr — and those were two different code paths with two different answers
/// about `--color`. The stdout half already obeyed the flag through
/// `Table`'s column styles; the stderr half wrote through `anstream`'s global
/// stream, which re-ran its own terminal check and stripped everything. So a
/// suite that only checked the differing case would have passed over a `dctl
/// check` that emitted zero escapes on every successful run.
///
/// The matching case compares a tree against itself, which is the cheapest
/// arrangement that cannot go flaky: a second tree copied on disk would have to
/// carry the same modification times, and a test that turned amber whenever the
/// filesystem rounded a timestamp would teach a maintainer to ignore it.
///
/// `copy` is here for the same reason at the other end: the end-of-run summary
/// is stderr too, and it is the block an operator watches most.
fn commands(sandbox: &Sandbox) -> Vec<(&'static str, Vec<String>)> {
    let left = sandbox.path("left").display().to_string();
    let right = sandbox.path("right").display().to_string();
    let into = sandbox.path("into").display().to_string();
    vec![
        ("ls", vec!["ls".into(), left.clone()]),
        ("lsl", vec!["lsl".into(), left.clone()]),
        ("lsd", vec!["lsd".into(), left.clone()]),
        ("tree", vec!["tree".into(), left.clone()]),
        ("size", vec!["size".into(), left.clone()]),
        ("check-differs", vec!["check".into(), left.clone(), right]),
        (
            "check-matches",
            vec!["check".into(), left.clone(), left.clone()],
        ),
        ("copy", vec!["copy".into(), left, into]),
    ]
}

fn borrow(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

#[test]
fn color_always_reaches_every_command_an_operator_reads() {
    // The defect, stated as an assertion. Five of these six produced zero
    // escapes while `--color always` was in force and the run exited 0.
    let sandbox = Sandbox::new();
    for (name, args) in commands(&sandbox) {
        let bytes = output(&sandbox, "always", &borrow(&args));
        assert!(
            escapes(&bytes) > 0,
            "`dctl {name}` emitted no escape sequences under --color always:\n{}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

#[test]
fn color_never_emits_nothing_from_any_of_them() {
    let sandbox = Sandbox::new();
    for (name, args) in commands(&sandbox) {
        let bytes = output(&sandbox, "never", &borrow(&args));
        assert_eq!(
            escapes(&bytes),
            0,
            "`dctl {name}` emitted escape sequences under --color never:\n{}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

#[test]
fn color_auto_stays_plain_when_the_output_is_redirected() {
    // stdout and stderr are both pipes here, which is what every other
    // `contains(...)` assertion in this suite relies on.
    let sandbox = Sandbox::new();
    for (name, args) in commands(&sandbox) {
        let bytes = output(&sandbox, "auto", &borrow(&args));
        assert_eq!(
            escapes(&bytes),
            0,
            "`dctl {name}` coloured a redirected stream under --color auto:\n{}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

#[test]
fn a_machine_format_is_never_coloured_however_loudly_it_is_asked_for() {
    // `--color always --format json` must still produce parseable JSON: escape
    // sequences inside it break every consumer downstream, and the flag
    // combination is one a script reaches for by accident.
    let sandbox = Sandbox::new();
    let left = sandbox.path("left").display().to_string();
    for args in [
        vec!["ls", &left, "--format", "json"],
        vec!["lsjson", &left],
        vec!["size", &left, "--format", "json"],
    ] {
        let bytes = output(&sandbox, "always", &args);
        assert_eq!(
            escapes(&bytes),
            0,
            "{args:?} coloured a machine format:\n{}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

/// The size and modification-time columns keep their width once styled.
///
/// Escape sequences are zero-width on a terminal but not zero-*length* in a
/// `String`, so a renderer that pads after styling produces columns that look
/// right in a test and are ragged on screen. Asserted by comparing the two
/// modes' visible text rather than by counting bytes.
#[test]
fn colour_changes_the_bytes_and_not_the_layout() {
    let sandbox = Sandbox::new();
    let left = sandbox.path("left").display().to_string();
    for verb in ["ls", "lsl", "lsd"] {
        let plain = output(&sandbox, "never", &[verb, &left]);
        let painted = output(&sandbox, "always", &[verb, &left]);
        assert_eq!(
            strip(&plain),
            strip(&painted),
            "`dctl {verb}` changed its layout when coloured"
        );
    }
}

/// Remove every ANSI escape sequence, leaving the visible text.
///
/// Deliberately hand-written and minimal: it understands CSI sequences
/// (`ESC [ … final-byte`), which is all `anstyle` ever emits here, and would
/// leave anything else visible — so a renderer that started writing some other
/// control sequence would fail the comparison rather than have it quietly
/// stripped.
fn strip(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(bytes.len());
    let mut rest = bytes.iter().copied().peekable();
    while let Some(byte) = rest.next() {
        if byte != ESC {
            out.push(byte);
            continue;
        }
        if rest.peek() == Some(&b'[') {
            rest.next();
            for byte in rest.by_ref() {
                if (0x40..=0x7e).contains(&byte) {
                    break;
                }
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A guard against the sandbox itself going stale.
///
/// Every assertion above is over the *bytes a command wrote*, so a command that
/// silently started failing — a renamed flag, a moved fixture — would write
/// nothing and pass the two negative tests. This one fails instead.
#[test]
fn every_command_under_test_actually_produces_output() {
    let sandbox = Sandbox::new();
    for (name, args) in commands(&sandbox) {
        let bytes = output(&sandbox, "never", &borrow(&args));
        assert!(
            !strip(&bytes).trim().is_empty(),
            "`dctl {name}` produced nothing at all, so the colour assertions are vacuous"
        );
    }
}
