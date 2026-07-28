//! Every `#[ignore]`d test in the workspace, checked for the one shape that can
//! report a pass it did not earn.
//!
//! # What this guards
//!
//! `tests/s3_live.rs` used to open each test with an environment check and a
//! bare `return`, so a run with no S3 credentials printed
//!
//! ```text
//! test s3_full_round_trip ... ok
//! ```
//!
//! having touched nothing. Two whole backends' worth of assurance rested on it.
//! The tests themselves are fixed; this file is the reason it cannot come back —
//! the same relationship `cli::reach` has to the eleven inert flags. Fixing four
//! tests fixes four tests; fixing the reason there were four is this.
//!
//! # The rule, and why it is exactly this one
//!
//! **A test marked `#[ignore]` may not contain a `return` statement.**
//!
//! Narrow on purpose. A gated test has one job: touch the real thing. It either
//! runs to a conclusion or it panics, and there is no third outcome worth having
//! — so an early exit inside one is always the defect, never a style. That makes
//! the rule mechanically checkable without understanding the test, which is what
//! a guard has to be. The looser rule ("must not print `skipping`") would be
//! defeated by changing the wording; the tighter one ("must call
//! `gated::require`") cannot cross a crate boundary, and `dctl-cli`'s restore
//! drill has its own harness for its own reasons.
//!
//! **And its `#[ignore]` must carry a reason naming what it needs.** libtest
//! prints that reason on the default run — `test … ignored, needs a live B2
//! bucket: …` — which is what makes "did not run" a *distinguishable, explained*
//! third state rather than an absence. Cargo already totals ignored tests in
//! their own column, so with both halves in place no suite summary can let a
//! test that did not run read as one that passed.
//!
//! # Why it lives in `dctl-store`
//!
//! Because that is where four of the five gated tests are, and because a guard
//! nobody can find is a guard nobody maintains. It reads the whole workspace, so
//! a gated test added under any crate is covered from the moment it is written.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

/// Gated tests known to exist when this guard was written: four in `b2_live`,
/// two in `s3_live`, and one each in `sftp_live`, `write_failure` and
/// `dctl-cli`'s `restore_drill`.
///
/// The guard's own guard, and it is not decoration: a scanner whose file walk or
/// attribute match silently found nothing would pass every assertion below
/// forever, which is the exact shape of the defect this file exists to prevent
/// reproduced inside it. Growing past this number is fine; falling below it
/// means the scan stopped reaching.
const KNOWN_GATED_TESTS: usize = 9;

/// A `#[ignore]`d test found by the scan.
struct Gated {
    /// Where it lives, for a failure message somebody can act on.
    file: PathBuf,
    /// The reason string on the attribute, empty when there was none.
    reason: String,
    /// The function body, comments and all.
    body: String,
    /// The function's name, taken from the signature that follows the attribute.
    name: String,
}

/// The workspace root, from this crate's manifest directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/<name> always has two ancestors")
        .to_path_buf()
}

/// Every `.rs` file under any crate's `tests/` directory.
fn test_sources() -> Vec<PathBuf> {
    let mut found = Vec::new();
    let crates = workspace_root().join("crates");
    let entries = std::fs::read_dir(&crates).unwrap_or_else(|e| {
        panic!(
            "the workspace must be readable at {}: {e}",
            crates.display()
        )
    });
    for entry in entries.filter_map(Result::ok) {
        collect_rust_files(&entry.path().join("tests"), &mut found);
    }
    found.sort();
    found
}

/// Append every `.rs` file at or below `dir`.
fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return; // a crate with no integration tests
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Every `#[ignore …]`d test in the workspace's integration tests.
///
/// The body runs from the attribute to the first line that is a lone `}` in
/// column zero — which is where `rustfmt` puts the end of a top-level function,
/// and `cargo fmt --all` is one of the three gates, so the assumption is
/// enforced elsewhere rather than merely hoped for.
fn gated_tests() -> Vec<Gated> {
    let mut found = Vec::new();
    for file in test_sources() {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if !line.trim_start().starts_with("#[ignore") {
                continue;
            }
            let mut reason = String::new();
            let mut cursor = index;
            // The attribute may be wrapped over several lines; take it up to the
            // closing bracket.
            while cursor < lines.len() {
                reason.push_str(lines[cursor]);
                if lines[cursor].trim_end().ends_with(']') {
                    break;
                }
                cursor += 1;
            }
            let start = cursor + 1;
            let end = lines[start..]
                .iter()
                .position(|l| *l == "}")
                .map_or(lines.len(), |offset| start + offset);
            found.push(Gated {
                file: file.clone(),
                reason,
                name: lines
                    .get(start)
                    .map(|signature| signature.trim().to_string())
                    .unwrap_or_default(),
                body: lines[start..end].join("\n"),
            });
        }
    }
    found
}

/// A line with its `//` comment removed, so prose about the rule is not mistaken
/// for a breach of it.
fn code_only(line: &str) -> &str {
    match line.find("//") {
        Some(at) => &line[..at],
        None => line,
    }
}

#[test]
fn the_scan_reaches_the_tests_it_is_supposed_to_check() {
    let gated = gated_tests();
    assert!(
        gated.len() >= KNOWN_GATED_TESTS,
        "the scan found {} gated tests and there were {KNOWN_GATED_TESTS} when this \
         guard was written — it has stopped reaching them, and every assertion \
         below is now vacuous",
        gated.len()
    );
    // And it is reading real bodies, not empty strings.
    assert!(
        gated.iter().all(|test| !test.body.trim().is_empty()),
        "a gated test was found with an empty body, so the body scan reads nothing"
    );
}

#[test]
fn no_credential_gated_test_can_return_early() {
    // The defect, exactly: `let Some(x) = env else { eprintln!("skipping…");
    // return; }` — and libtest reports `ok`. A gated test runs to a conclusion or
    // it panics; there is no third outcome that is worth reporting.
    for test in gated_tests() {
        let offending: Vec<&str> = test
            .body
            .lines()
            .map(code_only)
            .filter(|line| {
                line.split_whitespace()
                    .any(|word| word.trim_end_matches(';') == "return")
            })
            .collect();
        assert!(
            offending.is_empty(),
            "{}: `{}` returns early:\n{}\n\nA test that needs credentials must FAIL when \
             they are absent, naming what is missing — never return, because libtest \
             reports that as `ok` and the suite then claims work that did not happen. \
             Obtain them through `gated::require` (crates/dctl-store/tests/gated/mod.rs) \
             or panic with the same information.",
            test.file.display(),
            test.name,
            offending.join("\n"),
        );
    }
}

#[test]
fn every_ignored_test_says_what_it_needs() {
    // What makes "did not run" a third state rather than an absence: libtest
    // prints this reason on the default run, beside the test's name.
    for test in gated_tests() {
        assert!(
            test.reason.contains('='),
            "{}: `{}` is `#[ignore]` with no reason. The reason is what a reader of \
             `cargo test` output sees instead of a result, so it has to name what the \
             test needs in order to run.",
            test.file.display(),
            test.name,
        );
        let quoted = test.reason.matches('"').count();
        assert!(
            quoted >= 2 && test.reason.len() > "#[ignore = \"\"]".len() + 20,
            "{}: `{}` gives a reason too short to name anything: {}",
            test.file.display(),
            test.name,
            test.reason.trim(),
        );
    }
}

#[test]
fn the_rule_can_tell_a_return_from_the_word_return() {
    // The guard's own guard. Both halves matter: a matcher that missed a real
    // `return;` would clear every gated test in silence, and one that fired on
    // the word in a comment would make the rule unusable and be loosened.
    let body =
        "    let Some(x) = y else {\n        eprintln!(\"skipping\");\n        return;\n    };";
    assert!(
        body.lines().map(code_only).any(|line| line
            .split_whitespace()
            .any(|w| w.trim_end_matches(';') == "return")),
        "the matcher must find the shape that actually happened"
    );

    let prose = "    // never return early: see the module docs\n    let value = 1;";
    assert!(
        !prose.lines().map(code_only).any(|line| line
            .split_whitespace()
            .any(|w| w.trim_end_matches(';') == "return")),
        "…and must not fire on prose about it"
    );

    let word = "    let returned = compute();";
    assert!(
        !word.lines().map(code_only).any(|line| line
            .split_whitespace()
            .any(|w| w.trim_end_matches(';') == "return")),
        "…nor on an identifier that merely starts with it"
    );
}
