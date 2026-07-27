//! Two local files, one vault path: the collision the drill's dataset avoids.
//!
//! [`crate::drill`] proves that an NFD name comes back NFC with identical bytes,
//! and that this is correct: one file gets one logical path, and therefore one
//! index key and one object key, on every platform. That rule has a sharp edge,
//! and it is here.
//!
//! On a byte-oriented filesystem — ext4, XFS, most of Linux —
//! `re\u{301}sume\u{301}.txt` and `r\u{e9}sum\u{e9}.txt` are **two different
//! files**. They are different byte sequences, `read_dir` returns both, and they
//! can hold different contents. Under NFC they are the same logical path, so a
//! vault can hold only one of them.
//!
//! There are exactly two honest things DCTL can do about that, and one dishonest
//! one. It can refuse and name both files, or it can store one and report the
//! other as skipped. What it must not do is store one, silently overwrite it
//! with the other, and print `Files: 2 / 2  Errors: 0`.
//!
//! **That is what it did when this drill was first run** — `dctl backup` and
//! `dctl copy` both — and the 23-byte file was gone while the run exited 0
//! having said it stored it. That is the failure `PLAN.md` §6 forbids by name,
//! and a backup tool is the worst possible place for it.
//!
//! So the refusal is the assertion below, and it is made for **every verb that
//! reads a local tree**, not only the one the drill happened to use. The bug was
//! in two commands with two independent walks; a test that pinned one of them
//! would have left the other free to lose data. The refusal is the conservative
//! choice and it matches what `dctl restore` already does with a case collision
//! on a case-insensitive volume: stop before anything is written, list every
//! offending name, and let the operator decide. Renaming one file at the source
//! is a five-second fix; discovering on restore day that a backup silently held
//! one of the two is not a fix at all.
//!
//! ## macOS cannot run this test, and says so
//!
//! APFS and HFS+ are normalisation-insensitive: creating the second spelling
//! opens the first file rather than making a new one, so the input this test
//! needs cannot exist there. The condition is checked on the filesystem rather
//! than assumed from `cfg!(target_os)`, because it is a property of the volume —
//! a case-sensitive, byte-oriented volume can be mounted anywhere — and because
//! an assumption that was wrong would make the test pass without an input.

use crate::harness::{Backend, Sandbox, VAULT_REMOTE, init};

/// The precomposed spelling: `r` + `U+00E9` + `sum` + `U+00E9` + `.txt`.
const PRECOMPOSED: &str = "r\u{e9}sum\u{e9}.txt";

/// The decomposed spelling of the same name: `e` + `U+0301`, twice.
const DECOMPOSED: &str = "re\u{301}sume\u{301}.txt";

/// How [`PRECOMPOSED`] must be rendered in the refusal.
///
/// Spelled out as a literal rather than derived from [`PRECOMPOSED`], because a
/// test that computed the expected escaping with the same rule the code uses
/// would pass whatever that rule became — including a rule that escaped nothing
/// and printed the two names identically, which is the failure this asserts
/// against.
const PRECOMPOSED_ESCAPED: &str = r"r\u{00e9}sum\u{00e9}.txt";

/// How [`DECOMPOSED`] must be rendered in the refusal.
const DECOMPOSED_ESCAPED: &str = r"re\u{0301}sume\u{0301}.txt";

/// Contents of the precomposed file. A different length from its twin, so a
/// truncation cannot be mistaken for a swap.
const PRECOMPOSED_BYTES: &[u8] = b"PRECOMPOSED-NFC-CONTENT\n";

/// Contents of the decomposed file.
const DECOMPOSED_BYTES: &[u8] = b"decomposed-nfd\n";

/// Exit code for a refusal made before anything is stored.
///
/// `fatal_error`, the same code the name pre-flight already uses. Spelled out
/// rather than imported: `docs/EXIT_CODES.md` is a published contract, and a
/// test that read the constant would keep passing if the constant changed.
const FATAL_ERROR: i32 = 7;

/// Every verb that reads a local tree and writes it into a vault.
///
/// `backup` and `copy` walk the tree through two independent code paths, and
/// both lost the file. `sync` and `move` share `copy`'s walk, and are here
/// because "shares the walk today" is not a property a test may assume: `move`
/// deletes its source, so a `move` that merged two files into one would destroy
/// the original of the one it dropped.
const VERBS: &[&str] = &["backup", "copy", "sync", "move"];

#[test]
fn two_files_that_normalise_to_one_path_are_refused_by_every_verb_that_reads_a_local_tree() {
    let sandbox = Sandbox::new();
    let backend = Backend::Local;
    let source = sandbox.path("source");
    std::fs::create_dir_all(&source).expect("create the source tree");

    std::fs::write(source.join(PRECOMPOSED), PRECOMPOSED_BYTES).expect("write the NFC spelling");
    std::fs::write(source.join(DECOMPOSED), DECOMPOSED_BYTES).expect("write the NFD spelling");

    let on_disk = std::fs::read_dir(&source)
        .expect("the source tree is readable")
        .count();
    if on_disk != 2 {
        // Neither a pass nor a failure: the input does not exist on this volume.
        // Reported loudly so a suite that ran here is not mistaken for one that
        // covered the case.
        eprintln!(
            "SKIPPED the normalisation-collision test: this filesystem is \
             normalisation-insensitive, so the two spellings are one file ({on_disk} entry) and \
             the collision cannot be created here."
        );
        return;
    }

    init(&sandbox, &backend);

    for verb in VERBS {
        let outcome = sandbox.run_with_password(
            &backend,
            &[
                verb,
                source.to_str().expect("a UTF-8 sandbox path"),
                &format!("{VAULT_REMOTE}:{verb}"),
            ],
        );

        assert_eq!(
            outcome.code,
            Some(FATAL_ERROR),
            "`dctl {verb}` must refuse two files that share one vault path, before storing \
             anything\n{}",
            outcome.transcript()
        );

        // Both native spellings have to appear, and they have to appear
        // **escaped**. The whole difficulty for the operator is telling the two
        // names apart: they are the same glyphs in every terminal, file manager
        // and editor, so a message that printed them as they display would print
        // one string twice and help nobody. The escapes are the only form of
        // this message that can be acted on, which is why they are asserted
        // rather than the raw names.
        for spelling in [PRECOMPOSED_ESCAPED, DECOMPOSED_ESCAPED] {
            assert!(
                outcome.stdout.contains(spelling) || outcome.stderr.contains(spelling),
                "`dctl {verb}` refused without naming {spelling}\n{}",
                outcome.transcript()
            );
        }

        // And nothing was stored, by any of them. A refusal that had already
        // written one of the two would leave the operator with a vault holding a
        // file they were told was rejected — and `move` would have deleted the
        // other from the source.
        assert_eq!(
            store_objects(&sandbox, &backend),
            1,
            "`dctl {verb}` wrote something into the store: only the envelope should be there"
        );
    }

    // The source tree is intact, which is the assertion `move` earns: a refusal
    // that had deleted a source file would have destroyed data while reporting a
    // failure.
    assert_eq!(
        std::fs::read(source.join(PRECOMPOSED)).expect("the NFC file survives"),
        PRECOMPOSED_BYTES
    );
    assert_eq!(
        std::fs::read(source.join(DECOMPOSED)).expect("the NFD file survives"),
        DECOMPOSED_BYTES
    );
}

/// Objects in the store, asked of the object view, which needs no password.
fn store_objects(sandbox: &Sandbox, backend: &Backend) -> u64 {
    let outcome = sandbox
        .run(
            backend,
            &[
                "size",
                &format!("{VAULT_REMOTE}-store:"),
                "--json",
                "--no-ask-password",
            ],
        )
        .expect_success("counting the objects in the store");
    let document: serde_json::Value =
        serde_json::from_str(&outcome.stdout).expect("size --json is a document");
    document
        .get("count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| panic!("no count in: {}", outcome.stdout))
}
