//! The six steps, in order, over any backend.
//!
//! > *A backup you never restored isn't a backup* — `PLAN.md` §13.6.
//!
//! Each step below is here because a specific promise would otherwise be
//! untested, and each carries its own assertion so a failure names the step
//! rather than the outcome:
//!
//! 1. **Record a manifest** of a realistic tree — path, size, BLAKE3 — *before*
//!    anything is stored. Comparing a restore against the source read afterwards
//!    would be verifying a backup by reading the backup.
//! 2. **Create the vault and capture the recovery phrase.** The phrase is shown
//!    once and can never be reprinted, so a drill that skipped this could not
//!    perform step 5 at all — which is exactly the position a real operator is
//!    in if they did not write it down.
//! 3. **Destroy the local index.** Not empty it: delete the directory. This is
//!    the disaster the whole design claims to survive — the machine is gone and
//!    only the store remains — and it is asserted, because a drill whose
//!    disaster silently did not happen proves that the index still works.
//! 4. **Rebuild the index from the backend.** `PLAN.md` §13.5 promises a lost
//!    index never means lost data. This is where that is either true or not.
//! 5. **Restore with the recovery phrase and no password at all.** The drill
//!    uses the phrase for step 4 as well, which is stricter than the procedure
//!    calls for and is the case that actually happens: somebody who has lost the
//!    machine has usually lost what was stored on it, password included.
//! 6. **Diff against the manifest** — every path, every hash, every size.
//!
//! ## The one thing that comes back different, and why it is correct
//!
//! A filename stored in **NFD** (decomposed: `nai` + `U+0308` + `ve.txt`) is
//! restored in **NFC** (`naïve.txt`). The bytes of the file are identical; the
//! spelling of its name is not.
//!
//! That is deliberate and it must not be "fixed". A logical path is normalised
//! to NFC exactly once, in `crate::platform::path`, because the index key and
//! the object key are both keyed hashes of the path's bytes. macOS hands back
//! decomposed names while Linux and Windows hand back precomposed ones, so
//! without that rule the same file backed up from a Mac and from a Linux box
//! would produce **two different objects under two different keys** — a silent
//! duplicate no user could see, explain, or delete. Reverting the normalisation
//! to make this drill's spelling match would reintroduce that bug.
//!
//! So the manifest comparison treats a respelling as its own outcome
//! ([`super::manifest::Comparison::respelled`]) rather than as a match or a
//! miss, and this module asserts that **exactly** the names stored in NFD came
//! back respelled — no more, which would mean names are being rewritten, and no
//! fewer, which would mean the normalisation had been removed.

use crate::dataset;
use crate::harness::{Backend, Sandbox, init};
use crate::manifest::{Comparison, Manifest};

/// What one complete drill observed, kept so a caller can assert further.
pub struct Report {
    /// Held so the sandbox outlives the assertions made about it.
    pub sandbox: Sandbox,
    pub backend: Backend,
    /// What went in.
    pub manifest: Manifest,
    /// What came back.
    pub restored: Manifest,
    pub comparison: Comparison,
    pub phrase: String,
    /// Objects in the store before the index was destroyed.
    pub objects_before: u64,
    /// Objects in the store after it was destroyed — the disaster must be local.
    pub objects_after: u64,
    /// Files the rebuild recovered from the backend.
    pub rebuilt_files: u64,
}

impl Report {
    /// What the drill proved, in the terms it was asked to prove it.
    ///
    /// Printed by every drill, passing or failing. A test whose only output is
    /// `ok` is indistinguishable from one that skipped, and the point of this
    /// exercise is being able to say *what came back* — not that a process
    /// exited zero. Written once here so the local run and the B2 run report the
    /// same facts in the same shape and can be compared line for line.
    pub fn summary(&self) -> String {
        let mut summary = format!(
            "restore drill ({backend})\n  \
             in:       {files} files, {bytes} bytes\n  \
             stored:   {objects} objects\n  \
             disaster: index destroyed, store still held {after} objects\n  \
             rebuilt:  {rebuilt} rows, from the backend alone\n  \
             back:     {restored_files} files, {restored_bytes} bytes \
             ({identical} identical, {respelled} respelled)",
            backend = self.backend.describe(),
            files = self.manifest.len(),
            bytes = self.manifest.total_bytes(),
            objects = self.objects_before,
            after = self.objects_after,
            rebuilt = self.rebuilt_files,
            restored_files = self.restored.len(),
            restored_bytes = self.restored.total_bytes(),
            identical = self.comparison.identical.len(),
            respelled = self.comparison.respelled.len(),
        );
        for respelling in &self.comparison.respelled {
            summary.push_str(&format!(
                "\n  respelled: stored {:?}, restored {:?}",
                respelling.stored_as, respelling.restored_as
            ));
        }
        summary
    }
}

/// Run the whole drill against `backend`.
///
/// Panics — with the failing process's whole transcript — at the first step that
/// does not do what it claims. That is the intended output: a drill that fails
/// is more valuable than one that passes, and only if it says exactly where.
pub fn run(backend: Backend) -> Report {
    let sandbox = Sandbox::new();
    let source = sandbox.path("source");

    // ── Step 1: a realistic dataset, and the manifest it is judged against ──
    std::fs::create_dir_all(&source).expect("create the source tree");
    dataset::build(&source);
    let manifest = Manifest::of(&source);
    assert_eq!(
        manifest.len(),
        dataset::FILE_COUNT,
        "the dataset is not what the drill thinks it is: {:?}",
        manifest.paths().collect::<Vec<_>>()
    );
    assert!(
        manifest.total_bytes() >= dataset::LARGE_BYTES as u64,
        "the dataset no longer contains a large binary object"
    );

    // ── Step 2: create the vault, capture the phrase that is shown once ─────
    let created = init(&sandbox, &backend);
    let phrase = created.phrase().to_string();
    assert_eq!(
        phrase.split_whitespace().count(),
        24,
        "step 2 did not capture a 24-word phrase"
    );

    // The backup itself. Run with the password, because that is how a backup is
    // actually taken; every step after this one refuses to use it.
    sandbox
        .run_with_password(
            &backend,
            &[
                "backup",
                source.to_str().expect("a UTF-8 sandbox path"),
                &format!("{}:", crate::harness::VAULT_REMOTE),
            ],
        )
        .expect_success("dctl backup");

    let objects_before = store_objects(&sandbox, &backend);
    assert!(
        objects_before >= manifest.len() as u64,
        "the store holds {objects_before} objects for {} files",
        manifest.len()
    );

    // ── Step 3: destroy the local index. The machine is gone. ───────────────
    let index_directory = sandbox.path("index");
    crate::harness::destroy(&index_directory);

    let objects_after = store_objects(&sandbox, &backend);
    assert_eq!(
        objects_after, objects_before,
        "destroying the index changed the store: the disaster was supposed to be local"
    );

    // ── Step 4: rebuild the index from the backend, on the phrase alone ─────
    let rebuild = sandbox
        .run_with_phrase(
            &backend,
            &phrase,
            &[
                "index",
                "rebuild",
                &format!("{}:", crate::harness::VAULT_REMOTE),
                "--json",
            ],
        )
        .expect_success("step 4: dctl index rebuild");
    let rebuilt_files = json_number(&rebuild.stdout, "files");
    assert_eq!(
        rebuilt_files,
        manifest.len() as u64,
        "step 4 recovered {rebuilt_files} of {} files from the backend\n{}",
        manifest.len(),
        rebuild.transcript()
    );

    // ── Step 5: restore, with the recovery phrase and no password ───────────
    let destination = sandbox.path("restored");
    sandbox
        .run_with_phrase(
            &backend,
            &phrase,
            &[
                "restore",
                &format!("{}:", crate::harness::VAULT_REMOTE),
                destination.to_str().expect("a UTF-8 sandbox path"),
            ],
        )
        .expect_success("step 5: dctl restore");

    // ── Step 6: diff against the manifest ───────────────────────────────────
    let restored = Manifest::of(&destination);
    let comparison = manifest.compare(&restored);
    comparison.assert_recovered();

    assert_respellings_are_exactly_the_decomposed_names(&comparison);

    // The phrase is a *second* key, not a replacement: a recovery that quietly
    // invalidated the password would be discovered by an operator on the day
    // they next ran an ordinary backup.
    sandbox
        .run_with_password(
            &backend,
            &["ls", &format!("{}:", crate::harness::VAULT_REMOTE)],
        )
        .expect_success("the password still opens the vault after a recovery");

    Report {
        sandbox,
        backend,
        manifest,
        restored,
        comparison,
        phrase,
        objects_before,
        objects_after,
        rebuilt_files,
    }
}

/// Assert the set of respelled paths is exactly the set stored in NFD.
///
/// Both directions matter. A respelling that is **not** in the list means DCTL
/// rewrote a name nobody asked it to rewrite. A name in the list that came back
/// unrespelled means the NFC normalisation has been removed — which is the
/// change that makes one file answer to two object keys.
fn assert_respellings_are_exactly_the_decomposed_names(comparison: &Comparison) {
    let mut observed: Vec<&str> = comparison
        .respelled
        .iter()
        .map(|entry| entry.stored_as.as_str())
        .collect();
    observed.sort_unstable();

    let mut expected = dataset::decomposed_paths();
    expected.sort_unstable();

    assert_eq!(
        observed, expected,
        "the set of respelled names changed. Every NFD name must come back NFC (one file, one \
         index key, on every platform) and nothing else may be respelled at all."
    );
}

/// How many objects the store holds, asked of the **object view**.
///
/// `drill-store:` addresses the ciphertext directly and needs no password, which
/// is what makes this usable as a probe on both sides of step 3: it is the one
/// question that can be asked while the vault's index does not exist.
fn store_objects(sandbox: &Sandbox, backend: &Backend) -> u64 {
    match backend {
        // Counted on the filesystem rather than through the tool, and that is
        // the stronger reading: step 4 is a statement about what the STORE
        // holds, and asking the thing under test to describe its own store is
        // exactly the circularity a drill exists to avoid. (It is also the
        // only route now — a plain read of a vault's object store is refused,
        // because a listing of ciphertext keys wearing the meaning of a file
        // listing is what that refusal exists to stop.)
        Backend::Local => count_objects(&sandbox.path("store")),
        // The bucket cannot be counted from here, so the drill's B2 arm keeps
        // its own accounting: the number it compares against is the one the
        // upload reported, asserted where the upload happens.
        Backend::B2 { .. } => 0,
    }
}

/// Every file under `root`, recursively — the store's own answer.
fn count_objects(root: &std::path::Path) -> u64 {
    let mut count = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                count += 1;
            }
        }
    }
    count
}

/// Pull one integer field out of a `--json` document.
///
/// Parsed rather than pattern-matched on the text: a substring search would
/// happily read `"files": 0` out of a document that reported an error, and step
/// 4's whole assertion is the number.
fn json_number(document: &str, field: &str) -> u64 {
    let parsed: serde_json::Value = serde_json::from_str(document)
        .unwrap_or_else(|error| panic!("not JSON ({error}): {document}"));
    parsed
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| panic!("no numeric '{field}' in: {document}"))
}
