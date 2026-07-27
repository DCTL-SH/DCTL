//! The other half of I4: **no combination of flags causes a plain write through
//! a vault remote.**
//!
//! A vault has two names and they are not interchangeable. `archive:` is the
//! sealed view — invariant I1 says every write through it is encrypted and no
//! flag turns that off. `archive-store:` is the object view — invariant I2 says
//! foreign plaintext never joins the ciphertext there, because such a file is
//! both unencrypted and unreadable to the vault that owns the tree.
//!
//! ## Why the assertion is about bytes and not about exit codes
//!
//! Enumerating a named remote is unimplemented in this build, so a write to
//! `archive:` fails before any object is produced. An assertion on the exit code
//! would therefore pin today's *limitation* and would have to be rewritten the
//! day uploads land — exactly when it most needs to keep watching.
//!
//! So what is asserted is the property that must hold in both worlds: **the
//! marker's bytes never appear under the store, in any file, whatever flags were
//! passed.** That is false if a plain write leaks through, and it stays true when
//! the sealed path starts working, because ciphertext does not contain its
//! plaintext.

use crate::harness::{
    self, FLAG_SETS, MARKER_FILE, STORE_REMOTE, Sandbox, VAULT_REMOTE, Verb,
    assert_marker_confined, row,
};

/// The full matrix against one destination spelling, asserting that no byte of
/// the marker reaches the vault's object store.
fn no_plaintext_reaches_the_store(dest: &str) {
    let sandbox = Sandbox::new();
    sandbox.init_vault(VAULT_REMOTE, "vault");

    for flags in FLAG_SETS {
        for verb in Verb::ALL {
            let source = sandbox.fresh_source("source");
            let outcome = sandbox.run(flags, verb.name(), &verb.args(&source, dest), verb.stdin());
            let context = format!("{} -> {dest}\n{}", row(*verb, flags), outcome.transcript());

            for file in harness::all_files(&sandbox.path("vault")) {
                let bytes = std::fs::read(&file).expect("read a file in the object store");
                assert!(
                    !harness::contains(&bytes, harness::MARKER),
                    "{context}: unsealed plaintext reached {} inside the vault's \
                     object store",
                    file.display()
                );
            }

            // And it did not land beside the store either — a destination
            // spelled `archive:` must never become a *directory* of that name,
            // which is a failure that looks exactly like a successful backup.
            let source_file = format!("{source}/{MARKER_FILE}");
            assert_marker_confined(&sandbox, &[source_file], &context);
        }
    }
}

#[test]
fn no_flag_and_no_verb_writes_plaintext_through_the_sealed_view() {
    // I1. `archive:` seals or it does nothing; there is no third behaviour, and
    // no flag introduces one.
    no_plaintext_reaches_the_store(&format!("{VAULT_REMOTE}:"));
}

#[test]
fn no_flag_and_no_verb_writes_plaintext_through_the_object_view() {
    // I2. `archive-store:` holds one vault's opaque objects, and foreign
    // plaintext among them is the mistake this address exists to catch.
    no_plaintext_reaches_the_store(&format!("{STORE_REMOTE}:"));
}

#[test]
fn the_object_view_is_refused_by_name_and_names_the_sealed_view() {
    // Addressed by name, the answer comes from the configuration alone — no
    // stat, no envelope, no contents — which is why it is the same answer on an
    // empty store, a full one, and a store on a provider this machine cannot
    // even reach.
    let sandbox = Sandbox::new();
    sandbox.init_vault(VAULT_REMOTE, "vault");
    let source = sandbox.fresh_source("source");

    let outcome = sandbox.run(&[], "copy", &[source, format!("{STORE_REMOTE}:")], b"");
    let context = outcome.transcript();

    assert_eq!(outcome.code, Some(7), "{context}");
    assert!(outcome.said(STORE_REMOTE), "{context}");
    assert!(
        outcome.said("Use `archive:` to store data sealed"),
        "the refusal must hand back the name that does what the operator meant: \
         {context}"
    );
}

#[test]
fn the_sealed_view_is_never_refused_by_the_addressing_rule() {
    // The mirror of the test above, and the one that stops the guard from
    // becoming a blanket ban on vaults. `archive:` is the address a user is
    // *supposed* to type: I2 refuses foreign plaintext in the object store, and
    // a guard that also refused the sealed view would leave a vault with no
    // usable address at all — a "safe" tool that cannot store anything.
    //
    // Written so it survives the sealed path being finished. Today the command
    // stops on unimplemented enumeration; when uploads land it will succeed.
    // Both are acceptable answers. The one answer that never is: a refusal from
    // the addressing rule.
    let sandbox = Sandbox::new();
    sandbox.init_vault(VAULT_REMOTE, "vault");
    let source = sandbox.fresh_source("source");

    let outcome = sandbox.run(&[], "copy", &[source, format!("{VAULT_REMOTE}:")], b"");
    let context = outcome.transcript();

    assert!(
        !outcome.said("is the object store"),
        "the sealed view must never be mistaken for its own object store: {context}"
    );
    assert!(
        outcome.code == Some(0) || outcome.said("not implemented in this build"),
        "the sealed view must either work or say plainly that it does not yet — \
         any other failure means the address a user is told to type is unusable \
         for a reason nobody documented: {context}"
    );
}
