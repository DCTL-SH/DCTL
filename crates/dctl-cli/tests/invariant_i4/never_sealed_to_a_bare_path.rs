//! Half of I4: **no combination of flags causes a sealed write to a bare path.**
//!
//! The direction people forget. Everyone tests that a vault directory refuses
//! plaintext; almost nobody tests that an ordinary directory is not quietly
//! encrypted. Both are the same invariant, and the second failure is the more
//! insidious: it exits 0, it looks like a successful backup, and the operator
//! discovers on restore day that the file their own tools should be able to read
//! is an opaque object produced by a command that never mentioned a vault.
//!
//! Every sandbox here holds a **real vault that would unlock**, and every
//! invocation carries `DCTL_PASSWORD`. The tool is fully capable of sealing.
//! That is the point: what is asserted is a decision, not an inability.

use crate::harness::{
    self, FLAG_SETS, MARKER, MARKER_FILE, Sandbox, VAULT_REMOTE, Verb, assert_marker_confined,
    assert_nothing_sealed_under, row,
};

#[test]
fn no_flag_and_no_verb_seals_a_write_to_an_ordinary_path() {
    // The full matrix against a destination that is nobody's vault. Every row
    // must land the source's bytes verbatim, or land nothing at all — and must
    // never land a `DSF1` object.
    let sandbox = Sandbox::new();
    sandbox.init_vault(VAULT_REMOTE, "vault");

    // Grows as the matrix legitimately writes. Every row's destination joins the
    // list, so the marker turning up *anywhere else* — a stray staging file, a
    // directory named after a remote, a previous row's destination written to
    // twice — is still caught.
    let mut allowed = vec![format!("source/{MARKER_FILE}")];

    for (index, flags) in FLAG_SETS.iter().enumerate() {
        for verb in Verb::ALL {
            let source = sandbox.fresh_source("source");
            // A fresh destination per row: a directory left over from the
            // previous row could satisfy the assertion without this row having
            // written anything.
            let dest = format!("ordinary-{index}-{}", verb.name());
            sandbox.dir(&dest);

            let outcome = sandbox.run(flags, verb.name(), &verb.args(&source, &dest), verb.stdin());
            let context = format!("{} -> {dest}\n{}", row(*verb, flags), outcome.transcript());
            let landed = verb.landing(&dest);

            // 1. Whatever is at the destination is plaintext, byte for byte.
            if sandbox.exists(&landed) {
                assert_eq!(
                    sandbox.read(&landed),
                    MARKER,
                    "{context}: the destination holds something other than the \
                     source's own bytes"
                );
            }

            // 2. Nothing anywhere under the destination is a sealed object —
            //    including a staging file an aborted write might have left.
            assert_nothing_sealed_under(&sandbox.path(&dest), &context);

            // 3. A run that reported success actually performed the write. Two
            //    and three together are what separate "DCTL wrote plaintext"
            //    from "DCTL wrote nothing and said nothing"; either alone would
            //    pass for a command that did no work.
            let rehearsal = flags.contains(&"--dry-run");
            if outcome.code == Some(0) && !rehearsal {
                assert!(
                    sandbox.exists(&landed),
                    "{context}: exit 0 with no file at {landed} — success was reported \
                     for work that did not happen"
                );
            }

            // 4. And the plaintext is only ever where this test put it.
            allowed.push(landed);
            assert_marker_confined(&sandbox, &allowed, &context);
        }
    }
}

#[test]
fn a_bare_path_naming_a_vaults_own_store_is_refused_and_never_sealed() {
    // The tempting "helpful" behaviour, and the one the model forbids: DCTL can
    // see that this directory is `archive:`'s object store, and could seal the
    // write on the operator's behalf. Doing so would deliver something other
    // than what the command line said, decided by configuration the caller did
    // not name at the destination. So the outcome is `refused` — a stop, not a
    // redirect — and the refusal hands back the name to type.
    let sandbox = Sandbox::new();
    sandbox.init_vault(VAULT_REMOTE, "vault");
    let before = harness::all_files(&sandbox.path("vault"));

    for flags in FLAG_SETS {
        for verb in Verb::ALL {
            let source = sandbox.fresh_source("source");
            let outcome = sandbox.run(
                flags,
                verb.name(),
                &verb.args(&source, "vault"),
                verb.stdin(),
            );
            let context = format!("{}\n{}", row(*verb, flags), outcome.transcript());

            assert_ne!(
                outcome.code,
                Some(0),
                "{context}: a write into a vault's object store reported success"
            );

            // Refused, not redirected: nothing new is in the store at all,
            // sealed or otherwise. A count would not do — `Files: 0 / 0` is
            // printed by a stage that did nothing *and* by one that wrote to a
            // path nobody is looking at.
            assert_eq!(
                harness::all_files(&sandbox.path("vault")),
                before,
                "{context}: the vault's object store changed"
            );

            let source_file = format!("{source}/{MARKER_FILE}");
            assert_marker_confined(&sandbox, &[source_file], &context);
        }
    }
}

#[test]
fn the_refusal_hands_back_the_two_names_that_address_the_place() {
    // A refusal that only says "no" leaves an operator with a job to finish and
    // no way to finish it, and the next thing they try is usually worse. Both
    // views are named on purpose: the sealed one is what stores data safely, and
    // the object one is how a backup operator copies ciphertext without ever
    // holding a password — the separation of duties the two-remote model exists
    // to make structural.
    let sandbox = Sandbox::new();
    sandbox.init_vault(VAULT_REMOTE, "vault");
    let source = sandbox.fresh_source("source");

    let outcome = sandbox.run(&[], "copy", &[source, "vault".into()], b"");
    let context = outcome.transcript();

    assert_eq!(outcome.code, Some(7), "{context}");
    assert!(
        outcome.said("is the object store for remote 'archive'"),
        "{context}"
    );
    assert!(
        outcome.said("Use `archive:` to store data sealed"),
        "the sealed view is the command the operator meant: {context}"
    );
    assert!(
        outcome.said("dctl replicate archive-store:"),
        "the object view is how ciphertext is copied without a password: {context}"
    );
    assert!(
        outcome.said("decided by the remote name typed"),
        "the refusal states the invariant, because this is the moment a user is \
         most likely to expect the tool to just encrypt it: {context}"
    );
}
