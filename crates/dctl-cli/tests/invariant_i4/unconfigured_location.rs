//! The residual, and the only place in DCTL where a destination's contents are
//! read before a write.
//!
//! For a location no configured remote describes, DCTL has nothing to reason
//! from but the bytes it can see. It looks for a vault envelope, and if it finds
//! one it stops. This module pins the exact shape of that behaviour, because the
//! shape is what makes it sound:
//!
//! * The contents-dependent outcome is **refusal, and only refusal**. The same
//!   command at the same location is either refused (envelope present) or
//!   performs the ordinary plaintext write it was asked for (envelope absent).
//!   It is never sealed. Contents move an outcome to `refused` or leave it
//!   alone; they never change what DCTL does.
//! * The refusal names **`dctl config import`** — the command that turns this
//!   location into a configured one, after which the answer comes from the
//!   configuration and stops depending on contents at all. A refusal whose
//!   remedy did not exist, or did not work, would be a dead end dressed up as
//!   guidance, so the remedy is executed here rather than merely quoted.
//!
//! That bound is the difference between this and auto-detection. Auto-detection
//! would see the envelope and seal the write — delivering something other than
//! what the command line asked for, decided by state the caller never named.
//! This only ever stops, and a stop cannot silently produce the wrong artefact.

use crate::harness::{
    FLAG_SETS, MARKER, MARKER_FILE, Sandbox, VAULT_REMOTE, Verb, assert_marker_confined,
    assert_nothing_sealed_under, row,
};

/// A sandbox holding two vaults: one the configuration knows, one it does not.
///
/// The configured vault is not scenery. Without it the fallback could pass by
/// accident — with no vault remote in the file there is no name it could have
/// wrongly offered. With one present, the refusal below is asserted to *not*
/// name `archive:`, which is the difference between "DCTL has no name for this"
/// and "DCTL guessed".
fn sandbox_with_a_stranger() -> Sandbox {
    let sandbox = Sandbox::new();
    sandbox.init_vault(VAULT_REMOTE, "configured-vault");

    // A second, real vault, created against a configuration this sandbox's
    // commands never read. This is exactly what an operator has after restoring
    // a drive, or after their config.toml was lost: the data is fine, the names
    // are gone (`PLAN.md` §13.1).
    sandbox.dir("stranger");
    sandbox
        .dctl_using("elsewhere.toml", "elsewhere.redb")
        .arg("init")
        .args(["--name", "lost", "--base"])
        .arg(sandbox.path("stranger"))
        .assert()
        .success();

    sandbox
}

/// Move the stranger's envelope out of the way, or put it back.
///
/// The *only* thing that changes between the two halves of the central test:
/// one file, whose presence is the whole of the evidence DCTL has.
fn set_envelope(sandbox: &Sandbox, present: bool) {
    let envelope = sandbox.path("stranger/system/envelope.bin");
    let aside = sandbox.path("stranger-envelope.bin");
    let (from, to) = if present {
        (&aside, &envelope)
    } else {
        (&envelope, &aside)
    };
    if from.exists() {
        std::fs::rename(from, to).expect("move the envelope");
    }
    assert_eq!(envelope.exists(), present);
}

#[test]
fn contents_can_only_turn_a_plain_write_into_a_refusal() {
    // The central claim, stated as the difference between two runs of one
    // command. Nothing changes between them except a single file at the
    // destination — no flag, no argument, no configuration.
    let sandbox = sandbox_with_a_stranger();

    // With the envelope there: refused, and nothing is written.
    set_envelope(&sandbox, true);
    let before = crate::harness::all_files(&sandbox.path("stranger"));
    let refused = {
        let source = sandbox.fresh_source("source");
        sandbox.run(&[], "copy", &[source, "stranger".into()], b"")
    };
    let context = refused.transcript();

    assert_eq!(refused.code, Some(7), "{context}");
    assert!(
        refused.said("no configured remote describes"),
        "{context}: the message must say why no remote is named"
    );
    assert!(
        !refused.said("archive"),
        "{context}: there is a vault remote in this configuration, and it is not \
         this location's — offering it would send the operator to seal their data \
         into the wrong vault"
    );
    assert_eq!(
        crate::harness::all_files(&sandbox.path("stranger")),
        before,
        "{context}: a refusal must leave the location exactly as it found it"
    );
    assert_marker_confined(&sandbox, &[format!("source/{MARKER_FILE}")], &context);

    // With the envelope gone: the very same command performs the very same
    // plaintext write it always meant to. The outcome moved from `refused` to
    // `plain` — never to `sealed`.
    set_envelope(&sandbox, false);
    let permitted = {
        let source = sandbox.fresh_source("source");
        sandbox.run(&[], "copy", &[source, "stranger".into()], b"")
    };
    let context = permitted.transcript();

    assert_eq!(permitted.code, Some(0), "{context}");
    assert_eq!(
        sandbox.read(&format!("stranger/{MARKER_FILE}")),
        MARKER,
        "{context}: the bytes must be the source's own — contents may withhold \
         permission, never change what is written"
    );
    assert_nothing_sealed_under(&sandbox.path("stranger"), &context);

    // And it is reversible, which is what makes it a property of the evidence
    // rather than of the order the tests happened to run in.
    set_envelope(&sandbox, true);
    let refused_again = {
        let source = sandbox.fresh_source("source");
        sandbox.run(&[], "copy", &[source, "stranger".into()], b"")
    };
    assert_eq!(
        refused_again.code,
        Some(7),
        "{}",
        refused_again.transcript()
    );
}

#[test]
fn no_flag_and_no_verb_turns_the_refusal_into_a_write() {
    // The refusal is not a default that a flag relaxes. There is no
    // `--yes-really`, and `--force` in particular does not become one: the
    // operator is being told DCTL cannot name the vault they are writing into,
    // and no amount of insistence supplies that name.
    let sandbox = sandbox_with_a_stranger();
    set_envelope(&sandbox, true);
    let before = crate::harness::all_files(&sandbox.path("stranger"));

    for flags in FLAG_SETS {
        for verb in Verb::ALL {
            let source = sandbox.fresh_source("source");
            let outcome = sandbox.run(
                flags,
                verb.name(),
                &verb.args(&source, "stranger"),
                verb.stdin(),
            );
            let context = format!("{}\n{}", row(*verb, flags), outcome.transcript());

            assert_ne!(
                outcome.code,
                Some(0),
                "{context}: a write into an unrecognised vault reported success"
            );
            assert_eq!(
                crate::harness::all_files(&sandbox.path("stranger")),
                before,
                "{context}: the location changed"
            );
            assert_marker_confined(&sandbox, &[format!("{source}/{MARKER_FILE}")], &context);
        }
    }
}

#[test]
fn the_refusal_names_dctl_config_import_and_that_remedy_works() {
    // A refusal is only as good as the way out of it. This asserts the way out
    // exists, is named, and — the half that is usually skipped — actually
    // resolves the situation when followed.
    let sandbox = sandbox_with_a_stranger();
    set_envelope(&sandbox, true);

    let refused = {
        let source = sandbox.fresh_source("source");
        sandbox.run(&[], "copy", &[source, "stranger".into()], b"")
    };
    let context = refused.transcript();
    assert!(
        refused.said("dctl config import"),
        "{context}: the remedy must be named in full, as something to type"
    );
    assert!(
        refused.said("never switches to sealed mode on its own"),
        "{context}: the message must say what DCTL will *not* do, because this is \
         the moment a user most expects it to just encrypt"
    );

    // Follow it. `config import` reads no secret and moves no bytes; it inspects
    // the location, confirms the envelope, and writes the two remotes `init`
    // would have written.
    sandbox
        .dctl()
        .args(["config", "import"])
        .arg(format!("local:{}", sandbox.path("stranger").display()))
        .args(["--name", "recovered"])
        .assert()
        .success();

    // The same command now gets the *configured* answer — which names a remote,
    // because there is finally one to name. Nothing about the destination
    // changed; only the configuration did, which is exactly where the addressing
    // model says the answer comes from.
    let after = {
        let source = sandbox.fresh_source("source");
        sandbox.run(&[], "copy", &[source, "stranger".into()], b"")
    };
    let context = after.transcript();

    assert_eq!(after.code, Some(7), "{context}");
    assert!(
        after.said("is the object store for remote 'recovered'"),
        "{context}: after import the refusal must name the vault remote to type"
    );
    assert!(
        after.said("Use `recovered:` to store data sealed"),
        "{context}"
    );
    assert!(
        !after.said("dctl config import"),
        "{context}: the fallback message must not survive the fix it recommended"
    );
}

#[test]
fn an_ordinary_directory_that_merely_sits_beside_a_vault_is_untouched() {
    // The rule must not spread. A sibling of a vault is an ordinary directory,
    // and refusing it would break invariant I3 for no gain — the file that says
    // "vault" is not there.
    let sandbox = sandbox_with_a_stranger();
    set_envelope(&sandbox, true);

    let source = sandbox.fresh_source("source");
    let outcome = sandbox.run(&[], "copy", &[source, "stranger-notes".into()], b"");
    let context = outcome.transcript();

    assert_eq!(outcome.code, Some(0), "{context}");
    assert_eq!(
        sandbox.read(&format!("stranger-notes/{MARKER_FILE}")),
        MARKER
    );
    assert_nothing_sealed_under(&sandbox.path("stranger-notes"), &context);
}
