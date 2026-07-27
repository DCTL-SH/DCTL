//! For a **configured** store, I4 holds in its strongest form: the answer is
//! read out of the configuration and the destination is never consulted at all.
//!
//! So the test is a comparison rather than an assertion about one run. The same
//! command is issued against three states of the destination —
//!
//! 1. the vault as `dctl init` left it, envelope and all;
//! 2. the same directory with the envelope taken away, so nothing on disk says
//!    "vault";
//! 3. no directory at all, so there is nothing on disk to say anything —
//!
//! and every observable must match: the exit code, the messages, standard
//! output. If any of the three differed, the encryption decision would be a
//! function of filesystem state, a runbook's meaning would change between
//! Tuesday and Wednesday, and I4 would be false.
//!
//! ## Why every spelling
//!
//! Because the gap this suite was written for was a *spelling*, not a state.
//! `dctl copy ./src staging/../vault` missed the configured claim — the raw
//! string did not match, `canonicalize` refused a path whose `staging` component
//! did not exist — fell through to the envelope check, missed that too for the
//! same reason, and wrote plaintext into a configured vault's object store while
//! reporting success. Same command, same configuration, one different way of
//! typing the destination, opposite outcome. An operator has no way to know that
//! `vault` and `staging/../vault` are different to a tool that treats them as
//! one place everywhere else.

use crate::harness::{
    ENVELOPE, MARKER_FILE, Outcome, Sandbox, VAULT_REMOTE, assert_marker_confined,
};

/// The state a destination is in when a command is issued at it.
#[derive(Clone, Copy, Debug)]
enum State {
    /// A real vault, exactly as `dctl init` created it.
    VaultOnDisk,
    /// The same directory, with the envelope moved out of the way. To the
    /// filesystem it is now an ordinary empty directory.
    NoEnvelope,
    /// Removed entirely. There is nothing to inspect even in principle.
    NothingAtAll,
}

impl State {
    const ALL: &'static [Self] = &[Self::VaultOnDisk, Self::NoEnvelope, Self::NothingAtAll];

    fn label(self) -> &'static str {
        match self {
            Self::VaultOnDisk => "a vault on disk",
            Self::NoEnvelope => "the envelope removed",
            Self::NothingAtAll => "the directory removed",
        }
    }
}

/// Put the store directory into `state`, from whatever state it is in.
///
/// Idempotent and total, so the caller can order the states however it likes and
/// a failure part-way through cannot leave the next case testing something other
/// than it claims to.
fn put_into(sandbox: &Sandbox, store: &str, state: State) {
    let envelope = sandbox.path(&format!("{store}/{ENVELOPE}"));
    let aside = sandbox.path("envelope-aside.bin");

    match state {
        State::VaultOnDisk => {
            std::fs::create_dir_all(envelope.parent().expect("the system directory"))
                .expect("recreate the system directory");
            if aside.exists() {
                std::fs::rename(&aside, &envelope).expect("restore the envelope");
            }
            assert!(envelope.is_file(), "the vault must be intact for this case");
        }
        State::NoEnvelope => {
            put_into(sandbox, store, State::VaultOnDisk);
            std::fs::rename(&envelope, &aside).expect("move the envelope aside");
            assert!(!envelope.exists());
        }
        State::NothingAtAll => {
            put_into(sandbox, store, State::NoEnvelope);
            std::fs::remove_dir_all(sandbox.path(store)).expect("remove the store directory");
            assert!(!sandbox.path(store).exists());
        }
    }
}

/// Every way one directory can be named on the command line.
///
/// Built against a live sandbox rather than listed as literals because three of
/// them only mean anything relative to a real filesystem — and the symlink cases
/// have to be created before they can be typed.
fn spellings(sandbox: &Sandbox, store: &str) -> Vec<(&'static str, String)> {
    let mut spellings = vec![
        ("bare", store.to_string()),
        ("relative", format!("./{store}")),
        ("absolute", sandbox.path(store).display().to_string()),
        // `staging` does not exist and is never created: this is the spelling
        // that defeated the old check, because `canonicalize` fails on the whole
        // path when any component of it is missing.
        ("parent hop", format!("staging/../{store}")),
        ("nested subdirectory", format!("{store}/photos/2024")),
        // The four below are the ones this list did NOT have, and their absence
        // is why it stayed green through a live plaintext write into a vault's
        // object store and a `sync` that deleted the ciphertext already there.
        //
        // `Location` compared paths as raw strings, so `store/` was a different
        // place from `store`; the resolved-path safety net was filtered with
        // `real != path`, which is `Path`'s component-wise equality and
        // normalises away precisely these spellings — so the net was disabled
        // for exactly the cases that needed it. A trailing slash is what shell
        // tab-completion produces, which made this the likeliest spelling of all
        // to be typed and the only one untested.
        ("trailing slash", format!("{store}/")),
        ("trailing dot", format!("{store}/.")),
        ("interior dot", format!("./{store}")),
        ("doubled separator", format!("{store}//")),
    ];

    #[cfg(unix)]
    {
        let link = sandbox.path("store-link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(sandbox.path(store), &link).expect("a symlink to the store");
        spellings.push(("symlink", "store-link".to_string()));
        spellings.push(("symlink and subdirectory", "store-link/photos".to_string()));
    }

    spellings
}

/// One `dctl copy` at `dest`, with a source freshly re-created.
fn copy_into(sandbox: &Sandbox, dest: &str) -> Outcome {
    let source = sandbox.fresh_source("source");
    sandbox.run(&[], "copy", &[source, dest.to_string()], b"")
}

#[test]
fn every_spelling_of_a_configured_store_answers_the_same_in_every_state() {
    let sandbox = Sandbox::new();
    sandbox.init_vault(VAULT_REMOTE, "vault");

    for (label, dest) in spellings(&sandbox, "vault") {
        let mut baseline: Option<(State, Outcome)> = None;

        for state in State::ALL {
            put_into(&sandbox, "vault", *state);
            let outcome = copy_into(&sandbox, &dest);
            let context = format!(
                "spelling `{label}` ({dest}) with {}\n{}",
                state.label(),
                outcome.transcript()
            );

            // The answer must be a refusal — identical failures would also be
            // "identical", and two identical plaintext writes into a vault would
            // pass a comparison that only compared.
            assert_eq!(
                outcome.code,
                Some(7),
                "{context}: a configured store must refuse a plaintext write \
                 however it is spelled"
            );
            assert!(
                outcome.said("is the object store for remote 'archive'"),
                "{context}: the answer must come from the configuration, which is \
                 the only source that can name the remote to type"
            );

            // Nothing was written, in any state, under any spelling.
            let source_file = format!("source/{MARKER_FILE}");
            assert_marker_confined(&sandbox, &[source_file], &context);

            match &baseline {
                None => baseline = Some((*state, outcome)),
                Some((first_state, first)) => {
                    assert_eq!(
                        outcome.code,
                        first.code,
                        "spelling `{label}`: exit code differs between {} and {}",
                        first_state.label(),
                        state.label()
                    );
                    assert_eq!(
                        outcome.messages(),
                        first.messages(),
                        "spelling `{label}`: the operator is told something different \
                         with {} than with {} — the decision depends on contents",
                        state.label(),
                        first_state.label()
                    );
                    assert_eq!(
                        outcome.stdout,
                        first.stdout,
                        "spelling `{label}`: machine-readable output differs between {} \
                         and {}",
                        first_state.label(),
                        state.label()
                    );
                    assert_eq!(
                        outcome.stderr_without_timestamps(),
                        first.stderr_without_timestamps(),
                        "spelling `{label}`: everything printed must match between {} \
                         and {}",
                        first_state.label(),
                        state.label()
                    );
                }
            }
        }
    }
}

#[test]
fn a_sibling_of_a_configured_store_is_an_ordinary_place() {
    // The complement, and the reason the test above is not satisfied by a rule
    // that refuses everything. A guard that spread to neighbouring directories
    // would break invariant I3 — a plaintext write to an ordinary location is a
    // first-class supported operation — and would do it in a way people work
    // around rather than report.
    let sandbox = Sandbox::new();
    sandbox.init_vault(VAULT_REMOTE, "vault");

    for dest in ["vault-2", "./beside", "staging/../beside-too"] {
        let source = sandbox.fresh_source("source");
        let outcome = sandbox.run(&[], "copy", &[source, dest.to_string()], b"");
        let context = format!("{dest}\n{}", outcome.transcript());

        assert_eq!(outcome.code, Some(0), "{context}");
        assert_eq!(
            std::fs::read(sandbox.path(&format!("{dest}/{MARKER_FILE}"))).expect("the copy landed"),
            crate::harness::MARKER,
            "{context}: an ordinary destination must receive the source's own bytes"
        );
    }
}

#[test]
fn a_subdirectory_of_the_store_is_refused_at_any_depth() {
    // The bypass an exact-path rule leaves open: one extra component and the
    // write lands in the middle of a vault's object tree. A guard that one path
    // component disables is worse than none, because it reads as protection.
    let sandbox = Sandbox::new();
    sandbox.init_vault(VAULT_REMOTE, "vault");

    for dest in [
        "vault/photos",
        "vault/photos/2024",
        "vault/photos/2024/raw/nested/deeper",
        "vault/system",
    ] {
        let outcome = copy_into(&sandbox, dest);
        let context = format!("{dest}\n{}", outcome.transcript());

        assert_eq!(outcome.code, Some(7), "{context}");
        assert!(
            outcome.said("is the object store for remote 'archive'"),
            "{context}"
        );
        // The refusal names the store's root, not the path that was typed: the
        // operator needs to know what they hit, not what they wrote.
        assert!(
            outcome.said(&sandbox.path("vault").display().to_string()),
            "{context}: the refusal must name the configured root"
        );
        assert_marker_confined(&sandbox, &[format!("source/{MARKER_FILE}")], &context);
    }
}
