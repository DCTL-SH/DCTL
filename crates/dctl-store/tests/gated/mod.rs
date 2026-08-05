//! How a credential-gated test obtains its credentials — and what it does when
//! there are none.
//!
//! # The defect this exists to make impossible
//!
//! `tests/s3_live.rs` opened both of its tests with
//!
//! ```ignore
//! let Some(config) = config_from_env() else {
//!     eprintln!("skipping s3_full_round_trip: DCTL_S3_* not set");
//!     return;
//! };
//! ```
//!
//! and libtest reported **ok**. Run with `--ignored` on a machine with no keys,
//! the suite said two S3 round trips had passed. They had not run at all — no S3
//! credentials have ever existed in this environment — so every line of the S3
//! backend, including the modification-time write the `sync` fix added, was
//! covered by a green tick and nothing else.
//!
//! A test that skips and prints `ok` is a lie in the exact place a buyer looks
//! for assurance, and it is the forbidden class of `PLAN.md` §6 — reporting
//! something that did not happen — moved into the test suite.
//!
//! # Three states, and a suite that keeps them apart
//!
//! Every credential-gated test reports exactly one of:
//!
//! | state | how it appears |
//! |---|---|
//! | ran and passed | `test … ok`, after really touching the provider |
//! | ran and failed | `test … FAILED`, with the provider's own error |
//! | **did not run** | `test … ignored, <the reason, naming the variables>` |
//!
//! The third comes from libtest itself: `#[ignore = "…"]` prints its reason on
//! the default run, and cargo totals ignored tests in their own column. So the
//! aggregate cannot read "did not run" as "passed" — provided nothing inside the
//! test quietly turns the second state into the first, which is what [`require`]
//! is for and what `tests/credential_gate.rs` proves of every gated test in the
//! workspace.

/// The values of `vars`, in order, or a **failure** naming every one that is
/// absent.
///
/// Panics rather than returning an `Option`, and that is the whole design. A
/// caller handed `None` has exactly two things it can do: skip (which is the
/// defect) or panic (which is this). Making the panic the only outcome removes
/// the choice from every call site, so there is no test that can be written
/// carelessly rather than one that has to be reviewed carefully.
///
/// Asking for a live test explicitly with `--ignored` on a machine with no keys
/// is a mistake worth being told about: the run proves nothing about the
/// provider, and the provider is the half of the exercise the rest of the suite
/// cannot reach.
///
/// # Panics
/// When any of `vars` is unset or empty, naming all of them at once — one run
/// per missing variable is a slow way to learn a list.
#[track_caller]
pub fn require(test: &str, vars: &[&str]) -> Vec<String> {
    let mut values = Vec::with_capacity(vars.len());
    let mut missing = Vec::new();
    for var in vars {
        match std::env::var(var) {
            Ok(value) if !value.is_empty() => values.push(value),
            _ => missing.push(*var),
        }
    }
    assert!(
        missing.is_empty(),
        "{test} was asked for and cannot run: {} is not set. This is reported as a \
         failure, not a pass, because a live test that did not run proves nothing \
         about the provider — which is the half of the exercise no other test in \
         this suite can reach. Export {} and run again, or drop `--ignored` to \
         leave it out of the run altogether.",
        missing.join(", "),
        vars.join(", "),
    );
    values
}
