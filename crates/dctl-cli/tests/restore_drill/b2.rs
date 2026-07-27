//! The same drill against a real Backblaze B2 bucket.
//!
//! ```sh
//! DCTL_B2_KEY_ID=… DCTL_B2_APP_KEY=… DCTL_DRILL_B2_BUCKET=DCTL001 \
//!   cargo test -p dctl-cli --test restore_drill -- --ignored --nocapture
//! ```
//!
//! **This is the run that matters, and it has now happened.** A local drill
//! decides everything DCTL controls; a provider decides everything it does not.
//! Listing every `n/*` record in step 4 is one `read_dir` locally and a paginated
//! API walk on B2, where a rebuild that stops at the first page recovers a
//! plausible-looking subset and reports a number nobody can tell is wrong. Step 5
//! pulls twelve chunks over the network instead of out of the page cache, so a
//! ranged request that is off by a byte, or a retry that restarts a stream
//! without rewinding the hasher, only shows up here. Neither failure is reachable
//! against a directory.
//!
//! ## What the first live run found
//!
//! It failed, which is what a drill is for. Five of the ten files came back
//!
//! ```text
//! b2 api error 503: {"code":"service_unavailable","message":"no tomes available"}
//! ```
//!
//! — B2's ordinary way of saying an upload pod is busy and the client should ask
//! for another URL — and the run reported `Files: 5 / 10`, `Errors: 5`, exit 6,
//! having stored half a backup. Nothing in `dctl-store` retried anything, while
//! every backend error carried the hint *"Retries were exhausted."*
//! `crates/dctl-store/src/b2/retry.rs` is the answer to that, and this drill is
//! what proves it: the same ten files, the same bucket, now `10 identical`.
//!
//! Local runs cannot reach that failure. No directory has ever been out of tomes.
//!
//! ## Why it is `#[ignore]` and why it panics instead of skipping
//!
//! `#[ignore]` keeps it out of the default suite: a test that silently passes
//! because no credentials were exported is worse than no test, because it makes
//! the suite report a drill that never ran. Asking for it explicitly with
//! `--ignored` and getting a pass on a machine with no keys would be the same
//! lie one layer down, so a missing variable is a **failure** here, naming
//! exactly what is absent.
//!
//! ## The bucket is scratch, and the drill says so
//!
//! [`crate::harness::B2_BUCKET_ENV`] has no default. The drill runs
//! `dctl init --force` against whatever it names, which writes a new envelope
//! and makes anything already in that bucket permanently unreadable — the bytes
//! stay, the provider keeps billing for them, and nothing can decrypt them
//! again. Requiring the bucket to be spelled out on the command line is what
//! stops a maintainer who exported keys for something else from discovering that
//! a test suite did that.

use crate::drill;
use crate::harness::Backend;

#[test]
#[ignore = "runs against a real B2 bucket: needs DCTL_B2_KEY_ID, DCTL_B2_APP_KEY \
            and DCTL_DRILL_B2_BUCKET, and re-initialises the bucket it is given"]
fn the_whole_dataset_survives_a_destroyed_index_and_comes_back_from_b2() {
    let backend = match Backend::from_env() {
        Ok(backend) => backend,
        Err(missing) => panic!(
            "the B2 restore drill was asked for and cannot run: {} is not set. It is not \
             reported as a pass, because a drill that did not run proves nothing about the \
             provider — which is the half of the exercise a local run cannot cover.",
            missing.join(", ")
        ),
    };

    let report = drill::run(backend);

    eprintln!("{}", report.summary());
}
