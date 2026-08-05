//! Trying an operation again when the reason it failed will not last — on
//! **every** backend, not only B2.
//!
//! # What this replaces
//!
//! `b2/retry.rs` was the whole of DCTL's retry story. It is a good module and it
//! covered one of five providers, so a `503 SlowDown` from S3 or R2 failed a
//! write on the *first* response with exactly one request made
//! (`tests/s3_mock.rs`), an `sftp` read that met a reset connection failed
//! immediately, and — worse than either — every one of those failures reached
//! the operator carrying the hint
//!
//! ```text
//! Retries were exhausted. Check connectivity and provider status.
//! ```
//!
//! over a run that had attempted the request exactly once. That is the forbidden
//! class of `PLAN.md` §6 in a single sentence: it tells an operator the tool has
//! already done the thing they would otherwise go and do.
//!
//! # The shape
//!
//! ```text
//!   Backend  ──wrapped by──▶  Retrying  ──consults──▶  classify::verdict
//!                                │                          │
//!                                │                     (pure: no clock,
//!                                │                      no sleep, no I/O)
//!                                └──waits──▶  backoff::jittered
//! ```
//!
//! * [`observed`] is what one attempt saw, derived **structurally** from the
//!   [`StoreError`](crate::StoreError) rather than by searching its text. A rule
//!   that decides whether to retry by looking for `"503"` in a message breaks
//!   the first time the message is reworded — silently, and in the direction of
//!   not retrying.
//! * [`policy`] is what a given provider considers worth another attempt, and
//!   how patient it is. Per provider, because a local filesystem returning
//!   `EAGAIN` and a bucket returning `503` want completely different schedules.
//! * [`classify`] is the decision. Pure, so every rule below is asserted
//!   directly instead of being inferred from a run against a provider that
//!   happened to be in a good mood.
//! * [`backoff`] is the waiting, including the jitter — kept out of `classify`
//!   precisely so `classify` stays deterministic and assertable.
//! * [`driver`] runs the loop and is the only part that sleeps.
//! * [`backend`] is the decorator that puts all of it in front of any
//!   [`Backend`](crate::Backend), which is what "every provider gets it" means
//!   in practice: one implementation, installed once, rather than five.
//!
//! # The count is reported, and it is the real one
//!
//! [`driver::run`] wraps its final error in
//! [`StoreError::Retried`](crate::StoreError::Retried) **only when it really did
//! try more than once**, so the CLI can word its hint from a number rather than
//! from an assumption. A failure that was classified as permanent arrives
//! unwrapped and carries no retry claim at all, because none was made.
//!
//! # What is deliberately still B2's own
//!
//! B2 keeps `b2::retry`, and that is not duplication. It retries at the
//! *request* level and can do something this layer cannot: fetch a fresh upload
//! URL, or re-authorize after `401 expired_auth_token`, before trying again. An
//! error it has already exhausted arrives here marked
//! [`Retried`](crate::StoreError::Retried), and [`classify::verdict`] refuses to
//! retry it a second time — the same idea as the "already exhausted, do not
//! retry me again" marker rclone attaches to such an error, and the reason a
//! six-attempt inner budget under a six-attempt outer one does not become
//! thirty-six.
//!
//! # What this does not do
//!
//! It does not **re-establish a connection**. A `Retrying` wrapper around
//! [`SftpBackend`](crate::SftpBackend) will retry a request that met a transient
//! I/O error, and it cannot help a run whose multiplexed `ssh` session has died,
//! because nothing below it can re-dial one. That case is classified as terminal
//! and says so rather than being retried five times into the same dead socket:
//! rclone re-dials out of its own SFTP connection pool, DCTL does not, and
//! pretending otherwise by spending the budget on it would be the same false
//! claim in a new place.

pub mod backend;
pub mod backoff;
pub mod classify;
pub mod constants;
pub mod driver;
pub mod observed;
pub mod policy;

pub use backend::Retrying;
pub use classify::{Verdict, verdict};
pub use observed::Observed;
pub use policy::RetryPolicy;
