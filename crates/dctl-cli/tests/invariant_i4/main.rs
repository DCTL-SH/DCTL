//! Invariant I4, proved against the shipped binary rather than asserted in prose.
//!
//! > **DCTL never applies or omits encryption because of a destination's
//! > contents. What a command encrypts is determined solely by the remote name
//! > typed. A destination's contents may cause DCTL to REFUSE, never to change
//! > what it does.**
//!
//! The outcome space for any destination is `{sealed, plain, refused}`. Contents
//! can only ever move an outcome to `refused`; they can never turn `plain` into
//! `sealed` or `sealed` into `plain`. That bound is what makes the envelope check
//! on an unconfigured location safe, and what makes it *not* auto-detection:
//! auto-detection changes behaviour, this only ever stops.
//!
//! A statement of that shape is only worth having if it is checked, and checked
//! where it can fail — in the shipped binary, across the flags a real operator
//! passes, against the bytes actually on disk. So this suite is deliberately
//! end-to-end: every assertion below is made about a real process's exit status,
//! its messages, and the files it left behind.
//!
//! ## What is asserted, and why in this form
//!
//! * **Filesystem, never counters.** A "Files: 1 / 1" line can be printed by a
//!   stage that did nothing, and an error can be printed by a run that wrote the
//!   file anyway. Every claim here is settled by reading the tree: is the marker
//!   there, byte for byte, and is it anywhere it should not be?
//! * **The whole sandbox, not just the destination.** A guard that refuses
//!   `archive:` and then writes into a *directory* called `archive:` has failed
//!   in the way that matters, so the plaintext search runs over the entire
//!   sandbox against an explicit allow-list.
//! * **Every flag combination, every write verb.** I4 says *no* flag changes the
//!   answer. One combination proves nothing; the matrix in [`harness::FLAG_SETS`]
//!   crossed with [`harness::Verb::ALL`] is the claim.
//! * **A real vault, unlocked and reachable.** Every sandbox holds a genuine
//!   vault created by `dctl init`, and `DCTL_PASSWORD` is exported on every
//!   invocation. The tool has everything it needs to seal a write. That it still
//!   never does — to a bare path — is the assertion; a test that withheld the
//!   password would prove only that a locked vault stays locked.
//!
//! ## The four claims, one module each
//!
//! | Module | Claim |
//! |---|---|
//! | [`never_sealed_to_a_bare_path`] | no flag causes a **sealed** write to a bare path |
//! | [`never_plain_through_a_vault_remote`] | no flag causes a **plain** write through a vault remote |
//! | [`configured_store_ignores_contents`] | a configured store answers identically with the envelope present and absent, in every path spelling |
//! | [`unconfigured_location`] | for a location no remote describes, contents may only ever cause a **refusal** — which names `dctl config import`, and that remedy works |
//!
//! ## What this suite asserts about a sealed write, stated precisely
//!
//! Every test below asserts the **absence** of plaintext, never the presence of
//! ciphertext: the claim is that no flag and no destination state makes a write
//! through a vault remote land unsealed. That is the dangerous half, and it is
//! the half I4 is about.
//!
//! A write through a vault remote does now complete — `dctl copy ./src archive:`
//! stores objects — and that a completed one is genuinely sealed is asserted in
//! `tests/cli.rs`
//! (`copy_into_a_vault_remote_still_needs_the_key_and_still_seals`), which reads
//! the store back and looks for the marker. The division is deliberate: this
//! suite is the flag × verb matrix, and one more assertion per row would say
//! nothing the row next to it does not.

mod harness;

mod configured_store_ignores_contents;
mod never_plain_through_a_vault_remote;
mod never_sealed_to_a_bare_path;
mod unconfigured_location;
