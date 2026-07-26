//! Opening a vault for a command that needs one.
//!
//! Everything between "the user named a remote" and "an unlocked
//! [`Vault`](dctl_core::Vault) exists" lives here: resolving the spec against
//! the config, building the backend, locating the index, acquiring the password,
//! and unwrapping the root key.
//!
//! It is a module rather than a helper function because the steps have real
//! failure modes that deserve their own diagnosis. "Which of these five things
//! went wrong?" is the first question on any support ticket, and a single
//! opaque `unlock failed` answers none of it.
//!
//! ## Why this is separate from the commands
//!
//! Three unrelated command families need a vault — transfers, listings and the
//! integrity checks — and each of them would otherwise re-derive the index path
//! and re-implement the password fallback chain. One divergence in that chain
//! (a command that forgets `--no-ask-password`, say) turns an unattended backup
//! into a job hanging on an invisible prompt.
//!
//! It is also the one place that can refuse a second factor the engine cannot
//! apply ([`factor`]). Every unlock in the binary passes through here, so a
//! command family added later inherits that refusal instead of having to
//! remember it.

pub mod factor;
pub mod open;
pub mod password;
pub mod store;

pub use open::{Session, open};
