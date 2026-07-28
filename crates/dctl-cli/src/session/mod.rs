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
//!
//! ## Two ways in, resolved once
//!
//! A vault has two independent unlock paths — the password and the recovery
//! phrase (`docs/FORMAT.md` §2) — and [`secret`] is the single place that
//! decides which one a run uses. That matters more than it looks: the value of a
//! second key is that it opens *everything*, so `ls`, `cat`, `copy` and
//! `restore` must all accept a phrase without any of them being taught about it.
//! They are, because they all arrive here.

pub mod factor;
pub mod index;
pub mod kdf_cost;
pub mod open;
pub mod password;
pub mod phrase;
pub mod secret;
pub mod store;
pub mod vault_present;

pub use open::{Session, open, open_with};
