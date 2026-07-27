//! Telling the operator when this build writes a reduced key-derivation cost.
//!
//! A vault whose slots were wrapped at the reduced Argon2id cost is not a
//! degraded vault in any way anyone can see. It opens with the same commands, on
//! any machine, forever — the envelope records the parameters it was written
//! with, so every later unlock simply honours them. That is precisely the
//! danger: nothing downstream ever looks wrong, and the only difference is that
//! guessing the password costs a few milliseconds instead of a third of a second
//! per attempt — four orders of magnitude off an offline attack.
//!
//! The parameters are fixed at creation and cannot be changed afterwards without
//! rewriting the slot, so the moment a slot is written is the last moment anyone
//! can be told. Both commands that write one — `dctl init` and the password
//! replacement inside `dctl vault recover` — say it here, in the same words, for
//! the same reason two tests share a harness.
//!
//! ## This cannot happen in a released DCTL
//!
//! `dctl_crypto::kdf::gate` decides the cost from Cargo's `PROFILE` at build
//! time and bakes it in as generated source: there is no feature, flag,
//! environment variable or `cfg` that reaches it, and a `--release` build has no
//! code path that selects anything but the production cost. So this warning can
//! only ever fire for somebody running a binary they compiled themselves without
//! `--release` — which is exactly the person who needs to hear it, and the
//! reason the message names the command that fixes it.

use dctl_core::KdfCost;

use crate::ctx::Ctx;

/// Warn, once, if the vault this run is about to write gets the reduced cost.
///
/// Silent in every shipped build, where [`KdfCost::is_production`] is a compile-
/// time `true` and this collapses to nothing.
pub fn warn_if_reduced(ctx: &Ctx) {
    if KdfCost::is_production() {
        return;
    }
    let reduced = KdfCost::shipped();
    let shipped = KdfCost::PRODUCTION;
    ctx.out.warn(format!(
        "this build derives keys at a REDUCED cost (Argon2id m={} KiB, t={}, p={}, \
         instead of m={} KiB, t={}, p={}). Any vault it writes is permanently cheaper \
         to attack and must not hold real data. Rebuild with `cargo build --release` \
         for a vault you intend to keep.",
        reduced.m_cost,
        reduced.t_cost,
        reduced.p_lanes,
        shipped.m_cost,
        shipped.t_cost,
        shipped.p_lanes,
    ));
}
