//! The Argon2id cost a slot is written at, and which one *this build* writes.
//!
//! `m_cost`, `t_cost` and `p_lanes` only ever mean anything together — a
//! memory figure without the passes it is swept for says nothing about what a
//! guess costs — so they travel as one value rather than as three `u32`
//! arguments in a row that a call site can silently transpose.
//!
//! ## Two costs, and only one of them can be shipped
//!
//! [`Cost::PRODUCTION`] is the shipped policy: 128 MiB, three passes, four
//! lanes, roughly a third of a second per guess on a desktop. It is what
//! `crates/dctl-decode/FORMAT.md` §2.1 publishes and what every vault a
//! released DCTL creates carries.
//!
//! `Cost::TEST` — private, below — is the §2 floor, the cheapest parameters the
//! format permits at all. It exists because DCTL's own test suite creates and
//! opens hundreds of vaults per run, and at the shipped cost `tests/invariant_i4`
//! alone took 863 seconds. At the floor it takes 5.5, and every assertion is
//! unchanged, because an envelope records the parameters it was written with and
//! any build re-derives from those.
//!
//! That last property is exactly why the choice cannot be a setting. A vault
//! written at the floor stays openable forever, by any DCTL, with no warning
//! anywhere — its password is simply brute-forceable. So which of the two a
//! build writes is decided by [`super::gate`] from Cargo's `PROFILE`, baked in
//! as generated source, and reachable by nothing else: no feature, no flag, no
//! environment variable, no `cfg`. A shipped build cannot be made to write the
//! reduced cost; it has no code path that reaches it and no input that would
//! select one.

use crate::constants::{
    ARGON2_MAX_P_LANES, ARGON2_MAX_T_COST, ARGON2_MIN_M_COST, DEFAULT_ARGON2_M_COST,
    DEFAULT_ARGON2_P_LANES, DEFAULT_ARGON2_T_COST, TEST_ARGON2_M_COST, TEST_ARGON2_P_LANES,
    TEST_ARGON2_T_COST,
};
use crate::error::Result;

use super::derive::validate_params;

// Written by `build.rs` into `OUT_DIR`; defines `WRITES_PRODUCTION_COST: bool`.
// Included as *source* rather than read from a `cargo::rustc-cfg`, because a
// `cfg` can also be set with `RUSTFLAGS="--cfg …"` and a gate with two inputs
// has one too many. See [`super::gate`].
include!(concat!(env!("OUT_DIR"), "/kdf_cost_profile.rs"));

/// One Argon2id cost setting: the three parameters an envelope slot records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cost {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Time cost — passes over the memory.
    pub t_cost: u32,
    /// Parallelism, in lanes.
    pub p_lanes: u32,
}

impl Cost {
    /// The shipped cost: what a released DCTL writes into every new vault.
    ///
    /// Stated as a named value rather than three loose constants so that "the
    /// cost this product ships" is one thing a reviewer can point at, and so
    /// the format-conformance test can pin it against
    /// `crates/dctl-decode/FORMAT.md` §2.1 whatever profile the suite happens
    /// to be built in.
    pub const PRODUCTION: Self = Self {
        m_cost: DEFAULT_ARGON2_M_COST,
        t_cost: DEFAULT_ARGON2_T_COST,
        p_lanes: DEFAULT_ARGON2_P_LANES,
    };

    /// The reduced cost a non-shipped build writes — the frozen §2 floor.
    ///
    /// Deliberately **not public**. The value is inert on its own, but a
    /// blessed `Cost::TEST` in the public API is an invitation, and a caller
    /// that wants weak parameters can already spell them out field by field.
    /// What matters is that nothing a shipped binary runs can *select* it, and
    /// [`Cost::shipped`] is the only selector there is.
    pub(crate) const TEST: Self = Self {
        m_cost: TEST_ARGON2_M_COST,
        t_cost: TEST_ARGON2_T_COST,
        p_lanes: TEST_ARGON2_P_LANES,
    };

    /// The cost **this build** writes into a new vault.
    ///
    /// [`Cost::PRODUCTION`] in every shipped build. See [`super::gate`] for the
    /// mechanism and for why it is not something a caller can influence.
    #[must_use]
    pub const fn shipped() -> Self {
        if WRITES_PRODUCTION_COST {
            Self::PRODUCTION
        } else {
            Self::TEST
        }
    }

    /// Whether this build writes the shipped cost.
    ///
    /// `false` only in a build made without `--release`, and then the binary
    /// says so out loud the moment it creates a vault — a reduced-cost build
    /// that stayed quiet would be indistinguishable from a released one at
    /// exactly the moment the difference is permanent.
    #[must_use]
    pub const fn is_production() -> bool {
        WRITES_PRODUCTION_COST
    }

    /// Validate against the mandatory §2 ceilings.
    ///
    /// # Errors
    /// [`crate::CryptoError::InvalidKdfParams`] if any parameter is outside the
    /// frozen range every decoder agrees on.
    pub fn validate(self) -> Result<()> {
        validate_params(self.m_cost, self.t_cost, self.p_lanes)
    }
}

// ── Compile-time gates ───────────────────────────────────────────────────────

// The second, independent gate. `build.rs` decides from Cargo's `PROFILE`;
// this decides from the compiler's own view of the build, and the reduced cost
// needs both. Neither can be forced on its own: `PROFILE` ignores the
// environment and `RUSTFLAGS`, and a hand-edited `OUT_DIR` file still meets a
// release build with debug assertions off. Defeating the pair means editing the
// source tree, which is the point.
const _: () = assert!(
    WRITES_PRODUCTION_COST || cfg!(debug_assertions),
    "a build without debug assertions must write the production Argon2id cost: \
     the reduced test cost is not shippable"
);

// The reduced cost still has to be a *legal* cost, or the suite would be
// proving things about envelopes no decoder would accept.
const _: () = assert!(Cost::TEST.m_cost >= ARGON2_MIN_M_COST);
const _: () = assert!(Cost::TEST.t_cost >= 1 && Cost::TEST.t_cost <= ARGON2_MAX_T_COST);
const _: () = assert!(Cost::TEST.p_lanes >= 1 && Cost::TEST.p_lanes <= ARGON2_MAX_P_LANES);

// …and it has to be genuinely cheaper, or the whole exercise bought nothing.
const _: () = assert!(Cost::TEST.m_cost < Cost::PRODUCTION.m_cost);
const _: () = assert!(Cost::TEST.t_cost <= Cost::PRODUCTION.t_cost);
