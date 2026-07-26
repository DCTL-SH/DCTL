//! Adaptive Argon2id calibration stays within the frozen ceilings and clamps lanes.

use std::time::Duration;

use dctl_crypto::constants::{
    ARGON2_MAX_M_COST, ARGON2_MAX_P_LANES, ARGON2_MAX_T_COST, ARGON2_MIN_M_COST,
};
use dctl_crypto::kdf;

#[test]
fn calibrate_stays_within_frozen_ceilings() {
    let p = kdf::calibrate(Duration::from_millis(150), 4).unwrap();
    assert!(
        (ARGON2_MIN_M_COST..=ARGON2_MAX_M_COST).contains(&p.m_cost),
        "m={}",
        p.m_cost
    );
    assert!(
        (1..=ARGON2_MAX_T_COST).contains(&p.t_cost),
        "t={}",
        p.t_cost
    );
    assert_eq!(p.p_lanes, 4);
    // The calibrated params must be accepted by the KDF validator.
    assert!(kdf::validate_params(p.m_cost, p.t_cost, p.p_lanes).is_ok());
}

#[test]
fn calibrate_clamps_lanes() {
    let hi = kdf::calibrate(Duration::from_millis(100), 999).unwrap();
    assert!((1..=ARGON2_MAX_P_LANES).contains(&hi.p_lanes));
    let lo = kdf::calibrate(Duration::from_millis(100), 0).unwrap();
    assert!(lo.p_lanes >= 1);
}
