//! Adaptive Argon2id calibration (§9.10).
//!
//! Picks cost params targeting a wall-clock unlock time on THIS device, clamped to the
//! frozen §2 ceilings. Memory is the primary hardness lever (scaled first at fixed time
//! cost); if memory saturates the ceiling, time cost is raised. Params are stored
//! per-slot, so calibration is free to adopt without any format change.
//!
//! **Portable slots:** calibrate for the WEAKEST device expected to unlock the vault
//! (mobile-affordable), never the strongest that created it — otherwise that device
//! cannot afford the memory/time to open it (cross-device requirement, §9.10).
//!
//! This measures a device; it is not the build-time choice between the shipped
//! and the reduced cost. That one is [`super::gate`], and nothing here can reach
//! below the frozen floor.

use std::time::{Duration, Instant};

use crate::constants::{
    ARGON2_MAX_M_COST, ARGON2_MAX_P_LANES, ARGON2_MAX_T_COST, ARGON2_MIN_M_COST,
    DEFAULT_ARGON2_T_COST,
};
use crate::error::Result;

use super::cost::Cost;
use super::derive::argon2id;

/// Probe memory cost (KiB) used to estimate this device's Argon2 throughput (64 MiB).
const PROBE_M_COST: u32 = 65_536;

/// Calibrate Argon2id params to approximately `target` on this device, clamped to the
/// frozen ceilings. `p_lanes` is clamped to `1..=8`.
///
/// # Errors
/// Whatever the probe derivation fails with — the probe runs the real KDF, so a
/// machine that cannot afford 64 MiB is reported rather than guessed around.
pub fn calibrate(target: Duration, p_lanes: u32) -> Result<Cost> {
    let p = p_lanes.clamp(1, ARGON2_MAX_P_LANES);
    let t = DEFAULT_ARGON2_T_COST.max(1);

    // One probe run to estimate throughput (Argon2 time ≈ linear in m·t).
    let salt = [0u8; 16];
    let start = Instant::now();
    let _ = argon2id(
        b"dctl-argon2-calibration-probe",
        &salt,
        Cost {
            m_cost: PROBE_M_COST,
            t_cost: t,
            p_lanes: p,
        },
    )?;
    let elapsed = start.elapsed().as_secs_f64().max(1e-6);
    let target_s = target.as_secs_f64();
    let ratio = target_s / elapsed;

    // Scale memory at fixed time cost, clamped to the ceilings.
    let scaled_m = (f64::from(PROBE_M_COST) * ratio).round();
    let m = scaled_m.clamp(f64::from(ARGON2_MIN_M_COST), f64::from(ARGON2_MAX_M_COST)) as u32;
    let m = m.max(ARGON2_MIN_M_COST);

    // If memory saturated the ceiling and we're still short of target, raise time cost.
    let t_final = if m >= ARGON2_MAX_M_COST && ratio > 1.0 {
        let time_at_cap = elapsed * (f64::from(ARGON2_MAX_M_COST) / f64::from(PROBE_M_COST));
        let t_ratio = target_s / time_at_cap.max(1e-6);
        (f64::from(t) * t_ratio)
            .round()
            .clamp(1.0, f64::from(ARGON2_MAX_T_COST)) as u32
    } else {
        t
    };

    Ok(Cost {
        m_cost: m,
        t_cost: t_final.max(1),
        p_lanes: p,
    })
}
