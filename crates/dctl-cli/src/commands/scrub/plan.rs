//! What a scrub will read, and when it gives up.
//!
//! Two knobs, both of which exist because a full read of a large vault is
//! expensive in egress and in time:
//!
//! * `--sample-percent` bounds the cost by reading a slice of the dataset;
//! * `--max-errors` bounds the *damage report*, for the case where something has
//!   gone catastrophically wrong and there is no value in reading another eight
//!   hours of it.
//!
//! Both default to "do the whole job" ([`SCRUB_FULL_SAMPLE_PERCENT`],
//! [`SCRUB_MAX_ERRORS_UNLIMITED`]), because a scrub that silently sampled would
//! print a health verdict it had not measured — which is the exact failure
//! [the plan](https://doc.dctl.sh/project/plan) §13.4 exists to prevent.
//!
//! ## Why the sample is keyed, not simply hashed
//!
//! Selection has to be *deterministic within a run* — the plan is decided before
//! the walk and must give the same answer if an object is revisited — but
//! *different between runs*, or `--sample-percent 10` would read the same tenth
//! of the vault forever and the other ninety percent would never be scrubbed at
//! all. The selector is therefore a BLAKE3 keyed hash of the logical path under
//! a per-run seed. The seed is reported, so a run that found damage can be
//! replayed over exactly the same slice.

use crate::constants::{
    SCRUB_FULL_SAMPLE_PERCENT, SCRUB_MAX_ERRORS_UNLIMITED, SCRUB_MIN_SAMPLE_PERCENT,
    SCRUB_SAMPLE_BASIS, SCRUB_SAMPLE_KEY_CONTEXT,
};
use crate::error::{CliError, Result};

/// Bytes of the selector hash read as a big-endian integer.
///
/// Eight is a `u64`: far more range than the hundred buckets the decision needs,
/// so the modulo bias is unmeasurable, and it costs nothing since the hash has
/// already been computed.
const SELECTOR_BYTES: usize = 8;

/// The scrub this run will perform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    sample_percent: u8,
    max_errors: u64,
    repair: bool,
    seed: u64,
}

impl Plan {
    /// Build a plan, validating the knobs.
    ///
    /// `repair` arrives already resolved by the caller, which is where the
    /// `--dry-run` decision belongs: a plan that still said "repair" under a dry
    /// run would be one accidental call away from writing.
    ///
    /// # Errors
    /// [`CliError::usage`] when `sample_percent` is outside
    /// [`SCRUB_MIN_SAMPLE_PERCENT`]..=[`SCRUB_FULL_SAMPLE_PERCENT`]. The flag's
    /// own parser enforces the same range, so this is the defence for a plan
    /// built from anywhere else.
    pub fn new(sample_percent: u8, max_errors: u64, repair: bool, seed: u64) -> Result<Self> {
        if !(SCRUB_MIN_SAMPLE_PERCENT..=SCRUB_FULL_SAMPLE_PERCENT).contains(&sample_percent) {
            return Err(CliError::usage(format!(
                "--sample-percent must be between {SCRUB_MIN_SAMPLE_PERCENT} and \
                 {SCRUB_FULL_SAMPLE_PERCENT}, got {sample_percent}"
            ))
            .with_hint(
                "A zero-percent scrub reads nothing, so it could only ever report \
                 health it never measured.",
            ));
        }
        Ok(Self {
            sample_percent,
            max_errors,
            repair,
            seed,
        })
    }

    /// A plan seeded from the wall clock.
    ///
    /// The seed only has to differ between runs, not be unpredictable — nothing
    /// about it is a security decision — so the clock is enough and avoids
    /// pulling a random-number generator into the CLI for one number.
    ///
    /// # Errors
    /// As [`Plan::new`].
    pub fn seeded(sample_percent: u8, max_errors: u64, repair: bool) -> Result<Self> {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos() as u64);
        Self::new(sample_percent, max_errors, repair, seed)
    }

    #[must_use]
    pub const fn sample_percent(&self) -> u8 {
        self.sample_percent
    }

    #[must_use]
    pub const fn max_errors(&self) -> u64 {
        self.max_errors
    }

    /// Whether damaged objects will be repaired from redundancy.
    #[must_use]
    pub const fn repairs(&self) -> bool {
        self.repair
    }

    /// The per-run seed, reported so a sampled run can be replayed exactly.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Whether this plan reads every object.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.sample_percent == SCRUB_FULL_SAMPLE_PERCENT
    }

    /// Whether the error budget can ever be exhausted.
    #[must_use]
    pub const fn is_bounded(&self) -> bool {
        self.max_errors != SCRUB_MAX_ERRORS_UNLIMITED
    }

    /// Whether this object is in the sample.
    ///
    /// A full scrub short-circuits: every object is selected, without hashing
    /// anything, so the common case costs nothing.
    #[must_use]
    pub fn selects(&self, path: &str) -> bool {
        if self.is_full() {
            return true;
        }
        self.bucket(path) < u64::from(self.sample_percent)
    }

    /// Which of the [`SCRUB_SAMPLE_BASIS`] buckets a path falls into.
    fn bucket(&self, path: &str) -> u64 {
        let mut key = [0u8; 32];
        // Domain-separate the key so this selector can never collide with any
        // other keyed hash the tool derives, then mix in the run's seed.
        let context = blake3::hash(SCRUB_SAMPLE_KEY_CONTEXT.as_bytes());
        key.copy_from_slice(context.as_bytes());
        for (slot, byte) in key.iter_mut().zip(self.seed.to_le_bytes()) {
            *slot ^= byte;
        }

        let digest = blake3::keyed_hash(&key, path.as_bytes());
        let mut selector = [0u8; SELECTOR_BYTES];
        selector.copy_from_slice(&digest.as_bytes()[..SELECTOR_BYTES]);
        u64::from_be_bytes(selector) % SCRUB_SAMPLE_BASIS
    }

    /// Whether the run should stop after this many damaged objects.
    #[must_use]
    pub const fn budget_exhausted(&self, errors: u64) -> bool {
        self.is_bounded() && errors >= self.max_errors
    }

    /// How many of `total` objects this plan expects to read.
    ///
    /// An estimate for a pre-flight message — the selector is a hash, so the
    /// realised count varies around it — which is why it is not used to decide
    /// anything.
    ///
    /// No caller yet, and for a reason worth stating: `total` is unknown before
    /// the walk. The walk streams the index one entry at a time
    /// ([`crate::source::Entries`]), so quoting an expected count up front would
    /// mean counting the whole dataset first, purely to print a number. What the
    /// run reports instead is the *realised* coverage, which is a fact rather
    /// than a projection. This becomes callable the day the index can answer
    /// "how many objects are under this prefix" without enumerating them.
    #[allow(dead_code)]
    #[must_use]
    pub const fn expected_objects(&self, total: u64) -> u64 {
        if self.is_full() {
            return total;
        }
        total.saturating_mul(self.sample_percent as u64) / SCRUB_SAMPLE_BASIS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::ExitCode;

    fn paths() -> Vec<String> {
        (0..2000)
            .map(|index| format!("photos/{index}.jpg"))
            .collect()
    }

    #[test]
    fn the_default_plan_reads_everything() {
        let plan = Plan::new(
            SCRUB_FULL_SAMPLE_PERCENT,
            SCRUB_MAX_ERRORS_UNLIMITED,
            false,
            0,
        )
        .unwrap();
        assert!(plan.is_full());
        assert!(!plan.is_bounded());
        for path in paths() {
            assert!(plan.selects(&path));
        }
        assert_eq!(plan.expected_objects(1234), 1234);
    }

    #[test]
    fn a_zero_percent_sample_is_rejected() {
        // It would read nothing and could still print a health grade.
        let error = Plan::new(0, 0, false, 0).unwrap_err();
        assert_eq!(error.code(), ExitCode::Usage);
        assert!(error.hint().is_some());
        assert!(Plan::new(101, 0, false, 0).is_err());
    }

    #[test]
    fn sampling_selects_roughly_the_requested_share() {
        let plan = Plan::new(10, 0, false, 12_345).unwrap();
        let selected = paths().iter().filter(|path| plan.selects(path)).count();
        // 2000 paths at 10%: hash-based selection is not exact, so allow slack.
        assert!(
            (120..=280).contains(&selected),
            "expected about 200 of 2000, got {selected}"
        );
        assert_eq!(plan.expected_objects(2000), 200);
    }

    #[test]
    fn selection_is_stable_within_a_run() {
        // The plan is decided once and must give the same answer every time an
        // object is looked at, or a resumed walk would drift.
        let plan = Plan::new(25, 0, false, 99).unwrap();
        for path in paths() {
            assert_eq!(plan.selects(&path), plan.selects(&path));
        }
    }

    #[test]
    fn a_different_seed_covers_a_different_slice() {
        // The whole reason the selector is keyed: a fixed hash would read the
        // same tenth forever and never scrub the rest.
        let first = Plan::new(10, 0, false, 1).unwrap();
        let second = Plan::new(10, 0, false, 2).unwrap();
        let differing = paths()
            .iter()
            .filter(|path| first.selects(path) != second.selects(path))
            .count();
        assert!(differing > 0, "two seeds selected identical samples");
    }

    #[test]
    fn an_unlimited_budget_never_stops_the_run() {
        let plan = Plan::new(100, SCRUB_MAX_ERRORS_UNLIMITED, false, 0).unwrap();
        assert!(!plan.budget_exhausted(0));
        assert!(!plan.budget_exhausted(1_000_000));
    }

    #[test]
    fn a_bounded_budget_stops_when_it_is_reached() {
        let plan = Plan::new(100, 3, false, 0).unwrap();
        assert!(!plan.budget_exhausted(2));
        assert!(plan.budget_exhausted(3));
        assert!(plan.budget_exhausted(4));
    }

    #[test]
    fn repair_is_carried_as_the_caller_resolved_it() {
        // --dry-run turns repair off before the plan is built, so a plan can
        // never be one call away from writing during a dry run.
        assert!(Plan::new(100, 0, true, 0).unwrap().repairs());
        assert!(!Plan::new(100, 0, false, 0).unwrap().repairs());
    }

    #[test]
    fn a_seeded_plan_validates_the_same_way() {
        assert!(Plan::seeded(100, 0, false).is_ok());
        assert!(Plan::seeded(0, 0, false).is_err());
    }
}
