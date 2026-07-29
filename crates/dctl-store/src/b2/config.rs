//! Backblaze B2 credentials, and the one tunable the bucket carries with them.
//!
//! Not `Debug` — the application key is secret.

use super::constants::{B2_MAX_PART_SIZE, MIN_PART_SIZE};

/// A B2 application key pair.
#[derive(Clone)]
pub struct B2Credentials {
    pub(crate) key_id: String,
    pub(crate) app_key: String,
}

impl B2Credentials {
    #[must_use]
    pub fn new(key_id: impl Into<String>, app_key: impl Into<String>) -> Self {
        Self {
            key_id: key_id.into(),
            app_key: app_key.into(),
        }
    }
}

/// A requested part size brought inside the envelope B2 publishes.
///
/// **Clamped rather than refused**, which is a deliberate asymmetry with how
/// DCTL treats most bad input and the same one the S3 client makes: the failure
/// a refusal would prevent is a configuration file that will not load, while the
/// failure clamping prevents is an upload that is accepted, runs for an hour, and
/// is rejected at the second part because the operator wrote a part size below
/// B2's five-megabyte floor. What is clamped is reported by
/// [`B2Backend::part_size`](super::B2Backend::part_size), so nothing downstream —
/// the plan, the logs, the memory figure — believes the number that was asked
/// for rather than the number that will be sent.
pub(super) fn clamp_part_size(part_size: u64) -> u64 {
    part_size.clamp(MIN_PART_SIZE, B2_MAX_PART_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_part_size_below_b2s_floor_is_raised_to_it() {
        // 1 MiB is a perfectly reasonable-looking number and B2 rejects every
        // part but the last below 5 MB. Raising it is what keeps the upload from
        // failing at the second part.
        assert_eq!(clamp_part_size(1024 * 1024), MIN_PART_SIZE);
        assert_eq!(clamp_part_size(0), MIN_PART_SIZE);
        assert_eq!(clamp_part_size(1), MIN_PART_SIZE);
    }

    #[test]
    fn a_part_size_above_b2s_ceiling_is_lowered_to_it() {
        assert_eq!(clamp_part_size(u64::MAX), B2_MAX_PART_SIZE);
        assert_eq!(
            clamp_part_size(B2_MAX_PART_SIZE + 1),
            B2_MAX_PART_SIZE,
            "one byte over the provider's maximum part is still over it"
        );
    }

    #[test]
    fn a_part_size_inside_the_envelope_is_taken_as_written() {
        // The whole point of the setting: an operator who says 8 MiB because
        // that is what their container can hold gets 8 MiB, not a default.
        for asked in [MIN_PART_SIZE, 8 * 1024 * 1024, B2_MAX_PART_SIZE] {
            assert_eq!(clamp_part_size(asked), asked);
        }
    }
}
