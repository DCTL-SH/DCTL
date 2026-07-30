//! The vault's chunk size: what it costs, and how an operator sets it.
//!
//! It was §11.3 item 8's remaining half. `chunk_size` is declared on five
//! provider definitions in the configuration, is documented in
//! `dctl config providers`, and until this module was **read by nothing on a
//! `vault` remote**: an operator could write `chunk_size = 262144`, see it in
//! `dctl config show`, and have every object sealed at the compiled-in default
//! anyway. That is the §13 defect — a setting that parses, is documented, and
//! reaches nothing — on the configuration surface rather than the flag surface.
//!
//! The B2 half was closed in §25 because on B2 the part size *is* an upload's
//! peak memory. This half is closed for the same kind of reason: since the
//! streaming write, the sealer's own buffers are a term in the peak
//! ([`put_stream`](super::put_stream)) rather than a detail of a temporary file
//! nobody measured.
//!
//! ## What the number does
//!
//! `chunk_size` is the plaintext bytes per AEAD chunk (`FORMAT.md` §3), and it is
//! three things at once:
//!
//! * **Two terms of the write's peak.** The sealer holds one scratch buffer and
//!   the ciphertext it produces from it, so it costs `2 × chunk_size`.
//! * **The granularity of a seek.** A read that wants one byte must fetch,
//!   authenticate and discard the whole chunk containing it, so a smaller chunk
//!   makes `dctl mount` cheaper on a random-access workload and a larger one
//!   makes a sequential read cheaper in requests.
//! * **The tag overhead.** Every chunk carries a 16-byte Poly1305 tag, so an
//!   object's stored size is its plaintext plus `16 × ceil(len / chunk_size)`.
//!   At the 1 MiB default that is fifteen parts per million; at the 4 KiB floor
//!   it is four parts per thousand, which is a real bill on a large archive.
//!
//! ## Why it is clamped and not refused
//!
//! The same argument B2's part size settled on (§25.3): the failure a refusal
//! prevents is a configuration file that will not load, and the failure clamping
//! prevents is an object sealed at a size the format cannot hold — which is
//! discovered when somebody tries to read it. A value outside the envelope is
//! logged at the size actually in force, so an operator who wrote something
//! unusable is told what they got rather than left to measure it.
//!
//! ## What it does **not** change
//!
//! Anything already stored. `chunk_size` is written into each object's head by
//! whoever sealed it and every reader takes the object's own value, so lowering
//! this setting affects the next write and nothing before it. That is a property
//! of the format and it is why this is safe to change on a live vault.

use dctl_crypto::constants::{DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE};

use super::Vault;

/// The smallest chunk this build will seal with.
///
/// 4 KiB — one page, and the size below which the per-chunk tag stops being
/// overhead and starts being the object. At 4 KiB an object is already 0.4%
/// bigger than its plaintext and needs one AEAD open per page on every read;
/// halving it again doubles both. It is a floor rather than a refusal for the
/// reason the module documents, and it is named here rather than left as the
/// format's `chunk_size != 0` because "legal" and "a size anybody should choose"
/// are different questions.
pub const MIN_CHUNK_SIZE: u32 = 4 * 1024;

/// The chunk size a value of `requested` will actually seal with.
///
/// Pure, and separate from [`Vault::with_chunk_size`] so the envelope is
/// assertable without a vault, a backend or a password — which matters, because
/// the middle of a setting's journey is where this project has lost one before
/// (§21.7: a meter installed in one arm of `registry::build` and silently dropped
/// in four).
#[must_use]
pub fn clamp_chunk_size(requested: Option<u64>) -> u32 {
    let Some(requested) = requested else {
        return DEFAULT_CHUNK_SIZE;
    };
    // Saturating rather than wrapping: a `chunk_size` larger than a `u32` is a
    // configuration somebody meant as "as large as possible", and the ceiling is
    // what that means here.
    let requested = u32::try_from(requested).unwrap_or(u32::MAX);
    requested.clamp(MIN_CHUNK_SIZE, MAX_CHUNK_SIZE)
}

impl Vault {
    /// The same vault, sealing subsequent writes in `requested`-byte chunks.
    ///
    /// A builder rather than a constructor argument, for the reason every other
    /// builder in this workspace is one: a vault is made by `init` or `unlock`
    /// from key material, and the dozens of internal constructions that want the
    /// default should not each have to name it. Only the CLI, which holds the
    /// remote's configuration, has anything to say.
    ///
    /// `None` leaves the default. A value outside the envelope is **clamped and
    /// logged**, not refused — see the module documentation for why.
    #[must_use]
    pub fn with_chunk_size(mut self, requested: Option<u64>) -> Self {
        let effective = clamp_chunk_size(requested);
        if let Some(requested) = requested {
            if u64::from(effective) != requested {
                tracing::warn!(
                    requested,
                    effective,
                    min = MIN_CHUNK_SIZE,
                    max = MAX_CHUNK_SIZE,
                    "chunk_size is outside the range this build seals with; \
                     the nearest usable size is in force"
                );
            } else {
                tracing::debug!(effective, "chunk_size in force for new objects");
            }
        }
        self.chunk_size = effective;
        self
    }

    /// The chunk size this vault will seal its next object with.
    ///
    /// Public because it is the far end of the setting's journey, and because a
    /// figure the program will not state is a figure that drifts from the code —
    /// the same argument `B2Backend::upload_peak_bytes` makes for the part size.
    /// It is what the resolver's test reads back.
    #[must_use]
    pub const fn chunk_size(&self) -> u32 {
        self.chunk_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_setting_leaves_the_default() {
        assert_eq!(clamp_chunk_size(None), DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn a_value_inside_the_envelope_is_taken_exactly() {
        for bytes in [
            u64::from(MIN_CHUNK_SIZE),
            256 * 1024,
            u64::from(DEFAULT_CHUNK_SIZE),
            4 * 1024 * 1024,
            u64::from(MAX_CHUNK_SIZE),
        ] {
            assert_eq!(u64::from(clamp_chunk_size(Some(bytes))), bytes);
        }
    }

    #[test]
    fn a_value_outside_the_envelope_is_clamped_rather_than_refused() {
        // Refusing would mean a configuration file that will not load; clamping
        // means an object that seals. Both ends, including the two a `u32` cannot
        // hold at all.
        assert_eq!(clamp_chunk_size(Some(1)), MIN_CHUNK_SIZE);
        assert_eq!(clamp_chunk_size(Some(0)), MIN_CHUNK_SIZE);
        assert_eq!(clamp_chunk_size(Some(u64::MAX)), MAX_CHUNK_SIZE);
        assert_eq!(
            clamp_chunk_size(Some(u64::from(MAX_CHUNK_SIZE) + 1)),
            MAX_CHUNK_SIZE
        );
    }

    #[test]
    fn the_envelope_is_one_the_format_accepts() {
        // The clamp exists to keep every value sealable. A floor below the
        // format's `chunk_size != 0`, or a ceiling above `MAX_CHUNK_SIZE`, would
        // produce an object no reader could parse — which is exactly the failure
        // clamping is here to prevent rather than to cause.
        const {
            assert!(MIN_CHUNK_SIZE > 0);
            assert!(MIN_CHUNK_SIZE <= DEFAULT_CHUNK_SIZE);
            assert!(DEFAULT_CHUNK_SIZE <= MAX_CHUNK_SIZE);
        }
    }
}
