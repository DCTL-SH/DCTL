//! A sampled verification: per-chunk authenticity at bounded cost.
//!
//! [`Vault::verify_file`](super::Vault::verify_file) reads every chunk and
//! makes the whole-object statement — every tag, the whole-plaintext BLAKE3,
//! the §3 footer, the stored length. This module is the deliberately weaker
//! sibling `--verify sample` promises: read the object's first and last chunks
//! plus a seeded handful of interior ones, authenticate exactly those, and
//! spend backend reads proportional to the sample rather than to the object.
//!
//! ## What a sample honestly proves, and what it cannot
//!
//! Every chunk read here carries a Poly1305 tag over an AAD binding the
//! object's DEK-authenticated head and the chunk's own index, so a clean
//! return means: *the geometry is authentic, the stored length matches it,
//! and the chunks that were read are the writer's bytes.* It deliberately
//! computes **no whole-object statement**: neither the whole-plaintext BLAKE3
//! nor the §3 footer can be evaluated over a subset (the split
//! [`crate::range`] documents), so a corrupt chunk *outside* the sample is
//! not detected, and nothing here pretends otherwise — there is no footer
//! fetch at all, because an uncompared fetch is dead weight that invites a
//! fake comparison later. The caller who needs the whole-object claim runs
//! [`Vault::verify_file`](super::Vault::verify_file); the caller who needs a
//! cheap spot check against bit rot runs this and gets told exactly how many
//! chunks it covered.
//!
//! ## Why head and tail are always in the sample
//!
//! Truncation, torn uploads and length games concentrate at the object's
//! seams. The first and last chunks are therefore not left to chance; the
//! seeded draws cover the interior.
//!
//! ## The selector is replayable
//!
//! Chunk picks derive from a keyed BLAKE3 over `(file_id, draw counter)` with
//! a key mixed from [`VERIFY_SAMPLE_KEY_CONTEXT`] and the run's seed — the
//! construction the CLI's scrub selector already uses for its path buckets.
//! `file_id` comes from the authenticated header, so the same `(seed,
//! samples)` names the same chunks on any machine, and a reported failure can
//! be replayed from the seed alone. The seed only has to differ between runs;
//! nothing about it is a security decision, and the doc on the draw budget
//! says why the loop is bounded.

use std::collections::BTreeSet;

use dctl_crypto::path;

use crate::constants::{
    STREAM_WINDOW_CHUNKS, VERIFY_SAMPLE_DRAW_FACTOR, VERIFY_SAMPLE_DRAW_SLACK,
    VERIFY_SAMPLE_KEY_CONTEXT,
};
use crate::error::Result;

use super::Vault;

/// What a sampled verification should read: `samples` seeded interior chunks
/// on top of the always-read first and last.
#[derive(Clone, Copy, Debug)]
pub struct SamplePlan {
    /// Interior chunks to draw, beyond the mandatory head and tail.
    pub samples: u32,
    /// The run's seed. Recorded by the caller so a failure can be replayed;
    /// see the module doc for why it carries no security weight.
    pub seed: u64,
}

/// What a sampled verification did — the coverage a caller must report,
/// because "verified" without "how much" is the misreport this mode existed
/// to stop making.
#[derive(Clone, Copy, Debug)]
pub struct SampledVerify {
    /// Chunks the object holds, from its authenticated header.
    pub chunks_total: u64,
    /// Chunks this run read and authenticated.
    pub chunks_read: u64,
    /// The seed the picks derived from, echoed for the caller's record.
    pub seed: u64,
}

/// The chunk indices a `(seed, samples)` pair selects for an object.
///
/// Pure and public: a test — or an operator replaying a reported failure —
/// must be able to compute the picks without a vault in hand. Always contains
/// chunk 0 and `chunk_count - 1` (when the object has any chunks at all);
/// interior picks are drawn by keyed-BLAKE3 counter-mod, distinct, and capped
/// at the chunk count.
#[must_use]
pub fn sample_indices(
    seed: u64,
    file_id: &[u8; 16],
    chunk_count: u64,
    samples: u32,
) -> BTreeSet<u64> {
    let mut picked = BTreeSet::new();
    if chunk_count == 0 {
        return picked;
    }
    picked.insert(0);
    picked.insert(chunk_count - 1);

    // The key: BLAKE3 of the context, seed XORed in — the scrub selector's
    // construction, under this module's own domain-separation context.
    let mut key = [0u8; 32];
    key.copy_from_slice(blake3::hash(VERIFY_SAMPLE_KEY_CONTEXT.as_bytes()).as_bytes());
    for (slot, byte) in key.iter_mut().zip(seed.to_le_bytes()) {
        *slot ^= byte;
    }

    let want = u64::from(samples)
        .saturating_add(picked.len() as u64)
        .min(chunk_count);
    let budget = u64::from(samples)
        .saturating_mul(VERIFY_SAMPLE_DRAW_FACTOR)
        .saturating_add(VERIFY_SAMPLE_DRAW_SLACK);
    let mut draw: u64 = 0;
    while (picked.len() as u64) < want && draw < budget {
        let mut material = [0u8; 24];
        material[..16].copy_from_slice(file_id);
        material[16..].copy_from_slice(&draw.to_le_bytes());
        let digest = blake3::keyed_hash(&key, &material);
        let mut selector = [0u8; 8];
        selector.copy_from_slice(&digest.as_bytes()[..8]);
        picked.insert(u64::from_be_bytes(selector) % chunk_count);
        draw = draw.wrapping_add(1);
    }
    picked
}

impl Vault {
    /// Verify a sample of the object at `path`: authenticated geometry, stored
    /// length, and the per-chunk authenticity of the sampled chunks — and
    /// **nothing more**. See the module doc for the honest contract; the
    /// whole-object statement belongs to
    /// [`verify_file`](Vault::verify_file).
    ///
    /// Reads are coalesced into contiguous runs and each run is fetched in
    /// windows of at most [`STREAM_WINDOW_CHUNKS`], so memory stays
    /// `O(window)` however the picks land.
    ///
    /// # Errors
    /// [`CoreError`](crate::CoreError) as
    /// [`verify_file`](Vault::verify_file) reports them: an object that is
    /// not there, a stored length that contradicts the authenticated
    /// geometry, or a sampled chunk that fails authentication.
    #[tracing::instrument(skip(self, plan), fields(backend = self.backend.name()))]
    pub async fn verify_file_sampled(
        &self,
        path: &str,
        plan: &SamplePlan,
    ) -> Result<SampledVerify> {
        let normalized = path::normalize(path)?;
        let reader = self.open_range_reader(&normalized).await?;
        reader.confirm_object_length().await?;

        let chunks_total = reader.chunk_count();
        let picks = sample_indices(plan.seed, reader.file_id(), chunks_total, plan.samples);

        // Contiguous picks become one run — one ranged request where the draw
        // happened to land neighbours — split back into stream-sized windows
        // so a run can never cost more memory than a streaming verify would.
        let mut runs: Vec<(u64, u64)> = Vec::new();
        for &index in &picks {
            match runs.last_mut() {
                Some((first, count)) if first.saturating_add(*count) == index => *count += 1,
                _ => runs.push((index, 1)),
            }
        }

        let mut chunks_read: u64 = 0;
        for (first, count) in runs {
            let mut at = first;
            let mut left = count;
            while left > 0 {
                let take = left.min(STREAM_WINDOW_CHUNKS);
                chunks_read += reader.read_chunks(at, take).await?.len() as u64;
                at = at.saturating_add(take);
                left -= take;
            }
        }

        Ok(SampledVerify {
            chunks_total,
            chunks_read,
            seed: plan.seed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::sample_indices;

    #[test]
    fn the_same_seed_names_the_same_chunks() {
        let id = [7u8; 16];
        assert_eq!(
            sample_indices(42, &id, 1_000, 8),
            sample_indices(42, &id, 1_000, 8),
        );
        assert_ne!(
            sample_indices(42, &id, 1_000, 8),
            sample_indices(43, &id, 1_000, 8),
            "a different seed must be able to pick differently"
        );
    }

    #[test]
    fn head_and_tail_are_never_left_to_chance() {
        let id = [9u8; 16];
        for seed in 0..32 {
            let picks = sample_indices(seed, &id, 65, 2);
            assert!(picks.contains(&0), "seed {seed} skipped the first chunk");
            assert!(picks.contains(&64), "seed {seed} skipped the last chunk");
        }
    }

    #[test]
    fn a_sample_never_exceeds_the_object() {
        let id = [1u8; 16];
        assert!(sample_indices(5, &id, 0, 8).is_empty());
        assert_eq!(sample_indices(5, &id, 1, 8).len(), 1);
        assert_eq!(sample_indices(5, &id, 2, 8).len(), 2);
        // More samples than chunks: every chunk, once.
        let all = sample_indices(5, &id, 4, 64);
        assert_eq!(all.len(), 4);
    }
}
