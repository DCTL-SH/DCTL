//! Cross-device restore: rebuild the local index from the backend's authoritative
//! §5 name records.
//!
//! Everything a read needs lives in the shared backend — the wrapped root (envelope),
//! the path→object map (`n/*` name records), and self-describing objects (`o/*`) that
//! embed their own DEK + metadata. So a wiped or brand-new device can recover the whole
//! vault with only the password: `unlock`, then [`Vault::rebuild_index`], and every
//! path is listable and readable. No other local state is ever required.
//!
//! ## Why the rebuild reads two things per file and not one
//!
//! It used to read only the name record, which gave it the path and the object
//! key and nothing else. Every row it wrote carried `size: 0`, no modification
//! time and an empty content hash, and **nothing ever filled them in** — `cat`,
//! `hashsum` and a whole `scrub` all left the row exactly as unmeasured as they
//! found it, because each of them measures the object and answers from that
//! rather than writing back. Only storing the file again recorded them.
//!
//! The damage was not cosmetic. `dctl check` cannot compare a row that carries no
//! size and no hash; `dctl size` reports a lower bound in the shape of a total;
//! `dctl sync` sees every file as changed and re-uploads the entire dataset. A
//! recovered machine was therefore *quietly* worse than a working one, and the
//! only signal was one warning at the top of the rebuild.
//!
//! The information was never expensive. Size, modification time and the whole
//! plaintext's BLAKE3 are all fields of the object's **own header**, sealed under
//! its DEK and cross-checked against the head — the same bounded read a mounted
//! vault performs to answer `getattr`, which is how a FUSE mount could report
//! correct sizes for the very objects a rebuild had just written zeroes for. So
//! the rebuild now costs one ranged header read per object on top of the name
//! record it already fetched: roughly twice the requests, a bounded few kilobytes
//! each, against a full read of the dataset that nobody ever proposed.
//!
//! There is no flag to go back. A flag whose only effect is to reproduce the
//! broken state is a way to build a half-index by accident, and an index that
//! describes only some of its rows is not a cheaper rebuild — it is the defect
//! with a switch on it.
//!
//! ## An object that cannot be described does not stop the rebuild
//!
//! The mapping is the recovery story, so the row is written either way and the
//! file stays listable and readable. What changes is that the rebuild **counts**
//! the rows it could not describe, because there are only two reasons for one:
//! the object the name record points at is not at the provider, or its metadata
//! is a schema this build does not parse. Both are facts an operator needs before
//! they trust a recovered index, and both were previously invisible until
//! somebody tried to read the file.

use dctl_crypto::constants::{KEM_ID_HYBRID, KEM_ID_NONE};
use dctl_crypto::object;
use dctl_index::Record;
use dctl_store::ObjectKey;

use super::{Vault, layout};
use crate::error::{CoreError, Result};
use crate::range;

/// What one rebuild recovered.
///
/// Three numbers rather than one, because "10 files" was equally true of a
/// rebuild that produced ten rows nothing could compare, and a caller that can
/// only report a count cannot tell an operator which of the two they now have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rebuilt {
    /// Rows written — every name record this vault could decrypt.
    pub files: u64,
    /// Rows carrying size, modification time and content hash, taken from each
    /// object's own authenticated header.
    pub measured: u64,
    /// Rows whose object could not be described: absent at the provider, or
    /// sealed with a metadata schema this build does not parse. The path is still
    /// mapped and still readable; only its measurements are missing.
    pub unmeasured: u64,
}

/// What an object's own header says about the file it holds.
struct Described {
    size: u64,
    modified_unix: Option<i64>,
    content_hash: Vec<u8>,
}

impl Described {
    /// The row for an object nothing could be read from. Zero is not a claim
    /// about the file here — [`Rebuilt::unmeasured`] counts it, and the caller
    /// says so — it is what an unmeasured row has always looked like.
    const fn unmeasured() -> Self {
        Self {
            size: 0,
            modified_unix: None,
            content_hash: Vec::new(),
        }
    }
}

impl Vault {
    /// Rebuild the local index by enumerating and decrypting every `n/*` name record
    /// in the backend (§5), describing each object from its own header.
    ///
    /// Idempotent — existing rows are overwritten with the authoritative mapping. A
    /// name record that cannot be decrypted (e.g. belongs to a different vault under a
    /// shared bucket) is skipped with a warning rather than aborting the rebuild, and an
    /// object whose header cannot be read leaves a mapped-but-unmeasured row counted in
    /// [`Rebuilt::unmeasured`] rather than ending the run.
    ///
    /// Costs one listing, one `get` per name record and one **bounded ranged** read
    /// per object — never a read of an object's payload, however large it is.
    #[tracing::instrument(skip(self), fields(backend = self.backend.name()))]
    pub async fn rebuild_index(&self) -> Result<Rebuilt> {
        let mut cursor: Option<String> = None;
        let mut rebuilt = Rebuilt::default();
        loop {
            let page = self
                .backend
                .list_page(layout::NAME_KEY_PREFIX, cursor)
                .await?;
            for item in &page.items {
                let name_key = item.key.as_str();
                let value = self.backend.get(&item.key).await?;
                let record = match self.name_keys.open_record(
                    &self.vault_id,
                    name_key,
                    value.as_ref(),
                ) {
                    Ok(record) => record,
                    Err(e) => {
                        tracing::warn!(key = name_key, error = %e, "skipping unreadable name record");
                        continue;
                    }
                };
                let object_key = ObjectKey::new(format!(
                    "{}{}",
                    layout::OBJECT_KEY_PREFIX,
                    hex::encode(record.file_id)
                ));

                let described = match self.describe(&object_key, &record.path).await {
                    Ok(described) => {
                        rebuilt.measured += 1;
                        described
                    }
                    Err(e) => {
                        // WARN and keep going. The mapping is what makes the file
                        // readable at all, so writing the row is strictly better
                        // than dropping it; the count is what stops the run
                        // reporting a complete index it does not have.
                        tracing::warn!(
                            path = %record.path,
                            object = %object_key,
                            error = %e,
                            "indexed the path but could not describe its object"
                        );
                        rebuilt.unmeasured += 1;
                        Described::unmeasured()
                    }
                };

                self.index.put(&Record {
                    path: record.path,
                    object_key: object_key.to_string(),
                    size: described.size,
                    modified_unix: described.modified_unix,
                    content_hash: described.content_hash,
                })?;
                rebuilt.files += 1;
            }
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        tracing::info!(
            files = rebuilt.files,
            measured = rebuilt.measured,
            unmeasured = rebuilt.unmeasured,
            "rebuilt index from backend name records"
        );
        Ok(rebuilt)
    }

    /// Read one object's authenticated header and take the three facts a row needs.
    ///
    /// The same decode [`Vault::open_range_reader`](crate::Vault::open_range_reader)
    /// performs, minus the path resolution the rebuild has already done: the object
    /// key comes from the name record in hand, so nothing here consults the index it
    /// is in the middle of writing.
    ///
    /// Both `kem_id` paths are handled, because a vault may hold objects sealed to
    /// it as a §12 recipient as well as ones it sealed itself, and a rebuild that
    /// could only describe the second kind would report the first as damaged.
    async fn describe(&self, key: &ObjectKey, path: &str) -> Result<Described> {
        let (prefix, header_len) = range::fetch_header(self.backend.as_ref(), key, path).await?;
        let described_head = object::parse_head(&prefix)?;
        // A rebuild takes the key from a §5 name record and the bytes from the
        // backend. If they disagree, the record is describing something it did
        // not name, and indexing it would write that disagreement into the index
        // as though it were a fact.
        super::get::require_object_identity(key.as_str(), &described_head)?;
        let header = match described_head.kem_id {
            KEM_ID_NONE => object::RangeHeader::open(self.root()?, &prefix[..header_len])?,
            KEM_ID_HYBRID => {
                let kw = self.recover_object_kw(&prefix).await?;
                object::RangeHeader::open_with_kw(&kw, &prefix[..header_len])?
            }
            // `parse_head` already rejects any other `kem_id`; keep the match total
            // without a panic (lib code never panics).
            other => {
                return Err(CoreError::Crypto(dctl_crypto::CryptoError::Format(
                    format!("unsupported kem_id {other}"),
                )));
            }
        };

        // The length comes from the head, which the DEK unwrap authenticated in
        // full, and the metadata decode has already enforced `meta.size ==
        // plaintext_len` — so this is established rather than reported.
        let size = header.plaintext_len();
        // A metadata schema this build does not parse (`crates/dctl-decode/FORMAT.md` §8) is
        // served, not refused, so the size is still recorded and only the time and the hash
        // are absent.
        let Some(meta) = header.metadata() else {
            return Ok(Described {
                size,
                ..Described::unmeasured()
            });
        };
        Ok(Described {
            // `recorded_mtime`, never the raw field. An object sealed before
            // anything wrote that field carries `0`, and reading it as a time
            // would stamp every such file `1970-01-01T00:00:00Z` — a fabricated
            // fact, and the one substitution `Modified::Unknown` exists to
            // refuse. Absent is the honest answer for an object that never
            // recorded one.
            modified_unix: meta.recorded_mtime(),
            size,
            content_hash: meta.content_blake3.to_vec(),
        })
    }
}
