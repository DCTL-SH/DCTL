//! DSF1 per-item metadata — the `enc_metadata` plaintext (§4). Positional, with a
//! trailing extension region for forward growth.

use crate::constants::{META_FLAG_TOMBSTONE, META_MIN_PLAINTEXT_LEN, META_SCHEMA_V1};
use crate::error::{CryptoError, Result};

/// Per-item metadata. `path_hint` is advisory (authoritative path lives in the name
/// record, §5) and MUST be NFC-normalized UTF-8 obeying every §5 path rule; the caller
/// is responsible for normalization/validation.
#[derive(Clone, Debug)]
pub struct Metadata {
    pub flags: u8,
    /// The content's last-modified time in whole unix seconds, or `0` for
    /// "not recorded".
    ///
    /// The sentinel is the field's original value and predates anything writing
    /// to it, so every object sealed before that carries a zero here. Reading one
    /// back as `1970-01-01T00:00:00Z` would put a fabricated timestamp on every
    /// such object — the exact substitution `dctl_core::Modified::Unknown`
    /// documents as worse than no answer, because the epoch makes every file look
    /// older than every other file and inverts an `--update` comparison. So `0`
    /// means absent, at the cost of mis-describing a file genuinely modified at
    /// the epoch as undated. That file is re-transferred once; the alternative
    /// mis-dates every object DCTL has ever written.
    pub mtime_unix: i64,
    pub birthtime_unix: i64,
    pub size: u64,
    pub content_blake3: [u8; 32],
    pub metadata_gen: u64,
    pub mode: u32,
    pub path_hint: String,
    pub content_type: Option<String>,
    pub ext: Vec<u8>,
}

impl Metadata {
    /// A minimal metadata record for a file at `path_hint` (size/hash filled by seal).
    #[must_use]
    pub fn new(path_hint: impl Into<String>) -> Self {
        Self {
            flags: 0,
            mtime_unix: 0,
            birthtime_unix: 0,
            size: 0,
            content_blake3: [0u8; 32],
            metadata_gen: 0,
            mode: 0,
            path_hint: path_hint.into(),
            content_type: None,
            ext: Vec::new(),
        }
    }

    /// Record the content's last-modified time, in whole unix seconds.
    ///
    /// `None` leaves the [`mtime_unix`](Self::mtime_unix) sentinel in place — see
    /// that field for why zero means "not recorded" rather than "the epoch".
    ///
    /// This exists because the field was declared, sealed into every object and
    /// never written to. The time lived only in the local index, so an index
    /// rebuilt from the backend could recover a file's name, its bytes and its
    /// hash but not the one fact that says when it was last changed — and a tree
    /// restored from it read as entirely rewritten to anything that sorts or
    /// syncs by date. Populating a field the §4 schema already reserves is not a
    /// format change: the layout is unaltered and an older reader parses it
    /// exactly as before.
    #[must_use]
    pub const fn with_mtime(mut self, unix: Option<i64>) -> Self {
        if let Some(seconds) = unix {
            self.mtime_unix = seconds;
        }
        self
    }

    /// Whether a modification time was recorded, and which.
    ///
    /// The reader's half of [`with_mtime`](Self::with_mtime): the sentinel comes
    /// back as [`None`] rather than as a date in 1970.
    #[must_use]
    pub const fn recorded_mtime(&self) -> Option<i64> {
        if self.mtime_unix == 0 {
            None
        } else {
            Some(self.mtime_unix)
        }
    }

    fn is_tombstone(&self) -> bool {
        self.flags & META_FLAG_TOMBSTONE != 0
    }
}

/// Serialize metadata to its §4 plaintext bytes.
pub fn build_metadata(m: &Metadata) -> Result<Vec<u8>> {
    let path = m.path_hint.as_bytes();
    if !m.is_tombstone() && path.is_empty() {
        return Err(CryptoError::Format(
            "path_hint required for non-tombstone object".into(),
        ));
    }
    let path_len: u16 = path
        .len()
        .try_into()
        .map_err(|_| CryptoError::Format("path_hint too long".into()))?;
    let ct_bytes = m.content_type.as_deref().unwrap_or("").as_bytes();
    let ct_len: u16 = ct_bytes
        .len()
        .try_into()
        .map_err(|_| CryptoError::Format("content_type too long".into()))?;
    let ext_len: u16 = m
        .ext
        .len()
        .try_into()
        .map_err(|_| CryptoError::Format("ext too long".into()))?;

    let mut out =
        Vec::with_capacity(META_MIN_PLAINTEXT_LEN + path.len() + ct_bytes.len() + m.ext.len());
    out.push(META_SCHEMA_V1);
    out.push(m.flags);
    out.extend_from_slice(&m.mtime_unix.to_le_bytes());
    out.extend_from_slice(&m.birthtime_unix.to_le_bytes());
    out.extend_from_slice(&m.size.to_le_bytes());
    out.extend_from_slice(&m.content_blake3);
    out.extend_from_slice(&m.metadata_gen.to_le_bytes());
    out.extend_from_slice(&m.mode.to_le_bytes());
    out.extend_from_slice(&path_len.to_le_bytes());
    out.extend_from_slice(path);
    out.extend_from_slice(&ct_len.to_le_bytes());
    out.extend_from_slice(ct_bytes);
    out.extend_from_slice(&ext_len.to_le_bytes());
    out.extend_from_slice(&m.ext);
    Ok(out)
}

/// Parse §4 metadata plaintext (schema `0x01`). Verifies `76 + P + T + E == len`.
pub fn parse_metadata(bytes: &[u8]) -> Result<Metadata> {
    if bytes.len() < META_MIN_PLAINTEXT_LEN {
        return Err(CryptoError::Format("metadata too short".into()));
    }
    if bytes[0] != META_SCHEMA_V1 {
        return Err(CryptoError::Format(
            "unexpected metadata schema_version".into(),
        ));
    }
    let flags = bytes[1];
    let mtime_unix = read_i64(&bytes[2..10])?;
    let birthtime_unix = read_i64(&bytes[10..18])?;
    let size = read_u64(&bytes[18..26])?;
    let mut content_blake3 = [0u8; 32];
    content_blake3.copy_from_slice(&bytes[26..58]);
    let metadata_gen = read_u64(&bytes[58..66])?;
    let mode = u32::from_le_bytes([bytes[66], bytes[67], bytes[68], bytes[69]]);
    let path_len = u16::from_le_bytes([bytes[70], bytes[71]]) as usize;

    let p_start: usize = 72;
    let p_end = p_start
        .checked_add(path_len)
        .ok_or_else(|| CryptoError::Format("path overruns".into()))?;
    if p_end + 2 > bytes.len() {
        return Err(CryptoError::Format("metadata truncated (ct_len)".into()));
    }
    let path_hint = String::from_utf8(bytes[p_start..p_end].to_vec())
        .map_err(|_| CryptoError::Format("path_hint not UTF-8".into()))?;

    let ct_len = u16::from_le_bytes([bytes[p_end], bytes[p_end + 1]]) as usize;
    let ct_start = p_end + 2;
    let ct_end = ct_start
        .checked_add(ct_len)
        .ok_or_else(|| CryptoError::Format("content_type overruns".into()))?;
    if ct_end + 2 > bytes.len() {
        return Err(CryptoError::Format("metadata truncated (ext_len)".into()));
    }
    let content_type = if ct_len == 0 {
        None
    } else {
        Some(
            String::from_utf8(bytes[ct_start..ct_end].to_vec())
                .map_err(|_| CryptoError::Format("content_type not UTF-8".into()))?,
        )
    };

    let ext_len = u16::from_le_bytes([bytes[ct_end], bytes[ct_end + 1]]) as usize;
    let ext_start = ct_end + 2;
    let ext_end = ext_start
        .checked_add(ext_len)
        .ok_or_else(|| CryptoError::Format("ext overruns".into()))?;
    if ext_end != bytes.len() {
        return Err(CryptoError::Format(
            "metadata length != 76 + P + T + E".into(),
        ));
    }
    let ext = bytes[ext_start..ext_end].to_vec();

    let md = Metadata {
        flags,
        mtime_unix,
        birthtime_unix,
        size,
        content_blake3,
        metadata_gen,
        mode,
        path_hint,
        content_type,
        ext,
    };
    if !md.is_tombstone() && md.path_hint.is_empty() {
        return Err(CryptoError::Format(
            "path_hint required for non-tombstone object".into(),
        ));
    }
    Ok(md)
}

fn read_i64(b: &[u8]) -> Result<i64> {
    let arr: [u8; 8] = b
        .try_into()
        .map_err(|_| CryptoError::Format("bad i64 field".into()))?;
    Ok(i64::from_le_bytes(arr))
}
fn read_u64(b: &[u8]) -> Result<u64> {
    let arr: [u8; 8] = b
        .try_into()
        .map_err(|_| CryptoError::Format("bad u64 field".into()))?;
    Ok(u64::from_le_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_time_survives_the_round_trip_through_the_wire_bytes() {
        // The field is positional and fixed-width, so an offset slip shows up
        // here rather than as a vault full of files dated 1970.
        let meta = Metadata::new("photos/a.jpg").with_mtime(Some(1_551_675_967));
        let parsed = parse_metadata(&build_metadata(&meta).expect("builds")).expect("parses");
        assert_eq!(parsed.recorded_mtime(), Some(1_551_675_967));
    }

    #[test]
    fn an_object_that_recorded_no_time_reads_back_as_absent_not_as_the_epoch() {
        // The whole reason `recorded_mtime` exists. Every object sealed before
        // anything wrote this field carries `0`, and an index rebuilt from those
        // objects would otherwise stamp the entire vault `1970-01-01T00:00:00Z` —
        // a fabricated fact, which makes every file look older than every other
        // file and inverts an `--update` comparison.
        let never_set = Metadata::new("legacy.bin");
        assert_eq!(never_set.mtime_unix, 0, "the sentinel is the default");
        assert_eq!(never_set.recorded_mtime(), None);

        // And `None` must leave the sentinel rather than write something over it.
        assert_eq!(Metadata::new("f").with_mtime(None).recorded_mtime(), None);

        let parsed = parse_metadata(&build_metadata(&never_set).expect("builds")).expect("parses");
        assert_eq!(parsed.recorded_mtime(), None);
    }

    #[test]
    fn a_time_before_the_epoch_is_recorded_rather_than_mistaken_for_absence() {
        // A restored archive legitimately holds pre-1970 timestamps. Only the
        // exact zero is the sentinel; a negative second is a real answer and must
        // survive the signed round trip.
        let meta = Metadata::new("archive/old.txt").with_mtime(Some(-86_400));
        let parsed = parse_metadata(&build_metadata(&meta).expect("builds")).expect("parses");
        assert_eq!(parsed.recorded_mtime(), Some(-86_400));
    }
}
