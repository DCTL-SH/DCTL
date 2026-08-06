//! The encrypted spill a file being written through a mount lives in.
//!
//! ## Why a spill exists at all
//!
//! A vault object is sealed in one pass: the format hashes the whole plaintext,
//! lays out its frames, and writes a header that commits to the result. A file
//! arriving through a filesystem does not work that way — the kernel delivers
//! arbitrary writes at arbitrary offsets, in any order, and only says the file
//! is finished when it is closed. So the bytes have to go somewhere until then.
//!
//! ## Why that somewhere is encrypted
//!
//! Because the alternative was measured. A widely-used sync tool's VFS cache
//! holds decrypted plaintext on local disk while a file is open: a canary
//! written through its encrypted remote was read straight out of the cache
//! directory in the clear, while the remote itself held only ciphertext. A
//! product whose claim is that data is encrypted before it leaves the machine
//! cannot leave a plaintext copy sitting in a temporary directory for the
//! lifetime of an open file handle.
//!
//! So every frame here is sealed under a key that exists only in this process's
//! memory and is never written anywhere. If the machine loses power, the spill
//! that survives on disk is undecryptable by anyone, including this program.
//! That is the intended outcome: an interrupted write must lose the write, not
//! leak it.
//!
//! ## What protects what
//!
//! - **Confidentiality at rest.** Each frame is XChaCha20-Poly1305 with a fresh
//!   random nonce chosen by [`aead::encrypt`] on every write. Rewriting a frame
//!   re-seals it under a new nonce, so the same slot written twice never reuses
//!   one — the failure that breaks this cipher outright.
//! - **Integrity and position.** The frame's index is the AAD, so a frame cannot
//!   be moved, duplicated or swapped with another frame of the same file without
//!   the tag failing. A torn or reordered spill is detected, not decoded.
//! - **What it does NOT protect.** An attacker who can read this process's
//!   memory has the key, and one who can attach a debugger has the plaintext.
//!   This defends against a stolen disk, another user on the machine, a backup
//!   that sweeps up temporary files, and a crash that leaves the spill behind.
//!   It is not a defence against a live adversary already inside the process,
//!   and nothing at this layer could be.
//!
//! ## The shape on disk
//!
//! Fixed-size slots so a random-access write does not have to rewrite the file:
//!
//! ```text
//!   slot i  at  i * SLOT_LEN
//!   SLOT_LEN = NONCE_LEN + FRAME_LEN + TAG_LEN
//! ```
//!
//! The last frame is short in *plaintext* terms but occupies a whole slot; the
//! logical length is held in memory rather than on disk, because the spill is
//! never read by a different process — the key would be gone.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};

use dctl_crypto::aead;
use zeroize::Zeroizing;

use crate::error::{CliError, Result};
use crate::exit::ExitCode;

/// Plaintext bytes per frame.
///
/// 64 KiB is a compromise between two costs that pull opposite ways: a write
/// that touches part of a frame must read, decrypt, patch, re-seal and write the
/// whole frame, which argues for small frames; and every frame carries a 24-byte
/// nonce and a 16-byte tag, which argues for large ones. At 64 KiB the overhead
/// is 0.06% and a one-byte write rewrites 64 KiB rather than a megabyte.
pub const FRAME_LEN: usize = 64 * 1024;

/// Bytes an [`aead::encrypt`] blob adds around its plaintext: the nonce it
/// chose, and the tag it computed.
const OVERHEAD: usize = 24 + 16;

/// Bytes one frame occupies on disk, whatever its plaintext length.
const SLOT_LEN: u64 = (FRAME_LEN + OVERHEAD) as u64;

/// Bytes the sealed blob for frame `index` occupies, given a plaintext length.
///
/// A slot is fixed-width so that a random-access write does not have to move
/// anything, but the blob inside the last slot is short. Deriving the length
/// rather than reading to the end of the slot is what stops zero padding — left
/// behind by a truncate that shortened the file — from being fed to the cipher
/// as though it were part of the tag.
fn blob_len(index: u64, plaintext_len: u64) -> usize {
    let start = index * FRAME_LEN as u64;
    if start >= plaintext_len {
        return 0;
    }
    let plain = (plaintext_len - start).min(FRAME_LEN as u64) as usize;
    plain + OVERHEAD
}

fn io_error(what: &str, error: &io::Error) -> CliError {
    CliError::new(
        ExitCode::FatalError,
        format!("the write spill could not be {what}: {error}"),
    )
}

fn crypto_error(what: &str) -> CliError {
    CliError::new(
        ExitCode::FatalError,
        format!(
            "the write spill failed to {what}. The spill is sealed under a key \
             held only in this process, so this means the file on disk was \
             altered or truncated underneath us; nothing has been written to \
             the vault."
        ),
    )
}

/// A file being written, held encrypted until it is sealed into the vault.
pub struct Spill {
    file: File,
    /// Ephemeral, memory-only, and never written to disk or logged. Dropped —
    /// and zeroized — with the spill, which is what makes the file on disk
    /// worthless the moment this process ends.
    key: Zeroizing<[u8; 32]>,
    /// Plaintext length, which the slots on disk cannot express because the last
    /// one is padded out to a whole slot.
    len: u64,
}

impl Spill {
    /// Create an empty spill backed by `file`.
    ///
    /// The caller supplies the file so that it can decide where it lives and,
    /// on platforms that allow it, unlink it before anything is written to it.
    ///
    /// # Errors
    /// Never fails today; the signature is fallible so that a future backing
    /// store which can fail to initialise does not change every call site.
    pub fn new(file: File) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; 32]);
        dctl_crypto::rng::fill(key.as_mut_slice());
        Ok(Self { file, key, len: 0 })
    }

    /// Plaintext length.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether nothing has been written.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Read one frame's plaintext, or an empty vector past the end.
    fn read_frame(&mut self, index: u64) -> Result<Zeroizing<Vec<u8>>> {
        let want = blob_len(index, self.len);
        if want == 0 {
            return Ok(Zeroizing::new(Vec::new()));
        }
        let mut blob = vec![0u8; want];
        self.file
            .seek(SeekFrom::Start(index * SLOT_LEN))
            .map_err(|e| io_error("sought", &e))?;
        let got = read_full(&mut self.file, &mut blob).map_err(|e| io_error("read", &e))?;
        if got < want {
            return Ok(Zeroizing::new(Vec::new()));
        }
        // The frame index is the AAD, so a frame lifted from elsewhere in the
        // file — or from another spill — fails to open rather than decoding as
        // somebody else's data at the wrong offset.
        aead::decrypt(&self.key, &blob, &index.to_le_bytes())
            .map_err(|_| crypto_error("open a frame"))
    }

    /// Seal `plaintext` into slot `index`, replacing whatever was there.
    fn write_frame(&mut self, index: u64, plaintext: &[u8]) -> Result<()> {
        // A fresh nonce every time, chosen inside `encrypt`. This is the whole
        // reason a frame is re-sealed rather than patched in place: reusing a
        // nonce with a different plaintext under the same key would leak both.
        let blob = aead::encrypt(&self.key, plaintext, &index.to_le_bytes())
            .map_err(|_| crypto_error("seal a frame"))?;
        debug_assert!(blob.len() as u64 <= SLOT_LEN);
        self.file
            .seek(SeekFrom::Start(index * SLOT_LEN))
            .map_err(|e| io_error("sought", &e))?;
        self.file
            .write_all(&blob)
            .map_err(|e| io_error("written", &e))?;
        Ok(())
    }

    /// Write `data` at `offset`, extending the file if it reaches past the end.
    ///
    /// # Errors
    /// Whatever the spill file reported, or a sealing failure.
    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        // Seal zero frames across any gap this write skips over. Leaving them
        // unwritten would make a hole indistinguishable from a corrupted frame,
        // and the reader must be free to treat a failed tag as tampering.
        if offset > self.len {
            let gap_start = self.len;
            let zeros = vec![0u8; FRAME_LEN];
            let mut at = gap_start;
            while at < offset {
                let index = at / FRAME_LEN as u64;
                let within = (at % FRAME_LEN as u64) as usize;
                let take = (FRAME_LEN - within).min((offset - at) as usize);
                let mut frame = self.read_frame(index)?.to_vec();
                if frame.len() < within + take {
                    frame.resize(within + take, 0);
                }
                frame[within..within + take].copy_from_slice(&zeros[..take]);
                self.write_frame(index, &frame)?;
                at += take as u64;
            }
            self.len = offset;
        }

        let mut written = 0usize;
        while written < data.len() {
            let position = offset + written as u64;
            let index = position / FRAME_LEN as u64;
            let within = (position % FRAME_LEN as u64) as usize;
            let take = (FRAME_LEN - within).min(data.len() - written);

            // Read–modify–write, because a frame is sealed as a unit: a partial
            // overwrite has to be re-sealed with the bytes it did not touch.
            let mut frame = self.read_frame(index)?.to_vec();
            if frame.len() < within + take {
                frame.resize(within + take, 0);
            }
            frame[within..within + take].copy_from_slice(&data[written..written + take]);
            self.write_frame(index, &frame)?;

            written += take;
            self.len = self.len.max(position + take as u64);
        }
        Ok(())
    }

    /// Shorten or extend the plaintext to `len`, zero-filling any gap.
    ///
    /// # Errors
    /// Whatever the spill file reported, or a sealing failure.
    pub fn truncate(&mut self, len: u64) -> Result<()> {
        if len < self.len {
            // Re-seal the frame the cut lands in so the bytes after the cut are
            // gone from the ciphertext, not merely unreachable by length.
            let index = len / FRAME_LEN as u64;
            let keep = (len % FRAME_LEN as u64) as usize;
            let frame = self.read_frame(index)?;
            let kept = frame.get(..keep.min(frame.len())).unwrap_or(&[]).to_vec();
            self.write_frame(index, &kept)?;
            let slots = len.div_ceil(FRAME_LEN as u64);
            self.file
                .set_len(slots * SLOT_LEN)
                .map_err(|e| io_error("truncated", &e))?;
        } else if len > self.len {
            let gap = len - self.len;
            let zeros = vec![0u8; gap.min(FRAME_LEN as u64) as usize];
            let mut at = self.len;
            while at < len {
                let take = (len - at).min(zeros.len() as u64) as usize;
                self.write_at(at, &zeros[..take])?;
                at += take as u64;
            }
        }
        self.len = len;
        Ok(())
    }

    /// A decrypting view over the spill, suitable for
    /// [`Vault::put_file_from_source`](dctl_core::Vault::put_file_from_source).
    ///
    /// Owns its own descriptor and a copy of the key so it can be moved onto a
    /// blocking thread, which is where sealing happens.
    ///
    /// # Errors
    /// Whatever duplicating the descriptor reported.
    pub fn reader(&self) -> Result<SpillReader> {
        let file = self
            .file
            .try_clone()
            .map_err(|e| io_error("duplicated for reading", &e))?;
        Ok(SpillReader {
            file,
            key: self.key.clone(),
            len: self.len,
            position: 0,
            frame: Zeroizing::new(Vec::new()),
            frame_index: u64::MAX,
        })
    }
}

/// A sequential, seekable, decrypting view over a [`Spill`].
///
/// `Read + Seek` rather than a plain reader because the sealer reads its input
/// twice: once to hash the plaintext and plan the frames, once to emit them.
pub struct SpillReader {
    file: File,
    key: Zeroizing<[u8; 32]>,
    len: u64,
    position: u64,
    /// The frame currently decrypted, so a sequential read does not re-open the
    /// same frame for every call the caller makes.
    frame: Zeroizing<Vec<u8>>,
    frame_index: u64,
}

impl SpillReader {
    fn load(&mut self, index: u64) -> io::Result<()> {
        if self.frame_index == index {
            return Ok(());
        }
        let want = blob_len(index, self.len);
        let mut blob = vec![0u8; want];
        self.file.seek(SeekFrom::Start(index * SLOT_LEN))?;
        let got = read_full(&mut self.file, &mut blob)?;
        blob.truncate(got);
        let plain = aead::decrypt(&self.key, &blob, &index.to_le_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "a write-spill frame failed authentication; the file was altered underneath us",
            )
        })?;
        self.frame = plain;
        self.frame_index = index;
        Ok(())
    }
}

impl Read for SpillReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.len || out.is_empty() {
            return Ok(0);
        }
        let index = self.position / FRAME_LEN as u64;
        let within = (self.position % FRAME_LEN as u64) as usize;
        self.load(index)?;
        let available = self.frame.len().saturating_sub(within);
        let remaining = (self.len - self.position) as usize;
        let take = available.min(remaining).min(out.len());
        if take == 0 {
            return Ok(0);
        }
        out[..take].copy_from_slice(&self.frame[within..within + take]);
        self.position += take as u64;
        Ok(take)
    }
}

impl Seek for SpillReader {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(d) => self.len as i128 + i128::from(d),
            SeekFrom::Current(d) => self.position as i128 + i128::from(d),
        };
        if target < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start of the spill",
            ));
        }
        self.position = target as u64;
        Ok(self.position)
    }
}

/// Read until the buffer is full or the file ends, returning how much arrived.
///
/// `read_exact` is wrong here: the final slot is short, and a short read at the
/// end of the file is the ordinary case rather than an error.
fn read_full(file: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The canary a leak test looks for. Long and distinctive so that finding it
    /// in a file is proof rather than coincidence.
    const CANARY: &[u8] = b"PLAINTEXT-CANARY-6f2a91c4-MUST-NEVER-REACH-DISK";

    fn spill() -> (tempfile::TempDir, Spill) {
        let dir = tempfile::tempdir().unwrap();
        let file = std::fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(dir.path().join("spill"))
            .unwrap();
        (dir, Spill::new(file).unwrap())
    }

    fn read_all(s: &Spill) -> Vec<u8> {
        let mut out = Vec::new();
        s.reader().unwrap().read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn nothing_written_reaches_the_disk_in_the_clear() {
        // The property this module exists for. A competing tool's VFS cache was
        // measured holding decrypted plaintext on local disk while a file was
        // open; a canary written through its encrypted remote was readable
        // straight out of the cache directory. This asserts DCTL does not.
        let (dir, mut s) = spill();
        s.write_at(0, CANARY).unwrap();
        s.write_at(200_000, CANARY).unwrap();

        let raw = std::fs::read(dir.path().join("spill")).unwrap();
        assert!(
            !raw.windows(CANARY.len()).any(|w| w == CANARY),
            "the plaintext canary was found in the spill file on disk"
        );
        // …and it is genuinely there when read back through the key.
        assert_eq!(&read_all(&s)[..CANARY.len()], CANARY);
    }

    #[test]
    fn writes_at_arbitrary_offsets_read_back_exactly() {
        // What a filesystem actually delivers: out of order, straddling frames.
        let (_d, mut s) = spill();
        let a = vec![b'A'; 100];
        let b = vec![b'B'; FRAME_LEN + 50]; // crosses a frame boundary
        s.write_at(FRAME_LEN as u64 - 20, &b).unwrap();
        s.write_at(0, &a).unwrap();

        let out = read_all(&s);
        assert_eq!(out.len(), 2 * FRAME_LEN + 30);
        assert_eq!(&out[..100], &a[..]);
        assert_eq!(&out[FRAME_LEN - 20..], &b[..]);
        // The gap between them was never written and must read as zeros, not as
        // whatever happened to be in the frame buffer.
        assert!(out[100..FRAME_LEN - 20].iter().all(|&x| x == 0));
    }

    #[test]
    fn rewriting_a_frame_never_reuses_its_nonce() {
        // Nonce reuse with XChaCha20-Poly1305 leaks both plaintexts outright, and
        // a spill is rewritten constantly — every partial write re-seals a whole
        // frame. Two writes of the SAME bytes must still differ on disk.
        let (dir, mut s) = spill();
        s.write_at(0, b"identical").unwrap();
        let first = std::fs::read(dir.path().join("spill")).unwrap();
        s.write_at(0, b"identical").unwrap();
        let second = std::fs::read(dir.path().join("spill")).unwrap();

        assert_ne!(
            first, second,
            "the same plaintext sealed twice produced identical ciphertext, so a \
             nonce was reused"
        );
        assert_eq!(&read_all(&s)[..], b"identical");
    }

    #[test]
    fn a_frame_moved_to_another_slot_fails_to_open() {
        // The frame index is the AAD. Without it, an attacker who can write the
        // spill could reorder a file's frames and the result would decrypt
        // cleanly as the wrong bytes in the wrong order.
        let (dir, mut s) = spill();
        s.write_at(0, &vec![b'0'; FRAME_LEN]).unwrap();
        s.write_at(FRAME_LEN as u64, &vec![b'1'; FRAME_LEN])
            .unwrap();

        let path = dir.path().join("spill");
        let mut raw = std::fs::read(&path).unwrap();
        let slot = SLOT_LEN as usize;
        let (a, b) = raw.split_at_mut(slot);
        a.swap_with_slice(&mut b[..slot]);
        std::fs::write(&path, &raw).unwrap();

        let mut out = Vec::new();
        let err = s.reader().unwrap().read_to_end(&mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    }

    #[test]
    fn truncation_removes_the_tail_from_the_ciphertext() {
        // Shortening by length alone would leave the discarded bytes sealed on
        // disk, recoverable by anyone who later obtains the key.
        let (dir, mut s) = spill();
        s.write_at(0, b"keep-this").unwrap();
        s.write_at(9, CANARY).unwrap();
        s.truncate(9).unwrap();

        assert_eq!(s.len(), 9);
        assert_eq!(read_all(&s), b"keep-this");
        let raw = std::fs::read(dir.path().join("spill")).unwrap();
        assert!(
            !raw.windows(CANARY.len()).any(|w| w == CANARY),
            "the truncated tail is still recoverable from the spill"
        );
    }

    #[test]
    fn extending_zero_fills_rather_than_exposing_old_bytes() {
        let (_d, mut s) = spill();
        s.write_at(0, b"abc").unwrap();
        s.truncate(FRAME_LEN as u64 + 10).unwrap();
        let out = read_all(&s);
        assert_eq!(out.len(), FRAME_LEN + 10);
        assert_eq!(&out[..3], b"abc");
        assert!(out[3..].iter().all(|&x| x == 0));
    }

    #[test]
    fn the_reader_seeks_so_the_sealer_can_read_it_twice() {
        // `Vault::put_file_from_source` reads its input twice — once to hash and
        // plan the frames, once to seal them. A reader that could not rewind
        // would fail on the second pass.
        let (_d, mut s) = spill();
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        s.write_at(0, &payload).unwrap();

        let mut r = s.reader().unwrap();
        let mut first = Vec::new();
        r.read_to_end(&mut first).unwrap();
        r.seek(SeekFrom::Start(0)).unwrap();
        let mut second = Vec::new();
        r.read_to_end(&mut second).unwrap();

        assert_eq!(first, payload);
        assert_eq!(first, second, "the second pass must see the same bytes");
    }

    #[test]
    fn an_empty_spill_is_empty_rather_than_a_zero_byte_file() {
        let (_d, s) = spill();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(read_all(&s).is_empty());
    }
}
