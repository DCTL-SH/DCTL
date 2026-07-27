//! The append path: open the log, append one record, make it durable.
//!
//! `PLAN.md` §6 step 8 puts the audit record at the end of the verified-write
//! pipeline, and §7 makes the chain a day-1 non-negotiable. This module is what
//! turns "we did something" into evidence that we did it.
//!
//! ## Three promises, and the mechanism for each
//!
//! * **A record is wholly present or wholly absent.** A record counts if and
//!   only if its line terminator is on the medium — see [`super::serialize`].
//!   A run that dies part-way leaves a fragment after the last terminator, which
//!   is unambiguously not a record. The chain before it is untouched and still
//!   verifies, so a torn write costs the one operation that was in flight and
//!   nothing else.
//! * **fsync before success.** [`Writer::append`] does not return until the
//!   bytes are on stable storage. An audit record that did not survive a power
//!   cut did not happen, and reporting an operation successful on the strength
//!   of a record that is still in the page cache would be reporting work that
//!   may not have been recorded.
//! * **Append-only.** The file is opened `O_APPEND`, so every write goes to the
//!   true end of the file whatever else is happening to it. The one exception is
//!   the torn-fragment repair below, which removes only bytes that follow the
//!   last complete record — bytes no operation was ever told had landed.
//!
//! ## The head is re-read whenever the file changes underneath us
//!
//! [`Writer`] caches the head hash and the next index so a million-file run does
//! not re-read the log a million times. But it checks the file's length before
//! every append and re-derives both if it moved: another process appending, or
//! something truncating the file, both change what the next record must link to,
//! and linking to a stale head would produce a break in the *middle* of the
//! chain — a break that looks exactly like a forgery we committed.
//!
//! That check narrows the race; it does not close it. Two processes appending at
//! the same instant can still both read the same head and fork the chain.
//! DCTL's answer to that is the index lock of `PLAN.md` §6 — one writer per
//! vault, enforced where the vault is opened — and this module deliberately does
//! not invent a second, weaker one. What it guarantees is that a fork is
//! **detectable**: the two records share an index, and `dctl audit verify`
//! reports an index discontinuity at a nameable position rather than silently
//! accepting one of them.
//!
//! ## Who calls this
//!
//! Nothing directly. Every call site goes through [`super::sink`], which owns
//! the one handle a run has, decides where the log lives, and decides what a
//! failure to append means for the command being recorded. Keeping that policy
//! out of here is deliberate: this module's job is to put a record on the medium
//! correctly, and a module that also decided exit codes would have two reasons
//! to change.
//!
//! The `dead_code` allow that used to sit here is gone. It covered the period in
//! which the writer was complete but unwired; the accessors below that only the
//! tests use are individually justified where they are declared.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::constants::{
    AUDIT_CHAIN_FIRST_INDEX, AUDIT_CHAIN_GENESIS_PREV, AUDIT_LOG_FILE_MODE, AUDIT_TAIL_SCAN_BYTES,
    AUDIT_TAIL_SCAN_LIMIT_BYTES,
};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::logging::fields;

use super::chain;
use super::record::{Entry, is_well_formed_hash};
use super::serialize::{self, Framing};

/// An open audit log, positioned to append.
///
/// Holds the file open for the life of a run rather than reopening per record:
/// the open, the tail scan and the permission hardening are per-log costs, and a
/// transfer of a million files should pay them once.
#[derive(Debug)]
pub struct Writer {
    /// Where the log is, so every message can name the file.
    path: PathBuf,
    /// Opened `O_APPEND` for write and readable for the tail scan.
    file: File,
    /// Hash of the last record — what the next record's `prev` must be.
    head: String,
    /// Index the next record will carry.
    next_index: u64,
    /// The file's length as of our last look, used to notice outside changes.
    length: u64,
}

impl Writer {
    /// Open (creating if needed) the log at `path` and find its head.
    ///
    /// The path is supplied rather than resolved here on purpose: the reader
    /// already decides where a log lives
    /// (`crate::commands::audit::source::resolve_path`), and a writer that
    /// resolved it a second way could write a chain the reader never looks at.
    ///
    /// # Errors
    /// [`ExitCode::AuditChainBroken`] if the last record in the file does not
    /// attest to itself — appending onto a corrupt head would bury the break in
    /// the middle of the chain. Any I/O failure is classified by [`CliError`]'s
    /// conversion, with the path named.
    pub fn open(path: &Path) -> Result<Self> {
        let parent = path.parent().filter(|dir| !dir.as_os_str().is_empty());
        // Sampled before the open, which is what creates the file.
        let is_new = !path.exists();

        if let Some(parent) = parent {
            // Hardened only when we are the ones who created it. The log sits
            // beside the index, which may be a directory the operator chose and
            // shares with other things; silently chmodding somebody's existing
            // `/srv/data` to owner-only would be a surprising side effect of
            // writing one file, and the file's own mode is what protects the
            // history in that case.
            let directory_is_new = !parent.exists();
            std::fs::create_dir_all(parent).map_err(|error| at_path(parent, error))?;
            if directory_is_new {
                harden_directory(parent)?;
            }
        }

        let file = open_appending(path)?;

        if is_new {
            // The bytes of the first record are useless if the directory entry
            // pointing at them did not survive the same power cut (`PLAN.md` §6,
            // "fsync the file *and* its directory").
            if let Some(parent) = parent {
                sync_directory(parent);
            }
        }

        let mut writer = Self {
            path: path.to_path_buf(),
            file,
            head: AUDIT_CHAIN_GENESIS_PREV.to_string(),
            next_index: AUDIT_CHAIN_FIRST_INDEX,
            length: 0,
        };
        writer.resync()?;
        Ok(writer)
    }

    /// The hash the next record will link to.
    ///
    /// Worth publishing: comparing it against an anchor kept outside the log is
    /// the only way to detect that records were removed from the end, which the
    /// chain itself cannot see (see [`super::chain`]).
    ///
    /// No command consults it yet, and inventing a caller to satisfy the lint
    /// would be worse than saying so: the anchor DCTL would compare it against
    /// does not exist. The tests do use it — it is how they assert that two runs
    /// continue one chain rather than starting two — so the accessor stays and
    /// the allow is narrowed to the non-test build.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn head(&self) -> &str {
        &self.head
    }

    /// The index the next record will carry.
    ///
    /// See [`Writer::head`] for why this is annotated rather than removed.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub const fn next_index(&self) -> u64 {
        self.next_index
    }

    // There is deliberately no `path()` accessor. The path a caller needs is
    // [`super::sink::Sink::path`] — the value this writer was opened *from* — and
    // a second way to ask the same question is how the two come to disagree.

    /// Append one entry and return the record as it was written.
    ///
    /// Returns only once the record is on stable storage, so a caller may report
    /// its operation successful the moment this returns and not before.
    ///
    /// # Errors
    /// [`ExitCode::AuditChainBroken`] if the log changed underneath us into
    /// something that cannot be appended to. [`ExitCode::IndexError`] if the
    /// chain has run out of indices. Otherwise the classified I/O failure — and
    /// an I/O failure here means the operation is **not** recorded, which the
    /// caller must not report as success.
    pub fn append(&mut self, entry: &Entry) -> Result<super::record::AuditRecord> {
        // Something may have appended to, or truncated, the file since we last
        // looked. Both change what the next record must link to.
        let observed = self.observed_length()?;
        if observed != self.length {
            tracing::debug!(
                { fields::PATH } = %self.path.display(),
                expected = self.length,
                found = observed,
                "the audit log changed underneath us; re-reading its head"
            );
            self.resync()?;
        }

        let record = chain::seal(entry, self.next_index, &self.head);
        let line = serialize::encode_line(&record)?;

        self.file
            .write_all(&line)
            .map_err(|error| at_path(&self.path, error))?;
        self.file
            .flush()
            .map_err(|error| at_path(&self.path, error))?;
        // `PLAN.md` §6: durability before success. Everything above this line is
        // a promise; this is what makes it one.
        self.file
            .sync_all()
            .map_err(|error| at_path(&self.path, error))?;

        self.length = self.length.saturating_add(line.len() as u64);
        self.next_index = self.next_index.checked_add(1).ok_or_else(|| {
            CliError::new(
                ExitCode::IndexError,
                format!(
                    "{}: the audit chain has no more indices",
                    self.path.display()
                ),
            )
            .with_hint(
                "A chain is 2^64 records long. Reaching the end means the index \
                 field was overwritten rather than that the log filled up.",
            )
        })?;
        self.head.clone_from(&record.hash);

        tracing::debug!(
            { fields::PATH } = %self.path.display(),
            index = record.index,
            { fields::OP } = record.op.as_str(),
            "appended an audit record"
        );
        Ok(record)
    }

    /// The file's current length.
    fn observed_length(&self) -> Result<u64> {
        Ok(self
            .file
            .metadata()
            .map_err(|error| at_path(&self.path, error))?
            .len())
    }

    /// Re-derive the head hash and the next index from the file itself, and
    /// clear any torn fragment first.
    fn resync(&mut self) -> Result<()> {
        let mut length = self.observed_length()?;
        let (last, fragment) = self.scan_tail(length)?;

        if fragment > 0 {
            // A previous run died between starting an append and finishing it.
            // The fragment is not a record and was never acknowledged to
            // anybody, so removing it discards nothing that was ever claimed to
            // have happened — and leaving it would put a line in the log that
            // the reader is obliged to treat as tampering.
            //
            // This is the only write in DCTL that shortens the audit log, and it
            // can only ever remove bytes that follow the last complete record.
            let boundary = length.saturating_sub(fragment);
            tracing::warn!(
                { fields::PATH } = %self.path.display(),
                { fields::BYTES } = fragment,
                offset = boundary,
                "discarding a torn audit record left by an interrupted run; \
                 the chain before it is intact"
            );
            self.file
                .set_len(boundary)
                .map_err(|error| at_path(&self.path, error))?;
            self.file
                .sync_all()
                .map_err(|error| at_path(&self.path, error))?;
            length = boundary;
        }

        match last {
            None => {
                self.head = AUDIT_CHAIN_GENESIS_PREV.to_string();
                self.next_index = AUDIT_CHAIN_FIRST_INDEX;
            }
            Some(line) => {
                let record = serialize::decode(&line).map_err(|error| {
                    self.broken(format!("its last line is not an audit record: {error}"))
                })?;

                // The head must attest to itself before anything is chained to
                // it. Linking a new record to a hash the head does not actually
                // have would put the break in the middle of the chain, where it
                // reads as a forgery committed by us rather than as the damage
                // it is.
                if !is_well_formed_hash(&record.hash)
                    || !record
                        .hash
                        .eq_ignore_ascii_case(&chain::compute_hash(&record))
                {
                    return Err(self.broken(format!(
                        "its last record (index {}) does not hash to the value it carries",
                        record.index
                    )));
                }

                self.next_index = record.index.checked_add(1).ok_or_else(|| {
                    self.broken("its last record claims the highest possible index".to_string())
                })?;
                self.head = record.hash;
            }
        }

        self.length = length;
        Ok(())
    }

    /// Read backwards from the end until the last complete record is framed.
    ///
    /// Returns the line (owned, because the buffer it was read into does not
    /// outlive the scan) and the length of any torn fragment after it.
    fn scan_tail(&mut self, length: u64) -> Result<(Option<Vec<u8>>, u64)> {
        let mut window = AUDIT_TAIL_SCAN_BYTES;

        loop {
            let start = length.saturating_sub(window);
            let span = length - start;
            let size = usize::try_from(span).map_err(|_| {
                self.broken("its last record is too large to read into memory".to_string())
            })?;

            let mut buffer = vec![0_u8; size];
            self.file
                .seek(SeekFrom::Start(start))
                .map_err(|error| at_path(&self.path, error))?;
            self.file
                .read_exact(&mut buffer)
                .map_err(|error| at_path(&self.path, error))?;

            match serialize::frame(&buffer, start == 0) {
                Framing::Resolved(tail) => {
                    return Ok((tail.last.map(<[u8]>::to_vec), tail.fragment.len() as u64));
                }
                Framing::NeedMore => {
                    if window >= AUDIT_TAIL_SCAN_LIMIT_BYTES {
                        return Err(self.broken(format!(
                            "its last {AUDIT_TAIL_SCAN_LIMIT_BYTES} bytes contain no complete record"
                        )));
                    }
                    window = window.saturating_mul(2);
                }
            }
        }
    }

    /// A refusal to append, because the file is not a chain we may extend.
    ///
    /// Always exit 24, never a silent repair: a log DCTL cannot read is a log an
    /// auditor cannot read either, and appending to it would add records that
    /// nothing can verify.
    fn broken(&self, why: String) -> CliError {
        CliError::new(
            ExitCode::AuditChainBroken,
            format!("cannot append to {}: {why}", self.path.display()),
        )
        .with_hint(
            "No record was appended. Move the file aside and compare it against \
             a mirrored copy before trusting anything in it; `dctl audit verify` \
             reports the exact record where the chain fails.",
        )
    }
}

/// Classify an I/O failure and name the file it happened to.
fn at_path(path: &Path, error: std::io::Error) -> CliError {
    CliError::from(error).with_hint(format!(
        "The audit log is {}. The operation this record describes is NOT recorded.",
        path.display()
    ))
}

/// `open(2)` for appending, creating the log owner-only.
///
/// Readable as well as writable because the head has to be read back before the
/// first append; `O_APPEND` is what guarantees the write itself always lands at
/// the true end, whatever the read left the file position at.
fn open_appending(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).append(true).create(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(AUDIT_LOG_FILE_MODE);
    }

    let file = options.open(path).map_err(|error| at_path(path, error))?;

    // `open` masks the requested mode through the umask and leaves an existing
    // file's mode alone, so neither a permissive umask nor a log created by an
    // earlier, laxer version can leave the history world-readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        file.set_permissions(std::fs::Permissions::from_mode(AUDIT_LOG_FILE_MODE))
            .map_err(|error| at_path(path, error))?;
    }

    Ok(file)
}

/// Enforce [`crate::constants::AUDIT_LOG_DIR_MODE`] on the log's directory.
///
/// A no-op on Windows, where access is an ACL rather than a mode and the profile
/// directory the log lives under is already owner-only.
#[cfg(unix)]
fn harden_directory(directory: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    use crate::constants::AUDIT_LOG_DIR_MODE;

    std::fs::set_permissions(
        directory,
        std::fs::Permissions::from_mode(AUDIT_LOG_DIR_MODE),
    )
    .map_err(|error| at_path(directory, error))
}

/// See the Unix definition.
#[cfg(not(unix))]
fn harden_directory(_directory: &Path) -> Result<()> {
    Ok(())
}

/// Make a newly created log's directory entry durable.
///
/// A failure to *open* the directory is tolerated with a debug line: some
/// filesystems — and Windows, where a directory is not an openable file at all —
/// do not support this, and turning an unsupported operation into a failed
/// append would break DCTL there for no gain. The record's own bytes are still
/// fsynced either way, which is the durability the caller was promised.
fn sync_directory(directory: &Path) {
    let Ok(handle) = File::open(directory) else {
        tracing::debug!(
            { fields::PATH } = %directory.display(),
            "cannot open the audit log's directory to flush it; the file is \
             visible but its directory entry's durability is the filesystem's business"
        );
        return;
    };

    if let Err(error) = handle.sync_all() {
        tracing::warn!(
            { fields::PATH } = %directory.display(),
            "cannot flush the audit log's directory: {error}"
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::audit::record::AuditRecord;
    use crate::commands::touch::timestamp::Timestamp;
    use crate::constants::{AUDIT_LOG_FILE_NAME, AUDIT_LOG_LINE_TERMINATOR};
    use crate::logging::redact::Secret;

    fn entry(op: &str, path: &str) -> Entry {
        Entry::at(op, ExitCode::Success, Timestamp::parse("@0").unwrap()).path(path)
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    /// Parse a log the way the reader does, so the tests assert on what an
    /// auditor would actually see.
    fn records(path: &Path) -> Vec<AuditRecord> {
        read(path)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn an_empty_log_starts_at_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let writer = Writer::open(&dir.path().join(AUDIT_LOG_FILE_NAME)).unwrap();
        assert_eq!(writer.head(), AUDIT_CHAIN_GENESIS_PREV);
        assert_eq!(writer.next_index(), AUDIT_CHAIN_FIRST_INDEX);
    }

    #[test]
    fn appended_records_form_a_chain_the_reader_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG_FILE_NAME);
        let mut writer = Writer::open(&path).unwrap();

        for index in 0..5 {
            writer
                .append(&entry("copy", &format!("photos/{index}.jpg")))
                .unwrap();
        }

        let records = records(&path);
        assert_eq!(records.len(), 5);
        let verified = chain::verify(&records).unwrap();
        assert_eq!(verified.records, 5);
        assert_eq!(verified.head, writer.head());
    }

    #[test]
    fn one_record_is_one_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG_FILE_NAME);
        let mut writer = Writer::open(&path).unwrap();
        writer.append(&entry("copy", "a.jpg")).unwrap();
        writer.append(&entry("delete", "b.jpg")).unwrap();

        let body = read(&path);
        assert_eq!(body.lines().count(), 2);
        assert!(body.ends_with(char::from(AUDIT_LOG_LINE_TERMINATOR)));
    }

    #[test]
    fn a_reopened_log_continues_the_same_chain() {
        // The property that makes the log a log: two runs of DCTL produce one
        // chain, not two.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG_FILE_NAME);

        let head = {
            let mut writer = Writer::open(&path).unwrap();
            writer.append(&entry("copy", "a.jpg")).unwrap();
            writer.append(&entry("copy", "b.jpg")).unwrap();
            writer.head().to_string()
        };

        let mut second = Writer::open(&path).unwrap();
        assert_eq!(second.head(), head);
        assert_eq!(second.next_index(), 2);
        let appended = second.append(&entry("delete", "a.jpg")).unwrap();
        assert_eq!(appended.index, 2);
        assert_eq!(appended.prev, head);

        chain::verify(&records(&path)).unwrap();
    }

    #[test]
    fn nothing_before_a_torn_write_is_lost() {
        // The crash case. A run died with a half-written final record; the
        // chain before it must still verify, and the log must still be
        // appendable.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG_FILE_NAME);

        {
            let mut writer = Writer::open(&path).unwrap();
            writer.append(&entry("copy", "a.jpg")).unwrap();
            writer.append(&entry("copy", "b.jpg")).unwrap();
        }
        let intact = read(&path);

        // Simulate the crash: bytes of a third record, no terminator.
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"index\":2,\"time\":\"2026").unwrap();
        drop(file);

        let mut writer = Writer::open(&path).unwrap();
        assert_eq!(read(&path), intact, "the fragment must be gone");
        assert_eq!(writer.next_index(), 2, "the torn record never counted");

        writer.append(&entry("copy", "c.jpg")).unwrap();
        let records = records(&path);
        assert_eq!(records.len(), 3);
        assert_eq!(records[2].path, "c.jpg");
        chain::verify(&records).unwrap();
    }

    #[test]
    fn a_torn_first_record_leaves_a_chain_that_starts_at_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG_FILE_NAME);
        std::fs::write(&path, b"{\"index\":0,\"ti").unwrap();

        let mut writer = Writer::open(&path).unwrap();
        assert_eq!(writer.head(), AUDIT_CHAIN_GENESIS_PREV);
        assert_eq!(writer.next_index(), AUDIT_CHAIN_FIRST_INDEX);

        writer.append(&entry("copy", "a.jpg")).unwrap();
        chain::verify(&records(&path)).unwrap();
    }

    #[test]
    fn a_head_that_does_not_hash_to_its_own_content_is_refused() {
        // Appending onto an edited head would put the break in the middle of the
        // chain, where it reads as a forgery we committed.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG_FILE_NAME);

        {
            let mut writer = Writer::open(&path).unwrap();
            writer.append(&entry("copy", "a.jpg")).unwrap();
        }

        let tampered = read(&path).replace("a.jpg", "b.jpg");
        std::fs::write(&path, tampered).unwrap();

        let error = Writer::open(&path).unwrap_err();
        assert_eq!(error.code(), ExitCode::AuditChainBroken);
        assert!(
            error.message().contains("does not hash"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn a_last_line_that_is_not_a_record_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG_FILE_NAME);
        std::fs::write(&path, "{ not json\n").unwrap();

        let error = Writer::open(&path).unwrap_err();
        assert_eq!(error.code(), ExitCode::AuditChainBroken);
        assert!(error.hint().is_some());
    }

    #[test]
    fn an_append_by_another_process_is_noticed_before_the_next_record() {
        // Linking to a stale head would break the chain in its middle. The
        // length check is what turns that into a re-read.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG_FILE_NAME);
        let mut ours = Writer::open(&path).unwrap();
        ours.append(&entry("copy", "a.jpg")).unwrap();

        {
            let mut theirs = Writer::open(&path).unwrap();
            theirs.append(&entry("copy", "b.jpg")).unwrap();
        }

        let appended = ours.append(&entry("copy", "c.jpg")).unwrap();
        assert_eq!(appended.index, 2, "the other writer's record was seen");
        chain::verify(&records(&path)).unwrap();
    }

    #[test]
    fn a_record_that_needs_a_wider_window_is_still_found() {
        // A path long enough that the last record does not fit in the first
        // backward window. Guessing instead of widening would hand the writer a
        // truncated record as the chain's head.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG_FILE_NAME);
        let long = "x".repeat(usize::try_from(AUDIT_TAIL_SCAN_BYTES).unwrap() * 2);

        {
            let mut writer = Writer::open(&path).unwrap();
            writer.append(&entry("copy", "a.jpg")).unwrap();
            writer.append(&entry("copy", &long)).unwrap();
        }

        let mut writer = Writer::open(&path).unwrap();
        assert_eq!(writer.next_index(), 2);
        writer.append(&entry("copy", "c.jpg")).unwrap();
        chain::verify(&records(&path)).unwrap();
    }

    #[test]
    fn blank_lines_at_the_end_do_not_hide_the_head() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG_FILE_NAME);
        {
            let mut writer = Writer::open(&path).unwrap();
            writer.append(&entry("copy", "a.jpg")).unwrap();
        }
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"\n\n").unwrap();
        drop(file);

        let mut writer = Writer::open(&path).unwrap();
        assert_eq!(writer.next_index(), 1);
        writer.append(&entry("copy", "b.jpg")).unwrap();
        chain::verify(&records(&path)).unwrap();
    }

    #[test]
    fn the_log_and_its_directory_are_created_owner_only() {
        // A filename inventory is exactly the metadata the vault exists to keep
        // private, even though the log holds no keys.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            use crate::constants::AUDIT_LOG_DIR_MODE;

            let dir = tempfile::tempdir().unwrap();
            let nested = dir.path().join("vault");
            let path = nested.join(AUDIT_LOG_FILE_NAME);
            Writer::open(&path).unwrap();

            let file_mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(file_mode & 0o777, AUDIT_LOG_FILE_MODE);
            let dir_mode = std::fs::metadata(&nested).unwrap().permissions().mode();
            assert_eq!(dir_mode & 0o777, AUDIT_LOG_DIR_MODE);
        }
    }

    #[test]
    fn an_existing_world_readable_log_is_closed_on_open() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(AUDIT_LOG_FILE_NAME);
            std::fs::write(&path, "").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

            Writer::open(&path).unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, AUDIT_LOG_FILE_MODE);
        }
    }

    #[test]
    fn no_secret_reaches_the_log() {
        // `PLAN.md` §7: keys, passwords and tokens never reach a log, and
        // secrets appear only as BLAKE3 fingerprints. This asserts it on the
        // bytes that actually land on disk, not on the builder's return value.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG_FILE_NAME);

        let password = Secret::new("correct-horse-battery-staple".to_string());
        let secrets = [
            "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
            "AKIAIOSFODNN7EXAMPLE",
            "deadbeefcafefeed",
            "correct-horse-battery-staple",
        ];

        let mut writer = Writer::open(&path).unwrap();
        writer
            .append(
                &Entry::at("copy", ExitCode::Success, Timestamp::parse("@0").unwrap())
                    .path("photos/2024/a.jpg")
                    .size(1024)
                    .remote(
                        "s3://AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\
                         @bucket.example.com/prefix?X-Amz-Signature=deadbeefcafefeed",
                    ),
            )
            .unwrap();
        // A `Secret` renders as its placeholder even if a caller passes it into
        // a field by mistake — the type is the last line of defence.
        writer
            .append(&entry("delete", &format!("keys/{password}")))
            .unwrap();

        let body = read(&path);
        for secret in secrets {
            assert!(!body.contains(secret), "the log leaked {secret}: {body}");
        }
        // And the credential is still *identifiable*, which is the point of a
        // fingerprint rather than a placeholder.
        assert!(body.contains("blake3:"), "{body}");
        chain::verify(&records(&path)).unwrap();
    }

    #[test]
    fn a_record_is_durable_before_append_returns() {
        // Read back through a second, independent handle: what an auditor (or a
        // machine that just lost power) would see.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG_FILE_NAME);
        let mut writer = Writer::open(&path).unwrap();
        let record = writer.append(&entry("copy", "a.jpg")).unwrap();

        let observed = records(&path);
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0], record);
    }
}
