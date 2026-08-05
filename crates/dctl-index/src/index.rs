//! The encrypted index over stored objects, backed by SQLCipher.
//!
//! Storage is a single SQLCipher database (SQLite with whole-database AEAD
//! encryption). Two independent, defence-in-depth encryption layers are kept —
//! matching the previous backend exactly (docs/FORMAT.md §9.4/§9.5, §5):
//!
//! 1. **Whole-DB (SQLCipher):** every page is encrypted under a raw 32-byte key
//!    derived from the index sub-key, so a stolen `.db`/`.db-wal` file is opaque.
//! 2. **Per-row (application AEAD):** the primary key is a keyed BLAKE3 hash of the
//!    path and the value is XChaCha20-Poly1305-sealed, so even a *decrypted* page
//!    reveals neither the plaintext path nor any metadata (metadata-private at rest).
//!
//! The store is multi-process-safe (`journal_mode = WAL` + a `busy_timeout`) so an
//! iOS App and its File-Provider extension can share one App-Group database. Within
//! a process the single connection is guarded by a mutex so `Index` stays
//! `Send + Sync` (identical to the previous backend, which `dctl-core` relies on to
//! hold `&Vault` across `.await`).

use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use dctl_crypto::aead;
use dctl_crypto::keys::derive_subkey;
use rusqlite::{Connection, OptionalExtension};
use zeroize::Zeroizing;

use crate::error::{IndexError, Result};
use crate::keying::index_key;
use crate::record::Record;

/// Wait up to this long for a competing writer (another process/thread) before
/// surfacing `SQLITE_BUSY`. WAL admits concurrent readers alongside a single
/// writer, so this only bounds the rare writer-vs-writer overlap between the App
/// and its File-Provider extension.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// An encrypted, metadata-private index over stored objects.
///
/// Constructed from the vault's index sub-key (`HKDF(root, "index")`), from which
/// three independent sub-keys are derived: one keys the path→row hash, one seals
/// each row value, and one is the SQLCipher whole-database key.
pub struct Index {
    conn: Mutex<Connection>,
    keying_key: Zeroizing<[u8; 32]>,
    enc_key: Zeroizing<[u8; 32]>,
}

/// Mode for a freshly-created index file: owner read/write, nobody else.
///
/// The records are encrypted, so this is not what protects them — but a
/// world-readable index publishes its size and modification time, which is how
/// many objects this machine tracks and when it last ran. The directory around
/// it carries `dctl_meta::paths::HOME_DIR_MODE` for the same reason.
#[cfg(unix)]
const INDEX_FILE_MODE: u32 = 0o600;

/// Close a freshly-created index file to everyone but its owner.
///
/// Best-effort and deliberately not fatal: a filesystem with no Unix modes —
/// a mounted share, an exotic target — must not stop a vault from opening,
/// and the encryption is what protects the records either way.
#[cfg(unix)]
fn harden_file(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(INDEX_FILE_MODE));
}

/// See the Unix definition.
#[cfg(not(unix))]
fn harden_file(_path: &std::path::Path) {}

impl Index {
    /// Open (or create) an index database at `path`.
    ///
    /// On an existing database opened with the **wrong** sub-key the SQLCipher key
    /// is wrong and the first page read (setting the journal mode) fails to decrypt
    /// the header — this returns [`IndexError::Db`] (`SQLITE_NOTADB`) rather than
    /// exposing any rows.
    pub fn open(path: &Path, index_subkey: &[u8; 32]) -> Result<Self> {
        let keying_key =
            derive_subkey(index_subkey, b"index-keying-v1").map_err(|_| IndexError::Crypto)?;
        let enc_key =
            derive_subkey(index_subkey, b"index-encryption-v1").map_err(|_| IndexError::Crypto)?;
        // Whole-DB SQLCipher key: a THIRD, domain-separated sub-key so the page-cipher
        // key is cryptographically independent of the row-hash and row-AEAD keys.
        let db_key =
            derive_subkey(index_subkey, b"index-sqlcipher-v1").map_err(|_| IndexError::Crypto)?;

        let is_new = !path.exists();
        let conn = Connection::open(path)?;
        if is_new {
            // Owner-only, like the configuration and the audit chain beside
            // it. The contents are encrypted, so this is not what protects the
            // records — but an index left world-readable publishes its *size*
            // and its modification time, which is how many objects this
            // machine tracks and when it last backed up, and there is no
            // reason to hand that to every account on the box.
            harden_file(path);
        }

        // `PRAGMA key` MUST be the first statement on the connection. The raw-key form
        // `"x'<hex>'"` makes SQLCipher use the 32 bytes directly and skip its PBKDF2 —
        // the sub-key is already a strong HKDF-SHA512 output, so the KDF adds nothing.
        // The hex alphabet cannot contain a quote, so the interpolation is
        // injection-free; the assembled SQL (which carries the key) is zeroized on drop.
        let key_pragma = Zeroizing::new(format!(
            "PRAGMA key = \"x'{}'\";",
            hex::encode(db_key.as_slice())
        ));
        conn.execute_batch(&key_pragma)?;

        // Multi-process safety: `busy_timeout` absorbs brief writer overlap instead of
        // erroring immediately, and WAL lets the App + File-Provider extension read
        // concurrently with a single writer. SQLCipher encrypts WAL frames too, so
        // nothing leaks via the `-wal` sidecar. Setting the journal mode reads the DB
        // header, so on a wrong key the open fails here with `SQLITE_NOTADB`.
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;

        // key BLOB = BLAKE3_keyed(keying-key, NFC(path)); value BLOB = AEAD(row bytes).
        // WITHOUT ROWID clusters storage on the key, so `ORDER BY key` (ascending byte
        // order) streams rows in the same order the previous key-ordered B-tree did.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS records(\
                 key   BLOB PRIMARY KEY NOT NULL, \
                 value BLOB NOT NULL\
             ) WITHOUT ROWID;",
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
            keying_key,
            enc_key,
        })
    }

    /// Lock the single connection. Poisoning can only follow a panic while the guard
    /// is held; lib code forbids panics, but we still map it rather than `unwrap`.
    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| IndexError::Db("index connection mutex poisoned".into()))
    }

    /// Insert or replace the record for its path.
    pub fn put(&self, record: &Record) -> Result<()> {
        let key = index_key(&self.keying_key, &record.path);
        let plaintext = postcard::to_allocvec(record).map_err(|_| IndexError::Serialize)?;
        let blob =
            aead::encrypt(&self.enc_key, &plaintext, &key).map_err(|_| IndexError::Crypto)?;

        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO records(key, value) VALUES(?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
            rusqlite::params![&key[..], &blob[..]],
        )?;
        Ok(())
    }

    /// Look up the record for `path`.
    pub fn get(&self, path: &str) -> Result<Option<Record>> {
        let key = index_key(&self.keying_key, path);
        let conn = self.lock()?;
        let value: Option<Vec<u8>> = conn
            .query_row(
                "SELECT value FROM records WHERE key = ?1;",
                rusqlite::params![&key[..]],
                |row| row.get(0),
            )
            .optional()?;
        let Some(value) = value else {
            return Ok(None);
        };
        let plaintext =
            aead::decrypt(&self.enc_key, &value, &key).map_err(|_| IndexError::Crypto)?;
        let record: Record = postcard::from_bytes(&plaintext).map_err(|_| IndexError::Serialize)?;
        Ok(Some(record))
    }

    /// Whether a record exists for `path` (no decryption).
    pub fn contains(&self, path: &str) -> Result<bool> {
        let key = index_key(&self.keying_key, path);
        let conn = self.lock()?;
        let found: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM records WHERE key = ?1;",
                rusqlite::params![&key[..]],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Remove the record for `path`. Returns whether a record was present.
    pub fn delete(&self, path: &str) -> Result<bool> {
        let key = index_key(&self.keying_key, path);
        let conn = self.lock()?;
        let changed = conn.execute(
            "DELETE FROM records WHERE key = ?1;",
            rusqlite::params![&key[..]],
        )?;
        Ok(changed > 0)
    }

    /// Number of records.
    pub fn count(&self) -> Result<u64> {
        let conn = self.lock()?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM records;", [], |row| row.get(0))?;
        Ok(n.max(0) as u64)
    }

    /// Decrypt and return all records. O(n); prefer [`for_each`](Index::for_each)
    /// for large indexes.
    pub fn all(&self) -> Result<Vec<Record>> {
        let mut out = Vec::new();
        self.for_each(|record| {
            out.push(record);
            true
        })?;
        Ok(out)
    }

    /// Invoke `f` for each decrypted record; stop early if `f` returns `false`.
    /// Rows stream in ascending key order (constant-memory; millions-of-files safe).
    pub fn for_each(&self, mut f: impl FnMut(Record) -> bool) -> Result<()> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT key, value FROM records ORDER BY key ASC;")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let key: Vec<u8> = row.get(0)?;
            let value: Vec<u8> = row.get(1)?;
            let plaintext =
                aead::decrypt(&self.enc_key, &value, &key).map_err(|_| IndexError::Crypto)?;
            let record: Record =
                postcard::from_bytes(&plaintext).map_err(|_| IndexError::Serialize)?;
            if !f(record) {
                break;
            }
        }
        Ok(())
    }
}
