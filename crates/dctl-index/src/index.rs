//! The encrypted index over stored objects, backed by SQLCipher.
//!
//! Storage is a single SQLCipher database (SQLite with whole-database AEAD
//! encryption). Two independent, defence-in-depth encryption layers are kept —
//! matching the previous backend exactly (docs/FORMAT.md §9 rule 5, §5):
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
//!
//! ## Three tables, because a hash has no order
//!
//! [`keying`](crate::keying) explains why the row key destroys path order and what
//! that cost: every listing had to decrypt every row, so a walk of the tree was
//! quadratic — 417 seconds over a 100,000-file vault, and a listing that matched
//! nothing cost as much as one that matched everything.
//!
//! - **`records`** — one row per file, keyed by the path hash, carrying the hash
//!   of the directory that holds it in an indexed `parent` column. That column is
//!   what turns `readdir` from a whole-index scan into one indexed lookup.
//! - **`dirs`** — one row per directory that currently holds something, with a
//!   reference count. A vault stores no directories, so every directory is
//!   implied by the files beneath it; the count is how a directory stops existing
//!   when its last file goes, without a scan to discover that it is empty.
//! - **`totals`** — a single sealed row carrying what `statfs` needs. Maintained
//!   on the way past by [`Index::put`] and [`Index::delete`] rather than counted,
//!   because counting it meant the whole-index scan again, on every `df`.
//!
//! All three are maintained inside one transaction per mutation, so a crash
//! between the record and its directories cannot leave the two disagreeing.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use dctl_crypto::aead;
use dctl_crypto::keys::derive_subkey;
use rusqlite::{Connection, OptionalExtension, Transaction};
use zeroize::Zeroizing;

use crate::error::{IndexError, Result};
use crate::keying::{ancestors_of, index_key, parent_of};
use crate::record::{Record, Totals};

/// Wait up to this long for a competing writer (another process/thread) before
/// surfacing `SQLITE_BUSY`. WAL admits concurrent readers alongside a single
/// writer, so this only bounds the rare writer-vs-writer overlap between the App
/// and its File-Provider extension.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Schema version this build writes and reads.
///
/// Bumped from the implicit `0` — records with no `parent` column and no `dirs`
/// or `totals` tables — when directory-keyed listing arrived. [`migrate`] is what
/// carries a version-0 database forward, and it runs once.
const SCHEMA_VERSION: i64 = 1;

/// AAD domain for the singleton totals row.
///
/// A NUL cannot occur in a logical path, so this can never collide with the key
/// of a real file however the paths above are normalised.
const TOTALS_DOMAIN: &str = "\0totals";

/// Primary key of the singleton totals row.
const TOTALS_ROW: i64 = 0;

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

        // `WITHOUT ROWID` clusters storage on the key, so a point lookup stays
        // one B-tree descent.
        //
        // The `records` statement is what a *fresh* database gets; a database
        // written before directory-keyed listing already has the table, without
        // the `parent` column, and `IF NOT EXISTS` leaves it exactly as it is.
        // That is why the index on `parent` is **not** created here — on a
        // version-0 database there would be no such column to index, and the
        // open would fail before the migration that adds it could run.
        // [`rewrite_with_parents`] creates it, once the column exists, on both
        // paths.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS records(\
                 key    BLOB PRIMARY KEY NOT NULL, \
                 parent BLOB NOT NULL DEFAULT x'', \
                 value  BLOB NOT NULL\
             ) WITHOUT ROWID;\
             CREATE TABLE IF NOT EXISTS dirs(\
                 key    BLOB PRIMARY KEY NOT NULL, \
                 parent BLOB NOT NULL, \
                 value  BLOB NOT NULL, \
                 refs   INTEGER NOT NULL\
             ) WITHOUT ROWID;\
             CREATE TABLE IF NOT EXISTS totals(\
                 id    INTEGER PRIMARY KEY CHECK(id = 0), \
                 value BLOB NOT NULL\
             );\
             CREATE INDEX IF NOT EXISTS dirs_parent ON dirs(parent);",
        )?;

        let index = Self {
            conn: Mutex::new(conn),
            keying_key,
            enc_key,
        };
        index.migrate()?;
        Ok(index)
    }

    /// Bring a database written by an older build up to [`SCHEMA_VERSION`].
    ///
    /// Version 0 had no `parent` column, no directory rows and no totals, so
    /// every one of them has to be derived from the records themselves — the
    /// paths are inside the sealed values, so this is the one operation that
    /// genuinely must read the whole index. It runs **once**, and a fresh
    /// database walks zero rows.
    ///
    /// Rows stream from the old table into a new one rather than being updated
    /// in place, so memory stays constant in the number of *files*. The only
    /// thing accumulated is one entry per *directory*, which is smaller by the
    /// tree's fan-out and is what the reference counts have to be totalled from
    /// before any of them can be written.
    fn migrate(&self) -> Result<()> {
        let mut conn = self.lock()?;
        let version: i64 = conn.query_row("PRAGMA user_version;", [], |row| row.get(0))?;
        if version >= SCHEMA_VERSION {
            return Ok(());
        }

        let tx = conn.transaction()?;
        // A version-0 table has no `parent`; a table this build created has one
        // and simply holds nothing to carry forward.
        let carried = Self::rewrite_with_parents(&tx, &self.keying_key, &self.enc_key)?;
        Self::write_totals(&tx, &self.keying_key, &self.enc_key, carried.totals)?;
        for (key, dir) in carried.dirs {
            let value = aead::encrypt(&self.enc_key, dir.path.as_bytes(), &key)
                .map_err(|_| IndexError::Crypto)?;
            tx.execute(
                "INSERT INTO dirs(key, parent, value, refs) VALUES(?1, ?2, ?3, ?4) \
                 ON CONFLICT(key) DO UPDATE SET refs = excluded.refs;",
                rusqlite::params![&key[..], &dir.parent[..], &value[..], dir.refs as i64],
            )?;
        }
        tx.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
        tx.commit()?;
        Ok(())
    }

    /// Stream every record into a fresh table that carries its parent, returning
    /// the directory counts and totals implied by what went past.
    fn rewrite_with_parents(
        tx: &Transaction<'_>,
        keying_key: &[u8; 32],
        enc_key: &[u8; 32],
    ) -> Result<Carried> {
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS records_migrating(\
                 key    BLOB PRIMARY KEY NOT NULL, \
                 parent BLOB NOT NULL, \
                 value  BLOB NOT NULL\
             ) WITHOUT ROWID;",
        )?;

        let mut carried = Carried::default();
        {
            let mut read = tx.prepare("SELECT key, value FROM records;")?;
            let mut write = tx.prepare(
                "INSERT INTO records_migrating(key, parent, value) VALUES(?1, ?2, ?3);",
            )?;
            let mut rows = read.query([])?;
            while let Some(row) = rows.next()? {
                let key: Vec<u8> = row.get(0)?;
                let value: Vec<u8> = row.get(1)?;
                let record = decode(enc_key, &key, &value)?;
                let parent = index_key(keying_key, parent_of(&record.path));
                write.execute(rusqlite::params![&key[..], &parent[..], &value[..]])?;
                carried.absorb(keying_key, &record);
            }
        }

        tx.execute_batch(
            "DROP TABLE records;\
             ALTER TABLE records_migrating RENAME TO records;\
             CREATE INDEX IF NOT EXISTS records_parent ON records(parent);",
        )?;
        Ok(carried)
    }

    /// Lock the single connection. Poisoning can only follow a panic while the guard
    /// is held; lib code forbids panics, but we still map it rather than `unwrap`.
    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| IndexError::Db("index connection mutex poisoned".into()))
    }

    /// Insert or replace the record for its path.
    ///
    /// One transaction covers the row, the directories it implies and the running
    /// totals, so the three cannot disagree if the process dies mid-write. A
    /// replacement adjusts the totals by the difference and leaves the directory
    /// counts alone: the file was already there, so nothing new is implied.
    pub fn put(&self, record: &Record) -> Result<()> {
        let key = index_key(&self.keying_key, &record.path);
        let parent = index_key(&self.keying_key, parent_of(&record.path));
        let plaintext = Zeroizing::new(
            postcard::to_allocvec(record).map_err(|_| IndexError::Serialize)?,
        );
        let blob =
            aead::encrypt(&self.enc_key, &plaintext, &key).map_err(|_| IndexError::Crypto)?;

        let mut conn = self.lock()?;
        let tx = conn.transaction()?;

        let previous = Self::read(&tx, &self.enc_key, &key)?;
        tx.execute(
            "INSERT INTO records(key, parent, value) VALUES(?1, ?2, ?3) \
             ON CONFLICT(key) DO UPDATE SET parent = excluded.parent, value = excluded.value;",
            rusqlite::params![&key[..], &parent[..], &blob[..]],
        )?;

        if previous.is_none() {
            for dir in ancestors_of(&record.path) {
                Self::bump_dir(&tx, &self.keying_key, &self.enc_key, dir, 1)?;
            }
        }
        Self::shift_totals(
            &tx,
            &self.keying_key,
            &self.enc_key,
            previous.as_ref(),
            Some(record),
        )?;
        tx.commit()?;
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
        Ok(Some(decode(&self.enc_key, &key, &value)?))
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

    /// Whether any file lives under the directory `dir`.
    ///
    /// A vault stores no directories, so this asks whether one is *implied* —
    /// which is exactly what the reference-counted row records. One indexed
    /// lookup, whatever the vault holds; the alternative was scanning the index
    /// for a path with the right prefix.
    pub fn contains_dir(&self, dir: &str) -> Result<bool> {
        let key = index_key(&self.keying_key, dir);
        let conn = self.lock()?;
        let found: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM dirs WHERE key = ?1;",
                rusqlite::params![&key[..]],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Remove the record for `path`. Returns whether a record was present.
    ///
    /// The directories it implied lose a reference each, and any that reaches
    /// zero goes with it — which is how the last file leaving a directory makes
    /// the directory stop existing, with no scan to discover that it is empty.
    pub fn delete(&self, path: &str) -> Result<bool> {
        let key = index_key(&self.keying_key, path);

        let mut conn = self.lock()?;
        let tx = conn.transaction()?;

        let Some(previous) = Self::read(&tx, &self.enc_key, &key)? else {
            return Ok(false);
        };
        tx.execute(
            "DELETE FROM records WHERE key = ?1;",
            rusqlite::params![&key[..]],
        )?;
        for dir in ancestors_of(path) {
            Self::bump_dir(&tx, &self.keying_key, &self.enc_key, dir, -1)?;
        }
        Self::shift_totals(&tx, &self.keying_key, &self.enc_key, Some(&previous), None)?;
        tx.commit()?;
        Ok(true)
    }

    /// Number of records.
    pub fn count(&self) -> Result<u64> {
        let conn = self.lock()?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM records;", [], |row| row.get(0))?;
        Ok(n.max(0) as u64)
    }

    /// What the whole index holds, in one row read.
    ///
    /// # Errors
    /// A failure to read or open the sealed totals row.
    pub fn totals(&self) -> Result<Totals> {
        let conn = self.lock()?;
        Self::read_totals(&conn, &self.keying_key, &self.enc_key)
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
    /// Rows stream in ascending key order (constant-memory).
    ///
    /// This reads the **whole** index, which is right for a question about the
    /// whole vault — a recursive listing, a scrub, a rebuild — and wrong for a
    /// question about one directory. [`children`](Index::children) is that one.
    pub fn for_each(&self, mut f: impl FnMut(Record) -> bool) -> Result<()> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT key, value FROM records ORDER BY key ASC;")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let key: Vec<u8> = row.get(0)?;
            let value: Vec<u8> = row.get(1)?;
            if !f(decode(&self.enc_key, &key, &value)?) {
                break;
            }
        }
        Ok(())
    }

    /// Invoke `f` for each file sitting **directly** in `dir`; stop on `false`.
    ///
    /// One indexed lookup on the parent column: the work is the directory's own
    /// width, not the vault's size. This is what `readdir` reads, and replacing
    /// a whole-index scan with it is what took a 100,000-file tree walk from 417
    /// seconds to linear.
    ///
    /// Rows arrive in no useful order — the key is a hash — so a caller that
    /// owes an ordered answer sorts what it received, which is bounded by the
    /// directory rather than by the vault.
    pub fn children(&self, dir: &str, mut f: impl FnMut(Record) -> bool) -> Result<()> {
        let parent = index_key(&self.keying_key, dir);
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT key, value FROM records WHERE parent = ?1;")?;
        let mut rows = stmt.query(rusqlite::params![&parent[..]])?;
        while let Some(row) = rows.next()? {
            let key: Vec<u8> = row.get(0)?;
            let value: Vec<u8> = row.get(1)?;
            if !f(decode(&self.enc_key, &key, &value)?) {
                break;
            }
        }
        Ok(())
    }

    /// Invoke `f` with the logical path of each directory sitting directly in
    /// `dir`; stop on `false`.
    ///
    /// The companion to [`children`](Index::children): together they are one
    /// `readdir`. A directory is here because something is under it, so this
    /// never reports one that would list empty.
    pub fn child_dirs(&self, dir: &str, mut f: impl FnMut(String) -> bool) -> Result<()> {
        let parent = index_key(&self.keying_key, dir);
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT key, value FROM dirs WHERE parent = ?1;")?;
        let mut rows = stmt.query(rusqlite::params![&parent[..]])?;
        while let Some(row) = rows.next()? {
            let key: Vec<u8> = row.get(0)?;
            let value: Vec<u8> = row.get(1)?;
            let plaintext =
                aead::decrypt(&self.enc_key, &value, &key).map_err(|_| IndexError::Crypto)?;
            let path = String::from_utf8(plaintext.to_vec()).map_err(|_| IndexError::Serialize)?;
            if !f(path) {
                break;
            }
        }
        Ok(())
    }

    /// Read one record inside an open transaction.
    fn read(tx: &Transaction<'_>, enc_key: &[u8; 32], key: &[u8; 32]) -> Result<Option<Record>> {
        let value: Option<Vec<u8>> = tx
            .query_row(
                "SELECT value FROM records WHERE key = ?1;",
                rusqlite::params![&key[..]],
                |row| row.get(0),
            )
            .optional()?;
        match value {
            Some(value) => Ok(Some(decode(enc_key, key, &value)?)),
            None => Ok(None),
        }
    }

    /// Move one directory's reference count, creating or collecting the row.
    ///
    /// `delta` is `+1` when a file arrives under it and `-1` when one leaves.
    /// The row is deleted the moment the count reaches zero, in the same
    /// statement that decrements it, so no later pass has to look for empties.
    fn bump_dir(
        tx: &Transaction<'_>,
        keying_key: &[u8; 32],
        enc_key: &[u8; 32],
        dir: &str,
        delta: i64,
    ) -> Result<()> {
        let key = index_key(keying_key, dir);
        if delta > 0 {
            let parent = index_key(keying_key, parent_of(dir));
            let value =
                aead::encrypt(enc_key, dir.as_bytes(), &key).map_err(|_| IndexError::Crypto)?;
            tx.execute(
                "INSERT INTO dirs(key, parent, value, refs) VALUES(?1, ?2, ?3, ?4) \
                 ON CONFLICT(key) DO UPDATE SET refs = refs + ?4;",
                rusqlite::params![&key[..], &parent[..], &value[..], delta],
            )?;
        } else {
            tx.execute(
                "UPDATE dirs SET refs = refs + ?2 WHERE key = ?1;",
                rusqlite::params![&key[..], delta],
            )?;
            tx.execute(
                "DELETE FROM dirs WHERE key = ?1 AND refs <= 0;",
                rusqlite::params![&key[..]],
            )?;
        }
        Ok(())
    }

    /// Carry the totals past one record being replaced by another.
    ///
    /// `was` is what the row held and `now` is what it will hold; either may be
    /// absent, which is how an insert and a delete are the same operation here.
    fn shift_totals(
        tx: &Transaction<'_>,
        keying_key: &[u8; 32],
        enc_key: &[u8; 32],
        was: Option<&Record>,
        now: Option<&Record>,
    ) -> Result<()> {
        let mut totals = Self::read_totals(tx, keying_key, enc_key)?;
        if let Some(record) = was {
            totals.objects = totals.objects.saturating_sub(1);
            if record.unmeasured() {
                totals.unmeasured = totals.unmeasured.saturating_sub(1);
            } else {
                totals.bytes = totals.bytes.saturating_sub(record.size);
            }
        }
        if let Some(record) = now {
            totals.objects = totals.objects.saturating_add(1);
            if record.unmeasured() {
                totals.unmeasured = totals.unmeasured.saturating_add(1);
            } else {
                totals.bytes = totals.bytes.saturating_add(record.size);
            }
        }
        Self::write_totals(tx, keying_key, enc_key, totals)
    }

    /// Read the sealed totals row, or a zeroed one when it has never been written.
    fn read_totals(
        conn: &Connection,
        keying_key: &[u8; 32],
        enc_key: &[u8; 32],
    ) -> Result<Totals> {
        let key = index_key(keying_key, TOTALS_DOMAIN);
        let value: Option<Vec<u8>> = conn
            .query_row(
                "SELECT value FROM totals WHERE id = ?1;",
                rusqlite::params![TOTALS_ROW],
                |row| row.get(0),
            )
            .optional()?;
        let Some(value) = value else {
            return Ok(Totals::default());
        };
        let plaintext = aead::decrypt(enc_key, &value, &key).map_err(|_| IndexError::Crypto)?;
        postcard::from_bytes(&plaintext).map_err(|_| IndexError::Serialize)
    }

    /// Seal and store the totals row.
    fn write_totals(
        conn: &Connection,
        keying_key: &[u8; 32],
        enc_key: &[u8; 32],
        totals: Totals,
    ) -> Result<()> {
        let key = index_key(keying_key, TOTALS_DOMAIN);
        let plaintext = postcard::to_allocvec(&totals).map_err(|_| IndexError::Serialize)?;
        let blob = aead::encrypt(enc_key, &plaintext, &key).map_err(|_| IndexError::Crypto)?;
        conn.execute(
            "INSERT INTO totals(id, value) VALUES(?1, ?2) \
             ON CONFLICT(id) DO UPDATE SET value = excluded.value;",
            rusqlite::params![TOTALS_ROW, &blob[..]],
        )?;
        Ok(())
    }
}

/// One directory discovered while migrating, and how much is under it.
struct MigratedDir {
    path: String,
    parent: [u8; 32],
    refs: u64,
}

/// What a migration pass accumulates: the directories implied by the records it
/// saw, and the totals they add up to.
///
/// Bounded by the number of *directories* rather than files — the tree's fan-out
/// smaller — which is why the record stream itself does not have to be buffered.
#[derive(Default)]
struct Carried {
    dirs: HashMap<[u8; 32], MigratedDir>,
    totals: Totals,
}

impl Carried {
    /// Fold one record into the counts.
    fn absorb(&mut self, keying_key: &[u8; 32], record: &Record) {
        for dir in ancestors_of(&record.path) {
            let key = index_key(keying_key, dir);
            self.dirs
                .entry(key)
                .or_insert_with(|| MigratedDir {
                    path: dir.to_string(),
                    parent: index_key(keying_key, parent_of(dir)),
                    refs: 0,
                })
                .refs += 1;
        }
        self.totals.objects = self.totals.objects.saturating_add(1);
        if record.unmeasured() {
            self.totals.unmeasured = self.totals.unmeasured.saturating_add(1);
        } else {
            self.totals.bytes = self.totals.bytes.saturating_add(record.size);
        }
    }
}

/// Open one sealed row into the record it holds.
fn decode(enc_key: &[u8; 32], key: &[u8], value: &[u8]) -> Result<Record> {
    let plaintext = aead::decrypt(enc_key, value, key).map_err(|_| IndexError::Crypto)?;
    postcard::from_bytes(&plaintext).map_err(|_| IndexError::Serialize)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample(path: &str, size: u64) -> Record {
        Record {
            path: path.to_string(),
            object_key: format!("obj/{size}"),
            size,
            modified_unix: Some(1_700_000_000),
            content_hash: vec![9, 9],
        }
    }

    /// Reshape an open index back into the version-0 layout: records carrying
    /// only a key and a value, no directory rows, no totals, no version stamp.
    ///
    /// This is what every database written before directory-keyed listing looks
    /// like, and the only way to test the migration against the real thing
    /// rather than against a hand-built fixture that might not match.
    fn downgrade_to_version_zero(index: &Index) {
        let conn = index.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE records_v0(\
                 key   BLOB PRIMARY KEY NOT NULL, \
                 value BLOB NOT NULL\
             ) WITHOUT ROWID;\
             INSERT INTO records_v0(key, value) SELECT key, value FROM records;\
             DROP TABLE records;\
             ALTER TABLE records_v0 RENAME TO records;\
             DROP TABLE dirs;\
             DROP TABLE totals;\
             PRAGMA user_version = 0;",
        )
        .unwrap();
    }

    #[test]
    fn a_version_zero_database_gains_its_directories_and_totals_on_open() {
        // The upgrade every existing index takes exactly once. The paths live
        // inside the sealed values, so the directories and the totals can only
        // be derived by reading the records — which is why this is the one
        // operation that legitimately reads the whole index.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v0.db");
        let subkey = [21u8; 32];

        {
            let index = Index::open(&path, &subkey).unwrap();
            for (file, size) in [
                ("photos/2024/a.jpg", 10),
                ("photos/b.jpg", 20),
                ("docs/report.pdf", 30),
                ("top.txt", 40),
            ] {
                index.put(&sample(file, size)).unwrap();
            }
            downgrade_to_version_zero(&index);
        }

        let upgraded = Index::open(&path, &subkey).unwrap();

        // Every record survived the table rewrite.
        assert_eq!(upgraded.count().unwrap(), 4);
        assert_eq!(upgraded.get("photos/b.jpg").unwrap().unwrap().size, 20);

        // …and the tree that was only ever implicit in the paths now exists.
        let mut roots = Vec::new();
        upgraded
            .child_dirs("", |path| {
                roots.push(path);
                true
            })
            .unwrap();
        roots.sort();
        assert_eq!(roots, vec!["docs".to_string(), "photos".to_string()]);

        let mut inside = Vec::new();
        upgraded
            .children("photos", |record| {
                inside.push(record.path);
                true
            })
            .unwrap();
        assert_eq!(inside, vec!["photos/b.jpg".to_string()]);
        assert!(upgraded.contains_dir("photos/2024").unwrap());

        let totals = upgraded.totals().unwrap();
        assert_eq!(
            (totals.objects, totals.measured_bytes()),
            (4, Some(100)),
            "the totals are derived from the records, not started from zero"
        );
    }

    #[test]
    fn a_migrated_database_is_not_migrated_again() {
        // The pass is O(the whole index); running it on every open would make
        // every start-up cost what the walk used to.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("once.db");
        let subkey = [22u8; 32];
        {
            let index = Index::open(&path, &subkey).unwrap();
            index.put(&sample("a/b.txt", 5)).unwrap();
            downgrade_to_version_zero(&index);
        }

        let first = Index::open(&path, &subkey).unwrap();
        assert_eq!(first.totals().unwrap().objects, 1);
        drop(first);

        // A second open must leave the counts exactly as they were — a migration
        // that ran twice would double every directory's reference count and
        // every byte of the totals.
        let second = Index::open(&path, &subkey).unwrap();
        let totals = second.totals().unwrap();
        assert_eq!((totals.objects, totals.measured_bytes()), (1, Some(5)));

        second.delete("a/b.txt").unwrap();
        assert!(
            !second.contains_dir("a").unwrap(),
            "a doubled reference count would leave the directory behind"
        );
    }

    #[test]
    fn a_freshly_created_database_is_already_current() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(&dir.path().join("new.db"), &[23u8; 32]).unwrap();
        let conn = index.lock().unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }
}
