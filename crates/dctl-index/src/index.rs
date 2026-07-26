//! The encrypted index over stored objects.

use std::path::Path;

use dctl_crypto::aead;
use dctl_crypto::keys::derive_subkey;
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use zeroize::Zeroizing;

use crate::error::{IndexError, Result};
use crate::keying::index_key;
use crate::record::Record;

/// Table mapping a 32-byte keyed-hash of the path to the AEAD-encrypted record.
const RECORDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("records");

/// An encrypted, metadata-private index over stored objects.
///
/// Constructed from the vault's index sub-key (`HKDF(root, "index")`), from which
/// two independent keys are derived: one for keying (hashing paths into database
/// keys) and one for encrypting record values.
pub struct Index {
    db: Database,
    keying_key: Zeroizing<[u8; 32]>,
    enc_key: Zeroizing<[u8; 32]>,
}

impl Index {
    /// Open (or create) an index database at `path`.
    pub fn open(path: &Path, index_subkey: &[u8; 32]) -> Result<Self> {
        let db = Database::create(path).map_err(|e| IndexError::Db(e.to_string()))?;

        // Ensure the table exists so read-only transactions on a fresh db succeed.
        let tx = db
            .begin_write()
            .map_err(|e| IndexError::Db(e.to_string()))?;
        tx.open_table(RECORDS)
            .map_err(|e| IndexError::Db(e.to_string()))?;
        tx.commit().map_err(|e| IndexError::Db(e.to_string()))?;

        let keying_key =
            derive_subkey(index_subkey, b"index-keying-v1").map_err(|_| IndexError::Crypto)?;
        let enc_key =
            derive_subkey(index_subkey, b"index-encryption-v1").map_err(|_| IndexError::Crypto)?;

        Ok(Self {
            db,
            keying_key,
            enc_key,
        })
    }

    /// Insert or replace the record for its path.
    pub fn put(&self, record: &Record) -> Result<()> {
        let key = index_key(&self.keying_key, &record.path);
        let plaintext = postcard::to_allocvec(record).map_err(|_| IndexError::Serialize)?;
        let blob =
            aead::encrypt(&self.enc_key, &plaintext, &key).map_err(|_| IndexError::Crypto)?;

        let tx = self
            .db
            .begin_write()
            .map_err(|e| IndexError::Db(e.to_string()))?;
        {
            let mut table = tx
                .open_table(RECORDS)
                .map_err(|e| IndexError::Db(e.to_string()))?;
            table
                .insert(key.as_slice(), blob.as_slice())
                .map_err(|e| IndexError::Db(e.to_string()))?;
        }
        tx.commit().map_err(|e| IndexError::Db(e.to_string()))?;
        Ok(())
    }

    /// Look up the record for `path`.
    pub fn get(&self, path: &str) -> Result<Option<Record>> {
        let key = index_key(&self.keying_key, path);
        let tx = self
            .db
            .begin_read()
            .map_err(|e| IndexError::Db(e.to_string()))?;
        let table = tx
            .open_table(RECORDS)
            .map_err(|e| IndexError::Db(e.to_string()))?;
        let Some(guard) = table
            .get(key.as_slice())
            .map_err(|e| IndexError::Db(e.to_string()))?
        else {
            return Ok(None);
        };
        let plaintext =
            aead::decrypt(&self.enc_key, guard.value(), &key).map_err(|_| IndexError::Crypto)?;
        let record: Record = postcard::from_bytes(&plaintext).map_err(|_| IndexError::Serialize)?;
        Ok(Some(record))
    }

    /// Whether a record exists for `path` (no decryption).
    pub fn contains(&self, path: &str) -> Result<bool> {
        let key = index_key(&self.keying_key, path);
        let tx = self
            .db
            .begin_read()
            .map_err(|e| IndexError::Db(e.to_string()))?;
        let table = tx
            .open_table(RECORDS)
            .map_err(|e| IndexError::Db(e.to_string()))?;
        Ok(table
            .get(key.as_slice())
            .map_err(|e| IndexError::Db(e.to_string()))?
            .is_some())
    }

    /// Remove the record for `path`. Returns whether a record was present.
    pub fn delete(&self, path: &str) -> Result<bool> {
        let key = index_key(&self.keying_key, path);
        let tx = self
            .db
            .begin_write()
            .map_err(|e| IndexError::Db(e.to_string()))?;
        let existed;
        {
            let mut table = tx
                .open_table(RECORDS)
                .map_err(|e| IndexError::Db(e.to_string()))?;
            existed = table
                .remove(key.as_slice())
                .map_err(|e| IndexError::Db(e.to_string()))?
                .is_some();
        }
        tx.commit().map_err(|e| IndexError::Db(e.to_string()))?;
        Ok(existed)
    }

    /// Number of records.
    pub fn count(&self) -> Result<u64> {
        let tx = self
            .db
            .begin_read()
            .map_err(|e| IndexError::Db(e.to_string()))?;
        let table = tx
            .open_table(RECORDS)
            .map_err(|e| IndexError::Db(e.to_string()))?;
        table.len().map_err(|e| IndexError::Db(e.to_string()))
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
    /// Constant-memory streaming enumeration (millions-of-files safe).
    pub fn for_each(&self, mut f: impl FnMut(Record) -> bool) -> Result<()> {
        let tx = self
            .db
            .begin_read()
            .map_err(|e| IndexError::Db(e.to_string()))?;
        let table = tx
            .open_table(RECORDS)
            .map_err(|e| IndexError::Db(e.to_string()))?;
        for entry in table.iter().map_err(|e| IndexError::Db(e.to_string()))? {
            let (key_guard, value_guard) = entry.map_err(|e| IndexError::Db(e.to_string()))?;
            let plaintext = aead::decrypt(&self.enc_key, value_guard.value(), key_guard.value())
                .map_err(|_| IndexError::Crypto)?;
            let record: Record =
                postcard::from_bytes(&plaintext).map_err(|_| IndexError::Serialize)?;
            if !f(record) {
                break;
            }
        }
        Ok(())
    }
}
