//! Persistent state storage
//!
//! This module owns the [`PersistentState`] trait and the production
//! [`RedbPersistentState`] implementation backed by `redb`. It also holds
//! the [`hash_data`] helper used by callers that need a blake3 hash of
//! arbitrary bytes.
//!
//! Thread safety: the trait is `Send + Sync`, but writes are not internally
//! synchronized. Callers must serialize concurrent writers (e.g. via a
//! `Mutex`, or by ensuring a single thread owns the instance).

use crate::hash;
use guisu_core::{Error, Result};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::path::Path;

/// Database bucket name for entry state (tracks file content hashes and modes)
pub const ENTRY_STATE_BUCKET: &str = "entryState";
/// Database bucket name for hook state (tracks hook execution and hashes)
pub const HOOK_STATE_BUCKET: &str = "hookState";
/// Database bucket name for config metadata (tracks rendered config and template hash)
pub const CONFIG_METADATA_BUCKET: &str = "configMetadata";

/// Trait for persistent state storage
///
/// # Thread safety
///
/// The trait is `Send + Sync`, but **write methods (`set`, `set_batch`,
/// `delete`, `delete_bucket`) are not internally synchronized** — the
/// redb backend's optimistic-MVCC model means concurrent writers can
/// surface `TransactionError` when two writes race. Callers sharing a
/// `PersistentState` across threads must serialize writes themselves
/// (e.g. by holding a `Mutex` over the instance, or by ensuring a
/// single thread owns it and others receive messages).
///
/// Read methods (`get`, `for_each`, `close`) are safe to call from
/// multiple threads concurrently against the same instance, subject
/// to the backend's own guarantees.
///
/// Write methods (`set`, `set_batch`, `delete`, `delete_bucket`) take
/// `&mut self` so the borrow checker enforces single-writer at
/// compile time. Callers that previously held a shared reference
/// (e.g. via `Arc<RedbPersistentState>`) must now pass `&mut`.
pub trait PersistentState: Send + Sync {
    /// Get a value from a bucket
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be retrieved (e.g., database error, read failure)
    fn get(&self, bucket: &str, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Set a value in a bucket
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be stored (e.g., database error, write failure, transaction error)
    fn set(&mut self, bucket: &str, key: &[u8], value: &[u8]) -> Result<()>;

    /// Set multiple values in a bucket in a single transaction
    ///
    /// This is more efficient than calling `set()` multiple times as it batches
    /// all writes into a single database transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the values cannot be stored (e.g., database error, write failure, transaction error)
    fn set_batch(&mut self, bucket: &str, entries: &[(&[u8], &[u8])]) -> Result<()>;

    /// Delete a key from a bucket
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be deleted (e.g., database error, write failure, transaction error)
    fn delete(&mut self, bucket: &str, key: &[u8]) -> Result<()>;

    /// Delete an entire bucket
    ///
    /// # Errors
    ///
    /// Returns an error if the bucket cannot be deleted (e.g., database error, transaction error)
    fn delete_bucket(&mut self, bucket: &str) -> Result<()>;

    /// Iterate over all key-value pairs in a bucket
    ///
    /// # Errors
    ///
    /// Returns an error if iteration fails or the callback returns an error (e.g., database error, read failure, callback error)
    fn for_each<F>(&self, bucket: &str, f: F) -> Result<()>
    where
        F: FnMut(&[u8], &[u8]) -> Result<()>;

    /// Close the database
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be closed properly (e.g., outstanding transactions, I/O error)
    fn close(self) -> Result<()>;
}

/// Persistent state implementation using redb
///
/// # Thread Safety
///
/// While `RedbPersistentState` is `Send + Sync` and can be shared across threads,
/// concurrent write operations are serialized internally by redb.
///
/// For application-level access control, use the singleton pattern in `database.rs`
/// which wraps this in `Arc<Mutex<Option<RedbPersistentState>>>` to ensure
/// exclusive access during operations.
pub struct RedbPersistentState {
    db: Database,
}

// Static assertions to ensure thread safety
const _: () = {
    const fn assert_send<T: Send>() {}
    const fn assert_sync<T: Sync>() {}

    let _ = assert_send::<RedbPersistentState>;
    let _ = assert_sync::<RedbPersistentState>;
};

impl RedbPersistentState {
    /// Create or open a persistent state database
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be created or opened (e.g., permission denied, disk full, corrupted database)
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path).map_err(|e| Error::DatabaseTransaction {
            operation: "create",
            source: Box::new(e),
        })?;
        Ok(Self { db })
    }

    /// Open in read-only mode
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened (e.g., file not found, permission denied, corrupted database)
    pub fn read_only(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::open(path).map_err(|e| Error::DatabaseTransaction {
            operation: "open",
            source: Box::new(e),
        })?;
        Ok(Self { db })
    }

    /// Create table definition for known bucket names
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidBucket` if called with an unknown bucket name.
    /// Valid bucket names are `ENTRY_STATE_BUCKET`, `HOOK_STATE_BUCKET`, and
    /// `CONFIG_METADATA_BUCKET`.
    #[inline]
    fn table_def_with_storage(
        bucket: &str,
    ) -> Result<TableDefinition<'static, &'static [u8], &'static [u8]>> {
        match bucket {
            ENTRY_STATE_BUCKET => Ok(TableDefinition::new(ENTRY_STATE_BUCKET)),
            HOOK_STATE_BUCKET => Ok(TableDefinition::new(HOOK_STATE_BUCKET)),
            CONFIG_METADATA_BUCKET => Ok(TableDefinition::new(CONFIG_METADATA_BUCKET)),
            _ => Err(Error::InvalidBucket {
                name: bucket.to_string(),
                context: "Valid buckets are ENTRY_STATE_BUCKET, HOOK_STATE_BUCKET, \
                          and CONFIG_METADATA_BUCKET. This is a programming error."
                    .to_string(),
            }),
        }
    }
}

impl PersistentState for RedbPersistentState {
    fn get(&self, bucket: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::DatabaseTransaction {
                operation: "begin_read",
                source: Box::new(e),
            })?;
        let table_def = Self::table_def_with_storage(bucket)?;

        // Table doesn't exist yet
        let Ok(table) = read_txn.open_table(table_def) else {
            return Ok(None);
        };

        match table.get(key) {
            Ok(Some(value)) => Ok(Some(value.value().to_vec())),
            Ok(None) => Ok(None),
            Err(e) => Err(Error::BucketOperation {
                operation: "get",
                bucket: bucket.to_string(),
                source: Box::new(e),
            }),
        }
    }

    fn set(&mut self, bucket: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| Error::DatabaseTransaction {
                operation: "begin_write",
                source: Box::new(e),
            })?;
        {
            let table_def = Self::table_def_with_storage(bucket)?;
            let mut table =
                write_txn
                    .open_table(table_def)
                    .map_err(|e| Error::BucketOperation {
                        operation: "open_table",
                        bucket: bucket.to_string(),
                        source: Box::new(e),
                    })?;
            table
                .insert(key, value)
                .map_err(|e| Error::BucketOperation {
                    operation: "insert",
                    bucket: bucket.to_string(),
                    source: Box::new(e),
                })?;
        }
        write_txn.commit().map_err(|e| Error::DatabaseTransaction {
            operation: "commit",
            source: Box::new(e),
        })?;
        Ok(())
    }

    fn set_batch(&mut self, bucket: &str, entries: &[(&[u8], &[u8])]) -> Result<()> {
        // Early return for empty batch
        if entries.is_empty() {
            return Ok(());
        }

        // Single transaction for all entries
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| Error::DatabaseTransaction {
                operation: "begin_write",
                source: Box::new(e),
            })?;
        {
            let table_def = Self::table_def_with_storage(bucket)?;
            let mut table =
                write_txn
                    .open_table(table_def)
                    .map_err(|e| Error::BucketOperation {
                        operation: "open_table",
                        bucket: bucket.to_string(),
                        source: Box::new(e),
                    })?;

            // Insert all entries in the same transaction
            for (key, value) in entries {
                table
                    .insert(*key, *value)
                    .map_err(|e| Error::BucketOperation {
                        operation: "insert",
                        bucket: bucket.to_string(),
                        source: Box::new(e),
                    })?;
            }
        }
        write_txn.commit().map_err(|e| Error::DatabaseTransaction {
            operation: "commit",
            source: Box::new(e),
        })?;
        Ok(())
    }

    fn delete(&mut self, bucket: &str, key: &[u8]) -> Result<()> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| Error::DatabaseTransaction {
                operation: "begin_write",
                source: Box::new(e),
            })?;
        {
            let table_def = Self::table_def_with_storage(bucket)?;
            let mut table =
                write_txn
                    .open_table(table_def)
                    .map_err(|e| Error::BucketOperation {
                        operation: "open_table",
                        bucket: bucket.to_string(),
                        source: Box::new(e),
                    })?;
            table.remove(key).map_err(|e| Error::BucketOperation {
                operation: "remove",
                bucket: bucket.to_string(),
                source: Box::new(e),
            })?;
        }
        write_txn.commit().map_err(|e| Error::DatabaseTransaction {
            operation: "commit",
            source: Box::new(e),
        })?;
        Ok(())
    }

    fn delete_bucket(&mut self, bucket: &str) -> Result<()> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| Error::DatabaseTransaction {
                operation: "begin_write",
                source: Box::new(e),
            })?;
        let table_def = Self::table_def_with_storage(bucket)?;
        write_txn
            .delete_table(table_def)
            .map_err(|e| Error::DatabaseTransaction {
                operation: "delete_table",
                source: Box::new(e),
            })?;
        write_txn.commit().map_err(|e| Error::DatabaseTransaction {
            operation: "commit",
            source: Box::new(e),
        })?;
        Ok(())
    }

    fn for_each<F>(&self, bucket: &str, mut f: F) -> Result<()>
    where
        F: FnMut(&[u8], &[u8]) -> Result<()>,
    {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::DatabaseTransaction {
                operation: "begin_read",
                source: Box::new(e),
            })?;
        let table_def = Self::table_def_with_storage(bucket)?;

        // No bucket yet
        let Ok(table) = read_txn.open_table(table_def) else {
            return Ok(());
        };

        let iter = table.iter().map_err(|e| Error::BucketOperation {
            operation: "iter",
            bucket: bucket.to_string(),
            source: Box::new(e),
        })?;

        for item in iter {
            let (key, value) = item.map_err(|e| Error::BucketOperation {
                operation: "iter_next",
                bucket: bucket.to_string(),
                source: Box::new(e),
            })?;
            f(key.value(), value.value())?;
        }

        Ok(())
    }

    fn close(self) -> Result<()> {
        // redb closes automatically when dropped
        drop(self.db);
        Ok(())
    }
}

/// Compute blake3 hash of data
#[inline]
#[must_use]
pub fn hash_data(data: &[u8]) -> [u8; 32] {
    hash::hash_content(data)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::state::{EntryState, HookState, ScriptState};

    fn test_db_setup() -> (tempfile::TempDir, RedbPersistentState) {
        let temp_dir = tempfile::TempDir::new().expect("failed to create temp directory");
        let db_path = temp_dir.path().join("test.db");
        let db = RedbPersistentState::new(&db_path).expect("failed to create database");
        (temp_dir, db)
    }

    #[test]
    fn test_set_and_get() {
        let (mut _temp, mut db) = test_db_setup();

        db.set(ENTRY_STATE_BUCKET, b"key1", b"value1")
            .expect("failed to set");
        let value = db.get(ENTRY_STATE_BUCKET, b"key1").expect("failed to get");
        assert_eq!(value, Some(b"value1".to_vec()));
    }

    #[test]
    fn test_overwrite() {
        let (mut _temp, mut db) = test_db_setup();

        db.set(ENTRY_STATE_BUCKET, b"key1", b"value1")
            .expect("failed to set");
        db.set(ENTRY_STATE_BUCKET, b"key1", b"value2")
            .expect("failed to overwrite");
        let value = db.get(ENTRY_STATE_BUCKET, b"key1").expect("failed to get");
        assert_eq!(value, Some(b"value2".to_vec()));
    }

    #[test]
    fn test_delete() {
        let (mut _temp, mut db) = test_db_setup();

        db.set(ENTRY_STATE_BUCKET, b"key1", b"value1")
            .expect("failed to set");
        db.delete(ENTRY_STATE_BUCKET, b"key1")
            .expect("failed to delete");
        let value = db.get(ENTRY_STATE_BUCKET, b"key1").expect("failed to get");
        assert_eq!(value, None);
    }

    #[test]
    fn test_set_batch() {
        let (mut _temp, mut db) = test_db_setup();

        let entries = [
            (b"key1".as_slice(), b"value1".as_slice()),
            (b"key2".as_slice(), b"value2".as_slice()),
            (b"key3".as_slice(), b"value3".as_slice()),
        ];
        db.set_batch(ENTRY_STATE_BUCKET, &entries)
            .expect("failed to set batch");

        for (key, expected) in &entries {
            let value = db
                .get(ENTRY_STATE_BUCKET, key)
                .expect("failed to get")
                .unwrap_or_else(|| panic!("key {key:?} should exist"));
            assert_eq!(&value, expected);
        }
    }

    #[test]
    fn test_delete_bucket() {
        let (mut _temp, mut db) = test_db_setup();

        db.set(ENTRY_STATE_BUCKET, b"key1", b"value1")
            .expect("failed to set");
        db.set(HOOK_STATE_BUCKET, b"key1", b"value1")
            .expect("failed to set in hook bucket");

        db.delete_bucket(ENTRY_STATE_BUCKET)
            .expect("failed to delete bucket");

        assert_eq!(
            db.get(ENTRY_STATE_BUCKET, b"key1").expect("failed to get"),
            None
        );
        // Other bucket should be untouched
        assert_eq!(
            db.get(HOOK_STATE_BUCKET, b"key1").expect("failed to get"),
            Some(b"value1".to_vec())
        );
    }

    #[test]
    fn test_for_each() {
        let (mut _temp, mut db) = test_db_setup();

        let entries = [
            (b"key1".as_slice(), b"value1".as_slice()),
            (b"key2".as_slice(), b"value2".as_slice()),
        ];
        db.set_batch(ENTRY_STATE_BUCKET, &entries)
            .expect("failed to set batch");

        let mut collected = std::collections::HashMap::new();
        db.for_each(ENTRY_STATE_BUCKET, |k, v| {
            collected.insert(k.to_vec(), v.to_vec());
            Ok(())
        })
        .expect("for_each failed");

        assert_eq!(collected.len(), 2);
        assert_eq!(collected.get(b"key1".as_slice()), Some(&b"value1".to_vec()));
        assert_eq!(collected.get(b"key2".as_slice()), Some(&b"value2".to_vec()));
    }

    #[test]
    fn test_invalid_bucket() {
        let (mut _temp, db) = test_db_setup();

        let result = db.get("nonexistent_bucket", b"key");
        assert!(result.is_err());
    }

    #[test]
    fn test_persistence_across_instances() {
        let temp_dir = tempfile::TempDir::new().expect("failed to create temp directory");
        let db_path = temp_dir.path().join("test.db");

        {
            let mut db = RedbPersistentState::new(&db_path).expect("failed to create database");
            db.set(ENTRY_STATE_BUCKET, b"key1", b"value1")
                .expect("failed to set");
        }

        {
            let db = RedbPersistentState::new(&db_path).expect("failed to reopen database");
            let value = db.get(ENTRY_STATE_BUCKET, b"key1").expect("failed to get");
            assert_eq!(value, Some(b"value1".to_vec()));
        }
    }

    #[test]
    fn test_mock_persistent_state() {
        let mut mock = MockPersistentState::new();

        mock.set(ENTRY_STATE_BUCKET, b"key1", b"value1")
            .expect("failed to set");
        let value = mock
            .get(ENTRY_STATE_BUCKET, b"key1")
            .expect("failed to get");
        assert_eq!(value, Some(b"value1".to_vec()));

        mock.delete(ENTRY_STATE_BUCKET, b"key1")
            .expect("failed to delete");
        let value = mock
            .get(ENTRY_STATE_BUCKET, b"key1")
            .expect("failed to get");
        assert_eq!(value, None);
    }

    #[test]
    fn test_entry_state_serialization() {
        let state = EntryState::new(b"test content", Some(0o644));
        let bytes = state.to_bytes().expect("failed to serialize");
        let restored = EntryState::from_bytes(&bytes).expect("failed to deserialize");
        assert_eq!(state, restored);
    }

    #[test]
    fn test_script_state_serialization() {
        let state = ScriptState::new(b"echo hello");
        let bytes = state.to_bytes().expect("failed to serialize");
        let restored = ScriptState::from_bytes(&bytes).expect("failed to deserialize");
        assert_eq!(state, restored);
    }

    #[test]
    fn test_hook_state_serialization() {
        let mut state = HookState::new();
        state.content_hash = Some([1u8; 32]);
        state.once_executed.insert("hook1".to_string());
        state.onchange_hashes.insert("hook2".to_string(), [2u8; 32]);
        state
            .onchange_rendered
            .insert("hook2".to_string(), "echo changed".to_string());

        let bytes = state.to_bytes().expect("failed to serialize");
        let restored = HookState::from_bytes(&bytes).expect("failed to deserialize");
        assert_eq!(state, restored);
    }

    #[test]
    fn test_hook_state_serialization_with_optional_fields() {
        // Test serialization roundtrip with None fields
        let state = HookState::new();
        let bytes = state.to_bytes().expect("failed to serialize");
        let restored = HookState::from_bytes(&bytes).expect("failed to deserialize");
        assert_eq!(state, restored);
    }

    mod mock {
        //! In-memory mock of [`super::PersistentState`] for tests.
        //!
        //! Wrapped in a `RwLock` so the impl satisfies `Send + Sync` — the
        //! supertrait requires it, even though every production caller holds
        //! the mock on a single thread.

        use std::collections::HashMap;
        use std::sync::RwLock;

        type BucketData = HashMap<Vec<u8>, Vec<u8>>;
        type StateData = HashMap<String, BucketData>;

        pub(super) struct MockPersistentState {
            data: RwLock<StateData>,
        }

        impl MockPersistentState {
            pub(super) fn new() -> Self {
                Self {
                    data: RwLock::new(HashMap::new()),
                }
            }
        }

        impl Default for MockPersistentState {
            fn default() -> Self {
                Self::new()
            }
        }

        impl super::PersistentState for MockPersistentState {
            fn get(&self, bucket: &str, key: &[u8]) -> super::Result<Option<Vec<u8>>> {
                let data = self
                    .data
                    .read()
                    .expect("MockPersistentState lock should not be poisoned");
                Ok(data.get(bucket).and_then(|b| b.get(key).cloned()))
            }

            fn set(&mut self, bucket: &str, key: &[u8], value: &[u8]) -> super::Result<()> {
                let mut data = self
                    .data
                    .write()
                    .expect("MockPersistentState lock should not be poisoned");
                data.entry(bucket.to_string())
                    .or_default()
                    .insert(key.to_vec(), value.to_vec());
                Ok(())
            }

            fn set_batch(&mut self, bucket: &str, entries: &[(&[u8], &[u8])]) -> super::Result<()> {
                let mut data = self
                    .data
                    .write()
                    .expect("MockPersistentState lock should not be poisoned");
                let bucket_data = data.entry(bucket.to_string()).or_default();
                for (key, value) in entries {
                    bucket_data.insert(key.to_vec(), value.to_vec());
                }
                Ok(())
            }

            fn delete(&mut self, bucket: &str, key: &[u8]) -> super::Result<()> {
                let mut data = self
                    .data
                    .write()
                    .expect("MockPersistentState lock should not be poisoned");
                if let Some(bucket_data) = data.get_mut(bucket) {
                    bucket_data.remove(key);
                }
                Ok(())
            }

            fn delete_bucket(&mut self, bucket: &str) -> super::Result<()> {
                let mut data = self
                    .data
                    .write()
                    .expect("MockPersistentState lock should not be poisoned");
                data.remove(bucket);
                Ok(())
            }

            fn for_each<F>(&self, bucket: &str, mut f: F) -> super::Result<()>
            where
                F: FnMut(&[u8], &[u8]) -> super::Result<()>,
            {
                let data = self
                    .data
                    .read()
                    .expect("MockPersistentState lock should not be poisoned");
                if let Some(bucket_data) = data.get(bucket) {
                    for (key, value) in bucket_data {
                        f(key, value)?;
                    }
                }
                Ok(())
            }

            fn close(self) -> super::Result<()> {
                Ok(())
            }
        }
    }

    use mock::MockPersistentState;
}
