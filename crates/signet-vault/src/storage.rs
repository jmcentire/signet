use rusqlite::{params, Connection};
use signet_core::{RecordId, SignetResult};
use std::sync::Mutex;
use subtle::ConstantTimeEq;

/// SQLite storage backend implementing the BlindDB server interface.
///
/// The server stores only opaque record IDs and ciphertext blobs.
/// It never sees plaintext, labels, or semantic meaning.
/// All addressing and encryption happen client-side.
pub struct SqliteBackend {
    conn: Mutex<Connection>,
}

impl SqliteBackend {
    /// Open or create a SQLite database at the given path.
    pub fn open(path: &str) -> SignetResult<Self> {
        let conn = Connection::open(path).map_err(|e| {
            signet_core::SignetError::Storage(format!("failed to open database: {}", e))
        })?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS records (
                record_id TEXT PRIMARY KEY NOT NULL,
                ciphertext BLOB NOT NULL,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );",
        )
        .map_err(|e| {
            signet_core::SignetError::Storage(format!("failed to create tables: {}", e))
        })?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create an in-memory database (for testing).
    pub fn in_memory() -> SignetResult<Self> {
        Self::open(":memory:")
    }
}

impl signet_core::StorageBackend for SqliteBackend {
    fn get(&self, record_id: &RecordId) -> SignetResult<Option<Vec<u8>>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| signet_core::SignetError::Storage(format!("lock poisoned: {}", e)))?;

        let result: Result<Vec<u8>, _> = conn.query_row(
            "SELECT ciphertext FROM records WHERE record_id = ?1",
            params![record_id.as_str()],
            |row| row.get(0),
        );

        match result {
            Ok(data) => Ok(Some(data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(signet_core::SignetError::Storage(format!(
                "query failed: {}",
                e
            ))),
        }
    }

    fn put(&self, record_id: &RecordId, ciphertext: &[u8]) -> SignetResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| signet_core::SignetError::Storage(format!("lock poisoned: {}", e)))?;

        conn.execute(
            "INSERT OR REPLACE INTO records (record_id, ciphertext, updated_at) VALUES (?1, ?2, datetime('now'))",
            params![record_id.as_str(), ciphertext],
        )
        .map_err(|e| {
            signet_core::SignetError::Storage(format!("insert failed: {}", e))
        })?;

        Ok(())
    }

    fn delete(&self, record_id: &RecordId) -> SignetResult<bool> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| signet_core::SignetError::Storage(format!("lock poisoned: {}", e)))?;

        let rows = conn
            .execute(
                "DELETE FROM records WHERE record_id = ?1",
                params![record_id.as_str()],
            )
            .map_err(|e| signet_core::SignetError::Storage(format!("delete failed: {}", e)))?;

        Ok(rows > 0)
    }

    fn compare_and_swap(
        &self,
        record_id: &RecordId,
        expected: Option<&[u8]>,
        new_value: &[u8],
    ) -> SignetResult<bool> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| signet_core::SignetError::Storage(format!("lock poisoned: {}", e)))?;

        let current: Option<Vec<u8>> = conn
            .query_row(
                "SELECT ciphertext FROM records WHERE record_id = ?1",
                params![record_id.as_str()],
                |row| row.get(0),
            )
            .ok();

        let matches = match (&current, expected) {
            (None, None) => true,
            (Some(curr), Some(exp)) => curr.as_slice().ct_eq(exp).into(),
            _ => false,
        };

        if matches {
            conn.execute(
                "INSERT OR REPLACE INTO records (record_id, ciphertext, updated_at) VALUES (?1, ?2, datetime('now'))",
                params![record_id.as_str(), new_value],
            )
            .map_err(|e| {
                signet_core::SignetError::Storage(format!("CAS insert failed: {}", e))
            })?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn exists(&self, record_id: &RecordId) -> SignetResult<bool> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| signet_core::SignetError::Storage(format!("lock poisoned: {}", e)))?;

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM records WHERE record_id = ?1",
                params![record_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|e| {
                signet_core::SignetError::Storage(format!("exists query failed: {}", e))
            })?;

        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signet_core::StorageBackend;

    fn test_backend() -> SqliteBackend {
        SqliteBackend::in_memory().unwrap()
    }

    #[test]
    fn test_get_nonexistent() {
        let backend = test_backend();
        let result = backend.get(&RecordId::new("nonexistent")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_put_and_get() {
        let backend = test_backend();
        let id = RecordId::new("test-record");
        let data = b"encrypted-data";

        backend.put(&id, data).unwrap();
        let result = backend.get(&id).unwrap().unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_put_overwrite() {
        let backend = test_backend();
        let id = RecordId::new("test-record");

        backend.put(&id, b"data-1").unwrap();
        backend.put(&id, b"data-2").unwrap();

        let result = backend.get(&id).unwrap().unwrap();
        assert_eq!(result, b"data-2");
    }

    #[test]
    fn test_delete() {
        let backend = test_backend();
        let id = RecordId::new("test-record");

        backend.put(&id, b"data").unwrap();
        assert!(backend.delete(&id).unwrap());
        assert!(backend.get(&id).unwrap().is_none());
    }

    #[test]
    fn test_delete_nonexistent() {
        let backend = test_backend();
        assert!(!backend.delete(&RecordId::new("nope")).unwrap());
    }

    #[test]
    fn test_exists() {
        let backend = test_backend();
        let id = RecordId::new("test-record");

        assert!(!backend.exists(&id).unwrap());
        backend.put(&id, b"data").unwrap();
        assert!(backend.exists(&id).unwrap());
    }

    #[test]
    fn test_compare_and_swap_insert() {
        let backend = test_backend();
        let id = RecordId::new("test-record");

        // CAS from None → should succeed
        assert!(backend.compare_and_swap(&id, None, b"new-data").unwrap());
        assert_eq!(backend.get(&id).unwrap().unwrap(), b"new-data");
    }

    #[test]
    fn test_compare_and_swap_update() {
        let backend = test_backend();
        let id = RecordId::new("test-record");

        backend.put(&id, b"old-data").unwrap();

        // CAS with correct expected → should succeed
        assert!(backend
            .compare_and_swap(&id, Some(b"old-data"), b"new-data")
            .unwrap());
        assert_eq!(backend.get(&id).unwrap().unwrap(), b"new-data");
    }

    #[test]
    fn test_compare_and_swap_conflict() {
        let backend = test_backend();
        let id = RecordId::new("test-record");

        backend.put(&id, b"actual-data").unwrap();

        // CAS with wrong expected → should fail
        assert!(!backend
            .compare_and_swap(&id, Some(b"wrong-data"), b"new-data")
            .unwrap());
        // Original data unchanged
        assert_eq!(backend.get(&id).unwrap().unwrap(), b"actual-data");
    }

    #[test]
    fn test_binary_data() {
        let backend = test_backend();
        let id = RecordId::new("binary");
        let data: Vec<u8> = (0..=255).collect();

        backend.put(&id, &data).unwrap();
        assert_eq!(backend.get(&id).unwrap().unwrap(), data);
    }

    #[test]
    fn test_large_data() {
        let backend = test_backend();
        let id = RecordId::new("large");
        let data = vec![0xAB; 1024 * 1024]; // 1MB

        backend.put(&id, &data).unwrap();
        assert_eq!(backend.get(&id).unwrap().unwrap(), data);
    }
}
