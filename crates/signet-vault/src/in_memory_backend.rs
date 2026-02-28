use signet_core::{RecordId, SignetResult, StorageBackend};
use std::collections::HashMap;
use std::sync::Mutex;
use subtle::ConstantTimeEq;

/// In-memory storage backend implementing StorageBackend.
///
/// Useful for testing and for scenarios where persistence isn't needed.
/// Also serves as the inner backend for BlindStorageWrapper in tests.
pub struct InMemoryBackend {
    data: Mutex<HashMap<String, Vec<u8>>>,
}

fn lock_data(
    mutex: &Mutex<HashMap<String, Vec<u8>>>,
) -> SignetResult<std::sync::MutexGuard<'_, HashMap<String, Vec<u8>>>> {
    mutex
        .lock()
        .map_err(|e| signet_core::SignetError::Storage(format!("lock poisoned: {}", e)))
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }

    /// Get all stored record IDs (for testing/inspection).
    pub fn all_record_ids(&self) -> Vec<String> {
        lock_data(&self.data)
            .map(|d| d.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Get all stored entries as (id, data) pairs (for testing/inspection).
    pub fn all_entries(&self) -> Vec<(String, Vec<u8>)> {
        lock_data(&self.data)
            .map(|d| d.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default()
    }

    /// Get the number of stored records.
    pub fn count(&self) -> usize {
        lock_data(&self.data).map(|d| d.len()).unwrap_or(0)
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for InMemoryBackend {
    fn get(&self, record_id: &RecordId) -> SignetResult<Option<Vec<u8>>> {
        let data = lock_data(&self.data)?;
        Ok(data.get(record_id.as_str()).cloned())
    }

    fn put(&self, record_id: &RecordId, data: &[u8]) -> SignetResult<()> {
        let mut store = lock_data(&self.data)?;
        store.insert(record_id.as_str().to_string(), data.to_vec());
        Ok(())
    }

    fn delete(&self, record_id: &RecordId) -> SignetResult<bool> {
        let mut data = lock_data(&self.data)?;
        Ok(data.remove(record_id.as_str()).is_some())
    }

    fn compare_and_swap(
        &self,
        record_id: &RecordId,
        expected: Option<&[u8]>,
        new_value: &[u8],
    ) -> SignetResult<bool> {
        let mut data = lock_data(&self.data)?;
        let current = data.get(record_id.as_str());
        let matches = match (current, expected) {
            (None, None) => true,
            (Some(c), Some(e)) => c.as_slice().ct_eq(e).into(),
            _ => false,
        };
        if matches {
            data.insert(record_id.as_str().to_string(), new_value.to_vec());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn exists(&self, record_id: &RecordId) -> SignetResult<bool> {
        let data = lock_data(&self.data)?;
        Ok(data.contains_key(record_id.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_operations() {
        let backend = InMemoryBackend::new();
        let id = RecordId::new("test");

        assert!(backend.get(&id).unwrap().is_none());
        backend.put(&id, b"hello").unwrap();
        assert_eq!(backend.get(&id).unwrap().unwrap(), b"hello");
        assert!(backend.exists(&id).unwrap());
        assert!(backend.delete(&id).unwrap());
        assert!(!backend.exists(&id).unwrap());
    }

    #[test]
    fn test_cas() {
        let backend = InMemoryBackend::new();
        let id = RecordId::new("test");

        assert!(backend.compare_and_swap(&id, None, b"v1").unwrap());
        assert!(backend.compare_and_swap(&id, Some(b"v1"), b"v2").unwrap());
        assert!(!backend.compare_and_swap(&id, Some(b"v1"), b"v3").unwrap());
        assert_eq!(backend.get(&id).unwrap().unwrap(), b"v2");
    }
}
