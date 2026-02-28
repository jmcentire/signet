//! One-time credential consumption tracking.
//!
//! Implements atomic compare-and-swap for one-time credential consumption
//! via the StorageBackend trait. Ensures no race conditions on concurrent
//! presentation attempts.

use crate::error::{CredError, CredErrorDetail, CredResult};
use crate::status;
use crate::types::*;
use signet_core::{RecordId, StorageBackend};

/// Storage key prefix for credential status records.
const STATUS_KEY_PREFIX: &str = "cred:status:";

/// Storage key prefix for credential record data.
const RECORD_KEY_PREFIX: &str = "cred:record:";

/// Storage key prefix for witness data.
const WITNESS_KEY_PREFIX: &str = "cred:witness:";

/// Storage key prefix for revocation data.
const REVOCATION_KEY_PREFIX: &str = "cred:revocation:";

/// Derive the storage record ID for a credential's status.
pub fn status_record_id(cred_id: &CredentialId) -> RecordId {
    RecordId::new(format!("{}{}", STATUS_KEY_PREFIX, cred_id.as_str()))
}

/// Derive the storage record ID for a credential record.
pub fn record_record_id(cred_id: &CredentialId) -> RecordId {
    RecordId::new(format!("{}{}", RECORD_KEY_PREFIX, cred_id.as_str()))
}

/// Derive the storage record ID for a credential's witness.
pub fn witness_record_id(cred_id: &CredentialId) -> RecordId {
    RecordId::new(format!("{}{}", WITNESS_KEY_PREFIX, cred_id.as_str()))
}

/// Serialize a credential status to bytes.
pub fn status_to_bytes(status: CredentialStatus) -> Vec<u8> {
    serde_json::to_vec(&status).unwrap_or_default()
}

/// Deserialize a credential status from bytes.
pub fn status_from_bytes(data: &[u8]) -> CredResult<CredentialStatus> {
    serde_json::from_slice(data).map_err(|_| {
        CredErrorDetail::new(
            CredError::DecodingFailed,
            "failed to decode credential status",
        )
    })
}

/// Atomically consume a one-time credential using compare-and-swap.
/// Returns Ok(true) if the credential was successfully consumed.
/// Returns Err if the credential was already consumed, or CAS failed.
pub fn atomic_consume(
    storage: &dyn StorageBackend,
    cred_id: &CredentialId,
    current_status: CredentialStatus,
) -> CredResult<bool> {
    // Verify the transition is valid
    let _new_status = status::status_after_presentation(current_status, true)?;

    let record_id = status_record_id(cred_id);
    let expected = status_to_bytes(current_status);
    let new_value = status_to_bytes(CredentialStatus::Consumed);

    let swapped = storage
        .compare_and_swap(&record_id, Some(&expected), &new_value)
        .map_err(|_| {
            CredErrorDetail::new(CredError::VaultError, "atomic consume CAS failed")
                .with_credential_id(cred_id.as_str())
        })?;

    if !swapped {
        // CAS failed — the status was changed by another operation
        Err(CredErrorDetail::new(
            CredError::CredentialConsumed,
            "credential was already consumed or status changed concurrently",
        )
        .with_credential_id(cred_id.as_str()))
    } else {
        Ok(true)
    }
}

/// Store the initial credential status (Active).
pub fn store_initial_status(
    storage: &dyn StorageBackend,
    cred_id: &CredentialId,
) -> CredResult<()> {
    let record_id = status_record_id(cred_id);
    let status_bytes = status_to_bytes(CredentialStatus::Active);
    storage
        .put(&record_id, &status_bytes)
        .map_err(|_| CredErrorDetail::new(CredError::VaultError, "failed to store initial status"))
}

/// Load the current credential status.
pub fn load_status(
    storage: &dyn StorageBackend,
    cred_id: &CredentialId,
) -> CredResult<CredentialStatus> {
    let record_id = status_record_id(cred_id);
    let data = storage
        .get(&record_id)
        .map_err(|_| CredErrorDetail::new(CredError::VaultError, "failed to load status"))?
        .ok_or_else(|| {
            CredErrorDetail::new(CredError::CredentialNotFound, "credential status not found")
                .with_credential_id(cred_id.as_str())
        })?;
    status_from_bytes(&data)
}

/// Update credential status (non-atomic, for non-one-time transitions).
pub fn update_status(
    storage: &dyn StorageBackend,
    cred_id: &CredentialId,
    new_status: CredentialStatus,
) -> CredResult<()> {
    let record_id = status_record_id(cred_id);
    let status_bytes = status_to_bytes(new_status);
    storage
        .put(&record_id, &status_bytes)
        .map_err(|_| CredErrorDetail::new(CredError::VaultError, "failed to update status"))
}

/// Store a credential record.
pub fn store_credential_record(
    storage: &dyn StorageBackend,
    cred_id: &CredentialId,
    record: &CredentialRecord,
) -> CredResult<()> {
    let record_id = record_record_id(cred_id);
    let data = serde_json::to_vec(record)
        .map_err(|_| CredErrorDetail::new(CredError::EncodingFailed, "failed to encode record"))?;
    storage
        .put(&record_id, &data)
        .map_err(|_| CredErrorDetail::new(CredError::VaultError, "failed to store record"))
}

/// Load a credential record.
pub fn load_credential_record(
    storage: &dyn StorageBackend,
    cred_id: &CredentialId,
) -> CredResult<CredentialRecord> {
    let record_id = record_record_id(cred_id);
    let data = storage
        .get(&record_id)
        .map_err(|_| CredErrorDetail::new(CredError::VaultError, "failed to load record"))?
        .ok_or_else(|| {
            CredErrorDetail::new(CredError::CredentialNotFound, "credential record not found")
                .with_credential_id(cred_id.as_str())
        })?;
    serde_json::from_slice(&data).map_err(|_| {
        CredErrorDetail::new(
            CredError::DecodingFailed,
            "failed to decode credential record",
        )
    })
}

/// Store a private witness.
pub fn store_witness(
    storage: &dyn StorageBackend,
    cred_id: &CredentialId,
    witness: &PrivateWitness,
) -> CredResult<()> {
    let record_id = witness_record_id(cred_id);
    let data = serde_json::to_vec(witness)
        .map_err(|_| CredErrorDetail::new(CredError::EncodingFailed, "failed to encode witness"))?;
    storage
        .put(&record_id, &data)
        .map_err(|_| CredErrorDetail::new(CredError::VaultError, "failed to store witness"))
}

/// Load a private witness.
pub fn load_witness(
    storage: &dyn StorageBackend,
    cred_id: &CredentialId,
) -> CredResult<PrivateWitness> {
    let record_id = witness_record_id(cred_id);
    let data = storage
        .get(&record_id)
        .map_err(|_| CredErrorDetail::new(CredError::VaultError, "failed to load witness"))?
        .ok_or_else(|| {
            CredErrorDetail::new(CredError::WitnessNotFound, "witness not found")
                .with_credential_id(cred_id.as_str())
        })?;
    serde_json::from_slice(&data)
        .map_err(|_| CredErrorDetail::new(CredError::DecodingFailed, "failed to decode witness"))
}

/// Delete a private witness.
pub fn delete_witness(storage: &dyn StorageBackend, cred_id: &CredentialId) -> CredResult<bool> {
    let record_id = witness_record_id(cred_id);
    storage.delete(&record_id).map_err(|_| {
        CredErrorDetail::new(CredError::VaultError, "failed to delete witness")
            .with_credential_id(cred_id.as_str())
    })
}

/// Check if a witness exists for a credential.
pub fn witness_exists(storage: &dyn StorageBackend, cred_id: &CredentialId) -> CredResult<bool> {
    let record_id = witness_record_id(cred_id);
    storage.exists(&record_id).map_err(|_| {
        CredErrorDetail::new(CredError::VaultError, "failed to check witness existence")
    })
}

/// Derive the storage record ID for a credential's revocation info.
pub fn revocation_record_id(cred_id: &CredentialId) -> RecordId {
    RecordId::new(format!("{}{}", REVOCATION_KEY_PREFIX, cred_id.as_str()))
}

/// Store revocation information for a credential.
pub fn store_revocation(
    storage: &dyn StorageBackend,
    cred_id: &CredentialId,
    info: &crate::types::RevocationInfo,
) -> CredResult<()> {
    let record_id = revocation_record_id(cred_id);
    let data = serde_json::to_vec(info).map_err(|_| {
        CredErrorDetail::new(CredError::EncodingFailed, "failed to encode revocation info")
    })?;
    storage.put(&record_id, &data).map_err(|_| {
        CredErrorDetail::new(CredError::VaultError, "failed to store revocation info")
    })
}

/// Load revocation information for a credential.
pub fn load_revocation(
    storage: &dyn StorageBackend,
    cred_id: &CredentialId,
) -> CredResult<Option<crate::types::RevocationInfo>> {
    let record_id = revocation_record_id(cred_id);
    let data = storage.get(&record_id).map_err(|_| {
        CredErrorDetail::new(CredError::VaultError, "failed to load revocation info")
    })?;
    match data {
        Some(bytes) => {
            let info = serde_json::from_slice(&bytes).map_err(|_| {
                CredErrorDetail::new(
                    CredError::DecodingFailed,
                    "failed to decode revocation info",
                )
            })?;
            Ok(Some(info))
        }
        None => Ok(None),
    }
}

/// Check if a credential is revoked.
pub fn is_revoked(
    storage: &dyn StorageBackend,
    cred_id: &CredentialId,
) -> CredResult<bool> {
    let record_id = revocation_record_id(cred_id);
    storage.exists(&record_id).map_err(|_| {
        CredErrorDetail::new(CredError::VaultError, "failed to check revocation status")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use signet_core::{RecordId, SignetResult, StorageBackend};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory storage backend for testing.
    struct MemoryStorage {
        data: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl MemoryStorage {
        fn new() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
            }
        }
    }

    impl StorageBackend for MemoryStorage {
        fn get(&self, record_id: &RecordId) -> SignetResult<Option<Vec<u8>>> {
            let data = self.data.lock().unwrap();
            Ok(data.get(record_id.as_str()).cloned())
        }

        fn put(&self, record_id: &RecordId, ciphertext: &[u8]) -> SignetResult<()> {
            let mut data = self.data.lock().unwrap();
            data.insert(record_id.as_str().to_string(), ciphertext.to_vec());
            Ok(())
        }

        fn delete(&self, record_id: &RecordId) -> SignetResult<bool> {
            let mut data = self.data.lock().unwrap();
            Ok(data.remove(record_id.as_str()).is_some())
        }

        fn compare_and_swap(
            &self,
            record_id: &RecordId,
            expected: Option<&[u8]>,
            new_value: &[u8],
        ) -> SignetResult<bool> {
            let mut data = self.data.lock().unwrap();
            let current = data.get(record_id.as_str());
            let matches = match (current, expected) {
                (None, None) => true,
                (Some(c), Some(e)) => c.as_slice() == e,
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
            let data = self.data.lock().unwrap();
            Ok(data.contains_key(record_id.as_str()))
        }
    }

    #[test]
    fn test_status_roundtrip() {
        let status = CredentialStatus::Active;
        let bytes = status_to_bytes(status);
        let restored = status_from_bytes(&bytes).unwrap();
        assert_eq!(restored, CredentialStatus::Active);
    }

    #[test]
    fn test_all_status_roundtrips() {
        for status in &[
            CredentialStatus::Active,
            CredentialStatus::Presented,
            CredentialStatus::Consumed,
            CredentialStatus::Expired,
            CredentialStatus::Revoked,
        ] {
            let bytes = status_to_bytes(*status);
            let restored = status_from_bytes(&bytes).unwrap();
            assert_eq!(restored, *status);
        }
    }

    #[test]
    fn test_store_and_load_status() {
        let storage = MemoryStorage::new();
        let cred_id = CredentialId::generate();

        store_initial_status(&storage, &cred_id).unwrap();
        let loaded = load_status(&storage, &cred_id).unwrap();
        assert_eq!(loaded, CredentialStatus::Active);
    }

    #[test]
    fn test_update_status() {
        let storage = MemoryStorage::new();
        let cred_id = CredentialId::generate();

        store_initial_status(&storage, &cred_id).unwrap();
        update_status(&storage, &cred_id, CredentialStatus::Presented).unwrap();
        let loaded = load_status(&storage, &cred_id).unwrap();
        assert_eq!(loaded, CredentialStatus::Presented);
    }

    #[test]
    fn test_load_status_not_found() {
        let storage = MemoryStorage::new();
        let cred_id = CredentialId::generate();
        let result = load_status(&storage, &cred_id);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().kind,
            CredError::CredentialNotFound
        ));
    }

    #[test]
    fn test_atomic_consume_active() {
        let storage = MemoryStorage::new();
        let cred_id = CredentialId::generate();

        store_initial_status(&storage, &cred_id).unwrap();
        let result = atomic_consume(&storage, &cred_id, CredentialStatus::Active).unwrap();
        assert!(result);

        let loaded = load_status(&storage, &cred_id).unwrap();
        assert_eq!(loaded, CredentialStatus::Consumed);
    }

    #[test]
    fn test_atomic_consume_presented() {
        let storage = MemoryStorage::new();
        let cred_id = CredentialId::generate();

        store_initial_status(&storage, &cred_id).unwrap();
        update_status(&storage, &cred_id, CredentialStatus::Presented).unwrap();

        let result = atomic_consume(&storage, &cred_id, CredentialStatus::Presented).unwrap();
        assert!(result);

        let loaded = load_status(&storage, &cred_id).unwrap();
        assert_eq!(loaded, CredentialStatus::Consumed);
    }

    #[test]
    fn test_atomic_consume_already_consumed() {
        let storage = MemoryStorage::new();
        let cred_id = CredentialId::generate();

        store_initial_status(&storage, &cred_id).unwrap();
        atomic_consume(&storage, &cred_id, CredentialStatus::Active).unwrap();

        // Try to consume again — CAS should fail because status is now Consumed
        let result = atomic_consume(&storage, &cred_id, CredentialStatus::Active);
        assert!(result.is_err());
    }

    #[test]
    fn test_atomic_consume_from_terminal_state() {
        let storage = MemoryStorage::new();
        let cred_id = CredentialId::generate();

        store_initial_status(&storage, &cred_id).unwrap();
        update_status(&storage, &cred_id, CredentialStatus::Revoked).unwrap();

        let result = atomic_consume(&storage, &cred_id, CredentialStatus::Revoked);
        assert!(result.is_err());
    }

    #[test]
    fn test_store_and_load_witness() {
        let storage = MemoryStorage::new();
        let cred_id = CredentialId::generate();

        let witness = PrivateWitness {
            credential_id: cred_id.clone(),
            entries: vec![WitnessEntry {
                attribute_name: "balance".into(),
                raw_value: 50000,
                blinding_factor: BlindingFactor {
                    attribute_name: "balance".into(),
                    factor_bytes: vec![0xAA; 32],
                },
            }],
            created_at: "2024-01-01T00:00:00Z".into(),
        };

        store_witness(&storage, &cred_id, &witness).unwrap();
        let loaded = load_witness(&storage, &cred_id).unwrap();
        assert_eq!(loaded.credential_id, cred_id);
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].raw_value, 50000);
    }

    #[test]
    fn test_delete_witness() {
        let storage = MemoryStorage::new();
        let cred_id = CredentialId::generate();

        let witness = PrivateWitness {
            credential_id: cred_id.clone(),
            entries: vec![],
            created_at: "2024-01-01T00:00:00Z".into(),
        };

        store_witness(&storage, &cred_id, &witness).unwrap();
        assert!(witness_exists(&storage, &cred_id).unwrap());

        let deleted = delete_witness(&storage, &cred_id).unwrap();
        assert!(deleted);
        assert!(!witness_exists(&storage, &cred_id).unwrap());
    }

    #[test]
    fn test_delete_witness_not_found() {
        let storage = MemoryStorage::new();
        let cred_id = CredentialId::generate();
        let deleted = delete_witness(&storage, &cred_id).unwrap();
        assert!(!deleted);
    }

    #[test]
    fn test_load_witness_not_found() {
        let storage = MemoryStorage::new();
        let cred_id = CredentialId::generate();
        let result = load_witness(&storage, &cred_id);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().kind,
            CredError::WitnessNotFound
        ));
    }

    #[test]
    fn test_status_record_id_derivation() {
        let cred_id = CredentialId::new("abcdef0123456789abcdef0123456789").unwrap();
        let record_id = status_record_id(&cred_id);
        assert_eq!(
            record_id.as_str(),
            "cred:status:abcdef0123456789abcdef0123456789"
        );
    }

    #[test]
    fn test_record_record_id_derivation() {
        let cred_id = CredentialId::new("abcdef0123456789abcdef0123456789").unwrap();
        let record_id = record_record_id(&cred_id);
        assert_eq!(
            record_id.as_str(),
            "cred:record:abcdef0123456789abcdef0123456789"
        );
    }

    #[test]
    fn test_witness_record_id_derivation() {
        let cred_id = CredentialId::new("abcdef0123456789abcdef0123456789").unwrap();
        let record_id = witness_record_id(&cred_id);
        assert_eq!(
            record_id.as_str(),
            "cred:witness:abcdef0123456789abcdef0123456789"
        );
    }

    #[test]
    fn test_store_and_load_credential_record() {
        let storage = MemoryStorage::new();
        let cred_id = CredentialId::generate();

        let record = CredentialRecord {
            metadata: CredentialMetadata {
                id: cred_id.clone(),
                schema_id: "test".into(),
                schema_version: 1,
                issued_at: "2024-01-01T00:00:00Z".into(),
                expires_at: "2024-01-01T01:00:00Z".into(),
                domain: Domain::new("example.com").unwrap(),
                one_time: false,
                issuer_public_key_id: "key-1".into(),
                decay: None,
            },
            status: CredentialStatus::Active,
            presentation_history: vec![],
            sd_jwt: SdJwtCredential {
                compact: "a.b.c~".into(),
                disclosures: vec![],
                key_binding_required: true,
            },
            bbs: BbsCredential {
                signature: BbsSignature {
                    signature_bytes: vec![0x01; 64],
                    public_key_bytes: vec![0x02; 32],
                },
                messages: vec![],
                attributes: vec![],
                message_count: 0,
            },
            decay_state: None,
            revocation: None,
        };

        store_credential_record(&storage, &cred_id, &record).unwrap();
        let loaded = load_credential_record(&storage, &cred_id).unwrap();
        assert_eq!(loaded.metadata.id, cred_id);
        assert_eq!(loaded.status, CredentialStatus::Active);
    }
}
