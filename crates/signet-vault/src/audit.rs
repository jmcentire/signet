use crate::envelope;
use crate::error::{VaultError, VaultResult};
use sha2::{Digest, Sha256};
use signet_core::{AuditEvent, AuditHash, RecordId, StorageBackend};
use std::sync::Mutex;
use zeroize::Zeroizing;

/// Hash-chained append-only audit log.
///
/// Each entry includes the hash of the previous entry for tamper evidence.
/// The chain can be verified by recomputing all hashes from the genesis entry.
///
/// When constructed with `with_storage`, every appended event is encrypted
/// before being persisted to the storage backend. The database never sees
/// plaintext event data — only opaque entry hashes and ciphertext.
///
/// Invariant: "All disclosures are on the audit chain."
pub struct AuditChain {
    entries: Mutex<Vec<AuditEntry>>,
    persistence: Option<AuditPersistence>,
}

/// Encrypted persistence layer for audit events.
struct AuditPersistence {
    storage: Box<dyn StorageBackend>,
    encryption_key: Zeroizing<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub event: AuditEvent,
    pub hash: AuditHash,
}

impl AuditChain {
    /// Create an in-memory-only audit chain (no persistence).
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            persistence: None,
        }
    }

    /// Create an audit chain with encrypted persistence.
    ///
    /// Events are encrypted with AES-256-GCM before being stored.
    /// Record IDs are the hex-encoded entry hash — opaque to the server.
    /// The storage backend never sees plaintext event data.
    pub fn with_storage(
        storage: Box<dyn StorageBackend>,
        encryption_key: Zeroizing<[u8; 32]>,
    ) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            persistence: Some(AuditPersistence {
                storage,
                encryption_key,
            }),
        }
    }

    /// Compute the hash of an audit event including the previous hash.
    fn compute_hash(event: &AuditEvent, previous: Option<&AuditHash>) -> AuditHash {
        let mut hasher = Sha256::new();

        // Include previous hash in the chain
        if let Some(prev) = previous {
            hasher.update(prev.0);
        }

        // Include timestamp
        hasher.update(event.timestamp.seconds_since_epoch.to_le_bytes());
        hasher.update(event.timestamp.nanoseconds.to_le_bytes());

        // Include event kind serialization
        let kind_bytes = serde_json::to_vec(&event.kind).unwrap_or_default();
        hasher.update(&kind_bytes);

        // Include signature if present
        if let Some(sig) = &event.signature {
            hasher.update(sig);
        }

        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        AuditHash(result)
    }

    /// Persist an audit entry as encrypted ciphertext.
    /// The record ID is the hex-encoded entry hash (opaque).
    /// The stored value is AES-256-GCM encrypted event JSON.
    fn persist_entry(&self, entry: &AuditEntry) -> signet_core::SignetResult<()> {
        let persistence = match &self.persistence {
            Some(p) => p,
            None => return Ok(()), // no persistence configured
        };

        let event_json = serde_json::to_vec(&entry.event).map_err(|e| {
            signet_core::SignetError::Internal(format!("audit serialize failed: {}", e))
        })?;

        let encrypted =
            envelope::encrypt(&persistence.encryption_key, &event_json).map_err(|e| {
                signet_core::SignetError::Internal(format!("audit encrypt failed: {}", e))
            })?;

        let encrypted_bytes = serde_json::to_vec(&encrypted).map_err(|e| {
            signet_core::SignetError::Internal(format!("audit envelope serialize failed: {}", e))
        })?;

        // Store under the entry hash — opaque ID, encrypted data
        let record_id = RecordId::new(hex::encode(entry.hash.0));
        persistence.storage.put(&record_id, &encrypted_bytes)
    }

    /// Load and decrypt a persisted audit entry by its hash.
    pub fn load_persisted_entry(&self, hash: &AuditHash) -> VaultResult<Option<AuditEvent>> {
        let persistence = match &self.persistence {
            Some(p) => p,
            None => return Ok(None),
        };

        let record_id = RecordId::new(hex::encode(hash.0));
        let encrypted_bytes = match persistence
            .storage
            .get(&record_id)
            .map_err(|e| VaultError::Audit(format!("failed to load audit entry: {}", e)))?
        {
            Some(data) => data,
            None => return Ok(None),
        };

        let env: envelope::EncryptedEnvelope =
            serde_json::from_slice(&encrypted_bytes).map_err(|e| {
                VaultError::Audit(format!("failed to deserialize audit envelope: {}", e))
            })?;

        let event_json = envelope::decrypt(&persistence.encryption_key, &env)
            .map_err(|e| VaultError::Audit(format!("failed to decrypt audit entry: {}", e)))?;

        let event: AuditEvent = serde_json::from_slice(&event_json)
            .map_err(|e| VaultError::Audit(format!("failed to parse audit event: {}", e)))?;

        Ok(Some(event))
    }

    /// Check whether this chain has persistence configured.
    pub fn has_persistence(&self) -> bool {
        self.persistence.is_some()
    }

    /// Get the raw storage backend (for testing/inspection).
    pub fn storage(&self) -> Option<&dyn StorageBackend> {
        self.persistence.as_ref().map(|p| &*p.storage)
    }
}

impl Default for AuditChain {
    fn default() -> Self {
        Self::new()
    }
}

impl signet_core::AuditChainWriter for AuditChain {
    fn append(&self, mut event: AuditEvent) -> signet_core::SignetResult<AuditHash> {
        let mut entries = self.entries.lock().map_err(|e| {
            signet_core::SignetError::Internal(format!("audit lock poisoned: {}", e))
        })?;

        let previous = entries.last().map(|e| &e.hash);
        event.previous_hash = previous.cloned();

        let hash = Self::compute_hash(&event, previous);

        let entry = AuditEntry {
            event,
            hash: hash.clone(),
        };

        // Persist encrypted before adding to in-memory chain
        self.persist_entry(&entry)?;

        entries.push(entry);

        Ok(hash)
    }

    fn verify_chain(&self) -> signet_core::SignetResult<bool> {
        let entries = self.entries.lock().map_err(|e| {
            signet_core::SignetError::Internal(format!("audit lock poisoned: {}", e))
        })?;

        if entries.is_empty() {
            return Ok(true);
        }

        // Verify genesis entry
        let genesis_hash = Self::compute_hash(&entries[0].event, None);
        if genesis_hash != entries[0].hash {
            return Ok(false);
        }

        // Verify each subsequent entry
        for i in 1..entries.len() {
            let expected_hash = Self::compute_hash(&entries[i].event, Some(&entries[i - 1].hash));
            if expected_hash != entries[i].hash {
                return Ok(false);
            }
            // Verify the stored previous_hash matches
            if entries[i].event.previous_hash.as_ref() != Some(&entries[i - 1].hash) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn head(&self) -> signet_core::SignetResult<Option<AuditHash>> {
        let entries = self.entries.lock().map_err(|e| {
            signet_core::SignetError::Internal(format!("audit lock poisoned: {}", e))
        })?;
        Ok(entries.last().map(|e| e.hash.clone()))
    }
}

impl AuditChain {
    /// Get the number of entries in the chain.
    pub fn len(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get all entries (for export/backup).
    pub fn entries(&self) -> VaultResult<Vec<AuditEntry>> {
        self.entries
            .lock()
            .map(|e| e.clone())
            .map_err(|e| VaultError::Audit(format!("lock poisoned: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signet_core::{AuditChainWriter, AuditEventKind, CredentialId, RecordId, Tier, Timestamp};

    fn make_event(kind: AuditEventKind) -> AuditEvent {
        AuditEvent {
            timestamp: Timestamp::now(),
            kind,
            previous_hash: None,
            signature: None,
        }
    }

    #[test]
    fn test_empty_chain_is_valid() {
        let chain = AuditChain::new();
        assert!(chain.verify_chain().unwrap());
        assert!(chain.is_empty());
    }

    #[test]
    fn test_append_and_verify() {
        let chain = AuditChain::new();

        let event = make_event(AuditEventKind::VaultAccess {
            tier: Tier::Tier1,
            record_id: RecordId::new("test"),
        });

        let hash = chain.append(event).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.head().unwrap(), Some(hash));
        assert!(chain.verify_chain().unwrap());
    }

    #[test]
    fn test_chain_integrity() {
        let chain = AuditChain::new();

        // Append multiple events
        for i in 0..10 {
            let event = make_event(AuditEventKind::VaultAccess {
                tier: Tier::Tier1,
                record_id: RecordId::new(format!("record-{}", i)),
            });
            chain.append(event).unwrap();
        }

        assert_eq!(chain.len(), 10);
        assert!(chain.verify_chain().unwrap());
    }

    #[test]
    fn test_different_event_types() {
        let chain = AuditChain::new();

        chain
            .append(make_event(AuditEventKind::VaultAccess {
                tier: Tier::Tier1,
                record_id: RecordId::new("r1"),
            }))
            .unwrap();

        chain
            .append(make_event(AuditEventKind::CredentialIssued {
                credential_id: CredentialId::new("cred-1"),
            }))
            .unwrap();

        chain
            .append(make_event(AuditEventKind::KeyRotation))
            .unwrap();

        assert_eq!(chain.len(), 3);
        assert!(chain.verify_chain().unwrap());
    }

    #[test]
    fn test_head_tracks_latest() {
        let chain = AuditChain::new();

        assert_eq!(chain.head().unwrap(), None);

        let h1 = chain
            .append(make_event(AuditEventKind::KeyRotation))
            .unwrap();
        assert_eq!(chain.head().unwrap(), Some(h1));

        let h2 = chain
            .append(make_event(AuditEventKind::KeyRotation))
            .unwrap();
        assert_eq!(chain.head().unwrap(), Some(h2));
    }

    #[test]
    fn test_hashes_are_unique() {
        let chain = AuditChain::new();

        let h1 = chain
            .append(make_event(AuditEventKind::KeyRotation))
            .unwrap();
        let h2 = chain
            .append(make_event(AuditEventKind::KeyRotation))
            .unwrap();

        // Even identical events get different hashes due to chaining
        assert_ne!(h1, h2);
    }
}
