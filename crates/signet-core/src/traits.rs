use crate::error::SignetResult;
use crate::types::{AuditEventKind, AuditHash, RecordId, Timestamp};

// ---------------------------------------------------------------------------
// Signer — Ed25519 signing capability
// ---------------------------------------------------------------------------

pub trait Signer: Send + Sync {
    fn sign_ed25519(&self, message: &[u8]) -> SignetResult<[u8; 64]>;
    fn public_key_ed25519(&self) -> [u8; 32];
}

// ---------------------------------------------------------------------------
// StorageBackend — the BlindDB server interface
//
// The server stores only opaque record IDs and ciphertext. It never sees
// plaintext, labels, or semantic meaning. All addressing and encryption
// happen client-side.
// ---------------------------------------------------------------------------

pub trait StorageBackend: Send + Sync {
    fn get(&self, record_id: &RecordId) -> SignetResult<Option<Vec<u8>>>;
    fn put(&self, record_id: &RecordId, ciphertext: &[u8]) -> SignetResult<()>;
    fn delete(&self, record_id: &RecordId) -> SignetResult<bool>;

    /// Atomic compare-and-swap for one-time credential consumption.
    /// Returns true if the swap succeeded (old value matched expected).
    fn compare_and_swap(
        &self,
        record_id: &RecordId,
        expected: Option<&[u8]>,
        new_value: &[u8],
    ) -> SignetResult<bool>;

    fn exists(&self, record_id: &RecordId) -> SignetResult<bool>;
}

// ---------------------------------------------------------------------------
// AuditChainWriter — append-only hash-chained audit log
//
// Each entry includes the hash of the previous entry for tamper evidence.
// ---------------------------------------------------------------------------

pub trait AuditChainWriter: Send + Sync {
    fn append(&self, event: AuditEvent) -> SignetResult<AuditHash>;
    fn verify_chain(&self) -> SignetResult<bool>;
    fn head(&self) -> SignetResult<Option<AuditHash>>;
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEvent {
    pub timestamp: Timestamp,
    pub kind: AuditEventKind,
    pub previous_hash: Option<AuditHash>,
    pub signature: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Tier;

    // Verify the trait objects are object-safe
    fn _assert_signer_object_safe(_: &dyn Signer) {}
    fn _assert_storage_object_safe(_: &dyn StorageBackend) {}
    fn _assert_audit_object_safe(_: &dyn AuditChainWriter) {}

    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent {
            timestamp: Timestamp::now(),
            kind: AuditEventKind::VaultAccess {
                tier: Tier::Tier1,
                record_id: RecordId::new("test-record"),
            },
            previous_hash: None,
            signature: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let event2: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.timestamp, event2.timestamp);
    }
}
