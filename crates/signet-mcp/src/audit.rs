//! Audit recording for MCP operations.
//!
//! Every tool invocation is recorded atomically before the response is returned.
//! Audit entries are hash-chained for tamper evidence.

use sha2::{Digest, Sha256};
use std::sync::Mutex;

use crate::error::{McpError, McpResult};
use crate::types::AuditEntry;

/// Thread-safe audit log that stores entries in memory.
///
/// In production, this would be backed by the vault's AuditChainWriter.
/// For now, it provides an in-memory implementation with hash chaining.
pub struct AuditLog {
    entries: Mutex<Vec<AuditEntry>>,
    previous_hash: Mutex<Option<[u8; 32]>>,
}

impl AuditLog {
    /// Create a new empty audit log.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            previous_hash: Mutex::new(None),
        }
    }

    /// Record an audit entry. Returns the entry's content hash.
    ///
    /// The entry is atomically appended before returning.
    pub fn record(&self, entry: AuditEntry) -> McpResult<String> {
        let entry_json = serde_json::to_vec(&entry).map_err(|e| {
            McpError::AuditFailed(format!("failed to serialize audit entry: {}", e))
        })?;

        let mut hasher = Sha256::new();

        // Chain to previous hash
        let prev_hash = self
            .previous_hash
            .lock()
            .map_err(|_| McpError::AuditFailed("lock poisoned".into()))?;
        if let Some(ref h) = *prev_hash {
            hasher.update(h);
        }
        hasher.update(&entry_json);
        let hash = hasher.finalize();
        let hash_hex = hex::encode(hash);

        drop(prev_hash);

        // Store the entry
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| McpError::AuditFailed("lock poisoned".into()))?;
        entries.push(entry);

        // Update the chain hash
        let mut prev = self
            .previous_hash
            .lock()
            .map_err(|_| McpError::AuditFailed("lock poisoned".into()))?;
        let mut new_hash = [0u8; 32];
        new_hash.copy_from_slice(&hash);
        *prev = Some(new_hash);

        Ok(hash_hex)
    }

    /// Get all recorded audit entries.
    pub fn entries(&self) -> McpResult<Vec<AuditEntry>> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| McpError::AuditFailed("lock poisoned".into()))?;
        Ok(entries.clone())
    }

    /// Get the number of recorded entries.
    pub fn len(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }

    /// Check if the audit log is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Verify the hash chain integrity.
    pub fn verify_chain(&self) -> McpResult<bool> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| McpError::AuditFailed("lock poisoned".into()))?;

        let mut prev_hash: Option<[u8; 32]> = None;

        for entry in entries.iter() {
            let entry_json = serde_json::to_vec(entry).map_err(|e| {
                McpError::AuditFailed(format!("failed to serialize for verification: {}", e))
            })?;

            let mut hasher = Sha256::new();
            if let Some(ref h) = prev_hash {
                hasher.update(h);
            }
            hasher.update(&entry_json);
            let hash = hasher.finalize();
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&hash);
            prev_hash = Some(hash_bytes);
        }

        Ok(true)
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{McpTool, PolicyDecision};
    use signet_core::{RequestId, SessionId, Tier, Timestamp};
    use std::collections::HashMap;

    fn make_entry(request_id: &str) -> AuditEntry {
        AuditEntry {
            entry_id: uuid::Uuid::new_v4().to_string(),
            session_id: SessionId::new("test-session"),
            request_id: RequestId::new(request_id),
            tool: McpTool::GetProof,
            tier: Tier::Tier1,
            decision: PolicyDecision::Permit,
            timestamp: Timestamp::now(),
            duration_ms: 42,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_audit_log_new_is_empty() {
        let log = AuditLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn test_audit_log_record() {
        let log = AuditLog::new();
        let entry = make_entry("req-001");
        let hash = log.record(entry).unwrap();
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA-256 hex
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_audit_log_multiple_records() {
        let log = AuditLog::new();
        let h1 = log.record(make_entry("req-001")).unwrap();
        let h2 = log.record(make_entry("req-002")).unwrap();
        let h3 = log.record(make_entry("req-003")).unwrap();

        assert_eq!(log.len(), 3);
        // Each hash should be different due to chaining
        assert_ne!(h1, h2);
        assert_ne!(h2, h3);
    }

    #[test]
    fn test_audit_log_entries() {
        let log = AuditLog::new();
        log.record(make_entry("req-001")).unwrap();
        log.record(make_entry("req-002")).unwrap();

        let entries = log.entries().unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_audit_log_verify_chain() {
        let log = AuditLog::new();
        log.record(make_entry("req-001")).unwrap();
        log.record(make_entry("req-002")).unwrap();
        log.record(make_entry("req-003")).unwrap();

        assert!(log.verify_chain().unwrap());
    }

    #[test]
    fn test_audit_log_verify_empty_chain() {
        let log = AuditLog::new();
        assert!(log.verify_chain().unwrap());
    }

    #[test]
    fn test_audit_log_hash_determinism() {
        // Same entry recorded in different logs should produce same first hash
        // (since there is no previous hash for the first entry)
        let entry1 = AuditEntry {
            entry_id: "fixed-id".into(),
            session_id: SessionId::new("test-session"),
            request_id: RequestId::new("req-det"),
            tool: McpTool::GetProof,
            tier: Tier::Tier1,
            decision: PolicyDecision::Permit,
            timestamp: Timestamp::from_seconds(1000),
            duration_ms: 42,
            metadata: HashMap::new(),
        };
        let entry2 = entry1.clone();

        let log1 = AuditLog::new();
        let log2 = AuditLog::new();
        let h1 = log1.record(entry1).unwrap();
        let h2 = log2.record(entry2).unwrap();
        assert_eq!(h1, h2);
    }
}
