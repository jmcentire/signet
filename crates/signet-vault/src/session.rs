use crate::error::{VaultError, VaultResult};
use ed25519_dalek::{Signer as _, SigningKey};
use signet_core::{SessionId, SignetId, Timestamp};
use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroizing;

/// Agent session management.
///
/// Sessions are Ed25519 key pairs that authenticate an agent to the vault.
/// Each session has a limited lifetime and can be revoked.
///
/// The session key is derived from the VaultSealingKey (NOT from URK),
/// which means sessions CANNOT access Tier 3 compartments.

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: SessionId,
    pub signet_id: SignetId,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub revoked: bool,
}

impl SessionInfo {
    pub fn is_valid(&self) -> bool {
        !self.revoked && !self.expires_at.is_expired()
    }
}

pub struct SessionManager {
    sessions: Mutex<HashMap<SessionId, SessionRecord>>,
}

struct SessionRecord {
    info: SessionInfo,
    signing_key: Zeroizing<[u8; 32]>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new agent session with a derived signing key.
    pub fn create_session(
        &self,
        session_id: SessionId,
        signing_key_bytes: Zeroizing<[u8; 32]>,
        ttl_seconds: u64,
    ) -> VaultResult<SessionInfo> {
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        let verifying_key = signing_key.verifying_key();
        let signet_id = signet_core::signet_id_from_pubkey(&verifying_key.to_bytes());

        let now = Timestamp::now();
        let info = SessionInfo {
            session_id: session_id.clone(),
            signet_id,
            created_at: now,
            expires_at: Timestamp::from_seconds(now.seconds_since_epoch + ttl_seconds),
            revoked: false,
        };

        let record = SessionRecord {
            info: info.clone(),
            signing_key: signing_key_bytes,
        };

        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| VaultError::Session(format!("lock poisoned: {}", e)))?;
        sessions.insert(session_id, record);

        Ok(info)
    }

    /// Sign a message with a session's key.
    pub fn sign(&self, session_id: &SessionId, message: &[u8]) -> VaultResult<[u8; 64]> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| VaultError::Session(format!("lock poisoned: {}", e)))?;

        let record = sessions
            .get(session_id)
            .ok_or_else(|| VaultError::Session(format!("session not found: {}", session_id)))?;

        if !record.info.is_valid() {
            return Err(VaultError::Session("session expired or revoked".into()));
        }

        let signing_key = SigningKey::from_bytes(&record.signing_key);
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes())
    }

    /// Get session info.
    pub fn get_session(&self, session_id: &SessionId) -> VaultResult<Option<SessionInfo>> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| VaultError::Session(format!("lock poisoned: {}", e)))?;
        Ok(sessions.get(session_id).map(|r| r.info.clone()))
    }

    /// Revoke a session.
    pub fn revoke_session(&self, session_id: &SessionId) -> VaultResult<bool> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| VaultError::Session(format!("lock poisoned: {}", e)))?;

        if let Some(record) = sessions.get_mut(session_id) {
            record.info.revoked = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// List all active (non-revoked, non-expired) sessions.
    pub fn active_sessions(&self) -> VaultResult<Vec<SessionInfo>> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| VaultError::Session(format!("lock poisoned: {}", e)))?;

        Ok(sessions
            .values()
            .filter(|r| r.info.is_valid())
            .map(|r| r.info.clone())
            .collect())
    }

    /// Clean up expired sessions.
    pub fn cleanup_expired(&self) -> VaultResult<usize> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| VaultError::Session(format!("lock poisoned: {}", e)))?;

        let before = sessions.len();
        sessions.retain(|_, r| !r.info.expires_at.is_expired());
        Ok(before - sessions.len())
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Zeroizing<[u8; 32]> {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Zeroizing::new(key)
    }

    #[test]
    fn test_create_session() {
        let mgr = SessionManager::new();
        let info = mgr
            .create_session(SessionId::new("s1"), test_key(), 3600)
            .unwrap();
        assert_eq!(info.session_id, SessionId::new("s1"));
        assert!(info.is_valid());
    }

    #[test]
    fn test_sign_with_session() {
        let mgr = SessionManager::new();
        let key = test_key();
        mgr.create_session(SessionId::new("s1"), key.clone(), 3600)
            .unwrap();

        let sig = mgr.sign(&SessionId::new("s1"), b"hello").unwrap();
        assert_eq!(sig.len(), 64);

        // Verify the signature
        let signing_key = SigningKey::from_bytes(&key);
        let verifying_key = signing_key.verifying_key();
        use ed25519_dalek::Verifier;
        let signature = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(verifying_key.verify(b"hello", &signature).is_ok());
    }

    #[test]
    fn test_revoke_session() {
        let mgr = SessionManager::new();
        mgr.create_session(SessionId::new("s1"), test_key(), 3600)
            .unwrap();

        assert!(mgr.revoke_session(&SessionId::new("s1")).unwrap());

        let info = mgr.get_session(&SessionId::new("s1")).unwrap().unwrap();
        assert!(!info.is_valid());

        // Signing should fail
        let result = mgr.sign(&SessionId::new("s1"), b"hello");
        assert!(result.is_err());
    }

    #[test]
    fn test_active_sessions() {
        let mgr = SessionManager::new();
        mgr.create_session(SessionId::new("s1"), test_key(), 3600)
            .unwrap();
        mgr.create_session(SessionId::new("s2"), test_key(), 3600)
            .unwrap();
        mgr.create_session(SessionId::new("s3"), test_key(), 3600)
            .unwrap();
        mgr.revoke_session(&SessionId::new("s2")).unwrap();

        let active = mgr.active_sessions().unwrap();
        assert_eq!(active.len(), 2);
    }

    #[test]
    fn test_sign_nonexistent_session() {
        let mgr = SessionManager::new();
        let result = mgr.sign(&SessionId::new("nonexistent"), b"hello");
        assert!(result.is_err());
    }

    #[test]
    fn test_revoke_nonexistent_session() {
        let mgr = SessionManager::new();
        let result = mgr.revoke_session(&SessionId::new("nonexistent")).unwrap();
        assert!(!result);
    }
}
