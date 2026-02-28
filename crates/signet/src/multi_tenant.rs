//! Multi-tenant hosting support for vault.signet.tools.
//!
//! BlindDB model: the server stores everyone's data as indistinguishable opaque blobs.
//! Authentication is Ed25519 challenge-response. The server never sees keys, labels,
//! or plaintext.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A nonce-based authentication challenge issued by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    /// Random nonce (hex-encoded, 32 bytes).
    pub nonce: String,
    /// When the challenge expires (Unix timestamp).
    pub expires_at: u64,
}

/// Client's response to an auth challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthVerifyRequest {
    /// The nonce that was signed.
    pub nonce: String,
    /// Ed25519 signature over the nonce bytes (hex-encoded).
    pub signature: String,
    /// Client's Ed25519 public key (hex-encoded, 32 bytes).
    pub public_key: String,
}

/// Session token returned after successful authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    /// Opaque session token.
    pub token: String,
    /// When the session expires (Unix timestamp).
    pub expires_at: u64,
}

/// Internal session state tracked by the server.
#[derive(Debug, Clone)]
struct SessionState {
    /// The client's public key (hex-encoded).
    public_key: String,
    /// When this session expires.
    expires_at: u64,
}

/// Request body for vault put operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultPutRequest {
    /// Opaque record ID (SHA-256 hash, hex-encoded).
    pub record_id: String,
    /// Opaque ciphertext blob (base64-encoded).
    pub ciphertext: String,
}

/// Request body for vault get operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultGetRequest {
    /// Opaque record ID to retrieve.
    pub record_id: String,
}

/// Request body for vault delete operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultDeleteRequest {
    /// Opaque record ID to delete.
    pub record_id: String,
}

/// Manages multi-tenant authentication and sessions.
///
/// Thread-safe: all state is behind a Mutex.
pub struct TenantManager {
    /// Pending challenges: nonce -> (challenge, issued_at).
    challenges: Mutex<HashMap<String, AuthChallenge>>,
    /// Active sessions: token -> session state.
    sessions: Mutex<HashMap<String, SessionState>>,
    /// Session duration in seconds.
    session_duration_secs: u64,
    /// Challenge validity in seconds.
    challenge_duration_secs: u64,
}

impl TenantManager {
    /// Create a new tenant manager.
    pub fn new() -> Self {
        Self {
            challenges: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            session_duration_secs: 3600, // 1 hour
            challenge_duration_secs: 300, // 5 minutes
        }
    }

    /// Issue a new authentication challenge.
    pub fn create_challenge(&self) -> AuthChallenge {
        let nonce_bytes: [u8; 32] = rand::random();
        let nonce = hex::encode(nonce_bytes);
        let now = now_secs();
        let expires_at = now + self.challenge_duration_secs;

        let challenge = AuthChallenge {
            nonce: nonce.clone(),
            expires_at,
        };

        let mut challenges = self.challenges.lock().unwrap();
        // Clean up expired challenges
        challenges.retain(|_, c| c.expires_at > now);
        challenges.insert(nonce, challenge.clone());

        challenge
    }

    /// Verify a signed challenge and create a session.
    ///
    /// Returns a session token on success, or an error string.
    pub fn verify_challenge(&self, req: &AuthVerifyRequest) -> Result<AuthSession, String> {
        let now = now_secs();

        // Look up and consume the challenge
        let challenge = {
            let mut challenges = self.challenges.lock().unwrap();
            challenges.remove(&req.nonce)
        };

        let challenge = challenge.ok_or("challenge not found or already used")?;

        if challenge.expires_at <= now {
            return Err("challenge expired".into());
        }

        // Decode public key
        let pk_bytes = hex::decode(&req.public_key)
            .map_err(|_| "invalid public key hex")?;
        let pk_array: [u8; 32] = pk_bytes
            .try_into()
            .map_err(|_| "public key must be 32 bytes")?;
        let verifying_key = VerifyingKey::from_bytes(&pk_array)
            .map_err(|_| "invalid Ed25519 public key")?;

        // Decode signature
        let sig_bytes = hex::decode(&req.signature)
            .map_err(|_| "invalid signature hex")?;
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|_| "invalid Ed25519 signature")?;

        // Verify signature over the nonce bytes
        let nonce_bytes = hex::decode(&req.nonce)
            .map_err(|_| "invalid nonce hex")?;
        verifying_key
            .verify_strict(&nonce_bytes, &signature)
            .map_err(|_| "signature verification failed")?;

        // Create session
        let token = generate_session_token(&req.public_key);
        let expires_at = now + self.session_duration_secs;

        let session_state = SessionState {
            public_key: req.public_key.clone(),
            expires_at,
        };

        let mut sessions = self.sessions.lock().unwrap();
        // Clean up expired sessions
        sessions.retain(|_, s| s.expires_at > now);
        sessions.insert(token.clone(), session_state);

        Ok(AuthSession { token, expires_at })
    }

    /// Validate a session token. Returns the public key if valid.
    pub fn validate_session(&self, token: &str) -> Option<String> {
        let now = now_secs();
        let sessions = self.sessions.lock().unwrap();
        sessions.get(token).and_then(|s| {
            if s.expires_at > now {
                Some(s.public_key.clone())
            } else {
                None
            }
        })
    }

    /// Get the number of active sessions (for monitoring).
    pub fn active_session_count(&self) -> usize {
        let now = now_secs();
        let sessions = self.sessions.lock().unwrap();
        sessions.values().filter(|s| s.expires_at > now).count()
    }

    /// Get the number of pending challenges (for monitoring).
    pub fn pending_challenge_count(&self) -> usize {
        let now = now_secs();
        let challenges = self.challenges.lock().unwrap();
        challenges.values().filter(|c| c.expires_at > now).count()
    }
}

impl Default for TenantManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a session token from a public key + random bytes.
fn generate_session_token(public_key: &str) -> String {
    let random_bytes: [u8; 32] = rand::random();
    let mut hasher = Sha256::new();
    hasher.update(public_key.as_bytes());
    hasher.update(random_bytes);
    hasher.update(now_secs().to_le_bytes());
    hex::encode(hasher.finalize())
}

/// Current time in seconds since UNIX epoch.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn make_test_keypair() -> (SigningKey, VerifyingKey) {
        let mut seed = [0u8; 32];
        seed[0] = 0x42;
        seed[31] = 0xFF;
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn test_create_challenge() {
        let mgr = TenantManager::new();
        let challenge = mgr.create_challenge();
        assert_eq!(challenge.nonce.len(), 64); // 32 bytes hex
        assert!(challenge.expires_at > now_secs());
    }

    #[test]
    fn test_challenge_response_success() {
        let mgr = TenantManager::new();
        let (sk, vk) = make_test_keypair();

        let challenge = mgr.create_challenge();
        let nonce_bytes = hex::decode(&challenge.nonce).unwrap();

        use ed25519_dalek::Signer;
        let signature = sk.sign(&nonce_bytes);

        let req = AuthVerifyRequest {
            nonce: challenge.nonce,
            signature: hex::encode(signature.to_bytes()),
            public_key: hex::encode(vk.to_bytes()),
        };

        let session = mgr.verify_challenge(&req).unwrap();
        assert_eq!(session.token.len(), 64); // SHA-256 hex
        assert!(session.expires_at > now_secs());
    }

    #[test]
    fn test_challenge_response_wrong_key() {
        let mgr = TenantManager::new();
        let (sk, _vk) = make_test_keypair();

        // Different key
        let mut wrong_seed = [0u8; 32];
        wrong_seed[0] = 0xAA;
        let wrong_sk = SigningKey::from_bytes(&wrong_seed);
        let wrong_vk = wrong_sk.verifying_key();

        let challenge = mgr.create_challenge();
        let nonce_bytes = hex::decode(&challenge.nonce).unwrap();

        // Sign with correct key but present wrong public key
        use ed25519_dalek::Signer;
        let signature = sk.sign(&nonce_bytes);

        let req = AuthVerifyRequest {
            nonce: challenge.nonce,
            signature: hex::encode(signature.to_bytes()),
            public_key: hex::encode(wrong_vk.to_bytes()),
        };

        assert!(mgr.verify_challenge(&req).is_err());
    }

    #[test]
    fn test_challenge_consumed_on_use() {
        let mgr = TenantManager::new();
        let (sk, vk) = make_test_keypair();

        let challenge = mgr.create_challenge();
        let nonce_bytes = hex::decode(&challenge.nonce).unwrap();

        use ed25519_dalek::Signer;
        let signature = sk.sign(&nonce_bytes);

        let req = AuthVerifyRequest {
            nonce: challenge.nonce,
            signature: hex::encode(signature.to_bytes()),
            public_key: hex::encode(vk.to_bytes()),
        };

        // First use succeeds
        assert!(mgr.verify_challenge(&req).is_ok());
        // Second use fails (challenge consumed)
        assert!(mgr.verify_challenge(&req).is_err());
    }

    #[test]
    fn test_session_validation() {
        let mgr = TenantManager::new();
        let (sk, vk) = make_test_keypair();

        let challenge = mgr.create_challenge();
        let nonce_bytes = hex::decode(&challenge.nonce).unwrap();

        use ed25519_dalek::Signer;
        let signature = sk.sign(&nonce_bytes);

        let req = AuthVerifyRequest {
            nonce: challenge.nonce,
            signature: hex::encode(signature.to_bytes()),
            public_key: hex::encode(vk.to_bytes()),
        };

        let session = mgr.verify_challenge(&req).unwrap();

        // Valid session
        let pk = mgr.validate_session(&session.token);
        assert!(pk.is_some());
        assert_eq!(pk.unwrap(), hex::encode(vk.to_bytes()));

        // Invalid token
        assert!(mgr.validate_session("invalid-token").is_none());
    }

    #[test]
    fn test_multiple_users_independent() {
        let mgr = TenantManager::new();

        // User A
        let mut seed_a = [0u8; 32];
        seed_a[0] = 0x01;
        let sk_a = SigningKey::from_bytes(&seed_a);
        let vk_a = sk_a.verifying_key();

        // User B
        let mut seed_b = [0u8; 32];
        seed_b[0] = 0x02;
        let sk_b = SigningKey::from_bytes(&seed_b);
        let vk_b = sk_b.verifying_key();

        use ed25519_dalek::Signer;

        // Both authenticate
        let ch_a = mgr.create_challenge();
        let sig_a = sk_a.sign(&hex::decode(&ch_a.nonce).unwrap());
        let session_a = mgr.verify_challenge(&AuthVerifyRequest {
            nonce: ch_a.nonce,
            signature: hex::encode(sig_a.to_bytes()),
            public_key: hex::encode(vk_a.to_bytes()),
        }).unwrap();

        let ch_b = mgr.create_challenge();
        let sig_b = sk_b.sign(&hex::decode(&ch_b.nonce).unwrap());
        let session_b = mgr.verify_challenge(&AuthVerifyRequest {
            nonce: ch_b.nonce,
            signature: hex::encode(sig_b.to_bytes()),
            public_key: hex::encode(vk_b.to_bytes()),
        }).unwrap();

        // Different sessions, different public keys
        assert_ne!(session_a.token, session_b.token);
        let pk_a = mgr.validate_session(&session_a.token).unwrap();
        let pk_b = mgr.validate_session(&session_b.token).unwrap();
        assert_ne!(pk_a, pk_b);

        assert_eq!(mgr.active_session_count(), 2);
    }
}
