//! Session management, PKCE verification, and session registry.
//!
//! Implements OAuth 2.1 PKCE (S256 only) for session provisioning,
//! Ed25519 signature verification for request authentication, and
//! a thread-safe session registry.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::{McpError, McpResult};
use crate::types::{OAuthProvisionRequest, OAuthProvisionResponse, OAuthTokenExchange, Session};
use signet_core::{SessionId, Timestamp};

// ---------------------------------------------------------------------------
// PKCE S256 verification
// ---------------------------------------------------------------------------

/// Verify a PKCE S256 challenge against a code verifier.
///
/// The challenge must equal `BASE64URL(SHA256(code_verifier))`.
pub fn verify_pkce_s256(code_verifier: &str, code_challenge: &str) -> McpResult<()> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    if code_verifier.len() < 43 || code_verifier.len() > 128 {
        return Err(McpError::PkceVerificationFailed);
    }

    let hash = Sha256::digest(code_verifier.as_bytes());
    let computed_challenge = URL_SAFE_NO_PAD.encode(hash);

    if computed_challenge != code_challenge {
        return Err(McpError::PkceVerificationFailed);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Ed25519 signature verification
// ---------------------------------------------------------------------------

/// Verify an Ed25519 signature on a message using the given public key bytes.
pub fn verify_ed25519_signature(
    public_key_bytes: &[u8],
    message: &[u8],
    signature: &[u8],
) -> McpResult<()> {
    use ed25519_dalek::{Signature, VerifyingKey};

    if public_key_bytes.len() != 32 {
        return Err(McpError::InvalidSignature);
    }
    if signature.len() != 64 {
        return Err(McpError::InvalidSignature);
    }

    let key_bytes: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| McpError::InvalidSignature)?;

    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| McpError::InvalidSignature)?;

    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| McpError::InvalidSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);

    use ed25519_dalek::Verifier;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| McpError::InvalidSignature)
}

// ---------------------------------------------------------------------------
// SessionManager — thread-safe session registry
// ---------------------------------------------------------------------------

/// Thread-safe session registry that manages session lifecycle.
pub struct SessionManager {
    sessions: Mutex<HashMap<String, Session>>,
    /// Stored PKCE verifiers for pending provisioning (authorization_code -> code_challenge).
    pending_provisions: Mutex<HashMap<String, PendingProvision>>,
    session_timeout_seconds: u64,
}

/// Internal tracking for a pending OAuth provision.
struct PendingProvision {
    pub code_challenge: String,
    pub client_id: String,
    #[allow(dead_code)]
    pub redirect_uri: String,
    #[allow(dead_code)]
    pub scope: Vec<String>,
    #[allow(dead_code)]
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
}

impl SessionManager {
    /// Create a new SessionManager with the given session timeout.
    pub fn new(session_timeout_seconds: u64) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            pending_provisions: Mutex::new(HashMap::new()),
            session_timeout_seconds,
        }
    }

    /// Provision a new session via OAuth PKCE.
    /// Returns an authorization code and redirect URI.
    pub fn provision_session(
        &self,
        request: &OAuthProvisionRequest,
    ) -> McpResult<OAuthProvisionResponse> {
        if request.pkce_challenge.code_challenge_method != "S256" {
            return Err(McpError::OAuthProvisionFailed(
                "only S256 PKCE method is supported".into(),
            ));
        }
        if request.pkce_challenge.code_challenge.is_empty() {
            return Err(McpError::OAuthProvisionFailed(
                "code_challenge must not be empty".into(),
            ));
        }
        if request.client_id.is_empty() {
            return Err(McpError::OAuthProvisionFailed(
                "client_id must not be empty".into(),
            ));
        }

        let authorization_code = uuid::Uuid::new_v4().to_string();
        let state = uuid::Uuid::new_v4().to_string();
        let now = Timestamp::now();
        let expires_at = Timestamp::from_seconds(now.seconds_since_epoch + 300);

        let provision = PendingProvision {
            code_challenge: request.pkce_challenge.code_challenge.clone(),
            client_id: request.client_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            scope: request.scope.clone(),
            created_at: now,
            expires_at,
        };

        let mut pending = self
            .pending_provisions
            .lock()
            .map_err(|_| McpError::InitializationFailed("lock poisoned".into()))?;
        pending.insert(authorization_code.clone(), provision);

        Ok(OAuthProvisionResponse {
            authorization_code,
            redirect_uri: request.redirect_uri.clone(),
            state,
            expires_in_seconds: 300,
        })
    }

    /// Exchange an authorization code + PKCE verifier for a session.
    pub fn exchange_token(
        &self,
        exchange: &OAuthTokenExchange,
        public_key: Vec<u8>,
    ) -> McpResult<Session> {
        let mut pending = self
            .pending_provisions
            .lock()
            .map_err(|_| McpError::TokenExchangeFailed("lock poisoned".into()))?;

        let provision =
            pending
                .remove(&exchange.authorization_code)
                .ok_or(McpError::TokenExchangeFailed(
                    "authorization code not found or already used".into(),
                ))?;

        // Verify the PKCE code_verifier against the stored challenge
        verify_pkce_s256(&exchange.code_verifier, &provision.code_challenge)?;

        // Verify client_id matches
        if exchange.client_id != provision.client_id {
            return Err(McpError::TokenExchangeFailed(
                "client_id does not match".into(),
            ));
        }

        // Check provision hasn't expired
        if provision.expires_at.is_expired() {
            return Err(McpError::TokenExchangeFailed(
                "authorization code has expired".into(),
            ));
        }

        // Create the session
        let now = Timestamp::now();
        let session = Session {
            session_id: SessionId::new(uuid::Uuid::new_v4().to_string()),
            public_key,
            created_at: now,
            expires_at: Timestamp::from_seconds(
                now.seconds_since_epoch + self.session_timeout_seconds,
            ),
            revoked: false,
            metadata: HashMap::new(),
        };

        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| McpError::TokenExchangeFailed("lock poisoned".into()))?;
        sessions.insert(session.session_id.as_str().to_string(), session.clone());

        Ok(session)
    }

    /// Validate a session by ID, verifying the Ed25519 signature on the message.
    pub fn validate_session(
        &self,
        session_id: &SessionId,
        signature: &[u8],
        message: &[u8],
    ) -> McpResult<Session> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| McpError::InitializationFailed("lock poisoned".into()))?;

        let session = sessions
            .get(session_id.as_str())
            .ok_or(McpError::SessionNotFound)?;

        if session.revoked {
            return Err(McpError::SessionRevoked);
        }

        if session.expires_at.is_expired() {
            return Err(McpError::SessionExpired);
        }

        verify_ed25519_signature(&session.public_key, message, signature)?;

        Ok(session.clone())
    }

    /// Revoke a session by ID.
    pub fn revoke_session(&self, session_id: &SessionId) -> McpResult<()> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| McpError::InitializationFailed("lock poisoned".into()))?;

        let session = sessions
            .get_mut(session_id.as_str())
            .ok_or(McpError::SessionNotFound)?;

        session.revoked = true;
        Ok(())
    }

    /// Get a session by ID (without validation).
    pub fn get_session(&self, session_id: &SessionId) -> McpResult<Session> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| McpError::InitializationFailed("lock poisoned".into()))?;

        sessions
            .get(session_id.as_str())
            .cloned()
            .ok_or(McpError::SessionNotFound)
    }

    /// Return the number of active (non-revoked, non-expired) sessions.
    pub fn active_session_count(&self) -> usize {
        let sessions = match self.sessions.lock() {
            Ok(s) => s,
            Err(_) => return 0,
        };
        sessions.values().filter(|s| s.is_valid()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_s256_verification_valid() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        // Generate a valid verifier / challenge pair
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-0123456789";
        let hash = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hash);

        assert!(verify_pkce_s256(verifier, &challenge).is_ok());
    }

    #[test]
    fn test_pkce_s256_verification_invalid() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-0123456789";
        assert!(verify_pkce_s256(verifier, "wrong_challenge").is_err());
    }

    #[test]
    fn test_pkce_s256_verifier_too_short() {
        assert!(verify_pkce_s256("short", "challenge").is_err());
    }

    #[test]
    fn test_ed25519_signature_wrong_key_length() {
        assert!(verify_ed25519_signature(&[0u8; 16], &[], &[0u8; 64]).is_err());
    }

    #[test]
    fn test_ed25519_signature_wrong_sig_length() {
        assert!(verify_ed25519_signature(&[0u8; 32], &[], &[0u8; 32]).is_err());
    }

    #[test]
    fn test_ed25519_signature_valid_roundtrip() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = b"test message for signet-mcp";
        let signature = signing_key.sign(message);

        assert!(
            verify_ed25519_signature(verifying_key.as_bytes(), message, &signature.to_bytes(),)
                .is_ok()
        );
    }

    #[test]
    fn test_ed25519_signature_invalid_signature() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = b"test message";
        let bad_signature = [0u8; 64];

        assert!(
            verify_ed25519_signature(verifying_key.as_bytes(), message, &bad_signature,).is_err()
        );
    }

    #[test]
    fn test_session_manager_provision_and_exchange() {
        use crate::types::OAuthPkceChallenge;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let manager = SessionManager::new(3600);

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-0123456789";
        let hash = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hash);

        let provision_req = OAuthProvisionRequest {
            client_id: "test-client".into(),
            redirect_uri: "https://example.com/callback".into(),
            pkce_challenge: OAuthPkceChallenge {
                code_challenge: challenge,
                code_challenge_method: "S256".into(),
            },
            scope: vec!["read".into()],
        };

        let provision_resp = manager.provision_session(&provision_req).unwrap();
        assert!(!provision_resp.authorization_code.is_empty());

        let exchange = OAuthTokenExchange {
            authorization_code: provision_resp.authorization_code,
            code_verifier: verifier.into(),
            client_id: "test-client".into(),
        };

        let session = manager.exchange_token(&exchange, vec![0u8; 32]).unwrap();
        assert!(!session.session_id.as_str().is_empty());
        assert!(session.is_valid());
    }

    #[test]
    fn test_session_manager_provision_non_s256_rejected() {
        use crate::types::OAuthPkceChallenge;
        let manager = SessionManager::new(3600);

        let provision_req = OAuthProvisionRequest {
            client_id: "test-client".into(),
            redirect_uri: "https://example.com/callback".into(),
            pkce_challenge: OAuthPkceChallenge {
                code_challenge: "challenge".into(),
                code_challenge_method: "plain".into(),
            },
            scope: vec![],
        };

        assert!(manager.provision_session(&provision_req).is_err());
    }

    #[test]
    fn test_session_manager_revoke() {
        use crate::types::OAuthPkceChallenge;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let manager = SessionManager::new(3600);
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-0123456789";
        let hash = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hash);

        let provision_req = OAuthProvisionRequest {
            client_id: "test-client".into(),
            redirect_uri: "https://example.com/callback".into(),
            pkce_challenge: OAuthPkceChallenge {
                code_challenge: challenge,
                code_challenge_method: "S256".into(),
            },
            scope: vec![],
        };

        let resp = manager.provision_session(&provision_req).unwrap();
        let exchange = OAuthTokenExchange {
            authorization_code: resp.authorization_code,
            code_verifier: verifier.into(),
            client_id: "test-client".into(),
        };
        let session = manager.exchange_token(&exchange, vec![0u8; 32]).unwrap();

        assert_eq!(manager.active_session_count(), 1);

        manager.revoke_session(&session.session_id).unwrap();
        assert_eq!(manager.active_session_count(), 0);

        let fetched = manager.get_session(&session.session_id).unwrap();
        assert!(fetched.revoked);
    }

    #[test]
    fn test_session_manager_double_exchange_fails() {
        use crate::types::OAuthPkceChallenge;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let manager = SessionManager::new(3600);
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-0123456789";
        let hash = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hash);

        let provision_req = OAuthProvisionRequest {
            client_id: "test-client".into(),
            redirect_uri: "https://example.com/callback".into(),
            pkce_challenge: OAuthPkceChallenge {
                code_challenge: challenge,
                code_challenge_method: "S256".into(),
            },
            scope: vec![],
        };

        let resp = manager.provision_session(&provision_req).unwrap();
        let exchange = OAuthTokenExchange {
            authorization_code: resp.authorization_code.clone(),
            code_verifier: verifier.into(),
            client_id: "test-client".into(),
        };

        // First exchange succeeds
        assert!(manager.exchange_token(&exchange, vec![0u8; 32]).is_ok());
        // Second exchange fails (code already consumed)
        assert!(manager.exchange_token(&exchange, vec![0u8; 32]).is_err());
    }

    #[test]
    fn test_session_not_found() {
        let manager = SessionManager::new(3600);
        let result = manager.get_session(&SessionId::new("nonexistent"));
        assert!(result.is_err());
    }
}
