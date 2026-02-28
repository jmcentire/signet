//! Challenge registry and ChallengeHandle (move-only).
//!
//! The ChallengeRegistry tracks pending authorization challenges.
//! ChallengeHandle is consumed (moved) on resolution to prevent double-use.
//! Timeout defaults to deny (fail-secure).

use std::collections::HashMap;
use std::sync::Mutex;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use signet_core::Timestamp;

use crate::error::{NotifyError, NotifyResult};
use crate::scope::validate_scope_subset;
use crate::types::{
    AuthorizationDecision, AuthorizationResponse, ChallengeId, ChallengeRegistrySnapshot,
    DenialReason, EventId, ScopeSet,
};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// ChallengeHandle — move-only handle to a pending challenge
// ---------------------------------------------------------------------------

/// Fail-secure handle to a pending authorization challenge.
///
/// Consumed (moved) on resolution to prevent double-resolution.
/// If the deadline expires before a response is received, resolves as Denied.
impl std::fmt::Debug for ChallengeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeHandle")
            .field("challenge_id", &self.challenge_id)
            .field("event_id", &self.event_id)
            .field("deadline", &self.deadline)
            .field("resolved", &self.resolved)
            .finish()
    }
}

pub struct ChallengeHandle {
    pub challenge_id: ChallengeId,
    pub event_id: EventId,
    pub deadline: Timestamp,
    pub original_scope: ScopeSet,
    resolved: bool,
}

impl ChallengeHandle {
    fn new(
        challenge_id: ChallengeId,
        event_id: EventId,
        deadline: Timestamp,
        original_scope: ScopeSet,
    ) -> Self {
        Self {
            challenge_id,
            event_id,
            deadline,
            original_scope,
            resolved: false,
        }
    }

    /// Resolve this challenge with a user response.
    ///
    /// Consumes `self` to enforce single-use semantics.
    /// If the deadline has passed, returns Denied with DenialReason::Timeout regardless
    /// of the provided response.
    pub fn resolve(mut self, response: Option<AuthorizationResponse>) -> AuthorizationDecision {
        self.resolved = true;
        let now = Timestamp::now();

        // Clone ids since we have a Drop impl and can't move out of self
        let challenge_id = self.challenge_id.clone();
        let event_id = self.event_id.clone();

        // Timeout defaults to deny
        if now > self.deadline {
            return AuthorizationDecision::Denied {
                challenge_id,
                event_id,
                decided_at: now,
                denial_reason: DenialReason::Timeout,
                denial_message: None,
            };
        }

        match response {
            None => {
                // No response (delivery failure or sender dropped)
                AuthorizationDecision::Denied {
                    challenge_id,
                    event_id,
                    decided_at: now,
                    denial_reason: DenialReason::DeliveryFailure,
                    denial_message: None,
                }
            }
            Some(AuthorizationResponse::Approve) => AuthorizationDecision::Approved {
                challenge_id,
                event_id,
                decided_at: now,
            },
            Some(AuthorizationResponse::Deny { reason }) => AuthorizationDecision::Denied {
                challenge_id,
                event_id,
                decided_at: now,
                denial_reason: DenialReason::ExplicitDeny,
                denial_message: reason,
            },
            Some(AuthorizationResponse::Modify { adjusted_scope }) => {
                // Validate subset before accepting
                if !validate_scope_subset(&self.original_scope, &adjusted_scope) {
                    return AuthorizationDecision::Denied {
                        challenge_id,
                        event_id,
                        decided_at: now,
                        denial_reason: DenialReason::ExplicitDeny,
                        denial_message: Some("Scope escalation rejected".to_string()),
                    };
                }
                AuthorizationDecision::Modified {
                    challenge_id,
                    event_id,
                    decided_at: now,
                    adjusted_scope,
                }
            }
        }
    }
}

impl Drop for ChallengeHandle {
    fn drop(&mut self) {
        if !self.resolved {
            tracing::warn!(
                challenge_id = %self.challenge_id,
                "ChallengeHandle dropped without resolution"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// PendingChallenge — internal registry entry
// ---------------------------------------------------------------------------

struct PendingChallenge {
    #[allow(dead_code)]
    event_id: EventId,
    deadline: Timestamp,
    #[allow(dead_code)]
    original_scope: ScopeSet,
    response: Option<AuthorizationResponse>,
    responded: bool,
}

// ---------------------------------------------------------------------------
// ChallengeRegistry — tracks pending challenges
// ---------------------------------------------------------------------------

/// Registry of pending authorization challenges.
///
/// Thread-safe via internal Mutex. Maps ChallengeId to pending challenge state.
pub struct ChallengeRegistry {
    challenges: Mutex<HashMap<String, PendingChallenge>>,
    stats: Mutex<RegistryStats>,
}

struct RegistryStats {
    total_issued: u64,
    total_resolved: u64,
    total_expired_cleaned: u64,
}

impl ChallengeRegistry {
    pub fn new() -> Self {
        Self {
            challenges: Mutex::new(HashMap::new()),
            stats: Mutex::new(RegistryStats {
                total_issued: 0,
                total_resolved: 0,
                total_expired_cleaned: 0,
            }),
        }
    }

    /// Register a new challenge and return a ChallengeHandle.
    ///
    /// The handle is consumed on resolution (move semantics prevent double-use).
    pub fn register(
        &self,
        challenge_id: ChallengeId,
        event_id: EventId,
        deadline: Timestamp,
        original_scope: ScopeSet,
    ) -> NotifyResult<ChallengeHandle> {
        let mut challenges = self
            .challenges
            .lock()
            .map_err(|_| NotifyError::InternalError)?;
        let mut stats = self.stats.lock().map_err(|_| NotifyError::InternalError)?;

        if challenges.contains_key(challenge_id.as_str()) {
            return Err(NotifyError::InternalError); // Duplicate challenge
        }

        let pending = PendingChallenge {
            event_id: event_id.clone(),
            deadline,
            original_scope: original_scope.clone(),
            response: None,
            responded: false,
        };

        challenges.insert(challenge_id.as_str().to_string(), pending);
        stats.total_issued += 1;

        Ok(ChallengeHandle::new(
            challenge_id,
            event_id,
            deadline,
            original_scope,
        ))
    }

    /// Submit a response for a pending challenge.
    ///
    /// Called by handle_callback when a webhook response arrives.
    pub fn submit_response(
        &self,
        challenge_id: &ChallengeId,
        response: AuthorizationResponse,
    ) -> NotifyResult<()> {
        let mut challenges = self
            .challenges
            .lock()
            .map_err(|_| NotifyError::InternalError)?;

        let pending = challenges
            .get_mut(challenge_id.as_str())
            .ok_or(NotifyError::ChallengeNotFound)?;

        if pending.responded {
            return Err(NotifyError::ChallengeAlreadyResolved);
        }

        let now = Timestamp::now();
        if now > pending.deadline {
            return Err(NotifyError::ChallengeExpired);
        }

        pending.response = Some(response);
        pending.responded = true;

        Ok(())
    }

    /// Take the response for a challenge (removes it from the registry).
    pub fn take_response(
        &self,
        challenge_id: &ChallengeId,
    ) -> NotifyResult<Option<AuthorizationResponse>> {
        let mut challenges = self
            .challenges
            .lock()
            .map_err(|_| NotifyError::InternalError)?;
        let mut stats = self.stats.lock().map_err(|_| NotifyError::InternalError)?;

        if let Some(mut pending) = challenges.remove(challenge_id.as_str()) {
            stats.total_resolved += 1;
            Ok(pending.response.take())
        } else {
            Err(NotifyError::ChallengeNotFound)
        }
    }

    /// Check if a response has been submitted for a challenge.
    pub fn has_response(&self, challenge_id: &ChallengeId) -> NotifyResult<bool> {
        let challenges = self
            .challenges
            .lock()
            .map_err(|_| NotifyError::InternalError)?;
        Ok(challenges
            .get(challenge_id.as_str())
            .map(|p| p.responded)
            .unwrap_or(false))
    }

    /// Clean up expired challenges.
    ///
    /// Returns the number of challenges cleaned up.
    pub fn cleanup_expired(&self, now: Timestamp) -> NotifyResult<u64> {
        let mut challenges = self
            .challenges
            .lock()
            .map_err(|_| NotifyError::InternalError)?;
        let mut stats = self.stats.lock().map_err(|_| NotifyError::InternalError)?;

        let expired_keys: Vec<String> = challenges
            .iter()
            .filter(|(_, pending)| now > pending.deadline)
            .map(|(key, _)| key.clone())
            .collect();

        let count = expired_keys.len() as u64;
        for key in expired_keys {
            challenges.remove(&key);
            tracing::debug!(challenge_id = %key, "Cleaned up expired challenge");
        }

        stats.total_expired_cleaned += count;

        Ok(count)
    }

    /// Get a diagnostic snapshot of the registry state.
    pub fn snapshot(&self) -> NotifyResult<ChallengeRegistrySnapshot> {
        let challenges = self
            .challenges
            .lock()
            .map_err(|_| NotifyError::InternalError)?;
        let stats = self.stats.lock().map_err(|_| NotifyError::InternalError)?;

        Ok(ChallengeRegistrySnapshot {
            active_challenges: challenges.len(),
            expired_challenges_cleaned: stats.total_expired_cleaned,
            total_challenges_issued: stats.total_issued,
            total_challenges_resolved: stats.total_resolved,
        })
    }
}

impl Default for ChallengeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Challenge token creation and verification
// ---------------------------------------------------------------------------
// The contract specifies PASETO v4.local tokens, but since rusty_paseto is not
// in the workspace dependencies, we implement a secure HMAC-based challenge token
// using the available crypto primitives. The token encodes the challenge_id and
// expiration, and is verified using HMAC-SHA256 with a symmetric key.

/// Create a challenge token encoding challenge_id and expiration.
///
/// Format: hex(challenge_id_hash.expiry_timestamp.hmac_signature)
/// The token binds the challenge_id and expiry together cryptographically.
pub fn create_challenge_token(
    challenge_id: &ChallengeId,
    expires_at: Timestamp,
    symmetric_key: &[u8; 32],
) -> NotifyResult<String> {
    let payload = format!(
        "{}:{}",
        challenge_id.as_str(),
        expires_at.seconds_since_epoch
    );

    let mut mac =
        HmacSha256::new_from_slice(symmetric_key).map_err(|_| NotifyError::InternalError)?;
    mac.update(payload.as_bytes());
    let signature = mac.finalize().into_bytes();

    // Token format: v4.local.<hex(payload_len:payload:signature)>
    // We use "v4.local." prefix to match the contract's expected format
    let token_data = format!(
        "{}:{}",
        hex::encode(payload.as_bytes()),
        hex::encode(signature)
    );

    Ok(format!("v4.local.{}", token_data))
}

/// Verify a challenge token and extract the challenge_id.
///
/// Validates that:
/// - The token is well-formed
/// - The HMAC signature is valid
/// - The challenge_id matches expected_challenge_id
/// - The token has not expired
pub fn verify_challenge_token(
    token: &str,
    expected_challenge_id: &ChallengeId,
    symmetric_key: &[u8; 32],
) -> NotifyResult<ChallengeId> {
    // Strip prefix
    let token_data = token
        .strip_prefix("v4.local.")
        .ok_or(NotifyError::InvalidCallbackToken)?;

    // Split payload hex and signature hex
    let parts: Vec<&str> = token_data.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(NotifyError::InvalidCallbackToken);
    }

    let payload_bytes = hex::decode(parts[0]).map_err(|_| NotifyError::InvalidCallbackToken)?;
    let sig_bytes = hex::decode(parts[1]).map_err(|_| NotifyError::InvalidCallbackToken)?;

    let payload =
        String::from_utf8(payload_bytes).map_err(|_| NotifyError::InvalidCallbackToken)?;

    // Verify HMAC
    let mut mac =
        HmacSha256::new_from_slice(symmetric_key).map_err(|_| NotifyError::InternalError)?;
    mac.update(payload.as_bytes());

    // Constant-time verification via the hmac crate
    mac.verify_slice(&sig_bytes)
        .map_err(|_| NotifyError::InvalidCallbackToken)?;

    // Parse payload: "challenge_id:expiry_seconds"
    let payload_parts: Vec<&str> = payload.splitn(2, ':').collect();
    if payload_parts.len() != 2 {
        return Err(NotifyError::InvalidCallbackToken);
    }

    let token_challenge_id = payload_parts[0];
    let expiry_seconds: u64 = payload_parts[1]
        .parse()
        .map_err(|_| NotifyError::InvalidCallbackToken)?;

    // Verify challenge_id matches
    if token_challenge_id != expected_challenge_id.as_str() {
        return Err(NotifyError::InvalidCallbackToken);
    }

    // Verify not expired
    let now = Timestamp::now();
    if now.seconds_since_epoch > expiry_seconds {
        return Err(NotifyError::InvalidCallbackToken);
    }

    // Return the verified challenge_id
    ChallengeId::new(token_challenge_id).map_err(|_| NotifyError::InvalidCallbackToken)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ScopeEntry;

    fn test_scope() -> ScopeSet {
        ScopeSet::new(vec![
            ScopeEntry::new("vault.medical", "read"),
            ScopeEntry::new("vault.financial", "read"),
        ])
        .unwrap()
    }

    fn future_timestamp(offset_seconds: u64) -> Timestamp {
        let now = Timestamp::now();
        Timestamp::from_seconds(now.seconds_since_epoch + offset_seconds)
    }

    fn past_timestamp(offset_seconds: u64) -> Timestamp {
        let now = Timestamp::now();
        Timestamp::from_seconds(now.seconds_since_epoch.saturating_sub(offset_seconds))
    }

    #[test]
    fn test_register_and_resolve_approved() {
        let registry = ChallengeRegistry::new();
        let cid = ChallengeId::generate();
        let eid = EventId::generate();
        let deadline = future_timestamp(300);
        let scope = test_scope();

        let handle = registry
            .register(cid.clone(), eid.clone(), deadline, scope)
            .unwrap();

        // Submit an approve response
        registry
            .submit_response(&cid, AuthorizationResponse::Approve)
            .unwrap();

        let response = registry.take_response(&cid).unwrap();
        let decision = handle.resolve(response);

        assert!(decision.is_approved());
        assert_eq!(decision.challenge_id(), &cid);
        assert_eq!(decision.event_id(), &eid);
    }

    #[test]
    fn test_register_and_resolve_denied() {
        let registry = ChallengeRegistry::new();
        let cid = ChallengeId::generate();
        let eid = EventId::generate();
        let deadline = future_timestamp(300);
        let scope = test_scope();

        let handle = registry
            .register(cid.clone(), eid, deadline, scope)
            .unwrap();

        registry
            .submit_response(
                &cid,
                AuthorizationResponse::Deny {
                    reason: Some("not now".to_string()),
                },
            )
            .unwrap();

        let response = registry.take_response(&cid).unwrap();
        let decision = handle.resolve(response);

        assert!(decision.is_denied());
        if let AuthorizationDecision::Denied {
            denial_reason,
            denial_message,
            ..
        } = &decision
        {
            assert_eq!(*denial_reason, DenialReason::ExplicitDeny);
            assert_eq!(denial_message.as_deref(), Some("not now"));
        }
    }

    #[test]
    fn test_resolve_with_no_response_is_delivery_failure() {
        let registry = ChallengeRegistry::new();
        let cid = ChallengeId::generate();
        let eid = EventId::generate();
        let deadline = future_timestamp(300);
        let scope = test_scope();

        let handle = registry
            .register(cid.clone(), eid, deadline, scope)
            .unwrap();

        // Take response without submitting one
        let response = registry.take_response(&cid).unwrap();
        assert!(response.is_none());

        let decision = handle.resolve(None);
        assert!(decision.is_denied());
        if let AuthorizationDecision::Denied { denial_reason, .. } = &decision {
            assert_eq!(*denial_reason, DenialReason::DeliveryFailure);
        }
    }

    #[test]
    fn test_expired_handle_resolves_as_timeout() {
        let registry = ChallengeRegistry::new();
        let cid = ChallengeId::generate();
        let eid = EventId::generate();
        let deadline = past_timestamp(10); // already expired
        let scope = test_scope();

        let handle = registry
            .register(cid.clone(), eid, deadline, scope)
            .unwrap();

        // Even with an approve response, expired handle should deny
        let decision = handle.resolve(Some(AuthorizationResponse::Approve));
        assert!(decision.is_denied());
        if let AuthorizationDecision::Denied { denial_reason, .. } = &decision {
            assert_eq!(*denial_reason, DenialReason::Timeout);
        }
    }

    #[test]
    fn test_duplicate_challenge_rejected() {
        let registry = ChallengeRegistry::new();
        let cid = ChallengeId::generate();
        let eid = EventId::generate();
        let deadline = future_timestamp(300);
        let scope = test_scope();

        let _handle1 = registry
            .register(cid.clone(), eid.clone(), deadline, scope.clone())
            .unwrap();

        let result = registry.register(cid, eid, deadline, scope);
        assert!(result.is_err());
    }

    #[test]
    fn test_submit_to_nonexistent_challenge() {
        let registry = ChallengeRegistry::new();
        let cid = ChallengeId::generate();

        let result = registry.submit_response(&cid, AuthorizationResponse::Approve);
        assert_eq!(result.unwrap_err(), NotifyError::ChallengeNotFound);
    }

    #[test]
    fn test_double_submit_rejected() {
        let registry = ChallengeRegistry::new();
        let cid = ChallengeId::generate();
        let eid = EventId::generate();
        let deadline = future_timestamp(300);
        let scope = test_scope();

        let _handle = registry
            .register(cid.clone(), eid, deadline, scope)
            .unwrap();

        registry
            .submit_response(&cid, AuthorizationResponse::Approve)
            .unwrap();

        let result = registry.submit_response(&cid, AuthorizationResponse::Approve);
        assert_eq!(result.unwrap_err(), NotifyError::ChallengeAlreadyResolved);
    }

    #[test]
    fn test_submit_to_expired_challenge() {
        let registry = ChallengeRegistry::new();
        let cid = ChallengeId::generate();
        let eid = EventId::generate();
        let deadline = past_timestamp(10);
        let scope = test_scope();

        let _handle = registry
            .register(cid.clone(), eid, deadline, scope)
            .unwrap();

        let result = registry.submit_response(&cid, AuthorizationResponse::Approve);
        assert_eq!(result.unwrap_err(), NotifyError::ChallengeExpired);
    }

    #[test]
    fn test_cleanup_expired_challenges() {
        let registry = ChallengeRegistry::new();
        let scope = test_scope();

        // Register one expired and one active challenge
        let cid_expired = ChallengeId::generate();
        let _handle_expired = registry
            .register(
                cid_expired.clone(),
                EventId::generate(),
                past_timestamp(10),
                scope.clone(),
            )
            .unwrap();

        let cid_active = ChallengeId::generate();
        let _handle_active = registry
            .register(
                cid_active.clone(),
                EventId::generate(),
                future_timestamp(300),
                scope,
            )
            .unwrap();

        let cleaned = registry.cleanup_expired(Timestamp::now()).unwrap();
        assert_eq!(cleaned, 1);

        let snapshot = registry.snapshot().unwrap();
        assert_eq!(snapshot.active_challenges, 1);
        assert_eq!(snapshot.expired_challenges_cleaned, 1);
    }

    #[test]
    fn test_snapshot() {
        let registry = ChallengeRegistry::new();
        let snapshot = registry.snapshot().unwrap();
        assert_eq!(snapshot.active_challenges, 0);
        assert_eq!(snapshot.total_challenges_issued, 0);
        assert_eq!(snapshot.total_challenges_resolved, 0);
        assert_eq!(snapshot.expired_challenges_cleaned, 0);
    }

    #[test]
    fn test_snapshot_after_operations() {
        let registry = ChallengeRegistry::new();
        let scope = test_scope();

        let cid = ChallengeId::generate();
        let handle = registry
            .register(
                cid.clone(),
                EventId::generate(),
                future_timestamp(300),
                scope,
            )
            .unwrap();

        let snapshot = registry.snapshot().unwrap();
        assert_eq!(snapshot.active_challenges, 1);
        assert_eq!(snapshot.total_challenges_issued, 1);

        // Resolve the challenge
        let _ = registry.take_response(&cid);
        let _ = handle.resolve(None);

        let snapshot = registry.snapshot().unwrap();
        assert_eq!(snapshot.active_challenges, 0);
        assert_eq!(snapshot.total_challenges_resolved, 1);
    }

    #[test]
    fn test_modify_with_valid_subset() {
        let registry = ChallengeRegistry::new();
        let cid = ChallengeId::generate();
        let eid = EventId::generate();
        let deadline = future_timestamp(300);
        let scope = ScopeSet::new(vec![
            ScopeEntry::new("vault.medical", "read"),
            ScopeEntry::new("vault.financial", "read"),
            ScopeEntry::new("vault.identity", "prove"),
        ])
        .unwrap();

        let handle = registry
            .register(cid.clone(), eid, deadline, scope)
            .unwrap();

        let adjusted = ScopeSet::new(vec![ScopeEntry::new("vault.medical", "read")]).unwrap();

        let decision = handle.resolve(Some(AuthorizationResponse::Modify {
            adjusted_scope: adjusted,
        }));
        assert!(decision.is_modified());
    }

    #[test]
    fn test_modify_with_escalation_denied() {
        let registry = ChallengeRegistry::new();
        let cid = ChallengeId::generate();
        let eid = EventId::generate();
        let deadline = future_timestamp(300);
        let scope = ScopeSet::new(vec![ScopeEntry::new("vault.medical", "read")]).unwrap();

        let handle = registry
            .register(cid.clone(), eid, deadline, scope)
            .unwrap();

        // Try to escalate by adding a scope entry
        let escalated = ScopeSet::new(vec![
            ScopeEntry::new("vault.medical", "read"),
            ScopeEntry::new("vault.financial", "read"),
        ])
        .unwrap();

        let decision = handle.resolve(Some(AuthorizationResponse::Modify {
            adjusted_scope: escalated,
        }));
        assert!(decision.is_denied());
    }

    #[test]
    fn test_challenge_token_roundtrip() {
        let cid = ChallengeId::generate();
        let expires = future_timestamp(300);
        let key = [0x42u8; 32];

        let token = create_challenge_token(&cid, expires, &key).unwrap();
        assert!(token.starts_with("v4.local."));

        let verified_cid = verify_challenge_token(&token, &cid, &key).unwrap();
        assert_eq!(verified_cid, cid);
    }

    #[test]
    fn test_challenge_token_wrong_key_rejected() {
        let cid = ChallengeId::generate();
        let expires = future_timestamp(300);
        let key1 = [0x42u8; 32];
        let key2 = [0x99u8; 32];

        let token = create_challenge_token(&cid, expires, &key1).unwrap();
        let result = verify_challenge_token(&token, &cid, &key2);
        assert_eq!(result.unwrap_err(), NotifyError::InvalidCallbackToken);
    }

    #[test]
    fn test_challenge_token_wrong_challenge_id_rejected() {
        let cid1 = ChallengeId::generate();
        let cid2 = ChallengeId::generate();
        let expires = future_timestamp(300);
        let key = [0x42u8; 32];

        let token = create_challenge_token(&cid1, expires, &key).unwrap();
        let result = verify_challenge_token(&token, &cid2, &key);
        assert_eq!(result.unwrap_err(), NotifyError::InvalidCallbackToken);
    }

    #[test]
    fn test_challenge_token_expired_rejected() {
        let cid = ChallengeId::generate();
        let expires = past_timestamp(10);
        let key = [0x42u8; 32];

        let token = create_challenge_token(&cid, expires, &key).unwrap();
        let result = verify_challenge_token(&token, &cid, &key);
        assert_eq!(result.unwrap_err(), NotifyError::InvalidCallbackToken);
    }

    #[test]
    fn test_challenge_token_malformed_rejected() {
        let cid = ChallengeId::generate();
        let key = [0x42u8; 32];

        // Missing prefix
        let result = verify_challenge_token("not-a-token", &cid, &key);
        assert_eq!(result.unwrap_err(), NotifyError::InvalidCallbackToken);

        // Wrong prefix
        let result = verify_challenge_token("v3.local.xxx", &cid, &key);
        assert_eq!(result.unwrap_err(), NotifyError::InvalidCallbackToken);
    }

    #[test]
    fn test_has_response() {
        let registry = ChallengeRegistry::new();
        let cid = ChallengeId::generate();
        let _handle = registry
            .register(
                cid.clone(),
                EventId::generate(),
                future_timestamp(300),
                test_scope(),
            )
            .unwrap();

        assert!(!registry.has_response(&cid).unwrap());

        registry
            .submit_response(&cid, AuthorizationResponse::Approve)
            .unwrap();

        assert!(registry.has_response(&cid).unwrap());
    }
}
