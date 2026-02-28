//! Main notification dispatcher — routes authorization requests to channels.
//!
//! The dispatcher is the primary integration point for the policy engine.
//! It manages endpoint configuration, challenge registration, webhook delivery,
//! and callback handling.

use signet_core::Timestamp;

use crate::challenge::{
    create_challenge_token, verify_challenge_token, ChallengeHandle, ChallengeRegistry,
};
use crate::circuit_breaker::CircuitBreaker;
use crate::error::{NotifyError, NotifyResult};
use crate::types::{
    AuthorizationRequest, AuthorizationResponse, CallbackPayload, ChallengeId,
    ChallengeRegistrySnapshot, DeliveryAttempt, DeliveryId, DeliveryOutcome, DeliveryReport,
    EndpointConfig, EndpointHealth, EventId, NotificationChannel, NotificationPayload, RetryPolicy,
    WebhookSignatureHeaders,
};
use crate::webhook::{sign_webhook_payload, verify_webhook_signature};

/// The main notification dispatcher.
///
/// Routes authorization requests to the configured webhook endpoint.
/// Manages challenge lifecycle, circuit breaker state, and callback processing.
pub struct NotificationDispatcher {
    endpoint: Option<EndpointConfig>,
    registry: ChallengeRegistry,
    circuit_breaker: CircuitBreaker,
    #[allow(dead_code)]
    retry_policy: RetryPolicy,
    token_key: [u8; 32],
}

impl NotificationDispatcher {
    /// Create a new dispatcher with the given endpoint configuration.
    pub fn new(
        endpoint: EndpointConfig,
        retry_policy: RetryPolicy,
        token_key: [u8; 32],
    ) -> NotifyResult<Self> {
        endpoint
            .validate()
            .map_err(|_| NotifyError::ConfigurationError)?;
        retry_policy
            .validate()
            .map_err(|_| NotifyError::ConfigurationError)?;

        let threshold = endpoint.circuit_breaker_threshold;
        Ok(Self {
            endpoint: Some(endpoint),
            registry: ChallengeRegistry::new(),
            circuit_breaker: CircuitBreaker::new(threshold),
            retry_policy,
            token_key,
        })
    }

    /// Create a dispatcher with no endpoint configured (for testing or in-app only mode).
    pub fn new_without_endpoint(token_key: [u8; 32]) -> Self {
        Self {
            endpoint: None,
            registry: ChallengeRegistry::new(),
            circuit_breaker: CircuitBreaker::new(5),
            retry_policy: RetryPolicy::default(),
            token_key,
        }
    }

    /// Send an authorization request and return a ChallengeHandle.
    ///
    /// This is the primary integration point for the policy engine.
    /// The returned ChallengeHandle is fail-secure: if no response arrives
    /// by the deadline, it resolves as Denied with DenialReason::Timeout.
    pub fn notify(&mut self, request: &AuthorizationRequest) -> NotifyResult<ChallengeHandle> {
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or(NotifyError::EndpointUnavailable)?;

        // Validate endpoint
        endpoint
            .validate()
            .map_err(|_| NotifyError::ConfigurationError)?;

        // Check circuit breaker
        if !self.circuit_breaker.should_allow() {
            return Err(NotifyError::CircuitBreakerOpen);
        }

        // Check that request hasn't already expired
        let now = Timestamp::now();
        if *request.expires_at() <= now {
            return Err(NotifyError::ChallengeExpired);
        }

        // Register the challenge
        let handle = self.registry.register(
            request.challenge_id().clone(),
            request.event_id().clone(),
            *request.expires_at(),
            request.requested_scope().clone(),
        )?;

        // Create challenge token for callback verification
        let challenge_token = create_challenge_token(
            request.challenge_id(),
            *request.expires_at(),
            &self.token_key,
        )?;

        // Build notification payload
        let _payload = NotificationPayload {
            channel: NotificationChannel::Webhook,
            request: request.clone(),
            challenge_token,
        };

        // Serialize and sign the payload
        let payload_json = serde_json::to_vec(&_payload).map_err(|_| NotifyError::InternalError)?;

        let _headers = sign_webhook_payload(&payload_json, &endpoint.current_secret)?;

        // In a real implementation, this would initiate async HTTP delivery.
        // For the synchronous library, we record the delivery attempt and
        // let the caller drive the actual HTTP request.
        tracing::info!(
            event_id = %request.event_id(),
            challenge_id = %request.challenge_id(),
            "Notification dispatched"
        );

        Ok(handle)
    }

    /// Simulate a webhook delivery attempt (for testing and synchronous usage).
    ///
    /// In production, this would be replaced by an async HTTP client.
    /// Returns a DeliveryReport recording the attempt.
    pub fn simulate_delivery(
        &mut self,
        challenge_id: &ChallengeId,
        event_id: &EventId,
        _payload_json: &[u8],
        success: bool,
    ) -> NotifyResult<DeliveryReport> {
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or(NotifyError::EndpointUnavailable)?;

        let start = Timestamp::now();
        let delivery_id = DeliveryId::generate();

        let outcome = if success {
            self.circuit_breaker.record_success();
            DeliveryOutcome::Success
        } else {
            self.circuit_breaker.record_failure();
            DeliveryOutcome::HttpError
        };

        let attempt = DeliveryAttempt {
            delivery_id: delivery_id.clone(),
            challenge_id: challenge_id.clone(),
            attempt_number: 1,
            attempted_at: start,
            outcome: outcome.clone(),
            http_status: if success { Some(200) } else { Some(500) },
            latency_ms: 10,
        };

        let _ = endpoint; // used for the URL in real implementation

        Ok(DeliveryReport {
            challenge_id: challenge_id.clone(),
            event_id: event_id.clone(),
            final_outcome: outcome,
            attempts: vec![attempt],
            total_duration_ms: 10,
        })
    }

    /// Handle an incoming webhook callback from the user.
    ///
    /// Verifies the challenge token, validates the response (including
    /// subset check for Modify), and submits the response to the registry.
    pub fn handle_callback(
        &self,
        challenge_id: &ChallengeId,
        callback: &CallbackPayload,
    ) -> NotifyResult<()> {
        // Verify the challenge token
        let verified_id =
            verify_challenge_token(&callback.challenge_token, challenge_id, &self.token_key)?;

        // Verify challenge_id matches
        if verified_id != *challenge_id {
            return Err(NotifyError::InvalidCallbackToken);
        }

        // Validate Modify responses for scope escalation
        if let AuthorizationResponse::Modify { ref adjusted_scope } = callback.response {
            // We need to check the original scope, which requires looking up the registry
            // The registry submit_response will fail if the challenge is not found
            // For now, we defer the scope check to the ChallengeHandle::resolve()
            let _ = adjusted_scope;
        }

        // Submit the response to the registry
        self.registry
            .submit_response(challenge_id, callback.response.clone())?;

        tracing::info!(
            challenge_id = %challenge_id,
            "Callback processed successfully"
        );

        Ok(())
    }

    /// Verify an incoming webhook signature.
    pub fn verify_signature(
        &self,
        headers: &WebhookSignatureHeaders,
        body: &[u8],
    ) -> NotifyResult<bool> {
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or(NotifyError::EndpointUnavailable)?;
        verify_webhook_signature(headers, body, endpoint)
    }

    /// Take the response for a challenge (removes it from the registry).
    /// Used to resolve a ChallengeHandle after a callback has been processed.
    pub fn take_response(
        &self,
        challenge_id: &ChallengeId,
    ) -> NotifyResult<Option<AuthorizationResponse>> {
        self.registry.take_response(challenge_id)
    }

    /// Get the registry snapshot for monitoring.
    pub fn registry_snapshot(&self) -> NotifyResult<ChallengeRegistrySnapshot> {
        self.registry.snapshot()
    }

    /// Get the endpoint health for monitoring.
    pub fn endpoint_health(&self) -> EndpointHealth {
        self.circuit_breaker.health().clone()
    }

    /// Clean up expired challenges.
    pub fn cleanup_expired(&self) -> NotifyResult<u64> {
        self.registry.cleanup_expired(Timestamp::now())
    }

    /// Update the endpoint configuration.
    pub fn update_endpoint(&mut self, endpoint: EndpointConfig) -> NotifyResult<()> {
        endpoint
            .validate()
            .map_err(|_| NotifyError::ConfigurationError)?;
        let threshold = endpoint.circuit_breaker_threshold;
        self.endpoint = Some(endpoint);
        self.circuit_breaker = CircuitBreaker::new(threshold);
        Ok(())
    }

    /// Access the challenge registry directly (for advanced usage).
    pub fn registry(&self) -> &ChallengeRegistry {
        &self.registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        AnomalyContext, AnomalyEscalationPayload, AuthorizationDecision, AvailableActions,
        DenialReason, RequesterInfo, ScopeEntry, ScopeSet, Tier3AccessPayload, WebhookSecret,
    };

    fn test_secret() -> WebhookSecret {
        WebhookSecret::new(vec![0x42u8; 32], "test-key").unwrap()
    }

    fn test_endpoint() -> EndpointConfig {
        EndpointConfig {
            url: "https://example.com/webhook".to_string(),
            current_secret: test_secret(),
            previous_secret: None,
            timeout_seconds: 30,
            max_retries: 3,
            circuit_breaker_threshold: 5,
        }
    }

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

    fn test_tier3_request() -> AuthorizationRequest {
        let cid = ChallengeId::generate();
        let eid = EventId::generate();
        AuthorizationRequest::Tier3Access {
            event_id: eid,
            challenge_id: cid,
            payload: Tier3AccessPayload {
                requester: RequesterInfo {
                    service_name: "Test Service".to_string(),
                    service_identifier: "test.example.com".to_string(),
                    agent_session_id: "session-123".to_string(),
                    request_timestamp: Timestamp::now(),
                },
                compartment_label: "Medical Records".to_string(),
                requested_scope: test_scope(),
                justification: "Need to verify insurance eligibility".to_string(),
                available_actions: AvailableActions {
                    can_approve: true,
                    can_deny: true,
                    can_modify: true,
                    suggested_scope: None,
                },
                expires_at: future_timestamp(300),
            },
        }
    }

    fn test_anomaly_request() -> AuthorizationRequest {
        let cid = ChallengeId::generate();
        let eid = EventId::generate();
        AuthorizationRequest::AnomalyEscalation {
            event_id: eid,
            challenge_id: cid,
            payload: AnomalyEscalationPayload {
                requester: RequesterInfo {
                    service_name: "Suspicious Service".to_string(),
                    service_identifier: "suspicious.example.com".to_string(),
                    agent_session_id: "session-456".to_string(),
                    request_timestamp: Timestamp::now(),
                },
                original_tier: 1,
                requested_scope: test_scope(),
                anomaly_context: AnomalyContext {
                    anomaly_type: "role_mismatch".to_string(),
                    severity: signet_core::AnomalySeverity::High,
                    explanation: "Commerce role asking for medical data".to_string(),
                    evidence_summary: "Role classification: Commerce, requested data type: Medical"
                        .to_string(),
                    policy_rule_id: "rule-42".to_string(),
                },
                available_actions: AvailableActions {
                    can_approve: true,
                    can_deny: true,
                    can_modify: false,
                    suggested_scope: None,
                },
                expires_at: future_timestamp(300),
            },
        }
    }

    #[test]
    fn test_create_dispatcher() {
        let endpoint = test_endpoint();
        let token_key = [0x42u8; 32];
        let dispatcher = NotificationDispatcher::new(endpoint, RetryPolicy::default(), token_key);
        assert!(dispatcher.is_ok());
    }

    #[test]
    fn test_notify_tier3_request() {
        let endpoint = test_endpoint();
        let token_key = [0x42u8; 32];
        let mut dispatcher =
            NotificationDispatcher::new(endpoint, RetryPolicy::default(), token_key).unwrap();

        let request = test_tier3_request();
        let handle = dispatcher.notify(&request);
        assert!(handle.is_ok());

        let handle = handle.unwrap();
        assert_eq!(handle.challenge_id, *request.challenge_id());
        assert_eq!(handle.event_id, *request.event_id());
    }

    #[test]
    fn test_notify_anomaly_request() {
        let endpoint = test_endpoint();
        let token_key = [0x42u8; 32];
        let mut dispatcher =
            NotificationDispatcher::new(endpoint, RetryPolicy::default(), token_key).unwrap();

        let request = test_anomaly_request();
        let handle = dispatcher.notify(&request);
        assert!(handle.is_ok());
    }

    #[test]
    fn test_notify_without_endpoint_fails() {
        let token_key = [0x42u8; 32];
        let mut dispatcher = NotificationDispatcher::new_without_endpoint(token_key);

        let request = test_tier3_request();
        let result = dispatcher.notify(&request);
        assert_eq!(result.unwrap_err(), NotifyError::EndpointUnavailable);
    }

    #[test]
    fn test_notify_expired_request_fails() {
        let endpoint = test_endpoint();
        let token_key = [0x42u8; 32];
        let mut dispatcher =
            NotificationDispatcher::new(endpoint, RetryPolicy::default(), token_key).unwrap();

        // Create an already-expired request
        let cid = ChallengeId::generate();
        let eid = EventId::generate();
        let past = Timestamp::from_seconds(1000); // way in the past
        let request = AuthorizationRequest::Tier3Access {
            event_id: eid,
            challenge_id: cid,
            payload: Tier3AccessPayload {
                requester: RequesterInfo {
                    service_name: "Test".to_string(),
                    service_identifier: "test.com".to_string(),
                    agent_session_id: "s-1".to_string(),
                    request_timestamp: Timestamp::now(),
                },
                compartment_label: "Test".to_string(),
                requested_scope: test_scope(),
                justification: "Test".to_string(),
                available_actions: AvailableActions {
                    can_approve: true,
                    can_deny: true,
                    can_modify: false,
                    suggested_scope: None,
                },
                expires_at: past,
            },
        };

        let result = dispatcher.notify(&request);
        assert_eq!(result.unwrap_err(), NotifyError::ChallengeExpired);
    }

    #[test]
    fn test_full_flow_approve() {
        let endpoint = test_endpoint();
        let token_key = [0x42u8; 32];
        let mut dispatcher =
            NotificationDispatcher::new(endpoint, RetryPolicy::default(), token_key).unwrap();

        let request = test_tier3_request();
        let cid = request.challenge_id().clone();
        let handle = dispatcher.notify(&request).unwrap();

        // Create a valid challenge token for the callback
        let token = create_challenge_token(&cid, *request.expires_at(), &token_key).unwrap();

        let callback = CallbackPayload {
            challenge_token: token,
            response: AuthorizationResponse::Approve,
        };

        dispatcher.handle_callback(&cid, &callback).unwrap();

        let response = dispatcher.take_response(&cid).unwrap();
        let decision = handle.resolve(response);
        assert!(decision.is_approved());
    }

    #[test]
    fn test_full_flow_deny() {
        let endpoint = test_endpoint();
        let token_key = [0x42u8; 32];
        let mut dispatcher =
            NotificationDispatcher::new(endpoint, RetryPolicy::default(), token_key).unwrap();

        let request = test_tier3_request();
        let cid = request.challenge_id().clone();
        let handle = dispatcher.notify(&request).unwrap();

        let token = create_challenge_token(&cid, *request.expires_at(), &token_key).unwrap();

        let callback = CallbackPayload {
            challenge_token: token,
            response: AuthorizationResponse::Deny {
                reason: Some("I don't trust this service".to_string()),
            },
        };

        dispatcher.handle_callback(&cid, &callback).unwrap();

        let response = dispatcher.take_response(&cid).unwrap();
        let decision = handle.resolve(response);
        assert!(decision.is_denied());

        if let AuthorizationDecision::Denied {
            denial_reason,
            denial_message,
            ..
        } = &decision
        {
            assert_eq!(*denial_reason, DenialReason::ExplicitDeny);
            assert_eq!(
                denial_message.as_deref(),
                Some("I don't trust this service")
            );
        }
    }

    #[test]
    fn test_full_flow_modify() {
        let endpoint = test_endpoint();
        let token_key = [0x42u8; 32];
        let mut dispatcher =
            NotificationDispatcher::new(endpoint, RetryPolicy::default(), token_key).unwrap();

        let request = test_tier3_request();
        let cid = request.challenge_id().clone();
        let handle = dispatcher.notify(&request).unwrap();

        let token = create_challenge_token(&cid, *request.expires_at(), &token_key).unwrap();

        // Modify to a strict subset
        let adjusted = ScopeSet::new(vec![ScopeEntry::new("vault.medical", "read")]).unwrap();

        let callback = CallbackPayload {
            challenge_token: token,
            response: AuthorizationResponse::Modify {
                adjusted_scope: adjusted,
            },
        };

        dispatcher.handle_callback(&cid, &callback).unwrap();

        let response = dispatcher.take_response(&cid).unwrap();
        let decision = handle.resolve(response);
        assert!(decision.is_modified());
    }

    #[test]
    fn test_callback_with_invalid_token_fails() {
        let endpoint = test_endpoint();
        let token_key = [0x42u8; 32];
        let dispatcher =
            NotificationDispatcher::new(endpoint, RetryPolicy::default(), token_key).unwrap();

        let cid = ChallengeId::generate();
        let callback = CallbackPayload {
            challenge_token: "v4.local.invalid".to_string(),
            response: AuthorizationResponse::Approve,
        };

        let result = dispatcher.handle_callback(&cid, &callback);
        assert!(result.is_err());
    }

    #[test]
    fn test_callback_with_wrong_challenge_id_fails() {
        let endpoint = test_endpoint();
        let token_key = [0x42u8; 32];
        let mut dispatcher =
            NotificationDispatcher::new(endpoint, RetryPolicy::default(), token_key).unwrap();

        let request = test_tier3_request();
        let cid = request.challenge_id().clone();
        let _handle = dispatcher.notify(&request).unwrap();

        // Create token for a different challenge_id
        let wrong_cid = ChallengeId::generate();
        let token = create_challenge_token(&wrong_cid, future_timestamp(300), &token_key).unwrap();

        let callback = CallbackPayload {
            challenge_token: token,
            response: AuthorizationResponse::Approve,
        };

        let result = dispatcher.handle_callback(&cid, &callback);
        assert!(result.is_err());
    }

    #[test]
    fn test_registry_snapshot() {
        let endpoint = test_endpoint();
        let token_key = [0x42u8; 32];
        let mut dispatcher =
            NotificationDispatcher::new(endpoint, RetryPolicy::default(), token_key).unwrap();

        let snapshot = dispatcher.registry_snapshot().unwrap();
        assert_eq!(snapshot.active_challenges, 0);

        let request = test_tier3_request();
        let _handle = dispatcher.notify(&request).unwrap();

        let snapshot = dispatcher.registry_snapshot().unwrap();
        assert_eq!(snapshot.active_challenges, 1);
        assert_eq!(snapshot.total_challenges_issued, 1);
    }

    #[test]
    fn test_endpoint_health() {
        let endpoint = test_endpoint();
        let token_key = [0x42u8; 32];
        let dispatcher =
            NotificationDispatcher::new(endpoint, RetryPolicy::default(), token_key).unwrap();

        let health = dispatcher.endpoint_health();
        assert_eq!(health.consecutive_failures, 0);
        assert_eq!(health.circuit_state, crate::types::CircuitState::Closed);
    }

    #[test]
    fn test_simulate_delivery_success() {
        let endpoint = test_endpoint();
        let token_key = [0x42u8; 32];
        let mut dispatcher =
            NotificationDispatcher::new(endpoint, RetryPolicy::default(), token_key).unwrap();

        let cid = ChallengeId::generate();
        let eid = EventId::generate();
        let report = dispatcher
            .simulate_delivery(&cid, &eid, b"test payload", true)
            .unwrap();

        assert_eq!(report.final_outcome, DeliveryOutcome::Success);
        assert_eq!(report.attempts.len(), 1);
        assert_eq!(report.attempts[0].http_status, Some(200));
    }

    #[test]
    fn test_simulate_delivery_failure() {
        let endpoint = test_endpoint();
        let token_key = [0x42u8; 32];
        let mut dispatcher =
            NotificationDispatcher::new(endpoint, RetryPolicy::default(), token_key).unwrap();

        let cid = ChallengeId::generate();
        let eid = EventId::generate();
        let report = dispatcher
            .simulate_delivery(&cid, &eid, b"test payload", false)
            .unwrap();

        assert_eq!(report.final_outcome, DeliveryOutcome::HttpError);
    }

    #[test]
    fn test_circuit_breaker_blocks_after_failures() {
        let secret = test_secret();
        let endpoint = EndpointConfig {
            url: "https://example.com/webhook".to_string(),
            current_secret: secret,
            previous_secret: None,
            timeout_seconds: 30,
            max_retries: 3,
            circuit_breaker_threshold: 2, // low threshold
        };
        let token_key = [0x42u8; 32];
        let mut dispatcher =
            NotificationDispatcher::new(endpoint, RetryPolicy::default(), token_key).unwrap();

        let cid = ChallengeId::generate();
        let eid = EventId::generate();

        // Simulate failures to open circuit
        let _ = dispatcher.simulate_delivery(&cid, &eid, b"test", false);
        let _ = dispatcher.simulate_delivery(&cid, &eid, b"test", false);

        // Circuit should now be open
        let request = test_tier3_request();
        let result = dispatcher.notify(&request);
        assert_eq!(result.unwrap_err(), NotifyError::CircuitBreakerOpen);
    }

    #[test]
    fn test_update_endpoint() {
        let endpoint = test_endpoint();
        let token_key = [0x42u8; 32];
        let mut dispatcher =
            NotificationDispatcher::new(endpoint, RetryPolicy::default(), token_key).unwrap();

        let new_secret = WebhookSecret::new(vec![0x99u8; 32], "new-key").unwrap();
        let new_endpoint = EndpointConfig {
            url: "https://new.example.com/webhook".to_string(),
            current_secret: new_secret,
            previous_secret: None,
            timeout_seconds: 60,
            max_retries: 5,
            circuit_breaker_threshold: 10,
        };

        dispatcher.update_endpoint(new_endpoint).unwrap();

        // Should still work with new endpoint
        let request = test_tier3_request();
        let _handle = dispatcher.notify(&request).unwrap();
    }

    #[test]
    fn test_cleanup_expired() {
        let endpoint = test_endpoint();
        let token_key = [0x42u8; 32];
        let dispatcher =
            NotificationDispatcher::new(endpoint, RetryPolicy::default(), token_key).unwrap();

        // Create an already-expired challenge by manually registering
        let cid = ChallengeId::generate();
        let eid = EventId::generate();
        let past = Timestamp::from_seconds(1000);
        let _handle = dispatcher
            .registry
            .register(cid, eid, past, test_scope())
            .unwrap();

        let cleaned = dispatcher.cleanup_expired().unwrap();
        assert_eq!(cleaned, 1);
    }
}
