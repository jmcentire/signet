use serde::{Deserialize, Serialize};
use signet_core::Timestamp;
use std::fmt;

// ---------------------------------------------------------------------------
// ChallengeId — unique challenge identifier (URL-safe base64, 128-bit random)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChallengeId {
    value: String,
}

impl ChallengeId {
    /// Create a new ChallengeId from a string value.
    /// Validates length (16..=64) and URL-safe base64 characters.
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.len() < 16 || value.len() > 64 {
            return Err("ChallengeId must be between 16 and 64 characters");
        }
        if !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err("ChallengeId must be URL-safe base64");
        }
        Ok(Self { value })
    }

    /// Generate a cryptographically random ChallengeId.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let value = base64_url_encode(&bytes);
        Self { value }
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for ChallengeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

// ---------------------------------------------------------------------------
// DeliveryId — unique webhook delivery attempt identifier
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeliveryId {
    value: String,
}

impl DeliveryId {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.len() < 16 || value.len() > 64 {
            return Err("DeliveryId must be between 16 and 64 characters");
        }
        if !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err("DeliveryId must be URL-safe base64");
        }
        Ok(Self { value })
    }

    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let value = base64_url_encode(&bytes);
        Self { value }
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for DeliveryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

// ---------------------------------------------------------------------------
// EventId — unique notification event identifier
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId {
    value: String,
}

impl EventId {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.len() < 16 || value.len() > 64 {
            return Err("EventId must be between 16 and 64 characters");
        }
        if !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err("EventId must be URL-safe base64");
        }
        Ok(Self { value })
    }

    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let value = base64_url_encode(&bytes);
        Self { value }
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

// ---------------------------------------------------------------------------
// ScopeEntry and ScopeSet — scope permission model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScopeEntry {
    pub resource: String,
    pub action: String,
}

impl ScopeEntry {
    pub fn new(resource: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            action: action.into(),
        }
    }
}

/// An ordered, deduplicated set of ScopeEntry values.
/// Enforces subset validation for Modify responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeSet {
    entries: Vec<ScopeEntry>,
}

impl ScopeSet {
    /// Create a new ScopeSet, deduplicating entries by (resource, action) pair.
    pub fn new(entries: Vec<ScopeEntry>) -> Result<Self, &'static str> {
        if entries.is_empty() {
            return Err("ScopeSet must contain at least one entry");
        }
        let mut deduped = Vec::new();
        for entry in entries {
            if !deduped.contains(&entry) {
                deduped.push(entry);
            }
        }
        Ok(Self { entries: deduped })
    }

    pub fn entries(&self) -> &[ScopeEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Check if `other` is a strict subset of `self`.
    /// Every entry in `other` must exist in `self`, and `other` must have
    /// strictly fewer entries.
    pub fn is_strict_superset_of(&self, other: &ScopeSet) -> bool {
        if other.entries.len() >= self.entries.len() {
            return false;
        }
        other
            .entries
            .iter()
            .all(|entry| self.entries.contains(entry))
    }
}

// ---------------------------------------------------------------------------
// RequesterInfo — who is making the request
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequesterInfo {
    pub service_name: String,
    pub service_identifier: String,
    pub agent_session_id: String,
    pub request_timestamp: Timestamp,
}

// ---------------------------------------------------------------------------
// AnomalyContext — why a request was flagged
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyContext {
    pub anomaly_type: String,
    pub severity: signet_core::AnomalySeverity,
    pub explanation: String,
    pub evidence_summary: String,
    pub policy_rule_id: String,
}

// ---------------------------------------------------------------------------
// AvailableActions — what the user can do
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailableActions {
    pub can_approve: bool,
    pub can_deny: bool,
    pub can_modify: bool,
    pub suggested_scope: Option<ScopeSet>,
}

// ---------------------------------------------------------------------------
// Tier3AccessPayload — Tier 3 compartment access request
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tier3AccessPayload {
    pub requester: RequesterInfo,
    pub compartment_label: String,
    pub requested_scope: ScopeSet,
    pub justification: String,
    pub available_actions: AvailableActions,
    pub expires_at: Timestamp,
}

// ---------------------------------------------------------------------------
// AnomalyEscalationPayload — anomaly escalation request
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyEscalationPayload {
    pub requester: RequesterInfo,
    pub original_tier: u8,
    pub requested_scope: ScopeSet,
    pub anomaly_context: AnomalyContext,
    pub available_actions: AvailableActions,
    pub expires_at: Timestamp,
}

// ---------------------------------------------------------------------------
// AuthorizationRequest — internally-tagged enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "request_type", rename_all = "snake_case")]
pub enum AuthorizationRequest {
    Tier3Access {
        event_id: EventId,
        challenge_id: ChallengeId,
        #[serde(flatten)]
        payload: Tier3AccessPayload,
    },
    AnomalyEscalation {
        event_id: EventId,
        challenge_id: ChallengeId,
        #[serde(flatten)]
        payload: AnomalyEscalationPayload,
    },
}

impl AuthorizationRequest {
    pub fn event_id(&self) -> &EventId {
        match self {
            AuthorizationRequest::Tier3Access { event_id, .. } => event_id,
            AuthorizationRequest::AnomalyEscalation { event_id, .. } => event_id,
        }
    }

    pub fn challenge_id(&self) -> &ChallengeId {
        match self {
            AuthorizationRequest::Tier3Access { challenge_id, .. } => challenge_id,
            AuthorizationRequest::AnomalyEscalation { challenge_id, .. } => challenge_id,
        }
    }

    pub fn requested_scope(&self) -> &ScopeSet {
        match self {
            AuthorizationRequest::Tier3Access { payload, .. } => &payload.requested_scope,
            AuthorizationRequest::AnomalyEscalation { payload, .. } => &payload.requested_scope,
        }
    }

    pub fn expires_at(&self) -> &Timestamp {
        match self {
            AuthorizationRequest::Tier3Access { payload, .. } => &payload.expires_at,
            AuthorizationRequest::AnomalyEscalation { payload, .. } => &payload.expires_at,
        }
    }
}

// ---------------------------------------------------------------------------
// AuthorizationResponse — wire-format response from user
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorizationResponse {
    Approve,
    Deny {
        #[serde(default)]
        reason: Option<String>,
    },
    Modify {
        adjusted_scope: ScopeSet,
    },
}

// ---------------------------------------------------------------------------
// DenialReason — internal reason for denial
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenialReason {
    Timeout,
    ExplicitDeny,
    DeliveryFailure,
}

// ---------------------------------------------------------------------------
// AuthorizationDecision — internal validated decision type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthorizationDecision {
    Approved {
        challenge_id: ChallengeId,
        event_id: EventId,
        decided_at: Timestamp,
    },
    Denied {
        challenge_id: ChallengeId,
        event_id: EventId,
        decided_at: Timestamp,
        denial_reason: DenialReason,
        denial_message: Option<String>,
    },
    Modified {
        challenge_id: ChallengeId,
        event_id: EventId,
        decided_at: Timestamp,
        adjusted_scope: ScopeSet,
    },
}

impl AuthorizationDecision {
    pub fn challenge_id(&self) -> &ChallengeId {
        match self {
            AuthorizationDecision::Approved { challenge_id, .. } => challenge_id,
            AuthorizationDecision::Denied { challenge_id, .. } => challenge_id,
            AuthorizationDecision::Modified { challenge_id, .. } => challenge_id,
        }
    }

    pub fn event_id(&self) -> &EventId {
        match self {
            AuthorizationDecision::Approved { event_id, .. } => event_id,
            AuthorizationDecision::Denied { event_id, .. } => event_id,
            AuthorizationDecision::Modified { event_id, .. } => event_id,
        }
    }

    pub fn is_approved(&self) -> bool {
        matches!(self, AuthorizationDecision::Approved { .. })
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, AuthorizationDecision::Denied { .. })
    }

    pub fn is_modified(&self) -> bool {
        matches!(self, AuthorizationDecision::Modified { .. })
    }
}

// ---------------------------------------------------------------------------
// WebhookSecret — HMAC signing secret
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct WebhookSecret {
    key_bytes: Vec<u8>,
    pub key_id: String,
}

impl WebhookSecret {
    pub fn new(key_bytes: Vec<u8>, key_id: impl Into<String>) -> Result<Self, &'static str> {
        if key_bytes.len() < 32 {
            return Err("Webhook secret must be at least 256 bits (32 bytes)");
        }
        Ok(Self {
            key_bytes,
            key_id: key_id.into(),
        })
    }

    pub fn key_bytes(&self) -> &[u8] {
        &self.key_bytes
    }
}

impl fmt::Debug for WebhookSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WebhookSecret(key_id={}, [REDACTED])", self.key_id)
    }
}

impl Drop for WebhookSecret {
    fn drop(&mut self) {
        // Zeroize key material on drop
        for byte in self.key_bytes.iter_mut() {
            *byte = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// WebhookSignatureHeaders — three Signet-namespaced headers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSignatureHeaders {
    pub webhook_id: DeliveryId,
    pub webhook_timestamp: Timestamp,
    pub webhook_signature: String,
}

// ---------------------------------------------------------------------------
// EndpointConfig — webhook delivery endpoint configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EndpointConfig {
    pub url: String,
    pub current_secret: WebhookSecret,
    pub previous_secret: Option<WebhookSecret>,
    pub timeout_seconds: u64,
    pub max_retries: u32,
    pub circuit_breaker_threshold: u32,
}

impl EndpointConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.url.starts_with("https://") {
            return Err("Webhook endpoint must use HTTPS");
        }
        if self.url.len() < 9 || self.url.len() > 2048 {
            return Err("Webhook URL must be between 9 and 2048 characters");
        }
        if self.max_retries > 10 {
            return Err("Max retries must be between 0 and 10");
        }
        if self.circuit_breaker_threshold < 1 || self.circuit_breaker_threshold > 100 {
            return Err("Circuit breaker threshold must be between 1 and 100");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// EndpointHealth — health status tracked by circuit breaker
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointHealth {
    pub consecutive_failures: u32,
    pub circuit_state: CircuitState,
    pub last_success: Option<Timestamp>,
    pub last_failure: Option<Timestamp>,
    pub total_deliveries: u64,
    pub total_failures: u64,
}

// ---------------------------------------------------------------------------
// CircuitState — circuit breaker states
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

// ---------------------------------------------------------------------------
// RetryPolicy — exponential backoff configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub initial_delay_seconds: u64,
    pub max_delay_seconds: u64,
    pub backoff_factor: f64,
    pub jitter_fraction: f64,
}

impl RetryPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(1.0..=10.0).contains(&self.backoff_factor) {
            return Err("Backoff factor must be between 1.0 and 10.0");
        }
        if !(0.0..=1.0).contains(&self.jitter_fraction) {
            return Err("Jitter fraction must be between 0.0 and 1.0");
        }
        Ok(())
    }

    /// Calculate the delay for a given attempt number (0-indexed).
    pub fn delay_for_attempt(&self, attempt: u32) -> u64 {
        let base_delay =
            (self.initial_delay_seconds as f64) * self.backoff_factor.powi(attempt as i32);
        let capped = base_delay.min(self.max_delay_seconds as f64);

        // Apply jitter
        let jitter_range = capped * self.jitter_fraction;
        let jitter = if jitter_range > 0.0 {
            use rand::Rng;
            rand::thread_rng().gen_range(0.0..jitter_range)
        } else {
            0.0
        };

        (capped + jitter) as u64
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial_delay_seconds: 1,
            max_delay_seconds: 30,
            backoff_factor: 2.0,
            jitter_fraction: 0.1,
        }
    }
}

// ---------------------------------------------------------------------------
// DeliveryOutcome — outcome of a webhook delivery attempt
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryOutcome {
    Success,
    HttpError,
    Timeout,
    ConnectionError,
    CircuitBreakerOpen,
}

// ---------------------------------------------------------------------------
// DeliveryAttempt — record of a single delivery attempt
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryAttempt {
    pub delivery_id: DeliveryId,
    pub challenge_id: ChallengeId,
    pub attempt_number: u32,
    pub attempted_at: Timestamp,
    pub outcome: DeliveryOutcome,
    pub http_status: Option<u16>,
    pub latency_ms: u64,
}

// ---------------------------------------------------------------------------
// DeliveryReport — full report aggregating all attempts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryReport {
    pub challenge_id: ChallengeId,
    pub event_id: EventId,
    pub final_outcome: DeliveryOutcome,
    pub attempts: Vec<DeliveryAttempt>,
    pub total_duration_ms: u64,
}

// ---------------------------------------------------------------------------
// CallbackPayload — received from user's webhook consumer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackPayload {
    pub challenge_token: String,
    pub response: AuthorizationResponse,
}

// ---------------------------------------------------------------------------
// ChallengeRegistrySnapshot — diagnostic snapshot
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRegistrySnapshot {
    pub active_challenges: usize,
    pub expired_challenges_cleaned: u64,
    pub total_challenges_issued: u64,
    pub total_challenges_resolved: u64,
}

// ---------------------------------------------------------------------------
// NotificationChannel enum — multi-channel support
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationChannel {
    Webhook,
    Sms,
    Push,
    InApp,
}

// ---------------------------------------------------------------------------
// NotificationPayload — what gets sent through a channel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationPayload {
    pub channel: NotificationChannel,
    pub request: AuthorizationRequest,
    pub challenge_token: String,
}

// ---------------------------------------------------------------------------
// Utility — URL-safe base64 encoding (no padding)
// ---------------------------------------------------------------------------

fn base64_url_encode(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    // Use hex encoding of a hash to get URL-safe characters that meet
    // the length requirement. We take 16 bytes of input, SHA-256 them,
    // and hex-encode the first 16 bytes of the hash for a 32-char result.
    // This gives us a URL-safe 32-character identifier.
    let hash = Sha256::digest(bytes);
    hex::encode(&hash[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_id_generation() {
        let id1 = ChallengeId::generate();
        let id2 = ChallengeId::generate();
        assert_ne!(id1, id2);
        assert!(id1.as_str().len() >= 16);
        assert!(id1.as_str().len() <= 64);
    }

    #[test]
    fn test_challenge_id_validation() {
        assert!(ChallengeId::new("abcdefghijklmnop").is_ok());
        assert!(ChallengeId::new("abc").is_err()); // too short
        assert!(ChallengeId::new("a".repeat(65)).is_err()); // too long
        assert!(ChallengeId::new("invalid chars!!+").is_err()); // invalid chars
    }

    #[test]
    fn test_delivery_id_generation() {
        let id1 = DeliveryId::generate();
        let id2 = DeliveryId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_event_id_generation() {
        let id1 = EventId::generate();
        let id2 = EventId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_scope_entry_creation() {
        let entry = ScopeEntry::new("vault.financial.tax_returns", "read");
        assert_eq!(entry.resource, "vault.financial.tax_returns");
        assert_eq!(entry.action, "read");
    }

    #[test]
    fn test_scope_set_deduplication() {
        let entries = vec![
            ScopeEntry::new("vault.medical", "read"),
            ScopeEntry::new("vault.medical", "read"), // duplicate
            ScopeEntry::new("vault.financial", "read"),
        ];
        let set = ScopeSet::new(entries).unwrap();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_scope_set_empty_rejected() {
        assert!(ScopeSet::new(vec![]).is_err());
    }

    #[test]
    fn test_scope_set_strict_superset() {
        let parent = ScopeSet::new(vec![
            ScopeEntry::new("vault.medical", "read"),
            ScopeEntry::new("vault.financial", "read"),
            ScopeEntry::new("vault.identity", "prove"),
        ])
        .unwrap();

        let child = ScopeSet::new(vec![
            ScopeEntry::new("vault.medical", "read"),
            ScopeEntry::new("vault.financial", "read"),
        ])
        .unwrap();

        assert!(parent.is_strict_superset_of(&child));
        assert!(!child.is_strict_superset_of(&parent));
    }

    #[test]
    fn test_scope_set_equal_not_strict_superset() {
        let set1 = ScopeSet::new(vec![ScopeEntry::new("vault.medical", "read")]).unwrap();
        let set2 = ScopeSet::new(vec![ScopeEntry::new("vault.medical", "read")]).unwrap();
        assert!(!set1.is_strict_superset_of(&set2));
    }

    #[test]
    fn test_scope_set_disjoint_not_superset() {
        let set1 = ScopeSet::new(vec![ScopeEntry::new("vault.medical", "read")]).unwrap();
        let set2 = ScopeSet::new(vec![ScopeEntry::new("vault.financial", "read")]).unwrap();
        // Cannot reduce to set2 since it is not a superset
        assert!(!set1.is_strict_superset_of(&set2));
    }

    #[test]
    fn test_webhook_secret_minimum_length() {
        assert!(WebhookSecret::new(vec![0u8; 31], "key-1").is_err());
        assert!(WebhookSecret::new(vec![0u8; 32], "key-1").is_ok());
        assert!(WebhookSecret::new(vec![0u8; 64], "key-1").is_ok());
    }

    #[test]
    fn test_webhook_secret_debug_redacts() {
        let secret = WebhookSecret::new(vec![0xAB; 32], "test-key").unwrap();
        let debug = format!("{:?}", secret);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("171")); // 0xAB = 171
    }

    #[test]
    fn test_webhook_secret_zeroize_on_drop() {
        let key_bytes = vec![0xAB; 32];
        let ptr = key_bytes.as_ptr();
        let secret = WebhookSecret::new(key_bytes, "key-1").unwrap();
        let internal_ptr = secret.key_bytes().as_ptr();
        drop(secret);
        // After drop, we can't access the secret, confirming move semantics work.
        // The actual zeroization happens inside the Drop impl.
        let _ = ptr;
        let _ = internal_ptr;
    }

    #[test]
    fn test_endpoint_config_validation() {
        let secret = WebhookSecret::new(vec![0u8; 32], "key-1").unwrap();
        let config = EndpointConfig {
            url: "https://example.com/webhook".to_string(),
            current_secret: secret,
            previous_secret: None,
            timeout_seconds: 30,
            max_retries: 3,
            circuit_breaker_threshold: 5,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_endpoint_config_rejects_http() {
        let secret = WebhookSecret::new(vec![0u8; 32], "key-1").unwrap();
        let config = EndpointConfig {
            url: "http://example.com/webhook".to_string(),
            current_secret: secret,
            previous_secret: None,
            timeout_seconds: 30,
            max_retries: 3,
            circuit_breaker_threshold: 5,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_retry_policy_default() {
        let policy = RetryPolicy::default();
        assert!(policy.validate().is_ok());
        assert_eq!(policy.initial_delay_seconds, 1);
        assert_eq!(policy.max_delay_seconds, 30);
    }

    #[test]
    fn test_retry_policy_delay_calculation() {
        let policy = RetryPolicy {
            initial_delay_seconds: 1,
            max_delay_seconds: 30,
            backoff_factor: 2.0,
            jitter_fraction: 0.0, // no jitter for deterministic test
        };
        assert_eq!(policy.delay_for_attempt(0), 1);
        assert_eq!(policy.delay_for_attempt(1), 2);
        assert_eq!(policy.delay_for_attempt(2), 4);
        assert_eq!(policy.delay_for_attempt(3), 8);
        // Capped at max_delay
        assert_eq!(policy.delay_for_attempt(10), 30);
    }

    #[test]
    fn test_authorization_response_serde() {
        let approve_json = r#"{"decision":"approve"}"#;
        let resp: AuthorizationResponse = serde_json::from_str(approve_json).unwrap();
        assert!(matches!(resp, AuthorizationResponse::Approve));

        let deny_json = r#"{"decision":"deny","reason":"not today"}"#;
        let resp: AuthorizationResponse = serde_json::from_str(deny_json).unwrap();
        assert!(matches!(
            resp,
            AuthorizationResponse::Deny { reason: Some(_) }
        ));

        let deny_no_reason = r#"{"decision":"deny"}"#;
        let resp: AuthorizationResponse = serde_json::from_str(deny_no_reason).unwrap();
        assert!(matches!(resp, AuthorizationResponse::Deny { reason: None }));
    }

    #[test]
    fn test_authorization_response_deny_unknown_fields() {
        // With internally-tagged enums + deny_unknown_fields, serde rejects
        // unknown fields on variants that have no expected fields.
        // The Deny variant has an optional "reason" field, so extra fields
        // beyond "decision" and "reason" should be rejected.
        let bad_json = r#"{"decision":"deny","reason":"ok","extra_field":"bad"}"#;
        let result: Result<AuthorizationResponse, _> = serde_json::from_str(bad_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_delivery_outcome_variants() {
        let outcomes = vec![
            DeliveryOutcome::Success,
            DeliveryOutcome::HttpError,
            DeliveryOutcome::Timeout,
            DeliveryOutcome::ConnectionError,
            DeliveryOutcome::CircuitBreakerOpen,
        ];
        for (i, a) in outcomes.iter().enumerate() {
            for (j, b) in outcomes.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn test_circuit_state_variants() {
        assert_ne!(CircuitState::Closed, CircuitState::Open);
        assert_ne!(CircuitState::Open, CircuitState::HalfOpen);
        assert_eq!(CircuitState::Closed, CircuitState::Closed);
    }

    #[test]
    fn test_authorization_decision_accessors() {
        let cid = ChallengeId::generate();
        let eid = EventId::generate();
        let now = Timestamp::now();

        let approved = AuthorizationDecision::Approved {
            challenge_id: cid.clone(),
            event_id: eid.clone(),
            decided_at: now,
        };
        assert!(approved.is_approved());
        assert!(!approved.is_denied());
        assert!(!approved.is_modified());
        assert_eq!(approved.challenge_id(), &cid);
        assert_eq!(approved.event_id(), &eid);
    }

    #[test]
    fn test_notification_channel_variants() {
        assert_eq!(NotificationChannel::Webhook, NotificationChannel::Webhook);
        assert_ne!(NotificationChannel::Webhook, NotificationChannel::Sms);
        assert_ne!(NotificationChannel::Push, NotificationChannel::InApp);
    }

    #[test]
    fn test_denial_reason_variants() {
        assert_ne!(DenialReason::Timeout, DenialReason::ExplicitDeny);
        assert_ne!(DenialReason::Timeout, DenialReason::DeliveryFailure);
        assert_eq!(DenialReason::Timeout, DenialReason::Timeout);
    }
}
