//! Signet Notification Channel
//!
//! Webhook-based authorization channel for Tier 3 requests and ANOMALY
//! escalations. Presents structured reasoning payload: who is asking, what
//! they want, why it is unusual, what options the user has.
//!
//! Accepts user response: approve, deny, or modify (with scope adjustment).
//! Timeout defaults to deny (fail-secure).
//!
//! Key features:
//! - Webhook HMAC-SHA256 signature generation and verification
//! - Challenge registry with move-only ChallengeHandle (prevents double-use)
//! - Circuit breaker pattern for failing notification channels
//! - Scope subset validation (prevents privilege escalation)
//! - Multi-channel notification: webhook, SMS (stub), push (stub), in-app
//! - Authorization flow: agent presents reasoning, user responds approve/deny/modify

pub mod authorization;
pub mod challenge;
pub mod circuit_breaker;
pub mod dispatcher;
pub mod error;
pub mod scope;
pub mod types;
pub mod webhook;

// Re-export primary types and functions
pub use authorization::{
    decision_summary, is_delivery_failure, is_timeout_denial, AnomalyRequestBuilder,
    Tier3RequestBuilder,
};
pub use challenge::{
    create_challenge_token, verify_challenge_token, ChallengeHandle, ChallengeRegistry,
};
pub use circuit_breaker::CircuitBreaker;
pub use dispatcher::NotificationDispatcher;
pub use error::{NotifyError, NotifyResult};
pub use scope::{detect_escalation, scopes_equal, validate_scope_subset};
pub use types::{
    AnomalyContext, AnomalyEscalationPayload, AuthorizationDecision, AuthorizationRequest,
    AuthorizationResponse, AvailableActions, CallbackPayload, ChallengeId,
    ChallengeRegistrySnapshot, CircuitState, DeliveryAttempt, DeliveryId, DeliveryOutcome,
    DeliveryReport, DenialReason, EndpointConfig, EndpointHealth, EventId, NotificationChannel,
    NotificationPayload, RequesterInfo, RetryPolicy, ScopeEntry, ScopeSet, Tier3AccessPayload,
    WebhookSecret, WebhookSignatureHeaders,
};
pub use webhook::{rotate_webhook_secret, sign_webhook_payload, verify_webhook_signature};
