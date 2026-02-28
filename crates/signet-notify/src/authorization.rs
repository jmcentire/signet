//! Authorization request/response flow.
//!
//! Provides builders for creating authorization requests and processing
//! authorization responses. This module ties together the types, challenge
//! registry, and scope validation into a cohesive authorization flow.

use signet_core::{AnomalySeverity, Timestamp};

use crate::error::{NotifyError, NotifyResult};
use crate::types::{
    AnomalyContext, AnomalyEscalationPayload, AuthorizationDecision, AuthorizationRequest,
    AvailableActions, ChallengeId, DenialReason, EventId, RequesterInfo, ScopeEntry, ScopeSet,
    Tier3AccessPayload,
};

// ---------------------------------------------------------------------------
// AuthorizationRequestBuilder — construct authorization requests
// ---------------------------------------------------------------------------

/// Builder for creating Tier 3 access authorization requests.
pub struct Tier3RequestBuilder {
    service_name: String,
    service_identifier: String,
    agent_session_id: String,
    compartment_label: String,
    scope_entries: Vec<ScopeEntry>,
    justification: String,
    timeout_seconds: u64,
    can_modify: bool,
    suggested_scope: Option<ScopeSet>,
}

impl Tier3RequestBuilder {
    /// Create a new builder for a Tier 3 access request.
    pub fn new(
        service_name: impl Into<String>,
        service_identifier: impl Into<String>,
        agent_session_id: impl Into<String>,
    ) -> Self {
        Self {
            service_name: service_name.into(),
            service_identifier: service_identifier.into(),
            agent_session_id: agent_session_id.into(),
            compartment_label: String::new(),
            scope_entries: Vec::new(),
            justification: String::new(),
            timeout_seconds: 300, // default 5 minutes
            can_modify: true,
            suggested_scope: None,
        }
    }

    /// Set the compartment label (e.g., "Medical Records").
    pub fn compartment(mut self, label: impl Into<String>) -> Self {
        self.compartment_label = label.into();
        self
    }

    /// Add a scope entry to the request.
    pub fn scope(mut self, resource: impl Into<String>, action: impl Into<String>) -> Self {
        self.scope_entries.push(ScopeEntry::new(resource, action));
        self
    }

    /// Set the justification text.
    pub fn justification(mut self, text: impl Into<String>) -> Self {
        self.justification = text.into();
        self
    }

    /// Set the timeout in seconds (defaults to 300).
    pub fn timeout(mut self, seconds: u64) -> Self {
        self.timeout_seconds = seconds;
        self
    }

    /// Set whether modification (scope reduction) is allowed.
    pub fn allow_modify(mut self, allow: bool) -> Self {
        self.can_modify = allow;
        self
    }

    /// Set a suggested reduced scope for the user.
    pub fn suggest_scope(mut self, scope: ScopeSet) -> Self {
        self.suggested_scope = Some(scope);
        self
    }

    /// Build the authorization request.
    pub fn build(self) -> NotifyResult<AuthorizationRequest> {
        if self.scope_entries.is_empty() {
            return Err(NotifyError::ConfigurationError);
        }
        if self.justification.is_empty() {
            return Err(NotifyError::ConfigurationError);
        }
        if self.compartment_label.is_empty() {
            return Err(NotifyError::ConfigurationError);
        }

        let scope =
            ScopeSet::new(self.scope_entries).map_err(|_| NotifyError::ConfigurationError)?;

        let now = Timestamp::now();
        let expires_at = Timestamp::from_seconds(now.seconds_since_epoch + self.timeout_seconds);

        Ok(AuthorizationRequest::Tier3Access {
            event_id: EventId::generate(),
            challenge_id: ChallengeId::generate(),
            payload: Tier3AccessPayload {
                requester: RequesterInfo {
                    service_name: self.service_name,
                    service_identifier: self.service_identifier,
                    agent_session_id: self.agent_session_id,
                    request_timestamp: now,
                },
                compartment_label: self.compartment_label,
                requested_scope: scope,
                justification: self.justification,
                available_actions: AvailableActions {
                    can_approve: true,
                    can_deny: true,
                    can_modify: self.can_modify,
                    suggested_scope: self.suggested_scope,
                },
                expires_at,
            },
        })
    }
}

/// Builder for creating anomaly escalation authorization requests.
pub struct AnomalyRequestBuilder {
    service_name: String,
    service_identifier: String,
    agent_session_id: String,
    original_tier: u8,
    scope_entries: Vec<ScopeEntry>,
    anomaly_type: String,
    severity: AnomalySeverity,
    explanation: String,
    evidence_summary: String,
    policy_rule_id: String,
    timeout_seconds: u64,
    can_modify: bool,
}

impl AnomalyRequestBuilder {
    /// Create a new builder for an anomaly escalation request.
    pub fn new(
        service_name: impl Into<String>,
        service_identifier: impl Into<String>,
        agent_session_id: impl Into<String>,
    ) -> Self {
        Self {
            service_name: service_name.into(),
            service_identifier: service_identifier.into(),
            agent_session_id: agent_session_id.into(),
            original_tier: 1,
            scope_entries: Vec::new(),
            anomaly_type: String::new(),
            severity: AnomalySeverity::Medium,
            explanation: String::new(),
            evidence_summary: String::new(),
            policy_rule_id: String::new(),
            timeout_seconds: 300,
            can_modify: false,
        }
    }

    /// Set the original tier (1 or 2).
    pub fn original_tier(mut self, tier: u8) -> Self {
        self.original_tier = tier;
        self
    }

    /// Add a scope entry to the request.
    pub fn scope(mut self, resource: impl Into<String>, action: impl Into<String>) -> Self {
        self.scope_entries.push(ScopeEntry::new(resource, action));
        self
    }

    /// Set the anomaly type (e.g., "role_mismatch").
    pub fn anomaly_type(mut self, anomaly_type: impl Into<String>) -> Self {
        self.anomaly_type = anomaly_type.into();
        self
    }

    /// Set the anomaly severity.
    pub fn severity(mut self, severity: AnomalySeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Set the explanation text.
    pub fn explanation(mut self, text: impl Into<String>) -> Self {
        self.explanation = text.into();
        self
    }

    /// Set the evidence summary.
    pub fn evidence(mut self, text: impl Into<String>) -> Self {
        self.evidence_summary = text.into();
        self
    }

    /// Set the policy rule that triggered the escalation.
    pub fn policy_rule(mut self, rule_id: impl Into<String>) -> Self {
        self.policy_rule_id = rule_id.into();
        self
    }

    /// Set the timeout in seconds.
    pub fn timeout(mut self, seconds: u64) -> Self {
        self.timeout_seconds = seconds;
        self
    }

    /// Set whether modification is allowed.
    pub fn allow_modify(mut self, allow: bool) -> Self {
        self.can_modify = allow;
        self
    }

    /// Build the authorization request.
    pub fn build(self) -> NotifyResult<AuthorizationRequest> {
        if self.scope_entries.is_empty() {
            return Err(NotifyError::ConfigurationError);
        }
        if self.explanation.is_empty() {
            return Err(NotifyError::ConfigurationError);
        }
        if self.anomaly_type.is_empty() {
            return Err(NotifyError::ConfigurationError);
        }
        if self.original_tier < 1 || self.original_tier > 2 {
            return Err(NotifyError::ConfigurationError);
        }

        let scope =
            ScopeSet::new(self.scope_entries).map_err(|_| NotifyError::ConfigurationError)?;

        let now = Timestamp::now();
        let expires_at = Timestamp::from_seconds(now.seconds_since_epoch + self.timeout_seconds);

        Ok(AuthorizationRequest::AnomalyEscalation {
            event_id: EventId::generate(),
            challenge_id: ChallengeId::generate(),
            payload: AnomalyEscalationPayload {
                requester: RequesterInfo {
                    service_name: self.service_name,
                    service_identifier: self.service_identifier,
                    agent_session_id: self.agent_session_id,
                    request_timestamp: now,
                },
                original_tier: self.original_tier,
                requested_scope: scope,
                anomaly_context: AnomalyContext {
                    anomaly_type: self.anomaly_type,
                    severity: self.severity,
                    explanation: self.explanation,
                    evidence_summary: self.evidence_summary,
                    policy_rule_id: self.policy_rule_id,
                },
                available_actions: AvailableActions {
                    can_approve: true,
                    can_deny: true,
                    can_modify: self.can_modify,
                    suggested_scope: None,
                },
                expires_at,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Response processing helpers
// ---------------------------------------------------------------------------

/// Process an authorization decision and extract a summary for audit logging.
pub fn decision_summary(decision: &AuthorizationDecision) -> String {
    match decision {
        AuthorizationDecision::Approved {
            challenge_id,
            event_id,
            ..
        } => {
            format!("APPROVED challenge={} event={}", challenge_id, event_id)
        }
        AuthorizationDecision::Denied {
            challenge_id,
            event_id,
            denial_reason,
            ..
        } => {
            format!(
                "DENIED challenge={} event={} reason={:?}",
                challenge_id, event_id, denial_reason
            )
        }
        AuthorizationDecision::Modified {
            challenge_id,
            event_id,
            adjusted_scope,
            ..
        } => {
            format!(
                "MODIFIED challenge={} event={} scope_entries={}",
                challenge_id,
                event_id,
                adjusted_scope.len()
            )
        }
    }
}

/// Check if a decision represents a timeout denial (fail-secure behavior).
pub fn is_timeout_denial(decision: &AuthorizationDecision) -> bool {
    matches!(
        decision,
        AuthorizationDecision::Denied {
            denial_reason: DenialReason::Timeout,
            ..
        }
    )
}

/// Check if a decision represents a delivery failure denial.
pub fn is_delivery_failure(decision: &AuthorizationDecision) -> bool {
    matches!(
        decision,
        AuthorizationDecision::Denied {
            denial_reason: DenialReason::DeliveryFailure,
            ..
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier3_builder_basic() {
        let request = Tier3RequestBuilder::new("TestService", "test.com", "session-1")
            .compartment("Medical Records")
            .scope("vault.medical", "read")
            .justification("Need insurance verification")
            .build()
            .unwrap();

        assert!(matches!(request, AuthorizationRequest::Tier3Access { .. }));

        if let AuthorizationRequest::Tier3Access { payload, .. } = &request {
            assert_eq!(payload.requester.service_name, "TestService");
            assert_eq!(payload.compartment_label, "Medical Records");
            assert_eq!(payload.justification, "Need insurance verification");
            assert_eq!(payload.requested_scope.len(), 1);
            assert!(payload.available_actions.can_approve);
            assert!(payload.available_actions.can_deny);
            assert!(payload.available_actions.can_modify);
        }
    }

    #[test]
    fn test_tier3_builder_multiple_scopes() {
        let request = Tier3RequestBuilder::new("TestService", "test.com", "session-1")
            .compartment("Financial")
            .scope("vault.financial.tax", "read")
            .scope("vault.financial.income", "prove")
            .justification("Tax filing verification")
            .build()
            .unwrap();

        if let AuthorizationRequest::Tier3Access { payload, .. } = &request {
            assert_eq!(payload.requested_scope.len(), 2);
        }
    }

    #[test]
    fn test_tier3_builder_custom_timeout() {
        let request = Tier3RequestBuilder::new("TestService", "test.com", "session-1")
            .compartment("Medical")
            .scope("vault.medical", "read")
            .justification("Test")
            .timeout(60)
            .build()
            .unwrap();

        let now = Timestamp::now();
        if let AuthorizationRequest::Tier3Access { payload, .. } = &request {
            let diff = payload.expires_at.seconds_since_epoch - now.seconds_since_epoch;
            assert!(diff <= 61 && diff >= 59); // allow 1 second of test execution time
        }
    }

    #[test]
    fn test_tier3_builder_no_modify() {
        let request = Tier3RequestBuilder::new("TestService", "test.com", "session-1")
            .compartment("Financial")
            .scope("vault.financial", "read")
            .justification("Test")
            .allow_modify(false)
            .build()
            .unwrap();

        if let AuthorizationRequest::Tier3Access { payload, .. } = &request {
            assert!(!payload.available_actions.can_modify);
        }
    }

    #[test]
    fn test_tier3_builder_with_suggested_scope() {
        let suggested = ScopeSet::new(vec![ScopeEntry::new("vault.medical", "read")]).unwrap();

        let request = Tier3RequestBuilder::new("TestService", "test.com", "session-1")
            .compartment("Medical")
            .scope("vault.medical", "read")
            .scope("vault.medical", "write")
            .justification("Test")
            .suggest_scope(suggested)
            .build()
            .unwrap();

        if let AuthorizationRequest::Tier3Access { payload, .. } = &request {
            assert!(payload.available_actions.suggested_scope.is_some());
        }
    }

    #[test]
    fn test_tier3_builder_empty_scope_fails() {
        let result = Tier3RequestBuilder::new("TestService", "test.com", "session-1")
            .compartment("Medical")
            .justification("Test")
            .build();

        assert_eq!(result.unwrap_err(), NotifyError::ConfigurationError);
    }

    #[test]
    fn test_tier3_builder_empty_justification_fails() {
        let result = Tier3RequestBuilder::new("TestService", "test.com", "session-1")
            .compartment("Medical")
            .scope("vault.medical", "read")
            .build();

        assert_eq!(result.unwrap_err(), NotifyError::ConfigurationError);
    }

    #[test]
    fn test_tier3_builder_empty_compartment_fails() {
        let result = Tier3RequestBuilder::new("TestService", "test.com", "session-1")
            .scope("vault.medical", "read")
            .justification("Test")
            .build();

        assert_eq!(result.unwrap_err(), NotifyError::ConfigurationError);
    }

    #[test]
    fn test_anomaly_builder_basic() {
        let request =
            AnomalyRequestBuilder::new("SuspiciousService", "suspicious.com", "session-2")
                .original_tier(1)
                .scope("vault.medical", "read")
                .anomaly_type("role_mismatch")
                .severity(AnomalySeverity::High)
                .explanation("Commerce role asking for medical data")
                .evidence("Role: Commerce, Data: Medical")
                .policy_rule("rule-42")
                .build()
                .unwrap();

        assert!(matches!(
            request,
            AuthorizationRequest::AnomalyEscalation { .. }
        ));

        if let AuthorizationRequest::AnomalyEscalation { payload, .. } = &request {
            assert_eq!(payload.original_tier, 1);
            assert_eq!(payload.anomaly_context.anomaly_type, "role_mismatch");
            assert_eq!(payload.anomaly_context.severity, AnomalySeverity::High);
            assert_eq!(
                payload.anomaly_context.explanation,
                "Commerce role asking for medical data"
            );
        }
    }

    #[test]
    fn test_anomaly_builder_tier2() {
        let request = AnomalyRequestBuilder::new("Service", "service.com", "session-1")
            .original_tier(2)
            .scope("vault.preferences", "read")
            .anomaly_type("frequency_spike")
            .severity(AnomalySeverity::Medium)
            .explanation("Unusual request frequency")
            .evidence("50 requests in 1 minute")
            .policy_rule("rule-99")
            .build()
            .unwrap();

        if let AuthorizationRequest::AnomalyEscalation { payload, .. } = &request {
            assert_eq!(payload.original_tier, 2);
        }
    }

    #[test]
    fn test_anomaly_builder_invalid_tier() {
        let result = AnomalyRequestBuilder::new("Service", "service.com", "session-1")
            .original_tier(3) // Invalid: tier 3 always requires explicit auth
            .scope("vault.medical", "read")
            .anomaly_type("test")
            .explanation("test")
            .build();

        assert_eq!(result.unwrap_err(), NotifyError::ConfigurationError);
    }

    #[test]
    fn test_anomaly_builder_empty_scope_fails() {
        let result = AnomalyRequestBuilder::new("Service", "service.com", "session-1")
            .anomaly_type("test")
            .explanation("test")
            .build();

        assert_eq!(result.unwrap_err(), NotifyError::ConfigurationError);
    }

    #[test]
    fn test_anomaly_builder_empty_explanation_fails() {
        let result = AnomalyRequestBuilder::new("Service", "service.com", "session-1")
            .scope("vault.medical", "read")
            .anomaly_type("test")
            .build();

        assert_eq!(result.unwrap_err(), NotifyError::ConfigurationError);
    }

    #[test]
    fn test_anomaly_builder_empty_anomaly_type_fails() {
        let result = AnomalyRequestBuilder::new("Service", "service.com", "session-1")
            .scope("vault.medical", "read")
            .explanation("test")
            .build();

        assert_eq!(result.unwrap_err(), NotifyError::ConfigurationError);
    }

    #[test]
    fn test_decision_summary_approved() {
        let decision = AuthorizationDecision::Approved {
            challenge_id: ChallengeId::generate(),
            event_id: EventId::generate(),
            decided_at: Timestamp::now(),
        };
        let summary = decision_summary(&decision);
        assert!(summary.starts_with("APPROVED"));
    }

    #[test]
    fn test_decision_summary_denied() {
        let decision = AuthorizationDecision::Denied {
            challenge_id: ChallengeId::generate(),
            event_id: EventId::generate(),
            decided_at: Timestamp::now(),
            denial_reason: DenialReason::Timeout,
            denial_message: None,
        };
        let summary = decision_summary(&decision);
        assert!(summary.starts_with("DENIED"));
        assert!(summary.contains("Timeout"));
    }

    #[test]
    fn test_decision_summary_modified() {
        let scope = ScopeSet::new(vec![ScopeEntry::new("vault.medical", "read")]).unwrap();
        let decision = AuthorizationDecision::Modified {
            challenge_id: ChallengeId::generate(),
            event_id: EventId::generate(),
            decided_at: Timestamp::now(),
            adjusted_scope: scope,
        };
        let summary = decision_summary(&decision);
        assert!(summary.starts_with("MODIFIED"));
        assert!(summary.contains("scope_entries=1"));
    }

    #[test]
    fn test_is_timeout_denial() {
        let timeout_decision = AuthorizationDecision::Denied {
            challenge_id: ChallengeId::generate(),
            event_id: EventId::generate(),
            decided_at: Timestamp::now(),
            denial_reason: DenialReason::Timeout,
            denial_message: None,
        };
        assert!(is_timeout_denial(&timeout_decision));

        let explicit_denial = AuthorizationDecision::Denied {
            challenge_id: ChallengeId::generate(),
            event_id: EventId::generate(),
            decided_at: Timestamp::now(),
            denial_reason: DenialReason::ExplicitDeny,
            denial_message: Some("No".to_string()),
        };
        assert!(!is_timeout_denial(&explicit_denial));

        let approved = AuthorizationDecision::Approved {
            challenge_id: ChallengeId::generate(),
            event_id: EventId::generate(),
            decided_at: Timestamp::now(),
        };
        assert!(!is_timeout_denial(&approved));
    }

    #[test]
    fn test_is_delivery_failure() {
        let failure = AuthorizationDecision::Denied {
            challenge_id: ChallengeId::generate(),
            event_id: EventId::generate(),
            decided_at: Timestamp::now(),
            denial_reason: DenialReason::DeliveryFailure,
            denial_message: None,
        };
        assert!(is_delivery_failure(&failure));

        let timeout = AuthorizationDecision::Denied {
            challenge_id: ChallengeId::generate(),
            event_id: EventId::generate(),
            decided_at: Timestamp::now(),
            denial_reason: DenialReason::Timeout,
            denial_message: None,
        };
        assert!(!is_delivery_failure(&timeout));
    }

    #[test]
    fn test_request_accessors() {
        let request = Tier3RequestBuilder::new("TestService", "test.com", "session-1")
            .compartment("Medical")
            .scope("vault.medical", "read")
            .justification("Test")
            .build()
            .unwrap();

        // Test the AuthorizationRequest accessor methods
        assert!(!request.event_id().as_str().is_empty());
        assert!(!request.challenge_id().as_str().is_empty());
        assert_eq!(request.requested_scope().len(), 1);
        assert!(request.expires_at().seconds_since_epoch > Timestamp::now().seconds_since_epoch);
    }

    #[test]
    fn test_anomaly_request_accessors() {
        let request = AnomalyRequestBuilder::new("Service", "service.com", "session-1")
            .original_tier(1)
            .scope("vault.medical", "read")
            .anomaly_type("role_mismatch")
            .explanation("Test anomaly")
            .build()
            .unwrap();

        assert!(!request.event_id().as_str().is_empty());
        assert!(!request.challenge_id().as_str().is_empty());
        assert_eq!(request.requested_scope().len(), 1);
    }

    #[test]
    fn test_unique_ids_per_build() {
        let req1 = Tier3RequestBuilder::new("Service", "s.com", "s-1")
            .compartment("Test")
            .scope("vault.test", "read")
            .justification("Test")
            .build()
            .unwrap();

        let req2 = Tier3RequestBuilder::new("Service", "s.com", "s-1")
            .compartment("Test")
            .scope("vault.test", "read")
            .justification("Test")
            .build()
            .unwrap();

        assert_ne!(req1.event_id(), req2.event_id());
        assert_ne!(req1.challenge_id(), req2.challenge_id());
    }
}
