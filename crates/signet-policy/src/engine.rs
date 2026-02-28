use std::sync::Mutex;

use signet_core::{DenyReason, PolicyVersion, Timestamp};

use crate::actor::detect_role_predicate_mismatch;
use crate::error::{PolicyError, PolicyResult};
use crate::predicate::required_tier_for_predicate;
use crate::rule::{combine_deny_overrides, evaluate_rule, validate_policy_set};
use crate::types::{
    AnomalyDecision, AnomalyReport, Decision, DenyDecision, EvaluationRequest, PermitDecision,
    PolicyAuditEvent, PolicyAuditEventKind, PolicySet, PolicySnapshot, Provenance, TimeoutConfig,
};

// ---------------------------------------------------------------------------
// AuditSink trait — policy-specific audit event emission
// ---------------------------------------------------------------------------

/// Trait for emitting policy audit events.
///
/// All audit events must be durably recorded before the triggering
/// operation returns (write-ahead guarantee).
pub trait AuditSink: Send + Sync {
    fn emit(&self, event: &PolicyAuditEvent) -> Result<(), String>;
}

/// In-memory audit sink for testing.
#[derive(Default)]
pub struct InMemoryAuditSink {
    events: Mutex<Vec<PolicyAuditEvent>>,
}

impl InMemoryAuditSink {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    pub fn events(&self) -> Vec<PolicyAuditEvent> {
        self.events
            .lock()
            .expect("audit sink lock poisoned")
            .clone()
    }

    pub fn clear(&self) {
        self.events
            .lock()
            .expect("audit sink lock poisoned")
            .clear();
    }
}

impl AuditSink for InMemoryAuditSink {
    fn emit(&self, event: &PolicyAuditEvent) -> Result<(), String> {
        self.events
            .lock()
            .map_err(|_| "audit sink lock poisoned".to_string())?
            .push(event.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PolicyEngine — the main evaluation engine
// ---------------------------------------------------------------------------

/// Policy evaluation engine.
///
/// Evaluates data requests as Actor + Predicate + Context = Decision.
/// Produces a three-way decision: PERMIT, DENY, or ANOMALY.
pub struct PolicyEngine<'a> {
    audit_sink: &'a dyn AuditSink,
}

impl<'a> PolicyEngine<'a> {
    pub fn new(audit_sink: &'a dyn AuditSink) -> Self {
        Self { audit_sink }
    }

    /// Core policy evaluation: Actor + Predicate + Context = Decision.
    ///
    /// Takes a PolicySnapshot for TOCTOU safety and an EvaluationRequest,
    /// applies deny-overrides combining over all matching rules, and returns
    /// a three-way Decision (Permit/Deny/Anomaly).
    ///
    /// If the evaluation pipeline exceeds the configured timeout, returns
    /// Decision::Deny with DenyReason::Timeout.
    pub fn evaluate(
        &self,
        snapshot: &PolicySnapshot,
        request: &EvaluationRequest,
        timeout_config: &TimeoutConfig,
    ) -> PolicyResult<Decision> {
        let start = std::time::Instant::now();

        // Validate request
        self.validate_request(request)?;

        // Validate snapshot freshness (5 minutes max age)
        let now = Timestamp::now();
        let snapshot_age_secs = now
            .seconds_since_epoch
            .saturating_sub(snapshot.snapshot_taken_at.seconds_since_epoch);
        if snapshot_age_secs > 300 {
            return Err(PolicyError::SnapshotStale);
        }

        // Validate the request classification matches the actor
        if request.actor_classification.actor_id.as_str() != request.actor_id.as_str() {
            return Err(PolicyError::InvalidRequest(
                "actor classification does not match requesting actor".to_string(),
            ));
        }

        // Check context expiration (request timestamp not too old: 5 min)
        let request_age = now
            .seconds_since_epoch
            .saturating_sub(request.context.request_timestamp.seconds_since_epoch);
        if request_age > 300 {
            let decision = Decision::Deny(DenyDecision {
                reason: DenyReason::ExpiredContext,
                policy_version: snapshot.policy_set.version,
            });
            self.emit_evaluation_audit(request, &decision, &snapshot.policy_set.version)?;
            return Ok(decision);
        }

        // Check for future timestamps (30 second clock skew tolerance)
        let future_cutoff_secs = now.seconds_since_epoch + 30;
        if request.context.request_timestamp.seconds_since_epoch > future_cutoff_secs {
            return Err(PolicyError::InvalidRequest(
                "request timestamp is in the future".to_string(),
            ));
        }

        // Check for role/predicate mismatch -> anomaly
        let required_tier =
            required_tier_for_predicate(&request.predicate_id, &snapshot.policy_set.rules);
        let actor_tier = request.actor_classification.tier;

        if detect_role_predicate_mismatch(actor_tier, required_tier) {
            let decision = Decision::Anomaly(AnomalyDecision {
                report: AnomalyReport {
                    who: request.actor_id.clone(),
                    what: request.predicate_id.clone(),
                    why_unusual: format!(
                        "Actor classified as {} is requesting data requiring {} tier. \
                         This doesn't match their role classification.",
                        actor_tier, required_tier
                    ),
                    options: crate::rule::default_anomaly_options(),
                    anomaly_factors: vec![
                        "role_predicate_mismatch".to_string(),
                        format!("actor_tier={}", actor_tier),
                        format!("required_tier={}", required_tier),
                    ],
                    request_context: request.context.clone(),
                    detected_at: now,
                },
            });

            // Emit both evaluation and anomaly escalated events
            self.emit_evaluation_audit(request, &decision, &snapshot.policy_set.version)?;
            self.emit_anomaly_escalated_audit(request, &now)?;

            return Ok(decision);
        }

        // Check timeout before rule evaluation
        let elapsed = start.elapsed().as_millis() as u64;
        if elapsed >= timeout_config.evaluation_timeout_ms {
            let decision = Decision::Deny(DenyDecision {
                reason: DenyReason::Timeout,
                policy_version: snapshot.policy_set.version,
            });
            self.emit_evaluation_audit(request, &decision, &snapshot.policy_set.version)?;
            return Ok(decision);
        }

        // Evaluate all rules
        let mut effects = Vec::with_capacity(snapshot.policy_set.rules.len());
        for rule in &snapshot.policy_set.rules {
            let effect = evaluate_rule(
                rule,
                &request.actor_id,
                actor_tier,
                &request.predicate_id,
                &request.context.domain_id,
                &request.context.request_timestamp,
            );
            effects.push(effect);

            // Check timeout during rule evaluation
            let elapsed = start.elapsed().as_millis() as u64;
            if elapsed >= timeout_config.evaluation_timeout_ms {
                let decision = Decision::Deny(DenyDecision {
                    reason: DenyReason::Timeout,
                    policy_version: snapshot.policy_set.version,
                });
                self.emit_evaluation_audit(request, &decision, &snapshot.policy_set.version)?;
                return Ok(decision);
            }
        }

        // Combine with deny-overrides
        let decision = combine_deny_overrides(
            &effects,
            snapshot.policy_set.version,
            now,
            &request.actor_id,
            &request.predicate_id,
            &request.context,
        );

        // Emit audit events
        self.emit_evaluation_audit(request, &decision, &snapshot.policy_set.version)?;
        if matches!(decision, Decision::Anomaly(_)) {
            self.emit_anomaly_escalated_audit(request, &now)?;
        }

        Ok(decision)
    }

    /// Create an immutable PolicySnapshot from the current PolicySet.
    pub fn take_snapshot(
        policy_set: &PolicySet,
        snapshot_time: Timestamp,
    ) -> PolicyResult<PolicySnapshot> {
        if let Err(errors) = validate_policy_set(policy_set) {
            return Err(PolicyError::ValidationError(errors.join("; ")));
        }
        Ok(PolicySnapshot {
            policy_set: policy_set.clone(),
            snapshot_taken_at: snapshot_time,
        })
    }

    /// Load a PolicySet from raw JSON bytes.
    pub fn load_policies(policy_data: &[u8]) -> PolicyResult<PolicySet> {
        if policy_data.is_empty() {
            return Err(PolicyError::LoadError("policy data is empty".to_string()));
        }
        if policy_data.len() > 10 * 1024 * 1024 {
            return Err(PolicyError::LoadError(
                "policy data exceeds 10MB size limit".to_string(),
            ));
        }

        let json_str = std::str::from_utf8(policy_data)
            .map_err(|_| PolicyError::LoadError("policy data is not valid UTF-8".to_string()))?;

        let policy_set: PolicySet = serde_json::from_str(json_str)
            .map_err(|e| PolicyError::DeserializationError(format!("JSON parse error: {}", e)))?;

        if let Err(errors) = validate_policy_set(&policy_set) {
            return Err(PolicyError::ValidationError(errors.join("; ")));
        }

        Ok(policy_set)
    }

    /// Serialize a PolicySet to JSON bytes for storage.
    pub fn save_policies(
        policy_set: &PolicySet,
        audit_sink: &dyn AuditSink,
    ) -> PolicyResult<Vec<u8>> {
        if let Err(errors) = validate_policy_set(policy_set) {
            return Err(PolicyError::ValidationError(errors.join("; ")));
        }

        let json = serde_json::to_vec_pretty(policy_set)
            .map_err(|e| PolicyError::SerializationError(format!("JSON serialize error: {}", e)))?;

        // Emit audit event
        let audit_event = PolicyAuditEvent {
            event_kind: PolicyAuditEventKind::PolicySetUpdated,
            timestamp: Timestamp::now(),
            actor_id: None,
            predicate_id: None,
            domain_id: None,
            decision_summary: Some(format!(
                "policy set version {} saved ({} rules)",
                policy_set.version.0,
                policy_set.rules.len()
            )),
            policy_version: Some(policy_set.version),
        };
        audit_sink.emit(&audit_event).map_err(|e| {
            PolicyError::AuditSinkError(format!("failed to emit save audit: {}", e))
        })?;

        Ok(json)
    }

    /// Resolve an anomaly decision.
    ///
    /// Takes the original AnomalyReport and the user's chosen option.
    /// Returns the final Decision (Permit or Deny) based on the chosen option.
    pub fn resolve_anomaly(
        &self,
        report: &AnomalyReport,
        chosen_option_id: &str,
        snapshot: &PolicySnapshot,
        resolved_at: Timestamp,
    ) -> PolicyResult<Decision> {
        // Find the chosen option
        let chosen = report
            .options
            .iter()
            .find(|o| o.option_id == chosen_option_id)
            .ok_or_else(|| {
                PolicyError::InvalidRequest(format!(
                    "option '{}' not found in anomaly report",
                    chosen_option_id
                ))
            })?;

        // Validate resolution timing
        if resolved_at < report.detected_at {
            return Err(PolicyError::ValidationError(
                "resolution cannot precede detection".to_string(),
            ));
        }

        let decision = match chosen.resulting_decision.as_str() {
            "permit" => Decision::Permit(PermitDecision {
                expires_at: Timestamp::from_seconds(resolved_at.seconds_since_epoch + 300),
                provenance: Provenance {
                    policy_version: snapshot.policy_set.version,
                    matching_rule_ids: vec![format!("anomaly-resolution:{}", chosen_option_id)],
                    evaluated_at: resolved_at,
                },
            }),
            "deny" => Decision::Deny(DenyDecision {
                reason: DenyReason::PolicyRuleDeny,
                policy_version: snapshot.policy_set.version,
            }),
            other => {
                return Err(PolicyError::InvalidRequest(format!(
                    "invalid resulting_decision: '{}'",
                    other
                )));
            }
        };

        // Emit audit event
        let audit_event = PolicyAuditEvent {
            event_kind: PolicyAuditEventKind::AnomalyResolved,
            timestamp: resolved_at,
            actor_id: Some(report.who.clone()),
            predicate_id: Some(report.what.clone()),
            domain_id: Some(report.request_context.domain_id.clone()),
            decision_summary: Some(format!(
                "anomaly resolved with option '{}': {}",
                chosen_option_id, chosen.resulting_decision
            )),
            policy_version: Some(snapshot.policy_set.version),
        };
        self.audit_sink.emit(&audit_event).map_err(|e| {
            PolicyError::AuditSinkError(format!("failed to emit resolution audit: {}", e))
        })?;

        Ok(decision)
    }

    /// Validate an EvaluationRequest.
    fn validate_request(&self, request: &EvaluationRequest) -> PolicyResult<()> {
        if request.actor_id.as_str().is_empty() {
            return Err(PolicyError::InvalidRequest(
                "actor_id must not be empty".to_string(),
            ));
        }
        if request.predicate_id.as_str().is_empty() {
            return Err(PolicyError::InvalidRequest(
                "predicate_id must not be empty".to_string(),
            ));
        }
        if request.context.domain_id.as_str().is_empty() {
            return Err(PolicyError::InvalidRequest(
                "domain_id must not be empty".to_string(),
            ));
        }
        Ok(())
    }

    /// Emit an EvaluationCompleted audit event.
    fn emit_evaluation_audit(
        &self,
        request: &EvaluationRequest,
        decision: &Decision,
        policy_version: &PolicyVersion,
    ) -> PolicyResult<()> {
        let summary = match decision {
            Decision::Permit(_) => "PERMIT".to_string(),
            Decision::Deny(d) => format!("DENY: {}", d.reason),
            Decision::Anomaly(_) => "ANOMALY".to_string(),
        };

        let audit_event = PolicyAuditEvent {
            event_kind: PolicyAuditEventKind::EvaluationCompleted,
            timestamp: Timestamp::now(),
            actor_id: Some(request.actor_id.clone()),
            predicate_id: Some(request.predicate_id.clone()),
            domain_id: Some(request.context.domain_id.clone()),
            decision_summary: Some(summary),
            policy_version: Some(*policy_version),
        };
        self.audit_sink.emit(&audit_event).map_err(|e| {
            PolicyError::AuditSinkError(format!("failed to emit evaluation audit: {}", e))
        })
    }

    /// Emit an AnomalyEscalated audit event.
    fn emit_anomaly_escalated_audit(
        &self,
        request: &EvaluationRequest,
        detected_at: &Timestamp,
    ) -> PolicyResult<()> {
        let audit_event = PolicyAuditEvent {
            event_kind: PolicyAuditEventKind::AnomalyEscalated,
            timestamp: *detected_at,
            actor_id: Some(request.actor_id.clone()),
            predicate_id: Some(request.predicate_id.clone()),
            domain_id: Some(request.context.domain_id.clone()),
            decision_summary: Some("anomaly escalated for user resolution".to_string()),
            policy_version: None,
        };
        self.audit_sink.emit(&audit_event).map_err(|e| {
            PolicyError::AuditSinkError(format!("failed to emit anomaly escalation audit: {}", e))
        })
    }
}

/// Validate a policy set (delegates to rule::validate_policy_set).
pub fn validate_policy_set_fn(policy_set: &PolicySet) -> PolicyResult<bool> {
    match validate_policy_set(policy_set) {
        Ok(()) => Ok(true),
        Err(errors) => Err(PolicyError::ValidationError(errors.join("; "))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use signet_core::{ActorId, ClassificationMethod, ConfidenceLevel, DomainId, PredicateId};
    use std::collections::HashMap;

    fn make_now() -> Timestamp {
        Timestamp::now()
    }

    fn make_policy_set() -> PolicySet {
        PolicySet {
            version: PolicyVersion::initial(),
            rules: vec![
                PolicyRule {
                    rule_id: "tier-public".to_string(),
                    kind: PolicyRuleKind::TierThreshold,
                    actor_pattern: "*".to_string(),
                    predicate_pattern: "user_exists".to_string(),
                    minimum_tier: SensitivityTier::Public,
                    domain_constraint: None,
                    valid_from: None,
                    valid_until: None,
                    priority: 0,
                    enabled: true,
                },
                PolicyRule {
                    rule_id: "tier-commerce".to_string(),
                    kind: PolicyRuleKind::TierThreshold,
                    actor_pattern: "*".to_string(),
                    predicate_pattern: "shipping_address".to_string(),
                    minimum_tier: SensitivityTier::Commerce,
                    domain_constraint: None,
                    valid_from: None,
                    valid_until: None,
                    priority: 0,
                    enabled: true,
                },
                PolicyRule {
                    rule_id: "tier-medical".to_string(),
                    kind: PolicyRuleKind::TierThreshold,
                    actor_pattern: "*".to_string(),
                    predicate_pattern: "health_data".to_string(),
                    minimum_tier: SensitivityTier::Medical,
                    domain_constraint: None,
                    valid_from: None,
                    valid_until: None,
                    priority: 0,
                    enabled: true,
                },
            ],
            created_at: make_now(),
            schema_version: 1,
        }
    }

    fn make_snapshot() -> PolicySnapshot {
        PolicySnapshot {
            policy_set: make_policy_set(),
            snapshot_taken_at: make_now(),
        }
    }

    fn make_classification(actor_id: &str, tier: SensitivityTier) -> ActorClassification {
        ActorClassification {
            actor_id: ActorId::new(actor_id),
            tier,
            method: ClassificationMethod::Explicit,
            confidence: ConfidenceLevel::High,
            evidence_count: 1,
            classified_at: make_now(),
        }
    }

    fn make_request(actor_id: &str, predicate: &str, tier: SensitivityTier) -> EvaluationRequest {
        let now = make_now();
        EvaluationRequest {
            actor_id: ActorId::new(actor_id),
            predicate_id: PredicateId::new(predicate),
            actor_classification: make_classification(actor_id, tier),
            context: RequestContext {
                domain_id: DomainId::new("example.com"),
                request_timestamp: now,
                metadata: HashMap::new(),
            },
        }
    }

    #[test]
    fn test_evaluate_permit() {
        let sink = InMemoryAuditSink::new();
        let engine = PolicyEngine::new(&sink);
        let snapshot = make_snapshot();
        let request = make_request("amazon", "shipping_address", SensitivityTier::Commerce);
        let timeout = TimeoutConfig::default();

        let decision = engine.evaluate(&snapshot, &request, &timeout).unwrap();
        assert!(matches!(decision, Decision::Permit(_)));

        if let Decision::Permit(p) = &decision {
            assert!(p.expires_at > Timestamp::now());
            assert_eq!(p.provenance.policy_version, PolicyVersion::initial());
        }
    }

    #[test]
    fn test_evaluate_deny_insufficient_tier() {
        let sink = InMemoryAuditSink::new();
        let engine = PolicyEngine::new(&sink);
        let snapshot = make_snapshot();
        let request = make_request("public-actor", "shipping_address", SensitivityTier::Public);
        let timeout = TimeoutConfig::default();

        let decision = engine.evaluate(&snapshot, &request, &timeout).unwrap();
        assert!(matches!(decision, Decision::Deny(_)));

        if let Decision::Deny(d) = &decision {
            assert_eq!(d.reason, DenyReason::InsufficientTier);
        }
    }

    #[test]
    fn test_evaluate_anomaly_role_mismatch() {
        let sink = InMemoryAuditSink::new();
        let engine = PolicyEngine::new(&sink);
        let snapshot = make_snapshot();
        // Commerce actor asking for Medical data -> anomaly
        let request = make_request("amazon", "health_data", SensitivityTier::Commerce);
        let timeout = TimeoutConfig::default();

        let decision = engine.evaluate(&snapshot, &request, &timeout).unwrap();
        assert!(matches!(decision, Decision::Anomaly(_)));

        if let Decision::Anomaly(a) = &decision {
            assert!(!a.report.options.is_empty());
            assert!(a.report.why_unusual.contains("Commerce"));
        }
    }

    #[test]
    fn test_evaluate_emits_audit_events() {
        let sink = InMemoryAuditSink::new();
        let engine = PolicyEngine::new(&sink);
        let snapshot = make_snapshot();
        let request = make_request("actor", "user_exists", SensitivityTier::Public);
        let timeout = TimeoutConfig::default();

        engine.evaluate(&snapshot, &request, &timeout).unwrap();

        let events = sink.events();
        assert!(events
            .iter()
            .any(|e| e.event_kind == PolicyAuditEventKind::EvaluationCompleted));
    }

    #[test]
    fn test_evaluate_anomaly_emits_escalation_audit() {
        let sink = InMemoryAuditSink::new();
        let engine = PolicyEngine::new(&sink);
        let snapshot = make_snapshot();
        let request = make_request("amazon", "health_data", SensitivityTier::Commerce);
        let timeout = TimeoutConfig::default();

        engine.evaluate(&snapshot, &request, &timeout).unwrap();

        let events = sink.events();
        assert!(events
            .iter()
            .any(|e| e.event_kind == PolicyAuditEventKind::AnomalyEscalated));
    }

    #[test]
    fn test_evaluate_invalid_request_empty_actor() {
        let sink = InMemoryAuditSink::new();
        let engine = PolicyEngine::new(&sink);
        let snapshot = make_snapshot();
        let now = make_now();
        let request = EvaluationRequest {
            actor_id: ActorId::new(""),
            predicate_id: PredicateId::new("test"),
            actor_classification: ActorClassification {
                actor_id: ActorId::new(""),
                tier: SensitivityTier::Public,
                method: ClassificationMethod::SelfDeclared,
                confidence: ConfidenceLevel::Low,
                evidence_count: 0,
                classified_at: now,
            },
            context: RequestContext {
                domain_id: DomainId::new("example.com"),
                request_timestamp: now,
                metadata: HashMap::new(),
            },
        };
        let timeout = TimeoutConfig::default();

        let result = engine.evaluate(&snapshot, &request, &timeout);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PolicyError::InvalidRequest(_)
        ));
    }

    #[test]
    fn test_evaluate_classification_mismatch() {
        let sink = InMemoryAuditSink::new();
        let engine = PolicyEngine::new(&sink);
        let snapshot = make_snapshot();
        let now = make_now();
        let request = EvaluationRequest {
            actor_id: ActorId::new("alice"),
            predicate_id: PredicateId::new("test"),
            actor_classification: ActorClassification {
                actor_id: ActorId::new("bob"), // Different from request.actor_id
                tier: SensitivityTier::Public,
                method: ClassificationMethod::Explicit,
                confidence: ConfidenceLevel::High,
                evidence_count: 1,
                classified_at: now,
            },
            context: RequestContext {
                domain_id: DomainId::new("example.com"),
                request_timestamp: now,
                metadata: HashMap::new(),
            },
        };
        let timeout = TimeoutConfig::default();

        let result = engine.evaluate(&snapshot, &request, &timeout);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PolicyError::InvalidRequest(_)
        ));
    }

    #[test]
    fn test_evaluate_stale_snapshot() {
        let sink = InMemoryAuditSink::new();
        let engine = PolicyEngine::new(&sink);
        let mut snapshot = make_snapshot();
        // Make snapshot 10 minutes old
        snapshot.snapshot_taken_at =
            Timestamp::from_seconds(Timestamp::now().seconds_since_epoch - 600);
        let request = make_request("actor", "test", SensitivityTier::Public);
        let timeout = TimeoutConfig::default();

        let result = engine.evaluate(&snapshot, &request, &timeout);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PolicyError::SnapshotStale));
    }

    #[test]
    fn test_evaluate_expired_context() {
        let sink = InMemoryAuditSink::new();
        let engine = PolicyEngine::new(&sink);
        let snapshot = make_snapshot();
        let mut request = make_request("actor", "user_exists", SensitivityTier::Public);
        // Make request timestamp 10 minutes old
        request.context.request_timestamp =
            Timestamp::from_seconds(Timestamp::now().seconds_since_epoch - 600);
        let timeout = TimeoutConfig::default();

        let decision = engine.evaluate(&snapshot, &request, &timeout).unwrap();
        assert!(matches!(decision, Decision::Deny(_)));
        if let Decision::Deny(d) = &decision {
            assert_eq!(d.reason, DenyReason::ExpiredContext);
        }
    }

    #[test]
    fn test_take_snapshot() {
        let policy_set = make_policy_set();
        let now = make_now();
        let snapshot = PolicyEngine::take_snapshot(&policy_set, now).unwrap();
        assert_eq!(snapshot.policy_set.version, policy_set.version);
        assert_eq!(snapshot.snapshot_taken_at, now);
    }

    #[test]
    fn test_take_snapshot_invalid_policy_set() {
        let policy_set = PolicySet {
            version: PolicyVersion::initial(),
            rules: vec![],
            created_at: make_now(),
            schema_version: 1,
        };
        let result = PolicyEngine::take_snapshot(&policy_set, make_now());
        assert!(result.is_err());
    }

    #[test]
    fn test_load_policies_valid() {
        let policy_set = make_policy_set();
        let json = serde_json::to_vec(&policy_set).unwrap();
        let loaded = PolicyEngine::load_policies(&json).unwrap();
        assert_eq!(loaded.version, policy_set.version);
        assert_eq!(loaded.rules.len(), policy_set.rules.len());
    }

    #[test]
    fn test_load_policies_empty() {
        let result = PolicyEngine::load_policies(&[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PolicyError::LoadError(_)));
    }

    #[test]
    fn test_load_policies_invalid_json() {
        let result = PolicyEngine::load_policies(b"not json");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PolicyError::DeserializationError(_)
        ));
    }

    #[test]
    fn test_load_policies_invalid_utf8() {
        let result = PolicyEngine::load_policies(&[0xFF, 0xFE]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PolicyError::LoadError(_)));
    }

    #[test]
    fn test_save_policies() {
        let sink = InMemoryAuditSink::new();
        let policy_set = make_policy_set();
        let json = PolicyEngine::save_policies(&policy_set, &sink).unwrap();
        assert!(!json.is_empty());

        // Verify roundtrip
        let loaded = PolicyEngine::load_policies(&json).unwrap();
        assert_eq!(loaded.version, policy_set.version);

        // Verify audit event
        let events = sink.events();
        assert!(events
            .iter()
            .any(|e| e.event_kind == PolicyAuditEventKind::PolicySetUpdated));
    }

    #[test]
    fn test_save_policies_invalid() {
        let sink = InMemoryAuditSink::new();
        let policy_set = PolicySet {
            version: PolicyVersion::initial(),
            rules: vec![],
            created_at: make_now(),
            schema_version: 1,
        };
        let result = PolicyEngine::save_policies(&policy_set, &sink);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_anomaly_permit() {
        let sink = InMemoryAuditSink::new();
        let engine = PolicyEngine::new(&sink);
        let snapshot = make_snapshot();
        let now = make_now();
        let report = AnomalyReport {
            who: ActorId::new("amazon"),
            what: PredicateId::new("health_data"),
            why_unusual: "role mismatch".to_string(),
            options: vec![
                AnomalyOption {
                    option_id: "grant_exception".to_string(),
                    label: "Grant".to_string(),
                    description: "Grant exception".to_string(),
                    resulting_decision: "permit".to_string(),
                },
                AnomalyOption {
                    option_id: "deny_once".to_string(),
                    label: "Deny".to_string(),
                    description: "Deny once".to_string(),
                    resulting_decision: "deny".to_string(),
                },
            ],
            anomaly_factors: vec!["role_mismatch".to_string()],
            request_context: RequestContext {
                domain_id: DomainId::new("amazon.com"),
                request_timestamp: now,
                metadata: HashMap::new(),
            },
            detected_at: now,
        };

        let decision = engine
            .resolve_anomaly(&report, "grant_exception", &snapshot, now)
            .unwrap();
        assert!(matches!(decision, Decision::Permit(_)));
    }

    #[test]
    fn test_resolve_anomaly_deny() {
        let sink = InMemoryAuditSink::new();
        let engine = PolicyEngine::new(&sink);
        let snapshot = make_snapshot();
        let now = make_now();
        let report = AnomalyReport {
            who: ActorId::new("amazon"),
            what: PredicateId::new("health_data"),
            why_unusual: "role mismatch".to_string(),
            options: vec![AnomalyOption {
                option_id: "deny_once".to_string(),
                label: "Deny".to_string(),
                description: "Deny once".to_string(),
                resulting_decision: "deny".to_string(),
            }],
            anomaly_factors: vec!["role_mismatch".to_string()],
            request_context: RequestContext {
                domain_id: DomainId::new("amazon.com"),
                request_timestamp: now,
                metadata: HashMap::new(),
            },
            detected_at: now,
        };

        let decision = engine
            .resolve_anomaly(&report, "deny_once", &snapshot, now)
            .unwrap();
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_resolve_anomaly_invalid_option() {
        let sink = InMemoryAuditSink::new();
        let engine = PolicyEngine::new(&sink);
        let snapshot = make_snapshot();
        let now = make_now();
        let report = AnomalyReport {
            who: ActorId::new("actor"),
            what: PredicateId::new("pred"),
            why_unusual: "test".to_string(),
            options: vec![AnomalyOption {
                option_id: "deny_once".to_string(),
                label: "Deny".to_string(),
                description: "Deny once".to_string(),
                resulting_decision: "deny".to_string(),
            }],
            anomaly_factors: vec![],
            request_context: RequestContext {
                domain_id: DomainId::new("example.com"),
                request_timestamp: now,
                metadata: HashMap::new(),
            },
            detected_at: now,
        };

        let result = engine.resolve_anomaly(&report, "nonexistent", &snapshot, now);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PolicyError::InvalidRequest(_)
        ));
    }

    #[test]
    fn test_resolve_anomaly_emits_audit() {
        let sink = InMemoryAuditSink::new();
        let engine = PolicyEngine::new(&sink);
        let snapshot = make_snapshot();
        let now = make_now();
        let report = AnomalyReport {
            who: ActorId::new("actor"),
            what: PredicateId::new("pred"),
            why_unusual: "test".to_string(),
            options: vec![AnomalyOption {
                option_id: "deny_once".to_string(),
                label: "Deny".to_string(),
                description: "Deny once".to_string(),
                resulting_decision: "deny".to_string(),
            }],
            anomaly_factors: vec![],
            request_context: RequestContext {
                domain_id: DomainId::new("example.com"),
                request_timestamp: now,
                metadata: HashMap::new(),
            },
            detected_at: now,
        };

        engine
            .resolve_anomaly(&report, "deny_once", &snapshot, now)
            .unwrap();

        let events = sink.events();
        assert!(events
            .iter()
            .any(|e| e.event_kind == PolicyAuditEventKind::AnomalyResolved));
    }

    #[test]
    fn test_resolve_anomaly_before_detection() {
        let sink = InMemoryAuditSink::new();
        let engine = PolicyEngine::new(&sink);
        let snapshot = make_snapshot();
        let now = make_now();
        let report = AnomalyReport {
            who: ActorId::new("actor"),
            what: PredicateId::new("pred"),
            why_unusual: "test".to_string(),
            options: vec![AnomalyOption {
                option_id: "deny_once".to_string(),
                label: "Deny".to_string(),
                description: "Deny once".to_string(),
                resulting_decision: "deny".to_string(),
            }],
            anomaly_factors: vec![],
            request_context: RequestContext {
                domain_id: DomainId::new("example.com"),
                request_timestamp: now,
                metadata: HashMap::new(),
            },
            detected_at: now,
        };

        // Try to resolve before detection (impossible)
        let earlier = Timestamp::from_seconds(now.seconds_since_epoch - 100);
        let result = engine.resolve_anomaly(&report, "deny_once", &snapshot, earlier);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PolicyError::ValidationError(_)
        ));
    }

    #[test]
    fn test_validate_policy_set_fn_valid() {
        let policy_set = make_policy_set();
        assert!(validate_policy_set_fn(&policy_set).unwrap());
    }

    #[test]
    fn test_validate_policy_set_fn_invalid() {
        let policy_set = PolicySet {
            version: PolicyVersion::initial(),
            rules: vec![],
            created_at: make_now(),
            schema_version: 1,
        };
        let result = validate_policy_set_fn(&policy_set);
        assert!(result.is_err());
    }

    #[test]
    fn test_in_memory_audit_sink() {
        let sink = InMemoryAuditSink::new();
        let event = PolicyAuditEvent {
            event_kind: PolicyAuditEventKind::EvaluationCompleted,
            timestamp: make_now(),
            actor_id: Some(ActorId::new("test")),
            predicate_id: None,
            domain_id: None,
            decision_summary: Some("test".to_string()),
            policy_version: None,
        };
        sink.emit(&event).unwrap();
        assert_eq!(sink.events().len(), 1);

        sink.clear();
        assert!(sink.events().is_empty());
    }

    #[test]
    fn test_evaluate_no_matching_rules_for_predicate() {
        let sink = InMemoryAuditSink::new();
        let engine = PolicyEngine::new(&sink);
        let snapshot = make_snapshot();
        // Use a predicate that has no matching rules
        let request = make_request("actor", "nonexistent_predicate", SensitivityTier::Public);
        let timeout = TimeoutConfig::default();

        let decision = engine.evaluate(&snapshot, &request, &timeout).unwrap();
        // Should get NoMatchingPermitRule since no rules match this predicate
        assert!(matches!(decision, Decision::Deny(_)));
        if let Decision::Deny(d) = &decision {
            assert_eq!(d.reason, DenyReason::NoMatchingPermitRule);
        }
    }

    #[test]
    fn test_evaluate_permit_has_correct_provenance() {
        let sink = InMemoryAuditSink::new();
        let engine = PolicyEngine::new(&sink);
        let snapshot = make_snapshot();
        let request = make_request("actor", "user_exists", SensitivityTier::Public);
        let timeout = TimeoutConfig::default();

        let decision = engine.evaluate(&snapshot, &request, &timeout).unwrap();
        if let Decision::Permit(p) = &decision {
            assert_eq!(p.provenance.policy_version, PolicyVersion::initial());
            assert!(!p.provenance.matching_rule_ids.is_empty());
        } else {
            panic!("expected Permit decision");
        }
    }
}
