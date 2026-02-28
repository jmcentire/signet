use serde::{Deserialize, Serialize};
use signet_core::{
    ActorId, ClassificationMethod, ConfidenceLevel, DenyReason, DomainId, PolicyVersion,
    PredicateId, Timestamp,
};
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// SensitivityTier — six-level sensitivity hierarchy
// ---------------------------------------------------------------------------

/// Six-level sensitivity hierarchy with manual Ord implementation.
/// Exhaustive (no #[non_exhaustive]) so new tiers force compile-time review
/// of all match sites.
///
/// Ordering: Public < Commerce < Financial < Medical < Identity < TrustedAgent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SensitivityTier {
    Public,
    Commerce,
    Financial,
    Medical,
    Identity,
    TrustedAgent,
}

impl SensitivityTier {
    /// Returns the numeric rank for ordering purposes.
    /// Public=1, Commerce=3, Financial=4, Medical=5, Identity=5, TrustedAgent=6
    pub fn rank(self) -> u8 {
        match self {
            SensitivityTier::Public => 1,
            SensitivityTier::Commerce => 3,
            SensitivityTier::Financial => 4,
            SensitivityTier::Medical => 5,
            SensitivityTier::Identity => 5,
            SensitivityTier::TrustedAgent => 6,
        }
    }

    /// Returns the ordinal position for strict total ordering.
    /// This is used for Ord, which establishes:
    /// Public < Commerce < Financial < Medical < Identity < TrustedAgent
    fn ordinal(self) -> u8 {
        match self {
            SensitivityTier::Public => 0,
            SensitivityTier::Commerce => 1,
            SensitivityTier::Financial => 2,
            SensitivityTier::Medical => 3,
            SensitivityTier::Identity => 4,
            SensitivityTier::TrustedAgent => 5,
        }
    }
}

impl PartialOrd for SensitivityTier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SensitivityTier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ordinal().cmp(&other.ordinal())
    }
}

impl fmt::Display for SensitivityTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SensitivityTier::Public => write!(f, "Public"),
            SensitivityTier::Commerce => write!(f, "Commerce"),
            SensitivityTier::Financial => write!(f, "Financial"),
            SensitivityTier::Medical => write!(f, "Medical"),
            SensitivityTier::Identity => write!(f, "Identity"),
            SensitivityTier::TrustedAgent => write!(f, "TrustedAgent"),
        }
    }
}

/// Compare two SensitivityTier values.
/// Returns -1 if left < right, 0 if equal, 1 if left > right.
pub fn compare_tiers(left: SensitivityTier, right: SensitivityTier) -> i8 {
    match left.cmp(&right) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

// ---------------------------------------------------------------------------
// ClassificationEvidence — a single piece of evidence for actor classification
// ---------------------------------------------------------------------------

/// A single piece of evidence used to classify an actor.
/// Combines the method of classification with supporting data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationEvidence {
    pub method: ClassificationMethod,
    pub tier_claim: SensitivityTier,
    pub evidence_ref: String,
    pub obtained_at: Timestamp,
}

// ---------------------------------------------------------------------------
// ActorClassification — the result of classifying an actor
// ---------------------------------------------------------------------------

/// The result of classifying an actor: their determined sensitivity tier,
/// the method used, confidence level, and all evidence considered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorClassification {
    pub actor_id: ActorId,
    pub tier: SensitivityTier,
    pub method: ClassificationMethod,
    pub confidence: ConfidenceLevel,
    pub evidence_count: usize,
    pub classified_at: Timestamp,
}

// ---------------------------------------------------------------------------
// RequestContext — contextual information for an evaluation request
// ---------------------------------------------------------------------------

/// Contextual information accompanying an evaluation request:
/// domain binding, timestamp, and optional metadata key-value pairs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    pub domain_id: DomainId,
    pub request_timestamp: Timestamp,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// EvaluationRequest — a complete policy evaluation request
// ---------------------------------------------------------------------------

/// A complete policy evaluation request: who (actor) wants what (predicate)
/// in what context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationRequest {
    pub actor_id: ActorId,
    pub predicate_id: PredicateId,
    pub actor_classification: ActorClassification,
    pub context: RequestContext,
}

// ---------------------------------------------------------------------------
// Decision types
// ---------------------------------------------------------------------------

/// Three-way evaluation output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Decision {
    Permit(PermitDecision),
    Deny(DenyDecision),
    Anomaly(AnomalyDecision),
}

/// Payload for a PERMIT decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermitDecision {
    pub expires_at: Timestamp,
    pub provenance: Provenance,
}

/// Traceability record linking a PERMIT decision back to the specific
/// policy rules and version that authorized it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    pub policy_version: PolicyVersion,
    pub matching_rule_ids: Vec<String>,
    pub evaluated_at: Timestamp,
}

/// Payload for a DENY decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenyDecision {
    pub reason: DenyReason,
    pub policy_version: PolicyVersion,
}

/// Payload for an ANOMALY decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDecision {
    pub report: AnomalyReport,
}

// ---------------------------------------------------------------------------
// AnomalyReport — structured escalation payload
// ---------------------------------------------------------------------------

/// Structured escalation payload for ANOMALY decisions.
/// Contains who, what, why unusual, and available options.
/// Must never be silently resolved -- requires explicit user action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyReport {
    pub who: ActorId,
    pub what: PredicateId,
    pub why_unusual: String,
    pub options: Vec<AnomalyOption>,
    pub anomaly_factors: Vec<String>,
    pub request_context: RequestContext,
    pub detected_at: Timestamp,
}

/// A single resolution option for an ANOMALY decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyOption {
    pub option_id: String,
    pub label: String,
    pub description: String,
    /// Must be "permit" or "deny".
    pub resulting_decision: String,
}

// ---------------------------------------------------------------------------
// PolicyRule types
// ---------------------------------------------------------------------------

/// Discriminator for policy rule types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyRuleKind {
    TierThreshold,
    ExplicitGrant,
    ExplicitDeny,
    DomainRestriction,
    TimeWindow,
    AnomalyTrigger,
}

/// A single policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub rule_id: String,
    pub kind: PolicyRuleKind,
    pub actor_pattern: String,
    pub predicate_pattern: String,
    #[serde(default = "default_public_tier")]
    pub minimum_tier: SensitivityTier,
    #[serde(default)]
    pub domain_constraint: Option<String>,
    #[serde(default)]
    pub valid_from: Option<Timestamp>,
    #[serde(default)]
    pub valid_until: Option<Timestamp>,
    #[serde(default)]
    pub priority: i64,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_public_tier() -> SensitivityTier {
    SensitivityTier::Public
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// PolicySet — versioned collection of policy rules
// ---------------------------------------------------------------------------

/// Versioned collection of policy rules.
/// Serialized as JSON. Stored in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySet {
    pub version: PolicyVersion,
    pub rules: Vec<PolicyRule>,
    pub created_at: Timestamp,
    pub schema_version: u32,
}

// ---------------------------------------------------------------------------
// PolicySnapshot — immutable point-in-time snapshot
// ---------------------------------------------------------------------------

/// An immutable, point-in-time snapshot of a PolicySet used for
/// TOCTOU-safe evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySnapshot {
    pub policy_set: PolicySet,
    pub snapshot_taken_at: Timestamp,
}

// ---------------------------------------------------------------------------
// Pattern tracker types
// ---------------------------------------------------------------------------

/// The user's decision on an evaluated request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PatternDecision {
    Approved,
    Denied,
}

/// Records user approve/deny decisions for a specific actor+predicate pair.
/// MAC-protected to detect tampering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternRecord {
    pub actor_id: ActorId,
    pub predicate_id: PredicateId,
    pub approve_count: u64,
    pub deny_count: u64,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub mac: Vec<u8>,
}

/// Configuration for when the pattern tracker should generate suggestions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestionThresholds {
    pub min_occurrences: u64,
    pub approval_ratio_permit: u8,
    pub denial_ratio_deny: u8,
}

/// A suggested policy rule generated by the pattern tracker.
/// Suggest-only, never auto-applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySuggestion {
    pub suggested_rule: PolicyRule,
    pub based_on_record: PatternRecord,
    pub rationale: String,
    pub confidence: ConfidenceLevel,
}

// ---------------------------------------------------------------------------
// Audit types (policy-specific)
// ---------------------------------------------------------------------------

/// Types of auditable events emitted by the policy engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAuditEventKind {
    EvaluationCompleted,
    AnomalyEscalated,
    AnomalyResolved,
    PolicySetUpdated,
    PatternRecorded,
    SuggestionGenerated,
    ClassificationPerformed,
}

/// A structured audit event emitted to the audit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAuditEvent {
    pub event_kind: PolicyAuditEventKind,
    pub timestamp: Timestamp,
    pub actor_id: Option<ActorId>,
    pub predicate_id: Option<PredicateId>,
    pub domain_id: Option<DomainId>,
    pub decision_summary: Option<String>,
    pub policy_version: Option<PolicyVersion>,
}

// ---------------------------------------------------------------------------
// TimeoutConfig — fail-secure evaluation timeout
// ---------------------------------------------------------------------------

/// Configuration for the fail-secure evaluation timeout.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Maximum time in milliseconds for a complete evaluation pipeline.
    pub evaluation_timeout_ms: u64,
    /// Maximum time in milliseconds for actor classification.
    pub classification_timeout_ms: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            evaluation_timeout_ms: 5000,
            classification_timeout_ms: 2000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensitivity_tier_ordering() {
        assert!(SensitivityTier::Public < SensitivityTier::Commerce);
        assert!(SensitivityTier::Commerce < SensitivityTier::Financial);
        assert!(SensitivityTier::Financial < SensitivityTier::Medical);
        assert!(SensitivityTier::Medical < SensitivityTier::Identity);
        assert!(SensitivityTier::Identity < SensitivityTier::TrustedAgent);
        assert!(SensitivityTier::Public < SensitivityTier::TrustedAgent);
    }

    #[test]
    fn test_sensitivity_tier_equality() {
        assert_eq!(SensitivityTier::Public, SensitivityTier::Public);
        assert_ne!(SensitivityTier::Public, SensitivityTier::Commerce);
    }

    #[test]
    fn test_sensitivity_tier_ranks() {
        assert_eq!(SensitivityTier::Public.rank(), 1);
        assert_eq!(SensitivityTier::Commerce.rank(), 3);
        assert_eq!(SensitivityTier::Financial.rank(), 4);
        assert_eq!(SensitivityTier::Medical.rank(), 5);
        assert_eq!(SensitivityTier::Identity.rank(), 5);
        assert_eq!(SensitivityTier::TrustedAgent.rank(), 6);
    }

    #[test]
    fn test_compare_tiers() {
        assert_eq!(
            compare_tiers(SensitivityTier::Public, SensitivityTier::TrustedAgent),
            -1
        );
        assert_eq!(
            compare_tiers(SensitivityTier::TrustedAgent, SensitivityTier::Public),
            1
        );
        assert_eq!(
            compare_tiers(SensitivityTier::Financial, SensitivityTier::Financial),
            0
        );
    }

    #[test]
    fn test_compare_tiers_antisymmetry() {
        let tiers = [
            SensitivityTier::Public,
            SensitivityTier::Commerce,
            SensitivityTier::Financial,
            SensitivityTier::Medical,
            SensitivityTier::Identity,
            SensitivityTier::TrustedAgent,
        ];
        for a in &tiers {
            for b in &tiers {
                assert_eq!(
                    compare_tiers(*a, *b),
                    -compare_tiers(*b, *a),
                    "antisymmetry failed for {:?} and {:?}",
                    a,
                    b
                );
            }
        }
    }

    #[test]
    fn test_compare_tiers_reflexivity() {
        let tiers = [
            SensitivityTier::Public,
            SensitivityTier::Commerce,
            SensitivityTier::Financial,
            SensitivityTier::Medical,
            SensitivityTier::Identity,
            SensitivityTier::TrustedAgent,
        ];
        for t in &tiers {
            assert_eq!(compare_tiers(*t, *t), 0);
        }
    }

    #[test]
    fn test_compare_tiers_transitivity() {
        assert_eq!(
            compare_tiers(SensitivityTier::Public, SensitivityTier::Commerce),
            -1
        );
        assert_eq!(
            compare_tiers(SensitivityTier::Commerce, SensitivityTier::Financial),
            -1
        );
        assert_eq!(
            compare_tiers(SensitivityTier::Public, SensitivityTier::Financial),
            -1
        );
    }

    #[test]
    fn test_sensitivity_tier_display() {
        assert_eq!(SensitivityTier::Public.to_string(), "Public");
        assert_eq!(SensitivityTier::TrustedAgent.to_string(), "TrustedAgent");
    }

    #[test]
    fn test_sensitivity_tier_serde_roundtrip() {
        let tier = SensitivityTier::Financial;
        let json = serde_json::to_string(&tier).unwrap();
        let deserialized: SensitivityTier = serde_json::from_str(&json).unwrap();
        assert_eq!(tier, deserialized);
    }

    #[test]
    fn test_policy_rule_kind_serde() {
        let kind = PolicyRuleKind::TierThreshold;
        let json = serde_json::to_string(&kind).unwrap();
        let deserialized: PolicyRuleKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, deserialized);
    }

    #[test]
    fn test_pattern_decision_variants() {
        assert_ne!(PatternDecision::Approved, PatternDecision::Denied);
    }

    #[test]
    fn test_timeout_config_default() {
        let config = TimeoutConfig::default();
        assert_eq!(config.evaluation_timeout_ms, 5000);
        assert_eq!(config.classification_timeout_ms, 2000);
    }

    #[test]
    fn test_decision_variants() {
        let now = Timestamp::now();
        let permit = Decision::Permit(PermitDecision {
            expires_at: Timestamp::from_seconds(now.seconds_since_epoch + 300),
            provenance: Provenance {
                policy_version: PolicyVersion::initial(),
                matching_rule_ids: vec!["rule-1".to_string()],
                evaluated_at: now,
            },
        });
        let deny = Decision::Deny(DenyDecision {
            reason: DenyReason::InsufficientTier,
            policy_version: PolicyVersion::initial(),
        });
        let anomaly = Decision::Anomaly(AnomalyDecision {
            report: AnomalyReport {
                who: ActorId::new("test-actor"),
                what: PredicateId::new("test-predicate"),
                why_unusual: "role mismatch".to_string(),
                options: vec![AnomalyOption {
                    option_id: "deny-once".to_string(),
                    label: "Deny this request".to_string(),
                    description: "Deny access for this request only".to_string(),
                    resulting_decision: "deny".to_string(),
                }],
                anomaly_factors: vec!["role_mismatch".to_string()],
                request_context: RequestContext {
                    domain_id: DomainId::new("example.com"),
                    request_timestamp: now,
                    metadata: HashMap::new(),
                },
                detected_at: now,
            },
        });

        // Verify each variant matches
        assert!(matches!(permit, Decision::Permit(_)));
        assert!(matches!(deny, Decision::Deny(_)));
        assert!(matches!(anomaly, Decision::Anomaly(_)));
    }

    #[test]
    fn test_anomaly_option_resulting_decision() {
        let permit_option = AnomalyOption {
            option_id: "grant".to_string(),
            label: "Grant access".to_string(),
            description: "Grant this request".to_string(),
            resulting_decision: "permit".to_string(),
        };
        let deny_option = AnomalyOption {
            option_id: "deny".to_string(),
            label: "Deny access".to_string(),
            description: "Deny this request".to_string(),
            resulting_decision: "deny".to_string(),
        };
        assert_eq!(permit_option.resulting_decision, "permit");
        assert_eq!(deny_option.resulting_decision, "deny");
    }

    #[test]
    fn test_policy_set_serde_roundtrip() {
        let now = Timestamp::now();
        let policy_set = PolicySet {
            version: PolicyVersion::initial(),
            rules: vec![PolicyRule {
                rule_id: "rule-1".to_string(),
                kind: PolicyRuleKind::TierThreshold,
                actor_pattern: "*".to_string(),
                predicate_pattern: "*".to_string(),
                minimum_tier: SensitivityTier::Public,
                domain_constraint: None,
                valid_from: None,
                valid_until: None,
                priority: 0,
                enabled: true,
            }],
            created_at: now,
            schema_version: 1,
        };
        let json = serde_json::to_string(&policy_set).unwrap();
        let deserialized: PolicySet = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.version, policy_set.version);
        assert_eq!(deserialized.rules.len(), 1);
        assert_eq!(deserialized.schema_version, 1);
    }

    #[test]
    fn test_policy_audit_event_kind_variants() {
        let kinds = vec![
            PolicyAuditEventKind::EvaluationCompleted,
            PolicyAuditEventKind::AnomalyEscalated,
            PolicyAuditEventKind::AnomalyResolved,
            PolicyAuditEventKind::PolicySetUpdated,
            PolicyAuditEventKind::PatternRecorded,
            PolicyAuditEventKind::SuggestionGenerated,
            PolicyAuditEventKind::ClassificationPerformed,
        ];
        for kind in &kinds {
            let json = serde_json::to_string(kind).unwrap();
            let deserialized: PolicyAuditEventKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, deserialized);
        }
    }

    #[test]
    fn test_evaluation_request_construction() {
        let now = Timestamp::now();
        let request = EvaluationRequest {
            actor_id: ActorId::new("amazon"),
            predicate_id: PredicateId::new("shipping_address"),
            actor_classification: ActorClassification {
                actor_id: ActorId::new("amazon"),
                tier: SensitivityTier::Commerce,
                method: ClassificationMethod::Explicit,
                confidence: ConfidenceLevel::High,
                evidence_count: 1,
                classified_at: now,
            },
            context: RequestContext {
                domain_id: DomainId::new("amazon.com"),
                request_timestamp: now,
                metadata: HashMap::new(),
            },
        };
        assert_eq!(request.actor_id.as_str(), "amazon");
        assert_eq!(request.actor_classification.actor_id.as_str(), "amazon");
    }

    #[test]
    fn test_suggestion_thresholds() {
        let thresholds = SuggestionThresholds {
            min_occurrences: 5,
            approval_ratio_permit: 90,
            denial_ratio_deny: 90,
        };
        assert_eq!(thresholds.min_occurrences, 5);
        assert!(thresholds.approval_ratio_permit <= 100);
        assert!(thresholds.denial_ratio_deny <= 100);
    }
}
