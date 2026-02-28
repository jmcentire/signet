use signet_core::{ActorId, ClassificationMethod, ConfidenceLevel, Timestamp};

use crate::engine::AuditSink;
use crate::error::{PolicyError, PolicyResult};
use crate::types::{
    ActorClassification, ClassificationEvidence, PolicyAuditEvent, PolicyAuditEventKind,
    SensitivityTier,
};

/// Classify an actor's sensitivity tier based on provided evidence.
///
/// Examines all ClassificationEvidence items, applies confidence-weighted
/// tier determination, and returns an ActorClassification.
///
/// Uses the highest-confidence evidence; in case of tie, uses the most
/// restrictive (lowest) tier.
pub fn classify(
    actor_id: &ActorId,
    evidence: &[ClassificationEvidence],
    audit_sink: &dyn AuditSink,
) -> PolicyResult<ActorClassification> {
    if evidence.is_empty() {
        return Err(PolicyError::ClassificationError(
            "evidence list is empty".to_string(),
        ));
    }

    // Validate all evidence items
    let now = Timestamp::now();
    for ev in evidence {
        if ev.evidence_ref.is_empty() || ev.evidence_ref.len() > 1024 {
            return Err(PolicyError::ValidationError(
                "evidence reference must be between 1 and 1024 bytes".to_string(),
            ));
        }
        // Allow 30 seconds of clock skew
        let future_cutoff = Timestamp::from_seconds(now.seconds_since_epoch + 30);
        if ev.obtained_at > future_cutoff {
            return Err(PolicyError::ValidationError(
                "evidence timestamp is in the future".to_string(),
            ));
        }
    }

    // Determine confidence for each evidence method
    let best = select_best_evidence(evidence);

    let classification = ActorClassification {
        actor_id: actor_id.clone(),
        tier: best.tier_claim,
        method: best.method,
        confidence: method_confidence(best.method),
        evidence_count: evidence.len(),
        classified_at: Timestamp::now(),
    };

    // Emit audit event
    let audit_event = PolicyAuditEvent {
        event_kind: PolicyAuditEventKind::ClassificationPerformed,
        timestamp: classification.classified_at,
        actor_id: Some(actor_id.clone()),
        predicate_id: None,
        domain_id: None,
        decision_summary: Some(format!(
            "classified as {} via {:?} with confidence {:?}",
            classification.tier, classification.method, classification.confidence
        )),
        policy_version: None,
    };
    audit_sink.emit(&audit_event).map_err(|e| {
        PolicyError::AuditSinkError(format!("failed to emit classification audit: {}", e))
    })?;

    Ok(classification)
}

/// Returns the baseline confidence for a classification method.
fn method_confidence(method: ClassificationMethod) -> ConfidenceLevel {
    match method {
        ClassificationMethod::Explicit => ConfidenceLevel::Verified,
        ClassificationMethod::CredentialBased => ConfidenceLevel::High,
        ClassificationMethod::DomainInferred => ConfidenceLevel::Medium,
        ClassificationMethod::SelfDeclared => ConfidenceLevel::Low,
    }
}

/// Select the best evidence item from the list.
///
/// Priority: highest method confidence. On tie, most restrictive (lowest) tier.
fn select_best_evidence(evidence: &[ClassificationEvidence]) -> &ClassificationEvidence {
    evidence
        .iter()
        .reduce(|best, current| {
            let best_conf = method_confidence(best.method);
            let curr_conf = method_confidence(current.method);
            if curr_conf > best_conf {
                current
            } else if curr_conf == best_conf {
                // Same confidence: choose most restrictive (lowest) tier
                if current.tier_claim < best.tier_claim {
                    current
                } else {
                    best
                }
            } else {
                best
            }
        })
        .expect("evidence is non-empty, checked at call site")
}

/// Check whether an actor's tier is sufficient for a predicate's minimum tier.
pub fn is_tier_sufficient(actor_tier: SensitivityTier, required_tier: SensitivityTier) -> bool {
    actor_tier >= required_tier
}

/// Determine if a given actor-predicate pair represents a role/predicate mismatch.
///
/// A mismatch is when an actor classified for one domain (e.g., Commerce)
/// requests predicates belonging to a different, unrelated domain (e.g., Medical).
pub fn detect_role_predicate_mismatch(
    actor_tier: SensitivityTier,
    predicate_tier: SensitivityTier,
) -> bool {
    // If the predicate requires a higher tier than the actor has, it is a mismatch
    // that should result in anomaly, not deny.
    // Specifically: if the actor has a tier in one branch (e.g., Commerce)
    // and the predicate needs a tier in a separate branch (e.g., Medical),
    // treat it as anomaly.
    //
    // We model this as: mismatch when the required tier is higher but the
    // actor is not on the path toward it.
    if actor_tier >= predicate_tier {
        return false; // sufficient tier, no mismatch
    }

    // Check if the mismatch crosses "branches" in the hierarchy.
    // Commerce actors asking for Financial is a natural escalation.
    // Commerce actors asking for Medical or Identity is a branch crossing.
    match (actor_tier, predicate_tier) {
        // Natural escalation paths (not anomalies, just insufficient tier)
        (SensitivityTier::Public, _) => false,
        (SensitivityTier::Commerce, SensitivityTier::Financial) => false,
        // Branch crossings (anomalies)
        (SensitivityTier::Commerce, SensitivityTier::Medical) => true,
        (SensitivityTier::Commerce, SensitivityTier::Identity) => true,
        (SensitivityTier::Financial, SensitivityTier::Medical) => true,
        (SensitivityTier::Financial, SensitivityTier::Identity) => true,
        (SensitivityTier::Medical, SensitivityTier::Identity) => true,
        (SensitivityTier::Medical, SensitivityTier::Financial) => true,
        (SensitivityTier::Identity, SensitivityTier::Medical) => true,
        // Any actor asking for TrustedAgent when they are not is not a mismatch,
        // it is just insufficient tier
        (_, SensitivityTier::TrustedAgent) => false,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::InMemoryAuditSink;

    fn make_evidence(
        method: ClassificationMethod,
        tier: SensitivityTier,
        evidence_ref: &str,
    ) -> ClassificationEvidence {
        ClassificationEvidence {
            method,
            tier_claim: tier,
            evidence_ref: evidence_ref.to_string(),
            obtained_at: Timestamp::now(),
        }
    }

    #[test]
    fn test_classify_single_evidence() {
        let sink = InMemoryAuditSink::new();
        let actor_id = ActorId::new("amazon");
        let evidence = vec![make_evidence(
            ClassificationMethod::Explicit,
            SensitivityTier::Commerce,
            "credential-hash-abc",
        )];
        let result = classify(&actor_id, &evidence, &sink).unwrap();
        assert_eq!(result.actor_id.as_str(), "amazon");
        assert_eq!(result.tier, SensitivityTier::Commerce);
        assert_eq!(result.method, ClassificationMethod::Explicit);
        assert_eq!(result.confidence, ConfidenceLevel::Verified);
        assert_eq!(result.evidence_count, 1);
    }

    #[test]
    fn test_classify_multiple_evidence_picks_highest_confidence() {
        let sink = InMemoryAuditSink::new();
        let actor_id = ActorId::new("service-x");
        let evidence = vec![
            make_evidence(
                ClassificationMethod::SelfDeclared,
                SensitivityTier::Financial,
                "self-declared-ref",
            ),
            make_evidence(
                ClassificationMethod::CredentialBased,
                SensitivityTier::Commerce,
                "credential-ref",
            ),
        ];
        let result = classify(&actor_id, &evidence, &sink).unwrap();
        assert_eq!(result.tier, SensitivityTier::Commerce);
        assert_eq!(result.method, ClassificationMethod::CredentialBased);
        assert_eq!(result.confidence, ConfidenceLevel::High);
    }

    #[test]
    fn test_classify_same_confidence_picks_lowest_tier() {
        let sink = InMemoryAuditSink::new();
        let actor_id = ActorId::new("service-y");
        let evidence = vec![
            make_evidence(
                ClassificationMethod::DomainInferred,
                SensitivityTier::Financial,
                "domain-ref-1",
            ),
            make_evidence(
                ClassificationMethod::DomainInferred,
                SensitivityTier::Commerce,
                "domain-ref-2",
            ),
        ];
        let result = classify(&actor_id, &evidence, &sink).unwrap();
        // Same confidence (Medium for DomainInferred), should pick Commerce (lower tier)
        assert_eq!(result.tier, SensitivityTier::Commerce);
    }

    #[test]
    fn test_classify_empty_evidence_error() {
        let sink = InMemoryAuditSink::new();
        let actor_id = ActorId::new("nobody");
        let result = classify(&actor_id, &[], &sink);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PolicyError::ClassificationError(_)
        ));
    }

    #[test]
    fn test_classify_invalid_evidence_ref() {
        let sink = InMemoryAuditSink::new();
        let actor_id = ActorId::new("bad-actor");
        let evidence = vec![ClassificationEvidence {
            method: ClassificationMethod::Explicit,
            tier_claim: SensitivityTier::Commerce,
            evidence_ref: String::new(), // empty, invalid
            obtained_at: Timestamp::now(),
        }];
        let result = classify(&actor_id, &evidence, &sink);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PolicyError::ValidationError(_)
        ));
    }

    #[test]
    fn test_classify_emits_audit_event() {
        let sink = InMemoryAuditSink::new();
        let actor_id = ActorId::new("audited-actor");
        let evidence = vec![make_evidence(
            ClassificationMethod::Explicit,
            SensitivityTier::Public,
            "ref-1",
        )];
        let _ = classify(&actor_id, &evidence, &sink).unwrap();
        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_kind,
            PolicyAuditEventKind::ClassificationPerformed
        );
    }

    #[test]
    fn test_method_confidence_ordering() {
        assert_eq!(
            method_confidence(ClassificationMethod::Explicit),
            ConfidenceLevel::Verified
        );
        assert_eq!(
            method_confidence(ClassificationMethod::CredentialBased),
            ConfidenceLevel::High
        );
        assert_eq!(
            method_confidence(ClassificationMethod::DomainInferred),
            ConfidenceLevel::Medium
        );
        assert_eq!(
            method_confidence(ClassificationMethod::SelfDeclared),
            ConfidenceLevel::Low
        );
    }

    #[test]
    fn test_is_tier_sufficient() {
        assert!(is_tier_sufficient(
            SensitivityTier::Commerce,
            SensitivityTier::Public
        ));
        assert!(is_tier_sufficient(
            SensitivityTier::Commerce,
            SensitivityTier::Commerce
        ));
        assert!(!is_tier_sufficient(
            SensitivityTier::Public,
            SensitivityTier::Commerce
        ));
        assert!(is_tier_sufficient(
            SensitivityTier::TrustedAgent,
            SensitivityTier::Identity
        ));
    }

    #[test]
    fn test_detect_role_predicate_mismatch() {
        // Commerce asking for Medical => mismatch
        assert!(detect_role_predicate_mismatch(
            SensitivityTier::Commerce,
            SensitivityTier::Medical
        ));
        // Commerce asking for Identity => mismatch
        assert!(detect_role_predicate_mismatch(
            SensitivityTier::Commerce,
            SensitivityTier::Identity
        ));
        // Commerce asking for Financial => not mismatch (natural escalation)
        assert!(!detect_role_predicate_mismatch(
            SensitivityTier::Commerce,
            SensitivityTier::Financial
        ));
        // Financial asking for Medical => mismatch (branch cross)
        assert!(detect_role_predicate_mismatch(
            SensitivityTier::Financial,
            SensitivityTier::Medical
        ));
        // Sufficient tier => no mismatch
        assert!(!detect_role_predicate_mismatch(
            SensitivityTier::TrustedAgent,
            SensitivityTier::Commerce
        ));
        // Public asking for anything is not a mismatch, just insufficient
        assert!(!detect_role_predicate_mismatch(
            SensitivityTier::Public,
            SensitivityTier::Medical
        ));
    }

    #[test]
    fn test_classify_evidence_count_matches() {
        let sink = InMemoryAuditSink::new();
        let actor_id = ActorId::new("multi-evidence");
        let evidence = vec![
            make_evidence(
                ClassificationMethod::SelfDeclared,
                SensitivityTier::Commerce,
                "ref-a",
            ),
            make_evidence(
                ClassificationMethod::DomainInferred,
                SensitivityTier::Commerce,
                "ref-b",
            ),
            make_evidence(
                ClassificationMethod::Explicit,
                SensitivityTier::Commerce,
                "ref-c",
            ),
        ];
        let result = classify(&actor_id, &evidence, &sink).unwrap();
        assert_eq!(result.evidence_count, 3);
    }
}
