use signet_core::{ActorId, DenyReason, DomainId, PolicyVersion, PredicateId, Timestamp};

use crate::predicate::{pattern_matches_actor, pattern_matches_predicate};
use crate::types::{
    AnomalyDecision, AnomalyOption, AnomalyReport, Decision, DenyDecision, PermitDecision,
    PolicyRule, PolicyRuleKind, PolicySet, Provenance, RequestContext, SensitivityTier,
};

/// Result of evaluating a single rule against a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleEffect {
    /// This rule permits the request.
    Permit { rule_id: String },
    /// This rule denies the request.
    Deny { rule_id: String, reason: DenyReason },
    /// This rule triggers an anomaly.
    Anomaly { rule_id: String, reason: String },
    /// This rule does not apply to the request.
    NotApplicable,
}

/// Evaluate a single policy rule against the request parameters.
pub fn evaluate_rule(
    rule: &PolicyRule,
    actor_id: &ActorId,
    actor_tier: SensitivityTier,
    predicate_id: &PredicateId,
    domain_id: &DomainId,
    request_time: &Timestamp,
) -> RuleEffect {
    if !rule.enabled {
        return RuleEffect::NotApplicable;
    }

    // Check actor pattern match
    if !pattern_matches_actor(&rule.actor_pattern, actor_id, actor_tier) {
        return RuleEffect::NotApplicable;
    }

    // Check predicate pattern match
    if !pattern_matches_predicate(&rule.predicate_pattern, predicate_id) {
        return RuleEffect::NotApplicable;
    }

    // Check domain constraint
    if let Some(ref domain_constraint) = rule.domain_constraint {
        if !domain_constraint.is_empty() && domain_constraint != domain_id.as_str() {
            return RuleEffect::NotApplicable;
        }
    }

    // Check time window
    if let Some(ref valid_from) = rule.valid_from {
        if request_time < valid_from {
            return RuleEffect::NotApplicable;
        }
    }
    if let Some(ref valid_until) = rule.valid_until {
        if request_time > valid_until {
            return RuleEffect::NotApplicable;
        }
    }

    // Apply rule based on kind
    match rule.kind {
        PolicyRuleKind::TierThreshold => {
            if actor_tier >= rule.minimum_tier {
                RuleEffect::Permit {
                    rule_id: rule.rule_id.clone(),
                }
            } else {
                RuleEffect::Deny {
                    rule_id: rule.rule_id.clone(),
                    reason: DenyReason::InsufficientTier,
                }
            }
        }
        PolicyRuleKind::ExplicitGrant => RuleEffect::Permit {
            rule_id: rule.rule_id.clone(),
        },
        PolicyRuleKind::ExplicitDeny => RuleEffect::Deny {
            rule_id: rule.rule_id.clone(),
            reason: DenyReason::PolicyRuleDeny,
        },
        PolicyRuleKind::DomainRestriction => {
            // Domain restriction rules deny if domain doesn't match.
            // If we got here, the domain already matched in the constraint check above.
            // If there was no domain_constraint set, this rule denies (no domain specified).
            if rule.domain_constraint.is_some() {
                RuleEffect::Permit {
                    rule_id: rule.rule_id.clone(),
                }
            } else {
                RuleEffect::Deny {
                    rule_id: rule.rule_id.clone(),
                    reason: DenyReason::DomainMismatch,
                }
            }
        }
        PolicyRuleKind::TimeWindow => {
            // If we reached here, the time window check passed above.
            RuleEffect::Permit {
                rule_id: rule.rule_id.clone(),
            }
        }
        PolicyRuleKind::AnomalyTrigger => RuleEffect::Anomaly {
            rule_id: rule.rule_id.clone(),
            reason: format!(
                "Anomaly rule '{}' triggered for actor '{}' requesting '{}'",
                rule.rule_id,
                actor_id.as_str(),
                predicate_id.as_str()
            ),
        },
    }
}

/// Apply deny-overrides combining algorithm to a list of rule effects.
///
/// Deny-overrides: if any matching rule produces DENY, the result is DENY.
/// If any matching rule produces ANOMALY and there are no DENYs, the result is ANOMALY.
/// Otherwise, if there's at least one PERMIT, the result is PERMIT.
/// If no rules match, the result is DENY with NoMatchingPermitRule.
pub fn combine_deny_overrides(
    effects: &[RuleEffect],
    policy_version: PolicyVersion,
    request_time: Timestamp,
    actor_id: &ActorId,
    predicate_id: &PredicateId,
    context: &RequestContext,
) -> Decision {
    let mut has_permit = false;
    let mut permit_rule_ids: Vec<String> = Vec::new();
    let mut deny_reason: Option<DenyReason> = None;
    let mut anomaly_reasons: Vec<String> = Vec::new();
    let mut anomaly_rule_ids: Vec<String> = Vec::new();

    for effect in effects {
        match effect {
            RuleEffect::Deny { reason, .. } => {
                // Deny overrides everything
                deny_reason = Some(reason.clone());
                // In deny-overrides, we take the first deny reason
                break;
            }
            RuleEffect::Anomaly { rule_id, reason } => {
                anomaly_reasons.push(reason.clone());
                anomaly_rule_ids.push(rule_id.clone());
            }
            RuleEffect::Permit { rule_id } => {
                has_permit = true;
                permit_rule_ids.push(rule_id.clone());
            }
            RuleEffect::NotApplicable => {}
        }
    }

    // Deny overrides
    if let Some(reason) = deny_reason {
        return Decision::Deny(DenyDecision {
            reason,
            policy_version,
        });
    }

    // Anomaly takes precedence over permit
    if !anomaly_reasons.is_empty() {
        let why = anomaly_reasons.join("; ");
        return Decision::Anomaly(AnomalyDecision {
            report: AnomalyReport {
                who: actor_id.clone(),
                what: predicate_id.clone(),
                why_unusual: why,
                options: default_anomaly_options(),
                anomaly_factors: anomaly_reasons,
                request_context: context.clone(),
                detected_at: request_time,
            },
        });
    }

    // Permit if any rule matched
    if has_permit {
        return Decision::Permit(PermitDecision {
            expires_at: Timestamp::from_seconds(request_time.seconds_since_epoch + 300),
            provenance: Provenance {
                policy_version,
                matching_rule_ids: permit_rule_ids,
                evaluated_at: request_time,
            },
        });
    }

    // No matching rules at all
    Decision::Deny(DenyDecision {
        reason: DenyReason::NoMatchingPermitRule,
        policy_version,
    })
}

/// Generate the default anomaly options presented to the user.
pub fn default_anomaly_options() -> Vec<AnomalyOption> {
    vec![
        AnomalyOption {
            option_id: "deny_once".to_string(),
            label: "Deny this request".to_string(),
            description: "Deny access for this request only. The actor can ask again.".to_string(),
            resulting_decision: "deny".to_string(),
        },
        AnomalyOption {
            option_id: "deny_always".to_string(),
            label: "Deny always".to_string(),
            description: "Create a permanent deny rule for this actor+predicate pair.".to_string(),
            resulting_decision: "deny".to_string(),
        },
        AnomalyOption {
            option_id: "grant_exception".to_string(),
            label: "Grant exception".to_string(),
            description: "Allow this request as a one-time exception. Logged to audit chain."
                .to_string(),
            resulting_decision: "permit".to_string(),
        },
    ]
}

/// Validate a PolicySet for structural integrity.
///
/// Checks:
/// - Schema version is supported (currently only 1)
/// - Version is >= 1
/// - At least one rule exists
/// - All rule IDs are unique
/// - All rule IDs are non-empty and within length bounds
/// - Time windows are coherent (valid_from < valid_until where both are specified)
pub fn validate_policy_set(policy_set: &PolicySet) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    if policy_set.schema_version != 1 {
        errors.push(format!(
            "unsupported schema version: {} (only version 1 is supported)",
            policy_set.schema_version
        ));
    }

    if policy_set.version.0 < 1 {
        errors.push("policy version must be >= 1".to_string());
    }

    if policy_set.rules.is_empty() {
        errors.push("policy set must contain at least one rule".to_string());
    }

    let mut seen_ids = std::collections::HashSet::new();
    for rule in &policy_set.rules {
        if rule.rule_id.is_empty() {
            errors.push("rule ID must not be empty".to_string());
        } else if rule.rule_id.len() > 128 {
            errors.push(format!(
                "rule ID '{}...' exceeds 128 bytes",
                &rule.rule_id[..20]
            ));
        } else if !seen_ids.insert(&rule.rule_id) {
            errors.push(format!("duplicate rule ID: '{}'", rule.rule_id));
        }

        // Validate actor_pattern length
        if rule.actor_pattern.is_empty() || rule.actor_pattern.len() > 512 {
            errors.push(format!(
                "rule '{}': actor_pattern must be between 1 and 512 bytes",
                rule.rule_id
            ));
        }

        // Validate predicate_pattern length
        if rule.predicate_pattern.is_empty() || rule.predicate_pattern.len() > 512 {
            errors.push(format!(
                "rule '{}': predicate_pattern must be between 1 and 512 bytes",
                rule.rule_id
            ));
        }

        // Validate time windows
        if let (Some(from), Some(until)) = (&rule.valid_from, &rule.valid_until) {
            if from >= until {
                errors.push(format!(
                    "rule '{}': valid_from must be before valid_until",
                    rule.rule_id
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signet_core::{ActorId, DomainId, PredicateId, Timestamp};
    use std::collections::HashMap;

    fn make_actor() -> ActorId {
        ActorId::new("test-actor")
    }

    fn make_predicate() -> PredicateId {
        PredicateId::new("test-predicate")
    }

    fn make_domain() -> DomainId {
        DomainId::new("example.com")
    }

    fn make_time() -> Timestamp {
        Timestamp::from_seconds(1_700_000_000)
    }

    fn make_rule(kind: PolicyRuleKind, rule_id: &str) -> PolicyRule {
        PolicyRule {
            rule_id: rule_id.to_string(),
            kind,
            actor_pattern: "*".to_string(),
            predicate_pattern: "*".to_string(),
            minimum_tier: SensitivityTier::Public,
            domain_constraint: None,
            valid_from: None,
            valid_until: None,
            priority: 0,
            enabled: true,
        }
    }

    fn make_context() -> RequestContext {
        RequestContext {
            domain_id: make_domain(),
            request_timestamp: make_time(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_evaluate_rule_disabled() {
        let mut rule = make_rule(PolicyRuleKind::ExplicitGrant, "r1");
        rule.enabled = false;
        let effect = evaluate_rule(
            &rule,
            &make_actor(),
            SensitivityTier::Commerce,
            &make_predicate(),
            &make_domain(),
            &make_time(),
        );
        assert_eq!(effect, RuleEffect::NotApplicable);
    }

    #[test]
    fn test_evaluate_rule_actor_mismatch() {
        let mut rule = make_rule(PolicyRuleKind::ExplicitGrant, "r1");
        rule.actor_pattern = "other-actor".to_string();
        let effect = evaluate_rule(
            &rule,
            &make_actor(),
            SensitivityTier::Commerce,
            &make_predicate(),
            &make_domain(),
            &make_time(),
        );
        assert_eq!(effect, RuleEffect::NotApplicable);
    }

    #[test]
    fn test_evaluate_rule_predicate_mismatch() {
        let mut rule = make_rule(PolicyRuleKind::ExplicitGrant, "r1");
        rule.predicate_pattern = "other-predicate".to_string();
        let effect = evaluate_rule(
            &rule,
            &make_actor(),
            SensitivityTier::Commerce,
            &make_predicate(),
            &make_domain(),
            &make_time(),
        );
        assert_eq!(effect, RuleEffect::NotApplicable);
    }

    #[test]
    fn test_evaluate_rule_domain_mismatch() {
        let mut rule = make_rule(PolicyRuleKind::ExplicitGrant, "r1");
        rule.domain_constraint = Some("other-domain.com".to_string());
        let effect = evaluate_rule(
            &rule,
            &make_actor(),
            SensitivityTier::Commerce,
            &make_predicate(),
            &make_domain(),
            &make_time(),
        );
        assert_eq!(effect, RuleEffect::NotApplicable);
    }

    #[test]
    fn test_evaluate_rule_before_time_window() {
        let mut rule = make_rule(PolicyRuleKind::ExplicitGrant, "r1");
        rule.valid_from = Some(Timestamp::from_seconds(2_000_000_000));
        let effect = evaluate_rule(
            &rule,
            &make_actor(),
            SensitivityTier::Commerce,
            &make_predicate(),
            &make_domain(),
            &make_time(),
        );
        assert_eq!(effect, RuleEffect::NotApplicable);
    }

    #[test]
    fn test_evaluate_rule_after_time_window() {
        let mut rule = make_rule(PolicyRuleKind::ExplicitGrant, "r1");
        rule.valid_until = Some(Timestamp::from_seconds(1_000_000_000));
        let effect = evaluate_rule(
            &rule,
            &make_actor(),
            SensitivityTier::Commerce,
            &make_predicate(),
            &make_domain(),
            &make_time(),
        );
        assert_eq!(effect, RuleEffect::NotApplicable);
    }

    #[test]
    fn test_evaluate_rule_tier_threshold_sufficient() {
        let mut rule = make_rule(PolicyRuleKind::TierThreshold, "r1");
        rule.minimum_tier = SensitivityTier::Commerce;
        let effect = evaluate_rule(
            &rule,
            &make_actor(),
            SensitivityTier::Financial,
            &make_predicate(),
            &make_domain(),
            &make_time(),
        );
        assert_eq!(
            effect,
            RuleEffect::Permit {
                rule_id: "r1".to_string()
            }
        );
    }

    #[test]
    fn test_evaluate_rule_tier_threshold_insufficient() {
        let mut rule = make_rule(PolicyRuleKind::TierThreshold, "r1");
        rule.minimum_tier = SensitivityTier::Financial;
        let effect = evaluate_rule(
            &rule,
            &make_actor(),
            SensitivityTier::Commerce,
            &make_predicate(),
            &make_domain(),
            &make_time(),
        );
        assert_eq!(
            effect,
            RuleEffect::Deny {
                rule_id: "r1".to_string(),
                reason: DenyReason::InsufficientTier
            }
        );
    }

    #[test]
    fn test_evaluate_rule_explicit_grant() {
        let rule = make_rule(PolicyRuleKind::ExplicitGrant, "r1");
        let effect = evaluate_rule(
            &rule,
            &make_actor(),
            SensitivityTier::Commerce,
            &make_predicate(),
            &make_domain(),
            &make_time(),
        );
        assert_eq!(
            effect,
            RuleEffect::Permit {
                rule_id: "r1".to_string()
            }
        );
    }

    #[test]
    fn test_evaluate_rule_explicit_deny() {
        let rule = make_rule(PolicyRuleKind::ExplicitDeny, "r1");
        let effect = evaluate_rule(
            &rule,
            &make_actor(),
            SensitivityTier::Commerce,
            &make_predicate(),
            &make_domain(),
            &make_time(),
        );
        assert_eq!(
            effect,
            RuleEffect::Deny {
                rule_id: "r1".to_string(),
                reason: DenyReason::PolicyRuleDeny
            }
        );
    }

    #[test]
    fn test_evaluate_rule_anomaly_trigger() {
        let rule = make_rule(PolicyRuleKind::AnomalyTrigger, "r1");
        let effect = evaluate_rule(
            &rule,
            &make_actor(),
            SensitivityTier::Commerce,
            &make_predicate(),
            &make_domain(),
            &make_time(),
        );
        assert!(matches!(effect, RuleEffect::Anomaly { .. }));
    }

    #[test]
    fn test_evaluate_rule_domain_restriction_with_matching_domain() {
        let mut rule = make_rule(PolicyRuleKind::DomainRestriction, "r1");
        rule.domain_constraint = Some("example.com".to_string());
        let effect = evaluate_rule(
            &rule,
            &make_actor(),
            SensitivityTier::Commerce,
            &make_predicate(),
            &make_domain(),
            &make_time(),
        );
        assert_eq!(
            effect,
            RuleEffect::Permit {
                rule_id: "r1".to_string()
            }
        );
    }

    #[test]
    fn test_evaluate_rule_time_window_within_window() {
        let mut rule = make_rule(PolicyRuleKind::TimeWindow, "r1");
        rule.valid_from = Some(Timestamp::from_seconds(1_600_000_000));
        rule.valid_until = Some(Timestamp::from_seconds(1_800_000_000));
        let effect = evaluate_rule(
            &rule,
            &make_actor(),
            SensitivityTier::Commerce,
            &make_predicate(),
            &make_domain(),
            &make_time(),
        );
        assert_eq!(
            effect,
            RuleEffect::Permit {
                rule_id: "r1".to_string()
            }
        );
    }

    #[test]
    fn test_combine_deny_overrides_all_permit() {
        let effects = vec![
            RuleEffect::Permit {
                rule_id: "r1".to_string(),
            },
            RuleEffect::Permit {
                rule_id: "r2".to_string(),
            },
        ];
        let decision = combine_deny_overrides(
            &effects,
            PolicyVersion::initial(),
            make_time(),
            &make_actor(),
            &make_predicate(),
            &make_context(),
        );
        assert!(matches!(decision, Decision::Permit(_)));
        if let Decision::Permit(p) = &decision {
            assert_eq!(p.provenance.matching_rule_ids.len(), 2);
        }
    }

    #[test]
    fn test_combine_deny_overrides_deny_wins() {
        let effects = vec![
            RuleEffect::Permit {
                rule_id: "r1".to_string(),
            },
            RuleEffect::Deny {
                rule_id: "r2".to_string(),
                reason: DenyReason::PolicyRuleDeny,
            },
            RuleEffect::Permit {
                rule_id: "r3".to_string(),
            },
        ];
        let decision = combine_deny_overrides(
            &effects,
            PolicyVersion::initial(),
            make_time(),
            &make_actor(),
            &make_predicate(),
            &make_context(),
        );
        assert!(matches!(decision, Decision::Deny(_)));
        if let Decision::Deny(d) = &decision {
            assert_eq!(d.reason, DenyReason::PolicyRuleDeny);
        }
    }

    #[test]
    fn test_combine_deny_overrides_anomaly_over_permit() {
        let effects = vec![
            RuleEffect::Permit {
                rule_id: "r1".to_string(),
            },
            RuleEffect::Anomaly {
                rule_id: "r2".to_string(),
                reason: "suspicious".to_string(),
            },
        ];
        let decision = combine_deny_overrides(
            &effects,
            PolicyVersion::initial(),
            make_time(),
            &make_actor(),
            &make_predicate(),
            &make_context(),
        );
        assert!(matches!(decision, Decision::Anomaly(_)));
    }

    #[test]
    fn test_combine_deny_overrides_deny_over_anomaly() {
        let effects = vec![
            RuleEffect::Deny {
                rule_id: "r1".to_string(),
                reason: DenyReason::PolicyRuleDeny,
            },
            RuleEffect::Anomaly {
                rule_id: "r2".to_string(),
                reason: "suspicious".to_string(),
            },
        ];
        let decision = combine_deny_overrides(
            &effects,
            PolicyVersion::initial(),
            make_time(),
            &make_actor(),
            &make_predicate(),
            &make_context(),
        );
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_combine_deny_overrides_no_matching_rules() {
        let effects = vec![RuleEffect::NotApplicable, RuleEffect::NotApplicable];
        let decision = combine_deny_overrides(
            &effects,
            PolicyVersion::initial(),
            make_time(),
            &make_actor(),
            &make_predicate(),
            &make_context(),
        );
        assert!(matches!(decision, Decision::Deny(_)));
        if let Decision::Deny(d) = &decision {
            assert_eq!(d.reason, DenyReason::NoMatchingPermitRule);
        }
    }

    #[test]
    fn test_combine_deny_overrides_empty_effects() {
        let effects: Vec<RuleEffect> = Vec::new();
        let decision = combine_deny_overrides(
            &effects,
            PolicyVersion::initial(),
            make_time(),
            &make_actor(),
            &make_predicate(),
            &make_context(),
        );
        assert!(matches!(decision, Decision::Deny(_)));
        if let Decision::Deny(d) = &decision {
            assert_eq!(d.reason, DenyReason::NoMatchingPermitRule);
        }
    }

    #[test]
    fn test_combine_permit_has_expiration() {
        let effects = vec![RuleEffect::Permit {
            rule_id: "r1".to_string(),
        }];
        let now = make_time();
        let decision = combine_deny_overrides(
            &effects,
            PolicyVersion::initial(),
            now,
            &make_actor(),
            &make_predicate(),
            &make_context(),
        );
        if let Decision::Permit(p) = &decision {
            assert!(p.expires_at > now);
        } else {
            panic!("expected Permit decision");
        }
    }

    #[test]
    fn test_combine_anomaly_has_options() {
        let effects = vec![RuleEffect::Anomaly {
            rule_id: "r1".to_string(),
            reason: "test anomaly".to_string(),
        }];
        let decision = combine_deny_overrides(
            &effects,
            PolicyVersion::initial(),
            make_time(),
            &make_actor(),
            &make_predicate(),
            &make_context(),
        );
        if let Decision::Anomaly(a) = &decision {
            assert!(!a.report.options.is_empty());
            assert!(a.report.options.len() >= 1);
        } else {
            panic!("expected Anomaly decision");
        }
    }

    #[test]
    fn test_validate_policy_set_valid() {
        let policy_set = PolicySet {
            version: PolicyVersion::initial(),
            rules: vec![make_rule(PolicyRuleKind::ExplicitGrant, "r1")],
            created_at: Timestamp::now(),
            schema_version: 1,
        };
        assert!(validate_policy_set(&policy_set).is_ok());
    }

    #[test]
    fn test_validate_policy_set_bad_schema_version() {
        let policy_set = PolicySet {
            version: PolicyVersion::initial(),
            rules: vec![make_rule(PolicyRuleKind::ExplicitGrant, "r1")],
            created_at: Timestamp::now(),
            schema_version: 2,
        };
        let result = validate_policy_set(&policy_set);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("schema version")));
    }

    #[test]
    fn test_validate_policy_set_empty_rules() {
        let policy_set = PolicySet {
            version: PolicyVersion::initial(),
            rules: vec![],
            created_at: Timestamp::now(),
            schema_version: 1,
        };
        let result = validate_policy_set(&policy_set);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_policy_set_duplicate_rule_ids() {
        let policy_set = PolicySet {
            version: PolicyVersion::initial(),
            rules: vec![
                make_rule(PolicyRuleKind::ExplicitGrant, "r1"),
                make_rule(PolicyRuleKind::ExplicitDeny, "r1"),
            ],
            created_at: Timestamp::now(),
            schema_version: 1,
        };
        let result = validate_policy_set(&policy_set);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("duplicate")));
    }

    #[test]
    fn test_validate_policy_set_empty_rule_id() {
        let policy_set = PolicySet {
            version: PolicyVersion::initial(),
            rules: vec![make_rule(PolicyRuleKind::ExplicitGrant, "")],
            created_at: Timestamp::now(),
            schema_version: 1,
        };
        let result = validate_policy_set(&policy_set);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_policy_set_invalid_time_window() {
        let mut rule = make_rule(PolicyRuleKind::TimeWindow, "r1");
        rule.valid_from = Some(Timestamp::from_seconds(2_000_000_000));
        rule.valid_until = Some(Timestamp::from_seconds(1_000_000_000));
        let policy_set = PolicySet {
            version: PolicyVersion::initial(),
            rules: vec![rule],
            created_at: Timestamp::now(),
            schema_version: 1,
        };
        let result = validate_policy_set(&policy_set);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.contains("valid_from must be before valid_until")));
    }

    #[test]
    fn test_default_anomaly_options() {
        let options = default_anomaly_options();
        assert_eq!(options.len(), 3);
        // Must have at least one permit and one deny option
        assert!(options.iter().any(|o| o.resulting_decision == "permit"));
        assert!(options.iter().any(|o| o.resulting_decision == "deny"));
    }
}
