use signet_core::PredicateId;

use crate::types::{PolicyRule, PolicyRuleKind, SensitivityTier};

/// Predicate legitimacy result from checking whether a predicate
/// is legitimate for a given actor classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredicateLegitimacy {
    /// The predicate is legitimate for the actor's tier.
    Legitimate,
    /// The predicate requires a higher tier than the actor has,
    /// but within a natural escalation path.
    InsufficientTier {
        required: SensitivityTier,
        actual: SensitivityTier,
    },
    /// The predicate is in a different branch of the tier hierarchy
    /// relative to the actor's classification, resulting in anomaly.
    BranchMismatch {
        actor_tier: SensitivityTier,
        predicate_tier: SensitivityTier,
        reason: String,
    },
}

/// Determine the minimum tier required for a given predicate based on the policy rules.
///
/// Scans all enabled rules to find those that match the predicate and returns
/// the highest minimum_tier among matching TierThreshold rules.
pub fn required_tier_for_predicate(
    predicate_id: &PredicateId,
    rules: &[PolicyRule],
) -> SensitivityTier {
    let mut highest_tier = SensitivityTier::Public;

    for rule in rules {
        if !rule.enabled {
            continue;
        }
        if rule.kind != PolicyRuleKind::TierThreshold {
            continue;
        }
        if !pattern_matches_predicate(&rule.predicate_pattern, predicate_id) {
            continue;
        }
        if rule.minimum_tier > highest_tier {
            highest_tier = rule.minimum_tier;
        }
    }

    highest_tier
}

/// Check if a pattern string matches a given predicate ID.
///
/// Patterns:
/// - `"*"` matches all predicates
/// - An exact string match
/// - A prefix match with trailing `"*"` (e.g., `"health_*"` matches `"health_data"`)
pub fn pattern_matches_predicate(pattern: &str, predicate_id: &PredicateId) -> bool {
    if pattern == "*" {
        return true;
    }
    let pred = predicate_id.as_str();
    if let Some(prefix) = pattern.strip_suffix('*') {
        pred.starts_with(prefix)
    } else {
        pred == pattern
    }
}

/// Check if a pattern string matches a given actor ID.
///
/// Patterns:
/// - `"*"` matches all actors
/// - An exact string match
/// - A prefix match with trailing `"*"`
/// - A tier pattern like `"tier:Commerce+"` (matches actors at that tier or above)
pub fn pattern_matches_actor(
    pattern: &str,
    actor_id: &signet_core::ActorId,
    actor_tier: SensitivityTier,
) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.starts_with("tier:") {
        return tier_pattern_matches(pattern, actor_tier);
    }
    let actor = actor_id.as_str();
    if let Some(prefix) = pattern.strip_suffix('*') {
        actor.starts_with(prefix)
    } else {
        actor == pattern
    }
}

/// Match a tier pattern like "tier:Commerce+" against an actor's tier.
/// The "+" suffix means "at or above this tier".
fn tier_pattern_matches(pattern: &str, actor_tier: SensitivityTier) -> bool {
    let tier_part = &pattern[5..]; // skip "tier:"
    let (tier_name, at_or_above) = if let Some(prefix) = tier_part.strip_suffix('+') {
        (prefix, true)
    } else {
        (tier_part, false)
    };

    let target_tier = match tier_name {
        "Public" => SensitivityTier::Public,
        "Commerce" => SensitivityTier::Commerce,
        "Financial" => SensitivityTier::Financial,
        "Medical" => SensitivityTier::Medical,
        "Identity" => SensitivityTier::Identity,
        "TrustedAgent" => SensitivityTier::TrustedAgent,
        _ => return false,
    };

    if at_or_above {
        actor_tier >= target_tier
    } else {
        actor_tier == target_tier
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signet_core::{ActorId, PredicateId};

    fn make_tier_rule(rule_id: &str, pred_pattern: &str, min_tier: SensitivityTier) -> PolicyRule {
        PolicyRule {
            rule_id: rule_id.to_string(),
            kind: PolicyRuleKind::TierThreshold,
            actor_pattern: "*".to_string(),
            predicate_pattern: pred_pattern.to_string(),
            minimum_tier: min_tier,
            domain_constraint: None,
            valid_from: None,
            valid_until: None,
            priority: 0,
            enabled: true,
        }
    }

    #[test]
    fn test_pattern_matches_predicate_wildcard() {
        let pred = PredicateId::new("anything");
        assert!(pattern_matches_predicate("*", &pred));
    }

    #[test]
    fn test_pattern_matches_predicate_exact() {
        let pred = PredicateId::new("shipping_address");
        assert!(pattern_matches_predicate("shipping_address", &pred));
        assert!(!pattern_matches_predicate("billing_address", &pred));
    }

    #[test]
    fn test_pattern_matches_predicate_prefix() {
        let pred = PredicateId::new("health_data");
        assert!(pattern_matches_predicate("health_*", &pred));
        assert!(!pattern_matches_predicate("finance_*", &pred));
    }

    #[test]
    fn test_pattern_matches_actor_wildcard() {
        let actor = ActorId::new("amazon");
        assert!(pattern_matches_actor(
            "*",
            &actor,
            SensitivityTier::Commerce
        ));
    }

    #[test]
    fn test_pattern_matches_actor_exact() {
        let actor = ActorId::new("amazon");
        assert!(pattern_matches_actor(
            "amazon",
            &actor,
            SensitivityTier::Commerce
        ));
        assert!(!pattern_matches_actor(
            "google",
            &actor,
            SensitivityTier::Commerce
        ));
    }

    #[test]
    fn test_pattern_matches_actor_prefix() {
        let actor = ActorId::new("amazon-us");
        assert!(pattern_matches_actor(
            "amazon*",
            &actor,
            SensitivityTier::Commerce
        ));
    }

    #[test]
    fn test_pattern_matches_actor_tier_exact() {
        let actor = ActorId::new("shop");
        assert!(pattern_matches_actor(
            "tier:Commerce",
            &actor,
            SensitivityTier::Commerce
        ));
        assert!(!pattern_matches_actor(
            "tier:Financial",
            &actor,
            SensitivityTier::Commerce
        ));
    }

    #[test]
    fn test_pattern_matches_actor_tier_at_or_above() {
        let actor = ActorId::new("bank");
        assert!(pattern_matches_actor(
            "tier:Commerce+",
            &actor,
            SensitivityTier::Financial
        ));
        assert!(pattern_matches_actor(
            "tier:Commerce+",
            &actor,
            SensitivityTier::Commerce
        ));
        assert!(!pattern_matches_actor(
            "tier:Financial+",
            &actor,
            SensitivityTier::Commerce
        ));
    }

    #[test]
    fn test_tier_pattern_invalid_tier_name() {
        let actor = ActorId::new("any");
        assert!(!pattern_matches_actor(
            "tier:Nonsense+",
            &actor,
            SensitivityTier::Commerce
        ));
    }

    #[test]
    fn test_required_tier_for_predicate_no_matching_rules() {
        let pred = PredicateId::new("something");
        let rules = vec![make_tier_rule(
            "r1",
            "other_thing",
            SensitivityTier::Financial,
        )];
        assert_eq!(
            required_tier_for_predicate(&pred, &rules),
            SensitivityTier::Public
        );
    }

    #[test]
    fn test_required_tier_for_predicate_single_match() {
        let pred = PredicateId::new("health_data");
        let rules = vec![make_tier_rule("r1", "health_*", SensitivityTier::Medical)];
        assert_eq!(
            required_tier_for_predicate(&pred, &rules),
            SensitivityTier::Medical
        );
    }

    #[test]
    fn test_required_tier_for_predicate_multiple_matches_takes_highest() {
        let pred = PredicateId::new("health_data");
        let rules = vec![
            make_tier_rule("r1", "*", SensitivityTier::Public),
            make_tier_rule("r2", "health_*", SensitivityTier::Medical),
            make_tier_rule("r3", "health_data", SensitivityTier::Commerce),
        ];
        assert_eq!(
            required_tier_for_predicate(&pred, &rules),
            SensitivityTier::Medical
        );
    }

    #[test]
    fn test_required_tier_skips_disabled_rules() {
        let pred = PredicateId::new("sensitive");
        let mut rule = make_tier_rule("r1", "sensitive", SensitivityTier::Identity);
        rule.enabled = false;
        let rules = vec![rule];
        assert_eq!(
            required_tier_for_predicate(&pred, &rules),
            SensitivityTier::Public
        );
    }

    #[test]
    fn test_required_tier_skips_non_tier_threshold_rules() {
        let pred = PredicateId::new("data");
        let rules = vec![PolicyRule {
            rule_id: "r1".to_string(),
            kind: PolicyRuleKind::ExplicitDeny,
            actor_pattern: "*".to_string(),
            predicate_pattern: "data".to_string(),
            minimum_tier: SensitivityTier::TrustedAgent,
            domain_constraint: None,
            valid_from: None,
            valid_until: None,
            priority: 0,
            enabled: true,
        }];
        assert_eq!(
            required_tier_for_predicate(&pred, &rules),
            SensitivityTier::Public
        );
    }

    #[test]
    fn test_predicate_legitimacy_enum() {
        let legitimate = PredicateLegitimacy::Legitimate;
        let insufficient = PredicateLegitimacy::InsufficientTier {
            required: SensitivityTier::Financial,
            actual: SensitivityTier::Commerce,
        };
        let mismatch = PredicateLegitimacy::BranchMismatch {
            actor_tier: SensitivityTier::Commerce,
            predicate_tier: SensitivityTier::Medical,
            reason: "Commerce actor requesting Medical data".to_string(),
        };

        assert_eq!(legitimate, PredicateLegitimacy::Legitimate);
        assert_ne!(legitimate, insufficient);
        assert_ne!(insufficient, mismatch);
    }

    #[test]
    fn test_pattern_matches_predicate_empty_pattern() {
        let pred = PredicateId::new("test");
        // Empty pattern should not match (it's not "*")
        assert!(!pattern_matches_predicate("", &pred));
    }

    #[test]
    fn test_wildcard_only_star_prefix() {
        let pred = PredicateId::new("abc");
        // Pattern "a*" should match "abc"
        assert!(pattern_matches_predicate("a*", &pred));
        // Pattern "ab*" should match "abc"
        assert!(pattern_matches_predicate("ab*", &pred));
        // Pattern "abc*" should match "abc" (prefix "abc" matches "abc")
        assert!(pattern_matches_predicate("abc*", &pred));
        // Pattern "abcd*" should not match "abc"
        assert!(!pattern_matches_predicate("abcd*", &pred));
    }
}
