//! Tier classification and policy evaluation.
//!
//! Classifies requests into tiers and delegates policy evaluation to signet-policy.

use crate::error::McpResult;
use crate::types::{McpTool, PolicyDecision, PolicyEvaluationResult};
use signet_core::{Tier, Timestamp};

/// Classify the tier for an incoming request based on the tool and query content.
///
/// Tier classification rules:
/// - GetProof: always Tier1 (freely provable)
/// - Query: analyze the query content for sensitivity indicators
/// - RequestCapability: Tier2 or Tier3 depending on constraints
/// - NegotiateContext: Tier2 (agent-internal reasoning)
/// - CheckStatus: Tier1 (status check is non-sensitive)
pub fn classify_tier(tool: &McpTool, params: &serde_json::Value) -> McpResult<Tier> {
    match tool {
        McpTool::GetProof => Ok(Tier::Tier1),
        McpTool::CheckStatus => Ok(Tier::Tier1),
        McpTool::NegotiateContext => Ok(Tier::Tier2),
        McpTool::Query => classify_query_tier(params),
        McpTool::RequestCapability => classify_capability_tier(params),
    }
}

/// Classify query tier based on content analysis.
fn classify_query_tier(params: &serde_json::Value) -> McpResult<Tier> {
    let query = params.get("query").and_then(|v| v.as_str()).unwrap_or("");

    // Tier 3 indicators: payment, medical, identity
    let tier3_keywords = [
        "payment",
        "credit_card",
        "bank_account",
        "medical",
        "health",
        "diagnosis",
        "ssn",
        "social_security",
        "passport",
        "identity_document",
        "biometric",
    ];
    for keyword in &tier3_keywords {
        if query.to_lowercase().contains(keyword) {
            return Ok(Tier::Tier3);
        }
    }

    // Tier 2 indicators: preferences, history, internal reasoning
    let tier2_keywords = [
        "preference",
        "history",
        "order",
        "purchase",
        "shipping",
        "address",
        "recommend",
        "suggest",
    ];
    for keyword in &tier2_keywords {
        if query.to_lowercase().contains(keyword) {
            return Ok(Tier::Tier2);
        }
    }

    // Default: Tier 1
    Ok(Tier::Tier1)
}

/// Classify capability tier based on constraints.
fn classify_capability_tier(params: &serde_json::Value) -> McpResult<Tier> {
    let capability_type = params
        .get("capability_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match capability_type {
        "payment" | "financial" | "identity" | "medical" => Ok(Tier::Tier3),
        "commerce" | "shipping" | "order" => Ok(Tier::Tier2),
        _ => Ok(Tier::Tier2),
    }
}

/// Evaluate policy for an authenticated request.
///
/// Delegates to the signet-policy engine for the actual evaluation,
/// translating the result into MCP-layer types.
pub fn evaluate_policy(
    tool: &McpTool,
    tier: Tier,
    _params: &serde_json::Value,
) -> McpResult<PolicyEvaluationResult> {
    // Tier 1 is auto-permitted
    if tier == Tier::Tier1 {
        return Ok(PolicyEvaluationResult {
            decision: PolicyDecision::Permit,
            tier,
            reason: "tier 1 auto-permit".into(),
            evaluated_at: Timestamp::now(),
        });
    }

    // Tier 2: permit for query/negotiate, but conclusions-only enforcement
    // happens at the tool execution layer
    if tier == Tier::Tier2 {
        return Ok(PolicyEvaluationResult {
            decision: PolicyDecision::Permit,
            tier,
            reason: "tier 2 permitted with conclusions-only enforcement".into(),
            evaluated_at: Timestamp::now(),
        });
    }

    // Tier 3: requires user authorization (suspend + notify)
    // For now, return Anomaly which will trigger the notification flow
    match tool {
        McpTool::RequestCapability | McpTool::Query => Ok(PolicyEvaluationResult {
            decision: PolicyDecision::Anomaly,
            tier,
            reason: "tier 3 request requires user authorization".into(),
            evaluated_at: Timestamp::now(),
        }),
        _ => Ok(PolicyEvaluationResult {
            decision: PolicyDecision::Deny,
            tier,
            reason: "tier 3 access denied for this tool".into(),
            evaluated_at: Timestamp::now(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_get_proof_is_tier1() {
        let tier = classify_tier(&McpTool::GetProof, &serde_json::json!({})).unwrap();
        assert_eq!(tier, Tier::Tier1);
    }

    #[test]
    fn test_classify_check_status_is_tier1() {
        let tier = classify_tier(&McpTool::CheckStatus, &serde_json::json!({})).unwrap();
        assert_eq!(tier, Tier::Tier1);
    }

    #[test]
    fn test_classify_negotiate_context_is_tier2() {
        let tier = classify_tier(&McpTool::NegotiateContext, &serde_json::json!({})).unwrap();
        assert_eq!(tier, Tier::Tier2);
    }

    #[test]
    fn test_classify_query_tier1_default() {
        let params = serde_json::json!({"query": "user_exists"});
        let tier = classify_tier(&McpTool::Query, &params).unwrap();
        assert_eq!(tier, Tier::Tier1);
    }

    #[test]
    fn test_classify_query_tier2_preferences() {
        let params = serde_json::json!({"query": "what are the user's preferences?"});
        let tier = classify_tier(&McpTool::Query, &params).unwrap();
        assert_eq!(tier, Tier::Tier2);
    }

    #[test]
    fn test_classify_query_tier2_history() {
        let params = serde_json::json!({"query": "purchase history for last month"});
        let tier = classify_tier(&McpTool::Query, &params).unwrap();
        assert_eq!(tier, Tier::Tier2);
    }

    #[test]
    fn test_classify_query_tier3_payment() {
        let params = serde_json::json!({"query": "get payment credit_card details"});
        let tier = classify_tier(&McpTool::Query, &params).unwrap();
        assert_eq!(tier, Tier::Tier3);
    }

    #[test]
    fn test_classify_query_tier3_medical() {
        let params = serde_json::json!({"query": "access medical records"});
        let tier = classify_tier(&McpTool::Query, &params).unwrap();
        assert_eq!(tier, Tier::Tier3);
    }

    #[test]
    fn test_classify_capability_payment_is_tier3() {
        let params = serde_json::json!({"capability_type": "payment"});
        let tier = classify_tier(&McpTool::RequestCapability, &params).unwrap();
        assert_eq!(tier, Tier::Tier3);
    }

    #[test]
    fn test_classify_capability_commerce_is_tier2() {
        let params = serde_json::json!({"capability_type": "commerce"});
        let tier = classify_tier(&McpTool::RequestCapability, &params).unwrap();
        assert_eq!(tier, Tier::Tier2);
    }

    #[test]
    fn test_evaluate_policy_tier1_auto_permit() {
        let result =
            evaluate_policy(&McpTool::GetProof, Tier::Tier1, &serde_json::json!({})).unwrap();
        assert_eq!(result.decision, PolicyDecision::Permit);
        assert_eq!(result.tier, Tier::Tier1);
    }

    #[test]
    fn test_evaluate_policy_tier2_permit() {
        let result = evaluate_policy(&McpTool::Query, Tier::Tier2, &serde_json::json!({})).unwrap();
        assert_eq!(result.decision, PolicyDecision::Permit);
    }

    #[test]
    fn test_evaluate_policy_tier3_anomaly() {
        let result = evaluate_policy(&McpTool::Query, Tier::Tier3, &serde_json::json!({})).unwrap();
        assert_eq!(result.decision, PolicyDecision::Anomaly);
    }

    #[test]
    fn test_evaluate_policy_tier3_capability_anomaly() {
        let result = evaluate_policy(
            &McpTool::RequestCapability,
            Tier::Tier3,
            &serde_json::json!({}),
        )
        .unwrap();
        assert_eq!(result.decision, PolicyDecision::Anomaly);
    }

    #[test]
    fn test_evaluate_policy_tier3_check_status_deny() {
        let result =
            evaluate_policy(&McpTool::CheckStatus, Tier::Tier3, &serde_json::json!({})).unwrap();
        assert_eq!(result.decision, PolicyDecision::Deny);
    }

    #[test]
    fn test_classify_query_case_insensitive() {
        let params = serde_json::json!({"query": "get MEDICAL data"});
        let tier = classify_tier(&McpTool::Query, &params).unwrap();
        assert_eq!(tier, Tier::Tier3);
    }
}
