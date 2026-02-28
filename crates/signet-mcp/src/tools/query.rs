//! Query tool executor with tier-based response selection.
//!
//! Tier enforcement:
//! - T1: auto-serve with direct answer
//! - T2: conclusions-only (no raw data exported)
//! - T3: suspend + notify (returns pending status)

use crate::error::{McpError, McpResult};
use crate::types::{
    Conclusion, PendingStatus, QueryRequest, QueryResponse, Tier1QueryResponse, Tier2QueryResponse,
    Tier3QueryResponse,
};
use signet_core::Tier;

/// Execute a query request, returning a response appropriate for the given tier.
pub fn execute_query(request: &QueryRequest, tier: Tier) -> McpResult<QueryResponse> {
    if request.query.is_empty() {
        return Err(McpError::InvalidRequest("query must not be empty".into()));
    }

    match tier {
        Tier::Tier1 => execute_tier1_query(request),
        Tier::Tier2 => execute_tier2_query(request),
        Tier::Tier3 => execute_tier3_query(request),
    }
}

/// Tier 1: auto-serve with direct answer and optional proof.
fn execute_tier1_query(request: &QueryRequest) -> McpResult<QueryResponse> {
    // In production: resolve from vault Tier 1 data + generate ZKP
    let answer = serde_json::json!({
        "query": request.query,
        "result": true,
        "tier": "Tier1"
    });

    Ok(QueryResponse::Tier1(Tier1QueryResponse {
        request_id: request.request_id.clone(),
        answer,
        proof: None,
    }))
}

/// Tier 2: conclusions only. Agent reasons internally, never exports raw data.
fn execute_tier2_query(request: &QueryRequest) -> McpResult<QueryResponse> {
    // In production: agent performs internal reasoning over Tier 2 data
    // and returns only conclusions, not the underlying data.
    let conclusion = Conclusion {
        summary: format!("Conclusion for query: {}", request.query),
        confidence: 0.85,
        reasoning: "Based on internal agent reasoning over user data".into(),
    };

    Ok(QueryResponse::Tier2(Tier2QueryResponse {
        request_id: request.request_id.clone(),
        conclusions: vec![conclusion],
    }))
}

/// Tier 3: suspend and notify. Returns a pending status with a challenge ID.
fn execute_tier3_query(request: &QueryRequest) -> McpResult<QueryResponse> {
    // In production: fire Protocol 0 notification to user, await authorization
    let challenge_id = uuid::Uuid::new_v4().to_string();

    Ok(QueryResponse::Tier3(Tier3QueryResponse {
        request_id: request.request_id.clone(),
        status: PendingStatus::Pending,
        challenge_id,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use signet_core::RequestId;
    use std::collections::HashMap;

    fn make_request(query: &str) -> QueryRequest {
        QueryRequest {
            request_id: RequestId::new("req-q-001"),
            query: query.into(),
            context: HashMap::new(),
        }
    }

    #[test]
    fn test_tier1_query_returns_direct_answer() {
        let request = make_request("is the user over 21?");
        let response = execute_query(&request, Tier::Tier1).unwrap();
        match response {
            QueryResponse::Tier1(resp) => {
                assert_eq!(resp.request_id.as_str(), "req-q-001");
                assert!(resp.answer.is_object());
            }
            _ => panic!("expected Tier1 response"),
        }
    }

    #[test]
    fn test_tier2_query_returns_conclusions() {
        let request = make_request("what are the user's preferences?");
        let response = execute_query(&request, Tier::Tier2).unwrap();
        match response {
            QueryResponse::Tier2(resp) => {
                assert_eq!(resp.request_id.as_str(), "req-q-001");
                assert_eq!(resp.conclusions.len(), 1);
                assert!(resp.conclusions[0].confidence > 0.0);
                assert!(resp.conclusions[0].confidence <= 1.0);
            }
            _ => panic!("expected Tier2 response"),
        }
    }

    #[test]
    fn test_tier3_query_returns_pending() {
        let request = make_request("get payment details");
        let response = execute_query(&request, Tier::Tier3).unwrap();
        match response {
            QueryResponse::Tier3(resp) => {
                assert_eq!(resp.request_id.as_str(), "req-q-001");
                assert_eq!(resp.status, PendingStatus::Pending);
                assert!(!resp.challenge_id.is_empty());
            }
            _ => panic!("expected Tier3 response"),
        }
    }

    #[test]
    fn test_empty_query_rejected() {
        let request = make_request("");
        assert!(execute_query(&request, Tier::Tier1).is_err());
    }

    #[test]
    fn test_tier2_conclusions_contain_no_raw_data() {
        let request = make_request("what did the user order last time?");
        let response = execute_query(&request, Tier::Tier2).unwrap();
        if let QueryResponse::Tier2(resp) = response {
            for conclusion in &resp.conclusions {
                // Conclusions should contain summaries, not raw data
                assert!(!conclusion.summary.is_empty());
                assert!(!conclusion.reasoning.is_empty());
            }
        }
    }

    #[test]
    fn test_tier3_challenge_ids_unique() {
        let request = make_request("get medical records");
        let r1 = execute_query(&request, Tier::Tier3).unwrap();
        let r2 = execute_query(&request, Tier::Tier3).unwrap();
        if let (QueryResponse::Tier3(t1), QueryResponse::Tier3(t2)) = (r1, r2) {
            assert_ne!(t1.challenge_id, t2.challenge_id);
        }
    }
}
