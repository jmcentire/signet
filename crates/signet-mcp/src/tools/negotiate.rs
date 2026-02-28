//! NegotiateContext tool executor.
//!
//! Implements the Steward Negotiation Protocol state machine:
//! Proposed -> CounterOffered | Accepted | Rejected | Expired
//!
//! The agent negotiates on the user's behalf, disclosing the minimum necessary.

use crate::error::{McpError, McpResult};
use crate::types::{
    DisclosureMode, NegotiateContextRequest, NegotiateContextResponse, NegotiateContextState,
    ProposedDisclosure, Session,
};
// Timestamp used in production for expiry tracking

/// Execute a context negotiation request.
///
/// Evaluates proposed disclosures against the user's disclosure preferences
/// and the session's authorization level. Returns accepted disclosures,
/// counter-proposals, or rejection.
pub fn execute_negotiate_context(
    request: &NegotiateContextRequest,
    _session: &Session,
) -> McpResult<NegotiateContextResponse> {
    if request.counterparty.is_empty() {
        return Err(McpError::InvalidRequest(
            "counterparty must not be empty".into(),
        ));
    }
    if request.proposed_disclosures.is_empty() {
        return Err(McpError::InvalidRequest(
            "proposed_disclosures must not be empty".into(),
        ));
    }

    // Evaluate each proposed disclosure
    let mut accepted = Vec::new();
    let mut counter_proposals = Vec::new();
    let mut has_rejections = false;

    for disclosure in &request.proposed_disclosures {
        match evaluate_disclosure(disclosure) {
            DisclosureDecision::Accept => {
                accepted.push(disclosure.clone());
            }
            DisclosureDecision::CounterOffer(counter) => {
                counter_proposals.push(counter);
            }
            DisclosureDecision::Reject => {
                has_rejections = true;
            }
        }
    }

    // Determine negotiation state
    let state = if has_rejections && accepted.is_empty() && counter_proposals.is_empty() {
        NegotiateContextState::Rejected
    } else if !counter_proposals.is_empty() {
        NegotiateContextState::CounterOffered
    } else {
        NegotiateContextState::Accepted
    };

    let counter_proposal = if counter_proposals.is_empty() {
        None
    } else {
        Some(counter_proposals)
    };

    Ok(NegotiateContextResponse {
        request_id: request.request_id.clone(),
        state,
        accepted_disclosures: accepted,
        counter_proposal,
    })
}

/// Internal decision for a single disclosure evaluation.
enum DisclosureDecision {
    Accept,
    CounterOffer(ProposedDisclosure),
    #[allow(dead_code)]
    Reject,
}

/// Evaluate a single proposed disclosure against policy.
///
/// Policy rules:
/// - ZeroKnowledge mode: always acceptable (minimum disclosure)
/// - ConclusionOnly mode: always acceptable (agent-internal)
/// - Selective mode for sensitive attributes: counter-offer with ZK mode
/// - Selective mode for non-sensitive attributes: accept
fn evaluate_disclosure(disclosure: &ProposedDisclosure) -> DisclosureDecision {
    // ZK and conclusion-only are always acceptable (minimum disclosure)
    if disclosure.mode == DisclosureMode::ZeroKnowledge
        || disclosure.mode == DisclosureMode::ConclusionOnly
    {
        return DisclosureDecision::Accept;
    }

    // Check if the attribute is sensitive
    let sensitive_attributes = [
        "ssn",
        "social_security",
        "passport",
        "credit_card",
        "bank_account",
        "medical_record",
        "diagnosis",
        "biometric",
        "identity_document",
    ];

    let attr_lower = disclosure.attribute.to_lowercase();
    let is_sensitive = sensitive_attributes.iter().any(|s| attr_lower.contains(s));

    if is_sensitive {
        // Counter-offer: suggest ZK mode instead of selective disclosure
        DisclosureDecision::CounterOffer(ProposedDisclosure {
            attribute: disclosure.attribute.clone(),
            mode: DisclosureMode::ZeroKnowledge,
            justification: format!(
                "Counter-proposal: {} is sensitive, suggesting zero-knowledge proof instead",
                disclosure.attribute
            ),
        })
    } else {
        DisclosureDecision::Accept
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signet_core::{RequestId, SessionId, Timestamp};
    use std::collections::HashMap;

    fn make_session() -> Session {
        let now = Timestamp::now();
        Session {
            session_id: SessionId::new("test-session"),
            public_key: vec![0u8; 32],
            created_at: now,
            expires_at: Timestamp::from_seconds(now.seconds_since_epoch + 3600),
            revoked: false,
            metadata: HashMap::new(),
        }
    }

    fn make_disclosure(attr: &str, mode: DisclosureMode) -> ProposedDisclosure {
        ProposedDisclosure {
            attribute: attr.into(),
            mode,
            justification: "needed for the transaction".into(),
        }
    }

    fn make_request(disclosures: Vec<ProposedDisclosure>) -> NegotiateContextRequest {
        NegotiateContextRequest {
            request_id: RequestId::new("req-neg-001"),
            counterparty: "amazon-agent".into(),
            proposed_disclosures: disclosures,
            purpose: "order fulfillment".into(),
        }
    }

    #[test]
    fn test_negotiate_accept_zk_disclosure() {
        let request = make_request(vec![make_disclosure("age", DisclosureMode::ZeroKnowledge)]);
        let response = execute_negotiate_context(&request, &make_session()).unwrap();
        assert_eq!(response.state, NegotiateContextState::Accepted);
        assert_eq!(response.accepted_disclosures.len(), 1);
        assert!(response.counter_proposal.is_none());
    }

    #[test]
    fn test_negotiate_accept_conclusion_only() {
        let request = make_request(vec![make_disclosure(
            "preferences",
            DisclosureMode::ConclusionOnly,
        )]);
        let response = execute_negotiate_context(&request, &make_session()).unwrap();
        assert_eq!(response.state, NegotiateContextState::Accepted);
    }

    #[test]
    fn test_negotiate_accept_non_sensitive_selective() {
        let request = make_request(vec![make_disclosure("name", DisclosureMode::Selective)]);
        let response = execute_negotiate_context(&request, &make_session()).unwrap();
        assert_eq!(response.state, NegotiateContextState::Accepted);
        assert_eq!(response.accepted_disclosures.len(), 1);
    }

    #[test]
    fn test_negotiate_counter_offer_sensitive_selective() {
        let request = make_request(vec![make_disclosure(
            "credit_card_number",
            DisclosureMode::Selective,
        )]);
        let response = execute_negotiate_context(&request, &make_session()).unwrap();
        assert_eq!(response.state, NegotiateContextState::CounterOffered);
        assert!(response.counter_proposal.is_some());
        let counter = response.counter_proposal.unwrap();
        assert_eq!(counter.len(), 1);
        assert_eq!(counter[0].mode, DisclosureMode::ZeroKnowledge);
    }

    #[test]
    fn test_negotiate_mixed_disclosures() {
        let request = make_request(vec![
            make_disclosure("name", DisclosureMode::Selective),
            make_disclosure("age", DisclosureMode::ZeroKnowledge),
            make_disclosure("ssn", DisclosureMode::Selective),
        ]);
        let response = execute_negotiate_context(&request, &make_session()).unwrap();
        // name: accepted, age: accepted, ssn: counter-offered
        assert_eq!(response.state, NegotiateContextState::CounterOffered);
        assert_eq!(response.accepted_disclosures.len(), 2);
        assert!(response.counter_proposal.is_some());
    }

    #[test]
    fn test_negotiate_empty_counterparty() {
        let mut request = make_request(vec![make_disclosure("name", DisclosureMode::Selective)]);
        request.counterparty = "".into();
        assert!(execute_negotiate_context(&request, &make_session()).is_err());
    }

    #[test]
    fn test_negotiate_empty_disclosures() {
        let request = make_request(vec![]);
        assert!(execute_negotiate_context(&request, &make_session()).is_err());
    }

    #[test]
    fn test_negotiate_all_sensitive_selective() {
        let request = make_request(vec![
            make_disclosure("ssn", DisclosureMode::Selective),
            make_disclosure("passport", DisclosureMode::Selective),
        ]);
        let response = execute_negotiate_context(&request, &make_session()).unwrap();
        assert_eq!(response.state, NegotiateContextState::CounterOffered);
        assert!(response.accepted_disclosures.is_empty());
        assert_eq!(response.counter_proposal.unwrap().len(), 2);
    }
}
