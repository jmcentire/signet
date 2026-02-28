//! Wire types — JSON-facing representations with TryFrom conversions to domain types.
//!
//! These types mirror the domain types but are designed for JSON-RPC serialization.
//! TryFrom conversions enforce validation at the boundary.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{McpError, McpResult};
use crate::types::{
    CheckStatusRequest, DisclosureMode, GetProofRequest, NegotiateContextRequest,
    PendingRequestType, PredicateOperator, PredicateQuery, ProofType, ProposedDisclosure,
    QueryRequest, RequestCapabilityRequest,
};
use signet_core::RequestId;

// ---------------------------------------------------------------------------
// Wire types — JSON-facing, with validation on conversion
// ---------------------------------------------------------------------------

/// Wire representation of a GetProof request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGetProofRequest {
    pub request_id: String,
    pub predicates: Vec<WirePredicateQuery>,
    pub proof_type: String,
    pub domain: String,
    pub nonce: String,
}

/// Wire representation of a predicate query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirePredicateQuery {
    pub attribute: String,
    pub operator: String,
    pub value: serde_json::Value,
}

/// Wire representation of a Query request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireQueryRequest {
    pub request_id: String,
    pub query: String,
    #[serde(default)]
    pub context: HashMap<String, String>,
}

/// Wire representation of a RequestCapability request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireRequestCapabilityRequest {
    pub request_id: String,
    pub capability_type: String,
    pub domain: String,
    pub purpose: String,
    #[serde(default)]
    pub constraints: HashMap<String, serde_json::Value>,
}

/// Wire representation of a NegotiateContext request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireNegotiateContextRequest {
    pub request_id: String,
    pub counterparty: String,
    pub proposed_disclosures: Vec<WireProposedDisclosure>,
    pub purpose: String,
}

/// Wire representation of a proposed disclosure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireProposedDisclosure {
    pub attribute: String,
    pub mode: String,
    pub justification: String,
}

/// Wire representation of a CheckStatus request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireCheckStatusRequest {
    pub request_id: String,
    pub pending_type: String,
}

// ---------------------------------------------------------------------------
// TryFrom conversions
// ---------------------------------------------------------------------------

fn parse_predicate_operator(s: &str) -> McpResult<PredicateOperator> {
    match s {
        "eq" | "=" | "==" => Ok(PredicateOperator::Eq),
        "gt" | ">" => Ok(PredicateOperator::Gt),
        "gte" | ">=" => Ok(PredicateOperator::Gte),
        "lt" | "<" => Ok(PredicateOperator::Lt),
        "lte" | "<=" => Ok(PredicateOperator::Lte),
        "in" => Ok(PredicateOperator::In),
        other => Err(McpError::InvalidRequest(format!(
            "unknown predicate operator: {}",
            other
        ))),
    }
}

fn parse_proof_type(s: &str) -> McpResult<ProofType> {
    match s {
        "sd_jwt" | "sd-jwt" | "SdJwt" => Ok(ProofType::SdJwt),
        "bbs" | "bbs+" | "Bbs" => Ok(ProofType::Bbs),
        "bulletproof" | "range" | "Bulletproof" => Ok(ProofType::Bulletproof),
        other => Err(McpError::InvalidRequest(format!(
            "unknown proof type: {}",
            other
        ))),
    }
}

fn parse_disclosure_mode(s: &str) -> McpResult<DisclosureMode> {
    match s {
        "selective" => Ok(DisclosureMode::Selective),
        "zero_knowledge" | "zk" => Ok(DisclosureMode::ZeroKnowledge),
        "conclusion_only" | "conclusions" => Ok(DisclosureMode::ConclusionOnly),
        other => Err(McpError::InvalidRequest(format!(
            "unknown disclosure mode: {}",
            other
        ))),
    }
}

fn parse_pending_request_type(s: &str) -> McpResult<PendingRequestType> {
    match s {
        "tier3_authorization" | "tier3" => Ok(PendingRequestType::Tier3Authorization),
        "negotiate_context" | "negotiation" => Ok(PendingRequestType::NegotiateContext),
        "capability_grant" | "capability" => Ok(PendingRequestType::CapabilityGrant),
        other => Err(McpError::InvalidRequest(format!(
            "unknown pending request type: {}",
            other
        ))),
    }
}

impl TryFrom<WirePredicateQuery> for PredicateQuery {
    type Error = McpError;

    fn try_from(wire: WirePredicateQuery) -> McpResult<Self> {
        if wire.attribute.is_empty() {
            return Err(McpError::InvalidRequest(
                "predicate attribute must not be empty".into(),
            ));
        }
        Ok(PredicateQuery {
            attribute: wire.attribute,
            operator: parse_predicate_operator(&wire.operator)?,
            value: wire.value,
        })
    }
}

impl TryFrom<WireGetProofRequest> for GetProofRequest {
    type Error = McpError;

    fn try_from(wire: WireGetProofRequest) -> McpResult<Self> {
        if wire.request_id.is_empty() {
            return Err(McpError::InvalidRequest(
                "request_id must not be empty".into(),
            ));
        }
        if wire.predicates.is_empty() {
            return Err(McpError::InvalidRequest(
                "predicates must not be empty".into(),
            ));
        }
        if wire.domain.is_empty() {
            return Err(McpError::InvalidRequest("domain must not be empty".into()));
        }
        if wire.nonce.is_empty() {
            return Err(McpError::InvalidRequest("nonce must not be empty".into()));
        }

        let predicates = wire
            .predicates
            .into_iter()
            .map(PredicateQuery::try_from)
            .collect::<McpResult<Vec<_>>>()?;

        Ok(GetProofRequest {
            request_id: RequestId::new(wire.request_id),
            predicates,
            proof_type: parse_proof_type(&wire.proof_type)?,
            domain: wire.domain,
            nonce: wire.nonce,
        })
    }
}

impl TryFrom<WireQueryRequest> for QueryRequest {
    type Error = McpError;

    fn try_from(wire: WireQueryRequest) -> McpResult<Self> {
        if wire.request_id.is_empty() {
            return Err(McpError::InvalidRequest(
                "request_id must not be empty".into(),
            ));
        }
        if wire.query.is_empty() {
            return Err(McpError::InvalidRequest("query must not be empty".into()));
        }
        Ok(QueryRequest {
            request_id: RequestId::new(wire.request_id),
            query: wire.query,
            context: wire.context,
        })
    }
}

impl TryFrom<WireRequestCapabilityRequest> for RequestCapabilityRequest {
    type Error = McpError;

    fn try_from(wire: WireRequestCapabilityRequest) -> McpResult<Self> {
        if wire.request_id.is_empty() {
            return Err(McpError::InvalidRequest(
                "request_id must not be empty".into(),
            ));
        }
        if wire.capability_type.is_empty() {
            return Err(McpError::InvalidRequest(
                "capability_type must not be empty".into(),
            ));
        }
        if wire.domain.is_empty() {
            return Err(McpError::InvalidRequest("domain must not be empty".into()));
        }
        Ok(RequestCapabilityRequest {
            request_id: RequestId::new(wire.request_id),
            capability_type: wire.capability_type,
            domain: wire.domain,
            purpose: wire.purpose,
            constraints: wire.constraints,
        })
    }
}

impl TryFrom<WireProposedDisclosure> for ProposedDisclosure {
    type Error = McpError;

    fn try_from(wire: WireProposedDisclosure) -> McpResult<Self> {
        if wire.attribute.is_empty() {
            return Err(McpError::InvalidRequest(
                "disclosure attribute must not be empty".into(),
            ));
        }
        Ok(ProposedDisclosure {
            attribute: wire.attribute,
            mode: parse_disclosure_mode(&wire.mode)?,
            justification: wire.justification,
        })
    }
}

impl TryFrom<WireNegotiateContextRequest> for NegotiateContextRequest {
    type Error = McpError;

    fn try_from(wire: WireNegotiateContextRequest) -> McpResult<Self> {
        if wire.request_id.is_empty() {
            return Err(McpError::InvalidRequest(
                "request_id must not be empty".into(),
            ));
        }
        if wire.counterparty.is_empty() {
            return Err(McpError::InvalidRequest(
                "counterparty must not be empty".into(),
            ));
        }
        if wire.proposed_disclosures.is_empty() {
            return Err(McpError::InvalidRequest(
                "proposed_disclosures must not be empty".into(),
            ));
        }

        let disclosures = wire
            .proposed_disclosures
            .into_iter()
            .map(ProposedDisclosure::try_from)
            .collect::<McpResult<Vec<_>>>()?;

        Ok(NegotiateContextRequest {
            request_id: RequestId::new(wire.request_id),
            counterparty: wire.counterparty,
            proposed_disclosures: disclosures,
            purpose: wire.purpose,
        })
    }
}

impl TryFrom<WireCheckStatusRequest> for CheckStatusRequest {
    type Error = McpError;

    fn try_from(wire: WireCheckStatusRequest) -> McpResult<Self> {
        if wire.request_id.is_empty() {
            return Err(McpError::InvalidRequest(
                "request_id must not be empty".into(),
            ));
        }
        Ok(CheckStatusRequest {
            request_id: RequestId::new(wire.request_id),
            pending_type: parse_pending_request_type(&wire.pending_type)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_get_proof_request_valid() {
        let wire = WireGetProofRequest {
            request_id: "req-001".into(),
            predicates: vec![WirePredicateQuery {
                attribute: "age".into(),
                operator: "gte".into(),
                value: serde_json::json!(21),
            }],
            proof_type: "sd_jwt".into(),
            domain: "example.com".into(),
            nonce: "abc123".into(),
        };
        let result = GetProofRequest::try_from(wire);
        assert!(result.is_ok());
        let req = result.unwrap();
        assert_eq!(req.request_id.as_str(), "req-001");
        assert_eq!(req.proof_type, ProofType::SdJwt);
    }

    #[test]
    fn test_wire_get_proof_request_empty_request_id() {
        let wire = WireGetProofRequest {
            request_id: "".into(),
            predicates: vec![WirePredicateQuery {
                attribute: "age".into(),
                operator: "gte".into(),
                value: serde_json::json!(21),
            }],
            proof_type: "sd_jwt".into(),
            domain: "example.com".into(),
            nonce: "abc123".into(),
        };
        assert!(GetProofRequest::try_from(wire).is_err());
    }

    #[test]
    fn test_wire_get_proof_request_empty_predicates() {
        let wire = WireGetProofRequest {
            request_id: "req-001".into(),
            predicates: vec![],
            proof_type: "sd_jwt".into(),
            domain: "example.com".into(),
            nonce: "abc123".into(),
        };
        assert!(GetProofRequest::try_from(wire).is_err());
    }

    #[test]
    fn test_wire_get_proof_request_unknown_operator() {
        let wire = WireGetProofRequest {
            request_id: "req-001".into(),
            predicates: vec![WirePredicateQuery {
                attribute: "age".into(),
                operator: "xor".into(),
                value: serde_json::json!(21),
            }],
            proof_type: "sd_jwt".into(),
            domain: "example.com".into(),
            nonce: "abc123".into(),
        };
        assert!(GetProofRequest::try_from(wire).is_err());
    }

    #[test]
    fn test_wire_get_proof_request_unknown_proof_type() {
        let wire = WireGetProofRequest {
            request_id: "req-001".into(),
            predicates: vec![WirePredicateQuery {
                attribute: "age".into(),
                operator: "gte".into(),
                value: serde_json::json!(21),
            }],
            proof_type: "unknown".into(),
            domain: "example.com".into(),
            nonce: "abc123".into(),
        };
        assert!(GetProofRequest::try_from(wire).is_err());
    }

    #[test]
    fn test_wire_query_request_valid() {
        let wire = WireQueryRequest {
            request_id: "req-002".into(),
            query: "what is the user's preferred delivery?".into(),
            context: HashMap::new(),
        };
        let result = QueryRequest::try_from(wire);
        assert!(result.is_ok());
    }

    #[test]
    fn test_wire_query_request_empty_query() {
        let wire = WireQueryRequest {
            request_id: "req-002".into(),
            query: "".into(),
            context: HashMap::new(),
        };
        assert!(QueryRequest::try_from(wire).is_err());
    }

    #[test]
    fn test_wire_request_capability_valid() {
        let wire = WireRequestCapabilityRequest {
            request_id: "req-003".into(),
            capability_type: "payment".into(),
            domain: "shop.example.com".into(),
            purpose: "purchase".into(),
            constraints: HashMap::new(),
        };
        let result = RequestCapabilityRequest::try_from(wire);
        assert!(result.is_ok());
    }

    #[test]
    fn test_wire_negotiate_context_valid() {
        let wire = WireNegotiateContextRequest {
            request_id: "req-004".into(),
            counterparty: "amazon-agent".into(),
            proposed_disclosures: vec![WireProposedDisclosure {
                attribute: "shipping_address".into(),
                mode: "selective".into(),
                justification: "needed for delivery".into(),
            }],
            purpose: "order fulfillment".into(),
        };
        let result = NegotiateContextRequest::try_from(wire);
        assert!(result.is_ok());
    }

    #[test]
    fn test_wire_negotiate_context_empty_disclosures() {
        let wire = WireNegotiateContextRequest {
            request_id: "req-004".into(),
            counterparty: "amazon-agent".into(),
            proposed_disclosures: vec![],
            purpose: "order fulfillment".into(),
        };
        assert!(NegotiateContextRequest::try_from(wire).is_err());
    }

    #[test]
    fn test_wire_check_status_valid() {
        let wire = WireCheckStatusRequest {
            request_id: "req-005".into(),
            pending_type: "tier3_authorization".into(),
        };
        let result = CheckStatusRequest::try_from(wire);
        assert!(result.is_ok());
        let req = result.unwrap();
        assert_eq!(req.pending_type, PendingRequestType::Tier3Authorization);
    }

    #[test]
    fn test_wire_check_status_unknown_type() {
        let wire = WireCheckStatusRequest {
            request_id: "req-005".into(),
            pending_type: "unknown_type".into(),
        };
        assert!(CheckStatusRequest::try_from(wire).is_err());
    }

    #[test]
    fn test_all_predicate_operators() {
        for (input, expected) in &[
            ("eq", PredicateOperator::Eq),
            ("=", PredicateOperator::Eq),
            ("==", PredicateOperator::Eq),
            ("gt", PredicateOperator::Gt),
            (">", PredicateOperator::Gt),
            ("gte", PredicateOperator::Gte),
            (">=", PredicateOperator::Gte),
            ("lt", PredicateOperator::Lt),
            ("<", PredicateOperator::Lt),
            ("lte", PredicateOperator::Lte),
            ("<=", PredicateOperator::Lte),
            ("in", PredicateOperator::In),
        ] {
            assert_eq!(parse_predicate_operator(input).unwrap(), *expected);
        }
    }

    #[test]
    fn test_all_proof_types() {
        for (input, expected) in &[
            ("sd_jwt", ProofType::SdJwt),
            ("sd-jwt", ProofType::SdJwt),
            ("SdJwt", ProofType::SdJwt),
            ("bbs", ProofType::Bbs),
            ("bbs+", ProofType::Bbs),
            ("Bbs", ProofType::Bbs),
            ("bulletproof", ProofType::Bulletproof),
            ("range", ProofType::Bulletproof),
            ("Bulletproof", ProofType::Bulletproof),
        ] {
            assert_eq!(parse_proof_type(input).unwrap(), *expected);
        }
    }

    #[test]
    fn test_all_disclosure_modes() {
        assert_eq!(
            parse_disclosure_mode("selective").unwrap(),
            DisclosureMode::Selective
        );
        assert_eq!(
            parse_disclosure_mode("zero_knowledge").unwrap(),
            DisclosureMode::ZeroKnowledge
        );
        assert_eq!(
            parse_disclosure_mode("zk").unwrap(),
            DisclosureMode::ZeroKnowledge
        );
        assert_eq!(
            parse_disclosure_mode("conclusion_only").unwrap(),
            DisclosureMode::ConclusionOnly
        );
        assert_eq!(
            parse_disclosure_mode("conclusions").unwrap(),
            DisclosureMode::ConclusionOnly
        );
    }

    #[test]
    fn test_all_pending_request_types() {
        assert_eq!(
            parse_pending_request_type("tier3_authorization").unwrap(),
            PendingRequestType::Tier3Authorization
        );
        assert_eq!(
            parse_pending_request_type("tier3").unwrap(),
            PendingRequestType::Tier3Authorization
        );
        assert_eq!(
            parse_pending_request_type("negotiate_context").unwrap(),
            PendingRequestType::NegotiateContext
        );
        assert_eq!(
            parse_pending_request_type("capability_grant").unwrap(),
            PendingRequestType::CapabilityGrant
        );
    }

    #[test]
    fn test_wire_get_proof_serde_roundtrip() {
        let wire = WireGetProofRequest {
            request_id: "req-rt".into(),
            predicates: vec![WirePredicateQuery {
                attribute: "age".into(),
                operator: "gte".into(),
                value: serde_json::json!(21),
            }],
            proof_type: "sd_jwt".into(),
            domain: "example.com".into(),
            nonce: "nonce123".into(),
        };
        let json = serde_json::to_string(&wire).unwrap();
        let parsed: WireGetProofRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.request_id, "req-rt");
    }
}
