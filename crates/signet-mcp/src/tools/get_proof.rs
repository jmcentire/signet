//! GetProof tool executor.
//!
//! Generates proofs (SD-JWT, BBS+, Bulletproof) for the given predicate queries.
//! All proofs are domain-bound and time-limited.

use crate::error::{McpError, McpResult};
use crate::types::{GetProofRequest, GetProofResponse, ProofType};
use sha2::{Digest, Sha256};
use signet_core::Timestamp;

/// Execute a GetProof request.
///
/// Generates a proof based on the requested type and predicates.
/// In production, this delegates to signet-proof's ProofEngine.
/// The current implementation generates a domain-bound placeholder proof.
pub fn execute_get_proof(request: &GetProofRequest) -> McpResult<GetProofResponse> {
    if request.predicates.is_empty() {
        return Err(McpError::InvalidRequest(
            "at least one predicate is required".into(),
        ));
    }
    if request.domain.is_empty() {
        return Err(McpError::InvalidRequest("domain must not be empty".into()));
    }
    if request.nonce.is_empty() {
        return Err(McpError::InvalidRequest("nonce must not be empty".into()));
    }

    // Generate domain-bound proof bytes
    // In production: delegate to signet_proof::ProofEngine::run_pipeline()
    let proof_bytes = generate_proof_bytes(request)?;

    let now = Timestamp::now();
    let expires_at = Timestamp::from_seconds(now.seconds_since_epoch + 300);

    Ok(GetProofResponse {
        request_id: request.request_id.clone(),
        proof_type: request.proof_type.clone(),
        proof_bytes,
        domain: request.domain.clone(),
        expires_at,
    })
}

/// Generate proof bytes bound to the domain and nonce.
///
/// This is a placeholder that produces a deterministic hash-based proof.
/// Real implementation would call into signet-proof's typestate pipeline.
fn generate_proof_bytes(request: &GetProofRequest) -> McpResult<Vec<u8>> {
    let mut hasher = Sha256::new();

    // Domain binding
    hasher.update(request.domain.as_bytes());
    hasher.update(request.nonce.as_bytes());

    // Include proof type in the binding
    let proof_type_tag = match request.proof_type {
        ProofType::SdJwt => "sd-jwt",
        ProofType::Bbs => "bbs+",
        ProofType::Bulletproof => "bulletproof",
    };
    hasher.update(proof_type_tag.as_bytes());

    // Include each predicate
    for pred in &request.predicates {
        hasher.update(pred.attribute.as_bytes());
        let pred_json = serde_json::to_vec(&pred.value)
            .map_err(|e| McpError::SerializationError(e.to_string()))?;
        hasher.update(&pred_json);
    }

    let hash = hasher.finalize();
    Ok(hash.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PredicateOperator, PredicateQuery};
    use signet_core::RequestId;

    fn make_request() -> GetProofRequest {
        GetProofRequest {
            request_id: RequestId::new("req-gp-001"),
            predicates: vec![PredicateQuery {
                attribute: "age".into(),
                operator: PredicateOperator::Gte,
                value: serde_json::json!(21),
            }],
            proof_type: ProofType::SdJwt,
            domain: "example.com".into(),
            nonce: "test-nonce-123".into(),
        }
    }

    #[test]
    fn test_execute_get_proof_success() {
        let request = make_request();
        let response = execute_get_proof(&request).unwrap();
        assert_eq!(response.request_id.as_str(), "req-gp-001");
        assert_eq!(response.proof_type, ProofType::SdJwt);
        assert_eq!(response.domain, "example.com");
        assert!(!response.proof_bytes.is_empty());
        assert!(!response.expires_at.is_expired());
    }

    #[test]
    fn test_execute_get_proof_empty_predicates() {
        let mut request = make_request();
        request.predicates = vec![];
        assert!(execute_get_proof(&request).is_err());
    }

    #[test]
    fn test_execute_get_proof_empty_domain() {
        let mut request = make_request();
        request.domain = "".into();
        assert!(execute_get_proof(&request).is_err());
    }

    #[test]
    fn test_execute_get_proof_empty_nonce() {
        let mut request = make_request();
        request.nonce = "".into();
        assert!(execute_get_proof(&request).is_err());
    }

    #[test]
    fn test_proof_bytes_differ_by_domain() {
        let mut req1 = make_request();
        req1.domain = "example.com".into();
        let mut req2 = make_request();
        req2.domain = "other.com".into();

        let resp1 = execute_get_proof(&req1).unwrap();
        let resp2 = execute_get_proof(&req2).unwrap();
        assert_ne!(resp1.proof_bytes, resp2.proof_bytes);
    }

    #[test]
    fn test_proof_bytes_differ_by_nonce() {
        let mut req1 = make_request();
        req1.nonce = "nonce-a".into();
        let mut req2 = make_request();
        req2.nonce = "nonce-b".into();

        let resp1 = execute_get_proof(&req1).unwrap();
        let resp2 = execute_get_proof(&req2).unwrap();
        assert_ne!(resp1.proof_bytes, resp2.proof_bytes);
    }

    #[test]
    fn test_proof_bytes_differ_by_proof_type() {
        let mut req1 = make_request();
        req1.proof_type = ProofType::SdJwt;
        let mut req2 = make_request();
        req2.proof_type = ProofType::Bbs;

        let resp1 = execute_get_proof(&req1).unwrap();
        let resp2 = execute_get_proof(&req2).unwrap();
        assert_ne!(resp1.proof_bytes, resp2.proof_bytes);
    }

    #[test]
    fn test_proof_deterministic_for_same_input() {
        let req = make_request();
        let resp1 = execute_get_proof(&req).unwrap();
        let resp2 = execute_get_proof(&req).unwrap();
        assert_eq!(resp1.proof_bytes, resp2.proof_bytes);
    }

    #[test]
    fn test_all_proof_types() {
        for proof_type in &[ProofType::SdJwt, ProofType::Bbs, ProofType::Bulletproof] {
            let mut request = make_request();
            request.proof_type = proof_type.clone();
            let response = execute_get_proof(&request).unwrap();
            assert_eq!(&response.proof_type, proof_type);
            assert!(!response.proof_bytes.is_empty());
        }
    }
}
