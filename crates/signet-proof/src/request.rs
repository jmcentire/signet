//! ProofRequest construction and validation.
//!
//! ProofRequest is typestate stage 1: an incoming proof request from a relying
//! party. This module handles construction and initial validation.

use signet_core::{DomainBinding, TimeBudget};

use crate::error::{ProofError, ProofResult};
use crate::types::{DisclosureRequest, ProofEngineConfig, ProofRequest};

/// Builder for constructing a ProofRequest with validation.
pub struct ProofRequestBuilder {
    request_id: Option<String>,
    domain_binding: Option<DomainBinding>,
    requested_disclosures: Vec<DisclosureRequest>,
    time_budget: Option<TimeBudget>,
}

impl ProofRequestBuilder {
    pub fn new() -> Self {
        Self {
            request_id: None,
            domain_binding: None,
            requested_disclosures: Vec::new(),
            time_budget: None,
        }
    }

    pub fn request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    pub fn domain_binding(mut self, binding: DomainBinding) -> Self {
        self.domain_binding = Some(binding);
        self
    }

    pub fn add_disclosure(mut self, disclosure: DisclosureRequest) -> Self {
        self.requested_disclosures.push(disclosure);
        self
    }

    pub fn disclosures(mut self, disclosures: Vec<DisclosureRequest>) -> Self {
        self.requested_disclosures = disclosures;
        self
    }

    pub fn time_budget(mut self, budget: TimeBudget) -> Self {
        self.time_budget = Some(budget);
        self
    }

    /// Build the ProofRequest, performing initial validation.
    pub fn build(self) -> ProofResult<ProofRequest> {
        let request_id = self
            .request_id
            .ok_or_else(|| ProofError::InvalidDomainBinding("request_id is required".into()))?;

        let domain_binding = self
            .domain_binding
            .ok_or_else(|| ProofError::InvalidDomainBinding("domain_binding is required".into()))?;

        let time_budget = self.time_budget.ok_or(ProofError::TimeBudgetExceeded)?;

        if self.requested_disclosures.is_empty() {
            return Err(ProofError::CompositionFailed(
                "at least one disclosure request is required".into(),
            ));
        }

        if time_budget.remaining_ms == 0 {
            return Err(ProofError::TimeBudgetExceeded);
        }

        Ok(ProofRequest {
            request_id,
            domain_binding,
            requested_disclosures: self.requested_disclosures,
            time_budget,
        })
    }
}

impl Default for ProofRequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate a ProofRequest against engine configuration constraints.
pub fn validate_request_constraints(
    request: &ProofRequest,
    config: &ProofEngineConfig,
) -> ProofResult<()> {
    // Check disclosure count limit
    if request.requested_disclosures.len() > config.max_proofs_per_presentation {
        return Err(ProofError::CompositionFailed(format!(
            "requested {} disclosures but max is {}",
            request.requested_disclosures.len(),
            config.max_proofs_per_presentation
        )));
    }

    // Check time budget is positive
    if request.time_budget.remaining_ms == 0 {
        return Err(ProofError::TimeBudgetExceeded);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        BbsDisclosureRequest, PedersenWitness, Predicate, RangeDisclosureRequest, RevealedClaims,
        SdJwtDisclosureRequest,
    };
    use signet_core::{Nonce, RpIdentifier, Timestamp};

    fn make_binding(ttl: u64) -> DomainBinding {
        let now = Timestamp::now();
        DomainBinding {
            relying_party: RpIdentifier::Origin("https://example.com".into()),
            nonce: Nonce::generate(),
            issued_at: Timestamp::from_seconds(now.seconds_since_epoch.saturating_sub(1)),
            expires_at: Timestamp::from_seconds(now.seconds_since_epoch + ttl),
        }
    }

    fn make_sd_jwt_disclosure() -> DisclosureRequest {
        DisclosureRequest::SelectiveDisclosure(SdJwtDisclosureRequest {
            credential_handle: "cred_1".into(),
            claim_paths: RevealedClaims::new(vec!["name".into()]).unwrap(),
        })
    }

    #[test]
    fn test_builder_success() {
        let req = ProofRequestBuilder::new()
            .request_id("req_001")
            .domain_binding(make_binding(300))
            .add_disclosure(make_sd_jwt_disclosure())
            .time_budget(TimeBudget::new(500))
            .build()
            .unwrap();

        assert_eq!(req.request_id, "req_001");
        assert_eq!(req.requested_disclosures.len(), 1);
        assert_eq!(req.time_budget.remaining_ms, 500);
    }

    #[test]
    fn test_builder_missing_request_id() {
        let result = ProofRequestBuilder::new()
            .domain_binding(make_binding(300))
            .add_disclosure(make_sd_jwt_disclosure())
            .time_budget(TimeBudget::new(500))
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_missing_domain_binding() {
        let result = ProofRequestBuilder::new()
            .request_id("req_001")
            .add_disclosure(make_sd_jwt_disclosure())
            .time_budget(TimeBudget::new(500))
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_no_disclosures() {
        let result = ProofRequestBuilder::new()
            .request_id("req_001")
            .domain_binding(make_binding(300))
            .time_budget(TimeBudget::new(500))
            .build();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProofError::CompositionFailed(_)
        ));
    }

    #[test]
    fn test_builder_zero_budget() {
        let result = ProofRequestBuilder::new()
            .request_id("req_001")
            .domain_binding(make_binding(300))
            .add_disclosure(make_sd_jwt_disclosure())
            .time_budget(TimeBudget::new(0))
            .build();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProofError::TimeBudgetExceeded
        ));
    }

    #[test]
    fn test_builder_multiple_disclosures() {
        let bbs_disclosure = DisclosureRequest::UnlinkableProof(BbsDisclosureRequest {
            credential_handle: "cred_2".into(),
            disclosed_indices: vec![0, 2],
        });

        let witness = PedersenWitness::new(50000, [0x01; 32]);
        let commitment = witness.compute_commitment();
        let range_disclosure = DisclosureRequest::RangeAssertion(RangeDisclosureRequest {
            credential_handle: "cred_3".into(),
            attribute_name: "income".into(),
            predicate: Predicate::Gte(30000),
            witness,
            commitment,
        });

        let req = ProofRequestBuilder::new()
            .request_id("req_002")
            .domain_binding(make_binding(300))
            .add_disclosure(make_sd_jwt_disclosure())
            .add_disclosure(bbs_disclosure)
            .add_disclosure(range_disclosure)
            .time_budget(TimeBudget::new(1000))
            .build()
            .unwrap();

        assert_eq!(req.requested_disclosures.len(), 3);
    }

    #[test]
    fn test_builder_disclosures_batch() {
        let disclosures = vec![make_sd_jwt_disclosure(), make_sd_jwt_disclosure()];

        let req = ProofRequestBuilder::new()
            .request_id("req_003")
            .domain_binding(make_binding(300))
            .disclosures(disclosures)
            .time_budget(TimeBudget::new(500))
            .build()
            .unwrap();

        assert_eq!(req.requested_disclosures.len(), 2);
    }

    #[test]
    fn test_validate_request_constraints_ok() {
        let req = ProofRequestBuilder::new()
            .request_id("req_001")
            .domain_binding(make_binding(300))
            .add_disclosure(make_sd_jwt_disclosure())
            .time_budget(TimeBudget::new(500))
            .build()
            .unwrap();

        let config = ProofEngineConfig::default();
        assert!(validate_request_constraints(&req, &config).is_ok());
    }

    #[test]
    fn test_validate_request_constraints_too_many_disclosures() {
        let mut disclosures = Vec::new();
        for _ in 0..20 {
            disclosures.push(make_sd_jwt_disclosure());
        }

        let req = ProofRequest {
            request_id: "req_001".into(),
            domain_binding: make_binding(300),
            requested_disclosures: disclosures,
            time_budget: TimeBudget::new(5000),
        };

        let config = ProofEngineConfig {
            max_proofs_per_presentation: 10,
            ..ProofEngineConfig::default()
        };

        let result = validate_request_constraints(&req, &config);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProofError::CompositionFailed(_)
        ));
    }

    #[test]
    fn test_validate_request_constraints_zero_budget() {
        let req = ProofRequest {
            request_id: "req_001".into(),
            domain_binding: make_binding(300),
            requested_disclosures: vec![make_sd_jwt_disclosure()],
            time_budget: TimeBudget {
                total_ms: 500,
                remaining_ms: 0,
            },
        };

        let config = ProofEngineConfig::default();
        let result = validate_request_constraints(&req, &config);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProofError::TimeBudgetExceeded
        ));
    }
}
