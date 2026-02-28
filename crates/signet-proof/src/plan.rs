//! ProofPlan creation from ProofRequest.
//!
//! Typestate transition: ProofRequest -> ProofPlan.
//! Validates the incoming proof request, resolves credential handles, validates
//! claim paths, checks predicates, and estimates total proof generation time.
//! No cryptographic operations are performed in this phase.

use std::time::Instant;

use crate::binding::validate_domain_binding_with_ttl;
use crate::error::{ProofError, ProofResult};
use crate::request::validate_request_constraints;
use crate::types::{
    CachedCredential, CredentialFormat, CredentialStore, DisclosureRequest, PlannedEntry,
    ProofEngineConfig, ProofPlan, ProofRequest, ResolvedBbsPlan, ResolvedRangePlan,
    ResolvedSdJwtPlan,
};

/// Typestate transition: ProofRequest -> ProofPlan.
///
/// Validates the incoming request, resolves credentials, checks predicates,
/// and produces an immutable ProofPlan. No cryptographic operations performed.
pub fn validate_proof_request(
    config: &ProofEngineConfig,
    request: &ProofRequest,
    store: &dyn CredentialStore,
) -> ProofResult<ProofPlan> {
    let start = Instant::now();

    // Validate config
    config
        .validate()
        .map_err(|e| ProofError::InvalidDomainBinding(format!("invalid engine config: {}", e)))?;

    // Validate request constraints (disclosure count, budget)
    validate_request_constraints(request, config)?;

    // Validate domain binding (not expired, minimum TTL)
    validate_domain_binding_with_ttl(&request.domain_binding, config)?;

    // Resolve and validate each disclosure request
    let mut planned_entries = Vec::with_capacity(request.requested_disclosures.len());
    let mut estimated_total_ms: u64 = 0;

    for disclosure in &request.requested_disclosures {
        let (entry, est_ms) = resolve_disclosure(config, disclosure, store)?;
        estimated_total_ms += est_ms;
        planned_entries.push(entry);
    }

    // Check if estimated time fits within budget
    let elapsed_ms = start.elapsed().as_millis() as u64;
    let mut remaining_budget = request.time_budget;
    remaining_budget.consume(elapsed_ms);

    if estimated_total_ms > remaining_budget.remaining_ms {
        return Err(ProofError::TimeBudgetExceeded);
    }

    Ok(ProofPlan {
        request_id: request.request_id.clone(),
        domain_binding: request.domain_binding.clone(),
        planned_entries,
        remaining_budget,
        estimated_total_ms,
    })
}

/// Resolve a single disclosure request into a planned entry.
fn resolve_disclosure(
    config: &ProofEngineConfig,
    disclosure: &DisclosureRequest,
    store: &dyn CredentialStore,
) -> ProofResult<(PlannedEntry, u64)> {
    match disclosure {
        DisclosureRequest::SelectiveDisclosure(sd_req) => {
            let cred = resolve_credential(store, &sd_req.credential_handle)?;
            validate_sd_jwt_credential(&cred, sd_req)?;

            let estimated_ms = config.sd_jwt_budget_ms;
            let entry = PlannedEntry::SdJwtPlan(ResolvedSdJwtPlan {
                credential_handle: sd_req.credential_handle.clone(),
                revealed_claims: sd_req.claim_paths.clone(),
                estimated_ms,
            });
            Ok((entry, estimated_ms))
        }
        DisclosureRequest::UnlinkableProof(bbs_req) => {
            let cred = resolve_credential(store, &bbs_req.credential_handle)?;
            validate_bbs_credential(&cred, bbs_req)?;

            let estimated_ms = config.bbs_budget_ms;
            let entry = PlannedEntry::BbsPlan(ResolvedBbsPlan {
                credential_handle: bbs_req.credential_handle.clone(),
                disclosed_indices: bbs_req.disclosed_indices.clone(),
                estimated_ms,
            });
            Ok((entry, estimated_ms))
        }
        DisclosureRequest::RangeAssertion(range_req) => {
            // Resolve credential (for validation that it exists)
            let _cred = resolve_credential(store, &range_req.credential_handle)?;

            // Validate predicate
            if !range_req.predicate.validate() {
                return Err(ProofError::InvalidPredicate(format!(
                    "malformed predicate: {:?}",
                    range_req.predicate
                )));
            }

            // Verify witness matches commitment
            let computed = range_req.witness.compute_commitment();
            if computed.commitment_bytes != range_req.commitment.commitment_bytes {
                return Err(ProofError::WitnessCommitmentMismatch);
            }

            // Verify witness satisfies predicate
            if !range_req.predicate.is_satisfied_by(range_req.witness.value) {
                return Err(ProofError::PredicateNotSatisfied(format!(
                    "value does not satisfy predicate {:?}",
                    range_req.predicate
                )));
            }

            let estimated_ms = config.range_proof_budget_ms;
            let entry = PlannedEntry::RangePlan(ResolvedRangePlan {
                credential_handle: range_req.credential_handle.clone(),
                attribute_name: range_req.attribute_name.clone(),
                predicate: range_req.predicate.clone(),
                witness: range_req.witness.clone(),
                commitment: range_req.commitment.clone(),
                estimated_ms,
            });
            Ok((entry, estimated_ms))
        }
    }
}

/// Resolve a credential handle via the store.
fn resolve_credential(store: &dyn CredentialStore, handle: &str) -> ProofResult<CachedCredential> {
    let cred = store
        .resolve(handle)
        .ok_or_else(|| ProofError::CredentialNotFound(handle.to_string()))?;

    // Check expiry
    if let Some(expires_at) = &cred.expires_at {
        if expires_at.is_expired() {
            return Err(ProofError::CredentialExpired(handle.to_string()));
        }
    }

    Ok(cred)
}

/// Validate an SD-JWT credential against the disclosure request.
fn validate_sd_jwt_credential(
    cred: &CachedCredential,
    req: &crate::types::SdJwtDisclosureRequest,
) -> ProofResult<()> {
    if cred.format != CredentialFormat::SdJwt {
        return Err(ProofError::CredentialTypeMismatch(format!(
            "expected SD-JWT, got {:?}",
            cred.format
        )));
    }

    // Validate claim paths
    for path in &req.claim_paths.paths {
        if !cred.claims.contains(path) {
            return Err(ProofError::InvalidClaimPath(format!(
                "claim '{}' not found in credential '{}'",
                path, cred.handle
            )));
        }
    }

    // Prevent full disclosure
    if req.claim_paths.paths.len() >= cred.total_claim_count {
        return Err(ProofError::FullDisclosurePrevented(format!(
            "revealing all {} claims would defeat selective disclosure",
            cred.total_claim_count
        )));
    }

    Ok(())
}

/// Validate a BBS+ credential against the disclosure request.
fn validate_bbs_credential(
    cred: &CachedCredential,
    req: &crate::types::BbsDisclosureRequest,
) -> ProofResult<()> {
    if cred.format != CredentialFormat::Bbs {
        return Err(ProofError::CredentialTypeMismatch(format!(
            "expected BBS+, got {:?}",
            cred.format
        )));
    }

    // Validate indices
    for &idx in &req.disclosed_indices {
        if idx >= cred.total_claim_count {
            return Err(ProofError::InvalidClaimPath(format!(
                "index {} out of range (credential has {} messages)",
                idx, cred.total_claim_count
            )));
        }
    }

    // Prevent full disclosure
    if req.disclosed_indices.len() >= cred.total_claim_count {
        return Err(ProofError::FullDisclosurePrevented(format!(
            "disclosing all {} messages would defeat unlinkability",
            cred.total_claim_count
        )));
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
    use signet_core::{DomainBinding, Nonce, RpIdentifier, TimeBudget, Timestamp};
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct TestCredentialStore {
        creds: Mutex<HashMap<String, CachedCredential>>,
    }

    impl TestCredentialStore {
        fn new() -> Self {
            Self {
                creds: Mutex::new(HashMap::new()),
            }
        }

        fn add(&self, cred: CachedCredential) {
            self.creds.lock().unwrap().insert(cred.handle.clone(), cred);
        }
    }

    impl CredentialStore for TestCredentialStore {
        fn resolve(&self, handle: &str) -> Option<CachedCredential> {
            self.creds.lock().unwrap().get(handle).cloned()
        }
    }

    fn make_binding(ttl: u64) -> DomainBinding {
        let now = Timestamp::now();
        DomainBinding {
            relying_party: RpIdentifier::Origin("https://example.com".into()),
            nonce: Nonce::generate(),
            issued_at: Timestamp::from_seconds(now.seconds_since_epoch.saturating_sub(1)),
            expires_at: Timestamp::from_seconds(now.seconds_since_epoch + ttl),
        }
    }

    fn make_sd_jwt_cred(handle: &str) -> CachedCredential {
        CachedCredential {
            handle: handle.to_string(),
            format: CredentialFormat::SdJwt,
            claims: vec!["name".into(), "age".into(), "email".into()],
            raw_data: b"eyJ0eXAiOiJKV1QifQ.eyJ0ZXN0IjoiMSJ9.sig".to_vec(),
            expires_at: None,
            total_claim_count: 5,
        }
    }

    fn make_bbs_cred(handle: &str) -> CachedCredential {
        CachedCredential {
            handle: handle.to_string(),
            format: CredentialFormat::Bbs,
            claims: vec!["msg_0".into(), "msg_1".into(), "msg_2".into()],
            raw_data: vec![0x42; 64],
            expires_at: None,
            total_claim_count: 5,
        }
    }

    fn make_sd_jwt_disclosure() -> DisclosureRequest {
        DisclosureRequest::SelectiveDisclosure(SdJwtDisclosureRequest {
            credential_handle: "sd_cred".into(),
            claim_paths: RevealedClaims::new(vec!["name".into()]).unwrap(),
        })
    }

    fn make_bbs_disclosure() -> DisclosureRequest {
        DisclosureRequest::UnlinkableProof(BbsDisclosureRequest {
            credential_handle: "bbs_cred".into(),
            disclosed_indices: vec![0, 2],
        })
    }

    fn make_range_disclosure() -> DisclosureRequest {
        let witness = PedersenWitness::new(25, [0x42; 32]);
        let commitment = witness.compute_commitment();
        DisclosureRequest::RangeAssertion(RangeDisclosureRequest {
            credential_handle: "sd_cred".into(),
            attribute_name: "age".into(),
            predicate: Predicate::Gte(21),
            witness,
            commitment,
        })
    }

    #[test]
    fn test_validate_proof_request_sd_jwt() {
        let store = TestCredentialStore::new();
        store.add(make_sd_jwt_cred("sd_cred"));

        let request = ProofRequest {
            request_id: "req_001".into(),
            domain_binding: make_binding(300),
            requested_disclosures: vec![make_sd_jwt_disclosure()],
            time_budget: TimeBudget::new(500),
        };

        let config = ProofEngineConfig::default();
        let plan = validate_proof_request(&config, &request, &store).unwrap();

        assert_eq!(plan.request_id, "req_001");
        assert_eq!(plan.planned_entries.len(), 1);
        assert!(matches!(
            plan.planned_entries[0],
            PlannedEntry::SdJwtPlan(_)
        ));
        assert_eq!(plan.estimated_total_ms, config.sd_jwt_budget_ms);
    }

    #[test]
    fn test_validate_proof_request_bbs() {
        let store = TestCredentialStore::new();
        store.add(make_bbs_cred("bbs_cred"));

        let request = ProofRequest {
            request_id: "req_002".into(),
            domain_binding: make_binding(300),
            requested_disclosures: vec![make_bbs_disclosure()],
            time_budget: TimeBudget::new(500),
        };

        let config = ProofEngineConfig::default();
        let plan = validate_proof_request(&config, &request, &store).unwrap();

        assert_eq!(plan.planned_entries.len(), 1);
        assert!(matches!(plan.planned_entries[0], PlannedEntry::BbsPlan(_)));
    }

    #[test]
    fn test_validate_proof_request_range() {
        let store = TestCredentialStore::new();
        store.add(make_sd_jwt_cred("sd_cred"));

        let request = ProofRequest {
            request_id: "req_003".into(),
            domain_binding: make_binding(300),
            requested_disclosures: vec![make_range_disclosure()],
            time_budget: TimeBudget::new(500),
        };

        let config = ProofEngineConfig::default();
        let plan = validate_proof_request(&config, &request, &store).unwrap();

        assert_eq!(plan.planned_entries.len(), 1);
        assert!(matches!(
            plan.planned_entries[0],
            PlannedEntry::RangePlan(_)
        ));
    }

    #[test]
    fn test_validate_proof_request_mixed() {
        let store = TestCredentialStore::new();
        store.add(make_sd_jwt_cred("sd_cred"));
        store.add(make_bbs_cred("bbs_cred"));

        let request = ProofRequest {
            request_id: "req_004".into(),
            domain_binding: make_binding(300),
            requested_disclosures: vec![
                make_sd_jwt_disclosure(),
                make_bbs_disclosure(),
                make_range_disclosure(),
            ],
            time_budget: TimeBudget::new(5000),
        };

        let config = ProofEngineConfig::default();
        let plan = validate_proof_request(&config, &request, &store).unwrap();

        assert_eq!(plan.planned_entries.len(), 3);
        assert_eq!(
            plan.estimated_total_ms,
            config.sd_jwt_budget_ms + config.bbs_budget_ms + config.range_proof_budget_ms
        );
    }

    #[test]
    fn test_validate_proof_request_credential_not_found() {
        let store = TestCredentialStore::new();
        // Don't add the credential

        let request = ProofRequest {
            request_id: "req_005".into(),
            domain_binding: make_binding(300),
            requested_disclosures: vec![make_sd_jwt_disclosure()],
            time_budget: TimeBudget::new(500),
        };

        let config = ProofEngineConfig::default();
        let result = validate_proof_request(&config, &request, &store);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::CredentialNotFound(_)
        ));
    }

    #[test]
    fn test_validate_proof_request_type_mismatch() {
        let store = TestCredentialStore::new();
        // Add a BBS+ cred but try SD-JWT disclosure against it
        store.add(CachedCredential {
            handle: "sd_cred".into(), // Same handle as SD-JWT disclosure expects
            format: CredentialFormat::Bbs,
            claims: vec!["name".into()],
            raw_data: vec![],
            expires_at: None,
            total_claim_count: 3,
        });

        let request = ProofRequest {
            request_id: "req_006".into(),
            domain_binding: make_binding(300),
            requested_disclosures: vec![make_sd_jwt_disclosure()],
            time_budget: TimeBudget::new(500),
        };

        let config = ProofEngineConfig::default();
        let result = validate_proof_request(&config, &request, &store);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::CredentialTypeMismatch(_)
        ));
    }

    #[test]
    fn test_validate_proof_request_invalid_claim_path() {
        let store = TestCredentialStore::new();
        store.add(make_sd_jwt_cred("sd_cred"));

        let request = ProofRequest {
            request_id: "req_007".into(),
            domain_binding: make_binding(300),
            requested_disclosures: vec![DisclosureRequest::SelectiveDisclosure(
                SdJwtDisclosureRequest {
                    credential_handle: "sd_cred".into(),
                    claim_paths: RevealedClaims::new(vec!["nonexistent".into()]).unwrap(),
                },
            )],
            time_budget: TimeBudget::new(500),
        };

        let config = ProofEngineConfig::default();
        let result = validate_proof_request(&config, &request, &store);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::InvalidClaimPath(_)
        ));
    }

    #[test]
    fn test_validate_proof_request_domain_expired() {
        let store = TestCredentialStore::new();
        store.add(make_sd_jwt_cred("sd_cred"));

        let request = ProofRequest {
            request_id: "req_008".into(),
            domain_binding: DomainBinding {
                relying_party: RpIdentifier::Origin("https://example.com".into()),
                nonce: Nonce::generate(),
                issued_at: Timestamp::from_seconds(1000),
                expires_at: Timestamp::from_seconds(1001),
            },
            requested_disclosures: vec![make_sd_jwt_disclosure()],
            time_budget: TimeBudget::new(500),
        };

        let config = ProofEngineConfig::default();
        let result = validate_proof_request(&config, &request, &store);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::DomainBindingExpired
        ));
    }

    #[test]
    fn test_validate_proof_request_budget_exceeded() {
        let store = TestCredentialStore::new();
        store.add(make_sd_jwt_cred("sd_cred"));
        store.add(make_bbs_cred("bbs_cred"));

        let request = ProofRequest {
            request_id: "req_009".into(),
            domain_binding: make_binding(300),
            requested_disclosures: vec![
                make_sd_jwt_disclosure(),
                make_bbs_disclosure(),
                make_range_disclosure(),
            ],
            time_budget: TimeBudget::new(10), // Way too small for 3 proofs
        };

        let config = ProofEngineConfig::default();
        let result = validate_proof_request(&config, &request, &store);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::TimeBudgetExceeded
        ));
    }

    #[test]
    fn test_validate_proof_request_invalid_range_predicate() {
        let store = TestCredentialStore::new();
        store.add(make_sd_jwt_cred("sd_cred"));

        let witness = PedersenWitness::new(30, [0x42; 32]);
        let commitment = witness.compute_commitment();
        let request = ProofRequest {
            request_id: "req_010".into(),
            domain_binding: make_binding(300),
            requested_disclosures: vec![DisclosureRequest::RangeAssertion(
                RangeDisclosureRequest {
                    credential_handle: "sd_cred".into(),
                    attribute_name: "age".into(),
                    predicate: Predicate::InRange(65, 18), // Invalid
                    witness,
                    commitment,
                },
            )],
            time_budget: TimeBudget::new(500),
        };

        let config = ProofEngineConfig::default();
        let result = validate_proof_request(&config, &request, &store);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::InvalidPredicate(_)
        ));
    }

    #[test]
    fn test_validate_proof_request_full_disclosure_sd_jwt() {
        let store = TestCredentialStore::new();
        store.add(CachedCredential {
            handle: "sd_cred".into(),
            format: CredentialFormat::SdJwt,
            claims: vec!["name".into(), "age".into()],
            raw_data: b"jwt".to_vec(),
            expires_at: None,
            total_claim_count: 2,
        });

        let request = ProofRequest {
            request_id: "req_011".into(),
            domain_binding: make_binding(300),
            requested_disclosures: vec![DisclosureRequest::SelectiveDisclosure(
                SdJwtDisclosureRequest {
                    credential_handle: "sd_cred".into(),
                    claim_paths: RevealedClaims::new(vec!["name".into(), "age".into()]).unwrap(),
                },
            )],
            time_budget: TimeBudget::new(500),
        };

        let config = ProofEngineConfig::default();
        let result = validate_proof_request(&config, &request, &store);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::FullDisclosurePrevented(_)
        ));
    }

    #[test]
    fn test_validate_proof_request_expired_credential() {
        let store = TestCredentialStore::new();
        store.add(CachedCredential {
            handle: "sd_cred".into(),
            format: CredentialFormat::SdJwt,
            claims: vec!["name".into()],
            raw_data: b"jwt".to_vec(),
            expires_at: Some(Timestamp::from_seconds(1000)),
            total_claim_count: 3,
        });

        let request = ProofRequest {
            request_id: "req_012".into(),
            domain_binding: make_binding(300),
            requested_disclosures: vec![make_sd_jwt_disclosure()],
            time_budget: TimeBudget::new(500),
        };

        let config = ProofEngineConfig::default();
        let result = validate_proof_request(&config, &request, &store);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::CredentialExpired(_)
        ));
    }
}
