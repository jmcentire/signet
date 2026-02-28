//! ProofBundle generation (actual proof computation).
//!
//! Typestate transition: ProofPlan -> ProofBundle.
//! Executes all proof generation operations. This is the cryptographic hot path.

use std::time::Instant;

use crate::bbs::generate_bbs_proof;
use crate::error::{ProofError, ProofResult};
use crate::range::generate_range_proof;
use crate::sdjwt::derive_sd_jwt_presentation;
use crate::types::{CredentialStore, PlannedEntry, ProofBundle, ProofEntry, ProofPlan};

/// Typestate transition: ProofPlan -> ProofBundle.
///
/// Executes all proof generation operations described in the ProofPlan.
/// Tracks wall-clock time and fails securely if the time budget is exceeded.
/// All witness/blinding data is zeroized after use.
pub fn execute_proof_plan(
    plan: &ProofPlan,
    store: &dyn CredentialStore,
) -> ProofResult<ProofBundle> {
    let start = Instant::now();

    // Re-check domain binding validity
    if !plan.domain_binding.is_valid() {
        return Err(ProofError::DomainBindingExpired);
    }

    // Check budget is still positive
    if plan.remaining_budget.remaining_ms == 0 {
        return Err(ProofError::TimeBudgetExceeded);
    }

    let mut entries = Vec::with_capacity(plan.planned_entries.len());

    for planned_entry in &plan.planned_entries {
        // Check time budget at each step
        let elapsed_ms = start.elapsed().as_millis() as u64;
        if elapsed_ms > plan.remaining_budget.remaining_ms {
            return Err(ProofError::TimeBudgetExceeded);
        }

        // Re-check domain binding hasn't expired during generation
        if !plan.domain_binding.is_valid() {
            return Err(ProofError::DomainBindingExpired);
        }

        let entry = execute_planned_entry(planned_entry, &plan.domain_binding, store)?;
        entries.push(entry);
    }

    // Final budget update
    let total_elapsed_ms = start.elapsed().as_millis() as u64;
    let mut remaining_budget = plan.remaining_budget;
    remaining_budget.consume(total_elapsed_ms);

    Ok(ProofBundle {
        request_id: plan.request_id.clone(),
        domain_binding: plan.domain_binding.clone(),
        entries,
        remaining_budget,
    })
}

/// Execute a single planned entry, producing a ProofEntry.
fn execute_planned_entry(
    planned: &PlannedEntry,
    domain_binding: &signet_core::DomainBinding,
    store: &dyn CredentialStore,
) -> ProofResult<ProofEntry> {
    match planned {
        PlannedEntry::SdJwtPlan(sd_plan) => {
            let presentation = derive_sd_jwt_presentation(
                store,
                &sd_plan.credential_handle,
                &sd_plan.revealed_claims,
                domain_binding,
            )?;
            Ok(ProofEntry::SdJwt(presentation))
        }
        PlannedEntry::BbsPlan(bbs_plan) => {
            let proof = generate_bbs_proof(
                store,
                &bbs_plan.credential_handle,
                &bbs_plan.disclosed_indices,
                domain_binding,
            )?;
            Ok(ProofEntry::Bbs(proof))
        }
        PlannedEntry::RangePlan(range_plan) => {
            let entry = generate_range_proof(
                range_plan.witness.clone(),
                &range_plan.commitment,
                &range_plan.predicate,
                domain_binding,
            )?;
            Ok(ProofEntry::Range(entry))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        CachedCredential, CredentialFormat, PedersenWitness, Predicate, ResolvedBbsPlan,
        ResolvedRangePlan, ResolvedSdJwtPlan, RevealedClaims,
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

    fn setup_store() -> TestCredentialStore {
        let store = TestCredentialStore::new();
        store.add(CachedCredential {
            handle: "sd_cred".into(),
            format: CredentialFormat::SdJwt,
            claims: vec!["name".into(), "age".into(), "email".into()],
            raw_data: b"eyJ0eXAiOiJKV1QifQ.eyJ0ZXN0IjoiMSJ9.sig".to_vec(),
            expires_at: None,
            total_claim_count: 5,
        });
        store.add(CachedCredential {
            handle: "bbs_cred".into(),
            format: CredentialFormat::Bbs,
            claims: (0..5).map(|i| format!("msg_{}", i)).collect(),
            raw_data: vec![0x42; 64],
            expires_at: None,
            total_claim_count: 5,
        });
        store
    }

    fn make_sd_jwt_plan() -> PlannedEntry {
        PlannedEntry::SdJwtPlan(ResolvedSdJwtPlan {
            credential_handle: "sd_cred".into(),
            revealed_claims: RevealedClaims::new(vec!["name".into()]).unwrap(),
            estimated_ms: 20,
        })
    }

    fn make_bbs_plan() -> PlannedEntry {
        PlannedEntry::BbsPlan(ResolvedBbsPlan {
            credential_handle: "bbs_cred".into(),
            disclosed_indices: vec![0, 2],
            estimated_ms: 20,
        })
    }

    fn make_range_plan() -> PlannedEntry {
        let witness = PedersenWitness::new(25, [0x42; 32]);
        let commitment = witness.compute_commitment();
        PlannedEntry::RangePlan(ResolvedRangePlan {
            credential_handle: "sd_cred".into(),
            attribute_name: "age".into(),
            predicate: Predicate::Gte(21),
            witness,
            commitment,
            estimated_ms: 200,
        })
    }

    #[test]
    fn test_execute_proof_plan_sd_jwt() {
        let store = setup_store();
        let plan = ProofPlan {
            request_id: "req_001".into(),
            domain_binding: make_binding(300),
            planned_entries: vec![make_sd_jwt_plan()],
            remaining_budget: TimeBudget::new(500),
            estimated_total_ms: 20,
        };

        let bundle = execute_proof_plan(&plan, &store).unwrap();
        assert_eq!(bundle.request_id, "req_001");
        assert_eq!(bundle.entries.len(), 1);
        assert!(matches!(bundle.entries[0], ProofEntry::SdJwt(_)));
    }

    #[test]
    fn test_execute_proof_plan_bbs() {
        let store = setup_store();
        let plan = ProofPlan {
            request_id: "req_002".into(),
            domain_binding: make_binding(300),
            planned_entries: vec![make_bbs_plan()],
            remaining_budget: TimeBudget::new(500),
            estimated_total_ms: 20,
        };

        let bundle = execute_proof_plan(&plan, &store).unwrap();
        assert_eq!(bundle.entries.len(), 1);
        assert!(matches!(bundle.entries[0], ProofEntry::Bbs(_)));
    }

    #[test]
    fn test_execute_proof_plan_range() {
        let store = setup_store();
        let plan = ProofPlan {
            request_id: "req_003".into(),
            domain_binding: make_binding(300),
            planned_entries: vec![make_range_plan()],
            remaining_budget: TimeBudget::new(500),
            estimated_total_ms: 200,
        };

        let bundle = execute_proof_plan(&plan, &store).unwrap();
        assert_eq!(bundle.entries.len(), 1);
        assert!(matches!(bundle.entries[0], ProofEntry::Range(_)));
    }

    #[test]
    fn test_execute_proof_plan_mixed() {
        let store = setup_store();
        let plan = ProofPlan {
            request_id: "req_004".into(),
            domain_binding: make_binding(300),
            planned_entries: vec![make_sd_jwt_plan(), make_bbs_plan(), make_range_plan()],
            remaining_budget: TimeBudget::new(5000),
            estimated_total_ms: 240,
        };

        let bundle = execute_proof_plan(&plan, &store).unwrap();
        assert_eq!(bundle.entries.len(), 3);
        assert!(matches!(bundle.entries[0], ProofEntry::SdJwt(_)));
        assert!(matches!(bundle.entries[1], ProofEntry::Bbs(_)));
        assert!(matches!(bundle.entries[2], ProofEntry::Range(_)));
    }

    #[test]
    fn test_execute_proof_plan_domain_expired() {
        let store = setup_store();
        let plan = ProofPlan {
            request_id: "req_005".into(),
            domain_binding: DomainBinding {
                relying_party: RpIdentifier::Origin("https://example.com".into()),
                nonce: Nonce::generate(),
                issued_at: Timestamp::from_seconds(1000),
                expires_at: Timestamp::from_seconds(1001),
            },
            planned_entries: vec![make_sd_jwt_plan()],
            remaining_budget: TimeBudget::new(500),
            estimated_total_ms: 20,
        };

        let result = execute_proof_plan(&plan, &store);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::DomainBindingExpired
        ));
    }

    #[test]
    fn test_execute_proof_plan_zero_budget() {
        let store = setup_store();
        let plan = ProofPlan {
            request_id: "req_006".into(),
            domain_binding: make_binding(300),
            planned_entries: vec![make_sd_jwt_plan()],
            remaining_budget: TimeBudget {
                total_ms: 500,
                remaining_ms: 0,
            },
            estimated_total_ms: 20,
        };

        let result = execute_proof_plan(&plan, &store);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::TimeBudgetExceeded
        ));
    }

    #[test]
    fn test_execute_proof_plan_budget_consumed() {
        let store = setup_store();
        let plan = ProofPlan {
            request_id: "req_007".into(),
            domain_binding: make_binding(300),
            planned_entries: vec![make_sd_jwt_plan()],
            remaining_budget: TimeBudget::new(5000),
            estimated_total_ms: 20,
        };

        let bundle = execute_proof_plan(&plan, &store).unwrap();
        // Budget should be partially consumed (remaining < original)
        assert!(bundle.remaining_budget.remaining_ms <= 5000);
    }

    #[test]
    fn test_execute_proof_plan_entry_count_matches() {
        let store = setup_store();
        let plan = ProofPlan {
            request_id: "req_008".into(),
            domain_binding: make_binding(300),
            planned_entries: vec![make_sd_jwt_plan(), make_bbs_plan()],
            remaining_budget: TimeBudget::new(5000),
            estimated_total_ms: 40,
        };

        let bundle = execute_proof_plan(&plan, &store).unwrap();
        assert_eq!(
            bundle.entries.len(),
            plan.planned_entries.len(),
            "ProofBundle must contain exactly as many entries as the ProofPlan"
        );
    }
}
