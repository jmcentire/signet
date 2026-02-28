//! Proof composition: combining multiple proofs into a single presentation.
//!
//! Typestate transition: ProofBundle -> PresentationWithAudit.
//! Composes all proof entries into a single BoundPresentation with deterministic
//! CBOR-like serialization. Co-produces an AuditManifest.

use sha2::{Digest, Sha256};

use signet_core::Timestamp;

use crate::error::{ProofError, ProofResult};
use crate::types::{
    AuditManifest, BoundPresentation, ClaimSummary, PresentationWithAudit, ProofBundle,
    ProofEngineConfig, ProofEntry,
};

/// Typestate transition: ProofBundle -> PresentationWithAudit.
///
/// Composes all proof entries into a single BoundPresentation with deterministic
/// serialization. Co-produces an AuditManifest recording what was disclosed.
pub fn compose_presentation(
    config: &ProofEngineConfig,
    bundle: &ProofBundle,
) -> ProofResult<PresentationWithAudit> {
    // Check budget
    if bundle.remaining_budget.remaining_ms == 0 {
        return Err(ProofError::TimeBudgetExceeded);
    }

    // Check domain binding validity
    if !bundle.domain_binding.is_valid() {
        return Err(ProofError::DomainBindingExpired);
    }

    // Check minimum remaining TTL
    let now = Timestamp::now();
    let remaining_seconds = bundle
        .domain_binding
        .expires_at
        .seconds_since_epoch
        .saturating_sub(now.seconds_since_epoch);

    if remaining_seconds < config.minimum_remaining_ttl_seconds {
        return Err(ProofError::MinimumTtlViolation(format!(
            "remaining TTL {}s < minimum {}s",
            remaining_seconds, config.minimum_remaining_ttl_seconds
        )));
    }

    // Verify entries is non-empty
    if bundle.entries.is_empty() {
        return Err(ProofError::CompositionFailed(
            "proof bundle has no entries".into(),
        ));
    }

    // Serialize to deterministic CBOR-like format
    let cbor_encoded = serialize_deterministic(&bundle.entries)?;

    // Compute presentation timestamps
    let created_at = Timestamp::now();
    let expires_at = bundle.domain_binding.expires_at;

    // Build the BoundPresentation
    let presentation = BoundPresentation {
        request_id: bundle.request_id.clone(),
        domain_binding: bundle.domain_binding.clone(),
        entries: bundle.entries.clone(),
        cbor_encoded: cbor_encoded.clone(),
        created_at,
        expires_at,
    };

    // Compute presentation hash for audit
    let presentation_hash = {
        let hash = Sha256::digest(&cbor_encoded);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        bytes
    };

    // Build claim summaries for audit
    let disclosed_claim_summary = build_claim_summaries(&bundle.entries);

    // Collect proof types used
    let mut proof_types_used: Vec<String> = bundle
        .entries
        .iter()
        .map(|e| e.proof_type_name().to_string())
        .collect();
    proof_types_used.dedup();

    // Build audit manifest
    let audit_manifest = AuditManifest {
        request_id: bundle.request_id.clone(),
        rp_identifier: bundle.domain_binding.relying_party.clone(),
        disclosed_claim_summary,
        proof_types_used,
        issued_at: created_at,
        expires_at,
        presentation_hash,
    };

    Ok(PresentationWithAudit {
        presentation,
        audit_manifest,
    })
}

/// Serialize proof entries into a deterministic CBOR-like byte format.
///
/// Uses a canonical JSON serialization as the deterministic encoding.
/// In production this would use ciborium with canonical mode.
fn serialize_deterministic(entries: &[ProofEntry]) -> ProofResult<Vec<u8>> {
    // Use serde_json with sorted keys as a deterministic serialization format.
    // This mirrors the canonical CBOR requirement from the contract.
    let json = serde_json::to_vec(entries).map_err(|_| ProofError::CborSerializationFailed)?;
    Ok(json)
}

/// Build claim summaries from proof entries for audit.
fn build_claim_summaries(entries: &[ProofEntry]) -> Vec<ClaimSummary> {
    let mut summaries = Vec::new();

    for entry in entries {
        match entry {
            ProofEntry::SdJwt(sd_jwt) => {
                for claim_name in &sd_jwt.disclosed_claim_names {
                    summaries.push(ClaimSummary {
                        credential_handle: "sd-jwt-credential".into(),
                        claim_name: claim_name.clone(),
                        proof_type: "sd-jwt".into(),
                    });
                }
            }
            ProofEntry::Bbs(bbs) => {
                for &idx in &bbs.disclosed_indices {
                    summaries.push(ClaimSummary {
                        credential_handle: "bbs-credential".into(),
                        claim_name: format!("message_{}", idx),
                        proof_type: "bbs+".into(),
                    });
                }
            }
            ProofEntry::Range(range) => {
                summaries.push(ClaimSummary {
                    credential_handle: "range-credential".into(),
                    claim_name: format!("range_proof({:?})", range.predicate),
                    proof_type: "bulletproof".into(),
                });
            }
        }
    }

    summaries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BbsProof, Predicate, RangeProofEntry, SdJwtPresentation};
    use signet_core::{DomainBinding, Nonce, PedersenCommitment, RpIdentifier, TimeBudget};

    fn make_binding(ttl: u64) -> DomainBinding {
        let now = Timestamp::now();
        DomainBinding {
            relying_party: RpIdentifier::Origin("https://example.com".into()),
            nonce: Nonce::generate(),
            issued_at: Timestamp::from_seconds(now.seconds_since_epoch.saturating_sub(1)),
            expires_at: Timestamp::from_seconds(now.seconds_since_epoch + ttl),
        }
    }

    fn make_sd_jwt_entry(binding: &DomainBinding) -> ProofEntry {
        ProofEntry::SdJwt(SdJwtPresentation {
            compact_serialization: "header.payload.sig~disc1~kb_jwt".into(),
            disclosed_claim_names: vec!["name".into(), "age".into()],
            domain_binding: binding.clone(),
        })
    }

    fn make_bbs_entry(binding: &DomainBinding) -> ProofEntry {
        ProofEntry::Bbs(BbsProof {
            proof_bytes: vec![0x42; 128],
            disclosed_indices: vec![0, 2],
            domain_binding: binding.clone(),
            embedded_nonce_hash: [0xAA; 32],
        })
    }

    fn make_range_entry(binding: &DomainBinding) -> ProofEntry {
        ProofEntry::Range(RangeProofEntry {
            proof_bytes: vec![0x55; 160],
            commitment: PedersenCommitment {
                commitment_bytes: [0x01; 32],
            },
            predicate: Predicate::Gte(21),
            domain_binding: binding.clone(),
        })
    }

    #[test]
    fn test_compose_presentation_single_sd_jwt() {
        let binding = make_binding(300);
        let config = ProofEngineConfig::default();

        let bundle = ProofBundle {
            request_id: "req_001".into(),
            domain_binding: binding.clone(),
            entries: vec![make_sd_jwt_entry(&binding)],
            remaining_budget: TimeBudget::new(500),
        };

        let result = compose_presentation(&config, &bundle).unwrap();

        assert_eq!(result.presentation.request_id, "req_001");
        assert_eq!(result.presentation.entries.len(), 1);
        assert!(!result.presentation.cbor_encoded.is_empty());
        assert_eq!(result.audit_manifest.request_id, "req_001");
        assert!(!result.audit_manifest.disclosed_claim_summary.is_empty());
    }

    #[test]
    fn test_compose_presentation_mixed_proofs() {
        let binding = make_binding(300);
        let config = ProofEngineConfig::default();

        let bundle = ProofBundle {
            request_id: "req_002".into(),
            domain_binding: binding.clone(),
            entries: vec![
                make_sd_jwt_entry(&binding),
                make_bbs_entry(&binding),
                make_range_entry(&binding),
            ],
            remaining_budget: TimeBudget::new(5000),
        };

        let result = compose_presentation(&config, &bundle).unwrap();

        assert_eq!(result.presentation.entries.len(), 3);
        // Check audit manifest
        assert!(result
            .audit_manifest
            .proof_types_used
            .contains(&"sd-jwt".to_string()));
        assert!(result
            .audit_manifest
            .proof_types_used
            .contains(&"bbs+".to_string()));
        assert!(result
            .audit_manifest
            .proof_types_used
            .contains(&"bulletproof".to_string()));
    }

    #[test]
    fn test_compose_presentation_hash_is_sha256_of_cbor() {
        let binding = make_binding(300);
        let config = ProofEngineConfig::default();

        let bundle = ProofBundle {
            request_id: "req_003".into(),
            domain_binding: binding.clone(),
            entries: vec![make_sd_jwt_entry(&binding)],
            remaining_budget: TimeBudget::new(500),
        };

        let result = compose_presentation(&config, &bundle).unwrap();

        // Verify the presentation hash matches SHA-256 of cbor_encoded
        let expected_hash = Sha256::digest(&result.presentation.cbor_encoded);
        assert_eq!(
            &result.audit_manifest.presentation_hash[..],
            &expected_hash[..],
            "AuditManifest.presentation_hash must equal SHA-256(BoundPresentation.cbor_encoded)"
        );
    }

    #[test]
    fn test_compose_presentation_audit_claim_summaries() {
        let binding = make_binding(300);
        let config = ProofEngineConfig::default();

        let bundle = ProofBundle {
            request_id: "req_004".into(),
            domain_binding: binding.clone(),
            entries: vec![make_sd_jwt_entry(&binding)],
            remaining_budget: TimeBudget::new(500),
        };

        let result = compose_presentation(&config, &bundle).unwrap();

        // SD-JWT with "name" and "age" disclosed should produce 2 claim summaries
        assert_eq!(result.audit_manifest.disclosed_claim_summary.len(), 2);
        assert_eq!(
            result.audit_manifest.disclosed_claim_summary[0].claim_name,
            "name"
        );
        assert_eq!(
            result.audit_manifest.disclosed_claim_summary[1].claim_name,
            "age"
        );
    }

    #[test]
    fn test_compose_presentation_audit_rp_matches() {
        let binding = make_binding(300);
        let config = ProofEngineConfig::default();

        let bundle = ProofBundle {
            request_id: "req_005".into(),
            domain_binding: binding.clone(),
            entries: vec![make_sd_jwt_entry(&binding)],
            remaining_budget: TimeBudget::new(500),
        };

        let result = compose_presentation(&config, &bundle).unwrap();

        // RP identifier in audit must match domain binding
        match (&result.audit_manifest.rp_identifier, &binding.relying_party) {
            (RpIdentifier::Origin(a), RpIdentifier::Origin(b)) => assert_eq!(a, b),
            (RpIdentifier::Did(a), RpIdentifier::Did(b)) => assert_eq!(a, b),
            _ => panic!("RP identifier mismatch"),
        }
    }

    #[test]
    fn test_compose_presentation_domain_expired() {
        let config = ProofEngineConfig::default();

        let binding = DomainBinding {
            relying_party: RpIdentifier::Origin("https://example.com".into()),
            nonce: Nonce::generate(),
            issued_at: Timestamp::from_seconds(1000),
            expires_at: Timestamp::from_seconds(1001),
        };

        let bundle = ProofBundle {
            request_id: "req_006".into(),
            domain_binding: binding.clone(),
            entries: vec![make_sd_jwt_entry(&binding)],
            remaining_budget: TimeBudget::new(500),
        };

        let result = compose_presentation(&config, &bundle);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::DomainBindingExpired
        ));
    }

    #[test]
    fn test_compose_presentation_zero_budget() {
        let binding = make_binding(300);
        let config = ProofEngineConfig::default();

        let bundle = ProofBundle {
            request_id: "req_007".into(),
            domain_binding: binding.clone(),
            entries: vec![make_sd_jwt_entry(&binding)],
            remaining_budget: TimeBudget {
                total_ms: 500,
                remaining_ms: 0,
            },
        };

        let result = compose_presentation(&config, &bundle);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::TimeBudgetExceeded
        ));
    }

    #[test]
    fn test_compose_presentation_empty_entries() {
        let binding = make_binding(300);
        let config = ProofEngineConfig::default();

        let bundle = ProofBundle {
            request_id: "req_008".into(),
            domain_binding: binding,
            entries: vec![],
            remaining_budget: TimeBudget::new(500),
        };

        let result = compose_presentation(&config, &bundle);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::CompositionFailed(_)
        ));
    }

    #[test]
    fn test_compose_presentation_minimum_ttl_violation() {
        let binding = make_binding(2); // Only 2 seconds remaining
        let config = ProofEngineConfig {
            minimum_remaining_ttl_seconds: 10, // Requires 10 seconds
            ..ProofEngineConfig::default()
        };

        let bundle = ProofBundle {
            request_id: "req_009".into(),
            domain_binding: binding.clone(),
            entries: vec![make_sd_jwt_entry(&binding)],
            remaining_budget: TimeBudget::new(500),
        };

        let result = compose_presentation(&config, &bundle);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::MinimumTtlViolation(_)
        ));
    }

    #[test]
    fn test_compose_presentation_expires_at_from_domain() {
        let binding = make_binding(300);
        let config = ProofEngineConfig::default();

        let bundle = ProofBundle {
            request_id: "req_010".into(),
            domain_binding: binding.clone(),
            entries: vec![make_sd_jwt_entry(&binding)],
            remaining_budget: TimeBudget::new(500),
        };

        let result = compose_presentation(&config, &bundle).unwrap();

        // Expires at should match domain binding
        assert_eq!(
            result.presentation.expires_at, binding.expires_at,
            "BoundPresentation.expires_at should be domain_binding.expires_at"
        );
    }

    #[test]
    fn test_deterministic_serialization() {
        let binding = make_binding(300);

        let entries1 = vec![make_sd_jwt_entry(&binding)];
        let entries2 = vec![make_sd_jwt_entry(&binding)];

        let ser1 = serialize_deterministic(&entries1).unwrap();
        let ser2 = serialize_deterministic(&entries2).unwrap();

        assert_eq!(
            ser1, ser2,
            "Identical entries must produce identical serialization"
        );
    }

    #[test]
    fn test_claim_summary_no_actual_values() {
        let binding = make_binding(300);
        let entries = vec![make_sd_jwt_entry(&binding)];

        let summaries = build_claim_summaries(&entries);

        for summary in &summaries {
            // Summaries must not contain actual claim values
            assert_ne!(summary.claim_name, "John Doe");
            assert_ne!(summary.claim_name, "25");
            // Should be the claim path name, not the value
            assert!(
                summary.claim_name == "name" || summary.claim_name == "age",
                "unexpected claim name: {}",
                summary.claim_name
            );
        }
    }

    #[test]
    fn test_compose_presentation_audit_timestamps_match() {
        let binding = make_binding(300);
        let config = ProofEngineConfig::default();

        let bundle = ProofBundle {
            request_id: "req_011".into(),
            domain_binding: binding.clone(),
            entries: vec![make_sd_jwt_entry(&binding)],
            remaining_budget: TimeBudget::new(500),
        };

        let result = compose_presentation(&config, &bundle).unwrap();

        // Audit timestamps should match presentation
        assert_eq!(
            result.audit_manifest.issued_at,
            result.presentation.created_at
        );
        assert_eq!(
            result.audit_manifest.expires_at,
            result.presentation.expires_at
        );
    }
}
