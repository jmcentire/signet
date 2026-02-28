use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use signet_core::{DomainBinding, PedersenCommitment, RpIdentifier, TimeBudget, Timestamp};

// ---------------------------------------------------------------------------
// Predicate -- range assertion for Bulletproof range proofs
// ---------------------------------------------------------------------------

/// Range predicate for Bulletproof range proofs. Defines the assertion to be
/// proven about a committed value without revealing the value itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Predicate {
    /// Value >= threshold
    Gte(u64),
    /// Value <= threshold
    Lte(u64),
    /// lower <= value <= upper
    InRange(u64, u64),
}

impl Predicate {
    /// Validate that the predicate is well-formed.
    pub fn validate(&self) -> bool {
        match self {
            Predicate::Gte(_) | Predicate::Lte(_) => true,
            Predicate::InRange(lower, upper) => lower < upper,
        }
    }

    /// Check if a value satisfies this predicate.
    pub fn is_satisfied_by(&self, value: u64) -> bool {
        match self {
            Predicate::Gte(threshold) => value >= *threshold,
            Predicate::Lte(threshold) => value <= *threshold,
            Predicate::InRange(lower, upper) => value >= *lower && value <= *upper,
        }
    }
}

// ---------------------------------------------------------------------------
// RevealedClaims -- newtype preventing accidental full-credential leakage
// ---------------------------------------------------------------------------

/// Newtype wrapper around a list of claim paths to selectively disclose.
/// Prevents accidental full-credential leakage by requiring explicit construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevealedClaims {
    pub paths: Vec<String>,
}

impl RevealedClaims {
    /// Create a new RevealedClaims, enforcing at least one path.
    pub fn new(paths: Vec<String>) -> Result<Self, &'static str> {
        if paths.is_empty() {
            return Err("RevealedClaims must contain at least one claim path");
        }
        Ok(Self { paths })
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

// ---------------------------------------------------------------------------
// PedersenWitness -- secret material for range proofs (Zeroizing)
// ---------------------------------------------------------------------------

/// Witness for a Pedersen commitment: the secret value and blinding factor.
/// Both fields are zeroized on drop. Debug impl fully redacts.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PedersenWitness {
    pub value: u64,
    pub blinding_factor: [u8; 32],
}

impl fmt::Debug for PedersenWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PedersenWitness")
            .field("value", &"[REDACTED]")
            .field("blinding_factor", &"[REDACTED]")
            .finish()
    }
}

impl PedersenWitness {
    pub fn new(value: u64, blinding_factor: [u8; 32]) -> Self {
        Self {
            value,
            blinding_factor,
        }
    }

    /// Compute the Pedersen commitment for this witness.
    /// Uses SHA-256(value || blinding_factor) as a simulated commitment.
    /// In production this would use actual Ristretto/curve25519 math.
    pub fn compute_commitment(&self) -> PedersenCommitment {
        let mut hasher = Sha256::new();
        hasher.update(self.value.to_le_bytes());
        hasher.update(self.blinding_factor);
        let hash = hasher.finalize();
        let mut commitment_bytes = [0u8; 32];
        commitment_bytes.copy_from_slice(&hash);
        PedersenCommitment { commitment_bytes }
    }
}

// ---------------------------------------------------------------------------
// SD-JWT presentation
// ---------------------------------------------------------------------------

/// An SD-JWT selective disclosure presentation in compact serialization format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdJwtPresentation {
    /// SD-JWT presentation in compact serialization format (tilde-delimited).
    pub compact_serialization: String,
    /// List of claim names that were disclosed in this presentation.
    pub disclosed_claim_names: Vec<String>,
    /// The domain binding this presentation is bound to.
    pub domain_binding: DomainBinding,
}

// ---------------------------------------------------------------------------
// BBS+ proof
// ---------------------------------------------------------------------------

/// A BBS+ unlinkable zero-knowledge proof. Nonce is generated internally and
/// embedded. Two presentations of the same credential are computationally unlinkable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BbsProof {
    /// Serialized BBS+ proof of knowledge.
    pub proof_bytes: Vec<u8>,
    /// Indices of messages disclosed in the proof.
    pub disclosed_indices: Vec<usize>,
    /// The domain binding this proof is bound to.
    pub domain_binding: DomainBinding,
    /// SHA-256 hash of the internally-generated nonce (for audit, not the nonce itself).
    pub embedded_nonce_hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// Range proof entry
// ---------------------------------------------------------------------------

/// A Bulletproof range proof entry: proof that a committed value satisfies a
/// predicate without revealing the value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeProofEntry {
    /// Serialized Bulletproof range proof.
    pub proof_bytes: Vec<u8>,
    /// The Pedersen commitment the proof is about.
    pub commitment: PedersenCommitment,
    /// The predicate proven.
    pub predicate: Predicate,
    /// The domain binding this proof is bound to.
    pub domain_binding: DomainBinding,
}

// ---------------------------------------------------------------------------
// ProofEntry -- tagged union of proof types
// ---------------------------------------------------------------------------

/// Tagged union of proof types for composition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProofEntry {
    SdJwt(SdJwtPresentation),
    Bbs(BbsProof),
    Range(RangeProofEntry),
}

impl ProofEntry {
    /// Return the proof type name for audit purposes.
    pub fn proof_type_name(&self) -> &'static str {
        match self {
            ProofEntry::SdJwt(_) => "sd-jwt",
            ProofEntry::Bbs(_) => "bbs+",
            ProofEntry::Range(_) => "bulletproof",
        }
    }
}

// ---------------------------------------------------------------------------
// Disclosure request types
// ---------------------------------------------------------------------------

/// Request for SD-JWT selective disclosure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdJwtDisclosureRequest {
    pub credential_handle: String,
    pub claim_paths: RevealedClaims,
}

/// Request for BBS+ unlinkable proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BbsDisclosureRequest {
    pub credential_handle: String,
    pub disclosed_indices: Vec<usize>,
}

/// Request for Bulletproof range proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeDisclosureRequest {
    pub credential_handle: String,
    pub attribute_name: String,
    pub predicate: Predicate,
    pub witness: PedersenWitness,
    pub commitment: PedersenCommitment,
}

/// A single disclosure request in a proof request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DisclosureRequest {
    SelectiveDisclosure(SdJwtDisclosureRequest),
    UnlinkableProof(BbsDisclosureRequest),
    RangeAssertion(RangeDisclosureRequest),
}

// ---------------------------------------------------------------------------
// ProofRequest -- typestate stage 1
// ---------------------------------------------------------------------------

/// Typestate stage 1: Incoming proof request from a relying party.
/// Parsed and validated but not yet planned. Immutable after construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRequest {
    pub request_id: String,
    pub domain_binding: DomainBinding,
    pub requested_disclosures: Vec<DisclosureRequest>,
    pub time_budget: TimeBudget,
}

// ---------------------------------------------------------------------------
// Planned entry types (resolved and validated)
// ---------------------------------------------------------------------------

/// Resolved SD-JWT proof plan with cached credential data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedSdJwtPlan {
    pub credential_handle: String,
    pub revealed_claims: RevealedClaims,
    pub estimated_ms: u64,
}

/// Resolved BBS+ proof plan with cached credential data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedBbsPlan {
    pub credential_handle: String,
    pub disclosed_indices: Vec<usize>,
    pub estimated_ms: u64,
}

/// Resolved Bulletproof range proof plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedRangePlan {
    pub credential_handle: String,
    pub attribute_name: String,
    pub predicate: Predicate,
    pub witness: PedersenWitness,
    pub commitment: PedersenCommitment,
    pub estimated_ms: u64,
}

/// A resolved, validated proof generation plan entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlannedEntry {
    SdJwtPlan(ResolvedSdJwtPlan),
    BbsPlan(ResolvedBbsPlan),
    RangePlan(ResolvedRangePlan),
}

// ---------------------------------------------------------------------------
// ProofPlan -- typestate stage 2
// ---------------------------------------------------------------------------

/// Typestate stage 2: A validated and resolved plan for proof generation.
/// All credential handles have been resolved, all predicates validated,
/// and the time budget has been checked for feasibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofPlan {
    pub request_id: String,
    pub domain_binding: DomainBinding,
    pub planned_entries: Vec<PlannedEntry>,
    pub remaining_budget: TimeBudget,
    pub estimated_total_ms: u64,
}

// ---------------------------------------------------------------------------
// ProofBundle -- typestate stage 3
// ---------------------------------------------------------------------------

/// Typestate stage 3: All individual proofs have been generated but not yet
/// composed into a bound presentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBundle {
    pub request_id: String,
    pub domain_binding: DomainBinding,
    pub entries: Vec<ProofEntry>,
    pub remaining_budget: TimeBudget,
}

// ---------------------------------------------------------------------------
// BoundPresentation -- typestate stage 4 (terminal)
// ---------------------------------------------------------------------------

/// Typestate stage 4: A fully composed, domain-bound, time-limited presentation
/// ready for transmission to the relying party. Serialized as deterministic CBOR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundPresentation {
    pub request_id: String,
    pub domain_binding: DomainBinding,
    pub entries: Vec<ProofEntry>,
    pub cbor_encoded: Vec<u8>,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
}

// ---------------------------------------------------------------------------
// ClaimSummary -- for audit
// ---------------------------------------------------------------------------

/// Summary of a disclosed claim for audit purposes. Contains the claim name
/// and proof type but never the claim value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimSummary {
    pub credential_handle: String,
    pub claim_name: String,
    pub proof_type: String,
}

// ---------------------------------------------------------------------------
// AuditManifest -- co-produced with every BoundPresentation
// ---------------------------------------------------------------------------

/// Audit record co-produced with every BoundPresentation. Records what was
/// disclosed, to whom, and when. Written to the audit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditManifest {
    pub request_id: String,
    pub rp_identifier: RpIdentifier,
    pub disclosed_claim_summary: Vec<ClaimSummary>,
    pub proof_types_used: Vec<String>,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub presentation_hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// PresentationWithAudit -- composite return type
// ---------------------------------------------------------------------------

/// Composite return type co-producing a BoundPresentation with its AuditManifest.
/// Ensures no presentation can be created without a corresponding audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationWithAudit {
    pub presentation: BoundPresentation,
    pub audit_manifest: AuditManifest,
}

// ---------------------------------------------------------------------------
// BatchRangeRequest -- batched Bulletproof range proof generation
// ---------------------------------------------------------------------------

/// A single entry in a batch range proof request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRangeEntry {
    pub attribute_name: String,
    pub predicate: Predicate,
    pub witness: PedersenWitness,
    pub commitment: PedersenCommitment,
}

/// Request for batched Bulletproof range proof generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRangeRequest {
    pub entries: Vec<BatchRangeEntry>,
    pub domain_binding: DomainBinding,
}

// ---------------------------------------------------------------------------
// ProofEngineConfig -- configuration for the ProofEngine
// ---------------------------------------------------------------------------

/// Configuration for the ProofEngine. Immutable after construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofEngineConfig {
    /// Default time-to-live for generated proofs in seconds (10..=3600).
    pub default_ttl_seconds: u64,
    /// Minimum remaining TTL required on domain binding before proof generation (1..=60).
    pub minimum_remaining_ttl_seconds: u64,
    /// Per-proof time budget estimate for SD-JWT derivation in ms.
    pub sd_jwt_budget_ms: u64,
    /// Per-proof time budget estimate for BBS+ proof generation in ms.
    pub bbs_budget_ms: u64,
    /// Per-proof time budget estimate for Bulletproof range proof in ms.
    pub range_proof_budget_ms: u64,
    /// Maximum number of proof entries in a single composite presentation (1..=64).
    pub max_proofs_per_presentation: usize,
}

impl Default for ProofEngineConfig {
    fn default() -> Self {
        Self {
            default_ttl_seconds: 300,
            minimum_remaining_ttl_seconds: 5,
            sd_jwt_budget_ms: 20,
            bbs_budget_ms: 20,
            range_proof_budget_ms: 200,
            max_proofs_per_presentation: 16,
        }
    }
}

impl ProofEngineConfig {
    /// Validate configuration constraints.
    pub fn validate(&self) -> Result<(), String> {
        if self.default_ttl_seconds < 10 || self.default_ttl_seconds > 3600 {
            return Err("default_ttl_seconds must be between 10 and 3600".into());
        }
        if self.minimum_remaining_ttl_seconds < 1 || self.minimum_remaining_ttl_seconds > 60 {
            return Err("minimum_remaining_ttl_seconds must be between 1 and 60".into());
        }
        if self.max_proofs_per_presentation < 1 || self.max_proofs_per_presentation > 64 {
            return Err("max_proofs_per_presentation must be between 1 and 64".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CredentialFormat -- what kind of credential a handle refers to
// ---------------------------------------------------------------------------

/// The format of a cached credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialFormat {
    SdJwt,
    Bbs,
}

// ---------------------------------------------------------------------------
// CachedCredential -- a resolved credential from the store
// ---------------------------------------------------------------------------

/// A credential resolved from the cache. Contains the data needed for
/// proof generation. The `claims` list represents available claim paths
/// (for SD-JWT) or message count (for BBS+).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedCredential {
    pub handle: String,
    pub format: CredentialFormat,
    /// Available claim paths for SD-JWT, or indexed message names for BBS+.
    pub claims: Vec<String>,
    /// For SD-JWT: the compact serialized issuer JWT with all disclosures.
    /// For BBS+: the serialized BBS+ signature and messages.
    pub raw_data: Vec<u8>,
    /// When this credential expires, if ever.
    pub expires_at: Option<Timestamp>,
    /// Total number of messages/claims in the credential.
    pub total_claim_count: usize,
}

// ---------------------------------------------------------------------------
// CredentialStore -- trait for resolving credential handles
// ---------------------------------------------------------------------------

/// Trait for resolving credential handles to cached credentials.
/// In production, this would be backed by signet-cred's credential cache.
pub trait CredentialStore: Send + Sync {
    fn resolve(&self, handle: &str) -> Option<CachedCredential>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use signet_core::Nonce;

    #[test]
    fn test_predicate_validate() {
        assert!(Predicate::Gte(21).validate());
        assert!(Predicate::Lte(100).validate());
        assert!(Predicate::InRange(18, 65).validate());
        assert!(!Predicate::InRange(65, 18).validate());
        assert!(!Predicate::InRange(10, 10).validate());
    }

    #[test]
    fn test_predicate_is_satisfied_by() {
        assert!(Predicate::Gte(21).is_satisfied_by(21));
        assert!(Predicate::Gte(21).is_satisfied_by(30));
        assert!(!Predicate::Gte(21).is_satisfied_by(20));

        assert!(Predicate::Lte(100).is_satisfied_by(50));
        assert!(Predicate::Lte(100).is_satisfied_by(100));
        assert!(!Predicate::Lte(100).is_satisfied_by(101));

        assert!(Predicate::InRange(18, 65).is_satisfied_by(30));
        assert!(Predicate::InRange(18, 65).is_satisfied_by(18));
        assert!(Predicate::InRange(18, 65).is_satisfied_by(65));
        assert!(!Predicate::InRange(18, 65).is_satisfied_by(17));
        assert!(!Predicate::InRange(18, 65).is_satisfied_by(66));
    }

    #[test]
    fn test_revealed_claims_new_valid() {
        let rc = RevealedClaims::new(vec!["name".into(), "age".into()]).unwrap();
        assert_eq!(rc.len(), 2);
        assert!(!rc.is_empty());
    }

    #[test]
    fn test_revealed_claims_new_empty() {
        let rc = RevealedClaims::new(vec![]);
        assert!(rc.is_err());
    }

    #[test]
    fn test_pedersen_witness_debug_redacts() {
        let w = PedersenWitness::new(42, [0xAB; 32]);
        let debug = format!("{:?}", w);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("42"));
        assert!(!debug.contains("ab"));
    }

    #[test]
    fn test_pedersen_witness_compute_commitment_deterministic() {
        let w1 = PedersenWitness::new(100, [0x01; 32]);
        let w2 = PedersenWitness::new(100, [0x01; 32]);
        assert_eq!(w1.compute_commitment(), w2.compute_commitment());
    }

    #[test]
    fn test_pedersen_witness_different_values_different_commitments() {
        let w1 = PedersenWitness::new(100, [0x01; 32]);
        let w2 = PedersenWitness::new(200, [0x01; 32]);
        assert_ne!(
            w1.compute_commitment().commitment_bytes,
            w2.compute_commitment().commitment_bytes
        );
    }

    #[test]
    fn test_pedersen_witness_different_blinding_different_commitments() {
        let w1 = PedersenWitness::new(100, [0x01; 32]);
        let w2 = PedersenWitness::new(100, [0x02; 32]);
        assert_ne!(
            w1.compute_commitment().commitment_bytes,
            w2.compute_commitment().commitment_bytes
        );
    }

    #[test]
    fn test_proof_entry_type_name() {
        let now = Timestamp::now();
        let binding = DomainBinding {
            relying_party: RpIdentifier::Origin("https://example.com".into()),
            nonce: Nonce::generate(),
            issued_at: now,
            expires_at: Timestamp::from_seconds(now.seconds_since_epoch + 300),
        };

        let sd = ProofEntry::SdJwt(SdJwtPresentation {
            compact_serialization: "test".into(),
            disclosed_claim_names: vec!["name".into()],
            domain_binding: binding.clone(),
        });
        assert_eq!(sd.proof_type_name(), "sd-jwt");

        let bbs = ProofEntry::Bbs(BbsProof {
            proof_bytes: vec![0u8; 64],
            disclosed_indices: vec![0],
            domain_binding: binding.clone(),
            embedded_nonce_hash: [0u8; 32],
        });
        assert_eq!(bbs.proof_type_name(), "bbs+");

        let range = ProofEntry::Range(RangeProofEntry {
            proof_bytes: vec![0u8; 64],
            commitment: PedersenCommitment {
                commitment_bytes: [0u8; 32],
            },
            predicate: Predicate::Gte(21),
            domain_binding: binding,
        });
        assert_eq!(range.proof_type_name(), "bulletproof");
    }

    #[test]
    fn test_proof_engine_config_default() {
        let config = ProofEngineConfig::default();
        assert_eq!(config.default_ttl_seconds, 300);
        assert_eq!(config.minimum_remaining_ttl_seconds, 5);
        assert_eq!(config.sd_jwt_budget_ms, 20);
        assert_eq!(config.bbs_budget_ms, 20);
        assert_eq!(config.range_proof_budget_ms, 200);
        assert_eq!(config.max_proofs_per_presentation, 16);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_proof_engine_config_validate() {
        let mut config = ProofEngineConfig::default();

        config.default_ttl_seconds = 5;
        assert!(config.validate().is_err());

        config.default_ttl_seconds = 300;
        config.minimum_remaining_ttl_seconds = 0;
        assert!(config.validate().is_err());

        config.minimum_remaining_ttl_seconds = 5;
        config.max_proofs_per_presentation = 0;
        assert!(config.validate().is_err());

        config.max_proofs_per_presentation = 65;
        assert!(config.validate().is_err());

        config.max_proofs_per_presentation = 16;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_credential_format_equality() {
        assert_eq!(CredentialFormat::SdJwt, CredentialFormat::SdJwt);
        assert_ne!(CredentialFormat::SdJwt, CredentialFormat::Bbs);
    }

    #[test]
    fn test_claim_summary() {
        let cs = ClaimSummary {
            credential_handle: "cred_1".into(),
            claim_name: "age".into(),
            proof_type: "sd-jwt".into(),
        };
        assert_eq!(cs.claim_name, "age");
        assert_eq!(cs.proof_type, "sd-jwt");
    }

    #[test]
    fn test_pedersen_witness_zeroize_on_drop() {
        let blinding = [0xAB; 32];
        let w = PedersenWitness::new(42, blinding);
        // Just confirm it can be dropped without panic
        drop(w);
    }

    #[test]
    fn test_disclosure_request_variants() {
        let sd = DisclosureRequest::SelectiveDisclosure(SdJwtDisclosureRequest {
            credential_handle: "h1".into(),
            claim_paths: RevealedClaims::new(vec!["name".into()]).unwrap(),
        });
        assert!(matches!(sd, DisclosureRequest::SelectiveDisclosure(_)));

        let bbs = DisclosureRequest::UnlinkableProof(BbsDisclosureRequest {
            credential_handle: "h2".into(),
            disclosed_indices: vec![0, 1],
        });
        assert!(matches!(bbs, DisclosureRequest::UnlinkableProof(_)));

        let range = DisclosureRequest::RangeAssertion(RangeDisclosureRequest {
            credential_handle: "h3".into(),
            attribute_name: "income".into(),
            predicate: Predicate::Gte(50000),
            witness: PedersenWitness::new(75000, [0x01; 32]),
            commitment: PedersenWitness::new(75000, [0x01; 32]).compute_commitment(),
        });
        assert!(matches!(range, DisclosureRequest::RangeAssertion(_)));
    }

    #[test]
    fn test_proof_request_construction() {
        let now = Timestamp::now();
        let req = ProofRequest {
            request_id: "req_001".into(),
            domain_binding: DomainBinding {
                relying_party: RpIdentifier::Origin("https://shop.example.com".into()),
                nonce: Nonce::generate(),
                issued_at: now,
                expires_at: Timestamp::from_seconds(now.seconds_since_epoch + 300),
            },
            requested_disclosures: vec![DisclosureRequest::SelectiveDisclosure(
                SdJwtDisclosureRequest {
                    credential_handle: "cred_sd_1".into(),
                    claim_paths: RevealedClaims::new(vec!["age".into()]).unwrap(),
                },
            )],
            time_budget: TimeBudget::new(500),
        };
        assert_eq!(req.request_id, "req_001");
        assert_eq!(req.requested_disclosures.len(), 1);
    }
}
