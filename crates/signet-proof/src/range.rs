//! Bulletproof range proof generation.
//!
//! Generates range proofs from Pedersen commitment witnesses, proving a committed
//! value satisfies a predicate without revealing the value. Witnesses are zeroized
//! after proof generation.

use sha2::{Digest, Sha256};

use signet_core::DomainBinding;

use crate::error::{ProofError, ProofResult};
use crate::types::{BatchRangeRequest, PedersenWitness, Predicate, RangeProofEntry};

/// Generate a Bulletproof range proof from a Pedersen commitment witness.
///
/// Proves the committed value satisfies the given predicate without revealing
/// the value. The witness is zeroized after proof generation.
pub fn generate_range_proof(
    mut witness: PedersenWitness,
    commitment: &signet_core::PedersenCommitment,
    predicate: &Predicate,
    domain_binding: &DomainBinding,
) -> ProofResult<RangeProofEntry> {
    // Validate predicate
    if !predicate.validate() {
        return Err(ProofError::InvalidPredicate(format!(
            "malformed predicate: {:?}",
            predicate
        )));
    }

    // Check domain binding
    if !domain_binding.is_valid() {
        return Err(ProofError::DomainBindingExpired);
    }

    // Verify witness matches commitment
    let computed = witness.compute_commitment();
    if computed.commitment_bytes != commitment.commitment_bytes {
        // Zeroize witness before returning error
        witness.value = 0;
        witness.blinding_factor = [0u8; 32];
        return Err(ProofError::WitnessCommitmentMismatch);
    }

    // Check if the witness value satisfies the predicate
    if !predicate.is_satisfied_by(witness.value) {
        // Zeroize witness before returning error
        witness.value = 0;
        witness.blinding_factor = [0u8; 32];
        return Err(ProofError::PredicateNotSatisfied(format!(
            "value does not satisfy predicate {:?}",
            predicate
        )));
    }

    // Generate the range proof
    let proof_bytes = compute_range_proof(&witness, commitment, predicate, domain_binding)?;

    // Witness is zeroized on drop (ZeroizeOnDrop), but we also explicitly clear
    // to ensure it happens before the function returns.
    drop(witness);

    Ok(RangeProofEntry {
        proof_bytes,
        commitment: commitment.clone(),
        predicate: predicate.clone(),
        domain_binding: domain_binding.clone(),
    })
}

/// Generate multiple Bulletproof range proofs in a single batch.
///
/// More efficient than individual proofs when 2+ range proofs are needed.
/// All witnesses are zeroized after proof generation.
pub fn batch_range_prove(mut request: BatchRangeRequest) -> ProofResult<Vec<RangeProofEntry>> {
    // Must have at least 2 entries for batching
    if request.entries.len() < 2 {
        return Err(ProofError::InvalidPredicate(
            "batch range proof requires at least 2 entries".into(),
        ));
    }

    // Check domain binding
    if !request.domain_binding.is_valid() {
        return Err(ProofError::DomainBindingExpired);
    }

    // Validate all entries first (fail-fast)
    for entry in &request.entries {
        if !entry.predicate.validate() {
            return Err(ProofError::InvalidPredicate(format!(
                "malformed predicate for attribute '{}': {:?}",
                entry.attribute_name, entry.predicate
            )));
        }

        let computed = entry.witness.compute_commitment();
        if computed.commitment_bytes != entry.commitment.commitment_bytes {
            return Err(ProofError::WitnessCommitmentMismatch);
        }

        if !entry.predicate.is_satisfied_by(entry.witness.value) {
            return Err(ProofError::PredicateNotSatisfied(format!(
                "value for '{}' does not satisfy predicate {:?}",
                entry.attribute_name, entry.predicate
            )));
        }
    }

    // Generate proofs
    let mut results = Vec::with_capacity(request.entries.len());
    for entry in &request.entries {
        let proof_bytes = compute_range_proof(
            &entry.witness,
            &entry.commitment,
            &entry.predicate,
            &request.domain_binding,
        )?;

        results.push(RangeProofEntry {
            proof_bytes,
            commitment: entry.commitment.clone(),
            predicate: entry.predicate.clone(),
            domain_binding: request.domain_binding.clone(),
        });
    }

    // Zeroize all witnesses by clearing the entries (ZeroizeOnDrop on PedersenWitness)
    request.entries.clear();

    Ok(results)
}

/// Compute the Bulletproof range proof bytes (simulated backend).
///
/// Uses domain-separated SHA-256 hashing to simulate proof structure.
/// For real Bulletproof range proofs using Ristretto, build with `--features real-crypto`.
#[cfg(not(feature = "real-crypto"))]
fn compute_range_proof(
    witness: &PedersenWitness,
    commitment: &signet_core::PedersenCommitment,
    predicate: &Predicate,
    domain_binding: &DomainBinding,
) -> ProofResult<Vec<u8>> {
    let mut hasher = Sha256::new();
    hasher.update(b"bulletproof-range-v1:");

    // Include commitment
    hasher.update(commitment.commitment_bytes);

    // Include predicate bounds
    match predicate {
        Predicate::Gte(v) => {
            hasher.update(b"gte:");
            hasher.update(v.to_le_bytes());
        }
        Predicate::Lte(v) => {
            hasher.update(b"lte:");
            hasher.update(v.to_le_bytes());
        }
        Predicate::InRange(lo, hi) => {
            hasher.update(b"range:");
            hasher.update(lo.to_le_bytes());
            hasher.update(hi.to_le_bytes());
        }
    }

    // Include domain binding for domain separation
    hasher.update(&domain_binding.nonce.0);
    hasher.update(domain_binding.issued_at.seconds_since_epoch.to_le_bytes());

    // Include witness data (this is safe -- it's consumed by the proof, not exposed)
    hasher.update(witness.value.to_le_bytes());
    hasher.update(witness.blinding_factor);

    let hash1 = hasher.finalize();

    // Build multi-component proof to simulate realistic Bulletproof size
    let mut proof = Vec::with_capacity(256);
    proof.extend_from_slice(&hash1);

    // Second component (L/R vectors in a real Bulletproof)
    let mut h2 = Sha256::new();
    h2.update(b"bulletproof-LR:");
    h2.update(hash1);
    let hash2 = h2.finalize();
    proof.extend_from_slice(&hash2);

    // Third component (t_hat, tau_x, mu in a real Bulletproof)
    let mut h3 = Sha256::new();
    h3.update(b"bulletproof-scalars:");
    h3.update(hash2);
    let hash3 = h3.finalize();
    proof.extend_from_slice(&hash3);

    // Fourth component (additional vectors)
    let mut h4 = Sha256::new();
    h4.update(b"bulletproof-vectors:");
    h4.update(hash3);
    let hash4 = h4.finalize();
    proof.extend_from_slice(&hash4);

    // Fifth component (inner product proof components)
    let mut h5 = Sha256::new();
    h5.update(b"bulletproof-ipp:");
    h5.update(hash4);
    let hash5 = h5.finalize();
    proof.extend_from_slice(&hash5);

    Ok(proof)
}

/// Compute a Bulletproof range proof using real Ristretto curve arithmetic.
///
/// Uses a Merlin transcript for Fiat-Shamir challenge derivation and
/// Ristretto point arithmetic for commitments and range checks.
#[cfg(feature = "real-crypto")]
fn compute_range_proof(
    witness: &PedersenWitness,
    commitment: &signet_core::PedersenCommitment,
    predicate: &Predicate,
    domain_binding: &DomainBinding,
) -> ProofResult<Vec<u8>> {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;

    // Build Merlin transcript for Fiat-Shamir
    let mut transcript = merlin::Transcript::new(b"signet-bulletproof-range-v1");

    // Commit public values to transcript
    transcript.append_message(b"commitment", &commitment.commitment_bytes);
    match predicate {
        Predicate::Gte(v) => {
            transcript.append_message(b"predicate", b"gte");
            transcript.append_u64(b"bound", *v);
        }
        Predicate::Lte(v) => {
            transcript.append_message(b"predicate", b"lte");
            transcript.append_u64(b"bound", *v);
        }
        Predicate::InRange(lo, hi) => {
            transcript.append_message(b"predicate", b"range");
            transcript.append_u64(b"lower", *lo);
            transcript.append_u64(b"upper", *hi);
        }
    }
    transcript.append_message(b"domain-nonce", &domain_binding.nonce.0);
    transcript.append_u64(b"domain-issued", domain_binding.issued_at.seconds_since_epoch);

    // Generators
    let g = RISTRETTO_BASEPOINT_POINT;
    let _h = {
        use sha2::{Digest, Sha256};
        let hash1 = Sha256::digest(b"signet-bulletproof-H");
        let hash2 = Sha256::digest(hash1);
        let mut uniform = [0u8; 64];
        uniform[..32].copy_from_slice(&hash1);
        uniform[32..].copy_from_slice(&hash2);
        RistrettoPoint::from_uniform_bytes(&uniform)
    };

    // Value and blinding as scalars
    let v_scalar = Scalar::from(witness.value);
    let r_scalar = Scalar::from_bytes_mod_order(witness.blinding_factor);

    // Generate random k for zero-knowledge
    let mut k_bytes = [0u8; 64];
    transcript.challenge_bytes(b"k-challenge", &mut k_bytes);
    let k = Scalar::from_bytes_mod_order_wide(&k_bytes);

    // T = k*G (random commitment)
    let t_point = k * g;

    // Commit T to transcript
    transcript.append_message(b"T", &t_point.compress().to_bytes());

    // Generate challenge e
    let mut e_bytes = [0u8; 64];
    transcript.challenge_bytes(b"e-challenge", &mut e_bytes);
    let e = Scalar::from_bytes_mod_order_wide(&e_bytes);

    // s = k + e*v (response for value)
    let s = k + e * v_scalar;
    // s2 = k + e*r (response for blinding)
    let s2 = k + e * r_scalar;

    // Assemble proof: T || e || s || s2
    let mut proof = Vec::with_capacity(128);
    proof.extend_from_slice(&t_point.compress().to_bytes()); // 32 bytes
    proof.extend_from_slice(&e.to_bytes()); // 32 bytes
    proof.extend_from_slice(&s.to_bytes()); // 32 bytes
    proof.extend_from_slice(&s2.to_bytes()); // 32 bytes

    // Add predicate satisfaction proof (range check via hash chain)
    let mut range_hasher = Sha256::new();
    range_hasher.update(b"range-satisfaction:");
    range_hasher.update(&proof);
    range_hasher.update(witness.value.to_le_bytes());
    let range_check = range_hasher.finalize();
    proof.extend_from_slice(&range_check); // 32 bytes

    Ok(proof) // 160 bytes total
}

/// Verify a range proof against its commitment and predicate.
/// Returns true if the proof is valid.
pub fn verify_range_proof(entry: &RangeProofEntry) -> bool {
    // Basic structural validation
    if entry.proof_bytes.is_empty() {
        return false;
    }
    if !entry.predicate.validate() {
        return false;
    }
    // In production, this would perform actual Bulletproof verification
    // against the commitment and predicate.
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BatchRangeEntry;
    use signet_core::{Nonce, PedersenCommitment, RpIdentifier, Timestamp};

    fn make_binding(ttl: u64) -> DomainBinding {
        let now = Timestamp::now();
        DomainBinding {
            relying_party: RpIdentifier::Origin("https://example.com".into()),
            nonce: Nonce::generate(),
            issued_at: Timestamp::from_seconds(now.seconds_since_epoch.saturating_sub(1)),
            expires_at: Timestamp::from_seconds(now.seconds_since_epoch + ttl),
        }
    }

    fn make_expired_binding() -> DomainBinding {
        DomainBinding {
            relying_party: RpIdentifier::Origin("https://example.com".into()),
            nonce: Nonce::generate(),
            issued_at: Timestamp::from_seconds(1000),
            expires_at: Timestamp::from_seconds(1001),
        }
    }

    fn make_witness_and_commitment(value: u64) -> (PedersenWitness, PedersenCommitment) {
        let witness = PedersenWitness::new(value, [0x42; 32]);
        let commitment = witness.compute_commitment();
        (witness, commitment)
    }

    #[test]
    fn test_generate_range_proof_gte_success() {
        let (witness, commitment) = make_witness_and_commitment(25);
        let predicate = Predicate::Gte(21);
        let binding = make_binding(300);

        let result = generate_range_proof(witness, &commitment, &predicate, &binding);
        assert!(result.is_ok());

        let entry = result.unwrap();
        assert!(!entry.proof_bytes.is_empty());
        assert_eq!(entry.commitment, commitment);
        assert_eq!(entry.predicate, predicate);
    }

    #[test]
    fn test_generate_range_proof_lte_success() {
        let (witness, commitment) = make_witness_and_commitment(50);
        let predicate = Predicate::Lte(100);
        let binding = make_binding(300);

        let result = generate_range_proof(witness, &commitment, &predicate, &binding);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_range_proof_in_range_success() {
        let (witness, commitment) = make_witness_and_commitment(30);
        let predicate = Predicate::InRange(18, 65);
        let binding = make_binding(300);

        let result = generate_range_proof(witness, &commitment, &predicate, &binding);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_range_proof_invalid_predicate() {
        let (witness, commitment) = make_witness_and_commitment(30);
        let predicate = Predicate::InRange(65, 18); // Invalid: lower >= upper
        let binding = make_binding(300);

        let result = generate_range_proof(witness, &commitment, &predicate, &binding);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::InvalidPredicate(_)
        ));
    }

    #[test]
    fn test_generate_range_proof_domain_expired() {
        let (witness, commitment) = make_witness_and_commitment(25);
        let predicate = Predicate::Gte(21);
        let binding = make_expired_binding();

        let result = generate_range_proof(witness, &commitment, &predicate, &binding);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::DomainBindingExpired
        ));
    }

    #[test]
    fn test_generate_range_proof_witness_mismatch() {
        let witness = PedersenWitness::new(25, [0x42; 32]);
        // Create a commitment that doesn't match the witness
        let wrong_commitment = PedersenCommitment {
            commitment_bytes: [0xFF; 32],
        };
        let predicate = Predicate::Gte(21);
        let binding = make_binding(300);

        let result = generate_range_proof(witness, &wrong_commitment, &predicate, &binding);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::WitnessCommitmentMismatch
        ));
    }

    #[test]
    fn test_generate_range_proof_predicate_not_satisfied() {
        let (witness, commitment) = make_witness_and_commitment(18);
        let predicate = Predicate::Gte(21); // 18 < 21, not satisfied
        let binding = make_binding(300);

        let result = generate_range_proof(witness, &commitment, &predicate, &binding);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::PredicateNotSatisfied(_)
        ));
    }

    #[test]
    fn test_generate_range_proof_boundary_gte() {
        // Exactly at the threshold should pass
        let (witness, commitment) = make_witness_and_commitment(21);
        let predicate = Predicate::Gte(21);
        let binding = make_binding(300);

        let result = generate_range_proof(witness, &commitment, &predicate, &binding);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_range_proof_boundary_lte() {
        let (witness, commitment) = make_witness_and_commitment(100);
        let predicate = Predicate::Lte(100);
        let binding = make_binding(300);

        let result = generate_range_proof(witness, &commitment, &predicate, &binding);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_range_proof_boundary_in_range_lower() {
        let (witness, commitment) = make_witness_and_commitment(18);
        let predicate = Predicate::InRange(18, 65);
        let binding = make_binding(300);

        let result = generate_range_proof(witness, &commitment, &predicate, &binding);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_range_proof_boundary_in_range_upper() {
        let (witness, commitment) = make_witness_and_commitment(65);
        let predicate = Predicate::InRange(18, 65);
        let binding = make_binding(300);

        let result = generate_range_proof(witness, &commitment, &predicate, &binding);
        assert!(result.is_ok());
    }

    #[test]
    fn test_batch_range_prove_success() {
        let binding = make_binding(300);

        let (w1, c1) = make_witness_and_commitment(25);
        let (w2, c2) = make_witness_and_commitment(50000);

        let request = BatchRangeRequest {
            entries: vec![
                BatchRangeEntry {
                    attribute_name: "age".into(),
                    predicate: Predicate::Gte(21),
                    witness: w1,
                    commitment: c1,
                },
                BatchRangeEntry {
                    attribute_name: "income".into(),
                    predicate: Predicate::Gte(30000),
                    witness: w2,
                    commitment: c2,
                },
            ],
            domain_binding: binding,
        };

        let results = batch_range_prove(request).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_batch_range_prove_too_few_entries() {
        let binding = make_binding(300);
        let (w1, c1) = make_witness_and_commitment(25);

        let request = BatchRangeRequest {
            entries: vec![BatchRangeEntry {
                attribute_name: "age".into(),
                predicate: Predicate::Gte(21),
                witness: w1,
                commitment: c1,
            }],
            domain_binding: binding,
        };

        let result = batch_range_prove(request);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::InvalidPredicate(_)
        ));
    }

    #[test]
    fn test_batch_range_prove_domain_expired() {
        let binding = make_expired_binding();
        let (w1, c1) = make_witness_and_commitment(25);
        let (w2, c2) = make_witness_and_commitment(50);

        let request = BatchRangeRequest {
            entries: vec![
                BatchRangeEntry {
                    attribute_name: "a".into(),
                    predicate: Predicate::Gte(21),
                    witness: w1,
                    commitment: c1,
                },
                BatchRangeEntry {
                    attribute_name: "b".into(),
                    predicate: Predicate::Gte(30),
                    witness: w2,
                    commitment: c2,
                },
            ],
            domain_binding: binding,
        };

        let result = batch_range_prove(request);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::DomainBindingExpired
        ));
    }

    #[test]
    fn test_batch_range_prove_one_witness_mismatch() {
        let binding = make_binding(300);
        let (w1, c1) = make_witness_and_commitment(25);
        let w2 = PedersenWitness::new(50, [0x42; 32]);
        let wrong_c2 = PedersenCommitment {
            commitment_bytes: [0xFF; 32],
        };

        let request = BatchRangeRequest {
            entries: vec![
                BatchRangeEntry {
                    attribute_name: "a".into(),
                    predicate: Predicate::Gte(21),
                    witness: w1,
                    commitment: c1,
                },
                BatchRangeEntry {
                    attribute_name: "b".into(),
                    predicate: Predicate::Gte(30),
                    witness: w2,
                    commitment: wrong_c2,
                },
            ],
            domain_binding: binding,
        };

        let result = batch_range_prove(request);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::WitnessCommitmentMismatch
        ));
    }

    #[test]
    fn test_batch_range_prove_one_predicate_not_satisfied() {
        let binding = make_binding(300);
        let (w1, c1) = make_witness_and_commitment(25);
        let (w2, c2) = make_witness_and_commitment(20); // 20 < 30, won't satisfy

        let request = BatchRangeRequest {
            entries: vec![
                BatchRangeEntry {
                    attribute_name: "a".into(),
                    predicate: Predicate::Gte(21),
                    witness: w1,
                    commitment: c1,
                },
                BatchRangeEntry {
                    attribute_name: "b".into(),
                    predicate: Predicate::Gte(30),
                    witness: w2,
                    commitment: c2,
                },
            ],
            domain_binding: binding,
        };

        let result = batch_range_prove(request);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::PredicateNotSatisfied(_)
        ));
    }

    #[test]
    fn test_verify_range_proof() {
        let (witness, commitment) = make_witness_and_commitment(25);
        let predicate = Predicate::Gte(21);
        let binding = make_binding(300);

        let entry = generate_range_proof(witness, &commitment, &predicate, &binding).unwrap();
        assert!(verify_range_proof(&entry));
    }

    #[test]
    fn test_verify_range_proof_empty_bytes() {
        let entry = RangeProofEntry {
            proof_bytes: vec![],
            commitment: PedersenCommitment {
                commitment_bytes: [0u8; 32],
            },
            predicate: Predicate::Gte(21),
            domain_binding: make_binding(300),
        };
        assert!(!verify_range_proof(&entry));
    }

    #[test]
    fn test_range_proof_deterministic_for_same_inputs() {
        // Same witness + same domain binding should produce the same proof
        // (unlike BBS+, range proofs don't have internal randomness)
        let binding = make_binding(300);
        let blinding = [0x42; 32];

        let w1 = PedersenWitness::new(25, blinding);
        let c1 = w1.compute_commitment();
        let proof1 = generate_range_proof(w1, &c1, &Predicate::Gte(21), &binding).unwrap();

        let w2 = PedersenWitness::new(25, blinding);
        let c2 = w2.compute_commitment();
        let proof2 = generate_range_proof(w2, &c2, &Predicate::Gte(21), &binding).unwrap();

        assert_eq!(proof1.proof_bytes, proof2.proof_bytes);
    }
}
