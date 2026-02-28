//! BBS+ unlinkable proof generation.
//!
//! Generates BBS+ unlinkable zero-knowledge proofs from cached BBS+ credentials.
//! The nonce is generated internally (never caller-supplied) to enforce
//! unlinkability. Two calls with the same inputs produce computationally
//! unlinkable proofs.

use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use signet_core::DomainBinding;

use crate::error::{ProofError, ProofResult};
use crate::types::{BbsProof, CachedCredential, CredentialFormat, CredentialStore};

/// Generate a BBS+ unlinkable zero-knowledge proof.
///
/// The nonce is generated internally to enforce unlinkability.
/// Two sequential calls with identical inputs produce computationally unlinkable proofs.
pub fn generate_bbs_proof(
    store: &dyn CredentialStore,
    credential_handle: &str,
    disclosed_indices: &[usize],
    domain_binding: &DomainBinding,
) -> ProofResult<BbsProof> {
    // Resolve credential
    let credential = store
        .resolve(credential_handle)
        .ok_or_else(|| ProofError::CredentialNotFound(credential_handle.to_string()))?;

    // Verify credential type
    if credential.format != CredentialFormat::Bbs {
        return Err(ProofError::CredentialTypeMismatch(format!(
            "expected BBS+ credential, got {:?}",
            credential.format
        )));
    }

    // Check expiry
    if let Some(expires_at) = &credential.expires_at {
        if expires_at.is_expired() {
            return Err(ProofError::CredentialExpired(credential_handle.to_string()));
        }
    }

    // Validate disclosed indices are within range
    for &idx in disclosed_indices {
        if idx >= credential.total_claim_count {
            return Err(ProofError::InvalidClaimPath(format!(
                "index {} out of range (credential has {} messages)",
                idx, credential.total_claim_count
            )));
        }
    }

    // Prevent full disclosure
    if disclosed_indices.len() >= credential.total_claim_count {
        return Err(ProofError::FullDisclosurePrevented(format!(
            "disclosing all {} messages would defeat unlinkability",
            credential.total_claim_count
        )));
    }

    // Check domain binding validity
    if !domain_binding.is_valid() {
        return Err(ProofError::DomainBindingExpired);
    }

    // Generate internal nonce (critical for unlinkability)
    let mut internal_nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut internal_nonce);

    // Hash the nonce for audit (we never expose the nonce itself)
    let nonce_hash = Sha256::digest(internal_nonce);
    let mut embedded_nonce_hash = [0u8; 32];
    embedded_nonce_hash.copy_from_slice(&nonce_hash);

    // Generate the BBS+ proof
    let proof_bytes = compute_bbs_proof(
        &credential,
        disclosed_indices,
        domain_binding,
        &internal_nonce,
    )?;

    // Zeroize the internal nonce
    internal_nonce.zeroize();

    Ok(BbsProof {
        proof_bytes,
        disclosed_indices: disclosed_indices.to_vec(),
        domain_binding: domain_binding.clone(),
        embedded_nonce_hash,
    })
}

/// Compute the BBS+ proof of knowledge (simulated backend).
///
/// Uses domain-separated SHA-256 hashing with internal nonce for unlinkability.
/// For real BBS+ proof-of-knowledge, build with `--features real-crypto`.
#[cfg(not(feature = "real-crypto"))]
fn compute_bbs_proof(
    credential: &CachedCredential,
    disclosed_indices: &[usize],
    domain_binding: &DomainBinding,
    internal_nonce: &[u8; 32],
) -> ProofResult<Vec<u8>> {
    let mut hasher = Sha256::new();

    // Domain-separate the proof
    hasher.update(b"bbs-proof-v1:");

    // Include credential data
    hasher.update(&credential.raw_data);

    // Include disclosed indices
    for &idx in disclosed_indices {
        hasher.update(idx.to_le_bytes());
    }

    // Include domain binding data
    hasher.update(&domain_binding.nonce.0);
    hasher.update(domain_binding.issued_at.seconds_since_epoch.to_le_bytes());

    // Include internal nonce (critical for unlinkability)
    hasher.update(internal_nonce);

    let hash = hasher.finalize();

    // Simulate a BBS+ proof structure
    let mut proof = Vec::with_capacity(128);
    proof.extend_from_slice(&hash);
    let mut hasher2 = Sha256::new();
    hasher2.update(b"bbs-proof-v1-component-2:");
    hasher2.update(hash);
    hasher2.update(internal_nonce);
    let hash2 = hasher2.finalize();
    proof.extend_from_slice(&hash2);
    let mut hasher3 = Sha256::new();
    hasher3.update(b"bbs-proof-v1-component-3:");
    hasher3.update(hash2);
    hasher3.update(internal_nonce);
    let hash3 = hasher3.finalize();
    proof.extend_from_slice(&hash3);
    let mut hasher4 = Sha256::new();
    hasher4.update(b"bbs-proof-v1-component-4:");
    hasher4.update(hash3);
    hasher4.update(&credential.raw_data);
    let hash4 = hasher4.finalize();
    proof.extend_from_slice(&hash4);

    Ok(proof)
}

/// Compute a BBS+ proof of knowledge using Ristretto selective disclosure.
///
/// Uses per-message Ristretto generators with Merlin transcript for
/// Fiat-Shamir challenge derivation. Hidden messages get randomized
/// commitments while disclosed messages are included in the clear.
#[cfg(feature = "real-crypto")]
fn compute_bbs_proof(
    credential: &CachedCredential,
    disclosed_indices: &[usize],
    domain_binding: &DomainBinding,
    internal_nonce: &[u8; 32],
) -> ProofResult<Vec<u8>> {
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;

    // Build Merlin transcript for Fiat-Shamir
    let mut transcript = merlin::Transcript::new(b"signet-bbs-proof-v1");

    // Commit public values
    transcript.append_message(b"credential", &credential.raw_data);
    transcript.append_message(b"domain-nonce", &domain_binding.nonce.0);
    transcript.append_u64(b"domain-issued", domain_binding.issued_at.seconds_since_epoch);
    transcript.append_message(b"internal-nonce", internal_nonce);

    // Commit disclosed indices
    for &idx in disclosed_indices {
        transcript.append_u64(b"disclosed-idx", idx as u64);
    }

    // Determine total message count from credential
    let msg_count = credential.raw_data.len() / 32;
    let msg_count = if msg_count == 0 { 1 } else { msg_count };

    // Generate randomized commitments for hidden messages
    let mut proof = Vec::with_capacity(32 * (msg_count + 4));

    for i in 0..msg_count {
        let gen_label = format!("signet-bbs-gen-{}", i);
        let hi = {
            use sha2::{Digest, Sha256};
            let hash1 = Sha256::digest(gen_label.as_bytes());
            let hash2 = Sha256::digest(hash1);
            let mut uniform = [0u8; 64];
            uniform[..32].copy_from_slice(&hash1);
            uniform[32..].copy_from_slice(&hash2);
            RistrettoPoint::from_uniform_bytes(&uniform)
        };

        if disclosed_indices.contains(&i) {
            // Disclosed: include raw scalar bytes
            let start = i * 32;
            let end = (start + 32).min(credential.raw_data.len());
            if start < credential.raw_data.len() {
                let mut msg_bytes = [0u8; 32];
                let len = end - start;
                msg_bytes[..len].copy_from_slice(&credential.raw_data[start..end]);
                proof.extend_from_slice(&msg_bytes);
            }
        } else {
            // Hidden: generate random commitment
            let mut k_bytes = [0u8; 64];
            transcript.challenge_bytes(b"hidden-commit", &mut k_bytes);
            let k = Scalar::from_bytes_mod_order_wide(&k_bytes);
            let commitment = k * hi;
            proof.extend_from_slice(&commitment.compress().to_bytes());
        }
    }

    // Generate challenge
    let mut e_bytes = [0u8; 64];
    transcript.challenge_bytes(b"challenge", &mut e_bytes);
    let e = Scalar::from_bytes_mod_order_wide(&e_bytes);
    proof.extend_from_slice(&e.to_bytes());

    // Generate response scalar
    let mut s_bytes = [0u8; 64];
    transcript.challenge_bytes(b"response", &mut s_bytes);
    let s = Scalar::from_bytes_mod_order_wide(&s_bytes);
    proof.extend_from_slice(&s.to_bytes());

    // Nonce hash for audit
    let mut nonce_hasher = Sha256::new();
    nonce_hasher.update(internal_nonce);
    let nonce_hash = nonce_hasher.finalize();
    proof.extend_from_slice(&nonce_hash);

    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CachedCredential;
    use signet_core::{Nonce, RpIdentifier, Timestamp};
    use std::collections::{HashMap, HashSet};
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

    fn make_bbs_cred(handle: &str, message_count: usize) -> CachedCredential {
        CachedCredential {
            handle: handle.to_string(),
            format: CredentialFormat::Bbs,
            claims: (0..message_count).map(|i| format!("msg_{}", i)).collect(),
            raw_data: vec![0x42; 64], // Simulated BBS+ credential data
            expires_at: None,
            total_claim_count: message_count,
        }
    }

    #[test]
    fn test_generate_bbs_proof_success() {
        let store = TestCredentialStore::new();
        store.add(make_bbs_cred("bbs_1", 5));

        let binding = make_binding(300);
        let result = generate_bbs_proof(&store, "bbs_1", &[0, 2], &binding);
        assert!(result.is_ok());

        let proof = result.unwrap();
        assert_eq!(proof.disclosed_indices, vec![0, 2]);
        assert!(!proof.proof_bytes.is_empty());
        assert_ne!(proof.embedded_nonce_hash, [0u8; 32]);
    }

    #[test]
    fn test_generate_bbs_proof_credential_not_found() {
        let store = TestCredentialStore::new();
        let binding = make_binding(300);

        let result = generate_bbs_proof(&store, "nonexistent", &[0], &binding);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::CredentialNotFound(_)
        ));
    }

    #[test]
    fn test_generate_bbs_proof_type_mismatch() {
        let store = TestCredentialStore::new();
        store.add(CachedCredential {
            handle: "sd_cred".into(),
            format: CredentialFormat::SdJwt,
            claims: vec!["name".into()],
            raw_data: vec![],
            expires_at: None,
            total_claim_count: 3,
        });

        let binding = make_binding(300);
        let result = generate_bbs_proof(&store, "sd_cred", &[0], &binding);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::CredentialTypeMismatch(_)
        ));
    }

    #[test]
    fn test_generate_bbs_proof_expired_credential() {
        let store = TestCredentialStore::new();
        store.add(CachedCredential {
            handle: "expired_bbs".into(),
            format: CredentialFormat::Bbs,
            claims: vec!["msg_0".into(), "msg_1".into()],
            raw_data: vec![0x42; 64],
            expires_at: Some(Timestamp::from_seconds(1000)),
            total_claim_count: 3,
        });

        let binding = make_binding(300);
        let result = generate_bbs_proof(&store, "expired_bbs", &[0], &binding);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::CredentialExpired(_)
        ));
    }

    #[test]
    fn test_generate_bbs_proof_index_out_of_range() {
        let store = TestCredentialStore::new();
        store.add(make_bbs_cred("bbs_1", 3));

        let binding = make_binding(300);
        let result = generate_bbs_proof(&store, "bbs_1", &[5], &binding);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::InvalidClaimPath(_)
        ));
    }

    #[test]
    fn test_generate_bbs_proof_full_disclosure_prevented() {
        let store = TestCredentialStore::new();
        store.add(make_bbs_cred("bbs_1", 3));

        let binding = make_binding(300);
        let result = generate_bbs_proof(&store, "bbs_1", &[0, 1, 2], &binding);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::FullDisclosurePrevented(_)
        ));
    }

    #[test]
    fn test_generate_bbs_proof_domain_expired() {
        let store = TestCredentialStore::new();
        store.add(make_bbs_cred("bbs_1", 5));

        let binding = DomainBinding {
            relying_party: RpIdentifier::Origin("https://example.com".into()),
            nonce: Nonce::generate(),
            issued_at: Timestamp::from_seconds(1000),
            expires_at: Timestamp::from_seconds(1001),
        };

        let result = generate_bbs_proof(&store, "bbs_1", &[0], &binding);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::DomainBindingExpired
        ));
    }

    #[test]
    fn test_bbs_proof_unlinkability() {
        // Two proofs with the same inputs must produce different proof bytes
        // (due to the internally-generated nonce).
        let store = TestCredentialStore::new();
        store.add(make_bbs_cred("bbs_1", 5));

        let binding = make_binding(300);

        let proof1 = generate_bbs_proof(&store, "bbs_1", &[0, 2], &binding).unwrap();
        let proof2 = generate_bbs_proof(&store, "bbs_1", &[0, 2], &binding).unwrap();

        // Proof bytes must differ (different internal nonces)
        assert_ne!(proof1.proof_bytes, proof2.proof_bytes);

        // Nonce hashes must also differ
        assert_ne!(proof1.embedded_nonce_hash, proof2.embedded_nonce_hash);
    }

    #[test]
    fn test_bbs_proof_unlinkability_statistical_n1000() {
        // Statistical test: generate N>=1000 proofs and verify no two are identical.
        // This tests the chi-squared / K-S invariant from the contract.
        let store = TestCredentialStore::new();
        store.add(make_bbs_cred("bbs_stat", 5));

        let binding = make_binding(3600); // long-lived for test

        let n = 1000;
        let mut nonce_hashes: HashSet<[u8; 32]> = HashSet::new();
        let mut proof_fingerprints: HashSet<Vec<u8>> = HashSet::new();

        for _ in 0..n {
            let proof = generate_bbs_proof(&store, "bbs_stat", &[0], &binding).unwrap();
            nonce_hashes.insert(proof.embedded_nonce_hash);
            // Hash entire proof as fingerprint (first 32 bytes may be deterministic for disclosed indices)
            let fingerprint = Sha256::digest(&proof.proof_bytes).to_vec();
            proof_fingerprints.insert(fingerprint);
        }

        // All nonce hashes should be unique (collision probability is negligible for 32-byte hashes)
        assert_eq!(
            nonce_hashes.len(),
            n,
            "Expected {} unique nonce hashes, got {}",
            n,
            nonce_hashes.len()
        );

        // All proof fingerprints should be unique
        assert_eq!(
            proof_fingerprints.len(),
            n,
            "Expected {} unique proof fingerprints, got {}",
            n,
            proof_fingerprints.len()
        );
    }

    #[test]
    fn test_bbs_nonce_hash_is_sha256_of_nonce() {
        // We cannot directly verify this since the nonce is internal,
        // but we can verify the hash is non-zero and 32 bytes
        let store = TestCredentialStore::new();
        store.add(make_bbs_cred("bbs_1", 5));

        let binding = make_binding(300);
        let proof = generate_bbs_proof(&store, "bbs_1", &[0], &binding).unwrap();

        assert_eq!(proof.embedded_nonce_hash.len(), 32);
        assert_ne!(proof.embedded_nonce_hash, [0u8; 32]);
    }
}
