//! Authority credential protocol.
//!
//! Authorities push credentials to users. Users accept by counter-signing.
//! The credential key is a tuple `(authority_pubkey, user_signet_id)` — two
//! authorities can independently assert about the same user.
//!
//! Protocol:
//! 1. Authority creates an `AuthorityOffer`, signs it with Ed25519
//! 2. Offer is delivered to the user's vault
//! 3. User reviews the offer (claims, decay config, authority chain)
//! 4. User accepts by counter-signing with their vault key -> `AcceptedCredential`
//! 5. The double-signed credential is stored in the vault
//!
//! Multi-authority chains: each link in the chain is signed by a different authority
//! (e.g., state issues, DMV counter-signs). All signatures are independently verifiable.

use crate::decay::DecayConfig;
use crate::error::{CredError, CredErrorDetail, CredResult};
use crate::types::ClaimValue;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signet_core::RecordId;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// AuthorityCredentialKey — the tuple (authority, account)
// ---------------------------------------------------------------------------

/// Unique key for an authority credential.
/// Two authorities can independently assert about the same user.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthorityCredentialKey {
    /// Hex-encoded Ed25519 public key of the authority.
    pub authority_pubkey: String,
    /// Base58 signet ID of the user.
    pub user_signet_id: String,
}

// ---------------------------------------------------------------------------
// ChainLink — for multi-authority chains
// ---------------------------------------------------------------------------

/// A signature link in a multi-authority chain.
/// Example: state issues a driver's license, local DMV counter-signs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainLink {
    /// Hex-encoded Ed25519 public key of the signer.
    pub signer_pubkey: String,
    /// Role description (e.g., "issuing_state", "local_dmv").
    pub signer_role: String,
    /// Ed25519 signature over the canonical payload at this link.
    pub signature: Vec<u8>,
    /// When this link was signed (RFC 3339).
    pub signed_at: String,
}

// ---------------------------------------------------------------------------
// AuthorityOffer — what the authority creates and signs
// ---------------------------------------------------------------------------

/// An authority's signed offer to push a credential to a user.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorityOffer {
    /// The (authority, user) tuple key.
    pub key: AuthorityCredentialKey,
    /// Type of credential (e.g., "drivers_license", "age_verification").
    pub credential_type: String,
    /// The claims being asserted.
    pub claims: BTreeMap<String, ClaimValue>,
    /// Optional decay configuration set by the authority.
    pub decay: Option<DecayConfig>,
    /// Ed25519 signature by the authority over canonical(key + type + claims + decay).
    pub authority_signature: Vec<u8>,
    /// When the offer was created (RFC 3339).
    pub offered_at: String,
    /// How long the user has to accept (RFC 3339).
    pub offer_expires_at: String,
    /// Multi-authority chain (may be empty for single-authority offers).
    #[serde(default)]
    pub authority_chain: Vec<ChainLink>,
}

// ---------------------------------------------------------------------------
// AcceptedCredential — double-signed result
// ---------------------------------------------------------------------------

/// What the user produces after reviewing and accepting an authority offer.
/// Contains the original offer plus the user's counter-signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AcceptedCredential {
    /// The full original offer.
    pub offer: AuthorityOffer,
    /// User's Ed25519 counter-signature over canonical(offer).
    pub user_signature: Vec<u8>,
    /// When the user accepted (RFC 3339).
    pub accepted_at: String,
    /// Hex-encoded Ed25519 public key of the user.
    pub user_pubkey: String,
}

// ---------------------------------------------------------------------------
// OfferStatus — from the user's perspective
// ---------------------------------------------------------------------------

/// Status of an authority offer from the user's perspective.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OfferStatus {
    Pending,
    Accepted,
    Rejected { reason: Option<String> },
    Expired,
}

// ---------------------------------------------------------------------------
// Storage key prefix
// ---------------------------------------------------------------------------

const OFFER_KEY_PREFIX: &str = "cred:offer:";
const ACCEPTED_KEY_PREFIX: &str = "cred:accepted:";

/// Derive the storage record ID for an authority offer.
pub fn offer_record_id(offer_id: &str) -> RecordId {
    RecordId::new(format!("{}{}", OFFER_KEY_PREFIX, offer_id))
}

/// Derive the storage record ID for an accepted credential.
pub fn accepted_record_id(key: &AuthorityCredentialKey) -> RecordId {
    let mut hasher = Sha256::new();
    hasher.update(key.authority_pubkey.as_bytes());
    hasher.update(b"||");
    hasher.update(key.user_signet_id.as_bytes());
    let hash = hasher.finalize();
    RecordId::new(format!("{}{}", ACCEPTED_KEY_PREFIX, hex::encode(hash)))
}

/// Generate a unique offer ID from the offer contents.
pub fn generate_offer_id(offer: &AuthorityOffer) -> String {
    let canonical = canonical_offer_bytes(offer);
    let hash = Sha256::digest(canonical);
    hex::encode(&hash[..16]) // 32-char hex
}

// ---------------------------------------------------------------------------
// Canonical serialization
// ---------------------------------------------------------------------------

/// Produce a deterministic byte representation of an authority offer for signing.
/// Uses sorted JSON with BTreeMap for deterministic key ordering.
fn canonical_signable_bytes(offer: &AuthorityOffer) -> Vec<u8> {
    // Build a deterministic representation of the signable fields
    // (everything except the authority_signature itself)
    let signable = serde_json::json!({
        "key": {
            "authority_pubkey": offer.key.authority_pubkey,
            "user_signet_id": offer.key.user_signet_id,
        },
        "credential_type": offer.credential_type,
        "claims": offer.claims,
        "decay": offer.decay,
        "offered_at": offer.offered_at,
        "offer_expires_at": offer.offer_expires_at,
        "authority_chain": offer.authority_chain.iter().map(|link| {
            serde_json::json!({
                "signer_pubkey": link.signer_pubkey,
                "signer_role": link.signer_role,
                "signature": hex::encode(&link.signature),
                "signed_at": link.signed_at,
            })
        }).collect::<Vec<_>>(),
    });
    serde_json::to_vec(&signable).unwrap_or_default()
}

/// Produce a deterministic byte representation of a complete offer (including signature).
pub fn canonical_offer_bytes(offer: &AuthorityOffer) -> Vec<u8> {
    serde_json::to_vec(offer).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Signing and verification
// ---------------------------------------------------------------------------

/// Create a signed authority offer.
pub fn sign_authority_offer(
    key: AuthorityCredentialKey,
    credential_type: String,
    claims: BTreeMap<String, ClaimValue>,
    decay: Option<DecayConfig>,
    offered_at: String,
    offer_expires_at: String,
    authority_chain: Vec<ChainLink>,
    authority_signing_key: &[u8; 32],
) -> CredResult<AuthorityOffer> {
    let signing_key = SigningKey::from_bytes(authority_signing_key);

    // Build the offer without signature first
    let mut offer = AuthorityOffer {
        key,
        credential_type,
        claims,
        decay,
        authority_signature: vec![],
        offered_at,
        offer_expires_at,
        authority_chain,
    };

    // Sign the canonical representation
    let signable = canonical_signable_bytes(&offer);
    let signature = signing_key.sign(&signable);
    offer.authority_signature = signature.to_bytes().to_vec();

    Ok(offer)
}

/// Verify an authority offer's signature.
pub fn verify_authority_offer(offer: &AuthorityOffer) -> CredResult<bool> {
    let pubkey_bytes = hex::decode(&offer.key.authority_pubkey).map_err(|_| {
        CredErrorDetail::new(
            CredError::DecodingFailed,
            "invalid hex in authority public key",
        )
    })?;

    if pubkey_bytes.len() != 32 {
        return Err(CredErrorDetail::new(
            CredError::InvalidAuthoritySignature,
            "authority public key must be 32 bytes",
        ));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&pubkey_bytes);

    let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
        CredErrorDetail::new(
            CredError::InvalidAuthoritySignature,
            "invalid Ed25519 public key",
        )
    })?;

    if offer.authority_signature.len() != 64 {
        return Err(CredErrorDetail::new(
            CredError::InvalidAuthoritySignature,
            "signature must be 64 bytes",
        ));
    }

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&offer.authority_signature);
    let signature = Signature::from_bytes(&sig_bytes);

    let signable = canonical_signable_bytes(offer);
    verifying_key
        .verify(&signable, &signature)
        .map(|_| true)
        .map_err(|_| {
            CredErrorDetail::new(
                CredError::InvalidAuthoritySignature,
                "authority signature verification failed",
            )
        })
}

/// Verify all chain links in an authority offer.
/// Chain links sign the pre-chain canonical (the offer content without the authority_chain field),
/// since the chain is assembled before the final offer is signed.
pub fn verify_chain(offer: &AuthorityOffer) -> CredResult<bool> {
    // Build the pre-chain version for verification
    let pre_chain_offer = AuthorityOffer {
        key: offer.key.clone(),
        credential_type: offer.credential_type.clone(),
        claims: offer.claims.clone(),
        decay: offer.decay.clone(),
        authority_signature: vec![],
        offered_at: offer.offered_at.clone(),
        offer_expires_at: offer.offer_expires_at.clone(),
        authority_chain: vec![], // empty — pre-chain canonical
    };
    let signable = canonical_signable_bytes(&pre_chain_offer);

    for (i, link) in offer.authority_chain.iter().enumerate() {
        let pubkey_bytes = hex::decode(&link.signer_pubkey).map_err(|_| {
            CredErrorDetail::new(
                CredError::ChainVerificationFailed,
                format!("invalid hex in chain link {} public key", i),
            )
        })?;

        if pubkey_bytes.len() != 32 {
            return Err(CredErrorDetail::new(
                CredError::ChainVerificationFailed,
                format!("chain link {} public key must be 32 bytes", i),
            ));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&pubkey_bytes);

        let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
            CredErrorDetail::new(
                CredError::ChainVerificationFailed,
                format!("invalid Ed25519 key in chain link {}", i),
            )
        })?;

        if link.signature.len() != 64 {
            return Err(CredErrorDetail::new(
                CredError::ChainVerificationFailed,
                format!("chain link {} signature must be 64 bytes", i),
            ));
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&link.signature);
        let signature = Signature::from_bytes(&sig_bytes);

        verifying_key
            .verify(&signable, &signature)
            .map_err(|_| {
                CredErrorDetail::new(
                    CredError::ChainVerificationFailed,
                    format!("chain link {} signature verification failed", i),
                )
            })?;
    }

    Ok(true)
}

/// User accepts an authority offer by counter-signing.
pub fn accept_offer(
    offer: &AuthorityOffer,
    signer: &dyn signet_core::Signer,
) -> CredResult<AcceptedCredential> {
    // First verify the authority's signature
    verify_authority_offer(offer)?;

    // Verify chain if present
    if !offer.authority_chain.is_empty() {
        verify_chain(offer)?;
    }

    // Check offer expiry
    let now = chrono::Utc::now();
    let expires_at = chrono::DateTime::parse_from_rfc3339(&offer.offer_expires_at)
        .map_err(|_| {
            CredErrorDetail::new(CredError::DecodingFailed, "invalid offer_expires_at timestamp")
        })?;

    if now > expires_at {
        return Err(CredErrorDetail::new(
            CredError::OfferExpired,
            "authority offer has expired",
        ));
    }

    // Counter-sign the full offer (including authority signature)
    let offer_bytes = canonical_offer_bytes(offer);
    let user_signature = signer.sign_ed25519(&offer_bytes).map_err(|_| {
        CredErrorDetail::new(CredError::SigningFailed, "failed to counter-sign offer")
    })?;

    let user_pubkey = hex::encode(signer.public_key_ed25519());

    Ok(AcceptedCredential {
        offer: offer.clone(),
        user_signature: user_signature.to_vec(),
        accepted_at: now.to_rfc3339(),
        user_pubkey,
    })
}

/// Verify an accepted credential's user counter-signature.
pub fn verify_acceptance(accepted: &AcceptedCredential) -> CredResult<bool> {
    let pubkey_bytes = hex::decode(&accepted.user_pubkey).map_err(|_| {
        CredErrorDetail::new(CredError::DecodingFailed, "invalid hex in user public key")
    })?;

    if pubkey_bytes.len() != 32 {
        return Err(CredErrorDetail::new(
            CredError::InvalidAuthoritySignature,
            "user public key must be 32 bytes",
        ));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&pubkey_bytes);

    let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
        CredErrorDetail::new(
            CredError::InvalidAuthoritySignature,
            "invalid Ed25519 user public key",
        )
    })?;

    if accepted.user_signature.len() != 64 {
        return Err(CredErrorDetail::new(
            CredError::InvalidAuthoritySignature,
            "user signature must be 64 bytes",
        ));
    }

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&accepted.user_signature);
    let signature = Signature::from_bytes(&sig_bytes);

    let offer_bytes = canonical_offer_bytes(&accepted.offer);
    verifying_key
        .verify(&offer_bytes, &signature)
        .map(|_| true)
        .map_err(|_| {
            CredErrorDetail::new(
                CredError::InvalidAuthoritySignature,
                "user counter-signature verification failed",
            )
        })
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

/// Store an authority offer in storage.
pub fn store_authority_offer(
    storage: &dyn signet_core::StorageBackend,
    offer: &AuthorityOffer,
) -> CredResult<String> {
    let offer_id = generate_offer_id(offer);
    let record_id = offer_record_id(&offer_id);
    let data = serde_json::to_vec(offer).map_err(|_| {
        CredErrorDetail::new(CredError::EncodingFailed, "failed to encode authority offer")
    })?;
    storage.put(&record_id, &data).map_err(|_| {
        CredErrorDetail::new(CredError::VaultError, "failed to store authority offer")
    })?;
    Ok(offer_id)
}

/// Load an authority offer from storage.
pub fn load_authority_offer(
    storage: &dyn signet_core::StorageBackend,
    offer_id: &str,
) -> CredResult<AuthorityOffer> {
    let record_id = offer_record_id(offer_id);
    let data = storage
        .get(&record_id)
        .map_err(|_| CredErrorDetail::new(CredError::VaultError, "failed to load offer"))?
        .ok_or_else(|| {
            CredErrorDetail::new(CredError::CredentialNotFound, "authority offer not found")
        })?;
    serde_json::from_slice(&data).map_err(|_| {
        CredErrorDetail::new(CredError::DecodingFailed, "failed to decode authority offer")
    })
}

/// Store an accepted credential.
pub fn store_accepted_credential(
    storage: &dyn signet_core::StorageBackend,
    accepted: &AcceptedCredential,
) -> CredResult<()> {
    let record_id = accepted_record_id(&accepted.offer.key);
    let data = serde_json::to_vec(accepted).map_err(|_| {
        CredErrorDetail::new(
            CredError::EncodingFailed,
            "failed to encode accepted credential",
        )
    })?;
    storage.put(&record_id, &data).map_err(|_| {
        CredErrorDetail::new(
            CredError::VaultError,
            "failed to store accepted credential",
        )
    })
}

/// Load an accepted credential.
pub fn load_accepted_credential(
    storage: &dyn signet_core::StorageBackend,
    key: &AuthorityCredentialKey,
) -> CredResult<AcceptedCredential> {
    let record_id = accepted_record_id(key);
    let data = storage
        .get(&record_id)
        .map_err(|_| {
            CredErrorDetail::new(CredError::VaultError, "failed to load accepted credential")
        })?
        .ok_or_else(|| {
            CredErrorDetail::new(
                CredError::CredentialNotFound,
                "accepted credential not found",
            )
        })?;
    serde_json::from_slice(&data).map_err(|_| {
        CredErrorDetail::new(
            CredError::DecodingFailed,
            "failed to decode accepted credential",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use signet_core::{RecordId, SignetResult, StorageBackend};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory storage backend for testing.
    struct MemoryStorage {
        data: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl MemoryStorage {
        fn new() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
            }
        }
    }

    impl StorageBackend for MemoryStorage {
        fn get(&self, record_id: &RecordId) -> SignetResult<Option<Vec<u8>>> {
            let data = self.data.lock().unwrap();
            Ok(data.get(record_id.as_str()).cloned())
        }
        fn put(&self, record_id: &RecordId, ciphertext: &[u8]) -> SignetResult<()> {
            let mut data = self.data.lock().unwrap();
            data.insert(record_id.as_str().to_string(), ciphertext.to_vec());
            Ok(())
        }
        fn delete(&self, record_id: &RecordId) -> SignetResult<bool> {
            let mut data = self.data.lock().unwrap();
            Ok(data.remove(record_id.as_str()).is_some())
        }
        fn compare_and_swap(
            &self,
            record_id: &RecordId,
            expected: Option<&[u8]>,
            new_value: &[u8],
        ) -> SignetResult<bool> {
            let mut data = self.data.lock().unwrap();
            let current = data.get(record_id.as_str());
            let matches = match (current, expected) {
                (None, None) => true,
                (Some(c), Some(e)) => c.as_slice() == e,
                _ => false,
            };
            if matches {
                data.insert(record_id.as_str().to_string(), new_value.to_vec());
                Ok(true)
            } else {
                Ok(false)
            }
        }
        fn exists(&self, record_id: &RecordId) -> SignetResult<bool> {
            let data = self.data.lock().unwrap();
            Ok(data.contains_key(record_id.as_str()))
        }
    }

    /// Test signer that implements signet_core::Signer.
    struct TestSigner {
        signing_key: SigningKey,
    }

    impl TestSigner {
        fn new() -> Self {
            let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
            Self { signing_key }
        }

        fn from_bytes(bytes: [u8; 32]) -> Self {
            Self {
                signing_key: SigningKey::from_bytes(&bytes),
            }
        }
    }

    impl signet_core::Signer for TestSigner {
        fn sign_ed25519(&self, message: &[u8]) -> SignetResult<[u8; 64]> {
            use ed25519_dalek::Signer as _;
            let sig = self.signing_key.sign(message);
            Ok(sig.to_bytes())
        }
        fn public_key_ed25519(&self) -> [u8; 32] {
            self.signing_key.verifying_key().to_bytes()
        }
    }

    fn make_authority_key() -> ([u8; 32], String) {
        let sk = SigningKey::from_bytes(&[0xAA; 32]);
        let pk = sk.verifying_key();
        ([0xAA; 32], hex::encode(pk.to_bytes()))
    }

    fn make_test_claims() -> BTreeMap<String, ClaimValue> {
        let mut claims = BTreeMap::new();
        claims.insert("name".to_string(), ClaimValue::StringVal("Alice".to_string()));
        claims.insert("age".to_string(), ClaimValue::IntVal(29));
        claims
    }

    fn make_test_offer(authority_sk: &[u8; 32], authority_pk_hex: &str) -> AuthorityOffer {
        sign_authority_offer(
            AuthorityCredentialKey {
                authority_pubkey: authority_pk_hex.to_string(),
                user_signet_id: "user123".to_string(),
            },
            "age_verification".to_string(),
            make_test_claims(),
            None,
            "2024-01-01T00:00:00Z".to_string(),
            "2030-12-31T23:59:59Z".to_string(),
            vec![],
            authority_sk,
        )
        .unwrap()
    }

    // --- Authority signature tests ---

    #[test]
    fn test_sign_and_verify_authority_offer() {
        let (sk, pk_hex) = make_authority_key();
        let offer = make_test_offer(&sk, &pk_hex);
        assert!(verify_authority_offer(&offer).is_ok());
    }

    #[test]
    fn test_tampered_offer_fails_verification() {
        let (sk, pk_hex) = make_authority_key();
        let mut offer = make_test_offer(&sk, &pk_hex);
        // Tamper with claims
        offer
            .claims
            .insert("age".to_string(), ClaimValue::IntVal(12));
        let result = verify_authority_offer(&offer);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().kind,
            CredError::InvalidAuthoritySignature
        ));
    }

    #[test]
    fn test_wrong_authority_key_fails() {
        let (sk, _pk_hex) = make_authority_key();
        let other_sk = SigningKey::from_bytes(&[0xBB; 32]);
        let other_pk_hex = hex::encode(other_sk.verifying_key().to_bytes());
        // Sign with sk but claim the pubkey is other_pk
        let mut offer = make_test_offer(&sk, &other_pk_hex);
        // Re-sign with the original sk (so sig is valid for sk's pk, not other_pk)
        let signable = canonical_signable_bytes(&offer);
        let signing_key = SigningKey::from_bytes(&sk);
        let signature = ed25519_dalek::Signer::sign(&signing_key, &signable);
        offer.authority_signature = signature.to_bytes().to_vec();

        let result = verify_authority_offer(&offer);
        assert!(result.is_err());
    }

    // --- User acceptance tests ---

    #[test]
    fn test_user_accepts_offer() {
        let (sk, pk_hex) = make_authority_key();
        let offer = make_test_offer(&sk, &pk_hex);
        let user_signer = TestSigner::new();
        let accepted = accept_offer(&offer, &user_signer).unwrap();
        assert_eq!(
            accepted.user_pubkey,
            hex::encode(user_signer.signing_key.verifying_key().to_bytes())
        );
        assert!(!accepted.user_signature.is_empty());
    }

    #[test]
    fn test_verify_user_acceptance() {
        let (sk, pk_hex) = make_authority_key();
        let offer = make_test_offer(&sk, &pk_hex);
        let user_signer = TestSigner::new();
        let accepted = accept_offer(&offer, &user_signer).unwrap();
        assert!(verify_acceptance(&accepted).is_ok());
    }

    #[test]
    fn test_tampered_acceptance_fails() {
        let (sk, pk_hex) = make_authority_key();
        let offer = make_test_offer(&sk, &pk_hex);
        let user_signer = TestSigner::new();
        let mut accepted = accept_offer(&offer, &user_signer).unwrap();
        // Tamper with the offer after acceptance
        accepted
            .offer
            .claims
            .insert("age".to_string(), ClaimValue::IntVal(99));
        let result = verify_acceptance(&accepted);
        assert!(result.is_err());
    }

    // --- Offer expiry ---

    #[test]
    fn test_expired_offer_cannot_be_accepted() {
        let (sk, pk_hex) = make_authority_key();
        let offer = sign_authority_offer(
            AuthorityCredentialKey {
                authority_pubkey: pk_hex,
                user_signet_id: "user123".to_string(),
            },
            "age_verification".to_string(),
            make_test_claims(),
            None,
            "2024-01-01T00:00:00Z".to_string(),
            "2024-01-02T00:00:00Z".to_string(), // expired in the past
            vec![],
            &sk,
        )
        .unwrap();

        let user_signer = TestSigner::new();
        let result = accept_offer(&offer, &user_signer);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().kind,
            CredError::OfferExpired
        ));
    }

    // --- Two authorities, same user ---

    #[test]
    fn test_two_authorities_distinct_keys() {
        let (sk1, pk1_hex) = make_authority_key();
        let sk2_bytes = [0xCC; 32];
        let sk2 = SigningKey::from_bytes(&sk2_bytes);
        let pk2_hex = hex::encode(sk2.verifying_key().to_bytes());

        let offer1 = make_test_offer(&sk1, &pk1_hex);
        let offer2 = sign_authority_offer(
            AuthorityCredentialKey {
                authority_pubkey: pk2_hex.clone(),
                user_signet_id: "user123".to_string(),
            },
            "age_verification".to_string(),
            make_test_claims(),
            None,
            "2024-01-01T00:00:00Z".to_string(),
            "2030-12-31T23:59:59Z".to_string(),
            vec![],
            &sk2_bytes,
        )
        .unwrap();

        // Both verify independently
        assert!(verify_authority_offer(&offer1).is_ok());
        assert!(verify_authority_offer(&offer2).is_ok());

        // Different authority keys
        assert_ne!(offer1.key.authority_pubkey, offer2.key.authority_pubkey);

        // Different accepted record IDs
        let rid1 = accepted_record_id(&offer1.key);
        let rid2 = accepted_record_id(&offer2.key);
        assert_ne!(rid1.as_str(), rid2.as_str());
    }

    // --- Multi-authority chain ---

    #[test]
    fn test_multi_authority_chain_verifies() {
        let (authority_sk, authority_pk_hex) = make_authority_key();

        // Chain link signer (e.g., "issuing_state")
        let chain_sk_bytes = [0xDD; 32];
        let chain_sk = SigningKey::from_bytes(&chain_sk_bytes);
        let chain_pk_hex = hex::encode(chain_sk.verifying_key().to_bytes());

        // Build a preliminary unsigned offer to compute canonical bytes for chain signing
        let preliminary_offer = AuthorityOffer {
            key: AuthorityCredentialKey {
                authority_pubkey: authority_pk_hex.clone(),
                user_signet_id: "user123".to_string(),
            },
            credential_type: "drivers_license".to_string(),
            claims: make_test_claims(),
            decay: None,
            authority_signature: vec![],
            offered_at: "2024-01-01T00:00:00Z".to_string(),
            offer_expires_at: "2030-12-31T23:59:59Z".to_string(),
            authority_chain: vec![], // chain link signs the pre-chain canonical
        };

        // Chain link signer signs the canonical payload (without chain)
        let signable = canonical_signable_bytes(&preliminary_offer);
        let chain_sig = ed25519_dalek::Signer::sign(&chain_sk, &signable);
        let chain = vec![ChainLink {
            signer_pubkey: chain_pk_hex,
            signer_role: "issuing_state".to_string(),
            signature: chain_sig.to_bytes().to_vec(),
            signed_at: "2024-01-01T00:00:00Z".to_string(),
        }];

        // Now sign the full offer (authority signs with chain included)
        let offer = sign_authority_offer(
            preliminary_offer.key.clone(),
            preliminary_offer.credential_type.clone(),
            preliminary_offer.claims.clone(),
            None,
            preliminary_offer.offered_at.clone(),
            preliminary_offer.offer_expires_at.clone(),
            chain,
            &authority_sk,
        )
        .unwrap();

        assert!(verify_authority_offer(&offer).is_ok());
        assert!(verify_chain(&offer).is_ok());
    }

    #[test]
    fn test_chain_with_invalid_link_fails() {
        let (authority_sk, authority_pk_hex) = make_authority_key();

        let mut offer = make_test_offer(&authority_sk, &authority_pk_hex);

        // Add a chain link with a bad signature
        let chain_sk = SigningKey::from_bytes(&[0xDD; 32]);
        let chain_pk_hex = hex::encode(chain_sk.verifying_key().to_bytes());
        offer.authority_chain.push(ChainLink {
            signer_pubkey: chain_pk_hex,
            signer_role: "bad_signer".to_string(),
            signature: vec![0u8; 64], // invalid signature
            signed_at: "2024-01-01T00:00:00Z".to_string(),
        });

        let result = verify_chain(&offer);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().kind,
            CredError::ChainVerificationFailed
        ));
    }

    // --- Canonical serialization ---

    #[test]
    fn test_canonical_serialization_is_deterministic() {
        let (sk, pk_hex) = make_authority_key();
        let offer1 = make_test_offer(&sk, &pk_hex);
        let offer2 = make_test_offer(&sk, &pk_hex);
        let bytes1 = canonical_offer_bytes(&offer1);
        let bytes2 = canonical_offer_bytes(&offer2);
        assert_eq!(bytes1, bytes2);
    }

    // --- Storage round-trip ---

    #[test]
    fn test_store_and_load_authority_offer() {
        let storage = MemoryStorage::new();
        let (sk, pk_hex) = make_authority_key();
        let offer = make_test_offer(&sk, &pk_hex);

        let offer_id = store_authority_offer(&storage, &offer).unwrap();
        let loaded = load_authority_offer(&storage, &offer_id).unwrap();
        assert_eq!(loaded.key, offer.key);
        assert_eq!(loaded.credential_type, offer.credential_type);
        assert_eq!(loaded.claims, offer.claims);
    }

    #[test]
    fn test_store_and_load_accepted_credential() {
        let storage = MemoryStorage::new();
        let (sk, pk_hex) = make_authority_key();
        let offer = make_test_offer(&sk, &pk_hex);
        let user_signer = TestSigner::new();
        let accepted = accept_offer(&offer, &user_signer).unwrap();

        store_accepted_credential(&storage, &accepted).unwrap();
        let loaded = load_accepted_credential(&storage, &accepted.offer.key).unwrap();
        assert_eq!(loaded.user_pubkey, accepted.user_pubkey);
        assert_eq!(loaded.offer.key, accepted.offer.key);
    }

    // --- Offer with decay config ---

    #[test]
    fn test_offer_with_decay_config() {
        let (sk, pk_hex) = make_authority_key();
        let decay = Some(crate::decay::DecayConfig {
            ttl: Some(crate::decay::TtlDecay {
                expires_after_seconds: 30 * 86400,
            }),
            use_count: Some(crate::decay::UseCountDecay { max_uses: 10 }),
            rate_limit: None,
            phases: vec![],
        });

        let offer = sign_authority_offer(
            AuthorityCredentialKey {
                authority_pubkey: pk_hex,
                user_signet_id: "user123".to_string(),
            },
            "limited_access".to_string(),
            make_test_claims(),
            decay.clone(),
            "2024-01-01T00:00:00Z".to_string(),
            "2030-12-31T23:59:59Z".to_string(),
            vec![],
            &sk,
        )
        .unwrap();

        assert!(verify_authority_offer(&offer).is_ok());
        assert_eq!(offer.decay, decay);
    }

    // --- Offer ID generation ---

    #[test]
    fn test_offer_id_is_deterministic() {
        let (sk, pk_hex) = make_authority_key();
        let offer = make_test_offer(&sk, &pk_hex);
        let id1 = generate_offer_id(&offer);
        let id2 = generate_offer_id(&offer);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 32);
    }
}
