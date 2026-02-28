//! SD-JWT selective disclosure proof generation.
//!
//! Derives an SD-JWT selective disclosure presentation from a cached SD-JWT
//! credential. Selects the specified claims for disclosure and produces a
//! key-binding JWT bound to the domain.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};

use signet_core::DomainBinding;

use crate::error::{ProofError, ProofResult};
use crate::types::{
    CachedCredential, CredentialFormat, CredentialStore, RevealedClaims, SdJwtPresentation,
};

/// Derive an SD-JWT selective disclosure presentation.
///
/// This creates an SD-JWT presentation in compact serialization format with
/// only the specified claims disclosed. A key-binding JWT is appended to bind
/// the presentation to the domain.
pub fn derive_sd_jwt_presentation(
    store: &dyn CredentialStore,
    credential_handle: &str,
    revealed_claims: &RevealedClaims,
    domain_binding: &DomainBinding,
) -> ProofResult<SdJwtPresentation> {
    // Resolve credential
    let credential = store
        .resolve(credential_handle)
        .ok_or_else(|| ProofError::CredentialNotFound(credential_handle.to_string()))?;

    // Verify credential type
    if credential.format != CredentialFormat::SdJwt {
        return Err(ProofError::CredentialTypeMismatch(format!(
            "expected SD-JWT credential, got {:?}",
            credential.format
        )));
    }

    // Check expiry
    if let Some(expires_at) = &credential.expires_at {
        if expires_at.is_expired() {
            return Err(ProofError::CredentialExpired(credential_handle.to_string()));
        }
    }

    // Validate claim paths exist in credential
    for path in &revealed_claims.paths {
        if !credential.claims.contains(path) {
            return Err(ProofError::InvalidClaimPath(format!(
                "claim '{}' not found in credential '{}'",
                path, credential_handle
            )));
        }
    }

    // Prevent full disclosure
    if revealed_claims.paths.len() >= credential.total_claim_count {
        return Err(ProofError::FullDisclosurePrevented(format!(
            "revealing all {} claims would defeat selective disclosure",
            credential.total_claim_count
        )));
    }

    // Check domain binding validity
    if !domain_binding.is_valid() {
        return Err(ProofError::DomainBindingExpired);
    }

    // Build the SD-JWT compact serialization
    let compact = build_sd_jwt_compact(&credential, revealed_claims, domain_binding)?;

    Ok(SdJwtPresentation {
        compact_serialization: compact,
        disclosed_claim_names: revealed_claims.paths.clone(),
        domain_binding: domain_binding.clone(),
    })
}

/// Build the SD-JWT compact serialization string.
///
/// Format: <issuer-jwt>~<disclosure1>~<disclosure2>~...~<key-binding-jwt>
fn build_sd_jwt_compact(
    credential: &CachedCredential,
    revealed_claims: &RevealedClaims,
    domain_binding: &DomainBinding,
) -> ProofResult<String> {
    // The issuer JWT is the first part of the raw data
    let issuer_jwt = String::from_utf8(credential.raw_data.clone())
        .map_err(|_| ProofError::SdJwtDerivationFailed)?;

    // Build disclosures for revealed claims
    let mut disclosures = Vec::new();
    for claim_path in &revealed_claims.paths {
        let disclosure = build_disclosure(claim_path);
        disclosures.push(disclosure);
    }

    // Build key-binding JWT for domain binding
    let kb_jwt = build_key_binding_jwt(domain_binding, &disclosures)?;

    // Compose compact serialization: issuer_jwt~disclosure1~disclosure2~...~kb_jwt
    let mut parts = vec![issuer_jwt];
    parts.extend(disclosures);
    let serialization = format!("{}~{}", parts.join("~"), kb_jwt);

    Ok(serialization)
}

/// Build a disclosure value for a claim.
/// In SD-JWT, disclosures are base64url-encoded JSON arrays: [salt, claim_name, claim_value].
fn build_disclosure(claim_name: &str) -> String {
    // Generate a deterministic-for-testing salt from the claim name
    let mut hasher = Sha256::new();
    hasher.update(b"sd-jwt-disclosure-salt:");
    hasher.update(claim_name.as_bytes());
    let salt = hasher.finalize();
    let salt_b64 = URL_SAFE_NO_PAD.encode(&salt[..16]);

    // Build the disclosure array: [salt, claim_name, "***"]
    // The actual value would come from the credential in production
    let disclosure_json = format!("[\"{}\",\"{}\",\"disclosed\"]", salt_b64, claim_name);

    URL_SAFE_NO_PAD.encode(disclosure_json.as_bytes())
}

/// Build a key-binding JWT that binds the presentation to the domain.
fn build_key_binding_jwt(
    domain_binding: &DomainBinding,
    disclosures: &[String],
) -> ProofResult<String> {
    // Build the header
    let header = r#"{"typ":"kb+jwt","alg":"ES256"}"#;
    let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());

    // Build the payload with domain binding data
    let rp_str = match &domain_binding.relying_party {
        signet_core::RpIdentifier::Origin(s) => s.clone(),
        signet_core::RpIdentifier::Did(s) => s.clone(),
    };

    // Compute SD hash over the disclosures
    let mut sd_hasher = Sha256::new();
    for d in disclosures {
        sd_hasher.update(d.as_bytes());
    }
    let sd_hash = sd_hasher.finalize();
    let sd_hash_b64 = URL_SAFE_NO_PAD.encode(&sd_hash[..]);

    let nonce_b64 = URL_SAFE_NO_PAD.encode(&domain_binding.nonce.0);

    let payload = format!(
        r#"{{"aud":"{}","nonce":"{}","iat":{},"sd_hash":"{}"}}"#,
        rp_str, nonce_b64, domain_binding.issued_at.seconds_since_epoch, sd_hash_b64
    );
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());

    // Simulated signature (in production, this would use the holder's key)
    let mut sig_hasher = Sha256::new();
    sig_hasher.update(header_b64.as_bytes());
    sig_hasher.update(b".");
    sig_hasher.update(payload_b64.as_bytes());
    let sig = sig_hasher.finalize();
    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig[..]);

    Ok(format!("{}.{}.{}", header_b64, payload_b64, sig_b64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CachedCredential;
    use signet_core::{Nonce, RpIdentifier, Timestamp};
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

    fn make_sd_jwt_cred(handle: &str, claims: Vec<&str>) -> CachedCredential {
        let total = claims.len() + 2; // more claims than revealed to prevent full disclosure
        CachedCredential {
            handle: handle.to_string(),
            format: CredentialFormat::SdJwt,
            claims: claims.into_iter().map(String::from).collect(),
            raw_data: b"eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWdlIiwibmFtZSJdfQ.sig".to_vec(),
            expires_at: None,
            total_claim_count: total,
        }
    }

    #[test]
    fn test_derive_sd_jwt_presentation_success() {
        let store = TestCredentialStore::new();
        store.add(make_sd_jwt_cred("cred_1", vec!["name", "age", "email"]));

        let revealed = RevealedClaims::new(vec!["name".into(), "age".into()]).unwrap();
        let binding = make_binding(300);

        let result = derive_sd_jwt_presentation(&store, "cred_1", &revealed, &binding);
        assert!(result.is_ok());

        let presentation = result.unwrap();
        assert_eq!(presentation.disclosed_claim_names, vec!["name", "age"]);
        assert!(presentation.compact_serialization.contains('~'));
    }

    #[test]
    fn test_derive_sd_jwt_credential_not_found() {
        let store = TestCredentialStore::new();
        let revealed = RevealedClaims::new(vec!["name".into()]).unwrap();
        let binding = make_binding(300);

        let result = derive_sd_jwt_presentation(&store, "nonexistent", &revealed, &binding);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::CredentialNotFound(_)
        ));
    }

    #[test]
    fn test_derive_sd_jwt_type_mismatch() {
        let store = TestCredentialStore::new();
        store.add(CachedCredential {
            handle: "bbs_cred".into(),
            format: CredentialFormat::Bbs,
            claims: vec!["name".into()],
            raw_data: vec![],
            expires_at: None,
            total_claim_count: 3,
        });

        let revealed = RevealedClaims::new(vec!["name".into()]).unwrap();
        let binding = make_binding(300);

        let result = derive_sd_jwt_presentation(&store, "bbs_cred", &revealed, &binding);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::CredentialTypeMismatch(_)
        ));
    }

    #[test]
    fn test_derive_sd_jwt_credential_expired() {
        let store = TestCredentialStore::new();
        store.add(CachedCredential {
            handle: "expired_cred".into(),
            format: CredentialFormat::SdJwt,
            claims: vec!["name".into()],
            raw_data: b"eyJ0eXAiOiJKV1QifQ.eyJ0ZXN0IjoiMSJ9.sig".to_vec(),
            expires_at: Some(Timestamp::from_seconds(1000)), // Long expired
            total_claim_count: 3,
        });

        let revealed = RevealedClaims::new(vec!["name".into()]).unwrap();
        let binding = make_binding(300);

        let result = derive_sd_jwt_presentation(&store, "expired_cred", &revealed, &binding);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::CredentialExpired(_)
        ));
    }

    #[test]
    fn test_derive_sd_jwt_invalid_claim_path() {
        let store = TestCredentialStore::new();
        store.add(make_sd_jwt_cred("cred_1", vec!["name", "age"]));

        let revealed = RevealedClaims::new(vec!["nonexistent_claim".into()]).unwrap();
        let binding = make_binding(300);

        let result = derive_sd_jwt_presentation(&store, "cred_1", &revealed, &binding);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::InvalidClaimPath(_)
        ));
    }

    #[test]
    fn test_derive_sd_jwt_full_disclosure_prevented() {
        let store = TestCredentialStore::new();
        // Credential with exactly 2 claims and total_claim_count = 2
        store.add(CachedCredential {
            handle: "cred_small".into(),
            format: CredentialFormat::SdJwt,
            claims: vec!["name".into(), "age".into()],
            raw_data: b"eyJ0eXAiOiJKV1QifQ.eyJ0ZXN0IjoiMSJ9.sig".to_vec(),
            expires_at: None,
            total_claim_count: 2,
        });

        let revealed = RevealedClaims::new(vec!["name".into(), "age".into()]).unwrap();
        let binding = make_binding(300);

        let result = derive_sd_jwt_presentation(&store, "cred_small", &revealed, &binding);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::FullDisclosurePrevented(_)
        ));
    }

    #[test]
    fn test_derive_sd_jwt_domain_binding_expired() {
        let store = TestCredentialStore::new();
        store.add(make_sd_jwt_cred("cred_1", vec!["name", "age"]));

        let revealed = RevealedClaims::new(vec!["name".into()]).unwrap();
        // Create an expired binding
        let binding = DomainBinding {
            relying_party: RpIdentifier::Origin("https://example.com".into()),
            nonce: Nonce::generate(),
            issued_at: Timestamp::from_seconds(1000),
            expires_at: Timestamp::from_seconds(1001),
        };

        let result = derive_sd_jwt_presentation(&store, "cred_1", &revealed, &binding);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::DomainBindingExpired
        ));
    }

    #[test]
    fn test_sd_jwt_compact_format() {
        let store = TestCredentialStore::new();
        store.add(make_sd_jwt_cred("cred_1", vec!["name", "age", "email"]));

        let revealed = RevealedClaims::new(vec!["name".into()]).unwrap();
        let binding = make_binding(300);

        let presentation =
            derive_sd_jwt_presentation(&store, "cred_1", &revealed, &binding).unwrap();

        // Should contain tilde-delimited parts
        let parts: Vec<&str> = presentation.compact_serialization.split('~').collect();
        // At least: issuer_jwt, disclosure, kb_jwt
        assert!(
            parts.len() >= 3,
            "Expected at least 3 parts, got {}",
            parts.len()
        );
    }

    #[test]
    fn test_disclosure_is_base64url() {
        let disclosure = build_disclosure("test_claim");
        // Should be valid base64url (no +, /, or =)
        assert!(!disclosure.contains('+'));
        assert!(!disclosure.contains('/'));
        assert!(!disclosure.contains('='));
        // Should decode successfully
        let decoded = URL_SAFE_NO_PAD.decode(&disclosure);
        assert!(decoded.is_ok());
    }
}
