//! # Signet SDK
//!
//! Developer-facing SDK for external service integration with the Signet
//! sovereign agent stack. Provides four core primitives:
//!
//! - [`verify`] — Validate a ZK proof against a claimed attribute.
//! - [`request_capability`] — Request a scoped capability token.
//! - [`check_authority`] — Confirm a Signet identity's authority.
//! - [`parse_credential`] — Decode credential claims from a token.
//!
//! The SDK is intentionally minimal. All complexity lives in the vault and
//! policy engine; the SDK provides a thin verification and parsing layer
//! that does not require vault access.
//!
//! # Example
//!
//! ```rust
//! use signet_sdk::{verify, Proof, Claim};
//!
//! // Create a claim to verify
//! let claim = Claim::new("age_over_21", true);
//!
//! // In production, the proof comes from a Signet agent
//! let proof = Proof::new(vec![/* proof bytes */]);
//!
//! // Verify returns a VerifyResult (never panics)
//! let result = verify(&proof, &claim).unwrap();
//! if result.valid {
//!     println!("Proof verified for format: {:?}", result.proof_format);
//! }
//! ```

pub mod error;
pub mod types;

mod authority;
mod capability;
mod credential;
pub mod verify;

// Re-export the four public API functions at crate root.
pub use authority::check_authority;
pub use capability::request_capability;
pub use credential::parse_credential;
pub use verify::verify;

// Re-export SDK types for ergonomic usage.
pub use error::{SdkError, SdkErrorKind, SdkResult};
pub use types::{
    AuthorityResult, CapabilityResult, CapabilitySpec, Claim, CredentialResult, ParsedCredential,
    Proof, ProofFormat, VerifyResult,
};

// Re-export commonly used signet-core types so SDK users don't need to
// depend on signet-core directly.
pub use signet_core::{
    CredentialId, DomainBinding, Nonce, RpIdentifier, SignetId, Tier, Timestamp,
};

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Integration tests exercising the four primitives together
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_primitive() {
        // Create a proof envelope via the verify module's internal helper
        let proof_data = crate::verify::create_proof_envelope(
            ProofFormat::SdJwt,
            "age_over_21",
            &serde_json::Value::Bool(true),
            Some("shop.example.com"),
            b"crypto-payload",
        );
        let proof = Proof::new(proof_data);
        let claim = Claim::new("age_over_21", true);

        let result = verify(&proof, &claim).unwrap();
        assert!(result.valid);
        assert_eq!(result.proof_format, Some(ProofFormat::SdJwt));
        assert_eq!(result.domain.as_deref(), Some("shop.example.com"));
    }

    #[test]
    fn test_request_capability_primitive() {
        let spec = CapabilitySpec {
            permissions: vec!["payment:one-time".into()],
            expiration: Timestamp::now().seconds_since_epoch + 600,
            domain: Some("amazon.com".into()),
        };

        let result = request_capability(&spec).unwrap();
        assert!(result.token.is_some());
        assert!(result.error.is_none());
    }

    #[test]
    fn test_check_authority_primitive() {
        let pubkey = [0x42u8; 32];
        let id = signet_core::crypto::signet_id_from_pubkey(&pubkey);

        let result = check_authority(&id, "verify").unwrap();
        assert!(result.authorized);
    }

    #[test]
    fn test_parse_credential_primitive() {
        let token = crate::credential::create_credential_token(
            ProofFormat::BbsPlus,
            "country",
            &serde_json::json!("US"),
            Some("gov.example"),
            Some(1_800_000_000),
        );

        let result = parse_credential(&token).unwrap();
        let cred = result.credential.unwrap();
        assert_eq!(cred.claim.attribute, "country");
        assert_eq!(cred.claim.value, serde_json::json!("US"));
        assert_eq!(cred.format, ProofFormat::BbsPlus);
        assert_eq!(cred.issuer.as_deref(), Some("gov.example"));
    }

    // -----------------------------------------------------------------------
    // End-to-end flow: issue credential, parse it, verify proof
    // -----------------------------------------------------------------------

    #[test]
    fn test_end_to_end_credential_flow() {
        // Step 1: A credential is issued (simulating vault/cred layer)
        let token = crate::credential::create_credential_token(
            ProofFormat::SdJwt,
            "email_verified",
            &serde_json::Value::Bool(true),
            Some("auth.signet.local"),
            Some(Timestamp::now().seconds_since_epoch + 3600),
        );

        // Step 2: Service parses the credential
        let parsed = parse_credential(&token).unwrap();
        let cred = parsed.credential.unwrap();
        assert_eq!(cred.claim.attribute, "email_verified");
        assert_eq!(cred.format, ProofFormat::SdJwt);

        // Step 3: A proof is constructed from the claim
        let proof_data = crate::verify::create_proof_envelope(
            ProofFormat::SdJwt,
            &cred.claim.attribute,
            &cred.claim.value,
            Some("service.example.com"),
            b"zk-proof-payload",
        );
        let proof = Proof::new(proof_data);

        // Step 4: Service verifies the proof
        let verify_result = verify(&proof, &cred.claim).unwrap();
        assert!(verify_result.valid);
        assert_eq!(verify_result.domain.as_deref(), Some("service.example.com"));
    }

    #[test]
    fn test_end_to_end_capability_flow() {
        // Step 1: Check authority
        let pubkey = [0x55u8; 32];
        let id = signet_core::crypto::signet_id_from_pubkey(&pubkey);
        let auth = check_authority(&id, "issue").unwrap();
        assert!(auth.authorized);

        // Step 2: Request capability
        let spec = CapabilitySpec {
            permissions: vec!["read:profile".into(), "verify:age".into()],
            expiration: Timestamp::now().seconds_since_epoch + 300,
            domain: Some("app.example.com".into()),
        };
        let cap = request_capability(&spec).unwrap();
        assert!(cap.token.is_some());
    }

    #[test]
    fn test_sd_jwt_credential_end_to_end() {
        // Create an SD-JWT credential
        let token = crate::credential::create_sd_jwt_token(
            "age_over_21",
            &serde_json::Value::Bool(true),
            Some("issuer.signet.io"),
            Some(1_900_000_000),
        );

        // Parse it
        let result = parse_credential(&token).unwrap();
        let cred = result.credential.unwrap();
        assert_eq!(cred.claim.attribute, "age_over_21");
        assert_eq!(cred.format, ProofFormat::SdJwt);
        assert_eq!(cred.issuer.as_deref(), Some("issuer.signet.io"));
    }

    // -----------------------------------------------------------------------
    // Re-export verification: ensure core types are accessible
    // -----------------------------------------------------------------------

    #[test]
    fn test_core_type_reexports() {
        // Verify that re-exported types from signet_core are usable
        let _id = SignetId("test".into());
        let _tier = Tier::Tier1;
        let _ts = Timestamp::now();
        let _nonce = Nonce::generate();
        let _cred_id = CredentialId::new("cred-1");
        let _rp = RpIdentifier::Origin("https://example.com".into());
    }

    #[test]
    fn test_error_reexports() {
        let e = SdkError::InvalidProof("test".into());
        let kind: SdkErrorKind = (&e).into();
        assert_eq!(kind, SdkErrorKind::InvalidProof);
    }

    // -----------------------------------------------------------------------
    // Negative / edge case integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_then_parse_mismatch() {
        // Create a credential with one claim
        let token = crate::credential::create_credential_token(
            ProofFormat::BbsPlus,
            "country",
            &serde_json::json!("US"),
            None,
            None,
        );
        let parsed = parse_credential(&token).unwrap();
        let cred = parsed.credential.unwrap();

        // Create a proof for a different claim
        let proof_data = crate::verify::create_proof_envelope(
            ProofFormat::BbsPlus,
            "age_over_21",
            &serde_json::Value::Bool(true),
            None,
            b"payload",
        );
        let proof = Proof::new(proof_data);

        // Verification should fail: proof is for age_over_21, claim is for country
        let result = verify(&proof, &cred.claim).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_all_four_primitives_return_ok() {
        // None of the four primitives should return Err for well-formed but
        // semantically invalid inputs (they return result structs instead).

        // verify: empty proof
        let r = verify(&Proof::new(vec![]), &Claim::new("x", true));
        assert!(r.is_ok());

        // request_capability: empty permissions
        let r = request_capability(&CapabilitySpec {
            permissions: vec![],
            expiration: 0,
            domain: None,
        });
        assert!(r.is_ok());

        // check_authority: empty id
        let r = check_authority(&SignetId("".into()), "verify");
        assert!(r.is_ok());

        // parse_credential: empty token
        let r = parse_credential("");
        assert!(r.is_ok());
    }
}
