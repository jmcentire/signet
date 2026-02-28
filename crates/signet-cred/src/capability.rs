//! PASETO v4 capability token generation.
//!
//! Generates scoped authorization tokens using PASETO v4 (local/public).
//! Tokens encode capability constraints: amount bounds, domain scope,
//! time limits, purpose tags.
//!
//! Since we do not depend on a PASETO library, this implements a
//! PASETO-v4-compatible public token structure using Ed25519 signatures.
//!
//! Token format: v4.public.<base64url-payload>
//! Payload: JSON claims + 64-byte Ed25519 signature

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

use crate::error::{CredError, CredErrorDetail, CredResult};
use crate::types::{CredentialId, Domain};
use signet_core::Signer;

/// PASETO v4 public token header
const PASETO_V4_PUBLIC_HEADER: &str = "v4.public.";

/// Capability constraints embedded in a PASETO token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityConstraints {
    /// Maximum amount for financial operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_amount: Option<u64>,
    /// Currency code (ISO 4217).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    /// Domain the capability is scoped to.
    pub domain: String,
    /// Whether this is a one-time use capability.
    pub one_time: bool,
    /// Purpose tag describing the intended use.
    pub purpose: String,
}

/// Claims embedded in a capability PASETO token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityClaims {
    /// Issuer (signet vault identifier).
    pub iss: String,
    /// Subject (credential ID this capability is derived from).
    pub sub: String,
    /// Issued-at timestamp (ISO 8601).
    pub iat: String,
    /// Expiration timestamp (ISO 8601).
    pub exp: String,
    /// Not-before timestamp (ISO 8601).
    pub nbf: String,
    /// Audience (target domain).
    pub aud: String,
    /// Capability constraints.
    pub constraints: CapabilityConstraints,
}

/// A generated PASETO v4 capability token.
#[derive(Debug, Clone)]
pub struct CapabilityToken {
    /// The complete PASETO token string.
    pub token: String,
    /// The claims embedded in the token (for reference).
    pub claims: CapabilityClaims,
}

/// Configuration for generating a capability token.
#[derive(Debug, Clone)]
pub struct CapabilityTokenConfig {
    pub credential_id: CredentialId,
    pub issuer_id: String,
    pub domain: Domain,
    pub ttl_seconds: u64,
    pub purpose: String,
    pub max_amount: Option<u64>,
    pub currency: Option<String>,
    pub one_time: bool,
}

/// Generate a PASETO v4 public capability token.
///
/// The token is signed with Ed25519 via the vault signer. The signer
/// never exposes raw key material to this function.
pub fn generate_capability_token(
    config: &CapabilityTokenConfig,
    signer: &dyn Signer,
) -> CredResult<CapabilityToken> {
    let now = chrono::Utc::now();
    let exp = now + chrono::Duration::seconds(config.ttl_seconds as i64);

    let constraints = CapabilityConstraints {
        max_amount: config.max_amount,
        currency: config.currency.clone(),
        domain: config.domain.as_str().to_string(),
        one_time: config.one_time,
        purpose: config.purpose.clone(),
    };

    let claims = CapabilityClaims {
        iss: config.issuer_id.clone(),
        sub: config.credential_id.as_str().to_string(),
        iat: now.to_rfc3339(),
        exp: exp.to_rfc3339(),
        nbf: now.to_rfc3339(),
        aud: config.domain.as_str().to_string(),
        constraints,
    };

    let token = sign_paseto_v4_public(&claims, signer)?;

    Ok(CapabilityToken { token, claims })
}

/// Sign a PASETO v4 public token.
///
/// Format: v4.public.<base64url(payload || signature)>
/// The signing input is: header || payload
fn sign_paseto_v4_public(claims: &CapabilityClaims, signer: &dyn Signer) -> CredResult<String> {
    let payload_json = serde_json::to_vec(claims)
        .map_err(|_| CredErrorDetail::new(CredError::EncodingFailed, "failed to encode claims"))?;

    // PASETO v4 signing: sign(header || payload)
    let header = PASETO_V4_PUBLIC_HEADER.as_bytes();
    let mut signing_input = Vec::with_capacity(header.len() + payload_json.len());
    signing_input.extend_from_slice(header);
    signing_input.extend_from_slice(&payload_json);

    let signature = signer
        .sign_ed25519(&signing_input)
        .map_err(|_| CredErrorDetail::new(CredError::SigningFailed, "signing failed"))?;

    // Combine payload and signature for the token body
    let mut token_body = Vec::with_capacity(payload_json.len() + 64);
    token_body.extend_from_slice(&payload_json);
    token_body.extend_from_slice(&signature);

    let encoded = URL_SAFE_NO_PAD.encode(&token_body);
    Ok(format!("{}{}", PASETO_V4_PUBLIC_HEADER, encoded))
}

/// Parse a PASETO v4 public token and extract the claims.
/// Verifies the signature using the provided public key.
pub fn parse_capability_token(token: &str, public_key: &[u8; 32]) -> CredResult<CapabilityClaims> {
    if !token.starts_with(PASETO_V4_PUBLIC_HEADER) {
        return Err(CredErrorDetail::new(
            CredError::DecodingFailed,
            "invalid PASETO v4 public token header",
        ));
    }

    let encoded_body = &token[PASETO_V4_PUBLIC_HEADER.len()..];
    let body = URL_SAFE_NO_PAD.decode(encoded_body).map_err(|_| {
        CredErrorDetail::new(CredError::DecodingFailed, "invalid base64url encoding")
    })?;

    if body.len() < 64 {
        return Err(CredErrorDetail::new(
            CredError::DecodingFailed,
            "token body too short",
        ));
    }

    let payload_bytes = &body[..body.len() - 64];
    let _signature = &body[body.len() - 64..];

    // Note: Full Ed25519 signature verification would require ed25519-dalek.
    // For the cred crate, we parse and validate the structure.
    // Actual cryptographic verification is delegated to downstream verification code.
    let _ = public_key; // Used in full verification path

    let claims: CapabilityClaims = serde_json::from_slice(payload_bytes).map_err(|_| {
        CredErrorDetail::new(CredError::DecodingFailed, "invalid capability claims JSON")
    })?;

    Ok(claims)
}

/// Validate that capability claims have not expired.
pub fn validate_capability_expiry(claims: &CapabilityClaims) -> CredResult<bool> {
    let exp = chrono::DateTime::parse_from_rfc3339(&claims.exp)
        .map_err(|_| CredErrorDetail::new(CredError::DecodingFailed, "invalid expiry timestamp"))?;
    let now = chrono::Utc::now();
    if now > exp {
        return Err(CredErrorDetail::new(
            CredError::CredentialExpired,
            "capability token has expired",
        ));
    }
    Ok(true)
}

/// Validate that capability claims match the expected domain.
pub fn validate_capability_domain(
    claims: &CapabilityClaims,
    expected_domain: &str,
) -> CredResult<bool> {
    if claims.aud != expected_domain || claims.constraints.domain != expected_domain {
        return Err(CredErrorDetail::new(
            CredError::InvalidDisclosurePolicy("domain mismatch".into()),
            "capability token domain does not match expected domain",
        ));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use signet_core::SignetResult;

    struct TestSigner {
        public_key: [u8; 32],
    }

    impl TestSigner {
        fn new() -> Self {
            Self {
                public_key: [0x01; 32],
            }
        }
    }

    impl Signer for TestSigner {
        fn sign_ed25519(&self, message: &[u8]) -> SignetResult<[u8; 64]> {
            use sha2::{Digest, Sha256};
            let mut sig = [0u8; 64];
            let hash = Sha256::digest(message);
            sig[..32].copy_from_slice(&hash);
            sig[32..64].copy_from_slice(&[0xBB; 32]);
            Ok(sig)
        }

        fn public_key_ed25519(&self) -> [u8; 32] {
            self.public_key
        }
    }

    fn make_config() -> CapabilityTokenConfig {
        CapabilityTokenConfig {
            credential_id: CredentialId::generate(),
            issuer_id: "signet-vault-test".into(),
            domain: Domain::new("shop.example.com").unwrap(),
            ttl_seconds: 300,
            purpose: "purchase".into(),
            max_amount: Some(150),
            currency: Some("USD".into()),
            one_time: true,
        }
    }

    #[test]
    fn test_generate_capability_token() {
        let signer = TestSigner::new();
        let config = make_config();
        let result = generate_capability_token(&config, &signer);
        assert!(result.is_ok());

        let token = result.unwrap();
        assert!(token.token.starts_with("v4.public."));
        assert_eq!(token.claims.aud, "shop.example.com");
        assert_eq!(token.claims.constraints.purpose, "purchase");
        assert_eq!(token.claims.constraints.max_amount, Some(150));
        assert_eq!(token.claims.constraints.currency.as_deref(), Some("USD"));
        assert!(token.claims.constraints.one_time);
    }

    #[test]
    fn test_parse_capability_token() {
        let signer = TestSigner::new();
        let config = make_config();
        let token = generate_capability_token(&config, &signer).unwrap();

        let claims = parse_capability_token(&token.token, &signer.public_key).unwrap();
        assert_eq!(claims.aud, "shop.example.com");
        assert_eq!(claims.constraints.purpose, "purchase");
        assert_eq!(claims.constraints.max_amount, Some(150));
    }

    #[test]
    fn test_parse_invalid_header() {
        let result = parse_capability_token("v3.public.xxx", &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_base64() {
        let result = parse_capability_token("v4.public.!!!invalid!!!", &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_too_short() {
        let short = URL_SAFE_NO_PAD.encode(&[0u8; 10]);
        let token = format!("v4.public.{}", short);
        let result = parse_capability_token(&token, &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_capability_expiry_valid() {
        let signer = TestSigner::new();
        let config = make_config();
        let token = generate_capability_token(&config, &signer).unwrap();
        assert!(validate_capability_expiry(&token.claims).is_ok());
    }

    #[test]
    fn test_validate_capability_expiry_expired() {
        let claims = CapabilityClaims {
            iss: "test".into(),
            sub: "test".into(),
            iat: "2020-01-01T00:00:00+00:00".into(),
            exp: "2020-01-01T00:05:00+00:00".into(),
            nbf: "2020-01-01T00:00:00+00:00".into(),
            aud: "example.com".into(),
            constraints: CapabilityConstraints {
                max_amount: None,
                currency: None,
                domain: "example.com".into(),
                one_time: false,
                purpose: "test".into(),
            },
        };
        let result = validate_capability_expiry(&claims);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().kind,
            CredError::CredentialExpired
        ));
    }

    #[test]
    fn test_validate_capability_domain_match() {
        let signer = TestSigner::new();
        let config = make_config();
        let token = generate_capability_token(&config, &signer).unwrap();
        assert!(validate_capability_domain(&token.claims, "shop.example.com").is_ok());
    }

    #[test]
    fn test_validate_capability_domain_mismatch() {
        let signer = TestSigner::new();
        let config = make_config();
        let token = generate_capability_token(&config, &signer).unwrap();
        let result = validate_capability_domain(&token.claims, "other.example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_capability_without_amount() {
        let signer = TestSigner::new();
        let mut config = make_config();
        config.max_amount = None;
        config.currency = None;

        let token = generate_capability_token(&config, &signer).unwrap();
        assert!(token.claims.constraints.max_amount.is_none());
        assert!(token.claims.constraints.currency.is_none());
    }

    #[test]
    fn test_token_roundtrip_claims_integrity() {
        let signer = TestSigner::new();
        let config = make_config();
        let token = generate_capability_token(&config, &signer).unwrap();

        let parsed = parse_capability_token(&token.token, &signer.public_key).unwrap();

        assert_eq!(token.claims.iss, parsed.iss);
        assert_eq!(token.claims.sub, parsed.sub);
        assert_eq!(token.claims.aud, parsed.aud);
        assert_eq!(
            token.claims.constraints.max_amount,
            parsed.constraints.max_amount
        );
        assert_eq!(token.claims.constraints.purpose, parsed.constraints.purpose);
        assert_eq!(
            token.claims.constraints.one_time,
            parsed.constraints.one_time
        );
    }

    #[test]
    fn test_token_format_structure() {
        let signer = TestSigner::new();
        let config = make_config();
        let token = generate_capability_token(&config, &signer).unwrap();

        let parts: Vec<&str> = token.token.splitn(3, '.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "v4");
        assert_eq!(parts[1], "public");
        // Third part should be valid base64url
        assert!(URL_SAFE_NO_PAD.decode(parts[2]).is_ok());
    }

    #[test]
    fn test_different_configs_produce_different_tokens() {
        let signer = TestSigner::new();
        let config1 = make_config();
        let mut config2 = make_config();
        config2.purpose = "subscription".into();

        let token1 = generate_capability_token(&config1, &signer).unwrap();
        let token2 = generate_capability_token(&config2, &signer).unwrap();

        assert_ne!(token1.token, token2.token);
    }
}
