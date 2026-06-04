//! Signet capability envelope generation and verification.
//!
//! Tokens encode capability constraints: amount bounds, domain scope, time
//! limits, and purpose tags. This is a Signet-specific Ed25519-signed
//! envelope, not a PASETO implementation.
//!
//! Token format: signet.cap.v1.<base64url-payload>
//! Payload: JSON claims + 64-byte Ed25519 signature

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{CredError, CredErrorDetail, CredResult};
use crate::types::{CredentialId, Domain};
use signet_core::Signer;

/// Signet capability envelope v1 header.
const SIGNET_CAPABILITY_V1_HEADER: &str = "signet.cap.v1.";

/// Capability constraints embedded in a signed capability envelope.
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

/// Claims embedded in a signed capability envelope.
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

/// A generated signed capability envelope.
#[derive(Debug, Clone)]
pub struct CapabilityToken {
    /// The complete Signet capability envelope string.
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

/// Generate a signed Signet capability envelope.
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

    let token = sign_capability_envelope(&claims, signer)?;

    Ok(CapabilityToken { token, claims })
}

/// Sign a Signet capability envelope.
///
/// Format: signet.cap.v1.<base64url(payload || signature)>
/// The signing input is: header || payload
fn sign_capability_envelope(claims: &CapabilityClaims, signer: &dyn Signer) -> CredResult<String> {
    let payload_json = serde_json::to_vec(claims)
        .map_err(|_| CredErrorDetail::new(CredError::EncodingFailed, "failed to encode claims"))?;

    let header = SIGNET_CAPABILITY_V1_HEADER.as_bytes();
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
    Ok(format!("{}{}", SIGNET_CAPABILITY_V1_HEADER, encoded))
}

/// Verification boundary used by capability parsing.
///
/// Implementations must accept a message only after validating the
/// authenticator supplied with the envelope.
trait CapabilitySignatureVerifier {
    fn verify(&self, message: &[u8], signature: &[u8; 64]) -> CredResult<()>;
}

/// Ed25519 verifier for signed Signet capability envelopes.
#[derive(Debug, Clone)]
struct Ed25519CapabilityVerifier {
    verifying_key: VerifyingKey,
}

impl Ed25519CapabilityVerifier {
    fn from_public_key(public_key: &[u8; 32]) -> CredResult<Self> {
        let verifying_key =
            VerifyingKey::from_bytes(public_key).map_err(|_| invalid_capability_signature())?;
        Ok(Self { verifying_key })
    }
}

impl CapabilitySignatureVerifier for Ed25519CapabilityVerifier {
    fn verify(&self, message: &[u8], signature: &[u8; 64]) -> CredResult<()> {
        self.verifying_key
            .verify_strict(message, &Signature::from_bytes(signature))
            .map_err(|_| invalid_capability_signature())
    }
}

fn invalid_capability_signature() -> CredErrorDetail {
    CredErrorDetail::new(
        CredError::InvalidCapabilitySignature,
        "invalid capability signature",
    )
}

/// Parse a signed capability envelope using an Ed25519 public verification key.
pub fn parse_capability_token(token: &str, public_key: &[u8; 32]) -> CredResult<CapabilityClaims> {
    let verifier = Ed25519CapabilityVerifier::from_public_key(public_key)?;
    parse_capability_token_with_verifier(token, &verifier)
}

/// Parse a signed capability envelope after its authenticator is accepted.
///
/// The public entry point always constructs the Ed25519 verifier. This private
/// seam permits key-free parser tests without exposing a bypass to consumers.
fn parse_capability_token_with_verifier(
    token: &str,
    verifier: &dyn CapabilitySignatureVerifier,
) -> CredResult<CapabilityClaims> {
    if !token.starts_with(SIGNET_CAPABILITY_V1_HEADER) {
        return Err(CredErrorDetail::new(
            CredError::DecodingFailed,
            "invalid Signet capability envelope header",
        ));
    }

    let encoded_body = &token[SIGNET_CAPABILITY_V1_HEADER.len()..];
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
    let signature: &[u8; 64] = body[body.len() - 64..]
        .try_into()
        .map_err(|_| invalid_capability_signature())?;

    let mut signing_input =
        Vec::with_capacity(SIGNET_CAPABILITY_V1_HEADER.len() + payload_bytes.len());
    signing_input.extend_from_slice(SIGNET_CAPABILITY_V1_HEADER.as_bytes());
    signing_input.extend_from_slice(payload_bytes);
    verifier.verify(&signing_input, signature)?;

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

    struct AcceptingVerifier;

    impl CapabilitySignatureVerifier for AcceptingVerifier {
        fn verify(&self, message: &[u8], _signature: &[u8; 64]) -> CredResult<()> {
            if message.starts_with(SIGNET_CAPABILITY_V1_HEADER.as_bytes()) {
                Ok(())
            } else {
                Err(invalid_capability_signature())
            }
        }
    }

    struct RejectingVerifier;

    impl CapabilitySignatureVerifier for RejectingVerifier {
        fn verify(&self, _message: &[u8], _signature: &[u8; 64]) -> CredResult<()> {
            Err(invalid_capability_signature())
        }
    }

    fn make_claims() -> CapabilityClaims {
        CapabilityClaims {
            iss: "signet-vault-test".into(),
            sub: "cred-test".into(),
            iat: "2099-01-01T00:00:00+00:00".into(),
            exp: "2099-01-01T00:05:00+00:00".into(),
            nbf: "2099-01-01T00:00:00+00:00".into(),
            aud: "shop.example.com".into(),
            constraints: CapabilityConstraints {
                max_amount: Some(150),
                currency: Some("USD".into()),
                domain: "shop.example.com".into(),
                one_time: true,
                purpose: "purchase".into(),
            },
        }
    }

    fn make_envelope(claims: &CapabilityClaims) -> String {
        let mut body = serde_json::to_vec(claims).unwrap();
        body.extend_from_slice(&[0u8; 64]);
        format!(
            "{}{}",
            SIGNET_CAPABILITY_V1_HEADER,
            URL_SAFE_NO_PAD.encode(body)
        )
    }

    #[test]
    fn test_parse_capability_requires_accepted_verification() {
        let claims = parse_capability_token_with_verifier(
            &make_envelope(&make_claims()),
            &AcceptingVerifier,
        )
        .unwrap();
        assert_eq!(claims.aud, "shop.example.com");
        assert_eq!(claims.constraints.purpose, "purchase");
    }

    #[test]
    fn test_parse_capability_rejects_failed_verification() {
        let result = parse_capability_token_with_verifier(
            &make_envelope(&make_claims()),
            &RejectingVerifier,
        );
        assert!(matches!(
            result.unwrap_err().kind,
            CredError::InvalidCapabilitySignature
        ));
    }

    #[test]
    fn test_parse_invalid_header() {
        let result = parse_capability_token_with_verifier("v3.public.xxx", &AcceptingVerifier);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_base64() {
        let result =
            parse_capability_token_with_verifier("signet.cap.v1.!!!invalid!!!", &AcceptingVerifier);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_too_short() {
        let short = URL_SAFE_NO_PAD.encode(&[0u8; 10]);
        let token = format!("signet.cap.v1.{}", short);
        let result = parse_capability_token_with_verifier(&token, &AcceptingVerifier);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_capability_expiry_valid() {
        assert!(validate_capability_expiry(&make_claims()).is_ok());
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
        assert!(validate_capability_domain(&make_claims(), "shop.example.com").is_ok());
    }

    #[test]
    fn test_validate_capability_domain_mismatch() {
        let result = validate_capability_domain(&make_claims(), "other.example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_capability_without_amount() {
        let mut claims = make_claims();
        claims.constraints.max_amount = None;
        claims.constraints.currency = None;
        assert!(claims.constraints.max_amount.is_none());
        assert!(claims.constraints.currency.is_none());
    }
}
