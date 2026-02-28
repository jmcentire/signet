use serde::{Deserialize, Serialize};

use crate::error::SdkErrorKind;

// ---------------------------------------------------------------------------
// ProofFormat — detected proof encoding format
// ---------------------------------------------------------------------------

/// The cryptographic proof format detected in a credential token or proof blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProofFormat {
    /// SD-JWT (Selective Disclosure JSON Web Token) — RFC 9901 baseline interop format.
    SdJwt,
    /// BBS+ Signatures — unlinkable selective disclosure.
    BbsPlus,
    /// Bulletproofs — range proofs with no trusted setup.
    Bulletproof,
    /// Format could not be determined from the input.
    Unknown,
}

impl std::fmt::Display for ProofFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SdJwt => write!(f, "SD-JWT"),
            Self::BbsPlus => write!(f, "BBS+"),
            Self::Bulletproof => write!(f, "Bulletproof"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// Claim — an attribute/value pair asserted by a proof
// ---------------------------------------------------------------------------

/// A claim consisting of an attribute name and its associated value.
///
/// Maps to the Pact contract `Claim` type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    /// The attribute claimed by the proof (e.g. "age_over_21", "country").
    pub attribute: String,
    /// The value associated with the attribute, encoded as a JSON value.
    pub value: serde_json::Value,
}

impl Claim {
    /// Create a new claim with a string value.
    pub fn new(attribute: impl Into<String>, value: impl Into<serde_json::Value>) -> Self {
        Self {
            attribute: attribute.into(),
            value: value.into(),
        }
    }

    /// Returns true if the attribute name is non-empty.
    pub fn is_valid(&self) -> bool {
        !self.attribute.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Proof — serialized proof data
// ---------------------------------------------------------------------------

/// Serialized representation of a cryptographic proof.
///
/// Maps to the Pact contract `Proof` type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// The raw serialized proof bytes.
    pub data: Vec<u8>,
}

impl Proof {
    /// Create a new proof from raw bytes.
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self { data: data.into() }
    }

    /// Returns true if the proof data is non-empty.
    pub fn is_non_empty(&self) -> bool {
        !self.data.is_empty()
    }
}

// ---------------------------------------------------------------------------
// VerifyResult — outcome of proof verification
// ---------------------------------------------------------------------------

/// Result of proof verification against a claim.
///
/// Maps to the Pact contract `VerifyResult` type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyResult {
    /// Whether the proof verified successfully.
    pub valid: bool,
    /// Error information if verification failed.
    pub error: Option<SdkErrorKind>,
    /// The domain the proof was bound to (if domain-binding was present).
    pub domain: Option<String>,
    /// The proof format that was detected.
    pub proof_format: Option<ProofFormat>,
    /// Whether the Ed25519 signature was verified against the issuer's public key.
    /// `false` if the envelope was unsigned (backward compatible).
    #[serde(default)]
    pub signature_verified: bool,
    /// The issuer's public key (hex-encoded Ed25519), if present in the envelope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_public_key: Option<String>,
}

impl VerifyResult {
    /// Create a successful verification result.
    pub fn success(proof_format: ProofFormat, domain: Option<String>) -> Self {
        Self {
            valid: true,
            error: None,
            domain,
            proof_format: Some(proof_format),
            signature_verified: false,
            issuer_public_key: None,
        }
    }

    /// Create a failed verification result.
    pub fn failure(error: SdkErrorKind) -> Self {
        Self {
            valid: false,
            error: Some(error),
            domain: None,
            proof_format: None,
            signature_verified: false,
            issuer_public_key: None,
        }
    }
}

// ---------------------------------------------------------------------------
// CapabilitySpec — specification for a requested capability
// ---------------------------------------------------------------------------

/// Specifies a capability by describing its permissions and expiration.
///
/// Maps to the Pact contract `CapabilitySpec` type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySpec {
    /// The permissions requested (e.g. ["read:profile", "payment:one-time"]).
    pub permissions: Vec<String>,
    /// Expiration time in seconds since the Unix epoch.
    pub expiration: u64,
    /// Optional domain restriction for the capability.
    pub domain: Option<String>,
}

impl CapabilitySpec {
    /// Returns true if the spec has at least one permission and a future expiration.
    pub fn is_valid(&self) -> bool {
        !self.permissions.is_empty() && self.expiration > 0
    }

    /// Returns true if the capability has expired relative to the given timestamp.
    pub fn is_expired_at(&self, now_epoch_seconds: u64) -> bool {
        self.expiration <= now_epoch_seconds
    }
}

// ---------------------------------------------------------------------------
// CapabilityResult — outcome of a capability request
// ---------------------------------------------------------------------------

/// Result of a capability request to an MCP server.
///
/// Maps to the Pact contract `CapabilityResult` type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityResult {
    /// Capability token if the request succeeded.
    pub token: Option<String>,
    /// Error information if the request failed.
    pub error: Option<SdkErrorKind>,
}

impl CapabilityResult {
    /// Create a successful capability result with a token.
    pub fn success(token: String) -> Self {
        Self {
            token: Some(token),
            error: None,
        }
    }

    /// Create a failed capability result.
    pub fn failure(error: SdkErrorKind) -> Self {
        Self {
            token: None,
            error: Some(error),
        }
    }
}

// ---------------------------------------------------------------------------
// AuthorityResult — outcome of an authority check
// ---------------------------------------------------------------------------

/// Result of checking whether a Signet identity possesses a given authority.
///
/// Maps to the Pact contract `AuthorityResult` type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityResult {
    /// Whether the authority check passed.
    pub authorized: bool,
    /// Error information if the check failed.
    pub error: Option<SdkErrorKind>,
}

impl AuthorityResult {
    /// Create a result indicating the identity is authorized.
    pub fn authorized() -> Self {
        Self {
            authorized: true,
            error: None,
        }
    }

    /// Create a result indicating the identity is not authorized.
    pub fn unauthorized() -> Self {
        Self {
            authorized: false,
            error: None,
        }
    }

    /// Create a result indicating the check itself failed.
    pub fn failure(error: SdkErrorKind) -> Self {
        Self {
            authorized: false,
            error: Some(error),
        }
    }
}

// ---------------------------------------------------------------------------
// ParsedCredential — a successfully parsed credential
// ---------------------------------------------------------------------------

/// A credential that has been parsed and validated from a token string.
///
/// Contains the extracted claim, the detected proof format, and metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedCredential {
    /// The claim extracted from the credential.
    pub claim: Claim,
    /// The proof format detected in the token.
    pub format: ProofFormat,
    /// The issuer's SignetId, if present in the credential.
    pub issuer: Option<String>,
    /// Expiration timestamp, if present.
    pub expires_at: Option<u64>,
}

// ---------------------------------------------------------------------------
// CredentialResult — outcome of credential parsing
// ---------------------------------------------------------------------------

/// Result of parsing a credential token.
///
/// Maps to the Pact contract `CredentialResult` type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialResult {
    /// The parsed credential if parsing succeeded.
    pub credential: Option<ParsedCredential>,
    /// Error information if parsing failed.
    pub error: Option<SdkErrorKind>,
}

impl CredentialResult {
    /// Create a successful parse result.
    pub fn success(credential: ParsedCredential) -> Self {
        Self {
            credential: Some(credential),
            error: None,
        }
    }

    /// Create a failed parse result.
    pub fn failure(error: SdkErrorKind) -> Self {
        Self {
            credential: None,
            error: Some(error),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal proof envelope — the structured format we recognize inside proof bytes
// ---------------------------------------------------------------------------

/// Internal structure representing a proof envelope that carries metadata
/// alongside the raw cryptographic proof.
///
/// When proof bytes are created by signet components, they encode this
/// structure as JSON. Third-party raw proofs are handled as opaque blobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProofEnvelope {
    /// Version tag for forward compatibility.
    pub version: u8,
    /// The proof format identifier.
    pub format: ProofFormat,
    /// The attribute this proof covers.
    pub attribute: String,
    /// The claimed value, as a JSON value.
    pub value: serde_json::Value,
    /// Optional domain binding for the proof.
    pub domain: Option<String>,
    /// The raw cryptographic payload (base64-encoded inside JSON).
    pub payload: String,
    /// HMAC-SHA256 binding of (attribute || value || domain || payload) using
    /// a key derived from the payload itself (self-binding integrity check).
    pub binding: String,
    /// Optional Ed25519 signature over the binding hash, hex-encoded.
    /// When present, enables cryptographic verification against issuer_public_key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Optional issuer public key (Ed25519), hex-encoded.
    /// Required for signature verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_public_key: Option<String>,
}

/// Internal structure representing a credential token body.
///
/// Credential tokens are base64-encoded JSON of this structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CredentialTokenBody {
    /// Version tag.
    pub version: u8,
    /// Proof format.
    pub format: ProofFormat,
    /// The attribute name.
    pub attribute: String,
    /// The claimed value.
    pub value: serde_json::Value,
    /// Issuer identifier (SignetId string).
    pub issuer: Option<String>,
    /// Expiration in seconds since epoch.
    pub expires_at: Option<u64>,
    /// HMAC-SHA256 integrity binding.
    pub binding: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claim_new() {
        let c = Claim::new("age_over_21", serde_json::Value::Bool(true));
        assert_eq!(c.attribute, "age_over_21");
        assert_eq!(c.value, serde_json::Value::Bool(true));
    }

    #[test]
    fn test_claim_validity() {
        let valid = Claim::new("name", "Alice");
        let invalid = Claim::new("", "empty attribute");
        assert!(valid.is_valid());
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_proof_non_empty() {
        let p = Proof::new(vec![1, 2, 3]);
        assert!(p.is_non_empty());
        let empty = Proof::new(vec![]);
        assert!(!empty.is_non_empty());
    }

    #[test]
    fn test_verify_result_success() {
        let r = VerifyResult::success(ProofFormat::SdJwt, Some("example.com".into()));
        assert!(r.valid);
        assert!(r.error.is_none());
        assert_eq!(r.domain.as_deref(), Some("example.com"));
        assert_eq!(r.proof_format, Some(ProofFormat::SdJwt));
    }

    #[test]
    fn test_verify_result_failure() {
        let r = VerifyResult::failure(SdkErrorKind::InvalidProof);
        assert!(!r.valid);
        assert_eq!(r.error, Some(SdkErrorKind::InvalidProof));
    }

    #[test]
    fn test_capability_spec_validity() {
        let valid = CapabilitySpec {
            permissions: vec!["read:profile".into()],
            expiration: 1_700_000_000,
            domain: None,
        };
        assert!(valid.is_valid());

        let no_perms = CapabilitySpec {
            permissions: vec![],
            expiration: 1_700_000_000,
            domain: None,
        };
        assert!(!no_perms.is_valid());

        let zero_exp = CapabilitySpec {
            permissions: vec!["read".into()],
            expiration: 0,
            domain: None,
        };
        assert!(!zero_exp.is_valid());
    }

    #[test]
    fn test_capability_spec_expiration() {
        let spec = CapabilitySpec {
            permissions: vec!["pay".into()],
            expiration: 100,
            domain: None,
        };
        assert!(spec.is_expired_at(100));
        assert!(spec.is_expired_at(200));
        assert!(!spec.is_expired_at(50));
    }

    #[test]
    fn test_capability_result_success() {
        let r = CapabilityResult::success("tok_abc123".into());
        assert_eq!(r.token.as_deref(), Some("tok_abc123"));
        assert!(r.error.is_none());
    }

    #[test]
    fn test_capability_result_failure() {
        let r = CapabilityResult::failure(SdkErrorKind::CapabilityRequestFailed);
        assert!(r.token.is_none());
        assert_eq!(r.error, Some(SdkErrorKind::CapabilityRequestFailed));
    }

    #[test]
    fn test_authority_result_authorized() {
        let r = AuthorityResult::authorized();
        assert!(r.authorized);
        assert!(r.error.is_none());
    }

    #[test]
    fn test_authority_result_unauthorized() {
        let r = AuthorityResult::unauthorized();
        assert!(!r.authorized);
        assert!(r.error.is_none());
    }

    #[test]
    fn test_authority_result_failure() {
        let r = AuthorityResult::failure(SdkErrorKind::AuthorityCheckFailed);
        assert!(!r.authorized);
        assert_eq!(r.error, Some(SdkErrorKind::AuthorityCheckFailed));
    }

    #[test]
    fn test_credential_result_success() {
        let cred = ParsedCredential {
            claim: Claim::new("age_over_21", true),
            format: ProofFormat::BbsPlus,
            issuer: Some("issuer123".into()),
            expires_at: Some(1_700_000_000),
        };
        let r = CredentialResult::success(cred.clone());
        assert!(r.error.is_none());
        assert_eq!(r.credential.unwrap().claim, cred.claim);
    }

    #[test]
    fn test_credential_result_failure() {
        let r = CredentialResult::failure(SdkErrorKind::CredentialParseError);
        assert!(r.credential.is_none());
        assert_eq!(r.error, Some(SdkErrorKind::CredentialParseError));
    }

    #[test]
    fn test_proof_format_display() {
        assert_eq!(ProofFormat::SdJwt.to_string(), "SD-JWT");
        assert_eq!(ProofFormat::BbsPlus.to_string(), "BBS+");
        assert_eq!(ProofFormat::Bulletproof.to_string(), "Bulletproof");
        assert_eq!(ProofFormat::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_proof_format_serde_roundtrip() {
        for fmt in &[
            ProofFormat::SdJwt,
            ProofFormat::BbsPlus,
            ProofFormat::Bulletproof,
            ProofFormat::Unknown,
        ] {
            let json = serde_json::to_string(fmt).unwrap();
            let back: ProofFormat = serde_json::from_str(&json).unwrap();
            assert_eq!(*fmt, back);
        }
    }

    #[test]
    fn test_claim_serde_roundtrip() {
        let c = Claim::new("country", "US");
        let json = serde_json::to_string(&c).unwrap();
        let back: Claim = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn test_verify_result_serde_roundtrip() {
        let r = VerifyResult::success(ProofFormat::Bulletproof, Some("test.com".into()));
        let json = serde_json::to_string(&r).unwrap();
        let back: VerifyResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn test_parsed_credential_serde_roundtrip() {
        let cred = ParsedCredential {
            claim: Claim::new("email_verified", true),
            format: ProofFormat::SdJwt,
            issuer: None,
            expires_at: None,
        };
        let json = serde_json::to_string(&cred).unwrap();
        let back: ParsedCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred, back);
    }

    #[test]
    fn test_capability_spec_serde_roundtrip() {
        let spec = CapabilitySpec {
            permissions: vec!["read".into(), "write".into()],
            expiration: 999,
            domain: Some("example.com".into()),
        };
        let json = serde_json::to_string(&spec).unwrap();
        let back: CapabilitySpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
    }
}
