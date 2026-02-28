use std::fmt;
use thiserror::Error;

/// Oracle-safe error type for the credential engine.
/// All Display implementations are constant-time-safe and never leak secret material.
/// Crypto failures return generic error types to prevent oracle attacks.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CredError {
    #[error("schema violation: {0}")]
    SchemaViolation(String),

    #[error("signing failed")]
    SigningFailed,

    #[error("encoding failed")]
    EncodingFailed,

    #[error("decoding failed")]
    DecodingFailed,

    #[error("credential expired")]
    CredentialExpired,

    #[error("credential consumed")]
    CredentialConsumed,

    #[error("credential revoked")]
    CredentialRevoked,

    #[error("credential not found")]
    CredentialNotFound,

    #[error("invalid predicate: {0}")]
    InvalidPredicate(String),

    #[error("invalid claim path: {0}")]
    InvalidClaimPath(String),

    #[error("attribute limit exceeded")]
    AttributeLimitExceeded,

    #[error("invalid disclosure policy: {0}")]
    InvalidDisclosurePolicy(String),

    #[error("witness not found")]
    WitnessNotFound,

    #[error("status transition denied: {0}")]
    StatusTransitionDenied(String),

    #[error("vault error")]
    VaultError,

    #[error("credential decayed: {0}")]
    CredentialDecayed(String),

    #[error("invalid authority signature")]
    InvalidAuthoritySignature,

    #[error("authority offer expired")]
    OfferExpired,

    #[error("chain verification failed")]
    ChainVerificationFailed,

    #[error("internal error")]
    InternalError,
}

/// Structured error with a CredError variant and a safe (non-secret-leaking) message.
#[derive(Debug, Clone)]
pub struct CredErrorDetail {
    pub kind: CredError,
    pub message: String,
    pub credential_id: Option<String>,
}

impl fmt::Display for CredErrorDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(ref id) = self.credential_id {
            write!(f, " (credential: {})", id)?;
        }
        Ok(())
    }
}

impl std::error::Error for CredErrorDetail {}

impl CredErrorDetail {
    pub fn new(kind: CredError, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            credential_id: None,
        }
    }

    pub fn with_credential_id(mut self, id: impl Into<String>) -> Self {
        self.credential_id = Some(id.into());
        self
    }
}

impl From<CredError> for CredErrorDetail {
    fn from(kind: CredError) -> Self {
        let message = kind.to_string();
        Self {
            kind,
            message,
            credential_id: None,
        }
    }
}

impl From<signet_core::SignetError> for CredErrorDetail {
    fn from(_err: signet_core::SignetError) -> Self {
        // Oracle-safe: never expose vault error details
        Self {
            kind: CredError::VaultError,
            message: "vault operation failed".to_string(),
            credential_id: None,
        }
    }
}

pub type CredResult<T> = Result<T, CredErrorDetail>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cred_error_display_no_secrets() {
        let err = CredError::SigningFailed;
        let s = err.to_string();
        assert_eq!(s, "signing failed");
        assert!(!s.contains("key"));
        assert!(!s.contains("0x"));
    }

    #[test]
    fn test_cred_error_detail_construction() {
        let detail = CredErrorDetail::new(
            CredError::SchemaViolation("duplicate field".into()),
            "field 'age' appears twice",
        );
        assert_eq!(
            detail.kind,
            CredError::SchemaViolation("duplicate field".into())
        );
        assert_eq!(detail.message, "field 'age' appears twice");
        assert!(detail.credential_id.is_none());
    }

    #[test]
    fn test_cred_error_detail_with_credential_id() {
        let detail = CredErrorDetail::new(CredError::CredentialNotFound, "not found")
            .with_credential_id("abcdef0123456789abcdef0123456789");
        assert_eq!(
            detail.credential_id.as_deref(),
            Some("abcdef0123456789abcdef0123456789")
        );
        let display = format!("{}", detail);
        assert!(display.contains("credential: abcdef0123456789abcdef0123456789"));
    }

    #[test]
    fn test_cred_error_detail_from_cred_error() {
        let detail: CredErrorDetail = CredError::CredentialExpired.into();
        assert_eq!(detail.kind, CredError::CredentialExpired);
    }

    #[test]
    fn test_vault_error_oracle_safe() {
        let signet_err = signet_core::SignetError::Vault("secret key material xyz".to_string());
        let detail: CredErrorDetail = signet_err.into();
        assert_eq!(detail.kind, CredError::VaultError);
        // Must NOT leak the original vault error message
        assert!(!detail.message.contains("secret"));
        assert!(!detail.message.contains("xyz"));
    }

    #[test]
    fn test_all_error_variants_display() {
        let variants: Vec<CredError> = vec![
            CredError::SchemaViolation("test".into()),
            CredError::SigningFailed,
            CredError::EncodingFailed,
            CredError::DecodingFailed,
            CredError::CredentialExpired,
            CredError::CredentialConsumed,
            CredError::CredentialRevoked,
            CredError::CredentialNotFound,
            CredError::InvalidPredicate("test".into()),
            CredError::InvalidClaimPath("test".into()),
            CredError::AttributeLimitExceeded,
            CredError::InvalidDisclosurePolicy("test".into()),
            CredError::WitnessNotFound,
            CredError::StatusTransitionDenied("test".into()),
            CredError::CredentialDecayed("test".into()),
            CredError::InvalidAuthoritySignature,
            CredError::OfferExpired,
            CredError::ChainVerificationFailed,
            CredError::VaultError,
            CredError::InternalError,
        ];
        for v in variants {
            let s = v.to_string();
            assert!(!s.is_empty(), "Display for {:?} should not be empty", v);
        }
    }
}
