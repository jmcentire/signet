use std::fmt;
use thiserror::Error;

/// Errors that can occur during SDK operations.
///
/// Maps to the `SignetError` enum defined in the Pact contract.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SdkError {
    /// Proof data format is invalid or corrupted.
    #[error("invalid proof: {0}")]
    InvalidProof(String),

    /// The claim does not match the verified proof.
    #[error("invalid claim: {0}")]
    InvalidClaim(String),

    /// Request to MCP server failed due to network issues or invalid spec.
    #[error("capability request failed: {0}")]
    CapabilityRequestFailed(String),

    /// The authority check could not be completed.
    #[error("authority check failed: {0}")]
    AuthorityCheckFailed(String),

    /// Token is not valid or cannot be parsed.
    #[error("credential parse error: {0}")]
    CredentialParseError(String),

    /// A cryptographic operation failed.
    #[error("crypto operation failed: {0}")]
    CryptoOperationFailed(String),

    /// The caller lacks required authorization.
    #[error("unauthorized access: {0}")]
    UnauthorizedAccess(String),

    /// A network request failed.
    #[error("network error: {0}")]
    NetworkError(String),
}

/// Convenience result type for SDK operations.
pub type SdkResult<T> = Result<T, SdkError>;

impl From<SdkError> for signet_core::SignetError {
    fn from(e: SdkError) -> Self {
        signet_core::SignetError::Sdk(e.to_string())
    }
}

/// Error variant tag for embedding in result structs when only the variant
/// name matters (not the full message).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SdkErrorKind {
    InvalidProof,
    InvalidClaim,
    CapabilityRequestFailed,
    AuthorityCheckFailed,
    CredentialParseError,
    CryptoOperationFailed,
    UnauthorizedAccess,
    NetworkError,
}

impl fmt::Display for SdkErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProof => write!(f, "InvalidProof"),
            Self::InvalidClaim => write!(f, "InvalidClaim"),
            Self::CapabilityRequestFailed => write!(f, "CapabilityRequestFailed"),
            Self::AuthorityCheckFailed => write!(f, "AuthorityCheckFailed"),
            Self::CredentialParseError => write!(f, "CredentialParseError"),
            Self::CryptoOperationFailed => write!(f, "CryptoOperationFailed"),
            Self::UnauthorizedAccess => write!(f, "UnauthorizedAccess"),
            Self::NetworkError => write!(f, "NetworkError"),
        }
    }
}

impl From<&SdkError> for SdkErrorKind {
    fn from(e: &SdkError) -> Self {
        match e {
            SdkError::InvalidProof(_) => Self::InvalidProof,
            SdkError::InvalidClaim(_) => Self::InvalidClaim,
            SdkError::CapabilityRequestFailed(_) => Self::CapabilityRequestFailed,
            SdkError::AuthorityCheckFailed(_) => Self::AuthorityCheckFailed,
            SdkError::CredentialParseError(_) => Self::CredentialParseError,
            SdkError::CryptoOperationFailed(_) => Self::CryptoOperationFailed,
            SdkError::UnauthorizedAccess(_) => Self::UnauthorizedAccess,
            SdkError::NetworkError(_) => Self::NetworkError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let e = SdkError::InvalidProof("bad data".into());
        assert_eq!(e.to_string(), "invalid proof: bad data");
    }

    #[test]
    fn test_error_kind_from_error() {
        let e = SdkError::CredentialParseError("oops".into());
        let kind: SdkErrorKind = (&e).into();
        assert_eq!(kind, SdkErrorKind::CredentialParseError);
    }

    #[test]
    fn test_error_kind_display() {
        assert_eq!(SdkErrorKind::InvalidProof.to_string(), "InvalidProof");
        assert_eq!(SdkErrorKind::NetworkError.to_string(), "NetworkError");
    }

    #[test]
    fn test_all_error_variants_display() {
        let errors = vec![
            SdkError::InvalidProof("a".into()),
            SdkError::InvalidClaim("b".into()),
            SdkError::CapabilityRequestFailed("c".into()),
            SdkError::AuthorityCheckFailed("d".into()),
            SdkError::CredentialParseError("e".into()),
            SdkError::CryptoOperationFailed("f".into()),
            SdkError::UnauthorizedAccess("g".into()),
            SdkError::NetworkError("h".into()),
        ];
        for e in &errors {
            // Ensure each Display impl doesn't panic
            let _ = e.to_string();
        }
    }

    #[test]
    fn test_error_equality() {
        let e1 = SdkError::InvalidProof("same".into());
        let e2 = SdkError::InvalidProof("same".into());
        let e3 = SdkError::InvalidProof("different".into());
        assert_eq!(e1, e2);
        assert_ne!(e1, e3);
    }

    #[test]
    fn test_conversion_to_signet_error() {
        let e = SdkError::InvalidProof("proof failed".into());
        let se: signet_core::SignetError = e.into();
        match se {
            signet_core::SignetError::Sdk(msg) => {
                assert!(msg.contains("proof failed"));
            }
            _ => panic!("expected Sdk variant"),
        }
    }

    #[test]
    fn test_error_kind_serde_roundtrip() {
        let kind = SdkErrorKind::CryptoOperationFailed;
        let json = serde_json::to_string(&kind).unwrap();
        let deserialized: SdkErrorKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, deserialized);
    }

    #[test]
    fn test_all_error_kinds_roundtrip() {
        let kinds = vec![
            SdkErrorKind::InvalidProof,
            SdkErrorKind::InvalidClaim,
            SdkErrorKind::CapabilityRequestFailed,
            SdkErrorKind::AuthorityCheckFailed,
            SdkErrorKind::CredentialParseError,
            SdkErrorKind::CryptoOperationFailed,
            SdkErrorKind::UnauthorizedAccess,
            SdkErrorKind::NetworkError,
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let back: SdkErrorKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }
}
