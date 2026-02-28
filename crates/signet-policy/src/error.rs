use std::fmt;
use thiserror::Error;

/// Single error enum for all policy engine operations.
///
/// Display implementations never contain sensitive data (no key material,
/// no raw evidence, no plaintext). Crypto failures return generic variants
/// (no oracle information leakage). Timeouts produce `Decision::Deny`,
/// not `PolicyError`.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy load error: {0}")]
    LoadError(String),

    #[error("policy save error: {0}")]
    SaveError(String),

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("deserialization error: {0}")]
    DeserializationError(String),

    #[error("validation error: {0}")]
    ValidationError(String),

    #[error("classification error: {0}")]
    ClassificationError(String),

    #[error("pattern error: {0}")]
    PatternError(String),

    #[error("MAC verification failed")]
    MacVerificationFailed,

    #[error("audit sink error: {0}")]
    AuditSinkError(String),

    #[error("internal error: {0}")]
    InternalError(String),

    #[error("snapshot is stale")]
    SnapshotStale,

    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

/// Structured error detail accompanying a PolicyError variant.
/// Contains a safe message and an optional error code, but never sensitive data.
#[derive(Debug, Clone)]
pub struct PolicyErrorDetail {
    pub variant: PolicyErrorKind,
    pub message: String,
    pub error_code: Option<String>,
}

/// Discriminator for PolicyError variants, used in PolicyErrorDetail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyErrorKind {
    LoadError,
    SaveError,
    SerializationError,
    DeserializationError,
    ValidationError,
    ClassificationError,
    PatternError,
    MacVerificationFailed,
    AuditSinkError,
    InternalError,
    SnapshotStale,
    InvalidRequest,
}

impl fmt::Display for PolicyErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyErrorKind::LoadError => write!(f, "LoadError"),
            PolicyErrorKind::SaveError => write!(f, "SaveError"),
            PolicyErrorKind::SerializationError => write!(f, "SerializationError"),
            PolicyErrorKind::DeserializationError => write!(f, "DeserializationError"),
            PolicyErrorKind::ValidationError => write!(f, "ValidationError"),
            PolicyErrorKind::ClassificationError => write!(f, "ClassificationError"),
            PolicyErrorKind::PatternError => write!(f, "PatternError"),
            PolicyErrorKind::MacVerificationFailed => write!(f, "MacVerificationFailed"),
            PolicyErrorKind::AuditSinkError => write!(f, "AuditSinkError"),
            PolicyErrorKind::InternalError => write!(f, "InternalError"),
            PolicyErrorKind::SnapshotStale => write!(f, "SnapshotStale"),
            PolicyErrorKind::InvalidRequest => write!(f, "InvalidRequest"),
        }
    }
}

impl fmt::Display for PolicyErrorDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.variant, self.message)?;
        if let Some(ref code) = self.error_code {
            write!(f, " (code: {})", code)?;
        }
        Ok(())
    }
}

pub type PolicyResult<T> = Result<T, PolicyError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_error_display_no_sensitive_data() {
        let err = PolicyError::MacVerificationFailed;
        let msg = format!("{}", err);
        assert_eq!(msg, "MAC verification failed");
        assert!(!msg.contains("key"));
    }

    #[test]
    fn test_policy_error_variants() {
        let errors = vec![
            PolicyError::LoadError("file not found".into()),
            PolicyError::SaveError("disk full".into()),
            PolicyError::SerializationError("invalid json".into()),
            PolicyError::DeserializationError("unexpected field".into()),
            PolicyError::ValidationError("duplicate rule id".into()),
            PolicyError::ClassificationError("no evidence".into()),
            PolicyError::PatternError("invalid key length".into()),
            PolicyError::MacVerificationFailed,
            PolicyError::AuditSinkError("sink unavailable".into()),
            PolicyError::InternalError("unexpected state".into()),
            PolicyError::SnapshotStale,
            PolicyError::InvalidRequest("empty actor id".into()),
        ];
        for err in errors {
            let msg = format!("{}", err);
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn test_policy_error_detail_display() {
        let detail = PolicyErrorDetail {
            variant: PolicyErrorKind::ValidationError,
            message: "duplicate rule id".into(),
            error_code: Some("E001".into()),
        };
        let msg = format!("{}", detail);
        assert!(msg.contains("ValidationError"));
        assert!(msg.contains("duplicate rule id"));
        assert!(msg.contains("E001"));
    }

    #[test]
    fn test_policy_error_detail_without_code() {
        let detail = PolicyErrorDetail {
            variant: PolicyErrorKind::InternalError,
            message: "something broke".into(),
            error_code: None,
        };
        let msg = format!("{}", detail);
        assert!(msg.contains("InternalError"));
        assert!(!msg.contains("code"));
    }

    #[test]
    fn test_policy_error_kind_all_variants() {
        let kinds = vec![
            PolicyErrorKind::LoadError,
            PolicyErrorKind::SaveError,
            PolicyErrorKind::SerializationError,
            PolicyErrorKind::DeserializationError,
            PolicyErrorKind::ValidationError,
            PolicyErrorKind::ClassificationError,
            PolicyErrorKind::PatternError,
            PolicyErrorKind::MacVerificationFailed,
            PolicyErrorKind::AuditSinkError,
            PolicyErrorKind::InternalError,
            PolicyErrorKind::SnapshotStale,
            PolicyErrorKind::InvalidRequest,
        ];
        for kind in kinds {
            let msg = format!("{}", kind);
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn test_policy_result_type_alias() {
        fn test_fn() -> PolicyResult<u32> {
            Ok(42)
        }
        assert_eq!(test_fn().unwrap(), 42);

        fn test_err() -> PolicyResult<u32> {
            Err(PolicyError::InternalError("test".into()))
        }
        assert!(test_err().is_err());
    }
}
