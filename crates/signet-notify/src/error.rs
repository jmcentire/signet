use thiserror::Error;

/// Error type for the signet-notify crate.
///
/// All messages are generic to prevent secret leakage and timing oracles.
/// Crypto failures produce the same generic error regardless of cause.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NotifyError {
    #[error("delivery failed")]
    DeliveryFailed,

    #[error("challenge not found")]
    ChallengeNotFound,

    #[error("challenge expired")]
    ChallengeExpired,

    #[error("challenge already resolved")]
    ChallengeAlreadyResolved,

    #[error("invalid callback token")]
    InvalidCallbackToken,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid response")]
    InvalidResponse,

    #[error("scope escalation detected")]
    ScopeEscalation,

    #[error("endpoint unavailable")]
    EndpointUnavailable,

    #[error("circuit breaker open")]
    CircuitBreakerOpen,

    #[error("configuration error")]
    ConfigurationError,

    #[error("internal error")]
    InternalError,
}

/// Result type alias for signet-notify operations.
pub type NotifyResult<T> = Result<T, NotifyError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_messages_are_generic() {
        // Verify error messages don't leak sensitive information
        let errors = vec![
            NotifyError::DeliveryFailed,
            NotifyError::ChallengeNotFound,
            NotifyError::ChallengeExpired,
            NotifyError::ChallengeAlreadyResolved,
            NotifyError::InvalidCallbackToken,
            NotifyError::InvalidSignature,
            NotifyError::InvalidResponse,
            NotifyError::ScopeEscalation,
            NotifyError::EndpointUnavailable,
            NotifyError::CircuitBreakerOpen,
            NotifyError::ConfigurationError,
            NotifyError::InternalError,
        ];

        for err in &errors {
            let msg = err.to_string();
            // Messages should not contain key material, tokens, or URLs
            assert!(!msg.contains("http"), "Error message leaked URL: {msg}");
            assert!(
                !msg.contains("secret"),
                "Error message leaked secret: {msg}"
            );
            assert!(!msg.contains("key"), "Error message leaked key info: {msg}");
        }
    }

    #[test]
    fn test_error_clone_and_eq() {
        let e1 = NotifyError::InvalidSignature;
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_all_variants_distinct() {
        let variants: Vec<NotifyError> = vec![
            NotifyError::DeliveryFailed,
            NotifyError::ChallengeNotFound,
            NotifyError::ChallengeExpired,
            NotifyError::ChallengeAlreadyResolved,
            NotifyError::InvalidCallbackToken,
            NotifyError::InvalidSignature,
            NotifyError::InvalidResponse,
            NotifyError::ScopeEscalation,
            NotifyError::EndpointUnavailable,
            NotifyError::CircuitBreakerOpen,
            NotifyError::ConfigurationError,
            NotifyError::InternalError,
        ];

        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "Variants at index {i} and {j} should differ");
                }
            }
        }
    }
}
