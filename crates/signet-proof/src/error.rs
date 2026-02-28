use thiserror::Error;

/// Error type for the signet-proof crate.
///
/// Crypto failure variants are intentionally opaque to prevent oracle attacks.
/// No raw key material appears in any variant.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProofError {
    #[error("credential not found: {0}")]
    CredentialNotFound(String),

    #[error("credential expired: {0}")]
    CredentialExpired(String),

    #[error("credential type mismatch: {0}")]
    CredentialTypeMismatch(String),

    #[error("invalid claim path: {0}")]
    InvalidClaimPath(String),

    #[error("claim path not selective: {0}")]
    ClaimPathNotSelective(String),

    #[error("full disclosure prevented: {0}")]
    FullDisclosurePrevented(String),

    #[error("invalid predicate: {0}")]
    InvalidPredicate(String),

    #[error("predicate not satisfied: {0}")]
    PredicateNotSatisfied(String),

    #[error("invalid domain binding: {0}")]
    InvalidDomainBinding(String),

    #[error("domain binding expired")]
    DomainBindingExpired,

    #[error("nonce rejected")]
    NonceRejected,

    #[error("time budget exceeded")]
    TimeBudgetExceeded,

    #[error("SD-JWT derivation failed")]
    SdJwtDerivationFailed,

    #[error("BBS+ proof generation failed")]
    BbsProofGenerationFailed,

    #[error("range proof generation failed")]
    RangeProofGenerationFailed,

    #[error("batch range proof failed")]
    BatchRangeProofFailed,

    #[error("CBOR serialization failed")]
    CborSerializationFailed,

    #[error("composition failed: {0}")]
    CompositionFailed(String),

    #[error("witness-commitment mismatch")]
    WitnessCommitmentMismatch,

    #[error("internal cryptographic error")]
    InternalCryptoError,

    #[error("audit write failed: {0}")]
    AuditWriteFailed(String),

    #[error("minimum TTL violation: {0}")]
    MinimumTtlViolation(String),
}

pub type ProofResult<T> = Result<T, ProofError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let e = ProofError::CredentialNotFound("handle_abc".into());
        assert_eq!(e.to_string(), "credential not found: handle_abc");
    }

    #[test]
    fn test_error_display_domain_binding_expired() {
        let e = ProofError::DomainBindingExpired;
        assert_eq!(e.to_string(), "domain binding expired");
    }

    #[test]
    fn test_error_display_time_budget_exceeded() {
        let e = ProofError::TimeBudgetExceeded;
        assert_eq!(e.to_string(), "time budget exceeded");
    }

    #[test]
    fn test_error_display_opaque_crypto() {
        // Crypto errors must be opaque -- no inner details
        let e = ProofError::SdJwtDerivationFailed;
        assert_eq!(e.to_string(), "SD-JWT derivation failed");

        let e = ProofError::BbsProofGenerationFailed;
        assert_eq!(e.to_string(), "BBS+ proof generation failed");

        let e = ProofError::RangeProofGenerationFailed;
        assert_eq!(e.to_string(), "range proof generation failed");

        let e = ProofError::InternalCryptoError;
        assert_eq!(e.to_string(), "internal cryptographic error");
    }

    #[test]
    fn test_error_is_non_exhaustive() {
        // This test just ensures the enum compiles with #[non_exhaustive]
        let e: ProofError = ProofError::TimeBudgetExceeded;
        // We can match known variants
        match e {
            ProofError::TimeBudgetExceeded => {}
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_proof_result_ok() {
        let r: ProofResult<u32> = Ok(42);
        assert_eq!(r.unwrap(), 42);
    }

    #[test]
    fn test_proof_result_err() {
        let r: ProofResult<u32> = Err(ProofError::NonceRejected);
        assert!(r.is_err());
    }
}
