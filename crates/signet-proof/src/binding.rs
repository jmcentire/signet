//! Domain binding construction and verification.
//!
//! Every proof is bound to a specific relying party, challenge nonce, and time window.
//! This module provides construction helpers and validation logic.

use signet_core::{DomainBinding, Nonce, RpIdentifier, Timestamp};

use crate::error::{ProofError, ProofResult};
use crate::types::ProofEngineConfig;

/// Create a new domain binding with the given parameters.
pub fn create_domain_binding(
    rp: RpIdentifier,
    nonce: Nonce,
    ttl_seconds: u64,
) -> ProofResult<DomainBinding> {
    let now = Timestamp::now();
    let expires_at = Timestamp::from_seconds(now.seconds_since_epoch + ttl_seconds);

    validate_rp_identifier(&rp)?;

    Ok(DomainBinding {
        relying_party: rp,
        nonce,
        issued_at: now,
        expires_at,
    })
}

/// Validate a domain binding is well-formed and not expired.
pub fn validate_domain_binding(binding: &DomainBinding) -> ProofResult<()> {
    validate_rp_identifier(&binding.relying_party)?;

    if binding.expires_at <= binding.issued_at {
        return Err(ProofError::InvalidDomainBinding(
            "expires_at must be after issued_at".into(),
        ));
    }

    let now = Timestamp::now();
    if now >= binding.expires_at {
        return Err(ProofError::DomainBindingExpired);
    }

    Ok(())
}

/// Validate domain binding with minimum remaining TTL check.
pub fn validate_domain_binding_with_ttl(
    binding: &DomainBinding,
    config: &ProofEngineConfig,
) -> ProofResult<()> {
    validate_domain_binding(binding)?;

    let now = Timestamp::now();
    let remaining_seconds = binding
        .expires_at
        .seconds_since_epoch
        .saturating_sub(now.seconds_since_epoch);

    if remaining_seconds < config.minimum_remaining_ttl_seconds {
        return Err(ProofError::MinimumTtlViolation(format!(
            "remaining TTL {}s < minimum {}s",
            remaining_seconds, config.minimum_remaining_ttl_seconds
        )));
    }

    Ok(())
}

/// Validate the relying party identifier is not empty.
fn validate_rp_identifier(rp: &RpIdentifier) -> ProofResult<()> {
    let is_empty = match rp {
        RpIdentifier::Origin(s) => s.is_empty(),
        RpIdentifier::Did(s) => s.is_empty(),
    };

    if is_empty {
        return Err(ProofError::InvalidDomainBinding(
            "relying party identifier must not be empty".into(),
        ));
    }
    Ok(())
}

/// Compute the remaining TTL in seconds for a domain binding.
pub fn remaining_ttl_seconds(binding: &DomainBinding) -> u64 {
    let now = Timestamp::now();
    binding
        .expires_at
        .seconds_since_epoch
        .saturating_sub(now.seconds_since_epoch)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_binding(ttl: u64) -> DomainBinding {
        let now = Timestamp::now();
        DomainBinding {
            relying_party: RpIdentifier::Origin("https://example.com".into()),
            nonce: Nonce::generate(),
            issued_at: Timestamp::from_seconds(now.seconds_since_epoch.saturating_sub(1)),
            expires_at: Timestamp::from_seconds(now.seconds_since_epoch + ttl),
        }
    }

    fn make_expired_binding() -> DomainBinding {
        DomainBinding {
            relying_party: RpIdentifier::Origin("https://example.com".into()),
            nonce: Nonce::generate(),
            issued_at: Timestamp::from_seconds(1000),
            expires_at: Timestamp::from_seconds(1001),
        }
    }

    #[test]
    fn test_create_domain_binding_origin() {
        let binding = create_domain_binding(
            RpIdentifier::Origin("https://shop.example.com".into()),
            Nonce::generate(),
            300,
        )
        .unwrap();

        assert!(matches!(binding.relying_party, RpIdentifier::Origin(_)));
        assert!(binding.expires_at > binding.issued_at);
    }

    #[test]
    fn test_create_domain_binding_did() {
        let binding = create_domain_binding(
            RpIdentifier::Did("did:key:z6Mkf5rG...".into()),
            Nonce::generate(),
            300,
        )
        .unwrap();

        assert!(matches!(binding.relying_party, RpIdentifier::Did(_)));
    }

    #[test]
    fn test_create_domain_binding_empty_rp_rejected() {
        let result = create_domain_binding(RpIdentifier::Origin("".into()), Nonce::generate(), 300);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProofError::InvalidDomainBinding(_)
        ));
    }

    #[test]
    fn test_validate_domain_binding_valid() {
        let binding = make_valid_binding(300);
        assert!(validate_domain_binding(&binding).is_ok());
    }

    #[test]
    fn test_validate_domain_binding_expired() {
        let binding = make_expired_binding();
        let result = validate_domain_binding(&binding);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProofError::DomainBindingExpired
        ));
    }

    #[test]
    fn test_validate_domain_binding_invalid_time_order() {
        let now = Timestamp::now();
        let binding = DomainBinding {
            relying_party: RpIdentifier::Origin("https://example.com".into()),
            nonce: Nonce::generate(),
            issued_at: Timestamp::from_seconds(now.seconds_since_epoch + 300),
            expires_at: Timestamp::from_seconds(now.seconds_since_epoch + 100),
        };
        let result = validate_domain_binding(&binding);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_domain_binding_with_ttl_sufficient() {
        let binding = make_valid_binding(300);
        let config = ProofEngineConfig::default();
        assert!(validate_domain_binding_with_ttl(&binding, &config).is_ok());
    }

    #[test]
    fn test_validate_domain_binding_with_ttl_insufficient() {
        let binding = make_valid_binding(2); // Only 2 seconds remaining
        let config = ProofEngineConfig {
            minimum_remaining_ttl_seconds: 10, // Requires 10 seconds
            ..ProofEngineConfig::default()
        };
        let result = validate_domain_binding_with_ttl(&binding, &config);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProofError::MinimumTtlViolation(_)
        ));
    }

    #[test]
    fn test_remaining_ttl_seconds() {
        let binding = make_valid_binding(300);
        let ttl = remaining_ttl_seconds(&binding);
        // Should be approximately 300 (within a second of creation)
        assert!(ttl >= 298 && ttl <= 301);
    }

    #[test]
    fn test_remaining_ttl_seconds_expired() {
        let binding = make_expired_binding();
        let ttl = remaining_ttl_seconds(&binding);
        assert_eq!(ttl, 0);
    }

    #[test]
    fn test_validate_empty_did_rejected() {
        let now = Timestamp::now();
        let binding = DomainBinding {
            relying_party: RpIdentifier::Did("".into()),
            nonce: Nonce::generate(),
            issued_at: now,
            expires_at: Timestamp::from_seconds(now.seconds_since_epoch + 300),
        };
        let result = validate_domain_binding(&binding);
        assert!(result.is_err());
    }
}
