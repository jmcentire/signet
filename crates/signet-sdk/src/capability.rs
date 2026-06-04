//! Capability request validation.
//!
//! The SDK validates caller input, but cannot construct authorization
//! locally. A capability may only be returned by an issuer-backed transport
//! whose output a consumer can verify against configured trusted authority.

use signet_core::Timestamp;

use crate::error::{SdkErrorKind, SdkResult};
use crate::types::{CapabilityResult, CapabilitySpec};

/// Request a scoped capability from the Signet system.
///
/// Valid requests fail closed until the SDK is configured with an
/// issuer-backed transport. This prevents callers from mistaking locally
/// constructed, unsigned data for delegated authority.
pub fn request_capability(spec: &CapabilitySpec) -> SdkResult<CapabilityResult> {
    tracing::debug!(
        permissions = ?spec.permissions,
        expiration = spec.expiration,
        domain = ?spec.domain,
        "validating capability request"
    );

    if spec.permissions.is_empty() {
        tracing::warn!("capability request rejected: no permissions specified");
        return Ok(CapabilityResult::failure(
            SdkErrorKind::CapabilityRequestFailed,
        ));
    }

    if spec.expiration == 0 {
        tracing::warn!("capability request rejected: zero expiration");
        return Ok(CapabilityResult::failure(
            SdkErrorKind::CapabilityRequestFailed,
        ));
    }

    let now = Timestamp::now();
    if spec.is_expired_at(now.seconds_since_epoch) {
        tracing::warn!(
            expiration = spec.expiration,
            now = now.seconds_since_epoch,
            "capability request rejected: expiration is in the past"
        );
        return Ok(CapabilityResult::failure(
            SdkErrorKind::CapabilityRequestFailed,
        ));
    }

    for permission in &spec.permissions {
        if permission.trim().is_empty() {
            tracing::warn!("capability request rejected: empty permission string");
            return Ok(CapabilityResult::failure(
                SdkErrorKind::CapabilityRequestFailed,
            ));
        }
    }

    tracing::warn!("capability issuance rejected: no configured verified issuer transport");
    Ok(CapabilityResult::failure(
        SdkErrorKind::CapabilityRequestFailed,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn future_expiration() -> u64 {
        Timestamp::now().seconds_since_epoch + 3600
    }

    fn valid_spec() -> CapabilitySpec {
        CapabilitySpec {
            permissions: vec!["read:profile".into()],
            expiration: future_expiration(),
            domain: Some("example.com".into()),
        }
    }

    #[test]
    fn test_valid_request_fails_closed_without_verified_issuer_transport() {
        let result = request_capability(&valid_spec()).unwrap();
        assert!(result.token.is_none());
        assert_eq!(result.error, Some(SdkErrorKind::CapabilityRequestFailed));
    }

    #[test]
    fn test_multiple_permissions_fail_closed_without_verified_issuer_transport() {
        let spec = CapabilitySpec {
            permissions: vec!["read:profile".into(), "write:preferences".into()],
            expiration: future_expiration(),
            domain: None,
        };
        let result = request_capability(&spec).unwrap();
        assert!(result.token.is_none());
        assert_eq!(result.error, Some(SdkErrorKind::CapabilityRequestFailed));
    }

    #[test]
    fn test_request_capability_empty_permissions() {
        let spec = CapabilitySpec {
            permissions: vec![],
            expiration: future_expiration(),
            domain: None,
        };
        let result = request_capability(&spec).unwrap();
        assert!(result.token.is_none());
        assert_eq!(result.error, Some(SdkErrorKind::CapabilityRequestFailed));
    }

    #[test]
    fn test_request_capability_zero_expiration() {
        let spec = CapabilitySpec {
            permissions: vec!["read".into()],
            expiration: 0,
            domain: None,
        };
        let result = request_capability(&spec).unwrap();
        assert!(result.token.is_none());
        assert_eq!(result.error, Some(SdkErrorKind::CapabilityRequestFailed));
    }

    #[test]
    fn test_request_capability_past_expiration() {
        let spec = CapabilitySpec {
            permissions: vec!["read".into()],
            expiration: 1,
            domain: None,
        };
        let result = request_capability(&spec).unwrap();
        assert!(result.token.is_none());
        assert_eq!(result.error, Some(SdkErrorKind::CapabilityRequestFailed));
    }

    #[test]
    fn test_request_capability_empty_permission_string() {
        let spec = CapabilitySpec {
            permissions: vec!["read".into(), "  ".into()],
            expiration: future_expiration(),
            domain: None,
        };
        let result = request_capability(&spec).unwrap();
        assert!(result.token.is_none());
        assert_eq!(result.error, Some(SdkErrorKind::CapabilityRequestFailed));
    }
}
