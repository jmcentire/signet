//! Capability request construction.
//!
//! The `request_capability` function constructs a scoped capability token
//! from a `CapabilitySpec`. In a full deployment this would communicate with
//! an MCP server; in this self-contained SDK implementation it constructs the
//! token locally using the spec's permissions, expiration, and domain binding.
//!
//! The token format is: base64(JSON({ permissions, expiration, domain, nonce, issued_at, binding }))
//! where binding = hex(SHA-256(permissions_json || "\0" || expiration || "\0" || domain || "\0" || nonce)).

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha2::{Digest, Sha256};

use signet_core::Timestamp;

use crate::error::{SdkError, SdkErrorKind, SdkResult};
use crate::types::{CapabilityResult, CapabilitySpec};

/// Token body structure serialized into capability tokens.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct CapabilityTokenBody {
    permissions: Vec<String>,
    expiration: u64,
    domain: Option<String>,
    nonce: String,
    issued_at: u64,
    binding: String,
}

/// Requests a scoped capability from the Signet system.
///
/// This is one of the four SDK primitives. In this self-contained
/// implementation, the capability token is constructed locally. A full
/// deployment would forward the request to an MCP server.
///
/// # Preconditions
/// - `spec.permissions` must contain at least one permission.
/// - `spec.expiration` must be a valid future timestamp.
///
/// # Returns
/// A `CapabilityResult` containing the capability token on success.
pub fn request_capability(spec: &CapabilitySpec) -> SdkResult<CapabilityResult> {
    tracing::debug!(
        permissions = ?spec.permissions,
        expiration = spec.expiration,
        domain = ?spec.domain,
        "requesting capability"
    );

    // Validate the spec
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

    // Check that the expiration is in the future
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

    // Validate individual permissions (must be non-empty strings)
    for perm in &spec.permissions {
        if perm.trim().is_empty() {
            tracing::warn!("capability request rejected: empty permission string");
            return Ok(CapabilityResult::failure(
                SdkErrorKind::CapabilityRequestFailed,
            ));
        }
    }

    // Generate a nonce for this token
    let nonce = generate_nonce();

    // Build the token
    let token = build_capability_token(spec, &nonce, now.seconds_since_epoch);

    tracing::info!(
        permissions_count = spec.permissions.len(),
        "capability token issued"
    );

    Ok(CapabilityResult::success(token))
}

/// Build a capability token string from a spec, nonce, and issuance time.
fn build_capability_token(spec: &CapabilitySpec, nonce: &str, issued_at: u64) -> String {
    let binding = compute_capability_binding(
        &spec.permissions,
        spec.expiration,
        spec.domain.as_deref(),
        nonce,
    );

    let body = CapabilityTokenBody {
        permissions: spec.permissions.clone(),
        expiration: spec.expiration,
        domain: spec.domain.clone(),
        nonce: nonce.to_string(),
        issued_at,
        binding,
    };

    let json = serde_json::to_vec(&body).expect("token body serialization should not fail");
    BASE64.encode(&json)
}

/// Compute the integrity binding for a capability token.
fn compute_capability_binding(
    permissions: &[String],
    expiration: u64,
    domain: Option<&str>,
    nonce: &str,
) -> String {
    let perms_json = serde_json::to_string(permissions).unwrap_or_default();
    let domain_str = domain.unwrap_or("");

    let mut hasher = Sha256::new();
    hasher.update(perms_json.as_bytes());
    hasher.update(b"\0");
    hasher.update(expiration.to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(domain_str.as_bytes());
    hasher.update(b"\0");
    hasher.update(nonce.as_bytes());

    hex::encode(hasher.finalize())
}

/// Generate a hex-encoded random nonce.
fn generate_nonce() -> String {
    use sha2::Digest;
    // Use timestamp + a simple counter-like mechanism for uniqueness.
    // In production this would use a CSPRNG; here we use SHA-256 of
    // current time nanoseconds for deterministic-enough uniqueness.
    let now = Timestamp::now();
    let mut hasher = Sha256::new();
    hasher.update(now.seconds_since_epoch.to_le_bytes());
    hasher.update(now.nanoseconds.to_le_bytes());
    hasher.update(b"signet-sdk-capability-nonce");
    hex::encode(hasher.finalize())
}

/// Decode and validate a capability token, returning the parsed body.
///
/// This is useful for services that receive a capability token and want to
/// inspect its contents before acting on the granted permissions.
#[allow(dead_code)]
pub(crate) fn decode_capability_token(token: &str) -> SdkResult<CapabilityTokenBody> {
    let bytes = BASE64
        .decode(token)
        .map_err(|e| SdkError::CapabilityRequestFailed(format!("invalid base64: {e}")))?;

    let body: CapabilityTokenBody = serde_json::from_slice(&bytes)
        .map_err(|e| SdkError::CapabilityRequestFailed(format!("invalid token JSON: {e}")))?;

    // Verify the binding
    let expected = compute_capability_binding(
        &body.permissions,
        body.expiration,
        body.domain.as_deref(),
        &body.nonce,
    );

    if body.binding != expected {
        return Err(SdkError::CapabilityRequestFailed(
            "token binding mismatch".into(),
        ));
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn future_expiration() -> u64 {
        Timestamp::now().seconds_since_epoch + 3600
    }

    #[test]
    fn test_request_capability_success() {
        let spec = CapabilitySpec {
            permissions: vec!["read:profile".into()],
            expiration: future_expiration(),
            domain: Some("example.com".into()),
        };
        let result = request_capability(&spec).unwrap();
        assert!(result.token.is_some());
        assert!(result.error.is_none());
    }

    #[test]
    fn test_request_capability_multiple_permissions() {
        let spec = CapabilitySpec {
            permissions: vec!["read:profile".into(), "write:preferences".into()],
            expiration: future_expiration(),
            domain: None,
        };
        let result = request_capability(&spec).unwrap();
        assert!(result.token.is_some());
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
            expiration: 1, // epoch + 1 second, definitely in the past
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

    #[test]
    fn test_decode_issued_token() {
        let spec = CapabilitySpec {
            permissions: vec!["pay:one-time".into()],
            expiration: future_expiration(),
            domain: Some("shop.example.com".into()),
        };
        let result = request_capability(&spec).unwrap();
        let token = result.token.unwrap();

        let body = decode_capability_token(&token).unwrap();
        assert_eq!(body.permissions, vec!["pay:one-time".to_string()]);
        assert_eq!(body.expiration, spec.expiration);
        assert_eq!(body.domain.as_deref(), Some("shop.example.com"));
    }

    #[test]
    fn test_decode_invalid_base64() {
        let err = decode_capability_token("not-valid-base64!!!").unwrap_err();
        assert!(matches!(err, SdkError::CapabilityRequestFailed(_)));
    }

    #[test]
    fn test_decode_invalid_json() {
        let token = BASE64.encode(b"not json");
        let err = decode_capability_token(&token).unwrap_err();
        assert!(matches!(err, SdkError::CapabilityRequestFailed(_)));
    }

    #[test]
    fn test_decode_tampered_token() {
        let spec = CapabilitySpec {
            permissions: vec!["read".into()],
            expiration: future_expiration(),
            domain: None,
        };
        let result = request_capability(&spec).unwrap();
        let token = result.token.unwrap();

        // Decode, tamper, re-encode
        let bytes = BASE64.decode(&token).unwrap();
        let mut body: CapabilityTokenBody = serde_json::from_slice(&bytes).unwrap();
        body.permissions.push("admin:all".into()); // tamper
        let tampered_json = serde_json::to_vec(&body).unwrap();
        let tampered_token = BASE64.encode(&tampered_json);

        let err = decode_capability_token(&tampered_token).unwrap_err();
        assert!(matches!(err, SdkError::CapabilityRequestFailed(_)));
    }

    #[test]
    fn test_capability_binding_deterministic() {
        let b1 = compute_capability_binding(&["r".into()], 100, Some("d"), "n");
        let b2 = compute_capability_binding(&["r".into()], 100, Some("d"), "n");
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_capability_binding_differs() {
        let b1 = compute_capability_binding(&["r".into()], 100, Some("d"), "n");
        let b2 = compute_capability_binding(&["w".into()], 100, Some("d"), "n");
        assert_ne!(b1, b2);
    }

    #[test]
    fn test_token_contains_domain() {
        let spec = CapabilitySpec {
            permissions: vec!["read".into()],
            expiration: future_expiration(),
            domain: Some("restricted.example.com".into()),
        };
        let result = request_capability(&spec).unwrap();
        let token = result.token.unwrap();
        let body = decode_capability_token(&token).unwrap();
        assert_eq!(body.domain.as_deref(), Some("restricted.example.com"));
    }

    #[test]
    fn test_token_no_domain() {
        let spec = CapabilitySpec {
            permissions: vec!["read".into()],
            expiration: future_expiration(),
            domain: None,
        };
        let result = request_capability(&spec).unwrap();
        let token = result.token.unwrap();
        let body = decode_capability_token(&token).unwrap();
        assert!(body.domain.is_none());
    }
}
