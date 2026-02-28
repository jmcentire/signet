//! RequestCapability tool executor.
//!
//! Issues scoped PASETO v4 capability tokens for authorized requests.

use crate::error::{McpError, McpResult};
use crate::types::{PasetoClaims, RequestCapabilityRequest, RequestCapabilityResponse};
use signet_core::Timestamp;

/// Execute a capability token request.
///
/// In production, this delegates to signet_cred::generate_capability_token
/// with the vault's signer. The current implementation generates a
/// structured placeholder token.
pub fn execute_request_capability(
    request: &RequestCapabilityRequest,
) -> McpResult<RequestCapabilityResponse> {
    if request.capability_type.is_empty() {
        return Err(McpError::InvalidRequest(
            "capability_type must not be empty".into(),
        ));
    }
    if request.domain.is_empty() {
        return Err(McpError::InvalidRequest("domain must not be empty".into()));
    }

    let now = Timestamp::now();
    let expires_at = Timestamp::from_seconds(now.seconds_since_epoch + 300);

    let claims = PasetoClaims {
        issuer: "signet-vault".into(),
        subject: request.request_id.as_str().into(),
        audience: request.domain.clone(),
        expiration: expires_at.to_rfc3339(),
        not_before: now.to_rfc3339(),
        issued_at: now.to_rfc3339(),
        purpose: request.purpose.clone(),
        constraints: request.constraints.clone(),
    };

    // In production: signet_cred::generate_capability_token(config, signer)
    // For now, generate a structured placeholder token
    let token = format!(
        "v4.public.{}.{}",
        request.capability_type,
        uuid::Uuid::new_v4()
    );

    Ok(RequestCapabilityResponse {
        request_id: request.request_id.clone(),
        token,
        claims,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use signet_core::RequestId;
    use std::collections::HashMap;

    fn make_request() -> RequestCapabilityRequest {
        let mut constraints = HashMap::new();
        constraints.insert("max_amount".into(), serde_json::json!(150));
        constraints.insert("currency".into(), serde_json::json!("USD"));

        RequestCapabilityRequest {
            request_id: RequestId::new("req-cap-001"),
            capability_type: "payment".into(),
            domain: "shop.example.com".into(),
            purpose: "purchase".into(),
            constraints,
        }
    }

    #[test]
    fn test_execute_request_capability_success() {
        let request = make_request();
        let response = execute_request_capability(&request).unwrap();
        assert_eq!(response.request_id.as_str(), "req-cap-001");
        assert!(response.token.starts_with("v4.public."));
        assert_eq!(response.claims.audience, "shop.example.com");
        assert_eq!(response.claims.purpose, "purchase");
        assert!(!response.expires_at.is_expired());
    }

    #[test]
    fn test_execute_request_capability_empty_type() {
        let mut request = make_request();
        request.capability_type = "".into();
        assert!(execute_request_capability(&request).is_err());
    }

    #[test]
    fn test_execute_request_capability_empty_domain() {
        let mut request = make_request();
        request.domain = "".into();
        assert!(execute_request_capability(&request).is_err());
    }

    #[test]
    fn test_capability_token_format() {
        let request = make_request();
        let response = execute_request_capability(&request).unwrap();
        assert!(response.token.starts_with("v4.public.payment."));
    }

    #[test]
    fn test_capability_claims_timestamps() {
        let request = make_request();
        let response = execute_request_capability(&request).unwrap();
        assert!(!response.claims.issued_at.is_empty());
        assert!(!response.claims.expiration.is_empty());
        assert!(!response.claims.not_before.is_empty());
    }

    #[test]
    fn test_capability_constraints_preserved() {
        let request = make_request();
        let response = execute_request_capability(&request).unwrap();
        assert_eq!(
            response.claims.constraints.get("max_amount"),
            Some(&serde_json::json!(150))
        );
        assert_eq!(
            response.claims.constraints.get("currency"),
            Some(&serde_json::json!("USD"))
        );
    }

    #[test]
    fn test_capability_tokens_unique() {
        let request = make_request();
        let r1 = execute_request_capability(&request).unwrap();
        let r2 = execute_request_capability(&request).unwrap();
        assert_ne!(r1.token, r2.token);
    }
}
