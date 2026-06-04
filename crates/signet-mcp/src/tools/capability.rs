//! RequestCapability tool executor.
//!
//! Fails closed until an issuer-backed capability service is configured.

use crate::error::{McpError, McpResult};
use crate::types::{RequestCapabilityRequest, RequestCapabilityResponse};

/// Execute a capability token request.
///
/// A valid authorization token may only be returned after a configured issuer
/// signs an envelope that consumers verify. Placeholder tokens must never be
/// accepted as authority.
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

    Err(McpError::AccessDenied(
        "capability issuance requires a configured verified issuer".into(),
    ))
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
    fn test_valid_request_fails_closed_without_verified_issuer() {
        let request = make_request();
        match execute_request_capability(&request) {
            Err(McpError::AccessDenied(message)) => assert_eq!(
                message,
                "capability issuance requires a configured verified issuer"
            ),
            _ => panic!("capability issuance must fail closed without an issuer"),
        }
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
}
