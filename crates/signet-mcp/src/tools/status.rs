//! CheckStatus tool executor.
//!
//! Checks the status of pending requests (Tier 3 authorization, negotiations,
//! capability grants).

use crate::error::{McpError, McpResult};
use crate::types::{CheckStatusRequest, CheckStatusResponse, PendingStatus};
use signet_core::Timestamp;

/// Execute a status check request.
///
/// In production, this queries the notification channel's challenge registry
/// and the negotiation state map. The current implementation returns a
/// pending status with timestamp.
pub fn execute_check_status(request: &CheckStatusRequest) -> McpResult<CheckStatusResponse> {
    if request.request_id.as_str().is_empty() {
        return Err(McpError::InvalidRequest(
            "request_id must not be empty".into(),
        ));
    }

    // In production: look up the actual pending request status from
    // signet_notify::ChallengeRegistry or the negotiation state map.
    // For now, return a Pending status.
    Ok(CheckStatusResponse {
        request_id: request.request_id.clone(),
        pending_type: request.pending_type.clone(),
        status: PendingStatus::Pending,
        detail: Some("Awaiting user authorization".into()),
        updated_at: Timestamp::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PendingRequestType;
    use signet_core::RequestId;

    #[test]
    fn test_check_status_tier3() {
        let request = CheckStatusRequest {
            request_id: RequestId::new("req-status-001"),
            pending_type: PendingRequestType::Tier3Authorization,
        };
        let response = execute_check_status(&request).unwrap();
        assert_eq!(response.request_id.as_str(), "req-status-001");
        assert_eq!(
            response.pending_type,
            PendingRequestType::Tier3Authorization
        );
        assert_eq!(response.status, PendingStatus::Pending);
        assert!(response.detail.is_some());
    }

    #[test]
    fn test_check_status_negotiate() {
        let request = CheckStatusRequest {
            request_id: RequestId::new("req-status-002"),
            pending_type: PendingRequestType::NegotiateContext,
        };
        let response = execute_check_status(&request).unwrap();
        assert_eq!(response.pending_type, PendingRequestType::NegotiateContext);
    }

    #[test]
    fn test_check_status_capability() {
        let request = CheckStatusRequest {
            request_id: RequestId::new("req-status-003"),
            pending_type: PendingRequestType::CapabilityGrant,
        };
        let response = execute_check_status(&request).unwrap();
        assert_eq!(response.pending_type, PendingRequestType::CapabilityGrant);
    }

    #[test]
    fn test_check_status_has_timestamp() {
        let request = CheckStatusRequest {
            request_id: RequestId::new("req-status-004"),
            pending_type: PendingRequestType::Tier3Authorization,
        };
        let response = execute_check_status(&request).unwrap();
        assert!(!response.updated_at.is_expired() || response.updated_at.seconds_since_epoch > 0);
    }
}
