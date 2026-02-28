//! MCP tool dispatch.
//!
//! Routes tool invocations to the appropriate executor based on the McpTool enum.

pub mod capability;
pub mod get_proof;
pub mod negotiate;
pub mod query;
pub mod status;
pub mod store;

use crate::error::{McpError, McpResult};
use crate::types::{
    CheckStatusRequest, GetProofRequest, McpTool, NegotiateContextRequest, QueryRequest,
    RequestCapabilityRequest, Session,
};
use signet_core::Tier;

/// Dispatch a tool invocation to the appropriate executor.
///
/// Parses the JSON-RPC params into the appropriate domain request type
/// and delegates to the corresponding tool executor.
pub fn dispatch_tool(
    tool: &McpTool,
    params: &serde_json::Value,
    tier: Tier,
    session: &Session,
) -> McpResult<serde_json::Value> {
    match tool {
        McpTool::GetProof => {
            let request: GetProofRequest = serde_json::from_value(params.clone()).map_err(|e| {
                McpError::InvalidRequest(format!("invalid get_proof params: {}", e))
            })?;
            let response = get_proof::execute_get_proof(&request)?;
            serde_json::to_value(response).map_err(|e| McpError::SerializationError(e.to_string()))
        }
        McpTool::Query => {
            let request: QueryRequest = serde_json::from_value(params.clone())
                .map_err(|e| McpError::InvalidRequest(format!("invalid query params: {}", e)))?;
            let response = query::execute_query(&request, tier)?;
            serde_json::to_value(response).map_err(|e| McpError::SerializationError(e.to_string()))
        }
        McpTool::RequestCapability => {
            let request: RequestCapabilityRequest = serde_json::from_value(params.clone())
                .map_err(|e| {
                    McpError::InvalidRequest(format!("invalid request_capability params: {}", e))
                })?;
            let response = capability::execute_request_capability(&request)?;
            serde_json::to_value(response).map_err(|e| McpError::SerializationError(e.to_string()))
        }
        McpTool::NegotiateContext => {
            let request: NegotiateContextRequest =
                serde_json::from_value(params.clone()).map_err(|e| {
                    McpError::InvalidRequest(format!("invalid negotiate_context params: {}", e))
                })?;
            let response = negotiate::execute_negotiate_context(&request, session)?;
            serde_json::to_value(response).map_err(|e| McpError::SerializationError(e.to_string()))
        }
        McpTool::CheckStatus => {
            let request: CheckStatusRequest =
                serde_json::from_value(params.clone()).map_err(|e| {
                    McpError::InvalidRequest(format!("invalid check_status params: {}", e))
                })?;
            let response = status::execute_check_status(&request)?;
            serde_json::to_value(response).map_err(|e| McpError::SerializationError(e.to_string()))
        }
        McpTool::StoreData | McpTool::ListData => {
            // Handled directly in the dispatcher with vault access
            Err(McpError::ToolExecutionFailed(
                "store/list tools must be dispatched with vault access".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Session;
    use signet_core::{SessionId, Timestamp};
    use std::collections::HashMap;

    fn make_session() -> Session {
        let now = Timestamp::now();
        Session {
            session_id: SessionId::new("test-session"),
            public_key: vec![0u8; 32],
            created_at: now,
            expires_at: Timestamp::from_seconds(now.seconds_since_epoch + 3600),
            revoked: false,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_dispatch_get_proof() {
        let params = serde_json::json!({
            "request_id": "req-001",
            "predicates": [{"attribute": "age", "operator": "Gte", "value": 21}],
            "proof_type": "SdJwt",
            "domain": "example.com",
            "nonce": "test-nonce"
        });
        let result = dispatch_tool(&McpTool::GetProof, &params, Tier::Tier1, &make_session());
        assert!(result.is_ok());
    }

    #[test]
    fn test_dispatch_query() {
        let params = serde_json::json!({
            "request_id": "req-002",
            "query": "is the user over 21?",
            "context": {}
        });
        let result = dispatch_tool(&McpTool::Query, &params, Tier::Tier1, &make_session());
        assert!(result.is_ok());
    }

    #[test]
    fn test_dispatch_check_status() {
        let params = serde_json::json!({
            "request_id": "req-003",
            "pending_type": "Tier3Authorization"
        });
        let result = dispatch_tool(&McpTool::CheckStatus, &params, Tier::Tier1, &make_session());
        assert!(result.is_ok());
    }

    #[test]
    fn test_dispatch_invalid_params() {
        let params = serde_json::json!({"bad": "params"});
        let result = dispatch_tool(&McpTool::GetProof, &params, Tier::Tier1, &make_session());
        assert!(result.is_err());
    }
}
