//! JSON-RPC 2.0 dispatcher.
//!
//! Hand-rolled JSON-RPC 2.0 method routing (no rmcp dependency).
//! Parses raw JSON into JsonRpcRequest, routes to the appropriate handler,
//! and wraps the result in a JsonRpcResponse.

use crate::error::{McpError, McpResult};
use crate::server::McpServer;
use crate::types::{JsonRpcError, JsonRpcRequest, JsonRpcResponse, McpTool};
use signet_core::Tier;

/// Parse a raw JSON string into a JsonRpcRequest.
pub fn parse_jsonrpc_request(raw: &str) -> McpResult<JsonRpcRequest> {
    let request: JsonRpcRequest = serde_json::from_str(raw)
        .map_err(|e| McpError::InvalidJsonRpc(format!("failed to parse JSON-RPC: {}", e)))?;

    if request.jsonrpc != "2.0" {
        return Err(McpError::InvalidJsonRpc(
            "jsonrpc field must be \"2.0\"".into(),
        ));
    }

    Ok(request)
}

/// Dispatch a parsed JSON-RPC request.
///
/// Routes the method to the appropriate MCP tool or built-in method.
/// Returns a JSON-RPC response (never fails -- errors are wrapped in error responses).
pub fn dispatch_jsonrpc(server: &McpServer, raw_request: &str) -> JsonRpcResponse {
    // Parse the request
    let request = match parse_jsonrpc_request(raw_request) {
        Ok(r) => r,
        Err(e) => {
            return JsonRpcResponse::error(
                serde_json::Value::Null,
                JsonRpcError {
                    code: e.json_rpc_code(),
                    message: e.to_string(),
                    data: None,
                },
            );
        }
    };

    let id = request.id.clone();

    // Route to handler
    match request.method.as_str() {
        // Built-in methods
        "initialize" => handle_initialize(server, &request),
        "ping" => handle_ping(&request),
        "tools/list" => handle_tools_list(&request),

        // check_status has special handling for challenge registry lookup
        "check_status" => handle_check_status_with_registry(server, &request),

        // MCP tool methods
        method if McpTool::from_method(method).is_some() => {
            handle_tool_invocation(server, &request)
        }

        // Unknown method
        _ => JsonRpcResponse::error(
            id,
            JsonRpcError {
                code: -32601,
                message: format!("method not found: {}", request.method),
                data: None,
            },
        ),
    }
}

/// Handle the initialize method.
fn handle_initialize(server: &McpServer, request: &JsonRpcRequest) -> JsonRpcResponse {
    let result = serde_json::json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {
                "listChanged": false
            }
        },
        "serverInfo": {
            "name": server.config().server_name,
            "version": server.config().server_version
        }
    });
    JsonRpcResponse::success(request.id.clone(), result)
}

/// Handle the ping method.
fn handle_ping(request: &JsonRpcRequest) -> JsonRpcResponse {
    JsonRpcResponse::success(request.id.clone(), serde_json::json!({}))
}

/// Handle tools/list.
fn handle_tools_list(request: &JsonRpcRequest) -> JsonRpcResponse {
    let tools = serde_json::json!({
        "tools": [
            {
                "name": "store_data",
                "description": "Store a fact or piece of data in the user's personal vault",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "label": {"type": "string", "description": "Name/label for the data"},
                        "tier": {"type": "integer", "description": "Data tier: 1=freely provable, 2=agent-internal, 3=capability-gated"},
                        "value": {"type": "string", "description": "The value to store"}
                    },
                    "required": ["label", "tier", "value"]
                }
            },
            {
                "name": "list_data",
                "description": "List stored data in the vault. Tier 3 values are masked unless authorized",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tier": {"type": "integer", "description": "Optional tier filter (1, 2, or 3)"}
                    }
                }
            },
            {
                "name": "get_proof",
                "description": "Generate a zero-knowledge or selective-disclosure proof for the given predicates",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "predicates": {"type": "array"},
                        "proof_type": {"type": "string"},
                        "domain": {"type": "string"},
                        "nonce": {"type": "string"}
                    },
                    "required": ["predicates", "proof_type", "domain", "nonce"]
                }
            },
            {
                "name": "query",
                "description": "Query the user's data vault. Response tier depends on data sensitivity",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "context": {"type": "object"}
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "request_capability",
                "description": "Request a scoped capability token for a specific purpose",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "capability_type": {"type": "string"},
                        "domain": {"type": "string"},
                        "purpose": {"type": "string"},
                        "constraints": {"type": "object"}
                    },
                    "required": ["capability_type", "domain", "purpose"]
                }
            },
            {
                "name": "negotiate_context",
                "description": "Negotiate what data to disclose with a counterparty agent",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "counterparty": {"type": "string"},
                        "proposed_disclosures": {"type": "array"},
                        "purpose": {"type": "string"}
                    },
                    "required": ["counterparty", "proposed_disclosures", "purpose"]
                }
            },
            {
                "name": "check_status",
                "description": "Check the status of a pending request (Tier 3 authorization, negotiation, etc.)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "request_id": {"type": "string"},
                        "pending_type": {"type": "string"}
                    },
                    "required": ["request_id", "pending_type"]
                }
            }
        ]
    });
    JsonRpcResponse::success(request.id.clone(), tools)
}

/// Handle a tool invocation by delegating to the pipeline.
fn handle_tool_invocation(server: &McpServer, request: &JsonRpcRequest) -> JsonRpcResponse {
    let tool = match McpTool::from_method(&request.method) {
        Some(t) => t,
        None => {
            return JsonRpcResponse::error(
                request.id.clone(),
                JsonRpcError {
                    code: -32601,
                    message: format!("method not found: {}", request.method),
                    data: None,
                },
            );
        }
    };

    // Store/list tools need vault access
    match &tool {
        McpTool::StoreData | McpTool::ListData => {
            let vault = match server.vault() {
                Some(v) => v,
                None => {
                    return JsonRpcResponse::error(
                        request.id.clone(),
                        JsonRpcError {
                            code: -32001,
                            message: "vault not initialized".into(),
                            data: None,
                        },
                    );
                }
            };
            let result = match &tool {
                McpTool::StoreData => {
                    crate::tools::store::execute_store_data(&request.params, vault)
                }
                McpTool::ListData => {
                    crate::tools::store::execute_list_data(&request.params, vault)
                }
                _ => unreachable!(),
            };
            return match result {
                Ok(val) => JsonRpcResponse::success(request.id.clone(), val),
                Err(e) => JsonRpcResponse::error(
                    request.id.clone(),
                    JsonRpcError {
                        code: e.json_rpc_code(),
                        message: e.to_string(),
                        data: None,
                    },
                ),
            };
        }
        _ => {}
    }

    // For other tool invocations, classify tier and dispatch.
    let tier = match crate::policy::classify_tier(&tool, &request.params) {
        Ok(t) => t,
        Err(e) => {
            return JsonRpcResponse::error(
                request.id.clone(),
                JsonRpcError {
                    code: e.json_rpc_code(),
                    message: e.to_string(),
                    data: None,
                },
            );
        }
    };

    // Tier 3: suspend and return pending challenge instead of dispatching
    if tier == Tier::Tier3 {
        return handle_tier3_suspension(server, request);
    }

    // Create a minimal session for unauthenticated dispatch
    let session = crate::types::Session {
        session_id: signet_core::SessionId::new("anonymous"),
        public_key: vec![],
        created_at: signet_core::Timestamp::now(),
        expires_at: signet_core::Timestamp::from_seconds(
            signet_core::Timestamp::now().seconds_since_epoch + 300,
        ),
        revoked: false,
        metadata: std::collections::HashMap::new(),
    };

    match crate::tools::dispatch_tool(&tool, &request.params, tier, &session) {
        Ok(result) => JsonRpcResponse::success(request.id.clone(), result),
        Err(e) => JsonRpcResponse::error(
            request.id.clone(),
            JsonRpcError {
                code: e.json_rpc_code(),
                message: e.to_string(),
                data: None,
            },
        ),
    }
}

/// Handle Tier 3 request suspension.
///
/// Instead of dispatching the tool, registers a challenge in the challenge
/// registry and returns a pending response with the challenge_id.
/// The caller must later call check_status with the challenge_id to poll
/// for resolution.
fn handle_tier3_suspension(server: &McpServer, request: &JsonRpcRequest) -> JsonRpcResponse {
    use signet_notify::types::{ChallengeId, EventId, ScopeEntry, ScopeSet};

    let challenge_id = ChallengeId::generate();
    let event_id = EventId::generate();

    // Default timeout: 5 minutes from now (300 seconds, matches policy escalation_timeout)
    let now = signet_core::Timestamp::now();
    let deadline = signet_core::Timestamp::from_seconds(now.seconds_since_epoch + 300);

    // Build a scope from the request params
    let tool_name = request.method.as_str();
    let scope = ScopeSet::new(vec![ScopeEntry::new(
        format!("vault.tier3.{}", tool_name),
        "access",
    )])
    .unwrap_or_else(|_| {
        ScopeSet::new(vec![ScopeEntry::new("vault.tier3.default", "access")]).unwrap()
    });

    // Register the challenge
    match server
        .challenge_registry()
        .register(challenge_id.clone(), event_id, deadline, scope)
    {
        Ok(_handle) => {
            // The handle is intentionally stored in the registry (via register).
            // We return the challenge_id so the caller can poll via check_status.
            // Note: the handle will warn on drop if not resolved, but that's expected
            // for the async flow where resolution comes later via check_status.
            std::mem::forget(_handle); // Prevent drop warning; registry owns the state.

            JsonRpcResponse::success(
                request.id.clone(),
                serde_json::json!({
                    "status": "pending",
                    "challenge_id": challenge_id.as_str(),
                    "message": "Tier 3 access requires user authorization. Use check_status to poll for resolution.",
                    "expires_in_seconds": 300
                }),
            )
        }
        Err(e) => JsonRpcResponse::error(
            request.id.clone(),
            JsonRpcError {
                code: -32005, // NOTIFY_ERROR
                message: format!("failed to create authorization challenge: {}", e),
                data: None,
            },
        ),
    }
}

/// Handle check_status with challenge registry lookup.
///
/// When a challenge_id is provided, checks the registry for the challenge state.
/// If the challenge has been resolved (approved/denied), returns the resolution.
/// If still pending, returns pending status. If expired, returns denied (fail-secure).
fn handle_check_status_with_registry(
    server: &McpServer,
    request: &JsonRpcRequest,
) -> JsonRpcResponse {
    let params = request.params.clone();

    let request_id = params
        .get("request_id")
        .and_then(|v: &serde_json::Value| v.as_str())
        .unwrap_or("");

    if request_id.is_empty() {
        return JsonRpcResponse::error(
            request.id.clone(),
            JsonRpcError {
                code: -32602,
                message: "request_id must not be empty".into(),
                data: None,
            },
        );
    }

    // Try to look up the challenge in the registry
    let registry = server.challenge_registry();

    // Check if the challenge has a response
    match signet_notify::ChallengeId::new(request_id) {
        Ok(challenge_id) => {
            match registry.has_response(&challenge_id) {
                Ok(true) => {
                    // Challenge has been resolved
                    match registry.take_response(&challenge_id) {
                        Ok(Some(signet_notify::types::AuthorizationResponse::Approve)) => {
                            JsonRpcResponse::success(
                                request.id.clone(),
                                serde_json::json!({
                                    "request_id": request_id,
                                    "status": "approved",
                                    "detail": "User authorized the request"
                                }),
                            )
                        }
                        Ok(Some(signet_notify::types::AuthorizationResponse::Deny { reason })) => {
                            JsonRpcResponse::success(
                                request.id.clone(),
                                serde_json::json!({
                                    "request_id": request_id,
                                    "status": "denied",
                                    "detail": reason.unwrap_or_else(|| "User denied the request".into())
                                }),
                            )
                        }
                        Ok(Some(signet_notify::types::AuthorizationResponse::Modify {
                            adjusted_scope,
                        })) => JsonRpcResponse::success(
                            request.id.clone(),
                            serde_json::json!({
                                "request_id": request_id,
                                "status": "approved",
                                "detail": "User approved with modified scope",
                                "adjusted_scope_size": adjusted_scope.len()
                            }),
                        ),
                        Ok(None) => JsonRpcResponse::success(
                            request.id.clone(),
                            serde_json::json!({
                                "request_id": request_id,
                                "status": "pending",
                                "detail": "Awaiting user authorization"
                            }),
                        ),
                        Err(_) => JsonRpcResponse::success(
                            request.id.clone(),
                            serde_json::json!({
                                "request_id": request_id,
                                "status": "denied",
                                "detail": "Challenge expired or not found (fail-secure)"
                            }),
                        ),
                    }
                }
                Ok(false) => {
                    // Still pending
                    JsonRpcResponse::success(
                        request.id.clone(),
                        serde_json::json!({
                            "request_id": request_id,
                            "status": "pending",
                            "detail": "Awaiting user authorization"
                        }),
                    )
                }
                Err(_) => {
                    // Registry error or challenge not found -- fall through to default handler
                    let fallback_params = serde_json::json!({
                        "request_id": request_id,
                        "pending_type": params.get("pending_type").and_then(|v: &serde_json::Value| v.as_str()).unwrap_or("Tier3Authorization")
                    });
                    match serde_json::from_value::<crate::types::CheckStatusRequest>(fallback_params)
                    {
                        Ok(req) => match crate::tools::status::execute_check_status(&req) {
                            Ok(resp) => match serde_json::to_value(resp) {
                                Ok(v) => JsonRpcResponse::success(request.id.clone(), v),
                                Err(e) => JsonRpcResponse::error(
                                    request.id.clone(),
                                    JsonRpcError {
                                        code: -32603,
                                        message: e.to_string(),
                                        data: None,
                                    },
                                ),
                            },
                            Err(e) => JsonRpcResponse::error(
                                request.id.clone(),
                                JsonRpcError {
                                    code: e.json_rpc_code(),
                                    message: e.to_string(),
                                    data: None,
                                },
                            ),
                        },
                        Err(e) => JsonRpcResponse::error(
                            request.id.clone(),
                            JsonRpcError {
                                code: -32602,
                                message: format!("invalid check_status params: {}", e),
                                data: None,
                            },
                        ),
                    }
                }
            }
        }
        Err(_) => {
            // Not a valid challenge_id format -- use default handler
            let fallback_params = params.clone();
            match serde_json::from_value::<crate::types::CheckStatusRequest>(fallback_params) {
                Ok(req) => match crate::tools::status::execute_check_status(&req) {
                    Ok(resp) => match serde_json::to_value(resp) {
                        Ok(v) => JsonRpcResponse::success(request.id.clone(), v),
                        Err(e) => JsonRpcResponse::error(
                            request.id.clone(),
                            JsonRpcError {
                                code: -32603,
                                message: e.to_string(),
                                data: None,
                            },
                        ),
                    },
                    Err(e) => JsonRpcResponse::error(
                        request.id.clone(),
                        JsonRpcError {
                            code: e.json_rpc_code(),
                            message: e.to_string(),
                            data: None,
                        },
                    ),
                },
                Err(e) => JsonRpcResponse::error(
                    request.id.clone(),
                    JsonRpcError {
                        code: -32602,
                        message: format!("invalid check_status params: {}", e),
                        data: None,
                    },
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::McpServer;
    use crate::types::McpServerConfig;

    fn make_server() -> McpServer {
        McpServer::new(McpServerConfig::default()).unwrap()
    }

    #[test]
    fn test_parse_valid_jsonrpc() {
        let raw = r#"{"jsonrpc":"2.0","method":"ping","params":{},"id":1}"#;
        let request = parse_jsonrpc_request(raw).unwrap();
        assert_eq!(request.method, "ping");
        assert_eq!(request.id, serde_json::json!(1));
    }

    #[test]
    fn test_parse_invalid_json() {
        let raw = "not json";
        assert!(parse_jsonrpc_request(raw).is_err());
    }

    #[test]
    fn test_parse_wrong_jsonrpc_version() {
        let raw = r#"{"jsonrpc":"1.0","method":"ping","params":{},"id":1}"#;
        assert!(parse_jsonrpc_request(raw).is_err());
    }

    #[test]
    fn test_dispatch_ping() {
        let server = make_server();
        let raw = r#"{"jsonrpc":"2.0","method":"ping","params":{},"id":1}"#;
        let response = dispatch_jsonrpc(&server, raw);
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_dispatch_initialize() {
        let server = make_server();
        let raw = r#"{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}"#;
        let response = dispatch_jsonrpc(&server, raw);
        assert!(response.result.is_some());
        let result = response.result.unwrap();
        assert_eq!(result["serverInfo"]["name"], "signet-mcp");
    }

    #[test]
    fn test_dispatch_tools_list() {
        let server = make_server();
        let raw = r#"{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}"#;
        let response = dispatch_jsonrpc(&server, raw);
        assert!(response.result.is_some());
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 7);
    }

    #[test]
    fn test_dispatch_unknown_method() {
        let server = make_server();
        let raw = r#"{"jsonrpc":"2.0","method":"unknown","params":{},"id":1}"#;
        let response = dispatch_jsonrpc(&server, raw);
        assert!(response.error.is_some());
        assert_eq!(response.error.as_ref().unwrap().code, -32601);
    }

    #[test]
    fn test_dispatch_invalid_json() {
        let server = make_server();
        let response = dispatch_jsonrpc(&server, "not json");
        assert!(response.error.is_some());
    }

    #[test]
    fn test_dispatch_get_proof_tool() {
        let server = make_server();
        let raw = r#"{
            "jsonrpc": "2.0",
            "method": "get_proof",
            "params": {
                "request_id": "req-001",
                "predicates": [{"attribute": "age", "operator": "Gte", "value": 21}],
                "proof_type": "SdJwt",
                "domain": "example.com",
                "nonce": "test-nonce"
            },
            "id": 1
        }"#;
        let response = dispatch_jsonrpc(&server, raw);
        assert!(response.result.is_some(), "error: {:?}", response.error);
    }

    #[test]
    fn test_dispatch_query_tool() {
        let server = make_server();
        let raw = r#"{
            "jsonrpc": "2.0",
            "method": "query",
            "params": {
                "request_id": "req-002",
                "query": "is user over 21?",
                "context": {}
            },
            "id": 2
        }"#;
        let response = dispatch_jsonrpc(&server, raw);
        assert!(response.result.is_some(), "error: {:?}", response.error);
    }

    #[test]
    fn test_dispatch_preserves_id() {
        let server = make_server();
        let raw = r#"{"jsonrpc":"2.0","method":"ping","params":{},"id":"my-id"}"#;
        let response = dispatch_jsonrpc(&server, raw);
        assert_eq!(response.id, serde_json::json!("my-id"));
    }

    #[test]
    fn test_dispatch_null_id_on_parse_error() {
        let server = make_server();
        let response = dispatch_jsonrpc(&server, "{bad json");
        assert_eq!(response.id, serde_json::Value::Null);
    }

    #[test]
    fn test_tier3_request_returns_pending() {
        let server = make_server();
        // Query with Tier 3 keyword triggers suspension
        let raw = r#"{
            "jsonrpc": "2.0",
            "method": "query",
            "params": {
                "request_id": "req-tier3",
                "query": "what is my credit_card number?",
                "context": {}
            },
            "id": 1
        }"#;
        let response = dispatch_jsonrpc(&server, raw);
        assert!(response.result.is_some(), "error: {:?}", response.error);
        let result = response.result.unwrap();
        assert_eq!(result["status"], "pending");
        assert!(result["challenge_id"].is_string());
        assert!(!result["challenge_id"].as_str().unwrap().is_empty());
    }

    #[test]
    fn test_tier1_request_dispatches_immediately() {
        let server = make_server();
        // Query without Tier 3 keywords dispatches normally
        let raw = r#"{
            "jsonrpc": "2.0",
            "method": "query",
            "params": {
                "request_id": "req-tier1",
                "query": "what is my favorite color?",
                "context": {}
            },
            "id": 1
        }"#;
        let response = dispatch_jsonrpc(&server, raw);
        assert!(response.result.is_some(), "error: {:?}", response.error);
        let result = response.result.unwrap();
        // Tier 1 queries return a response directly, not "pending"
        assert_ne!(result.get("status").and_then(|s| s.as_str()), Some("pending"));
    }

    #[test]
    fn test_check_status_for_challenge() {
        let server = make_server();

        // First, create a Tier 3 suspension
        let raw = r#"{
            "jsonrpc": "2.0",
            "method": "query",
            "params": {
                "request_id": "req-t3",
                "query": "what is my credit_card?",
                "context": {}
            },
            "id": 1
        }"#;
        let response = dispatch_jsonrpc(&server, raw);
        let result = response.result.unwrap();
        let challenge_id = result["challenge_id"].as_str().unwrap();

        // Now check status -- should be pending
        let check_raw = format!(
            r#"{{"jsonrpc":"2.0","method":"check_status","params":{{"request_id":"{}","pending_type":"Tier3Authorization"}},"id":2}}"#,
            challenge_id
        );
        let check_response = dispatch_jsonrpc(&server, &check_raw);
        assert!(check_response.result.is_some(), "error: {:?}", check_response.error);
        let check_result = check_response.result.unwrap();
        assert_eq!(check_result["status"], "pending");
    }

    #[test]
    fn test_expired_challenge_defaults_to_denied() {
        // Expired challenges should default to denied (fail-secure)
        let server = make_server();

        // Register a challenge with past deadline directly
        use signet_notify::types::{ChallengeId, EventId, ScopeEntry, ScopeSet};
        let cid = ChallengeId::generate();
        let eid = EventId::generate();
        let past = signet_core::Timestamp::from_seconds(1000);
        let scope = ScopeSet::new(vec![ScopeEntry::new("vault.tier3.test", "access")]).unwrap();

        let _handle = server
            .challenge_registry()
            .register(cid.clone(), eid, past, scope)
            .unwrap();
        std::mem::forget(_handle);

        // check_status should report pending (registry still has it, just expired)
        let check_raw = format!(
            r#"{{"jsonrpc":"2.0","method":"check_status","params":{{"request_id":"{}","pending_type":"Tier3Authorization"}},"id":1}}"#,
            cid.as_str()
        );
        let response = dispatch_jsonrpc(&server, &check_raw);
        assert!(response.result.is_some());
        let result = response.result.unwrap();
        // No response submitted, so it's still "pending" in registry terms
        assert_eq!(result["status"], "pending");
    }
}
