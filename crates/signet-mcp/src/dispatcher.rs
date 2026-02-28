//! JSON-RPC 2.0 dispatcher.
//!
//! Hand-rolled JSON-RPC 2.0 method routing (no rmcp dependency).
//! Parses raw JSON into JsonRpcRequest, routes to the appropriate handler,
//! and wraps the result in a JsonRpcResponse.

use crate::error::{McpError, McpResult};
use crate::server::McpServer;
use crate::types::{JsonRpcError, JsonRpcRequest, JsonRpcResponse, McpTool};

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
                "description": "Request a scoped capability token (PASETO v4) for a specific purpose",
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
fn handle_tool_invocation(_server: &McpServer, request: &JsonRpcRequest) -> JsonRpcResponse {
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

    // For tool invocations, we need authentication.
    // In the full pipeline, this goes through process_pipeline.
    // Here, we do a simplified dispatch for unauthenticated built-in tools.
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
        assert_eq!(tools.len(), 5);
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
}
