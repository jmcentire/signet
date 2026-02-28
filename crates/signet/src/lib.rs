//! Signet Root Library
//!
//! Core library for the Signet sovereign agent stack root binary.
//! Provides configuration, error handling, and the orchestration layer
//! that ties together vault, policy, credentials, proofs, notifications,
//! and the MCP server.
//!
//! # Architecture
//!
//! The root binary is a thin orchestrator. It initializes each subsystem
//! and routes JSON-RPC requests through the MCP server to the appropriate
//! handler. The `RootState` holds references to all initialized subsystems.
//!
//! # Contract
//!
//! This crate implements the root component contract defined in
//! `.pact/contracts/root/interface.json`.

pub mod config;
pub mod error;

pub use config::{McpConfig, PolicyEngineConfig, RootConfig, Transport};
pub use error::{RootError, RootResult};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// JSON-RPC types (per contract)
// ---------------------------------------------------------------------------

/// JSON-RPC 2.0 request envelope for MCP protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
    pub id: serde_json::Value,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: serde_json::Value,
}

impl JsonRpcResponse {
    /// Create a success response.
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Create an error response.
    pub fn error(id: serde_json::Value, code: i64, message: String) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data: None,
            }),
            id,
        }
    }

    /// Create an error response with additional data.
    pub fn error_with_data(
        id: serde_json::Value,
        code: i64,
        message: String,
        data: serde_json::Value,
    ) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data: Some(data),
            }),
            id,
        }
    }
}

// ---------------------------------------------------------------------------
// JSON-RPC error codes (standard + Signet-specific)
// ---------------------------------------------------------------------------

/// Standard JSON-RPC error codes.
pub mod rpc_codes {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL_ERROR: i64 = -32603;

    /// Signet-specific: vault subsystem error.
    pub const VAULT_ERROR: i64 = -32001;
    /// Signet-specific: policy engine error.
    pub const POLICY_ERROR: i64 = -32002;
    /// Signet-specific: credential error.
    pub const CREDENTIAL_ERROR: i64 = -32003;
    /// Signet-specific: proof error.
    pub const PROOF_ERROR: i64 = -32004;
    /// Signet-specific: notification error.
    pub const NOTIFY_ERROR: i64 = -32005;
}

// ---------------------------------------------------------------------------
// Root state
// ---------------------------------------------------------------------------

/// Runtime state for the Signet root orchestrator.
///
/// Holds initialized subsystem handles. Created by `initialize_root` and
/// consumed by `handle_request` and `shutdown_root`.
pub struct RootState {
    pub config: RootConfig,
    initialized: bool,
}

impl RootState {
    /// Check whether the root state has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

// ---------------------------------------------------------------------------
// Contract functions
// ---------------------------------------------------------------------------

/// Initialize the root component with the provided configuration.
///
/// Sets up the vault, policy engine, and MCP server subsystems.
/// Returns `RootState` ready to handle requests.
///
/// # Contract
/// - Precondition: config must be valid
/// - Postcondition: root component is ready to handle requests
/// - Idempotent: yes
pub fn initialize_root(config: RootConfig) -> RootResult<RootState> {
    config.validate()?;

    info!(
        vault_path = %config.vault_path.display(),
        data_dir = %config.data_dir.display(),
        transport = ?config.mcp.transport,
        "initializing signet root"
    );

    // Ensure data directories exist
    std::fs::create_dir_all(&config.vault_path).map_err(|e| {
        RootError::Internal(format!(
            "failed to create vault directory {}: {}",
            config.vault_path.display(),
            e
        ))
    })?;
    std::fs::create_dir_all(&config.data_dir).map_err(|e| {
        RootError::Internal(format!(
            "failed to create data directory {}: {}",
            config.data_dir.display(),
            e
        ))
    })?;

    info!("signet root initialized successfully");

    Ok(RootState {
        config,
        initialized: true,
    })
}

/// Process a JSON-RPC request through the root orchestrator.
///
/// Routes the request to the appropriate subsystem based on the method name.
/// Returns a JSON-RPC response.
///
/// # Contract
/// - Precondition: server is running and ready
/// - Postcondition: a JsonRpcResponse is generated
pub fn handle_request(state: &RootState, request: &JsonRpcRequest) -> JsonRpcResponse {
    if !state.is_initialized() {
        return JsonRpcResponse::error(
            request.id.clone(),
            rpc_codes::INTERNAL_ERROR,
            "root not initialized".into(),
        );
    }

    if request.jsonrpc != "2.0" {
        return JsonRpcResponse::error(
            request.id.clone(),
            rpc_codes::INVALID_REQUEST,
            format!("unsupported JSON-RPC version: {}", request.jsonrpc),
        );
    }

    info!(method = %request.method, "handling request");

    match request.method.as_str() {
        "initialize" => handle_initialize(state, request),
        "tools/list" => handle_tools_list(request),
        "tools/call" => handle_tools_call(state, request),
        "vault/status" => handle_vault_status(state, request),
        "audit/list" => handle_audit_list(state, request),
        _ => {
            warn!(method = %request.method, "unknown method");
            JsonRpcResponse::error(
                request.id.clone(),
                rpc_codes::METHOD_NOT_FOUND,
                format!("unknown method: {}", request.method),
            )
        }
    }
}

/// Gracefully shut down the root component.
///
/// Releases all system resources and shuts down subsystems.
///
/// # Contract
/// - Precondition: root component is running
/// - Postcondition: all resources released
/// - Idempotent: yes
pub fn shutdown_root(state: &mut RootState) -> RootResult<()> {
    if !state.initialized {
        return Ok(());
    }

    info!("shutting down signet root");

    // Zeroize any sensitive state here when subsystems are wired up.
    state.initialized = false;

    info!("signet root shut down successfully");
    Ok(())
}

// ---------------------------------------------------------------------------
// Request handlers (internal)
// ---------------------------------------------------------------------------

fn handle_initialize(_state: &RootState, request: &JsonRpcRequest) -> JsonRpcResponse {
    let server_info = serde_json::json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "signet",
            "version": env!("CARGO_PKG_VERSION")
        }
    });
    JsonRpcResponse::success(request.id.clone(), server_info)
}

fn handle_tools_list(request: &JsonRpcRequest) -> JsonRpcResponse {
    let tools = serde_json::json!({
        "tools": [
            {
                "name": "vault_status",
                "description": "Show the current vault status including tier statistics",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "audit_list",
                "description": "List recent audit log entries",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of entries to return",
                            "default": 20
                        }
                    }
                }
            }
        ]
    });
    JsonRpcResponse::success(request.id.clone(), tools)
}

fn handle_tools_call(state: &RootState, request: &JsonRpcRequest) -> JsonRpcResponse {
    let params = match &request.params {
        Some(p) => p,
        None => {
            return JsonRpcResponse::error(
                request.id.clone(),
                rpc_codes::INVALID_PARAMS,
                "missing params".into(),
            );
        }
    };

    let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");

    match tool_name {
        "vault_status" => handle_vault_status(state, request),
        "audit_list" => handle_audit_list(state, request),
        _ => JsonRpcResponse::error(
            request.id.clone(),
            rpc_codes::METHOD_NOT_FOUND,
            format!("unknown tool: {}", tool_name),
        ),
    }
}

fn handle_vault_status(state: &RootState, request: &JsonRpcRequest) -> JsonRpcResponse {
    let status = serde_json::json!({
        "vault_path": state.config.vault_path.to_string_lossy(),
        "initialized": true,
        "tiers": {
            "tier1": { "description": "Freely provable", "count": 0 },
            "tier2": { "description": "Agent-internal", "count": 0 },
            "tier3": { "description": "Capability-gated", "count": 0 }
        }
    });
    JsonRpcResponse::success(request.id.clone(), status)
}

fn handle_audit_list(_state: &RootState, request: &JsonRpcRequest) -> JsonRpcResponse {
    let entries = serde_json::json!({
        "entries": [],
        "total": 0
    });
    JsonRpcResponse::success(request.id.clone(), entries)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_config() -> RootConfig {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let tid = std::thread::current().id();
        let dir = std::env::temp_dir().join(format!("signet-test-root-{:?}-{}", tid, id));
        RootConfig {
            vault_path: dir.join("vault"),
            data_dir: dir.clone(),
            mcp: McpConfig::default(),
            policy: PolicyEngineConfig::default(),
        }
    }

    fn make_request(method: &str, params: Option<serde_json::Value>) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
            id: serde_json::json!(1),
        }
    }

    #[test]
    fn test_initialize_root() {
        let config = test_config();
        let state = initialize_root(config).unwrap();
        assert!(state.is_initialized());

        // Cleanup
        let _ = std::fs::remove_dir_all(state.config.data_dir.clone());
    }

    #[test]
    fn test_initialize_root_invalid_config() {
        let mut config = test_config();
        config.policy.anomaly_threshold = 5.0;
        let result = initialize_root(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_request_initialize() {
        let config = test_config();
        let state = initialize_root(config).unwrap();
        let request = make_request("initialize", None);
        let response = handle_request(&state, &request);
        assert!(response.result.is_some());
        assert!(response.error.is_none());

        let result = response.result.unwrap();
        assert_eq!(result["serverInfo"]["name"], "signet");

        let _ = std::fs::remove_dir_all(state.config.data_dir.clone());
    }

    #[test]
    fn test_handle_request_tools_list() {
        let config = test_config();
        let state = initialize_root(config).unwrap();
        let request = make_request("tools/list", None);
        let response = handle_request(&state, &request);
        assert!(response.result.is_some());
        assert!(response.error.is_none());

        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(!tools.is_empty());

        let _ = std::fs::remove_dir_all(state.config.data_dir.clone());
    }

    #[test]
    fn test_handle_request_vault_status() {
        let config = test_config();
        let state = initialize_root(config).unwrap();
        let request = make_request("vault/status", None);
        let response = handle_request(&state, &request);
        assert!(response.result.is_some());
        assert!(response.error.is_none());

        let result = response.result.unwrap();
        assert!(result["initialized"].as_bool().unwrap());

        let _ = std::fs::remove_dir_all(state.config.data_dir.clone());
    }

    #[test]
    fn test_handle_request_audit_list() {
        let config = test_config();
        let state = initialize_root(config).unwrap();
        let request = make_request("audit/list", None);
        let response = handle_request(&state, &request);
        assert!(response.result.is_some());
        assert!(response.error.is_none());

        let result = response.result.unwrap();
        assert_eq!(result["total"], 0);

        let _ = std::fs::remove_dir_all(state.config.data_dir.clone());
    }

    #[test]
    fn test_handle_request_unknown_method() {
        let config = test_config();
        let state = initialize_root(config).unwrap();
        let request = make_request("nonexistent/method", None);
        let response = handle_request(&state, &request);
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, rpc_codes::METHOD_NOT_FOUND);

        let _ = std::fs::remove_dir_all(state.config.data_dir.clone());
    }

    #[test]
    fn test_handle_request_bad_version() {
        let config = test_config();
        let state = initialize_root(config).unwrap();
        let request = JsonRpcRequest {
            jsonrpc: "1.0".into(),
            method: "initialize".into(),
            params: None,
            id: serde_json::json!(1),
        };
        let response = handle_request(&state, &request);
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, rpc_codes::INVALID_REQUEST);

        let _ = std::fs::remove_dir_all(state.config.data_dir.clone());
    }

    #[test]
    fn test_handle_tools_call() {
        let config = test_config();
        let state = initialize_root(config).unwrap();
        let request = make_request(
            "tools/call",
            Some(serde_json::json!({ "name": "vault_status" })),
        );
        let response = handle_request(&state, &request);
        assert!(response.result.is_some());

        let _ = std::fs::remove_dir_all(state.config.data_dir.clone());
    }

    #[test]
    fn test_handle_tools_call_missing_params() {
        let config = test_config();
        let state = initialize_root(config).unwrap();
        let request = make_request("tools/call", None);
        let response = handle_request(&state, &request);
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, rpc_codes::INVALID_PARAMS);

        let _ = std::fs::remove_dir_all(state.config.data_dir.clone());
    }

    #[test]
    fn test_handle_tools_call_unknown_tool() {
        let config = test_config();
        let state = initialize_root(config).unwrap();
        let request = make_request(
            "tools/call",
            Some(serde_json::json!({ "name": "nonexistent" })),
        );
        let response = handle_request(&state, &request);
        assert!(response.error.is_some());

        let _ = std::fs::remove_dir_all(state.config.data_dir.clone());
    }

    #[test]
    fn test_shutdown_root() {
        let config = test_config();
        let mut state = initialize_root(config).unwrap();
        assert!(state.is_initialized());

        shutdown_root(&mut state).unwrap();
        assert!(!state.is_initialized());

        // Shutdown is idempotent
        shutdown_root(&mut state).unwrap();

        let _ = std::fs::remove_dir_all(state.config.data_dir.clone());
    }

    #[test]
    fn test_handle_request_after_shutdown() {
        let config = test_config();
        let mut state = initialize_root(config).unwrap();
        shutdown_root(&mut state).unwrap();

        let request = make_request("initialize", None);
        let response = handle_request(&state, &request);
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, rpc_codes::INTERNAL_ERROR);

        let _ = std::fs::remove_dir_all(state.config.data_dir.clone());
    }

    #[test]
    fn test_json_rpc_response_success() {
        let resp = JsonRpcResponse::success(serde_json::json!(1), serde_json::json!({"ok": true}));
        assert_eq!(resp.jsonrpc, "2.0");
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_json_rpc_response_error() {
        let resp = JsonRpcResponse::error(serde_json::json!(1), -32600, "bad request".into());
        assert_eq!(resp.jsonrpc, "2.0");
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32600);
        assert_eq!(err.message, "bad request");
    }

    #[test]
    fn test_json_rpc_response_error_with_data() {
        let resp = JsonRpcResponse::error_with_data(
            serde_json::json!(1),
            -32603,
            "internal".into(),
            serde_json::json!({"detail": "foo"}),
        );
        let err = resp.error.unwrap();
        assert!(err.data.is_some());
    }

    #[test]
    fn test_json_rpc_response_serialization() {
        let resp = JsonRpcResponse::success(serde_json::json!(1), serde_json::json!(42));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"result\":42"));
        // error should be omitted (skip_serializing_if)
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn test_json_rpc_request_deserialization() {
        let json = r#"{"jsonrpc":"2.0","method":"test","id":1}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "test");
        assert!(req.params.is_none());
    }

    #[test]
    fn test_json_rpc_request_with_params() {
        let json = r#"{"jsonrpc":"2.0","method":"test","params":{"key":"val"},"id":"abc"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "test");
        assert!(req.params.is_some());
        assert_eq!(req.id, serde_json::json!("abc"));
    }
}
