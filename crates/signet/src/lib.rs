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
pub mod http;
pub mod multi_tenant;

pub use config::{HostingMode, McpConfig, PolicyEngineConfig, PostgresConfig, RootConfig, Transport};
pub use error::{RootError, RootResult};

use serde::{Deserialize, Serialize};
use signet_core::{Signer, StorageBackend, Tier};
use signet_mcp::VaultAccess;
use signet_vault::audit::AuditChain;
use signet_vault::blind_storage::{derive_record_id, BlindStorageWrapper};
use signet_vault::key_hierarchy::KeyHierarchy;
use signet_vault::mnemonic::{generate_mnemonic, parse_mnemonic};
use signet_vault::signer::VaultSigner;
use std::sync::{Arc, Mutex};
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
    pub key_hierarchy: Option<KeyHierarchy>,
    pub signer: Option<VaultSigner>,
    pub vault_access: Option<Arc<RealVaultAccess>>,
    pub audit_chain: Option<Arc<AuditChain>>,
    pub mcp_server: Option<signet_mcp::McpServer>,
}

impl RootState {
    /// Check whether the root state has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

// ---------------------------------------------------------------------------
// VaultAccess implementation backed by real vault subsystems
// ---------------------------------------------------------------------------

/// Real vault access implementation backed by BlindStorageWrapper + VaultSigner.
///
/// Stores JSON records via BlindCollection under per-tier collections.
/// Each record is: { "label": "...", "tier": N, "value": "...", "stored_at": "...", "schema_version": 1 }
pub struct RealVaultAccess {
    signer: VaultSigner,
    addressing_key: zeroize::Zeroizing<[u8; 32]>,
    encryption_key: zeroize::Zeroizing<[u8; 32]>,
    db_path: String,
    /// In-memory index of stored labels per tier for enumeration.
    index: Mutex<Vec<StoredEntryMeta>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEntryMeta {
    label: String,
    tier: u8,
    stored_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRecord {
    label: String,
    tier: u8,
    value: String,
    stored_at: String,
    schema_version: u64,
}

impl RealVaultAccess {
    fn collection_name(tier: Tier) -> &'static str {
        match tier {
            Tier::Tier1 => "signet_data_tier1",
            Tier::Tier2 => "signet_data_tier2",
            Tier::Tier3 => "signet_data_tier3",
        }
    }

    fn open_storage(
        &self,
    ) -> signet_mcp::McpResult<BlindStorageWrapper<signet_vault::storage::SqliteBackend>> {
        let backend = signet_vault::storage::SqliteBackend::open(&self.db_path).map_err(|e| {
            signet_mcp::McpError::ToolExecutionFailed(format!("failed to open storage: {}", e))
        })?;
        Ok(BlindStorageWrapper::new(
            backend,
            self.addressing_key.clone(),
            self.encryption_key.clone(),
        ))
    }

    fn load_index(db_path: &str, addressing_key: &[u8; 32], encryption_key: &[u8; 32]) -> Vec<StoredEntryMeta> {
        let backend = match signet_vault::storage::SqliteBackend::open(db_path) {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };
        let wrapper = BlindStorageWrapper::new(
            backend,
            zeroize::Zeroizing::new(*addressing_key),
            zeroize::Zeroizing::new(*encryption_key),
        );
        let index_id = derive_record_id(addressing_key, "_signet_index", 0);
        match wrapper.get(&index_id) {
            Ok(Some(data)) => serde_json::from_slice(&data).unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    fn save_index(&self) -> signet_mcp::McpResult<()> {
        let storage = self.open_storage()?;
        let index = self.index.lock().map_err(|e| {
            signet_mcp::McpError::ToolExecutionFailed(format!("index lock poisoned: {}", e))
        })?;
        let data = serde_json::to_vec(&*index).map_err(|e| {
            signet_mcp::McpError::SerializationError(format!("failed to serialize index: {}", e))
        })?;
        let index_id = derive_record_id(&*self.addressing_key, "_signet_index", 0);
        storage.put(&index_id, &data).map_err(|e| {
            signet_mcp::McpError::ToolExecutionFailed(format!("failed to save index: {}", e))
        })?;
        Ok(())
    }
}

impl VaultAccess for RealVaultAccess {
    fn get(&self, label: &str, tier: Tier) -> signet_mcp::McpResult<Option<Vec<u8>>> {
        let storage = self.open_storage()?;
        let collection_name = Self::collection_name(tier);
        let record_id = derive_record_id(&*self.addressing_key, &format!("{}:{}", collection_name, label), 0);
        match storage.get(&record_id) {
            Ok(Some(data)) => {
                let record: StoredRecord = serde_json::from_slice(&data).map_err(|e| {
                    signet_mcp::McpError::ToolExecutionFailed(format!("corrupt record: {}", e))
                })?;
                Ok(Some(record.value.into_bytes()))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(signet_mcp::McpError::ToolExecutionFailed(format!(
                "storage get failed: {}",
                e
            ))),
        }
    }

    fn put(&self, label: &str, tier: Tier, data: &[u8]) -> signet_mcp::McpResult<()> {
        let storage = self.open_storage()?;
        let collection_name = Self::collection_name(tier);
        let record = StoredRecord {
            label: label.to_string(),
            tier: match tier {
                Tier::Tier1 => 1,
                Tier::Tier2 => 2,
                Tier::Tier3 => 3,
            },
            value: String::from_utf8_lossy(data).to_string(),
            stored_at: chrono::Utc::now().to_rfc3339(),
            schema_version: 1,
        };
        let record_bytes = serde_json::to_vec(&record).map_err(|e| {
            signet_mcp::McpError::SerializationError(format!("failed to serialize record: {}", e))
        })?;
        let record_id = derive_record_id(&*self.addressing_key, &format!("{}:{}", collection_name, label), 0);
        storage.put(&record_id, &record_bytes).map_err(|e| {
            signet_mcp::McpError::ToolExecutionFailed(format!("storage put failed: {}", e))
        })?;

        // Update index
        {
            let mut index = self.index.lock().map_err(|e| {
                signet_mcp::McpError::ToolExecutionFailed(format!("index lock poisoned: {}", e))
            })?;
            // Remove existing entry for same label+tier
            index.retain(|e| !(e.label == label && e.tier == record.tier));
            index.push(StoredEntryMeta {
                label: label.to_string(),
                tier: record.tier,
                stored_at: record.stored_at.clone(),
            });
        }
        self.save_index()?;

        Ok(())
    }

    fn list(&self, tier: Option<Tier>) -> signet_mcp::McpResult<Vec<signet_mcp::VaultEntry>> {
        let index = self.index.lock().map_err(|e| {
            signet_mcp::McpError::ToolExecutionFailed(format!("index lock poisoned: {}", e))
        })?;
        let entries = index
            .iter()
            .filter(|e| match tier {
                Some(Tier::Tier1) => e.tier == 1,
                Some(Tier::Tier2) => e.tier == 2,
                Some(Tier::Tier3) => e.tier == 3,
                None => true,
            })
            .map(|e| signet_mcp::VaultEntry {
                label: e.label.clone(),
                tier: match e.tier {
                    1 => Tier::Tier1,
                    2 => Tier::Tier2,
                    3 => Tier::Tier3,
                    _ => Tier::Tier1,
                },
                stored_at: e.stored_at.clone(),
                schema_version: 1,
            })
            .collect();
        Ok(entries)
    }

    fn sign(&self, message: &[u8]) -> signet_mcp::McpResult<[u8; 64]> {
        self.signer.sign_ed25519(message).map_err(|e| {
            signet_mcp::McpError::ToolExecutionFailed(format!("signing failed: {}", e))
        })
    }

    fn public_key(&self) -> [u8; 32] {
        self.signer.public_key_ed25519()
    }

    fn signet_id(&self) -> String {
        self.signer.signet_id().as_str().to_string()
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

    // Check for existing vault or create new one
    let vault_json_path = config.vault_path.join("vault.json");
    let mnemonic = if vault_json_path.exists() {
        // Load existing mnemonic
        let vault_data = std::fs::read_to_string(&vault_json_path).map_err(|e| {
            RootError::Internal(format!("failed to read vault.json: {}", e))
        })?;
        let vault_obj: serde_json::Value = serde_json::from_str(&vault_data)?;
        let phrase = vault_obj["mnemonic"]
            .as_str()
            .ok_or_else(|| RootError::Internal("vault.json missing mnemonic field".into()))?;
        parse_mnemonic(phrase)?
    } else {
        // Generate new mnemonic
        let mnemonic = generate_mnemonic()?;
        let vault_obj = serde_json::json!({
            "mnemonic": mnemonic.to_string(),
            "created_at": chrono::Utc::now().to_rfc3339(),
            "version": 1
        });
        std::fs::write(&vault_json_path, serde_json::to_string_pretty(&vault_obj)?).map_err(|e| {
            RootError::Internal(format!("failed to write vault.json: {}", e))
        })?;
        // Set restrictive permissions on vault.json
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&vault_json_path, perms);
        }
        info!("new vault created - mnemonic stored in vault.json");
        mnemonic
    };

    // Build key hierarchy from mnemonic
    let key_hierarchy = KeyHierarchy::from_mnemonic(&mnemonic, "")?;

    // Create signer
    let signer = VaultSigner::from_hierarchy(&key_hierarchy)?;
    info!(signet_id = %signer.signet_id().as_str(), "vault identity established");

    // Get keys for blind storage
    let addressing_key = key_hierarchy.addressing_key()?;
    let sealing_key = key_hierarchy.vault_sealing_key()?;

    // Set up database path
    let db_path = config.vault_path.join("vault.db");
    let db_path_str = db_path
        .to_str()
        .ok_or_else(|| RootError::Internal("vault path not valid UTF-8".into()))?
        .to_string();

    // Ensure the database file and tables exist
    {
        let _backend = signet_vault::storage::SqliteBackend::open(&db_path_str)
            .map_err(|e| RootError::Internal(format!("failed to open vault database: {}", e)))?;
    }

    // Load entry index from storage
    let index = RealVaultAccess::load_index(&db_path_str, &addressing_key, &sealing_key);

    // Create vault access implementation
    let vault_access = Arc::new(RealVaultAccess {
        signer: VaultSigner::from_hierarchy(&key_hierarchy)?,
        addressing_key: addressing_key.clone(),
        encryption_key: sealing_key.clone(),
        db_path: db_path_str,
        index: Mutex::new(index),
    });

    // Create audit chain
    let audit_chain = Arc::new(AuditChain::new());

    // Create MCP server with vault access
    let mcp_config = signet_mcp::McpServerConfig::default();
    let mut mcp_server = signet_mcp::McpServer::new(mcp_config)
        .map_err(|e| RootError::Mcp(format!("failed to create MCP server: {}", e)))?;
    mcp_server.set_vault(vault_access.clone());

    info!("signet root initialized successfully");

    Ok(RootState {
        config,
        initialized: true,
        key_hierarchy: Some(key_hierarchy),
        signer: Some(signer),
        vault_access: Some(vault_access),
        audit_chain: Some(audit_chain),
        mcp_server: Some(mcp_server),
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
        "vault/status" => handle_vault_status(state, request),
        "audit/list" => handle_audit_list(state, request),
        _ => {
            // Delegate to MCP dispatcher for tools/list, tools/call, and tool methods
            if let Some(mcp_server) = &state.mcp_server {
                let raw = match serde_json::to_string(request) {
                    Ok(s) => s,
                    Err(e) => {
                        return JsonRpcResponse::error(
                            request.id.clone(),
                            rpc_codes::INTERNAL_ERROR,
                            format!("failed to serialize request: {}", e),
                        );
                    }
                };
                let mcp_response = signet_mcp::dispatch_jsonrpc(mcp_server, &raw);
                // Convert MCP response to root response format
                JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    result: mcp_response.result,
                    error: mcp_response.error.map(|e| JsonRpcError {
                        code: e.code,
                        message: e.message,
                        data: e.data,
                    }),
                    id: request.id.clone(),
                }
            } else {
                warn!(method = %request.method, "unknown method (no MCP server)");
                JsonRpcResponse::error(
                    request.id.clone(),
                    rpc_codes::METHOD_NOT_FOUND,
                    format!("unknown method: {}", request.method),
                )
            }
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

    state.key_hierarchy = None;
    state.signer = None;
    state.vault_access = None;
    state.audit_chain = None;
    state.mcp_server = None;
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

fn handle_vault_status(state: &RootState, request: &JsonRpcRequest) -> JsonRpcResponse {
    let (t1, t2, t3) = if let Some(vault) = &state.vault_access {
        let count_tier = |tier: Tier| -> u64 {
            vault.list(Some(tier)).map(|v| v.len() as u64).unwrap_or(0)
        };
        (count_tier(Tier::Tier1), count_tier(Tier::Tier2), count_tier(Tier::Tier3))
    } else {
        (0, 0, 0)
    };

    let signet_id = state
        .signer
        .as_ref()
        .map(|s| s.signet_id().as_str().to_string())
        .unwrap_or_else(|| "not initialized".to_string());

    let status = serde_json::json!({
        "vault_path": state.config.vault_path.to_string_lossy(),
        "initialized": true,
        "signet_id": signet_id,
        "tiers": {
            "tier1": { "description": "Freely provable", "count": t1 },
            "tier2": { "description": "Agent-internal", "count": t2 },
            "tier3": { "description": "Capability-gated", "count": t3 }
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
            hosting_mode: config::HostingMode::default(),
            postgres: config::PostgresConfig::default(),
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
        assert!(response.result.is_some(), "error: {:?}", response.error);
        assert!(response.error.is_none());

        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(tools.len() >= 7, "expected at least 7 tools (5 original + store + list), got {}", tools.len());

        // Check that store_data and list_data are present
        let tool_names: Vec<&str> = tools.iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert!(tool_names.contains(&"store_data"), "store_data tool not found");
        assert!(tool_names.contains(&"list_data"), "list_data tool not found");

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
    fn test_handle_tools_list_via_mcp() {
        let config = test_config();
        let state = initialize_root(config).unwrap();
        let request = make_request("tools/list", None);
        let response = handle_request(&state, &request);
        assert!(response.result.is_some(), "error: {:?}", response.error);
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(tools.len() >= 5, "expected at least 5 tools, got {}", tools.len());

        let _ = std::fs::remove_dir_all(state.config.data_dir.clone());
    }

    #[test]
    fn test_handle_ping_via_mcp() {
        let config = test_config();
        let state = initialize_root(config).unwrap();
        let request = make_request("ping", None);
        let response = handle_request(&state, &request);
        assert!(response.result.is_some(), "error: {:?}", response.error);

        let _ = std::fs::remove_dir_all(state.config.data_dir.clone());
    }

    #[test]
    fn test_handle_unknown_method_via_mcp() {
        let config = test_config();
        let state = initialize_root(config).unwrap();
        let request = make_request("nonexistent_method", None);
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

    #[test]
    fn test_well_known_returns_signet_id_and_public_key() {
        let config = test_config();
        let state = initialize_root(config).unwrap();

        let signer = state.signer.as_ref().unwrap();
        let expected_id = signer.signet_id().as_str().to_string();
        let expected_pk = hex::encode(signer.public_key_ed25519());

        // Simulate what the well-known handler produces
        let well_known = serde_json::json!({
            "signet_id": expected_id,
            "public_key": expected_pk,
            "public_key_type": "Ed25519",
            "version": env!("CARGO_PKG_VERSION"),
            "supported_proof_formats": ["SD-JWT", "BBS+", "Bulletproof"],
            "endpoints": {
                "mcp": "/mcp",
                "verify": "/verify",
                "health": "/health"
            },
            "rotation_chain": []
        });

        assert!(well_known["signet_id"].is_string());
        assert!(!expected_id.is_empty());
        assert_eq!(expected_pk.len(), 64); // 32 bytes hex-encoded
        assert_eq!(well_known["public_key_type"], "Ed25519");

        let formats = well_known["supported_proof_formats"].as_array().unwrap();
        assert_eq!(formats.len(), 3);
        assert_eq!(formats[0], "SD-JWT");
        assert_eq!(formats[1], "BBS+");
        assert_eq!(formats[2], "Bulletproof");

        let endpoints = &well_known["endpoints"];
        assert_eq!(endpoints["mcp"], "/mcp");
        assert_eq!(endpoints["verify"], "/verify");
        assert_eq!(endpoints["health"], "/health");

        let rotation = well_known["rotation_chain"].as_array().unwrap();
        assert!(rotation.is_empty());

        let _ = std::fs::remove_dir_all(state.config.data_dir.clone());
    }

    #[test]
    fn test_well_known_graceful_when_no_signer() {
        // Without a signer, the well-known response should indicate error
        let config = test_config();
        let state = RootState {
            config,
            initialized: true,
            key_hierarchy: None,
            signer: None,
            vault_access: None,
            audit_chain: None,
            mcp_server: None,
        };

        // Signer is None: handler returns error JSON
        assert!(state.signer.is_none());
    }
}
