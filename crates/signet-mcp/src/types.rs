//! Domain types for the MCP trust bridge.
//!
//! All core domain types: transport config, sessions, tool requests/responses,
//! pipeline stages, audit entries, policy decisions, and OAuth types.

use serde::{Deserialize, Serialize};
use signet_core::{RequestId, SessionId, Tier, Timestamp};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Transport configuration
// ---------------------------------------------------------------------------

/// Transport kinds supported by the MCP server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportKind {
    Stdio,
    HttpSse,
}

/// Transport-level configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub kind: TransportKind,
    pub host: Option<String>,
    pub port: Option<u16>,
}

/// Full MCP server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    pub transport: TransportConfig,
    pub server_name: String,
    pub server_version: String,
    pub session_timeout_seconds: u64,
    pub pipeline_timeout_ms: u64,
    pub stage_timeouts_ms: HashMap<String, u64>,
}

impl Default for McpServerConfig {
    fn default() -> Self {
        let mut stage_timeouts = HashMap::new();
        stage_timeouts.insert("session_validator".into(), 500);
        stage_timeouts.insert("tier_classifier".into(), 500);
        stage_timeouts.insert("policy_evaluator".into(), 1000);
        stage_timeouts.insert("tool_executor".into(), 5000);
        stage_timeouts.insert("audit_recorder".into(), 1000);
        Self {
            transport: TransportConfig {
                kind: TransportKind::Stdio,
                host: None,
                port: None,
            },
            server_name: "signet-mcp".into(),
            server_version: "0.1.0".into(),
            session_timeout_seconds: 3600,
            pipeline_timeout_ms: 10000,
            stage_timeouts_ms: stage_timeouts,
        }
    }
}

// ---------------------------------------------------------------------------
// Session types
// ---------------------------------------------------------------------------

/// A validated MCP session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: SessionId,
    pub public_key: Vec<u8>,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub revoked: bool,
    pub metadata: HashMap<String, String>,
}

impl Session {
    /// Check if the session is currently valid (not expired and not revoked).
    pub fn is_valid(&self) -> bool {
        !self.revoked && !self.expires_at.is_expired()
    }
}

// ---------------------------------------------------------------------------
// OAuth / PKCE types
// ---------------------------------------------------------------------------

/// PKCE challenge for OAuth 2.1 session provisioning. S256 only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthPkceChallenge {
    pub code_challenge: String,
    pub code_challenge_method: String,
}

/// Request to provision a new session via OAuth PKCE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProvisionRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub pkce_challenge: OAuthPkceChallenge,
    pub scope: Vec<String>,
}

/// Response from session provisioning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProvisionResponse {
    pub authorization_code: String,
    pub redirect_uri: String,
    pub state: String,
    pub expires_in_seconds: u64,
}

/// Token exchange request (authorization code + PKCE verifier).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokenExchange {
    pub authorization_code: String,
    pub code_verifier: String,
    pub client_id: String,
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 types
// ---------------------------------------------------------------------------

/// JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
    pub id: serde_json::Value,
}

/// JSON-RPC 2.0 response.
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
    pub fn error(id: serde_json::Value, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: None,
            error: Some(error),
            id,
        }
    }
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Pipeline types
// ---------------------------------------------------------------------------

/// Sequential middleware pipeline stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipelineStage {
    SessionValidator,
    TierClassifier,
    PolicyEvaluator,
    ToolExecutor,
    AuditRecorder,
}

impl PipelineStage {
    /// Return the config key name for this stage.
    pub fn config_key(&self) -> &'static str {
        match self {
            PipelineStage::SessionValidator => "session_validator",
            PipelineStage::TierClassifier => "tier_classifier",
            PipelineStage::PolicyEvaluator => "policy_evaluator",
            PipelineStage::ToolExecutor => "tool_executor",
            PipelineStage::AuditRecorder => "audit_recorder",
        }
    }
}

/// Pipeline configuration (timeout per stage).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    pub stage_timeouts_ms: HashMap<String, u64>,
    pub total_timeout_ms: u64,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        let mut stage_timeouts = HashMap::new();
        stage_timeouts.insert("session_validator".into(), 500);
        stage_timeouts.insert("tier_classifier".into(), 500);
        stage_timeouts.insert("policy_evaluator".into(), 1000);
        stage_timeouts.insert("tool_executor".into(), 5000);
        stage_timeouts.insert("audit_recorder".into(), 1000);
        Self {
            stage_timeouts_ms: stage_timeouts,
            total_timeout_ms: 10000,
        }
    }
}

/// An authenticated request that has passed session validation.
#[derive(Debug, Clone)]
pub struct AuthenticatedRequest {
    pub session: Session,
    pub request: JsonRpcRequest,
    pub received_at: Timestamp,
    pub signature: Vec<u8>,
    pub signed_message: Vec<u8>,
}

// ---------------------------------------------------------------------------
// MCP Tool types
// ---------------------------------------------------------------------------

/// The five MCP tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum McpTool {
    GetProof,
    Query,
    RequestCapability,
    NegotiateContext,
    CheckStatus,
}

impl McpTool {
    /// Map method name to MCP tool.
    pub fn from_method(method: &str) -> Option<Self> {
        match method {
            "get_proof" => Some(McpTool::GetProof),
            "query" => Some(McpTool::Query),
            "request_capability" => Some(McpTool::RequestCapability),
            "negotiate_context" => Some(McpTool::NegotiateContext),
            "check_status" => Some(McpTool::CheckStatus),
            _ => None,
        }
    }
}

// -- GetProof --

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PredicateOperator {
    Eq,
    Gt,
    Gte,
    Lt,
    Lte,
    In,
}

/// Query for a predicate in a proof request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredicateQuery {
    pub attribute: String,
    pub operator: PredicateOperator,
    pub value: serde_json::Value,
}

/// Type of proof to generate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofType {
    SdJwt,
    Bbs,
    Bulletproof,
}

/// Request to generate a proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetProofRequest {
    pub request_id: RequestId,
    pub predicates: Vec<PredicateQuery>,
    pub proof_type: ProofType,
    pub domain: String,
    pub nonce: String,
}

/// Response containing a generated proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetProofResponse {
    pub request_id: RequestId,
    pub proof_type: ProofType,
    pub proof_bytes: Vec<u8>,
    pub domain: String,
    pub expires_at: Timestamp,
}

// -- Query --

/// Request for a query operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryRequest {
    pub request_id: RequestId,
    pub query: String,
    pub context: HashMap<String, String>,
}

/// Conclusion-only response for Tier 2 queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conclusion {
    pub summary: String,
    pub confidence: f64,
    pub reasoning: String,
}

/// Tier 1 query response: direct proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tier1QueryResponse {
    pub request_id: RequestId,
    pub answer: serde_json::Value,
    pub proof: Option<Vec<u8>>,
}

/// Tier 2 query response: conclusions only, no raw data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tier2QueryResponse {
    pub request_id: RequestId,
    pub conclusions: Vec<Conclusion>,
}

/// Tier 3 query response: suspended pending user authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tier3QueryResponse {
    pub request_id: RequestId,
    pub status: PendingStatus,
    pub challenge_id: String,
}

/// A single result item from a query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResultItem {
    pub key: String,
    pub value: serde_json::Value,
    pub tier: Tier,
}

/// Union response for queries, determined by tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryResponse {
    Tier1(Tier1QueryResponse),
    Tier2(Tier2QueryResponse),
    Tier3(Tier3QueryResponse),
}

// -- RequestCapability --

/// Request for a scoped capability token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestCapabilityRequest {
    pub request_id: RequestId,
    pub capability_type: String,
    pub domain: String,
    pub purpose: String,
    pub constraints: HashMap<String, serde_json::Value>,
}

/// PASETO claims embedded in capability tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasetoClaims {
    pub issuer: String,
    pub subject: String,
    pub audience: String,
    pub expiration: String,
    pub not_before: String,
    pub issued_at: String,
    pub purpose: String,
    pub constraints: HashMap<String, serde_json::Value>,
}

/// Response containing a capability token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestCapabilityResponse {
    pub request_id: RequestId,
    pub token: String,
    pub claims: PasetoClaims,
    pub expires_at: Timestamp,
}

// -- NegotiateContext --

/// Disclosure mode for context negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisclosureMode {
    /// Disclose specific attributes.
    Selective,
    /// Prove a predicate without revealing the value.
    ZeroKnowledge,
    /// Provide only conclusions from agent reasoning.
    ConclusionOnly,
}

/// A proposed disclosure in context negotiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedDisclosure {
    pub attribute: String,
    pub mode: DisclosureMode,
    pub justification: String,
}

/// Request to negotiate context disclosure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiateContextRequest {
    pub request_id: RequestId,
    pub counterparty: String,
    pub proposed_disclosures: Vec<ProposedDisclosure>,
    pub purpose: String,
}

/// State of a context negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NegotiateContextState {
    Proposed,
    CounterOffered,
    Accepted,
    Rejected,
    Expired,
}

/// Entry in the negotiation state map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiateContextStateEntry {
    pub state: NegotiateContextState,
    pub updated_at: Timestamp,
    pub disclosures: Vec<ProposedDisclosure>,
}

/// Map from request_id to negotiation state.
pub type NegotiateContextStateMap = HashMap<String, NegotiateContextStateEntry>;

/// Response from context negotiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiateContextResponse {
    pub request_id: RequestId,
    pub state: NegotiateContextState,
    pub accepted_disclosures: Vec<ProposedDisclosure>,
    pub counter_proposal: Option<Vec<ProposedDisclosure>>,
}

// -- CheckStatus --

/// Types of pending requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingRequestType {
    Tier3Authorization,
    NegotiateContext,
    CapabilityGrant,
}

/// Status of a pending request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// Request to check the status of a pending operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckStatusRequest {
    pub request_id: RequestId,
    pub pending_type: PendingRequestType,
}

/// Response with current status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckStatusResponse {
    pub request_id: RequestId,
    pub pending_type: PendingRequestType,
    pub status: PendingStatus,
    pub detail: Option<String>,
    pub updated_at: Timestamp,
}

// ---------------------------------------------------------------------------
// Policy types
// ---------------------------------------------------------------------------

/// Decision from policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    Permit,
    Deny,
    Anomaly,
}

/// Result of a policy evaluation in the MCP pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationResult {
    pub decision: PolicyDecision,
    pub tier: Tier,
    pub reason: String,
    pub evaluated_at: Timestamp,
}

// ---------------------------------------------------------------------------
// Audit types
// ---------------------------------------------------------------------------

/// An MCP-level audit entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub entry_id: String,
    pub session_id: SessionId,
    pub request_id: RequestId,
    pub tool: McpTool,
    pub tier: Tier,
    pub decision: PolicyDecision,
    pub timestamp: Timestamp,
    pub duration_ms: u64,
    pub metadata: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Session registry types
// ---------------------------------------------------------------------------

/// Thread-safe session registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRegistry {
    pub sessions: HashMap<String, Session>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_kind_serde() {
        let kind = TransportKind::Stdio;
        let json = serde_json::to_string(&kind).unwrap();
        let parsed: TransportKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, parsed);
    }

    #[test]
    fn test_mcp_server_config_default() {
        let config = McpServerConfig::default();
        assert_eq!(config.server_name, "signet-mcp");
        assert_eq!(config.session_timeout_seconds, 3600);
        assert_eq!(config.pipeline_timeout_ms, 10000);
        assert_eq!(config.stage_timeouts_ms.len(), 5);
    }

    #[test]
    fn test_session_validity() {
        let now = Timestamp::now();
        let session = Session {
            session_id: SessionId::new("test-session"),
            public_key: vec![0u8; 32],
            created_at: now,
            expires_at: Timestamp::from_seconds(now.seconds_since_epoch + 3600),
            revoked: false,
            metadata: HashMap::new(),
        };
        assert!(session.is_valid());
    }

    #[test]
    fn test_session_expired() {
        let session = Session {
            session_id: SessionId::new("test-session"),
            public_key: vec![0u8; 32],
            created_at: Timestamp::from_seconds(100),
            expires_at: Timestamp::from_seconds(101),
            revoked: false,
            metadata: HashMap::new(),
        };
        assert!(!session.is_valid());
    }

    #[test]
    fn test_session_revoked() {
        let now = Timestamp::now();
        let session = Session {
            session_id: SessionId::new("test-session"),
            public_key: vec![0u8; 32],
            created_at: now,
            expires_at: Timestamp::from_seconds(now.seconds_since_epoch + 3600),
            revoked: true,
            metadata: HashMap::new(),
        };
        assert!(!session.is_valid());
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
        let resp = JsonRpcResponse::error(
            serde_json::json!(1),
            JsonRpcError {
                code: -32600,
                message: "Invalid Request".into(),
                data: None,
            },
        );
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
        assert_eq!(resp.error.as_ref().unwrap().code, -32600);
    }

    #[test]
    fn test_mcp_tool_from_method() {
        assert_eq!(McpTool::from_method("get_proof"), Some(McpTool::GetProof));
        assert_eq!(McpTool::from_method("query"), Some(McpTool::Query));
        assert_eq!(
            McpTool::from_method("request_capability"),
            Some(McpTool::RequestCapability)
        );
        assert_eq!(
            McpTool::from_method("negotiate_context"),
            Some(McpTool::NegotiateContext)
        );
        assert_eq!(
            McpTool::from_method("check_status"),
            Some(McpTool::CheckStatus)
        );
        assert_eq!(McpTool::from_method("unknown"), None);
    }

    #[test]
    fn test_pipeline_stage_config_keys() {
        assert_eq!(
            PipelineStage::SessionValidator.config_key(),
            "session_validator"
        );
        assert_eq!(
            PipelineStage::TierClassifier.config_key(),
            "tier_classifier"
        );
        assert_eq!(
            PipelineStage::PolicyEvaluator.config_key(),
            "policy_evaluator"
        );
        assert_eq!(PipelineStage::ToolExecutor.config_key(), "tool_executor");
        assert_eq!(PipelineStage::AuditRecorder.config_key(), "audit_recorder");
    }

    #[test]
    fn test_predicate_operator_serde() {
        let op = PredicateOperator::Gte;
        let json = serde_json::to_string(&op).unwrap();
        let parsed: PredicateOperator = serde_json::from_str(&json).unwrap();
        assert_eq!(op, parsed);
    }

    #[test]
    fn test_disclosure_mode_variants() {
        assert_ne!(DisclosureMode::Selective, DisclosureMode::ZeroKnowledge);
        assert_ne!(
            DisclosureMode::ZeroKnowledge,
            DisclosureMode::ConclusionOnly
        );
    }

    #[test]
    fn test_negotiate_context_state_variants() {
        let states = vec![
            NegotiateContextState::Proposed,
            NegotiateContextState::CounterOffered,
            NegotiateContextState::Accepted,
            NegotiateContextState::Rejected,
            NegotiateContextState::Expired,
        ];
        for (i, s) in states.iter().enumerate() {
            for (j, t) in states.iter().enumerate() {
                if i == j {
                    assert_eq!(s, t);
                } else {
                    assert_ne!(s, t);
                }
            }
        }
    }

    #[test]
    fn test_pending_status_variants() {
        assert_ne!(PendingStatus::Pending, PendingStatus::Approved);
        assert_ne!(PendingStatus::Denied, PendingStatus::Expired);
    }

    #[test]
    fn test_policy_decision_variants() {
        assert_ne!(PolicyDecision::Permit, PolicyDecision::Deny);
        assert_ne!(PolicyDecision::Deny, PolicyDecision::Anomaly);
    }

    #[test]
    fn test_session_registry_new() {
        let registry = SessionRegistry::new();
        assert!(registry.sessions.is_empty());
    }

    #[test]
    fn test_query_response_variants() {
        let t1 = QueryResponse::Tier1(Tier1QueryResponse {
            request_id: RequestId::new("r1"),
            answer: serde_json::json!(true),
            proof: None,
        });
        assert!(matches!(t1, QueryResponse::Tier1(_)));

        let t2 = QueryResponse::Tier2(Tier2QueryResponse {
            request_id: RequestId::new("r2"),
            conclusions: vec![],
        });
        assert!(matches!(t2, QueryResponse::Tier2(_)));
    }

    #[test]
    fn test_proof_type_variants() {
        assert_ne!(ProofType::SdJwt, ProofType::Bbs);
        assert_ne!(ProofType::Bbs, ProofType::Bulletproof);
    }

    #[test]
    fn test_pipeline_config_default() {
        let config = PipelineConfig::default();
        assert_eq!(config.total_timeout_ms, 10000);
        assert_eq!(config.stage_timeouts_ms.len(), 5);
    }
}
