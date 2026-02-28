//! Signet MCP — Model Context Protocol server and trust bridge.
//!
//! This crate implements the MCP server for the Signet sovereign agent stack.
//! It serves as the trust bridge between the personal agent, the vault, and
//! external agents/services.
//!
//! # Architecture
//!
//! The server processes requests through a sequential middleware pipeline:
//!
//! ```text
//! SessionValidator -> TierClassifier -> PolicyEvaluator -> ToolExecutor -> AuditRecorder
//! ```
//!
//! Each stage has a per-stage timeout. Timeout = DENY (fail-secure).
//!
//! # Tools
//!
//! Five MCP tools are exposed:
//! - `get_proof`: Generate ZK/selective-disclosure proofs
//! - `query`: Query the vault with tier-based response selection
//! - `request_capability`: Issue scoped PASETO v4 capability tokens
//! - `negotiate_context`: Negotiate disclosure with counterparty agents
//! - `check_status`: Check status of pending requests
//!
//! # Session Management
//!
//! Sessions are provisioned via OAuth 2.1 PKCE (S256 only) and authenticated
//! with Ed25519 signatures on every request.

pub mod audit;
pub mod dispatcher;
pub mod error;
pub mod pipeline;
pub mod policy;
pub mod server;
pub mod session;
pub mod tools;
pub mod types;
pub mod vault_access;
pub mod wire;

// Re-export primary types and functions for convenience
pub use audit::AuditLog;
pub use dispatcher::{dispatch_jsonrpc, parse_jsonrpc_request};
pub use error::{McpError, McpResult};
pub use pipeline::process_pipeline;
pub use policy::{classify_tier, evaluate_policy};
pub use server::{initialize_server, McpServer};
pub use session::{verify_ed25519_signature, verify_pkce_s256, SessionManager};
pub use types::{
    AuditEntry, AuthenticatedRequest, CheckStatusRequest, CheckStatusResponse, Conclusion,
    DisclosureMode, GetProofRequest, GetProofResponse, JsonRpcError, JsonRpcRequest,
    JsonRpcResponse, McpServerConfig, McpTool, NegotiateContextRequest, NegotiateContextResponse,
    NegotiateContextState, OAuthPkceChallenge, OAuthProvisionRequest, OAuthProvisionResponse,
    OAuthTokenExchange, PasetoClaims, PendingRequestType, PendingStatus, PipelineConfig,
    PipelineStage, PolicyDecision, PolicyEvaluationResult, PredicateOperator, PredicateQuery,
    ProofType, ProposedDisclosure, QueryRequest, QueryResponse, RequestCapabilityRequest,
    RequestCapabilityResponse, Session, SessionRegistry, Tier1QueryResponse, Tier2QueryResponse,
    Tier3QueryResponse, TransportConfig, TransportKind,
};
pub use vault_access::{VaultAccess, VaultEntry};
pub use wire::{
    WireCheckStatusRequest, WireGetProofRequest, WireNegotiateContextRequest, WireQueryRequest,
    WireRequestCapabilityRequest,
};
