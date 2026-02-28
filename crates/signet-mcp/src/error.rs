//! MCP error types.
//!
//! 21-variant error enum covering all failure modes in the MCP trust bridge.
//! Display impls never contain key material.

use thiserror::Error;

/// Result type alias for MCP operations.
pub type McpResult<T> = Result<T, McpError>;

/// Comprehensive error enum for all MCP operations.
///
/// Display implementations intentionally omit any secret material.
/// Crypto failures use generic messages to prevent oracle attacks.
#[derive(Debug, Error)]
pub enum McpError {
    // -- Transport / initialization errors --
    #[error("server initialization failed: {0}")]
    InitializationFailed(String),

    #[error("transport error: {0}")]
    TransportError(String),

    #[error("configuration error: {0}")]
    ConfigError(String),

    // -- Session / auth errors --
    #[error("session not found")]
    SessionNotFound,

    #[error("session expired")]
    SessionExpired,

    #[error("session revoked")]
    SessionRevoked,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("PKCE verification failed")]
    PkceVerificationFailed,

    #[error("OAuth provisioning failed: {0}")]
    OAuthProvisionFailed(String),

    #[error("token exchange failed: {0}")]
    TokenExchangeFailed(String),

    // -- Pipeline / dispatch errors --
    #[error("pipeline stage timed out: {stage}")]
    PipelineTimeout { stage: String },

    #[error("pipeline error: {0}")]
    PipelineError(String),

    #[error("method not found: {0}")]
    MethodNotFound(String),

    #[error("invalid JSON-RPC request: {0}")]
    InvalidJsonRpc(String),

    // -- Policy / tier errors --
    #[error("policy evaluation failed: {0}")]
    PolicyEvaluationFailed(String),

    #[error("tier classification failed: {0}")]
    TierClassificationFailed(String),

    #[error("access denied: {0}")]
    AccessDenied(String),

    // -- Tool execution errors --
    #[error("tool execution failed: {0}")]
    ToolExecutionFailed(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    // -- Audit errors --
    #[error("audit recording failed: {0}")]
    AuditFailed(String),

    // -- Serialization --
    #[error("serialization error: {0}")]
    SerializationError(String),
}

impl McpError {
    /// Returns a JSON-RPC error code for this error variant.
    pub fn json_rpc_code(&self) -> i64 {
        match self {
            McpError::InvalidJsonRpc(_) => -32600,
            McpError::MethodNotFound(_) => -32601,
            McpError::InvalidRequest(_) => -32602,
            McpError::SerializationError(_) => -32700,
            McpError::SessionNotFound
            | McpError::SessionExpired
            | McpError::SessionRevoked
            | McpError::InvalidSignature
            | McpError::PkceVerificationFailed => -32001,
            McpError::AccessDenied(_) | McpError::PolicyEvaluationFailed(_) => -32003,
            McpError::PipelineTimeout { .. } => -32004,
            _ => -32000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_error_variants_display() {
        let errors: Vec<McpError> = vec![
            McpError::InitializationFailed("test".into()),
            McpError::TransportError("test".into()),
            McpError::ConfigError("test".into()),
            McpError::SessionNotFound,
            McpError::SessionExpired,
            McpError::SessionRevoked,
            McpError::InvalidSignature,
            McpError::PkceVerificationFailed,
            McpError::OAuthProvisionFailed("test".into()),
            McpError::TokenExchangeFailed("test".into()),
            McpError::PipelineTimeout {
                stage: "test".into(),
            },
            McpError::PipelineError("test".into()),
            McpError::MethodNotFound("test".into()),
            McpError::InvalidJsonRpc("test".into()),
            McpError::PolicyEvaluationFailed("test".into()),
            McpError::TierClassificationFailed("test".into()),
            McpError::AccessDenied("test".into()),
            McpError::ToolExecutionFailed("test".into()),
            McpError::InvalidRequest("test".into()),
            McpError::AuditFailed("test".into()),
            McpError::SerializationError("test".into()),
        ];
        assert_eq!(errors.len(), 21, "must have exactly 21 error variants");
        for err in &errors {
            let msg = format!("{}", err);
            assert!(!msg.is_empty());
            // Ensure no secret material leaks
            assert!(!msg.contains("secret"));
            assert!(!msg.contains("key_bytes"));
            assert!(!msg.contains("private"));
        }
    }

    #[test]
    fn test_json_rpc_error_codes() {
        assert_eq!(McpError::InvalidJsonRpc("x".into()).json_rpc_code(), -32600);
        assert_eq!(McpError::MethodNotFound("x".into()).json_rpc_code(), -32601);
        assert_eq!(McpError::InvalidRequest("x".into()).json_rpc_code(), -32602);
        assert_eq!(
            McpError::SerializationError("x".into()).json_rpc_code(),
            -32700
        );
        assert_eq!(McpError::SessionNotFound.json_rpc_code(), -32001);
        assert_eq!(McpError::AccessDenied("x".into()).json_rpc_code(), -32003);
        assert_eq!(
            McpError::PipelineTimeout { stage: "x".into() }.json_rpc_code(),
            -32004
        );
        assert_eq!(McpError::TransportError("x".into()).json_rpc_code(), -32000);
    }

    #[test]
    fn test_display_never_contains_key_material() {
        let err = McpError::InvalidSignature;
        let msg = format!("{}", err);
        assert_eq!(msg, "invalid signature");
        assert!(!msg.contains("0x"));
        assert!(!msg.contains("ed25519"));
    }
}
