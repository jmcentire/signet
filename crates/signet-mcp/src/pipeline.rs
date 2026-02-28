//! Sequential middleware pipeline.
//!
//! Pipeline stages: SessionValidator -> TierClassifier -> PolicyEvaluator -> ToolExecutor -> AuditRecorder
//!
//! Per-stage timeouts enforce fail-secure semantics: timeout = DENY.
//! Audit is recorded atomically before the response is returned.

use std::time::Instant;

use crate::audit::AuditLog;
use crate::error::{McpError, McpResult};
use crate::policy;
use crate::session::SessionManager;
use crate::tools;
use crate::types::{
    AuditEntry, AuthenticatedRequest, JsonRpcError, JsonRpcResponse, McpTool, PipelineConfig,
    PipelineStage, PolicyDecision,
};
use signet_core::Timestamp;

/// Process a request through the full pipeline.
///
/// Stages execute sequentially:
/// 1. SessionValidator: verify session and Ed25519 signature
/// 2. TierClassifier: classify the request tier
/// 3. PolicyEvaluator: evaluate policy for the tier
/// 4. ToolExecutor: execute the appropriate tool
/// 5. AuditRecorder: record the audit entry
///
/// If any stage exceeds its timeout, the pipeline returns DENY (fail-secure).
pub fn process_pipeline(
    session_manager: &SessionManager,
    audit_log: &AuditLog,
    config: &PipelineConfig,
    auth_request: &AuthenticatedRequest,
) -> McpResult<JsonRpcResponse> {
    let pipeline_start = Instant::now();
    let request = &auth_request.request;
    let id = request.id.clone();

    // Stage 1: Session Validation
    let stage_start = Instant::now();
    check_stage_timeout(
        config,
        PipelineStage::SessionValidator,
        stage_start,
        pipeline_start,
    )?;

    let session = session_manager.validate_session(
        &auth_request.session.session_id,
        &auth_request.signature,
        &auth_request.signed_message,
    )?;

    check_stage_timeout(
        config,
        PipelineStage::SessionValidator,
        stage_start,
        pipeline_start,
    )?;

    // Stage 2: Tier Classification
    let stage_start = Instant::now();
    let tool = McpTool::from_method(&request.method)
        .ok_or_else(|| McpError::MethodNotFound(request.method.clone()))?;

    let tier = policy::classify_tier(&tool, &request.params)?;

    check_stage_timeout(
        config,
        PipelineStage::TierClassifier,
        stage_start,
        pipeline_start,
    )?;

    // Stage 3: Policy Evaluation
    let stage_start = Instant::now();
    let policy_result = policy::evaluate_policy(&tool, tier, &request.params)?;

    check_stage_timeout(
        config,
        PipelineStage::PolicyEvaluator,
        stage_start,
        pipeline_start,
    )?;

    // Check policy decision
    if policy_result.decision == PolicyDecision::Deny {
        // Record audit for denied request
        let entry = AuditEntry {
            entry_id: uuid::Uuid::new_v4().to_string(),
            session_id: session.session_id.clone(),
            request_id: signet_core::RequestId::new(request.id.to_string()),
            tool: tool.clone(),
            tier,
            decision: PolicyDecision::Deny,
            timestamp: Timestamp::now(),
            duration_ms: pipeline_start.elapsed().as_millis() as u64,
            metadata: std::collections::HashMap::new(),
        };
        let _ = audit_log.record(entry);

        return Ok(JsonRpcResponse::error(
            id,
            JsonRpcError {
                code: -32003,
                message: format!("access denied: {}", policy_result.reason),
                data: None,
            },
        ));
    }

    // Stage 4: Tool Execution
    let stage_start = Instant::now();
    let tool_result = tools::dispatch_tool(&tool, &request.params, tier, &session);

    check_stage_timeout(
        config,
        PipelineStage::ToolExecutor,
        stage_start,
        pipeline_start,
    )?;

    // Stage 5: Audit Recording
    let stage_start = Instant::now();
    let decision = match &tool_result {
        Ok(_) => PolicyDecision::Permit,
        Err(_) => PolicyDecision::Deny,
    };

    let entry = AuditEntry {
        entry_id: uuid::Uuid::new_v4().to_string(),
        session_id: session.session_id.clone(),
        request_id: signet_core::RequestId::new(request.id.to_string()),
        tool,
        tier,
        decision,
        timestamp: Timestamp::now(),
        duration_ms: pipeline_start.elapsed().as_millis() as u64,
        metadata: std::collections::HashMap::new(),
    };
    audit_log.record(entry)?;

    check_stage_timeout(
        config,
        PipelineStage::AuditRecorder,
        stage_start,
        pipeline_start,
    )?;

    // Return result
    match tool_result {
        Ok(result) => Ok(JsonRpcResponse::success(id, result)),
        Err(e) => Ok(JsonRpcResponse::error(
            id,
            JsonRpcError {
                code: e.json_rpc_code(),
                message: e.to_string(),
                data: None,
            },
        )),
    }
}

/// Check if a pipeline stage has exceeded its timeout.
/// Fail-secure: timeout = DENY.
fn check_stage_timeout(
    config: &PipelineConfig,
    stage: PipelineStage,
    stage_start: Instant,
    pipeline_start: Instant,
) -> McpResult<()> {
    let stage_elapsed = stage_start.elapsed().as_millis() as u64;
    let total_elapsed = pipeline_start.elapsed().as_millis() as u64;

    // Check per-stage timeout
    let stage_timeout = config
        .stage_timeouts_ms
        .get(stage.config_key())
        .copied()
        .unwrap_or(5000);

    if stage_elapsed > stage_timeout {
        return Err(McpError::PipelineTimeout {
            stage: stage.config_key().into(),
        });
    }

    // Check total pipeline timeout
    if total_elapsed > config.total_timeout_ms {
        return Err(McpError::PipelineTimeout {
            stage: "total_pipeline".into(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{JsonRpcRequest, PipelineConfig, Session};
    use signet_core::{SessionId, Timestamp};
    use std::collections::HashMap;

    fn make_config() -> PipelineConfig {
        PipelineConfig::default()
    }

    #[allow(dead_code)]
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

    #[allow(dead_code)]
    fn make_auth_request(method: &str, params: serde_json::Value) -> AuthenticatedRequest {
        AuthenticatedRequest {
            session: make_session(),
            request: JsonRpcRequest {
                jsonrpc: "2.0".into(),
                method: method.into(),
                params,
                id: serde_json::json!(1),
            },
            received_at: Timestamp::now(),
            signature: vec![0u8; 64],
            signed_message: vec![],
        }
    }

    #[test]
    fn test_check_stage_timeout_within_limits() {
        let config = make_config();
        let now = Instant::now();
        let result = check_stage_timeout(&config, PipelineStage::SessionValidator, now, now);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_stage_timeout_total_exceeded() {
        let mut config = make_config();
        config.total_timeout_ms = 0; // Immediate timeout
        let start = Instant::now();
        // Wait a tiny bit to ensure elapsed > 0
        std::thread::sleep(std::time::Duration::from_millis(1));
        let result = check_stage_timeout(
            &config,
            PipelineStage::SessionValidator,
            Instant::now(),
            start,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_pipeline_config_default_has_all_stages() {
        let config = PipelineConfig::default();
        assert!(config.stage_timeouts_ms.contains_key("session_validator"));
        assert!(config.stage_timeouts_ms.contains_key("tier_classifier"));
        assert!(config.stage_timeouts_ms.contains_key("policy_evaluator"));
        assert!(config.stage_timeouts_ms.contains_key("tool_executor"));
        assert!(config.stage_timeouts_ms.contains_key("audit_recorder"));
    }

    #[test]
    fn test_pipeline_timeout_is_deny() {
        // Verify that PipelineTimeout maps to DENY error code
        let err = McpError::PipelineTimeout {
            stage: "test".into(),
        };
        assert_eq!(err.json_rpc_code(), -32004);
    }
}
