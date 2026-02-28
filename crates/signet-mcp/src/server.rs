//! McpServer struct and initialization.
//!
//! The McpServer bundles all MCP components (session manager, audit log,
//! pipeline config) into a single entry point.

use crate::audit::AuditLog;
use crate::error::{McpError, McpResult};
use crate::session::SessionManager;
use crate::types::{McpServerConfig, PipelineConfig};
use crate::vault_access::VaultAccess;
use signet_notify::ChallengeRegistry;
use std::sync::Arc;

/// The MCP server instance.
///
/// Owns the session manager, audit log, and pipeline configuration.
/// Created via `initialize_server`.
pub struct McpServer {
    config: McpServerConfig,
    session_manager: SessionManager,
    audit_log: AuditLog,
    pipeline_config: PipelineConfig,
    vault: Option<Arc<dyn VaultAccess>>,
    challenge_registry: ChallengeRegistry,
}

impl McpServer {
    /// Create a new McpServer with the given configuration.
    pub fn new(config: McpServerConfig) -> McpResult<Self> {
        if config.server_name.is_empty() {
            return Err(McpError::ConfigError(
                "server_name must not be empty".into(),
            ));
        }
        if config.pipeline_timeout_ms == 0 {
            return Err(McpError::ConfigError(
                "pipeline_timeout_ms must be greater than 0".into(),
            ));
        }
        if config.session_timeout_seconds == 0 {
            return Err(McpError::ConfigError(
                "session_timeout_seconds must be greater than 0".into(),
            ));
        }

        let session_manager = SessionManager::new(config.session_timeout_seconds);
        let audit_log = AuditLog::new();
        let pipeline_config = PipelineConfig {
            stage_timeouts_ms: config.stage_timeouts_ms.clone(),
            total_timeout_ms: config.pipeline_timeout_ms,
        };

        Ok(Self {
            config,
            session_manager,
            audit_log,
            pipeline_config,
            vault: None,
            challenge_registry: ChallengeRegistry::new(),
        })
    }

    /// Get a reference to the server configuration.
    pub fn config(&self) -> &McpServerConfig {
        &self.config
    }

    /// Get a reference to the session manager.
    pub fn session_manager(&self) -> &SessionManager {
        &self.session_manager
    }

    /// Get a reference to the audit log.
    pub fn audit_log(&self) -> &AuditLog {
        &self.audit_log
    }

    /// Get a reference to the pipeline configuration.
    pub fn pipeline_config(&self) -> &PipelineConfig {
        &self.pipeline_config
    }

    /// Set the vault access implementation.
    pub fn set_vault(&mut self, vault: Arc<dyn VaultAccess>) {
        self.vault = Some(vault);
    }

    /// Get a reference to the vault access implementation.
    pub fn vault(&self) -> Option<&Arc<dyn VaultAccess>> {
        self.vault.as_ref()
    }

    /// Get a reference to the challenge registry for Tier 3 authorization flow.
    pub fn challenge_registry(&self) -> &ChallengeRegistry {
        &self.challenge_registry
    }
}

/// Initialize an MCP server with the given configuration.
///
/// This is the primary entry point for creating an MCP server instance.
pub fn initialize_server(config: McpServerConfig) -> McpResult<McpServer> {
    tracing::info!(
        server_name = %config.server_name,
        server_version = %config.server_version,
        transport = ?config.transport.kind,
        "initializing MCP server"
    );

    let server = McpServer::new(config)?;

    tracing::info!("MCP server initialized successfully");

    Ok(server)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize_server_default_config() {
        let config = McpServerConfig::default();
        let server = initialize_server(config).unwrap();
        assert_eq!(server.config().server_name, "signet-mcp");
        assert_eq!(server.config().server_version, "0.1.0");
    }

    #[test]
    fn test_initialize_server_custom_config() {
        let mut config = McpServerConfig::default();
        config.server_name = "custom-server".into();
        config.server_version = "1.0.0".into();
        config.session_timeout_seconds = 7200;

        let server = initialize_server(config).unwrap();
        assert_eq!(server.config().server_name, "custom-server");
        assert_eq!(server.config().server_version, "1.0.0");
    }

    #[test]
    fn test_initialize_server_empty_name() {
        let mut config = McpServerConfig::default();
        config.server_name = "".into();
        assert!(initialize_server(config).is_err());
    }

    #[test]
    fn test_initialize_server_zero_timeout() {
        let mut config = McpServerConfig::default();
        config.pipeline_timeout_ms = 0;
        assert!(initialize_server(config).is_err());
    }

    #[test]
    fn test_initialize_server_zero_session_timeout() {
        let mut config = McpServerConfig::default();
        config.session_timeout_seconds = 0;
        assert!(initialize_server(config).is_err());
    }

    #[test]
    fn test_server_components_accessible() {
        let server = McpServer::new(McpServerConfig::default()).unwrap();
        assert_eq!(server.session_manager().active_session_count(), 0);
        assert!(server.audit_log().is_empty());
        assert!(server.pipeline_config().total_timeout_ms > 0);
    }

    #[test]
    fn test_server_pipeline_config_derived_from_server_config() {
        let config = McpServerConfig::default();
        let server = McpServer::new(config.clone()).unwrap();
        assert_eq!(
            server.pipeline_config().total_timeout_ms,
            config.pipeline_timeout_ms
        );
        assert_eq!(
            server.pipeline_config().stage_timeouts_ms.len(),
            config.stage_timeouts_ms.len()
        );
    }
}
