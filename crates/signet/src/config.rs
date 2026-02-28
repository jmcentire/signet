use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::{RootError, RootResult};

/// Transport protocol for the MCP server.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// Standard I/O transport (default for MCP).
    #[default]
    Stdio,
    /// HTTP transport with optional bind address.
    Http { bind: String, port: u16 },
}

/// Configuration for the policy engine subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEngineConfig {
    /// Default decision when no policy rule matches (deny or permit).
    #[serde(default = "default_decision")]
    pub default_decision: String,

    /// Threshold for role-anomaly detection (0.0 to 1.0).
    #[serde(default = "default_anomaly_threshold")]
    pub anomaly_threshold: f64,

    /// Timeout in seconds before escalation defaults to deny.
    #[serde(default = "default_escalation_timeout")]
    pub escalation_timeout_secs: u64,
}

fn default_decision() -> String {
    "deny".to_string()
}

fn default_anomaly_threshold() -> f64 {
    0.7
}

fn default_escalation_timeout() -> u64 {
    300
}

impl Default for PolicyEngineConfig {
    fn default() -> Self {
        Self {
            default_decision: default_decision(),
            anomaly_threshold: default_anomaly_threshold(),
            escalation_timeout_secs: default_escalation_timeout(),
        }
    }
}

/// Configuration for the MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// Transport protocol to use.
    #[serde(default)]
    pub transport: Transport,

    /// Server name advertised in MCP initialization.
    #[serde(default = "default_server_name")]
    pub server_name: String,

    /// Server version advertised in MCP initialization.
    #[serde(default = "default_server_version")]
    pub server_version: String,
}

fn default_server_name() -> String {
    "signet".to_string()
}

fn default_server_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            transport: Transport::default(),
            server_name: default_server_name(),
            server_version: default_server_version(),
        }
    }
}

/// Top-level configuration for the Signet root binary.
///
/// Loaded from a TOML file (typically `~/.signet/config.toml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootConfig {
    /// Path to the vault data directory.
    #[serde(default = "default_vault_path")]
    pub vault_path: PathBuf,

    /// General data directory for Signet state.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// MCP server configuration.
    #[serde(default)]
    pub mcp: McpConfig,

    /// Policy engine configuration.
    #[serde(default)]
    pub policy: PolicyEngineConfig,
}

fn default_vault_path() -> PathBuf {
    dirs_or_default(".signet/vault")
}

fn default_data_dir() -> PathBuf {
    dirs_or_default(".signet")
}

/// Returns `$HOME/<suffix>` if HOME is available, otherwise `./<suffix>`.
fn dirs_or_default(suffix: &str) -> PathBuf {
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(suffix))
        .unwrap_or_else(|_| PathBuf::from(suffix))
}

impl Default for RootConfig {
    fn default() -> Self {
        Self {
            vault_path: default_vault_path(),
            data_dir: default_data_dir(),
            mcp: McpConfig::default(),
            policy: PolicyEngineConfig::default(),
        }
    }
}

impl RootConfig {
    /// Load configuration from a TOML file. If the file does not exist,
    /// returns a default configuration.
    pub fn load(path: &Path) -> RootResult<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(path).map_err(RootError::Io)?;
        let config: RootConfig = toml::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    /// Write the current configuration to a TOML file.
    pub fn save(&self, path: &Path) -> RootResult<()> {
        let contents = toml::to_string_pretty(self)
            .map_err(|e| RootError::Config(format!("TOML serialize error: {}", e)))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(RootError::Io)?;
        }
        std::fs::write(path, contents).map_err(RootError::Io)?;
        Ok(())
    }

    /// Validate configuration values.
    pub fn validate(&self) -> RootResult<()> {
        if self.policy.anomaly_threshold < 0.0 || self.policy.anomaly_threshold > 1.0 {
            return Err(RootError::Config(format!(
                "anomaly_threshold must be between 0.0 and 1.0, got {}",
                self.policy.anomaly_threshold
            )));
        }
        let valid_decisions = ["deny", "permit"];
        if !valid_decisions.contains(&self.policy.default_decision.as_str()) {
            return Err(RootError::Config(format!(
                "default_decision must be 'deny' or 'permit', got '{}'",
                self.policy.default_decision
            )));
        }
        if self.policy.escalation_timeout_secs == 0 {
            return Err(RootError::Config(
                "escalation_timeout_secs must be > 0".into(),
            ));
        }
        Ok(())
    }

    /// Return the path to the default config file location.
    pub fn default_config_path() -> PathBuf {
        dirs_or_default(".signet/config.toml")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RootConfig::default();
        assert!(config
            .vault_path
            .to_str()
            .unwrap()
            .contains(".signet/vault"));
        assert!(config.data_dir.to_str().unwrap().contains(".signet"));
        assert_eq!(config.policy.default_decision, "deny");
        assert!((config.policy.anomaly_threshold - 0.7).abs() < f64::EPSILON);
        assert_eq!(config.policy.escalation_timeout_secs, 300);
        assert_eq!(config.mcp.transport, Transport::Stdio);
    }

    #[test]
    fn test_default_transport() {
        let transport = Transport::default();
        assert_eq!(transport, Transport::Stdio);
    }

    #[test]
    fn test_config_from_toml() {
        let toml_str = r#"
vault_path = "/tmp/test-vault"
data_dir = "/tmp/test-signet"

[mcp]
server_name = "test-signet"

[mcp.transport]
http = { bind = "127.0.0.1", port = 8080 }

[policy]
default_decision = "deny"
anomaly_threshold = 0.5
escalation_timeout_secs = 120
"#;
        let config: RootConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.vault_path, PathBuf::from("/tmp/test-vault"));
        assert_eq!(config.data_dir, PathBuf::from("/tmp/test-signet"));
        assert_eq!(config.policy.default_decision, "deny");
        assert!((config.policy.anomaly_threshold - 0.5).abs() < f64::EPSILON);
        assert_eq!(config.policy.escalation_timeout_secs, 120);
        assert_eq!(config.mcp.server_name, "test-signet");
    }

    #[test]
    fn test_config_validate_ok() {
        let config = RootConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_bad_threshold_high() {
        let mut config = RootConfig::default();
        config.policy.anomaly_threshold = 1.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_bad_threshold_negative() {
        let mut config = RootConfig::default();
        config.policy.anomaly_threshold = -0.1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_bad_decision() {
        let mut config = RootConfig::default();
        config.policy.default_decision = "allow".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_zero_timeout() {
        let mut config = RootConfig::default();
        config.policy.escalation_timeout_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_load_missing_file() {
        let config = RootConfig::load(Path::new("/nonexistent/config.toml")).unwrap();
        // Should return default config
        assert_eq!(config.policy.default_decision, "deny");
    }

    #[test]
    fn test_config_roundtrip() {
        let config = RootConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let restored: RootConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config.vault_path, restored.vault_path);
        assert_eq!(
            config.policy.default_decision,
            restored.policy.default_decision
        );
    }

    #[test]
    fn test_config_save_and_load() {
        let dir = std::env::temp_dir().join("signet-test-config");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("config.toml");

        let config = RootConfig {
            vault_path: PathBuf::from("/tmp/vault-test"),
            data_dir: PathBuf::from("/tmp/data-test"),
            mcp: McpConfig::default(),
            policy: PolicyEngineConfig {
                default_decision: "permit".into(),
                anomaly_threshold: 0.3,
                escalation_timeout_secs: 60,
            },
        };

        config.save(&path).unwrap();
        let loaded = RootConfig::load(&path).unwrap();

        assert_eq!(loaded.vault_path, PathBuf::from("/tmp/vault-test"));
        assert_eq!(loaded.policy.default_decision, "permit");
        assert!((loaded.policy.anomaly_threshold - 0.3).abs() < f64::EPSILON);
        assert_eq!(loaded.policy.escalation_timeout_secs, 60);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_policy_engine_config_default() {
        let config = PolicyEngineConfig::default();
        assert_eq!(config.default_decision, "deny");
        assert!((config.anomaly_threshold - 0.7).abs() < f64::EPSILON);
        assert_eq!(config.escalation_timeout_secs, 300);
    }

    #[test]
    fn test_mcp_config_default() {
        let config = McpConfig::default();
        assert_eq!(config.transport, Transport::Stdio);
        assert_eq!(config.server_name, "signet");
    }

    #[test]
    fn test_transport_serde_stdio() {
        let t = Transport::Stdio;
        let json = serde_json::to_string(&t).unwrap();
        let restored: Transport = serde_json::from_str(&json).unwrap();
        assert_eq!(t, restored);
    }

    #[test]
    fn test_transport_serde_http() {
        let t = Transport::Http {
            bind: "0.0.0.0".into(),
            port: 9090,
        };
        let json = serde_json::to_string(&t).unwrap();
        let restored: Transport = serde_json::from_str(&json).unwrap();
        assert_eq!(t, restored);
    }
}
