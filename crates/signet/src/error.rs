use thiserror::Error;

/// Comprehensive error type for the Signet root binary, aggregating errors
/// from all dependency crates.
///
/// Each variant wraps the corresponding crate's error type where available.
/// For crates still under development (signet-mcp), a string-based variant
/// is used as a temporary bridge.
#[derive(Debug, Error)]
pub enum RootError {
    #[error("vault error: {0}")]
    Vault(#[from] signet_vault::VaultError),

    #[error("policy error: {0}")]
    Policy(#[from] signet_policy::PolicyError),

    #[error("credential error: {0}")]
    Credential(#[from] signet_cred::CredError),

    #[error("proof error: {0}")]
    Proof(#[from] signet_proof::ProofError),

    #[error("notification error: {0}")]
    Notify(#[from] signet_notify::NotifyError),

    #[error("sdk error: {0}")]
    Sdk(#[from] signet_sdk::SdkError),

    /// MCP errors. signet-mcp is under concurrent development; this variant
    /// uses a string until McpError is stabilized.
    #[error("mcp error: {0}")]
    Mcp(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<serde_json::Error> for RootError {
    fn from(e: serde_json::Error) -> Self {
        RootError::Serialization(e.to_string())
    }
}

impl From<toml::de::Error> for RootError {
    fn from(e: toml::de::Error) -> Self {
        RootError::Config(format!("TOML parse error: {}", e))
    }
}

pub type RootResult<T> = Result<T, RootError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_error_display() {
        let err = RootError::Internal("something broke".into());
        assert_eq!(err.to_string(), "internal error: something broke");
    }

    #[test]
    fn test_root_error_config() {
        let err = RootError::Config("missing vault_path".into());
        assert_eq!(err.to_string(), "configuration error: missing vault_path");
    }

    #[test]
    fn test_root_error_mcp_string() {
        let err = RootError::Mcp("transport failed".into());
        assert_eq!(err.to_string(), "mcp error: transport failed");
    }

    #[test]
    fn test_root_error_from_vault() {
        let vault_err = signet_vault::VaultError::NotFound("key-123".into());
        let root_err: RootError = vault_err.into();
        assert!(root_err.to_string().contains("key-123"));
    }

    #[test]
    fn test_root_error_from_policy() {
        let policy_err = signet_policy::PolicyError::InternalError("engine down".into());
        let root_err: RootError = policy_err.into();
        assert!(root_err.to_string().contains("engine down"));
    }

    #[test]
    fn test_root_error_from_cred() {
        let cred_err = signet_cred::CredError::SigningFailed;
        let root_err: RootError = cred_err.into();
        assert!(root_err.to_string().contains("signing failed"));
    }

    #[test]
    fn test_root_error_from_proof() {
        let proof_err = signet_proof::ProofError::NonceRejected;
        let root_err: RootError = proof_err.into();
        assert!(root_err.to_string().contains("nonce rejected"));
    }

    #[test]
    fn test_root_error_from_notify() {
        let notify_err = signet_notify::NotifyError::DeliveryFailed;
        let root_err: RootError = notify_err.into();
        assert!(root_err.to_string().contains("delivery failed"));
    }

    #[test]
    fn test_root_error_from_sdk() {
        let sdk_err = signet_sdk::SdkError::InvalidProof("bad proof".into());
        let root_err: RootError = sdk_err.into();
        assert!(root_err.to_string().contains("bad proof"));
    }

    #[test]
    fn test_root_error_from_serde_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let root_err: RootError = json_err.into();
        assert!(matches!(root_err, RootError::Serialization(_)));
    }

    #[test]
    fn test_root_error_from_toml() {
        let toml_err = toml::from_str::<toml::Value>("= invalid").unwrap_err();
        let root_err: RootError = toml_err.into();
        assert!(matches!(root_err, RootError::Config(_)));
    }

    #[test]
    fn test_root_result_alias() {
        fn ok_fn() -> RootResult<u32> {
            Ok(42)
        }
        assert_eq!(ok_fn().unwrap(), 42);

        fn err_fn() -> RootResult<u32> {
            Err(RootError::Internal("test".into()))
        }
        assert!(err_fn().is_err());
    }

    #[test]
    fn test_all_variants_have_display() {
        let errors: Vec<RootError> = vec![
            RootError::Mcp("mcp".into()),
            RootError::Internal("internal".into()),
            RootError::Config("config".into()),
            RootError::Serialization("json".into()),
        ];
        for err in errors {
            let msg = err.to_string();
            assert!(!msg.is_empty());
        }
    }
}
