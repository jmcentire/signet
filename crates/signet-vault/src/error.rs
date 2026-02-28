use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("mnemonic error: {0}")]
    Mnemonic(String),

    #[error("key derivation error: {0}")]
    KeyDerivation(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("decryption error: {0}")]
    Decryption(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("session error: {0}")]
    Session(String),

    #[error("audit error: {0}")]
    Audit(String),

    #[error("tier violation: {0}")]
    TierViolation(String),

    #[error("record not found: {0}")]
    NotFound(String),

    #[error("record ID collision: {0}")]
    Collision(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl From<VaultError> for signet_core::SignetError {
    fn from(e: VaultError) -> Self {
        signet_core::SignetError::Vault(e.to_string())
    }
}

pub type VaultResult<T> = Result<T, VaultError>;
