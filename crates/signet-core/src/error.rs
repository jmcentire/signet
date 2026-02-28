use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignetError {
    #[error("vault error: {0}")]
    Vault(String),

    #[error("policy error: {0}")]
    Policy(String),

    #[error("proof error: {0}")]
    Proof(String),

    #[error("credential error: {0}")]
    Credential(String),

    #[error("mcp error: {0}")]
    Mcp(String),

    #[error("notification error: {0}")]
    Notify(String),

    #[error("sdk error: {0}")]
    Sdk(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type SignetResult<T> = Result<T, SignetError>;
