use signet_passkey::PasskeyError;

/// Why something on the computer side failed.
#[derive(Debug, thiserror::Error)]
pub enum DesktopError {
    #[error("{0}")]
    Protocol(#[from] PasskeyError),
    #[error("not set up yet: run `signet-passkey init`")]
    NotInitialized,
    #[error("already set up in {0}")]
    AlreadyInitialized(String),
    #[error("storage: {0}")]
    Storage(String),
    #[error("could not reach the relay: {0}")]
    RelayUnreachable(String),
    /// The relay answered, and said no.
    #[error("the relay refused: {code} (HTTP {status})")]
    RelayRefused { status: u16, code: String },
    #[error(
        "this build reaches a relay over plain HTTP on this machine only; https is not built yet"
    )]
    TlsNotBuilt,
    #[error("{0}")]
    Other(String),
}

impl DesktopError {
    pub(crate) fn storage(context: &str, error: impl std::fmt::Display) -> Self {
        Self::Storage(format!("{context}: {error}"))
    }

    /// The relay's error code, when the relay refused.
    pub fn relay_code(&self) -> Option<&str> {
        match self {
            Self::RelayRefused { code, .. } => Some(code),
            _ => None,
        }
    }
}
