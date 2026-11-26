/// Why a message or operation was rejected.
///
/// Errors are returned to the local caller only. Nothing here is sent to the
/// other device: a party that fails authentication gets no reply at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PasskeyError {
    #[error("malformed message: {0}")]
    Malformed(&'static str),
    #[error("unknown or revoked pairing")]
    UnknownPairing,
    #[error("signature verification failed")]
    BadSignature,
    #[error("message could not be opened")]
    SealFailure,
    #[error("request expired or not yet valid")]
    Expired,
    #[error("request was already handled")]
    Replay,
    #[error("site binding rejected: {0}")]
    SiteBinding(&'static str),
    #[error("no pending request matches this response")]
    NoPendingRequest,
    #[error("key operation failed")]
    Key,
    #[error("pairing rejected: {0}")]
    Pairing(&'static str),
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
}
