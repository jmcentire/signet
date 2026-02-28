//! VaultAccess trait for MCP tools to interact with the vault.
//!
//! This trait abstracts vault operations so MCP tools can store, retrieve,
//! list, and sign data without depending on concrete vault implementations.

use crate::error::McpResult;
use serde::{Deserialize, Serialize};
use signet_core::Tier;

/// Metadata for a stored vault entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub label: String,
    pub tier: Tier,
    pub stored_at: String,
    pub schema_version: u64,
}

/// Trait for MCP tools to access vault operations.
///
/// Implementations provide storage, retrieval, signing, and identity
/// operations backed by the real vault subsystem.
pub trait VaultAccess: Send + Sync {
    /// Retrieve a value by label and tier.
    fn get(&self, label: &str, tier: Tier) -> McpResult<Option<Vec<u8>>>;

    /// Store a value under a label at the given tier.
    fn put(&self, label: &str, tier: Tier, data: &[u8]) -> McpResult<()>;

    /// List stored entries, optionally filtered by tier.
    fn list(&self, tier: Option<Tier>) -> McpResult<Vec<VaultEntry>>;

    /// Sign a message with the vault's Ed25519 key.
    fn sign(&self, message: &[u8]) -> McpResult<[u8; 64]>;

    /// Get the vault's Ed25519 public key.
    fn public_key(&self) -> [u8; 32];

    /// Get the SignetId string for this vault.
    fn signet_id(&self) -> String;
}
