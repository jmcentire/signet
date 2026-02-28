//! Store and list data tool executors.
//!
//! These tools allow storing and retrieving facts in the vault
//! through the VaultAccess trait.

use crate::error::{McpError, McpResult};
use crate::vault_access::VaultAccess;
use serde::{Deserialize, Serialize};
use signet_core::Tier;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize)]
pub struct StoreDataRequest {
    pub label: String,
    pub tier: u8,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StoreDataResponse {
    pub label: String,
    pub tier: u8,
    pub stored: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListDataRequest {
    pub tier: Option<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListDataEntry {
    pub label: String,
    pub tier: u8,
    pub value: String,
    pub stored_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListDataResponse {
    pub entries: Vec<ListDataEntry>,
    pub total: usize,
}

fn tier_from_u8(n: u8) -> McpResult<Tier> {
    match n {
        1 => Ok(Tier::Tier1),
        2 => Ok(Tier::Tier2),
        3 => Ok(Tier::Tier3),
        _ => Err(McpError::InvalidRequest(format!(
            "tier must be 1, 2, or 3, got {}",
            n
        ))),
    }
}

fn tier_to_u8(tier: &Tier) -> u8 {
    match tier {
        Tier::Tier1 => 1,
        Tier::Tier2 => 2,
        Tier::Tier3 => 3,
    }
}

/// Execute a store_data tool invocation.
pub fn execute_store_data(
    params: &serde_json::Value,
    vault: &Arc<dyn VaultAccess>,
) -> McpResult<serde_json::Value> {
    let request: StoreDataRequest = serde_json::from_value(params.clone())
        .map_err(|e| McpError::InvalidRequest(format!("invalid store_data params: {}", e)))?;

    if request.label.is_empty() {
        return Err(McpError::InvalidRequest("label must not be empty".into()));
    }

    let tier = tier_from_u8(request.tier)?;
    vault.put(&request.label, tier, request.value.as_bytes())?;

    let response = StoreDataResponse {
        label: request.label,
        tier: request.tier,
        stored: true,
    };
    serde_json::to_value(response).map_err(|e| McpError::SerializationError(e.to_string()))
}

/// Execute a list_data tool invocation.
pub fn execute_list_data(
    params: &serde_json::Value,
    vault: &Arc<dyn VaultAccess>,
) -> McpResult<serde_json::Value> {
    let request: ListDataRequest = serde_json::from_value(params.clone())
        .map_err(|e| McpError::InvalidRequest(format!("invalid list_data params: {}", e)))?;

    let tier_filter = match request.tier {
        Some(t) => Some(tier_from_u8(t)?),
        None => None,
    };

    let entries = vault.list(tier_filter)?;

    let display_entries: Vec<ListDataEntry> = entries
        .into_iter()
        .map(|entry| {
            let tier_n = tier_to_u8(&entry.tier);
            let value = match entry.tier {
                Tier::Tier3 => "[REQUIRES GRANT]".to_string(),
                _ => {
                    // Retrieve the actual value
                    match vault.get(&entry.label, entry.tier) {
                        Ok(Some(data)) => String::from_utf8_lossy(&data).to_string(),
                        _ => "[error reading value]".to_string(),
                    }
                }
            };
            ListDataEntry {
                label: entry.label,
                tier: tier_n,
                value,
                stored_at: entry.stored_at,
            }
        })
        .collect();

    let total = display_entries.len();
    let response = ListDataResponse {
        entries: display_entries,
        total,
    };
    serde_json::to_value(response).map_err(|e| McpError::SerializationError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_from_u8() {
        assert_eq!(tier_from_u8(1).unwrap(), Tier::Tier1);
        assert_eq!(tier_from_u8(2).unwrap(), Tier::Tier2);
        assert_eq!(tier_from_u8(3).unwrap(), Tier::Tier3);
        assert!(tier_from_u8(0).is_err());
        assert!(tier_from_u8(4).is_err());
    }

    #[test]
    fn test_tier_to_u8() {
        assert_eq!(tier_to_u8(&Tier::Tier1), 1);
        assert_eq!(tier_to_u8(&Tier::Tier2), 2);
        assert_eq!(tier_to_u8(&Tier::Tier3), 3);
    }
}
