//! Versioned wire contract. Sign the original decoded payload bytes, not reserialized JSON.
use serde::{Deserialize, Serialize};

pub const OWNER_DOMAIN: &str = "signet.owner-approval.v1";
pub const CLIENT_DOMAIN: &str = "signet.authority-request.v1";
pub const QUOTE_DOMAIN: &str = "signet.executor-quote.v1";
pub const MAX_TTL: i64 = 300;
pub const MAX_MESSAGE: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMessage {
    /// Unpadded base64url of UTF-8 JSON, signed verbatim after domain + NUL.
    pub payload: String,
    /// 64-byte Ed25519 signature, lowercase hex.
    pub signature: String,
}

/// Provisioned by the operator, never accepted from an agent request. No private keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConfig {
    pub authority_id: String,
    pub owner_key: String,
    pub agent_keys: Vec<String>,
    pub executor_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Purchase {
    pub merchant: String,
    pub currency: String,
    pub item_id: String,
    pub description: String,
    pub category: String,
    pub quantity: u32,
    /// Final total including mandatory fees/tax/shipping, integer minor units.
    pub total_minor: u64,
    /// Exact owner-defined requirements and executor-verified terms/fulfillment.
    pub requirements_digest: String,
    pub terms_digest: String,
    pub fulfillment_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quote {
    pub authority_id: String,
    pub client_key: String,
    pub quote_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub purchase: Purchase,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Rule {
    SpendLimit {
        merchant: String,
        currency: String,
        requirements_digest: String,
        max_total_minor: u64,
    },
    RequireConfirmation {
        category: Option<String>,
    },
    /// Only a completed, authenticated executor receipt can establish a baseline.
    Reorder {
        receipt_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Mutation {
    Add {
        rule_id: String,
        rule: Rule,
    },
    Edit {
        rule_id: String,
        expected_version: u64,
        rule: Rule,
    },
    Remove {
        rule_id: String,
        expected_version: u64,
    },
    RevokeGrant {
        grant_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovedAction {
    Purchase { quote: SignedMessage },
    RuleMutation { mutation: Mutation },
}

/// A trusted owner surface signs this only after authenticating the owner and
/// displaying this exact action. Key possession alone is not a user-presence UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerApproval {
    pub authority_id: String,
    pub client_key: String,
    pub nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub policy_revision: u64,
    pub action: ApprovedAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    ProposeApproval {
        action: ApprovedAction,
        documents: std::collections::BTreeMap<String, String>,
    },
    ApprovalStatus {
        proposal_id: String,
    },
    Snapshot,
    PreparePurchase {
        quote: SignedMessage,
    },
    /// Recover the committed result after a lost raw approval response. Never reissues a grant.
    SubmittedApprovalStatus {
        owner_nonce: String,
    },
    SubmitApproval {
        approval: SignedMessage,
    },
    CommitMutation {
        grant_id: String,
    },
    /// Executor-only: atomically consume once and durably reserve exact work.
    ConsumePurchase {
        grant_id: String,
        purchase: Purchase,
    },
    /// Executor-only: one terminal result for the previously reserved purchase.
    CompletePurchase {
        execution_id: String,
        outcome: Completion,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Completion {
    Succeeded {
        provider_reference: String,
    },
    Failed {
        reason: String,
    },
    /// Permanently burns the grant; manual/provider reconciliation is needed.
    Unknown {
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub authority_id: String,
    pub client_key: String,
    pub nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub command: Command,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredGrant {
    pub client_key: String,
    pub expires_at: i64,
    pub policy_revision: u64,
    pub action: ApprovedAction,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorityError {
    #[error("authorization rejected: {0}")]
    Rejected(&'static str),
    #[error("authority storage unavailable")]
    Storage(#[from] rusqlite::Error),
    #[error("invalid authority message")]
    Json(#[from] serde_json::Error),
    #[error("authority file unavailable")]
    Io(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, AuthorityError>;
