use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Tier — three-tier data sensitivity classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tier {
    /// Freely provable. Agent answers without asking.
    /// Key derivation: username-derived, survives password reset.
    Tier1,
    /// Agent-internal. Used for reasoning, never exported raw.
    /// Key derivation: username+password-derived, session-bound.
    Tier2,
    /// Capability-gated. Encrypted such that agent cannot read without user grant.
    /// Key derivation: client-generated random, unrecoverable without explicit grant.
    Tier3,
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tier::Tier1 => write!(f, "Tier1"),
            Tier::Tier2 => write!(f, "Tier2"),
            Tier::Tier3 => write!(f, "Tier3"),
        }
    }
}

// ---------------------------------------------------------------------------
// Timestamp — canonical time representation (seconds + nanoseconds)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp {
    pub seconds_since_epoch: u64,
    pub nanoseconds: u32,
}

impl Timestamp {
    pub fn now() -> Self {
        let now = chrono::Utc::now();
        Self {
            seconds_since_epoch: now.timestamp() as u64,
            nanoseconds: now.timestamp_subsec_nanos(),
        }
    }

    pub fn from_seconds(seconds: u64) -> Self {
        Self {
            seconds_since_epoch: seconds,
            nanoseconds: 0,
        }
    }

    pub fn to_rfc3339(&self) -> String {
        let dt =
            chrono::DateTime::from_timestamp(self.seconds_since_epoch as i64, self.nanoseconds);
        dt.map(|d| d.to_rfc3339())
            .unwrap_or_else(|| "invalid".to_string())
    }

    pub fn is_expired(&self) -> bool {
        *self < Self::now()
    }
}

impl From<chrono::DateTime<chrono::Utc>> for Timestamp {
    fn from(dt: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            seconds_since_epoch: dt.timestamp() as u64,
            nanoseconds: dt.timestamp_subsec_nanos(),
        }
    }
}

// ---------------------------------------------------------------------------
// SignetId — Ed25519 public key fingerprint: Base58(SHA-256(pubkey)[0:20])
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignetId(pub String);

impl SignetId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SignetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// DomainBinding — ties proofs to a relying party + time window
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainBinding {
    pub relying_party: RpIdentifier,
    pub nonce: Nonce,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
}

impl DomainBinding {
    pub fn is_valid(&self) -> bool {
        let now = Timestamp::now();
        now >= self.issued_at && now < self.expires_at
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpIdentifier {
    /// Web origin (e.g., "https://amazon.com")
    Origin(String),
    /// Decentralized identifier
    Did(String),
}

// ---------------------------------------------------------------------------
// Nonce — 32-byte cryptographic nonce
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
pub struct Nonce(#[serde(with = "hex_bytes")] pub [u8; 32]);

impl Nonce {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({})", hex::encode(&self.0[..8]))
    }
}

impl Drop for Nonce {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Typed identifiers — prevent stringly-typed confusion
// ---------------------------------------------------------------------------

macro_rules! define_id {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(id: impl Into<String>) -> Self {
                Self(id.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }
    };
}

define_id!(
    ActorId,
    "Unique identifier for an actor in the policy system."
);
define_id!(PredicateId, "Unique identifier for a policy predicate.");
define_id!(DomainId, "Unique identifier for a domain context.");
define_id!(CredentialId, "Unique identifier for a credential.");
define_id!(RequestId, "Unique identifier for a request.");
define_id!(SessionId, "Unique identifier for an agent session.");
define_id!(RecordId, "Content-addressed record identifier (BlindDB).");

// ---------------------------------------------------------------------------
// PolicyVersion — monotonically increasing version number
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PolicyVersion(pub u64);

impl PolicyVersion {
    pub fn initial() -> Self {
        Self(1)
    }

    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

// ---------------------------------------------------------------------------
// ConfidenceLevel — classification confidence
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
    Verified,
}

// ---------------------------------------------------------------------------
// ClassificationMethod — how an actor was classified
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClassificationMethod {
    Explicit,
    CredentialBased,
    DomainInferred,
    SelfDeclared,
}

// ---------------------------------------------------------------------------
// DenyReason — why a policy decision was denied
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DenyReason {
    Timeout,
    InsufficientTier,
    PolicyRuleDeny,
    Revoked,
    ExpiredContext,
    DomainMismatch,
    NoMatchingPermitRule,
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DenyReason::Timeout => write!(f, "timeout"),
            DenyReason::InsufficientTier => write!(f, "insufficient_tier"),
            DenyReason::PolicyRuleDeny => write!(f, "policy_rule_deny"),
            DenyReason::Revoked => write!(f, "revoked"),
            DenyReason::ExpiredContext => write!(f, "expired_context"),
            DenyReason::DomainMismatch => write!(f, "domain_mismatch"),
            DenyReason::NoMatchingPermitRule => write!(f, "no_matching_permit_rule"),
        }
    }
}

// ---------------------------------------------------------------------------
// AnomalySeverity — severity of detected anomalies
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

// ---------------------------------------------------------------------------
// AuditEventKind — types of events in the audit chain
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventKind {
    VaultAccess {
        tier: Tier,
        record_id: RecordId,
    },
    CredentialIssued {
        credential_id: CredentialId,
    },
    ProofGenerated {
        domain: DomainBinding,
    },
    PolicyDecision {
        actor_id: ActorId,
        decision: PolicyDecisionKind,
    },
    SessionCreated {
        session_id: SessionId,
    },
    SessionRevoked {
        session_id: SessionId,
    },
    KeyRotation,
    Tier3Grant {
        credential_id: CredentialId,
    },
    Tier3Revoke {
        credential_id: CredentialId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecisionKind {
    Permit,
    Deny,
    Anomaly,
}

// ---------------------------------------------------------------------------
// AuditHash — hash of an audit entry (for chain integrity)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuditHash(#[serde(with = "hex_bytes")] pub [u8; 32]);

impl fmt::Display for AuditHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// ---------------------------------------------------------------------------
// PedersenCommitment — compressed Ristretto point (32 bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PedersenCommitment {
    #[serde(with = "hex_bytes")]
    pub commitment_bytes: [u8; 32],
}

// ---------------------------------------------------------------------------
// TimeBudget — performance SLA tracking for proof generation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TimeBudget {
    pub total_ms: u64,
    pub remaining_ms: u64,
}

impl TimeBudget {
    pub fn new(total_ms: u64) -> Self {
        Self {
            total_ms,
            remaining_ms: total_ms,
        }
    }

    pub fn is_exhausted(&self) -> bool {
        self.remaining_ms == 0
    }

    pub fn consume(&mut self, ms: u64) {
        self.remaining_ms = self.remaining_ms.saturating_sub(ms);
    }
}

// ---------------------------------------------------------------------------
// Hex serialization helper for fixed-size byte arrays
// ---------------------------------------------------------------------------

mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom(format!("expected {} bytes", N)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_display() {
        assert_eq!(Tier::Tier1.to_string(), "Tier1");
        assert_eq!(Tier::Tier2.to_string(), "Tier2");
        assert_eq!(Tier::Tier3.to_string(), "Tier3");
    }

    #[test]
    fn test_timestamp_ordering() {
        let t1 = Timestamp::from_seconds(100);
        let t2 = Timestamp::from_seconds(200);
        assert!(t1 < t2);
    }

    #[test]
    fn test_timestamp_rfc3339() {
        let t = Timestamp::from_seconds(1_700_000_000);
        let s = t.to_rfc3339();
        assert!(s.contains("2023"));
    }

    #[test]
    fn test_nonce_generation() {
        let n1 = Nonce::generate();
        let n2 = Nonce::generate();
        assert_ne!(n1.0, n2.0);
    }

    #[test]
    fn test_typed_ids() {
        let actor = ActorId::new("alice");
        let pred = PredicateId::new("age_over_21");
        assert_ne!(actor.as_str(), pred.as_str());
    }

    #[test]
    fn test_policy_version() {
        let v1 = PolicyVersion::initial();
        let v2 = v1.next();
        assert!(v2 > v1);
        assert_eq!(v2.0, 2);
    }

    #[test]
    fn test_time_budget() {
        let mut budget = TimeBudget::new(100);
        assert!(!budget.is_exhausted());
        budget.consume(60);
        assert_eq!(budget.remaining_ms, 40);
        budget.consume(50);
        assert!(budget.is_exhausted());
    }

    #[test]
    fn test_domain_binding_validity() {
        let now = Timestamp::now();
        let binding = DomainBinding {
            relying_party: RpIdentifier::Origin("https://example.com".into()),
            nonce: Nonce::generate(),
            issued_at: Timestamp::from_seconds(now.seconds_since_epoch - 60),
            expires_at: Timestamp::from_seconds(now.seconds_since_epoch + 300),
        };
        assert!(binding.is_valid());
    }

    #[test]
    fn test_confidence_level_ordering() {
        assert!(ConfidenceLevel::Low < ConfidenceLevel::High);
        assert!(ConfidenceLevel::Verified > ConfidenceLevel::Medium);
    }

    #[test]
    fn test_anomaly_severity_ordering() {
        assert!(AnomalySeverity::Low < AnomalySeverity::Critical);
    }

    #[test]
    fn test_signet_id_display() {
        let id = SignetId("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy".to_string());
        assert_eq!(format!("{}", id), "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy");
    }

    #[test]
    fn test_audit_hash_display() {
        let hash = AuditHash([0xab; 32]);
        let s = hash.to_string();
        assert!(s.starts_with("abab"));
        assert_eq!(s.len(), 64);
    }

    #[test]
    fn test_pedersen_commitment_serde() {
        let pc = PedersenCommitment {
            commitment_bytes: [0x42; 32],
        };
        let json = serde_json::to_string(&pc).unwrap();
        let pc2: PedersenCommitment = serde_json::from_str(&json).unwrap();
        assert_eq!(pc, pc2);
    }

    #[test]
    fn test_deny_reason_display() {
        assert_eq!(DenyReason::Timeout.to_string(), "timeout");
        assert_eq!(
            DenyReason::NoMatchingPermitRule.to_string(),
            "no_matching_permit_rule"
        );
    }
}
