use crate::decay::{DecayConfig, DecayState};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// CredentialId — 128-bit random, encoded as 32-char lowercase hex
// ---------------------------------------------------------------------------

/// Globally unique credential identifier. 128-bit random, encoded as 32-char hex string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialId {
    value: String,
}

impl CredentialId {
    /// Create a new CredentialId from a hex string. Validates format.
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.len() != 32 {
            return Err("CredentialId must be exactly 32 hex characters");
        }
        if !value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err("CredentialId must be lowercase hex");
        }
        Ok(Self { value })
    }

    /// Generate a random CredentialId.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self {
            value: hex::encode(bytes),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Display for CredentialId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

// ---------------------------------------------------------------------------
// Domain — DNS-style domain identifier
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Domain {
    value: String,
}

impl Domain {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.is_empty() || value.len() > 253 {
            return Err("Domain must be 1-253 characters");
        }
        // Simple DNS-style validation
        let valid = value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.');
        if !valid {
            return Err("Domain must be valid DNS-style identifier");
        }
        if value.starts_with('-')
            || value.starts_with('.')
            || value.ends_with('-')
            || value.ends_with('.')
        {
            return Err("Domain must be valid DNS-style identifier");
        }
        Ok(Self { value })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

// ---------------------------------------------------------------------------
// ClaimPath — RFC 6901 JSON Pointer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClaimPath {
    pub pointer: String,
}

impl ClaimPath {
    pub fn new(pointer: impl Into<String>) -> Result<Self, &'static str> {
        let pointer = pointer.into();
        if !pointer.starts_with('/') {
            return Err("ClaimPath must be a valid non-empty JSON Pointer starting with '/'");
        }
        Ok(Self { pointer })
    }

    pub fn as_str(&self) -> &str {
        &self.pointer
    }

    /// Extract the segments of the pointer (splitting on '/').
    pub fn segments(&self) -> Vec<&str> {
        self.pointer[1..].split('/').collect()
    }
}

// ---------------------------------------------------------------------------
// ClaimValue — typed claim value
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClaimValue {
    StringVal(String),
    IntVal(i64),
    FloatVal(f64),
    BoolVal(bool),
    BytesVal(Vec<u8>),
    /// ISO 8601 date string (YYYY-MM-DD)
    DateVal(String),
}

impl ClaimValue {
    /// Get the value as an integer, if it is one.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            ClaimValue::IntVal(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            ClaimValue::StringVal(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ClaimValue::BoolVal(v) => Some(*v),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Predicate — fixed set for pre-computing DerivedBoolean attributes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Predicate {
    GreaterThan(i64),
    LessThan(i64),
    GreaterThanOrEqual(i64),
    LessThanOrEqual(i64),
    EqualTo(ClaimValue),
    NotEqualTo(ClaimValue),
    InSet(Vec<ClaimValue>),
}

// ---------------------------------------------------------------------------
// AttributeKind — three-category attribute model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttributeKind {
    Raw,
    DerivedBoolean,
    Committed,
}

// ---------------------------------------------------------------------------
// RawAttribute
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawAttribute {
    pub name: String,
    pub value: ClaimValue,
}

// ---------------------------------------------------------------------------
// DerivedBooleanAttribute
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DerivedBooleanAttribute {
    pub name: String,
    pub predicate: Predicate,
    pub source_path: ClaimPath,
    pub value: bool,
}

// ---------------------------------------------------------------------------
// CommittedAttribute
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommittedAttribute {
    pub name: String,
    pub commitment: PedersenCommitment,
    pub source_path: ClaimPath,
}

// ---------------------------------------------------------------------------
// PedersenCommitment (cred-local, richer than core's)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PedersenCommitment {
    pub commitment_bytes: Vec<u8>,
    pub generator_domain_tag: String,
}

impl PedersenCommitment {
    pub const DOMAIN_TAG: &'static str = "signet-cred-pedersen-v1";
}

// ---------------------------------------------------------------------------
// AttributeEntry — wraps all three attribute kinds
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttributeEntry {
    pub index: usize,
    pub kind: AttributeKind,
    pub raw: Option<RawAttribute>,
    pub derived_boolean: Option<DerivedBooleanAttribute>,
    pub committed: Option<CommittedAttribute>,
}

// ---------------------------------------------------------------------------
// SchemaField
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchemaField {
    pub name: String,
    pub kind: AttributeKind,
    pub source_path: ClaimPath,
    pub predicate: Option<Predicate>,
    pub required: bool,
}

// ---------------------------------------------------------------------------
// DisclosureLevel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DisclosureLevel {
    Always,
    Selectable,
    Never,
}

// ---------------------------------------------------------------------------
// DisclosureRule
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureRule {
    pub field_name: String,
    pub level: DisclosureLevel,
}

// ---------------------------------------------------------------------------
// DisclosurePolicy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DisclosurePolicy {
    pub rules: Vec<DisclosureRule>,
    pub default_level: DisclosureLevel,
}

impl DisclosurePolicy {
    pub fn new(rules: Vec<DisclosureRule>, default_level: DisclosureLevel) -> Self {
        Self {
            rules,
            default_level,
        }
    }

    /// Get the disclosure level for a given field name.
    pub fn level_for(&self, field_name: &str) -> DisclosureLevel {
        self.rules
            .iter()
            .find(|r| r.field_name == field_name)
            .map(|r| r.level)
            .unwrap_or(self.default_level)
    }
}

// ---------------------------------------------------------------------------
// CredentialSchema
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialSchema {
    pub schema_id: String,
    pub version: u64,
    pub fields: Vec<SchemaField>,
    pub disclosure_policy: DisclosurePolicy,
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------
// ClaimSet — input data from vault
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimSet {
    /// Map from JSON Pointer path strings to ClaimValue entries
    pub claims: HashMap<String, ClaimValue>,
    pub source_vault_id: String,
    pub retrieved_at: String,
}

impl ClaimSet {
    /// Look up a claim by its JSON Pointer path.
    pub fn get(&self, path: &str) -> Option<&ClaimValue> {
        self.claims.get(path)
    }
}

// ---------------------------------------------------------------------------
// CredentialMetadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialMetadata {
    pub id: CredentialId,
    pub schema_id: String,
    pub schema_version: u64,
    pub issued_at: String,
    pub expires_at: String,
    pub domain: Domain,
    pub one_time: bool,
    pub issuer_public_key_id: String,
    /// Optional decay configuration. If present, the credential decays over time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decay: Option<DecayConfig>,
}

// ---------------------------------------------------------------------------
// SdJwtCredential
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SdJwtCredential {
    pub compact: String,
    pub disclosures: Vec<String>,
    pub key_binding_required: bool,
}

// ---------------------------------------------------------------------------
// BbsMessage
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BbsMessage {
    pub index: usize,
    pub scalar_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// BbsSignature
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BbsSignature {
    pub signature_bytes: Vec<u8>,
    pub public_key_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// BbsCredential
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BbsCredential {
    pub signature: BbsSignature,
    pub messages: Vec<BbsMessage>,
    pub attributes: Vec<AttributeEntry>,
    pub message_count: usize,
}

// ---------------------------------------------------------------------------
// BlindingFactor (zeroize on drop)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct BlindingFactor {
    pub attribute_name: String,
    pub factor_bytes: Vec<u8>,
}

// Manual Serialize/Deserialize to avoid leaking through serde default impls
impl Serialize for BlindingFactor {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("BlindingFactor", 2)?;
        state.serialize_field("attribute_name", &self.attribute_name)?;
        state.serialize_field(
            "factor_bytes",
            &base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &self.factor_bytes,
            ),
        )?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for BlindingFactor {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Helper {
            attribute_name: String,
            factor_bytes: String,
        }
        let h = Helper::deserialize(deserializer)?;
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &h.factor_bytes)
                .map_err(serde::de::Error::custom)?;
        Ok(Self {
            attribute_name: h.attribute_name,
            factor_bytes: bytes,
        })
    }
}

// ---------------------------------------------------------------------------
// WitnessEntry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct WitnessEntry {
    pub attribute_name: String,
    pub raw_value: i64,
    #[zeroize(skip)]
    pub blinding_factor: BlindingFactor,
}

impl Serialize for WitnessEntry {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("WitnessEntry", 3)?;
        state.serialize_field("attribute_name", &self.attribute_name)?;
        state.serialize_field("raw_value", &self.raw_value)?;
        state.serialize_field("blinding_factor", &self.blinding_factor)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for WitnessEntry {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Helper {
            attribute_name: String,
            raw_value: i64,
            blinding_factor: BlindingFactor,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(Self {
            attribute_name: h.attribute_name,
            raw_value: h.raw_value,
            blinding_factor: h.blinding_factor,
        })
    }
}

// ---------------------------------------------------------------------------
// PrivateWitness (zeroize on drop)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PrivateWitness {
    pub credential_id: CredentialId,
    pub entries: Vec<WitnessEntry>,
    pub created_at: String,
}

impl Drop for PrivateWitness {
    fn drop(&mut self) {
        // WitnessEntry and BlindingFactor implement ZeroizeOnDrop
        // but we also clear the vec
        self.entries.clear();
    }
}

impl Serialize for PrivateWitness {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("PrivateWitness", 3)?;
        state.serialize_field("credential_id", &self.credential_id)?;
        state.serialize_field("entries", &self.entries)?;
        state.serialize_field("created_at", &self.created_at)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PrivateWitness {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Helper {
            credential_id: CredentialId,
            entries: Vec<WitnessEntry>,
            created_at: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(Self {
            credential_id: h.credential_id,
            entries: h.entries,
            created_at: h.created_at,
        })
    }
}

// ---------------------------------------------------------------------------
// CredentialBundle
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialBundle {
    pub sd_jwt: SdJwtCredential,
    pub bbs: BbsCredential,
    pub witness: PrivateWitness,
    pub metadata: CredentialMetadata,
}

// ---------------------------------------------------------------------------
// CredentialStatus — five-state lifecycle
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CredentialStatus {
    Active,
    Presented,
    Consumed,
    Expired,
    Revoked,
}

impl CredentialStatus {
    /// Returns true if this is a terminal state (no outbound transitions).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Consumed | Self::Expired | Self::Revoked)
    }
}

impl std::fmt::Display for CredentialStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Presented => write!(f, "Presented"),
            Self::Consumed => write!(f, "Consumed"),
            Self::Expired => write!(f, "Expired"),
            Self::Revoked => write!(f, "Revoked"),
        }
    }
}

// ---------------------------------------------------------------------------
// RevocationInfo — who revoked and why
// ---------------------------------------------------------------------------

/// Who revoked a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevokedBy {
    /// Revoked by the credential owner.
    User,
    /// Revoked by the issuing authority. Carries the authority's hex Ed25519 public key.
    Authority(String),
}

/// Information about a credential revocation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RevocationInfo {
    /// Who initiated the revocation.
    pub revoked_by: RevokedBy,
    /// When the revocation occurred (RFC 3339).
    pub revoked_at: String,
    /// Optional human-readable reason.
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// PresentationRecord
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PresentationRecord {
    pub presented_at: String,
    pub presented_to: Domain,
    pub disclosed_fields: Vec<String>,
}

// ---------------------------------------------------------------------------
// CredentialRecord — full record as stored
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub metadata: CredentialMetadata,
    pub status: CredentialStatus,
    pub presentation_history: Vec<PresentationRecord>,
    pub sd_jwt: SdJwtCredential,
    pub bbs: BbsCredential,
    /// Runtime decay state. Present when metadata.decay is Some.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decay_state: Option<DecayState>,
    /// Revocation information. Present when status is Revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<RevocationInfo>,
}

// ---------------------------------------------------------------------------
// IssuanceConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuanceConfig {
    pub ttl_seconds: u64,
    pub domain: Domain,
    pub one_time: bool,
    pub clock_skew_tolerance_seconds: u64,
}

// ---------------------------------------------------------------------------
// CredentialEngineConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEngineConfig {
    pub default_ttl_seconds: u64,
    pub default_clock_skew_tolerance_seconds: u64,
    pub pedersen_domain_tag: String,
    pub max_attributes_per_credential: usize,
}

impl Default for CredentialEngineConfig {
    fn default() -> Self {
        Self {
            default_ttl_seconds: 3600,
            default_clock_skew_tolerance_seconds: 30,
            pedersen_domain_tag: PedersenCommitment::DOMAIN_TAG.to_string(),
            max_attributes_per_credential: 128,
        }
    }
}

// ---------------------------------------------------------------------------
// ScalarEncoding — canonical encoding scheme for BBS+ scalars
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScalarEncoding {
    Utf8HashToScalar,
    Int64LittleEndian,
    BoolSingleByte,
    BytesDirect,
    DateToEpochDays,
}

// ---------------------------------------------------------------------------
// CredentialAuditEvent
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredAuditEventKind {
    CredentialIssued,
    CredentialPresented,
    CredentialConsumed,
    CredentialExpired,
    CredentialRevoked,
    WitnessAccessed,
    WitnessDeleted,
    SchemaRegistered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialAuditEvent {
    pub event_kind: CredAuditEventKind,
    pub credential_id: String,
    pub timestamp: String,
    pub domain: Option<String>,
    pub details: Option<String>,
}

// ---------------------------------------------------------------------------
// ExpiryCheckResult
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpiryCheckResult {
    pub credential_id: CredentialId,
    pub is_expired: bool,
    pub expires_at: String,
    pub remaining_seconds: i64,
    pub status_updated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_id_valid() {
        let id = CredentialId::new("abcdef0123456789abcdef0123456789");
        assert!(id.is_ok());
        assert_eq!(id.unwrap().as_str(), "abcdef0123456789abcdef0123456789");
    }

    #[test]
    fn test_credential_id_invalid_length() {
        let id = CredentialId::new("abcdef");
        assert!(id.is_err());
    }

    #[test]
    fn test_credential_id_invalid_uppercase() {
        let id = CredentialId::new("ABCDEF0123456789abcdef0123456789");
        assert!(id.is_err());
    }

    #[test]
    fn test_credential_id_generate() {
        let id1 = CredentialId::generate();
        let id2 = CredentialId::generate();
        assert_ne!(id1, id2);
        assert_eq!(id1.as_str().len(), 32);
    }

    #[test]
    fn test_domain_valid() {
        assert!(Domain::new("example.com").is_ok());
        assert!(Domain::new("bank.example.com").is_ok());
        assert!(Domain::new("a").is_ok());
    }

    #[test]
    fn test_domain_invalid() {
        assert!(Domain::new("").is_err());
        assert!(Domain::new("-invalid").is_err());
        assert!(Domain::new("UPPER.com").is_err());
    }

    #[test]
    fn test_claim_path_valid() {
        let path = ClaimPath::new("/personal/age").unwrap();
        assert_eq!(path.segments(), vec!["personal", "age"]);
    }

    #[test]
    fn test_claim_path_invalid() {
        assert!(ClaimPath::new("no-leading-slash").is_err());
    }

    #[test]
    fn test_claim_value_accessors() {
        assert_eq!(ClaimValue::IntVal(42).as_int(), Some(42));
        assert_eq!(
            ClaimValue::StringVal("hello".into()).as_string(),
            Some("hello")
        );
        assert_eq!(ClaimValue::BoolVal(true).as_bool(), Some(true));
        assert_eq!(ClaimValue::FloatVal(1.23).as_int(), None);
    }

    #[test]
    fn test_disclosure_policy_level_for() {
        let policy = DisclosurePolicy::new(
            vec![
                DisclosureRule {
                    field_name: "name".into(),
                    level: DisclosureLevel::Always,
                },
                DisclosureRule {
                    field_name: "ssn".into(),
                    level: DisclosureLevel::Never,
                },
            ],
            DisclosureLevel::Selectable,
        );
        assert_eq!(policy.level_for("name"), DisclosureLevel::Always);
        assert_eq!(policy.level_for("ssn"), DisclosureLevel::Never);
        assert_eq!(policy.level_for("age"), DisclosureLevel::Selectable);
    }

    #[test]
    fn test_credential_status_terminal() {
        assert!(!CredentialStatus::Active.is_terminal());
        assert!(!CredentialStatus::Presented.is_terminal());
        assert!(CredentialStatus::Consumed.is_terminal());
        assert!(CredentialStatus::Expired.is_terminal());
        assert!(CredentialStatus::Revoked.is_terminal());
    }

    #[test]
    fn test_credential_status_display() {
        assert_eq!(CredentialStatus::Active.to_string(), "Active");
        assert_eq!(CredentialStatus::Consumed.to_string(), "Consumed");
    }

    #[test]
    fn test_credential_engine_config_default() {
        let config = CredentialEngineConfig::default();
        assert_eq!(config.default_ttl_seconds, 3600);
        assert_eq!(config.default_clock_skew_tolerance_seconds, 30);
        assert_eq!(config.pedersen_domain_tag, "signet-cred-pedersen-v1");
        assert_eq!(config.max_attributes_per_credential, 128);
    }

    #[test]
    fn test_blinding_factor_zeroize() {
        let mut bf = BlindingFactor {
            attribute_name: "test".into(),
            factor_bytes: vec![0xAA; 32],
        };
        bf.zeroize();
        assert!(bf.factor_bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_witness_entry_zeroize() {
        let mut entry = WitnessEntry {
            attribute_name: "balance".into(),
            raw_value: 12345,
            blinding_factor: BlindingFactor {
                attribute_name: "balance".into(),
                factor_bytes: vec![0xBB; 32],
            },
        };
        entry.zeroize();
        assert_eq!(entry.raw_value, 0);
    }

    #[test]
    fn test_pedersen_commitment_domain_tag() {
        assert_eq!(PedersenCommitment::DOMAIN_TAG, "signet-cred-pedersen-v1");
    }

    #[test]
    fn test_claim_set_get() {
        let mut claims = HashMap::new();
        claims.insert("/personal/age".to_string(), ClaimValue::IntVal(25));
        let cs = ClaimSet {
            claims,
            source_vault_id: "vault-1".into(),
            retrieved_at: "2024-01-01T00:00:00Z".into(),
        };
        assert_eq!(cs.get("/personal/age"), Some(&ClaimValue::IntVal(25)));
        assert_eq!(cs.get("/personal/name"), None);
    }

    #[test]
    fn test_issuance_config_serde_roundtrip() {
        let config = IssuanceConfig {
            ttl_seconds: 3600,
            domain: Domain::new("example.com").unwrap(),
            one_time: true,
            clock_skew_tolerance_seconds: 30,
        };
        let json = serde_json::to_string(&config).unwrap();
        let config2: IssuanceConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config2.ttl_seconds, 3600);
        assert!(config2.one_time);
    }

    #[test]
    fn test_credential_id_serde_roundtrip() {
        let id = CredentialId::generate();
        let json = serde_json::to_string(&id).unwrap();
        let id2: CredentialId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, id2);
    }
}
