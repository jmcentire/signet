//! Native rings, rules, provider-held assets and task assignments.
//! A ring definition confers no authority. Every transition verifies an owner or
//! registered caller signature and must commit the full aggregate through object
//! CAS before its result is exposed. No raw credentials or provider calls here.
use super::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
pub mod persistence;
#[cfg(test)]
mod tests;
pub const OWNER_RING_DOMAIN: &str = "signet.ring-owner.v1";
pub const RING_REQUEST_DOMAIN: &str = "signet.ring-request.v1";
pub const CAPABILITY_QUOTE_DOMAIN: &str = "signet.capability-quote.v1";
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub id: String,
    pub version: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record<T> {
    pub version: u64,
    pub value: T,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Payment,
    PersonalData,
    Credential,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InteractionMode {
    Interactive,
    Delegated,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub provider: String,
    pub account_label: String,
    /// Opaque broker/provider identifier, NEVER the secret or sensitive value.
    pub capability_ref: String,
    /// Verified adapter-supported operations; metadata is not proof of provider support.
    pub operations: BTreeSet<String>,
    pub interaction_mode: InteractionMode,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub name: String,
    pub kind: AssetKind,
    pub source: Source,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleDefinition {
    Spend {
        merchant: String,
        category: String,
        currency: String,
        requirements_digest: String,
        item_ids: BTreeSet<String>,
        max_purchase_minor: u64,
    },
    ShareFields {
        fields: BTreeSet<String>,
        destination: String,
        purpose: String,
    },
    /// Permission to invoke these broker operations does not permit reveal/export.
    UseCredential {
        operations: BTreeSet<String>,
        destination: String,
        purpose: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub asset: Reference,
    pub rules: BTreeSet<Reference>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Ring {
    pub name: String,
    pub bindings: Vec<Binding>,
}
impl Ring {
    pub fn content_hash(&self) -> String {
        hex::encode(Sha256::digest(
            serde_json::to_vec(self).expect("serializable ring"),
        ))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    pub id: String,
    pub client_key: String,
    pub task_id: String,
    pub targets: BTreeSet<Reference>,
    pub currency: String,
    pub budget_minor: u64,
    pub max_operations: u32,
    pub expires_at: i64,
    pub max_activation_seconds: u32,
    pub max_swaps: u32,
    pub shared_budget_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Permission {
    scope: Delegation,
    used_minor: u64,
    operations: u32,
    swaps: u32,
    revoked: bool,
    active: Option<Activation>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activation {
    pub ring: Reference,
    pub expires_at: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Budget {
    currency: String,
    limit_minor: u64,
    used_minor: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Restrictions {
    pub blocked_categories: BTreeSet<String>,
    pub per_purchase_ceilings: BTreeMap<String, u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Management {
    PutAsset {
        id: String,
        expected_version: Option<u64>,
        asset: Asset,
    },
    PutRule {
        id: String,
        expected_version: Option<u64>,
        rule: RuleDefinition,
    },
    PutRing {
        id: String,
        expected_version: Option<u64>,
        ring: Ring,
    },
    Delegate {
        permission: Delegation,
    },
    Revoke {
        permission_id: String,
    },
    CreateSharedBudget {
        id: String,
        currency: String,
        total_minor: u64,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerApproval {
    pub authority_id: String,
    pub nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub expected_revision: u64,
    pub action: Management,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Capability {
    Purchase {
        purchase: Purchase,
    },
    ShareFields {
        fields: BTreeSet<String>,
        destination: String,
        purpose: String,
    },
    UseCredential {
        operation: String,
        destination: String,
        purpose: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityQuote {
    pub authority_id: String,
    pub quote_id: String,
    pub permission_id: String,
    pub client_key: String,
    pub task_id: String,
    pub asset: Reference,
    pub capability: Capability,
    /// Executor attestation of provider-required owner authorization for this exact quote.
    pub provider_authorization: Option<String>,
    pub issued_at: i64,
    pub expires_at: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome {
    Succeeded { provider_reference: String },
    FailedBeforeExecution { reason: String },
    Unknown { reason: String },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Activate {
        permission_id: String,
        ring: Reference,
        expires_at: i64,
    },
    CompleteTask {
        task_id: String,
    },
    Freeze {
        permission_id: String,
    },
    Reserve {
        quote: SignedMessage,
    },
    Report {
        quote_id: String,
        outcome: Outcome,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingRequest {
    pub authority_id: String,
    pub client_key: String,
    pub nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub expected_revision: u64,
    pub operation: Operation,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reservation {
    quote: CapabilityQuote,
    outcome: Option<Outcome>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingAuthority {
    config: AuthorityConfig,
    revision: u64,
    assets: BTreeMap<String, Record<Asset>>,
    rules: BTreeMap<String, Record<RuleDefinition>>,
    rings: BTreeMap<String, Record<Ring>>,
    permissions: BTreeMap<String, Permission>,
    completed_tasks: BTreeSet<(String, String)>,
    shared_budgets: BTreeMap<String, Budget>,
    restrictions: Restrictions,
    reservations: BTreeMap<String, Reservation>,
    owner_nonces: BTreeSet<String>,
    request_nonces: BTreeSet<(String, String)>,
    audit: Vec<Value>,
    #[serde(default)]
    receipts: BTreeMap<String, Value>,
}
fn currency(s: &str) -> bool {
    s.len() == 3 && s.bytes().all(|c| c.is_ascii_uppercase())
}
fn reference<'a, T>(records: &'a BTreeMap<String, Record<T>>, r: &Reference) -> Result<&'a T> {
    records
        .get(&r.id)
        .filter(|v| v.version == r.version)
        .map(|v| &v.value)
        .ok_or(AuthorityError::Rejected(
            "missing or stale record reference",
        ))
}
fn put<T>(
    records: &mut BTreeMap<String, Record<T>>,
    id: &str,
    expected: Option<u64>,
    value: T,
) -> Result<()> {
    if !text(id) || records.get(id).map(|r| r.version) != expected {
        return reject("record identifier or version mismatch");
    }
    let version = expected
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(AuthorityError::Rejected("record version overflow"))?;
    records.insert(id.into(), Record { version, value });
    Ok(())
}
impl RingAuthority {
    pub fn new(config: AuthorityConfig, restrictions: Restrictions) -> Result<Self> {
        validate_config(&config)?;
        if restrictions.blocked_categories.iter().any(|c| !text(c))
            || restrictions
                .per_purchase_ceilings
                .iter()
                .any(|(c, n)| !currency(c) || *n > i64::MAX as u64)
        {
            return reject("invalid mandatory restrictions");
        }
        Ok(Self {
            config,
            revision: 0,
            assets: BTreeMap::new(),
            rules: BTreeMap::new(),
            rings: BTreeMap::from([(
                "zero".into(),
                Record {
                    version: 1,
                    value: Ring {
                        name: "Zero permissions".into(),
                        bindings: vec![],
                    },
                },
            )]),
            permissions: BTreeMap::new(),
            completed_tasks: BTreeSet::new(),
            shared_budgets: BTreeMap::new(),
            restrictions,
            reservations: BTreeMap::new(),
            owner_nonces: BTreeSet::new(),
            request_nonces: BTreeSet::new(),
            audit: vec![],
            receipts: BTreeMap::new(),
        })
    }
    pub(crate) fn trust(&self) -> &AuthorityConfig {
        &self.config
    }
    pub(crate) fn validate_management(&self, action: &Management, time: i64) -> Result<()> {
        let mut next = self.clone();
        next.manage(action, time)
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn catalog(&self) -> Value {
        json!({"rings":self.rings,"rules":self.rules,"assets":self.assets})
    }
    pub fn assignments(&self, time: i64) -> Value {
        json!(self.permissions.values().map(|p|{let ring=self.active(p,time).ok();json!({"permission_id":p.scope.id,"client_key":p.scope.client_key,"task_id":p.scope.task_id,"state":if ring.is_some(){"thawed"}else{"zero"},"ring":ring.map(|r|r.name.as_str()),"expires_at":p.active.as_ref().map(|a|a.expires_at),"currency":p.scope.currency,"budget_minor":p.scope.budget_minor.to_string(),"spent_or_reserved_minor":p.used_minor.to_string(),"operations":p.operations})}).collect::<Vec<_>>())
    }
    fn bump(&mut self, event: Value) -> Result<()> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(AuthorityError::Rejected("revision overflow"))?;
        self.audit
            .push(json!({"revision":self.revision,"event":event}));
        Ok(())
    }
    /// Trusted owner surface signs this exact payload after a fresh owner check.
    pub fn approve(&mut self, message: &SignedMessage, time: i64) -> Result<Value> {
        let a: OwnerApproval = verify(message, &self.config.owner_key, OWNER_RING_DOMAIN)?;
        lifetime(a.issued_at, a.expires_at, time)?;
        if a.authority_id != self.config.authority_id
            || a.expected_revision != self.revision
            || !digest(&a.nonce)
            || self.owner_nonces.contains(&a.nonce)
        {
            return reject("owner ring scope, revision or replay");
        }
        let mut next = self.clone();
        next.manage(&a.action, time)?;
        next.owner_nonces.insert(a.nonce);
        next.bump(json!({"owner_approval":message}))?;
        let result = json!({"state":"committed","revision":next.revision});
        next.receipts
            .insert(next.receipt_key(message, true)?, result.clone());
        *self = next;
        Ok(result)
    }
    // Exact signed request recovery is read-only: it bypasses expiry/revision only
    // to return its already committed result. It never grants fresh execution.
    fn receipt_key(&self, message: &SignedMessage, owner: bool) -> Result<String> {
        let domain = if owner {
            let _: OwnerApproval = verify(message, &self.config.owner_key, OWNER_RING_DOMAIN)?;
            OWNER_RING_DOMAIN
        } else {
            let (r, _): (RingRequest, _) = decode(message)?;
            if r.client_key != self.config.executor_key
                && !self.config.agent_keys.contains(&r.client_key)
            {
                return reject("unknown recovery caller");
            }
            let _: RingRequest = verify(message, &r.client_key, RING_REQUEST_DOMAIN)?;
            RING_REQUEST_DOMAIN
        };
        Ok(hex::encode(Sha256::digest(signing_bytes(
            domain,
            message.payload.as_bytes(),
        ))))
    }
    pub(crate) fn recovered(&self, message: &SignedMessage, owner: bool) -> Result<Option<Value>> {
        Ok(self
            .receipts
            .get(&self.receipt_key(message, owner)?)
            .cloned())
    }
    fn validate_ring(&self, ring: &Ring) -> Result<()> {
        if !text(&ring.name) || ring.bindings.len() > 32 {
            return reject("invalid ring");
        }
        let mut assets = BTreeSet::new();
        for binding in &ring.bindings {
            let asset = reference(&self.assets, &binding.asset)?;
            if !assets.insert(binding.asset.id.clone())
                || binding.rules.is_empty()
                || binding.rules.len() > 16
            {
                return reject("ambiguous or unprotected asset binding");
            }
            for r in &binding.rules {
                let rule = reference(&self.rules, r)?;
                if !matches!(
                    (&asset.kind, rule),
                    (AssetKind::Payment, RuleDefinition::Spend { .. })
                        | (AssetKind::PersonalData, RuleDefinition::ShareFields { .. })
                        | (AssetKind::Credential, RuleDefinition::UseCredential { .. })
                ) {
                    return reject("rule does not protect this asset kind");
                }
            }
        }
        Ok(())
    }
    fn manage(&mut self, action: &Management, time: i64) -> Result<()> {
        match action {
            Management::PutAsset {
                id,
                expected_version,
                asset,
            } => {
                if !text(&asset.name)
                    || !text(&asset.source.provider)
                    || !text(&asset.source.account_label)
                    || !text(&asset.source.capability_ref)
                    || asset.source.operations.is_empty()
                    || asset.source.operations.len() > 32
                    || asset.source.operations.iter().any(|v| !text(v))
                {
                    return reject("invalid provider-held asset metadata");
                }
                put(&mut self.assets, id, *expected_version, asset.clone())?;
            }
            Management::PutRule {
                id,
                expected_version,
                rule,
            } => {
                match rule {
                    RuleDefinition::Spend {
                        merchant,
                        category,
                        currency: c,
                        requirements_digest,
                        item_ids,
                        max_purchase_minor,
                    } => {
                        if !text(merchant)
                            || !text(category)
                            || !currency(c)
                            || !digest(requirements_digest)
                            || item_ids.len() > 64
                            || item_ids.iter().any(|v| !text(v))
                            || *max_purchase_minor == 0
                            || *max_purchase_minor > i64::MAX as u64
                        {
                            return reject("invalid spending rule");
                        }
                    }
                    RuleDefinition::ShareFields {
                        fields,
                        destination,
                        purpose,
                    } => {
                        if fields.is_empty()
                            || fields.len() > 32
                            || fields.iter().any(|v| !text(v))
                            || !text(destination)
                            || !text(purpose)
                        {
                            return reject("invalid disclosure rule");
                        }
                    }
                    RuleDefinition::UseCredential {
                        operations,
                        destination,
                        purpose,
                    } => {
                        if operations.is_empty()
                            || operations.len() > 32
                            || operations.iter().any(|v| {
                                !text(v)
                                    || matches!(
                                        v.as_str(),
                                        "reveal"
                                            | "export"
                                            | "reveal_secret"
                                            | "export_secret"
                                            | "rotate"
                                    )
                            })
                            || !text(destination)
                            || !text(purpose)
                        {
                            return reject("use does not authorize secret export or rotation");
                        }
                    }
                }
                put(&mut self.rules, id, *expected_version, rule.clone())?;
            }
            Management::PutRing {
                id,
                expected_version,
                ring,
            } => {
                if id == "zero" {
                    return reject("zero ring is immutable");
                }
                self.validate_ring(ring)?;
                put(&mut self.rings, id, *expected_version, ring.clone())?;
            }
            Management::Delegate { permission: p } => {
                if !digest(&p.id)
                    || self.permissions.contains_key(&p.id)
                    || !self.config.agent_keys.contains(&p.client_key)
                    || !text(&p.task_id)
                    || self
                        .completed_tasks
                        .contains(&(p.client_key.clone(), p.task_id.clone()))
                    || p.targets.is_empty()
                    || p.targets.len() > 16
                    || !currency(&p.currency)
                    || p.budget_minor > i64::MAX as u64
                    || p.max_operations == 0
                    || p.expires_at <= time
                    || p.max_activation_seconds == 0
                    || p.max_swaps == 0
                {
                    return reject("invalid task ring permission");
                }
                for target in &p.targets {
                    self.validate_ring(reference(&self.rings, target)?)?;
                }
                if let Some(id) = &p.shared_budget_id {
                    let b = self
                        .shared_budgets
                        .get(id)
                        .ok_or(AuthorityError::Rejected("unknown shared budget"))?;
                    if b.currency != p.currency {
                        return reject("shared budget currency mismatch");
                    }
                }
                self.permissions.insert(
                    p.id.clone(),
                    Permission {
                        scope: p.clone(),
                        used_minor: 0,
                        operations: 0,
                        swaps: 0,
                        revoked: false,
                        active: None,
                    },
                );
            }
            Management::Revoke { permission_id } => {
                self.permissions
                    .get_mut(permission_id)
                    .ok_or(AuthorityError::Rejected("unknown permission"))?
                    .revoked = true;
            }
            Management::CreateSharedBudget {
                id,
                currency: c,
                total_minor,
            } => {
                if !text(id)
                    || !currency(c)
                    || *total_minor == 0
                    || *total_minor > i64::MAX as u64
                    || self.shared_budgets.contains_key(id)
                {
                    return reject("invalid or existing shared budget");
                }
                self.shared_budgets.insert(
                    id.clone(),
                    Budget {
                        currency: c.clone(),
                        limit_minor: *total_minor,
                        used_minor: 0,
                    },
                );
            }
        }
        Ok(())
    }
    fn active<'a>(&'a self, p: &'a Permission, time: i64) -> Result<&'a Ring> {
        if p.revoked
            || p.scope.expires_at <= time
            || self
                .completed_tasks
                .contains(&(p.scope.client_key.clone(), p.scope.task_id.clone()))
        {
            return reject("task permission ended");
        }
        let a = p.active.as_ref().ok_or(AuthorityError::Rejected(
            "zero permissions until authorized activation",
        ))?;
        if a.expires_at <= time {
            return reject("task permission expired");
        }
        let ring = reference(&self.rings, &a.ring)?;
        self.validate_ring(ring)?;
        Ok(ring)
    }
    pub fn handle(&mut self, message: &SignedMessage, time: i64) -> Result<Value> {
        let (untrusted, _): (RingRequest, _) = decode(message)?;
        let executor = untrusted.client_key == self.config.executor_key;
        if !executor && !self.config.agent_keys.contains(&untrusted.client_key) {
            return reject("unknown ring client");
        }
        let r: RingRequest = verify(message, &untrusted.client_key, RING_REQUEST_DOMAIN)?;
        lifetime(r.issued_at, r.expires_at, time)?;
        if r.authority_id != self.config.authority_id
            || !digest(&r.nonce)
            || r.expected_revision != self.revision
            || self
                .request_nonces
                .contains(&(r.client_key.clone(), r.nonce.clone()))
        {
            return reject("ring request scope, revision or replay");
        }
        let mut next = self.clone();
        let output = next.apply(&r, executor, time)?;
        next.request_nonces
            .insert((r.client_key.clone(), r.nonce.clone()));
        next.bump(json!({"request":message}))?;
        next.receipts
            .insert(next.receipt_key(message, false)?, output.clone());
        *self = next;
        Ok(output)
    }
    fn allowed(&self, ring: &Ring, q: &CapabilityQuote) -> Result<u64> {
        let binding = ring
            .bindings
            .iter()
            .find(|b| b.asset == q.asset)
            .ok_or(AuthorityError::Rejected("asset not in ring"))?;
        let asset = reference(&self.assets, &binding.asset)?;
        let operation = match &q.capability {
            Capability::Purchase { .. } => "purchase",
            Capability::ShareFields { .. } => "share_fields",
            Capability::UseCredential { operation, .. } => operation,
        };
        if !asset.source.operations.contains(operation) {
            return reject("provider adapter does not expose this operation");
        }
        if asset.source.interaction_mode == InteractionMode::Interactive
            && !q.provider_authorization.as_ref().is_some_and(|e| text(e))
        {
            return reject("provider user confirmation still required");
        }
        for rule in &binding.rules {
            let allowed = match (reference(&self.rules, rule)?, &q.capability) {
                (
                    RuleDefinition::Spend {
                        merchant,
                        category,
                        currency,
                        requirements_digest,
                        item_ids,
                        max_purchase_minor,
                    },
                    Capability::Purchase { purchase: p },
                ) => {
                    merchant == &p.merchant
                        && category == &p.category
                        && currency == &p.currency
                        && requirements_digest == &p.requirements_digest
                        && (item_ids.is_empty() || item_ids.contains(&p.item_id))
                        && p.total_minor <= *max_purchase_minor
                }
                (
                    RuleDefinition::ShareFields {
                        fields,
                        destination,
                        purpose,
                    },
                    Capability::ShareFields {
                        fields: f,
                        destination: d,
                        purpose: p,
                    },
                ) => !f.is_empty() && f.is_subset(fields) && d == destination && p == purpose,
                (
                    RuleDefinition::UseCredential {
                        operations,
                        destination,
                        purpose,
                    },
                    Capability::UseCredential {
                        operation,
                        destination: d,
                        purpose: p,
                    },
                ) => operations.contains(operation) && d == destination && p == purpose,
                _ => false,
            };
            if !allowed {
                return reject("capability violates an asset rule");
            }
        }
        if let Capability::Purchase { purchase: p } = &q.capability {
            if p.total_minor == 0
                || p.quantity == 0
                || !text(&p.item_id)
                || !text(&p.description)
                || !digest(&p.terms_digest)
                || !digest(&p.fulfillment_digest)
                || self.restrictions.blocked_categories.contains(&p.category)
                || self
                    .restrictions
                    .per_purchase_ceilings
                    .get(&p.currency)
                    .is_some_and(|n| p.total_minor > *n)
            {
                return reject("purchase violates mandatory restrictions");
            }
            Ok(p.total_minor)
        } else {
            Ok(0)
        }
    }
    fn apply(&mut self, r: &RingRequest, executor: bool, time: i64) -> Result<Value> {
        match &r.operation {
            Operation::Activate {
                permission_id,
                ring,
                expires_at,
            } if !executor => {
                self.validate_ring(reference(&self.rings, ring)?)?;
                let p = self
                    .permissions
                    .get_mut(permission_id)
                    .ok_or(AuthorityError::Rejected("unknown permission"))?;
                if p.scope.client_key != r.client_key
                    || p.revoked
                    || !p.scope.targets.contains(ring)
                    || self
                        .completed_tasks
                        .contains(&(r.client_key.clone(), p.scope.task_id.clone()))
                    || p.swaps >= p.scope.max_swaps
                    || *expires_at <= time
                    || *expires_at > p.scope.expires_at
                    || *expires_at
                        > time
                            .checked_add(i64::from(p.scope.max_activation_seconds))
                            .ok_or(AuthorityError::Rejected("expiry overflow"))?
                    || p.active
                        .as_ref()
                        .is_some_and(|a| a.expires_at <= time || *expires_at > a.expires_at)
                {
                    return reject("swap not covered by owner permission");
                }
                p.swaps += 1;
                p.active = Some(Activation {
                    ring: ring.clone(),
                    expires_at: *expires_at,
                });
                Ok(json!({"state":"active","ring":ring,"expires_at":expires_at}))
            }
            Operation::Freeze { permission_id } if !executor => {
                let p = self
                    .permissions
                    .get_mut(permission_id)
                    .ok_or(AuthorityError::Rejected("unknown permission"))?;
                if p.scope.client_key != r.client_key {
                    return reject("wrong task owner");
                }
                p.revoked = true;
                Ok(json!({"state":"zero"}))
            }
            Operation::CompleteTask { task_id } if !executor => {
                if !text(task_id)
                    || !self
                        .permissions
                        .values()
                        .any(|p| p.scope.client_key == r.client_key && p.scope.task_id == *task_id)
                {
                    return reject("unknown bound task");
                }
                self.completed_tasks
                    .insert((r.client_key.clone(), task_id.clone()));
                Ok(json!({"state":"completed"}))
            }
            Operation::Reserve { quote: signed } if executor => {
                let q: CapabilityQuote =
                    verify(signed, &self.config.executor_key, CAPABILITY_QUOTE_DOMAIN)?;
                lifetime(q.issued_at, q.expires_at, time)?;
                if q.authority_id != self.config.authority_id
                    || !digest(&q.quote_id)
                    || self.reservations.contains_key(&q.quote_id)
                {
                    return reject("capability quote scope or replay");
                }
                let p = self
                    .permissions
                    .get(&q.permission_id)
                    .ok_or(AuthorityError::Rejected("unknown task permission"))?;
                let ring = self.active(p, time)?;
                if q.client_key != p.scope.client_key
                    || q.task_id != p.scope.task_id
                    || p.operations >= p.scope.max_operations
                {
                    return reject("wrong task or operation limit");
                }
                let dispatch_before = q
                    .expires_at
                    .min(p.scope.expires_at)
                    .min(p.active.as_ref().unwrap().expires_at);
                let total = self.allowed(ring, &q)?;
                if let Capability::Purchase { purchase } = &q.capability {
                    if purchase.currency != p.scope.currency {
                        return reject("task budget currency mismatch");
                    }
                }
                let used = p
                    .used_minor
                    .checked_add(total)
                    .filter(|n| *n <= p.scope.budget_minor)
                    .ok_or(AuthorityError::Rejected("task budget exhausted"))?;
                if let Some(id) = &p.scope.shared_budget_id {
                    let b = self
                        .shared_budgets
                        .get_mut(id)
                        .ok_or(AuthorityError::Rejected("shared budget missing"))?;
                    b.used_minor = b
                        .used_minor
                        .checked_add(total)
                        .filter(|n| *n <= b.limit_minor)
                        .ok_or(AuthorityError::Rejected("shared budget exhausted"))?;
                }
                let p = self.permissions.get_mut(&q.permission_id).unwrap();
                p.used_minor = used;
                p.operations += 1;
                let id = q.quote_id.clone();
                self.reservations.insert(
                    id.clone(),
                    Reservation {
                        quote: q,
                        outcome: None,
                    },
                );
                Ok(
                    json!({"state":"reserved","execution_id":id,"idempotency_key":id,"executed":false,"dispatch_before":dispatch_before}),
                )
            }
            Operation::Report { quote_id, outcome } if executor => {
                if let Outcome::Succeeded { provider_reference } = outcome {
                    if self.reservations.iter().any(|(id,r)|id!=quote_id&&matches!(&r.outcome,Some(Outcome::Succeeded{provider_reference:other}) if other==provider_reference)){return reject("provider receipt already recorded");}
                }
                let reservation = self
                    .reservations
                    .get_mut(quote_id)
                    .ok_or(AuthorityError::Rejected("unknown execution"))?;
                if let Some(old) = &reservation.outcome {
                    if old == outcome {
                        return Ok(json!({"state":"already_recorded"}));
                    }
                    return reject("terminal outcome cannot change");
                }
                let detail = match outcome {
                    Outcome::Succeeded { provider_reference } => provider_reference,
                    Outcome::FailedBeforeExecution { reason } | Outcome::Unknown { reason } => {
                        reason
                    }
                };
                if !text(detail) {
                    return reject("missing verified outcome");
                }
                if matches!(outcome, Outcome::FailedBeforeExecution { .. }) {
                    let amount = match &reservation.quote.capability {
                        Capability::Purchase { purchase } => purchase.total_minor,
                        _ => 0,
                    };
                    let p = self
                        .permissions
                        .get_mut(&reservation.quote.permission_id)
                        .ok_or(AuthorityError::Rejected("permission missing"))?;
                    p.used_minor = p
                        .used_minor
                        .checked_sub(amount)
                        .ok_or(AuthorityError::Rejected("budget integrity"))?;
                    if let Some(id) = &p.scope.shared_budget_id {
                        let b = self
                            .shared_budgets
                            .get_mut(id)
                            .ok_or(AuthorityError::Rejected("budget missing"))?;
                        b.used_minor = b
                            .used_minor
                            .checked_sub(amount)
                            .ok_or(AuthorityError::Rejected("shared budget integrity"))?;
                    }
                }
                reservation.outcome = Some(outcome.clone());
                Ok(json!({"state":"recorded"}))
            }
            _ => reject("operation requires another role"),
        }
    }
}
