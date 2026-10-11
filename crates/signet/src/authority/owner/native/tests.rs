use super::*;
use crate::authority::{
    object_store::{Condition, Object},
    rings::*,
};
use ed25519_dalek::{Signer as _, SigningKey};
use rand::rngs::OsRng;
use std::sync::{Arc, Mutex};
use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};
#[derive(Clone, Default)]
struct Memory(Arc<Mutex<MemoryState>>);
#[derive(Default)]
struct MemoryState {
    objects: BTreeMap<String, Object>,
    serial: u64,
    lose_reply: bool,
}
impl Store for Memory {
    fn get(&self, key: &str) -> object_store::Result<Option<Object>> {
        Ok(self.0.lock().unwrap().objects.get(key).cloned())
    }
    fn put(&self, key: &str, bytes: &[u8], condition: &Condition) -> object_store::Result<()> {
        let mut m = self.0.lock().unwrap();
        let old = m.objects.get(key);
        if match condition {
            Condition::Absent => old.is_some(),
            Condition::Matches(t) => old.is_none_or(|o| &o.etag != t),
        } {
            return Err(object_store::Error::Conflict);
        }
        m.serial += 1;
        let etag = format!("opaque-{}", m.serial);
        m.objects.insert(
            key.into(),
            Object {
                bytes: bytes.into(),
                etag,
            },
        );
        if key.ends_with("head.json") && m.lose_reply {
            m.lose_reply = false;
            return Err(object_store::Error::Unavailable);
        }
        Ok(())
    }
}
struct TestSigner(SigningKey);
impl Signer for TestSigner {
    fn sign_ed25519(&self, b: &[u8]) -> signet_core::SignetResult<[u8; 64]> {
        Ok(self.0.sign(b).to_bytes())
    }
    fn public_key_ed25519(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}
fn public(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().to_bytes())
}
fn signed(k: &SigningKey, domain: &str, value: &impl Serialize) -> SignedMessage {
    let b = serde_json::to_vec(value).unwrap();
    SignedMessage {
        payload: URL_SAFE_NO_PAD.encode(&b),
        signature: hex::encode(k.sign(&signing_bytes(domain, &b)).to_bytes()),
    }
}
struct Fixture {
    memory: Memory,
    service: NativeOwnerService,
    owner: SigningKey,
    agent: SigningKey,
    executor: SigningKey,
    sid: String,
    csrf: String,
    token: String,
    auth: WebauthnAuthenticator<SoftPasskey>,
}
impl Fixture {
    fn new() -> Self {
        let memory = Memory::default();
        let owner = SigningKey::generate(&mut OsRng);
        let agent = SigningKey::generate(&mut OsRng);
        let executor = SigningKey::generate(&mut OsRng);
        let token = id();
        let trust = AuthorityConfig {
            authority_id: id(),
            owner_key: public(&owner),
            agent_keys: vec![public(&agent)],
            executor_key: public(&executor),
        };
        let config = OwnerConfig {
            rp_id: "signet.test".into(),
            origin: "https://owner.signet.test".into(),
            user_id: uuid::Uuid::new_v4(),
            display_name: "Synthetic owner".into(),
            agent_labels: BTreeMap::from([(public(&agent), "Test worker".into())]),
            enrollment_token_hash: hex::encode(Sha256::digest(token.as_bytes())),
            enrollment_expires_at: now() + 600,
        };
        NativeOwnerService::initialize(
            Box::new(memory.clone()),
            "a".repeat(64),
            config.clone(),
            trust,
            Restrictions::default(),
        )
        .unwrap();
        let mut service = NativeOwnerService::open(
            Box::new(memory.clone()),
            "a".repeat(64),
            Box::new(TestSigner(owner.clone())),
            config,
        )
        .unwrap();
        let (sid, s) = service.session(None).unwrap();
        Self {
            memory,
            service,
            owner,
            agent,
            executor,
            sid,
            csrf: s["csrf"].as_str().unwrap().into(),
            token,
            auth: WebauthnAuthenticator::new(SoftPasskey::new(true)),
        }
    }
    fn enroll(&mut self) -> String {
        let b = self
            .service
            .begin_enrollment(&self.sid, &self.csrf, &self.token, "First key".into())
            .unwrap();
        let r = self
            .auth
            .do_registration(
                Url::parse(self.service.origin()).unwrap(),
                serde_json::from_value(b["options"].clone()).unwrap(),
            )
            .unwrap();
        self.service
            .finish_registration(
                &self.sid,
                &self.csrf,
                b["challenge_id"].as_str().unwrap(),
                &r,
            )
            .unwrap()["credential_id"]
            .as_str()
            .unwrap()
            .into()
    }
    fn begin(&mut self, intent: OwnerIntent) -> (Value, PublicKeyCredential) {
        let b = self
            .service
            .begin_authentication(&self.sid, &self.csrf, intent)
            .unwrap();
        let r = self
            .auth
            .do_authentication(
                Url::parse(self.service.origin()).unwrap(),
                serde_json::from_value(b["options"].clone()).unwrap(),
            )
            .unwrap();
        (b, r)
    }
    fn finish(&mut self, b: &Value, r: &PublicKeyCredential) -> Result<Value> {
        self.service.finish_authentication(
            &self.sid,
            &self.csrf,
            b["challenge_id"].as_str().unwrap(),
            r,
        )
    }
    fn manage(&mut self, action: Management) -> Value {
        let rev = self.service.load().unwrap().state.rings.revision();
        let (b, r) = self.begin(OwnerIntent::ManageRings {
            expected_revision: rev,
            action,
        });
        self.finish(&b, &r).unwrap()
    }
    fn catalog(&mut self) -> Value {
        self.service.dashboard(&self.sid, &self.csrf).unwrap()["catalog"].clone()
    }
    fn request(&self, k: &SigningKey, operation: Operation) -> SignedMessage {
        let state = self.service.load().unwrap().state;
        signed(
            k,
            RING_REQUEST_DOMAIN,
            &RingRequest {
                authority_id: state.rings.trust().authority_id.clone(),
                client_key: public(k),
                nonce: id(),
                issued_at: now(),
                expires_at: now() + 100,
                expected_revision: state.rings.revision(),
                operation,
            },
        )
    }
    fn setup_ring(&mut self) {
        self.enroll();
        self.manage(Management::PutAsset {
            id: "card".into(),
            expected_version: None,
            asset: Asset {
                name: "Synthetic card".into(),
                kind: AssetKind::Payment,
                source: Source {
                    provider: "Synthetic broker".into(),
                    account_label: "Test".into(),
                    capability_ref: "test:card".into(),
                    operations: ["purchase".into()].into(),
                    interaction_mode: InteractionMode::Delegated,
                },
            },
        });
        self.manage(Management::PutRule {
            id: "spend".into(),
            expected_version: None,
            rule: Self::rule(500),
        });
        self.manage(Management::PutRing {
            id: "shop".into(),
            expected_version: None,
            ring: Self::ring(1),
        });
    }
    fn rule(amount: u64) -> RuleDefinition {
        RuleDefinition::Spend {
            merchant: "shop.test".into(),
            category: "supplies".into(),
            currency: "USD".into(),
            requirements_digest: "a".repeat(64),
            item_ids: ["item".into()].into(),
            max_purchase_minor: amount,
        }
    }
    fn ring(v: u64) -> Ring {
        Ring {
            name: "Supplies".into(),
            bindings: vec![Binding {
                asset: Reference {
                    id: "card".into(),
                    version: 1,
                },
                rules: [Reference {
                    id: "spend".into(),
                    version: v,
                }]
                .into(),
            }],
        }
    }
    fn grant(&mut self) -> String {
        let pid = id();
        self.manage(Management::Delegate {
            permission: Delegation {
                id: pid.clone(),
                client_key: public(&self.agent),
                task_id: "task".into(),
                targets: [Reference {
                    id: "shop".into(),
                    version: 1,
                }]
                .into(),
                currency: "USD".into(),
                budget_minor: 700,
                max_operations: 3,
                expires_at: now() + 300,
                max_activation_seconds: 120,
                max_swaps: 1,
                shared_budget_id: None,
            },
        });
        let request = self.request(
            &self.agent,
            Operation::Activate {
                permission_id: pid.clone(),
                ring: Reference {
                    id: "shop".into(),
                    version: 1,
                },
                expires_at: now() + 100,
            },
        );
        self.service.agent_request(&request).unwrap();
        pid
    }
    fn reserve(&mut self, pid: &str, amount: u64) -> Result<Value> {
        let quote = signed(
            &self.executor,
            CAPABILITY_QUOTE_DOMAIN,
            &CapabilityQuote {
                authority_id: self
                    .service
                    .load()?
                    .state
                    .rings
                    .trust()
                    .authority_id
                    .clone(),
                quote_id: id(),
                permission_id: pid.into(),
                client_key: public(&self.agent),
                task_id: "task".into(),
                asset: Reference {
                    id: "card".into(),
                    version: 1,
                },
                capability: Capability::Purchase {
                    purchase: Purchase {
                        merchant: "shop.test".into(),
                        currency: "USD".into(),
                        item_id: "item".into(),
                        description: "Synthetic".into(),
                        category: "supplies".into(),
                        quantity: 1,
                        total_minor: amount,
                        requirements_digest: "a".repeat(64),
                        terms_digest: "b".repeat(64),
                        fulfillment_digest: "c".repeat(64),
                    },
                },
                provider_authorization: None,
                issued_at: now(),
                expires_at: now() + 60,
            },
        );
        let req = self.request(&self.executor, Operation::Reserve { quote });
        self.service.agent_request(&req)
    }
}
#[test]
fn passkey_ring_lifecycle_budget_revocation_and_restore_preserve_ledger() {
    let mut f = Fixture::new();
    f.enroll();
    assert_eq!(f.catalog()["rings"].as_object().unwrap().len(), 1);
    assert!(f.catalog()["assets"].as_object().unwrap().is_empty());
    let mut f = Fixture::new();
    f.setup_ring();
    let pid = f.grant();
    let first = f.reserve(&pid, 400).unwrap();
    assert_eq!(first["outcome"], "committed_now");
    assert!(f.reserve(&pid, 400).is_err());
    f.manage(Management::PutRule {
        id: "spend".into(),
        expected_version: Some(1),
        rule: Fixture::rule(450),
    });
    assert!(f.reserve(&pid, 100).is_err());
    f.manage(Management::PutRule {
        id: "spend".into(),
        expected_version: Some(2),
        rule: Fixture::rule(500),
    });
    assert_eq!(f.catalog()["rules"]["spend"]["version"], 3);
    f.manage(Management::PutRing {
        id: "shop".into(),
        expected_version: Some(1),
        ring: Fixture::ring(3),
    });
    assert!(f.reserve(&pid, 100).is_err());
    f.manage(Management::Revoke {
        permission_id: pid.clone(),
    });
    let state = f.service.load().unwrap().state;
    let assignment = state.rings.assignments(now());
    assert_eq!(assignment[0]["spent_or_reserved_minor"], "400");
    assert_eq!(assignment[0]["state"], "zero");
    assert!(f.reserve(&pid, 100).is_err());
    let ring_count = f.catalog()["rings"].as_object().unwrap().len();
    assert_eq!(ring_count, 2);
}
#[test]
fn uncertain_owner_commit_recovers_exact_receipt_without_reapplying() {
    let mut f = Fixture::new();
    f.enroll();
    let (b, r) = f.begin(OwnerIntent::ManageRings {
        expected_revision: 0,
        action: Management::PutRing {
            id: "empty".into(),
            expected_version: None,
            ring: Ring {
                name: "Empty".into(),
                bindings: vec![],
            },
        },
    });
    f.memory.0.lock().unwrap().lose_reply = true;
    assert!(f.finish(&b, &r).is_err());
    let got = f.finish(&b, &r).unwrap();
    assert_eq!(got["state"], "recovered");
    assert_eq!(got["dispatch"], false);
    assert_eq!(f.catalog()["rings"]["empty"]["version"], 1);
}
#[test]
fn fresh_passkey_review_cannot_be_rebound_after_concurrent_change() {
    let mut f = Fixture::new();
    f.enroll();
    let intent = OwnerIntent::ManageRings {
        expected_revision: 0,
        action: Management::PutRing {
            id: "first".into(),
            expected_version: None,
            ring: Ring {
                name: "First".into(),
                bindings: vec![],
            },
        },
    };
    let (b, r) = f.begin(intent);
    f.manage(Management::PutRing {
        id: "other".into(),
        expected_version: None,
        ring: Ring {
            name: "Other".into(),
            bindings: vec![],
        },
    });
    assert!(f.finish(&b, &r).is_err());
    assert!(f.catalog()["rings"].get("first").is_none());
    assert!(f
        .service
        .begin_authentication(&f.sid, "wrong", OwnerIntent::Login)
        .is_err());
}
#[test]
fn restart_retains_credentials_and_rules_but_requires_new_session() {
    let mut f = Fixture::new();
    f.setup_ring();
    let mut reopened = NativeOwnerService::open(
        Box::new(f.memory.clone()),
        "a".repeat(64),
        Box::new(TestSigner(f.owner.clone())),
        f.service.config.clone(),
    )
    .unwrap();
    assert!(reopened.dashboard(&f.sid, &f.csrf).is_err());
    let (sid, s) = reopened.session(None).unwrap();
    assert_eq!(s["enrolled"], true);
    let csrf = s["csrf"].as_str().unwrap();
    let b = reopened
        .begin_authentication(&sid, csrf, OwnerIntent::Login)
        .unwrap();
    let r = f
        .auth
        .do_authentication(
            Url::parse(reopened.origin()).unwrap(),
            serde_json::from_value(b["options"].clone()).unwrap(),
        )
        .unwrap();
    reopened
        .finish_authentication(&sid, csrf, b["challenge_id"].as_str().unwrap(), &r)
        .unwrap();
    assert_eq!(
        reopened.dashboard(&sid, csrf).unwrap()["catalog"]["rings"]["shop"]["version"],
        1
    );
}
#[test]
fn task_completion_and_expiry_stop_authority_without_releasing_reservations() {
    let mut f = Fixture::new();
    f.setup_ring();
    let pid = f.grant();
    f.reserve(&pid, 300).unwrap();
    let req = f.request(
        &f.agent,
        Operation::CompleteTask {
            task_id: "task".into(),
        },
    );
    f.service.agent_request(&req).unwrap();
    assert!(f.reserve(&pid, 100).is_err());
    assert_eq!(
        f.service.load().unwrap().state.rings.assignments(now())[0]["spent_or_reserved_minor"],
        "300"
    );
    let mut f = Fixture::new();
    f.setup_ring();
    let pid = f.grant();
    assert_eq!(
        f.service
            .load()
            .unwrap()
            .state
            .rings
            .assignments(now() + 121)[0]["state"],
        "zero"
    );
    assert!(f.reserve(&pid, 701).is_err());
}
