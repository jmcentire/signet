//! Synthetic WebAuthn credentials only. SoftPasskey's simulated UV is test-only.
use super::*;
use ed25519_dalek::{Signer as EdSigner, SigningKey};
use rand::rngs::OsRng;
use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};
type Authenticator = WebauthnAuthenticator<SoftPasskey>;
struct TestSigner(SigningKey);
impl Signer for TestSigner {
    fn sign_ed25519(&self, message: &[u8]) -> signet_core::SignetResult<[u8; 64]> {
        Ok(self.0.sign(message).to_bytes())
    }
    fn public_key_ed25519(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}
fn public(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().to_bytes())
}
fn sign(k: &SigningKey, domain: &str, value: &impl Serialize) -> SignedMessage {
    let bytes = serde_json::to_vec(value).unwrap();
    SignedMessage {
        payload: URL_SAFE_NO_PAD.encode(&bytes),
        signature: hex::encode(k.sign(&signing_bytes(domain, &bytes)).to_bytes()),
    }
}
fn hash(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}
struct Fixture {
    _dir: tempfile::TempDir,
    service: OwnerService,
    agent: SigningKey,
    executor: SigningKey,
    sid: String,
    csrf: String,
    token: String,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let owner = SigningKey::generate(&mut OsRng);
        let agent = SigningKey::generate(&mut OsRng);
        let executor = SigningKey::generate(&mut OsRng);
        let trust = AuthorityConfig {
            authority_id: id(),
            owner_key: public(&owner),
            agent_keys: vec![public(&agent)],
            executor_key: public(&executor),
        };
        let authority = Authority::create(&dir.path().join("authority.sqlite"), trust).unwrap();
        let token = id();
        let config = OwnerConfig {
            rp_id: "signet.test".into(),
            origin: "https://owner.signet.test".into(),
            user_id: uuid::Uuid::new_v4(),
            display_name: "Synthetic owner".into(),
            agent_labels: BTreeMap::from([(public(&agent), "Personal agent".into())]),
            enrollment_token_hash: hash(&token),
            enrollment_expires_at: now() + 600,
        };
        let mut service =
            OwnerService::open(authority, Box::new(TestSigner(owner)), config).unwrap();
        let (sid, s) = service.session(None).unwrap();
        let csrf = s["csrf"].as_str().unwrap().into();
        Self {
            _dir: dir,
            service,
            agent,
            executor,
            sid,
            csrf,
            token,
        }
    }
    fn origin(&self) -> Url {
        Url::parse(self.service.origin()).unwrap()
    }
    fn enroll(&mut self, auth: &mut Authenticator) -> String {
        let begin = self
            .service
            .begin_enrollment(&self.sid, &self.csrf, &self.token, "First passkey".into())
            .unwrap();
        let response = auth
            .do_registration(
                self.origin(),
                serde_json::from_value(begin["options"].clone()).unwrap(),
            )
            .unwrap();
        self.service
            .finish_registration(
                &self.sid,
                &self.csrf,
                begin["challenge_id"].as_str().unwrap(),
                &response,
            )
            .unwrap()["credential_id"]
            .as_str()
            .unwrap()
            .into()
    }
    fn begin(&mut self, intent: OwnerIntent) -> Value {
        self.service
            .begin_authentication(&self.sid, &self.csrf, intent)
            .unwrap()
    }
    fn response(&self, auth: &mut Authenticator, begin: &Value) -> PublicKeyCredential {
        auth.do_authentication(
            self.origin(),
            serde_json::from_value(begin["options"].clone()).unwrap(),
        )
        .unwrap()
    }
    fn finish(&mut self, begin: &Value, response: &PublicKeyCredential) -> Result<Value> {
        self.service.finish_authentication(
            &self.sid,
            &self.csrf,
            begin["challenge_id"].as_str().unwrap(),
            response,
        )
    }
    fn authenticate(&mut self, auth: &mut Authenticator, intent: OwnerIntent) -> Value {
        let begin = self.begin(intent);
        let response = self.response(auth, &begin);
        self.finish(&begin, &response).unwrap()
    }
    fn agent_message(&self, command: Command) -> SignedMessage {
        sign(
            &self.agent,
            CLIENT_DOMAIN,
            &Request {
                authority_id: self.service.authority.config.authority_id.clone(),
                client_key: public(&self.agent),
                nonce: id(),
                issued_at: now(),
                expires_at: now() + 120,
                command,
            },
        )
    }
    fn call(&mut self, command: Command) -> Value {
        let signed = self.agent_message(command);
        self.service.agent_request(&signed).unwrap()
    }
    fn propose(&mut self, action: ApprovedAction, documents: BTreeMap<String, String>) -> Value {
        self.call(Command::ProposeApproval { action, documents })
    }
    fn rule(&mut self) -> Value {
        self.propose(
            ApprovedAction::RuleMutation {
                mutation: Mutation::Add {
                    rule_id: id(),
                    rule: Rule::RequireConfirmation {
                        category: Some("electronics".into()),
                    },
                },
            },
            BTreeMap::new(),
        )
    }
    fn purchase(&mut self) -> (Value, Purchase) {
        let words = [
            "Warm light and the approved size.",
            "One purchase; no subscription.",
            "Approved address, standard delivery.",
        ];
        let docs = words.iter().map(|s| (hash(s), s.to_string())).collect();
        let p = Purchase {
            merchant: "amazon.com".into(),
            currency: "USD".into(),
            item_id: "test-lamp".into(),
            description: "Synthetic desk lamp".into(),
            category: "electronics".into(),
            quantity: 1,
            total_minor: 7500,
            requirements_digest: hash(words[0]),
            terms_digest: hash(words[1]),
            fulfillment_digest: hash(words[2]),
        };
        let quote = sign(
            &self.executor,
            QUOTE_DOMAIN,
            &Quote {
                authority_id: self.service.authority.config.authority_id.clone(),
                client_key: public(&self.agent),
                quote_id: id(),
                issued_at: now(),
                expires_at: now() + 120,
                purchase: p.clone(),
            },
        );
        (self.propose(ApprovedAction::Purchase { quote }, docs), p)
    }
}
fn authenticator() -> Authenticator {
    WebauthnAuthenticator::new(SoftPasskey::new(true))
}

#[test]
fn passkey_approves_exact_rule_and_core_rejects_replay() {
    let mut f = Fixture::new();
    let mut auth = authenticator();
    f.enroll(&mut auth);
    let proposal = f.rule();
    let id = proposal["proposal_id"].as_str().unwrap().to_owned();
    let begin = f.begin(OwnerIntent::Approve {
        proposal_id: id.clone(),
    });
    let response = f.response(&mut auth, &begin);
    assert_eq!(f.finish(&begin, &response).unwrap()["state"], "committed");
    assert!(f.finish(&begin, &response).is_err());
    assert_eq!(
        f.call(Command::ApprovalStatus { proposal_id: id })["state"],
        "committed"
    );
    assert_eq!(
        f.call(Command::Snapshot)["rules"].as_array().unwrap().len(),
        1
    );
}
#[test]
fn purchase_approval_creates_one_grant_without_execution_or_rule_changes() {
    let mut f = Fixture::new();
    let mut auth = authenticator();
    f.enroll(&mut auth);
    let (proposal, p) = f.purchase();
    let id = proposal["proposal_id"].as_str().unwrap().to_owned();
    assert_eq!(proposal["review"]["purchase"]["total_minor"], "7500");
    let result = f.authenticate(
        &mut auth,
        OwnerIntent::Approve {
            proposal_id: id.clone(),
        },
    );
    assert_eq!(result["executed"], false);
    let status = f.call(Command::ApprovalStatus { proposal_id: id });
    let grant_id = status["grant_id"].as_str().unwrap();
    let signed = sign(
        &f.executor,
        CLIENT_DOMAIN,
        &Request {
            authority_id: f.service.authority.config.authority_id.clone(),
            client_key: public(&f.executor),
            nonce: super::super::id(),
            issued_at: now(),
            expires_at: now() + 120,
            command: Command::ConsumePurchase {
                grant_id: grant_id.into(),
                purchase: p,
            },
        },
    );
    assert_eq!(
        f.service.agent_request(&signed).unwrap()["state"],
        "reserved"
    );
    assert!(f.service.agent_request(&signed).is_err());
    assert!(f.call(Command::Snapshot)["rules"]
        .as_array()
        .unwrap()
        .is_empty());
}
#[test]
fn login_is_not_approval_and_anonymous_sessions_cannot_review() {
    let mut f = Fixture::new();
    let p = f.rule();
    assert!(f.service.dashboard(&f.sid, &f.csrf).is_err());
    assert!(f
        .service
        .begin_authentication(
            &f.sid,
            &f.csrf,
            OwnerIntent::Approve {
                proposal_id: p["proposal_id"].as_str().unwrap().into()
            }
        )
        .is_err());
    let mut auth = authenticator();
    f.enroll(&mut auth);
    let p = f.rule();
    f.authenticate(&mut auth, OwnerIntent::Login);
    assert_eq!(
        f.call(Command::ApprovalStatus {
            proposal_id: p["proposal_id"].as_str().unwrap().into()
        })["state"],
        "pending"
    );
    assert!(f.call(Command::Snapshot)["rules"]
        .as_array()
        .unwrap()
        .is_empty());
}
#[test]
fn enrollment_invitation_is_single_use_and_not_a_recovery_backdoor() {
    let mut f = Fixture::new();
    let mut auth = authenticator();
    assert!(f
        .service
        .begin_enrollment(&f.sid, &f.csrf, "wrong", "Key".into())
        .is_err());
    f.enroll(&mut auth);
    assert!(f
        .service
        .begin_enrollment(&f.sid, &f.csrf, &f.token, "Key".into())
        .is_err());
    f.service
        .authority
        .connection
        .execute("UPDATE owner_credentials SET revoked=1", [])
        .unwrap();
    assert!(f
        .service
        .begin_enrollment(&f.sid, &f.csrf, &f.token, "Recovery".into())
        .is_err());
    assert!(f
        .service
        .begin_authentication(&f.sid, &f.csrf, OwnerIntent::Login)
        .is_err());
}
#[test]
fn wrong_origin_port_and_rp_id_are_rejected() {
    let mut f = Fixture::new();
    let mut auth = authenticator();
    f.enroll(&mut auth);
    for origin in ["https://evil.signet.test", "https://owner.signet.test:8443"] {
        let begin = f.begin(OwnerIntent::Login);
        let response = auth
            .do_authentication(
                Url::parse(origin).unwrap(),
                serde_json::from_value(begin["options"].clone()).unwrap(),
            )
            .unwrap();
        assert!(f.finish(&begin, &response).is_err());
    }
    let begin = f.begin(OwnerIntent::Login);
    let mut options: RequestChallengeResponse =
        serde_json::from_value(begin["options"].clone()).unwrap();
    options.public_key.rp_id = "owner.signet.test".into();
    let response = auth.do_authentication(f.origin(), options).unwrap();
    assert!(f.finish(&begin, &response).is_err());
}
#[test]
fn valid_signed_assertion_without_user_verification_is_rejected() {
    let mut f = Fixture::new();
    let mut auth = authenticator();
    f.enroll(&mut auth);
    let begin = f.begin(OwnerIntent::Login);
    let mut options: RequestChallengeResponse =
        serde_json::from_value(begin["options"].clone()).unwrap();
    options.public_key.user_verification = serde_json::from_value(json!("discouraged")).unwrap();
    let response = auth.do_authentication(f.origin(), options).unwrap();
    assert!(f.finish(&begin, &response).is_err());
    let mut f = Fixture::new();
    let begin = f
        .service
        .begin_enrollment(&f.sid, &f.csrf, &f.token, "No UV".into())
        .unwrap();
    let mut options: CreationChallengeResponse =
        serde_json::from_value(begin["options"].clone()).unwrap();
    options
        .public_key
        .authenticator_selection
        .as_mut()
        .unwrap()
        .user_verification = serde_json::from_value(json!("discouraged")).unwrap();
    let response = auth.do_registration(f.origin(), options).unwrap();
    assert!(f
        .service
        .finish_registration(
            &f.sid,
            &f.csrf,
            begin["challenge_id"].as_str().unwrap(),
            &response
        )
        .is_err());
}
#[test]
fn challenges_bind_session_action_expiry_and_policy_revision() {
    let mut f = Fixture::new();
    let mut auth = authenticator();
    f.enroll(&mut auth);
    let p = f.rule();
    let begin = f.begin(OwnerIntent::Approve {
        proposal_id: p["proposal_id"].as_str().unwrap().into(),
    });
    let response = f.response(&mut auth, &begin);
    let (other, s) = f.service.session(None).unwrap();
    assert!(f
        .service
        .finish_authentication(
            &other,
            s["csrf"].as_str().unwrap(),
            begin["challenge_id"].as_str().unwrap(),
            &response
        )
        .is_err());
    let second = f.begin(OwnerIntent::Login);
    assert!(f.finish(&second, &response).is_err());
    f.service
        .authority
        .connection
        .execute(
            "UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key='revision'",
            [],
        )
        .unwrap();
    assert!(f.finish(&begin, &response).is_err());
    let begin = f.begin(OwnerIntent::Login);
    let response = f.response(&mut auth, &begin);
    f.service
        .pending
        .get_mut(begin["challenge_id"].as_str().unwrap())
        .unwrap()
        .expires = now() - 1;
    assert!(f.finish(&begin, &response).is_err());
    assert!(f.call(Command::Snapshot)["rules"]
        .as_array()
        .unwrap()
        .is_empty());
}
#[test]
fn backup_enrollment_and_revocation_require_fresh_proof_and_invalidate_old_challenges() {
    let mut f = Fixture::new();
    let mut first = authenticator();
    let cid = f.enroll(&mut first);
    assert!(f
        .service
        .begin_authentication(
            &f.sid,
            &f.csrf,
            OwnerIntent::RevokePasskey {
                credential_id: cid.clone()
            }
        )
        .is_err());
    let old = f.begin(OwnerIntent::Login);
    let old_response = f.response(&mut first, &old);
    let registration = f.authenticate(
        &mut first,
        OwnerIntent::AddPasskey {
            label: "Backup".into(),
        },
    );
    let mut backup = authenticator();
    let response = backup
        .do_registration(
            f.origin(),
            serde_json::from_value(registration["options"].clone()).unwrap(),
        )
        .unwrap();
    f.service
        .finish_registration(
            &f.sid,
            &f.csrf,
            registration["challenge_id"].as_str().unwrap(),
            &response,
        )
        .unwrap();
    assert!(f.finish(&old, &old_response).is_err());
    let result = f.authenticate(
        &mut backup,
        OwnerIntent::RevokePasskey { credential_id: cid },
    );
    assert_eq!(result["state"], "revoked");
    assert_eq!(
        f.service.dashboard(&f.sid, &f.csrf).unwrap()["passkeys"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let begin = f.begin(OwnerIntent::Login);
    assert!(first
        .do_authentication(
            f.origin(),
            serde_json::from_value(begin["options"].clone()).unwrap()
        )
        .is_err());
}
#[test]
fn counter_updates_reject_out_of_order_authentication_and_approval_tampering() {
    let mut f = Fixture::new();
    let mut auth = authenticator();
    f.enroll(&mut auth);
    let first = f.begin(OwnerIntent::Login);
    let a = f.response(&mut auth, &first);
    let second = f.begin(OwnerIntent::Login);
    let b = f.response(&mut auth, &second);
    f.finish(&second, &b).unwrap();
    assert!(f.finish(&first, &a).is_err());
    let p = f.rule();
    let begin = f.begin(OwnerIntent::Approve {
        proposal_id: p["proposal_id"].as_str().unwrap().into(),
    });
    let response = f.response(&mut auth, &begin);
    f.service
        .authority
        .connection
        .execute(
            "UPDATE owner_proposals SET review='{}' WHERE id=?1",
            [p["proposal_id"].as_str().unwrap()],
        )
        .unwrap();
    assert!(f.finish(&begin, &response).is_err());
}
#[test]
fn readable_terms_are_hash_bound_and_signer_failures_do_not_commit() {
    let mut f = Fixture::new();
    let mut auth = authenticator();
    f.enroll(&mut auth);
    let action = ApprovedAction::RuleMutation {
        mutation: Mutation::Add {
            rule_id: "limit".into(),
            rule: Rule::SpendLimit {
                merchant: "amazon.com".into(),
                currency: "USD".into(),
                requirements_digest: hash("Real conditions"),
                max_total_minor: 5000,
            },
        },
    };
    let signed = f.agent_message(Command::ProposeApproval {
        action: action.clone(),
        documents: BTreeMap::from([(hash("Real conditions"), "Misleading conditions".into())]),
    });
    assert!(f.service.agent_request(&signed).is_err());
    let signed = f.agent_message(Command::ProposeApproval {
        action: action.clone(),
        documents: BTreeMap::new(),
    });
    assert!(f.service.agent_request(&signed).is_err());
    let p = f.propose(
        action,
        BTreeMap::from([(hash("Real conditions"), "Real conditions".into())]),
    );
    // A signer mismatch/failure must roll back passkey counter, grant and rule state.
    f.service.signer = Box::new(TestSigner(SigningKey::generate(&mut OsRng)));
    let begin = f.begin(OwnerIntent::Approve {
        proposal_id: p["proposal_id"].as_str().unwrap().into(),
    });
    let response = f.response(&mut auth, &begin);
    assert!(f.finish(&begin, &response).is_err());
    assert!(f.call(Command::Snapshot)["rules"]
        .as_array()
        .unwrap()
        .is_empty());
    let count: u64 = f
        .service
        .authority
        .connection
        .query_row("SELECT COUNT(*) FROM grants", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn two_fresh_approvals_cannot_commit_one_proposal_twice() {
    let mut f = Fixture::new();
    let mut auth = authenticator();
    f.enroll(&mut auth);
    let p = f.rule();
    let intent = OwnerIntent::Approve {
        proposal_id: p["proposal_id"].as_str().unwrap().into(),
    };
    let a = f.begin(intent.clone());
    let ra = f.response(&mut auth, &a);
    let b = f.begin(intent);
    let rb = f.response(&mut auth, &b);
    f.finish(&a, &ra).unwrap();
    assert!(f.finish(&b, &rb).is_err());
    let count: u64 = f
        .service
        .authority
        .connection
        .query_row("SELECT COUNT(*) FROM grants", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
}
#[test]
fn registration_is_one_shot_expiring_and_restart_loses_all_sessions() {
    let mut f = Fixture::new();
    let mut auth = authenticator();
    let begin = f
        .service
        .begin_enrollment(&f.sid, &f.csrf, &f.token, "First".into())
        .unwrap();
    let response = auth
        .do_registration(
            f.origin(),
            serde_json::from_value(begin["options"].clone()).unwrap(),
        )
        .unwrap();
    let cid = begin["challenge_id"].as_str().unwrap();
    f.service.pending.get_mut(cid).unwrap().expires = now() - 1;
    assert!(f
        .service
        .finish_registration(&f.sid, &f.csrf, cid, &response)
        .is_err());
    f.enroll(&mut auth);
    let begin = f.begin(OwnerIntent::Login);
    let response = f.response(&mut auth, &begin);
    let OwnerService {
        authority,
        signer,
        config,
        ..
    } = f.service;
    let mut changed = config.clone();
    changed.origin = "https://wrong.signet.test".into();
    let mut service = OwnerService::open(authority, signer, config).unwrap();
    assert!(service
        .finish_authentication(
            &f.sid,
            &f.csrf,
            begin["challenge_id"].as_str().unwrap(),
            &response
        )
        .is_err());
    let OwnerService {
        authority, signer, ..
    } = service;
    assert!(OwnerService::open(authority, signer, changed).is_err());
}
#[test]
fn removing_a_passkey_invalidates_unspent_purchase_authority() {
    let mut f = Fixture::new();
    let mut auth = authenticator();
    let first = f.enroll(&mut auth);
    let registration = f.authenticate(
        &mut auth,
        OwnerIntent::AddPasskey {
            label: "Backup".into(),
        },
    );
    let mut backup = authenticator();
    let response = backup
        .do_registration(
            f.origin(),
            serde_json::from_value(registration["options"].clone()).unwrap(),
        )
        .unwrap();
    f.service
        .finish_registration(
            &f.sid,
            &f.csrf,
            registration["challenge_id"].as_str().unwrap(),
            &response,
        )
        .unwrap();
    let (proposal, purchase) = f.purchase();
    let pid = proposal["proposal_id"].as_str().unwrap().to_owned();
    f.authenticate(
        &mut auth,
        OwnerIntent::Approve {
            proposal_id: pid.clone(),
        },
    );
    let grant = f.call(Command::ApprovalStatus { proposal_id: pid })["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    f.authenticate(
        &mut backup,
        OwnerIntent::RevokePasskey {
            credential_id: first,
        },
    );
    let message = sign(
        &f.executor,
        CLIENT_DOMAIN,
        &Request {
            authority_id: f.service.authority.config.authority_id.clone(),
            client_key: public(&f.executor),
            nonce: id(),
            issued_at: now(),
            expires_at: now() + 120,
            command: Command::ConsumePurchase {
                grant_id: grant,
                purchase,
            },
        },
    );
    assert!(f.service.agent_request(&message).is_err());
}
#[cfg(unix)]
#[test]
fn file_signer_requires_private_regular_files_and_matches_provisioned_identity() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("synthetic.seed");
    let key = SigningKey::generate(&mut OsRng);
    fs::write(&path, key.to_bytes()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(file_signer::load(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        file_signer::load(&path).unwrap().public_key_ed25519(),
        key.verifying_key().to_bytes()
    );
    let link = dir.path().join("linked.seed");
    symlink(&path, &link).unwrap();
    assert!(file_signer::load(&link).is_err());
    let hard = dir.path().join("hard.seed");
    fs::hard_link(&path, &hard).unwrap();
    assert!(file_signer::load(&path).is_err());
}
async fn http_request(
    app: &axum::Router,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: Value,
) -> (axum::http::StatusCode, axum::http::HeaderMap, Value) {
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let mut r = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "owner.signet.test")
        .header("content-type", "application/json");
    for (k, v) in extra {
        r = r.header(*k, *v);
    }
    let response = app
        .clone()
        .oneshot(r.body(axum::body::Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        headers,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
    )
}
#[tokio::test]
async fn http_passkey_flow_rotates_cookies_checks_csrf_and_approves_signed_proposal() {
    let f = Fixture::new();
    let origin = f.origin();
    let invitation = f.token.clone();
    let agent = f.agent.clone();
    let aid = f.service.authority.config.authority_id.clone();
    let app = http::router(f.service);
    let mut auth = authenticator();
    let (status, headers, session) =
        http_request(&app, "GET", "/api/session", &[], json!(null)).await;
    assert_eq!(status, 200);
    assert!(headers["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("frame-ancestors 'none'"));
    let raw = headers["set-cookie"].to_str().unwrap();
    assert!(raw.contains("HttpOnly") && raw.contains("SameSite=Strict") && raw.contains("Secure"));
    let cookie = raw.split(';').next().unwrap().to_owned();
    let csrf = session["csrf"].as_str().unwrap();
    let h = [
        ("origin", origin.as_str().trim_end_matches('/')),
        ("cookie", cookie.as_str()),
        ("x-signet-csrf", csrf),
    ];
    assert_eq!(
        http_request(&app, "POST", "/api/dashboard", &h, json!({}))
            .await
            .0,
        400
    );
    let (status, _, start) = http_request(
        &app,
        "POST",
        "/api/enroll/begin",
        &h,
        json!({"token":invitation,"label":"Synthetic browser key"}),
    )
    .await;
    assert_eq!(status, 200);
    let credential = auth
        .do_registration(
            origin.clone(),
            serde_json::from_value(start["options"].clone()).unwrap(),
        )
        .unwrap();
    let body = json!({"challenge_id":start["challenge_id"],"credential":credential});
    let (status, headers, _) =
        http_request(&app, "POST", "/api/enroll/finish", &h, body.clone()).await;
    assert_eq!(status, 200);
    let rotated = headers["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert_ne!(cookie, rotated);
    assert_eq!(
        http_request(&app, "POST", "/api/enroll/finish", &h, body)
            .await
            .0,
        400
    );
    let (_, _, s) = http_request(
        &app,
        "GET",
        "/api/session",
        &[("cookie", &rotated)],
        json!(null),
    )
    .await;
    assert_eq!(s["authenticated"], true);
    let csrf = s["csrf"].as_str().unwrap();
    let h = [
        ("origin", origin.as_str().trim_end_matches('/')),
        ("cookie", rotated.as_str()),
        ("x-signet-csrf", csrf),
    ];
    assert_eq!(
        http_request(&app, "POST", "/api/dashboard", &h, json!({}))
            .await
            .0,
        200
    );
    assert_eq!(
        http_request(
            &app,
            "POST",
            "/api/dashboard",
            &[
                ("origin", "https://owner.signet.test"),
                ("cookie", &rotated)
            ],
            json!({})
        )
        .await
        .0,
        400
    );
    let signed = sign(
        &agent,
        CLIENT_DOMAIN,
        &Request {
            authority_id: aid,
            client_key: public(&agent),
            nonce: id(),
            issued_at: now(),
            expires_at: now() + 120,
            command: Command::ProposeApproval {
                action: ApprovedAction::RuleMutation {
                    mutation: Mutation::Add {
                        rule_id: "electronics".into(),
                        rule: Rule::RequireConfirmation {
                            category: Some("electronics".into()),
                        },
                    },
                },
                documents: BTreeMap::new(),
            },
        },
    );
    let (status, _, proposal) = http_request(
        &app,
        "POST",
        "/api/agent",
        &[],
        serde_json::to_value(signed).unwrap(),
    )
    .await;
    assert_eq!(status, 200);
    let (_, _, start) = http_request(
        &app,
        "POST",
        "/api/auth/begin",
        &h,
        json!({"purpose":"approve","proposal_id":proposal["proposal_id"]}),
    )
    .await;
    let credential = auth
        .do_authentication(
            origin.clone(),
            serde_json::from_value(start["options"].clone()).unwrap(),
        )
        .unwrap();
    let (status, _, finished) = http_request(
        &app,
        "POST",
        "/api/auth/finish",
        &h,
        json!({"challenge_id":start["challenge_id"],"credential":credential}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(finished["state"], "committed");
    let (_, _, dashboard) = http_request(&app, "POST", "/api/dashboard", &h, json!({})).await;
    assert_eq!(dashboard["rules"].as_array().unwrap().len(), 1);
}
#[tokio::test]
async fn http_transport_rejects_untrusted_origins_and_mcp_never_infers_approval() {
    let f = Fixture::new();
    let app = http::router(f.service);
    for path in ["/api/session", "/mcp", "/"] {
        assert_eq!(
            http_request(
                &app,
                "GET",
                path,
                &[("origin", "https://evil.example")],
                json!(null)
            )
            .await
            .0,
            403
        );
    }
    assert_eq!(
        http_request(
            &app,
            "GET",
            "/api/session",
            &[("sec-fetch-site", "cross-site")],
            json!(null)
        )
        .await
        .0,
        403
    );
    assert_eq!(
        http_request(&app, "GET", "/mcp", &[], json!(null)).await.0,
        405
    );
    let h = [("accept", "application/json, text/event-stream")];
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}});
    assert_eq!(
        http_request(&app, "POST", "/mcp", &[], init.clone())
            .await
            .0,
        400
    );
    assert_eq!(
        http_request(
            &app,
            "POST",
            "/mcp",
            &[("accept", h[0].1), ("mcp-protocol-version", "invalid")],
            init.clone()
        )
        .await
        .0,
        400
    );
    let (status, _, r) = http_request(&app, "POST", "/mcp", &h, init).await;
    assert_eq!(status, 200);
    assert_eq!(r["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(
        http_request(
            &app,
            "POST",
            "/mcp",
            &h,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .await
        .0,
        202
    );
    let (_,_,r)=http_request(&app,"POST","/mcp",&h,json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"authority_request","arguments":{"approved":true}}})).await;
    assert_eq!(r["result"]["isError"], true);
    assert_eq!(
        http_request(
            &http::preview_router(),
            "POST",
            "/api/enroll/begin",
            &[],
            json!({})
        )
        .await
        .0,
        404
    );
}

#[test]
fn backup_registration_cannot_adopt_epoch_after_authorizing_key_revocation() {
    let mut f = Fixture::new();
    let mut first = authenticator();
    let credential = f.enroll(&mut first);
    // Model the precise cross-process interleaving after the assertion commits,
    // before registration() is called: another connection revokes the authorizer.
    let authorized_epoch = epoch(&f.service.authority.connection).unwrap();
    let mut other = Connection::open(f._dir.path().join("authority.sqlite")).unwrap();
    let tx = other
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    tx.execute(
        "UPDATE owner_credentials SET revoked=1 WHERE id=?1",
        [&credential],
    )
    .unwrap();
    bump_epoch(&tx).unwrap();
    tx.commit().unwrap();
    let challenge = f
        .service
        .registration(
            &f.sid,
            "Attacker backup".into(),
            Some((authorized_epoch, credential)),
        )
        .unwrap();
    let mut backup = authenticator();
    let response = backup
        .do_registration(
            f.origin(),
            serde_json::from_value(challenge["options"].clone()).unwrap(),
        )
        .unwrap();
    assert!(f
        .service
        .finish_registration(
            &f.sid,
            &f.csrf,
            challenge["challenge_id"].as_str().unwrap(),
            &response
        )
        .is_err());
    let count: u64 = other
        .query_row("SELECT COUNT(*) FROM owner_credentials", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1, "revoked proof must not create a new credential");
}
