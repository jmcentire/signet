//! Fresh random keys and synthetic transactions only; never loads ambient credentials.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use serde_json::{json, Value};
use signet::authority::*;
use std::path::PathBuf;

fn nonce() -> String {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
fn public(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().to_bytes())
}
fn signed(k: &SigningKey, domain: &str, value: &impl Serialize) -> SignedMessage {
    let bytes = serde_json::to_vec(value).unwrap();
    SignedMessage {
        payload: URL_SAFE_NO_PAD.encode(&bytes),
        signature: hex::encode(k.sign(&signing_bytes(domain, &bytes)).to_bytes()),
    }
}
fn request(c: &AuthorityConfig, k: &SigningKey, command: Command) -> SignedMessage {
    let now = chrono::Utc::now().timestamp();
    signed(
        k,
        CLIENT_DOMAIN,
        &Request {
            authority_id: c.authority_id.clone(),
            client_key: public(k),
            nonce: nonce(),
            issued_at: now,
            expires_at: now + 120,
            command,
        },
    )
}
struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
    config: AuthorityConfig,
    core: Authority,
    owner: SigningKey,
    agent: SigningKey,
    other: SigningKey,
    executor: SigningKey,
    revision: u64,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let owner = SigningKey::generate(&mut OsRng);
        let agent = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let executor = SigningKey::generate(&mut OsRng);
        let config = AuthorityConfig {
            authority_id: nonce(),
            owner_key: public(&owner),
            agent_keys: vec![public(&agent), public(&other)],
            executor_key: public(&executor),
        };
        let path = dir.path().join("authority.sqlite");
        let core = Authority::create(&path, config.clone()).unwrap();
        Self {
            _dir: dir,
            path,
            config,
            core,
            owner,
            agent,
            other,
            executor,
            revision: 0,
        }
    }
    fn agent(&mut self, c: Command) -> Result<Value> {
        self.core.handle(&request(&self.config, &self.agent, c))
    }
    fn executor(&mut self, c: Command) -> Result<Value> {
        self.core.handle(&request(&self.config, &self.executor, c))
    }
    fn approval(&self, action: ApprovedAction) -> SignedMessage {
        let now = chrono::Utc::now().timestamp();
        signed(
            &self.owner,
            OWNER_DOMAIN,
            &OwnerApproval {
                authority_id: self.config.authority_id.clone(),
                client_key: public(&self.agent),
                nonce: nonce(),
                issued_at: now,
                expires_at: now + 120,
                policy_revision: self.revision,
                action,
            },
        )
    }
    fn submit(&mut self, action: ApprovedAction) -> String {
        let approval = self.approval(action);
        self.agent(Command::SubmitApproval { approval }).unwrap()["grant_id"]
            .as_str()
            .unwrap()
            .into()
    }
    fn mutate(&mut self, m: Mutation) {
        let grant_id = self.submit(ApprovedAction::RuleMutation { mutation: m });
        self.revision = self.agent(Command::CommitMutation { grant_id }).unwrap()
            ["policy_revision"]
            .as_u64()
            .unwrap();
    }
    fn limit(&mut self) {
        self.mutate(Mutation::Add {
            rule_id: "amazon-limit".into(),
            rule: Rule::SpendLimit {
                merchant: "amazon.com".into(),
                currency: "USD".into(),
                requirements_digest: "a".repeat(64),
                max_total_minor: 5000,
            },
        });
    }
    fn quote(&self, p: Purchase) -> SignedMessage {
        let now = chrono::Utc::now().timestamp();
        signed(
            &self.executor,
            QUOTE_DOMAIN,
            &Quote {
                authority_id: self.config.authority_id.clone(),
                client_key: public(&self.agent),
                quote_id: nonce(),
                issued_at: now,
                expires_at: now + 120,
                purchase: p,
            },
        )
    }
    fn prepare(&mut self, p: Purchase) -> Value {
        let quote = self.quote(p);
        self.agent(Command::PreparePurchase { quote }).unwrap()
    }
    fn reserve(&mut self, p: Purchase) -> String {
        let quote = self.quote(p.clone());
        let grant_id = self.submit(ApprovedAction::Purchase { quote });
        self.executor(Command::ConsumePurchase {
            grant_id,
            purchase: p,
        })
        .unwrap()["execution_id"]
            .as_str()
            .unwrap()
            .into()
    }
    fn receipt(&mut self, p: Purchase) -> String {
        let execution_id = self.reserve(p);
        self.executor(Command::CompletePurchase {
            execution_id: execution_id.clone(),
            outcome: Completion::Succeeded {
                provider_reference: nonce(),
            },
        })
        .unwrap();
        execution_id
    }
}
fn purchase(total: u64) -> Purchase {
    Purchase {
        merchant: "amazon.com".into(),
        currency: "USD".into(),
        item_id: "usb-c-1".into(),
        description: "Synthetic USB-C cable".into(),
        category: "electronics".into(),
        quantity: 1,
        total_minor: total,
        requirements_digest: "a".repeat(64),
        terms_digest: "b".repeat(64),
        fulfillment_digest: "c".repeat(64),
    }
}

#[test]
fn no_authority_without_exact_owner_signature() {
    let mut f = Fixture::new();
    assert_eq!(
        f.prepare(purchase(1800))["state"],
        "requires_owner_approval"
    );
    let mut a = f.approval(ApprovedAction::RuleMutation {
        mutation: Mutation::Add {
            rule_id: "rule".into(),
            rule: Rule::RequireConfirmation { category: None },
        },
    });
    let mut v: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&a.payload).unwrap()).unwrap();
    v["action"]["mutation"]["rule_id"] = json!("different");
    a.payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&v).unwrap());
    assert!(f.agent(Command::SubmitApproval { approval: a }).is_err());
    let forged = signed(&f.agent, OWNER_DOMAIN, &v);
    assert!(f
        .agent(Command::SubmitApproval { approval: forged })
        .is_err());
    let wrong_domain = signed(&f.owner, CLIENT_DOMAIN, &v);
    assert!(f
        .agent(Command::SubmitApproval {
            approval: wrong_domain
        })
        .is_err());
    assert!(serde_json::from_value::<OwnerApproval>(json!({"approved":true})).is_err());
    assert!(f.agent(Command::Snapshot).unwrap()["rules"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn grants_are_client_authority_scope_and_revision_bound() {
    let mut f = Fixture::new();
    let approval = f.approval(ApprovedAction::RuleMutation {
        mutation: Mutation::Add {
            rule_id: "a".into(),
            rule: Rule::RequireConfirmation { category: None },
        },
    });
    let other = request(
        &f.config,
        &f.other,
        Command::SubmitApproval {
            approval: approval.clone(),
        },
    );
    assert!(f.core.handle(&other).is_err());
    let grant = f
        .agent(Command::SubmitApproval {
            approval: approval.clone(),
        })
        .unwrap()["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(f.agent(Command::SubmitApproval { approval }).is_err());
    let other = request(
        &f.config,
        &f.other,
        Command::CommitMutation {
            grant_id: grant.clone(),
        },
    );
    assert!(f.core.handle(&other).is_err());
    let mut changed = f.config.clone();
    changed.authority_id = "another-authority".into();
    assert!(f
        .core
        .handle(&request(&changed, &f.agent, Command::Snapshot))
        .is_err());
    f.limit();
    assert!(f
        .agent(Command::CommitMutation { grant_id: grant })
        .is_err());
}

#[test]
fn rules_are_versioned_and_tombstones_prevent_aba() {
    let mut f = Fixture::new();
    f.limit();
    let stale = f.approval(ApprovedAction::RuleMutation {
        mutation: Mutation::Remove {
            rule_id: "amazon-limit".into(),
            expected_version: 2,
        },
    });
    assert!(f
        .agent(Command::SubmitApproval { approval: stale })
        .is_err());
    f.mutate(Mutation::Edit {
        rule_id: "amazon-limit".into(),
        expected_version: 1,
        rule: Rule::RequireConfirmation { category: None },
    });
    let snapshot = f.agent(Command::Snapshot).unwrap();
    assert_eq!(snapshot["rules"][0]["version"], 2);
    f.mutate(Mutation::Remove {
        rule_id: "amazon-limit".into(),
        expected_version: 2,
    });
    let a = f.approval(ApprovedAction::RuleMutation {
        mutation: Mutation::Add {
            rule_id: "amazon-limit".into(),
            rule: Rule::RequireConfirmation { category: None },
        },
    });
    assert!(f.agent(Command::SubmitApproval { approval: a }).is_err());
}

#[test]
fn exact_exception_does_not_expand_rules_or_cross_operation_scope() {
    let mut f = Fixture::new();
    f.limit();
    let p = purchase(7500);
    let q = f.quote(p.clone());
    assert_eq!(
        f.agent(Command::PreparePurchase { quote: q.clone() })
            .unwrap()["state"],
        "requires_owner_approval"
    );
    let grant = f.submit(ApprovedAction::Purchase { quote: q });
    assert!(f
        .agent(Command::CommitMutation {
            grant_id: grant.clone()
        })
        .is_err());
    assert!(f
        .agent(Command::ConsumePurchase {
            grant_id: grant.clone(),
            purchase: p.clone()
        })
        .is_err());
    for altered in [
        Purchase {
            total_minor: 7499,
            ..p.clone()
        },
        Purchase {
            merchant: "other.example".into(),
            ..p.clone()
        },
        Purchase {
            quantity: 2,
            ..p.clone()
        },
        Purchase {
            terms_digest: "d".repeat(64),
            ..p.clone()
        },
    ] {
        assert!(f
            .executor(Command::ConsumePurchase {
                grant_id: grant.clone(),
                purchase: altered
            })
            .is_err());
    }
    assert_eq!(
        f.executor(Command::ConsumePurchase {
            grant_id: grant.clone(),
            purchase: p.clone()
        })
        .unwrap()["state"],
        "reserved"
    );
    assert!(f
        .executor(Command::ConsumePurchase {
            grant_id: grant,
            purchase: p
        })
        .is_err());
    assert_eq!(
        f.agent(Command::Snapshot).unwrap()["rules"][0]["rule"]["max_total_minor"],
        5000
    );
    assert_eq!(
        f.prepare(purchase(7500))["state"],
        "requires_owner_approval"
    );
    let grant = f.submit(ApprovedAction::RuleMutation {
        mutation: Mutation::Remove {
            rule_id: "amazon-limit".into(),
            expected_version: 1,
        },
    });
    assert!(f
        .executor(Command::ConsumePurchase {
            grant_id: grant,
            purchase: purchase(1)
        })
        .is_err());
}

#[test]
fn purchase_details_require_authenticated_executor_attestation() {
    let mut f = Fixture::new();
    f.limit();
    let q = f.quote(purchase(1800));
    let mut v: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(q.payload).unwrap()).unwrap();
    v["purchase"]["total_minor"] = json!(1);
    let forged = signed(&f.agent, QUOTE_DOMAIN, &v);
    assert!(f.agent(Command::PreparePurchase { quote: forged }).is_err());
    v["purchase"]["requirements_met"] = json!(true);
    let signed = signed(&f.executor, QUOTE_DOMAIN, &v);
    assert!(f.agent(Command::PreparePurchase { quote: signed }).is_err());
    assert_eq!(
        f.prepare(Purchase {
            requirements_digest: "d".repeat(64),
            ..purchase(1800)
        })["state"],
        "requires_owner_approval"
    );
}

#[test]
fn standing_rules_confirmations_and_stricter_limits_compose() {
    let mut f = Fixture::new();
    f.limit();
    assert_eq!(f.prepare(purchase(5000))["state"], "issued");
    assert_eq!(
        f.prepare(purchase(5001))["state"],
        "requires_owner_approval"
    );
    assert_eq!(
        f.prepare(Purchase {
            currency: "EUR".into(),
            ..purchase(1800)
        })["state"],
        "requires_owner_approval"
    );
    f.mutate(Mutation::Add {
        rule_id: "stricter".into(),
        rule: Rule::SpendLimit {
            merchant: "amazon.com".into(),
            currency: "USD".into(),
            requirements_digest: "a".repeat(64),
            max_total_minor: 1000,
        },
    });
    assert_eq!(
        f.prepare(purchase(1800))["state"],
        "requires_owner_approval"
    );
    f.mutate(Mutation::Add {
        rule_id: "electronics".into(),
        rule: Rule::RequireConfirmation {
            category: Some("electronics".into()),
        },
    });
    assert_eq!(f.prepare(purchase(999))["state"], "requires_owner_approval");
}

#[test]
fn recurring_baselines_require_completed_receipts_and_never_ratchet() {
    let mut f = Fixture::new();
    f.limit();
    let fake = f.approval(ApprovedAction::RuleMutation {
        mutation: Mutation::Add {
            rule_id: "dog".into(),
            rule: Rule::Reorder {
                receipt_id: "invented".into(),
            },
        },
    });
    assert!(f.agent(Command::SubmitApproval { approval: fake }).is_err());
    let dog = Purchase {
        item_id: "dog-food".into(),
        category: "pet".into(),
        description: "Synthetic dog food, 8kg".into(),
        ..purchase(4600)
    };
    let receipt_id = f.receipt(dog.clone());
    f.mutate(Mutation::Add {
        rule_id: "dog".into(),
        rule: Rule::Reorder {
            receipt_id: receipt_id.clone(),
        },
    });
    for price in [4200, 4600] {
        assert_eq!(
            f.prepare(Purchase {
                total_minor: price,
                ..dog.clone()
            })["state"],
            "issued"
        );
    }
    for p in [
        Purchase {
            total_minor: 4900,
            ..dog.clone()
        },
        Purchase {
            quantity: 2,
            ..dog.clone()
        },
        Purchase {
            merchant: "other.example".into(),
            ..dog.clone()
        },
    ] {
        assert_eq!(f.prepare(p)["state"], "requires_owner_approval");
    }
    f.receipt(Purchase {
        total_minor: 4900,
        ..dog.clone()
    });
    assert_eq!(
        f.prepare(Purchase {
            total_minor: 4900,
            ..dog.clone()
        })["state"],
        "requires_owner_approval"
    );
    assert_eq!(
        f.agent(Command::Snapshot).unwrap()["rules"][1]["rule"]["receipt_id"],
        receipt_id
    );
    let failed = f.reserve(dog);
    f.executor(Command::CompletePurchase {
        execution_id: failed.clone(),
        outcome: Completion::Unknown {
            reason: "timeout".into(),
        },
    })
    .unwrap();
    let a = f.approval(ApprovedAction::RuleMutation {
        mutation: Mutation::Edit {
            rule_id: "dog".into(),
            expected_version: 1,
            rule: Rule::Reorder { receipt_id: failed },
        },
    });
    assert!(f.agent(Command::SubmitApproval { approval: a }).is_err());
}

#[test]
fn request_replay_expiry_and_unknown_keys_fail_closed() {
    let mut f = Fixture::new();
    let r = request(&f.config, &f.agent, Command::Snapshot);
    f.core.handle(&r).unwrap();
    assert!(f.core.handle(&r).is_err());
    assert!(f
        .core
        .handle(&request(
            &f.config,
            &SigningKey::generate(&mut OsRng),
            Command::Snapshot
        ))
        .is_err());
    let now = chrono::Utc::now().timestamp();
    for (issued, expires) in [
        (now - 200, now - 1),
        (now + 1, now + 2),
        (now, now + MAX_TTL + 1),
    ] {
        let r = signed(
            &f.agent,
            CLIENT_DOMAIN,
            &Request {
                authority_id: f.config.authority_id.clone(),
                client_key: public(&f.agent),
                nonce: nonce(),
                issued_at: issued,
                expires_at: expires,
                command: Command::Snapshot,
            },
        );
        assert!(f.core.handle(&r).is_err());
        let a = signed(
            &f.owner,
            OWNER_DOMAIN,
            &OwnerApproval {
                authority_id: f.config.authority_id.clone(),
                client_key: public(&f.agent),
                nonce: nonce(),
                issued_at: issued,
                expires_at: expires,
                policy_revision: 0,
                action: ApprovedAction::RuleMutation {
                    mutation: Mutation::Add {
                        rule_id: "x".into(),
                        rule: Rule::RequireConfirmation { category: None },
                    },
                },
            },
        );
        assert!(f.agent(Command::SubmitApproval { approval: a }).is_err());
    }
}

#[test]
fn grant_revocation_and_policy_changes_invalidate_unspent_work() {
    let mut f = Fixture::new();
    f.limit();
    let grant = f.prepare(purchase(1800))["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    f.mutate(Mutation::RevokeGrant {
        grant_id: grant.clone(),
    });
    assert!(f
        .executor(Command::ConsumePurchase {
            grant_id: grant,
            purchase: purchase(1800)
        })
        .is_err());
    let grant = f.prepare(purchase(1800))["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    f.mutate(Mutation::Add {
        rule_id: "confirm".into(),
        rule: Rule::RequireConfirmation { category: None },
    });
    assert!(f
        .executor(Command::ConsumePurchase {
            grant_id: grant,
            purchase: purchase(1800)
        })
        .is_err());
}

#[test]
fn concurrent_consumers_reserve_exactly_once_and_restart_keeps_replay_state() {
    let mut f = Fixture::new();
    f.limit();
    let grant = f.prepare(purchase(1800))["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let workers = (0..8)
        .map(|_| {
            let path = f.path.clone();
            let config = f.config.clone();
            let barrier = barrier.clone();
            let req = request(
                &f.config,
                &f.executor,
                Command::ConsumePurchase {
                    grant_id: grant.clone(),
                    purchase: purchase(1800),
                },
            );
            std::thread::spawn(move || {
                let mut a = Authority::open(&path, config).unwrap();
                barrier.wait();
                a.handle(&req).is_ok()
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        workers
            .into_iter()
            .filter_map(|w| w.join().ok())
            .filter(|v| *v)
            .count(),
        1
    );
    let mut reopened = Authority::open(&f.path, f.config.clone()).unwrap();
    assert!(reopened
        .handle(&request(
            &f.config,
            &f.executor,
            Command::ConsumePurchase {
                grant_id: grant,
                purchase: purchase(1800)
            }
        ))
        .is_err());
    assert_eq!(
        f.agent(Command::Snapshot).unwrap()["executions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn database_failure_rolls_back_consumption_and_reservation_together() {
    let mut f = Fixture::new();
    f.limit();
    let grant = f.prepare(purchase(1800))["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let db = rusqlite::Connection::open(&f.path).unwrap();
    db.execute_batch("CREATE TRIGGER fail_insert BEFORE INSERT ON executions BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
    assert!(f
        .executor(Command::ConsumePurchase {
            grant_id: grant.clone(),
            purchase: purchase(1800)
        })
        .is_err());
    db.execute_batch("DROP TRIGGER fail_insert").unwrap();
    assert_eq!(
        f.executor(Command::ConsumePurchase {
            grant_id: grant,
            purchase: purchase(1800)
        })
        .unwrap()["state"],
        "reserved"
    );
}

#[test]
fn one_purchase_intent_cannot_be_reissued_into_duplicate_execution() {
    let mut f = Fixture::new();
    f.limit();
    let q = f.quote(purchase(1800));
    let a = f
        .agent(Command::PreparePurchase { quote: q.clone() })
        .unwrap()["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let b = f.agent(Command::PreparePurchase { quote: q }).unwrap()["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    f.executor(Command::ConsumePurchase {
        grant_id: a,
        purchase: purchase(1800),
    })
    .unwrap();
    assert!(f
        .executor(Command::ConsumePurchase {
            grant_id: b,
            purchase: purchase(1800)
        })
        .is_err());
}

#[test]
fn agents_cannot_fabricate_receipts_and_terminal_outcomes_are_immutable() {
    let mut f = Fixture::new();
    let id = f.reserve(purchase(1800));
    assert!(f
        .agent(Command::CompletePurchase {
            execution_id: id.clone(),
            outcome: Completion::Succeeded {
                provider_reference: "fake".into()
            }
        })
        .is_err());
    f.executor(Command::CompletePurchase {
        execution_id: id.clone(),
        outcome: Completion::Unknown {
            reason: "connection lost".into(),
        },
    })
    .unwrap();
    assert!(f
        .executor(Command::CompletePurchase {
            execution_id: id,
            outcome: Completion::Succeeded {
                provider_reference: "fake".into()
            }
        })
        .is_err());
}

#[test]
fn operator_bootstrap_is_explicit_pinned_and_private() {
    let f = Fixture::new();
    assert!(Authority::create(&f.path, f.config.clone()).is_err());
    let mut config = f.config.clone();
    config.owner_key = public(&SigningKey::generate(&mut OsRng));
    assert!(Authority::open(&f.path, config).is_err());
    assert!(Authority::open(&f._dir.path().join("missing"), f.config.clone()).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&f.path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Authority::open(&f.path, f.config).is_err());
    }
}

#[test]
fn malformed_amounts_and_untrusted_flags_are_rejected() {
    for amount in [json!(-1), json!(1.5), json!("1800")] {
        let mut p = serde_json::to_value(purchase(1800)).unwrap();
        p["total_minor"] = amount;
        assert!(serde_json::from_value::<Purchase>(p).is_err());
    }
    let mut f = Fixture::new();
    f.limit();
    for amount in [0, u64::MAX] {
        let q = f.quote(purchase(amount));
        assert!(f.agent(Command::PreparePurchase { quote: q }).is_err());
    }
    let r = signed(
        &f.agent,
        CLIENT_DOMAIN,
        &json!({"authority_id":f.config.authority_id,"client_key":public(&f.agent),"nonce":nonce(),"issued_at":0,"expires_at":1,"command":{"method":"snapshot"},"approved":true}),
    );
    assert!(f.core.handle(&r).is_err());
}

#[test]
fn mcp_relay_requires_initialization_and_preserves_signature_boundary() {
    let f = Fixture::new();
    let mut mcp = AuthorityMcpSession::new(Authority::open(&f.path, f.config.clone()).unwrap());
    let call = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"authority_request","arguments":request(&f.config,&f.agent,Command::Snapshot)}});
    assert_eq!(
        mcp.handle(&call.to_string()).unwrap()["error"]["code"],
        -32002
    );
    assert_eq!(mcp.handle(r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#).unwrap()["result"]["protocolVersion"],"2025-11-25");
    assert!(mcp
        .handle(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
        .is_none());
    assert_eq!(
        mcp.handle(&call.to_string()).unwrap()["result"]["isError"],
        false
    );
    let tools = mcp
        .handle(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
        .unwrap();
    assert_eq!(
        tools["result"]["tools"][0]["annotations"]["readOnlyHint"],
        false
    );
    assert_eq!(
        mcp.handle(&call.to_string()).unwrap()["result"]["isError"],
        true
    );
    let mut notification = call;
    notification.as_object_mut().unwrap().remove("id");
    assert!(mcp.handle(&notification.to_string()).is_none());
}

#[test]
fn binary_raw_and_mcp_transports_use_only_authenticated_protocol_messages() {
    use std::io::Write;
    use std::process::{Command as Process, Stdio};
    let f = Fixture::new();
    let config_path = f._dir.path().join("trust.json");
    std::fs::write(&config_path, serde_json::to_vec(&f.config).unwrap()).unwrap();
    for mcp in [false, true] {
        let mut command = Process::new(env!("CARGO_BIN_EXE_signet"));
        command
            .args([
                "--config",
                "/nonexistent-legacy-config",
                "authority-serve",
                "--database",
            ])
            .arg(&f.path)
            .arg("--trust-config")
            .arg(&config_path);
        if mcp {
            command.arg("--mcp");
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let req = request(&f.config, &f.agent, Command::Snapshot);
        let input = if mcp {
            format!(
                "{}\n{}\n{}\n",
                json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}),
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"authority_request","arguments":req}})
            )
        } else {
            format!("{}\n", serde_json::to_string(&req).unwrap())
        };
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let lines = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), if mcp { 2 } else { 1 });
        if mcp {
            assert_eq!(
                lines[1]["result"]["structuredContent"]["policy_revision"],
                0
            );
        } else {
            assert_eq!(lines[0]["ok"], true);
        }
    }
}

#[test]
fn binary_bootstrap_uses_public_trust_only_and_never_overwrites() {
    use std::process::Command as Process;
    let f = Fixture::new();
    let config_path = f._dir.path().join("trust.json");
    std::fs::write(&config_path, serde_json::to_vec(&f.config).unwrap()).unwrap();
    let database = f._dir.path().join("separate.sqlite");
    let run = || {
        Process::new(env!("CARGO_BIN_EXE_signet"))
            .arg("authority-init")
            .arg("--database")
            .arg(&database)
            .arg("--trust-config")
            .arg(&config_path)
            .output()
            .unwrap()
    };
    assert!(run().status.success());
    assert!(!run().status.success());
    assert!(Authority::open(&database, f.config).is_ok());
}

#[test]
fn expired_quote_is_rejected_even_with_fresh_owner_approval() {
    let mut f = Fixture::new();
    let now = chrono::Utc::now().timestamp();
    let quote = signed(
        &f.executor,
        QUOTE_DOMAIN,
        &Quote {
            authority_id: f.config.authority_id.clone(),
            client_key: public(&f.agent),
            quote_id: nonce(),
            issued_at: now - 100,
            expires_at: now - 1,
            purchase: purchase(1800),
        },
    );
    let approval = f.approval(ApprovedAction::Purchase {
        quote: quote.clone(),
    });
    assert!(f.agent(Command::SubmitApproval { approval }).is_err());
    assert!(f.agent(Command::PreparePurchase { quote }).is_err());
}

#[test]
fn lost_approval_response_is_recoverable_without_reissuing_or_cross_client_disclosure() {
    let mut f = Fixture::new();
    let approval = f.approval(ApprovedAction::RuleMutation {
        mutation: Mutation::Add {
            rule_id: "recoverable-limit".into(),
            rule: Rule::RequireConfirmation { category: None },
        },
    });
    let claims: OwnerApproval =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&approval.payload).unwrap()).unwrap();
    let submitted = f
        .agent(Command::SubmitApproval {
            approval: approval.clone(),
        })
        .unwrap();
    drop(f.core);
    f.core = Authority::open(&f.path, f.config.clone()).unwrap();
    let lookup = || Command::SubmittedApprovalStatus {
        owner_nonce: claims.nonce.clone(),
    };
    let recovered = f.agent(lookup()).unwrap();
    assert_eq!(recovered["grant_id"], submitted["grant_id"]);
    assert_eq!(recovered["state"], "issued");
    assert!(f
        .core
        .handle(&request(&f.config, &f.other, lookup()))
        .is_err());
    assert!(f.executor(lookup()).is_err());
    assert!(f.agent(Command::SubmitApproval { approval }).is_err());
    f.agent(Command::CommitMutation {
        grant_id: recovered["grant_id"].as_str().unwrap().into(),
    })
    .unwrap();
    assert_eq!(f.agent(lookup()).unwrap()["state"], "consumed");
    assert!(f
        .agent(Command::CommitMutation {
            grant_id: recovered["grant_id"].as_str().unwrap().into()
        })
        .is_err());
}
