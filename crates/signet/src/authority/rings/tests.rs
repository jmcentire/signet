use super::*;
use ed25519_dalek::{Signer as _, SigningKey};
use rand::rngs::OsRng;
struct Fixture {
    book: RingAuthority,
    owner: SigningKey,
    planner: SigningKey,
    replenish: SigningKey,
    executor: SigningKey,
    time: i64,
    travel: String,
    dog: String,
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
impl Fixture {
    fn new() -> Self {
        let owner = SigningKey::generate(&mut OsRng);
        let planner = SigningKey::generate(&mut OsRng);
        let replenish = SigningKey::generate(&mut OsRng);
        let executor = SigningKey::generate(&mut OsRng);
        let config = AuthorityConfig {
            authority_id: id(),
            owner_key: public(&owner),
            agent_keys: vec![public(&planner), public(&replenish)],
            executor_key: public(&executor),
        };
        let book = RingAuthority::new(
            config,
            Restrictions {
                blocked_categories: BTreeSet::from(["prohibited".into()]),
                per_purchase_ceilings: BTreeMap::new(),
            },
        )
        .unwrap();
        let mut f = Self {
            book,
            owner,
            planner,
            replenish,
            executor,
            time: 1000,
            travel: String::new(),
            dog: String::new(),
        };
        for (tag, name, merchant, category, requirements, items, maximum) in [
            (
                "vacation",
                "Vacation",
                "hotel.test",
                "travel",
                "a",
                BTreeSet::new(),
                1_000_000,
            ),
            (
                "replenish",
                "Replenish",
                "pet.test",
                "dog_food",
                "b",
                BTreeSet::from(["usual-dog-food".into()]),
                6400,
            ),
        ] {
            f.approve(Management::PutAsset {
                id: format!("{tag}-card"),
                expected_version: None,
                asset: Asset {
                    name: format!("{name} card"),
                    kind: AssetKind::Payment,
                    source: Source {
                        provider: "Synthetic payment broker".into(),
                        account_label: "Fictional account".into(),
                        capability_ref: format!("test:{tag}"),
                        operations: BTreeSet::from(["purchase".into()]),
                        interaction_mode: InteractionMode::Delegated,
                    },
                },
            })
            .unwrap();
            f.approve(Management::PutRule {
                id: format!("{tag}-rule"),
                expected_version: None,
                rule: RuleDefinition::Spend {
                    merchant: merchant.into(),
                    category: category.into(),
                    currency: "USD".into(),
                    requirements_digest: requirements.repeat(64),
                    item_ids: items,
                    max_purchase_minor: maximum,
                },
            })
            .unwrap();
            f.approve(Management::PutRing {
                id: tag.into(),
                expected_version: None,
                ring: Ring {
                    name: name.into(),
                    bindings: vec![Binding {
                        asset: Reference {
                            id: format!("{tag}-card"),
                            version: 1,
                        },
                        rules: BTreeSet::from([Reference {
                            id: format!("{tag}-rule"),
                            version: 1,
                        }]),
                    }],
                },
            })
            .unwrap();
        }
        f.travel = "vacation".into();
        f.dog = "replenish".into();
        f
    }
    fn approve(&mut self, action: Management) -> Result<Value> {
        let a = OwnerApproval {
            authority_id: self.book.config.authority_id.clone(),
            nonce: id(),
            issued_at: self.time,
            expires_at: self.time + 100,
            expected_revision: self.book.revision(),
            action,
        };
        self.book
            .approve(&sign(&self.owner, OWNER_RING_DOMAIN, &a), self.time)
    }
    fn grant(&mut self, travel: bool, shared: Option<&str>) -> String {
        let pid = id();
        let p = Delegation {
            id: pid.clone(),
            client_key: public(if travel {
                &self.planner
            } else {
                &self.replenish
            }),
            task_id: if travel { "trip" } else { "dog-food" }.into(),
            targets: BTreeSet::from([Reference {
                id: if travel {
                    self.travel.clone()
                } else {
                    self.dog.clone()
                },
                version: 1,
            }]),
            currency: "USD".into(),
            budget_minor: if travel { 1_000_000 } else { 12800 },
            max_operations: 10,
            expires_at: self.time + 1000,
            max_activation_seconds: 120,
            max_swaps: 3,
            shared_budget_id: shared.map(str::to_owned),
        };
        self.approve(Management::Delegate { permission: p })
            .unwrap();
        pid
    }
    fn request(&self, key: &SigningKey, operation: Operation) -> SignedMessage {
        sign(
            key,
            RING_REQUEST_DOMAIN,
            &RingRequest {
                authority_id: self.book.config.authority_id.clone(),
                client_key: public(key),
                nonce: id(),
                issued_at: self.time,
                expires_at: self.time + 100,
                expected_revision: self.book.revision(),
                operation,
            },
        )
    }
    fn agent(&mut self, travel: bool, op: Operation) -> Result<Value> {
        let s = self.request(
            if travel {
                &self.planner
            } else {
                &self.replenish
            },
            op,
        );
        self.book.handle(&s, self.time)
    }
    fn executor(&mut self, op: Operation) -> Result<Value> {
        let s = self.request(&self.executor, op);
        self.book.handle(&s, self.time)
    }
    fn activate(&mut self, pid: &str, travel: bool) -> Result<Value> {
        self.agent(
            travel,
            Operation::Activate {
                permission_id: pid.into(),
                ring: Reference {
                    id: if travel {
                        self.travel.clone()
                    } else {
                        self.dog.clone()
                    },
                    version: 1,
                },
                expires_at: self.time + 100,
            },
        )
    }
    fn quote(&self, pid: &str, travel: bool, amount: u64, card: &str) -> SignedMessage {
        sign(
            &self.executor,
            CAPABILITY_QUOTE_DOMAIN,
            &CapabilityQuote {
                authority_id: self.book.config.authority_id.clone(),
                quote_id: id(),
                permission_id: pid.into(),
                client_key: public(if travel {
                    &self.planner
                } else {
                    &self.replenish
                }),
                task_id: if travel { "trip" } else { "dog-food" }.into(),
                asset: Reference {
                    id: match card {
                        "travel-card" => "vacation-card",
                        "household-card" => "replenish-card",
                        _ => card,
                    }
                    .into(),
                    version: 1,
                },
                provider_authorization: None,
                capability: Capability::Purchase {
                    purchase: Purchase {
                        merchant: if travel { "hotel.test" } else { "pet.test" }.into(),
                        currency: "USD".into(),
                        item_id: if travel {
                            "hotel-room"
                        } else {
                            "usual-dog-food"
                        }
                        .into(),
                        description: "Synthetic purchase".into(),
                        category: if travel { "travel" } else { "dog_food" }.into(),
                        quantity: 1,
                        total_minor: amount,
                        requirements_digest: if travel { "a" } else { "b" }.repeat(64),
                        terms_digest: "c".repeat(64),
                        fulfillment_digest: "d".repeat(64),
                    },
                },
                issued_at: self.time,
                expires_at: self.time + 100,
            },
        )
    }
}
#[test]
fn simultaneous_rings_isolate_agents_cards_items_and_aggregate_budgets() {
    let mut f = Fixture::new();
    let trip = f.grant(true, None);
    let dog = f.grant(false, None);
    assert!(f
        .executor(Operation::Reserve {
            quote: f.quote(&trip, true, 600_000, "travel-card")
        })
        .is_err()); // safe default
    f.activate(&trip, true).unwrap();
    f.activate(&dog, false).unwrap();
    assert!(f
        .agent(
            false,
            Operation::Activate {
                permission_id: trip.clone(),
                ring: Reference {
                    id: f.travel.clone(),
                    version: 1
                },
                expires_at: f.time + 100
            }
        )
        .is_err());
    assert!(f
        .agent(
            false,
            Operation::Activate {
                permission_id: dog.clone(),
                ring: Reference {
                    id: f.travel.clone(),
                    version: 1
                },
                expires_at: f.time + 100
            }
        )
        .is_err());
    assert!(f
        .executor(Operation::Reserve {
            quote: f.quote(&trip, true, 100, "household-card")
        })
        .is_err());
    f.executor(Operation::Reserve {
        quote: f.quote(&trip, true, 600_000, "travel-card"),
    })
    .unwrap();
    assert!(f
        .executor(Operation::Reserve {
            quote: f.quote(&trip, true, 500_000, "travel-card")
        })
        .is_err());
    f.executor(Operation::Reserve {
        quote: f.quote(&dog, false, 6400, "household-card"),
    })
    .unwrap();
    assert_eq!(f.book.assignments(f.time).as_array().unwrap().len(), 2);
    assert_eq!(f.book.permissions[&trip].used_minor, 600_000);
    assert_eq!(f.book.permissions[&dog].used_minor, 6400);
}
#[test]
fn completion_or_ttl_ends_new_spending_but_allows_idempotent_outcome_reporting() {
    for completed in [false, true] {
        let mut f = Fixture::new();
        let trip = f.grant(true, None);
        f.activate(&trip, true).unwrap();
        let quote = f.quote(&trip, true, 100_000, "travel-card");
        let reserved = f
            .executor(Operation::Reserve {
                quote: quote.clone(),
            })
            .unwrap();
        assert!(f.executor(Operation::Reserve { quote }).is_err());
        if completed {
            f.agent(
                true,
                Operation::CompleteTask {
                    task_id: "trip".into(),
                },
            )
            .unwrap();
        } else {
            f.time += 100;
        }
        assert!(f
            .executor(Operation::Reserve {
                quote: f.quote(&trip, true, 100, "travel-card")
            })
            .is_err());
        assert!(f.activate(&trip, true).is_err());
        f.agent(
            true,
            Operation::CompleteTask {
                task_id: "trip".into(),
            },
        )
        .unwrap(); // late/idempotent termination
        let op = Operation::Report {
            quote_id: reserved["execution_id"].as_str().unwrap().into(),
            outcome: Outcome::Succeeded {
                provider_reference: "synthetic-receipt".into(),
            },
        };
        f.executor(op.clone()).unwrap();
        assert_eq!(f.executor(op).unwrap()["state"], "already_recorded");
        assert_eq!(f.book.permissions[&trip].used_minor, 100_000);
    }
}
#[test]
fn bounded_swaps_cannot_extend_deadline_refreeze_requires_new_owner_authority() {
    let mut f = Fixture::new();
    let trip = f.grant(true, None);
    f.activate(&trip, true).unwrap();
    f.time += 1;
    assert!(f.activate(&trip, true).is_err()); // requested now+100 exceeds original deadline
    assert!(f
        .agent(
            false,
            Operation::CompleteTask {
                task_id: "trip".into()
            }
        )
        .is_err());
    f.agent(
        true,
        Operation::Freeze {
            permission_id: trip.clone(),
        },
    )
    .unwrap();
    assert!(f.activate(&trip, true).is_err());
    assert_eq!(f.book.assignments(f.time)[0]["state"], "zero");
}
#[test]
fn shared_reservations_and_failed_vs_unknown_outcomes_cannot_double_spend() {
    let mut f = Fixture::new();
    f.approve(Management::CreateSharedBudget {
        id: "shared".into(),
        currency: "USD".into(),
        total_minor: 6500,
    })
    .unwrap();
    let trip = f.grant(true, Some("shared"));
    let dog = f.grant(false, Some("shared"));
    f.activate(&trip, true).unwrap();
    f.activate(&dog, false).unwrap();
    let reserved = f
        .executor(Operation::Reserve {
            quote: f.quote(&dog, false, 6400, "household-card"),
        })
        .unwrap();
    assert!(f
        .executor(Operation::Reserve {
            quote: f.quote(&trip, true, 200, "travel-card")
        })
        .is_err());
    f.executor(Operation::Report {
        quote_id: reserved["execution_id"].as_str().unwrap().into(),
        outcome: Outcome::FailedBeforeExecution {
            reason: "verified no action".into(),
        },
    })
    .unwrap();
    let reserved = f
        .executor(Operation::Reserve {
            quote: f.quote(&trip, true, 6500, "travel-card"),
        })
        .unwrap();
    f.executor(Operation::Report {
        quote_id: reserved["execution_id"].as_str().unwrap().into(),
        outcome: Outcome::Unknown {
            reason: "provider timed out".into(),
        },
    })
    .unwrap();
    assert!(f
        .executor(Operation::Reserve {
            quote: f.quote(&dog, false, 1, "household-card")
        })
        .is_err());
    assert_eq!(f.book.shared_budgets["shared"].used_minor, 6500);
}
#[test]
fn global_restrictions_revocation_definition_changes_and_replays_fail_closed() {
    let mut f = Fixture::new();
    let trip = f.grant(true, None);
    f.activate(&trip, true).unwrap();
    f.book
        .restrictions
        .per_purchase_ceilings
        .insert("USD".into(), 100);
    assert!(f
        .executor(Operation::Reserve {
            quote: f.quote(&trip, true, 101, "travel-card")
        })
        .is_err());
    f.book
        .restrictions
        .blocked_categories
        .insert("travel".into());
    assert!(f
        .executor(Operation::Reserve {
            quote: f.quote(&trip, true, 100, "travel-card")
        })
        .is_err());
    let request = f.request(
        &f.planner,
        Operation::CompleteTask {
            task_id: "trip".into(),
        },
    );
    f.book.handle(&request, f.time).unwrap();
    assert!(f.book.handle(&request, f.time).is_err());
    let mut f = Fixture::new();
    let trip = f.grant(true, None);
    f.activate(&trip, true).unwrap();
    f.approve(Management::Revoke {
        permission_id: trip.clone(),
    })
    .unwrap();
    assert!(f
        .executor(Operation::Reserve {
            quote: f.quote(&trip, true, 1, "travel-card")
        })
        .is_err());
    let mut f = Fixture::new();
    let trip = f.grant(true, None);
    f.activate(&trip, true).unwrap();
    let ring = f.book.rings["vacation"].value.clone();
    f.approve(Management::PutRing {
        id: "vacation".into(),
        expected_version: Some(1),
        ring,
    })
    .unwrap();
    assert!(f
        .executor(Operation::Reserve {
            quote: f.quote(&trip, true, 1, "travel-card")
        })
        .is_err()); // same content, new epoch
}

#[test]
fn empty_account_has_only_zero_ring_and_no_implicit_assets_or_authority() {
    let f = Fixture::new();
    let book = RingAuthority::new(f.book.config.clone(), Restrictions::default()).unwrap();
    assert!(book.assets.is_empty());
    assert!(book.rules.is_empty());
    assert_eq!(book.rings.len(), 1);
    assert!(book.rings["zero"].value.bindings.is_empty());
    assert!(book.permissions.is_empty());
    let mut f = Fixture::new();
    assert!(f
        .approve(Management::PutRing {
            id: "zero".into(),
            expected_version: Some(1),
            ring: Ring {
                name: "Changed".into(),
                bindings: vec![]
            }
        })
        .is_err());
}
#[test]
fn versioned_rules_and_assets_cannot_be_silently_rebound_or_export_credentials() {
    let mut f = Fixture::new();
    let trip = f.grant(true, None);
    f.activate(&trip, true).unwrap();
    let rule = f.book.rules["vacation-rule"].value.clone();
    f.approve(Management::PutRule {
        id: "vacation-rule".into(),
        expected_version: Some(1),
        rule,
    })
    .unwrap();
    assert!(f
        .executor(Operation::Reserve {
            quote: f.quote(&trip, true, 1, "travel-card")
        })
        .is_err());
    assert!(f
        .approve(Management::PutRule {
            id: "credential-export".into(),
            expected_version: None,
            rule: RuleDefinition::UseCredential {
                operations: BTreeSet::from(["export_secret".into()]),
                destination: "api.test".into(),
                purpose: "work".into()
            }
        })
        .is_err());
}
#[test]
fn interactive_provider_confirmation_is_independent_of_ring_permission() {
    let mut f = Fixture::new();
    let asset = &mut f.book.assets.get_mut("vacation-card").unwrap().value;
    asset.source.interaction_mode = InteractionMode::Interactive;
    let trip = f.grant(true, None);
    f.activate(&trip, true).unwrap();
    let quote = f.quote(&trip, true, 100, "travel-card");
    assert!(f
        .executor(Operation::Reserve {
            quote: quote.clone()
        })
        .is_err());
    let (mut claims, _): (CapabilityQuote, _) = decode(&quote).unwrap();
    claims.provider_authorization = Some("synthetic-provider-user-approval".into());
    let attested = sign(&f.executor, CAPABILITY_QUOTE_DOMAIN, &claims);
    f.executor(Operation::Reserve { quote: attested }).unwrap();
}
#[test]
fn native_ring_aggregate_roundtrips_json_without_relational_conversion() {
    let mut f = Fixture::new();
    let trip = f.grant(true, None);
    f.activate(&trip, true).unwrap();
    let bytes = serde_json::to_vec(&f.book).unwrap();
    let restored: RingAuthority = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(restored.revision(), f.book.revision());
    assert_eq!(restored.catalog(), f.book.catalog());
}

#[derive(Clone, Default)]
struct RecoveryStore(
    std::sync::Arc<
        std::sync::Mutex<(
            BTreeMap<String, super::super::object_store::Object>,
            bool,
            u64,
        )>,
    >,
);
impl super::super::object_store::Store for RecoveryStore {
    fn get(
        &self,
        key: &str,
    ) -> super::super::object_store::Result<Option<super::super::object_store::Object>> {
        Ok(self.0.lock().unwrap().0.get(key).cloned())
    }
    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: &super::super::object_store::Condition,
    ) -> super::super::object_store::Result<()> {
        use super::super::object_store::{Condition, Error, Object};
        let mut m = self.0.lock().unwrap();
        let old = m.0.get(key);
        if match condition {
            Condition::Absent => old.is_some(),
            Condition::Matches(tag) => old.is_none_or(|o| &o.etag != tag),
        } {
            return Err(Error::Conflict);
        }
        m.2 += 1;
        let etag = format!("opaque-{}", m.2);
        m.0.insert(
            key.into(),
            Object {
                bytes: bytes.into(),
                etag,
            },
        );
        if key.ends_with("head.json") && m.1 {
            m.1 = false;
            return Err(Error::Unavailable);
        }
        Ok(())
    }
}
#[test]
fn persisted_receipts_recover_owner_and_reservation_after_lost_reply_and_later_commits() {
    use super::super::object_store::{CommitOutcome, Versioned};
    let mut f = Fixture::new();
    let pid = f.grant(true, None);
    f.activate(&pid, true).unwrap();
    let memory = RecoveryStore::default();
    let user = "a".repeat(64);
    let service = persistence::Service::new(memory.clone(), user.clone()).unwrap();
    service.initialize(&f.book).unwrap();
    let owner = sign(
        &f.owner,
        OWNER_RING_DOMAIN,
        &OwnerApproval {
            authority_id: f.book.config.authority_id.clone(),
            nonce: id(),
            issued_at: f.time,
            expires_at: f.time + 100,
            expected_revision: f.book.revision(),
            action: Management::PutRing {
                id: "empty".into(),
                expected_version: None,
                ring: Ring {
                    name: "Empty".into(),
                    bindings: vec![],
                },
            },
        },
    );
    memory.0.lock().unwrap().1 = true;
    assert!(service.owner(&owner, f.time).is_err());
    let recovered = service.owner(&owner, f.time + 200).unwrap();
    assert_eq!(recovered.outcome, CommitOutcome::Recovered);
    f.book = Versioned::new(memory.clone(), user.clone())
        .unwrap()
        .load::<RingAuthority>()
        .unwrap()
        .state;
    let request = f.request(
        &f.executor,
        Operation::Reserve {
            quote: f.quote(&pid, true, 500, "travel-card"),
        },
    );
    memory.0.lock().unwrap().1 = true;
    assert!(service.request(&request, f.time).is_err());
    let recovered = service.request(&request, f.time).unwrap();
    assert_eq!(recovered.outcome, CommitOutcome::Recovered);
    assert_eq!(recovered.output["dispatch_before"], f.time + 100);
    let execution = recovered.output["execution_id"]
        .as_str()
        .unwrap()
        .to_owned();
    f.book = Versioned::new(memory.clone(), user.clone())
        .unwrap()
        .load::<RingAuthority>()
        .unwrap()
        .state;
    let report = f.request(
        &f.executor,
        Operation::Report {
            quote_id: execution.clone(),
            outcome: Outcome::Succeeded {
                provider_reference: "synthetic-receipt".into(),
            },
        },
    );
    service.request(&report, f.time).unwrap();
    let late = service.request(&request, f.time + 1000).unwrap();
    assert_eq!(late.outcome, CommitOutcome::Recovered);
    assert_eq!(late.output["execution_id"], execution);
    assert_eq!(
        service.owner(&owner, f.time + 1000).unwrap().outcome,
        CommitOutcome::Recovered
    );
    let mut forged = request.clone();
    forged.signature = "00".repeat(64);
    assert!(service.request(&forged, f.time).is_err());
    let stored = Versioned::new(memory, user)
        .unwrap()
        .load::<RingAuthority>()
        .unwrap()
        .state;
    assert_eq!(stored.reservations.len(), 1);
    assert_eq!(stored.permissions[&pid].used_minor, 500);
}
