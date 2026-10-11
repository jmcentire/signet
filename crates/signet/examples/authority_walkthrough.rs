//! Synthetic contract walkthrough, NOT an owner-authentication UI or merchant adapter.
//! All four private keys are random, temporary, in-memory test identities.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use serde_json::{json, Value};
use signet::authority::*;

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
fn call(
    core: &mut Authority,
    config: &AuthorityConfig,
    k: &SigningKey,
    command: Command,
) -> Result<Value> {
    let now = chrono::Utc::now().timestamp();
    core.handle(&signed(
        k,
        CLIENT_DOMAIN,
        &Request {
            authority_id: config.authority_id.clone(),
            client_key: public(k),
            nonce: nonce(),
            issued_at: now,
            expires_at: now + 120,
            command,
        },
    ))
}
fn approve(
    core: &mut Authority,
    c: &AuthorityConfig,
    owner: &SigningKey,
    agent: &SigningKey,
    revision: u64,
    action: ApprovedAction,
) -> Result<String> {
    let now = chrono::Utc::now().timestamp();
    let approval = signed(
        owner,
        OWNER_DOMAIN,
        &OwnerApproval {
            authority_id: c.authority_id.clone(),
            client_key: public(agent),
            nonce: nonce(),
            issued_at: now,
            expires_at: now + 120,
            policy_revision: revision,
            action,
        },
    );
    Ok(
        call(core, c, agent, Command::SubmitApproval { approval })?["grant_id"]
            .as_str()
            .unwrap()
            .to_owned(),
    )
}
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let owner = SigningKey::generate(&mut OsRng);
    let agent = SigningKey::generate(&mut OsRng);
    let executor = SigningKey::generate(&mut OsRng);
    let config = AuthorityConfig {
        authority_id: nonce(),
        owner_key: public(&owner),
        agent_keys: vec![public(&agent)],
        executor_key: public(&executor),
    };
    let mut core = Authority::create(&dir.path().join("synthetic.sqlite"), config.clone())?;
    let grant_id = approve(
        &mut core,
        &config,
        &owner,
        &agent,
        0,
        ApprovedAction::RuleMutation {
            mutation: Mutation::Add {
                rule_id: "amazon-limit".into(),
                rule: Rule::SpendLimit {
                    merchant: "amazon.com".into(),
                    currency: "USD".into(),
                    requirements_digest: "a".repeat(64),
                    max_total_minor: 5000,
                },
            },
        },
    )?;
    let added = call(
        &mut core,
        &config,
        &agent,
        Command::CommitMutation { grant_id },
    )?;
    let p = Purchase {
        merchant: "amazon.com".into(),
        currency: "USD".into(),
        item_id: "synthetic-lamp".into(),
        description: "Synthetic desk lamp".into(),
        category: "electronics".into(),
        quantity: 1,
        total_minor: 7500,
        requirements_digest: "a".repeat(64),
        terms_digest: "b".repeat(64),
        fulfillment_digest: "c".repeat(64),
    };
    let now = chrono::Utc::now().timestamp();
    let quote = signed(
        &executor,
        QUOTE_DOMAIN,
        &Quote {
            authority_id: config.authority_id.clone(),
            client_key: public(&agent),
            quote_id: nonce(),
            issued_at: now,
            expires_at: now + 120,
            purchase: p.clone(),
        },
    );
    let decision = call(
        &mut core,
        &config,
        &agent,
        Command::PreparePurchase {
            quote: quote.clone(),
        },
    )?;
    let grant_id = approve(
        &mut core,
        &config,
        &owner,
        &agent,
        1,
        ApprovedAction::Purchase { quote },
    )?;
    let reserved = call(
        &mut core,
        &config,
        &executor,
        Command::ConsumePurchase {
            grant_id: grant_id.clone(),
            purchase: p.clone(),
        },
    )?;
    let replay_rejected = call(
        &mut core,
        &config,
        &executor,
        Command::ConsumePurchase {
            grant_id,
            purchase: p,
        },
    )
    .is_err();
    let snapshot = call(&mut core, &config, &agent, Command::Snapshot)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "mode":"synthetic_contract_walkthrough","real_owner_authenticated":false,"network_calls":0,"purchases_executed":0,
            "rule_addition":added,"standing_rule_decision":decision,"exact_exception_reservation":reserved,
            "replay_rejected":replay_rejected,"standing_limit_unchanged":snapshot["rules"][0]["rule"]["max_total_minor"]==5000,
            "notice":"Synthetic in-memory signers exercise the core contract only. They are not a deployable owner approval surface. The temporary database is removed on exit."
        }))?
    );
    Ok(())
}
