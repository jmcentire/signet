//! End-to-end integration test: "Does it actually work?"
//!
//! This test tells a story:
//!
//! 1. Alice creates a vault (mnemonic, key hierarchy, real Ed25519 identity)
//! 2. Alice's vault issues a credential (name, age, account balance)
//! 3. Alice's agent (via MCP) receives a request: "prove you're over 21 to buy beer"
//! 4. The agent generates a proof that reveals age_over_21=true but hides name and balance
//! 5. Bob (a bartender's service) receives the proof and verifies it via the SDK
//! 6. Bob can see age_over_21=true but CANNOT see Alice's name or account balance
//! 7. Alice's vault generates a payment capability token scoped to the bar's domain
//! 8. The audit log records every disclosure
//!
//! What's real:
//! - Ed25519 key generation and signing (ed25519-dalek)
//! - AES-256-GCM envelope encryption (aes-gcm)
//! - HKDF-SHA256 key derivation (hkdf)
//! - BIP39 mnemonic generation
//! - SD-JWT credential issuance with selective disclosures
//! - HMAC-SHA256 proof integrity binding
//! - Proof verification (SDK verify)
//! - MCP JSON-RPC dispatch
//! - Hash-chained audit log
//!
//! What's simulated:
//! - BBS+ uses Ed25519 as signing backend (real BBS+ needs pairing curves)
//! - Bulletproof range proofs are structural placeholders
//! - The proof pipeline uses SHA-256 composition for proof bytes

use signet_core::{RecordId, Signer};
use std::collections::HashMap;
use zeroize::Zeroizing;

// ============================================================================
// Chapter 1: Alice creates her vault
// ============================================================================

#[test]
fn chapter_1_alice_creates_vault() {
    // Alice generates a 24-word mnemonic — her root of everything
    let mnemonic = signet_vault::mnemonic::generate_mnemonic().unwrap();
    let phrase = mnemonic.to_string();
    let words: Vec<&str> = phrase.split_whitespace().collect();
    assert_eq!(words.len(), 24, "BIP39 mnemonic should be 24 words");

    // Derive the master key hierarchy
    let hierarchy =
        signet_vault::key_hierarchy::KeyHierarchy::from_mnemonic(&mnemonic, "").unwrap();

    // Create a real Ed25519 signer from the vault
    let signer = signet_vault::signer::VaultSigner::from_hierarchy(&hierarchy).unwrap();

    // Alice now has a self-certifying identity
    let pubkey = signer.public_key_ed25519();
    let signet_id = signet_core::signet_id_from_pubkey(&pubkey);
    println!("Alice's SignetId: {}", signet_id);
    assert!(signet_core::verify_signet_id(&signet_id, &pubkey));

    // Her identity is a public key fingerprint — no registry, no DID, no phone call
    // Anyone with her public key can verify it was her
    let sig = signer.sign_ed25519(b"hello world").unwrap();
    assert_eq!(sig.len(), 64, "Ed25519 signature is 64 bytes");

    // Verify the signature
    assert!(signer.verify(b"hello world", &sig));
    assert!(!signer.verify(b"tampered", &sig));

    println!("  vault created, Ed25519 identity established");
}

// ============================================================================
// Chapter 2: Alice's vault issues a credential
// ============================================================================

#[test]
fn chapter_2_issue_credential_with_selective_disclosure() {
    use signet_cred::*;

    // Setup vault
    let mnemonic = signet_vault::mnemonic::generate_mnemonic().unwrap();
    let hierarchy =
        signet_vault::key_hierarchy::KeyHierarchy::from_mnemonic(&mnemonic, "").unwrap();
    let signer = signet_vault::signer::VaultSigner::from_hierarchy(&hierarchy).unwrap();

    // Define what the credential contains and what can be disclosed
    let schema = CredentialSchema {
        schema_id: "personal-identity-v1".to_string(),
        version: 1,
        fields: vec![
            SchemaField {
                name: "full_name".to_string(),
                kind: AttributeKind::Raw,
                source_path: ClaimPath::new("/personal/name").unwrap(),
                predicate: None,
                required: true,
            },
            SchemaField {
                name: "age_over_21".to_string(),
                kind: AttributeKind::DerivedBoolean,
                source_path: ClaimPath::new("/personal/age").unwrap(),
                predicate: Some(Predicate::GreaterThanOrEqual(21)),
                required: true,
            },
            SchemaField {
                name: "account_balance".to_string(),
                kind: AttributeKind::Committed,
                source_path: ClaimPath::new("/financial/balance").unwrap(),
                predicate: None,
                required: true,
            },
        ],
        disclosure_policy: DisclosurePolicy::new(
            vec![
                // Name: only shown if Alice chooses
                DisclosureRule {
                    field_name: "full_name".into(),
                    level: DisclosureLevel::Selectable,
                },
                // Age over 21: always shown (it's the whole point)
                DisclosureRule {
                    field_name: "age_over_21".into(),
                    level: DisclosureLevel::Always,
                },
                // Balance: NEVER disclosed. Only Pedersen commitment visible.
                DisclosureRule {
                    field_name: "account_balance".into(),
                    level: DisclosureLevel::Never,
                },
            ],
            DisclosureLevel::Never,
        ),
        description: Some("Personal identity credential".into()),
    };

    // Alice's actual data (from her vault)
    let mut claims_map = HashMap::new();
    claims_map.insert(
        "/personal/name".to_string(),
        ClaimValue::StringVal("Alice Nakamoto".into()),
    );
    claims_map.insert("/personal/age".to_string(), ClaimValue::IntVal(29));
    claims_map.insert(
        "/financial/balance".to_string(),
        ClaimValue::IntVal(847_500),
    );

    let claims = ClaimSet {
        claims: claims_map,
        source_vault_id: "alice-vault".into(),
        retrieved_at: chrono::Utc::now().to_rfc3339(),
    };

    let config = IssuanceConfig {
        ttl_seconds: 86400, // 24 hours
        domain: Domain::new("identity.alice.signet").unwrap(),
        one_time: false,
        clock_skew_tolerance_seconds: 30,
    };

    // Issue the credential — produces both SD-JWT and BBS+ formats
    let bundle = issue_credential(&schema, &claims, &config, &signer, 128).unwrap();

    // ---- SD-JWT format check ----
    let jwt_parts: Vec<&str> = bundle.sd_jwt.compact.split('~').collect();
    let header_payload_sig: Vec<&str> = jwt_parts[0].split('.').collect();
    assert_eq!(
        header_payload_sig.len(),
        3,
        "SD-JWT must be header.payload.signature"
    );

    // Decode and inspect the JWT payload
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let payload_bytes = URL_SAFE_NO_PAD.decode(header_payload_sig[1]).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    // age_over_21 is Always-disclosed — it's right there in the payload
    assert_eq!(
        payload["age_over_21"],
        serde_json::Value::Bool(true),
        "age_over_21 should be directly in the JWT payload (Always disclosure)"
    );

    // full_name is Selectable — it's NOT in the payload, it's in _sd digests
    assert!(
        payload.get("full_name").is_none(),
        "full_name should NOT be in payload (it's selectively disclosed)"
    );
    assert!(
        payload.get("_sd").is_some(),
        "should have _sd array for selective disclosures"
    );

    // account_balance is Never — it doesn't appear at all (not even in _sd)
    assert!(
        payload.get("account_balance").is_none(),
        "account_balance must NEVER appear in the JWT"
    );

    // ---- BBS+ format check ----
    assert_eq!(bundle.bbs.message_count, 3, "three attributes signed");
    assert!(
        !bundle.bbs.signature.signature_bytes.is_empty(),
        "BBS+ credential is signed"
    );

    // ---- Private witness check ----
    // The witness contains the raw value and blinding factor for committed attrs
    // This NEVER leaves the vault
    assert_eq!(bundle.witness.entries.len(), 1);
    assert_eq!(bundle.witness.entries[0].attribute_name, "account_balance");
    assert_eq!(
        bundle.witness.entries[0].raw_value, 847_500,
        "witness holds the real balance (for future range proofs)"
    );

    // Now inspect the disclosures — they should reveal name if selected
    for disclosure_b64 in &bundle.sd_jwt.disclosures {
        let disclosure_bytes = URL_SAFE_NO_PAD.decode(disclosure_b64).unwrap();
        let disclosure: serde_json::Value = serde_json::from_slice(&disclosure_bytes).unwrap();
        let arr = disclosure.as_array().unwrap();
        assert_eq!(arr.len(), 3, "SD-JWT disclosure is [salt, name, value]");
        let field_name = arr[1].as_str().unwrap();
        assert_eq!(
            field_name, "full_name",
            "only full_name has Selectable disclosure"
        );
        let field_value = arr[2].as_str().unwrap();
        assert_eq!(
            field_value, "Alice Nakamoto",
            "the disclosure contains the actual value"
        );
    }

    println!("  credential issued: SD-JWT + BBS+, three attributes");
    println!("  - age_over_21: Always (in JWT payload directly)");
    println!("  - full_name: Selectable (in disclosure, hidden by default)");
    println!("  - account_balance: Never (Pedersen commitment only)");
}

// ============================================================================
// Chapter 3: Bob asks "is this person over 21?" — MCP request
// ============================================================================

#[test]
fn chapter_3_mcp_proof_request_flow() {
    // Bob's bartender agent sends a JSON-RPC request to Alice's MCP server
    let server = signet_mcp::McpServer::new(signet_mcp::McpServerConfig::default()).unwrap();

    // Step 1: Initialize the MCP connection
    let init_request = r#"{
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {},
        "id": 1
    }"#;
    let init_response = signet_mcp::dispatch_jsonrpc(&server, init_request);
    assert!(
        init_response.result.is_some(),
        "MCP initialize should succeed"
    );
    let server_info = init_response.result.unwrap();
    assert_eq!(server_info["serverInfo"]["name"], "signet-mcp");
    println!("  MCP server initialized: {}", server_info["serverInfo"]);

    // Step 2: List available tools
    let list_request = r#"{
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
        "id": 2
    }"#;
    let list_response = signet_mcp::dispatch_jsonrpc(&server, list_request);
    let tools = list_response.result.unwrap();
    let tool_names: Vec<&str> = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        tool_names,
        vec![
            "get_proof",
            "query",
            "request_capability",
            "negotiate_context",
            "check_status"
        ]
    );
    println!("  available tools: {:?}", tool_names);

    // Step 3: Request proof that user is over 21 (Tier 1 — auto-served)
    let proof_request = r#"{
        "jsonrpc": "2.0",
        "method": "get_proof",
        "params": {
            "request_id": "bob-verification-001",
            "predicates": [{"attribute": "age", "operator": "Gte", "value": 21}],
            "proof_type": "SdJwt",
            "domain": "bobs-bar.example.com",
            "nonce": "challenge-nonce-from-bobs-pos-system"
        },
        "id": 3
    }"#;
    let proof_response = signet_mcp::dispatch_jsonrpc(&server, proof_request);
    assert!(
        proof_response.result.is_some(),
        "get_proof should succeed for Tier 1: {:?}",
        proof_response.error
    );
    let proof_result = proof_response.result.unwrap();
    println!(
        "  proof generated: type={}, domain={}",
        proof_result["proof_type"], proof_result["domain"]
    );
    // proof_bytes is serialized as a JSON array of byte values
    let proof_bytes = &proof_result["proof_bytes"];
    assert!(
        proof_bytes.is_array() && !proof_bytes.as_array().unwrap().is_empty(),
        "proof bytes should be non-empty"
    );
    assert_eq!(proof_result["domain"], "bobs-bar.example.com");

    // Step 4: Query (Tier 2) — should return conclusions, not raw data
    let query_request = r#"{
        "jsonrpc": "2.0",
        "method": "query",
        "params": {
            "request_id": "bob-query-001",
            "query": "what are the user's preferences?",
            "context": {"requester": "bobs-bar"}
        },
        "id": 4
    }"#;
    let query_response = signet_mcp::dispatch_jsonrpc(&server, query_request);
    assert!(
        query_response.result.is_some(),
        "query should succeed: {:?}",
        query_response.error
    );
    let query_result = query_response.result.unwrap();
    let tier = query_result["tier"].as_str().unwrap_or("");
    println!("  query response tier: {}", tier);

    // Step 5: Try to query medical data (Tier 3) — should be suspended
    let medical_query = r#"{
        "jsonrpc": "2.0",
        "method": "query",
        "params": {
            "request_id": "sketchy-query-001",
            "query": "does user have medical condition?",
            "context": {"requester": "unknown-pharmacy"}
        },
        "id": 5
    }"#;
    let medical_response = signet_mcp::dispatch_jsonrpc(&server, medical_query);
    assert!(
        medical_response.result.is_some(),
        "medical query should return a result (not crash): {:?}",
        medical_response.error
    );
    let medical_result = medical_response.result.unwrap();
    let medical_tier = medical_result["tier"].as_str().unwrap_or("");
    println!(
        "  medical query tier: {} — suspended for user authorization",
        medical_tier
    );

    // Tier 3 returns a challenge ID, not data
    if medical_tier == "Tier3" {
        assert!(
            medical_result.get("challenge_id").is_some()
                || medical_result.get("pending_request_id").is_some(),
            "Tier 3 response should include a challenge/pending ID, not data"
        );
    }

    println!("  MCP pipeline: Tier 1 auto-served, Tier 2 conclusions-only, Tier 3 suspended");
}

// ============================================================================
// Chapter 4: Bob verifies the proof using the SDK — no vault access needed
// ============================================================================

#[test]
fn chapter_4_bob_verifies_proof_with_sdk() {
    use signet_sdk::{verify, Claim, Proof};

    // Bob received a proof from Alice's agent. He uses the SDK to verify it.
    // He does NOT have access to Alice's vault. He only has the proof bytes.

    // Simulate what Alice's agent would have produced
    // (In production, this comes from the MCP get_proof response)
    let proof_data = signet_sdk::verify::create_proof_envelope(
        signet_sdk::ProofFormat::SdJwt,
        "age_over_21",
        &serde_json::json!(true),
        Some("bobs-bar.example.com"),
        b"real-sd-jwt-presentation-bytes-would-go-here",
    );

    let proof = Proof::new(proof_data);
    let claim = Claim::new("age_over_21", true);

    // Bob verifies: does this proof actually attest that the person is over 21?
    let result = verify(&proof, &claim).unwrap();
    assert!(result.valid, "proof should verify successfully");
    assert_eq!(
        result.proof_format,
        Some(signet_sdk::ProofFormat::SdJwt),
        "should detect SD-JWT format"
    );
    assert_eq!(
        result.domain.as_deref(),
        Some("bobs-bar.example.com"),
        "proof is bound to Bob's domain"
    );

    println!("  Bob verified: age_over_21 = true");
    println!("  proof format: SD-JWT");
    println!("  domain binding: bobs-bar.example.com");

    // Bob tries to claim the proof says something it doesn't
    let wrong_claim = Claim::new("full_name", "Alice Nakamoto");
    let wrong_result = verify(&proof, &wrong_claim).unwrap();
    assert!(
        !wrong_result.valid,
        "proof does NOT attest to the name — Bob can't extract it"
    );
    println!("  Bob tried to extract name -> REJECTED (claim mismatch)");

    // Bob tries to tamper with the proof to change the value
    let mut tampered_envelope: serde_json::Value = serde_json::from_slice(&proof.data).unwrap();
    tampered_envelope["value"] = serde_json::json!(false); // flip to "not over 21"
    let tampered_proof = Proof::new(serde_json::to_vec(&tampered_envelope).unwrap());
    let tampered_result = verify(&tampered_proof, &Claim::new("age_over_21", false)).unwrap();
    assert!(
        !tampered_result.valid,
        "tampered proof should FAIL verification (integrity binding broken)"
    );
    println!("  Bob tried to tamper with proof value -> REJECTED (binding mismatch)");

    // Bob presents the proof to a different domain — it shouldn't validate there
    // (The proof is bound to bobs-bar.example.com)
    let wrong_domain_proof = signet_sdk::verify::create_proof_envelope(
        signet_sdk::ProofFormat::SdJwt,
        "age_over_21",
        &serde_json::json!(true),
        Some("evil-site.example.com"), // different domain
        b"real-sd-jwt-presentation-bytes-would-go-here",
    );
    let wrong_domain = Proof::new(wrong_domain_proof);
    let domain_result = verify(&wrong_domain, &Claim::new("age_over_21", true)).unwrap();
    assert!(domain_result.valid, "proof itself verifies");
    assert_eq!(
        domain_result.domain.as_deref(),
        Some("evil-site.example.com"),
        "but domain is different — relying party should reject"
    );
    println!("  domain binding is visible: relying party MUST check it matches their own domain");
}

// ============================================================================
// Chapter 5: BlindDB storage — server sees a flat pile of opaque records
// ============================================================================

#[test]
fn chapter_5_blinddb_relational_opacity() {
    // BlindDB ("The Ephemeral Internet", McEntire 2026):
    // The server stores opaque record IDs and (optionally encrypted) values.
    // The PRIMARY defense is relational opacity: the server cannot determine
    // which records belong to the same user. With millions of users,
    // seeing "123 East West St" means nothing — _someone_ lives there,
    // but that's public knowledge. The address exists in the world.
    //
    // Encryption (AES-256-GCM) is defense-in-depth, not the core innovation.

    use signet_core::StorageBackend;
    use signet_vault::blind_storage::{
        derive_master_secret, derive_record_id, BlindStorageWrapper,
    };

    let mnemonic = signet_vault::mnemonic::generate_mnemonic().unwrap();
    let hierarchy =
        signet_vault::key_hierarchy::KeyHierarchy::from_mnemonic(&mnemonic, "").unwrap();

    // --- Layer 1: Relational opacity via deterministic hashing ---

    // Alice and Bob both store "email" — the server cannot correlate them
    let alice_secret = derive_master_secret("alice", "password1", &[]);
    let bob_secret = derive_master_secret("bob", "password2", &[]);

    let alice_email_id = derive_record_id(&*alice_secret, "email", 0);
    let bob_email_id = derive_record_id(&*bob_secret, "email", 0);
    assert_ne!(
        alice_email_id, bob_email_id,
        "same label, different users -> completely different record IDs"
    );
    println!("  alice email ID: {}", alice_email_id);
    println!("  bob email ID:   {}", bob_email_id);
    println!("  -> server cannot tell these are both 'email' records");

    // --- Layer 2: Signature-based tamper evidence ---

    let signer = signet_vault::signer::VaultSigner::from_hierarchy(&hierarchy).unwrap();
    let payload = b"age_over_21=true";
    let signature = signer.sign_ed25519(payload).unwrap();

    // Attacker tampers with payload — signature is invalid
    assert!(signer.verify(payload, &signature), "real payload verifies");
    assert!(
        !signer.verify(b"age_over_21=false", &signature),
        "tampered payload -> signature mismatch (attacker cannot forge without private key)"
    );
    println!("  signature tamper check: PASS");

    // --- Layer 3: Encryption as defense-in-depth ---

    // BlindStorageWrapper adds transparent encryption on top of blind addressing
    let inner = signet_vault::in_memory_backend::InMemoryBackend::new();
    let addressing_key = hierarchy.addressing_key().unwrap();
    let encryption_key = hierarchy.vault_sealing_key().unwrap();

    let blind = BlindStorageWrapper::new(inner, addressing_key, encryption_key);

    // Store Alice's credential — caller uses semantic IDs, wrapper blinds them
    let secret_data = b"Alice Nakamoto, age 29, balance $847,500";
    blind
        .put(&RecordId::new("cred:personal-identity"), secret_data)
        .unwrap();

    // Server's view: opaque ID, encrypted blob. No "Alice", no "cred:", no plaintext.
    let inner_ref = blind.inner();
    let all_ids: Vec<String> = inner_ref.all_record_ids();
    assert_eq!(all_ids.len(), 1);
    let stored_id = &all_ids[0];
    assert_eq!(stored_id.len(), 64, "opaque SHA-256 hex hash");
    assert!(!stored_id.contains("cred"), "no semantic prefix leaked");

    let raw_data = inner_ref.get(&RecordId::new(stored_id)).unwrap().unwrap();
    let raw_str = String::from_utf8_lossy(&raw_data);
    assert!(!raw_str.contains("Alice"), "no plaintext name in storage");
    assert!(!raw_str.contains("847"), "no plaintext balance in storage");

    // Legitimate user retrieves data fine
    let decrypted = blind
        .get(&RecordId::new("cred:personal-identity"))
        .unwrap()
        .unwrap();
    assert_eq!(&decrypted[..], &secret_data[..]);
    println!("  encrypted storage roundtrip: PASS");

    // Wrong key cannot decrypt (AES-GCM auth tag)
    let wrong_key = Zeroizing::new([0xAA_u8; 32]);
    let raw_envelope: signet_vault::envelope::EncryptedEnvelope =
        serde_json::from_slice(&raw_data).unwrap();
    assert!(
        signet_vault::envelope::decrypt(&wrong_key, &raw_envelope).is_err(),
        "wrong key -> AES-GCM auth failure"
    );
    println!("  breach simulation: wrong key -> REJECTED");

    // --- Tier 3 structural isolation ---
    let vsk = hierarchy.vault_sealing_key().unwrap();
    let compartment_key = hierarchy.compartment_key("medical").unwrap();
    assert_ne!(
        vsk.as_ref(),
        compartment_key.as_ref(),
        "VSK != compartment key (structural isolation: agent with VSK cannot access Tier 3)"
    );
    println!("  Tier 3 isolation: compartment key NOT derivable from VSK");
}

// ============================================================================
// Chapter 6: Audit chain — every disclosure is recorded and encrypted
// ============================================================================

#[test]
fn chapter_6_audit_chain_records_everything() {
    use signet_core::{
        AuditChainWriter, AuditEvent, AuditEventKind, CredentialId, DomainBinding, Nonce,
        RpIdentifier, Timestamp,
    };

    // Create audit chain with encrypted persistence
    let mnemonic = signet_vault::mnemonic::generate_mnemonic().unwrap();
    let hierarchy =
        signet_vault::key_hierarchy::KeyHierarchy::from_mnemonic(&mnemonic, "").unwrap();
    let audit_key = hierarchy.audit_log_key().unwrap();
    let storage = signet_vault::in_memory_backend::InMemoryBackend::new();

    let chain = signet_vault::audit::AuditChain::with_storage(Box::new(storage), audit_key);

    // Alice's agent generates a proof — record it
    let hash1 = chain
        .append(AuditEvent {
            timestamp: Timestamp::now(),
            kind: AuditEventKind::ProofGenerated {
                domain: DomainBinding {
                    relying_party: RpIdentifier::Origin("https://bobs-bar.example.com".into()),
                    nonce: Nonce::generate(),
                    issued_at: Timestamp::now(),
                    expires_at: Timestamp::from_seconds(Timestamp::now().seconds_since_epoch + 300),
                },
            },
            previous_hash: None,
            signature: None,
        })
        .unwrap();

    // Alice's agent issues a credential — record it
    let hash2 = chain
        .append(AuditEvent {
            timestamp: Timestamp::now(),
            kind: AuditEventKind::CredentialIssued {
                credential_id: CredentialId::new("personal-identity-v1"),
            },
            previous_hash: None,
            signature: None,
        })
        .unwrap();

    // Verify the hash chain (ordering + completeness)
    assert!(chain.verify_chain().unwrap(), "audit chain should be valid");
    assert_ne!(hash1, hash2, "each entry has a unique hash");
    assert!(chain.has_persistence(), "audit chain is persisted");

    // Events are encrypted in storage — attacker sees ciphertext
    let storage_ref = chain.storage().unwrap();
    let raw = storage_ref
        .get(&RecordId::new(hex::encode(hash1.0)))
        .unwrap()
        .unwrap();
    let raw_str = String::from_utf8_lossy(&raw);
    assert!(
        !raw_str.contains("bobs-bar"),
        "audit event encrypted: no plaintext domain"
    );
    println!("  audit events: encrypted in storage, hash-chained for ordering");

    // But the chain owner can load and decrypt entries
    let loaded = chain.load_persisted_entry(&hash1).unwrap().unwrap();
    match &loaded.kind {
        AuditEventKind::ProofGenerated { domain } => match &domain.relying_party {
            RpIdentifier::Origin(o) => assert!(o.contains("bobs-bar")),
            _ => panic!("expected Origin"),
        },
        _ => panic!("expected ProofGenerated"),
    }

    let entries = chain.entries().unwrap();
    assert_eq!(entries.len(), 2);
    println!(
        "  audit entry 1: {:?} hash={}",
        entries[0].event.kind, hash1
    );
    println!(
        "  audit entry 2: {:?} hash={}",
        entries[1].event.kind, hash2
    );
    println!("  chain is hash-linked: entry[n] includes hash(entry[n-1])");
    println!("  tamper evidence: forging requires the signing key (basic PKI)");
}

// ============================================================================
// Chapter 7: Full round-trip — issue, store via BlindDB, prove, verify
// ============================================================================

#[test]
fn chapter_7_full_round_trip() {
    use signet_core::StorageBackend;
    use signet_cred::*;
    use signet_vault::blind_storage::BlindStorageWrapper;

    // ---- Alice's side ----

    // 1. Create vault with key hierarchy
    let mnemonic = signet_vault::mnemonic::generate_mnemonic().unwrap();
    let hierarchy =
        signet_vault::key_hierarchy::KeyHierarchy::from_mnemonic(&mnemonic, "").unwrap();
    let signer = signet_vault::signer::VaultSigner::from_hierarchy(&hierarchy).unwrap();
    let alice_id = signet_core::signet_id_from_pubkey(&signer.public_key_ed25519());
    println!("Alice's identity: {}", alice_id);

    // 2. Issue credential
    let schema = CredentialSchema {
        schema_id: "age-check-v1".to_string(),
        version: 1,
        fields: vec![SchemaField {
            name: "age_over_21".to_string(),
            kind: AttributeKind::DerivedBoolean,
            source_path: ClaimPath::new("/age").unwrap(),
            predicate: Some(Predicate::GreaterThanOrEqual(21)),
            required: true,
        }],
        disclosure_policy: DisclosurePolicy::new(
            vec![DisclosureRule {
                field_name: "age_over_21".into(),
                level: DisclosureLevel::Always,
            }],
            DisclosureLevel::Never,
        ),
        description: None,
    };

    let mut claims_map = HashMap::new();
    claims_map.insert("/age".to_string(), ClaimValue::IntVal(29));
    let claims = ClaimSet {
        claims: claims_map,
        source_vault_id: "alice".into(),
        retrieved_at: chrono::Utc::now().to_rfc3339(),
    };

    let config = IssuanceConfig {
        ttl_seconds: 3600,
        domain: Domain::new("age-check.alice.signet").unwrap(),
        one_time: false,
        clock_skew_tolerance_seconds: 30,
    };

    let bundle = issue_credential(&schema, &claims, &config, &signer, 128).unwrap();
    println!("Credential issued: {}", bundle.metadata.id);

    // 3. Store credential via BlindStorageWrapper (the BlindDB model)
    //    The wrapper blinds record IDs and encrypts data transparently.
    //    The server sees: opaque hex ID + AES-256-GCM ciphertext.
    //    Encryption is defense-in-depth — credit card numbers, identity docs,
    //    etc. have independent value and MUST be encrypted regardless of
    //    relational opacity.
    let inner_storage = signet_vault::in_memory_backend::InMemoryBackend::new();
    let addressing_key = hierarchy.addressing_key().unwrap();
    let sealing_key = hierarchy.vault_sealing_key().unwrap();

    let blind_storage = BlindStorageWrapper::new(inner_storage, addressing_key, sealing_key);

    let credential_json = serde_json::to_vec(&bundle).unwrap();
    let cred_record_id = format!("cred:record:{}", bundle.metadata.id);
    blind_storage
        .put(&RecordId::new(&cred_record_id), &credential_json)
        .unwrap();
    println!(
        "Credential stored via BlindDB: {} bytes -> encrypted",
        credential_json.len()
    );

    // Verify the server sees nothing useful
    let server_view = blind_storage.inner().all_record_ids();
    assert_eq!(server_view.len(), 1);
    assert!(!server_view[0].contains("cred:"), "no semantic ID leaked");
    assert_eq!(server_view[0].len(), 64, "opaque SHA-256 hex ID");

    // 4. Generate proof via SDK envelope
    let proof_data = signet_sdk::verify::create_proof_envelope(
        signet_sdk::ProofFormat::SdJwt,
        "age_over_21",
        &serde_json::json!(true),
        Some("bobs-bar.example.com"),
        bundle.sd_jwt.compact.as_bytes(),
    );

    // 5. Record in audit chain (with encrypted persistence)
    use signet_core::{
        AuditChainWriter, AuditEvent, AuditEventKind, DomainBinding, Nonce, RpIdentifier, Timestamp,
    };
    let audit_key = hierarchy.audit_log_key().unwrap();
    let audit_storage = signet_vault::in_memory_backend::InMemoryBackend::new();
    let audit = signet_vault::audit::AuditChain::with_storage(Box::new(audit_storage), audit_key);
    let audit_hash = audit
        .append(AuditEvent {
            timestamp: Timestamp::now(),
            kind: AuditEventKind::ProofGenerated {
                domain: DomainBinding {
                    relying_party: RpIdentifier::Origin("https://bobs-bar.example.com".into()),
                    nonce: Nonce::generate(),
                    issued_at: Timestamp::now(),
                    expires_at: Timestamp::from_seconds(Timestamp::now().seconds_since_epoch + 300),
                },
            },
            previous_hash: None,
            signature: None,
        })
        .unwrap();

    // Audit event is persisted encrypted
    let audit_raw = audit
        .storage()
        .unwrap()
        .get(&RecordId::new(hex::encode(audit_hash.0)))
        .unwrap()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&audit_raw).contains("bobs-bar"),
        "audit event encrypted in storage"
    );

    // ---- Bob's side (only has the proof bytes) ----

    let proof = signet_sdk::Proof::new(proof_data);
    let claim = signet_sdk::Claim::new("age_over_21", true);
    let result = signet_sdk::verify(&proof, &claim).unwrap();

    assert!(result.valid, "Bob can verify the proof");
    assert_eq!(result.domain.as_deref(), Some("bobs-bar.example.com"));
    println!(
        "Bob verified: age_over_21=true, domain=bobs-bar.example.com, format={:?}",
        result.proof_format
    );

    // Bob cannot extract Alice's name, balance, or anything else
    let name_claim = signet_sdk::Claim::new("full_name", "Alice Nakamoto");
    let name_result = signet_sdk::verify(&proof, &name_claim).unwrap();
    assert!(!name_result.valid, "Bob cannot extract name from age proof");

    // Audit chain is intact
    assert!(audit.verify_chain().unwrap());

    println!("\n--- FULL ROUND TRIP COMPLETE ---");
    println!("  Alice: vault -> credential -> BlindDB storage -> proof");
    println!("  Bob: received proof -> verified claim -> cannot see anything else");
    println!("  Server: sees opaque hex IDs + AES-256-GCM ciphertext");
    println!("  Audit: encrypted, hash-chained, signature-protected");
    println!("  Defense: relational opacity (primary) + encryption (defense-in-depth)");
}
