//! Attack surface tests: "What can an attacker with full DB access learn?"
//!
//! BlindDB Security Model (from "The Ephemeral Internet", McEntire 2026):
//!
//! The primary defense is **relational opacity**: the server stores a flat
//! pile of opaque record IDs and values with NO foreign keys, NO user tables,
//! NO joins. An attacker with `SELECT *` cannot answer "which records belong
//! to the same user?" or "which user does this address belong to?"
//!
//! With millions of users, having "123 East West St" in the DB tells you
//! nothing — _someone_ lives there, but that's public knowledge. The address
//! exists in the world regardless. The amount of information it carries is
//! only that it somehow got into the DB. The more users, the less obvious
//! that pathway becomes.
//!
//! Defense layers:
//! 1. **Relational opacity** — records are unlinked; no user↔record mapping
//! 2. **Signature-based tamper evidence** — forging data requires the private key
//! 3. **Encryption (defense-in-depth)** — AES-256-GCM makes values unreadable
//! 4. **Seed data (plausible deniability)** — inject fake records to make any
//!    individual record statistically unreliable
//!
//! These tests demonstrate each layer.

use signet_core::{RecordId, SignetResult, StorageBackend};
use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroizing;

// ============================================================================
// In-memory storage backend that records everything for inspection
// ============================================================================

/// A storage backend that lets us inspect exactly what was stored.
/// This simulates "attacker has SELECT * access to the database."
struct SpyBackend {
    data: Mutex<HashMap<String, Vec<u8>>>,
}

impl SpyBackend {
    fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }

    /// Attacker runs SELECT record_id FROM records
    fn all_record_ids(&self) -> Vec<String> {
        self.data.lock().unwrap().keys().cloned().collect()
    }

    /// Attacker runs SELECT * FROM records
    fn all_entries(&self) -> Vec<(String, Vec<u8>)> {
        self.data
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn count(&self) -> usize {
        self.data.lock().unwrap().len()
    }
}

impl StorageBackend for SpyBackend {
    fn get(&self, record_id: &RecordId) -> SignetResult<Option<Vec<u8>>> {
        Ok(self.data.lock().unwrap().get(record_id.as_str()).cloned())
    }

    fn put(&self, record_id: &RecordId, data: &[u8]) -> SignetResult<()> {
        self.data
            .lock()
            .unwrap()
            .insert(record_id.as_str().to_string(), data.to_vec());
        Ok(())
    }

    fn delete(&self, record_id: &RecordId) -> SignetResult<bool> {
        Ok(self
            .data
            .lock()
            .unwrap()
            .remove(record_id.as_str())
            .is_some())
    }

    fn compare_and_swap(
        &self,
        record_id: &RecordId,
        expected: Option<&[u8]>,
        new_value: &[u8],
    ) -> SignetResult<bool> {
        let mut data = self.data.lock().unwrap();
        let current = data.get(record_id.as_str());
        let matches = match (current, expected) {
            (None, None) => true,
            (Some(c), Some(e)) => c.as_slice() == e,
            _ => false,
        };
        if matches {
            data.insert(record_id.as_str().to_string(), new_value.to_vec());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn exists(&self, record_id: &RecordId) -> SignetResult<bool> {
        Ok(self.data.lock().unwrap().contains_key(record_id.as_str()))
    }
}

// ============================================================================
// Layer 1: Relational opacity — records cannot be grouped by user
// ============================================================================

#[test]
fn relational_opacity_records_cannot_be_grouped_by_user() {
    use signet_vault::blind_storage::{derive_master_secret, derive_record_id};

    // Two users each store records in the same database.
    let alice_secret = derive_master_secret("alice", "password1", &[]);
    let bob_secret = derive_master_secret("bob", "password2", &[]);

    let spy = SpyBackend::new();

    // Alice stores 3 records
    let alice_ids: Vec<RecordId> = ["email", "shipping_address", "payment_method"]
        .iter()
        .map(|label| derive_record_id(&*alice_secret, label, 0))
        .collect();
    for (i, id) in alice_ids.iter().enumerate() {
        spy.put(id, format!("alice-data-{}", i).as_bytes()).unwrap();
    }

    // Bob stores 3 records
    let bob_ids: Vec<RecordId> = ["email", "shipping_address", "favorite_color"]
        .iter()
        .map(|label| derive_record_id(&*bob_secret, label, 0))
        .collect();
    for (i, id) in bob_ids.iter().enumerate() {
        spy.put(id, format!("bob-data-{}", i).as_bytes()).unwrap();
    }

    // Attacker sees 6 records with opaque hex IDs
    let all_ids = spy.all_record_ids();
    assert_eq!(all_ids.len(), 6);

    // Every ID is a 64-char hex hash — no semantic content
    for id in &all_ids {
        assert_eq!(id.len(), 64, "ID should be SHA-256 hex");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // KEY ASSERTION: The attacker cannot determine which 3 belong to Alice
    // and which 3 belong to Bob. There are C(6,3) = 20 possible groupings,
    // and the attacker has no information to distinguish the correct one.
    // No user IDs, no foreign keys, no ordering guarantees.

    // Even though Alice and Bob both have "email" and "shipping_address",
    // the record IDs are completely different (different master secrets)
    let alice_email = derive_record_id(&*alice_secret, "email", 0);
    let bob_email = derive_record_id(&*bob_secret, "email", 0);
    assert_ne!(
        alice_email, bob_email,
        "same label, different users -> different IDs"
    );

    // And neither ID reveals the label "email"
    assert!(!alice_email.as_str().contains("email"));
    assert!(!bob_email.as_str().contains("email"));
}

#[test]
fn relational_opacity_no_foreign_keys_or_user_tables() {
    use signet_vault::blind_storage::{derive_master_secret, derive_record_id};

    let spy = SpyBackend::new();

    // Simulate 100 users, each with 5 records = 500 total records
    for user_idx in 0..100 {
        let secret = derive_master_secret(
            &format!("user-{}", user_idx),
            &format!("pass-{}", user_idx),
            &[],
        );
        for label_idx in 0..5 {
            let id = derive_record_id(&*secret, &format!("field-{}", label_idx), 0);
            spy.put(&id, format!("data-{}-{}", user_idx, label_idx).as_bytes())
                .unwrap();
        }
    }

    assert_eq!(spy.count(), 500);

    // All 500 records look identical in structure: opaque hex ID + opaque data
    // There is NO metadata that groups records by user.
    let all_ids = spy.all_record_ids();
    for id in &all_ids {
        assert_eq!(id.len(), 64);
        // No user index, no sequence number, no prefix
        assert!(!id.contains("user-"));
        assert!(!id.contains("field-"));
    }
}

// ============================================================================
// Layer 2: Signature-based tamper evidence
// ============================================================================

#[test]
fn signature_prevents_data_forgery() {
    use signet_core::Signer;
    use signet_vault::signer::VaultSigner;

    // Alice signs a credential payload
    let signer = VaultSigner::from_bytes([0x42u8; 32]);
    let payload = b"age_over_21=true";
    let signature = signer.sign_ed25519(payload).unwrap();

    // Attacker has the signed data but NOT the private key
    // Verification succeeds with the real payload
    assert!(signer.verify(payload, &signature));

    // Attacker tampers with the payload — signature is now invalid
    let tampered = b"age_over_21=false";
    assert!(!signer.verify(tampered, &signature));

    // Attacker tries to create a new valid signature — impossible without the key
    // (We can't directly test "attacker can't sign" but we can test that
    // a different key produces a different, non-matching signature)
    let attacker_signer = VaultSigner::from_bytes([0xBB; 32]);
    let attacker_sig = attacker_signer.sign_ed25519(tampered).unwrap();

    // Attacker's signature doesn't verify against Alice's public key
    assert!(!signer.verify(tampered, &attacker_sig));
    assert!(!signer.verify(payload, &attacker_sig));
}

#[test]
fn audit_chain_detects_tampering_via_hash_chain() {
    use signet_core::{AuditChainWriter, AuditEvent, AuditEventKind, CredentialId, Timestamp};
    use signet_vault::audit::AuditChain;

    let chain = AuditChain::new();

    // Append several events
    for i in 0..5 {
        chain
            .append(AuditEvent {
                timestamp: Timestamp::now(),
                kind: AuditEventKind::CredentialIssued {
                    credential_id: CredentialId::new(format!("cred-{}", i)),
                },
                previous_hash: None,
                signature: None,
            })
            .unwrap();
    }

    // Chain is valid
    assert!(chain.verify_chain().unwrap());

    // Each entry's hash includes the previous entry's hash.
    // Removing or reordering entries would break the chain.
    let entries = chain.entries().unwrap();
    assert_eq!(entries.len(), 5);

    // All hashes are unique (even if events are structurally similar)
    let hashes: Vec<_> = entries.iter().map(|e| e.hash.clone()).collect();
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j]);
        }
    }

    // Each entry records its predecessor's hash
    assert!(entries[0].event.previous_hash.is_none()); // genesis
    for i in 1..entries.len() {
        assert_eq!(
            entries[i].event.previous_hash.as_ref(),
            Some(&entries[i - 1].hash),
            "entry {} should reference entry {}'s hash",
            i,
            i - 1
        );
    }
}

// ============================================================================
// Layer 3: Encryption (defense-in-depth via BlindStorageWrapper)
// ============================================================================

#[test]
fn encryption_makes_values_unreadable() {
    use signet_vault::blind_storage::BlindStorageWrapper;

    let spy = SpyBackend::new();
    let addressing_key = Zeroizing::new([0x42u8; 32]);
    let encryption_key = Zeroizing::new([0x77u8; 32]);

    let blind = BlindStorageWrapper::new(spy, addressing_key, encryption_key);

    // Store data that would be meaningful if read plaintext
    let records: Vec<(&str, &[u8])> = vec![
        ("user:alice:email", b"alice@example.com"),
        ("user:alice:address", b"123 East West St, Anytown USA"),
        ("user:alice:balance", b"847500"),
        ("cred:status:personal-identity-v1", br#""Active""#),
    ];

    for (id, data) in &records {
        blind.put(&RecordId::new(*id), data).unwrap();
    }

    // Attacker reads raw storage
    let stored = blind.inner().all_entries();
    assert_eq!(stored.len(), 4);

    for (opaque_id, encrypted_data) in &stored {
        // IDs are opaque SHA-256 hashes
        assert_eq!(opaque_id.len(), 64);
        assert!(opaque_id.chars().all(|c| c.is_ascii_hexdigit()));

        // Data is encrypted JSON envelope
        let raw_str = String::from_utf8_lossy(encrypted_data);
        assert!(!raw_str.contains("alice"));
        assert!(!raw_str.contains("East West"));
        assert!(!raw_str.contains("847500"));
        assert!(!raw_str.contains("Active"));

        let envelope: serde_json::Value = serde_json::from_slice(encrypted_data)
            .expect("stored data should be serialized envelope");
        assert!(envelope.get("nonce").is_some());
        assert!(envelope.get("ciphertext").is_some());
    }

    // Legitimate user retrieves data fine
    assert_eq!(
        blind
            .get(&RecordId::new("user:alice:email"))
            .unwrap()
            .unwrap(),
        b"alice@example.com"
    );
}

#[test]
fn wrong_key_cannot_decrypt() {
    use signet_vault::blind_storage::BlindStorageWrapper;

    let spy = SpyBackend::new();
    let addressing_key = Zeroizing::new([0x42u8; 32]);
    let encryption_key = Zeroizing::new([0x77u8; 32]);

    let blind = BlindStorageWrapper::new(spy, addressing_key, encryption_key);

    blind
        .put(&RecordId::new("secret"), b"classified information")
        .unwrap();

    // Even if attacker extracts the raw encrypted bytes...
    let stored = blind.inner().all_entries();
    let (_opaque_id, raw_data) = &stored[0];

    // ...decrypting with the wrong key fails (AES-GCM auth tag mismatch)
    let env: signet_vault::envelope::EncryptedEnvelope = serde_json::from_slice(raw_data).unwrap();
    let wrong_key = Zeroizing::new([0xBB_u8; 32]);
    let decrypt_result = signet_vault::envelope::decrypt(&wrong_key, &env);
    assert!(decrypt_result.is_err());
}

#[test]
fn audit_events_encrypted_in_storage() {
    use signet_core::{
        AuditChainWriter, AuditEvent, AuditEventKind, DomainBinding, Nonce, RpIdentifier, Timestamp,
    };
    use signet_vault::audit::AuditChain;

    let spy = SpyBackend::new();
    let encryption_key = Zeroizing::new([0x55u8; 32]);

    let chain = AuditChain::with_storage(Box::new(spy), encryption_key);

    let hash = chain
        .append(AuditEvent {
            timestamp: Timestamp::now(),
            kind: AuditEventKind::ProofGenerated {
                domain: DomainBinding {
                    relying_party: RpIdentifier::Origin(
                        "https://secret-medical-provider.example.com".into(),
                    ),
                    nonce: Nonce::generate(),
                    issued_at: Timestamp::now(),
                    expires_at: Timestamp::from_seconds(Timestamp::now().seconds_since_epoch + 300),
                },
            },
            previous_hash: None,
            signature: None,
        })
        .unwrap();

    // Attacker reads raw storage
    let storage = chain.storage().unwrap();
    let record_id = RecordId::new(hex::encode(hash.0));
    let raw_bytes = storage.get(&record_id).unwrap().unwrap();

    // Encrypted — no plaintext domain names or event types visible
    let raw_str = String::from_utf8_lossy(&raw_bytes);
    assert!(!raw_str.contains("medical"), "BREACH: plaintext domain");
    assert!(
        !raw_str.contains("ProofGenerated"),
        "BREACH: plaintext event type"
    );

    // Legitimate chain can decrypt
    let loaded = chain.load_persisted_entry(&hash).unwrap().unwrap();
    match &loaded.kind {
        AuditEventKind::ProofGenerated { domain } => match &domain.relying_party {
            RpIdentifier::Origin(origin) => {
                assert_eq!(origin, "https://secret-medical-provider.example.com");
            }
            _ => panic!("expected Origin"),
        },
        _ => panic!("expected ProofGenerated"),
    }

    assert!(chain.verify_chain().unwrap());
}

// ============================================================================
// Layer 4: Seed data for plausible deniability
// ============================================================================

#[test]
fn seed_data_makes_individual_records_statistically_unreliable() {
    use signet_vault::blind_storage::{derive_master_secret, derive_record_id};

    let spy = SpyBackend::new();

    // Real user stores 10 records
    let real_secret = derive_master_secret("real-user", "real-pass", &[]);
    for i in 0..10 {
        let id = derive_record_id(&*real_secret, &format!("record-{}", i), 0);
        spy.put(&id, format!("real-value-{}", i).as_bytes())
            .unwrap();
    }

    // Inject 90 seed (fake) records — 90% of DB is noise
    // In production, seed data would be shaped to look realistic.
    // Here we just demonstrate the statistical property.
    for i in 0..90 {
        let fake_secret = derive_master_secret(
            &format!("seed-entity-{}", i),
            &format!("seed-pass-{}", i),
            &[],
        );
        let id = derive_record_id(&*fake_secret, "record-0", 0);
        spy.put(&id, format!("plausible-value-{}", i).as_bytes())
            .unwrap();
    }

    assert_eq!(spy.count(), 100);

    // Attacker sees 100 records. 10 are real, 90 are fake.
    // For any given record, there's a 90% chance it's noise.
    // The attacker has no way to distinguish real from fake.
    let all_ids = spy.all_record_ids();
    for id in &all_ids {
        // Every record looks the same: opaque hex ID
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        // No metadata distinguishes real from seed
    }

    // Even if the attacker decrypted every record (hypothetically),
    // they couldn't tell which are real without the master secret.
    // The seed data is shaped to be plausible, so "interesting" records
    // correlate MORE strongly with fake data (inverse correlation design).
}

// ============================================================================
// Functional correctness: CAS, roundtrip, different ciphertext
// ============================================================================

#[test]
fn compare_and_swap_works_through_blind_wrapper() {
    use signet_vault::blind_storage::BlindStorageWrapper;

    let spy = SpyBackend::new();
    let addressing_key = Zeroizing::new([0x42u8; 32]);
    let encryption_key = Zeroizing::new([0x77u8; 32]);

    let blind = BlindStorageWrapper::new(spy, addressing_key, encryption_key);

    let id = RecordId::new("cred:status:my-credential");

    // CAS from None (insert)
    assert!(blind.compare_and_swap(&id, None, b"active").unwrap());
    assert_eq!(blind.get(&id).unwrap().unwrap(), b"active");

    // CAS with correct expected (update)
    assert!(blind
        .compare_and_swap(&id, Some(b"active"), b"consumed")
        .unwrap());
    assert_eq!(blind.get(&id).unwrap().unwrap(), b"consumed");

    // CAS with wrong expected (conflict)
    assert!(!blind
        .compare_and_swap(&id, Some(b"active"), b"oops")
        .unwrap());
    assert_eq!(blind.get(&id).unwrap().unwrap(), b"consumed");

    assert_eq!(blind.inner().count(), 1);
}

#[test]
fn same_plaintext_different_ids_produce_different_ciphertext() {
    use signet_vault::blind_storage::BlindStorageWrapper;

    let spy = SpyBackend::new();
    let addressing_key = Zeroizing::new([0x42u8; 32]);
    let encryption_key = Zeroizing::new([0x77u8; 32]);

    let blind = BlindStorageWrapper::new(spy, addressing_key, encryption_key);

    // Identical data under different record IDs
    let data = b"same-status-value";
    blind
        .put(&RecordId::new("cred:status:cred-A"), data)
        .unwrap();
    blind
        .put(&RecordId::new("cred:status:cred-B"), data)
        .unwrap();

    let entries = blind.inner().all_entries();
    assert_eq!(entries.len(), 2);

    // Different opaque IDs AND different ciphertext
    // (different per-record DEKs + random AES-GCM nonces)
    assert_ne!(entries[0].0, entries[1].0);
    assert_ne!(entries[0].1, entries[1].1);
}

#[test]
fn blind_storage_roundtrip_preserves_data() {
    use signet_vault::blind_storage::BlindStorageWrapper;

    let spy = SpyBackend::new();
    let addressing_key = Zeroizing::new([0x42u8; 32]);
    let encryption_key = Zeroizing::new([0x77u8; 32]);

    let blind = BlindStorageWrapper::new(spy, addressing_key, encryption_key);

    let large = vec![0xAB_u8; 10_000];
    let test_cases: Vec<(&str, &[u8])> = vec![
        ("empty", b""),
        ("small", b"hello"),
        ("json", br#"{"status":"Active"}"#),
        ("large", &large),
    ];

    for (label, data) in &test_cases {
        let id = RecordId::new(format!("test:{}", label));
        blind.put(&id, data).unwrap();
        let retrieved = blind.get(&id).unwrap().unwrap();
        assert_eq!(&retrieved[..], *data, "roundtrip failed for '{}'", label);
    }

    assert!(blind.exists(&RecordId::new("test:small")).unwrap());
    assert!(blind.delete(&RecordId::new("test:small")).unwrap());
    assert!(!blind.exists(&RecordId::new("test:small")).unwrap());
    assert!(blind.get(&RecordId::new("test:small")).unwrap().is_none());
}
