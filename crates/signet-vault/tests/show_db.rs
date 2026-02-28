//! Dump what the server sees after a realistic multi-user session.
//! Run with: cargo test --package signet-vault --test show_db -- --nocapture

use signet_core::{RecordId, StorageBackend};
use signet_vault::blind_storage::{derive_master_secret, BlindCollection, BlindStorageWrapper};
use signet_vault::in_memory_backend::InMemoryBackend;
use zeroize::Zeroizing;

#[test]
fn show_what_the_server_sees() {
    let inner = InMemoryBackend::new();
    let addr_key = Zeroizing::new([0x42u8; 32]);
    let enc_key = Zeroizing::new([0x77u8; 32]);
    let blind = BlindStorageWrapper::new(inner, addr_key, enc_key);

    // === Alice stores her data ===
    let alice = derive_master_secret("alice", "s3cret_alice!", &[]);

    // Her email, shipping address, and payment card
    blind
        .put(&RecordId::new("alice:email"), b"alice@protonmail.com")
        .unwrap();
    blind
        .put(
            &RecordId::new("alice:address"),
            b"742 Evergreen Terrace, Springfield IL",
        )
        .unwrap();
    blind
        .put(
            &RecordId::new("alice:payment"),
            b"4111-1111-1111-1111 exp 03/28 cvv 123",
        )
        .unwrap();

    // Her video watch history (collection)
    let alice_vids = BlindCollection::new(&blind, &*alice, "videos_watched");
    alice_vids.add(b"Inception (2010)").unwrap();
    alice_vids.add(b"The Matrix (1999)").unwrap();
    alice_vids.add(b"Interstellar (2014)").unwrap();

    // Her credential status
    blind
        .put(
            &RecordId::new("cred:status:alice-identity-v1"),
            br#""Active""#,
        )
        .unwrap();
    blind
        .put(
            &RecordId::new("cred:status:alice-payment-v1"),
            br#""Active""#,
        )
        .unwrap();

    // === Bob stores his data ===
    let bob = derive_master_secret("bob", "b0b_pa$$word", &[]);

    blind
        .put(&RecordId::new("bob:email"), b"bob@gmail.com")
        .unwrap();
    blind
        .put(
            &RecordId::new("bob:address"),
            b"1600 Pennsylvania Ave NW, Washington DC",
        )
        .unwrap();
    blind
        .put(&RecordId::new("bob:ssn"), b"078-05-1120")
        .unwrap();

    // Bob's video watch history
    let bob_vids = BlindCollection::new(&blind, &*bob, "videos_watched");
    bob_vids.add(b"Fight Club (1999)").unwrap();
    bob_vids.add(b"Pulp Fiction (1994)").unwrap();

    // Bob's credential
    blind
        .put(
            &RecordId::new("cred:status:bob-drivers-license"),
            br#""Active""#,
        )
        .unwrap();

    // === Carol stores her data ===
    blind
        .put(&RecordId::new("carol:email"), b"carol@fastmail.com")
        .unwrap();
    blind
        .put(
            &RecordId::new("carol:medical"),
            b"diagnosis: hypertension, rx: lisinopril 10mg",
        )
        .unwrap();

    // === Now show what the server sees ===
    println!("\n{}", "=".repeat(72));
    println!("SERVER VIEW: SELECT * FROM records");
    println!("(What an attacker with full database access sees)");
    println!("{}\n", "=".repeat(72));

    let entries = blind.inner().all_entries();
    println!("Total records: {}\n", entries.len());

    println!("{:<6} {:<66} {}", "#", "record_id", "data (first 80 chars)");
    println!("{}", "-".repeat(160));

    let mut sorted: Vec<_> = entries.iter().collect();
    sorted.sort_by_key(|(id, _)| id.clone());

    for (i, (id, data)) in sorted.iter().enumerate() {
        let data_preview = String::from_utf8_lossy(data);
        let truncated: String = data_preview.chars().take(80).collect();
        println!("{:<6} {} {}", i + 1, id, truncated);
    }

    println!("\n{}", "=".repeat(160));
    println!("\nQUESTIONS THE ATTACKER CANNOT ANSWER:");
    println!("  - Which records belong to Alice? Bob? Carol?");
    println!("  - Which email goes with which address?");
    println!("  - Who has the credit card? The SSN? The medical record?");
    println!("  - How many users are there? (could be 3, could be 300)");
    println!("  - Which records are in the same collection?");
    println!("  - Is record #5 an email, an address, or a video?");
    println!("  - Are any of these records fake (seed data)?");
}

#[test]
fn show_collection_index_structure() {
    let inner = InMemoryBackend::new();
    let addr_key = Zeroizing::new([0x42u8; 32]);
    let enc_key = Zeroizing::new([0x77u8; 32]);
    let blind = BlindStorageWrapper::new(inner, addr_key, enc_key);

    let secret = derive_master_secret("alice", "s3cret!", &[]);
    let coll = BlindCollection::new(&blind, &*secret, "videos_watched");

    coll.add(b"Inception (2010)").unwrap();
    coll.add(b"The Matrix (1999)").unwrap();
    coll.add(b"Interstellar (2014)").unwrap();

    println!("\n{}", "=".repeat(80));
    println!("COLLECTION INTERNAL STRUCTURE (client-side only — server never sees this)");
    println!("{}\n", "=".repeat(80));

    let indices = coll.read_indices().unwrap();
    println!("Index record (stored encrypted): {:?}", indices);
    println!("Items:");
    for &idx in &indices {
        let data = coll.get(idx).unwrap().unwrap();
        println!("  [{}] = {:?}", idx, String::from_utf8_lossy(&data));
    }

    println!("\nWhat the server sees for this collection:");
    let entries = blind.inner().all_entries();
    let mut sorted: Vec<_> = entries.iter().collect();
    sorted.sort_by_key(|(id, _)| id.clone());
    for (i, (id, _data)) in sorted.iter().enumerate() {
        // 1 index record + 3 item records = 4 total
        println!("  record {}: {} (encrypted blob)", i + 1, id);
    }
    println!("\nThe server sees 4 unrelated records. It cannot tell:");
    println!("  - That 3 of them form a collection");
    println!("  - That 1 of them is an index pointing to the other 3");
    println!("  - What order they were added in");
    println!("  - That they all belong to the same user");
}
