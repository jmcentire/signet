//! BlindDB addressing scheme from "The Ephemeral Internet" (McEntire, 2026).
//!
//! # Security Model
//!
//! Information is not just records — it's also the **relationships between
//! records**. Often the relationships are more valuable than the data itself.
//! Knowing "123 East West St" tells you nothing. Knowing that *this person*
//! lives there AND watched *these videos* AND has *this credit card* — that's
//! the valuable information.
//!
//! BlindDB destroys those relationships by making them **generative**: the
//! client constructs record addresses via one-way deterministic hashing from
//! secrets the server never sees. The server stores a flat pile of opaque
//! record IDs and values — no user tables, no foreign keys, no joins.
//!
//! # Defense Layers
//!
//! 1. **Relational opacity** (primary) — no way to group records by user
//! 2. **Signatures** — tamper evidence via Ed25519 (forging requires the key)
//! 3. **Hash chains** — provenance and ordering (completeness guarantee)
//! 4. **Encryption** (defense-in-depth) — AES-256-GCM for data with
//!    independent value (credit cards work regardless of who they belong to)
//! 5. **Seed data** — tunable plausible deniability via fake records
//!
//! # Collision Handling
//!
//! SHA-256 has a 2^256 target space, making collisions essentially impossible.
//! But even if a collision occurs on INSERT, the client detects it and signals
//! upstream to bump the index and rehash. The server never knows a collision
//! happened — it just sees a different opaque ID on retry.

use crate::envelope;
use crate::error::{VaultError, VaultResult};
use sha2::{Digest, Sha256};
use signet_core::{RecordId, SignetResult, StorageBackend};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Derive a deterministic record address from client-side secrets.
///
/// `record_id = SHA-256(master_secret || label || index_bytes)`
///
/// The label is a semantic name (e.g., "email", "shipping_address").
/// The index allows multiple records under the same label, and enables
/// collision recovery: if an INSERT collides, bump the index and rehash.
pub fn derive_record_id(master_secret: &[u8], label: &str, index: u64) -> RecordId {
    let mut hasher = Sha256::new();
    hasher.update(master_secret);
    hasher.update(label.as_bytes());
    hasher.update(index.to_le_bytes());
    let hash = hasher.finalize();
    RecordId::new(hex::encode(hash))
}

/// Derive a per-record encryption key.
///
/// `enc_key = SHA-256(master_secret || record_id || "encrypt")`
///
/// Each record has its own encryption key, derived from the master secret
/// and the record's address. Compromising one key reveals nothing about others.
pub fn derive_record_key(master_secret: &[u8], record_id: &RecordId) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(master_secret);
    hasher.update(record_id.as_str().as_bytes());
    hasher.update(b"encrypt");
    let hash = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    Zeroizing::new(key)
}

/// Iterative hash for collection enumeration.
///
/// The server can't enumerate records for you — it doesn't know which records
/// belong to the same collection. So the client must know the count:
///
/// 1. Read count: `derive_count_record_id(secret, "videos_watched")` → stored count
/// 2. Generate N record IDs: `derive_collection_ids(secret, "videos_watched", N)`
///
/// Each record ID is independently addressable. The collection is only
/// enumerable by someone who knows the master_secret AND the count.
pub fn derive_collection_ids(master_secret: &[u8], label: &str, count: u64) -> Vec<RecordId> {
    (0..count)
        .map(|i| derive_record_id(master_secret, label, i))
        .collect()
}

/// Derive a collection count record ID.
///
/// The count of items in a collection is itself stored as a BlindDB record.
/// This is the address where that count is stored.
pub fn derive_count_record_id(master_secret: &[u8], label: &str) -> RecordId {
    derive_record_id(master_secret, &format!("{}_count", label), 0)
}

/// Derive a master secret from credentials (BlindDB key input model).
///
/// Different credential combinations produce different hash spaces:
/// - `derive_master_secret("jmcentire", "work", &[])` → work experience
/// - `derive_master_secret("jmcentire", "play", &[])` → personal experience
/// - `derive_master_secret("jmcentire", "", &[])` → username-only (survives password reset)
///
/// Additional inputs (e.g., PIN) can further partition the key space.
pub fn derive_master_secret(
    username: &str,
    password: &str,
    additional_inputs: &[&str],
) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    if !password.is_empty() {
        hasher.update(password.as_bytes());
    }
    for input in additional_inputs {
        hasher.update(input.as_bytes());
    }
    hasher.update(b"master");
    let hash = hasher.finalize();

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&hash);
    Zeroizing::new(secret)
}

/// Derive a tier-specific master secret.
///
/// Tier 1: username-derived only (survives password reset)
/// Tier 2: username + password (lost on password reset)
/// Tier 3: not applicable (uses random keys)
pub fn derive_tiered_secret(
    username: &str,
    password: &str,
    tier: signet_core::Tier,
) -> VaultResult<Zeroizing<[u8; 32]>> {
    match tier {
        signet_core::Tier::Tier1 => Ok(derive_master_secret(username, "", &[])),
        signet_core::Tier::Tier2 => Ok(derive_master_secret(username, password, &[])),
        signet_core::Tier::Tier3 => Err(VaultError::TierViolation(
            "Tier 3 uses random keys, not credential-derived secrets".into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// BlindStorageWrapper — transparent blind addressing + encryption
// ---------------------------------------------------------------------------

/// Wraps a raw `StorageBackend` with blind addressing and envelope encryption.
///
/// The primary defense is **relational opacity**: the server stores a flat
/// pile of unrelated records. Encryption is defense-in-depth — it protects
/// data whose value is independent of relationships (e.g., credit card
/// numbers work regardless of whose they are).
///
/// Every `put` operation:
/// 1. Hashes the record ID through SHA-256(addressing_key || original_id)
/// 2. Encrypts the data with a per-record DEK derived from encryption_key + opaque_id
/// 3. Stores the (opaque_id, ciphertext) pair
///
/// The underlying backend never sees semantic record IDs or plaintext data.
pub struct BlindStorageWrapper<S: StorageBackend> {
    inner: S,
    addressing_key: Zeroizing<[u8; 32]>,
    encryption_key: Zeroizing<[u8; 32]>,
}

impl<S: StorageBackend> BlindStorageWrapper<S> {
    /// Create a new blind storage wrapper.
    ///
    /// - `inner`: The raw storage backend (SQLite, in-memory, etc.)
    /// - `addressing_key`: Secret key for hashing record IDs (from KeyHierarchy::addressing_key)
    /// - `encryption_key`: Secret key for deriving per-record DEKs (from KeyHierarchy::vault_sealing_key)
    pub fn new(
        inner: S,
        addressing_key: Zeroizing<[u8; 32]>,
        encryption_key: Zeroizing<[u8; 32]>,
    ) -> Self {
        Self {
            inner,
            addressing_key,
            encryption_key,
        }
    }

    /// Hash a semantic record ID into an opaque one.
    fn blind_id(&self, record_id: &RecordId) -> RecordId {
        let mut hasher = Sha256::new();
        hasher.update(*self.addressing_key);
        hasher.update(record_id.as_str().as_bytes());
        let hash = hasher.finalize();
        RecordId::new(hex::encode(hash))
    }

    /// Derive a per-record encryption key from the opaque record ID.
    fn record_dek(&self, opaque_id: &RecordId) -> Zeroizing<[u8; 32]> {
        derive_record_key(&*self.encryption_key, opaque_id)
    }

    /// Encrypt data for a given opaque record ID.
    fn encrypt_data(&self, opaque_id: &RecordId, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
        let dek = self.record_dek(opaque_id);
        let env = envelope::encrypt(&dek, plaintext)?;
        serde_json::to_vec(&env)
            .map_err(|e| VaultError::Encryption(format!("failed to serialize envelope: {}", e)))
    }

    /// Decrypt data for a given opaque record ID.
    fn decrypt_data(&self, opaque_id: &RecordId, ciphertext: &[u8]) -> VaultResult<Vec<u8>> {
        let env: envelope::EncryptedEnvelope = serde_json::from_slice(ciphertext).map_err(|e| {
            VaultError::Decryption(format!("failed to deserialize envelope: {}", e))
        })?;
        let dek = self.record_dek(opaque_id);
        envelope::decrypt(&dek, &env)
    }

    /// Insert a new record, detecting collisions.
    ///
    /// Unlike `put` (which overwrites), `insert_unique` checks whether the
    /// opaque ID already exists. If it does, and the caller didn't write it,
    /// that's a hash collision — astronomically rare in SHA-256, but handled.
    ///
    /// Returns `Ok(())` on success, `Err(VaultError::Collision)` if the
    /// opaque ID is already occupied. The caller should bump their index
    /// and retry with a new record ID.
    pub fn insert_unique(&self, record_id: &RecordId, data: &[u8]) -> VaultResult<()> {
        let opaque = self.blind_id(record_id);

        if self
            .inner
            .exists(&opaque)
            .map_err(|e| VaultError::Storage(format!("collision check failed: {}", e)))?
        {
            return Err(VaultError::Collision(
                "opaque ID already exists (blind hash collision or duplicate insert)".into(),
            ));
        }

        let encrypted = self.encrypt_data(&opaque, data)?;
        self.inner
            .put(&opaque, &encrypted)
            .map_err(|e| VaultError::Storage(format!("insert failed: {}", e)))
    }

    /// Get a reference to the inner backend (for testing/inspection).
    pub fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: StorageBackend> StorageBackend for BlindStorageWrapper<S> {
    fn get(&self, record_id: &RecordId) -> SignetResult<Option<Vec<u8>>> {
        let opaque = self.blind_id(record_id);
        match self.inner.get(&opaque)? {
            Some(encrypted) => {
                let plaintext = self.decrypt_data(&opaque, &encrypted).map_err(|e| {
                    signet_core::SignetError::Storage(format!("blind decrypt failed: {}", e))
                })?;
                Ok(Some(plaintext))
            }
            None => Ok(None),
        }
    }

    fn put(&self, record_id: &RecordId, data: &[u8]) -> SignetResult<()> {
        let opaque = self.blind_id(record_id);
        let encrypted = self.encrypt_data(&opaque, data).map_err(|e| {
            signet_core::SignetError::Storage(format!("blind encrypt failed: {}", e))
        })?;
        self.inner.put(&opaque, &encrypted)
    }

    fn delete(&self, record_id: &RecordId) -> SignetResult<bool> {
        let opaque = self.blind_id(record_id);
        self.inner.delete(&opaque)
    }

    fn compare_and_swap(
        &self,
        record_id: &RecordId,
        expected: Option<&[u8]>,
        new_value: &[u8],
    ) -> SignetResult<bool> {
        let opaque = self.blind_id(record_id);

        // Read + decrypt current value for comparison
        let current_plaintext = match self.inner.get(&opaque)? {
            Some(encrypted) => {
                let pt = self.decrypt_data(&opaque, &encrypted).map_err(|e| {
                    signet_core::SignetError::Storage(format!("blind CAS decrypt failed: {}", e))
                })?;
                Some(pt)
            }
            None => None,
        };

        // Compare plaintext values (constant-time to prevent timing side-channels)
        let matches = match (&current_plaintext, expected) {
            (None, None) => true,
            (Some(curr), Some(exp)) => curr.as_slice().ct_eq(exp).into(),
            _ => false,
        };

        if matches {
            let encrypted = self.encrypt_data(&opaque, new_value).map_err(|e| {
                signet_core::SignetError::Storage(format!("blind CAS encrypt failed: {}", e))
            })?;
            self.inner.put(&opaque, &encrypted)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn exists(&self, record_id: &RecordId) -> SignetResult<bool> {
        let opaque = self.blind_id(record_id);
        self.inner.exists(&opaque)
    }
}

// ---------------------------------------------------------------------------
// BlindCollection — collision-aware collection management
// ---------------------------------------------------------------------------

/// Manages a named collection of records with collision-aware index assignment.
///
/// Implements the BlindDB collection pattern:
///
/// ```text
/// hash(secret, "videos_watched_count", 0) → count record (stores N)
/// hash(secret, "videos_watched", 0)       → item 0
/// hash(secret, "videos_watched", 1)       → item 1
/// ...
/// hash(secret, "videos_watched", N-1)     → item N-1
/// ```
///
/// When adding a new item, if the derived record ID collides with an existing
/// record (astronomically rare but handled), the index is bumped and retried.
/// The index record is updated to reflect the actual indices used.
///
/// The server cannot enumerate the collection — only someone with the
/// master_secret AND the count can reconstruct the record IDs.
pub struct BlindCollection<'a, S: StorageBackend> {
    storage: &'a BlindStorageWrapper<S>,
    master_secret: &'a [u8],
    label: String,
}

impl<'a, S: StorageBackend> BlindCollection<'a, S> {
    /// Create a collection manager for the given label.
    pub fn new(
        storage: &'a BlindStorageWrapper<S>,
        master_secret: &'a [u8],
        label: impl Into<String>,
    ) -> Self {
        Self {
            storage,
            master_secret,
            label: label.into(),
        }
    }

    /// Read the current index list for this collection.
    ///
    /// The index record stores a JSON array of u64 indices that map to
    /// the actual record IDs in use. Normally these are sequential [0,1,2,...N],
    /// but a collision bump can cause gaps (e.g., [0,1,2,4] if index 3 collided).
    pub fn read_indices(&self) -> VaultResult<Vec<u64>> {
        let count_id = derive_count_record_id(self.master_secret, &self.label);
        match self
            .storage
            .get(&count_id)
            .map_err(|e| VaultError::Storage(format!("failed to read index: {}", e)))?
        {
            Some(data) => serde_json::from_slice(&data)
                .map_err(|e| VaultError::Storage(format!("failed to parse index: {}", e))),
            None => Ok(Vec::new()),
        }
    }

    /// Write the index list for this collection.
    fn write_indices(&self, indices: &[u64]) -> VaultResult<()> {
        let count_id = derive_count_record_id(self.master_secret, &self.label);
        let data = serde_json::to_vec(indices)
            .map_err(|e| VaultError::Storage(format!("failed to serialize index: {}", e)))?;
        self.storage
            .put(&count_id, &data)
            .map_err(|e| VaultError::Storage(format!("failed to write index: {}", e)))
    }

    /// Add an item to the collection with collision-aware index assignment.
    ///
    /// Tries the next sequential index first. If a collision is detected
    /// (the opaque ID already exists for a different record), bumps the
    /// index and retries. The server never knows a collision happened.
    ///
    /// Returns the index that was used.
    pub fn add(&self, data: &[u8]) -> VaultResult<u64> {
        let mut indices = self.read_indices()?;
        let mut next_index = indices.last().map(|i| i + 1).unwrap_or(0);

        // Try inserting with increasing indices until we find one without collision
        let max_retries = 16; // 16 consecutive SHA-256 collisions = never happens
        for _attempt in 0..max_retries {
            let record_id = derive_record_id(self.master_secret, &self.label, next_index);
            match self.storage.insert_unique(&record_id, data) {
                Ok(()) => {
                    // Success — update the index record
                    indices.push(next_index);
                    self.write_indices(&indices)?;
                    return Ok(next_index);
                }
                Err(VaultError::Collision(_)) => {
                    // Collision detected — bump index and retry
                    next_index += 1;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Err(VaultError::Internal(format!(
            "exhausted {} collision retries for collection '{}' — this should never happen",
            max_retries, self.label
        )))
    }

    /// Get an item by its index.
    pub fn get(&self, index: u64) -> VaultResult<Option<Vec<u8>>> {
        let record_id = derive_record_id(self.master_secret, &self.label, index);
        self.storage
            .get(&record_id)
            .map_err(|e| VaultError::Storage(format!("failed to get collection item: {}", e)))
    }

    /// Get all items in the collection.
    pub fn get_all(&self) -> VaultResult<Vec<(u64, Vec<u8>)>> {
        let indices = self.read_indices()?;
        let mut results = Vec::with_capacity(indices.len());
        for &idx in &indices {
            if let Some(data) = self.get(idx)? {
                results.push((idx, data));
            }
        }
        Ok(results)
    }

    /// Get the number of items in the collection.
    pub fn len(&self) -> VaultResult<usize> {
        Ok(self.read_indices()?.len())
    }

    /// Check if the collection is empty.
    pub fn is_empty(&self) -> VaultResult<bool> {
        Ok(self.read_indices()?.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::in_memory_backend::InMemoryBackend;

    #[test]
    fn test_derive_record_id_deterministic() {
        let secret = b"my-secret-key";
        let id1 = derive_record_id(secret, "email", 0);
        let id2 = derive_record_id(secret, "email", 0);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_derive_record_id_differs_by_label() {
        let secret = b"my-secret-key";
        let id1 = derive_record_id(secret, "email", 0);
        let id2 = derive_record_id(secret, "phone", 0);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_derive_record_id_differs_by_index() {
        let secret = b"my-secret-key";
        let id1 = derive_record_id(secret, "email", 0);
        let id2 = derive_record_id(secret, "email", 1);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_derive_record_id_differs_by_secret() {
        let id1 = derive_record_id(b"secret-1", "email", 0);
        let id2 = derive_record_id(b"secret-2", "email", 0);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_derive_record_key_deterministic() {
        let secret = b"my-secret-key";
        let record_id = derive_record_id(secret, "email", 0);
        let key1 = derive_record_key(secret, &record_id);
        let key2 = derive_record_key(secret, &record_id);
        assert_eq!(*key1, *key2);
    }

    #[test]
    fn test_derive_record_key_differs_per_record() {
        let secret = b"my-secret-key";
        let r1 = derive_record_id(secret, "email", 0);
        let r2 = derive_record_id(secret, "phone", 0);
        let k1 = derive_record_key(secret, &r1);
        let k2 = derive_record_key(secret, &r2);
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn test_collection_enumeration() {
        let secret = b"my-secret-key";
        let ids = derive_collection_ids(secret, "videos_watched", 5);
        assert_eq!(ids.len(), 5);

        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j]);
            }
        }

        for (i, id) in ids.iter().enumerate() {
            let expected = derive_record_id(secret, "videos_watched", i as u64);
            assert_eq!(*id, expected);
        }
    }

    #[test]
    fn test_master_secret_different_passwords() {
        let s1 = derive_master_secret("jmcentire", "work", &[]);
        let s2 = derive_master_secret("jmcentire", "play", &[]);
        assert_ne!(*s1, *s2);
    }

    #[test]
    fn test_master_secret_username_only() {
        let s1 = derive_master_secret("jmcentire", "", &[]);
        let s2 = derive_master_secret("jmcentire", "", &[]);
        assert_eq!(*s1, *s2);
    }

    #[test]
    fn test_master_secret_with_pin() {
        let s1 = derive_master_secret("jmcentire", "work", &[]);
        let s2 = derive_master_secret("jmcentire", "work", &["1234"]);
        assert_ne!(*s1, *s2);
    }

    #[test]
    fn test_tiered_secret_tier1() {
        let s1 = derive_tiered_secret("user", "pass1", signet_core::Tier::Tier1).unwrap();
        let s2 = derive_tiered_secret("user", "pass2", signet_core::Tier::Tier1).unwrap();
        assert_eq!(*s1, *s2);
    }

    #[test]
    fn test_tiered_secret_tier2() {
        let s1 = derive_tiered_secret("user", "pass1", signet_core::Tier::Tier2).unwrap();
        let s2 = derive_tiered_secret("user", "pass2", signet_core::Tier::Tier2).unwrap();
        assert_ne!(*s1, *s2);
    }

    #[test]
    fn test_tiered_secret_tier3_errors() {
        let result = derive_tiered_secret("user", "pass", signet_core::Tier::Tier3);
        assert!(result.is_err());
    }

    #[test]
    fn test_count_record_id() {
        let secret = b"my-secret-key";
        let count_id = derive_count_record_id(secret, "videos_watched");
        let regular_id = derive_record_id(secret, "videos_watched", 0);
        assert_ne!(count_id, regular_id);
    }

    #[test]
    fn test_crypto_erasure() {
        let secret = b"my-secret-that-will-be-erased";
        let id = derive_record_id(secret, "email", 0);
        let wrong_id = derive_record_id(b"wrong-secret", "email", 0);
        assert_ne!(id, wrong_id);
    }

    // --- insert_unique collision detection ---

    #[test]
    fn test_insert_unique_succeeds() {
        let inner = InMemoryBackend::new();
        let addr_key = Zeroizing::new([0x42u8; 32]);
        let enc_key = Zeroizing::new([0x77u8; 32]);
        let blind = BlindStorageWrapper::new(inner, addr_key, enc_key);

        blind
            .insert_unique(&RecordId::new("record-1"), b"data-1")
            .unwrap();
        assert_eq!(
            blind.get(&RecordId::new("record-1")).unwrap().unwrap(),
            b"data-1"
        );
    }

    #[test]
    fn test_insert_unique_detects_collision() {
        let inner = InMemoryBackend::new();
        let addr_key = Zeroizing::new([0x42u8; 32]);
        let enc_key = Zeroizing::new([0x77u8; 32]);
        let blind = BlindStorageWrapper::new(inner, addr_key, enc_key);

        // First insert succeeds
        blind
            .insert_unique(&RecordId::new("record-1"), b"data-1")
            .unwrap();

        // Second insert with SAME semantic ID detects "collision" (same opaque ID)
        let result = blind.insert_unique(&RecordId::new("record-1"), b"data-2");
        assert!(matches!(result, Err(VaultError::Collision(_))));
    }

    // --- BlindCollection tests ---

    #[test]
    fn test_collection_add_and_retrieve() {
        let inner = InMemoryBackend::new();
        let addr_key = Zeroizing::new([0x42u8; 32]);
        let enc_key = Zeroizing::new([0x77u8; 32]);
        let blind = BlindStorageWrapper::new(inner, addr_key, enc_key);
        let secret = b"test-secret";

        let coll = BlindCollection::new(&blind, secret, "videos_watched");

        assert!(coll.is_empty().unwrap());

        let idx0 = coll.add(b"video-A").unwrap();
        assert_eq!(idx0, 0);

        let idx1 = coll.add(b"video-B").unwrap();
        assert_eq!(idx1, 1);

        let idx2 = coll.add(b"video-C").unwrap();
        assert_eq!(idx2, 2);

        assert_eq!(coll.len().unwrap(), 3);

        // Retrieve by index
        assert_eq!(coll.get(0).unwrap().unwrap(), b"video-A");
        assert_eq!(coll.get(1).unwrap().unwrap(), b"video-B");
        assert_eq!(coll.get(2).unwrap().unwrap(), b"video-C");

        // Retrieve all
        let all = coll.get_all().unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0], (0, b"video-A".to_vec()));
        assert_eq!(all[1], (1, b"video-B".to_vec()));
        assert_eq!(all[2], (2, b"video-C".to_vec()));
    }

    #[test]
    fn test_collection_index_persists_across_instances() {
        let inner = InMemoryBackend::new();
        let addr_key = Zeroizing::new([0x42u8; 32]);
        let enc_key = Zeroizing::new([0x77u8; 32]);
        let blind = BlindStorageWrapper::new(inner, addr_key, enc_key);
        let secret = b"test-secret";

        // Add items with first collection instance
        {
            let coll = BlindCollection::new(&blind, secret, "my_list");
            coll.add(b"item-1").unwrap();
            coll.add(b"item-2").unwrap();
        }

        // Read with a new collection instance (same storage + secret)
        {
            let coll = BlindCollection::new(&blind, secret, "my_list");
            assert_eq!(coll.len().unwrap(), 2);
            assert_eq!(coll.get(0).unwrap().unwrap(), b"item-1");
            assert_eq!(coll.get(1).unwrap().unwrap(), b"item-2");

            // Continue adding
            let idx = coll.add(b"item-3").unwrap();
            assert_eq!(idx, 2);
        }
    }

    #[test]
    fn test_collection_collision_bumps_index() {
        let inner = InMemoryBackend::new();
        let addr_key = Zeroizing::new([0x42u8; 32]);
        let enc_key = Zeroizing::new([0x77u8; 32]);
        let blind = BlindStorageWrapper::new(inner, addr_key, enc_key);
        let secret = b"test-secret";

        // Pre-occupy the slot that index 1 would hash to, simulating a collision.
        // We do this by directly inserting with the exact record ID that
        // derive_record_id(secret, "coll", 1) would produce.
        let conflicting_id = derive_record_id(secret, "coll", 1);
        blind.put(&conflicting_id, b"pre-existing-data").unwrap();

        let coll = BlindCollection::new(&blind, secret, "coll");

        // First add gets index 0 (no collision)
        let idx0 = coll.add(b"item-A").unwrap();
        assert_eq!(idx0, 0);

        // Second add tries index 1 → collision! Bumps to index 2.
        let idx1 = coll.add(b"item-B").unwrap();
        assert_eq!(idx1, 2, "should skip index 1 due to collision");

        // Index record reflects the gap: [0, 2]
        let indices = coll.read_indices().unwrap();
        assert_eq!(indices, vec![0, 2]);

        // Data is correct
        assert_eq!(coll.get(0).unwrap().unwrap(), b"item-A");
        assert_eq!(coll.get(2).unwrap().unwrap(), b"item-B");
    }

    #[test]
    fn test_different_collections_are_independent() {
        let inner = InMemoryBackend::new();
        let addr_key = Zeroizing::new([0x42u8; 32]);
        let enc_key = Zeroizing::new([0x77u8; 32]);
        let blind = BlindStorageWrapper::new(inner, addr_key, enc_key);
        let secret = b"test-secret";

        let videos = BlindCollection::new(&blind, secret, "videos");
        let articles = BlindCollection::new(&blind, secret, "articles");

        videos.add(b"video-1").unwrap();
        videos.add(b"video-2").unwrap();
        articles.add(b"article-1").unwrap();

        assert_eq!(videos.len().unwrap(), 2);
        assert_eq!(articles.len().unwrap(), 1);
    }
}
