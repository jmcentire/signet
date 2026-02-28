use crate::error::{VaultError, VaultResult};
use crate::mnemonic::{mnemonic_to_seed, Slip0010MasterKey};
use bip39::Mnemonic;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Key hierarchy derived from a BIP39 mnemonic:
///
/// ```text
/// Mnemonic → UserRootKey (SLIP-0010)
///   → VaultSealingKey (HKDF from URK + "vault-seal")
///     → Per-record DEKs (HKDF from VSK + record_id)
///   → CompartmentKey per Tier 3 category (HKDF from URK + compartment_id)
///     → Tier 3 DEKs (NOT derivable from VSK — structural isolation)
///   → DeviceKey per device (HKDF from URK + device_id)
/// ```
///
/// Critical invariant: Tier 3 CompartmentKeys are derived from URK directly,
/// NOT from VaultSealingKey. This means an agent session with VSK access
/// CANNOT derive CompartmentKeys — structural isolation by construction.
pub struct KeyHierarchy {
    user_root_key: Zeroizing<[u8; 32]>,
}

impl KeyHierarchy {
    /// Create a key hierarchy from a mnemonic phrase.
    pub fn from_mnemonic(mnemonic: &Mnemonic, passphrase: &str) -> VaultResult<Self> {
        let seed = mnemonic_to_seed(mnemonic, passphrase);
        let master = Slip0010MasterKey::from_seed(&seed)?;

        Ok(Self {
            user_root_key: master.secret_key,
        })
    }

    /// Create a key hierarchy from a raw 32-byte root key (for testing).
    pub fn from_raw_key(key: [u8; 32]) -> Self {
        Self {
            user_root_key: Zeroizing::new(key),
        }
    }

    /// Derive the VaultSealingKey from the URK.
    /// Used for Tier 1 and Tier 2 record encryption.
    pub fn vault_sealing_key(&self) -> VaultResult<Zeroizing<[u8; 32]>> {
        self.hkdf_derive(
            &*self.user_root_key,
            b"vault-seal",
            b"signet-vault-sealing-key",
        )
    }

    /// Derive a per-record Data Encryption Key from the VaultSealingKey.
    pub fn record_dek(&self, record_id: &[u8]) -> VaultResult<Zeroizing<[u8; 32]>> {
        let vsk = self.vault_sealing_key()?;
        self.hkdf_derive(&*vsk, record_id, b"signet-record-dek")
    }

    /// Derive a Tier 3 CompartmentKey from the URK (NOT from VSK).
    ///
    /// This is the structural isolation mechanism: an agent with VSK
    /// cannot derive CompartmentKeys. Only the user with URK can.
    pub fn compartment_key(&self, compartment_id: &str) -> VaultResult<Zeroizing<[u8; 32]>> {
        self.hkdf_derive(
            &*self.user_root_key,
            compartment_id.as_bytes(),
            b"signet-compartment-key",
        )
    }

    /// Derive a Tier 3 per-record DEK from a CompartmentKey.
    pub fn tier3_record_dek(
        &self,
        compartment_id: &str,
        record_id: &[u8],
    ) -> VaultResult<Zeroizing<[u8; 32]>> {
        let ck = self.compartment_key(compartment_id)?;
        self.hkdf_derive(&*ck, record_id, b"signet-tier3-record-dek")
    }

    /// Derive a DeviceKey for device provisioning.
    pub fn device_key(&self, device_id: &str) -> VaultResult<Zeroizing<[u8; 32]>> {
        self.hkdf_derive(
            &*self.user_root_key,
            device_id.as_bytes(),
            b"signet-device-key",
        )
    }

    /// Derive an Ed25519 signing key from the URK for the vault's identity.
    pub fn vault_signing_key(&self) -> VaultResult<Zeroizing<[u8; 32]>> {
        self.hkdf_derive(
            &*self.user_root_key,
            b"vault-identity",
            b"signet-vault-signing",
        )
    }

    /// Derive the addressing key for BlindDB record ID derivation.
    /// Used to hash semantic labels into opaque record IDs.
    pub fn addressing_key(&self) -> VaultResult<Zeroizing<[u8; 32]>> {
        self.hkdf_derive(
            &*self.user_root_key,
            b"blind-addressing",
            b"signet-addressing-key",
        )
    }

    /// Derive the audit log encryption key.
    /// All audit events are encrypted with this key before persistence.
    pub fn audit_log_key(&self) -> VaultResult<Zeroizing<[u8; 32]>> {
        self.hkdf_derive(&*self.user_root_key, b"audit-log", b"signet-audit-key")
    }

    /// Derive a session key for agent authentication.
    pub fn agent_session_key(&self, session_id: &str) -> VaultResult<Zeroizing<[u8; 32]>> {
        let vsk = self.vault_sealing_key()?;
        self.hkdf_derive(&*vsk, session_id.as_bytes(), b"signet-agent-session")
    }

    /// HKDF-SHA256 key derivation.
    fn hkdf_derive(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
    ) -> VaultResult<Zeroizing<[u8; 32]>> {
        let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm)
            .map_err(|e| VaultError::KeyDerivation(format!("HKDF expand failed: {}", e)))?;
        Ok(Zeroizing::new(okm))
    }
}

impl Drop for KeyHierarchy {
    fn drop(&mut self) {
        // Zeroizing handles cleanup of user_root_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::generate_mnemonic;

    fn test_hierarchy() -> KeyHierarchy {
        let m = generate_mnemonic().unwrap();
        KeyHierarchy::from_mnemonic(&m, "").unwrap()
    }

    #[test]
    fn test_vault_sealing_key_deterministic() {
        let kh = KeyHierarchy::from_raw_key([0x42; 32]);
        let vsk1 = kh.vault_sealing_key().unwrap();
        let vsk2 = kh.vault_sealing_key().unwrap();
        assert_eq!(*vsk1, *vsk2);
    }

    #[test]
    fn test_vsk_differs_from_urk() {
        let raw = [0x42; 32];
        let kh = KeyHierarchy::from_raw_key(raw);
        let vsk = kh.vault_sealing_key().unwrap();
        assert_ne!(*vsk, raw);
    }

    #[test]
    fn test_record_dek_deterministic() {
        let kh = test_hierarchy();
        let dek1 = kh.record_dek(b"record-1").unwrap();
        let dek2 = kh.record_dek(b"record-1").unwrap();
        assert_eq!(*dek1, *dek2);
    }

    #[test]
    fn test_record_dek_differs_per_record() {
        let kh = test_hierarchy();
        let dek1 = kh.record_dek(b"record-1").unwrap();
        let dek2 = kh.record_dek(b"record-2").unwrap();
        assert_ne!(*dek1, *dek2);
    }

    #[test]
    fn test_tier3_structural_isolation() {
        // Critical invariant: VSK-derived keys CANNOT reach Tier 3 compartments.
        // CompartmentKey is derived from URK, not VSK.
        let kh = test_hierarchy();

        let vsk = kh.vault_sealing_key().unwrap();
        let ck = kh.compartment_key("payment-cards").unwrap();

        // These must be different — VSK cannot derive CK
        assert_ne!(*vsk, *ck);

        // A Tier 3 DEK must differ from a Tier 1/2 DEK for same record ID
        let tier12_dek = kh.record_dek(b"record-X").unwrap();
        let tier3_dek = kh.tier3_record_dek("payment-cards", b"record-X").unwrap();
        assert_ne!(*tier12_dek, *tier3_dek);
    }

    #[test]
    fn test_compartment_keys_differ() {
        let kh = test_hierarchy();
        let ck1 = kh.compartment_key("payment-cards").unwrap();
        let ck2 = kh.compartment_key("medical-records").unwrap();
        assert_ne!(*ck1, *ck2);
    }

    #[test]
    fn test_device_key_derivation() {
        let kh = test_hierarchy();
        let dk1 = kh.device_key("laptop-1").unwrap();
        let dk2 = kh.device_key("phone-1").unwrap();
        assert_ne!(*dk1, *dk2);
    }

    #[test]
    fn test_device_key_deterministic() {
        let kh = KeyHierarchy::from_raw_key([0x77; 32]);
        let dk1 = kh.device_key("laptop-1").unwrap();
        let dk2 = kh.device_key("laptop-1").unwrap();
        assert_eq!(*dk1, *dk2);
    }

    #[test]
    fn test_vault_signing_key() {
        let kh = test_hierarchy();
        let sk = kh.vault_signing_key().unwrap();
        assert_ne!(*sk, [0u8; 32]);
    }

    #[test]
    fn test_agent_session_key() {
        let kh = test_hierarchy();
        let sk1 = kh.agent_session_key("session-1").unwrap();
        let sk2 = kh.agent_session_key("session-2").unwrap();
        assert_ne!(*sk1, *sk2);
    }

    #[test]
    fn test_from_mnemonic() {
        let m = generate_mnemonic().unwrap();
        let kh1 = KeyHierarchy::from_mnemonic(&m, "").unwrap();
        let kh2 = KeyHierarchy::from_mnemonic(&m, "").unwrap();

        let vsk1 = kh1.vault_sealing_key().unwrap();
        let vsk2 = kh2.vault_sealing_key().unwrap();
        assert_eq!(*vsk1, *vsk2);
    }

    #[test]
    fn test_passphrase_changes_hierarchy() {
        let m = generate_mnemonic().unwrap();
        let kh1 = KeyHierarchy::from_mnemonic(&m, "").unwrap();
        let kh2 = KeyHierarchy::from_mnemonic(&m, "different").unwrap();

        let vsk1 = kh1.vault_sealing_key().unwrap();
        let vsk2 = kh2.vault_sealing_key().unwrap();
        assert_ne!(*vsk1, *vsk2);
    }
}
