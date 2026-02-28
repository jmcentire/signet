use crate::error::{VaultError, VaultResult};
use bip39::Mnemonic;
use hmac::Hmac;
use sha2::Sha512;

// BIP39 mnemonic generation and SLIP-0010 Ed25519 key derivation.
//
// BIP39 → seed → SLIP-0010 → Ed25519 master key
//
// SLIP-0010 is used instead of BIP32 because Ed25519 requires specific
// key derivation that BIP32's secp256k1-oriented approach doesn't support.

/// Generate a new 24-word BIP39 mnemonic (256 bits of entropy).
pub fn generate_mnemonic() -> VaultResult<Mnemonic> {
    let mut entropy = [0u8; 32]; // 256 bits = 24 words
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut entropy);
    Mnemonic::from_entropy(&entropy)
        .map_err(|e| VaultError::Mnemonic(format!("failed to generate mnemonic: {}", e)))
}

/// Parse and validate a mnemonic phrase.
pub fn parse_mnemonic(phrase: &str) -> VaultResult<Mnemonic> {
    Mnemonic::parse(phrase).map_err(|e| VaultError::Mnemonic(format!("invalid mnemonic: {}", e)))
}

use zeroize::Zeroizing;

/// Derive a 64-byte seed from mnemonic + optional passphrase (BIP39 standard).
pub fn mnemonic_to_seed(mnemonic: &Mnemonic, passphrase: &str) -> Zeroizing<[u8; 64]> {
    let seed = mnemonic.to_seed(passphrase);
    Zeroizing::new(seed)
}

/// SLIP-0010 master key derivation for Ed25519.
///
/// From the seed, derive a master key and chain code using HMAC-SHA512
/// with the key "ed25519 seed".
pub struct Slip0010MasterKey {
    pub secret_key: Zeroizing<[u8; 32]>,
    pub chain_code: Zeroizing<[u8; 32]>,
}

impl Slip0010MasterKey {
    pub fn from_seed(seed: &[u8; 64]) -> VaultResult<Self> {
        use hmac::Mac;

        let mut mac = Hmac::<Sha512>::new_from_slice(b"ed25519 seed")
            .map_err(|e| VaultError::KeyDerivation(format!("HMAC init failed: {}", e)))?;
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let mut secret_key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        secret_key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        Ok(Self {
            secret_key: Zeroizing::new(secret_key),
            chain_code: Zeroizing::new(chain_code),
        })
    }

    /// Derive a child key at a hardened index (SLIP-0010 Ed25519 only supports hardened).
    ///
    /// index must be >= 0x80000000 (hardened). We add the hardened bit automatically.
    pub fn derive_child(&self, index: u32) -> VaultResult<Slip0010MasterKey> {
        use hmac::Mac;

        let hardened_index = index | 0x80000000;

        let mut mac = Hmac::<Sha512>::new_from_slice(&*self.chain_code)
            .map_err(|e| VaultError::KeyDerivation(format!("HMAC init failed: {}", e)))?;

        // For Ed25519 SLIP-0010: 0x00 || secret_key || index
        mac.update(&[0x00]);
        mac.update(&*self.secret_key);
        mac.update(&hardened_index.to_be_bytes());

        let result = mac.finalize().into_bytes();

        let mut secret_key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        secret_key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        Ok(Self {
            secret_key: Zeroizing::new(secret_key),
            chain_code: Zeroizing::new(chain_code),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic() {
        let m = generate_mnemonic().unwrap();
        let phrase = m.to_string();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_mnemonic_roundtrip() {
        let m1 = generate_mnemonic().unwrap();
        let phrase = m1.to_string();
        let m2 = parse_mnemonic(&phrase).unwrap();
        assert_eq!(m1.to_string(), m2.to_string());
    }

    #[test]
    fn test_seed_deterministic() {
        let m = parse_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        ).unwrap();
        let s1 = mnemonic_to_seed(&m, "");
        let s2 = mnemonic_to_seed(&m, "");
        assert_eq!(*s1, *s2);
    }

    #[test]
    fn test_seed_differs_with_passphrase() {
        let m = generate_mnemonic().unwrap();
        let s1 = mnemonic_to_seed(&m, "");
        let s2 = mnemonic_to_seed(&m, "my-passphrase");
        assert_ne!(*s1, *s2);
    }

    #[test]
    fn test_slip0010_master_key() {
        let m = generate_mnemonic().unwrap();
        let seed = mnemonic_to_seed(&m, "");
        let master = Slip0010MasterKey::from_seed(&seed).unwrap();
        assert_ne!(*master.secret_key, [0u8; 32]);
        assert_ne!(*master.chain_code, [0u8; 32]);
    }

    #[test]
    fn test_slip0010_child_derivation() {
        let m = generate_mnemonic().unwrap();
        let seed = mnemonic_to_seed(&m, "");
        let master = Slip0010MasterKey::from_seed(&seed).unwrap();

        let child0 = master.derive_child(0).unwrap();
        let child1 = master.derive_child(1).unwrap();

        // Different indices produce different keys
        assert_ne!(*child0.secret_key, *child1.secret_key);
    }

    #[test]
    fn test_slip0010_deterministic() {
        let m = generate_mnemonic().unwrap();
        let seed = mnemonic_to_seed(&m, "");

        let master1 = Slip0010MasterKey::from_seed(&seed).unwrap();
        let master2 = Slip0010MasterKey::from_seed(&seed).unwrap();

        assert_eq!(*master1.secret_key, *master2.secret_key);

        let child1 = master1.derive_child(42).unwrap();
        let child2 = master2.derive_child(42).unwrap();
        assert_eq!(*child1.secret_key, *child2.secret_key);
    }
}
