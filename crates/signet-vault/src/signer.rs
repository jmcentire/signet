use crate::error::VaultResult;
use crate::key_hierarchy::KeyHierarchy;
use ed25519_dalek::{Signer as DalekSigner, SigningKey, VerifyingKey};
use signet_core::SignetResult;
use zeroize::Zeroizing;

/// Vault signer that implements the `signet_core::Signer` trait.
///
/// Delegates to the key hierarchy for key material.
pub struct VaultSigner {
    signing_key: Zeroizing<[u8; 32]>,
    verifying_key: [u8; 32],
}

impl VaultSigner {
    /// Create a signer from the vault's signing key.
    pub fn from_hierarchy(hierarchy: &KeyHierarchy) -> VaultResult<Self> {
        let sk_bytes = hierarchy.vault_signing_key()?;
        let signing_key = SigningKey::from_bytes(&sk_bytes);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key: sk_bytes,
            verifying_key: verifying_key.to_bytes(),
        })
    }

    /// Create a signer from raw key bytes (for testing).
    pub fn from_bytes(key_bytes: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key: Zeroizing::new(key_bytes),
            verifying_key: verifying_key.to_bytes(),
        }
    }

    /// Get the SignetId for this signer.
    pub fn signet_id(&self) -> signet_core::SignetId {
        signet_core::signet_id_from_pubkey(&self.verifying_key)
    }

    /// Verify a signature against this signer's public key.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        let vk = VerifyingKey::from_bytes(&self.verifying_key);
        match vk {
            Ok(vk) => {
                let sig = ed25519_dalek::Signature::from_bytes(signature);
                vk.verify_strict(message, &sig).is_ok()
            }
            Err(_) => false,
        }
    }
}

impl signet_core::Signer for VaultSigner {
    fn sign_ed25519(&self, message: &[u8]) -> SignetResult<[u8; 64]> {
        let signing_key = SigningKey::from_bytes(&self.signing_key);
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes())
    }

    fn public_key_ed25519(&self) -> [u8; 32] {
        self.verifying_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::generate_mnemonic;
    use signet_core::Signer;

    #[test]
    fn test_vault_signer_from_hierarchy() {
        let m = generate_mnemonic().unwrap();
        let kh = KeyHierarchy::from_mnemonic(&m, "").unwrap();
        let signer = VaultSigner::from_hierarchy(&kh).unwrap();

        let msg = b"test message";
        let sig = signer.sign_ed25519(msg).unwrap();
        assert!(signer.verify(msg, &sig));
    }

    #[test]
    fn test_vault_signer_deterministic() {
        let m = generate_mnemonic().unwrap();
        let kh1 = KeyHierarchy::from_mnemonic(&m, "").unwrap();
        let kh2 = KeyHierarchy::from_mnemonic(&m, "").unwrap();

        let s1 = VaultSigner::from_hierarchy(&kh1).unwrap();
        let s2 = VaultSigner::from_hierarchy(&kh2).unwrap();

        assert_eq!(s1.public_key_ed25519(), s2.public_key_ed25519());
        assert_eq!(s1.signet_id(), s2.signet_id());
    }

    #[test]
    fn test_vault_signer_from_bytes() {
        let key = [0x42u8; 32];
        let signer = VaultSigner::from_bytes(key);

        let msg = b"hello";
        let sig = signer.sign_ed25519(msg).unwrap();
        assert!(signer.verify(msg, &sig));
    }

    #[test]
    fn test_wrong_message_fails_verify() {
        let signer = VaultSigner::from_bytes([0x42u8; 32]);
        let sig = signer.sign_ed25519(b"message A").unwrap();
        assert!(!signer.verify(b"message B", &sig));
    }

    #[test]
    fn test_signet_id_format() {
        let signer = VaultSigner::from_bytes([0x42u8; 32]);
        let id = signer.signet_id();
        // Base58 encoding should produce a reasonable-length string
        assert!(!id.as_str().is_empty());
        assert!(id.as_str().len() < 50);
    }
}
