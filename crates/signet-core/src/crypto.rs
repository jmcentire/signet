use crate::types::SignetId;
use sha2::{Digest, Sha256};

/// Derive a SignetId from an Ed25519 public key.
///
/// Formula: Base58(SHA-256(Ed25519_pubkey)[0:20])
///
/// Self-certifying identity: no registry, no resolution protocol.
pub fn signet_id_from_pubkey(pubkey: &[u8; 32]) -> SignetId {
    let hash = Sha256::digest(pubkey);
    let truncated = &hash[..20];
    SignetId(bs58::encode(truncated).into_string())
}

/// Verify that a SignetId matches a given Ed25519 public key.
pub fn verify_signet_id(id: &SignetId, pubkey: &[u8; 32]) -> bool {
    signet_id_from_pubkey(pubkey) == *id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signet_id_deterministic() {
        let pubkey = [0x42u8; 32];
        let id1 = signet_id_from_pubkey(&pubkey);
        let id2 = signet_id_from_pubkey(&pubkey);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_signet_id_different_keys() {
        let pk1 = [0x01u8; 32];
        let pk2 = [0x02u8; 32];
        let id1 = signet_id_from_pubkey(&pk1);
        let id2 = signet_id_from_pubkey(&pk2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_signet_id_is_base58() {
        let pubkey = [0xABu8; 32];
        let id = signet_id_from_pubkey(&pubkey);
        // Base58 should only contain valid characters
        assert!(id.as_str().chars().all(|c| {
            matches!(c, '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z')
        }));
    }

    #[test]
    fn test_verify_signet_id() {
        let pubkey = [0x55u8; 32];
        let id = signet_id_from_pubkey(&pubkey);
        assert!(verify_signet_id(&id, &pubkey));
        assert!(!verify_signet_id(&id, &[0x66u8; 32]));
    }

    #[test]
    fn test_signet_id_length() {
        let pubkey = [0x99u8; 32];
        let id = signet_id_from_pubkey(&pubkey);
        // Base58 encoding of 20 bytes should be 27-28 chars
        assert!(id.as_str().len() >= 25 && id.as_str().len() <= 30);
    }
}
