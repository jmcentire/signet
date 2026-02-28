use crate::error::{VaultError, VaultResult};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

// AES-256-GCM envelope encryption.
//
// Each record is encrypted with its own Data Encryption Key (DEK).
// The DEK is derived from the key hierarchy — never stored directly.
// The nonce is randomly generated per-encryption and stored alongside the ciphertext.

const NONCE_SIZE: usize = 12; // AES-GCM standard nonce size

/// Encrypted envelope: nonce + ciphertext (includes GCM tag).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext: Vec<u8>,
}

/// Encrypt plaintext using AES-256-GCM with the given key.
pub fn encrypt(key: &Zeroizing<[u8; 32]>, plaintext: &[u8]) -> VaultResult<EncryptedEnvelope> {
    let cipher = Aes256Gcm::new_from_slice(&**key)
        .map_err(|e| VaultError::Encryption(format!("cipher init failed: {}", e)))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = AesNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| VaultError::Encryption(format!("encryption failed: {}", e)))?;

    Ok(EncryptedEnvelope {
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypt an encrypted envelope using AES-256-GCM with the given key.
pub fn decrypt(key: &Zeroizing<[u8; 32]>, envelope: &EncryptedEnvelope) -> VaultResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(&**key)
        .map_err(|e| VaultError::Decryption(format!("cipher init failed: {}", e)))?;

    let nonce = AesNonce::from_slice(&envelope.nonce);

    cipher
        .decrypt(nonce, envelope.ciphertext.as_ref())
        .map_err(|e| VaultError::Decryption(format!("decryption failed: {}", e)))
}

/// Encrypt and serialize a value to an envelope.
pub fn encrypt_value<T: Serialize>(
    key: &Zeroizing<[u8; 32]>,
    value: &T,
) -> VaultResult<EncryptedEnvelope> {
    let plaintext = serde_json::to_vec(value)
        .map_err(|e| VaultError::Serialization(format!("serialize failed: {}", e)))?;
    encrypt(key, &plaintext)
}

/// Decrypt an envelope and deserialize to a value.
pub fn decrypt_value<T: for<'de> Deserialize<'de>>(
    key: &Zeroizing<[u8; 32]>,
    envelope: &EncryptedEnvelope,
) -> VaultResult<T> {
    let plaintext = decrypt(key, envelope)?;
    serde_json::from_slice(&plaintext)
        .map_err(|e| VaultError::Serialization(format!("deserialize failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Zeroizing<[u8; 32]> {
        Zeroizing::new([0x42; 32])
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"hello, signet!";
        let envelope = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &envelope).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_nonces() {
        let key = test_key();
        let plaintext = b"same message";
        let e1 = encrypt(&key, plaintext).unwrap();
        let e2 = encrypt(&key, plaintext).unwrap();
        // Different nonces → different ciphertext
        assert_ne!(e1.nonce, e2.nonce);
        assert_ne!(e1.ciphertext, e2.ciphertext);
        // Both decrypt to same plaintext
        assert_eq!(decrypt(&key, &e1).unwrap(), plaintext);
        assert_eq!(decrypt(&key, &e2).unwrap(), plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = Zeroizing::new([0x42; 32]);
        let key2 = Zeroizing::new([0x43; 32]);
        let envelope = encrypt(&key1, b"secret data").unwrap();
        let result = decrypt(&key2, &envelope);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = test_key();
        let mut envelope = encrypt(&key, b"integrity check").unwrap();
        // Flip a bit in the ciphertext
        if let Some(byte) = envelope.ciphertext.first_mut() {
            *byte ^= 0x01;
        }
        let result = decrypt(&key, &envelope);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_value() {
        let key = test_key();
        let value = serde_json::json!({
            "name": "Alice",
            "age": 30,
            "tier": "Tier1"
        });
        let envelope = encrypt_value(&key, &value).unwrap();
        let decrypted: serde_json::Value = decrypt_value(&key, &envelope).unwrap();
        assert_eq!(value, decrypted);
    }

    #[test]
    fn test_envelope_serialization() {
        let key = test_key();
        let envelope = encrypt(&key, b"test").unwrap();
        let json = serde_json::to_string(&envelope).unwrap();
        let envelope2: EncryptedEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(envelope.nonce, envelope2.nonce);
        assert_eq!(envelope.ciphertext, envelope2.ciphertext);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = test_key();
        let envelope = encrypt(&key, b"").unwrap();
        let decrypted = decrypt(&key, &envelope).unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn test_large_plaintext() {
        let key = test_key();
        let plaintext = vec![0xAB; 1024 * 1024]; // 1MB
        let envelope = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &envelope).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
