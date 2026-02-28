//! Passkey/FIDO2 support for hardware-backed Ed25519 root keys.
//!
//! This module provides a `PasskeySigner` that wraps a FIDO2/WebAuthn credential
//! as a `Signer` implementation. The private key never leaves the authenticator.
//!
//! Feature-gated behind the `passkey` feature flag.
//!
//! Current implementation provides:
//! - `PasskeySigner` struct implementing `signet_core::Signer`
//! - `PasskeyAuthenticator` trait for abstracting authenticator access
//! - `MockAuthenticator` for testing
//!
//! Real authenticator backends (USB HID, platform API) can be wired in
//! by implementing `PasskeyAuthenticator`.

use crate::error::VaultError;
use signet_core::{SignetResult, Signer};
use std::sync::Arc;

/// Trait for abstracting FIDO2 authenticator access.
/// Implementations handle the platform-specific details of talking to
/// hardware tokens or platform authenticators.
pub trait PasskeyAuthenticator: Send + Sync {
    /// Sign a message using the credential's private key.
    /// This may block while waiting for user interaction (tap, biometric).
    fn sign(&self, credential_id: &[u8], message: &[u8]) -> Result<[u8; 64], VaultError>;

    /// Get the public key associated with a credential.
    fn public_key(&self, credential_id: &[u8]) -> Result<[u8; 32], VaultError>;

    /// Register a new credential.
    /// Returns (credential_id, public_key).
    fn register(&self, rp_id: &str, user_id: &[u8]) -> Result<(Vec<u8>, [u8; 32]), VaultError>;
}

/// Wraps a FIDO2/WebAuthn credential as a Signer implementation.
/// The private key never leaves the authenticator hardware.
pub struct PasskeySigner {
    /// Opaque credential identifier from the authenticator.
    pub credential_id: Vec<u8>,
    /// Ed25519 public key extracted from the COSE key at registration.
    pub public_key: [u8; 32],
    /// Authenticator backend.
    authenticator: Arc<dyn PasskeyAuthenticator>,
}

impl PasskeySigner {
    /// Create a PasskeySigner from existing credential data and an authenticator.
    pub fn new(
        credential_id: Vec<u8>,
        public_key: [u8; 32],
        authenticator: Arc<dyn PasskeyAuthenticator>,
    ) -> Self {
        Self {
            credential_id,
            public_key,
            authenticator,
        }
    }

    /// Register a new passkey and return a PasskeySigner.
    pub fn register(
        rp_id: &str,
        user_id: &[u8],
        authenticator: Arc<dyn PasskeyAuthenticator>,
    ) -> Result<Self, VaultError> {
        let (credential_id, public_key) = authenticator.register(rp_id, user_id)?;
        Ok(Self {
            credential_id,
            public_key,
            authenticator,
        })
    }
}

impl Signer for PasskeySigner {
    fn sign_ed25519(&self, message: &[u8]) -> SignetResult<[u8; 64]> {
        self.authenticator
            .sign(&self.credential_id, message)
            .map_err(|e| signet_core::SignetError::Vault(format!("passkey sign failed: {}", e)))
    }

    fn public_key_ed25519(&self) -> [u8; 32] {
        self.public_key
    }
}

/// Mock authenticator for testing. Uses an in-memory Ed25519 keypair
/// that simulates a hardware-backed key.
pub struct MockAuthenticator {
    signing_key_bytes: [u8; 32],
}

impl MockAuthenticator {
    /// Create a mock authenticator with a deterministic key.
    pub fn new(key_seed: [u8; 32]) -> Self {
        Self {
            signing_key_bytes: key_seed,
        }
    }
}

impl PasskeyAuthenticator for MockAuthenticator {
    fn sign(&self, _credential_id: &[u8], message: &[u8]) -> Result<[u8; 64], VaultError> {
        use ed25519_dalek::{Signer as _, SigningKey};
        let signing_key = SigningKey::from_bytes(&self.signing_key_bytes);
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes())
    }

    fn public_key(&self, _credential_id: &[u8]) -> Result<[u8; 32], VaultError> {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&self.signing_key_bytes);
        Ok(signing_key.verifying_key().to_bytes())
    }

    fn register(&self, _rp_id: &str, user_id: &[u8]) -> Result<(Vec<u8>, [u8; 32]), VaultError> {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&self.signing_key_bytes);
        let public_key = signing_key.verifying_key().to_bytes();
        // Credential ID is derived from user_id for determinism in tests
        let credential_id = user_id.to_vec();
        Ok((credential_id, public_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passkey_signer_implements_signer_trait() {
        let authenticator = Arc::new(MockAuthenticator::new([0x42; 32]));
        let signer = PasskeySigner::register("signet.tools", b"user1", authenticator).unwrap();

        // Verify it implements Signer
        let _: &dyn Signer = &signer;
    }

    #[test]
    fn test_mock_sign_and_verify_roundtrip() {
        let authenticator = Arc::new(MockAuthenticator::new([0x42; 32]));
        let signer = PasskeySigner::register("signet.tools", b"user1", authenticator).unwrap();

        let message = b"test message";
        let signature = signer.sign_ed25519(message).unwrap();

        // Verify with ed25519-dalek
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let verifying_key = VerifyingKey::from_bytes(&signer.public_key).unwrap();
        let sig = Signature::from_bytes(&signature);
        assert!(verifying_key.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_public_key_matches_registered() {
        let authenticator = Arc::new(MockAuthenticator::new([0x42; 32]));
        let public_key_direct = authenticator.public_key(b"any").unwrap();
        let signer = PasskeySigner::register(
            "signet.tools",
            b"user1",
            authenticator.clone(),
        )
        .unwrap();
        assert_eq!(signer.public_key_ed25519(), public_key_direct);
    }

    #[test]
    fn test_credential_id_preserved() {
        let authenticator = Arc::new(MockAuthenticator::new([0x42; 32]));
        let signer = PasskeySigner::register(
            "signet.tools",
            b"user_abc",
            authenticator,
        )
        .unwrap();
        assert_eq!(signer.credential_id, b"user_abc".to_vec());
    }

    #[test]
    fn test_different_keys_produce_different_signatures() {
        let auth1 = Arc::new(MockAuthenticator::new([0x01; 32]));
        let auth2 = Arc::new(MockAuthenticator::new([0x02; 32]));

        let signer1 = PasskeySigner::register("signet.tools", b"u1", auth1).unwrap();
        let signer2 = PasskeySigner::register("signet.tools", b"u2", auth2).unwrap();

        let message = b"same message";
        let sig1 = signer1.sign_ed25519(message).unwrap();
        let sig2 = signer2.sign_ed25519(message).unwrap();

        assert_ne!(sig1, sig2);
        assert_ne!(signer1.public_key_ed25519(), signer2.public_key_ed25519());
    }
}
