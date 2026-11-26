//! Key custody boundaries.
//!
//! Every key in this subsystem is P-256, the curve that phone and laptop secure
//! hardware hold. The traits are cut at the operations that hardware can perform
//! without releasing a key: sign, and open a sealed message.
use crate::{b64, random_bytes, unb64, PasskeyError};
use hpke::{aead::AesGcm256, kdf::HkdfSha256, kem::DhP256HkdfSha256, Deserializable, Serializable};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

type Kem = DhP256HkdfSha256;
type KemPrivate = <Kem as hpke::Kem>::PrivateKey;
type KemPublic = <Kem as hpke::Kem>::PublicKey;
type KemEncapped = <Kem as hpke::Kem>::EncappedKey;

/// The public half of a device identity: one key to verify its signatures and
/// one to seal messages to it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIdentity {
    /// SEC1 compressed P-256 point, base64url.
    pub signing: String,
    /// SEC1 uncompressed P-256 point, base64url (the HPKE public key encoding).
    pub sealing: String,
}

impl PublicIdentity {
    /// Short stable name for this identity, safe to show to a person.
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(crate::transcript(&[
            b"signet.passkey.identity.v1",
            self.signing.as_bytes(),
            self.sealing.as_bytes(),
        ]));
        hex::encode(&digest[..16])
    }

    /// Verify a 64-byte `r || s` signature made by [`IdentityKeys::sign`].
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), PasskeyError> {
        let key = VerifyingKey::from_sec1_bytes(&unb64(&self.signing)?)
            .map_err(|_| PasskeyError::Malformed("signing key"))?;
        let signature = Signature::from_slice(signature).map_err(|_| PasskeyError::BadSignature)?;
        key.verify(message, &signature)
            .map_err(|_| PasskeyError::BadSignature)
    }

    /// Seal `plaintext` so only this identity can open it (HPKE base mode,
    /// DHKEM P-256 / HKDF-SHA256 / AES-256-GCM). Returns the encapsulated key
    /// and the ciphertext.
    pub fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), PasskeyError> {
        let public = KemPublic::from_bytes(&unb64(&self.sealing)?)
            .map_err(|_| PasskeyError::Malformed("sealing key"))?;
        let (encapped, ciphertext) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, Kem>(
            &hpke::OpModeS::Base,
            &public,
            info,
            plaintext,
            aad,
        )
        .map_err(|_| PasskeyError::SealFailure)?;
        Ok((encapped.to_bytes().to_vec(), ciphertext))
    }
}

/// A device's own identity keys. A phone implements this over its secure
/// hardware; private keys never cross this boundary.
pub trait IdentityKeys {
    fn public(&self) -> PublicIdentity;
    /// ECDSA P-256 over SHA-256 of `message`, as 64 bytes `r || s`.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PasskeyError>;
    /// Open a message sealed with [`PublicIdentity::seal`].
    fn open(
        &self,
        encapped_key: &[u8],
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, PasskeyError>;
}

fn random_signing_key() -> SigningKey {
    loop {
        // A uniformly random 32-byte string is a valid scalar with overwhelming
        // probability; retry on the rest.
        if let Ok(key) = SigningKey::from_slice(&random_bytes::<32>()) {
            return key;
        }
    }
}

/// In-memory identity keys for tests and the reference flow. No hardware
/// binding: anything that can read this process can copy the keys.
pub struct SoftwareIdentity {
    signing: SigningKey,
    sealing: KemPrivate,
    sealing_public: KemPublic,
}

impl SoftwareIdentity {
    pub fn generate() -> Self {
        let (sealing, sealing_public) = <Kem as hpke::Kem>::gen_keypair();
        Self {
            signing: random_signing_key(),
            sealing,
            sealing_public,
        }
    }
}

impl IdentityKeys for SoftwareIdentity {
    fn public(&self) -> PublicIdentity {
        PublicIdentity {
            signing: b64(self.signing.verifying_key().to_sec1_point(true).as_bytes()),
            sealing: b64(&self.sealing_public.to_bytes()),
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PasskeyError> {
        let signature: Signature = self
            .signing
            .try_sign(message)
            .map_err(|_| PasskeyError::Key)?;
        Ok(signature.to_bytes().to_vec())
    }

    fn open(
        &self,
        encapped_key: &[u8],
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, PasskeyError> {
        let encapped =
            KemEncapped::from_bytes(encapped_key).map_err(|_| PasskeyError::SealFailure)?;
        hpke::single_shot_open::<AesGcm256, HkdfSha256, Kem>(
            &hpke::OpModeR::Base,
            &self.sealing,
            &encapped,
            info,
            ciphertext,
            aad,
        )
        .map_err(|_| PasskeyError::SealFailure)
    }
}

/// How a passkey's private key is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyClass {
    /// Created inside secure hardware and never exportable. A lost device loses it.
    HardwareBound,
    /// An ordinary key encrypted under a hardware key. Can be backed up and
    /// exported. Every imported passkey is this class.
    Portable,
}

/// A newly created passkey key pair, as seen from outside the key store.
#[derive(Debug, Clone)]
pub struct GeneratedKey {
    /// Opaque reference the store accepts in [`CredentialKeys::sign`].
    pub handle: Vec<u8>,
    /// SEC1 uncompressed public key (65 bytes).
    pub public_sec1: Vec<u8>,
}

/// Where passkey private keys live. A phone implements this over its secure
/// hardware.
pub trait CredentialKeys {
    fn generate(&mut self, class: KeyClass) -> Result<GeneratedKey, PasskeyError>;
    /// ECDSA P-256 over SHA-256 of `message`, ASN.1 DER, as WebAuthn ES256 requires.
    fn sign(&self, handle: &[u8], message: &[u8]) -> Result<Vec<u8>, PasskeyError>;
}

/// In-memory passkey keys for tests and the reference flow.
///
/// This type cannot provide hardware binding. It records nothing about the
/// requested [`KeyClass`]; both classes are plain keys in process memory.
#[derive(Default)]
pub struct SoftwareCredentialKeys {
    keys: HashMap<Vec<u8>, SigningKey>,
}

impl SoftwareCredentialKeys {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CredentialKeys for SoftwareCredentialKeys {
    fn generate(&mut self, _class: KeyClass) -> Result<GeneratedKey, PasskeyError> {
        let key = random_signing_key();
        let handle = random_bytes::<16>().to_vec();
        let public_sec1 = key.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        self.keys.insert(handle.clone(), key);
        Ok(GeneratedKey {
            handle,
            public_sec1,
        })
    }

    fn sign(&self, handle: &[u8], message: &[u8]) -> Result<Vec<u8>, PasskeyError> {
        let key = self.keys.get(handle).ok_or(PasskeyError::Key)?;
        let signature: Signature = key.try_sign(message).map_err(|_| PasskeyError::Key)?;
        Ok(signature.to_der().as_bytes().to_vec())
    }
}
