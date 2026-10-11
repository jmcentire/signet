//! User-held asset encryption, independent of account/passkey recovery.
//! These client-side primitives never fetch, persist, escrow or recover keys.
//! A service must separately require fresh owner MFA for creating/replacing assets.
//! Decryption/key possession does not grant authority to execute an action.
use crate::error::{VaultError, VaultResult};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetCiphertext {
    pub schema: u32,
    pub asset_id: String,
    pub key_epoch: u64,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}
fn error() -> VaultError {
    VaultError::Decryption("asset key or authenticated envelope mismatch".into())
}
fn aad(asset_id: &str, epoch: u64) -> VaultResult<Vec<u8>> {
    if asset_id.len() != 64
        || !asset_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(error());
    }
    Ok([
        b"signet.asset-cipher.v1\0".as_slice(),
        asset_id.as_bytes(),
        &epoch.to_be_bytes(),
    ]
    .concat())
}
pub fn encrypt(
    key: &Zeroizing<[u8; 32]>,
    asset_id: &str,
    key_epoch: u64,
    plaintext: &[u8],
) -> VaultResult<AssetCiphertext> {
    let associated = aad(asset_id, key_epoch)?;
    let cipher = Aes256Gcm::new_from_slice(&**key).map_err(|_| error())?;
    let mut nonce = [0; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &associated,
            },
        )
        .map_err(|_| error())?;
    Ok(AssetCiphertext {
        schema: 1,
        asset_id: asset_id.into(),
        key_epoch,
        nonce,
        ciphertext,
    })
}
pub fn decrypt(
    key: &Zeroizing<[u8; 32]>,
    expected_asset: &str,
    expected_epoch: u64,
    envelope: &AssetCiphertext,
) -> VaultResult<Zeroizing<Vec<u8>>> {
    if envelope.schema != 1
        || envelope.asset_id != expected_asset
        || envelope.key_epoch != expected_epoch
    {
        return Err(error());
    }
    let associated = aad(expected_asset, expected_epoch)?;
    let cipher = Aes256Gcm::new_from_slice(&**key).map_err(|_| error())?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&envelope.nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: &associated,
            },
        )
        .map_err(|_| error())?;
    Ok(Zeroizing::new(plaintext))
}
/// Prepare immutable replacement ciphertext. The old key is required to decrypt.
/// Keep the old key locally until the new ciphertext's head CAS is confirmed.
/// Never destroy the old working version before committing the replacement.
/// Old retained/copied ciphertext still decrypts with the old key: rotation cannot
/// retroactively erase copies. No key is included in the returned envelope.
pub fn rotate(
    current_key: &Zeroizing<[u8; 32]>,
    new_key: &Zeroizing<[u8; 32]>,
    expected_asset: &str,
    expected_epoch: u64,
    envelope: &AssetCiphertext,
) -> VaultResult<AssetCiphertext> {
    let plaintext = decrypt(current_key, expected_asset, expected_epoch, envelope)?;
    let epoch = expected_epoch.checked_add(1).ok_or_else(error)?;
    encrypt(new_key, expected_asset, epoch, &plaintext)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn key() -> Zeroizing<[u8; 32]> {
        let mut key = Zeroizing::new([0; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *key);
        key
    }
    #[test]
    fn rotation_requires_current_key_and_keeps_old_copy_until_explicit_commit() {
        let current = key();
        let next = key();
        let wrong = key();
        let id = "a".repeat(64);
        let old = encrypt(&current, &id, 1, b"synthetic credential only").unwrap();
        assert!(rotate(&wrong, &next, &id, 1, &old).is_err());
        let replacement = rotate(&current, &next, &id, 1, &old).unwrap();
        assert_eq!(
            &*decrypt(&next, &id, 2, &replacement).unwrap(),
            b"synthetic credential only"
        );
        assert!(decrypt(&current, &id, 2, &replacement).is_err());
        assert!(decrypt(&next, &id, 1, &old).is_err());
        assert!(decrypt(&current, &id, 1, &old).is_ok()); // interrupted upload leaves current version usable
    }
    #[test]
    fn wrong_key_identity_epoch_and_modified_ciphertext_fail_closed() {
        let key = key();
        let id = "b".repeat(64);
        let mut envelope = encrypt(&key, &id, 7, b"synthetic").unwrap();
        assert!(decrypt(&key, &"c".repeat(64), 7, &envelope).is_err());
        assert!(decrypt(&key, &id, 8, &envelope).is_err());
        envelope.ciphertext[0] ^= 1;
        assert!(decrypt(&key, &id, 7, &envelope).is_err());
    }
}
