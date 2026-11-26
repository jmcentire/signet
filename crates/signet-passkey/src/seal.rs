//! Signed, then sealed, messages between two paired devices.
//!
//! The sender signs the exact payload bytes together with a domain and the
//! recipient's fingerprint, so a signed message cannot be re-sealed to someone
//! else. The result is sealed to the recipient with HPKE. A relay that carries
//! the envelope sees the pairing id, the message kind and ciphertext.
use crate::keys::{IdentityKeys, PublicIdentity};
use crate::{b64, transcript, unb64, PasskeyError, PROTOCOL_VERSION};
use sha2::{Digest, Sha256};

/// Which of the two messages an envelope carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    Request,
    Response,
}

impl MessageKind {
    fn domain(self) -> &'static str {
        match self {
            Self::Request => "signet.passkey.request.v1",
            Self::Response => "signet.passkey.response.v1",
        }
    }
}

/// What travels through the relay.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub v: u8,
    pub pairing_id: String,
    pub kind: MessageKind,
    /// HPKE encapsulated key, base64url.
    pub enc: String,
    /// HPKE ciphertext, base64url.
    pub ct: String,
}

impl Envelope {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PasskeyError> {
        let envelope: Self =
            serde_json::from_slice(bytes).map_err(|_| PasskeyError::Malformed("envelope"))?;
        if envelope.v != PROTOCOL_VERSION {
            return Err(PasskeyError::Unsupported("protocol version"));
        }
        Ok(envelope)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed {
    payload: String,
    sig: String,
}

fn info(
    kind: MessageKind,
    pairing_id: &str,
    sender: &PublicIdentity,
    to: &PublicIdentity,
) -> Vec<u8> {
    transcript(&[
        b"signet.passkey.hpke.v1",
        kind.domain().as_bytes(),
        pairing_id.as_bytes(),
        sender.fingerprint().as_bytes(),
        to.fingerprint().as_bytes(),
    ])
}

fn aad(kind: MessageKind, pairing_id: &str) -> Vec<u8> {
    transcript(&[
        &[PROTOCOL_VERSION],
        kind.domain().as_bytes(),
        pairing_id.as_bytes(),
    ])
}

fn signing_bytes(kind: MessageKind, recipient: &PublicIdentity, payload: &[u8]) -> Vec<u8> {
    [
        kind.domain().as_bytes(),
        &[0],
        recipient.fingerprint().as_bytes(),
        &[0],
        payload,
    ]
    .concat()
}

/// SHA-256 of the exact payload bytes that were signed, hex. A response names
/// the request it answers by this digest.
pub fn payload_digest(payload: &[u8]) -> String {
    hex::encode(Sha256::digest(payload))
}

/// Sign `payload` as `sender`, seal it to `recipient`, and return envelope bytes.
pub fn seal_signed(
    sender: &dyn IdentityKeys,
    recipient: &PublicIdentity,
    pairing_id: &str,
    kind: MessageKind,
    payload: &[u8],
) -> Result<Vec<u8>, PasskeyError> {
    let signature = sender.sign(&signing_bytes(kind, recipient, payload))?;
    let signed = serde_json::to_vec(&Signed {
        payload: b64(payload),
        sig: b64(&signature),
    })
    .map_err(|_| PasskeyError::Malformed("signed message"))?;
    let (enc, ct) = recipient.seal(
        &info(kind, pairing_id, &sender.public(), recipient),
        &aad(kind, pairing_id),
        &signed,
    )?;
    serde_json::to_vec(&Envelope {
        v: PROTOCOL_VERSION,
        pairing_id: pairing_id.to_owned(),
        kind,
        enc: b64(&enc),
        ct: b64(&ct),
    })
    .map_err(|_| PasskeyError::Malformed("envelope"))
}

/// Open an envelope as `recipient` and verify it was signed by `sender` for
/// this recipient. Returns the exact payload bytes that were signed.
pub fn open_signed(
    recipient: &dyn IdentityKeys,
    sender: &PublicIdentity,
    envelope: &Envelope,
    expected: MessageKind,
) -> Result<Vec<u8>, PasskeyError> {
    if envelope.kind != expected {
        return Err(PasskeyError::Malformed("message kind"));
    }
    let me = recipient.public();
    let signed = recipient.open(
        &unb64(&envelope.enc)?,
        &info(expected, &envelope.pairing_id, sender, &me),
        &aad(expected, &envelope.pairing_id),
        &unb64(&envelope.ct)?,
    )?;
    let signed: Signed =
        serde_json::from_slice(&signed).map_err(|_| PasskeyError::Malformed("signed message"))?;
    let payload = unb64(&signed.payload)?;
    sender.verify(
        &signing_bytes(expected, &me, &payload),
        &unb64(&signed.sig)?,
    )?;
    Ok(payload)
}
