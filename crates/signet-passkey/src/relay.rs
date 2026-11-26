//! What both devices say to the relay.
//!
//! The relay is a mailbox. It holds sealed envelopes for a few minutes and
//! hands them to the device they are addressed to. It is not trusted with
//! content: every envelope is signed by its sender and sealed to its recipient
//! ([`crate::seal`]), so a relay can drop or delay a message and can see who
//! talks to whom and when, and nothing else.
//!
//! A device proves which mailbox is its own by signing each HTTP request with
//! its identity key. Mailboxes are named by identity fingerprint, and the
//! request carries the public keys the fingerprint is computed from, so the
//! relay needs no account database. A device also tells the relay which
//! fingerprints may leave messages for it, namely its paired devices, so
//! strangers cannot fill its mailbox.
//!
//! This module defines the request signature, the JSON bodies and the paths.
//! The server is in the `signet-passkey-relay` crate.
use crate::keys::{IdentityKeys, PublicIdentity};
use crate::{b64, random_bytes, transcript, unb64, PasskeyError, PROTOCOL_VERSION};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// How far a signed relay request's timestamp may be from the relay's clock.
pub const AUTH_WINDOW_SECS: i64 = 60;
/// Longest a relay keeps a message when the sender does not say.
pub const DEFAULT_MESSAGE_TTL_SECS: i64 = 150;
/// The authorization scheme name in the `Authorization` header.
pub const AUTH_SCHEME: &str = "Signet-Relay";

const AUTH_DOMAIN: &[u8] = b"signet.passkey.relay.auth.v1";
const SLOT_DOMAIN: &[u8] = b"signet.passkey.relay.slot.v1";
const RENDEZVOUS_DOMAIN: &[u8] = b"signet.passkey.relay.rendezvous.v1";

/// Encode bytes the way every relay body does (base64url, no padding).
pub fn encode(bytes: &[u8]) -> String {
    b64(bytes)
}

/// Decode [`encode`].
pub fn decode(text: &str) -> Result<Vec<u8>, PasskeyError> {
    unb64(text)
}

/// Whether `text` is shaped like a mailbox name, slot or rendezvous id:
/// 32 lowercase hexadecimal characters.
pub fn is_id(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The slot the response to a request is left in, derived from the request
/// envelope's bytes.
///
/// A computer may have several requests in flight, each waited on by a
/// different process. The phone leaves each response in the slot of the
/// request it answers, and each waiter reads only its own slot. Both sides
/// compute the slot from the envelope they hold, so nothing the relay says
/// decides where a response goes.
pub fn reply_slot(request_envelope: &[u8]) -> String {
    let digest = Sha256::digest(transcript(&[SLOT_DOMAIN, request_envelope]));
    hex::encode(&digest[..16])
}

/// Where the reply to a pairing ticket is left, derived from the ticket's
/// one-time secret.
pub fn rendezvous_id(ticket_secret: &[u8]) -> String {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(ticket_secret).expect("any key length works");
    mac.update(RENDEZVOUS_DOMAIN);
    hex::encode(&mac.finalize().into_bytes()[..16])
}

fn is_loopback(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(name) => *name == "localhost",
        url::Host::Ipv4(address) => address.is_loopback(),
        url::Host::Ipv6(address) => address.is_loopback(),
    }
}

/// Check a relay address and return its normal form: scheme, host, port if not
/// the default, and any path prefix, without a trailing slash.
///
/// `https` is required, except that plain `http` is accepted for a relay on
/// this same machine, which is how the tests run one.
pub fn normalize_relay_url(address: &str) -> Result<String, PasskeyError> {
    let url = url::Url::parse(address.trim()).map_err(|_| PasskeyError::Relay("address"))?;
    let host = url.host().ok_or(PasskeyError::Relay("address"))?;
    match url.scheme() {
        "https" => {}
        "http" if is_loopback(&host) => {}
        "http" => return Err(PasskeyError::Relay("plain http is only for this machine")),
        _ => return Err(PasskeyError::Relay("address")),
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(PasskeyError::Relay("address"));
    }
    let mut normal = format!("{}://{}", url.scheme(), host);
    if let Some(port) = url.port() {
        normal.push_str(&format!(":{port}"));
    }
    normal.push_str(url.path().trim_end_matches('/'));
    Ok(normal)
}

/// Path for leaving a message in `recipient`'s mailbox.
pub fn deposit_path(recipient: &str, slot: Option<&str>) -> String {
    match slot {
        Some(slot) => format!("/v1/mailbox/{recipient}/messages?slot={slot}"),
        None => format!("/v1/mailbox/{recipient}/messages"),
    }
}

/// Path for reading one's own mailbox.
pub fn poll_path(owner: &str) -> String {
    format!("/v1/mailbox/{owner}/poll")
}

/// Path for a pairing reply.
pub fn rendezvous_path(id: &str) -> String {
    format!("/v1/rendezvous/{id}")
}

/// Body of a mailbox read.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollRequest {
    /// Fingerprints allowed to leave messages for this device. Replaces the
    /// previous list. A device sends its paired devices on every read, so a
    /// relay that restarts relearns the list without keeping it on disk.
    pub peers: Vec<String>,
    /// Read only messages left in this slot. Absent: messages left in no slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<String>,
    /// How long the relay may hold the request open waiting for a message.
    #[serde(default)]
    pub wait_secs: u64,
    /// Messages received earlier, to delete. A message is offered again on
    /// every read until it is acknowledged or expires.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ack: Vec<String>,
}

/// One message as the relay hands it over.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayMessage {
    pub id: String,
    /// Fingerprint of the device that left it, as authenticated by the relay.
    /// Informational: the envelope's own signature is what a device checks.
    pub from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<String>,
    /// The envelope, [`encode`]d.
    pub body: String,
    pub expires_at: i64,
}

/// Reply to a mailbox read.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollResponse {
    pub messages: Vec<RelayMessage>,
}

/// Reply to leaving a message.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepositReceipt {
    pub id: String,
    pub expires_at: i64,
}

/// A signed relay request, as carried in the `Authorization` header.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayAuth {
    pub v: u8,
    pub identity: PublicIdentity,
    /// Unix seconds on the caller's clock.
    pub timestamp: i64,
    /// Random, base64url. A relay refuses a nonce it has already seen.
    pub nonce: String,
    /// Signature by `identity`, base64url.
    pub signature: String,
}

/// What a relay learns from a valid [`RelayAuth`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub fingerprint: String,
    pub nonce: String,
    pub timestamp: i64,
}

fn auth_transcript(
    audience: &str,
    method: &str,
    path_and_query: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
) -> Vec<u8> {
    transcript(&[
        AUTH_DOMAIN,
        audience.as_bytes(),
        method.as_bytes(),
        path_and_query.as_bytes(),
        timestamp.to_string().as_bytes(),
        nonce.as_bytes(),
        &Sha256::digest(body),
    ])
}

impl RelayAuth {
    /// Sign one HTTP request.
    ///
    /// `audience` is the relay's address in normal form. Binding it means a
    /// request made to one relay cannot be replayed at another.
    pub fn sign(
        identity: &dyn IdentityKeys,
        audience: &str,
        method: &str,
        path_and_query: &str,
        body: &[u8],
        now: i64,
    ) -> Result<Self, PasskeyError> {
        let nonce = b64(&random_bytes::<16>());
        let message = auth_transcript(audience, method, path_and_query, now, &nonce, body);
        Ok(Self {
            v: PROTOCOL_VERSION,
            identity: identity.public(),
            timestamp: now,
            nonce,
            signature: b64(&identity.sign(&message)?),
        })
    }

    /// The `Authorization` header value.
    pub fn to_header(&self) -> String {
        let json = serde_json::to_vec(self).expect("auth serializes");
        format!("{AUTH_SCHEME} {}", b64(&json))
    }

    /// Parse an `Authorization` header value.
    pub fn from_header(value: &str) -> Result<Self, PasskeyError> {
        let encoded = value
            .strip_prefix(AUTH_SCHEME)
            .and_then(|rest| rest.strip_prefix(' '))
            .ok_or(PasskeyError::Relay("authorization scheme"))?;
        if encoded.len() > 1024 {
            return Err(PasskeyError::Relay("authorization"));
        }
        let auth: Self = serde_json::from_slice(&unb64(encoded)?)
            .map_err(|_| PasskeyError::Relay("authorization"))?;
        if auth.v != PROTOCOL_VERSION {
            return Err(PasskeyError::Unsupported("protocol version"));
        }
        Ok(auth)
    }

    /// Check the signature against the request the relay actually received.
    ///
    /// Returns who is calling. The relay must also refuse a repeated
    /// `(fingerprint, nonce)` within the window; that state is the relay's.
    pub fn verify(
        &self,
        audiences: &[String],
        method: &str,
        path_and_query: &str,
        body: &[u8],
        now: i64,
    ) -> Result<Caller, PasskeyError> {
        if (now - self.timestamp).abs() > AUTH_WINDOW_SECS {
            return Err(PasskeyError::Expired);
        }
        if unb64(&self.nonce)?.len() != 16 {
            return Err(PasskeyError::Relay("nonce"));
        }
        let signature = unb64(&self.signature)?;
        // The caller signed exactly one audience; accept whichever of this
        // relay's names it was.
        let accepted = audiences.iter().any(|audience| {
            let message = auth_transcript(
                audience,
                method,
                path_and_query,
                self.timestamp,
                &self.nonce,
                body,
            );
            self.identity.verify(&message, &signature).is_ok()
        });
        if !accepted {
            return Err(PasskeyError::BadSignature);
        }
        Ok(Caller {
            fingerprint: self.identity.fingerprint(),
            nonce: self.nonce.clone(),
            timestamp: self.timestamp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SoftwareIdentity;

    const RELAY: &str = "https://relay.example";

    #[test]
    fn relay_addresses_are_normalized_and_restricted() {
        assert_eq!(
            normalize_relay_url("https://Relay.Example/").unwrap(),
            "https://relay.example"
        );
        assert_eq!(
            normalize_relay_url("https://relay.example:8443/signet/").unwrap(),
            "https://relay.example:8443/signet"
        );
        assert_eq!(
            normalize_relay_url("http://127.0.0.1:8787").unwrap(),
            "http://127.0.0.1:8787"
        );
        assert_eq!(
            normalize_relay_url("http://localhost:8787/").unwrap(),
            "http://localhost:8787"
        );
        assert_eq!(
            normalize_relay_url("http://[::1]:8787").unwrap(),
            "http://[::1]:8787"
        );
        for bad in [
            "http://relay.example",
            "http://192.168.1.10:8787",
            "http://localhost.example",
            "ftp://relay.example",
            "https://user:pw@relay.example",
            "https://relay.example/?x=1",
            "https://relay.example/#x",
            "relay.example",
            "",
        ] {
            assert!(normalize_relay_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_signed_request_verifies_only_as_sent() {
        let device = SoftwareIdentity::generate();
        let fingerprint = device.public().fingerprint();
        let path = poll_path(&fingerprint);
        let auth = RelayAuth::sign(&device, RELAY, "POST", &path, b"{}", 1_000).unwrap();
        let auth = RelayAuth::from_header(&auth.to_header()).unwrap();
        let audiences = vec![RELAY.to_owned()];
        let caller = auth
            .verify(&audiences, "POST", &path, b"{}", 1_010)
            .unwrap();
        assert_eq!(caller.fingerprint, fingerprint);

        let other = vec!["https://other.example".to_owned()];
        assert_eq!(
            auth.verify(&other, "POST", &path, b"{}", 1_010),
            Err(PasskeyError::BadSignature)
        );
        assert_eq!(
            auth.verify(&audiences, "GET", &path, b"{}", 1_010),
            Err(PasskeyError::BadSignature)
        );
        assert_eq!(
            auth.verify(&audiences, "POST", "/v1/mailbox/x/poll", b"{}", 1_010),
            Err(PasskeyError::BadSignature)
        );
        assert_eq!(
            auth.verify(&audiences, "POST", &path, b"{ }", 1_010),
            Err(PasskeyError::BadSignature)
        );
        assert_eq!(
            auth.verify(
                &audiences,
                "POST",
                &path,
                b"{}",
                1_000 + AUTH_WINDOW_SECS + 1
            ),
            Err(PasskeyError::Expired)
        );
        assert_eq!(
            auth.verify(
                &audiences,
                "POST",
                &path,
                b"{}",
                1_000 - AUTH_WINDOW_SECS - 1
            ),
            Err(PasskeyError::Expired)
        );

        // Another device cannot claim this one's mailbox: the fingerprint is
        // computed from the keys that signed.
        let stranger = SoftwareIdentity::generate();
        let forged = RelayAuth::sign(&stranger, RELAY, "POST", &path, b"{}", 1_000).unwrap();
        let caller = forged
            .verify(&audiences, "POST", &path, b"{}", 1_000)
            .unwrap();
        assert_ne!(caller.fingerprint, fingerprint);
        let mut swapped = forged.clone();
        swapped.identity = device.public();
        assert_eq!(
            swapped.verify(&audiences, "POST", &path, b"{}", 1_000),
            Err(PasskeyError::BadSignature)
        );
    }

    #[test]
    fn ids_are_derived_and_well_formed() {
        let slot = reply_slot(b"envelope-1");
        assert!(is_id(&slot));
        assert_ne!(slot, reply_slot(b"envelope-2"));
        let rendezvous = rendezvous_id(&[7u8; 32]);
        assert!(is_id(&rendezvous));
        assert_ne!(rendezvous, rendezvous_id(&[8u8; 32]));
        assert!(!is_id("ABCDEF0123456789abcdef0123456789"));
        assert!(!is_id("0123"));
        assert!(!is_id("../../../../../../../../../../.."));
    }

    #[test]
    fn a_stored_identity_is_the_same_device() {
        let device = SoftwareIdentity::generate();
        let again = SoftwareIdentity::from_secret_bytes(&device.to_secret_bytes()).unwrap();
        assert_eq!(device.public(), again.public());
        let (enc, ct) = device.public().seal(b"info", b"aad", b"hello").unwrap();
        assert_eq!(again.open(&enc, b"info", b"aad", &ct).unwrap(), b"hello");
        assert!(SoftwareIdentity::from_secret_bytes(&[0u8; 64]).is_err());
        assert!(SoftwareIdentity::from_secret_bytes(&[1u8; 63]).is_err());
    }
}
