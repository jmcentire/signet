//! One-time pairing between a phone and a computer.
//!
//! Pairing is what replaces Bluetooth proximity: a phone answers only machines
//! its owner has enrolled. One side issues a ticket and shows it as a QR code or
//! a string. The other side reads it and replies. The ticket carries a 256-bit
//! one-time secret, so whoever answers must have seen the ticket; the reply is
//! authenticated with that secret and signed by the answering device's key.
//!
//! The ticket must travel over a channel the owner trusts: a screen they are
//! looking at, or a session they already control. Anyone who sees a live ticket
//! can pair in the owner's place until it is used or expires.
use crate::keys::{IdentityKeys, PublicIdentity};
use crate::{
    b64, random_bytes, transcript, unb64, PasskeyError, PAIRING_TTL_SECS, PROTOCOL_VERSION,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const TICKET_PREFIX: &str = "signet-pair:";
const MAX_NAME: usize = 60;

/// Which side of the protocol a device plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// The phone: holds passkeys, decides and signs.
    Authenticator,
    /// The computer: forwards requests and returns results.
    Requester,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Authenticator => "authenticator",
            Self::Requester => "requester",
        }
    }
}

/// What one device remembers about the other after pairing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pairing {
    pub id: String,
    pub peer: PublicIdentity,
    /// The name the peer gave itself. Shown to the owner; not an identity.
    pub peer_name: String,
    pub peer_role: Role,
    pub created_at: i64,
    pub revoked: bool,
    /// The relay both devices agreed to use when they paired, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
}

impl Pairing {
    /// Six digits both devices show after pairing, for the owner to compare.
    ///
    /// A ticket proves that whoever answered saw it; it does not prove they
    /// were the owner's device. If someone else read the ticket and answered
    /// first, the two devices the owner is holding show different codes, and
    /// the pairing should be revoked.
    pub fn confirmation_code(&self, own: &PublicIdentity) -> String {
        let (requester, authenticator) = match self.peer_role {
            Role::Requester => (&self.peer, own),
            Role::Authenticator => (own, &self.peer),
        };
        let digest = Sha256::digest(transcript(&[
            b"signet.passkey.pairing.confirm.v1",
            self.id.as_bytes(),
            requester.signing.as_bytes(),
            requester.sealing.as_bytes(),
            authenticator.signing.as_bytes(),
            authenticator.sealing.as_bytes(),
        ]));
        let number = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        format!("{:06}", number % 1_000_000)
    }
}

/// The ticket one device shows and the other reads.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingTicket {
    pub v: u8,
    pub pairing_id: String,
    /// One-time secret, base64url.
    pub secret: String,
    pub issuer: PublicIdentity,
    pub issuer_name: String,
    pub issuer_role: Role,
    pub expires_at: i64,
    /// Where the reply, and later traffic, should be sent. The relay is not
    /// trusted with content; see [`crate::relay`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
}

impl PairingTicket {
    /// The string form shown to the other device.
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).expect("ticket serializes");
        format!("{TICKET_PREFIX}{}", b64(&json))
    }

    pub fn decode(text: &str) -> Result<Self, PasskeyError> {
        let body = text
            .trim()
            .strip_prefix(TICKET_PREFIX)
            .ok_or(PasskeyError::Pairing("not a pairing ticket"))?;
        let ticket: Self = serde_json::from_slice(&unb64(body)?)
            .map_err(|_| PasskeyError::Pairing("ticket contents"))?;
        if ticket.v != PROTOCOL_VERSION {
            return Err(PasskeyError::Unsupported("protocol version"));
        }
        if let Some(relay) = &ticket.relay {
            if crate::relay::normalize_relay_url(relay)? != *relay {
                return Err(PasskeyError::Pairing("relay address"));
            }
        }
        Ok(ticket)
    }

    /// Where on the relay the reply to this ticket is left. Derived from the
    /// one-time secret, so only a device that read the ticket can find it.
    pub fn rendezvous_id(&self) -> Result<String, PasskeyError> {
        let mut secret = unb64(&self.secret)?;
        let id = crate::relay::rendezvous_id(&secret);
        secret.zeroize();
        Ok(id)
    }
}

/// The reply to a ticket.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PairingAccept {
    v: u8,
    pairing_id: String,
    acceptor: PublicIdentity,
    acceptor_name: String,
    acceptor_role: Role,
    /// HMAC-SHA256 under the ticket secret, hex.
    mac: String,
    /// Acceptor's signature over the same transcript, base64url.
    sig: String,
}

/// The issuing device's half-finished pairing. Completing it consumes it, so a
/// ticket pairs at most one device.
pub struct PairingOffer {
    ticket: PairingTicket,
    secret: [u8; 32],
}

impl Drop for PairingOffer {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.ticket.secret.zeroize();
    }
}

fn valid_name(name: &str) -> bool {
    !name.trim().is_empty() && name.len() <= MAX_NAME && !name.chars().any(char::is_control)
}

fn accept_transcript(
    pairing_id: &str,
    issuer: &PublicIdentity,
    issuer_role: Role,
    acceptor: &PublicIdentity,
    acceptor_role: Role,
    acceptor_name: &str,
    relay: Option<&str>,
) -> Vec<u8> {
    transcript(&[
        b"signet.passkey.pairing.v1",
        pairing_id.as_bytes(),
        issuer.signing.as_bytes(),
        issuer.sealing.as_bytes(),
        issuer_role.as_str().as_bytes(),
        acceptor.signing.as_bytes(),
        acceptor.sealing.as_bytes(),
        acceptor_role.as_str().as_bytes(),
        acceptor_name.as_bytes(),
        // Both devices must have read the same relay address from the ticket.
        relay.unwrap_or("").as_bytes(),
    ])
}

fn mac(secret: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("any key length works");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Start pairing: create a ticket for the other device to read.
pub fn issue_ticket(
    identity: &dyn IdentityKeys,
    name: &str,
    role: Role,
    now: i64,
) -> Result<PairingOffer, PasskeyError> {
    if !valid_name(name) {
        return Err(PasskeyError::Pairing("device name"));
    }
    let secret = random_bytes::<32>();
    Ok(PairingOffer {
        ticket: PairingTicket {
            v: PROTOCOL_VERSION,
            pairing_id: b64(&random_bytes::<16>()),
            secret: b64(&secret),
            issuer: identity.public(),
            issuer_name: name.to_owned(),
            issuer_role: role,
            expires_at: now + PAIRING_TTL_SECS,
            relay: None,
        },
        secret,
    })
}

/// Read a ticket. Returns this device's record of the pairing and the reply to
/// send back to the issuer. The reply contains no secret and may cross an
/// untrusted relay.
pub fn accept_ticket(
    ticket: &str,
    identity: &dyn IdentityKeys,
    name: &str,
    role: Role,
    now: i64,
) -> Result<(Pairing, Vec<u8>), PasskeyError> {
    if !valid_name(name) {
        return Err(PasskeyError::Pairing("device name"));
    }
    let ticket = PairingTicket::decode(ticket)?;
    if now >= ticket.expires_at {
        return Err(PasskeyError::Pairing("ticket expired"));
    }
    if ticket.issuer_role == role {
        return Err(PasskeyError::Pairing("both devices have the same role"));
    }
    if !valid_name(&ticket.issuer_name) {
        return Err(PasskeyError::Pairing("device name"));
    }
    let mut secret = unb64(&ticket.secret)?;
    if secret.len() != 32 {
        return Err(PasskeyError::Pairing("ticket contents"));
    }
    let acceptor = identity.public();
    if acceptor == ticket.issuer {
        return Err(PasskeyError::Pairing("a device cannot pair with itself"));
    }
    let message = accept_transcript(
        &ticket.pairing_id,
        &ticket.issuer,
        ticket.issuer_role,
        &acceptor,
        role,
        name,
        ticket.relay.as_deref(),
    );
    let accept = PairingAccept {
        v: PROTOCOL_VERSION,
        pairing_id: ticket.pairing_id.clone(),
        acceptor,
        acceptor_name: name.to_owned(),
        acceptor_role: role,
        mac: hex::encode(mac(&secret, &message)),
        sig: b64(&identity.sign(&message)?),
    };
    secret.zeroize();
    let reply = serde_json::to_vec(&accept).map_err(|_| PasskeyError::Pairing("reply"))?;
    Ok((
        Pairing {
            id: ticket.pairing_id,
            peer: ticket.issuer,
            peer_name: ticket.issuer_name,
            peer_role: ticket.issuer_role,
            created_at: now,
            revoked: false,
            relay: ticket.relay,
        },
        reply,
    ))
}

impl PairingOffer {
    /// The ticket to show the other device.
    pub fn ticket(&self) -> &PairingTicket {
        &self.ticket
    }

    /// Name the relay the two devices will use. The address is checked and
    /// stored in its normal form.
    pub fn with_relay(mut self, relay: &str) -> Result<Self, PasskeyError> {
        self.ticket.relay = Some(crate::relay::normalize_relay_url(relay)?);
        Ok(self)
    }

    /// Finish pairing with the other device's reply. Consumes the offer whether
    /// or not the reply is accepted.
    pub fn complete(self, reply: &[u8], now: i64) -> Result<Pairing, PasskeyError> {
        if now >= self.ticket.expires_at {
            return Err(PasskeyError::Pairing("ticket expired"));
        }
        let accept: PairingAccept =
            serde_json::from_slice(reply).map_err(|_| PasskeyError::Pairing("reply"))?;
        if accept.v != PROTOCOL_VERSION {
            return Err(PasskeyError::Unsupported("protocol version"));
        }
        if accept.pairing_id != self.ticket.pairing_id {
            return Err(PasskeyError::Pairing("reply is for another ticket"));
        }
        if accept.acceptor_role == self.ticket.issuer_role {
            return Err(PasskeyError::Pairing("both devices have the same role"));
        }
        if !valid_name(&accept.acceptor_name) {
            return Err(PasskeyError::Pairing("device name"));
        }
        if accept.acceptor == self.ticket.issuer {
            return Err(PasskeyError::Pairing("a device cannot pair with itself"));
        }
        let message = accept_transcript(
            &self.ticket.pairing_id,
            &self.ticket.issuer,
            self.ticket.issuer_role,
            &accept.acceptor,
            accept.acceptor_role,
            &accept.acceptor_name,
            self.ticket.relay.as_deref(),
        );
        let expected = mac(&self.secret, &message);
        let supplied = hex::decode(&accept.mac).map_err(|_| PasskeyError::Pairing("reply"))?;
        if !bool::from(expected.ct_eq(&supplied)) {
            return Err(PasskeyError::Pairing("reply was not made from this ticket"));
        }
        accept
            .acceptor
            .verify(&message, &unb64(&accept.sig)?)
            .map_err(|_| PasskeyError::Pairing("reply signature"))?;
        Ok(Pairing {
            id: self.ticket.pairing_id.clone(),
            peer: accept.acceptor.clone(),
            peer_name: accept.acceptor_name.clone(),
            peer_role: accept.acceptor_role,
            created_at: now,
            revoked: false,
            relay: self.ticket.relay.clone(),
        })
    }
}
