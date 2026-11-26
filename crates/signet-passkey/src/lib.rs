//! Remote passkey approval: the phone signs, the computer relays.
//!
//! A computer that is asked for a passkey forwards the request to the owner's
//! phone. The phone shows the site and the machine, the owner approves with a
//! biometric, the phone signs, and the computer hands an ordinary WebAuthn
//! response back to the browser. The design, threat model and build order are
//! in `docs/remote-passkey.md`.
//!
//! This crate is the protocol core. It contains:
//!
//! - the two wire messages and their signed, sealed envelope ([`seal`]);
//! - the one-time pairing ceremony ([`pairing`]);
//! - the phone side, [`Authenticator`], and the computer side, [`Requester`];
//! - the site-binding check a WebAuthn client must perform ([`rp`]);
//! - WebAuthn byte encodings ([`webauthn`]).
//!
//! It also defines what both ends say to the store-and-forward relay
//! ([`relay`]). It does **not** contain a phone app, a browser or
//! operating-system integration, or the relay itself. [`SoftwareIdentity`] and [`SoftwareCredentialKeys`]
//! keep keys in process memory. They exist so the protocol can be exercised and
//! tested; they provide no hardware binding. A phone implementation supplies the
//! [`IdentityKeys`] and [`CredentialKeys`] traits from its secure hardware.
//!
//! Time is always passed in by the caller as Unix seconds, so every check is
//! deterministic under test.
#![forbid(unsafe_code)]

pub mod authenticator;
mod error;
pub mod keys;
pub mod message;
pub mod pairing;
pub mod relay;
pub mod requester;
pub mod rp;
pub mod seal;
pub mod webauthn;

pub use authenticator::{
    AccountView, Approval, Approver, Authenticator, OperationKind, RequestView, StoredCredential,
};
pub use error::PasskeyError;
pub use keys::{
    CredentialKeys, GeneratedKey, IdentityKeys, KeyClass, PublicIdentity, SoftwareCredentialKeys,
    SoftwareIdentity,
};
pub use message::{
    Decision, Initiator, Operation, Outcome, Refusal, RequestContext, SignRequest, SignResponse,
    UserVerification,
};
pub use pairing::{accept_ticket, issue_ticket, Pairing, PairingOffer, PairingTicket, Role};
pub use requester::{Begun, Completed, CreateOptions, GetOptions, Requester};

/// Wire protocol version carried in every message.
pub const PROTOCOL_VERSION: u8 = 1;
/// Lifetime a requester gives a request. Matches the owner app's ceremony TTL.
pub const REQUEST_TTL_SECS: i64 = 120;
/// Longest lifetime an authenticator will accept.
pub const MAX_REQUEST_TTL_SECS: i64 = 300;
/// Tolerated clock difference between the two devices.
pub const CLOCK_SKEW_SECS: i64 = 30;
/// Lifetime of a pairing ticket.
pub const PAIRING_TTL_SECS: i64 = 600;

/// Authenticator model identifier reported to sites when a passkey is created.
///
/// Provisional: `418d1f0e-0027-4770-84be-1e11f0f8004b`. It must be fixed before
/// any real passkey is created, because sites record it at registration.
pub const AAGUID: [u8; 16] = [
    0x41, 0x8d, 0x1f, 0x0e, 0x00, 0x27, 0x47, 0x70, 0x84, 0xbe, 0x1e, 0x11, 0xf0, 0xf8, 0x00, 0x4b,
];

pub(crate) fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn unb64(text: &str) -> Result<Vec<u8>, PasskeyError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| PasskeyError::Malformed("base64url"))
}

pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut bytes = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Length-prefixed concatenation, so no field can run into the next.
pub(crate) fn transcript(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}
