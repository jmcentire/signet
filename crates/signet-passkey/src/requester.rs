//! The computer side: turns a passkey request into a sealed message for the
//! phone, and the phone's answer into an ordinary WebAuthn response.
//!
//! A requester holds a machine identity key and no passkey key. It accepts a
//! response only if the paired phone signed it and it answers one request this
//! requester is still waiting on.
use crate::keys::{IdentityKeys, KeyClass};
use crate::message::{
    Decision, Operation, Outcome, Refusal, RequestContext, SignRequest, SignResponse,
    UserVerification,
};
use crate::pairing::{Pairing, Role};
use crate::seal::{open_signed, payload_digest, seal_signed, Envelope, MessageKind};
use crate::webauthn::{
    client_data_json, parse_authenticator_data, sha256, Ceremony, FLAG_AT, FLAG_UP,
};
use crate::{
    b64, random_bytes, rp, unb64, PasskeyError, CLOCK_SKEW_SECS, PROTOCOL_VERSION, REQUEST_TTL_SECS,
};
use std::collections::HashMap;

/// A site's sign-in request, as a page passes it to `navigator.credentials.get`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetOptions {
    /// The site's challenge, base64url.
    pub challenge: String,
    /// The relying party identifier the site asked for, if any.
    pub rp_id: Option<String>,
    /// Credential ids the site will accept, base64url. Empty means any.
    pub allow_credentials: Vec<String>,
    pub user_verification: UserVerification,
}

/// A site's request to create a passkey, as a page passes it to
/// `navigator.credentials.create`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateOptions {
    pub challenge: String,
    pub rp_id: Option<String>,
    pub rp_name: String,
    /// The site's handle for the account, base64url.
    pub user_id: String,
    pub user_name: String,
    pub user_display_name: String,
    /// COSE algorithm identifiers the site accepts.
    pub algorithms: Vec<i64>,
    pub exclude_credentials: Vec<String>,
    pub user_verification: UserVerification,
    pub key_class: Option<KeyClass>,
}

/// A request that has been sealed and is waiting for the phone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Begun {
    pub request_id: String,
    /// Envelope bytes to hand to the relay.
    pub envelope: Vec<u8>,
}

/// The end of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completed {
    Assertion {
        credential_id: String,
        authenticator_data: String,
        signature: String,
        user_handle: String,
        /// Present when this requester built the client data itself.
        client_data_json: Option<Vec<u8>>,
    },
    Attestation {
        credential_id: String,
        attestation_object: String,
        authenticator_data: String,
        public_key: String,
        client_data_json: Option<Vec<u8>>,
    },
    /// The owner declined.
    Denied,
    /// The phone refused.
    Refused(Refusal),
}

impl Completed {
    /// The standard WebAuthn JSON form of a successful result
    /// (`AuthenticationResponseJSON` or `RegistrationResponseJSON`), ready to
    /// hand to the page. `None` for a denial or refusal, and when the operating
    /// system, not this requester, holds the client data.
    pub fn to_json(&self) -> Option<serde_json::Value> {
        match self {
            Self::Assertion {
                credential_id,
                authenticator_data,
                signature,
                user_handle,
                client_data_json: Some(client_data),
            } => Some(serde_json::json!({
                "id": credential_id,
                "rawId": credential_id,
                "type": "public-key",
                "authenticatorAttachment": "platform",
                "response": {
                    "clientDataJSON": b64(client_data),
                    "authenticatorData": authenticator_data,
                    "signature": signature,
                    "userHandle": user_handle,
                },
                "clientExtensionResults": {},
            })),
            Self::Attestation {
                credential_id,
                attestation_object,
                authenticator_data,
                client_data_json: Some(client_data),
                ..
            } => Some(serde_json::json!({
                "id": credential_id,
                "rawId": credential_id,
                "type": "public-key",
                "authenticatorAttachment": "platform",
                "response": {
                    "clientDataJSON": b64(client_data),
                    "attestationObject": attestation_object,
                    "authenticatorData": authenticator_data,
                    "publicKeyAlgorithm": crate::webauthn::ES256,
                    "transports": ["internal"],
                },
                "clientExtensionResults": {},
            })),
            _ => None,
        }
    }
}

struct Pending {
    pairing_id: String,
    digest: String,
    expires_at: i64,
    ceremony: Ceremony,
    rp_id: String,
    allow_credentials: Vec<String>,
    client_data_json: Option<Vec<u8>>,
}

/// The computer side of the protocol.
pub struct Requester {
    identity: Box<dyn IdentityKeys>,
    pairings: Vec<Pairing>,
    pending: HashMap<String, Pending>,
}

impl Requester {
    pub fn new(identity: Box<dyn IdentityKeys>) -> Self {
        Self {
            identity,
            pairings: Vec::new(),
            pending: HashMap::new(),
        }
    }

    pub fn identity(&self) -> &dyn IdentityKeys {
        self.identity.as_ref()
    }

    /// Record a completed pairing with a phone.
    pub fn add_pairing(&mut self, pairing: Pairing) -> Result<(), PasskeyError> {
        if pairing.peer_role != Role::Authenticator {
            return Err(PasskeyError::Pairing("a computer pairs only with phones"));
        }
        if self.pairings.iter().any(|p| p.id == pairing.id) {
            return Err(PasskeyError::Pairing("pairing already recorded"));
        }
        self.pairings.push(pairing);
        Ok(())
    }

    /// Stop using a phone. Pending requests to it are dropped.
    pub fn revoke_pairing(&mut self, pairing_id: &str) -> bool {
        self.pending.retain(|_, p| p.pairing_id != pairing_id);
        match self
            .pairings
            .iter_mut()
            .find(|p| p.id == pairing_id && !p.revoked)
        {
            Some(pairing) => {
                pairing.revoked = true;
                true
            }
            None => false,
        }
    }

    fn pairing(&self, pairing_id: &str) -> Result<Pairing, PasskeyError> {
        self.pairings
            .iter()
            .find(|p| p.id == pairing_id && !p.revoked && p.peer_role == Role::Authenticator)
            .cloned()
            .ok_or(PasskeyError::UnknownPairing)
    }

    /// Sign in, for software that answers a page's passkey call in the
    /// browser's place. `origin` must come from the browser, never from the
    /// page. The site binding is checked here.
    pub fn begin_get(
        &mut self,
        pairing_id: &str,
        origin: &str,
        options: &GetOptions,
        context: Option<RequestContext>,
        now: i64,
    ) -> Result<Begun, PasskeyError> {
        let rp_id = rp::effective_rp_id(origin, options.rp_id.as_deref())?;
        unb64(&options.challenge)?;
        let client_data = client_data_json(Ceremony::Get, &options.challenge, origin);
        self.begin(
            pairing_id,
            Operation::Get {
                allow_credentials: options.allow_credentials.clone(),
            },
            rp_id,
            sha256(&client_data),
            Some((origin.to_owned(), client_data)),
            options.user_verification,
            context,
            now,
        )
    }

    /// Create a passkey, for software that answers a page's passkey call in the
    /// browser's place. See [`Requester::begin_get`] for `origin`.
    pub fn begin_create(
        &mut self,
        pairing_id: &str,
        origin: &str,
        options: &CreateOptions,
        context: Option<RequestContext>,
        now: i64,
    ) -> Result<Begun, PasskeyError> {
        let rp_id = rp::effective_rp_id(origin, options.rp_id.as_deref())?;
        unb64(&options.challenge)?;
        let client_data = client_data_json(Ceremony::Create, &options.challenge, origin);
        self.begin(
            pairing_id,
            create_operation(options),
            rp_id,
            sha256(&client_data),
            Some((origin.to_owned(), client_data)),
            options.user_verification,
            context,
            now,
        )
    }

    /// Sign in, when the operating system has already checked the site binding
    /// and supplies only the identifier and the client-data hash.
    /// `options.challenge` and `options.rp_id` are ignored.
    pub fn begin_get_with_hash(
        &mut self,
        pairing_id: &str,
        rp_id: &str,
        client_data_hash: [u8; 32],
        options: &GetOptions,
        context: Option<RequestContext>,
        now: i64,
    ) -> Result<Begun, PasskeyError> {
        rp::validate_rp_id(rp_id)?;
        self.begin(
            pairing_id,
            Operation::Get {
                allow_credentials: options.allow_credentials.clone(),
            },
            rp_id.to_owned(),
            client_data_hash,
            None,
            options.user_verification,
            context,
            now,
        )
    }

    /// Create a passkey, when the operating system supplies only the identifier
    /// and the client-data hash. `options.challenge` and `options.rp_id` are
    /// ignored.
    pub fn begin_create_with_hash(
        &mut self,
        pairing_id: &str,
        rp_id: &str,
        client_data_hash: [u8; 32],
        options: &CreateOptions,
        context: Option<RequestContext>,
        now: i64,
    ) -> Result<Begun, PasskeyError> {
        rp::validate_rp_id(rp_id)?;
        self.begin(
            pairing_id,
            create_operation(options),
            rp_id.to_owned(),
            client_data_hash,
            None,
            options.user_verification,
            context,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn begin(
        &mut self,
        pairing_id: &str,
        operation: Operation,
        rp_id: String,
        client_data_hash: [u8; 32],
        page: Option<(String, Vec<u8>)>,
        user_verification: UserVerification,
        context: Option<RequestContext>,
        now: i64,
    ) -> Result<Begun, PasskeyError> {
        let pairing = self.pairing(pairing_id)?;
        self.pending
            .retain(|_, p| p.expires_at + CLOCK_SKEW_SECS > now);
        let (origin, client_data) = match page {
            Some((origin, client_data)) => (Some(origin), Some(client_data)),
            None => (None, None),
        };
        let (ceremony, allow_credentials) = match &operation {
            Operation::Get { allow_credentials } => (Ceremony::Get, allow_credentials.clone()),
            Operation::Create { .. } => (Ceremony::Create, Vec::new()),
        };
        let request = SignRequest {
            v: PROTOCOL_VERSION,
            request_id: b64(&random_bytes::<16>()),
            pairing_id: pairing.id.clone(),
            operation,
            rp_id: rp_id.clone(),
            client_data_hash: b64(&client_data_hash),
            origin,
            user_verification,
            context,
            created_at: now,
            expires_at: now + REQUEST_TTL_SECS,
        };
        let payload =
            serde_json::to_vec(&request).map_err(|_| PasskeyError::Malformed("request"))?;
        let envelope = seal_signed(
            self.identity.as_ref(),
            &pairing.peer,
            &pairing.id,
            MessageKind::Request,
            &payload,
        )?;
        self.pending.insert(
            request.request_id.clone(),
            Pending {
                pairing_id: pairing.id,
                digest: payload_digest(&payload),
                expires_at: request.expires_at,
                ceremony,
                rp_id,
                allow_credentials,
                client_data_json: client_data,
            },
        );
        Ok(Begun {
            request_id: request.request_id,
            envelope,
        })
    }

    /// Accept the phone's sealed response.
    ///
    /// The response must be signed by the paired phone and must name, by id and
    /// digest, one request still pending here. That request is consumed, so a
    /// response is accepted at most once.
    pub fn finish(&mut self, envelope: &[u8], now: i64) -> Result<Completed, PasskeyError> {
        let envelope = Envelope::from_bytes(envelope)?;
        let pairing = self.pairing(&envelope.pairing_id)?;
        let payload = open_signed(
            self.identity.as_ref(),
            &pairing.peer,
            &envelope,
            MessageKind::Response,
        )?;
        let response: SignResponse =
            serde_json::from_slice(&payload).map_err(|_| PasskeyError::Malformed("response"))?;
        if response.v != PROTOCOL_VERSION {
            return Err(PasskeyError::Unsupported("protocol version"));
        }
        let matches = self
            .pending
            .get(&response.request_id)
            .is_some_and(|p| p.pairing_id == pairing.id && p.digest == response.request_digest);
        if !matches {
            return Err(PasskeyError::NoPendingRequest);
        }
        let pending = self
            .pending
            .remove(&response.request_id)
            .ok_or(PasskeyError::NoPendingRequest)?;
        if now > pending.expires_at + CLOCK_SKEW_SECS {
            return Err(PasskeyError::Expired);
        }

        let outcome = match response.decision {
            Decision::Denied => return Ok(Completed::Denied),
            Decision::Refused { reason } => return Ok(Completed::Refused(reason)),
            Decision::Approved { outcome } => outcome,
        };
        // The site verifies the signature. These checks catch a phone that
        // answered a different question than the one asked.
        let check_auth_data = |encoded: &str, need: u8| -> Result<(), PasskeyError> {
            let bytes = unb64(encoded)?;
            let parsed = parse_authenticator_data(&bytes)?;
            if parsed.rp_id_hash != sha256(pending.rp_id.as_bytes()) {
                return Err(PasskeyError::SiteBinding("response is for another site"));
            }
            if parsed.flags & need != need {
                return Err(PasskeyError::Malformed("authenticator flags"));
            }
            Ok(())
        };
        match (pending.ceremony, outcome) {
            (
                Ceremony::Get,
                Outcome::Assertion {
                    credential_id,
                    authenticator_data,
                    signature,
                    user_handle,
                },
            ) => {
                check_auth_data(&authenticator_data, FLAG_UP)?;
                if !pending.allow_credentials.is_empty()
                    && !pending.allow_credentials.contains(&credential_id)
                {
                    return Err(PasskeyError::Malformed("credential was not requested"));
                }
                Ok(Completed::Assertion {
                    credential_id,
                    authenticator_data,
                    signature,
                    user_handle,
                    client_data_json: pending.client_data_json,
                })
            }
            (
                Ceremony::Create,
                Outcome::Attestation {
                    credential_id,
                    attestation_object,
                    authenticator_data,
                    public_key,
                },
            ) => {
                check_auth_data(&authenticator_data, FLAG_UP | FLAG_AT)?;
                Ok(Completed::Attestation {
                    credential_id,
                    attestation_object,
                    authenticator_data,
                    public_key,
                    client_data_json: pending.client_data_json,
                })
            }
            _ => Err(PasskeyError::Malformed("response does not match request")),
        }
    }

    /// How many requests are waiting for a phone.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

fn create_operation(options: &CreateOptions) -> Operation {
    Operation::Create {
        rp_name: options.rp_name.clone(),
        user_id: options.user_id.clone(),
        user_name: options.user_name.clone(),
        user_display_name: options.user_display_name.clone(),
        algorithms: options.algorithms.clone(),
        exclude_credentials: options.exclude_credentials.clone(),
        key_class: options.key_class,
    }
}
