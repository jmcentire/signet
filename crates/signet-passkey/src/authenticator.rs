//! The phone side: holds passkeys, shows the owner each request, and signs
//! only what the owner approved.
use crate::keys::{CredentialKeys, IdentityKeys, KeyClass};
use crate::message::{
    Decision, Operation, Outcome, Refusal, RequestContext, SignRequest, SignResponse,
    UserVerification,
};
use crate::pairing::{Pairing, Role};
use crate::seal::{open_signed, payload_digest, seal_signed, Envelope, MessageKind};
use crate::webauthn::{
    attestation_object_none, authenticator_data, AttestedCredential, ES256, FLAG_BE, FLAG_BS,
    FLAG_UP, FLAG_UV,
};
use crate::{
    b64, random_bytes, rp, unb64, PasskeyError, AAGUID, CLOCK_SKEW_SECS, MAX_REQUEST_TTL_SECS,
    PROTOCOL_VERSION,
};
use std::collections::HashMap;

/// A passkey as the phone stores it. The private key is behind `key_handle` in
/// the key store and never appears here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredCredential {
    /// Credential identifier, base64url.
    pub credential_id: String,
    /// The only site this passkey may ever sign for.
    pub rp_id: String,
    /// The site's handle for the account, base64url.
    pub user_id: String,
    pub user_name: String,
    pub user_display_name: String,
    /// Key-store reference, base64url.
    pub key_handle: String,
    /// SEC1 uncompressed public key, base64url.
    pub public_key: String,
    pub class: KeyClass,
    /// Whether a portable key currently has a backup. Always false for
    /// hardware-bound keys.
    pub backed_up: bool,
    pub created_at: i64,
}

impl StoredCredential {
    fn flags(&self) -> u8 {
        match (self.class, self.backed_up) {
            (KeyClass::HardwareBound, _) => 0,
            (KeyClass::Portable, false) => FLAG_BE,
            (KeyClass::Portable, true) => FLAG_BE | FLAG_BS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    SignIn,
    CreatePasskey,
}

/// An account the owner can choose or is about to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountView {
    pub user_name: String,
    pub user_display_name: String,
}

/// Exactly what the owner is asked to approve. The phone signs for this request
/// and no other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestView {
    pub operation: OperationKind,
    /// The site, for example `github.com`.
    pub rp_id: String,
    /// The page origin, when the computer reported one.
    pub origin: Option<String>,
    /// The paired machine's name, as recorded when it was paired, and its key
    /// fingerprint. A request cannot change the name it is shown under.
    pub requester_name: String,
    pub requester_fingerprint: String,
    /// The computer's own account of who started this. A claim, not a fact.
    pub context: Option<RequestContext>,
    /// For a sign-in, the accounts to choose from. For a new passkey, the one
    /// account it will belong to.
    pub accounts: Vec<AccountView>,
    pub user_verification_required: bool,
    pub expires_at: i64,
}

/// The owner's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    Approve {
        /// Index into [`RequestView::accounts`].
        account: usize,
        /// Whether the owner was verified by biometric or device passcode.
        user_verified: bool,
    },
    Deny,
}

/// The screen and biometric prompt. The phone app implements this.
pub trait Approver {
    fn decide(&mut self, view: &RequestView) -> Approval;
}

/// The phone side of the protocol.
pub struct Authenticator {
    identity: Box<dyn IdentityKeys>,
    keys: Box<dyn CredentialKeys>,
    pairings: Vec<Pairing>,
    credentials: Vec<StoredCredential>,
    /// Request ids already handled, with the time each one expires.
    seen: HashMap<String, i64>,
    default_class: KeyClass,
}

impl Authenticator {
    pub fn new(identity: Box<dyn IdentityKeys>, keys: Box<dyn CredentialKeys>) -> Self {
        Self {
            identity,
            keys,
            pairings: Vec::new(),
            credentials: Vec::new(),
            seen: HashMap::new(),
            default_class: KeyClass::HardwareBound,
        }
    }

    /// The class given to a new passkey when the request does not ask for one.
    pub fn set_default_class(&mut self, class: KeyClass) {
        self.default_class = class;
    }

    pub fn identity(&self) -> &dyn IdentityKeys {
        self.identity.as_ref()
    }

    /// Record a completed pairing with a computer.
    pub fn add_pairing(&mut self, pairing: Pairing) -> Result<(), PasskeyError> {
        if pairing.peer_role != Role::Requester {
            return Err(PasskeyError::Pairing("a phone pairs only with computers"));
        }
        if self.pairings.iter().any(|p| p.id == pairing.id) {
            return Err(PasskeyError::Pairing("pairing already recorded"));
        }
        self.pairings.push(pairing);
        Ok(())
    }

    /// Stop answering a computer. Returns whether an active pairing was found.
    pub fn revoke_pairing(&mut self, pairing_id: &str) -> bool {
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

    pub fn pairings(&self) -> &[Pairing] {
        &self.pairings
    }

    pub fn credentials(&self) -> &[StoredCredential] {
        &self.credentials
    }

    /// Handle one sealed request from the relay.
    ///
    /// Returns the sealed response to send back. Returns an error, and sends
    /// nothing, when the request cannot be attributed to an active pairing, has
    /// expired or was seen before: a party that fails those checks learns
    /// nothing from the phone.
    pub fn handle(
        &mut self,
        envelope: &[u8],
        now: i64,
        approver: &mut dyn Approver,
    ) -> Result<Vec<u8>, PasskeyError> {
        let envelope = Envelope::from_bytes(envelope)?;
        let pairing = self
            .pairings
            .iter()
            .find(|p| p.id == envelope.pairing_id && !p.revoked && p.peer_role == Role::Requester)
            .cloned()
            .ok_or(PasskeyError::UnknownPairing)?;
        let payload = open_signed(
            self.identity.as_ref(),
            &pairing.peer,
            &envelope,
            MessageKind::Request,
        )?;
        let request: SignRequest =
            serde_json::from_slice(&payload).map_err(|_| PasskeyError::Malformed("request"))?;
        if request.v != PROTOCOL_VERSION {
            return Err(PasskeyError::Unsupported("protocol version"));
        }
        if request.pairing_id != pairing.id {
            return Err(PasskeyError::Malformed("pairing id"));
        }
        if request.created_at > now + CLOCK_SKEW_SECS
            || request.expires_at <= now
            || request.expires_at <= request.created_at
            || request.expires_at - request.created_at > MAX_REQUEST_TTL_SECS
        {
            return Err(PasskeyError::Expired);
        }
        if unb64(&request.client_data_hash)?.len() != 32 {
            return Err(PasskeyError::Malformed("client data hash"));
        }
        // Record the id before asking the owner, so a copy that arrives while
        // the prompt is open is rejected too.
        self.seen.retain(|_, expires| *expires > now);
        if self
            .seen
            .insert(request.request_id.clone(), request.expires_at)
            .is_some()
        {
            return Err(PasskeyError::Replay);
        }

        let decision = self.decide(&request, &pairing, now, approver)?;
        let response = SignResponse {
            v: PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            request_digest: payload_digest(&payload),
            decision,
            decided_at: now,
        };
        let response =
            serde_json::to_vec(&response).map_err(|_| PasskeyError::Malformed("response"))?;
        seal_signed(
            self.identity.as_ref(),
            &pairing.peer,
            &pairing.id,
            MessageKind::Response,
            &response,
        )
    }

    fn decide(
        &mut self,
        request: &SignRequest,
        pairing: &Pairing,
        now: i64,
        approver: &mut dyn Approver,
    ) -> Result<Decision, PasskeyError> {
        let refused = |reason| Ok(Decision::Refused { reason });
        let bound = match &request.origin {
            Some(origin) => rp::check_binding(origin, &request.rp_id),
            None => rp::validate_rp_id(&request.rp_id),
        };
        if bound.is_err() {
            return refused(Refusal::SiteBinding);
        }
        let uv_required = request.user_verification == UserVerification::Required;
        let view = |operation, accounts| RequestView {
            operation,
            rp_id: request.rp_id.clone(),
            origin: request.origin.clone(),
            requester_name: pairing.peer_name.clone(),
            requester_fingerprint: pairing.peer.fingerprint(),
            context: request.context.clone(),
            accounts,
            user_verification_required: uv_required,
            expires_at: request.expires_at,
        };

        match &request.operation {
            Operation::Get { allow_credentials } => {
                // The one rule an authenticator must never break: a passkey
                // signs only for the site it was created for.
                let mut candidates: Vec<StoredCredential> = self
                    .credentials
                    .iter()
                    .filter(|c| c.rp_id == request.rp_id)
                    .filter(|c| {
                        allow_credentials.is_empty() || allow_credentials.contains(&c.credential_id)
                    })
                    .cloned()
                    .collect();
                if allow_credentials.is_empty() {
                    // When the site names no passkey, offer one per account:
                    // the newest. Older ones stay usable when a site asks for
                    // them by id.
                    let mut newest: Vec<StoredCredential> = Vec::new();
                    for candidate in candidates.into_iter().rev() {
                        if !newest.iter().any(|n| n.user_id == candidate.user_id) {
                            newest.push(candidate);
                        }
                    }
                    newest.reverse();
                    candidates = newest;
                }
                if candidates.is_empty() {
                    return refused(Refusal::NoCredential);
                }
                let accounts = candidates
                    .iter()
                    .map(|c| AccountView {
                        user_name: c.user_name.clone(),
                        user_display_name: c.user_display_name.clone(),
                    })
                    .collect();
                let (account, user_verified) =
                    match approver.decide(&view(OperationKind::SignIn, accounts)) {
                        Approval::Deny => return Ok(Decision::Denied),
                        Approval::Approve {
                            account,
                            user_verified,
                        } => (account, user_verified),
                    };
                let credential = candidates
                    .get(account)
                    .ok_or(PasskeyError::Malformed("approved account"))?;
                if uv_required && !user_verified {
                    return refused(Refusal::UserVerificationRequired);
                }
                let mut flags = FLAG_UP | credential.flags();
                if user_verified {
                    flags |= FLAG_UV;
                }
                let auth_data = authenticator_data(&request.rp_id, flags, 0, None)?;
                let signed = [auth_data.as_slice(), &unb64(&request.client_data_hash)?].concat();
                let signature = self.keys.sign(&unb64(&credential.key_handle)?, &signed)?;
                Ok(Decision::Approved {
                    outcome: Outcome::Assertion {
                        credential_id: credential.credential_id.clone(),
                        authenticator_data: b64(&auth_data),
                        signature: b64(&signature),
                        user_handle: credential.user_id.clone(),
                    },
                })
            }
            Operation::Create {
                user_id,
                user_name,
                user_display_name,
                algorithms,
                exclude_credentials,
                key_class,
                ..
            } => {
                if !algorithms.contains(&ES256) {
                    return refused(Refusal::UnsupportedAlgorithm);
                }
                let user_id_len = unb64(user_id)?.len();
                if user_id_len == 0 || user_id_len > 64 {
                    return Err(PasskeyError::Malformed("user id"));
                }
                if self.credentials.iter().any(|c| {
                    c.rp_id == request.rp_id && exclude_credentials.contains(&c.credential_id)
                }) {
                    return refused(Refusal::CredentialExcluded);
                }
                let accounts = vec![AccountView {
                    user_name: user_name.clone(),
                    user_display_name: user_display_name.clone(),
                }];
                let user_verified =
                    match approver.decide(&view(OperationKind::CreatePasskey, accounts)) {
                        Approval::Deny => return Ok(Decision::Denied),
                        Approval::Approve { user_verified, .. } => user_verified,
                    };
                if uv_required && !user_verified {
                    return refused(Refusal::UserVerificationRequired);
                }
                let class = key_class.unwrap_or(self.default_class);
                let key = self.keys.generate(class)?;
                let credential_id = random_bytes::<32>();
                let credential = StoredCredential {
                    credential_id: b64(&credential_id),
                    rp_id: request.rp_id.clone(),
                    user_id: user_id.clone(),
                    user_name: user_name.clone(),
                    user_display_name: user_display_name.clone(),
                    key_handle: b64(&key.handle),
                    public_key: b64(&key.public_sec1),
                    class,
                    backed_up: false,
                    created_at: now,
                };
                let mut flags = FLAG_UP | credential.flags();
                if user_verified {
                    flags |= FLAG_UV;
                }
                let auth_data = authenticator_data(
                    &request.rp_id,
                    flags,
                    0,
                    Some(&AttestedCredential {
                        aaguid: &AAGUID,
                        credential_id: &credential_id,
                        public_sec1: &key.public_sec1,
                    }),
                )?;
                let attestation = attestation_object_none(&auth_data)?;
                // An earlier passkey for the same account is kept. If the site
                // fails to record this new one, the old one must still work.
                let outcome = Outcome::Attestation {
                    credential_id: credential.credential_id.clone(),
                    attestation_object: b64(&attestation),
                    authenticator_data: b64(&auth_data),
                    public_key: credential.public_key.clone(),
                };
                self.credentials.push(credential);
                Ok(Decision::Approved { outcome })
            }
        }
    }
}
