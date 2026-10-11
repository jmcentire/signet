//! Passkey owner management and signed task requests in one native JSON CAS aggregate.
//! Authentication counters, credential revocation and ring transitions share one commit.
use super::*;
use crate::authority::{
    object_store::{self, CommitOutcome, Loaded, Store, Versioned},
    rings::{Management, OwnerApproval, Restrictions, RingAuthority, OWNER_RING_DOMAIN},
};
#[derive(Clone, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    passkey: Passkey,
    label: String,
    counter: u32,
    revoked: bool,
}
#[derive(Clone, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    config: OwnerConfig,
    rings: RingAuthority,
    epoch: u64,
    initialized: bool,
    credentials: BTreeMap<String, Credential>,
    receipts: BTreeMap<String, Value>,
}
pub struct NativeOwnerService {
    store: Versioned<Box<dyn Store>>,
    signer: Box<dyn Signer>,
    config: OwnerConfig,
    webauthn: Webauthn,
    sessions: HashMap<String, Session>,
    pending: HashMap<String, Pending>,
}
fn storage(_: object_store::Error) -> AuthorityError {
    AuthorityError::Rejected(
        "native storage conflict or uncertain outcome; refresh and recover before acting",
    )
}
impl NativeOwnerService {
    /// Explicit operator bootstrap. Never called by HTTP or after a missing live head.
    pub fn initialize(
        store: Box<dyn Store>,
        user_hash: String,
        config: OwnerConfig,
        trust: AuthorityConfig,
        restrictions: Restrictions,
    ) -> Result<()> {
        validate_owner_config(&config, &trust)?;
        if config.enrollment_expires_at <= now() || config.enrollment_expires_at > now() + 900 {
            return reject("enrollment invitation must expire within 15 minutes");
        }
        let store = Versioned::new(store, user_hash).map_err(storage)?;
        let state = State {
            config,
            rings: RingAuthority::new(trust, restrictions)?,
            epoch: 0,
            initialized: false,
            credentials: BTreeMap::new(),
            receipts: BTreeMap::new(),
        };
        store
            .commit(&store.initialize(&state).map_err(storage)?)
            .map_err(storage)?;
        Ok(())
    }
    pub fn open(
        store: Box<dyn Store>,
        user_hash: String,
        signer: Box<dyn Signer>,
        config: OwnerConfig,
    ) -> Result<Self> {
        let store = Versioned::new(store, user_hash).map_err(storage)?;
        let current = store.load::<State>().map_err(storage)?;
        let webauthn = validate_owner_config(&config, current.state.rings.trust())?;
        if current.state.config != config
            || hex::encode(signer.public_key_ed25519()) != current.state.rings.trust().owner_key
        {
            return reject("native owner configuration or signer mismatch");
        }
        Ok(Self {
            store,
            signer,
            config,
            webauthn,
            sessions: HashMap::new(),
            pending: HashMap::new(),
        })
    }
    pub fn origin(&self) -> &str {
        &self.config.origin
    }
    fn load(&self) -> Result<Loaded<State>> {
        let current = self.store.load::<State>().map_err(storage)?;
        if current.state.config != self.config {
            return reject("native owner config changed");
        }
        Ok(current)
    }
    fn commit(&self, current: &Loaded<State>, next: &State) -> Result<CommitOutcome> {
        self.store
            .commit(&self.store.prepare(current, next).map_err(storage)?)
            .map_err(storage)
    }
    fn cleanup(&mut self) {
        let t = now();
        self.sessions.retain(|_, s| s.expires > t);
        self.pending.retain(|_, p| p.expires > t);
    }
    fn check(&self, sid: &str, csrf: &str, state: &State, authenticated: bool) -> Result<()> {
        let s = self
            .sessions
            .get(sid)
            .ok_or(AuthorityError::Rejected("session expired"))?;
        if s.expires <= now()
            || !bool::from(s.csrf.as_bytes().ct_eq(csrf.as_bytes()))
            || (authenticated && s.authenticated_epoch != Some(state.epoch))
        {
            return reject("session or CSRF invalid; sign in again");
        }
        Ok(())
    }
    pub fn session(&mut self, existing: Option<&str>) -> Result<(String, Value)> {
        self.cleanup();
        let state = self.load()?.state;
        let sid = existing
            .filter(|id| self.sessions.contains_key(*id))
            .map(str::to_owned)
            .unwrap_or_else(id);
        if !self.sessions.contains_key(&sid) {
            if self.sessions.len() >= 256 {
                return reject("session capacity reached");
            }
            self.sessions.insert(
                sid.clone(),
                Session {
                    csrf: id(),
                    expires: now() + SESSION_TTL,
                    authenticated_epoch: None,
                },
            );
        }
        let s = &self.sessions[&sid];
        Ok((
            sid,
            json!({"csrf":s.csrf,"authenticated":s.authenticated_epoch==Some(state.epoch),"enrolled":state.initialized,"native_rings":true}),
        ))
    }
    pub fn logout(&mut self, sid: &str, csrf: &str) -> Result<Value> {
        let current = self.load()?;
        self.check(sid, csrf, &current.state, false)?;
        self.sessions.remove(sid);
        self.pending.retain(|_, p| p.session != sid);
        Ok(json!({"state":"signed_out"}))
    }
    pub fn rotate_session(&mut self, sid: &str) -> Result<String> {
        let old = self
            .sessions
            .remove(sid)
            .ok_or(AuthorityError::Rejected("session expired"))?;
        self.pending.retain(|_, p| p.session != sid);
        let new = id();
        self.sessions.insert(
            new.clone(),
            Session {
                csrf: id(),
                expires: now() + SESSION_TTL,
                authenticated_epoch: old.authenticated_epoch,
            },
        );
        Ok(new)
    }
    fn pending(&mut self, sid: &str, epoch: u64, ceremony: Ceremony) -> Result<String> {
        self.cleanup();
        if self.pending.len() >= 256
            || self.pending.values().filter(|p| p.session == sid).count() >= 4
        {
            return reject("passkey prompt capacity reached");
        }
        let cid = id();
        self.pending.insert(
            cid.clone(),
            Pending {
                session: sid.into(),
                epoch,
                expires: now() + CHALLENGE_TTL,
                ceremony,
            },
        );
        Ok(cid)
    }
    fn take(&mut self, sid: &str, cid: &str, epoch: u64) -> Result<Pending> {
        let p = self.pending.get(cid).ok_or(AuthorityError::Rejected(
            "unknown or used passkey challenge",
        ))?;
        if p.session != sid {
            return reject("challenge belongs to another session");
        }
        let p = self.pending.remove(cid).unwrap();
        if p.epoch != epoch || p.expires <= now() {
            return reject("challenge expired or revoked");
        }
        Ok(p)
    }
    fn registration(
        &mut self,
        sid: &str,
        state: &State,
        label: String,
        authorized_by: Option<String>,
    ) -> Result<Value> {
        if !valid_label(&label) || state.credentials.values().filter(|c| !c.revoked).count() >= 8 {
            return reject("invalid passkey label or capacity");
        }
        let (options, ceremony) = self
            .webauthn
            .start_passkey_registration(
                self.config.user_id,
                &self.config.display_name,
                &self.config.display_name,
                Some(
                    state
                        .credentials
                        .values()
                        .map(|c| c.passkey.cred_id().clone())
                        .collect(),
                ),
            )
            .map_err(webauthn_error)?;
        let challenge = self.pending(
            sid,
            state.epoch,
            Ceremony::Register {
                state: ceremony,
                label,
                bootstrap: authorized_by.is_none(),
                authorized_by,
            },
        )?;
        Ok(
            json!({"challenge_id":challenge,"options":options,"ceremony":"registration","expires_at":now()+CHALLENGE_TTL}),
        )
    }
    pub fn begin_enrollment(
        &mut self,
        sid: &str,
        csrf: &str,
        token: &str,
        label: String,
    ) -> Result<Value> {
        let current = self.load()?;
        self.check(sid, csrf, &current.state, false)?;
        let hash = hex::encode(Sha256::digest(token.as_bytes()));
        if current.state.initialized
            || self.config.enrollment_expires_at <= now()
            || !bool::from(
                hash.as_bytes()
                    .ct_eq(self.config.enrollment_token_hash.as_bytes()),
            )
        {
            return reject("invalid or used enrollment invitation");
        }
        self.registration(sid, &current.state, label, None)
    }
    pub fn finish_registration(
        &mut self,
        sid: &str,
        csrf: &str,
        challenge: &str,
        response: &RegisterPublicKeyCredential,
    ) -> Result<Value> {
        let current = self.load()?;
        self.check(sid, csrf, &current.state, false)?;
        let p = self.take(sid, challenge, current.state.epoch)?;
        let Ceremony::Register {
            state,
            label,
            bootstrap,
            authorized_by,
        } = p.ceremony
        else {
            return reject("wrong passkey ceremony");
        };
        if bootstrap && (current.state.initialized || self.config.enrollment_expires_at <= now()) {
            return reject("enrollment changed or expired");
        }
        if let Some(cid) = authorized_by {
            if current
                .state
                .credentials
                .get(&cid)
                .is_none_or(|c| c.revoked)
            {
                return reject("authorizing passkey revoked");
            }
        }
        if current
            .state
            .credentials
            .values()
            .filter(|c| !c.revoked)
            .count()
            >= 8
        {
            return reject("passkey capacity reached");
        }
        let passkey = self
            .webauthn
            .finish_passkey_registration(response, &state)
            .map_err(webauthn_error)?;
        let cid = credential_id(passkey.cred_id());
        if current.state.credentials.contains_key(&cid) {
            return reject("credential already registered or revoked");
        }
        let mut next = current.state.clone();
        next.credentials.insert(
            cid.clone(),
            Credential {
                passkey,
                label,
                counter: 0,
                revoked: false,
            },
        );
        next.initialized = true;
        next.epoch = next
            .epoch
            .checked_add(1)
            .ok_or(AuthorityError::Rejected("epoch overflow"))?;
        self.commit(&current, &next)?;
        self.sessions.get_mut(sid).unwrap().authenticated_epoch = Some(next.epoch);
        self.pending.clear();
        Ok(json!({"state":"enrolled","credential_id":cid}))
    }
    pub fn begin_authentication(
        &mut self,
        sid: &str,
        csrf: &str,
        intent: OwnerIntent,
    ) -> Result<Value> {
        let current = self.load()?;
        self.check(
            sid,
            csrf,
            &current.state,
            !matches!(intent, OwnerIntent::Login),
        )?;
        let creds = current
            .state
            .credentials
            .iter()
            .filter(|(_, c)| !c.revoked)
            .collect::<Vec<_>>();
        if creds.is_empty() {
            return reject("no active passkeys");
        }
        let review = match &intent {
            OwnerIntent::ManageRings {
                expected_revision,
                action,
            } => {
                if *expected_revision != current.state.rings.revision() {
                    return reject("ring state changed; review again");
                }
                self.validate_management(&current.state.rings, action)?;
                json!({"title":"Approve this exact ring change","action":action,"revision":expected_revision,"effect":"Only this change. Definitions do not activate a worker. Earlier policy content is restored as a new version; spent budgets and receipts remain."})
            }
            OwnerIntent::Login => json!({"title":"Sign in to your Signet"}),
            OwnerIntent::AddPasskey { label } => {
                if !valid_label(label) || creds.len() >= 8 {
                    return reject("invalid passkey label or capacity");
                }
                json!({"title":"Add backup passkey","label":label})
            }
            OwnerIntent::RevokePasskey { credential_id: cid } => {
                if creds.len() < 2 || current.state.credentials.get(cid).is_none_or(|c| c.revoked) {
                    return reject("cannot revoke last or unknown passkey");
                }
                json!({"title":"Remove passkey","label":current.state.credentials[cid].label,"effect":"Other sessions and pending approvals expire."})
            }
            _ => return reject("legacy purchase proposals are not part of native rings"),
        };
        let allowed=creds.into_iter().filter(|(cid,_)| !matches!(&intent,OwnerIntent::RevokePasskey{credential_id} if credential_id==*cid)).map(|(_,c)|c.passkey.clone()).collect::<Vec<_>>();
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&allowed)
            .map_err(webauthn_error)?;
        let challenge = self.pending(
            sid,
            current.state.epoch,
            Ceremony::Authenticate {
                state,
                intent,
                revision: current.state.rings.revision(),
                proposal_digest: None,
            },
        )?;
        Ok(
            json!({"challenge_id":challenge,"options":options,"review":review,"expires_at":now()+CHALLENGE_TTL,"ceremony":"authentication"}),
        )
    }
    fn signed_management(
        &self,
        rings: &RingAuthority,
        action: &Management,
        nonce: String,
    ) -> Result<SignedMessage> {
        let payload = serde_json::to_vec(&OwnerApproval {
            authority_id: rings.trust().authority_id.clone(),
            nonce,
            issued_at: now(),
            expires_at: now() + CHALLENGE_TTL,
            expected_revision: rings.revision(),
            action: action.clone(),
        })?;
        let signature = self
            .signer
            .sign_ed25519(&signing_bytes(OWNER_RING_DOMAIN, &payload))
            .map_err(|_| AuthorityError::Rejected("owner signer unavailable"))?;
        Ok(SignedMessage {
            payload: URL_SAFE_NO_PAD.encode(payload),
            signature: hex::encode(signature),
        })
    }
    fn validate_management(&self, rings: &RingAuthority, action: &Management) -> Result<()> {
        rings.validate_management(action, now())
    }
    pub fn finish_authentication(
        &mut self,
        sid: &str,
        csrf: &str,
        challenge: &str,
        response: &PublicKeyCredential,
    ) -> Result<Value> {
        let current = self.load()?;
        self.check(sid, csrf, &current.state, false)?;
        // A retry of exactly the same assertion is read-only receipt recovery.
        let receipt = hex::encode(Sha256::digest(serde_json::to_vec(&(
            sid, challenge, response,
        ))?));
        if let Some(value) = current.state.receipts.get(&receipt) {
            return Ok(json!({"state":"recovered","result":value,"dispatch":false}));
        }
        let p = self.take(sid, challenge, current.state.epoch)?;
        let Ceremony::Authenticate {
            state,
            intent,
            revision,
            ..
        } = p.ceremony
        else {
            return reject("wrong passkey ceremony");
        };
        let result = self
            .webauthn
            .finish_passkey_authentication(response, &state)
            .map_err(webauthn_error)?;
        if !result.user_verified() {
            return reject("passkey user verification required");
        }
        let cid = credential_id(result.cred_id());
        let mut next = current.state.clone();
        let c = next
            .credentials
            .get_mut(&cid)
            .filter(|c| !c.revoked)
            .ok_or(AuthorityError::Rejected("passkey revoked"))?;
        if (c.counter > 0 || result.counter() > 0) && result.counter() <= c.counter {
            return reject("passkey counter replay");
        }
        c.passkey
            .update_credential(&result)
            .ok_or(AuthorityError::Rejected("passkey mismatch"))?;
        c.counter = result.counter();
        if !matches!(intent, OwnerIntent::Login) && revision != next.rings.revision() {
            return reject("ring state changed; review again");
        }
        let value = match &intent {
            OwnerIntent::ManageRings { action, .. } => {
                let signed = self.signed_management(&next.rings, action, challenge.into())?;
                next.rings.approve(&signed, now())?
            }
            OwnerIntent::Login => json!({"state":"signed_in"}),
            OwnerIntent::AddPasskey { .. } => json!({"state":"registration_authorized"}),
            OwnerIntent::RevokePasskey {
                credential_id: target,
            } => {
                if target == &cid || next.credentials.values().filter(|c| !c.revoked).count() < 2 {
                    return reject("use another passkey; cannot revoke last credential");
                }
                next.credentials
                    .get_mut(target)
                    .filter(|c| !c.revoked)
                    .ok_or(AuthorityError::Rejected("unknown active passkey"))?
                    .revoked = true;
                next.epoch = next
                    .epoch
                    .checked_add(1)
                    .ok_or(AuthorityError::Rejected("epoch overflow"))?;
                json!({"state":"revoked"})
            }
            _ => return reject("unsupported native intent"),
        };
        next.receipts.insert(receipt, value.clone());
        let outcome = self.commit(&current, &next)?;
        if outcome == CommitOutcome::Recovered {
            return Ok(json!({"state":"recovered","result":value,"dispatch":false}));
        }
        self.sessions.get_mut(sid).unwrap().authenticated_epoch = Some(next.epoch);
        if next.epoch != p.epoch {
            self.pending.clear();
        }
        if let OwnerIntent::AddPasskey { label } = intent {
            self.registration(sid, &next, label, Some(cid))
        } else {
            Ok(value)
        }
    }
    pub fn dashboard(&mut self, sid: &str, csrf: &str) -> Result<Value> {
        let current = self.load()?;
        self.check(sid, csrf, &current.state, true)?;
        Ok(
            json!({"native_rings":true,"display_name":self.config.display_name,"policy_revision":current.state.rings.revision(),"catalog":current.state.rings.catalog(),"assignments":current.state.rings.assignments(now()),"agents":self.config.agent_labels,"passkeys":current.state.credentials.iter().filter(|(_,c)|!c.revoked).map(|(id,c)|json!({"id":id,"label":c.label})).collect::<Vec<_>>(),"requests":[],"rules":[]}),
        )
    }
    pub fn agent_request(&mut self, message: &SignedMessage) -> Result<Value> {
        let current = self.load()?;
        if let Some(output) = current.state.rings.recovered(message, false)? {
            return Ok(json!({"outcome":"recovered","output":output,"dispatch":false}));
        }
        let mut next = current.state.clone();
        let output = next.rings.handle(message, now())?;
        let outcome = self.commit(&current, &next)?;
        Ok(
            json!({"outcome":if outcome==CommitOutcome::CommittedNow{"committed_now"}else{"recovered"},"output":output,"dispatch":outcome==CommitOutcome::CommittedNow}),
        )
    }
}
fn validate_owner_config(config: &OwnerConfig, trust: &AuthorityConfig) -> Result<Webauthn> {
    validate_config(trust)?;
    if !valid_label(&config.display_name)
        || !digest(&config.enrollment_token_hash)
        || config
            .agent_labels
            .iter()
            .any(|(k, n)| !trust.agent_keys.contains(k) || !valid_label(n))
    {
        return reject("invalid owner config");
    }
    let origin =
        Url::parse(&config.origin).map_err(|_| AuthorityError::Rejected("invalid owner origin"))?;
    if origin.origin().ascii_serialization() != config.origin
        || !origin.username().is_empty()
        || origin.password().is_some()
        || !(origin.scheme() == "https"
            || (origin.scheme() == "http"
                && origin.host_str() == Some("localhost")
                && config.rp_id == "localhost"))
    {
        return reject("exact HTTPS origin required; localhost allowed for development");
    }
    WebauthnBuilder::new(&config.rp_id, &origin)
        .map_err(webauthn_error)?
        .rp_name("Signet")
        .allow_subdomains(false)
        .allow_any_port(false)
        .timeout(Duration::from_secs(CHALLENGE_TTL as u64))
        .build()
        .map_err(webauthn_error)
}
#[cfg(test)]
mod tests;
