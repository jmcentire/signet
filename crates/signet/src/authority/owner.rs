//! Isolated owner approval boundary. WebAuthn state never leaves this process.
//! The injected owner signer is inaccessible to agent/browser request parameters.
use super::*;
use sha2::{Digest, Sha256};
use signet_core::Signer;
use std::collections::{BTreeMap, HashMap};
use subtle::ConstantTimeEq;
use webauthn_rs::prelude::*;

pub mod api;
pub mod cloud_kms;
pub mod file_signer;
pub mod http;
pub mod native;
#[cfg(test)]
mod tests;
const CHALLENGE_TTL: i64 = 120;
const SESSION_TTL: i64 = 900;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerConfig {
    pub rp_id: String,
    pub origin: String,
    pub user_id: uuid::Uuid,
    pub display_name: String,
    pub agent_labels: BTreeMap<String, String>,
    /// Operator-delivered, one-time enrollment invitation. Never a recovery bypass.
    pub enrollment_token_hash: String,
    pub enrollment_expires_at: i64,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "purpose", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerIntent {
    ManageRings {
        expected_revision: u64,
        action: super::rings::Management,
    },
    Login,
    Approve {
        proposal_id: String,
    },
    Reject {
        proposal_id: String,
    },
    AddPasskey {
        label: String,
    },
    RevokePasskey {
        credential_id: String,
    },
}
struct Session {
    csrf: String,
    expires: i64,
    authenticated_epoch: Option<u64>,
}
enum Ceremony {
    Register {
        state: PasskeyRegistration,
        label: String,
        bootstrap: bool,
        authorized_by: Option<String>,
    },
    Authenticate {
        state: PasskeyAuthentication,
        intent: OwnerIntent,
        revision: u64,
        proposal_digest: Option<String>,
    },
}
struct Pending {
    session: String,
    expires: i64,
    epoch: u64,
    ceremony: Ceremony,
}
pub struct OwnerService {
    authority: Authority,
    signer: Box<dyn Signer>,
    config: OwnerConfig,
    webauthn: Webauthn,
    sessions: HashMap<String, Session>,
    pending: HashMap<String, Pending>,
}
fn webauthn_error(_: WebauthnError) -> AuthorityError {
    AuthorityError::Rejected("passkey verification failed")
}
fn credential_id(value: &CredentialID) -> String {
    hex::encode(Sha256::digest(value.as_ref()))
}
fn owner_meta(conn: &Connection, key: &str) -> Result<String> {
    Ok(
        conn.query_row("SELECT value FROM owner_meta WHERE key=?1", [key], |r| {
            r.get(0)
        })?,
    )
}
fn epoch(conn: &Connection) -> Result<u64> {
    owner_meta(conn, "epoch")?
        .parse()
        .map_err(|_| AuthorityError::Rejected("invalid owner epoch"))
}
fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
fn valid_label(value: &str) -> bool {
    text(value) && value.len() <= 60
}
fn bump_epoch(tx: &Transaction<'_>) -> Result<u64> {
    let next = epoch(tx)?
        .checked_add(1)
        .ok_or(AuthorityError::Rejected("owner epoch overflow"))?;
    tx.execute(
        "UPDATE owner_meta SET value=?1 WHERE key='epoch'",
        [next.to_string()],
    )?;
    let revision = revision(tx)?
        .checked_add(1)
        .filter(|r| *r <= i64::MAX as u64)
        .ok_or(AuthorityError::Rejected("revision overflow"))?;
    tx.execute(
        "UPDATE meta SET value=?1 WHERE key='revision'",
        [revision.to_string()],
    )?;
    Ok(next)
}
fn active_passkeys(conn: &Connection) -> Result<Vec<Passkey>> {
    let mut stmt =
        conn.prepare("SELECT passkey FROM owner_credentials WHERE revoked=0 ORDER BY id")?;
    let values = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    values
        .into_iter()
        .map(|v| serde_json::from_str(&v).map_err(Into::into))
        .collect()
}
fn proposal(conn: &Connection, id: &str) -> Result<Value> {
    let row: Option<(String, u64, i64, String, String, String)> = conn
        .query_row(
            "SELECT client,revision,expires,action,review,state FROM owner_proposals WHERE id=?1",
            [id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()?;
    let (client, revision, expires, action, review, state) =
        row.ok_or(AuthorityError::Rejected("unknown proposal"))?;
    Ok(
        json!({"proposal_id":id,"client_key":client,"policy_revision":revision,"expires_at":expires,"action":serde_json::from_str::<Value>(&action)?,"review":serde_json::from_str::<Value>(&review)?,"state":state}),
    )
}
fn proposal_digest(value: &Value) -> String {
    hex::encode(Sha256::digest(value.to_string().as_bytes()))
}
fn live_proposal(conn: &Connection, id: &str, rev: u64, time: i64) -> Result<Value> {
    let value = proposal(conn, id)?;
    if value["state"] != "pending"
        || value["expires_at"].as_i64().unwrap_or(0) <= time
        || value["policy_revision"] != rev
    {
        return reject("proposal expired, changed, or already handled");
    }
    Ok(value)
}

impl OwnerService {
    /// Operator-only construction. Config and signer public key are pinned to the protected store.
    pub fn open(
        mut authority: Authority,
        signer: Box<dyn Signer>,
        config: OwnerConfig,
    ) -> Result<Self> {
        if hex::encode(signer.public_key_ed25519()) != authority.config.owner_key
            || !valid_label(&config.display_name)
            || !digest(&config.enrollment_token_hash)
            || config
                .agent_labels
                .iter()
                .any(|(key, name)| !authority.config.agent_keys.contains(key) || !valid_label(name))
        {
            return reject("owner configuration or signer mismatch");
        }
        let origin = Url::parse(&config.origin)
            .map_err(|_| AuthorityError::Rejected("invalid owner origin"))?;
        if origin.origin().ascii_serialization() != config.origin
            || origin.username() != ""
            || origin.password().is_some()
            || !(origin.scheme() == "https"
                || (origin.scheme() == "http"
                    && origin.host_str() == Some("localhost")
                    && config.rp_id == "localhost"))
        {
            return reject(
                "exact HTTPS origin required; HTTP allowed only for localhost development",
            );
        }
        let webauthn = WebauthnBuilder::new(&config.rp_id, &origin)
            .map_err(webauthn_error)?
            .rp_name("Signet")
            .allow_subdomains(false)
            .allow_any_port(false)
            .timeout(Duration::from_secs(CHALLENGE_TTL as u64))
            .build()
            .map_err(webauthn_error)?;
        let tx = authority
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS owner_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS owner_credentials(id TEXT PRIMARY KEY,passkey TEXT NOT NULL,label TEXT NOT NULL,counter INTEGER NOT NULL DEFAULT 0,revoked INTEGER NOT NULL DEFAULT 0,created INTEGER NOT NULL,last_used INTEGER);")?;
        let saved: Option<String> = tx
            .query_row("SELECT value FROM owner_meta WHERE key='config'", [], |r| {
                r.get(0)
            })
            .optional()?;
        let encoded = serde_json::to_string(&config)?;
        if let Some(saved) = saved {
            if saved != encoded {
                return reject("owner relying-party configuration is pinned");
            }
        } else {
            if config.enrollment_expires_at <= now() || config.enrollment_expires_at > now() + 900 {
                return reject("initial enrollment invitation must expire within 15 minutes");
            }
            tx.execute(
                "INSERT INTO owner_meta VALUES ('config',?1),('epoch','0'),('initialized','0')",
                [encoded],
            )?;
        }
        tx.commit()?;
        Ok(Self {
            authority,
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
    pub fn agent_request(&mut self, message: &SignedMessage) -> Result<Value> {
        self.authority.handle(message)
    }
    fn cleanup(&mut self) {
        let time = now();
        self.sessions.retain(|_, v| v.expires > time);
        self.pending.retain(|_, v| v.expires > time);
    }
    /// Session cookies authenticate nothing until a completed passkey assertion.
    pub fn session(&mut self, existing: Option<&str>) -> Result<(String, Value)> {
        self.cleanup();
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
        let epoch = epoch(&self.authority.connection)?;
        let session = &self.sessions[&sid];
        let authenticated = session.authenticated_epoch == Some(epoch);
        Ok((
            sid.clone(),
            json!({"csrf":session.csrf,"authenticated":authenticated,"enrolled":owner_meta(&self.authority.connection,"initialized")?=="1","display_name":if authenticated{Some(&self.config.display_name)}else{None}}),
        ))
    }
    pub fn check_session(&self, sid: &str, csrf: &str, authenticated: bool) -> Result<()> {
        let session = self
            .sessions
            .get(sid)
            .ok_or(AuthorityError::Rejected("session expired"))?;
        if session.expires <= now() || !bool::from(session.csrf.as_bytes().ct_eq(csrf.as_bytes())) {
            return reject("invalid session or CSRF token");
        }
        if authenticated && session.authenticated_epoch != Some(epoch(&self.authority.connection)?)
        {
            return reject("sign in with your passkey");
        }
        Ok(())
    }
    pub fn logout(&mut self, sid: &str, csrf: &str) -> Result<Value> {
        self.check_session(sid, csrf, false)?;
        self.sessions.remove(sid);
        self.pending.retain(|_, p| p.session != sid);
        Ok(json!({"signed_out":true}))
    }
    fn put_pending(
        &mut self,
        sid: &str,
        epoch: u64,
        expires: i64,
        ceremony: Ceremony,
    ) -> Result<String> {
        self.cleanup();
        if self.pending.len() >= 256
            || self.pending.values().filter(|p| p.session == sid).count() >= 4
        {
            return reject("too many active passkey prompts");
        }
        let id = id();
        self.pending.insert(
            id.clone(),
            Pending {
                session: sid.to_owned(),
                expires,
                epoch,
                ceremony,
            },
        );
        Ok(id)
    }
    fn take_pending(&mut self, sid: &str, challenge: &str) -> Result<Pending> {
        let pending = self.pending.get(challenge).ok_or(AuthorityError::Rejected(
            "passkey challenge expired or already used",
        ))?;
        if pending.session != sid {
            return reject("passkey challenge belongs to another session");
        }
        let pending = self
            .pending
            .remove(challenge)
            .ok_or(AuthorityError::Rejected("challenge unavailable"))?;
        if pending.expires <= now() || pending.epoch != epoch(&self.authority.connection)? {
            return reject("passkey challenge expired or revoked");
        }
        Ok(pending)
    }
    fn registration(
        &mut self,
        sid: &str,
        label: String,
        authorization: Option<(u64, String)>,
    ) -> Result<Value> {
        let (authorized_epoch, authorized_by) = match authorization {
            Some((epoch, credential)) => (epoch, Some(credential)),
            None => (epoch(&self.authority.connection)?, None),
        };
        let bootstrap = authorized_by.is_none();
        let credentials = active_passkeys(&self.authority.connection)?;
        if !valid_label(&label) || credentials.len() >= 8 {
            return reject("valid passkey name and fewer than eight keys required");
        }
        let exclude = credentials.iter().map(|c| c.cred_id().clone()).collect();
        let (options, state) = self
            .webauthn
            .start_passkey_registration(
                self.config.user_id,
                &self.config.display_name,
                &self.config.display_name,
                Some(exclude),
            )
            .map_err(webauthn_error)?;
        let challenge_id = self.put_pending(
            sid,
            authorized_epoch,
            now() + CHALLENGE_TTL,
            Ceremony::Register {
                state,
                label,
                bootstrap,
                authorized_by,
            },
        )?;
        Ok(
            json!({"challenge_id":challenge_id,"options":options,"expires_at":now()+CHALLENGE_TTL,"ceremony":"registration"}),
        )
    }
    pub fn begin_enrollment(
        &mut self,
        sid: &str,
        csrf: &str,
        token: &str,
        label: String,
    ) -> Result<Value> {
        self.check_session(sid, csrf, false)?;
        let hash = hex::encode(Sha256::digest(token.as_bytes()));
        if owner_meta(&self.authority.connection, "initialized")? != "0"
            || self.config.enrollment_expires_at <= now()
            || !bool::from(
                hash.as_bytes()
                    .ct_eq(self.config.enrollment_token_hash.as_bytes()),
            )
        {
            return reject("enrollment invitation invalid, expired or already used");
        }
        self.registration(sid, label, None)
    }
    pub fn finish_registration(
        &mut self,
        sid: &str,
        csrf: &str,
        challenge_id: &str,
        response: &RegisterPublicKeyCredential,
    ) -> Result<Value> {
        self.check_session(sid, csrf, false)?;
        let pending = self.take_pending(sid, challenge_id)?;
        let Ceremony::Register {
            state,
            label,
            bootstrap,
            authorized_by,
        } = pending.ceremony
        else {
            return reject("wrong passkey ceremony");
        };
        let passkey = self
            .webauthn
            .finish_passkey_registration(response, &state)
            .map_err(webauthn_error)?;
        let tx = self
            .authority
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if epoch(&tx)? != pending.epoch
            || (bootstrap
                && (owner_meta(&tx, "initialized")? != "0"
                    || self.config.enrollment_expires_at <= now()))
        {
            return reject("enrollment changed or expired");
        }
        if let Some(credential) = authorized_by {
            if tx
                .query_row(
                    "SELECT 1 FROM owner_credentials WHERE id=?1 AND revoked=0",
                    [&credential],
                    |_| Ok(()),
                )
                .optional()?
                .is_none()
            {
                return reject("enrollment authorizing passkey revoked");
            }
        }
        let count: u64 = tx.query_row(
            "SELECT COUNT(*) FROM owner_credentials WHERE revoked=0",
            [],
            |r| r.get(0),
        )?;
        if count >= 8 || (!bootstrap && count == 0) {
            return reject("passkey enrollment state changed");
        }
        let cid = credential_id(passkey.cred_id());
        if tx
            .query_row(
                "SELECT 1 FROM owner_credentials WHERE id=?1",
                [&cid],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return reject("credential already registered or revoked");
        }
        tx.execute(
            "INSERT INTO owner_credentials(id,passkey,label,created) VALUES (?1,?2,?3,?4)",
            params![cid, serde_json::to_string(&passkey)?, label, now()],
        )?;
        tx.execute(
            "UPDATE owner_meta SET value='1' WHERE key='initialized'",
            [],
        )?;
        let new_epoch = bump_epoch(&tx)?;
        audit(
            &tx,
            "owner_passkey_added",
            &json!({"credential_id":cid,"label":label,"bootstrap":bootstrap}),
            now(),
        )?;
        tx.commit()?;
        self.sessions
            .get_mut(sid)
            .ok_or(AuthorityError::Rejected("session lost"))?
            .authenticated_epoch = Some(new_epoch);
        self.pending.clear();
        Ok(json!({"state":"enrolled","credential_id":cid}))
    }
    pub fn begin_authentication(
        &mut self,
        sid: &str,
        csrf: &str,
        intent: OwnerIntent,
    ) -> Result<Value> {
        self.check_session(sid, csrf, !matches!(intent, OwnerIntent::Login))?;
        let credentials = active_passkeys(&self.authority.connection)?;
        if credentials.is_empty() {
            return reject("no active passkey; recovery cannot bypass enrollment");
        }
        let tx = self
            .authority
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let rev = revision(&tx)?;
        let ep = epoch(&tx)?;
        let time = now();
        let mut fingerprint = None;
        let mut expires = time + CHALLENGE_TTL;
        let review = match &intent {
            OwnerIntent::ManageRings { .. } => return reject("use the native rings owner service"),
            OwnerIntent::Approve { proposal_id } | OwnerIntent::Reject { proposal_id } => {
                let p = live_proposal(&tx, proposal_id, rev, time)?;
                fingerprint = Some(proposal_digest(&p));
                expires = expires.min(p["expires_at"].as_i64().unwrap_or(time));
                p["review"].clone()
            }
            OwnerIntent::AddPasskey { label: name } => {
                if !valid_label(name) || credentials.len() >= 8 {
                    return reject("invalid passkey name or capacity");
                }
                json!({"title":"Add a backup passkey","label":name})
            }
            OwnerIntent::RevokePasskey { credential_id } => {
                if credentials.len() < 2 {
                    return reject("add and verify a backup passkey before removing this one");
                }
                let name: Option<String> = tx
                    .query_row(
                        "SELECT label FROM owner_credentials WHERE id=?1 AND revoked=0",
                        [credential_id],
                        |r| r.get(0),
                    )
                    .optional()?;
                json!({"title":"Remove this passkey","label":name.ok_or(AuthorityError::Rejected("unknown active passkey"))?,"effect":"Use a different passkey to confirm. Pending approvals will expire."})
            }
            OwnerIntent::Login => json!({"title":"Sign in to your Signet"}),
        };
        tx.commit()?;
        let allowed = if let OwnerIntent::RevokePasskey {
            credential_id: target,
        } = &intent
        {
            credentials
                .into_iter()
                .filter(|c| credential_id(c.cred_id()) != *target)
                .collect()
        } else {
            credentials
        };
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&allowed)
            .map_err(webauthn_error)?;
        let challenge_id = self.put_pending(
            sid,
            ep,
            expires,
            Ceremony::Authenticate {
                state,
                intent,
                revision: rev,
                proposal_digest: fingerprint,
            },
        )?;
        Ok(
            json!({"challenge_id":challenge_id,"options":options,"review":review,"expires_at":expires,"ceremony":"authentication"}),
        )
    }
    pub fn finish_authentication(
        &mut self,
        sid: &str,
        csrf: &str,
        challenge_id: &str,
        response: &PublicKeyCredential,
    ) -> Result<Value> {
        self.check_session(sid, csrf, false)?;
        let pending = self.take_pending(sid, challenge_id)?;
        let Ceremony::Authenticate {
            state,
            intent,
            revision: expected_revision,
            proposal_digest: expected_digest,
        } = pending.ceremony
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
        let tx = self
            .authority
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if epoch(&tx)? != pending.epoch || pending.expires <= now() {
            return reject("passkey challenge expired or revoked");
        }
        let row: Option<(String, u32)> = tx
            .query_row(
                "SELECT passkey,counter FROM owner_credentials WHERE id=?1 AND revoked=0",
                [&cid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (saved, counter) = row.ok_or(AuthorityError::Rejected("passkey revoked"))?;
        if (counter > 0 || result.counter() > 0) && result.counter() <= counter {
            return reject("passkey counter replay or regression");
        }
        let mut passkey: Passkey = serde_json::from_str(&saved)?;
        passkey
            .update_credential(&result)
            .ok_or(AuthorityError::Rejected("passkey mismatch"))?;
        tx.execute(
            "UPDATE owner_credentials SET passkey=?1,counter=?2,last_used=?3 WHERE id=?4",
            params![
                serde_json::to_string(&passkey)?,
                result.counter(),
                now(),
                cid
            ],
        )?;
        let rev = revision(&tx)?;
        let mut new_epoch = pending.epoch;
        if !matches!(intent, OwnerIntent::Login) && rev != expected_revision {
            return reject("policy changed; review the request again");
        }
        let value = match &intent {
            OwnerIntent::ManageRings { .. } => return reject("use the native rings owner service"),
            OwnerIntent::Login => json!({"state":"signed_in"}),
            OwnerIntent::Approve { proposal_id } | OwnerIntent::Reject { proposal_id } => {
                let p = live_proposal(&tx, proposal_id, rev, now())?;
                if expected_digest.as_deref() != Some(&proposal_digest(&p)) {
                    return reject("reviewed proposal changed");
                }
                if matches!(intent, OwnerIntent::Reject { .. }) {
                    tx.execute(
                        "UPDATE owner_proposals SET state='rejected' WHERE id=?1",
                        [proposal_id],
                    )?;
                    json!({"state":"rejected"})
                } else {
                    let client = p["client_key"]
                        .as_str()
                        .ok_or(AuthorityError::Rejected("proposal client"))?;
                    let action: ApprovedAction = serde_json::from_value(p["action"].clone())?;
                    let mutation = matches!(action, ApprovedAction::RuleMutation { .. });
                    let claims = OwnerApproval {
                        authority_id: self.authority.config.authority_id.clone(),
                        client_key: client.into(),
                        nonce: id(),
                        issued_at: now(),
                        expires_at: p["expires_at"]
                            .as_i64()
                            .unwrap_or(0)
                            .min(now() + CHALLENGE_TTL),
                        policy_revision: rev,
                        action,
                    };
                    let bytes = serde_json::to_vec(&claims)?;
                    let signature = self
                        .signer
                        .sign_ed25519(&signing_bytes(OWNER_DOMAIN, &bytes))
                        .map_err(|_| {
                            AuthorityError::Rejected("isolated owner signer unavailable")
                        })?;
                    let approval = SignedMessage {
                        payload: URL_SAFE_NO_PAD.encode(&bytes),
                        signature: hex::encode(signature),
                    };
                    let grant = submit_owner_grant(
                        &tx,
                        &self.authority.config,
                        client,
                        &approval,
                        rev,
                        now(),
                    )?;
                    let grant_id = grant["grant_id"]
                        .as_str()
                        .ok_or(AuthorityError::Rejected("grant unavailable"))?;
                    let value = if mutation {
                        commit_rule_grant(&tx, client, grant_id, rev, now())?
                    } else {
                        json!({"state":"approved","executed":false})
                    };
                    tx.execute(
                        "UPDATE owner_proposals SET state=?1,grant_id=?2 WHERE id=?3",
                        params![
                            if mutation { "committed" } else { "approved" },
                            grant_id,
                            proposal_id
                        ],
                    )?;
                    audit(
                        &tx,
                        "passkey_owner_approval",
                        &json!({"proposal_id":proposal_id,"credential_id":cid,"approval":approval}),
                        now(),
                    )?;
                    value
                }
            }
            OwnerIntent::AddPasskey { .. } => json!({"state":"registration_authorized"}),
            OwnerIntent::RevokePasskey {
                credential_id: target,
            } => {
                if target == &cid {
                    return reject("use a different passkey to revoke this credential");
                }
                let count: u64 = tx.query_row(
                    "SELECT COUNT(*) FROM owner_credentials WHERE revoked=0",
                    [],
                    |r| r.get(0),
                )?;
                if count < 2
                    || tx.execute(
                        "UPDATE owner_credentials SET revoked=1 WHERE id=?1 AND revoked=0",
                        [target],
                    )? != 1
                {
                    return reject("cannot revoke last or unknown passkey");
                }
                new_epoch = bump_epoch(&tx)?;
                audit(
                    &tx,
                    "owner_passkey_revoked",
                    &json!({"credential_id":target,"confirmed_by":cid}),
                    now(),
                )?;
                json!({"state":"revoked"})
            }
        };
        audit(
            &tx,
            "owner_verified",
            &json!({"credential_id":cid,"intent":intent}),
            now(),
        )?;
        tx.commit()?;
        self.sessions
            .get_mut(sid)
            .ok_or(AuthorityError::Rejected("session lost"))?
            .authenticated_epoch = Some(new_epoch);
        if new_epoch != pending.epoch {
            self.pending.clear();
        }
        if let OwnerIntent::AddPasskey { label } = intent {
            self.registration(sid, label, Some((pending.epoch, cid)))
        } else {
            Ok(value)
        }
    }
    pub fn dashboard(&mut self, sid: &str, csrf: &str) -> Result<Value> {
        self.check_session(sid, csrf, true)?;
        let tx = self
            .authority
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let rev = revision(&tx)?;
        let ids=tx.prepare("SELECT id FROM owner_proposals WHERE state='pending' AND expires>?1 AND revision=?2 ORDER BY rowid DESC LIMIT 32")?
            .query_map(params![now(),rev],|r|r.get::<_,String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?;
        let mut requests = Vec::new();
        for id in ids {
            let mut p = proposal(&tx, &id)?;
            let client = p["client_key"].as_str().unwrap_or_default();
            p["agent_label"] = json!(self
                .config
                .agent_labels
                .get(client)
                .map(String::as_str)
                .unwrap_or("Connected agent"));
            p.as_object_mut().unwrap().remove("action");
            requests.push(p);
        }
        let credentials=tx.prepare("SELECT id,label,created,last_used FROM owner_credentials WHERE revoked=0 ORDER BY created,id")?.query_map([],|r|Ok(json!({"id":r.get::<_,String>(0)?,"label":r.get::<_,String>(1)?,"created_at":r.get::<_,i64>(2)?,"last_used":r.get::<_,Option<i64>>(3)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
        let rules = tx
            .prepare("SELECT id,version,body FROM rules WHERE body IS NOT NULL ORDER BY id")?
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .map(|(id, version, body)| {
                let rule: Rule = serde_json::from_str(&body)?;
                let docs = proposals::saved_documents(&tx, &rule)?;
                let review = proposals::rule_review(&tx, &rule, &docs).ok();
                let mut rule_json = serde_json::to_value(&rule)?;
                if let Rule::SpendLimit {
                    max_total_minor, ..
                } = rule
                {
                    rule_json["max_total_minor"] = json!(max_total_minor.to_string());
                }
                Ok(json!({"id":id,"version":version,"rule":rule_json,"review":review}))
            })
            .collect::<Result<Vec<_>>>()?;
        tx.commit()?;
        Ok(
            json!({"display_name":self.config.display_name,"requests":requests,"passkeys":credentials,"rules":rules,"policy_revision":rev,"recovery":"Use a separately enrolled backup passkey. Losing every passkey requires an operator-reviewed new authority and ledger reconciliation; there is no email or agent reset."}),
        )
    }
}
