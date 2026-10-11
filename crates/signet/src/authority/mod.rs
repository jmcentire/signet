//! Durable, authenticated authority boundary; deliberately separate from legacy MCP dispatch.
//! Deploy in a process/account whose database, config and owner signer agents cannot modify.
mod mcp;
pub mod object_store;
pub mod owner;
mod proposals;
pub mod rings;
mod types;
pub use mcp::AuthorityMcpSession;
pub use types::*;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::{fs, path::Path, time::Duration};

fn reject<T>(reason: &'static str) -> Result<T> {
    Err(AuthorityError::Rejected(reason))
}
fn text(s: &str) -> bool {
    !s.trim().is_empty()
        && s.len() <= 512
        && !s.chars().any(|c| {
            c.is_control()
                || ('\u{202a}'..='\u{202e}').contains(&c)
                || ('\u{2066}'..='\u{2069}').contains(&c)
        })
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn key(s: &str) -> Result<VerifyingKey> {
    if !digest(s) {
        return reject("invalid public key");
    }
    let bytes: [u8; 32] = hex::decode(s)
        .map_err(|_| AuthorityError::Rejected("public key"))?
        .try_into()
        .map_err(|_| AuthorityError::Rejected("public key"))?;
    let key =
        VerifyingKey::from_bytes(&bytes).map_err(|_| AuthorityError::Rejected("public key"))?;
    if key.is_weak() {
        return reject("weak public key");
    }
    Ok(key)
}
/// Cross-language signing contract: UTF-8 domain, NUL, then original decoded JSON bytes.
pub fn signing_bytes(domain: &str, payload: &[u8]) -> Vec<u8> {
    [domain.as_bytes(), &[0], payload].concat()
}
fn decode<T: DeserializeOwned>(signed: &SignedMessage) -> Result<(T, Vec<u8>)> {
    if signed.payload.len() > MAX_MESSAGE || signed.signature.len() != 128 {
        return reject("message size");
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(&signed.payload)
        .map_err(|_| AuthorityError::Rejected("payload encoding"))?;
    let value = serde_json::from_slice(&bytes)?;
    Ok((value, bytes))
}
fn verify<T: DeserializeOwned>(signed: &SignedMessage, signer: &str, domain: &str) -> Result<T> {
    let (value, bytes) = decode(signed)?;
    let signature = hex::decode(&signed.signature)
        .map_err(|_| AuthorityError::Rejected("signature encoding"))?;
    let signature = Signature::from_slice(&signature)
        .map_err(|_| AuthorityError::Rejected("signature encoding"))?;
    key(signer)?
        .verify_strict(&signing_bytes(domain, &bytes), &signature)
        .map_err(|_| AuthorityError::Rejected("signature verification"))?;
    Ok(value)
}
fn lifetime(issued: i64, expires: i64, now: i64) -> Result<()> {
    if issued < 0
        || issued > now
        || expires <= now
        || expires <= issued
        || expires.saturating_sub(issued) > MAX_TTL
    {
        return reject("expired, future-dated or excessive lifetime");
    }
    Ok(())
}
fn validate_purchase(p: &Purchase) -> Result<()> {
    if [
        &p.merchant,
        &p.currency,
        &p.item_id,
        &p.description,
        &p.category,
    ]
    .iter()
    .any(|s| !text(s))
        || p.currency.len() != 3
        || !p.currency.bytes().all(|b| b.is_ascii_uppercase())
        || p.total_minor == 0
        || p.total_minor > i64::MAX as u64
        || p.quantity == 0
        || !digest(&p.requirements_digest)
        || !digest(&p.terms_digest)
        || !digest(&p.fulfillment_digest)
    {
        return reject("invalid exact purchase");
    }
    Ok(())
}
fn id() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

pub struct Authority {
    connection: Connection,
    config: AuthorityConfig,
}

impl Authority {
    /// Explicit operator bootstrap, not exposed through the agent adapter.
    /// The parent directory must already be private; the file must not exist.
    pub fn create(path: &Path, config: AuthorityConfig) -> Result<Self> {
        validate_config(&config)?;
        check_parent(path)?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        drop(options.open(path)?);
        let mut connection = connect(path)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE requests (client TEXT NOT NULL, nonce TEXT NOT NULL, PRIMARY KEY(client,nonce));
            CREATE TABLE owner_nonces (nonce TEXT PRIMARY KEY);
            CREATE TABLE grants (id TEXT PRIMARY KEY, body TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE rules (id TEXT PRIMARY KEY, version INTEGER NOT NULL, body TEXT);
            CREATE TABLE executions (id TEXT PRIMARY KEY, client TEXT NOT NULL, body TEXT NOT NULL, state TEXT NOT NULL, detail TEXT);
            CREATE TABLE receipts (id TEXT PRIMARY KEY, purchase TEXT NOT NULL, provider_reference TEXT NOT NULL UNIQUE, execution_id TEXT NOT NULL UNIQUE);
            CREATE TABLE audit (sequence INTEGER PRIMARY KEY, event TEXT NOT NULL, body TEXT NOT NULL, at INTEGER NOT NULL);")?;
        tx.execute(
            "INSERT INTO meta VALUES ('config',?1),('revision','0'),('schema','1')",
            [serde_json::to_string(&config)?],
        )?;
        tx.commit()?;
        approval_results_schema(&connection)?;
        proposals::schema(&connection)?;
        Ok(Self { connection, config })
    }
    /// Opens an existing pinned configuration; never silently bootstraps or changes keys.
    pub fn open(path: &Path, config: AuthorityConfig) -> Result<Self> {
        validate_config(&config)?;
        check_parent(path)?;
        let connection = connect(path)?;
        let saved: String =
            connection.query_row("SELECT value FROM meta WHERE key='config'", [], |r| {
                r.get(0)
            })?;
        let schema: String =
            connection.query_row("SELECT value FROM meta WHERE key='schema'", [], |r| {
                r.get(0)
            })?;
        if saved != serde_json::to_string(&config)? || schema != "1" {
            return reject("configuration or schema mismatch");
        }
        approval_results_schema(&connection)?;
        proposals::schema(&connection)?;
        Ok(Self { connection, config })
    }
    /// Every caller proves possession of a provisioned agent/executor key.
    /// Time comes from the service clock, never from model-provided approval flags.
    pub fn handle(&mut self, signed: &SignedMessage) -> Result<Value> {
        let (untrusted, _): (Request, _) = decode(signed)?;
        let executor = untrusted.client_key == self.config.executor_key;
        if !executor && !self.config.agent_keys.contains(&untrusted.client_key) {
            return reject("unregistered client");
        }
        let request: Request = verify(signed, &untrusted.client_key, CLIENT_DOMAIN)?;
        if request.authority_id != self.config.authority_id || !digest(&request.nonce) {
            return reject("request scope");
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = chrono::Utc::now().timestamp();
        lifetime(request.issued_at, request.expires_at, now)?;
        if tx.execute(
            "INSERT OR IGNORE INTO requests VALUES (?1,?2)",
            params![request.client_key, request.nonce],
        )? != 1
        {
            return reject("request replay");
        }
        let revision = revision(&tx)?;
        let value = dispatch(&tx, &self.config, &request, executor, revision, now)?;
        audit(&tx, "authenticated_request", signed, now)?;
        tx.commit()?;
        Ok(value)
    }
}

fn approval_results_schema(connection: &Connection) -> Result<()> {
    connection.execute_batch("CREATE TABLE IF NOT EXISTS approval_results (nonce TEXT PRIMARY KEY, client TEXT NOT NULL, grant_id TEXT NOT NULL UNIQUE REFERENCES grants(id));")?;
    Ok(())
}

fn validate_config(c: &AuthorityConfig) -> Result<()> {
    if !text(&c.authority_id) || c.agent_keys.is_empty() || c.agent_keys.len() > 64 {
        return reject("configuration");
    }
    key(&c.owner_key)?;
    key(&c.executor_key)?;
    let mut keys = std::collections::HashSet::new();
    for k in [&c.owner_key, &c.executor_key]
        .into_iter()
        .chain(c.agent_keys.iter())
    {
        key(k)?;
        if !keys.insert(k) {
            return reject("owner, executor and agents require distinct keys");
        }
    }
    Ok(())
}
fn check_parent(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or(AuthorityError::Rejected(
        "private parent directory required",
    ))?;
    let meta = fs::symlink_metadata(parent)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return reject("private parent directory required");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return reject("parent directory must be mode 0700");
        }
    }
    #[cfg(not(unix))]
    {
        return reject("OS access-control backend unavailable");
    }
    Ok(())
}
fn connect(path: &Path) -> Result<Connection> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return reject("regular private database required");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return reject("database must be mode 0600");
        }
    }
    let connection = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
    )?;
    Ok(connection)
}
fn revision(tx: &Transaction<'_>) -> Result<u64> {
    let v: String = tx.query_row("SELECT value FROM meta WHERE key='revision'", [], |r| {
        r.get(0)
    })?;
    v.parse()
        .map_err(|_| AuthorityError::Rejected("invalid policy revision"))
}
fn audit(tx: &Transaction<'_>, event: &str, value: &impl Serialize, now: i64) -> Result<()> {
    tx.execute(
        "INSERT INTO audit(event,body,at) VALUES (?1,?2,?3)",
        params![event, serde_json::to_string(value)?, now],
    )?;
    Ok(())
}
fn quote(
    config: &AuthorityConfig,
    signed: &SignedMessage,
    client: &str,
    now: i64,
) -> Result<Quote> {
    let q: Quote = verify(signed, &config.executor_key, QUOTE_DOMAIN)?;
    lifetime(q.issued_at, q.expires_at, now)?;
    if q.authority_id != config.authority_id || q.client_key != client || !digest(&q.quote_id) {
        return reject("quote scope");
    }
    validate_purchase(&q.purchase)?;
    Ok(q)
}
fn grant(
    tx: &Transaction<'_>,
    id: &str,
    client: Option<&str>,
    revision: u64,
    now: i64,
) -> Result<StoredGrant> {
    let row: Option<(String, bool, bool)> = tx
        .query_row(
            "SELECT body,consumed,revoked FROM grants WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let (body, consumed, revoked) = row.ok_or(AuthorityError::Rejected("unknown grant"))?;
    let g: StoredGrant = serde_json::from_str(&body)?;
    if consumed
        || revoked
        || g.expires_at <= now
        || g.policy_revision != revision
        || client.is_some_and(|c| c != g.client_key)
    {
        return reject("spent, revoked, expired, stale or wrong-client grant");
    }
    Ok(g)
}
fn issue(tx: &Transaction<'_>, g: StoredGrant, now: i64) -> Result<Value> {
    let id = id();
    tx.execute(
        "INSERT INTO grants(id,body) VALUES (?1,?2)",
        params![id, serde_json::to_string(&g)?],
    )?;
    audit(tx, "grant_issued", &json!({"grant_id":id,"grant":g}), now)?;
    Ok(
        json!({"grant_id":id,"policy_revision":g.policy_revision,"expires_at":g.expires_at,"state":"issued","executed":false}),
    )
}
fn consume(tx: &Transaction<'_>, id: &str) -> Result<()> {
    if tx.execute(
        "UPDATE grants SET consumed=1 WHERE id=?1 AND consumed=0 AND revoked=0",
        [id],
    )? != 1
    {
        return reject("grant replay");
    }
    Ok(())
}

fn dispatch(
    tx: &Transaction<'_>,
    c: &AuthorityConfig,
    r: &Request,
    executor: bool,
    rev: u64,
    now: i64,
) -> Result<Value> {
    match &r.command {
        Command::ProposeApproval { action, documents } if !executor => {
            proposals::create(tx, c, &r.client_key, rev, action, documents, now)
        }
        Command::ApprovalStatus { proposal_id } if !executor => {
            proposals::status(tx, proposal_id, &r.client_key, rev, now)
        }
        Command::SubmittedApprovalStatus { owner_nonce } if !executor => {
            if !digest(owner_nonce) {
                return reject("invalid owner nonce");
            }
            let row: Option<(String, String, bool, bool)> = tx.query_row(
                "SELECT g.id,g.body,g.consumed,g.revoked FROM approval_results a JOIN grants g ON g.id=a.grant_id WHERE a.nonce=?1 AND a.client=?2",
                params![owner_nonce,r.client_key],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
            ).optional()?;
            let (id, body, consumed, revoked) =
                row.ok_or(AuthorityError::Rejected("unknown submitted approval"))?;
            let grant: StoredGrant = serde_json::from_str(&body)?;
            let state = if consumed {
                "consumed"
            } else if revoked {
                "revoked"
            } else if grant.policy_revision != rev {
                "stale"
            } else if grant.expires_at <= now {
                "expired"
            } else {
                "issued"
            };
            Ok(
                json!({"grant_id":id,"state":state,"policy_revision":grant.policy_revision,"expires_at":grant.expires_at}),
            )
        }
        Command::Snapshot => {
            let mut stmt =
                tx.prepare("SELECT id,version,body FROM rules WHERE body IS NOT NULL ORDER BY id")?;
            let rules=stmt.query_map([],|row|Ok((row.get::<_,String>(0)?,row.get::<_,u64>(1)?,row.get::<_,String>(2)?)))?
                .map(|row|{let (id,version,body)=row?;Ok(json!({"id":id,"version":version,"rule":serde_json::from_str::<Value>(&body)?}))}).collect::<Result<Vec<_>>>()?;
            let mut stmt = tx.prepare(
                "SELECT id,state,detail,body FROM executions WHERE client=?1 OR ?2 ORDER BY id",
            )?;
            let executions=stmt.query_map(params![r.client_key,executor],|row|Ok(json!({"execution_id":row.get::<_,String>(0)?,"state":row.get::<_,String>(1)?,"detail":row.get::<_,Option<String>>(2)?,"purchase_json":row.get::<_,String>(3)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
            Ok(
                json!({"authority_id":c.authority_id,"policy_revision":rev,"rules":rules,"executions":executions}),
            )
        }
        Command::PreparePurchase { quote: signed } if !executor => {
            let q = quote(c, signed, &r.client_key, now)?;
            if let Some(reason) = needs_approval(tx, &q.purchase)? {
                return Ok(
                    json!({"state":"requires_owner_approval","reason":reason,"policy_revision":rev,"executed":false}),
                );
            }
            issue(
                tx,
                StoredGrant {
                    client_key: r.client_key.clone(),
                    expires_at: q.expires_at,
                    policy_revision: rev,
                    action: ApprovedAction::Purchase {
                        quote: signed.clone(),
                    },
                },
                now,
            )
        }
        Command::SubmitApproval { approval } if !executor => {
            submit_owner_grant(tx, c, &r.client_key, approval, rev, now)
        }
        Command::CommitMutation { grant_id } if !executor => {
            commit_rule_grant(tx, &r.client_key, grant_id, rev, now)
        }
        Command::ConsumePurchase { grant_id, purchase } if executor => {
            let g = grant(tx, grant_id, None, rev, now)?;
            let ApprovedAction::Purchase { quote: signed } = g.action else {
                return reject("rule grant cannot authorize purchases");
            };
            let q = quote(c, &signed, &g.client_key, now)?;
            if purchase != &q.purchase {
                return reject("purchase differs from exact grant");
            }
            // A quote identifies one purchase intent. Multiple grants for it cannot duplicate work.
            if tx
                .query_row(
                    "SELECT 1 FROM executions WHERE id=?1",
                    [&q.quote_id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some()
            {
                return reject("purchase intent already reserved");
            }
            consume(tx, grant_id)?;
            tx.execute(
                "INSERT INTO executions(id,client,body,state) VALUES (?1,?2,?3,'reserved')",
                params![q.quote_id, g.client_key, serde_json::to_string(purchase)?],
            )?;
            audit(
                tx,
                "purchase_reserved",
                &json!({"execution_id":q.quote_id,"grant_id":grant_id,"purchase":purchase}),
                now,
            )?;
            Ok(
                json!({"state":"reserved","execution_id":q.quote_id,"provider_idempotency_key":q.quote_id,"purchase":purchase,"executed":false}),
            )
        }
        Command::CompletePurchase {
            execution_id,
            outcome,
        } if executor => {
            let row: Option<(String, String)> = tx
                .query_row(
                    "SELECT body,state FROM executions WHERE id=?1",
                    [execution_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let (purchase, state) = row.ok_or(AuthorityError::Rejected("unknown execution"))?;
            if state != "reserved" {
                return reject("terminal execution cannot be overwritten");
            }
            let terminal = match outcome {
                Completion::Succeeded { provider_reference } => {
                    if !text(provider_reference) {
                        return reject("provider reference required");
                    }
                    tx.execute(
                        "INSERT INTO receipts VALUES (?1,?2,?3,?1)",
                        params![execution_id, purchase, provider_reference],
                    )?;
                    "succeeded"
                }
                Completion::Failed { reason } => {
                    if !text(reason) {
                        return reject("failure reason required");
                    }
                    "failed"
                }
                Completion::Unknown { reason } => {
                    if !text(reason) {
                        return reject("uncertainty reason required");
                    }
                    "unknown"
                }
            };
            tx.execute(
                "UPDATE executions SET state=?1,detail=?2 WHERE id=?3",
                params![terminal, serde_json::to_string(outcome)?, execution_id],
            )?;
            audit(
                tx,
                "executor_result",
                &json!({"execution_id":execution_id,"outcome":outcome}),
                now,
            )?;
            Ok(
                json!({"state":terminal,"execution_id":execution_id,"receipt_id":if terminal=="succeeded"{Some(execution_id)}else{None}}),
            )
        }
        _ => reject("caller role cannot perform operation"),
    }
}

fn receipt(tx: &Transaction<'_>, id: &str) -> Result<Purchase> {
    let body: Option<String> = tx
        .query_row("SELECT purchase FROM receipts WHERE id=?1", [id], |r| {
            r.get(0)
        })
        .optional()?;
    Ok(serde_json::from_str(&body.ok_or(
        AuthorityError::Rejected("verified completed receipt required"),
    )?)?)
}
fn validate_rule(tx: &Transaction<'_>, rule: &Rule) -> Result<()> {
    match rule {
        Rule::SpendLimit {
            merchant,
            currency,
            requirements_digest,
            max_total_minor,
        } => {
            if !text(merchant)
                || currency.len() != 3
                || !currency.bytes().all(|b| b.is_ascii_uppercase())
                || !digest(requirements_digest)
                || *max_total_minor == 0
                || *max_total_minor > i64::MAX as u64
            {
                return reject("invalid spend rule");
            }
        }
        Rule::RequireConfirmation { category } => {
            if category.as_ref().is_some_and(|x| !text(x)) {
                return reject("invalid category");
            }
        }
        Rule::Reorder { receipt_id } => {
            receipt(tx, receipt_id)?;
        }
    }
    Ok(())
}
fn validate_mutation(tx: &Transaction<'_>, mutation: &Mutation) -> Result<()> {
    let (id, expected, new) = match mutation {
        Mutation::Add { rule_id, rule } => (rule_id, None, Some(rule)),
        Mutation::Edit {
            rule_id,
            expected_version,
            rule,
        } => (rule_id, Some(*expected_version), Some(rule)),
        Mutation::Remove {
            rule_id,
            expected_version,
        } => (rule_id, Some(*expected_version), None),
        Mutation::RevokeGrant { grant_id } => {
            if tx
                .query_row("SELECT 1 FROM grants WHERE id=?1", [grant_id], |_| Ok(()))
                .optional()?
                .is_none()
            {
                return reject("unknown revocation target");
            }
            return Ok(());
        }
    };
    if !text(id) {
        return reject("rule identifier");
    }
    let row: Option<(u64, Option<String>)> = tx
        .query_row("SELECT version,body FROM rules WHERE id=?1", [id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    match (expected, row) {
        (None, None) => {}
        (Some(expected), Some((current, Some(_))))
            if expected == current && current < i64::MAX as u64 => {}
        _ => return reject("rule exists, is removed or has a stale version"),
    }
    if let Some(rule) = new {
        validate_rule(tx, rule)?;
    }
    Ok(())
}
fn apply_mutation(tx: &Transaction<'_>, m: &Mutation) -> Result<()> {
    match m {
        Mutation::Add { rule_id, rule } => {
            tx.execute(
                "INSERT INTO rules VALUES (?1,1,?2)",
                params![rule_id, serde_json::to_string(rule)?],
            )?;
        }
        Mutation::Edit { rule_id, rule, .. } => {
            tx.execute(
                "UPDATE rules SET version=version+1,body=?1 WHERE id=?2",
                params![serde_json::to_string(rule)?, rule_id],
            )?;
        }
        Mutation::Remove { rule_id, .. } => {
            tx.execute(
                "UPDATE rules SET version=version+1,body=NULL WHERE id=?1",
                [rule_id],
            )?;
        }
        Mutation::RevokeGrant { grant_id } => {
            tx.execute("UPDATE grants SET revoked=1 WHERE id=?1", [grant_id])?;
        }
    }
    Ok(())
}
fn same_reorder(a: &Purchase, b: &Purchase) -> bool {
    let mut a = a.clone();
    a.total_minor = b.total_minor;
    a == *b
}
fn needs_approval(tx: &Transaction<'_>, p: &Purchase) -> Result<Option<&'static str>> {
    let mut stmt = tx.prepare("SELECT body FROM rules WHERE body IS NOT NULL ORDER BY id")?;
    let rules = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut ceiling: Option<u64> = None;
    let mut reorders = Vec::new();
    for body in rules {
        match serde_json::from_str::<Rule>(&body)? {
            Rule::RequireConfirmation { category }
                if category.is_none() || category.as_ref() == Some(&p.category) =>
            {
                return Ok(Some("confirmation rule"))
            }
            Rule::SpendLimit {
                merchant,
                currency,
                requirements_digest,
                max_total_minor,
            } if merchant == p.merchant
                && currency == p.currency
                && requirements_digest == p.requirements_digest =>
            {
                ceiling = Some(ceiling.map_or(max_total_minor, |old| old.min(max_total_minor)));
            }
            Rule::Reorder { receipt_id } => {
                let prior = receipt(tx, &receipt_id)?;
                // Matching item cannot bypass its recurring conditions via a general limit.
                if prior.item_id == p.item_id {
                    reorders.push(prior);
                }
            }
            _ => {}
        }
    }
    if !reorders.is_empty() {
        for prior in reorders {
            if !same_reorder(&prior, p) || p.total_minor > prior.total_minor {
                return Ok(Some(
                    "reorder exceeds approved baseline or changes conditions",
                ));
            }
        }
        return Ok(None);
    }
    Ok(match ceiling {
        Some(limit) if p.total_minor <= limit => None,
        _ => Some("no matching standing allowance"),
    })
}

fn submit_owner_grant(
    tx: &Transaction<'_>,
    c: &AuthorityConfig,
    client: &str,
    approval: &SignedMessage,
    rev: u64,
    now: i64,
) -> Result<Value> {
    let a: OwnerApproval = verify(approval, &c.owner_key, OWNER_DOMAIN)?;
    lifetime(a.issued_at, a.expires_at, now)?;
    if a.authority_id != c.authority_id
        || a.client_key != client
        || a.policy_revision != rev
        || !digest(&a.nonce)
    {
        return reject("owner approval scope or revision");
    }
    let expires = match &a.action {
        ApprovedAction::Purchase { quote: signed } => {
            quote(c, signed, client, now)?.expires_at.min(a.expires_at)
        }
        ApprovedAction::RuleMutation { mutation } => {
            validate_mutation(tx, mutation)?;
            a.expires_at
        }
    };
    if tx.execute("INSERT OR IGNORE INTO owner_nonces VALUES (?1)", [&a.nonce])? != 1 {
        return reject("owner approval replay");
    }
    let result = issue(
        tx,
        StoredGrant {
            client_key: client.to_owned(),
            expires_at: expires,
            policy_revision: rev,
            action: a.action,
        },
        now,
    )?;
    tx.execute(
        "INSERT INTO approval_results(nonce,client,grant_id) VALUES (?1,?2,?3)",
        params![
            a.nonce,
            client,
            result["grant_id"]
                .as_str()
                .ok_or(AuthorityError::Rejected("grant unavailable"))?
        ],
    )?;
    Ok(result)
}

fn commit_rule_grant(
    tx: &Transaction<'_>,
    client: &str,
    grant_id: &str,
    rev: u64,
    now: i64,
) -> Result<Value> {
    let g = grant(tx, grant_id, Some(client), rev, now)?;
    let ApprovedAction::RuleMutation { mutation } = g.action else {
        return reject("purchase grant cannot mutate rules");
    };
    validate_mutation(tx, &mutation)?;
    apply_mutation(tx, &mutation)?;
    consume(tx, grant_id)?;
    let new_rev = rev
        .checked_add(1)
        .filter(|x| *x <= i64::MAX as u64)
        .ok_or(AuthorityError::Rejected("revision overflow"))?;
    tx.execute(
        "UPDATE meta SET value=?1 WHERE key='revision'",
        [new_rev.to_string()],
    )?;
    audit(
        tx,
        "rule_commit",
        &json!({"grant_id":grant_id,"mutation":mutation,"policy_revision":new_rev}),
        now,
    )?;
    Ok(json!({"state":"committed","policy_revision":new_rev}))
}
