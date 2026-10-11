//! Agent proposals are immutable, client-authenticated data, never owner approval.
use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(crate) fn schema(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS owner_proposals (
        id TEXT PRIMARY KEY, client TEXT NOT NULL, revision INTEGER NOT NULL,
        expires INTEGER NOT NULL, action TEXT NOT NULL, review TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'pending', grant_id TEXT);
        CREATE TABLE IF NOT EXISTS owner_documents(digest TEXT PRIMARY KEY,body TEXT NOT NULL);",
    )?;
    Ok(())
}
pub(crate) fn review(
    tx: &Transaction<'_>,
    config: &AuthorityConfig,
    client: &str,
    action: &ApprovedAction,
    documents: &BTreeMap<String, String>,
    now: i64,
) -> Result<Value> {
    if documents.len() > 12 {
        return reject("too many review documents");
    }
    for (hash, body) in documents {
        if body.trim().is_empty()
            || body.len() > 4096
            || body.chars().any(|c| {
                c.is_control()
                    || ('\u{202a}'..='\u{202e}').contains(&c)
                    || ('\u{2066}'..='\u{2069}').contains(&c)
            })
            || hex::encode(Sha256::digest(body.as_bytes())) != *hash
        {
            return reject("review text does not match signed digest");
        }
    }
    match action {
        ApprovedAction::Purchase { quote: signed } => {
            let q = quote(config, signed, client, now)?;
            Ok(
                json!({"kind":"purchase","title":q.purchase.description,"purchase":purchase_review(&q.purchase,documents)?,
                "effect":"One exact purchase. Your standing rules and reorder baselines stay unchanged.","expires_at":q.expires_at}),
            )
        }
        ApprovedAction::RuleMutation { mutation } => {
            validate_mutation(tx, mutation)?;
            match mutation {
                Mutation::Add { rule_id, rule } => Ok(
                    json!({"kind":"rule_add","title":"Add a rule","rule_id":rule_id,"before":Value::Null,"after":rule_review(tx,rule,documents)?,"effect":"Add this exact rule once. This does not approve a purchase."}),
                ),
                Mutation::Edit {
                    rule_id,
                    expected_version,
                    rule,
                } => Ok(
                    json!({"kind":"rule_edit","title":"Change a rule","rule_id":rule_id,"expected_version":expected_version,"before":current_rule(tx,rule_id,documents)?,"after":rule_review(tx,rule,documents)?,"effect":"Replace only this rule at the displayed version. This does not approve a purchase."}),
                ),
                Mutation::Remove {
                    rule_id,
                    expected_version,
                } => Ok(
                    json!({"kind":"rule_remove","title":"Remove a rule","rule_id":rule_id,"expected_version":expected_version,"before":current_rule(tx,rule_id,documents)?,"after":Value::Null,"effect":"Remove this rule once. Other rules stay in place. This may allow more actions without asking."}),
                ),
                Mutation::RevokeGrant { grant_id } => {
                    let body: String =
                        tx.query_row("SELECT body FROM grants WHERE id=?1", [grant_id], |r| {
                            r.get(0)
                        })?;
                    let grant: StoredGrant = serde_json::from_str(&body)?;
                    let target = match &grant.action {
                        ApprovedAction::Purchase { quote: signed } => {
                            let (q, _): (Quote, _) = decode(signed)?;
                            purchase_review(&q.purchase, documents)?
                        }
                        ApprovedAction::RuleMutation { mutation } => {
                            serde_json::to_value(mutation)?
                        }
                    };
                    Ok(
                        json!({"kind":"grant_revoke","title":"Revoke a permission","grant_id":grant_id,"target":target,"effect":"Revoke this grant and invalidate older unspent approvals. A purchase already reserved cannot be undone here."}),
                    )
                }
            }
        }
    }
}
fn document<'a>(documents: &'a BTreeMap<String, String>, hash: &str) -> Result<&'a str> {
    documents
        .get(hash)
        .map(String::as_str)
        .ok_or(AuthorityError::Rejected(
            "readable signed terms required before approval",
        ))
}
fn purchase_review(p: &Purchase, docs: &BTreeMap<String, String>) -> Result<Value> {
    Ok(
        json!({"merchant":p.merchant,"currency":p.currency,"total_minor":p.total_minor.to_string(),"item":p.description,
        "item_id":p.item_id,"quantity":p.quantity,"category":p.category,
        "requirements":document(docs,&p.requirements_digest)?,"terms":document(docs,&p.terms_digest)?,"fulfillment":document(docs,&p.fulfillment_digest)?}),
    )
}
pub(crate) fn rule_review(
    tx: &Transaction<'_>,
    rule: &Rule,
    docs: &BTreeMap<String, String>,
) -> Result<Value> {
    match rule {
        Rule::SpendLimit {
            merchant,
            currency,
            requirements_digest,
            max_total_minor,
        } => Ok(
            json!({"kind":"spend_limit","merchant":merchant,"currency":currency,"total_minor":max_total_minor.to_string(),"requirements":document(docs,requirements_digest)?,"meaning":"Per purchase, including mandatory charges. Not a daily budget."}),
        ),
        Rule::RequireConfirmation { category } => Ok(
            json!({"kind":"require_confirmation","category":category,"meaning":"Always ask before matching purchases, even inside a spending limit."}),
        ),
        Rule::Reorder { receipt_id } => Ok(
            json!({"kind":"reorder","receipt_id":receipt_id,"baseline":purchase_review(&receipt(tx,receipt_id)?,docs)?,"meaning":"Same order at or below this completed receipt total. This separate allowance can exceed a general spending limit; confirmation rules still apply. No automatic price increases."}),
        ),
    }
}
fn current_rule(tx: &Transaction<'_>, id: &str, docs: &BTreeMap<String, String>) -> Result<Value> {
    let body: String = tx.query_row("SELECT body FROM rules WHERE id=?1", [id], |r| r.get(0))?;
    rule_review(tx, &serde_json::from_str(&body)?, docs)
}
pub(crate) fn create(
    tx: &Transaction<'_>,
    c: &AuthorityConfig,
    client: &str,
    rev: u64,
    action: &ApprovedAction,
    documents: &BTreeMap<String, String>,
    now: i64,
) -> Result<Value> {
    let count: u64 = tx.query_row(
        "SELECT COUNT(*) FROM owner_proposals WHERE client=?1 AND state='pending' AND expires>?2",
        params![client, now],
        |r| r.get(0),
    )?;
    if count >= 32 {
        return reject("pending proposal limit");
    }
    let review = review(tx, c, client, action, documents, now)?;
    for (hash, body) in documents {
        tx.execute(
            "INSERT OR IGNORE INTO owner_documents(digest,body) VALUES (?1,?2)",
            params![hash, body],
        )?;
    }
    let expires = review
        .get("expires_at")
        .and_then(Value::as_i64)
        .unwrap_or(now + MAX_TTL)
        .min(now + MAX_TTL);
    let id = id();
    tx.execute("INSERT INTO owner_proposals(id,client,revision,expires,action,review) VALUES (?1,?2,?3,?4,?5,?6)",params![id,client,rev,expires,serde_json::to_string(action)?,serde_json::to_string(&review)?])?;
    Ok(
        json!({"proposal_id":id,"state":"pending","expires_at":expires,"policy_revision":rev,"review":review}),
    )
}
pub(crate) fn status(
    tx: &Transaction<'_>,
    id: &str,
    client: &str,
    rev: u64,
    now: i64,
) -> Result<Value> {
    let row: Option<(String, Option<String>, i64, u64)> = tx
        .query_row(
            "SELECT state,grant_id,expires,revision FROM owner_proposals WHERE id=?1 AND client=?2",
            params![id, client],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let (state, grant, expires, revision) =
        row.ok_or(AuthorityError::Rejected("unknown proposal"))?;
    let state = if state == "pending" && (expires <= now || revision != rev) {
        "expired"
    } else {
        &state
    };
    Ok(json!({"proposal_id":id,"state":state,"grant_id":grant,"expires_at":expires}))
}

pub(crate) fn saved_documents(
    tx: &Transaction<'_>,
    rule: &Rule,
) -> Result<BTreeMap<String, String>> {
    let hashes = match rule {
        Rule::SpendLimit {
            requirements_digest,
            ..
        } => vec![requirements_digest.clone()],
        Rule::Reorder { receipt_id } => {
            let p = receipt(tx, receipt_id)?;
            vec![p.requirements_digest, p.terms_digest, p.fulfillment_digest]
        }
        Rule::RequireConfirmation { .. } => Vec::new(),
    };
    let mut documents = BTreeMap::new();
    for hash in hashes {
        let body: Option<String> = tx
            .query_row(
                "SELECT body FROM owner_documents WHERE digest=?1",
                [&hash],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(body) = body {
            documents.insert(hash, body);
        }
    }
    Ok(documents)
}
