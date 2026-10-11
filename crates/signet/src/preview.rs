//! Read-only, agent-neutral product evaluation. Never issues authority or opens a vault.
//! Caller-supplied rules/history are hypothetical, not trusted authorization state.
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rules {
    merchant: String,
    currency: String,
    limit_minor: u64,
    confirm_all: bool,
    confirm_categories: Vec<String>,
    recurring_baseline: Option<Baseline>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Baseline {
    item_id: String,
    total_minor: u64,
    history_ref: String,
    requirements_fingerprint: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reorder {
    history_ref: String,
    requirements_fingerprint: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Purchase {
    merchant: String,
    currency: String,
    item_id: String,
    category: String,
    total_minor: u64,
    requirements_met: bool,
    reorder: Option<Reorder>,
    rules: Rules,
}
#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum RuleChange {
    Add {
        rule_id: String,
        proposed_rule: String,
    },
    Edit {
        rule_id: String,
        expected_version: String,
        proposed_rule: String,
    },
    Remove {
        rule_id: String,
        expected_version: String,
    },
}

fn valid_text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 1024
}
fn fingerprint(value: &Value) -> String {
    // This binds the illustrative request only. It is not a signed grant.
    hex::encode(Sha256::digest(value.to_string().as_bytes()))
}
fn preview_result(outcome: &str, reason: &str, args: &Value) -> Value {
    json!({"mode":"preview", "authorizes_execution":false, "outcome":outcome,
        "reason":reason, "request_fingerprint":fingerprint(args),
        "notice":"Caller-supplied rules and history are hypothetical. No vault, credentials, purchases, persistent rules, or one-time grants are changed."})
}
fn evaluate_purchase(args: &Value) -> Result<Value, String> {
    let p: Purchase = serde_json::from_value(args.clone()).map_err(|e| e.to_string())?;
    if [
        &p.merchant,
        &p.currency,
        &p.item_id,
        &p.category,
        &p.rules.merchant,
        &p.rules.currency,
    ]
    .iter()
    .any(|s| !valid_text(s))
        || p.currency.len() != 3
        || !p.currency.bytes().all(|b| b.is_ascii_uppercase())
        || p.rules.currency.len() != 3
        || !p.rules.currency.bytes().all(|b| b.is_ascii_uppercase())
        || p.total_minor == 0
        || p.rules.limit_minor == 0
        || p.rules.confirm_categories.len() > 64
        || p.rules.confirm_categories.iter().any(|s| !valid_text(s))
    {
        return Err("Use nonempty bounded identifiers, uppercase three-letter currency, positive integer minor-unit amounts, and at most 64 confirmation categories.".into());
    }
    let reason = if p.merchant != p.rules.merchant || p.currency != p.rules.currency {
        Some("Merchant or currency does not match the standing rule.")
    } else if !p.requirements_met {
        Some("The proposed item does not meet the person's requirements.")
    } else if p.rules.confirm_all || p.rules.confirm_categories.contains(&p.category) {
        Some("The person's confirmation preference requires explicit approval.")
    } else if let Some(reorder) = &p.reorder {
        match &p.rules.recurring_baseline {
            Some(b)
                if valid_text(&b.history_ref)
                    && valid_text(&b.item_id)
                    && valid_text(&b.requirements_fingerprint)
                    && b.total_minor > 0
                    && b.item_id == p.item_id
                    && b.history_ref == reorder.history_ref
                    && b.requirements_fingerprint == reorder.requirements_fingerprint =>
            {
                if p.total_minor > b.total_minor {
                    Some("The total exceeds the approved recurring baseline; an exception must not raise it.")
                } else {
                    None
                }
            }
            _ => {
                Some("A matching approved reorder baseline and unchanged requirements are needed.")
            }
        }
    } else if p.total_minor > p.rules.limit_minor {
        Some("The total exceeds the standing limit; this exact purchase needs a separate one-time approval.")
    } else {
        None
    };
    Ok(match reason {
        Some(reason) => preview_result("would_ask", reason, args),
        None => preview_result("would_fit_rules", "The hypothetical proposal fits the supplied rules. This result is not permission to execute.", args),
    })
}
fn evaluate_rule_change(args: &Value) -> Result<Value, String> {
    let change: RuleChange = serde_json::from_value(args.clone()).map_err(|e| e.to_string())?;
    let valid = match change {
        RuleChange::Add {
            rule_id,
            proposed_rule,
        } => valid_text(&rule_id) && valid_text(&proposed_rule),
        RuleChange::Edit {
            rule_id,
            expected_version,
            proposed_rule,
        } => valid_text(&rule_id) && valid_text(&expected_version) && valid_text(&proposed_rule),
        RuleChange::Remove {
            rule_id,
            expected_version,
        } => valid_text(&rule_id) && valid_text(&expected_version),
    };
    if !valid {
        return Err("Identify the exact rule, expected version for edit/remove, and proposed content for add/edit.".into());
    }
    Ok(preview_result("requires_rule_management_grant", "One-time authority must cover this exact rule operation. Purchase permission cannot authorize it. No grant is issued or consumed by this preview.", args))
}

fn text_schema() -> Value {
    json!({"type":"string","minLength":1,"maxLength":1024})
}
fn object(properties: Value, required: &[&str]) -> Value {
    json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}
fn tool_list() -> Value {
    let money = json!({"type":"integer","minimum":1});
    let currency = json!({"type":"string","pattern":"^[A-Z]{3}$"});
    let baseline = object(
        json!({"item_id":text_schema(),"total_minor":money,"history_ref":text_schema(),"requirements_fingerprint":text_schema()}),
        &[
            "item_id",
            "total_minor",
            "history_ref",
            "requirements_fingerprint",
        ],
    );
    let rules = object(
        json!({"merchant":text_schema(),"currency":currency,"limit_minor":money,"confirm_all":{"type":"boolean"},"confirm_categories":{"type":"array","maxItems":64,"items":text_schema()},"recurring_baseline":baseline}),
        &[
            "merchant",
            "currency",
            "limit_minor",
            "confirm_all",
            "confirm_categories",
        ],
    );
    let purchase = object(
        json!({"merchant":text_schema(),"currency":currency,"item_id":text_schema(),"category":text_schema(),"total_minor":money,"requirements_met":{"type":"boolean"},"rules":rules,"reorder":object(json!({"history_ref":text_schema(),"requirements_fingerprint":text_schema()}), &["history_ref","requirements_fingerprint"])}),
        &[
            "merchant",
            "currency",
            "item_id",
            "category",
            "total_minor",
            "requirements_met",
            "rules",
        ],
    );
    let change = json!({"type":"object","oneOf":[
        object(json!({"operation":{"const":"add"},"rule_id":text_schema(),"proposed_rule":text_schema()}), &["operation","rule_id","proposed_rule"]),
        object(json!({"operation":{"const":"edit"},"rule_id":text_schema(),"expected_version":text_schema(),"proposed_rule":text_schema()}), &["operation","rule_id","expected_version","proposed_rule"]),
        object(json!({"operation":{"const":"remove"},"rule_id":text_schema(),"expected_version":text_schema()}), &["operation","rule_id","expected_version"])
    ]});
    let annotations = json!({"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false});
    json!({"tools":[
        {"name":"preview_purchase","description":"Read-only simulation using hypothetical caller-supplied rules. NEVER authorizes execution or verifies consent/history. Amounts are total integer currency minor units.","inputSchema":purchase,"annotations":annotations},
        {"name":"preview_rule_change","description":"Describe the separate one-time authority required for an exact add/edit/remove proposal. NEVER applies rules or issues a grant.","inputSchema":change,"annotations":annotations}
    ]})
}
fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

/// MCP stdio preview session. No filesystem or network access; no authority state.
#[derive(Default)]
pub struct PreviewSession {
    initialized: bool,
    ready: bool,
}
impl PreviewSession {
    /// Process a line. Valid notifications receive no response.
    pub fn handle(&mut self, line: &str) -> Option<Value> {
        let request: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return Some(rpc_error(Value::Null, -32700, "Parse error")),
        };
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request.get("method").and_then(Value::as_str);
        if !request.is_object()
            || request.get("jsonrpc") != Some(&json!("2.0"))
            || method.is_none()
            || (!id.is_null() && !id.is_string() && !id.is_number())
        {
            return Some(rpc_error(Value::Null, -32600, "Invalid Request"));
        }
        let method = method.unwrap();
        if request.get("id").is_none() {
            if method == "notifications/initialized" && self.initialized {
                self.ready = true;
            }
            return None;
        }
        let params = request.get("params").cloned().unwrap_or(json!({}));
        let result = match method {
            "initialize" => {
                if self.initialized {
                    return Some(rpc_error(id, -32600, "Already initialized"));
                }
                let Some(version) = params.get("protocolVersion").and_then(Value::as_str) else {
                    return Some(rpc_error(id, -32602, "protocolVersion is required"));
                };
                let negotiated = match version {
                    "2024-11-05" | "2025-03-26" | "2025-06-18" | "2025-11-25" => version,
                    _ => "2025-11-25",
                };
                self.initialized = true;
                json!({"protocolVersion":negotiated,"capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"signet-preview","version":env!("CARGO_PKG_VERSION")},"instructions":"Read-only product simulation. No output authorizes any action. Supplied rules, consent, history and classifications are untrusted hypothetical inputs."})
            }
            "ping" => json!({}),
            _ if !self.ready => {
                return Some(rpc_error(
                    id,
                    -32000,
                    "Initialize the preview session first",
                ))
            }
            "tools/list" => tool_list(),
            "tools/call" => {
                let Some(name) = params.get("name").and_then(Value::as_str) else {
                    return Some(rpc_error(id, -32602, "Tool name is required"));
                };
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                let outcome = match name {
                    "preview_purchase" => evaluate_purchase(&args),
                    "preview_rule_change" => evaluate_rule_change(&args),
                    _ => return Some(rpc_error(id, -32602, "Unknown preview tool")),
                };
                match outcome {
                    Ok(value) => {
                        json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":false})
                    }
                    Err(message) => {
                        json!({"content":[{"type":"text","text":message}],"isError":true})
                    }
                }
            }
            _ => return Some(rpc_error(id, -32601, "Method not found")),
        };
        Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cable() -> Value {
        json!({"merchant":"amazon.com","currency":"USD","item_id":"cable-1","category":"electronics","total_minor":1800,"requirements_met":true,"rules":{"merchant":"amazon.com","currency":"USD","limit_minor":5000,"confirm_all":false,"confirm_categories":[]}})
    }
    fn outcome(p: &Value) -> Value {
        evaluate_purchase(p).unwrap()["outcome"].clone()
    }
    #[test]
    fn limit_is_inclusive_and_never_authorizes() {
        let mut p = cable();
        p["total_minor"] = json!(5000);
        assert_eq!(outcome(&p), "would_fit_rules");
        assert_eq!(
            evaluate_purchase(&p).unwrap()["authorizes_execution"],
            false
        );
        p["total_minor"] = json!(5001);
        assert_eq!(outcome(&p), "would_ask");
    }
    #[test]
    fn merchant_currency_requirements_and_confirmation_fail_closed() {
        for (field, value) in [
            ("merchant", json!("other.example")),
            ("currency", json!("EUR")),
            ("requirements_met", json!(false)),
        ] {
            let mut p = cable();
            p[field] = value;
            assert_eq!(outcome(&p), "would_ask");
        }
        let mut p = cable();
        p["rules"]["confirm_all"] = json!(true);
        assert_eq!(outcome(&p), "would_ask");
        p["rules"]["confirm_all"] = json!(false);
        p["rules"]["confirm_categories"] = json!(["electronics"]);
        assert_eq!(outcome(&p), "would_ask");
    }
    #[test]
    fn recurring_allows_better_or_usual_but_never_ratchets() {
        let mut p = cable();
        p["item_id"] = json!("dog-food");
        p["category"] = json!("pet-food");
        p["rules"]["recurring_baseline"] = json!({"item_id":"dog-food","total_minor":4600,"history_ref":"approved-order-1","requirements_fingerprint":"same-pack-merchant-delivery"});
        p["reorder"] = json!({"history_ref":"approved-order-1","requirements_fingerprint":"same-pack-merchant-delivery"});
        for amount in [4200, 4600] {
            p["total_minor"] = json!(amount);
            assert_eq!(outcome(&p), "would_fit_rules");
        }
        p["total_minor"] = json!(4900);
        assert_eq!(outcome(&p), "would_ask");
        assert_eq!(p["rules"]["recurring_baseline"]["total_minor"], 4600);
        p["total_minor"] = json!(4200);
        p["reorder"]["history_ref"] = json!("unapproved");
        assert_eq!(outcome(&p), "would_ask");
        p["reorder"]["history_ref"] = json!("approved-order-1");
        p["reorder"]["requirements_fingerprint"] = json!("different-pack");
        assert_eq!(outcome(&p), "would_ask");
        p["rules"]
            .as_object_mut()
            .unwrap()
            .remove("recurring_baseline");
        assert_eq!(outcome(&p), "would_ask");
    }
    #[test]
    fn exception_is_not_an_input_backdoor() {
        let mut p = cable();
        p["total_minor"] = json!(7500);
        assert_eq!(outcome(&p), "would_ask");
        p["approved"] = json!(true);
        assert!(evaluate_purchase(&p).is_err());
        assert_eq!(p["rules"]["limit_minor"], 5000);
    }
    #[test]
    fn rejects_malformed_money_and_missing_requirements() {
        for value in [json!(-1), json!(1.5), json!(0), json!("1800")] {
            let mut p = cable();
            p["total_minor"] = value;
            assert!(evaluate_purchase(&p).is_err());
        }
        let mut p = cable();
        p.as_object_mut().unwrap().remove("requirements_met");
        assert!(evaluate_purchase(&p).is_err());
    }
    #[test]
    fn rule_mutations_require_exact_separate_scope() {
        for value in [
            json!({"operation":"add","rule_id":"electronics-confirm","proposed_rule":"Always confirm electronics"}),
            json!({"operation":"edit","rule_id":"amazon-limit","expected_version":"v1","proposed_rule":"Amazon total at most 8000 USD minor units"}),
            json!({"operation":"remove","rule_id":"amazon-limit","expected_version":"v1"}),
        ] {
            let r = evaluate_rule_change(&value).unwrap();
            assert_eq!(r["outcome"], "requires_rule_management_grant");
            assert_eq!(r["authorizes_execution"], false);
        }
        assert!(
            evaluate_rule_change(&json!({"operation":"remove","rule_id":"amazon-limit"})).is_err()
        );
        let a = json!({"operation":"add","rule_id":"r","proposed_rule":"a"});
        let b = json!({"operation":"add","rule_id":"r","proposed_rule":"b"});
        assert_ne!(
            evaluate_rule_change(&a).unwrap()["request_fingerprint"],
            evaluate_rule_change(&b).unwrap()["request_fingerprint"]
        );
    }
    #[test]
    fn mcp_handshake_tools_call_and_notifications() {
        let mut s = PreviewSession::default();
        assert!(s
            .handle(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
            .unwrap()
            .get("error")
            .is_some());
        let init=s.handle(r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#).unwrap();
        assert_eq!(init["result"]["protocolVersion"], "2025-11-25");
        assert!(s
            .handle(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
            .is_none());
        let list = s
            .handle(r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#)
            .unwrap();
        assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 2);
        let response=s.handle(&json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"preview_purchase","arguments":cable()}}).to_string()).unwrap();
        assert_eq!(
            response["result"]["structuredContent"]["authorizes_execution"],
            false
        );
        assert_eq!(response["result"]["isError"], false);
        assert!(s
            .handle(r#"{"jsonrpc":"2.0","method":"notifications/cancelled"}"#)
            .is_none());
        let bad=s.handle(r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"preview_purchase","arguments":{"approved":true}}}"#).unwrap();
        assert_eq!(bad["result"]["isError"], true);
    }
}
