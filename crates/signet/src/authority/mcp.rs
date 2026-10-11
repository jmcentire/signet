//! MCP relay for authenticated requests. Host connection alone confers no authority.
use super::{Authority, SignedMessage};
use serde_json::{json, Value};

pub struct AuthorityMcpSession {
    authority: Authority,
    initialized: bool,
}
impl AuthorityMcpSession {
    pub fn new(authority: Authority) -> Self {
        Self {
            authority,
            initialized: false,
        }
    }
    pub fn handle(&mut self, text: &str) -> Option<Value> {
        handle(&mut self.authority, &mut self.initialized, text, false)
    }
}
pub(crate) fn stateless(authority: &mut Authority, text: &str) -> Option<Value> {
    handle(authority, &mut true, text, true)
}
fn handle(
    authority: &mut Authority,
    initialized: &mut bool,
    text: &str,
    http: bool,
) -> Option<Value> {
    if text.len() > super::MAX_MESSAGE {
        return Some(error(Value::Null, -32600, "Message too large"));
    }
    let request: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => return Some(error(Value::Null, -32700, "Parse error")),
    };
    let id = request.get("id").cloned();
    if request.get("jsonrpc") != Some(&json!("2.0"))
        || !request.get("method").is_some_and(Value::is_string)
        || id
            .as_ref()
            .is_some_and(|id| !id.is_string() && !id.is_i64() && !id.is_u64())
    {
        return Some(error(Value::Null, -32600, "Invalid Request"));
    }
    // Notifications never cause an authority operation or receive a response.
    let id = id?;
    let method = request["method"].as_str().unwrap_or_default();
    let result = match method {
        "initialize" => {
            *initialized = true;
            let wanted = request["params"]["protocolVersion"]
                .as_str()
                .unwrap_or_default();
            let version = match wanted {
                "2024-11-05" if !http => wanted,
                "2025-03-26" | "2025-06-18" | "2025-11-25" => wanted,
                _ => "2025-11-25",
            };
            json!({"protocolVersion":version,"capabilities":{"tools":{}},"serverInfo":{"name":"signet-authority","version":env!("CARGO_PKG_VERSION")},"instructions":"Owner approval requires a separately trusted signer. Host approval and natural-language consent are not authority signatures. This server never executes merchant network requests."})
        }
        "ping" => json!({}),
        _ if !*initialized => return Some(error(id, -32002, "Initialize before calling tools")),
        "tools/list" => json!({"tools":[{
            "name":"authority_request",
            "description":"Relay one signed Signet authority request. May commit persistent rules or reserve exact purchase authority. Requires provisioned agent/executor signatures and separately signed owner approvals. Treat as a sensitive write; never infer approval or expose signer keys to the model.",
            "inputSchema":{"type":"object","properties":{"payload":{"type":"string","maxLength":65536},"signature":{"type":"string","minLength":128,"maxLength":128}},"required":["payload","signature"],"additionalProperties":false},
            "annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":true}
        }]}),
        "tools/call" => {
            if request["params"]["name"] != "authority_request" {
                return Some(error(id, -32602, "Unknown tool"));
            }
            let result =
                serde_json::from_value::<SignedMessage>(request["params"]["arguments"].clone())
                    .map_err(super::AuthorityError::from)
                    .and_then(|message| authority.handle(&message));
            let (value, is_error) = match result {
                Ok(value) => (value, false),
                Err(err) => (json!({"error":err.to_string()}), true),
            };
            json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":is_error})
        }
        _ => return Some(error(id, -32601, "Method not found")),
    };
    Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
