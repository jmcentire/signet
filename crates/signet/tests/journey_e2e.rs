//! End-to-end journey tests covering the four primary user journeys.
//!
//! Journey 1: Store and list data via CLI-equivalent API
//! Journey 2: MCP tools (store_data, list_data, query, get_proof)
//! Journey 3: HTTP transport (health, MCP proxy, verify)
//! Journey 4: SPL capability token generation and verification

use signet::{initialize_root, handle_request, JsonRpcRequest, RootConfig};
use signet::config::{McpConfig, PolicyEngineConfig};
use signet_mcp::VaultAccess;
use std::sync::atomic::{AtomicU64, Ordering};

static JOURNEY_COUNTER: AtomicU64 = AtomicU64::new(0);

fn journey_config() -> RootConfig {
    let id = JOURNEY_COUNTER.fetch_add(1, Ordering::SeqCst);
    let tid = std::thread::current().id();
    let dir = std::env::temp_dir().join(format!("signet-journey-{:?}-{}", tid, id));
    RootConfig {
        vault_path: dir.join("vault"),
        data_dir: dir,
        mcp: McpConfig::default(),
        policy: PolicyEngineConfig::default(),
        hosting_mode: signet::HostingMode::default(),
        postgres: signet::PostgresConfig::default(),
    }
}

fn make_request(method: &str, params: Option<serde_json::Value>) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".into(),
        method: method.into(),
        params,
        id: serde_json::json!(1),
    }
}

// ============================================================================
// Journey 1: Store and list data
// ============================================================================

#[test]
fn test_journey_store_and_list() {
    let config = journey_config();
    let state = initialize_root(config).unwrap();
    let vault = state.vault_access.as_ref().unwrap();

    // Store items across tiers
    vault.put("age", signet_core::Tier::Tier1, b"29").unwrap();
    vault.put("name", signet_core::Tier::Tier1, b"Alice Nakamoto").unwrap();
    vault.put("credit_card", signet_core::Tier::Tier3, b"4111-1111-1111-1111").unwrap();

    // List all
    let all = vault.list(None).unwrap();
    assert_eq!(all.len(), 3, "should have 3 entries total");

    // List tier 1 only
    let tier1 = vault.list(Some(signet_core::Tier::Tier1)).unwrap();
    assert_eq!(tier1.len(), 2, "should have 2 tier-1 entries");
    let labels: Vec<&str> = tier1.iter().map(|e| e.label.as_str()).collect();
    assert!(labels.contains(&"age"));
    assert!(labels.contains(&"name"));

    // List tier 3 only
    let tier3 = vault.list(Some(signet_core::Tier::Tier3)).unwrap();
    assert_eq!(tier3.len(), 1, "should have 1 tier-3 entry");
    assert_eq!(tier3[0].label, "credit_card");

    // Retrieve tier 1 values
    let age = vault.get("age", signet_core::Tier::Tier1).unwrap().unwrap();
    assert_eq!(std::str::from_utf8(&age).unwrap(), "29");

    let name = vault.get("name", signet_core::Tier::Tier1).unwrap().unwrap();
    assert_eq!(std::str::from_utf8(&name).unwrap(), "Alice Nakamoto");

    // Retrieve tier 3 value (vault can access it, but external agents shouldn't)
    let cc = vault.get("credit_card", signet_core::Tier::Tier3).unwrap().unwrap();
    assert_eq!(std::str::from_utf8(&cc).unwrap(), "4111-1111-1111-1111");

    // Verify signet ID exists
    let id = vault.signet_id();
    assert!(!id.is_empty());

    // Cleanup
    let _ = std::fs::remove_dir_all(state.config.data_dir.clone());
}

// ============================================================================
// Journey 2: MCP tools dispatch
// ============================================================================

#[test]
fn test_journey_mcp_tools() {
    let config = journey_config();
    let state = initialize_root(config).unwrap();

    // List tools via JSON-RPC
    let list_resp = handle_request(&state, &make_request("tools/list", None));
    assert!(list_resp.result.is_some(), "tools/list failed: {:?}", list_resp.error);
    let tools = list_resp.result.unwrap();
    let tool_names: Vec<&str> = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(tool_names.contains(&"store_data"), "store_data tool missing");
    assert!(tool_names.contains(&"list_data"), "list_data tool missing");
    assert!(tool_names.contains(&"get_proof"), "get_proof tool missing");
    assert!(tool_names.contains(&"query"), "query tool missing");
    assert!(tool_names.contains(&"request_capability"), "request_capability tool missing");

    // Store data via MCP
    let store_resp = handle_request(
        &state,
        &make_request(
            "store_data",
            Some(serde_json::json!({
                "label": "favorite_color",
                "value": "blue",
                "tier": 1
            })),
        ),
    );
    assert!(store_resp.result.is_some(), "store_data failed: {:?}", store_resp.error);

    // List data via MCP
    let list_data_resp = handle_request(
        &state,
        &make_request("list_data", Some(serde_json::json!({}))),
    );
    assert!(list_data_resp.result.is_some(), "list_data failed: {:?}", list_data_resp.error);
    let list_result = list_data_resp.result.unwrap();
    let entries = list_result["entries"].as_array().unwrap();
    assert!(!entries.is_empty(), "should have at least one entry after storing");

    // Query via MCP
    let query_resp = handle_request(
        &state,
        &make_request(
            "query",
            Some(serde_json::json!({
                "request_id": "journey-query-001",
                "query": "what color does the user like?",
                "context": {"requester": "test"}
            })),
        ),
    );
    assert!(query_resp.result.is_some(), "query failed: {:?}", query_resp.error);

    // Get proof via MCP
    let proof_resp = handle_request(
        &state,
        &make_request(
            "get_proof",
            Some(serde_json::json!({
                "request_id": "journey-proof-001",
                "predicates": [{"attribute": "age", "operator": "Gte", "value": 21}],
                "proof_type": "SdJwt",
                "domain": "test.example.com",
                "nonce": "journey-nonce"
            })),
        ),
    );
    assert!(proof_resp.result.is_some(), "get_proof failed: {:?}", proof_resp.error);

    // Vault status shows real data
    let status_resp = handle_request(&state, &make_request("vault/status", None));
    assert!(status_resp.result.is_some());
    let status = status_resp.result.unwrap();
    assert!(status["initialized"].as_bool().unwrap());
    assert!(!status["signet_id"].as_str().unwrap().is_empty());

    // Cleanup
    let _ = std::fs::remove_dir_all(state.config.data_dir.clone());
}

// ============================================================================
// Journey 3: HTTP transport (router construction)
// ============================================================================

#[test]
fn test_journey_http_router() {
    use signet::http::{AppState, build_router};

    let config = journey_config();
    let state = initialize_root(config).unwrap();

    // Build the router (validates it compiles and wires correctly)
    let app_state = std::sync::Arc::new(AppState { root: state, tenant_manager: None });
    let _router = build_router(app_state.clone());

    // Verify the root state is accessible through AppState
    assert!(app_state.root.is_initialized());

    // Cleanup
    let _ = std::fs::remove_dir_all(app_state.root.config.data_dir.clone());
}

// ============================================================================
// Journey 4: SPL capability token generation and verification
// ============================================================================

#[test]
fn test_journey_spl_capability() {
    let config = journey_config();
    let state = initialize_root(config).unwrap();

    let signer = state.signer.as_ref().unwrap();

    // Generate an SPL capability token
    let constraints = signet_cred::spl_capability::SplCapabilityConstraints {
        domain: "amazon.com".to_string(),
        max_amount: Some(150),
        purpose: "purchase".to_string(),
        one_time: true,
        expires_seconds: Some(300),
    };

    let signing_key_hex = hex::encode(signer.signing_key_bytes());
    let token = signet_cred::spl_capability::generate_spl_capability(&constraints, &signing_key_hex)
        .unwrap();

    // Token should be sealed (one-time use)
    assert!(token.sealed, "one_time=true should produce a sealed token");
    assert!(token.expires.is_some(), "should have expiry");
    assert!(token.policy.contains("amazon.com"), "policy should bind to domain");
    assert!(token.policy.contains("150"), "policy should include amount limit");
    assert!(token.policy.contains("purchase"), "policy should include purpose");

    // Verify token with matching request
    let mut req = std::collections::HashMap::new();
    req.insert("domain".to_string(), agent_safe_spl::Node::Str("amazon.com".to_string()));
    req.insert("amount".to_string(), agent_safe_spl::Node::Number(100.0));
    req.insert("purpose".to_string(), agent_safe_spl::Node::Str("purchase".to_string()));

    let result = agent_safe_spl::verify_token(&token, req, std::collections::HashMap::new());
    assert!(result.allow, "valid request should be allowed: {:?}", result.error);

    // Verify token rejects wrong domain
    let mut bad_req = std::collections::HashMap::new();
    bad_req.insert("domain".to_string(), agent_safe_spl::Node::Str("evil.com".to_string()));
    bad_req.insert("amount".to_string(), agent_safe_spl::Node::Number(100.0));
    bad_req.insert("purpose".to_string(), agent_safe_spl::Node::Str("purchase".to_string()));

    let bad_result = agent_safe_spl::verify_token(&token, bad_req, std::collections::HashMap::new());
    assert!(!bad_result.allow, "wrong domain should be rejected");

    // Verify token rejects amount over limit
    let mut over_req = std::collections::HashMap::new();
    over_req.insert("domain".to_string(), agent_safe_spl::Node::Str("amazon.com".to_string()));
    over_req.insert("amount".to_string(), agent_safe_spl::Node::Number(200.0));
    over_req.insert("purpose".to_string(), agent_safe_spl::Node::Str("purchase".to_string()));

    let over_result = agent_safe_spl::verify_token(&token, over_req, std::collections::HashMap::new());
    assert!(!over_result.allow, "amount over limit should be rejected");

    // Cleanup
    let _ = std::fs::remove_dir_all(state.config.data_dir.clone());
}

// ============================================================================
// Journey 4b: SPL capability via CLI-equivalent path (vault signer -> token)
// ============================================================================

#[test]
fn test_journey_spl_via_mcp_capability() {
    let config = journey_config();
    let state = initialize_root(config).unwrap();

    // Request capability via MCP
    let cap_resp = handle_request(
        &state,
        &make_request(
            "request_capability",
            Some(serde_json::json!({
                "request_id": "journey-cap-001",
                "capability_type": "payment",
                "domain": "shop.example.com",
                "purpose": "purchase",
                "constraints": {
                    "max_amount": 50
                }
            })),
        ),
    );
    assert!(
        cap_resp.result.is_some(),
        "request_capability should succeed: {:?}",
        cap_resp.error
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(state.config.data_dir.clone());
}

// ============================================================================
// Journey 5: Authority credential flow via HTTP endpoints
// ============================================================================

#[tokio::test]
async fn test_journey_authority_cred_http_flow() {
    use axum::body::Body;
    use http_body_util::BodyExt;
    use signet::http::{AppState, build_router};
    use tower::ServiceExt;

    let config = journey_config();
    let state = initialize_root(config).unwrap();

    let app_state = std::sync::Arc::new(AppState {
        root: state,
        tenant_manager: None,
    });
    let app = build_router(app_state.clone());

    // Create an authority keypair and sign an offer
    let authority_seed = [0x42u8; 32];
    let authority_key = ed25519_dalek::SigningKey::from_bytes(&authority_seed);
    let authority_pubkey = hex::encode(authority_key.verifying_key().to_bytes());

    let user_signet_id = app_state
        .root
        .signer
        .as_ref()
        .map(|s| s.signet_id().as_str().to_string())
        .unwrap_or_else(|| "test-user".to_string());

    let mut claims = std::collections::BTreeMap::new();
    claims.insert(
        "age_verified".to_string(),
        signet_cred::types::ClaimValue::BoolVal(true),
    );

    let offer = signet_cred::authority::sign_authority_offer(
        signet_cred::authority::AuthorityCredentialKey {
            authority_pubkey: authority_pubkey.clone(),
            user_signet_id,
        },
        "age_verification".to_string(),
        claims,
        None, // no decay
        chrono::Utc::now().to_rfc3339(),
        "2030-12-31T23:59:59Z".to_string(),
        vec![], // no chain
        &authority_seed,
    )
    .unwrap();

    let offer_id = signet_cred::authority::generate_offer_id(&offer);

    // 1. POST /cred/offer — push offer
    let offer_json = serde_json::to_string(&offer).unwrap();
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/cred/offer")
        .header("content-type", "application/json")
        .body(Body::from(offer_json))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200, "offer push should succeed");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body_json["status"], "offer_stored");
    assert_eq!(body_json["offer_id"], offer_id);

    // 2. GET /cred/offers — list pending
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/cred/offers")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let offers = body_json["offers"].as_array().unwrap();
    assert!(!offers.is_empty(), "should have at least one pending offer");
    assert_eq!(offers[0]["credential_type"], "age_verification");

    // 3. GET /cred/status/:cred_id — check status (pending)
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/cred/status/{}", offer_id))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body_json["status"], "pending");

    // 4. POST /cred/accept/:offer_id — accept the offer
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/cred/accept/{}", offer_id))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200, "accept should succeed");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body_json["status"], "accepted");

    // 5. GET /cred/status/:cred_id — now shows accepted
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/cred/status/{}", offer_id))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body_json["status"], "accepted");
    assert_eq!(body_json["credential_type"], "age_verification");

    // 6. POST /cred/revoke/:cred_id — revoke the credential
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/cred/revoke/{}", offer_id))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"reason":"no longer needed"}"#))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body_json["status"], "revoked");

    // 7. GET /cred/status/:cred_id — now shows revoked
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/cred/status/{}", offer_id))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body_json["status"], "revoked");

    // Cleanup
    let _ = std::fs::remove_dir_all(app_state.root.config.data_dir.clone());
}

#[tokio::test]
async fn test_journey_invalid_authority_signature_rejected() {
    use axum::body::Body;
    use signet::http::{AppState, build_router};
    use tower::ServiceExt;

    let config = journey_config();
    let state = initialize_root(config).unwrap();
    let app_state = std::sync::Arc::new(AppState {
        root: state,
        tenant_manager: None,
    });
    let app = build_router(app_state.clone());

    // Create an offer with a valid signature, then tamper the claims
    let authority_seed = [0x55u8; 32];
    let authority_key = ed25519_dalek::SigningKey::from_bytes(&authority_seed);
    let authority_pubkey = hex::encode(authority_key.verifying_key().to_bytes());

    let mut claims = std::collections::BTreeMap::new();
    claims.insert(
        "verified".to_string(),
        signet_cred::types::ClaimValue::BoolVal(true),
    );

    let mut offer = signet_cred::authority::sign_authority_offer(
        signet_cred::authority::AuthorityCredentialKey {
            authority_pubkey,
            user_signet_id: "test-user".to_string(),
        },
        "test_cred".to_string(),
        claims,
        None,
        chrono::Utc::now().to_rfc3339(),
        "2030-12-31T23:59:59Z".to_string(),
        vec![],
        &authority_seed,
    )
    .unwrap();

    // Tamper with the claims after signing
    offer.claims.insert(
        "extra".to_string(),
        signet_cred::types::ClaimValue::BoolVal(false),
    );

    let offer_json = serde_json::to_string(&offer).unwrap();
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/cred/offer")
        .header("content-type", "application/json")
        .body(Body::from(offer_json))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401, "tampered offer should be rejected");

    // Cleanup
    let _ = std::fs::remove_dir_all(app_state.root.config.data_dir.clone());
}

#[tokio::test]
async fn test_journey_expired_offer_rejected() {
    use axum::body::Body;
    use signet::http::{AppState, build_router};
    use tower::ServiceExt;

    let config = journey_config();
    let state = initialize_root(config).unwrap();
    let app_state = std::sync::Arc::new(AppState {
        root: state,
        tenant_manager: None,
    });
    let app = build_router(app_state.clone());

    let authority_seed = [0x66u8; 32];
    let authority_key = ed25519_dalek::SigningKey::from_bytes(&authority_seed);
    let authority_pubkey = hex::encode(authority_key.verifying_key().to_bytes());

    let claims = std::collections::BTreeMap::new();

    // Create an offer that has already expired
    let offer = signet_cred::authority::sign_authority_offer(
        signet_cred::authority::AuthorityCredentialKey {
            authority_pubkey,
            user_signet_id: "test-user".to_string(),
        },
        "expired_cred".to_string(),
        claims,
        None,
        "2019-01-01T00:00:00Z".to_string(),
        "2020-01-01T00:00:00Z".to_string(), // already expired
        vec![],
        &authority_seed,
    )
    .unwrap();

    let offer_json = serde_json::to_string(&offer).unwrap();
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/cred/offer")
        .header("content-type", "application/json")
        .body(Body::from(offer_json))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 400, "expired offer should be rejected");

    // Cleanup
    let _ = std::fs::remove_dir_all(app_state.root.config.data_dir.clone());
}

#[tokio::test]
async fn test_journey_reject_offer_via_http() {
    use axum::body::Body;
    use http_body_util::BodyExt;
    use signet::http::{AppState, build_router};
    use tower::ServiceExt;

    let config = journey_config();
    let state = initialize_root(config).unwrap();
    let app_state = std::sync::Arc::new(AppState {
        root: state,
        tenant_manager: None,
    });
    let app = build_router(app_state.clone());

    let authority_seed = [0x77u8; 32];
    let authority_key = ed25519_dalek::SigningKey::from_bytes(&authority_seed);
    let authority_pubkey = hex::encode(authority_key.verifying_key().to_bytes());

    let claims = std::collections::BTreeMap::new();
    let offer = signet_cred::authority::sign_authority_offer(
        signet_cred::authority::AuthorityCredentialKey {
            authority_pubkey,
            user_signet_id: "test-user".to_string(),
        },
        "unwanted_cred".to_string(),
        claims,
        None,
        chrono::Utc::now().to_rfc3339(),
        "2030-12-31T23:59:59Z".to_string(),
        vec![],
        &authority_seed,
    )
    .unwrap();
    let offer_id = signet_cred::authority::generate_offer_id(&offer);

    // Push the offer first
    let offer_json = serde_json::to_string(&offer).unwrap();
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/cred/offer")
        .header("content-type", "application/json")
        .body(Body::from(offer_json))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    // Reject the offer
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/cred/reject/{}", offer_id))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"reason":"not interested"}"#))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body_json["status"], "rejected");
    assert_eq!(body_json["reason"], "not interested");

    // Cleanup
    let _ = std::fs::remove_dir_all(app_state.root.config.data_dir.clone());
}

#[tokio::test]
async fn test_journey_cred_status_not_found() {
    use axum::body::Body;
    use signet::http::{AppState, build_router};
    use tower::ServiceExt;

    let config = journey_config();
    let state = initialize_root(config).unwrap();
    let app_state = std::sync::Arc::new(AppState {
        root: state,
        tenant_manager: None,
    });
    let app = build_router(app_state.clone());

    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/cred/status/nonexistent-id")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 404);

    // Cleanup
    let _ = std::fs::remove_dir_all(app_state.root.config.data_dir.clone());
}
