//! Axum HTTP handlers for the Signet server.
//!
//! Provides REST endpoints for MCP JSON-RPC proxy, proof verification,
//! health checks, and multi-tenant vault operations.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;

use crate::multi_tenant::TenantManager;
use crate::{handle_request, JsonRpcRequest, JsonRpcResponse, RootState};
use signet_core::Signer;

/// Shared application state for Axum handlers.
pub struct AppState {
    pub root: RootState,
    pub tenant_manager: Option<TenantManager>,
}

/// Build the Axum router with all endpoints.
pub fn build_router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        .route("/mcp", post(handle_mcp))
        .route("/verify", post(handle_verify))
        .route("/health", get(handle_health))
        .route("/.well-known/signet.json", get(handle_well_known));

    // Multi-tenant endpoints (always registered, handlers check tenant_manager)
    router = router
        .route("/auth/challenge", post(handle_auth_challenge))
        .route("/auth/verify", post(handle_auth_verify))
        .route("/vault/put", post(handle_vault_put))
        .route("/vault/get", post(handle_vault_get))
        .route("/vault/delete", post(handle_vault_delete));

    // Authority credential flow endpoints
    router = router
        .route("/cred/offer", post(handle_cred_offer))
        .route("/cred/offers", get(handle_cred_offers))
        .route("/cred/accept/{offer_id}", post(handle_cred_accept))
        .route("/cred/reject/{offer_id}", post(handle_cred_reject))
        .route("/cred/revoke/{cred_id}", post(handle_cred_revoke))
        .route("/cred/status/{cred_id}", get(handle_cred_status));

    router.with_state(state)
}

/// POST /mcp -- JSON-RPC proxy to handle_request()
async fn handle_mcp(
    State(state): State<Arc<AppState>>,
    Json(request): Json<JsonRpcRequest>,
) -> Json<JsonRpcResponse> {
    let response = handle_request(&state.root, &request);
    Json(response)
}

/// Proof verification request body.
#[derive(serde::Deserialize)]
struct VerifyRequest {
    proof: String,
    claim: serde_json::Value,
}

/// POST /verify -- proof verification
async fn handle_verify(
    Json(req): Json<VerifyRequest>,
) -> impl IntoResponse {
    let proof = signet_sdk::Proof::new(req.proof.into_bytes());
    let claim = signet_sdk::Claim::new(
        req.claim.get("attribute")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown"),
        req.claim.get("value").cloned().unwrap_or(serde_json::Value::Null),
    );

    match signet_sdk::verify(&proof, &claim) {
        Ok(result) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "valid": result.valid,
                "proof_format": format!("{:?}", result.proof_format),
                "domain": result.domain,
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "valid": false,
                "error": e.to_string(),
            })),
        ),
    }
}

/// GET /health -- server info
async fn handle_health(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let signet_id = state.root.signer.as_ref()
        .map(|s| s.signet_id().as_str().to_string())
        .unwrap_or_else(|| "not initialized".to_string());

    let hosting_mode = format!("{:?}", state.root.config.hosting_mode);

    let mut health = serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "signet_id": signet_id,
        "hosting_mode": hosting_mode,
    });

    if let Some(tm) = &state.tenant_manager {
        health["active_sessions"] = serde_json::json!(tm.active_session_count());
        health["pending_challenges"] = serde_json::json!(tm.pending_challenge_count());
    }

    Json(health)
}

/// GET /.well-known/signet.json -- service discovery
async fn handle_well_known(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let (signet_id, public_key_hex) = match state.root.signer.as_ref() {
        Some(signer) => {
            let id = signer.signet_id().as_str().to_string();
            let pk = hex::encode(signer.public_key_ed25519());
            (id, pk)
        }
        None => {
            return Json(serde_json::json!({
                "error": "signer not initialized",
                "version": env!("CARGO_PKG_VERSION"),
            }));
        }
    };

    let is_multi_tenant = state.tenant_manager.is_some();

    let mut well_known = serde_json::json!({
        "signet_id": signet_id,
        "public_key": public_key_hex,
        "public_key_type": "Ed25519",
        "version": env!("CARGO_PKG_VERSION"),
        "supported_proof_formats": ["SD-JWT", "BBS+", "Bulletproof"],
        "endpoints": {
            "mcp": "/mcp",
            "verify": "/verify",
            "health": "/health",
            "cred_offer": "/cred/offer",
            "cred_offers": "/cred/offers",
            "cred_accept": "/cred/accept/{offer_id}",
            "cred_reject": "/cred/reject/{offer_id}",
            "cred_revoke": "/cred/revoke/{cred_id}",
            "cred_status": "/cred/status/{cred_id}"
        },
        "rotation_chain": []
    });

    if is_multi_tenant {
        well_known["hosting_mode"] = serde_json::json!("multi_tenant");
        well_known["endpoints"]["auth_challenge"] = serde_json::json!("/auth/challenge");
        well_known["endpoints"]["auth_verify"] = serde_json::json!("/auth/verify");
        well_known["endpoints"]["vault_put"] = serde_json::json!("/vault/put");
        well_known["endpoints"]["vault_get"] = serde_json::json!("/vault/get");
        well_known["endpoints"]["vault_delete"] = serde_json::json!("/vault/delete");
    }

    Json(well_known)
}

// ---------------------------------------------------------------------------
// Multi-tenant auth endpoints
// ---------------------------------------------------------------------------

/// POST /auth/challenge -- issue a nonce for Ed25519 challenge-response auth
async fn handle_auth_challenge(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    match &state.tenant_manager {
        Some(tm) => {
            let challenge = tm.create_challenge();
            (StatusCode::OK, Json(serde_json::json!(challenge)))
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "multi-tenant mode not enabled"
            })),
        ),
    }
}

/// POST /auth/verify -- verify signed nonce and issue session token
async fn handle_auth_verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<crate::multi_tenant::AuthVerifyRequest>,
) -> impl IntoResponse {
    match &state.tenant_manager {
        Some(tm) => match tm.verify_challenge(&req) {
            Ok(session) => (
                StatusCode::OK,
                Json(serde_json::json!(session)),
            ),
            Err(e) => (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": e
                })),
            ),
        },
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "multi-tenant mode not enabled"
            })),
        ),
    }
}

// ---------------------------------------------------------------------------
// Multi-tenant vault CRUD endpoints
// ---------------------------------------------------------------------------

/// Extract and validate session token from Authorization header.
fn extract_session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// POST /vault/put -- store an opaque record (authed)
async fn handle_vault_put(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<crate::multi_tenant::VaultPutRequest>,
) -> impl IntoResponse {
    let tm = match &state.tenant_manager {
        Some(tm) => tm,
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "multi-tenant mode not enabled"}))),
    };

    let token = match extract_session_token(&headers) {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "missing Authorization header"}))),
    };

    if tm.validate_session(&token).is_none() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid or expired session"})));
    }

    // Decode ciphertext from base64
    use base64::Engine;
    let ciphertext = match base64::engine::general_purpose::STANDARD.decode(&req.ciphertext) {
        Ok(ct) => ct,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid base64 ciphertext"}))),
    };

    // Store via the vault's storage backend
    let record_id = signet_core::RecordId::new(&req.record_id);
    match state.root.vault_access.as_ref() {
        Some(_vault) => {
            // Use direct storage backend access for opaque blob storage
            // In multi-tenant mode, we bypass the VaultAccess abstraction
            // and go directly to the storage backend with opaque record IDs.
            let db_path = state.root.config.vault_path.join("vault.db");
            let db_path_str = db_path.to_str().unwrap_or("vault.db");
            match signet_vault::storage::SqliteBackend::open(db_path_str) {
                Ok(backend) => {
                    use signet_core::StorageBackend;
                    match backend.put(&record_id, &ciphertext) {
                        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"status": "stored"}))),
                        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
                    }
                }
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
            }
        }
        None => {
            // Fallback: open the configured vault db path
            let db_path = state.root.config.vault_path.join("vault.db");
            let db_path_str = db_path.to_str().unwrap_or("vault.db");
            match signet_vault::storage::SqliteBackend::open(db_path_str) {
                Ok(backend) => {
                    use signet_core::StorageBackend;
                    match backend.put(&record_id, &ciphertext) {
                        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"status": "stored"}))),
                        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
                    }
                }
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
            }
        }
    }
}

/// POST /vault/get -- retrieve an opaque record (authed)
async fn handle_vault_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<crate::multi_tenant::VaultGetRequest>,
) -> impl IntoResponse {
    let tm = match &state.tenant_manager {
        Some(tm) => tm,
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "multi-tenant mode not enabled"}))),
    };

    let token = match extract_session_token(&headers) {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "missing Authorization header"}))),
    };

    if tm.validate_session(&token).is_none() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid or expired session"})));
    }

    let record_id = signet_core::RecordId::new(&req.record_id);
    let db_path = state.root.config.vault_path.join("vault.db");
    let db_path_str = db_path.to_str().unwrap_or("vault.db");
    match signet_vault::storage::SqliteBackend::open(db_path_str) {
        Ok(backend) => {
            use signet_core::StorageBackend;
            match backend.get(&record_id) {
                Ok(Some(data)) => {
                    use base64::Engine;
                    let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
                    (StatusCode::OK, Json(serde_json::json!({"ciphertext": encoded})))
                }
                Ok(None) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "record not found"}))),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
            }
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
    }
}

/// POST /vault/delete -- remove an opaque record (authed)
async fn handle_vault_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<crate::multi_tenant::VaultDeleteRequest>,
) -> impl IntoResponse {
    let tm = match &state.tenant_manager {
        Some(tm) => tm,
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "multi-tenant mode not enabled"}))),
    };

    let token = match extract_session_token(&headers) {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "missing Authorization header"}))),
    };

    if tm.validate_session(&token).is_none() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid or expired session"})));
    }

    let record_id = signet_core::RecordId::new(&req.record_id);
    let db_path = state.root.config.vault_path.join("vault.db");
    let db_path_str = db_path.to_str().unwrap_or("vault.db");
    match signet_vault::storage::SqliteBackend::open(db_path_str) {
        Ok(backend) => {
            use signet_core::StorageBackend;
            match backend.delete(&record_id) {
                Ok(true) => (StatusCode::OK, Json(serde_json::json!({"status": "deleted"}))),
                Ok(false) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "record not found"}))),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
            }
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
    }
}

// ---------------------------------------------------------------------------
// Authority credential flow endpoints
// ---------------------------------------------------------------------------

/// Storage label prefix for credential offers stored in the vault.
const CRED_OFFER_PREFIX: &str = "cred:offer:";
/// Storage label prefix for accepted credentials.
const CRED_ACCEPTED_PREFIX: &str = "cred:accepted:";
/// Storage label prefix for credential status.
const CRED_STATUS_PREFIX: &str = "cred:status:";

/// POST /cred/offer -- authority pushes a signed offer
async fn handle_cred_offer(
    State(state): State<Arc<AppState>>,
    Json(offer): Json<signet_cred::authority::AuthorityOffer>,
) -> impl IntoResponse {
    // Verify the authority's signature on the offer
    match signet_cred::authority::verify_authority_offer(&offer) {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid authority signature"})),
            );
        }
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": format!("signature verification failed: {}", e)})),
            );
        }
    }

    // Verify authority chain if present
    if !offer.authority_chain.is_empty() {
        match signet_cred::authority::verify_chain(&offer) {
            Ok(true) => {}
            Ok(false) | Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": "authority chain verification failed"})),
                );
            }
        }
    }

    // Check offer hasn't expired
    let now = chrono::Utc::now().to_rfc3339();
    if now > offer.offer_expires_at {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "offer has expired"})),
        );
    }

    // Store the offer in the vault
    let vault = match state.root.vault_access.as_ref() {
        Some(v) => v,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "vault not initialized"})),
            );
        }
    };

    let offer_id = signet_cred::authority::generate_offer_id(&offer);
    let offer_label = format!("{}{}", CRED_OFFER_PREFIX, offer_id);
    let offer_data = match serde_json::to_vec(&offer) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("serialization failed: {}", e)})),
            );
        }
    };

    use signet_mcp::VaultAccess;
    if let Err(e) = vault.put(&offer_label, signet_core::Tier::Tier2, &offer_data) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("storage failed: {}", e)})),
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "offer_stored",
            "offer_id": offer_id,
        })),
    )
}

/// GET /cred/offers -- list pending offers (authenticated)
async fn handle_cred_offers(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Auth check (if multi-tenant mode)
    if let Some(tm) = &state.tenant_manager {
        let token = match extract_session_token(&headers) {
            Some(t) => t,
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": "missing Authorization header"})),
                );
            }
        };
        if tm.validate_session(&token).is_none() {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid or expired session"})),
            );
        }
    }

    let vault = match state.root.vault_access.as_ref() {
        Some(v) => v,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "vault not initialized"})),
            );
        }
    };

    use signet_mcp::VaultAccess;
    let entries = match vault.list(None) {
        Ok(e) => e,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("list failed: {}", e)})),
            );
        }
    };

    let mut offers = Vec::new();
    for entry in &entries {
        if entry.label.starts_with(CRED_OFFER_PREFIX) {
            let offer_id = entry
                .label
                .strip_prefix(CRED_OFFER_PREFIX)
                .unwrap_or(&entry.label);
            if let Ok(Some(data)) = vault.get(&entry.label, entry.tier) {
                if let Ok(offer) =
                    serde_json::from_slice::<signet_cred::authority::AuthorityOffer>(&data)
                {
                    offers.push(serde_json::json!({
                        "offer_id": offer_id,
                        "authority": offer.key.authority_pubkey,
                        "user": offer.key.user_signet_id,
                        "credential_type": offer.credential_type,
                        "offered_at": offer.offered_at,
                        "expires_at": offer.offer_expires_at,
                    }));
                }
            }
        }
    }

    (StatusCode::OK, Json(serde_json::json!({"offers": offers})))
}

/// POST /cred/accept/:offer_id -- user accepts an offer (authenticated)
async fn handle_cred_accept(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(offer_id): Path<String>,
) -> impl IntoResponse {
    // Auth check (if multi-tenant mode)
    if let Some(tm) = &state.tenant_manager {
        let token = match extract_session_token(&headers) {
            Some(t) => t,
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": "missing Authorization header"})),
                );
            }
        };
        if tm.validate_session(&token).is_none() {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid or expired session"})),
            );
        }
    }

    let vault = match state.root.vault_access.as_ref() {
        Some(v) => v,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "vault not initialized"})),
            );
        }
    };

    let signer = match state.root.signer.as_ref() {
        Some(s) => s,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "signer not initialized"})),
            );
        }
    };

    use signet_mcp::VaultAccess;

    // Load the offer
    let offer_label = format!("{}{}", CRED_OFFER_PREFIX, offer_id);
    let offer_data = match vault.get(&offer_label, signet_core::Tier::Tier2) {
        Ok(Some(d)) => d,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "offer not found"})),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("load failed: {}", e)})),
            );
        }
    };

    let offer: signet_cred::authority::AuthorityOffer = match serde_json::from_slice(&offer_data) {
        Ok(o) => o,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("decode failed: {}", e)})),
            );
        }
    };

    // Check offer hasn't expired
    let now = chrono::Utc::now().to_rfc3339();
    if now > offer.offer_expires_at {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "offer has expired"})),
        );
    }

    // Accept the offer (counter-sign)
    let accepted = match signet_cred::authority::accept_offer(&offer, signer) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("accept failed: {}", e)})),
            );
        }
    };

    // Store the accepted credential
    let accepted_label = format!(
        "{}{}",
        CRED_ACCEPTED_PREFIX,
        signet_cred::authority::generate_offer_id(&offer)
    );
    let accepted_data = match serde_json::to_vec(&accepted) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("serialization failed: {}", e)})),
            );
        }
    };

    if let Err(e) = vault.put(&accepted_label, signet_core::Tier::Tier2, &accepted_data) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("storage failed: {}", e)})),
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "accepted",
            "offer_id": offer_id,
            "credential_type": offer.credential_type,
        })),
    )
}

/// Request body for rejecting an offer.
#[derive(serde::Deserialize)]
struct RejectRequest {
    reason: Option<String>,
}

/// POST /cred/reject/:offer_id -- user rejects an offer (authenticated)
async fn handle_cred_reject(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(offer_id): Path<String>,
    Json(req): Json<RejectRequest>,
) -> impl IntoResponse {
    // Auth check (if multi-tenant mode)
    if let Some(tm) = &state.tenant_manager {
        let token = match extract_session_token(&headers) {
            Some(t) => t,
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": "missing Authorization header"})),
                );
            }
        };
        if tm.validate_session(&token).is_none() {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid or expired session"})),
            );
        }
    }

    let vault = match state.root.vault_access.as_ref() {
        Some(v) => v,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "vault not initialized"})),
            );
        }
    };

    use signet_mcp::VaultAccess;

    let status = signet_cred::authority::OfferStatus::Rejected {
        reason: req.reason.clone(),
    };
    let status_label = format!("{}{}", CRED_STATUS_PREFIX, offer_id);
    let status_data = match serde_json::to_vec(&status) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("serialization failed: {}", e)})),
            );
        }
    };

    if let Err(e) = vault.put(&status_label, signet_core::Tier::Tier2, &status_data) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("storage failed: {}", e)})),
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "rejected",
            "offer_id": offer_id,
            "reason": req.reason,
        })),
    )
}

/// Request body for revoking a credential.
#[derive(serde::Deserialize)]
struct RevokeRequest {
    reason: Option<String>,
    /// If provided, the revoker is an authority (hex pubkey). Otherwise, user.
    authority_pubkey: Option<String>,
}

/// POST /cred/revoke/:cred_id -- user or authority revokes (authenticated/signed)
async fn handle_cred_revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(cred_id): Path<String>,
    Json(req): Json<RevokeRequest>,
) -> impl IntoResponse {
    // Auth check (if multi-tenant mode)
    if let Some(tm) = &state.tenant_manager {
        let token = match extract_session_token(&headers) {
            Some(t) => t,
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": "missing Authorization header"})),
                );
            }
        };
        if tm.validate_session(&token).is_none() {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid or expired session"})),
            );
        }
    }

    let vault = match state.root.vault_access.as_ref() {
        Some(v) => v,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "vault not initialized"})),
            );
        }
    };

    use signet_mcp::VaultAccess;

    let revoked_by = match &req.authority_pubkey {
        Some(pk) => signet_cred::RevokedBy::Authority(pk.clone()),
        None => signet_cred::RevokedBy::User,
    };

    let revocation = signet_cred::RevocationInfo {
        revoked_by,
        revoked_at: chrono::Utc::now().to_rfc3339(),
        reason: req.reason.clone(),
    };

    let status_label = format!("{}{}", CRED_STATUS_PREFIX, cred_id);
    let status_data = match serde_json::to_vec(&revocation) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("serialization failed: {}", e)})),
            );
        }
    };

    if let Err(e) = vault.put(&status_label, signet_core::Tier::Tier2, &status_data) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("storage failed: {}", e)})),
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "revoked",
            "credential_id": cred_id,
            "reason": req.reason,
        })),
    )
}

/// GET /cred/status/:cred_id -- check credential status + decay state
async fn handle_cred_status(
    State(state): State<Arc<AppState>>,
    Path(cred_id): Path<String>,
) -> impl IntoResponse {
    let vault = match state.root.vault_access.as_ref() {
        Some(v) => v,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "vault not initialized"})),
            );
        }
    };

    use signet_mcp::VaultAccess;

    let mut result = serde_json::json!({
        "credential_id": cred_id,
    });

    // Check revocation status
    let status_label = format!("{}{}", CRED_STATUS_PREFIX, cred_id);
    if let Ok(Some(data)) = vault.get(&status_label, signet_core::Tier::Tier2) {
        if let Ok(revocation) = serde_json::from_slice::<signet_cred::RevocationInfo>(&data) {
            result["status"] = serde_json::json!("revoked");
            result["revocation"] = serde_json::json!({
                "revoked_by": format!("{:?}", revocation.revoked_by),
                "revoked_at": revocation.revoked_at,
                "reason": revocation.reason,
            });
            return (StatusCode::OK, Json(result));
        }
        // Could also be an OfferStatus (rejected/etc.)
        if let Ok(offer_status) =
            serde_json::from_slice::<signet_cred::authority::OfferStatus>(&data)
        {
            result["offer_status"] = serde_json::json!(format!("{:?}", offer_status));
            return (StatusCode::OK, Json(result));
        }
    }

    // Check for accepted credential
    let accepted_label = format!("{}{}", CRED_ACCEPTED_PREFIX, cred_id);
    if let Ok(Some(data)) = vault.get(&accepted_label, signet_core::Tier::Tier2) {
        if let Ok(accepted) =
            serde_json::from_slice::<signet_cred::authority::AcceptedCredential>(&data)
        {
            result["status"] = serde_json::json!("accepted");
            result["credential_type"] = serde_json::json!(accepted.offer.credential_type);
            result["authority"] = serde_json::json!(accepted.offer.key.authority_pubkey);
            result["accepted_at"] = serde_json::json!(accepted.accepted_at);

            if let Some(ref decay) = accepted.offer.decay {
                let mut decay_info = serde_json::json!({});
                if let Some(ref ttl) = decay.ttl {
                    decay_info["ttl_seconds"] = serde_json::json!(ttl.expires_after_seconds);
                }
                if let Some(ref uc) = decay.use_count {
                    decay_info["max_uses"] = serde_json::json!(uc.max_uses);
                }
                if let Some(ref rl) = decay.rate_limit {
                    decay_info["rate_limit"] = serde_json::json!({
                        "max_per_window": rl.max_per_window,
                        "window_seconds": rl.window_seconds,
                        "grace": rl.grace,
                    });
                }
                if !decay.phases.is_empty() {
                    decay_info["phase_count"] = serde_json::json!(decay.phases.len());
                }
                result["decay"] = decay_info;
            }

            return (StatusCode::OK, Json(result));
        }
    }

    // Check for pending offer
    let offer_label = format!("{}{}", CRED_OFFER_PREFIX, cred_id);
    if let Ok(Some(data)) = vault.get(&offer_label, signet_core::Tier::Tier2) {
        if let Ok(offer) = serde_json::from_slice::<signet_cred::authority::AuthorityOffer>(&data) {
            result["status"] = serde_json::json!("pending");
            result["credential_type"] = serde_json::json!(offer.credential_type);
            result["authority"] = serde_json::json!(offer.key.authority_pubkey);
            result["offered_at"] = serde_json::json!(offer.offered_at);
            result["expires_at"] = serde_json::json!(offer.offer_expires_at);
            return (StatusCode::OK, Json(result));
        }
    }

    result["status"] = serde_json::json!("not_found");
    (StatusCode::NOT_FOUND, Json(result))
}
