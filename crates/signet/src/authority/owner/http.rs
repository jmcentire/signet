//! Loopback service adapter; deploy behind an authenticated HTTPS origin, never wildcard CORS.
use super::api::OwnerApi;
use super::*;
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::sync::{Arc, Mutex};
type Shared = Arc<Mutex<Box<dyn OwnerApi>>>;

const HTML: &str = include_str!("assets/index.html");
const CSS: &str = include_str!("assets/app.css");
const JS: &str = include_str!("assets/app.js");

fn headers(response: &mut Response) {
    for (name,value) in [
        ("cache-control","no-store"),("x-content-type-options","nosniff"),
        ("referrer-policy","no-referrer"),("x-frame-options","DENY"),
        ("content-security-policy","default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
        ("permissions-policy","publickey-credentials-get=(self), publickey-credentials-create=(self)")
    ] { response.headers_mut().insert(axum::http::HeaderName::from_static(name),HeaderValue::from_static(value)); }
}
fn reply(value: Result<Value>) -> Response {
    let mut response = match value {
        Ok(value) => Json(value).into_response(),
        Err(error) => (
            if matches!(
                error,
                AuthorityError::Rejected(
                    "unexpected host" | "unexpected origin" | "cross-site requests are not allowed"
                )
            ) {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::BAD_REQUEST
            },
            Json(json!({"error":error.to_string()})),
        )
            .into_response(),
    };
    headers(&mut response);
    response
}
fn asset(content: &'static str, kind: &'static str) -> Response {
    let mut r = ([(axum::http::header::CONTENT_TYPE, kind)], content).into_response();
    headers(&mut r);
    r
}
fn origin(service: &dyn OwnerApi, h: &HeaderMap, browser: bool) -> Result<()> {
    let expected = service
        .origin()
        .split_once("://")
        .ok_or(AuthorityError::Rejected("origin configuration"))?
        .1;
    if h.get("host").and_then(|v| v.to_str().ok()) != Some(expected) {
        return reject("unexpected host");
    }
    let supplied = h.get("origin").and_then(|v| v.to_str().ok());
    if (browser && supplied != Some(service.origin()))
        || supplied.is_some_and(|v| v != service.origin())
    {
        return reject("unexpected origin");
    }
    if h.get("sec-fetch-site").is_some_and(|v| v == "cross-site") {
        return reject("cross-site requests are not allowed");
    }
    Ok(())
}
fn cookie_name(service: &dyn OwnerApi) -> &'static str {
    if service.origin().starts_with("https:") {
        "__Host-signet-owner"
    } else {
        "signet-owner-dev"
    }
}
fn sid(service: &dyn OwnerApi, h: &HeaderMap) -> Result<String> {
    let cookie = h
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let name = cookie_name(service);
    cookie
        .split(';')
        .find_map(|p| {
            let (key, value) = p.trim().split_once('=')?;
            (key == name && digest(value)).then(|| value.to_owned())
        })
        .ok_or(AuthorityError::Rejected("owner session required"))
}
fn csrf(h: &HeaderMap) -> Result<&str> {
    h.get("x-signet-csrf")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthorityError::Rejected("CSRF token required"))
}
fn session_cookie(service: &dyn OwnerApi, sid: &str) -> String {
    format!(
        "{}={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=900{}",
        cookie_name(service),
        sid,
        if service.origin().starts_with("https:") {
            "; Secure"
        } else {
            ""
        }
    )
}
fn service(state: &Shared) -> Result<std::sync::MutexGuard<'_, Box<dyn OwnerApi>>> {
    state
        .lock()
        .map_err(|_| AuthorityError::Rejected("owner service unavailable"))
}
async fn page(State(state): State<Shared>, h: HeaderMap) -> Response {
    let check = service(&state).and_then(|s| origin(s.as_ref(), &h, false));
    match check {
        Ok(()) => asset(HTML, "text/html; charset=utf-8"),
        Err(e) => reply(Err(e)),
    }
}
async fn session(State(state): State<Shared>, h: HeaderMap) -> Response {
    let result = (|| {
        let mut s = service(&state)?;
        origin(s.as_ref(), &h, false)?;
        let existing = sid(s.as_ref(), &h).ok();
        let (id, value) = s.session(existing.as_deref())?;
        Ok((value, session_cookie(s.as_ref(), &id)))
    })();
    match result {
        Ok((value, cookie)) => {
            let mut r = reply(Ok(value));
            if let Ok(v) = HeaderValue::from_str(&cookie) {
                r.headers_mut().insert("set-cookie", v);
            }
            r
        }
        Err(e) => reply(Err(e)),
    }
}
async fn dashboard(State(state): State<Shared>, h: HeaderMap) -> Response {
    reply((|| {
        let mut s = service(&state)?;
        origin(s.as_ref(), &h, true)?;
        let id = sid(s.as_ref(), &h)?;
        s.dashboard(&id, csrf(&h)?)
    })())
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Enroll {
    token: String,
    label: String,
}
async fn enroll(State(state): State<Shared>, h: HeaderMap, Json(input): Json<Enroll>) -> Response {
    reply((|| {
        let mut s = service(&state)?;
        origin(s.as_ref(), &h, true)?;
        let id = sid(s.as_ref(), &h)?;
        s.begin_enrollment(&id, csrf(&h)?, &input.token, input.label)
    })())
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Register {
    challenge_id: String,
    credential: RegisterPublicKeyCredential,
}
async fn register(
    State(state): State<Shared>,
    h: HeaderMap,
    Json(input): Json<Register>,
) -> Response {
    finish_response(&state, &h, |s, id, csrf| {
        s.finish_registration(id, csrf, &input.challenge_id, &input.credential)
    })
}
async fn begin(
    State(state): State<Shared>,
    h: HeaderMap,
    Json(input): Json<OwnerIntent>,
) -> Response {
    reply((|| {
        let mut s = service(&state)?;
        origin(s.as_ref(), &h, true)?;
        let id = sid(s.as_ref(), &h)?;
        s.begin_authentication(&id, csrf(&h)?, input)
    })())
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Authenticate {
    challenge_id: String,
    credential: PublicKeyCredential,
}
async fn finish(
    State(state): State<Shared>,
    h: HeaderMap,
    Json(input): Json<Authenticate>,
) -> Response {
    finish_response(&state, &h, |s, id, csrf| {
        s.finish_authentication(id, csrf, &input.challenge_id, &input.credential)
    })
}
fn finish_response(
    state: &Shared,
    h: &HeaderMap,
    f: impl FnOnce(&mut dyn OwnerApi, &str, &str) -> Result<Value>,
) -> Response {
    let result = (|| {
        let mut s = service(state)?;
        origin(s.as_ref(), h, true)?;
        let id = sid(s.as_ref(), h)?;
        let value = f(s.as_mut(), &id, csrf(h)?)?;
        // Rotate the session on privilege elevation; registration authorization retains
        // its old session only until the bound registration ceremony is completed.
        let cookie = if value["state"] == "signed_in" || value["state"] == "enrolled" {
            let new = s.rotate_session(&id)?;
            Some(session_cookie(s.as_ref(), &new))
        } else {
            None
        };
        Ok((value, cookie))
    })();
    match result {
        Ok((value, cookie)) => {
            let mut r = reply(Ok(value));
            if let Some(cookie) = cookie {
                if let Ok(value) = HeaderValue::from_str(&cookie) {
                    r.headers_mut().insert("set-cookie", value);
                }
            }
            r
        }
        Err(e) => reply(Err(e)),
    }
}
async fn logout(State(state): State<Shared>, h: HeaderMap) -> Response {
    reply((|| {
        let mut s = service(&state)?;
        origin(s.as_ref(), &h, true)?;
        let id = sid(s.as_ref(), &h)?;
        s.logout(&id, csrf(&h)?)
    })())
}
async fn agent(
    State(state): State<Shared>,
    h: HeaderMap,
    Json(input): Json<SignedMessage>,
) -> Response {
    reply((|| {
        let mut s = service(&state)?;
        origin(s.as_ref(), &h, false)?;
        s.agent_request(&input)
    })())
}
async fn mcp(State(state): State<Shared>, h: HeaderMap, Json(input): Json<Value>) -> Response {
    let result = (|| {
        let mut s = service(&state)?;
        origin(s.as_ref(), &h, false)?;
        let accept = h
            .get("accept")
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default();
        if !accept.contains("application/json") || !accept.contains("text/event-stream") {
            return reject("MCP Accept must include application/json and text/event-stream");
        }
        if h.get("mcp-protocol-version").is_some_and(|v| {
            !matches!(
                v.to_str().unwrap_or_default(),
                "2025-03-26" | "2025-06-18" | "2025-11-25"
            )
        }) {
            return reject("unsupported MCP protocol version");
        }
        s.mcp(&input)
    })();
    match result {
        Ok(Some(value)) => reply(Ok(value)),
        Ok(None) => {
            let mut r = StatusCode::ACCEPTED.into_response();
            headers(&mut r);
            r
        }
        Err(e) => reply(Err(e)),
    }
}
async fn no_stream(State(state): State<Shared>, h: HeaderMap) -> Response {
    match service(&state).and_then(|s| origin(s.as_ref(), &h, false)) {
        Ok(()) => {
            let mut r = StatusCode::METHOD_NOT_ALLOWED.into_response();
            headers(&mut r);
            r
        }
        Err(e) => reply(Err(e)),
    }
}
pub fn router(owner: impl OwnerApi + 'static) -> Router {
    Router::new()
        .route("/", get(page))
        .route(
            "/app.css",
            get(|| async { asset(CSS, "text/css; charset=utf-8") }),
        )
        .route(
            "/app.js",
            get(|| async { asset(JS, "text/javascript; charset=utf-8") }),
        )
        .route("/api/session", get(session))
        .route("/api/dashboard", post(dashboard))
        .route("/api/enroll/begin", post(enroll))
        .route("/api/enroll/finish", post(register))
        .route("/api/auth/begin", post(begin))
        .route("/api/auth/finish", post(finish))
        .route("/api/logout", post(logout))
        .route("/api/agent", post(agent))
        .route("/mcp", post(mcp).get(no_stream))
        .layer(DefaultBodyLimit::max(MAX_MESSAGE))
        .with_state(Arc::new(Mutex::new(Box::new(owner) as Box<dyn OwnerApi>)))
}
/// Static-only design preview: no authority store, signer or WebAuthn endpoint exists.
pub fn preview_router() -> Router {
    Router::new()
        .route(
            "/",
            get(|| async {
                let mut r = (
                    [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    HTML.replace("data-preview=\"false\"", "data-preview=\"true\""),
                )
                    .into_response();
                headers(&mut r);
                r
            }),
        )
        .route(
            "/app.css",
            get(|| async { asset(CSS, "text/css; charset=utf-8") }),
        )
        .route(
            "/app.js",
            get(|| async { asset(JS, "text/javascript; charset=utf-8") }),
        )
}
