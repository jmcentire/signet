//! A small site that uses passkeys, for the browser end-to-end test.
//!
//! `webauthn-rs` issues the challenges and verifies the results, so the site's
//! side of WebAuthn is code this project did not write. The page calls the
//! browser's standard `navigator.credentials` API and nothing else: it does
//! not know whether the browser, a security key or Signet answers.
//!
//!     cargo run -p signet-passkey-desktop --example test_site
use axum::extract::State;
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use webauthn_rs::prelude::*;

struct Site {
    webauthn: Webauthn,
    registering: Option<PasskeyRegistration>,
    signing_in: Option<PasskeyAuthentication>,
    passkeys: Vec<Passkey>,
}

type Shared = Arc<Mutex<Site>>;

const PAGE: &str = r#"<!doctype html>
<meta charset="utf-8">
<title>Passkey test site</title>
<h1>Passkey test site</h1>
<button id="register">Create a passkey</button>
<button id="login">Sign in</button>
<pre id="out"></pre>
<script>
const b64u = {
  decode(text) {
    const pad = text.replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(pad + '='.repeat((4 - pad.length % 4) % 4));
    return Uint8Array.from(raw, c => c.charCodeAt(0)).buffer;
  },
  encode(buffer) {
    let raw = '';
    for (const byte of new Uint8Array(buffer)) raw += String.fromCharCode(byte);
    return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
};
async function post(path, body) {
  const reply = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
  return reply.json();
}
// What a careful site checks about the object the browser hands back.
function shape(credential, kind) {
  const response = credential.response;
  const facts = {
    isPublicKeyCredential: credential instanceof PublicKeyCredential,
    type: credential.type,
    idMatchesRawId: credential.id === b64u.encode(credential.rawId),
    rawIdIsBuffer: credential.rawId instanceof ArrayBuffer,
    clientDataIsBuffer: response.clientDataJSON instanceof ArrayBuffer,
    attachment: credential.authenticatorAttachment,
    extensions: credential.getClientExtensionResults(),
  };
  if (kind === 'create') {
    facts.isAttestationResponse = response instanceof AuthenticatorAttestationResponse;
    facts.transports = response.getTransports();
    facts.algorithm = response.getPublicKeyAlgorithm();
    facts.publicKeyBytes = response.getPublicKey()?.byteLength ?? null;
    facts.authenticatorDataBytes = response.getAuthenticatorData().byteLength;
  } else {
    facts.isAssertionResponse = response instanceof AuthenticatorAssertionResponse;
    facts.signatureIsBuffer = response.signature instanceof ArrayBuffer;
  }
  return facts;
}
async function register(name) {
  const { publicKey } = await post('/register/start', { name });
  publicKey.challenge = b64u.decode(publicKey.challenge);
  publicKey.user.id = b64u.decode(publicKey.user.id);
  for (const item of publicKey.excludeCredentials ?? []) item.id = b64u.decode(item.id);
  publicKey.extensions = { ...(publicKey.extensions ?? {}), credProps: true };
  const credential = await navigator.credentials.create({ publicKey });
  const result = await post('/register/finish', {
    id: credential.id,
    rawId: b64u.encode(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: b64u.encode(credential.response.clientDataJSON),
      attestationObject: b64u.encode(credential.response.attestationObject),
    },
    extensions: {},
  });
  return { ...result, client: shape(credential, 'create') };
}
async function login() {
  const { publicKey } = await post('/login/start');
  publicKey.challenge = b64u.decode(publicKey.challenge);
  for (const item of publicKey.allowCredentials ?? []) item.id = b64u.decode(item.id);
  const credential = await navigator.credentials.get({ publicKey });
  const response = credential.response;
  const result = await post('/login/finish', {
    id: credential.id,
    rawId: b64u.encode(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: b64u.encode(response.clientDataJSON),
      authenticatorData: b64u.encode(response.authenticatorData),
      signature: b64u.encode(response.signature),
      userHandle: response.userHandle ? b64u.encode(response.userHandle) : null,
    },
    extensions: {},
  });
  return { ...result, client: shape(credential, 'get') };
}
// The end-to-end test calls these directly. A person can use the buttons.
window.site = {
  register: name => register(name).catch(e => ({ error: e.name, message: e.message })),
  login: () => login().catch(e => ({ error: e.name, message: e.message })),
};
const show = promise => promise.then(result => {
  document.getElementById('out').textContent = JSON.stringify(result, null, 2);
});
document.getElementById('register').onclick = () => show(window.site.register('ada'));
document.getElementById('login').onclick = () => show(window.site.login());
</script>
"#;

fn refused(error: impl std::fmt::Display) -> Json<Value> {
    Json(json!({ "verified": false, "reason": error.to_string() }))
}

async fn register_start(State(site): State<Shared>, Json(body): Json<Value>) -> Json<Value> {
    let mut site = site.lock().unwrap();
    let name = body["name"].as_str().unwrap_or("ada").to_owned();
    let exclude = site.passkeys.iter().map(|p| p.cred_id().clone()).collect();
    match site
        .webauthn
        .start_passkey_registration(Uuid::new_v4(), &name, &name, Some(exclude))
    {
        Ok((challenge, state)) => {
            site.registering = Some(state);
            Json(serde_json::to_value(challenge).expect("challenge serializes"))
        }
        Err(error) => refused(error),
    }
}

async fn register_finish(
    State(site): State<Shared>,
    Json(credential): Json<RegisterPublicKeyCredential>,
) -> Json<Value> {
    let mut site = site.lock().unwrap();
    let Some(state) = site.registering.take() else {
        return refused("no registration in progress");
    };
    match site
        .webauthn
        .finish_passkey_registration(&credential, &state)
    {
        Ok(passkey) => {
            site.passkeys.push(passkey);
            Json(json!({ "verified": true, "passkeys": site.passkeys.len() }))
        }
        Err(error) => refused(error),
    }
}

async fn login_start(State(site): State<Shared>) -> Json<Value> {
    let mut site = site.lock().unwrap();
    match site.webauthn.start_passkey_authentication(&site.passkeys) {
        Ok((challenge, state)) => {
            site.signing_in = Some(state);
            Json(serde_json::to_value(challenge).expect("challenge serializes"))
        }
        Err(error) => refused(error),
    }
}

async fn login_finish(
    State(site): State<Shared>,
    Json(credential): Json<PublicKeyCredential>,
) -> Json<Value> {
    let mut site = site.lock().unwrap();
    let Some(state) = site.signing_in.take() else {
        return refused("no sign-in in progress");
    };
    match site
        .webauthn
        .finish_passkey_authentication(&credential, &state)
    {
        Ok(result) => Json(json!({
            "verified": true,
            "userVerified": result.user_verified(),
        })),
        Err(error) => refused(error),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a free port");
    let port = listener.local_addr().expect("bound").port();
    // `localhost` is the one host browsers allow passkeys on without HTTPS.
    let origin = format!("http://localhost:{port}");
    let webauthn = WebauthnBuilder::new("localhost", &Url::parse(&origin).expect("origin"))
        .expect("site configuration")
        .rp_name("Passkey test site")
        .build()
        .expect("site configuration");
    let site: Shared = Arc::new(Mutex::new(Site {
        webauthn,
        registering: None,
        signing_in: None,
        passkeys: Vec::new(),
    }));
    let app = Router::new()
        .route("/", get(|| async { Html(PAGE) }))
        .route("/register/start", post(register_start))
        .route("/register/finish", post(register_finish))
        .route("/login/start", post(login_start))
        .route("/login/finish", post(login_finish))
        .with_state(site);
    println!("listening {origin}");
    axum::serve(listener, app).await.expect("server runs");
}
