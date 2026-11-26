//! The relay: a mailbox between a phone and the computers paired with it.
//!
//! It holds sealed envelopes for a few minutes and hands each to the device it
//! is addressed to. It cannot read or forge them: the devices sign and seal
//! every message to each other (`signet_passkey::seal`). What a relay can do is
//! drop or delay messages, and observe which devices exchange messages and
//! when. The request format is defined in `signet_passkey::relay`.
//!
//! Everything is kept in memory. Messages live for minutes, and each device
//! restates who may write to it on every read, so a relay that restarts has
//! nothing to restore. TLS is expected to be terminated in front of it.
//!
//! # HTTP interface
//!
//! | Request | Caller | Purpose |
//! |---|---|---|
//! | `POST /v1/mailbox/{fp}/poll` | signed by `fp` | Read own mailbox, acknowledge earlier messages, restate allowed senders |
//! | `POST /v1/mailbox/{fp}/messages[?slot=][&ttl=]` | signed by an allowed sender | Leave a sealed envelope for `fp` |
//! | `PUT /v1/rendezvous/{id}` | anyone who read the pairing ticket | Leave the one pairing reply |
//! | `GET /v1/rendezvous/{id}[?wait=]` | anyone who read the pairing ticket | Collect the pairing reply, once |
//! | `GET /v1/health` | anyone | Liveness |
#![forbid(unsafe_code)]

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use signet_passkey::relay::{
    is_id, Caller, DepositReceipt, PollRequest, PollResponse, RelayAuth, RelayMessage,
    AUTH_WINDOW_SECS, DEFAULT_MESSAGE_TTL_SECS,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::sync::watch;

/// Source of the current time, Unix seconds. Injected so expiry can be tested.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// The system clock.
pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0)
    })
}

/// Limits and names for one relay.
#[derive(Clone)]
pub struct RelayConfig {
    /// The addresses devices know this relay by, in the normal form of
    /// `signet_passkey::relay::normalize_relay_url`. A signed request must
    /// name one of them.
    pub audiences: Vec<String>,
    pub max_message_bytes: usize,
    /// Messages one sender may have waiting in one mailbox.
    pub max_per_sender: usize,
    pub max_per_mailbox: usize,
    /// Senders one device may allow.
    pub max_peers: usize,
    pub max_message_ttl_secs: i64,
    pub max_wait_secs: u64,
    pub max_mailboxes: usize,
    pub max_rendezvous: usize,
    pub max_rendezvous_bytes: usize,
    pub rendezvous_ttl_secs: i64,
    /// How long a device's list of allowed senders is kept after its last read.
    pub registration_ttl_secs: i64,
    /// Signed requests one device may make per minute.
    pub requests_per_minute: u32,
    /// Pairing-reply requests the relay accepts per minute, from everyone
    /// together. These are unsigned, so this is the only limit they have here;
    /// a public deployment should also limit them by network address in front.
    pub rendezvous_per_minute: u32,
    pub clock: Clock,
}

impl RelayConfig {
    pub fn new(audiences: Vec<String>) -> Self {
        Self {
            audiences,
            max_message_bytes: 16 * 1024,
            max_per_sender: 8,
            max_per_mailbox: 64,
            max_peers: 32,
            max_message_ttl_secs: 330,
            max_wait_secs: 30,
            max_mailboxes: 50_000,
            max_rendezvous: 4096,
            max_rendezvous_bytes: 4096,
            rendezvous_ttl_secs: 600,
            registration_ttl_secs: 30 * 24 * 3600,
            requests_per_minute: 240,
            rendezvous_per_minute: 600,
            clock: system_clock(),
        }
    }
}

struct Stored {
    id: String,
    from: String,
    slot: Option<String>,
    body: Vec<u8>,
    expires_at: i64,
}

struct Mailbox {
    peers: HashSet<String>,
    last_read: i64,
    queue: Vec<Stored>,
    /// Bumped on every deposit, so a waiting reader wakes even if the deposit
    /// lands between its check and its wait.
    signal: watch::Sender<u64>,
}

#[derive(Default)]
struct Inner {
    mailboxes: HashMap<String, Mailbox>,
    rendezvous: HashMap<String, (Vec<u8>, i64)>,
    /// `(fingerprint, nonce)` of recent signed requests, with expiry.
    nonces: HashMap<(String, String), i64>,
    /// Per-device request count in the current minute.
    rates: HashMap<String, (i64, u32)>,
    rendezvous_rate: (i64, u32),
}

struct Shared {
    config: RelayConfig,
    inner: Mutex<Inner>,
    rendezvous_signal: watch::Sender<u64>,
}

/// Counts, for the health endpoint's operator and for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub mailboxes: usize,
    pub messages: usize,
    pub rendezvous: usize,
}

/// One relay's state and routes.
#[derive(Clone)]
pub struct Relay {
    shared: Arc<Shared>,
}

enum Reject {
    Unauthorized,
    Forbidden,
    NotAccepted,
    BadRequest(&'static str),
    TooLarge,
    Exists,
    Busy(&'static str),
}

impl IntoResponse for Reject {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            // One answer for every authentication failure: a caller that fails
            // learns nothing about why.
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            // The same answer whether the mailbox is unknown or the sender is
            // not on its list, so mailboxes cannot be enumerated.
            Self::NotAccepted => (StatusCode::FORBIDDEN, "not_accepted"),
            Self::BadRequest(code) => (StatusCode::BAD_REQUEST, code),
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "too_large"),
            Self::Exists => (StatusCode::CONFLICT, "exists"),
            Self::Busy(code) => (StatusCode::TOO_MANY_REQUESTS, code),
        };
        (status, Json(serde_json::json!({ "error": code }))).into_response()
    }
}

fn random_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

impl Shared {
    fn now(&self) -> i64 {
        (self.config.clock)()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panic while holding the lock leaves plain data behind, nothing
        // half-applied that a later request could misread.
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Check the request signature, the replay cache and the caller's rate.
    fn authenticate(
        &self,
        headers: &HeaderMap,
        method: &str,
        uri: &Uri,
        body: &[u8],
    ) -> Result<Caller, Reject> {
        let header = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(Reject::Unauthorized)?;
        let auth = RelayAuth::from_header(header).map_err(|_| Reject::Unauthorized)?;
        let path = uri
            .path_and_query()
            .map(|path| path.as_str())
            .unwrap_or_else(|| uri.path());
        let now = self.now();
        let caller = auth
            .verify(&self.config.audiences, method, path, body, now)
            .map_err(|_| Reject::Unauthorized)?;

        let mut inner = self.lock();
        let minute = now.div_euclid(60);
        let rate = inner
            .rates
            .entry(caller.fingerprint.clone())
            .or_insert((minute, 0));
        if rate.0 != minute {
            *rate = (minute, 0);
        }
        rate.1 += 1;
        if rate.1 > self.config.requests_per_minute {
            return Err(Reject::Busy("slow_down"));
        }
        let key = (caller.fingerprint.clone(), caller.nonce.clone());
        if inner.nonces.contains_key(&key) {
            return Err(Reject::Unauthorized);
        }
        inner
            .nonces
            .insert(key, caller.timestamp + AUTH_WINDOW_SECS + 1);
        Ok(caller)
    }

    fn sweep(&self) {
        let now = self.now();
        let registration_ttl = self.config.registration_ttl_secs;
        let mut inner = self.lock();
        inner.nonces.retain(|_, expires| *expires > now);
        let minute = now.div_euclid(60);
        inner.rates.retain(|_, (window, _)| *window == minute);
        inner.rendezvous.retain(|_, (_, expires)| *expires > now);
        inner.mailboxes.retain(|_, mailbox| {
            mailbox.queue.retain(|message| message.expires_at > now);
            !mailbox.queue.is_empty() || mailbox.last_read + registration_ttl > now
        });
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DepositQuery {
    slot: Option<String>,
    ttl: Option<i64>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WaitQuery {
    wait: Option<u64>,
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "v": signet_passkey::PROTOCOL_VERSION }))
}

async fn deposit(
    State(shared): State<Arc<Shared>>,
    Path(recipient): Path<String>,
    Query(query): Query<DepositQuery>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Reject> {
    if body.len() > shared.config.max_message_bytes {
        return Err(Reject::TooLarge);
    }
    let caller = shared.authenticate(&headers, "POST", &uri, &body)?;
    if !is_id(&recipient) || query.slot.as_deref().is_some_and(|slot| !is_id(slot)) {
        return Err(Reject::BadRequest("bad_address"));
    }
    if body.is_empty() {
        return Err(Reject::BadRequest("empty"));
    }
    let now = shared.now();
    let ttl = query
        .ttl
        .unwrap_or(DEFAULT_MESSAGE_TTL_SECS)
        .clamp(1, shared.config.max_message_ttl_secs);

    let mut inner = shared.lock();
    let mailbox = inner
        .mailboxes
        .get_mut(&recipient)
        .ok_or(Reject::NotAccepted)?;
    if !mailbox.peers.contains(&caller.fingerprint) {
        return Err(Reject::NotAccepted);
    }
    mailbox.queue.retain(|message| message.expires_at > now);
    let from_sender = mailbox
        .queue
        .iter()
        .filter(|message| message.from == caller.fingerprint)
        .count();
    if from_sender >= shared.config.max_per_sender
        || mailbox.queue.len() >= shared.config.max_per_mailbox
    {
        return Err(Reject::Busy("mailbox_full"));
    }
    let receipt = DepositReceipt {
        id: random_id(),
        expires_at: now + ttl,
    };
    mailbox.queue.push(Stored {
        id: receipt.id.clone(),
        from: caller.fingerprint,
        slot: query.slot,
        body: body.to_vec(),
        expires_at: receipt.expires_at,
    });
    mailbox.signal.send_modify(|version| *version += 1);
    Ok((StatusCode::ACCEPTED, Json(receipt)).into_response())
}

async fn poll(
    State(shared): State<Arc<Shared>>,
    Path(owner): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Reject> {
    let caller = shared.authenticate(&headers, "POST", &uri, &body)?;
    if caller.fingerprint != owner {
        return Err(Reject::Forbidden);
    }
    let request: PollRequest =
        serde_json::from_slice(&body).map_err(|_| Reject::BadRequest("bad_request"))?;
    if request.peers.len() > shared.config.max_peers
        || request.ack.len() > shared.config.max_per_mailbox
        || !request.peers.iter().all(|peer| is_id(peer))
        || !request.ack.iter().all(|id| is_id(id))
        || request.slot.as_deref().is_some_and(|slot| !is_id(slot))
    {
        return Err(Reject::BadRequest("bad_request"));
    }
    let wait = Duration::from_secs(request.wait_secs.min(shared.config.max_wait_secs));
    let deadline = tokio::time::Instant::now() + wait;
    let peers: HashSet<String> = request.peers.iter().cloned().collect();
    let mut first = true;

    loop {
        let mut wake = {
            let now = shared.now();
            let mut inner = shared.lock();
            if !inner.mailboxes.contains_key(&owner)
                && inner.mailboxes.len() >= shared.config.max_mailboxes
            {
                return Err(Reject::Busy("relay_full"));
            }
            let mailbox = inner
                .mailboxes
                .entry(owner.clone())
                .or_insert_with(|| Mailbox {
                    peers: HashSet::new(),
                    last_read: now,
                    queue: Vec::new(),
                    signal: watch::channel(0).0,
                });
            if first {
                first = false;
                mailbox.peers = peers.clone();
                mailbox
                    .queue
                    .retain(|message| !request.ack.contains(&message.id));
            }
            mailbox.last_read = now;
            // A sender taken off the list loses what it had queued.
            mailbox
                .queue
                .retain(|message| message.expires_at > now && peers.contains(&message.from));
            let messages: Vec<RelayMessage> = mailbox
                .queue
                .iter()
                .filter(|message| message.slot == request.slot)
                .map(|message| RelayMessage {
                    id: message.id.clone(),
                    from: message.from.clone(),
                    slot: message.slot.clone(),
                    body: signet_passkey::relay::encode(&message.body),
                    expires_at: message.expires_at,
                })
                .collect();
            if !messages.is_empty() || tokio::time::Instant::now() >= deadline {
                return Ok(Json(PollResponse { messages }).into_response());
            }
            mailbox.signal.subscribe()
        };
        // Woken by a deposit, by the mailbox being swept, or by the deadline.
        // Each case re-reads the mailbox above.
        let _ = tokio::time::timeout_at(deadline, wake.changed()).await;
    }
}

async fn rendezvous_put(
    State(shared): State<Arc<Shared>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, Reject> {
    if !is_id(&id) {
        return Err(Reject::BadRequest("bad_address"));
    }
    if body.len() > shared.config.max_rendezvous_bytes {
        return Err(Reject::TooLarge);
    }
    if body.is_empty() {
        return Err(Reject::BadRequest("empty"));
    }
    let now = shared.now();
    let mut inner = shared.lock();
    let minute = now.div_euclid(60);
    if inner.rendezvous_rate.0 != minute {
        inner.rendezvous_rate = (minute, 0);
    }
    inner.rendezvous_rate.1 += 1;
    if inner.rendezvous_rate.1 > shared.config.rendezvous_per_minute {
        return Err(Reject::Busy("slow_down"));
    }
    inner.rendezvous.retain(|_, (_, expires)| *expires > now);
    if inner.rendezvous.contains_key(&id) {
        return Err(Reject::Exists);
    }
    if inner.rendezvous.len() >= shared.config.max_rendezvous {
        return Err(Reject::Busy("relay_full"));
    }
    inner
        .rendezvous
        .insert(id, (body.to_vec(), now + shared.config.rendezvous_ttl_secs));
    drop(inner);
    shared
        .rendezvous_signal
        .send_modify(|version| *version += 1);
    Ok(StatusCode::CREATED.into_response())
}

async fn rendezvous_get(
    State(shared): State<Arc<Shared>>,
    Path(id): Path<String>,
    Query(query): Query<WaitQuery>,
) -> Result<Response, Reject> {
    if !is_id(&id) {
        return Err(Reject::BadRequest("bad_address"));
    }
    let wait = Duration::from_secs(query.wait.unwrap_or(0).min(shared.config.max_wait_secs));
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let mut wake = {
            let now = shared.now();
            let mut inner = shared.lock();
            let live = inner
                .rendezvous
                .get(&id)
                .is_some_and(|(_, expires)| *expires > now);
            if live {
                let (body, _) = inner.rendezvous.remove(&id).expect("checked above");
                return Ok((
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/octet-stream")],
                    body,
                )
                    .into_response());
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(StatusCode::NO_CONTENT.into_response());
            }
            shared.rendezvous_signal.subscribe()
        };
        let _ = tokio::time::timeout_at(deadline, wake.changed()).await;
    }
}

impl Relay {
    pub fn new(config: RelayConfig) -> Self {
        Self {
            shared: Arc::new(Shared {
                config,
                inner: Mutex::new(Inner::default()),
                rendezvous_signal: watch::channel(0).0,
            }),
        }
    }

    /// The HTTP routes.
    pub fn router(&self) -> Router {
        // Bodies are small by design. This is the outer bound; each route
        // applies its own.
        let limit = self
            .shared
            .config
            .max_message_bytes
            .max(self.shared.config.max_rendezvous_bytes)
            .max(16 * 1024);
        Router::new()
            .route("/v1/health", get(health))
            .route("/v1/mailbox/{fingerprint}/messages", post(deposit))
            .route("/v1/mailbox/{fingerprint}/poll", post(poll))
            .route(
                "/v1/rendezvous/{id}",
                get(rendezvous_get).put(rendezvous_put),
            )
            .layer(DefaultBodyLimit::max(limit))
            .with_state(self.shared.clone())
    }

    /// Drop everything that has expired. [`serve`] calls this periodically.
    pub fn sweep(&self) {
        self.shared.sweep();
    }

    pub fn stats(&self) -> Stats {
        let inner = self.shared.lock();
        Stats {
            mailboxes: inner.mailboxes.len(),
            messages: inner.mailboxes.values().map(|m| m.queue.len()).sum(),
            rendezvous: inner.rendezvous.len(),
        }
    }
}

/// Run a relay on `listener` until the task is dropped.
pub async fn serve(listener: tokio::net::TcpListener, config: RelayConfig) -> std::io::Result<()> {
    let relay = Relay::new(config);
    let sweeper = relay.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            sweeper.sweep();
        }
    });
    axum::serve(listener, relay.router()).await
}

/// The names a relay listening on a loopback address answers to when none are
/// configured: the address itself and `localhost`, over plain HTTP.
pub fn loopback_audiences(address: std::net::SocketAddr) -> Option<Vec<String>> {
    if !address.ip().is_loopback() {
        return None;
    }
    let host = match address.ip() {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    };
    Some(vec![
        format!("http://{host}:{}", address.port()),
        format!("http://localhost:{}", address.port()),
    ])
}
