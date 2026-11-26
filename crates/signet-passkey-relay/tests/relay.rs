//! The relay's rules, exercised through its HTTP routes.
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use signet_passkey::relay::{
    deposit_path, poll_path, rendezvous_path, DepositReceipt, PollRequest, PollResponse, RelayAuth,
};
use signet_passkey::{IdentityKeys, SoftwareIdentity};
use signet_passkey_relay::{Relay, RelayConfig};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use tower::ServiceExt;

const AUDIENCE: &str = "https://relay.example";
const START: i64 = 1_800_000_000;

struct Harness {
    relay: Relay,
    clock: Arc<AtomicI64>,
}

fn harness_with(adjust: impl FnOnce(&mut RelayConfig)) -> Harness {
    let clock = Arc::new(AtomicI64::new(START));
    let reader = clock.clone();
    let mut config = RelayConfig::new(vec![AUDIENCE.to_owned()]);
    config.clock = Arc::new(move || reader.load(Ordering::SeqCst));
    adjust(&mut config);
    Harness {
        relay: Relay::new(config),
        clock,
    }
}

fn harness() -> Harness {
    harness_with(|_| {})
}

struct Reply {
    status: StatusCode,
    body: Vec<u8>,
}

impl Reply {
    fn json<T: serde::de::DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body).expect("JSON body")
    }

    fn error(&self) -> String {
        let value: serde_json::Value = self.json();
        value["error"].as_str().unwrap_or_default().to_owned()
    }
}

impl Harness {
    fn now(&self) -> i64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn advance(&self, seconds: i64) {
        self.clock.fetch_add(seconds, Ordering::SeqCst);
    }

    async fn send(&self, request: Request<Body>) -> Reply {
        let response = self.relay.router().oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        Reply {
            status,
            body: body.to_vec(),
        }
    }

    fn signed(&self, who: &SoftwareIdentity, path: &str, body: &[u8]) -> Request<Body> {
        let auth = RelayAuth::sign(who, AUDIENCE, "POST", path, body, self.now()).unwrap();
        Request::post(path)
            .header(header::AUTHORIZATION, auth.to_header())
            .body(Body::from(body.to_vec()))
            .unwrap()
    }

    async fn poll_with(&self, who: &SoftwareIdentity, request: &PollRequest) -> Reply {
        let path = poll_path(&fp(who));
        let body = serde_json::to_vec(request).unwrap();
        self.send(self.signed(who, &path, &body)).await
    }

    /// Read `who`'s mailbox, allowing `peers` to write to it.
    async fn poll(&self, who: &SoftwareIdentity, peers: &[&SoftwareIdentity]) -> PollResponse {
        let reply = self.poll_with(who, &poll_request(peers)).await;
        assert_eq!(reply.status, StatusCode::OK);
        reply.json()
    }

    async fn deposit(
        &self,
        from: &SoftwareIdentity,
        to: &SoftwareIdentity,
        slot: Option<&str>,
        body: &[u8],
    ) -> Reply {
        let path = deposit_path(&fp(to), slot);
        self.send(self.signed(from, &path, body)).await
    }
}

fn fp(who: &SoftwareIdentity) -> String {
    who.public().fingerprint()
}

fn poll_request(peers: &[&SoftwareIdentity]) -> PollRequest {
    PollRequest {
        peers: peers.iter().map(|peer| fp(peer)).collect(),
        slot: None,
        wait_secs: 0,
        ack: Vec::new(),
    }
}

fn bodies(response: &PollResponse) -> Vec<Vec<u8>> {
    response
        .messages
        .iter()
        .map(|message| signet_passkey::relay::decode(&message.body).unwrap())
        .collect()
}

#[tokio::test]
async fn a_message_is_delivered_until_acknowledged() {
    let h = harness();
    let (phone, computer) = (SoftwareIdentity::generate(), SoftwareIdentity::generate());
    h.poll(&phone, &[&computer]).await;

    let reply = h.deposit(&computer, &phone, None, b"sealed").await;
    assert_eq!(reply.status, StatusCode::ACCEPTED);
    let receipt: DepositReceipt = reply.json();

    let first = h.poll(&phone, &[&computer]).await;
    assert_eq!(bodies(&first), vec![b"sealed".to_vec()]);
    assert_eq!(first.messages[0].id, receipt.id);
    assert_eq!(first.messages[0].from, fp(&computer));
    // Not acknowledged, so a reader that lost the reply gets it again.
    let again = h.poll(&phone, &[&computer]).await;
    assert_eq!(again.messages.len(), 1);

    let mut ack = poll_request(&[&computer]);
    ack.ack = vec![receipt.id];
    let after: PollResponse = h.poll_with(&phone, &ack).await.json();
    assert!(after.messages.is_empty());
    assert_eq!(h.relay.stats().messages, 0);
}

#[tokio::test]
async fn only_listed_senders_can_leave_messages() {
    let h = harness();
    let (phone, computer, stranger) = (
        SoftwareIdentity::generate(),
        SoftwareIdentity::generate(),
        SoftwareIdentity::generate(),
    );
    // No mailbox yet, and a mailbox that does not list the sender, look alike.
    let unknown = h.deposit(&stranger, &phone, None, b"x").await;
    assert_eq!(unknown.status, StatusCode::FORBIDDEN);
    assert_eq!(unknown.error(), "not_accepted");

    h.poll(&phone, &[&computer]).await;
    let unlisted = h.deposit(&stranger, &phone, None, b"x").await;
    assert_eq!(unlisted.status, StatusCode::FORBIDDEN);
    assert_eq!(unlisted.error(), "not_accepted");
    assert_eq!(unknown.body, unlisted.body);
    assert!(h.poll(&phone, &[&computer]).await.messages.is_empty());
}

#[tokio::test]
async fn only_the_owner_reads_a_mailbox() {
    let h = harness();
    let (phone, computer, stranger) = (
        SoftwareIdentity::generate(),
        SoftwareIdentity::generate(),
        SoftwareIdentity::generate(),
    );
    h.poll(&phone, &[&computer]).await;
    h.deposit(&computer, &phone, None, b"sealed").await;

    // A valid signature by another device, on the phone's mailbox path.
    let path = poll_path(&fp(&phone));
    let body = serde_json::to_vec(&poll_request(&[&stranger])).unwrap();
    let reply = h.send(h.signed(&stranger, &path, &body)).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    // The attempt changed nothing: the list of senders is intact.
    assert_eq!(
        h.deposit(&stranger, &phone, None, b"x").await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(h.poll(&phone, &[&computer]).await.messages.len(), 1);
}

#[tokio::test]
async fn unsigned_altered_stale_and_replayed_requests_are_refused() {
    let h = harness();
    let phone = SoftwareIdentity::generate();
    let path = poll_path(&fp(&phone));
    let body = serde_json::to_vec(&poll_request(&[])).unwrap();
    let auth = |audience: &str, method: &str, signed_body: &[u8], at: i64| {
        RelayAuth::sign(&phone, audience, method, &path, signed_body, at)
            .unwrap()
            .to_header()
    };
    let attempt = |header_value: Option<String>, sent_body: Vec<u8>| {
        let mut request = Request::post(&path);
        if let Some(value) = header_value {
            request = request.header(header::AUTHORIZATION, value);
        }
        h.send(request.body(Body::from(sent_body)).unwrap())
    };

    let cases: Vec<(&str, Option<String>, Vec<u8>)> = vec![
        ("no header", None, body.clone()),
        ("not our scheme", Some("Bearer abc".into()), body.clone()),
        ("garbage", Some("Signet-Relay !!!".into()), body.clone()),
        (
            "signed for another relay",
            Some(auth("https://other.example", "POST", &body, START)),
            body.clone(),
        ),
        (
            "signed for another method",
            Some(auth(AUDIENCE, "GET", &body, START)),
            body.clone(),
        ),
        (
            "body changed after signing",
            Some(auth(AUDIENCE, "POST", &body, START)),
            serde_json::to_vec(&PollRequest {
                wait_secs: 1,
                ..poll_request(&[])
            })
            .unwrap(),
        ),
        (
            "stale",
            Some(auth(AUDIENCE, "POST", &body, START - 120)),
            body.clone(),
        ),
        (
            "from the future",
            Some(auth(AUDIENCE, "POST", &body, START + 120)),
            body.clone(),
        ),
    ];
    for (name, header_value, sent) in cases {
        let reply = attempt(header_value, sent).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{name}");
        assert_eq!(reply.error(), "unauthorized", "{name}");
    }

    // The same signed request twice: the second is a replay.
    let once = auth(AUDIENCE, "POST", &body, START);
    assert_eq!(
        attempt(Some(once.clone()), body.clone()).await.status,
        StatusCode::OK
    );
    assert_eq!(
        attempt(Some(once), body.clone()).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn slots_keep_answers_for_different_waiters_apart() {
    let h = harness();
    let (phone, computer) = (SoftwareIdentity::generate(), SoftwareIdentity::generate());
    let slot_a = signet_passkey::relay::reply_slot(b"request-a");
    let slot_b = signet_passkey::relay::reply_slot(b"request-b");
    h.poll(&computer, &[&phone]).await;
    h.deposit(&phone, &computer, Some(&slot_a), b"answer-a")
        .await;
    h.deposit(&phone, &computer, Some(&slot_b), b"answer-b")
        .await;
    h.deposit(&phone, &computer, None, b"unslotted").await;

    let (relay, reader) = (&h, &computer);
    let read = |slot: Option<String>| {
        let mut request = poll_request(&[&phone]);
        request.slot = slot;
        async move {
            relay
                .poll_with(reader, &request)
                .await
                .json::<PollResponse>()
        }
    };
    assert_eq!(
        bodies(&read(Some(slot_a)).await),
        vec![b"answer-a".to_vec()]
    );
    assert_eq!(
        bodies(&read(Some(slot_b)).await),
        vec![b"answer-b".to_vec()]
    );
    assert_eq!(bodies(&read(None).await), vec![b"unslotted".to_vec()]);

    let bad = h
        .deposit(&phone, &computer, Some("../../etc/passwd"), b"x")
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn messages_expire_and_sizes_and_counts_are_bounded() {
    let h = harness_with(|config| {
        config.max_message_bytes = 64;
        config.max_per_sender = 2;
        config.max_peers = 2;
    });
    let (phone, computer) = (SoftwareIdentity::generate(), SoftwareIdentity::generate());
    h.poll(&phone, &[&computer]).await;

    assert_eq!(
        h.deposit(&computer, &phone, None, &[0u8; 65]).await.status,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        h.deposit(&computer, &phone, None, b"").await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        h.deposit(&computer, &phone, None, b"1").await.status,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        h.deposit(&computer, &phone, None, b"2").await.status,
        StatusCode::ACCEPTED
    );
    let full = h.deposit(&computer, &phone, None, b"3").await;
    assert_eq!(full.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(full.error(), "mailbox_full");

    // Past their lifetime the two that were accepted are gone, and there is
    // room again.
    h.advance(signet_passkey::relay::DEFAULT_MESSAGE_TTL_SECS + 1);
    assert!(h.poll(&phone, &[&computer]).await.messages.is_empty());
    assert_eq!(
        h.deposit(&computer, &phone, None, b"4").await.status,
        StatusCode::ACCEPTED
    );

    let extra = [SoftwareIdentity::generate(), SoftwareIdentity::generate()];
    let too_many = h
        .poll_with(&phone, &poll_request(&[&computer, &extra[0], &extra[1]]))
        .await;
    assert_eq!(too_many.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_sender_taken_off_the_list_loses_its_queued_messages() {
    let h = harness();
    let (phone, computer) = (SoftwareIdentity::generate(), SoftwareIdentity::generate());
    h.poll(&phone, &[&computer]).await;
    h.deposit(&computer, &phone, None, b"sealed").await;
    // The owner unpaired the computer before reading.
    assert!(h.poll(&phone, &[]).await.messages.is_empty());
    assert_eq!(h.relay.stats().messages, 0);
    assert_eq!(
        h.deposit(&computer, &phone, None, b"again").await.status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn a_waiting_reader_is_woken_by_a_deposit() {
    let h = Arc::new(harness());
    let phone = Arc::new(SoftwareIdentity::generate());
    let computer = Arc::new(SoftwareIdentity::generate());
    h.poll(&phone, &[&computer]).await;

    let reader = {
        let (h, phone, computer) = (h.clone(), phone.clone(), computer.clone());
        tokio::spawn(async move {
            let mut request = poll_request(&[&computer]);
            request.wait_secs = 20;
            let started = std::time::Instant::now();
            let response: PollResponse = h.poll_with(&phone, &request).await.json();
            (response, started.elapsed())
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    h.deposit(&computer, &phone, None, b"sealed").await;
    let (response, waited) = reader.await.unwrap();
    assert_eq!(bodies(&response), vec![b"sealed".to_vec()]);
    assert!(waited < std::time::Duration::from_secs(5), "{waited:?}");
}

#[tokio::test]
async fn a_reader_with_nothing_waiting_returns_empty_after_its_wait() {
    let h = harness();
    let phone = SoftwareIdentity::generate();
    let mut request = poll_request(&[]);
    request.wait_secs = 1;
    let started = std::time::Instant::now();
    let response: PollResponse = h.poll_with(&phone, &request).await.json();
    assert!(response.messages.is_empty());
    assert!(started.elapsed() >= std::time::Duration::from_millis(900));
}

#[tokio::test]
async fn a_pairing_reply_is_left_once_and_collected_once() {
    let h = harness_with(|config| config.max_rendezvous_bytes = 32);
    let id = signet_passkey::relay::rendezvous_id(&[9u8; 32]);
    let path = rendezvous_path(&id);
    let put =
        |body: &'static [u8]| h.send(Request::put(&path).body(Body::from(body.to_vec())).unwrap());
    let get = || h.send(Request::get(&path).body(Body::empty()).unwrap());

    assert_eq!(get().await.status, StatusCode::NO_CONTENT);
    assert_eq!(put(&[0u8; 33]).await.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(put(b"reply").await.status, StatusCode::CREATED);
    // A second device that read the same ticket cannot replace the reply.
    assert_eq!(put(b"other").await.status, StatusCode::CONFLICT);
    let collected = get().await;
    assert_eq!(collected.status, StatusCode::OK);
    assert_eq!(collected.body, b"reply");
    assert_eq!(get().await.status, StatusCode::NO_CONTENT);

    // An uncollected reply expires.
    assert_eq!(put(b"late").await.status, StatusCode::CREATED);
    h.advance(601);
    assert_eq!(get().await.status, StatusCode::NO_CONTENT);

    let bad = h
        .send(
            Request::put("/v1/rendezvous/not-an-id")
                .body(Body::from("x"))
                .unwrap(),
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn one_device_cannot_flood_the_relay() {
    let h = harness_with(|config| config.requests_per_minute = 3);
    let phone = SoftwareIdentity::generate();
    for _ in 0..3 {
        assert_eq!(
            h.poll_with(&phone, &poll_request(&[])).await.status,
            StatusCode::OK
        );
    }
    let limited = h.poll_with(&phone, &poll_request(&[])).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.error(), "slow_down");
    // Another device is unaffected, and the first recovers the next minute.
    let other = SoftwareIdentity::generate();
    assert_eq!(
        h.poll_with(&other, &poll_request(&[])).await.status,
        StatusCode::OK
    );
    h.advance(60);
    assert_eq!(
        h.poll_with(&phone, &poll_request(&[])).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn sweeping_drops_what_has_expired() {
    let h = harness_with(|config| config.registration_ttl_secs = 1_000);
    let (phone, computer) = (SoftwareIdentity::generate(), SoftwareIdentity::generate());
    h.poll(&phone, &[&computer]).await;
    h.deposit(&computer, &phone, None, b"sealed").await;
    assert_eq!(h.relay.stats().mailboxes, 1);
    h.advance(1_001);
    h.relay.sweep();
    let stats = h.relay.stats();
    assert_eq!((stats.mailboxes, stats.messages), (0, 0));
}
