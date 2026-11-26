//! The computer side end to end: a real relay over HTTP, the phone simulator
//! on the other side, and `webauthn-rs` as the site that issues challenges and
//! verifies what comes back.
#[path = "common/phone.rs"]
mod phone;

use phone::{Phone, Scripted};
use serde_json::{json, Value};
use signet_passkey::{OperationKind, Role};
use signet_passkey_desktop::native::{HostReply, HostRequest};
use signet_passkey_desktop::{flow, pair, system_now, Store};
use signet_passkey_relay::{loopback_audiences, serve, RelayConfig};
use std::sync::atomic::{AtomicI64, Ordering};
use webauthn_rs::prelude::*;

const ORIGIN: &str = "https://login.example.com";
const SITE: &str = "example.com";

struct World {
    _dir: tempfile::TempDir,
    store: Store,
    phone: Phone,
    site: Webauthn,
}

async fn start_relay() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = RelayConfig::new(loopback_audiences(address).unwrap());
    tokio::spawn(async move { serve(listener, config).await });
    format!("http://{address}")
}

fn site() -> Webauthn {
    WebauthnBuilder::new(SITE, &Url::parse(ORIGIN).unwrap())
        .unwrap()
        .rp_name("Example")
        .build()
        .unwrap()
}

fn new_store(relay: &str) -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("signet"));
    store.init("Test computer", relay).unwrap();
    (dir, store)
}

/// A computer and a phone, paired through the relay the way a person would.
async fn paired() -> World {
    let relay = start_relay().await;
    let (dir, store) = new_store(&relay);
    let started = pair::start(&store, system_now()).unwrap();
    let mut phone = Phone::new("Test phone");
    let code = phone.pair(&started.ticket, system_now()).await.unwrap();
    let answered = started.wait(&system_now).await.unwrap().unwrap();
    assert_eq!(answered.phone_name(), "Test phone");
    answered.confirm(&store, &code).unwrap();
    World {
        _dir: dir,
        store,
        phone,
        site: site(),
    }
}

fn request(kind: &str, origin: &str, options: Value) -> HostRequest {
    serde_json::from_value(json!({
        "v": 1, "id": "call", "type": kind, "origin": origin,
        "options": options, "browser": "Chrome",
    }))
    .unwrap()
}

impl World {
    /// Make one passkey call while the phone serves its mailbox.
    async fn call(&mut self, owner: &mut Scripted, request: HostRequest) -> HostReply {
        self.call_logged(owner, request).await.0
    }

    async fn call_logged(
        &mut self,
        owner: &mut Scripted,
        request: HostRequest,
    ) -> (HostReply, Vec<HostReply>) {
        let mut earlier = Vec::new();
        let mut progress = |reply: &HostReply| earlier.push(reply.clone());
        let reply = tokio::select! {
            reply = flow::handle(&self.store, request, &system_now, &mut progress) => reply,
            _ = self.phone.serve(owner, &system_now) => unreachable!("the phone serves forever"),
        };
        (reply, earlier)
    }

    fn create_options(&self) -> (Value, PasskeyRegistration) {
        let (challenge, state) = self
            .site
            .start_passkey_registration(Uuid::new_v4(), "ada", "Ada Lovelace", None)
            .unwrap();
        (
            serde_json::to_value(&challenge).unwrap()["publicKey"].clone(),
            state,
        )
    }
}

fn error_of(reply: &HostReply) -> (&str, &str) {
    match reply {
        HostReply::Error { name, message } => (name, message),
        other => panic!("expected an error, got {other:?}"),
    }
}

fn is_native(reply: &HostReply) -> bool {
    matches!(reply, HostReply::Native { .. })
}

#[tokio::test]
async fn a_passkey_is_created_and_used_through_the_relay() {
    let mut world = paired().await;
    let mut owner = Scripted::always(true);

    let (options, state) = world.create_options();
    let mut call = request("create", ORIGIN, options);
    call.options.as_mut().unwrap()["extensions"] = json!({ "credProps": true });
    let (reply, earlier) = world.call_logged(&mut owner, call).await;
    // The person at the computer is told where the request went.
    assert!(matches!(
        earlier.as_slice(),
        [HostReply::Pending { phone, .. }] if phone == "Test phone"
    ));
    let HostReply::Credential { credential } = reply else {
        panic!("expected a credential, got {reply:?}");
    };
    assert_eq!(
        credential["clientExtensionResults"]["credProps"]["rk"],
        true
    );
    assert!(credential["response"]["publicKey"].is_string());
    let parsed: RegisterPublicKeyCredential = serde_json::from_value(credential).unwrap();
    let passkey = world
        .site
        .finish_passkey_registration(&parsed, &state)
        .unwrap();

    // The site is now recorded, so its sign-ins go to the phone.
    assert!(world.store.load().unwrap().sites.contains(SITE));
    let (challenge, state) = world.site.start_passkey_authentication(&[passkey]).unwrap();
    let options = serde_json::to_value(&challenge).unwrap()["publicKey"].clone();
    let reply = world
        .call(&mut owner, request("get", ORIGIN, options))
        .await;
    let HostReply::Credential { credential } = reply else {
        panic!("expected a credential, got {reply:?}");
    };
    let parsed: PublicKeyCredential = serde_json::from_value(credential).unwrap();
    let result = world
        .site
        .finish_passkey_authentication(&parsed, &state)
        .unwrap();
    assert!(result.user_verified());

    // What the owner was shown: the site, the page, and which machine asked,
    // under the name given at pairing.
    assert_eq!(owner.shown.len(), 2);
    let shown = &owner.shown[0];
    assert_eq!(shown.operation, OperationKind::CreatePasskey);
    assert_eq!(shown.rp_id, SITE);
    assert_eq!(shown.origin.as_deref(), Some(ORIGIN));
    assert_eq!(shown.requester_name, "Test computer");
    assert_eq!(
        shown.context.as_ref().and_then(|c| c.app.as_deref()),
        Some("Chrome")
    );
    assert_eq!(owner.shown[1].operation, OperationKind::SignIn);
    assert_eq!(world.phone.authenticator.credentials().len(), 1);

    // Sign-in through the browser's autofill list is the browser's to draw,
    // even for a site whose passkey is on the phone.
    let mut autofill = request(
        "get",
        ORIGIN,
        json!({ "challenge": "Y2hhbGxlbmdl", "rpId": SITE }),
    );
    autofill.mediation = Some("conditional".into());
    assert!(is_native(&world.call(&mut owner, autofill).await));
    assert_eq!(owner.shown.len(), 2, "the phone was not asked again");
}

#[tokio::test]
async fn declining_on_the_phone_fails_the_call_like_a_dismissed_prompt() {
    let mut world = paired().await;
    let mut owner = Scripted::always(false);
    let (options, _) = world.create_options();
    let reply = world
        .call(&mut owner, request("create", ORIGIN, options))
        .await;
    assert_eq!(error_of(&reply).0, "NotAllowedError");
    assert_eq!(owner.shown.len(), 1);
    assert!(world.phone.authenticator.credentials().is_empty());
    assert!(world.store.load().unwrap().sites.is_empty());
}

#[tokio::test]
async fn calls_that_are_not_for_the_phone_stay_with_the_browser() {
    let mut world = paired().await;
    let mut owner = Scripted::always(true);
    let (create, _) = world.create_options();
    let get = json!({ "challenge": "Y2hhbGxlbmdl", "rpId": SITE });

    // Sign-in for a site with no passkey recorded here.
    let reply = world
        .call(&mut owner, request("get", ORIGIN, get.clone()))
        .await;
    assert!(is_native(&reply), "{reply:?}");
    // The site asked for a security key.
    let mut roaming = create.clone();
    roaming["authenticatorSelection"]["authenticatorAttachment"] = json!("cross-platform");
    assert!(is_native(
        &world
            .call(&mut owner, request("create", ORIGIN, roaming))
            .await
    ));
    // The site does not accept ES256.
    let mut rsa_only = create.clone();
    rsa_only["pubKeyCredParams"] = json!([{ "type": "public-key", "alg": -257 }]);
    assert!(is_native(
        &world
            .call(&mut owner, request("create", ORIGIN, rsa_only))
            .await
    ));
    // A page asking for another site's identifier. The browser refuses this
    // itself; nothing is sent to the phone.
    let reply = world
        .call(
            &mut owner,
            request("create", "https://evil.example", create.clone()),
        )
        .await;
    assert!(is_native(&reply), "{reply:?}");
    // Options this code cannot read.
    assert!(is_native(
        &world
            .call(&mut owner, request("create", ORIGIN, json!({})))
            .await
    ));
    // A request with no origin from the browser.
    let mut no_origin = request("create", ORIGIN, create.clone());
    no_origin.origin = None;
    assert!(is_native(&world.call(&mut owner, no_origin).await));
    // New passkeys switched off.
    world
        .store
        .update(|state| state.new_passkeys = false)
        .unwrap();
    assert!(is_native(
        &world
            .call(&mut owner, request("create", ORIGIN, create))
            .await
    ));

    assert!(owner.shown.is_empty(), "the owner was never asked");
    assert_eq!(
        world.phone.requests_received(),
        0,
        "nothing was sent to the phone at all"
    );
}

#[tokio::test]
async fn an_unpaired_computer_leaves_everything_to_the_browser() {
    let relay = start_relay().await;
    let (_dir, store) = new_store(&relay);
    let mut nothing = |_: &HostReply| {};
    let (options, _) = {
        let site = site();
        let (challenge, state) = site
            .start_passkey_registration(Uuid::new_v4(), "ada", "Ada", None)
            .unwrap();
        (
            serde_json::to_value(&challenge).unwrap()["publicKey"].clone(),
            state,
        )
    };
    let reply = flow::handle(
        &store,
        request("create", ORIGIN, options),
        &system_now,
        &mut nothing,
    )
    .await;
    assert!(is_native(&reply), "{reply:?}");

    let status: HostRequest =
        serde_json::from_value(json!({ "v": 1, "id": "s", "type": "status" })).unwrap();
    let reply = flow::handle(&store, status, &system_now, &mut nothing).await;
    assert_eq!(
        reply,
        HostReply::Status {
            paired: false,
            device: "Test computer".into(),
            phones: vec![],
            new_passkeys: true,
        }
    );
}

#[tokio::test]
async fn a_sign_in_the_phone_has_no_passkey_for_falls_back_to_the_browser() {
    let mut world = paired().await;
    let mut owner = Scripted::always(true);
    // Listed by hand, as for a passkey made from another computer, but this
    // phone holds nothing for the site.
    world
        .store
        .update(|state| state.sites.insert(SITE.to_owned()))
        .unwrap();
    let get = json!({ "challenge": "Y2hhbGxlbmdl", "rpId": SITE });
    let reply = world.call(&mut owner, request("get", ORIGIN, get)).await;
    assert!(is_native(&reply), "{reply:?}");
    assert!(owner.shown.is_empty(), "nothing to ask the owner about");
}

#[tokio::test]
async fn no_answer_from_the_phone_fails_when_the_request_runs_out() {
    let world = paired().await;
    let (options, _) = world.create_options();
    // Nobody serves the phone. Once the request is on its way, time passes.
    let skip = AtomicI64::new(0);
    let clock = || system_now() + skip.load(Ordering::SeqCst);
    let mut sent = false;
    let mut progress = |reply: &HostReply| {
        sent = matches!(reply, HostReply::Pending { .. });
        skip.store(300, Ordering::SeqCst);
    };
    let reply = flow::handle(
        &world.store,
        request("create", ORIGIN, options),
        &clock,
        &mut progress,
    )
    .await;
    assert!(sent);
    let (name, message) = error_of(&reply);
    assert_eq!(name, "NotAllowedError");
    assert!(message.contains("in time"), "{message}");
}

#[tokio::test]
async fn a_phone_that_dropped_this_computer_is_reported_plainly() {
    let mut world = paired().await;
    let mut owner = Scripted::always(true);
    let id = world.phone.authenticator.pairings()[0].id.clone();
    assert!(world.phone.authenticator.revoke_pairing(&id));
    world
        .phone
        .serve_once(&mut owner, 0, &system_now)
        .await
        .unwrap();

    let (options, _) = world.create_options();
    let mut nothing = |_: &HostReply| {};
    let reply = flow::handle(
        &world.store,
        request("create", ORIGIN, options),
        &system_now,
        &mut nothing,
    )
    .await;
    let (name, message) = error_of(&reply);
    assert_eq!(name, "NotAllowedError");
    assert!(message.contains("not accepting requests"), "{message}");
}

#[tokio::test]
async fn an_unreachable_relay_is_an_error_not_a_hang() {
    // Paired in memory, with a relay address nothing listens on.
    let (_dir, store) = new_store("http://127.0.0.1:9");
    let phone = signet_passkey::SoftwareIdentity::generate();
    let offer = signet_passkey::issue_ticket(
        &store.identity().unwrap(),
        "Test computer",
        Role::Requester,
        system_now(),
    )
    .unwrap()
    .with_relay("http://127.0.0.1:9")
    .unwrap();
    let (_, reply) = signet_passkey::accept_ticket(
        &offer.ticket().encode(),
        &phone,
        "Test phone",
        Role::Authenticator,
        system_now(),
    )
    .unwrap();
    let pairing = offer.complete(&reply, system_now()).unwrap();
    store.update(|state| state.pairings.push(pairing)).unwrap();

    let (challenge, _) = site()
        .start_passkey_registration(Uuid::new_v4(), "ada", "Ada", None)
        .unwrap();
    let options = serde_json::to_value(&challenge).unwrap()["publicKey"].clone();
    let mut nothing = |_: &HostReply| {};
    let started = std::time::Instant::now();
    let reply = flow::handle(
        &store,
        request("create", ORIGIN, options),
        &system_now,
        &mut nothing,
    )
    .await;
    let (name, message) = error_of(&reply);
    assert_eq!(name, "NotAllowedError");
    assert!(message.contains("could not send"), "{message}");
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}

#[tokio::test]
async fn one_page_cannot_flood_the_phone() {
    let mut world = paired().await;
    let mut owner = Scripted::always(false);
    for _ in 0..6 {
        let (options, _) = world.create_options();
        let reply = world
            .call(&mut owner, request("create", ORIGIN, options))
            .await;
        assert!(error_of(&reply).1.contains("declined"));
    }
    let (options, _) = world.create_options();
    let reply = world
        .call(&mut owner, request("create", ORIGIN, options))
        .await;
    assert!(error_of(&reply).1.contains("too many"), "{reply:?}");
    assert_eq!(owner.shown.len(), 6, "the seventh never reached the phone");
}

#[tokio::test]
async fn a_wrong_code_saves_nothing() {
    let relay = start_relay().await;
    let (_dir, store) = new_store(&relay);
    let started = pair::start(&store, system_now()).unwrap();
    let mut phone = Phone::new("Test phone");
    let code = phone.pair(&started.ticket, system_now()).await.unwrap();
    let wrong = if code == "000000" { "000001" } else { "000000" };
    let answered = started.wait(&system_now).await.unwrap().unwrap();
    assert!(answered.confirm(&store, wrong).is_err());
    assert!(store.load().unwrap().pairings.is_empty());
}

#[tokio::test]
async fn a_ticket_pairs_one_device_and_a_stranger_who_answers_first_is_caught() {
    let relay = start_relay().await;
    let (_dir, store) = new_store(&relay);
    let started = pair::start(&store, system_now()).unwrap();
    let ticket = started.ticket.clone();

    // Someone else saw the ticket and answered before the owner's phone.
    let mut stranger = Phone::new("Test phone");
    let strangers_code = stranger.pair(&ticket, system_now()).await.unwrap();
    // The owner's phone is told the ticket is used, and records nothing.
    let mut owners = Phone::new("Test phone");
    let refused = owners.pair(&ticket, system_now()).await.unwrap_err();
    assert!(refused.contains("exists"), "{refused}");
    assert!(owners.authenticator.pairings().is_empty());

    // The computer has the stranger's reply. The owner has no code to type
    // except one the stranger's device shows, which the owner cannot see.
    let answered = started.wait(&system_now).await.unwrap().unwrap();
    assert_eq!(answered.phone_fingerprint(), stranger.fingerprint());
    let guess = if strangers_code == "123456" {
        "654321"
    } else {
        "123456"
    };
    assert!(answered.confirm(&store, guess).is_err());
    assert!(store.load().unwrap().pairings.is_empty());
}

#[tokio::test]
async fn an_unanswered_ticket_expires() {
    let relay = start_relay().await;
    let (_dir, store) = new_store(&relay);
    let started = pair::start(&store, system_now()).unwrap();
    let later = || system_now() + signet_passkey::PAIRING_TTL_SECS + 1;
    assert!(started.wait(&later).await.unwrap().is_none());
}

#[tokio::test]
async fn pairing_the_same_phone_again_replaces_its_record_and_unpairing_removes_it() {
    let world = paired().await;
    let before = world.store.load().unwrap().pairings;
    assert_eq!(before.len(), 1);
    assert_eq!(
        before[0].relay.as_deref(),
        Some(world.store.load().unwrap().relay.as_str())
    );
    let removed = pair::unpair(&world.store, "Test phone").unwrap();
    assert_eq!(removed, vec!["Test phone".to_owned()]);
    assert!(world.store.load().unwrap().active_pairing().is_none());
    assert!(pair::unpair(&world.store, "Test phone").unwrap().is_empty());
}
