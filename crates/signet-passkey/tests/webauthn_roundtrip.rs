//! End-to-end acceptance against an independent WebAuthn relying party.
//!
//! `webauthn-rs` plays the site. It generates the challenges and verifies the
//! results with its own implementation of the standard. Nothing in this crate
//! is used to check the answers, so a shared misunderstanding between the phone
//! and computer sides cannot make these tests pass.
mod common;
use common::{paired, Tap, NOW};
use signet_passkey::webauthn::{sha256, Ceremony, FLAG_BE, FLAG_BS};
use signet_passkey::{
    Approval, Completed, CreateOptions, GetOptions, Initiator, KeyClass, OperationKind,
    RequestContext, UserVerification,
};
use webauthn_rs::prelude::*;

const SITE: &str = "https://login.example.com";

fn site() -> Webauthn {
    WebauthnBuilder::new("example.com", &Url::parse(SITE).unwrap())
        .unwrap()
        .rp_name("Example")
        .build()
        .unwrap()
}

fn user_verification(value: &serde_json::Value) -> UserVerification {
    match value.as_str() {
        Some("required") => UserVerification::Required,
        Some("discouraged") => UserVerification::Discouraged,
        _ => UserVerification::Preferred,
    }
}

fn ids(list: &serde_json::Value) -> Vec<String> {
    list.as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| item["id"].as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// What a page would pass to `navigator.credentials.create`, read from the
/// site's own JSON.
fn create_options(challenge: &CreationChallengeResponse) -> CreateOptions {
    let json = serde_json::to_value(challenge).unwrap();
    let options = &json["publicKey"];
    CreateOptions {
        challenge: options["challenge"].as_str().unwrap().into(),
        rp_id: options["rp"]["id"].as_str().map(Into::into),
        rp_name: options["rp"]["name"].as_str().unwrap().into(),
        user_id: options["user"]["id"].as_str().unwrap().into(),
        user_name: options["user"]["name"].as_str().unwrap().into(),
        user_display_name: options["user"]["displayName"].as_str().unwrap().into(),
        algorithms: options["pubKeyCredParams"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["alg"].as_i64().unwrap())
            .collect(),
        exclude_credentials: ids(&options["excludeCredentials"]),
        user_verification: user_verification(
            &options["authenticatorSelection"]["userVerification"],
        ),
        key_class: None,
    }
}

/// What a page would pass to `navigator.credentials.get`.
fn get_options(challenge: &RequestChallengeResponse) -> GetOptions {
    let json = serde_json::to_value(challenge).unwrap();
    let options = &json["publicKey"];
    GetOptions {
        challenge: options["challenge"].as_str().unwrap().into(),
        rp_id: options["rpId"].as_str().map(Into::into),
        allow_credentials: ids(&options["allowCredentials"]),
        user_verification: user_verification(&options["userVerification"]),
    }
}

fn flags(authenticator_data: &str) -> u8 {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(authenticator_data)
        .unwrap()[32]
}

#[test]
fn a_site_accepts_a_passkey_created_and_used_through_the_phone() {
    let site = site();
    let mut world = paired();
    let mut tap = Tap::approve();

    // The site asks the page to create a passkey.
    let (challenge, registration) = site
        .start_passkey_registration(Uuid::new_v4(), "jeremy", "Jeremy", None)
        .unwrap();
    let context = RequestContext {
        app: Some("Chrome".into()),
        initiated_by: Initiator::Agent,
        note: Some("Switching the model".into()),
    };
    let begun = world
        .computer
        .begin_create(
            &world.pairing_id,
            SITE,
            &create_options(&challenge),
            Some(context.clone()),
            NOW,
        )
        .unwrap();
    let response = world.phone.handle(&begun.envelope, NOW, &mut tap).unwrap();
    let completed = world.computer.finish(&response, NOW + 5).unwrap();

    // The owner was shown the site, the machine and who started it.
    let view = &tap.seen[0];
    assert_eq!(view.operation, OperationKind::CreatePasskey);
    assert_eq!(view.rp_id, "example.com");
    assert_eq!(view.origin.as_deref(), Some(SITE));
    assert_eq!(view.requester_name, "Mac Studio");
    assert_eq!(
        view.requester_fingerprint,
        world.computer.identity().public().fingerprint()
    );
    assert_eq!(view.context.as_ref(), Some(&context));
    assert_eq!(view.accounts[0].user_name, "jeremy");
    assert!(view.user_verification_required);

    // The site verifies the new passkey with its own code.
    let credential: RegisterPublicKeyCredential =
        serde_json::from_value(completed.to_json().unwrap()).unwrap();
    let passkey = site
        .finish_passkey_registration(&credential, &registration)
        .unwrap();

    // Later, the site asks the page to sign in with it.
    let (challenge, authentication) = site.start_passkey_authentication(&[passkey]).unwrap();
    let begun = world
        .computer
        .begin_get(
            &world.pairing_id,
            SITE,
            &get_options(&challenge),
            None,
            NOW + 60,
        )
        .unwrap();
    let response = world
        .phone
        .handle(&begun.envelope, NOW + 61, &mut tap)
        .unwrap();
    let completed = world.computer.finish(&response, NOW + 62).unwrap();
    assert_eq!(tap.seen[1].operation, OperationKind::SignIn);
    assert_eq!(tap.seen[1].accounts[0].user_name, "jeremy");

    let assertion: PublicKeyCredential =
        serde_json::from_value(completed.to_json().unwrap()).unwrap();
    let result = site
        .finish_passkey_authentication(&assertion, &authentication)
        .unwrap();
    assert!(result.user_verified());
    assert_eq!(world.computer.pending_count(), 0);
}

#[test]
fn the_operating_system_path_carries_only_a_hash() {
    // Here the test plays the operating system: it builds the client data, as a
    // browser would, and gives the computer side only the site identifier and
    // the hash. The computer never learns the origin.
    let site = site();
    let mut world = paired();
    let mut tap = Tap::approve();
    let client_data = |ceremony, challenge: &str| {
        signet_passkey::webauthn::client_data_json(ceremony, challenge, SITE)
    };

    let (challenge, registration) = site
        .start_passkey_registration(Uuid::new_v4(), "jeremy", "Jeremy", None)
        .unwrap();
    let options = create_options(&challenge);
    let create_data = client_data(Ceremony::Create, &options.challenge);
    let begun = world
        .computer
        .begin_create_with_hash(
            &world.pairing_id,
            "example.com",
            sha256(&create_data),
            &options,
            None,
            NOW,
        )
        .unwrap();
    let response = world.phone.handle(&begun.envelope, NOW, &mut tap).unwrap();
    assert_eq!(tap.seen[0].origin, None);
    let Completed::Attestation {
        credential_id,
        attestation_object,
        client_data_json: None,
        ..
    } = world.computer.finish(&response, NOW).unwrap()
    else {
        panic!("expected a new passkey without client data");
    };
    let encode = |bytes: &[u8]| {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    };
    let credential: RegisterPublicKeyCredential = serde_json::from_value(serde_json::json!({
        "id": credential_id, "rawId": credential_id, "type": "public-key",
        "response": {
            "clientDataJSON": encode(&create_data),
            "attestationObject": attestation_object,
        },
        "clientExtensionResults": {},
    }))
    .unwrap();
    let passkey = site
        .finish_passkey_registration(&credential, &registration)
        .unwrap();

    let (challenge, authentication) = site.start_passkey_authentication(&[passkey]).unwrap();
    let options = get_options(&challenge);
    let get_data = client_data(Ceremony::Get, &options.challenge);
    let begun = world
        .computer
        .begin_get_with_hash(
            &world.pairing_id,
            "example.com",
            sha256(&get_data),
            &options,
            None,
            NOW,
        )
        .unwrap();
    let response = world.phone.handle(&begun.envelope, NOW, &mut tap).unwrap();
    let Completed::Assertion {
        credential_id,
        authenticator_data,
        signature,
        user_handle,
        client_data_json: None,
    } = world.computer.finish(&response, NOW).unwrap()
    else {
        panic!("expected an assertion without client data");
    };
    let assertion: PublicKeyCredential = serde_json::from_value(serde_json::json!({
        "id": credential_id, "rawId": credential_id, "type": "public-key",
        "response": {
            "clientDataJSON": encode(&get_data),
            "authenticatorData": authenticator_data,
            "signature": signature,
            "userHandle": user_handle,
        },
        "clientExtensionResults": {},
    }))
    .unwrap();
    site.finish_passkey_authentication(&assertion, &authentication)
        .unwrap();
}

#[test]
fn the_site_is_told_the_truth_about_how_the_key_is_held() {
    let site = site();
    for (class, backed_up_flags) in [(KeyClass::HardwareBound, 0), (KeyClass::Portable, FLAG_BE)] {
        let mut world = paired();
        let (challenge, registration) = site
            .start_passkey_registration(Uuid::new_v4(), "jeremy", "Jeremy", None)
            .unwrap();
        let mut options = create_options(&challenge);
        options.key_class = Some(class);
        let begun = world
            .computer
            .begin_create(&world.pairing_id, SITE, &options, None, NOW)
            .unwrap();
        let response = world
            .phone
            .handle(&begun.envelope, NOW, &mut Tap::approve())
            .unwrap();
        let completed = world.computer.finish(&response, NOW).unwrap();
        let Completed::Attestation {
            authenticator_data, ..
        } = &completed
        else {
            panic!("expected a new passkey");
        };
        assert_eq!(
            flags(authenticator_data) & (FLAG_BE | FLAG_BS),
            backed_up_flags,
            "{class:?}"
        );
        assert_eq!(world.phone.credentials()[0].class, class);
        let credential: RegisterPublicKeyCredential =
            serde_json::from_value(completed.to_json().unwrap()).unwrap();
        site.finish_passkey_registration(&credential, &registration)
            .unwrap();
    }
}

#[test]
fn the_site_rejects_a_signature_the_owner_did_not_verify() {
    // The phone reports an approval without biometric verification. The phone
    // refuses when the site requires verification; this checks the site would
    // also have refused, by asking the phone under a weaker requirement and
    // presenting the result to a site that requires it.
    let site = site();
    let mut world = paired();
    let (challenge, registration) = site
        .start_passkey_registration(Uuid::new_v4(), "jeremy", "Jeremy", None)
        .unwrap();
    let mut options = create_options(&challenge);
    options.user_verification = UserVerification::Preferred;
    let begun = world
        .computer
        .begin_create(&world.pairing_id, SITE, &options, None, NOW)
        .unwrap();
    let mut unverified = Tap::answering(Approval::Approve {
        account: 0,
        user_verified: false,
    });
    let response = world
        .phone
        .handle(&begun.envelope, NOW, &mut unverified)
        .unwrap();
    let completed = world.computer.finish(&response, NOW).unwrap();
    let credential: RegisterPublicKeyCredential =
        serde_json::from_value(completed.to_json().unwrap()).unwrap();
    assert!(site
        .finish_passkey_registration(&credential, &registration)
        .is_err());
}

#[test]
fn the_site_rejects_an_assertion_changed_after_signing() {
    // Shows the site is really checking: the same flow as the first test, with
    // one byte of the signature, or the origin, changed on the way.
    let site = site();
    let mut world = paired();
    let mut tap = Tap::approve();
    let (challenge, registration) = site
        .start_passkey_registration(Uuid::new_v4(), "jeremy", "Jeremy", None)
        .unwrap();
    let begun = world
        .computer
        .begin_create(
            &world.pairing_id,
            SITE,
            &create_options(&challenge),
            None,
            NOW,
        )
        .unwrap();
    let response = world.phone.handle(&begun.envelope, NOW, &mut tap).unwrap();
    let completed = world.computer.finish(&response, NOW).unwrap();
    let credential: RegisterPublicKeyCredential =
        serde_json::from_value(completed.to_json().unwrap()).unwrap();
    let passkey = site
        .finish_passkey_registration(&credential, &registration)
        .unwrap();

    let sign_in = |world: &mut common::World, tap: &mut Tap, origin: &str| {
        let (challenge, authentication) = site
            .start_passkey_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let begun = world
            .computer
            .begin_get(
                &world.pairing_id,
                origin,
                &get_options(&challenge),
                None,
                NOW,
            )
            .unwrap();
        let response = world.phone.handle(&begun.envelope, NOW, tap).unwrap();
        let json = world
            .computer
            .finish(&response, NOW)
            .unwrap()
            .to_json()
            .unwrap();
        (json, authentication)
    };

    // Unchanged: accepted.
    let (json, authentication) = sign_in(&mut world, &mut tap, SITE);
    let assertion: PublicKeyCredential = serde_json::from_value(json).unwrap();
    site.finish_passkey_authentication(&assertion, &authentication)
        .unwrap();

    // One character of the signature changed: rejected.
    let (mut json, authentication) = sign_in(&mut world, &mut tap, SITE);
    let signature = json["response"]["signature"].as_str().unwrap().to_owned();
    let middle = signature.len() / 2;
    let swapped = if &signature[middle..=middle] == "A" {
        "B"
    } else {
        "A"
    };
    json["response"]["signature"] = format!(
        "{}{swapped}{}",
        &signature[..middle],
        &signature[middle + 1..]
    )
    .into();
    let assertion: PublicKeyCredential = serde_json::from_value(json).unwrap();
    assert!(site
        .finish_passkey_authentication(&assertion, &authentication)
        .is_err());

    // Signed for a sibling origin the site does not accept: rejected.
    let (json, authentication) = sign_in(&mut world, &mut tap, "https://other.example.com");
    let assertion: PublicKeyCredential = serde_json::from_value(json).unwrap();
    assert!(site
        .finish_passkey_authentication(&assertion, &authentication)
        .is_err());
}
