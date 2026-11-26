//! What each party must refuse. Each test names the attack it stands for.
mod common;
use common::{create_options, get_options, paired, Tap, NOW, ORIGIN};
use signet_passkey::message::Operation;
use signet_passkey::seal::{seal_signed, MessageKind};
use signet_passkey::{
    accept_ticket, issue_ticket, Approval, Completed, Decision, IdentityKeys, PasskeyError,
    PublicIdentity, Refusal, Role, SignRequest, SignResponse, SoftwareIdentity, UserVerification,
    MAX_REQUEST_TTL_SECS, PAIRING_TTL_SECS, PROTOCOL_VERSION, REQUEST_TTL_SECS,
};

fn request(pairing_id: &str, id: &str, rp_id: &str, origin: Option<&str>) -> SignRequest {
    SignRequest {
        v: PROTOCOL_VERSION,
        request_id: id.into(),
        pairing_id: pairing_id.into(),
        operation: Operation::Get {
            allow_credentials: Vec::new(),
        },
        rp_id: rp_id.into(),
        client_data_hash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        origin: origin.map(Into::into),
        user_verification: UserVerification::Required,
        context: None,
        created_at: NOW,
        expires_at: NOW + REQUEST_TTL_SECS,
    }
}

/// A request sealed by `sender` to `phone`, bypassing the honest computer's
/// own checks. Models a machine that holds a key and misbehaves.
fn sealed(sender: &dyn IdentityKeys, phone: &PublicIdentity, request: &SignRequest) -> Vec<u8> {
    seal_signed(
        sender,
        phone,
        &request.pairing_id,
        MessageKind::Request,
        &serde_json::to_vec(request).unwrap(),
    )
    .unwrap()
}

#[test]
fn a_stranger_s_computer_gets_no_answer() {
    let mut world = paired();
    world.create_passkey("dXNlci0x", "jeremy");
    let stranger = SoftwareIdentity::generate();
    let phone = world.phone.identity().public();
    let envelope = sealed(
        &stranger,
        &phone,
        &request(&world.pairing_id, "c3RyYW5nZXI", "example.com", None),
    );
    let mut tap = Tap::approve();
    // The envelope names a real pairing, but the stranger's key is not the
    // paired machine's key.
    let error = world.phone.handle(&envelope, NOW, &mut tap).unwrap_err();
    assert!(matches!(
        error,
        PasskeyError::SealFailure | PasskeyError::BadSignature
    ));
    assert!(tap.seen.is_empty(), "the owner must not even be asked");
}

#[test]
fn an_unknown_pairing_gets_no_answer() {
    let mut world = paired();
    let other = paired();
    let phone = world.phone.identity().public();
    let envelope = sealed(
        other.computer.identity(),
        &phone,
        &request(&other.pairing_id, "b3RoZXI", "example.com", None),
    );
    let mut tap = Tap::approve();
    assert_eq!(
        world.phone.handle(&envelope, NOW, &mut tap),
        Err(PasskeyError::UnknownPairing)
    );
    assert!(tap.seen.is_empty());
}

#[test]
fn the_relay_cannot_alter_a_request() {
    let mut world = paired();
    world.create_passkey("dXNlci0x", "jeremy");
    let begun = world
        .computer
        .begin_get(&world.pairing_id, ORIGIN, &get_options(), None, NOW)
        .unwrap();
    let mut envelope: serde_json::Value = serde_json::from_slice(&begun.envelope).unwrap();
    let ciphertext = envelope["ct"].as_str().unwrap().to_owned();
    // Change one character in the middle of the ciphertext.
    let middle = ciphertext.len() / 2;
    let swapped = if &ciphertext[middle..=middle] == "A" {
        "B"
    } else {
        "A"
    };
    envelope["ct"] = format!(
        "{}{swapped}{}",
        &ciphertext[..middle],
        &ciphertext[middle + 1..]
    )
    .into();
    let mut tap = Tap::approve();
    assert_eq!(
        world
            .phone
            .handle(&serde_json::to_vec(&envelope).unwrap(), NOW, &mut tap),
        Err(PasskeyError::SealFailure)
    );
    assert!(tap.seen.is_empty());
}

#[test]
fn the_relay_cannot_replay_a_request() {
    let mut world = paired();
    world.create_passkey("dXNlci0x", "jeremy");
    let begun = world
        .computer
        .begin_get(&world.pairing_id, ORIGIN, &get_options(), None, NOW)
        .unwrap();
    let mut tap = Tap::approve();
    world.phone.handle(&begun.envelope, NOW, &mut tap).unwrap();
    assert_eq!(
        world.phone.handle(&begun.envelope, NOW + 1, &mut tap),
        Err(PasskeyError::Replay)
    );
    assert_eq!(tap.seen.len(), 1, "the owner is asked once");
}

#[test]
fn a_late_or_long_lived_request_is_dropped() {
    let mut world = paired();
    world.create_passkey("dXNlci0x", "jeremy");
    let phone = world.phone.identity().public();
    let mut tap = Tap::approve();

    // Delivered after it expired.
    let begun = world
        .computer
        .begin_get(&world.pairing_id, ORIGIN, &get_options(), None, NOW)
        .unwrap();
    assert_eq!(
        world
            .phone
            .handle(&begun.envelope, NOW + REQUEST_TTL_SECS, &mut tap),
        Err(PasskeyError::Expired)
    );

    // A paired machine asks for a lifetime longer than the phone allows.
    let mut long = request(&world.pairing_id, "bG9uZw", "example.com", None);
    long.expires_at = NOW + MAX_REQUEST_TTL_SECS + 1;
    assert_eq!(
        world.phone.handle(
            &sealed(world.computer.identity(), &phone, &long),
            NOW,
            &mut tap
        ),
        Err(PasskeyError::Expired)
    );

    // A request dated well into the future.
    let mut future = request(&world.pairing_id, "ZnV0dXJl", "example.com", None);
    future.created_at = NOW + 3600;
    future.expires_at = NOW + 3600 + REQUEST_TTL_SECS;
    assert_eq!(
        world.phone.handle(
            &sealed(world.computer.identity(), &phone, &future),
            NOW,
            &mut tap
        ),
        Err(PasskeyError::Expired)
    );
    assert!(tap.seen.is_empty());
}

#[test]
fn a_phishing_page_cannot_ask_for_another_site_s_passkey() {
    let mut world = paired();
    world.create_passkey("dXNlci0x", "jeremy");
    let mut options = get_options();
    options.rp_id = Some("example.com".into());

    // The honest computer refuses before anything is sent.
    for origin in ["https://evil.com", "https://example.com.evil.com"] {
        assert!(matches!(
            world
                .computer
                .begin_get(&world.pairing_id, origin, &options, None, NOW),
            Err(PasskeyError::SiteBinding(_))
        ));
    }
    assert_eq!(world.computer.pending_count(), 0);

    // A computer that skips the check and reports the page honestly is refused
    // by the phone, without asking the owner.
    let phone = world.phone.identity().public();
    let envelope = sealed(
        world.computer.identity(),
        &phone,
        &request(
            &world.pairing_id,
            "cGhpc2g",
            "example.com",
            Some("https://evil.com"),
        ),
    );
    let mut tap = Tap::approve();
    let response = world.phone.handle(&envelope, NOW, &mut tap).unwrap();
    assert!(tap.seen.is_empty());
    assert_eq!(
        open_response(&world, &response).decision,
        Decision::Refused {
            reason: Refusal::SiteBinding
        }
    );
}

#[test]
fn a_passkey_never_signs_for_a_site_it_was_not_created_for() {
    let mut world = paired();
    let credential_id = world.create_passkey("dXNlci0x", "jeremy");
    let phone = world.phone.identity().public();
    // A paired machine names the example.com passkey but asks for another site.
    let mut other_site = request(&world.pairing_id, "b3RoZXItc2l0ZQ", "example.org", None);
    other_site.operation = Operation::Get {
        allow_credentials: vec![credential_id],
    };
    let mut tap = Tap::approve();
    let response = world
        .phone
        .handle(
            &sealed(world.computer.identity(), &phone, &other_site),
            NOW,
            &mut tap,
        )
        .unwrap();
    assert!(
        tap.seen.is_empty(),
        "no passkey matches, so nothing to approve"
    );
    // The honest computer was not waiting on this request, so read the phone's
    // answer directly: it must be a refusal, and carry no signature.
    let decision = open_response(&world, &response).decision;
    assert_eq!(
        decision,
        Decision::Refused {
            reason: Refusal::NoCredential
        }
    );
}

/// Open a phone response as the paired computer would, without consuming a
/// pending request.
fn open_response(world: &common::World, envelope: &[u8]) -> SignResponse {
    let envelope = signet_passkey::seal::Envelope::from_bytes(envelope).unwrap();
    let payload = signet_passkey::seal::open_signed(
        world.computer.identity(),
        &world.phone.identity().public(),
        &envelope,
        MessageKind::Response,
    )
    .unwrap();
    serde_json::from_slice(&payload).unwrap()
}

/// A device that presents someone else's public identity while holding only
/// its own keys. Sealing succeeds, because public keys are public; what must
/// stop it is the signature.
struct Impostor {
    claims: PublicIdentity,
    own: SoftwareIdentity,
}

impl IdentityKeys for Impostor {
    fn public(&self) -> PublicIdentity {
        self.claims.clone()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PasskeyError> {
        self.own.sign(message)
    }
    fn open(
        &self,
        encapped_key: &[u8],
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, PasskeyError> {
        self.own.open(encapped_key, info, aad, ciphertext)
    }
}

#[test]
fn claiming_the_paired_machine_s_identity_is_not_enough() {
    let mut world = paired();
    world.create_passkey("dXNlci0x", "jeremy");
    let impostor = Impostor {
        claims: world.computer.identity().public(),
        own: SoftwareIdentity::generate(),
    };
    let phone = world.phone.identity().public();
    let envelope = sealed(
        &impostor,
        &phone,
        &request(&world.pairing_id, "aW1wb3N0b3I", "example.com", None),
    );
    let mut tap = Tap::approve();
    assert_eq!(
        world.phone.handle(&envelope, NOW, &mut tap),
        Err(PasskeyError::BadSignature)
    );
    assert!(tap.seen.is_empty());
}

#[test]
fn claiming_the_phone_s_identity_is_not_enough() {
    let mut world = paired();
    let begun = world
        .computer
        .begin_create(
            &world.pairing_id,
            ORIGIN,
            &create_options("dXNlci0x", "jeremy"),
            None,
            NOW,
        )
        .unwrap();
    // Take the genuine request's digest from a genuine phone answer, so the
    // forgery is wrong in exactly one respect: who signed it.
    let genuine = world
        .phone
        .handle(&begun.envelope, NOW, &mut Tap::deny())
        .unwrap();
    let mut forged = open_response(&world, &genuine);
    forged.decision = Decision::Approved {
        outcome: signet_passkey::Outcome::Attestation {
            credential_id: "YXR0YWNrZXI".into(),
            attestation_object: "AA".into(),
            authenticator_data: "AA".into(),
            public_key: "AA".into(),
        },
    };
    let impostor = Impostor {
        claims: world.phone.identity().public(),
        own: SoftwareIdentity::generate(),
    };
    let forged = seal_signed(
        &impostor,
        &world.computer.identity().public(),
        &world.pairing_id,
        MessageKind::Response,
        &serde_json::to_vec(&forged).unwrap(),
    )
    .unwrap();
    assert_eq!(
        world.computer.finish(&forged, NOW),
        Err(PasskeyError::BadSignature)
    );
    assert_eq!(world.computer.pending_count(), 1);
}

#[test]
fn an_answer_to_a_different_question_is_rejected() {
    let mut world = paired();
    world.create_passkey("dXNlci0x", "jeremy");
    let begun = world
        .computer
        .begin_get(&world.pairing_id, ORIGIN, &get_options(), None, NOW)
        .unwrap();
    // Something holding the computer's key races the honest request with a
    // different one under the same id. The phone answers the impostor's.
    let phone = world.phone.identity().public();
    let mut other = request(&world.pairing_id, &begun.request_id, "example.com", None);
    other.client_data_hash = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".into();
    let response = world
        .phone
        .handle(
            &sealed(world.computer.identity(), &phone, &other),
            NOW,
            &mut Tap::approve(),
        )
        .unwrap();
    assert!(matches!(
        open_response(&world, &response).decision,
        Decision::Approved { .. }
    ));
    // The phone signed it and the id matches, but it answers other bytes than
    // the computer sent.
    assert_eq!(
        world.computer.finish(&response, NOW),
        Err(PasskeyError::NoPendingRequest)
    );
}

#[test]
fn a_denial_carries_no_signature() {
    let mut world = paired();
    world.create_passkey("dXNlci0x", "jeremy");
    let begun = world
        .computer
        .begin_get(&world.pairing_id, ORIGIN, &get_options(), None, NOW)
        .unwrap();
    let response = world
        .phone
        .handle(&begun.envelope, NOW, &mut Tap::deny())
        .unwrap();
    assert_eq!(open_response(&world, &response).decision, Decision::Denied);
    assert_eq!(
        world.computer.finish(&response, NOW).unwrap(),
        Completed::Denied
    );
}

#[test]
fn approval_without_verification_does_not_satisfy_a_site_that_requires_it() {
    let mut world = paired();
    world.create_passkey("dXNlci0x", "jeremy");
    let begun = world
        .computer
        .begin_get(&world.pairing_id, ORIGIN, &get_options(), None, NOW)
        .unwrap();
    let mut unverified = Tap::answering(Approval::Approve {
        account: 0,
        user_verified: false,
    });
    let response = world
        .phone
        .handle(&begun.envelope, NOW, &mut unverified)
        .unwrap();
    assert_eq!(
        world.computer.finish(&response, NOW).unwrap(),
        Completed::Refused(Refusal::UserVerificationRequired)
    );
}

#[test]
fn approval_without_verification_does_not_create_a_passkey_for_a_site_that_requires_it() {
    let mut world = paired();
    let begun = world
        .computer
        .begin_create(
            &world.pairing_id,
            ORIGIN,
            &create_options("dXNlci0x", "jeremy"),
            None,
            NOW,
        )
        .unwrap();
    let mut unverified = Tap::answering(Approval::Approve {
        account: 0,
        user_verified: false,
    });
    let response = world
        .phone
        .handle(&begun.envelope, NOW, &mut unverified)
        .unwrap();
    assert_eq!(
        world.computer.finish(&response, NOW).unwrap(),
        Completed::Refused(Refusal::UserVerificationRequired)
    );
    assert!(world.phone.credentials().is_empty(), "no key was created");
}

#[test]
fn the_relay_cannot_substitute_its_own_passkey() {
    let mut world = paired();
    let begun = world
        .computer
        .begin_create(
            &world.pairing_id,
            ORIGIN,
            &create_options("dXNlci0x", "jeremy"),
            None,
            NOW,
        )
        .unwrap();
    // The relay invents a response claiming a passkey it controls, signs it
    // with its own key and seals it to the computer.
    let relay = SoftwareIdentity::generate();
    let forged = SignResponse {
        v: PROTOCOL_VERSION,
        request_id: begun.request_id.clone(),
        request_digest: "0".repeat(64),
        decision: Decision::Denied,
        decided_at: NOW,
    };
    let forged = seal_signed(
        &relay,
        &world.computer.identity().public(),
        &world.pairing_id,
        MessageKind::Response,
        &serde_json::to_vec(&forged).unwrap(),
    )
    .unwrap();
    let error = world.computer.finish(&forged, NOW).unwrap_err();
    assert!(matches!(
        error,
        PasskeyError::SealFailure | PasskeyError::BadSignature
    ));
    // The real request is still waiting for the real phone.
    assert_eq!(world.computer.pending_count(), 1);
    let response = world
        .phone
        .handle(&begun.envelope, NOW, &mut Tap::approve())
        .unwrap();
    assert!(matches!(
        world.computer.finish(&response, NOW).unwrap(),
        Completed::Attestation { .. }
    ));
}

#[test]
fn a_response_is_accepted_once_and_only_for_its_own_request() {
    let mut world = paired();
    world.create_passkey("dXNlci0x", "jeremy");
    let first = world
        .computer
        .begin_get(&world.pairing_id, ORIGIN, &get_options(), None, NOW)
        .unwrap();
    let second = world
        .computer
        .begin_get(&world.pairing_id, ORIGIN, &get_options(), None, NOW)
        .unwrap();
    let mut tap = Tap::approve();
    let answer = world.phone.handle(&first.envelope, NOW, &mut tap).unwrap();
    assert!(matches!(
        world.computer.finish(&answer, NOW).unwrap(),
        Completed::Assertion { .. }
    ));
    // The same answer again: the first request is spent, and it does not
    // answer the second.
    assert_eq!(
        world.computer.finish(&answer, NOW),
        Err(PasskeyError::NoPendingRequest)
    );
    assert_eq!(world.computer.pending_count(), 1);
    let answer = world.phone.handle(&second.envelope, NOW, &mut tap).unwrap();
    assert!(world.computer.finish(&answer, NOW).is_ok());
}

#[test]
fn an_answer_that_arrives_too_late_is_discarded() {
    let mut world = paired();
    world.create_passkey("dXNlci0x", "jeremy");
    let begun = world
        .computer
        .begin_get(&world.pairing_id, ORIGIN, &get_options(), None, NOW)
        .unwrap();
    let response = world
        .phone
        .handle(&begun.envelope, NOW, &mut Tap::approve())
        .unwrap();
    assert_eq!(
        world
            .computer
            .finish(&response, NOW + REQUEST_TTL_SECS + 600),
        Err(PasskeyError::Expired)
    );
    assert_eq!(world.computer.pending_count(), 0);
}

#[test]
fn a_revoked_machine_gets_no_answer() {
    let mut world = paired();
    world.create_passkey("dXNlci0x", "jeremy");
    let begun = world
        .computer
        .begin_get(&world.pairing_id, ORIGIN, &get_options(), None, NOW)
        .unwrap();
    assert!(world.phone.revoke_pairing(&world.pairing_id));
    let mut tap = Tap::approve();
    assert_eq!(
        world.phone.handle(&begun.envelope, NOW, &mut tap),
        Err(PasskeyError::UnknownPairing)
    );
    assert!(tap.seen.is_empty());

    // Revoking on the computer drops what it was waiting for.
    assert!(world.computer.revoke_pairing(&world.pairing_id));
    assert_eq!(world.computer.pending_count(), 0);
    assert_eq!(
        world
            .computer
            .begin_get(&world.pairing_id, ORIGIN, &get_options(), None, NOW)
            .unwrap_err(),
        PasskeyError::UnknownPairing
    );
}

#[test]
fn a_message_of_the_wrong_kind_is_rejected() {
    let mut world = paired();
    world.create_passkey("dXNlci0x", "jeremy");
    let begun = world
        .computer
        .begin_get(&world.pairing_id, ORIGIN, &get_options(), None, NOW)
        .unwrap();
    let mut tap = Tap::approve();
    let response = world.phone.handle(&begun.envelope, NOW, &mut tap).unwrap();
    // A response fed to the phone, and a request fed to the computer.
    assert!(world.phone.handle(&response, NOW, &mut tap).is_err());
    assert!(world.computer.finish(&begun.envelope, NOW).is_err());
    assert_eq!(tap.seen.len(), 1);
}

#[test]
fn the_owner_chooses_between_accounts_and_sees_the_newest_passkey_for_each() {
    let mut world = paired();
    world.create_passkey("dXNlci0x", "work");
    let replaced = world.create_passkey("dXNlci0y", "personal");
    let current = world.create_passkey("dXNlci0y", "personal");
    let begun = world
        .computer
        .begin_get(&world.pairing_id, ORIGIN, &get_options(), None, NOW)
        .unwrap();
    let mut tap = Tap::answering(Approval::Approve {
        account: 1,
        user_verified: true,
    });
    let response = world.phone.handle(&begun.envelope, NOW, &mut tap).unwrap();
    let names: Vec<_> = tap.seen[0]
        .accounts
        .iter()
        .map(|a| a.user_name.as_str())
        .collect();
    assert_eq!(names, ["work", "personal"]);
    let Completed::Assertion { credential_id, .. } = world.computer.finish(&response, NOW).unwrap()
    else {
        panic!("expected an assertion");
    };
    assert_eq!(credential_id, current);

    // The earlier passkey still answers a site that asks for it by id.
    let mut options = get_options();
    options.allow_credentials = vec![replaced.clone()];
    let begun = world
        .computer
        .begin_get(&world.pairing_id, ORIGIN, &options, None, NOW)
        .unwrap();
    let response = world
        .phone
        .handle(&begun.envelope, NOW, &mut Tap::approve())
        .unwrap();
    let Completed::Assertion { credential_id, .. } = world.computer.finish(&response, NOW).unwrap()
    else {
        panic!("expected an assertion");
    };
    assert_eq!(credential_id, replaced);
}

#[test]
fn a_site_s_exclusion_list_and_algorithms_are_honored() {
    let mut world = paired();
    let existing = world.create_passkey("dXNlci0x", "jeremy");
    let mut tap = Tap::approve();

    let mut options = create_options("dXNlci0x", "jeremy");
    options.exclude_credentials = vec![existing];
    let begun = world
        .computer
        .begin_create(&world.pairing_id, ORIGIN, &options, None, NOW)
        .unwrap();
    let response = world.phone.handle(&begun.envelope, NOW, &mut tap).unwrap();
    assert_eq!(
        world.computer.finish(&response, NOW).unwrap(),
        Completed::Refused(Refusal::CredentialExcluded)
    );

    let mut options = create_options("dXNlci0z", "other");
    options.algorithms = vec![-257];
    let begun = world
        .computer
        .begin_create(&world.pairing_id, ORIGIN, &options, None, NOW)
        .unwrap();
    let response = world.phone.handle(&begun.envelope, NOW, &mut tap).unwrap();
    assert_eq!(
        world.computer.finish(&response, NOW).unwrap(),
        Completed::Refused(Refusal::UnsupportedAlgorithm)
    );
    assert!(tap.seen.is_empty());
    assert_eq!(world.phone.credentials().len(), 1);
}

/// A response the phone's own key signed, with a decision of the test's
/// choosing. Models a phone that misbehaves; an honest one never sends these.
fn phone_signed(
    world: &mut common::World,
    begun: &signet_passkey::Begun,
    outcome: signet_passkey::Outcome,
) -> Vec<u8> {
    let genuine = world
        .phone
        .handle(&begun.envelope, NOW, &mut Tap::deny())
        .unwrap();
    let mut response = open_response(world, &genuine);
    response.decision = Decision::Approved { outcome };
    seal_signed(
        world.phone.identity(),
        &world.computer.identity().public(),
        &world.pairing_id,
        MessageKind::Response,
        &serde_json::to_vec(&response).unwrap(),
    )
    .unwrap()
}

#[test]
fn the_computer_checks_the_answer_against_what_it_asked() {
    use base64::Engine;
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let auth_data = |rp_id: &str, flags: u8| {
        encode(&signet_passkey::webauthn::authenticator_data(rp_id, flags, 0, None).unwrap())
    };
    let assertion =
        |credential_id: &str, authenticator_data: String| signet_passkey::Outcome::Assertion {
            credential_id: credential_id.into(),
            authenticator_data,
            signature: "AA".into(),
            user_handle: "dXNlci0x".into(),
        };
    let mut world = paired();
    let wanted = world.create_passkey("dXNlci0x", "jeremy");
    let mut options = get_options();
    options.allow_credentials = vec![wanted.clone()];
    let begin = |world: &mut common::World| {
        world
            .computer
            .begin_get(&world.pairing_id, ORIGIN, &options, None, NOW)
            .unwrap()
    };
    let up = signet_passkey::webauthn::FLAG_UP;

    // A new-passkey result in answer to a sign-in.
    let begun = begin(&mut world);
    let wrong_shape = signet_passkey::Outcome::Attestation {
        credential_id: wanted.clone(),
        attestation_object: "AA".into(),
        authenticator_data: auth_data("example.com", up),
        public_key: "AA".into(),
    };
    let response = phone_signed(&mut world, &begun, wrong_shape);
    assert!(matches!(
        world.computer.finish(&response, NOW),
        Err(PasskeyError::Malformed(_))
    ));

    // A signature made for another site.
    let begun = begin(&mut world);
    let response = phone_signed(
        &mut world,
        &begun,
        assertion(&wanted, auth_data("example.org", up)),
    );
    assert!(matches!(
        world.computer.finish(&response, NOW),
        Err(PasskeyError::SiteBinding(_))
    ));

    // A passkey the site did not ask for.
    let begun = begin(&mut world);
    let response = phone_signed(
        &mut world,
        &begun,
        assertion("b3RoZXI", auth_data("example.com", up)),
    );
    assert!(matches!(
        world.computer.finish(&response, NOW),
        Err(PasskeyError::Malformed(_))
    ));

    // An answer that does not claim the owner was present.
    let begun = begin(&mut world);
    let response = phone_signed(
        &mut world,
        &begun,
        assertion(&wanted, auth_data("example.com", 0)),
    );
    assert!(matches!(
        world.computer.finish(&response, NOW),
        Err(PasskeyError::Malformed(_))
    ));
}

#[test]
fn pairing_needs_the_ticket() {
    let computer = SoftwareIdentity::generate();
    let phone = SoftwareIdentity::generate();
    let ticket = |offer: &signet_passkey::PairingOffer| offer.ticket().encode();

    // An attacker who learns the pairing id and the computer's public keys, but
    // never saw the ticket's secret, cannot complete the pairing.
    let offer = issue_ticket(&computer, "Mac Studio", Role::Requester, NOW).unwrap();
    let mut guessed = offer.ticket().clone();
    guessed.secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
    let attacker = SoftwareIdentity::generate();
    let (_, reply) = accept_ticket(
        &guessed.encode(),
        &attacker,
        "Phone",
        Role::Authenticator,
        NOW,
    )
    .unwrap();
    assert!(matches!(
        offer.complete(&reply, NOW),
        Err(PasskeyError::Pairing(_))
    ));

    // A genuine reply altered in transit is rejected.
    let offer = issue_ticket(&computer, "Mac Studio", Role::Requester, NOW).unwrap();
    let (_, reply) =
        accept_ticket(&ticket(&offer), &phone, "Phone", Role::Authenticator, NOW).unwrap();
    let mut altered: serde_json::Value = serde_json::from_slice(&reply).unwrap();
    altered["acceptor_name"] = "Someone else".into();
    assert!(offer
        .complete(&serde_json::to_vec(&altered).unwrap(), NOW)
        .is_err());

    // A reply carrying another device's keys under a genuine MAC is impossible
    // without the secret; one carrying them under the genuine signature fails.
    let offer = issue_ticket(&computer, "Mac Studio", Role::Requester, NOW).unwrap();
    let (_, reply) =
        accept_ticket(&ticket(&offer), &phone, "Phone", Role::Authenticator, NOW).unwrap();
    let mut swapped: serde_json::Value = serde_json::from_slice(&reply).unwrap();
    swapped["acceptor"] = serde_json::to_value(attacker.public()).unwrap();
    assert!(offer
        .complete(&serde_json::to_vec(&swapped).unwrap(), NOW)
        .is_err());

    // Someone who did see the ticket cannot enroll a device whose key they do
    // not hold: the reply must be signed by the key it presents.
    let offer = issue_ticket(&computer, "Mac Studio", Role::Requester, NOW).unwrap();
    let misbinding = Impostor {
        claims: phone.public(),
        own: SoftwareIdentity::generate(),
    };
    let (_, reply) = accept_ticket(
        &ticket(&offer),
        &misbinding,
        "Phone",
        Role::Authenticator,
        NOW,
    )
    .unwrap();
    assert_eq!(
        offer.complete(&reply, NOW),
        Err(PasskeyError::Pairing("reply signature"))
    );

    // An expired ticket pairs nothing, on either side.
    let offer = issue_ticket(&computer, "Mac Studio", Role::Requester, NOW).unwrap();
    let late = NOW + PAIRING_TTL_SECS;
    assert!(accept_ticket(&ticket(&offer), &phone, "Phone", Role::Authenticator, late).is_err());
    let (_, reply) =
        accept_ticket(&ticket(&offer), &phone, "Phone", Role::Authenticator, NOW).unwrap();
    assert!(offer.complete(&reply, late).is_err());

    // Two computers, or two phones, do not pair.
    let offer = issue_ticket(&computer, "Mac Studio", Role::Requester, NOW).unwrap();
    assert!(accept_ticket(&ticket(&offer), &phone, "Laptop", Role::Requester, NOW).is_err());
}

#[test]
fn a_confirmation_code_exposes_a_device_that_paired_in_the_owner_s_place() {
    let computer = SoftwareIdentity::generate();
    let phone = SoftwareIdentity::generate();
    let watcher = SoftwareIdentity::generate();

    // The genuine pairing: both devices show the same code.
    let offer = issue_ticket(&computer, "Mac Studio", Role::Requester, NOW).unwrap();
    let ticket = offer.ticket().encode();
    let (phone_record, reply) =
        accept_ticket(&ticket, &phone, "Phone", Role::Authenticator, NOW).unwrap();
    let computer_record = offer.complete(&reply, NOW).unwrap();
    let code = computer_record.confirmation_code(&computer.public());
    assert_eq!(code, phone_record.confirmation_code(&phone.public()));
    assert_eq!(code.len(), 6);
    assert!(code.bytes().all(|b| b.is_ascii_digit()));

    // Someone who saw the ticket answers first. The computer now shows a code
    // that the owner's phone does not.
    let offer = issue_ticket(&computer, "Mac Studio", Role::Requester, NOW).unwrap();
    let ticket = offer.ticket().encode();
    let (phone_record, _) =
        accept_ticket(&ticket, &phone, "Phone", Role::Authenticator, NOW).unwrap();
    let (_, watcher_reply) =
        accept_ticket(&ticket, &watcher, "Phone", Role::Authenticator, NOW).unwrap();
    let computer_record = offer.complete(&watcher_reply, NOW).unwrap();
    assert_ne!(
        computer_record.confirmation_code(&computer.public()),
        phone_record.confirmation_code(&phone.public())
    );
}

#[test]
fn each_side_accepts_only_the_other_role() {
    let world = paired();
    let mut phone = world.phone;
    let mut computer = world.computer;
    let phone_record = computer_record_of(&phone);
    // A phone will not record a pairing whose peer is a phone, nor a computer
    // one whose peer is a computer.
    let mut as_phone_peer = phone_record.clone();
    as_phone_peer.id = "bmV3".into();
    as_phone_peer.peer_role = Role::Authenticator;
    assert!(phone.add_pairing(as_phone_peer.clone()).is_err());
    as_phone_peer.peer_role = Role::Requester;
    assert!(computer.add_pairing(as_phone_peer).is_err());
}

fn computer_record_of(phone: &signet_passkey::Authenticator) -> signet_passkey::Pairing {
    phone.pairings()[0].clone()
}
