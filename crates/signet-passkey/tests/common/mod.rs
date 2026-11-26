//! Shared fixtures. Every key is generated at test time; nothing here is a
//! real credential.
#![allow(dead_code)]
use signet_passkey::{
    accept_ticket, issue_ticket, Approval, Approver, Authenticator, CreateOptions, GetOptions,
    RequestView, Requester, Role, SoftwareCredentialKeys, SoftwareIdentity, UserVerification,
};

pub const NOW: i64 = 1_800_000_000;
pub const ORIGIN: &str = "https://example.com";

/// Stands in for the phone's screen and biometric prompt.
pub struct Tap {
    pub answer: Approval,
    pub seen: Vec<RequestView>,
}

impl Tap {
    pub fn approve() -> Self {
        Self::answering(Approval::Approve {
            account: 0,
            user_verified: true,
        })
    }

    pub fn deny() -> Self {
        Self::answering(Approval::Deny)
    }

    pub fn answering(answer: Approval) -> Self {
        Self {
            answer,
            seen: Vec::new(),
        }
    }
}

impl Approver for Tap {
    fn decide(&mut self, view: &RequestView) -> Approval {
        self.seen.push(view.clone());
        self.answer
    }
}

pub struct World {
    pub phone: Authenticator,
    pub computer: Requester,
    pub pairing_id: String,
}

/// A phone and a computer that have completed the pairing ceremony: the
/// computer shows a ticket, the phone reads it and replies.
pub fn paired() -> World {
    let phone_identity = SoftwareIdentity::generate();
    let computer_identity = SoftwareIdentity::generate();
    let offer = issue_ticket(&computer_identity, "Mac Studio", Role::Requester, NOW).unwrap();
    let (phone_record, reply) = accept_ticket(
        &offer.ticket().encode(),
        &phone_identity,
        "Owner's phone",
        Role::Authenticator,
        NOW,
    )
    .unwrap();
    let computer_record = offer.complete(&reply, NOW).unwrap();
    let pairing_id = computer_record.id.clone();

    let mut phone = Authenticator::new(
        Box::new(phone_identity),
        Box::new(SoftwareCredentialKeys::new()),
    );
    phone.add_pairing(phone_record).unwrap();
    let mut computer = Requester::new(Box::new(computer_identity));
    computer.add_pairing(computer_record).unwrap();
    World {
        phone,
        computer,
        pairing_id,
    }
}

pub fn create_options(user_id: &str, user_name: &str) -> CreateOptions {
    CreateOptions {
        challenge: "Y2hhbGxlbmdlLWNyZWF0ZQ".into(),
        rp_id: None,
        rp_name: "Example".into(),
        user_id: user_id.into(),
        user_name: user_name.into(),
        user_display_name: user_name.into(),
        algorithms: vec![-7, -257],
        exclude_credentials: Vec::new(),
        user_verification: UserVerification::Required,
        key_class: None,
    }
}

pub fn get_options() -> GetOptions {
    GetOptions {
        challenge: "Y2hhbGxlbmdlLWdldA".into(),
        rp_id: None,
        allow_credentials: Vec::new(),
        user_verification: UserVerification::Required,
    }
}

impl World {
    /// Create a passkey for `user_name` at example.com and return its id.
    pub fn create_passkey(&mut self, user_id: &str, user_name: &str) -> String {
        let begun = self
            .computer
            .begin_create(
                &self.pairing_id,
                ORIGIN,
                &create_options(user_id, user_name),
                None,
                NOW,
            )
            .unwrap();
        let response = self
            .phone
            .handle(&begun.envelope, NOW, &mut Tap::approve())
            .unwrap();
        match self.computer.finish(&response, NOW).unwrap() {
            signet_passkey::Completed::Attestation { credential_id, .. } => credential_id,
            other => panic!("expected a new passkey, got {other:?}"),
        }
    }
}
