//! A stand-in for the phone app, for tests and local trials.
//!
//! It runs the real phone-side protocol (`signet_passkey::Authenticator`) and
//! talks to a real relay, but its keys are ordinary values in this process's
//! memory and vanish when the process exits. It is not an authenticator to
//! register with an account you care about.
#![allow(dead_code)]
use signet_passkey::relay::{decode, reply_slot, PollRequest, DEFAULT_MESSAGE_TTL_SECS};
use signet_passkey::seal::Envelope;
use signet_passkey::{
    accept_ticket, Approval, Approver, Authenticator, PairingTicket, RequestView, Role,
    SoftwareCredentialKeys, SoftwareIdentity,
};
use signet_passkey_desktop::RelayClient;
use std::collections::{HashSet, VecDeque};

/// The simulated phone.
pub struct Phone {
    pub name: String,
    pub authenticator: Authenticator,
    relay: Option<RelayClient>,
    to_ack: Vec<String>,
    handled: HashSet<String>,
}

/// An owner who answers from a prepared list, then with a fixed answer, and
/// keeps what they were shown.
pub struct Scripted {
    pub decisions: VecDeque<bool>,
    pub otherwise: bool,
    pub shown: Vec<RequestView>,
}

impl Scripted {
    pub fn always(approve: bool) -> Self {
        Self {
            decisions: VecDeque::new(),
            otherwise: approve,
            shown: Vec::new(),
        }
    }
}

impl Approver for Scripted {
    fn decide(&mut self, view: &RequestView) -> Approval {
        self.shown.push(view.clone());
        if self.decisions.pop_front().unwrap_or(self.otherwise) {
            Approval::Approve {
                account: 0,
                user_verified: true,
            }
        } else {
            Approval::Deny
        }
    }
}

impl Phone {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            authenticator: Authenticator::new(
                Box::new(SoftwareIdentity::generate()),
                Box::new(SoftwareCredentialKeys::new()),
            ),
            relay: None,
            to_ack: Vec::new(),
            handled: HashSet::new(),
        }
    }

    /// How many requests have reached this phone, whatever became of them.
    pub fn requests_received(&self) -> usize {
        self.handled.len()
    }

    pub fn fingerprint(&self) -> String {
        self.authenticator.identity().public().fingerprint()
    }

    /// Answer a pairing ticket. Returns the six digits to show the owner.
    pub async fn pair(&mut self, ticket: &str, now: i64) -> Result<String, String> {
        let parsed = PairingTicket::decode(ticket).map_err(|e| e.to_string())?;
        let address = parsed.relay.clone().ok_or("the ticket names no relay")?;
        let relay = RelayClient::new(&address).map_err(|e| e.to_string())?;
        let (pairing, reply) = accept_ticket(
            ticket,
            self.authenticator.identity(),
            &self.name,
            Role::Authenticator,
            now,
        )
        .map_err(|e| e.to_string())?;
        // If another device answered this ticket first, the relay says so and
        // nothing is recorded here.
        relay
            .put_rendezvous(&parsed.rendezvous_id().map_err(|e| e.to_string())?, reply)
            .await
            .map_err(|e| e.to_string())?;
        let code = pairing.confirmation_code(&self.authenticator.identity().public());
        self.authenticator
            .add_pairing(pairing)
            .map_err(|e| e.to_string())?;
        self.relay = Some(relay);
        // Check in, so the relay knows the computer may write to this phone.
        self.read(0, now).await?;
        Ok(code)
    }

    async fn read(
        &mut self,
        wait_secs: u64,
        now: i64,
    ) -> Result<Vec<signet_passkey::relay::RelayMessage>, String> {
        let relay = self.relay.as_ref().ok_or("not paired")?;
        let request = PollRequest {
            peers: self
                .authenticator
                .pairings()
                .iter()
                .filter(|pairing| !pairing.revoked)
                .map(|pairing| pairing.peer.fingerprint())
                .collect(),
            slot: None,
            wait_secs,
            ack: self.to_ack.clone(),
        };
        let response = relay
            .poll(self.authenticator.identity(), &request, now)
            .await
            .map_err(|e| e.to_string())?;
        self.to_ack.clear();
        Ok(response.messages)
    }

    /// Read the mailbox once, waiting up to `wait_secs`, and answer what
    /// arrived. Returns how many requests were answered.
    pub async fn serve_once(
        &mut self,
        approver: &mut dyn Approver,
        wait_secs: u64,
        clock: &dyn Fn() -> i64,
    ) -> Result<usize, String> {
        let mut answered = 0;
        for message in self.read(wait_secs, clock()).await? {
            self.to_ack.push(message.id.clone());
            if !self.handled.insert(message.id) {
                continue;
            }
            let Ok(request) = decode(&message.body) else {
                continue;
            };
            // A request that is not from a paired computer, is stale or was
            // seen before gets no reply at all.
            let Ok(response) = self.authenticator.handle(&request, clock(), approver) else {
                continue;
            };
            let Some(computer) = Envelope::from_bytes(&request).ok().and_then(|envelope| {
                self.authenticator
                    .pairings()
                    .iter()
                    .find(|pairing| pairing.id == envelope.pairing_id)
                    .map(|pairing| pairing.peer.fingerprint())
            }) else {
                continue;
            };
            let relay = self.relay.as_ref().ok_or("not paired")?;
            relay
                .deposit(
                    self.authenticator.identity(),
                    &computer,
                    Some(&reply_slot(&request)),
                    response,
                    DEFAULT_MESSAGE_TTL_SECS,
                    clock(),
                )
                .await
                .map_err(|e| e.to_string())?;
            answered += 1;
        }
        Ok(answered)
    }

    /// Serve until the future is dropped.
    pub async fn serve(&mut self, approver: &mut dyn Approver, clock: &dyn Fn() -> i64) {
        loop {
            if self.serve_once(approver, 2, clock).await.is_err() {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
    }
}
