//! Pairing this computer with a phone.
//!
//! The computer shows a one-time ticket. The phone reads it and leaves a reply
//! at the relay. The computer collects the reply, and the person types the six
//! digits the phone is showing. The pairing is saved only if those digits match
//! what this computer computed, which they do only when the phone in the
//! person's hand is the device that answered the ticket.
use crate::{DesktopError, RelayClient, Store};
use signet_passkey::{issue_ticket, IdentityKeys, Pairing, PairingOffer, Role};

/// A ticket that has been shown and not yet answered.
pub struct Started {
    offer: PairingOffer,
    /// The ticket to show the phone.
    pub ticket: String,
    pub expires_at: i64,
    relay: RelayClient,
    rendezvous: String,
}

/// A reply that has arrived and not yet been confirmed by the person.
pub struct Answered {
    pairing: Pairing,
}

/// Issue a ticket for the relay in this computer's settings.
pub fn start(store: &Store, now: i64) -> Result<Started, DesktopError> {
    let state = store.load()?;
    let identity = store.identity()?;
    let relay = RelayClient::new(&state.relay)?;
    let offer = issue_ticket(&identity, &state.device_name, Role::Requester, now)?
        .with_relay(relay.address())?;
    Ok(Started {
        ticket: offer.ticket().encode(),
        expires_at: offer.ticket().expires_at,
        rendezvous: offer.ticket().rendezvous_id()?,
        relay,
        offer,
    })
}

impl Started {
    /// Wait for the phone's reply, until the ticket expires. `Ok(None)` means
    /// it expired unanswered.
    pub async fn wait(self, clock: &dyn Fn() -> i64) -> Result<Option<Answered>, DesktopError> {
        loop {
            let remaining = self.expires_at - clock();
            if remaining <= 0 {
                return Ok(None);
            }
            let reply = self
                .relay
                .get_rendezvous(&self.rendezvous, 25.min(remaining as u64))
                .await?;
            if let Some(reply) = reply {
                let pairing = self.offer.complete(&reply, clock())?;
                return Ok(Some(Answered { pairing }));
            }
        }
    }
}

impl Answered {
    /// The name the answering device gave itself.
    pub fn phone_name(&self) -> &str {
        &self.pairing.peer_name
    }

    pub fn phone_fingerprint(&self) -> String {
        self.pairing.peer.fingerprint()
    }

    /// Save the pairing if `typed` is the code the phone is showing.
    ///
    /// A wrong code saves nothing. It means the reply came from a device other
    /// than the one in the person's hand, or a typing mistake; either way the
    /// answer is to start again.
    pub fn confirm(self, store: &Store, typed: &str) -> Result<Pairing, DesktopError> {
        // The digits this computer expects the phone to be showing.
        let expected = self.pairing.confirmation_code(&store.identity()?.public());
        let typed: String = typed.chars().filter(char::is_ascii_digit).collect();
        if typed != expected {
            return Err(DesktopError::Other(
                "the code does not match. Nothing was saved. Remove this computer on the phone \
                 if it appears there, and pair again"
                    .into(),
            ));
        }
        let pairing = self.pairing;
        let fingerprint = pairing.peer.fingerprint();
        store.update(|state| {
            // Pairing the same phone again replaces its older record.
            state
                .pairings
                .retain(|existing| existing.peer.fingerprint() != fingerprint);
            state.pairings.push(pairing.clone());
        })?;
        Ok(pairing)
    }
}

/// Stop using a phone, named by pairing id, fingerprint or name. Returns the
/// names removed.
pub fn unpair(store: &Store, which: &str) -> Result<Vec<String>, DesktopError> {
    store.update(|state| {
        let mut removed = Vec::new();
        state.pairings.retain(|pairing| {
            let matches = pairing.id == which
                || pairing.peer.fingerprint() == which
                || pairing.peer_name == which;
            if matches {
                removed.push(pairing.peer_name.clone());
            }
            !matches
        });
        removed
    })
}
