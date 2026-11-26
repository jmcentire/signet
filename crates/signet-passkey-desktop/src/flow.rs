//! Deciding what happens to one passkey call, and carrying it out.
//!
//! A call either goes to the phone or stays with the browser.
//!
//! - Creating a passkey goes to the phone when this computer is paired and new
//!   passkeys are switched on, unless the site asked for a roaming security
//!   key or does not accept ES256.
//! - Signing in goes to the phone for sites listed in the settings. A site is
//!   listed when a passkey is created for it through this computer, or by
//!   hand.
//! - Everything else, and anything this code cannot parse or validate, is
//!   handed back to the browser, which then behaves as if the extension were
//!   not installed and reports its own errors.
//!
//! Once a request is with the phone the outcome is the phone's: an approval
//! becomes a credential, a denial or a timeout becomes the same
//! `NotAllowedError` a dismissed browser prompt produces. The one exception is
//! a sign-in the phone has no passkey for, which is handed back to the browser
//! so a passkey kept elsewhere still works.
use crate::native::{HostReply, HostRequest, RequestKind, HOST_PROTOCOL};
use crate::options::{parse_create, parse_get};
use crate::{DesktopError, RelayClient, Store};
use signet_passkey::relay::{decode, reply_slot, PollRequest};
use signet_passkey::{
    Begun, Completed, Initiator, PasskeyError, Refusal, RequestContext, Requester, CLOCK_SKEW_SECS,
    REQUEST_TTL_SECS,
};

/// Requests one page origin may send to the phone per minute.
const MAX_PER_MINUTE: usize = 6;
/// How long one read of the mailbox waits.
const POLL_WAIT_SECS: u64 = 25;
/// Time allowed after a request expires for an answer already on its way.
const GRACE_SECS: i64 = 5;
const ES256: i64 = -7;

const NOT_ALLOWED: &str = "NotAllowedError";

fn browser_name(claimed: Option<&str>) -> Option<String> {
    let name: String = claimed?
        .chars()
        .filter(|c| !c.is_control())
        .take(40)
        .collect();
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_owned())
}

/// What the page receives when the phone has answered.
fn outcome_reply(completed: Completed, kind: RequestKind, cred_props: bool) -> HostReply {
    match completed {
        Completed::Denied => {
            HostReply::error(NOT_ALLOWED, "The request was declined on the phone.")
        }
        Completed::Refused(Refusal::NoCredential) if kind == RequestKind::Get => {
            HostReply::native("the phone has no passkey for this site")
        }
        Completed::Refused(Refusal::CredentialExcluded) => HostReply::error(
            "InvalidStateError",
            "The phone already holds a passkey for this account.",
        ),
        Completed::Refused(Refusal::UnsupportedAlgorithm) => {
            HostReply::native("the phone does not support the algorithms this site accepts")
        }
        Completed::Refused(Refusal::SiteBinding) => HostReply::error(
            "SecurityError",
            "The phone refused: the page and the passkey's site do not match.",
        ),
        Completed::Refused(_) => HostReply::error(NOT_ALLOWED, "The phone refused the request."),
        approved => match approved.to_json() {
            Some(mut credential) => {
                if cred_props {
                    // Passkeys made here are always discoverable.
                    credential["clientExtensionResults"] =
                        serde_json::json!({ "credProps": { "rk": true } });
                }
                HostReply::Credential { credential }
            }
            None => HostReply::error("UnknownError", "The phone's answer could not be used."),
        },
    }
}

fn relay_failure(error: &DesktopError) -> HostReply {
    let message = match error.relay_code() {
        Some("not_accepted") => "Your phone is not accepting requests from this computer. \
                                 Open Signet on the phone, and pair again if this computer \
                                 was removed there."
            .to_owned(),
        Some("mailbox_full") => "Too many requests are already waiting on your phone.".to_owned(),
        _ => format!("Signet could not send the request to your phone: {error}"),
    };
    HostReply::error(NOT_ALLOWED, &message)
}

/// Answer one message from the extension.
///
/// `progress` is called with any reply that precedes the final one. `clock`
/// supplies protocol time, Unix seconds.
pub async fn handle(
    store: &Store,
    request: HostRequest,
    clock: &dyn Fn() -> i64,
    progress: &mut dyn FnMut(&HostReply),
) -> HostReply {
    if request.v != HOST_PROTOCOL {
        return HostReply::native("the extension and this program are different versions");
    }
    let state = match store.load() {
        Ok(state) => state,
        Err(DesktopError::NotInitialized) if request.kind == RequestKind::Status => {
            return HostReply::Status {
                paired: false,
                device: String::new(),
                phones: Vec::new(),
                new_passkeys: false,
            }
        }
        Err(error) => return HostReply::native(&error.to_string()),
    };
    if request.kind == RequestKind::Status {
        return HostReply::Status {
            paired: state.active_pairing().is_some(),
            device: state.device_name.clone(),
            phones: state
                .pairings
                .iter()
                .filter(|pairing| !pairing.revoked)
                .map(|pairing| pairing.peer_name.clone())
                .collect(),
            new_passkeys: state.new_passkeys,
        };
    }

    // Routing. Every early return here leaves the call with the browser.
    if request.mediation.as_deref() == Some("conditional") {
        return HostReply::native("autofill sign-in stays with the browser");
    }
    let (Some(origin), Some(options)) = (request.origin.as_deref(), request.options.as_ref())
    else {
        return HostReply::native("incomplete request");
    };
    let Some(pairing) = state.active_pairing().cloned() else {
        return HostReply::native("this computer is not paired with a phone");
    };
    let create = match request.kind {
        RequestKind::Create => match parse_create(options) {
            Ok(parsed) => Some(parsed),
            Err(_) => return HostReply::native("options left to the browser"),
        },
        _ => None,
    };
    let get = match request.kind {
        RequestKind::Get => match parse_get(options) {
            Ok(parsed) => Some(parsed),
            Err(_) => return HostReply::native("options left to the browser"),
        },
        _ => None,
    };
    let requested_rp = create
        .as_ref()
        .map(|c| c.options.rp_id.as_deref())
        .or(get.as_ref().map(|g| g.rp_id.as_deref()))
        .flatten();
    let Ok(rp_id) = signet_passkey::rp::effective_rp_id(origin, requested_rp) else {
        // The browser refuses this with its own SecurityError.
        return HostReply::native("the page may not use that site identifier");
    };
    if let Some(create) = &create {
        if !state.new_passkeys {
            return HostReply::native("new passkeys are set to stay with the browser");
        }
        if create.wants_security_key {
            return HostReply::native("the site asked for a security key");
        }
        if !create.options.algorithms.contains(&ES256) {
            return HostReply::native("the site does not accept ES256");
        }
    } else if !state.sites.contains(&rp_id) {
        return HostReply::native("no Signet passkey is recorded for this site");
    }

    // From here the request goes to the phone.
    let now = clock();
    let allowed = store.update(|state| {
        state.recent.retain(|(_, at)| *at > now - 60 && *at <= now);
        let count = state.recent.iter().filter(|(o, _)| o == origin).count();
        if count >= MAX_PER_MINUTE {
            return false;
        }
        state.recent.push((origin.to_owned(), now));
        true
    });
    match allowed {
        Ok(true) => {}
        Ok(false) => {
            return HostReply::error(
                NOT_ALLOWED,
                "This page has sent too many passkey requests to your phone. Wait a minute.",
            )
        }
        Err(error) => return HostReply::error(NOT_ALLOWED, &error.to_string()),
    }

    let identity = match store.identity() {
        Ok(identity) => identity,
        Err(error) => return HostReply::error(NOT_ALLOWED, &error.to_string()),
    };
    let relay = match RelayClient::new(pairing.relay.as_deref().unwrap_or(&state.relay)) {
        Ok(relay) => relay,
        Err(error) => return HostReply::error(NOT_ALLOWED, &error.to_string()),
    };
    let mut requester = Requester::new(Box::new(identity));
    if let Err(error) = requester.add_pairing(pairing.clone()) {
        return HostReply::error(NOT_ALLOWED, &error.to_string());
    }
    let context = Some(RequestContext {
        app: browser_name(request.browser.as_deref()),
        // This program cannot tell a person at the keyboard from software
        // driving the browser, and says so.
        initiated_by: Initiator::Unknown,
        note: None,
    });
    let begun = match (&create, &get) {
        (Some(create), _) => {
            requester.begin_create(&pairing.id, origin, &create.options, context, now)
        }
        (_, Some(get)) => requester.begin_get(&pairing.id, origin, get, context, now),
        _ => unreachable!("one of the two was parsed above"),
    };
    let Begun { envelope, .. } = match begun {
        Ok(begun) => begun,
        Err(PasskeyError::SiteBinding(_)) | Err(PasskeyError::Malformed(_)) => {
            return HostReply::native("options left to the browser")
        }
        Err(error) => return HostReply::error(NOT_ALLOWED, &error.to_string()),
    };

    let slot = reply_slot(&envelope);
    let phone = pairing.peer.fingerprint();
    let peers: Vec<String> = state
        .pairings
        .iter()
        .filter(|pairing| !pairing.revoked)
        .map(|pairing| pairing.peer.fingerprint())
        .collect();
    let read = |wait_secs: u64, ack: Vec<String>| PollRequest {
        peers: peers.clone(),
        slot: Some(slot.clone()),
        wait_secs,
        ack,
    };
    // Tell the relay the phone may write to this computer before asking the
    // phone anything, so its answer is not turned away.
    if let Err(error) = relay
        .poll(requester.identity(), &read(0, Vec::new()), clock())
        .await
    {
        return relay_failure(&error);
    }
    if let Err(error) = relay
        .deposit(
            requester.identity(),
            &phone,
            None,
            envelope,
            REQUEST_TTL_SECS + CLOCK_SKEW_SECS,
            clock(),
        )
        .await
    {
        return relay_failure(&error);
    }
    let expires_at = now + REQUEST_TTL_SECS;
    progress(&HostReply::Pending {
        phone: pairing.peer_name.clone(),
        expires_at,
    });

    let mut ack = Vec::new();
    let mut outcome = None;
    while outcome.is_none() {
        let remaining = expires_at + GRACE_SECS - clock();
        if remaining <= 0 {
            break;
        }
        let wait = POLL_WAIT_SECS.min(remaining as u64);
        let poll = relay
            .poll(requester.identity(), &read(wait, ack.clone()), clock())
            .await;
        let messages = match poll {
            Ok(response) => response.messages,
            Err(_) => {
                // The relay may be restarting. Keep trying until the request
                // itself runs out.
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };
        for message in messages {
            if ack.contains(&message.id) {
                continue;
            }
            ack.push(message.id);
            let Ok(envelope) = decode(&message.body) else {
                continue;
            };
            // Anything that is not the paired phone's signed answer to this
            // request fails here and is ignored.
            if let Ok(completed) = requester.finish(&envelope, clock()) {
                outcome = Some(completed);
                break;
            }
        }
    }
    if !ack.is_empty() {
        let _ = relay
            .poll(requester.identity(), &read(0, ack), clock())
            .await;
    }

    let Some(completed) = outcome else {
        return HostReply::error(NOT_ALLOWED, "No answer came from your phone in time.");
    };
    if matches!(
        completed,
        Completed::Assertion { .. } | Completed::Attestation { .. }
    ) {
        // Remember that this site's passkey lives on the phone.
        let _ = store.update(|state| state.sites.insert(rp_id.clone()));
    }
    let cred_props = create.is_some() && options["extensions"]["credProps"] == true;
    outcome_reply(completed, request.kind, cred_props)
}
