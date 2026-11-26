//! The computer side of remote passkey approval.
//!
//! This is what is installed on a computer. It keeps a machine key and the
//! list of paired phones, and it does three things:
//!
//! - pairs with a phone ([`pair`]);
//! - answers the browser extension over Chrome native messaging ([`native`]),
//!   deciding for each passkey call whether it goes to the phone or stays with
//!   the browser ([`flow`]);
//! - carries the sealed request to the relay and waits for the sealed answer
//!   ([`relay_client`]).
//!
//! It holds no passkey. The machine key lets this computer ask; the phone
//! decides and signs. The protocol is in the `signet-passkey` crate and the
//! design in `docs/remote-passkey.md`.
//!
//! Limits of this slice, stated once: the machine key is a file readable by
//! the user's account, not a key in the operating system's key store; and the
//! relay client speaks plain HTTP to a relay on this machine only. Reaching a
//! relay over the network needs TLS, which is not built yet.
#![forbid(unsafe_code)]

pub mod browser;
mod error;
pub mod flow;
pub mod native;
pub mod options;
pub mod pair;
pub mod relay_client;
pub mod store;

pub use error::DesktopError;
pub use relay_client::RelayClient;
pub use store::{State, Store};

/// The current time, Unix seconds.
pub fn system_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}
