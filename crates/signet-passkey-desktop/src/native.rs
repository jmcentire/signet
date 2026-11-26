//! The conversation with the browser extension.
//!
//! Chrome starts this program as a native-messaging host and exchanges JSON
//! messages with it over standard input and output, each preceded by its
//! length as four bytes in the machine's byte order. The extension opens one
//! connection per passkey call, sends one [`HostRequest`], and reads replies
//! until a final one arrives. Closing the connection cancels the call.
use std::io::{Read, Write};

/// Version of this message format.
pub const HOST_PROTOCOL: u8 = 1;
/// The name Chrome knows this host by.
pub const HOST_NAME: &str = "io.github.jmcentire.signet_passkey";
/// Largest message accepted from the extension.
const MAX_REQUEST_BYTES: usize = 1024 * 1024;

/// What the extension asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestKind {
    /// Is this computer paired, and with what?
    Status,
    /// A page called `navigator.credentials.create`.
    Create,
    /// A page called `navigator.credentials.get`.
    Get,
}

/// One message from the extension.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct HostRequest {
    pub v: u8,
    /// Chosen by the extension and echoed on every reply.
    pub id: String,
    #[serde(rename = "type")]
    pub kind: RequestKind,
    /// The page's origin, as the browser reported it to the extension's
    /// service worker. Never taken from the page.
    #[serde(default)]
    pub origin: Option<String>,
    /// The `publicKey` options in the standard JSON form.
    #[serde(default)]
    pub options: Option<serde_json::Value>,
    /// The call's `mediation` value, if the page gave one.
    #[serde(default)]
    pub mediation: Option<String>,
    /// The browser's name, shown on the phone as a claim.
    #[serde(default)]
    pub browser: Option<String>,
}

/// What the host answers. `Pending` may precede a final reply; every other
/// variant ends the call.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum HostReply {
    Status {
        paired: bool,
        device: String,
        phones: Vec<String>,
        new_passkeys: bool,
    },
    /// The request is with the phone. Shown to the person at the computer.
    Pending { phone: String, expires_at: i64 },
    /// The phone approved. `credential` is the standard
    /// `RegistrationResponseJSON` or `AuthenticationResponseJSON`.
    Credential { credential: serde_json::Value },
    /// Not for the phone: the extension hands the call to the browser's own
    /// passkey support, as if the extension were not installed.
    Native { reason: String },
    /// The call fails. `name` is the DOMException name the page receives.
    Error { name: String, message: String },
}

impl HostReply {
    pub fn is_final(&self) -> bool {
        !matches!(self, Self::Pending { .. })
    }

    pub fn native(reason: &str) -> Self {
        Self::Native {
            reason: reason.to_owned(),
        }
    }

    pub fn error(name: &str, message: &str) -> Self {
        Self::Error {
            name: name.to_owned(),
            message: message.to_owned(),
        }
    }

    /// The message as sent: the reply with the protocol version and request id.
    pub fn to_message(&self, id: &str) -> serde_json::Value {
        let mut value = serde_json::to_value(self).expect("reply serializes");
        let object = value.as_object_mut().expect("reply is an object");
        object.insert("v".into(), HOST_PROTOCOL.into());
        object.insert("id".into(), id.into());
        value
    }
}

/// Read one message. `Ok(None)` when the extension closed the connection.
pub fn read_message(input: &mut impl Read) -> std::io::Result<Option<Vec<u8>>> {
    let mut length = [0u8; 4];
    match input.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u32::from_ne_bytes(length) as usize;
    if length > MAX_REQUEST_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut body = vec![0u8; length];
    input.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Write one message.
pub fn write_message(output: &mut impl Write, message: &serde_json::Value) -> std::io::Result<()> {
    let body = serde_json::to_vec(message).expect("message serializes");
    output.write_all(&(body.len() as u32).to_ne_bytes())?;
    output.write_all(&body)?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_survive_framing() {
        let mut wire = Vec::new();
        let reply = HostReply::Pending {
            phone: "Jeremy's phone".into(),
            expires_at: 99,
        };
        write_message(&mut wire, &reply.to_message("call-1")).unwrap();
        write_message(
            &mut wire,
            &HostReply::native("not paired").to_message("call-1"),
        )
        .unwrap();
        let mut reader = wire.as_slice();
        let first: serde_json::Value =
            serde_json::from_slice(&read_message(&mut reader).unwrap().unwrap()).unwrap();
        assert_eq!(first["result"], "pending");
        assert_eq!(first["id"], "call-1");
        assert_eq!(first["v"], 1);
        assert_eq!(first["phone"], "Jeremy's phone");
        let second: serde_json::Value =
            serde_json::from_slice(&read_message(&mut reader).unwrap().unwrap()).unwrap();
        assert_eq!(second["result"], "native");
        assert!(read_message(&mut reader).unwrap().is_none());
    }

    #[test]
    fn an_oversized_length_is_refused_without_reading_it() {
        let mut wire = (2_000_000u32).to_ne_bytes().to_vec();
        wire.extend_from_slice(b"{}");
        assert!(read_message(&mut wire.as_slice()).is_err());
    }

    #[test]
    fn requests_parse_and_ignore_what_they_do_not_know() {
        let request: HostRequest = serde_json::from_str(
            r#"{"v":1,"id":"a","type":"get","origin":"https://example.com",
                "options":{"challenge":"Yw"},"future":true}"#,
        )
        .unwrap();
        assert_eq!(request.kind, RequestKind::Get);
        assert_eq!(request.origin.as_deref(), Some("https://example.com"));
        assert!(serde_json::from_str::<HostRequest>(r#"{"v":1,"id":"a","type":"sign"}"#).is_err());
    }
}
