//! Talking to the relay.
//!
//! One short HTTP exchange per call. Every mailbox call is signed with this
//! device's identity key (`signet_passkey::relay::RelayAuth`). The signature is
//! made before the first network wait, so the returned futures do not hold the
//! key.
use crate::DesktopError;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::{header, Method, Request, StatusCode};
use signet_passkey::relay::{
    deposit_path, normalize_relay_url, poll_path, rendezvous_path, DepositReceipt, PollRequest,
    PollResponse, RelayAuth,
};
use signet_passkey::IdentityKeys;
use std::future::Future;
use std::time::Duration;

/// Largest reply the client will read.
const MAX_REPLY_BYTES: usize = 512 * 1024;
/// Time allowed for a call beyond any wait the relay was asked for.
const SLACK: Duration = Duration::from_secs(15);

/// A relay, by address.
#[derive(Debug, Clone)]
pub struct RelayClient {
    /// The address in normal form. Also the audience every request is signed for.
    base: String,
    host: String,
    port: u16,
    authority: String,
    prefix: String,
}

struct Prepared {
    method: Method,
    path: String,
    authorization: Option<String>,
    body: Vec<u8>,
    wait: Duration,
}

impl RelayClient {
    /// Use the relay at `address`.
    pub fn new(address: &str) -> Result<Self, DesktopError> {
        let base = normalize_relay_url(address)?;
        let url =
            url::Url::parse(&base).map_err(|_| DesktopError::Other("relay address".into()))?;
        if url.scheme() != "http" {
            // `normalize_relay_url` only lets plain HTTP through for this
            // machine, so anything that reaches the network arrives here.
            return Err(DesktopError::TlsNotBuilt);
        }
        let host = url
            .host_str()
            .ok_or_else(|| DesktopError::Other("relay address".into()))?;
        let port = url.port_or_known_default().unwrap_or(80);
        Ok(Self {
            authority: match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_owned(),
            },
            host: host.trim_matches(|c| c == '[' || c == ']').to_owned(),
            port,
            prefix: url.path().trim_end_matches('/').to_owned(),
            base,
        })
    }

    /// The relay's address in normal form.
    pub fn address(&self) -> &str {
        &self.base
    }

    fn signed(
        &self,
        identity: &dyn IdentityKeys,
        path: String,
        body: Vec<u8>,
        wait: Duration,
        now: i64,
    ) -> Result<Prepared, DesktopError> {
        let auth = RelayAuth::sign(identity, &self.base, "POST", &path, &body, now)?;
        Ok(Prepared {
            method: Method::POST,
            path,
            authorization: Some(auth.to_header()),
            body,
            wait,
        })
    }

    async fn send(&self, prepared: Prepared) -> Result<(StatusCode, Bytes), DesktopError> {
        let unreachable = |error: &dyn std::fmt::Display| {
            DesktopError::RelayUnreachable(format!("{}: {error}", self.base))
        };
        let exchange = async {
            let stream = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
                .await
                .map_err(|e| unreachable(&e))?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                    .await
                    .map_err(|e| unreachable(&e))?;
            // Drives the connection; ends when the exchange does.
            tokio::spawn(connection);
            let mut request = Request::builder()
                .method(prepared.method)
                .uri(format!("{}{}", self.prefix, prepared.path))
                .header(header::HOST, &self.authority)
                .header(header::CONTENT_LENGTH, prepared.body.len());
            if let Some(authorization) = &prepared.authorization {
                request = request.header(header::AUTHORIZATION, authorization);
            }
            let request = request
                .body(Full::new(Bytes::from(prepared.body)))
                .map_err(|e| DesktopError::Other(format!("relay request: {e}")))?;
            let response = sender
                .send_request(request)
                .await
                .map_err(|e| unreachable(&e))?;
            let status = response.status();
            let body = Limited::new(response.into_body(), MAX_REPLY_BYTES)
                .collect()
                .await
                .map_err(|e| unreachable(&e))?
                .to_bytes();
            Ok::<_, DesktopError>((status, body))
        };
        tokio::time::timeout(prepared.wait + SLACK, exchange)
            .await
            .map_err(|_| unreachable(&"timed out"))?
    }

    fn refused(status: StatusCode, body: &[u8]) -> DesktopError {
        let code = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|value| value["error"].as_str().map(str::to_owned))
            .unwrap_or_else(|| "unexpected_reply".into());
        DesktopError::RelayRefused {
            status: status.as_u16(),
            code,
        }
    }

    /// Leave a sealed envelope for `recipient`.
    pub fn deposit<'a>(
        &'a self,
        identity: &dyn IdentityKeys,
        recipient: &str,
        slot: Option<&str>,
        envelope: Vec<u8>,
        ttl_secs: i64,
        now: i64,
    ) -> impl Future<Output = Result<DepositReceipt, DesktopError>> + Send + 'a {
        let mut path = deposit_path(recipient, slot);
        path.push(if slot.is_some() { '&' } else { '?' });
        path.push_str(&format!("ttl={ttl_secs}"));
        let prepared = self.signed(identity, path, envelope, Duration::ZERO, now);
        async move {
            let (status, body) = self.send(prepared?).await?;
            if status != StatusCode::ACCEPTED {
                return Err(Self::refused(status, &body));
            }
            serde_json::from_slice(&body).map_err(|_| Self::refused(status, &body))
        }
    }

    /// Read this device's mailbox.
    pub fn poll<'a>(
        &'a self,
        identity: &dyn IdentityKeys,
        request: &PollRequest,
        now: i64,
    ) -> impl Future<Output = Result<PollResponse, DesktopError>> + Send + 'a {
        let path = poll_path(&identity.public().fingerprint());
        let body = serde_json::to_vec(request).expect("poll request serializes");
        let wait = Duration::from_secs(request.wait_secs);
        let prepared = self.signed(identity, path, body, wait, now);
        async move {
            let (status, body) = self.send(prepared?).await?;
            if status != StatusCode::OK {
                return Err(Self::refused(status, &body));
            }
            serde_json::from_slice(&body).map_err(|_| Self::refused(status, &body))
        }
    }

    /// Leave the reply to a pairing ticket. Fails with the relay code `exists`
    /// if another device answered the ticket first.
    pub async fn put_rendezvous(&self, id: &str, reply: Vec<u8>) -> Result<(), DesktopError> {
        let (status, body) = self
            .send(Prepared {
                method: Method::PUT,
                path: rendezvous_path(id),
                authorization: None,
                body: reply,
                wait: Duration::ZERO,
            })
            .await?;
        if status != StatusCode::CREATED {
            return Err(Self::refused(status, &body));
        }
        Ok(())
    }

    /// Collect the reply to a pairing ticket, waiting up to `wait_secs`.
    pub async fn get_rendezvous(
        &self,
        id: &str,
        wait_secs: u64,
    ) -> Result<Option<Vec<u8>>, DesktopError> {
        let (status, body) = self
            .send(Prepared {
                method: Method::GET,
                path: format!("{}?wait={wait_secs}", rendezvous_path(id)),
                authorization: None,
                body: Vec::new(),
                wait: Duration::from_secs(wait_secs),
            })
            .await?;
        match status {
            StatusCode::OK => Ok(Some(body.to_vec())),
            StatusCode::NO_CONTENT => Ok(None),
            _ => Err(Self::refused(status, &body)),
        }
    }

    /// Whether the relay answers.
    pub async fn health(&self) -> Result<(), DesktopError> {
        let (status, body) = self
            .send(Prepared {
                method: Method::GET,
                path: "/v1/health".into(),
                authorization: None,
                body: Vec::new(),
                wait: Duration::ZERO,
            })
            .await?;
        if status != StatusCode::OK {
            return Err(Self::refused(status, &body));
        }
        Ok(())
    }
}
