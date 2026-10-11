//! R2 S3 wire adapter: native JSON, If-None-Match:* for snapshots, If-Match for head.
//! Transport is injected so tests never discover or transmit ambient credentials.
use super::*;
use std::collections::BTreeMap;
pub struct Request {
    pub method: &'static str,
    pub key: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}
pub struct Response {
    pub status: u16,
    pub etag: Option<String>,
    pub body: Vec<u8>,
}
/// Production transport must sign every header using AWS SigV4 (region auto,
/// service s3), bind the approved account/bucket endpoint, disable redirects and
/// caches, enforce a bounded timeout and MAX_SNAPSHOT response size. Use an SDK,
/// not a hand-written signing implementation. Never use ambient AWS credentials.
pub trait Transport: Send + Sync {
    fn send(&self, request: Request) -> Result<Response>;
}
pub struct R2<T>(pub T);
impl<T: Transport> Store for R2<T> {
    fn get(&self, key: &str) -> Result<Option<Object>> {
        let response = self.0.send(Request {
            method: "GET",
            key: key.into(),
            headers: BTreeMap::from([("cache-control".into(), "no-store".into())]),
            body: vec![],
        })?;
        match response.status {
            404 => Ok(None),
            200 if response.body.len() <= MAX_SNAPSHOT => Ok(Some(Object {
                bytes: response.body,
                etag: response
                    .etag
                    .filter(|e| !e.is_empty())
                    .ok_or(Error::Integrity)?,
            })),
            _ => Err(Error::Unavailable),
        }
    }
    fn put(&self, key: &str, bytes: &[u8], condition: &Condition) -> Result<()> {
        if bytes.len() > MAX_SNAPSHOT {
            return Err(Error::Integrity);
        }
        let (name, value) = match condition {
            Condition::Absent => ("if-none-match", "*"),
            Condition::Matches(etag) if !etag.is_empty() => ("if-match", etag.as_str()),
            _ => return Err(Error::Integrity),
        };
        let response = self.0.send(Request {
            method: "PUT",
            key: key.into(),
            headers: BTreeMap::from([
                (name.into(), value.into()),
                ("content-type".into(), "application/json".into()),
                ("cache-control".into(), "no-store".into()),
            ]),
            body: bytes.to_vec(),
        })?;
        match response.status {
            200 => Ok(()),
            412 => Err(Error::Conflict),
            _ => Err(Error::Unavailable),
        }
    }
}

/// Local Node SDK bridge, configured only by the operator. The child inherits
/// explicitly provisioned SIGNET_R2_* runtime variables; it never uses AWS profiles.
/// A deployment may replace this with an in-process SDK transport without changing CAS.
pub struct NodeBridge {
    node: std::path::PathBuf,
    script: std::path::PathBuf,
}
impl NodeBridge {
    pub fn new(node: std::path::PathBuf, script: std::path::PathBuf) -> Result<Self> {
        if !node.is_absolute() || !script.is_absolute() {
            return Err(Error::Integrity);
        }
        Ok(Self { node, script })
    }
}
impl Transport for NodeBridge {
    fn send(&self, request: Request) -> Result<Response> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        let mut child = Command::new(&self.node)
            .arg(&self.script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Error::Unavailable)?;
        let wire = serde_json::json!({"method":request.method,"key":request.key,"headers":request.headers,"body":STANDARD.encode(request.body)});
        let mut stdin = child.stdin.take().ok_or(Error::Unavailable)?;
        if stdin
            .write_all(&serde_json::to_vec(&wire).map_err(|_| Error::Integrity)?)
            .is_err()
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Unavailable);
        }
        drop(stdin);
        let output = child.wait_with_output().map_err(|_| Error::Unavailable)?;
        if !output.status.success() || output.stdout.len() > 12 * 1024 * 1024 {
            return Err(Error::Unavailable);
        }
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).map_err(|_| Error::Unavailable)?;
        let status = value["status"]
            .as_u64()
            .and_then(|s| u16::try_from(s).ok())
            .ok_or(Error::Unavailable)?;
        let body = STANDARD
            .decode(value["body"].as_str().ok_or(Error::Unavailable)?)
            .map_err(|_| Error::Unavailable)?;
        if body.len() > MAX_SNAPSHOT {
            return Err(Error::Integrity);
        }
        Ok(Response {
            status,
            etag: value["etag"].as_str().map(str::to_owned),
            body,
        })
    }
}
