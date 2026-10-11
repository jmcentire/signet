//! Native JSON snapshot persistence. Only a successful conditional head update commits.
//! This is a storage boundary, not authentication or a policy engine. Callers must
//! validate the complete command against freshly loaded state before preparing it.
//! No callback is retried and no signing/provider operation runs inside this module.
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub mod r2;
pub mod retention;
#[cfg(test)]
mod tests;
const MAX_SNAPSHOT: usize = 8 * 1024 * 1024;
const MAX_RECOVERY_DEPTH: usize = 1024;
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("object write precondition failed")]
    Conflict,
    #[error("object operation outcome unknown; reload and recover before acting")]
    Unavailable,
    #[error("object integrity, scope, schema or size invalid")]
    Integrity,
    #[error("authority object missing; explicit operator bootstrap required")]
    Missing,
}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, Clone)]
pub struct Object {
    pub bytes: Vec<u8>,
    /// Opaque value supplied by the storage service, not a client-computed hash.
    pub etag: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    Absent,
    Matches(String),
}
/// Implementations MUST provide strongly consistent uncached reads and atomic PUT
/// preconditions. A timeout must return Unavailable, never an assumed success.
/// There is deliberately no unconditional write, delete, or list API.
pub trait Store: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Object>>;
    fn put(&self, key: &str, bytes: &[u8], condition: &Condition) -> Result<()>;
}
impl<T: Store + ?Sized> Store for Box<T> {
    fn get(&self, key: &str) -> Result<Option<Object>> {
        (**self).get(key)
    }
    fn put(&self, key: &str, bytes: &[u8], condition: &Condition) -> Result<()> {
        (**self).put(key, bytes, condition)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Pointer {
    version: String,
    revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    schema: u32,
    user_hash: String,
    current: Pointer,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot<T> {
    schema: u32,
    user_hash: String,
    revision: u64,
    previous: Option<Pointer>,
    state: T,
}
/// A read is never authorization by itself. The ETag is private to commit preparation.
pub struct Loaded<T> {
    user_hash: String,
    pub state: T,
    pointer: Pointer,
    etag: String,
}
impl<T> Loaded<T> {
    pub fn revision(&self) -> u64 {
        self.pointer.revision
    }
    pub fn version(&self) -> &str {
        &self.pointer.version
    }
}
/// Keep this receipt until success or definitive conflict. It contains private state
/// and must not be logged or placed in an agent/device cache.
pub struct Candidate {
    user_hash: String,
    pointer: Pointer,
    snapshot: Vec<u8>,
    condition: Condition,
}
impl Candidate {
    pub fn version(&self) -> &str {
        &self.pointer.version
    }
    pub fn revision(&self) -> u64 {
        self.pointer.revision
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum CommitOutcome {
    /// This caller won the head CAS. Dispatch still requires a durable reservation.
    CommittedNow,
    /// Already committed, possibly by another worker. Reconcile; do not dispatch again.
    Recovered,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Recovery {
    Committed,
    NotCommitted,
}
pub struct Versioned<S> {
    store: S,
    user_hash: String,
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn valid_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(value).map_err(|_| Error::Integrity)?;
    fn canonical(value: &mut serde_json::Value) -> Result<()> {
        match value {
            serde_json::Value::Number(n) if !n.is_i64() && !n.is_u64() => {
                return Err(Error::Integrity)
            }
            serde_json::Value::Array(a) => {
                for v in a {
                    canonical(v)?;
                }
            }
            serde_json::Value::Object(o) => {
                for v in o.values_mut() {
                    canonical(v)?;
                }
                o.sort_keys();
            }
            _ => {}
        }
        Ok(())
    }
    canonical(&mut value)?;
    let bytes = serde_json::to_vec(&value).map_err(|_| Error::Integrity)?;
    if bytes.len() > MAX_SNAPSHOT {
        return Err(Error::Integrity);
    }
    Ok(bytes)
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_SNAPSHOT {
        return Err(Error::Integrity);
    }
    serde_json::from_slice(bytes).map_err(|_| Error::Integrity)
}
impl<S: Store> Versioned<S> {
    /// user_hash is an opaque index provisioned by trusted routing, not authorization.
    pub fn new(store: S, user_hash: String) -> Result<Self> {
        if !valid_hex(&user_hash) {
            return Err(Error::Integrity);
        }
        Ok(Self { store, user_hash })
    }
    fn head_key(&self) -> String {
        format!("{}.head.json", self.user_hash)
    }
    fn version_key(&self, version: &str) -> String {
        format!("{}.{}.json", self.user_hash, version)
    }
    fn head(&self) -> Result<Option<(Head, String)>> {
        let Some(object) = self.store.get(&self.head_key())? else {
            return Ok(None);
        };
        let head: Head = decode(&object.bytes)?;
        if head.schema != 1
            || head.user_hash != self.user_hash
            || object.etag.is_empty()
            || !valid_hex(&head.current.version)
        {
            return Err(Error::Integrity);
        }
        Ok(Some((head, object.etag)))
    }
    fn snapshot<T: DeserializeOwned>(&self, pointer: &Pointer) -> Result<Snapshot<T>> {
        if !valid_hex(&pointer.version) {
            return Err(Error::Integrity);
        }
        let object = self
            .store
            .get(&self.version_key(&pointer.version))?
            .ok_or(Error::Integrity)?;
        if hash(&object.bytes) != pointer.version {
            return Err(Error::Integrity);
        }
        let snapshot: Snapshot<T> = decode(&object.bytes)?;
        if snapshot.schema != 1
            || snapshot.user_hash != self.user_hash
            || snapshot.revision != pointer.revision
            || match &snapshot.previous {
                Some(parent) => {
                    parent.revision.checked_add(1) != Some(snapshot.revision)
                        || !valid_hex(&parent.version)
                }
                None => snapshot.revision != 0,
            }
        {
            return Err(Error::Integrity);
        }
        Ok(snapshot)
    }
    pub fn load<T: DeserializeOwned>(&self) -> Result<Loaded<T>> {
        let (head, etag) = self.head()?.ok_or(Error::Missing)?;
        let snapshot = self.snapshot(&head.current)?;
        Ok(Loaded {
            user_hash: self.user_hash.clone(),
            state: snapshot.state,
            pointer: head.current,
            etag,
        })
    }
    /// Historical read, deliberately not Loaded: it cannot be passed as a commit
    /// base. A selected old policy must be proposed against a fresh current read.
    pub fn read_version<T: DeserializeOwned>(&self, version: &str) -> Result<T> {
        if !valid_hex(version) {
            return Err(Error::Integrity);
        }
        let object = self
            .store
            .get(&self.version_key(version))?
            .ok_or(Error::Missing)?;
        if hash(&object.bytes) != version {
            return Err(Error::Integrity);
        }
        let value: Snapshot<T> = decode(&object.bytes)?;
        if value.schema != 1 || value.user_hash != self.user_hash {
            return Err(Error::Integrity);
        }
        Ok(value.state)
    }
    /// Explicit bootstrap only. Never call in response to a missing live object.
    pub fn initialize<T: Serialize>(&self, state: &T) -> Result<Candidate> {
        self.prepare_inner(state, None, Condition::Absent)
    }
    /// Supply the COMPLETE new aggregate, including consumed nonces, grant states,
    /// reservations, issuance intents, credentials/epoch, rules and audit outbox.
    pub fn prepare<T: Serialize, U>(&self, base: &Loaded<U>, state: &T) -> Result<Candidate> {
        if base.user_hash != self.user_hash {
            return Err(Error::Integrity);
        }
        self.prepare_inner(
            state,
            Some(base.pointer.clone()),
            Condition::Matches(base.etag.clone()),
        )
    }
    fn prepare_inner<T: Serialize>(
        &self,
        state: &T,
        previous: Option<Pointer>,
        condition: Condition,
    ) -> Result<Candidate> {
        let revision = match &previous {
            Some(p) => p.revision.checked_add(1).ok_or(Error::Integrity)?,
            None => 0,
        };
        let snapshot = encode(&Snapshot {
            schema: 1,
            user_hash: self.user_hash.clone(),
            revision,
            previous,
            state,
        })?;
        Ok(Candidate {
            user_hash: self.user_hash.clone(),
            pointer: Pointer {
                version: hash(&snapshot),
                revision,
            },
            snapshot,
            condition,
        })
    }
    /// Persist candidate first, then commit the head with its original precondition.
    /// Return to the owner/executor ONLY after this succeeds. A Conflict requires
    /// fresh read + complete revalidation; never substitute a newer ETag here.
    pub fn commit(&self, candidate: &Candidate) -> Result<CommitOutcome> {
        if candidate.user_hash != self.user_hash {
            return Err(Error::Integrity);
        }
        let key = self.version_key(&candidate.pointer.version);
        match self
            .store
            .put(&key, &candidate.snapshot, &Condition::Absent)
        {
            Ok(()) => {}
            Err(Error::Conflict) => {
                let existing = self.store.get(&key)?.ok_or(Error::Integrity)?;
                if existing.bytes != candidate.snapshot {
                    return Err(Error::Integrity);
                }
            }
            Err(error) => return Err(error),
        }
        let head = encode(&Head {
            schema: 1,
            user_hash: self.user_hash.clone(),
            current: candidate.pointer.clone(),
        })?;
        match self
            .store
            .put(&self.head_key(), &head, &candidate.condition)
        {
            Ok(()) => Ok(CommitOutcome::CommittedNow),
            Err(Error::Conflict) => match self.recover(candidate)? {
                Recovery::Committed => Ok(CommitOutcome::Recovered),
                Recovery::NotCommitted => Err(Error::Conflict),
            },
            Err(error) => Err(error),
        }
    }
    /// Resolve a lost head response, even if another commit has since advanced it.
    /// Follow only head-reachable immutable parents, never bucket listings. Deep
    /// history beyond the bound is Unavailable, not permission to execute again.
    pub fn recover(&self, candidate: &Candidate) -> Result<Recovery> {
        if candidate.user_hash != self.user_hash {
            return Err(Error::Integrity);
        }
        let Some((head, _)) = self.head()? else {
            return Ok(Recovery::NotCommitted);
        };
        let mut pointer = head.current;
        for _ in 0..MAX_RECOVERY_DEPTH {
            let snapshot: Snapshot<serde_json::Value> = self.snapshot(&pointer)?;
            if pointer.revision < candidate.pointer.revision {
                return Ok(Recovery::NotCommitted);
            }
            if pointer.revision == candidate.pointer.revision {
                return Ok(if pointer == candidate.pointer {
                    Recovery::Committed
                } else {
                    Recovery::NotCommitted
                });
            }
            let Some(parent) = snapshot.previous else {
                return Ok(Recovery::NotCommitted);
            };
            pointer = parent;
        }
        Err(Error::Unavailable)
    }
}
