//! Connect native ring transitions directly to R2-compatible JSON storage, no SQL.
use super::*;
use crate::authority::object_store::{self, CommitOutcome, Store, Versioned};
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    #[error(transparent)]
    Persistence(#[from] object_store::Error),
}
pub struct Committed {
    pub outcome: CommitOutcome,
    pub output: Value,
    pub version: String,
}
/// Only CommittedNow may start newly reserved work. Recovered results require
/// reconciliation with the same execution ID, never another provider dispatch.
pub struct Service<S> {
    store: Versioned<S>,
}
impl<S: Store> Service<S> {
    pub fn new(store: S, user_hash: String) -> std::result::Result<Self, Error> {
        Ok(Self {
            store: Versioned::new(store, user_hash)?,
        })
    }
    /// Operator-only initialization. Missing live head is never silently initialized.
    pub fn initialize(&self, authority: &RingAuthority) -> std::result::Result<(), Error> {
        self.store.commit(&self.store.initialize(authority)?)?;
        Ok(())
    }
    pub fn owner(
        &self,
        message: &SignedMessage,
        time: i64,
    ) -> std::result::Result<Committed, Error> {
        self.transition(message, time, true)
    }
    pub fn request(
        &self,
        message: &SignedMessage,
        time: i64,
    ) -> std::result::Result<Committed, Error> {
        self.transition(message, time, false)
    }
    fn transition(
        &self,
        message: &SignedMessage,
        time: i64,
        owner: bool,
    ) -> std::result::Result<Committed, Error> {
        let current = self.store.load::<RingAuthority>()?;
        if let Some(output) = current.state.recovered(message, owner)? {
            return Ok(Committed {
                outcome: CommitOutcome::Recovered,
                output,
                version: current.version().into(),
            });
        }
        let mut next = current.state.clone();
        let output = if owner {
            next.approve(message, time)?
        } else {
            next.handle(message, time)?
        };
        let candidate = self.store.prepare(&current, &next)?;
        let outcome = self.store.commit(&candidate)?;
        Ok(Committed {
            outcome,
            output,
            version: candidate.version().into(),
        })
    }
}
