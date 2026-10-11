//! Shared HTTP contract for SQLite and native JSON owner services.
use super::*;
pub trait OwnerApi: Send {
    fn origin(&self) -> &str;
    fn session(&mut self, existing: Option<&str>) -> Result<(String, Value)>;
    fn dashboard(&mut self, sid: &str, csrf: &str) -> Result<Value>;
    fn begin_enrollment(
        &mut self,
        sid: &str,
        csrf: &str,
        token: &str,
        label: String,
    ) -> Result<Value>;
    fn finish_registration(
        &mut self,
        sid: &str,
        csrf: &str,
        challenge: &str,
        response: &RegisterPublicKeyCredential,
    ) -> Result<Value>;
    fn begin_authentication(&mut self, sid: &str, csrf: &str, intent: OwnerIntent)
        -> Result<Value>;
    fn finish_authentication(
        &mut self,
        sid: &str,
        csrf: &str,
        challenge: &str,
        response: &PublicKeyCredential,
    ) -> Result<Value>;
    fn logout(&mut self, sid: &str, csrf: &str) -> Result<Value>;
    fn agent_request(&mut self, message: &SignedMessage) -> Result<Value>;
    fn rotate_session(&mut self, sid: &str) -> Result<String>;
    fn mcp(&mut self, input: &Value) -> Result<Option<Value>>;
}
impl OwnerApi for OwnerService {
    fn origin(&self) -> &str {
        OwnerService::origin(self)
    }
    fn session(&mut self, existing: Option<&str>) -> Result<(String, Value)> {
        OwnerService::session(self, existing)
    }
    fn dashboard(&mut self, sid: &str, csrf: &str) -> Result<Value> {
        OwnerService::dashboard(self, sid, csrf)
    }
    fn begin_enrollment(
        &mut self,
        sid: &str,
        csrf: &str,
        token: &str,
        label: String,
    ) -> Result<Value> {
        OwnerService::begin_enrollment(self, sid, csrf, token, label)
    }
    fn finish_registration(
        &mut self,
        sid: &str,
        csrf: &str,
        challenge: &str,
        response: &RegisterPublicKeyCredential,
    ) -> Result<Value> {
        OwnerService::finish_registration(self, sid, csrf, challenge, response)
    }
    fn begin_authentication(
        &mut self,
        sid: &str,
        csrf: &str,
        intent: OwnerIntent,
    ) -> Result<Value> {
        OwnerService::begin_authentication(self, sid, csrf, intent)
    }
    fn finish_authentication(
        &mut self,
        sid: &str,
        csrf: &str,
        challenge: &str,
        response: &PublicKeyCredential,
    ) -> Result<Value> {
        OwnerService::finish_authentication(self, sid, csrf, challenge, response)
    }
    fn logout(&mut self, sid: &str, csrf: &str) -> Result<Value> {
        OwnerService::logout(self, sid, csrf)
    }
    fn agent_request(&mut self, message: &SignedMessage) -> Result<Value> {
        OwnerService::agent_request(self, message)
    }
    fn rotate_session(&mut self, sid: &str) -> Result<String> {
        let old = self
            .sessions
            .remove(sid)
            .ok_or(AuthorityError::Rejected("session expired"))?;
        self.pending.retain(|_, p| p.session != sid);
        let new = id();
        self.sessions.insert(
            new.clone(),
            Session {
                csrf: id(),
                expires: now() + SESSION_TTL,
                authenticated_epoch: old.authenticated_epoch,
            },
        );
        Ok(new)
    }
    fn mcp(&mut self, input: &Value) -> Result<Option<Value>> {
        Ok(super::super::mcp::stateless(
            &mut self.authority,
            &input.to_string(),
        ))
    }
}
impl OwnerApi for native::NativeOwnerService {
    fn origin(&self) -> &str {
        native::NativeOwnerService::origin(self)
    }
    fn session(&mut self, existing: Option<&str>) -> Result<(String, Value)> {
        native::NativeOwnerService::session(self, existing)
    }
    fn dashboard(&mut self, sid: &str, csrf: &str) -> Result<Value> {
        native::NativeOwnerService::dashboard(self, sid, csrf)
    }
    fn begin_enrollment(
        &mut self,
        sid: &str,
        csrf: &str,
        token: &str,
        label: String,
    ) -> Result<Value> {
        native::NativeOwnerService::begin_enrollment(self, sid, csrf, token, label)
    }
    fn finish_registration(
        &mut self,
        sid: &str,
        csrf: &str,
        challenge: &str,
        response: &RegisterPublicKeyCredential,
    ) -> Result<Value> {
        native::NativeOwnerService::finish_registration(self, sid, csrf, challenge, response)
    }
    fn begin_authentication(
        &mut self,
        sid: &str,
        csrf: &str,
        intent: OwnerIntent,
    ) -> Result<Value> {
        native::NativeOwnerService::begin_authentication(self, sid, csrf, intent)
    }
    fn finish_authentication(
        &mut self,
        sid: &str,
        csrf: &str,
        challenge: &str,
        response: &PublicKeyCredential,
    ) -> Result<Value> {
        native::NativeOwnerService::finish_authentication(self, sid, csrf, challenge, response)
    }
    fn logout(&mut self, sid: &str, csrf: &str) -> Result<Value> {
        native::NativeOwnerService::logout(self, sid, csrf)
    }
    fn agent_request(&mut self, message: &SignedMessage) -> Result<Value> {
        native::NativeOwnerService::agent_request(self, message)
    }
    fn rotate_session(&mut self, sid: &str) -> Result<String> {
        self.rotate_session(sid)
    }
    fn mcp(&mut self, _input: &Value) -> Result<Option<Value>> {
        reject("native rings use signed /api/agent; legacy MCP is unavailable")
    }
}
