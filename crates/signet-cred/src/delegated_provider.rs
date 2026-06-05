//! Acceptance-only delegated-provider authorization boundary.
//!
//! This envelope is intentionally separate from Signet's generic financial
//! capability. It carries the exact credential-free scope needed by a
//! delegated provider executor such as Baton and has no issuance API here.

use std::collections::BTreeSet;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{CredError, CredErrorDetail, CredResult};

const DELEGATED_PROVIDER_V1_HEADER: &str = "signet.delegated-provider.v1.";
const MAX_DELEGATED_PROVIDER_ENVELOPE_BYTES: usize = 16 * 1024;
const MAX_SCOPE_ENTRIES: usize = 128;
const MAX_SCOPE_VALUE_BYTES: usize = 256;
const MAX_POLICY_REF_BYTES: usize = 512;

/// Provider channel names shared with Baton's delegated connector contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegatedProviderChannel {
    Sms,
    Email,
}

/// Exact signed claims for one delegated provider authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedProviderAuthorizationClaims {
    pub authorization_id: String,
    pub issuer: String,
    pub audience: String,
    pub workload_id: String,
    pub issued_at: String,
    pub not_before: String,
    pub not_after: String,
    pub channel: DelegatedProviderChannel,
    pub allowed_connector_ids: Vec<String>,
    pub allowed_purposes: Vec<String>,
    pub request_fingerprint: String,
    pub max_uses: u32,
    pub max_provider_attempts: u32,
}

/// Exact runtime and trust-policy context required for acceptance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedProviderAcceptanceContext {
    pub issuer: String,
    pub audience: String,
    pub workload_id: String,
    pub channel: DelegatedProviderChannel,
    pub available_connector_ids: Vec<String>,
    pub purpose: String,
    pub request_fingerprint: String,
    pub issuer_policy_ref: String,
    pub rotation_policy_ref: String,
}

/// Credential-free authorization outcome safe to map into Baton grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedDelegatedProviderAuthorization {
    pub authorization_id: String,
    pub issuer: String,
    pub audience: String,
    pub workload_id: String,
    pub issued_at: String,
    pub not_before: String,
    pub not_after: String,
    pub channel: DelegatedProviderChannel,
    pub allowed_connector_ids: Vec<String>,
    pub allowed_purposes: Vec<String>,
    pub request_fingerprint: String,
    pub max_uses: u32,
    pub max_provider_attempts: u32,
    pub issuer_policy_ref: String,
    pub rotation_policy_ref: String,
}

/// Trust-policy boundary responsible for issuer and rotation enforcement.
///
/// Implementations must treat all envelope claims as untrusted input and
/// accept the authenticator only under the supplied policy references.
pub trait DelegatedProviderTrustVerifier {
    fn verify(
        &self,
        issuer: &str,
        issuer_policy_ref: &str,
        rotation_policy_ref: &str,
        message: &[u8],
        authenticator: &[u8; 64],
    ) -> CredResult<()>;
}

/// Verify one delegated-provider envelope for an exact runtime context.
pub fn verify_delegated_provider_authorization(
    envelope: &str,
    trust_verifier: &dyn DelegatedProviderTrustVerifier,
    context: &DelegatedProviderAcceptanceContext,
) -> CredResult<VerifiedDelegatedProviderAuthorization> {
    verify_delegated_provider_authorization_at(envelope, trust_verifier, context, Utc::now())
}

fn verify_delegated_provider_authorization_at(
    envelope: &str,
    trust_verifier: &dyn DelegatedProviderTrustVerifier,
    context: &DelegatedProviderAcceptanceContext,
    now: DateTime<Utc>,
) -> CredResult<VerifiedDelegatedProviderAuthorization> {
    validate_acceptance_context(context)?;
    if envelope.len() > MAX_DELEGATED_PROVIDER_ENVELOPE_BYTES {
        return Err(decoding_error(
            "delegated-provider envelope exceeds the maximum accepted size",
        ));
    }
    if !envelope.starts_with(DELEGATED_PROVIDER_V1_HEADER) {
        return Err(decoding_error("invalid delegated-provider envelope header"));
    }

    let encoded_body = &envelope[DELEGATED_PROVIDER_V1_HEADER.len()..];
    let body = URL_SAFE_NO_PAD
        .decode(encoded_body)
        .map_err(|_| decoding_error("invalid delegated-provider base64url encoding"))?;
    if body.len() < 64 {
        return Err(decoding_error("delegated-provider envelope body too short"));
    }

    let payload = &body[..body.len() - 64];
    let authenticator: &[u8; 64] = body[body.len() - 64..]
        .try_into()
        .map_err(|_| invalid_delegated_provider_authenticator())?;
    let claims: DelegatedProviderAuthorizationClaims = serde_json::from_slice(payload)
        .map_err(|_| decoding_error("invalid delegated-provider claims JSON"))?;

    // Compare the untrusted issuer to the configured expectation before using
    // it as trust-policy lookup input.
    if claims.issuer != context.issuer {
        return Err(scope_error(
            "issuer mismatch",
            "delegated-provider issuer does not match expected issuer",
        ));
    }

    let mut message = Vec::with_capacity(DELEGATED_PROVIDER_V1_HEADER.len() + payload.len());
    message.extend_from_slice(DELEGATED_PROVIDER_V1_HEADER.as_bytes());
    message.extend_from_slice(payload);
    trust_verifier.verify(
        &context.issuer,
        &context.issuer_policy_ref,
        &context.rotation_policy_ref,
        &message,
        authenticator,
    )?;

    validate_claims(&claims, context, now)?;
    Ok(VerifiedDelegatedProviderAuthorization {
        authorization_id: claims.authorization_id,
        issuer: claims.issuer,
        audience: claims.audience,
        workload_id: claims.workload_id,
        issued_at: claims.issued_at,
        not_before: claims.not_before,
        not_after: claims.not_after,
        channel: claims.channel,
        allowed_connector_ids: claims.allowed_connector_ids,
        allowed_purposes: claims.allowed_purposes,
        request_fingerprint: claims.request_fingerprint,
        max_uses: claims.max_uses,
        max_provider_attempts: claims.max_provider_attempts,
        issuer_policy_ref: context.issuer_policy_ref.clone(),
        rotation_policy_ref: context.rotation_policy_ref.clone(),
    })
}

fn validate_acceptance_context(context: &DelegatedProviderAcceptanceContext) -> CredResult<()> {
    validate_required_text(&context.issuer, "expected issuer", MAX_SCOPE_VALUE_BYTES)?;
    validate_required_text(
        &context.audience,
        "expected audience",
        MAX_SCOPE_VALUE_BYTES,
    )?;
    validate_required_text(
        &context.workload_id,
        "expected workload",
        MAX_SCOPE_VALUE_BYTES,
    )?;
    validate_required_text(&context.purpose, "expected purpose", MAX_SCOPE_VALUE_BYTES)?;
    validate_required_text(
        &context.issuer_policy_ref,
        "issuer policy reference",
        MAX_POLICY_REF_BYTES,
    )?;
    validate_required_text(
        &context.rotation_policy_ref,
        "rotation policy reference",
        MAX_POLICY_REF_BYTES,
    )?;
    validate_scope_values(&context.available_connector_ids, "available connector IDs")?;
    validate_request_fingerprint(&context.request_fingerprint)?;
    Ok(())
}

fn validate_claims(
    claims: &DelegatedProviderAuthorizationClaims,
    context: &DelegatedProviderAcceptanceContext,
    now: DateTime<Utc>,
) -> CredResult<()> {
    validate_required_text(
        &claims.authorization_id,
        "authorization ID",
        MAX_SCOPE_VALUE_BYTES,
    )?;
    validate_required_text(&claims.issuer, "issuer", MAX_SCOPE_VALUE_BYTES)?;
    validate_required_text(&claims.audience, "audience", MAX_SCOPE_VALUE_BYTES)?;
    validate_required_text(&claims.workload_id, "workload ID", MAX_SCOPE_VALUE_BYTES)?;
    validate_scope_values(&claims.allowed_connector_ids, "allowed connector IDs")?;
    validate_scope_values(&claims.allowed_purposes, "allowed purposes")?;
    validate_request_fingerprint(&claims.request_fingerprint)?;

    if claims.audience != context.audience {
        return Err(scope_error(
            "audience mismatch",
            "delegated-provider audience does not match expected audience",
        ));
    }
    if claims.workload_id != context.workload_id {
        return Err(scope_error(
            "workload mismatch",
            "delegated-provider workload does not match expected workload",
        ));
    }
    if claims.channel != context.channel {
        return Err(scope_error(
            "channel mismatch",
            "delegated-provider channel does not match expected channel",
        ));
    }
    if claims.request_fingerprint != context.request_fingerprint {
        return Err(scope_error(
            "request fingerprint mismatch",
            "delegated-provider request fingerprint does not match expected request",
        ));
    }
    if !claims
        .allowed_connector_ids
        .iter()
        .all(|connector| context.available_connector_ids.contains(connector))
    {
        return Err(scope_error(
            "connector scope mismatch",
            "delegated-provider connector scope exceeds the available runtime policy",
        ));
    }
    if claims.allowed_purposes.len() != 1
        || claims.allowed_purposes.first().map(String::as_str) != Some(context.purpose.as_str())
    {
        return Err(scope_error(
            "purpose mismatch",
            "delegated-provider purpose does not exactly match expected purpose",
        ));
    }
    if claims.max_uses != 1 {
        return Err(scope_error(
            "invalid use budget",
            "delegated-provider authorization must be single-use",
        ));
    }
    if claims.max_provider_attempts == 0 {
        return Err(scope_error(
            "invalid provider-attempt budget",
            "delegated-provider attempt budget must be positive",
        ));
    }

    validate_time_window(claims, now)
}

fn validate_time_window(
    claims: &DelegatedProviderAuthorizationClaims,
    now: DateTime<Utc>,
) -> CredResult<()> {
    let issued_at = parse_time(&claims.issued_at, "issued-at")?;
    let not_before = parse_time(&claims.not_before, "not-before")?;
    let not_after = parse_time(&claims.not_after, "not-after")?;
    if issued_at > now {
        return Err(scope_error(
            "issued in the future",
            "delegated-provider authorization was issued in the future",
        ));
    }
    if not_before < issued_at || not_after <= not_before {
        return Err(scope_error(
            "invalid time window",
            "delegated-provider authorization has an inconsistent time window",
        ));
    }
    if now < not_before {
        return Err(scope_error(
            "not yet valid",
            "delegated-provider authorization is not yet valid",
        ));
    }
    if now >= not_after {
        return Err(CredErrorDetail::new(
            CredError::CredentialExpired,
            "delegated-provider authorization has expired",
        ));
    }
    Ok(())
}

fn parse_time(value: &str, name: &str) -> CredResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| decoding_error(&format!("invalid delegated-provider {name} timestamp")))
}

fn validate_scope_values(values: &[String], name: &str) -> CredResult<()> {
    if values.is_empty() || values.len() > MAX_SCOPE_ENTRIES {
        return Err(schema_error(
            name,
            "delegated-provider scope must contain a bounded non-empty set",
        ));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_required_text(value, name, MAX_SCOPE_VALUE_BYTES)?;
        if !seen.insert(value) {
            return Err(schema_error(
                name,
                "delegated-provider scope must not contain duplicates",
            ));
        }
    }
    Ok(())
}

fn validate_request_fingerprint(value: &str) -> CredResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(schema_error(
            "request fingerprint",
            "delegated-provider request fingerprint must be a lowercase SHA-256 digest",
        ));
    }
    Ok(())
}

fn validate_required_text(value: &str, name: &str, max_bytes: usize) -> CredResult<()> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(schema_error(
            name,
            "delegated-provider required text is empty or exceeds its size bound",
        ));
    }
    Ok(())
}

fn schema_error(field: &str, message: &str) -> CredErrorDetail {
    CredErrorDetail::new(CredError::SchemaViolation(field.into()), message)
}

fn scope_error(reason: &str, message: &str) -> CredErrorDetail {
    CredErrorDetail::new(CredError::InvalidDisclosurePolicy(reason.into()), message)
}

fn decoding_error(message: &str) -> CredErrorDetail {
    CredErrorDetail::new(CredError::DecodingFailed, message)
}

fn invalid_delegated_provider_authenticator() -> CredErrorDetail {
    CredErrorDetail::new(
        CredError::InvalidCapabilitySignature,
        "invalid delegated-provider authenticator",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AcceptingTrust;

    impl DelegatedProviderTrustVerifier for AcceptingTrust {
        fn verify(
            &self,
            issuer: &str,
            issuer_policy_ref: &str,
            rotation_policy_ref: &str,
            message: &[u8],
            _authenticator: &[u8; 64],
        ) -> CredResult<()> {
            if issuer == "signet://issuer/mea"
                && issuer_policy_ref == "signet://issuer-policy/mea-comms"
                && rotation_policy_ref == "signet://rotation-policy/mea-comms"
                && message.starts_with(DELEGATED_PROVIDER_V1_HEADER.as_bytes())
            {
                Ok(())
            } else {
                Err(invalid_delegated_provider_authenticator())
            }
        }
    }

    struct RejectingTrust;

    impl DelegatedProviderTrustVerifier for RejectingTrust {
        fn verify(
            &self,
            _issuer: &str,
            _issuer_policy_ref: &str,
            _rotation_policy_ref: &str,
            _message: &[u8],
            _authenticator: &[u8; 64],
        ) -> CredResult<()> {
            Err(invalid_delegated_provider_authenticator())
        }
    }

    fn claims() -> DelegatedProviderAuthorizationClaims {
        DelegatedProviderAuthorizationClaims {
            authorization_id: "authorization-1".into(),
            issuer: "signet://issuer/mea".into(),
            audience: "baton://delegated-provider-executor".into(),
            workload_id: "mea-comms".into(),
            issued_at: "2026-06-04T22:00:00+00:00".into(),
            not_before: "2026-06-04T22:00:00+00:00".into(),
            not_after: "2026-06-04T22:10:00+00:00".into(),
            channel: DelegatedProviderChannel::Sms,
            allowed_connector_ids: vec!["sms-primary".into(), "sms-backup".into()],
            allowed_purposes: vec!["case_notification".into()],
            request_fingerprint: "a".repeat(64),
            max_uses: 1,
            max_provider_attempts: 2,
        }
    }

    fn context() -> DelegatedProviderAcceptanceContext {
        DelegatedProviderAcceptanceContext {
            issuer: "signet://issuer/mea".into(),
            audience: "baton://delegated-provider-executor".into(),
            workload_id: "mea-comms".into(),
            channel: DelegatedProviderChannel::Sms,
            available_connector_ids: vec!["sms-primary".into(), "sms-backup".into()],
            purpose: "case_notification".into(),
            request_fingerprint: "a".repeat(64),
            issuer_policy_ref: "signet://issuer-policy/mea-comms".into(),
            rotation_policy_ref: "signet://rotation-policy/mea-comms".into(),
        }
    }

    fn envelope(claims: &DelegatedProviderAuthorizationClaims) -> String {
        let mut body = serde_json::to_vec(claims).unwrap();
        body.extend_from_slice(&[0u8; 64]);
        format!(
            "{}{}",
            DELEGATED_PROVIDER_V1_HEADER,
            URL_SAFE_NO_PAD.encode(body)
        )
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-04T22:05:00+00:00")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn accepts_exact_scope_into_verified_outcome() {
        let verified = verify_delegated_provider_authorization_at(
            &envelope(&claims()),
            &AcceptingTrust,
            &context(),
            now(),
        )
        .unwrap();

        assert_eq!(verified.authorization_id, "authorization-1");
        assert_eq!(verified.workload_id, "mea-comms");
        assert_eq!(verified.allowed_connector_ids.len(), 2);
        assert_eq!(verified.max_uses, 1);
        assert_eq!(verified.max_provider_attempts, 2);
        assert_eq!(
            verified.issuer_policy_ref,
            "signet://issuer-policy/mea-comms"
        );
        assert_eq!(
            verified.rotation_policy_ref,
            "signet://rotation-policy/mea-comms"
        );
    }

    #[test]
    fn accepts_connector_scope_narrower_than_runtime_ceiling() {
        let mut narrowed = claims();
        narrowed.allowed_connector_ids = vec!["sms-primary".into()];

        let verified = verify_delegated_provider_authorization_at(
            &envelope(&narrowed),
            &AcceptingTrust,
            &context(),
            now(),
        )
        .unwrap();

        assert_eq!(verified.allowed_connector_ids, vec!["sms-primary"]);
    }

    #[test]
    fn rejects_unaccepted_authenticator() {
        let result = verify_delegated_provider_authorization_at(
            &envelope(&claims()),
            &RejectingTrust,
            &context(),
            now(),
        );

        assert!(matches!(
            result.unwrap_err().kind,
            CredError::InvalidCapabilitySignature
        ));
    }

    #[test]
    fn rejects_rebound_runtime_scope() {
        let mut wrong_audience = context();
        wrong_audience.audience = "baton://other-executor".into();
        assert!(verify_delegated_provider_authorization_at(
            &envelope(&claims()),
            &AcceptingTrust,
            &wrong_audience,
            now(),
        )
        .is_err());

        let mut wrong_workload = context();
        wrong_workload.workload_id = "other-workload".into();
        assert!(verify_delegated_provider_authorization_at(
            &envelope(&claims()),
            &AcceptingTrust,
            &wrong_workload,
            now(),
        )
        .is_err());

        let mut wrong_channel = context();
        wrong_channel.channel = DelegatedProviderChannel::Email;
        assert!(verify_delegated_provider_authorization_at(
            &envelope(&claims()),
            &AcceptingTrust,
            &wrong_channel,
            now(),
        )
        .is_err());

        let mut unavailable_connector = claims();
        unavailable_connector
            .allowed_connector_ids
            .push("sms-unapproved".into());
        assert!(verify_delegated_provider_authorization_at(
            &envelope(&unavailable_connector),
            &AcceptingTrust,
            &context(),
            now(),
        )
        .is_err());

        let mut wrong_purpose = context();
        wrong_purpose.purpose = "other_purpose".into();
        assert!(verify_delegated_provider_authorization_at(
            &envelope(&claims()),
            &AcceptingTrust,
            &wrong_purpose,
            now(),
        )
        .is_err());

        let mut extra_purpose = claims();
        extra_purpose.allowed_purposes.push("other_purpose".into());
        assert!(verify_delegated_provider_authorization_at(
            &envelope(&extra_purpose),
            &AcceptingTrust,
            &context(),
            now(),
        )
        .is_err());

        let mut wrong_fingerprint = context();
        wrong_fingerprint.request_fingerprint = "b".repeat(64);
        assert!(verify_delegated_provider_authorization_at(
            &envelope(&claims()),
            &AcceptingTrust,
            &wrong_fingerprint,
            now(),
        )
        .is_err());
    }

    #[test]
    fn rejects_invalid_time_use_and_attempt_budgets() {
        let mut future = claims();
        future.not_before = "2026-06-04T22:06:00+00:00".into();
        assert!(verify_delegated_provider_authorization_at(
            &envelope(&future),
            &AcceptingTrust,
            &context(),
            now(),
        )
        .is_err());

        let mut reusable = claims();
        reusable.max_uses = 2;
        assert!(verify_delegated_provider_authorization_at(
            &envelope(&reusable),
            &AcceptingTrust,
            &context(),
            now(),
        )
        .is_err());

        let mut no_attempts = claims();
        no_attempts.max_provider_attempts = 0;
        assert!(verify_delegated_provider_authorization_at(
            &envelope(&no_attempts),
            &AcceptingTrust,
            &context(),
            now(),
        )
        .is_err());
    }

    #[test]
    fn rejects_duplicate_scope_and_oversized_envelope() {
        let mut duplicate = claims();
        duplicate.allowed_connector_ids.push("sms-primary".into());
        assert!(verify_delegated_provider_authorization_at(
            &envelope(&duplicate),
            &AcceptingTrust,
            &context(),
            now(),
        )
        .is_err());

        let oversized = format!(
            "{}{}",
            DELEGATED_PROVIDER_V1_HEADER,
            "x".repeat(MAX_DELEGATED_PROVIDER_ENVELOPE_BYTES)
        );
        assert!(verify_delegated_provider_authorization_at(
            &oversized,
            &AcceptingTrust,
            &context(),
            now(),
        )
        .is_err());
    }
}
