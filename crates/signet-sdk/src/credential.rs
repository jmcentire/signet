//! Credential parsing logic.
//!
//! The `parse_credential` function decodes and validates an SD-JWT or BBS+
//! credential token, extracting the embedded claim without exposing the
//! underlying raw data.
//!
//! Token format:
//! - Signet tokens: base64(JSON(CredentialTokenBody))
//! - SD-JWT tokens: header.payload.signature~disclosure1~disclosure2~...
//!
//! The function detects the format automatically and extracts claims accordingly.

use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL};
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::error::{SdkError, SdkErrorKind, SdkResult};
use crate::types::{Claim, CredentialResult, CredentialTokenBody, ParsedCredential, ProofFormat};

/// Parses and validates a credential token string.
///
/// This is one of the four SDK primitives. It is idempotent and performs
/// self-contained parsing without vault access.
///
/// Supports two token formats:
/// - **Signet native**: base64-encoded JSON with binding integrity check.
/// - **SD-JWT**: dot-separated JWT with `~`-separated disclosures.
///
/// # Preconditions
/// - Token should be a valid SD-JWT or Signet credential format.
///
/// # Returns
/// A `CredentialResult` containing the parsed claim on success.
pub fn parse_credential(token: &str) -> SdkResult<CredentialResult> {
    tracing::debug!(token_len = token.len(), "parsing credential token");

    if token.is_empty() {
        tracing::warn!("credential parse rejected: empty token");
        return Ok(CredentialResult::failure(
            SdkErrorKind::CredentialParseError,
        ));
    }

    // Try SD-JWT format first (contains '~' and '.' separators)
    if looks_like_sd_jwt(token) {
        return parse_sd_jwt_credential(token);
    }

    // Try Signet native format (base64-encoded JSON)
    parse_signet_credential(token)
}

/// Check if a token string looks like an SD-JWT.
fn looks_like_sd_jwt(token: &str) -> bool {
    token.contains('~') && token.contains('.')
}

/// Parse an SD-JWT credential token.
///
/// SD-JWT format: <issuer-jwt>~<disclosure1>~<disclosure2>~...~[<kb-jwt>]
/// Each JWT segment is: header.payload.signature (base64url-encoded).
fn parse_sd_jwt_credential(token: &str) -> SdkResult<CredentialResult> {
    tracing::debug!("attempting SD-JWT parse");

    // Split on '~' to get the issuer JWT and disclosures
    let parts: Vec<&str> = token.split('~').collect();
    if parts.is_empty() {
        return Ok(CredentialResult::failure(
            SdkErrorKind::CredentialParseError,
        ));
    }

    let issuer_jwt = parts[0];

    // The issuer JWT should have three dot-separated segments
    let jwt_segments: Vec<&str> = issuer_jwt.split('.').collect();
    if jwt_segments.len() != 3 {
        tracing::warn!(
            segments = jwt_segments.len(),
            "SD-JWT issuer token has wrong number of segments"
        );
        return Ok(CredentialResult::failure(
            SdkErrorKind::CredentialParseError,
        ));
    }

    // Decode the payload (second segment)
    let payload_bytes = BASE64URL.decode(jwt_segments[1]).map_err(|e| {
        tracing::warn!(error = %e, "failed to decode SD-JWT payload");
        SdkError::CredentialParseError(format!("invalid base64url payload: {e}"))
    })?;

    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).map_err(|e| {
        tracing::warn!(error = %e, "failed to parse SD-JWT payload JSON");
        SdkError::CredentialParseError(format!("invalid JSON payload: {e}"))
    })?;

    // Extract claim from the SD-JWT payload.
    // We look for common SD-JWT claim patterns:
    // - "claim" object with "attribute" and "value"
    // - "sub" (subject) as the attribute, other fields as value
    // - "_sd" array for selective disclosure claims
    let (attribute, value) = extract_sd_jwt_claim(&payload)?;

    // Extract optional fields
    let issuer = payload
        .get("iss")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let expires_at = payload.get("exp").and_then(|v| v.as_u64());

    // Count disclosures (non-empty parts after the issuer JWT)
    let disclosure_count = parts[1..].iter().filter(|p| !p.is_empty()).count();
    tracing::debug!(disclosures = disclosure_count, "SD-JWT disclosures found");

    let credential = ParsedCredential {
        claim: Claim::new(attribute, value),
        format: ProofFormat::SdJwt,
        issuer,
        expires_at,
    };

    tracing::info!(
        attribute = %credential.claim.attribute,
        "SD-JWT credential parsed successfully"
    );

    Ok(CredentialResult::success(credential))
}

/// Extract a claim (attribute, value) from an SD-JWT payload.
fn extract_sd_jwt_claim(payload: &serde_json::Value) -> SdkResult<(String, serde_json::Value)> {
    // Pattern 1: explicit "claim" object
    if let Some(claim_obj) = payload.get("claim") {
        if let (Some(attr), Some(val)) = (
            claim_obj.get("attribute").and_then(|v| v.as_str()),
            claim_obj.get("value"),
        ) {
            return Ok((attr.to_string(), val.clone()));
        }
    }

    // Pattern 2: "sub" field as attribute with "value" field
    if let Some(sub) = payload.get("sub").and_then(|v| v.as_str()) {
        if let Some(val) = payload.get("value") {
            return Ok((sub.to_string(), val.clone()));
        }
        // If there's a "sub" but no "value", use the entire payload minus standard JWT fields
        let mut claim_data = payload.clone();
        if let Some(obj) = claim_data.as_object_mut() {
            obj.remove("iss");
            obj.remove("sub");
            obj.remove("aud");
            obj.remove("exp");
            obj.remove("nbf");
            obj.remove("iat");
            obj.remove("jti");
            obj.remove("_sd");
            obj.remove("_sd_alg");
            obj.remove("cnf");
        }
        return Ok((sub.to_string(), claim_data));
    }

    // Pattern 3: "_sd" selective disclosure - extract first available claim
    if let Some(sd_array) = payload.get("_sd").and_then(|v| v.as_array()) {
        if !sd_array.is_empty() {
            // We can't decode _sd hashes without the disclosures, but we note
            // the presence of selective disclosure claims.
            return Ok((
                "_sd".to_string(),
                serde_json::Value::Number(serde_json::Number::from(sd_array.len())),
            ));
        }
    }

    // Fallback: use the first non-standard field as the claim
    if let Some(obj) = payload.as_object() {
        let standard_fields = [
            "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "_sd", "_sd_alg", "cnf",
        ];
        for (key, value) in obj {
            if !standard_fields.contains(&key.as_str()) {
                return Ok((key.clone(), value.clone()));
            }
        }
    }

    Err(SdkError::CredentialParseError(
        "no extractable claim found in SD-JWT payload".into(),
    ))
}

/// Parse a Signet native credential token (base64-encoded JSON).
fn parse_signet_credential(token: &str) -> SdkResult<CredentialResult> {
    tracing::debug!("attempting Signet native credential parse");

    let bytes = match BASE64.decode(token) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "failed to decode credential token base64");
            return Ok(CredentialResult::failure(
                SdkErrorKind::CredentialParseError,
            ));
        }
    };

    let body: CredentialTokenBody = match serde_json::from_slice(&bytes) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "failed to parse credential token JSON");
            return Ok(CredentialResult::failure(
                SdkErrorKind::CredentialParseError,
            ));
        }
    };

    // Verify version
    if body.version != 1 {
        tracing::warn!(
            version = body.version,
            "unsupported credential token version"
        );
        return Ok(CredentialResult::failure(
            SdkErrorKind::CredentialParseError,
        ));
    }

    // Verify the integrity binding
    let expected_binding = compute_credential_binding(
        &body.attribute,
        &body.value,
        body.issuer.as_deref(),
        body.expires_at,
    );

    if body.binding != expected_binding {
        tracing::warn!("credential token binding mismatch");
        return Ok(CredentialResult::failure(
            SdkErrorKind::CredentialParseError,
        ));
    }

    // Validate the attribute is non-empty
    if body.attribute.is_empty() {
        tracing::warn!("credential token has empty attribute");
        return Ok(CredentialResult::failure(
            SdkErrorKind::CredentialParseError,
        ));
    }

    let credential = ParsedCredential {
        claim: Claim::new(&body.attribute, body.value),
        format: body.format,
        issuer: body.issuer,
        expires_at: body.expires_at,
    };

    tracing::info!(
        attribute = %credential.claim.attribute,
        format = %credential.format,
        "Signet credential parsed successfully"
    );

    Ok(CredentialResult::success(credential))
}

/// Compute the integrity binding for a credential token.
pub(crate) fn compute_credential_binding(
    attribute: &str,
    value: &serde_json::Value,
    issuer: Option<&str>,
    expires_at: Option<u64>,
) -> String {
    let value_str = serde_json::to_string(value).unwrap_or_default();
    let issuer_str = issuer.unwrap_or("");
    let exp_str = expires_at.map(|e| e.to_string()).unwrap_or_default();

    let mut hasher = Sha256::new();
    hasher.update(attribute.as_bytes());
    hasher.update(b"\0");
    hasher.update(value_str.as_bytes());
    hasher.update(b"\0");
    hasher.update(issuer_str.as_bytes());
    hasher.update(b"\0");
    hasher.update(exp_str.as_bytes());

    hex::encode(hasher.finalize())
}

/// Create a Signet native credential token from components.
///
/// This is a convenience function for producing tokens that `parse_credential`
/// can later validate.
#[allow(dead_code)]
pub(crate) fn create_credential_token(
    format: ProofFormat,
    attribute: &str,
    value: &serde_json::Value,
    issuer: Option<&str>,
    expires_at: Option<u64>,
) -> String {
    let binding = compute_credential_binding(attribute, value, issuer, expires_at);

    let body = CredentialTokenBody {
        version: 1,
        format,
        attribute: attribute.to_string(),
        value: value.clone(),
        issuer: issuer.map(|s| s.to_string()),
        expires_at,
        binding,
    };

    let json = serde_json::to_vec(&body).expect("credential body serialization should not fail");
    BASE64.encode(&json)
}

/// Create a minimal SD-JWT credential token for testing/demonstration.
///
/// Produces: `<base64url(header)>.<base64url(payload)>.<signature>~`
#[allow(dead_code)]
pub(crate) fn create_sd_jwt_token(
    attribute: &str,
    value: &serde_json::Value,
    issuer: Option<&str>,
    expires_at: Option<u64>,
) -> String {
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "sd+jwt"
    });
    let header_b64 = BASE64URL.encode(serde_json::to_vec(&header).unwrap());

    let mut payload = serde_json::json!({
        "claim": {
            "attribute": attribute,
            "value": value
        }
    });
    if let Some(iss) = issuer {
        payload["iss"] = serde_json::Value::String(iss.to_string());
    }
    if let Some(exp) = expires_at {
        payload["exp"] = serde_json::Value::Number(serde_json::Number::from(exp));
    }
    let payload_b64 = BASE64URL.encode(serde_json::to_vec(&payload).unwrap());

    // Fake signature (would be a real ECDSA signature in production)
    let sig_b64 = BASE64URL.encode(b"fake-signature-placeholder");

    format!("{}.{}.{}~", header_b64, payload_b64, sig_b64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_signet_credential_success() {
        let token = create_credential_token(
            ProofFormat::BbsPlus,
            "age_over_21",
            &serde_json::Value::Bool(true),
            Some("issuer123"),
            Some(1_700_000_000),
        );
        let result = parse_credential(&token).unwrap();
        assert!(result.error.is_none());
        let cred = result.credential.unwrap();
        assert_eq!(cred.claim.attribute, "age_over_21");
        assert_eq!(cred.claim.value, serde_json::Value::Bool(true));
        assert_eq!(cred.format, ProofFormat::BbsPlus);
        assert_eq!(cred.issuer.as_deref(), Some("issuer123"));
        assert_eq!(cred.expires_at, Some(1_700_000_000));
    }

    #[test]
    fn test_parse_signet_credential_no_issuer() {
        let token = create_credential_token(
            ProofFormat::SdJwt,
            "country",
            &serde_json::json!("US"),
            None,
            None,
        );
        let result = parse_credential(&token).unwrap();
        let cred = result.credential.unwrap();
        assert!(cred.issuer.is_none());
        assert!(cred.expires_at.is_none());
    }

    #[test]
    fn test_parse_empty_token() {
        let result = parse_credential("").unwrap();
        assert!(result.credential.is_none());
        assert_eq!(result.error, Some(SdkErrorKind::CredentialParseError));
    }

    #[test]
    fn test_parse_garbage_token() {
        let result = parse_credential("not-a-valid-token-at-all").unwrap();
        assert!(result.credential.is_none());
        assert_eq!(result.error, Some(SdkErrorKind::CredentialParseError));
    }

    #[test]
    fn test_parse_tampered_signet_token() {
        let token = create_credential_token(
            ProofFormat::SdJwt,
            "age_over_21",
            &serde_json::Value::Bool(true),
            None,
            None,
        );
        // Decode, tamper, re-encode
        let bytes = BASE64.decode(&token).unwrap();
        let mut body: CredentialTokenBody = serde_json::from_slice(&bytes).unwrap();
        body.attribute = "country".into(); // tamper
        let tampered = BASE64.encode(serde_json::to_vec(&body).unwrap());

        let result = parse_credential(&tampered).unwrap();
        assert!(result.credential.is_none());
        assert_eq!(result.error, Some(SdkErrorKind::CredentialParseError));
    }

    #[test]
    fn test_parse_bad_version() {
        let token = create_credential_token(
            ProofFormat::SdJwt,
            "test",
            &serde_json::Value::Bool(true),
            None,
            None,
        );
        let bytes = BASE64.decode(&token).unwrap();
        let mut body: CredentialTokenBody = serde_json::from_slice(&bytes).unwrap();
        body.version = 99;
        // Recompute binding won't help since version isn't in binding
        let tampered = BASE64.encode(serde_json::to_vec(&body).unwrap());

        let result = parse_credential(&tampered).unwrap();
        assert!(result.credential.is_none());
        assert_eq!(result.error, Some(SdkErrorKind::CredentialParseError));
    }

    #[test]
    fn test_parse_empty_attribute() {
        // Create a token with empty attribute (bypass create_credential_token)
        let binding = compute_credential_binding("", &serde_json::Value::Bool(true), None, None);
        let body = CredentialTokenBody {
            version: 1,
            format: ProofFormat::SdJwt,
            attribute: "".into(),
            value: serde_json::Value::Bool(true),
            issuer: None,
            expires_at: None,
            binding,
        };
        let token = BASE64.encode(serde_json::to_vec(&body).unwrap());

        let result = parse_credential(&token).unwrap();
        assert!(result.credential.is_none());
        assert_eq!(result.error, Some(SdkErrorKind::CredentialParseError));
    }

    #[test]
    fn test_parse_sd_jwt_with_claim_object() {
        let token = create_sd_jwt_token(
            "email_verified",
            &serde_json::Value::Bool(true),
            Some("auth.example.com"),
            Some(1_800_000_000),
        );
        let result = parse_credential(&token).unwrap();
        let cred = result.credential.unwrap();
        assert_eq!(cred.claim.attribute, "email_verified");
        assert_eq!(cred.claim.value, serde_json::Value::Bool(true));
        assert_eq!(cred.format, ProofFormat::SdJwt);
        assert_eq!(cred.issuer.as_deref(), Some("auth.example.com"));
        assert_eq!(cred.expires_at, Some(1_800_000_000));
    }

    #[test]
    fn test_parse_sd_jwt_with_sub_pattern() {
        // Create an SD-JWT with "sub" and "value" fields
        let header = serde_json::json!({"alg": "ES256", "typ": "sd+jwt"});
        let payload = serde_json::json!({
            "sub": "age_over_21",
            "value": true,
            "iss": "vault.signet.local"
        });
        let header_b64 = BASE64URL.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = BASE64URL.encode(serde_json::to_vec(&payload).unwrap());
        let sig_b64 = BASE64URL.encode(b"sig");
        let token = format!("{}.{}.{}~", header_b64, payload_b64, sig_b64);

        let result = parse_credential(&token).unwrap();
        let cred = result.credential.unwrap();
        assert_eq!(cred.claim.attribute, "age_over_21");
        assert_eq!(cred.claim.value, serde_json::Value::Bool(true));
    }

    #[test]
    fn test_parse_sd_jwt_malformed() {
        // Missing segments
        let token = "abc~def~";
        let result = parse_credential(token);
        // Should fail parsing since the JWT part doesn't have 3 segments
        let r = result.unwrap();
        assert!(r.credential.is_none());
        assert_eq!(r.error, Some(SdkErrorKind::CredentialParseError));
    }

    #[test]
    fn test_parse_sd_jwt_bad_payload_base64() {
        let token = "eyJhbGciOiJFUzI1NiJ9.!!!invalid!!!.sig~";
        let result = parse_credential(token);
        assert!(result.is_err() || result.unwrap().credential.is_none());
    }

    #[test]
    fn test_parse_sd_jwt_bad_payload_json() {
        let payload_b64 = BASE64URL.encode(b"not json at all");
        let token = format!("eyJhbGciOiJFUzI1NiJ9.{}.sig~", payload_b64);
        let result = parse_credential(&token);
        assert!(result.is_err() || result.unwrap().credential.is_none());
    }

    #[test]
    fn test_parse_credential_idempotent() {
        let token = create_credential_token(
            ProofFormat::Bulletproof,
            "score",
            &serde_json::json!(42),
            None,
            None,
        );
        let r1 = parse_credential(&token).unwrap();
        let r2 = parse_credential(&token).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_credential_binding_deterministic() {
        let b1 = compute_credential_binding("a", &serde_json::json!(1), Some("i"), Some(100));
        let b2 = compute_credential_binding("a", &serde_json::json!(1), Some("i"), Some(100));
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_credential_binding_differs_on_attribute() {
        let b1 = compute_credential_binding("a", &serde_json::json!(1), None, None);
        let b2 = compute_credential_binding("b", &serde_json::json!(1), None, None);
        assert_ne!(b1, b2);
    }

    #[test]
    fn test_credential_binding_differs_on_value() {
        let b1 = compute_credential_binding("a", &serde_json::json!(1), None, None);
        let b2 = compute_credential_binding("a", &serde_json::json!(2), None, None);
        assert_ne!(b1, b2);
    }

    #[test]
    fn test_credential_binding_differs_on_issuer() {
        let b1 = compute_credential_binding("a", &serde_json::json!(1), Some("x"), None);
        let b2 = compute_credential_binding("a", &serde_json::json!(1), Some("y"), None);
        assert_ne!(b1, b2);
    }

    #[test]
    fn test_credential_binding_differs_on_expiration() {
        let b1 = compute_credential_binding("a", &serde_json::json!(1), None, Some(100));
        let b2 = compute_credential_binding("a", &serde_json::json!(1), None, Some(200));
        assert_ne!(b1, b2);
    }

    #[test]
    fn test_all_proof_formats_in_credential() {
        for fmt in &[
            ProofFormat::SdJwt,
            ProofFormat::BbsPlus,
            ProofFormat::Bulletproof,
        ] {
            let token =
                create_credential_token(*fmt, "attr", &serde_json::json!("val"), None, None);
            let result = parse_credential(&token).unwrap();
            let cred = result.credential.unwrap();
            assert_eq!(cred.format, *fmt, "format mismatch for {:?}", fmt);
        }
    }

    #[test]
    fn test_parse_sd_jwt_with_multiple_disclosures() {
        let header = serde_json::json!({"alg": "ES256", "typ": "sd+jwt"});
        let payload = serde_json::json!({
            "claim": {"attribute": "profile", "value": {"name": "Alice", "verified": true}},
            "iss": "issuer"
        });
        let h = BASE64URL.encode(serde_json::to_vec(&header).unwrap());
        let p = BASE64URL.encode(serde_json::to_vec(&payload).unwrap());
        let s = BASE64URL.encode(b"sig");
        // Multiple disclosures
        let token = format!("{}.{}.{}~disc1~disc2~disc3~", h, p, s);

        let result = parse_credential(&token).unwrap();
        let cred = result.credential.unwrap();
        assert_eq!(cred.claim.attribute, "profile");
    }

    #[test]
    fn test_parse_sd_jwt_with_sd_array() {
        let header = serde_json::json!({"alg": "ES256", "typ": "sd+jwt"});
        let payload = serde_json::json!({
            "_sd": ["hash1", "hash2", "hash3"],
            "_sd_alg": "sha-256"
        });
        let h = BASE64URL.encode(serde_json::to_vec(&header).unwrap());
        let p = BASE64URL.encode(serde_json::to_vec(&payload).unwrap());
        let s = BASE64URL.encode(b"sig");
        let token = format!("{}.{}.{}~", h, p, s);

        let result = parse_credential(&token).unwrap();
        let cred = result.credential.unwrap();
        // Should extract _sd count as the claim
        assert_eq!(cred.claim.attribute, "_sd");
        assert_eq!(cred.claim.value, serde_json::json!(3));
    }

    #[test]
    fn test_looks_like_sd_jwt() {
        assert!(looks_like_sd_jwt("a.b.c~d~"));
        assert!(!looks_like_sd_jwt("just-base64-no-dots"));
        assert!(!looks_like_sd_jwt("has.dots.but.no.tilde"));
        assert!(!looks_like_sd_jwt("has~tilde~but~no~dots"));
    }

    #[test]
    fn test_create_sd_jwt_token_roundtrip() {
        let token = create_sd_jwt_token("test", &serde_json::json!("value"), None, None);
        assert!(looks_like_sd_jwt(&token));
        let result = parse_credential(&token).unwrap();
        assert!(result.credential.is_some());
    }
}
