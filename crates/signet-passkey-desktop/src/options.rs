//! Reading a page's passkey options.
//!
//! The browser extension sends the options a page passed to
//! `navigator.credentials.create` or `.get` in the standard JSON form
//! (`PublicKeyCredentialCreationOptionsJSON` and
//! `PublicKeyCredentialRequestOptionsJSON`): binary fields as base64url.
//! Fields this subsystem does not use are ignored. Oversized options are
//! reported as [`OptionsError::TooLarge`], and the caller leaves those to the
//! browser.
use signet_passkey::{CreateOptions, GetOptions, UserVerification};

/// Bounds that keep a sealed request well inside the relay's message limit.
const MAX_LIST: usize = 64;
const MAX_ID: usize = 1400;
const MAX_TEXT: usize = 256;
const MAX_CHALLENGE: usize = 1400;

/// Why options could not be used.
#[derive(Debug, PartialEq, Eq)]
pub enum OptionsError {
    /// Not the standard JSON form.
    Malformed,
    /// Valid, but larger than this subsystem carries.
    TooLarge,
}

#[derive(serde::Deserialize)]
struct Descriptor {
    id: String,
}

#[derive(serde::Deserialize)]
struct Party {
    id: Option<String>,
    name: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct User {
    id: String,
    name: String,
    display_name: String,
}

#[derive(serde::Deserialize)]
struct Parameter {
    alg: i64,
}

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Selection {
    authenticator_attachment: Option<String>,
    user_verification: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Creation {
    rp: Party,
    user: User,
    challenge: String,
    pub_key_cred_params: Vec<Parameter>,
    #[serde(default)]
    exclude_credentials: Vec<Descriptor>,
    #[serde(default)]
    authenticator_selection: Option<Selection>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Assertion {
    challenge: String,
    rp_id: Option<String>,
    #[serde(default)]
    allow_credentials: Vec<Descriptor>,
    user_verification: Option<String>,
}

/// A page's request to create a passkey, with what routing needs to know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCreate {
    pub options: CreateOptions,
    /// The site asked for a roaming security key specifically.
    pub wants_security_key: bool,
}

fn user_verification(value: Option<&str>) -> UserVerification {
    match value {
        Some("required") => UserVerification::Required,
        Some("discouraged") => UserVerification::Discouraged,
        _ => UserVerification::Preferred,
    }
}

fn ids(list: Vec<Descriptor>) -> Result<Vec<String>, OptionsError> {
    if list.len() > MAX_LIST || list.iter().any(|item| item.id.len() > MAX_ID) {
        return Err(OptionsError::TooLarge);
    }
    Ok(list.into_iter().map(|item| item.id).collect())
}

fn bounded(text: &str, limit: usize) -> Result<(), OptionsError> {
    if text.len() > limit {
        return Err(OptionsError::TooLarge);
    }
    Ok(())
}

/// Read creation options.
pub fn parse_create(options: &serde_json::Value) -> Result<ParsedCreate, OptionsError> {
    let parsed: Creation =
        serde_json::from_value(options.clone()).map_err(|_| OptionsError::Malformed)?;
    bounded(&parsed.challenge, MAX_CHALLENGE)?;
    bounded(&parsed.user.id, MAX_ID)?;
    for text in [
        &parsed.rp.name,
        &parsed.user.name,
        &parsed.user.display_name,
    ] {
        bounded(text, MAX_TEXT)?;
    }
    if parsed.pub_key_cred_params.len() > MAX_LIST {
        return Err(OptionsError::TooLarge);
    }
    let selection = parsed.authenticator_selection.unwrap_or_default();
    Ok(ParsedCreate {
        wants_security_key: selection.authenticator_attachment.as_deref() == Some("cross-platform"),
        options: CreateOptions {
            challenge: parsed.challenge,
            rp_id: parsed.rp.id,
            rp_name: parsed.rp.name,
            user_id: parsed.user.id,
            user_name: parsed.user.name,
            user_display_name: parsed.user.display_name,
            algorithms: parsed.pub_key_cred_params.iter().map(|p| p.alg).collect(),
            exclude_credentials: ids(parsed.exclude_credentials)?,
            user_verification: user_verification(selection.user_verification.as_deref()),
            key_class: None,
        },
    })
}

/// Read sign-in options.
pub fn parse_get(options: &serde_json::Value) -> Result<GetOptions, OptionsError> {
    let parsed: Assertion =
        serde_json::from_value(options.clone()).map_err(|_| OptionsError::Malformed)?;
    bounded(&parsed.challenge, MAX_CHALLENGE)?;
    Ok(GetOptions {
        challenge: parsed.challenge,
        rp_id: parsed.rp_id,
        allow_credentials: ids(parsed.allow_credentials)?,
        user_verification: user_verification(parsed.user_verification.as_deref()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn creation_options_are_read_from_the_standard_json() {
        let parsed = parse_create(&json!({
            "rp": { "id": "example.com", "name": "Example" },
            "user": { "id": "dXNlcg", "name": "ada", "displayName": "Ada L." },
            "challenge": "Y2hhbGxlbmdl",
            "pubKeyCredParams": [
                { "type": "public-key", "alg": -7 },
                { "type": "public-key", "alg": -257 }
            ],
            "timeout": 60000,
            "excludeCredentials": [{ "type": "public-key", "id": "b2xk", "transports": ["usb"] }],
            "authenticatorSelection": { "residentKey": "required", "userVerification": "required" },
            "attestation": "none",
            "extensions": { "credProps": true }
        }))
        .unwrap();
        assert!(!parsed.wants_security_key);
        assert_eq!(parsed.options.rp_id.as_deref(), Some("example.com"));
        assert_eq!(parsed.options.algorithms, vec![-7, -257]);
        assert_eq!(parsed.options.exclude_credentials, vec!["b2xk"]);
        assert_eq!(parsed.options.user_verification, UserVerification::Required);
    }

    #[test]
    fn sign_in_options_default_sensibly() {
        let parsed = parse_get(&json!({ "challenge": "Y2hhbGxlbmdl" })).unwrap();
        assert_eq!(parsed.rp_id, None);
        assert!(parsed.allow_credentials.is_empty());
        assert_eq!(parsed.user_verification, UserVerification::Preferred);
    }

    #[test]
    fn a_request_for_a_security_key_is_noticed() {
        let parsed = parse_create(&json!({
            "rp": { "name": "Example" },
            "user": { "id": "dQ", "name": "ada", "displayName": "Ada" },
            "challenge": "Yw",
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
            "authenticatorSelection": { "authenticatorAttachment": "cross-platform" }
        }))
        .unwrap();
        assert!(parsed.wants_security_key);
    }

    #[test]
    fn malformed_and_oversized_options_are_told_apart() {
        assert_eq!(
            parse_get(&json!({ "rpId": "example.com" })),
            Err(OptionsError::Malformed)
        );
        assert_eq!(
            parse_get(&json!({ "challenge": 7 })),
            Err(OptionsError::Malformed)
        );
        let many: Vec<_> = (0..65).map(|n| json!({ "id": format!("id{n}") })).collect();
        assert_eq!(
            parse_get(&json!({ "challenge": "Yw", "allowCredentials": many })),
            Err(OptionsError::TooLarge)
        );
        assert_eq!(
            parse_get(&json!({ "challenge": "a".repeat(2000) })),
            Err(OptionsError::TooLarge)
        );
    }
}
