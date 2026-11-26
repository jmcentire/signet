//! The two wire messages. Binary fields are base64url strings.
use crate::keys::KeyClass;

/// How strongly the site wants the person checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserVerification {
    Required,
    Preferred,
    Discouraged,
}

/// Who, as far as the computer knows, set this request in motion. A claim made
/// by the computer, shown to the owner as such.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Initiator {
    Owner,
    Agent,
    Unknown,
}

/// Optional detail the computer supplies to help the owner decide. Untrusted
/// beyond the fact that a paired machine said it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestContext {
    /// Application that asked, for example a browser name.
    pub app: Option<String>,
    pub initiated_by: Initiator,
    /// Short free text, for example the task an agent is carrying out.
    pub note: Option<String>,
}

/// What the site asked for.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    /// Sign in with an existing passkey. An empty list means any passkey the
    /// phone holds for the site.
    Get { allow_credentials: Vec<String> },
    /// Create a new passkey.
    Create {
        rp_name: String,
        user_id: String,
        user_name: String,
        user_display_name: String,
        /// COSE algorithm identifiers the site accepts. Only ES256 (-7) is supported.
        algorithms: Vec<i64>,
        exclude_credentials: Vec<String>,
        /// Requested key class; the phone's default applies when absent.
        key_class: Option<KeyClass>,
    },
}

/// Computer to phone. Signed by the computer's identity key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    pub v: u8,
    /// Random, unique per request.
    pub request_id: String,
    pub pairing_id: String,
    pub operation: Operation,
    /// The WebAuthn relying party identifier, for example `github.com`.
    pub rp_id: String,
    /// SHA-256 of the client data the site will verify.
    pub client_data_hash: String,
    /// Page origin, when the computer built the client data itself. Absent when
    /// the operating system supplied only the hash.
    pub origin: Option<String>,
    pub user_verification: UserVerification,
    pub context: Option<RequestContext>,
    pub created_at: i64,
    pub expires_at: i64,
}

/// Why the phone would not sign, without the owner having declined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// The phone holds no passkey for this site (or none of those allowed).
    NoCredential,
    /// The site identifier is malformed or does not belong to the page origin.
    SiteBinding,
    /// The site accepts no algorithm the phone supports.
    UnsupportedAlgorithm,
    /// The site listed a passkey the phone already holds for this account.
    CredentialExcluded,
    /// The site requires the person to be verified and they were not.
    UserVerificationRequired,
}

/// The signed result of an approved request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome {
    Assertion {
        credential_id: String,
        authenticator_data: String,
        signature: String,
        user_handle: String,
    },
    Attestation {
        credential_id: String,
        attestation_object: String,
        authenticator_data: String,
        /// SEC1 uncompressed public key of the new passkey.
        public_key: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Decision {
    Approved {
        outcome: Outcome,
    },
    /// The owner declined.
    Denied,
    /// The phone refused before or regardless of asking the owner.
    Refused {
        reason: Refusal,
    },
}

/// Phone to computer. Signed by the phone's identity key. It is also the audit
/// record of what was decided.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignResponse {
    pub v: u8,
    pub request_id: String,
    /// Digest of the exact signed request this answers.
    pub request_digest: String,
    pub decision: Decision,
    pub decided_at: i64,
}
