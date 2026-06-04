//! Agent-Safe SPL capability token generation.
//!
//! This legacy API accepts raw signing-key input. It is not an approved
//! issuance boundary for MEA delegated connectors until it is backed by
//! custody-controlled signing rather than caller-provided key material.

use crate::error::{CredError, CredErrorDetail, CredResult};
use agent_safe_spl::token::{mint, MintOptions, Token};

/// Constraints for an SPL capability token.
pub struct SplCapabilityConstraints {
    pub domain: String,
    pub max_amount: Option<u64>,
    pub purpose: String,
    pub one_time: bool,
    pub expires_seconds: Option<u64>,
}

/// Generate an SPL capability token from constraints.
///
/// Builds an S-expression policy from the constraints and signs it
/// with caller-provided Ed25519 material. Do not use this API in the MEA
/// delegated connector path.
pub fn generate_spl_capability(
    constraints: &SplCapabilityConstraints,
    signing_key_hex: &str,
) -> CredResult<Token> {
    let policy = build_policy(constraints);

    let expires = constraints.expires_seconds.map(|secs| {
        let ts = chrono::Utc::now() + chrono::Duration::seconds(secs as i64);
        ts.to_rfc3339()
    });

    let opts = MintOptions {
        sealed: constraints.one_time,
        expires,
        ..Default::default()
    };

    mint(&policy, signing_key_hex, opts).map_err(|e| {
        CredErrorDetail::new(CredError::InternalError, format!("SPL mint failed: {}", e))
    })
}

/// Build an SPL policy S-expression from constraints.
///
/// Example output:
/// ```lisp
/// (and (= (get req "domain") "amazon.com") (<= (get req "amount") 150) (= (get req "purpose") "purchase"))
/// ```
fn build_policy(constraints: &SplCapabilityConstraints) -> String {
    let mut clauses = Vec::new();

    // Domain binding
    clauses.push(format!(
        r#"(= (get req "domain") "{}")"#,
        constraints.domain
    ));

    // Amount limit
    if let Some(max) = constraints.max_amount {
        clauses.push(format!(r#"(<= (get req "amount") {})"#, max));
    }

    // Purpose binding
    clauses.push(format!(
        r#"(= (get req "purpose") "{}")"#,
        constraints.purpose
    ));

    if clauses.len() == 1 {
        clauses.into_iter().next().unwrap()
    } else {
        format!("(and {})", clauses.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_policy_full() {
        let constraints = SplCapabilityConstraints {
            domain: "amazon.com".to_string(),
            max_amount: Some(150),
            purpose: "purchase".to_string(),
            one_time: false,
            expires_seconds: None,
        };
        let policy = build_policy(&constraints);
        assert!(policy.contains(r#"(= (get req "domain") "amazon.com")"#));
        assert!(policy.contains(r#"(<= (get req "amount") 150)"#));
        assert!(policy.contains(r#"(= (get req "purpose") "purchase")"#));
        assert!(policy.starts_with("(and "));
    }

    #[test]
    fn test_build_policy_no_amount() {
        let constraints = SplCapabilityConstraints {
            domain: "test.com".to_string(),
            max_amount: None,
            purpose: "demo".to_string(),
            one_time: false,
            expires_seconds: None,
        };
        let policy = build_policy(&constraints);
        assert!(!policy.contains("amount"));
        assert!(policy.starts_with("(and "));
    }
}
