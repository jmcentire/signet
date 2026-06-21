//! Suspended Agent-Safe SPL capability issuance compatibility surface.
//!
//! The historical API accepted caller-provided signing-key input. It now
//! fails closed until an issuer can sign through the custody boundary
//! without exporting key material.

use crate::error::{CredError, CredErrorDetail, CredResult};
use agent_safe_spl::token::Token;

/// Constraints for an SPL capability token.
pub struct SplCapabilityConstraints {
    pub domain: String,
    pub max_amount: Option<u64>,
    pub purpose: String,
    pub one_time: bool,
    pub expires_seconds: Option<u64>,
}

/// Legacy SPL capability issuance entrypoint.
///
/// The legacy argument is retained for source compatibility but deliberately
/// ignored. Issuance must be reintroduced only through a custody-controlled
/// signer integration.
#[deprecated(note = "disabled until custody-controlled issuer integration is available")]
pub fn generate_spl_capability(
    _constraints: &SplCapabilityConstraints,
    _unaccepted_signing_key_hex: &str,
) -> CredResult<Token> {
    Err(CredErrorDetail::new(
        CredError::InternalError,
        "SPL capability issuance requires a custody-controlled issuer",
    ))
}

/// Build an SPL policy S-expression from constraints.
///
/// Example output:
/// ```lisp
/// (and (= (get req "domain") "amazon.com") (<= (get req "amount") 150) (= (get req "purpose") "purchase"))
/// ```
#[cfg(test)]
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
