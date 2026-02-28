//! Agent-Safe SPL capability token generation.
//!
//! Replaces the PASETO placeholder with real Ed25519-signed SPL tokens
//! that embed executable policy for microsecond verification.

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
/// with the provided Ed25519 key.
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

    mint(&policy, signing_key_hex, opts)
        .map_err(|e| CredErrorDetail::new(CredError::InternalError, format!("SPL mint failed: {}", e)))
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

    #[test]
    fn test_generate_spl_capability() {
        let (pub_hex, priv_hex) = agent_safe_spl::generate_keypair();
        let constraints = SplCapabilityConstraints {
            domain: "test.com".to_string(),
            max_amount: Some(100),
            purpose: "demo".to_string(),
            one_time: false,
            expires_seconds: Some(300),
        };
        let token = generate_spl_capability(&constraints, &priv_hex).unwrap();
        assert_eq!(token.public_key, pub_hex);
        assert!(!token.sealed);
        assert!(token.expires.is_some());
        assert!(token.policy.contains("test.com"));
    }

    #[test]
    fn test_generate_spl_capability_one_time() {
        let (_pub_hex, priv_hex) = agent_safe_spl::generate_keypair();
        let constraints = SplCapabilityConstraints {
            domain: "shop.com".to_string(),
            max_amount: Some(50),
            purpose: "purchase".to_string(),
            one_time: true,
            expires_seconds: None,
        };
        let token = generate_spl_capability(&constraints, &priv_hex).unwrap();
        assert!(token.sealed);
    }

    #[test]
    fn test_generated_token_verifies() {
        let (_pub_hex, priv_hex) = agent_safe_spl::generate_keypair();
        let constraints = SplCapabilityConstraints {
            domain: "test.com".to_string(),
            max_amount: Some(100),
            purpose: "demo".to_string(),
            one_time: false,
            expires_seconds: None,
        };
        let token = generate_spl_capability(&constraints, &priv_hex).unwrap();

        // Build request context that matches the policy
        let mut req = std::collections::HashMap::new();
        req.insert("domain".to_string(), agent_safe_spl::Node::Str("test.com".to_string()));
        req.insert("amount".to_string(), agent_safe_spl::Node::Number(50.0));
        req.insert("purpose".to_string(), agent_safe_spl::Node::Str("demo".to_string()));

        let result = agent_safe_spl::verify_token(&token, req, std::collections::HashMap::new());
        assert!(result.allow, "token should verify: {:?}", result.error);
    }

    #[test]
    fn test_generated_token_rejects_wrong_domain() {
        let (_pub_hex, priv_hex) = agent_safe_spl::generate_keypair();
        let constraints = SplCapabilityConstraints {
            domain: "test.com".to_string(),
            max_amount: Some(100),
            purpose: "demo".to_string(),
            one_time: false,
            expires_seconds: None,
        };
        let token = generate_spl_capability(&constraints, &priv_hex).unwrap();

        let mut req = std::collections::HashMap::new();
        req.insert("domain".to_string(), agent_safe_spl::Node::Str("evil.com".to_string()));
        req.insert("amount".to_string(), agent_safe_spl::Node::Number(50.0));
        req.insert("purpose".to_string(), agent_safe_spl::Node::Str("demo".to_string()));

        let result = agent_safe_spl::verify_token(&token, req, std::collections::HashMap::new());
        assert!(!result.allow);
    }
}
