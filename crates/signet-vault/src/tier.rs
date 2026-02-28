use crate::blind_storage;
use crate::error::{VaultError, VaultResult};
use rand::RngCore;
use signet_core::Tier;
use zeroize::Zeroizing;

// Tier classification and key input selection.
//
// Different tiers use different key derivation strategies:
//
// - Tier 1 (freely provable): `derive_key(username, server_salt)`
//   Survives password reset. Public posts, preferences, age proofs.
//
// - Tier 2 (agent-internal): `derive_key(username, password, "master")`
//   Session-bound. Lost on password reset. Agent reasoning context.
//
// - Tier 3 (capability-gated): `random_key()`
//   Client-generated, unrecoverable without explicit user grant.
//   Payment credentials, identity documents, medical data.

/// Generate a key for the given tier.
pub fn generate_tier_key(
    tier: Tier,
    username: &str,
    password: &str,
) -> VaultResult<Zeroizing<[u8; 32]>> {
    match tier {
        Tier::Tier1 => Ok(blind_storage::derive_master_secret(username, "", &[])),
        Tier::Tier2 => Ok(blind_storage::derive_master_secret(username, password, &[])),
        Tier::Tier3 => {
            let mut key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            Ok(Zeroizing::new(key))
        }
    }
}

/// Default tier classification based on data labels.
///
/// Users can override these defaults. This provides sensible starting points.
pub fn classify_default(label: &str) -> Tier {
    let label_lower = label.to_lowercase();

    // Tier 3: highly sensitive, capability-gated
    let tier3_patterns = [
        "credit_card",
        "bank_account",
        "social_security",
        "ssn",
        "passport",
        "drivers_license",
        "medical",
        "health",
        "identity_doc",
        "tax",
        "biometric",
        "private_key",
    ];
    for pattern in &tier3_patterns {
        if label_lower.contains(pattern) {
            return Tier::Tier3;
        }
    }

    // Tier 2: agent-internal reasoning context
    let tier2_patterns = [
        "preference",
        "history",
        "session",
        "context",
        "reasoning",
        "analysis",
        "recommendation",
        "behavior",
        "pattern",
        "financial_summary",
        "income",
    ];
    for pattern in &tier2_patterns {
        if label_lower.contains(pattern) {
            return Tier::Tier2;
        }
    }

    // Default: Tier 1 (freely provable)
    Tier::Tier1
}

/// Validate that a requested operation is appropriate for the given tier.
pub fn validate_tier_access(
    requested_tier: Tier,
    actual_tier: Tier,
    has_user_grant: bool,
) -> VaultResult<()> {
    match actual_tier {
        Tier::Tier3 if !has_user_grant => Err(VaultError::TierViolation(
            "Tier 3 access requires explicit user grant".into(),
        )),
        _ if (actual_tier as u8) > (requested_tier as u8) => Err(VaultError::TierViolation(
            format!("requested {} but data is {}", requested_tier, actual_tier),
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier1_key_survives_password_change() {
        let k1 = generate_tier_key(Tier::Tier1, "alice", "password1").unwrap();
        let k2 = generate_tier_key(Tier::Tier1, "alice", "password2").unwrap();
        // Tier 1 ignores password → same key
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn test_tier2_key_changes_with_password() {
        let k1 = generate_tier_key(Tier::Tier2, "alice", "password1").unwrap();
        let k2 = generate_tier_key(Tier::Tier2, "alice", "password2").unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn test_tier3_key_is_random() {
        let k1 = generate_tier_key(Tier::Tier3, "alice", "pass").unwrap();
        let k2 = generate_tier_key(Tier::Tier3, "alice", "pass").unwrap();
        // Random keys are never equal
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn test_classify_defaults() {
        assert_eq!(classify_default("credit_card_number"), Tier::Tier3);
        assert_eq!(classify_default("medical_records"), Tier::Tier3);
        assert_eq!(classify_default("passport_scan"), Tier::Tier3);
        assert_eq!(classify_default("user_preferences"), Tier::Tier2);
        assert_eq!(classify_default("browse_history"), Tier::Tier2);
        assert_eq!(classify_default("public_name"), Tier::Tier1);
        assert_eq!(classify_default("email_address"), Tier::Tier1);
    }

    #[test]
    fn test_tier3_access_requires_grant() {
        let result = validate_tier_access(Tier::Tier3, Tier::Tier3, false);
        assert!(result.is_err());

        let result = validate_tier_access(Tier::Tier3, Tier::Tier3, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_tier1_access_always_ok() {
        let result = validate_tier_access(Tier::Tier1, Tier::Tier1, false);
        assert!(result.is_ok());
    }
}
