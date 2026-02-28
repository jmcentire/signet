//! Scope validation — subset checking and privilege escalation detection.
//!
//! A Modify response's adjusted_scope must be a strict subset of the original
//! requested_scope. Equal or superset scopes are rejected.

use crate::types::ScopeSet;

/// Validate that adjusted_scope is a strict subset of original_scope.
///
/// A strict subset means:
/// - Every (resource, action) pair in adjusted_scope exists in original_scope
/// - adjusted_scope has strictly fewer entries than original_scope
///
/// Returns true if adjusted_scope is a valid (reduced) subset.
pub fn validate_scope_subset(original: &ScopeSet, adjusted: &ScopeSet) -> bool {
    original.is_strict_superset_of(adjusted)
}

/// Check if two ScopeSets are equal (same entries, regardless of order).
pub fn scopes_equal(a: &ScopeSet, b: &ScopeSet) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.entries().iter().all(|entry| b.entries().contains(entry))
        && b.entries().iter().all(|entry| a.entries().contains(entry))
}

/// Check if the adjusted scope contains any entry not present in the original.
/// This is a direct privilege escalation check.
pub fn detect_escalation(
    original: &ScopeSet,
    adjusted: &ScopeSet,
) -> Vec<crate::types::ScopeEntry> {
    adjusted
        .entries()
        .iter()
        .filter(|entry| !original.entries().contains(entry))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ScopeEntry;

    fn make_scope(entries: Vec<(&str, &str)>) -> ScopeSet {
        ScopeSet::new(
            entries
                .into_iter()
                .map(|(r, a)| ScopeEntry::new(r, a))
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn test_valid_strict_subset() {
        let original = make_scope(vec![
            ("vault.medical", "read"),
            ("vault.financial", "read"),
            ("vault.identity", "prove"),
        ]);
        let adjusted = make_scope(vec![("vault.medical", "read"), ("vault.financial", "read")]);
        assert!(validate_scope_subset(&original, &adjusted));
    }

    #[test]
    fn test_single_entry_subset() {
        let original = make_scope(vec![("vault.medical", "read"), ("vault.financial", "read")]);
        let adjusted = make_scope(vec![("vault.medical", "read")]);
        assert!(validate_scope_subset(&original, &adjusted));
    }

    #[test]
    fn test_equal_sets_not_strict_subset() {
        let original = make_scope(vec![("vault.medical", "read"), ("vault.financial", "read")]);
        let adjusted = make_scope(vec![("vault.medical", "read"), ("vault.financial", "read")]);
        assert!(!validate_scope_subset(&original, &adjusted));
    }

    #[test]
    fn test_superset_rejected() {
        let original = make_scope(vec![("vault.medical", "read")]);
        let adjusted = make_scope(vec![("vault.medical", "read"), ("vault.financial", "read")]);
        assert!(!validate_scope_subset(&original, &adjusted));
    }

    #[test]
    fn test_disjoint_sets_rejected() {
        let original = make_scope(vec![("vault.medical", "read")]);
        let adjusted = make_scope(vec![("vault.financial", "read")]);
        assert!(!validate_scope_subset(&original, &adjusted));
    }

    #[test]
    fn test_partial_overlap_not_subset() {
        let original = make_scope(vec![("vault.medical", "read"), ("vault.financial", "read")]);
        let adjusted = make_scope(vec![
            ("vault.medical", "read"),
            ("vault.identity", "prove"), // not in original
        ]);
        assert!(!validate_scope_subset(&original, &adjusted));
    }

    #[test]
    fn test_different_actions_not_subset() {
        let original = make_scope(vec![("vault.medical", "read")]);
        // Same resource, different action
        let adjusted = make_scope(vec![("vault.medical", "write")]);
        assert!(!validate_scope_subset(&original, &adjusted));
    }

    #[test]
    fn test_scopes_equal_same_entries() {
        let a = make_scope(vec![("vault.medical", "read"), ("vault.financial", "read")]);
        let b = make_scope(vec![("vault.financial", "read"), ("vault.medical", "read")]);
        assert!(scopes_equal(&a, &b));
    }

    #[test]
    fn test_scopes_equal_different_entries() {
        let a = make_scope(vec![("vault.medical", "read")]);
        let b = make_scope(vec![("vault.financial", "read")]);
        assert!(!scopes_equal(&a, &b));
    }

    #[test]
    fn test_scopes_equal_different_sizes() {
        let a = make_scope(vec![("vault.medical", "read"), ("vault.financial", "read")]);
        let b = make_scope(vec![("vault.medical", "read")]);
        assert!(!scopes_equal(&a, &b));
    }

    #[test]
    fn test_detect_escalation_none() {
        let original = make_scope(vec![("vault.medical", "read"), ("vault.financial", "read")]);
        let adjusted = make_scope(vec![("vault.medical", "read")]);
        let escalations = detect_escalation(&original, &adjusted);
        assert!(escalations.is_empty());
    }

    #[test]
    fn test_detect_escalation_found() {
        let original = make_scope(vec![("vault.medical", "read")]);
        let adjusted = make_scope(vec![("vault.medical", "read"), ("vault.financial", "read")]);
        let escalations = detect_escalation(&original, &adjusted);
        assert_eq!(escalations.len(), 1);
        assert_eq!(escalations[0].resource, "vault.financial");
        assert_eq!(escalations[0].action, "read");
    }

    #[test]
    fn test_detect_escalation_multiple() {
        let original = make_scope(vec![("vault.medical", "read")]);
        let adjusted = make_scope(vec![
            ("vault.financial", "read"),
            ("vault.identity", "prove"),
        ]);
        let escalations = detect_escalation(&original, &adjusted);
        assert_eq!(escalations.len(), 2);
    }

    #[test]
    fn test_hierarchical_resources_treated_as_opaque() {
        // Scope entries are opaque string comparisons, not hierarchical
        let original = make_scope(vec![("vault.medical", "read")]);
        let adjusted = make_scope(vec![("vault.medical.records", "read")]);
        // vault.medical.records is NOT a subset of vault.medical (opaque comparison)
        assert!(!validate_scope_subset(&original, &adjusted));
    }

    #[test]
    fn test_empty_action_string_handling() {
        // While ScopeEntry allows any string, the comparison should work correctly
        let original = make_scope(vec![("vault.medical", "read"), ("vault.medical", "")]);
        let adjusted = make_scope(vec![("vault.medical", "")]);
        assert!(validate_scope_subset(&original, &adjusted));
    }

    #[test]
    fn test_case_sensitive_comparison() {
        let original = make_scope(vec![("vault.medical", "Read")]);
        let adjusted = make_scope(vec![("vault.medical", "read")]);
        // Case sensitive: "Read" != "read"
        assert!(!validate_scope_subset(&original, &adjusted));
    }
}
