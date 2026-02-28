//! Schema validation and management.
//!
//! Validates structural invariants: unique field names, DerivedBoolean fields
//! have predicates, disclosure policy consistency, attribute count limits.

use crate::error::{CredError, CredErrorDetail, CredResult};
use crate::types::{AttributeKind, CredentialSchema, DisclosureLevel};
use std::collections::HashSet;

/// Validate a CredentialSchema without registering it.
/// Returns a list of validation error messages (empty list means valid).
pub fn validate_schema(schema: &CredentialSchema, max_attributes: usize) -> Vec<String> {
    let mut errors = Vec::new();

    // 1. Schema must have at least one field
    if schema.fields.is_empty() {
        errors.push("Schema must have at least one field".to_string());
    }

    // 2. Schema version must be >= 1
    if schema.version < 1 {
        errors.push("Schema version must be >= 1".to_string());
    }

    // 3. Check for duplicate field names
    let mut seen_names = HashSet::new();
    for field in &schema.fields {
        if !seen_names.insert(&field.name) {
            errors.push(format!("Duplicate field name: '{}'", field.name));
        }
    }

    // 4. DerivedBoolean fields must have predicates
    for field in &schema.fields {
        if field.kind == AttributeKind::DerivedBoolean && field.predicate.is_none() {
            errors.push(format!(
                "DerivedBoolean field '{}' must have a predicate",
                field.name
            ));
        }
    }

    // 5. Non-DerivedBoolean fields should NOT have predicates (warning-level, but still an error)
    for field in &schema.fields {
        if field.kind != AttributeKind::DerivedBoolean && field.predicate.is_some() {
            errors.push(format!(
                "Field '{}' is {:?} but has a predicate (only DerivedBoolean fields should have predicates)",
                field.name, field.kind
            ));
        }
    }

    // 6. Check attribute count limit
    if schema.fields.len() > max_attributes {
        errors.push(format!(
            "Schema has {} fields, exceeding max of {}",
            schema.fields.len(),
            max_attributes
        ));
    }

    // 7. Disclosure policy rules must reference valid field names
    let field_names: HashSet<&str> = schema.fields.iter().map(|f| f.name.as_str()).collect();
    for rule in &schema.disclosure_policy.rules {
        if !field_names.contains(rule.field_name.as_str()) {
            errors.push(format!(
                "Disclosure rule references unknown field: '{}'",
                rule.field_name
            ));
        }
    }

    // 8. Check for duplicate disclosure rules
    let mut seen_rule_names = HashSet::new();
    for rule in &schema.disclosure_policy.rules {
        if !seen_rule_names.insert(&rule.field_name) {
            errors.push(format!(
                "Duplicate disclosure rule for field: '{}'",
                rule.field_name
            ));
        }
    }

    errors
}

/// Validate a schema and return a result (for use in engine registration).
pub fn validate_schema_strict(schema: &CredentialSchema, max_attributes: usize) -> CredResult<()> {
    let errors = validate_schema(schema, max_attributes);
    if errors.is_empty() {
        Ok(())
    } else {
        let first_error = errors[0].clone();
        // Determine error kind based on the first error
        if first_error.contains("Disclosure") {
            Err(CredErrorDetail::new(
                CredError::InvalidDisclosurePolicy(first_error.clone()),
                first_error,
            ))
        } else if first_error.contains("exceeding max") {
            Err(CredErrorDetail::new(
                CredError::AttributeLimitExceeded,
                first_error,
            ))
        } else {
            Err(CredErrorDetail::new(
                CredError::SchemaViolation(first_error.clone()),
                first_error,
            ))
        }
    }
}

/// Compute the BBS+ message vector index mapping from a schema.
/// Returns a map from field name to index.
pub fn compute_field_index_map(
    schema: &CredentialSchema,
) -> std::collections::HashMap<String, usize> {
    schema
        .fields
        .iter()
        .enumerate()
        .map(|(i, f)| (f.name.clone(), i))
        .collect()
}

/// Get the disclosure level for a field in the schema's policy.
pub fn field_disclosure_level(schema: &CredentialSchema, field_name: &str) -> DisclosureLevel {
    schema.disclosure_policy.level_for(field_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn make_test_schema() -> CredentialSchema {
        CredentialSchema {
            schema_id: "test-schema".to_string(),
            version: 1,
            fields: vec![
                SchemaField {
                    name: "full_name".to_string(),
                    kind: AttributeKind::Raw,
                    source_path: ClaimPath::new("/personal/name").unwrap(),
                    predicate: None,
                    required: true,
                },
                SchemaField {
                    name: "age_over_21".to_string(),
                    kind: AttributeKind::DerivedBoolean,
                    source_path: ClaimPath::new("/personal/age").unwrap(),
                    predicate: Some(Predicate::GreaterThanOrEqual(21)),
                    required: true,
                },
                SchemaField {
                    name: "account_balance".to_string(),
                    kind: AttributeKind::Committed,
                    source_path: ClaimPath::new("/financial/balance").unwrap(),
                    predicate: None,
                    required: true,
                },
            ],
            disclosure_policy: DisclosurePolicy::new(
                vec![
                    DisclosureRule {
                        field_name: "full_name".into(),
                        level: DisclosureLevel::Selectable,
                    },
                    DisclosureRule {
                        field_name: "age_over_21".into(),
                        level: DisclosureLevel::Always,
                    },
                    DisclosureRule {
                        field_name: "account_balance".into(),
                        level: DisclosureLevel::Never,
                    },
                ],
                DisclosureLevel::Never,
            ),
            description: Some("Test schema".to_string()),
        }
    }

    #[test]
    fn test_valid_schema() {
        let schema = make_test_schema();
        let errors = validate_schema(&schema, 128);
        assert!(errors.is_empty(), "Expected no errors, got: {:?}", errors);
    }

    #[test]
    fn test_empty_fields() {
        let mut schema = make_test_schema();
        schema.fields.clear();
        let errors = validate_schema(&schema, 128);
        assert!(errors.iter().any(|e| e.contains("at least one field")));
    }

    #[test]
    fn test_duplicate_field_names() {
        let mut schema = make_test_schema();
        schema.fields.push(SchemaField {
            name: "full_name".to_string(),
            kind: AttributeKind::Raw,
            source_path: ClaimPath::new("/personal/other_name").unwrap(),
            predicate: None,
            required: false,
        });
        let errors = validate_schema(&schema, 128);
        assert!(errors.iter().any(|e| e.contains("Duplicate field name")));
    }

    #[test]
    fn test_derived_boolean_without_predicate() {
        let mut schema = make_test_schema();
        schema.fields[1].predicate = None;
        let errors = validate_schema(&schema, 128);
        assert!(errors.iter().any(|e| e.contains("must have a predicate")));
    }

    #[test]
    fn test_raw_field_with_predicate() {
        let mut schema = make_test_schema();
        schema.fields[0].predicate = Some(Predicate::GreaterThan(10));
        let errors = validate_schema(&schema, 128);
        assert!(errors.iter().any(|e| e.contains("only DerivedBoolean")));
    }

    #[test]
    fn test_attribute_limit_exceeded() {
        let schema = make_test_schema();
        let errors = validate_schema(&schema, 2);
        assert!(errors.iter().any(|e| e.contains("exceeding max")));
    }

    #[test]
    fn test_disclosure_rule_unknown_field() {
        let mut schema = make_test_schema();
        schema.disclosure_policy.rules.push(DisclosureRule {
            field_name: "nonexistent".into(),
            level: DisclosureLevel::Always,
        });
        let errors = validate_schema(&schema, 128);
        assert!(errors.iter().any(|e| e.contains("unknown field")));
    }

    #[test]
    fn test_schema_version_zero() {
        let mut schema = make_test_schema();
        schema.version = 0;
        let errors = validate_schema(&schema, 128);
        assert!(errors.iter().any(|e| e.contains("version must be >= 1")));
    }

    #[test]
    fn test_validate_schema_strict_ok() {
        let schema = make_test_schema();
        assert!(validate_schema_strict(&schema, 128).is_ok());
    }

    #[test]
    fn test_validate_schema_strict_err() {
        let mut schema = make_test_schema();
        schema.fields.clear();
        let result = validate_schema_strict(&schema, 128);
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_field_index_map() {
        let schema = make_test_schema();
        let map = compute_field_index_map(&schema);
        assert_eq!(map.get("full_name"), Some(&0));
        assert_eq!(map.get("age_over_21"), Some(&1));
        assert_eq!(map.get("account_balance"), Some(&2));
    }

    #[test]
    fn test_field_disclosure_level() {
        let schema = make_test_schema();
        assert_eq!(
            field_disclosure_level(&schema, "full_name"),
            DisclosureLevel::Selectable
        );
        assert_eq!(
            field_disclosure_level(&schema, "age_over_21"),
            DisclosureLevel::Always
        );
        assert_eq!(
            field_disclosure_level(&schema, "account_balance"),
            DisclosureLevel::Never
        );
        // Unknown field uses default
        assert_eq!(
            field_disclosure_level(&schema, "unknown"),
            DisclosureLevel::Never
        );
    }

    #[test]
    fn test_duplicate_disclosure_rules() {
        let mut schema = make_test_schema();
        schema.disclosure_policy.rules.push(DisclosureRule {
            field_name: "full_name".into(),
            level: DisclosureLevel::Never,
        });
        let errors = validate_schema(&schema, 128);
        assert!(errors
            .iter()
            .any(|e| e.contains("Duplicate disclosure rule")));
    }

    #[test]
    fn test_validate_strict_disclosure_error() {
        let mut schema = make_test_schema();
        schema.disclosure_policy.rules.push(DisclosureRule {
            field_name: "nonexistent".into(),
            level: DisclosureLevel::Always,
        });
        let result = validate_schema_strict(&schema, 128);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err.kind, CredError::InvalidDisclosurePolicy(_)));
    }

    #[test]
    fn test_validate_strict_attribute_limit_error() {
        let schema = make_test_schema();
        let result = validate_schema_strict(&schema, 1);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err.kind, CredError::AttributeLimitExceeded));
    }
}
