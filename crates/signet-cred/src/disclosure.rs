//! Selective disclosure policy evaluation.
//!
//! Validates that disclosed fields comply with the DisclosurePolicy:
//! - Always fields MUST be disclosed
//! - Never fields MUST NOT be disclosed
//! - Selectable fields MAY be disclosed

use crate::error::{CredError, CredErrorDetail, CredResult};
use crate::types::{CredentialSchema, DisclosureLevel, DisclosurePolicy};
use std::collections::HashSet;

/// Validate a set of disclosed field names against the disclosure policy.
/// Returns Ok(()) if the disclosure is valid.
pub fn validate_disclosure(
    policy: &DisclosurePolicy,
    schema_field_names: &[String],
    disclosed_fields: &[String],
) -> CredResult<()> {
    let disclosed_set: HashSet<&str> = disclosed_fields.iter().map(|s| s.as_str()).collect();
    let schema_set: HashSet<&str> = schema_field_names.iter().map(|s| s.as_str()).collect();

    // Check that all disclosed fields exist in the schema
    for field in &disclosed_set {
        if !schema_set.contains(field) {
            return Err(CredErrorDetail::new(
                CredError::InvalidDisclosurePolicy(format!(
                    "disclosed field '{}' not in schema",
                    field
                )),
                format!("field '{}' is not defined in the credential schema", field),
            ));
        }
    }

    // Check Always fields are all disclosed
    for field_name in schema_field_names {
        let level = policy.level_for(field_name);
        match level {
            DisclosureLevel::Always => {
                if !disclosed_set.contains(field_name.as_str()) {
                    return Err(CredErrorDetail::new(
                        CredError::InvalidDisclosurePolicy(format!(
                            "field '{}' has disclosure level Always but was not disclosed",
                            field_name
                        )),
                        format!("required field '{}' must be disclosed", field_name),
                    ));
                }
            }
            DisclosureLevel::Never => {
                if disclosed_set.contains(field_name.as_str()) {
                    return Err(CredErrorDetail::new(
                        CredError::InvalidDisclosurePolicy(format!(
                            "field '{}' has disclosure level Never but was disclosed",
                            field_name
                        )),
                        format!("field '{}' must not be disclosed", field_name),
                    ));
                }
            }
            DisclosureLevel::Selectable => {
                // Can be disclosed or not — no constraint
            }
        }
    }

    Ok(())
}

/// Validate disclosure using a schema directly.
pub fn validate_disclosure_for_schema(
    schema: &CredentialSchema,
    disclosed_fields: &[String],
) -> CredResult<()> {
    let field_names: Vec<String> = schema.fields.iter().map(|f| f.name.clone()).collect();
    validate_disclosure(&schema.disclosure_policy, &field_names, disclosed_fields)
}

/// Compute the set of fields that MUST be disclosed (Always level).
pub fn required_disclosures(
    policy: &DisclosurePolicy,
    schema_field_names: &[String],
) -> Vec<String> {
    schema_field_names
        .iter()
        .filter(|f| policy.level_for(f) == DisclosureLevel::Always)
        .cloned()
        .collect()
}

/// Compute the set of fields that CAN be disclosed (Always or Selectable).
pub fn disclosable_fields(policy: &DisclosurePolicy, schema_field_names: &[String]) -> Vec<String> {
    schema_field_names
        .iter()
        .filter(|f| {
            let level = policy.level_for(f);
            level == DisclosureLevel::Always || level == DisclosureLevel::Selectable
        })
        .cloned()
        .collect()
}

/// Compute the set of fields that MUST NOT be disclosed (Never level).
pub fn forbidden_fields(policy: &DisclosurePolicy, schema_field_names: &[String]) -> Vec<String> {
    schema_field_names
        .iter()
        .filter(|f| policy.level_for(f) == DisclosureLevel::Never)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn make_policy() -> DisclosurePolicy {
        DisclosurePolicy::new(
            vec![
                DisclosureRule {
                    field_name: "name".into(),
                    level: DisclosureLevel::Always,
                },
                DisclosureRule {
                    field_name: "age_over_21".into(),
                    level: DisclosureLevel::Selectable,
                },
                DisclosureRule {
                    field_name: "ssn".into(),
                    level: DisclosureLevel::Never,
                },
            ],
            DisclosureLevel::Never,
        )
    }

    fn field_names() -> Vec<String> {
        vec![
            "name".into(),
            "age_over_21".into(),
            "ssn".into(),
            "email".into(),
        ]
    }

    #[test]
    fn test_valid_disclosure_always_and_selectable() {
        let result = validate_disclosure(
            &make_policy(),
            &field_names(),
            &["name".into(), "age_over_21".into()],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_valid_disclosure_always_only() {
        let result = validate_disclosure(&make_policy(), &field_names(), &["name".into()]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_missing_always_field() {
        let result = validate_disclosure(&make_policy(), &field_names(), &["age_over_21".into()]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err.kind, CredError::InvalidDisclosurePolicy(_)));
        assert!(err.message.contains("name"));
    }

    #[test]
    fn test_disclosed_never_field() {
        let result = validate_disclosure(
            &make_policy(),
            &field_names(),
            &["name".into(), "ssn".into()],
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err.kind, CredError::InvalidDisclosurePolicy(_)));
        assert!(err.message.contains("ssn"));
    }

    #[test]
    fn test_disclosed_unknown_field() {
        let result = validate_disclosure(
            &make_policy(),
            &field_names(),
            &["name".into(), "nonexistent".into()],
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("nonexistent"));
    }

    #[test]
    fn test_default_level_never_undeclared_field() {
        // "email" is not in the policy rules, default is Never
        let result = validate_disclosure(
            &make_policy(),
            &field_names(),
            &["name".into(), "email".into()],
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("email"));
    }

    #[test]
    fn test_required_disclosures() {
        let required = required_disclosures(&make_policy(), &field_names());
        assert_eq!(required, vec!["name".to_string()]);
    }

    #[test]
    fn test_disclosable_fields() {
        let disclosable = disclosable_fields(&make_policy(), &field_names());
        assert!(disclosable.contains(&"name".to_string()));
        assert!(disclosable.contains(&"age_over_21".to_string()));
        assert!(!disclosable.contains(&"ssn".to_string()));
        assert!(!disclosable.contains(&"email".to_string())); // default Never
    }

    #[test]
    fn test_forbidden_fields() {
        let forbidden = forbidden_fields(&make_policy(), &field_names());
        assert!(forbidden.contains(&"ssn".to_string()));
        assert!(forbidden.contains(&"email".to_string())); // default Never
    }

    #[test]
    fn test_empty_disclosure_with_no_always_fields() {
        let policy = DisclosurePolicy::new(
            vec![DisclosureRule {
                field_name: "age".into(),
                level: DisclosureLevel::Selectable,
            }],
            DisclosureLevel::Selectable,
        );
        let result = validate_disclosure(&policy, &["age".into()], &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_disclosure_for_schema() {
        let schema = CredentialSchema {
            schema_id: "test".into(),
            version: 1,
            fields: vec![
                SchemaField {
                    name: "name".into(),
                    kind: AttributeKind::Raw,
                    source_path: ClaimPath::new("/name").unwrap(),
                    predicate: None,
                    required: true,
                },
                SchemaField {
                    name: "age".into(),
                    kind: AttributeKind::Raw,
                    source_path: ClaimPath::new("/age").unwrap(),
                    predicate: None,
                    required: true,
                },
            ],
            disclosure_policy: DisclosurePolicy::new(
                vec![
                    DisclosureRule {
                        field_name: "name".into(),
                        level: DisclosureLevel::Always,
                    },
                    DisclosureRule {
                        field_name: "age".into(),
                        level: DisclosureLevel::Selectable,
                    },
                ],
                DisclosureLevel::Never,
            ),
            description: None,
        };

        // Valid: disclose required "name"
        assert!(validate_disclosure_for_schema(&schema, &["name".into()]).is_ok());

        // Valid: disclose both
        assert!(validate_disclosure_for_schema(&schema, &["name".into(), "age".into()]).is_ok());

        // Invalid: missing "name"
        assert!(validate_disclosure_for_schema(&schema, &["age".into()]).is_err());
    }

    #[test]
    fn test_all_fields_always() {
        let policy = DisclosurePolicy::new(
            vec![
                DisclosureRule {
                    field_name: "a".into(),
                    level: DisclosureLevel::Always,
                },
                DisclosureRule {
                    field_name: "b".into(),
                    level: DisclosureLevel::Always,
                },
            ],
            DisclosureLevel::Always,
        );
        let names = vec!["a".into(), "b".into()];

        // Must disclose both
        assert!(validate_disclosure(&policy, &names, &["a".into(), "b".into()]).is_ok());
        assert!(validate_disclosure(&policy, &names, &["a".into()]).is_err());
    }
}
