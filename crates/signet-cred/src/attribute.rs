//! Attribute handling: raw, derived boolean, and committed attributes.
//!
//! Includes predicate evaluation, scalar encoding for BBS+ message vectors,
//! and Pedersen commitment generation.

use sha2::{Digest, Sha256};

use crate::error::{CredError, CredErrorDetail, CredResult};
use crate::types::*;

// ---------------------------------------------------------------------------
// Predicate evaluation
// ---------------------------------------------------------------------------

/// Evaluate a Predicate against a ClaimValue to produce a boolean result.
/// Pure function, deterministic.
pub fn evaluate_predicate(predicate: &Predicate, value: &ClaimValue) -> CredResult<bool> {
    match predicate {
        Predicate::GreaterThan(threshold) => {
            let v = require_int(value)?;
            Ok(v > *threshold)
        }
        Predicate::LessThan(threshold) => {
            let v = require_int(value)?;
            Ok(v < *threshold)
        }
        Predicate::GreaterThanOrEqual(threshold) => {
            let v = require_int(value)?;
            Ok(v >= *threshold)
        }
        Predicate::LessThanOrEqual(threshold) => {
            let v = require_int(value)?;
            Ok(v <= *threshold)
        }
        Predicate::EqualTo(expected) => Ok(values_equal(value, expected)),
        Predicate::NotEqualTo(expected) => Ok(!values_equal(value, expected)),
        Predicate::InSet(set) => {
            if set.is_empty() {
                return Err(CredErrorDetail::new(
                    CredError::InvalidPredicate("InSet predicate has an empty set".into()),
                    "empty set",
                ));
            }
            Ok(set.iter().any(|s| values_equal(value, s)))
        }
    }
}

fn require_int(value: &ClaimValue) -> CredResult<i64> {
    match value {
        ClaimValue::IntVal(v) => Ok(*v),
        _ => Err(CredErrorDetail::new(
            CredError::InvalidPredicate("comparison predicate requires IntVal".into()),
            "type mismatch",
        )),
    }
}

fn values_equal(a: &ClaimValue, b: &ClaimValue) -> bool {
    match (a, b) {
        (ClaimValue::StringVal(a), ClaimValue::StringVal(b)) => a == b,
        (ClaimValue::IntVal(a), ClaimValue::IntVal(b)) => a == b,
        (ClaimValue::BoolVal(a), ClaimValue::BoolVal(b)) => a == b,
        (ClaimValue::BytesVal(a), ClaimValue::BytesVal(b)) => a == b,
        (ClaimValue::DateVal(a), ClaimValue::DateVal(b)) => a == b,
        (ClaimValue::FloatVal(a), ClaimValue::FloatVal(b)) => (a - b).abs() < f64::EPSILON,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Scalar encoding — ClaimValue to 32-byte BBS+ scalar
// ---------------------------------------------------------------------------

/// Determine the canonical encoding for a ClaimValue type.
pub fn encoding_for_claim(value: &ClaimValue) -> ScalarEncoding {
    match value {
        ClaimValue::StringVal(_) => ScalarEncoding::Utf8HashToScalar,
        ClaimValue::IntVal(_) => ScalarEncoding::Int64LittleEndian,
        ClaimValue::FloatVal(_) => ScalarEncoding::Utf8HashToScalar,
        ClaimValue::BoolVal(_) => ScalarEncoding::BoolSingleByte,
        ClaimValue::BytesVal(_) => ScalarEncoding::BytesDirect,
        ClaimValue::DateVal(_) => ScalarEncoding::DateToEpochDays,
    }
}

/// Encode a ClaimValue to a 32-byte BBS+ scalar using the specified encoding scheme.
pub fn encode_claim_to_scalar(
    value: &ClaimValue,
    encoding: ScalarEncoding,
) -> CredResult<[u8; 32]> {
    match (encoding, value) {
        (ScalarEncoding::Utf8HashToScalar, ClaimValue::StringVal(s)) => {
            Ok(hash_to_scalar(s.as_bytes()))
        }
        (ScalarEncoding::Utf8HashToScalar, ClaimValue::FloatVal(f)) => {
            let s = format!("{}", f);
            Ok(hash_to_scalar(s.as_bytes()))
        }
        (ScalarEncoding::Int64LittleEndian, ClaimValue::IntVal(v)) => {
            let mut scalar = [0u8; 32];
            scalar[..8].copy_from_slice(&v.to_le_bytes());
            Ok(scalar)
        }
        (ScalarEncoding::BoolSingleByte, ClaimValue::BoolVal(b)) => {
            let mut scalar = [0u8; 32];
            scalar[0] = if *b { 1 } else { 0 };
            Ok(scalar)
        }
        (ScalarEncoding::BytesDirect, ClaimValue::BytesVal(b)) => {
            if b.len() > 32 {
                // Hash it if too long
                Ok(hash_to_scalar(b))
            } else {
                let mut scalar = [0u8; 32];
                scalar[..b.len()].copy_from_slice(b);
                Ok(scalar)
            }
        }
        (ScalarEncoding::DateToEpochDays, ClaimValue::DateVal(d)) => {
            let days = date_to_epoch_days(d)?;
            let mut scalar = [0u8; 32];
            scalar[..8].copy_from_slice(&days.to_le_bytes());
            Ok(scalar)
        }
        _ => Err(CredErrorDetail::new(
            CredError::EncodingFailed,
            "encoding scheme incompatible with value type",
        )),
    }
}

fn hash_to_scalar(data: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(data);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash);
    // Ensure the scalar is less than the group order by clearing the high bit
    scalar[31] &= 0x7F;
    scalar
}

fn date_to_epoch_days(date_str: &str) -> CredResult<i64> {
    // Parse YYYY-MM-DD format
    let parsed = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d").map_err(|_| {
        CredErrorDetail::new(
            CredError::EncodingFailed,
            "invalid date format (expected YYYY-MM-DD)",
        )
    })?;
    let epoch = chrono::NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();
    let days = (parsed - epoch).num_days();
    Ok(days)
}

// ---------------------------------------------------------------------------
// Build attribute entries from schema + claims
// ---------------------------------------------------------------------------

/// Build a RawAttribute from a schema field and claim value.
pub fn build_raw_attribute(name: &str, value: &ClaimValue) -> RawAttribute {
    RawAttribute {
        name: name.to_string(),
        value: value.clone(),
    }
}

/// Build a DerivedBooleanAttribute by evaluating the predicate.
pub fn build_derived_boolean(
    name: &str,
    predicate: &Predicate,
    source_path: &ClaimPath,
    value: &ClaimValue,
) -> CredResult<DerivedBooleanAttribute> {
    let result = evaluate_predicate(predicate, value)?;
    Ok(DerivedBooleanAttribute {
        name: name.to_string(),
        predicate: predicate.clone(),
        source_path: source_path.clone(),
        value: result,
    })
}

/// Generate a Pedersen commitment for a numeric value.
/// Returns (CommittedAttribute, BlindingFactor).
pub fn build_committed_attribute(
    name: &str,
    source_path: &ClaimPath,
    value: i64,
) -> CredResult<(CommittedAttribute, BlindingFactor)> {
    use rand::RngCore;

    // Generate random blinding factor
    let mut blinding_bytes = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut blinding_bytes);

    // Compute Pedersen commitment: C = v*G + r*H
    // Using hash-based simulation: commitment = SHA-256(domain_tag || value_le || blinding_factor)
    let commitment_bytes = compute_pedersen_commitment(value, &blinding_bytes);

    let commitment = PedersenCommitment {
        commitment_bytes: commitment_bytes.to_vec(),
        generator_domain_tag: PedersenCommitment::DOMAIN_TAG.to_string(),
    };

    let committed = CommittedAttribute {
        name: name.to_string(),
        commitment,
        source_path: source_path.clone(),
    };

    let blinding = BlindingFactor {
        attribute_name: name.to_string(),
        factor_bytes: blinding_bytes,
    };

    Ok((committed, blinding))
}

/// Compute a Pedersen commitment using hash-based construction.
/// C = SHA-256("signet-cred-pedersen-v1" || value_le || blinding_factor)
fn compute_pedersen_commitment(value: i64, blinding: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PedersenCommitment::DOMAIN_TAG.as_bytes());
    hasher.update(value.to_le_bytes());
    hasher.update(blinding);
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

/// Verify that a Pedersen commitment matches the given value and blinding factor.
pub fn verify_pedersen_commitment(
    commitment: &PedersenCommitment,
    value: i64,
    blinding: &[u8],
) -> bool {
    let expected = compute_pedersen_commitment(value, blinding);
    commitment.commitment_bytes == expected.to_vec()
}

/// Encode an AttributeEntry to a BBS+ scalar.
pub fn attribute_entry_to_scalar(entry: &AttributeEntry) -> CredResult<[u8; 32]> {
    match entry.kind {
        AttributeKind::Raw => {
            let raw = entry.raw.as_ref().ok_or_else(|| {
                CredErrorDetail::new(CredError::EncodingFailed, "Raw attribute missing value")
            })?;
            let encoding = encoding_for_claim(&raw.value);
            encode_claim_to_scalar(&raw.value, encoding)
        }
        AttributeKind::DerivedBoolean => {
            let derived = entry.derived_boolean.as_ref().ok_or_else(|| {
                CredErrorDetail::new(
                    CredError::EncodingFailed,
                    "DerivedBoolean attribute missing value",
                )
            })?;
            encode_claim_to_scalar(
                &ClaimValue::BoolVal(derived.value),
                ScalarEncoding::BoolSingleByte,
            )
        }
        AttributeKind::Committed => {
            let committed = entry.committed.as_ref().ok_or_else(|| {
                CredErrorDetail::new(
                    CredError::EncodingFailed,
                    "Committed attribute missing value",
                )
            })?;
            // For BBS+ message vector, encode the commitment bytes
            if committed.commitment.commitment_bytes.len() > 32 {
                Ok(hash_to_scalar(&committed.commitment.commitment_bytes))
            } else {
                let mut scalar = [0u8; 32];
                let len = committed.commitment.commitment_bytes.len().min(32);
                scalar[..len].copy_from_slice(&committed.commitment.commitment_bytes[..len]);
                Ok(scalar)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Predicate evaluation tests ---

    #[test]
    fn test_greater_than_true() {
        let result = evaluate_predicate(&Predicate::GreaterThan(18), &ClaimValue::IntVal(25));
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn test_greater_than_false() {
        let result = evaluate_predicate(&Predicate::GreaterThan(30), &ClaimValue::IntVal(25));
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_greater_than_equal_boundary() {
        let result = evaluate_predicate(&Predicate::GreaterThan(25), &ClaimValue::IntVal(25));
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_less_than() {
        assert!(evaluate_predicate(&Predicate::LessThan(30), &ClaimValue::IntVal(25)).unwrap());
        assert!(!evaluate_predicate(&Predicate::LessThan(20), &ClaimValue::IntVal(25)).unwrap());
    }

    #[test]
    fn test_greater_than_or_equal() {
        assert!(
            evaluate_predicate(&Predicate::GreaterThanOrEqual(21), &ClaimValue::IntVal(21))
                .unwrap()
        );
        assert!(
            evaluate_predicate(&Predicate::GreaterThanOrEqual(21), &ClaimValue::IntVal(25))
                .unwrap()
        );
        assert!(
            !evaluate_predicate(&Predicate::GreaterThanOrEqual(21), &ClaimValue::IntVal(20))
                .unwrap()
        );
    }

    #[test]
    fn test_less_than_or_equal() {
        assert!(
            evaluate_predicate(&Predicate::LessThanOrEqual(25), &ClaimValue::IntVal(25)).unwrap()
        );
        assert!(
            !evaluate_predicate(&Predicate::LessThanOrEqual(24), &ClaimValue::IntVal(25)).unwrap()
        );
    }

    #[test]
    fn test_equal_to() {
        assert!(evaluate_predicate(
            &Predicate::EqualTo(ClaimValue::StringVal("US".into())),
            &ClaimValue::StringVal("US".into()),
        )
        .unwrap());
        assert!(!evaluate_predicate(
            &Predicate::EqualTo(ClaimValue::StringVal("US".into())),
            &ClaimValue::StringVal("UK".into()),
        )
        .unwrap());
    }

    #[test]
    fn test_not_equal_to() {
        assert!(evaluate_predicate(
            &Predicate::NotEqualTo(ClaimValue::IntVal(0)),
            &ClaimValue::IntVal(42),
        )
        .unwrap());
    }

    #[test]
    fn test_in_set() {
        let set = vec![
            ClaimValue::StringVal("US".into()),
            ClaimValue::StringVal("CA".into()),
            ClaimValue::StringVal("UK".into()),
        ];
        assert!(evaluate_predicate(
            &Predicate::InSet(set.clone()),
            &ClaimValue::StringVal("US".into())
        )
        .unwrap());
        assert!(
            !evaluate_predicate(&Predicate::InSet(set), &ClaimValue::StringVal("FR".into()))
                .unwrap()
        );
    }

    #[test]
    fn test_in_set_empty() {
        let result = evaluate_predicate(&Predicate::InSet(vec![]), &ClaimValue::IntVal(1));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err.kind, CredError::InvalidPredicate(_)));
    }

    #[test]
    fn test_type_mismatch_predicate() {
        let result = evaluate_predicate(
            &Predicate::GreaterThan(10),
            &ClaimValue::StringVal("hello".into()),
        );
        assert!(result.is_err());
    }

    // --- Scalar encoding tests ---

    #[test]
    fn test_encode_string_to_scalar() {
        let scalar = encode_claim_to_scalar(
            &ClaimValue::StringVal("hello".into()),
            ScalarEncoding::Utf8HashToScalar,
        )
        .unwrap();
        assert_eq!(scalar.len(), 32);
        // Deterministic
        let scalar2 = encode_claim_to_scalar(
            &ClaimValue::StringVal("hello".into()),
            ScalarEncoding::Utf8HashToScalar,
        )
        .unwrap();
        assert_eq!(scalar, scalar2);
    }

    #[test]
    fn test_encode_int_to_scalar() {
        let scalar =
            encode_claim_to_scalar(&ClaimValue::IntVal(42), ScalarEncoding::Int64LittleEndian)
                .unwrap();
        assert_eq!(scalar[0], 42);
        assert_eq!(scalar[1], 0);
    }

    #[test]
    fn test_encode_negative_int() {
        let scalar =
            encode_claim_to_scalar(&ClaimValue::IntVal(-1), ScalarEncoding::Int64LittleEndian)
                .unwrap();
        // -1 in i64 LE is all 0xFF for the first 8 bytes
        assert_eq!(scalar[..8], (-1i64).to_le_bytes());
    }

    #[test]
    fn test_encode_bool_to_scalar() {
        let scalar_true =
            encode_claim_to_scalar(&ClaimValue::BoolVal(true), ScalarEncoding::BoolSingleByte)
                .unwrap();
        assert_eq!(scalar_true[0], 1);

        let scalar_false =
            encode_claim_to_scalar(&ClaimValue::BoolVal(false), ScalarEncoding::BoolSingleByte)
                .unwrap();
        assert_eq!(scalar_false[0], 0);
    }

    #[test]
    fn test_encode_bytes_to_scalar_short() {
        let bytes = vec![1, 2, 3, 4];
        let scalar = encode_claim_to_scalar(
            &ClaimValue::BytesVal(bytes.clone()),
            ScalarEncoding::BytesDirect,
        )
        .unwrap();
        assert_eq!(&scalar[..4], &bytes[..]);
        assert_eq!(scalar[4], 0);
    }

    #[test]
    fn test_encode_bytes_to_scalar_long() {
        let bytes = vec![0xAB; 64];
        let scalar =
            encode_claim_to_scalar(&ClaimValue::BytesVal(bytes), ScalarEncoding::BytesDirect)
                .unwrap();
        // Should be hashed since > 32 bytes
        assert_eq!(scalar.len(), 32);
    }

    #[test]
    fn test_encode_date_to_scalar() {
        let scalar = encode_claim_to_scalar(
            &ClaimValue::DateVal("2000-01-01".into()),
            ScalarEncoding::DateToEpochDays,
        )
        .unwrap();
        // 2000-01-01 is 10957 days after 1970-01-01
        let days = i64::from_le_bytes(scalar[..8].try_into().unwrap());
        assert_eq!(days, 10957);
    }

    #[test]
    fn test_encode_date_invalid() {
        let result = encode_claim_to_scalar(
            &ClaimValue::DateVal("not-a-date".into()),
            ScalarEncoding::DateToEpochDays,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_encoding_mismatch() {
        let result = encode_claim_to_scalar(
            &ClaimValue::StringVal("hello".into()),
            ScalarEncoding::Int64LittleEndian,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_encoding_for_claim_types() {
        assert_eq!(
            encoding_for_claim(&ClaimValue::StringVal("".into())),
            ScalarEncoding::Utf8HashToScalar
        );
        assert_eq!(
            encoding_for_claim(&ClaimValue::IntVal(0)),
            ScalarEncoding::Int64LittleEndian
        );
        assert_eq!(
            encoding_for_claim(&ClaimValue::BoolVal(true)),
            ScalarEncoding::BoolSingleByte
        );
        assert_eq!(
            encoding_for_claim(&ClaimValue::BytesVal(vec![])),
            ScalarEncoding::BytesDirect
        );
        assert_eq!(
            encoding_for_claim(&ClaimValue::DateVal("".into())),
            ScalarEncoding::DateToEpochDays
        );
    }

    // --- Attribute building tests ---

    #[test]
    fn test_build_raw_attribute() {
        let attr = build_raw_attribute("full_name", &ClaimValue::StringVal("Alice".into()));
        assert_eq!(attr.name, "full_name");
        assert_eq!(attr.value, ClaimValue::StringVal("Alice".into()));
    }

    #[test]
    fn test_build_derived_boolean() {
        let path = ClaimPath::new("/personal/age").unwrap();
        let attr = build_derived_boolean(
            "age_over_21",
            &Predicate::GreaterThanOrEqual(21),
            &path,
            &ClaimValue::IntVal(25),
        )
        .unwrap();
        assert_eq!(attr.name, "age_over_21");
        assert!(attr.value);
    }

    #[test]
    fn test_build_derived_boolean_false() {
        let path = ClaimPath::new("/personal/age").unwrap();
        let attr = build_derived_boolean(
            "age_over_21",
            &Predicate::GreaterThanOrEqual(21),
            &path,
            &ClaimValue::IntVal(18),
        )
        .unwrap();
        assert!(!attr.value);
    }

    #[test]
    fn test_build_committed_attribute() {
        let path = ClaimPath::new("/financial/balance").unwrap();
        let (committed, blinding) = build_committed_attribute("balance", &path, 50000).unwrap();
        assert_eq!(committed.name, "balance");
        assert_eq!(
            committed.commitment.generator_domain_tag,
            PedersenCommitment::DOMAIN_TAG
        );
        assert_eq!(blinding.attribute_name, "balance");
        assert_eq!(blinding.factor_bytes.len(), 32);
    }

    #[test]
    fn test_pedersen_commitment_verification() {
        let path = ClaimPath::new("/financial/balance").unwrap();
        let (committed, blinding) = build_committed_attribute("balance", &path, 50000).unwrap();
        assert!(verify_pedersen_commitment(
            &committed.commitment,
            50000,
            &blinding.factor_bytes,
        ));
        // Wrong value should fail
        assert!(!verify_pedersen_commitment(
            &committed.commitment,
            50001,
            &blinding.factor_bytes,
        ));
        // Wrong blinding should fail
        assert!(!verify_pedersen_commitment(
            &committed.commitment,
            50000,
            &vec![0u8; 32],
        ));
    }

    #[test]
    fn test_pedersen_commitment_deterministic() {
        let blinding = vec![0xAA; 32];
        let c1 = compute_pedersen_commitment(100, &blinding);
        let c2 = compute_pedersen_commitment(100, &blinding);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_pedersen_commitment_different_values() {
        let blinding = vec![0xAA; 32];
        let c1 = compute_pedersen_commitment(100, &blinding);
        let c2 = compute_pedersen_commitment(200, &blinding);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_attribute_entry_to_scalar_raw() {
        let entry = AttributeEntry {
            index: 0,
            kind: AttributeKind::Raw,
            raw: Some(RawAttribute {
                name: "name".into(),
                value: ClaimValue::StringVal("Alice".into()),
            }),
            derived_boolean: None,
            committed: None,
        };
        let scalar = attribute_entry_to_scalar(&entry).unwrap();
        assert_eq!(scalar.len(), 32);
    }

    #[test]
    fn test_attribute_entry_to_scalar_boolean() {
        let entry = AttributeEntry {
            index: 1,
            kind: AttributeKind::DerivedBoolean,
            raw: None,
            derived_boolean: Some(DerivedBooleanAttribute {
                name: "age_over_21".into(),
                predicate: Predicate::GreaterThanOrEqual(21),
                source_path: ClaimPath::new("/personal/age").unwrap(),
                value: true,
            }),
            committed: None,
        };
        let scalar = attribute_entry_to_scalar(&entry).unwrap();
        assert_eq!(scalar[0], 1);
    }

    #[test]
    fn test_attribute_entry_to_scalar_committed() {
        let entry = AttributeEntry {
            index: 2,
            kind: AttributeKind::Committed,
            raw: None,
            derived_boolean: None,
            committed: Some(CommittedAttribute {
                name: "balance".into(),
                commitment: PedersenCommitment {
                    commitment_bytes: vec![0x42; 32],
                    generator_domain_tag: PedersenCommitment::DOMAIN_TAG.to_string(),
                },
                source_path: ClaimPath::new("/financial/balance").unwrap(),
            }),
        };
        let scalar = attribute_entry_to_scalar(&entry).unwrap();
        assert_eq!(scalar.len(), 32);
    }

    #[test]
    fn test_scalar_high_bit_cleared() {
        // hash_to_scalar should clear the high bit for group order compliance
        let scalar = hash_to_scalar(b"test");
        assert_eq!(scalar[31] & 0x80, 0);
    }
}
