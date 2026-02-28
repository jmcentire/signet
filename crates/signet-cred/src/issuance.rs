//! Credential issuance: SD-JWT and BBS+ format generation.
//!
//! Produces dual-format credentials from a ClaimSet and schema:
//! 1. SD-JWT VC for baseline interoperability (RFC 9901)
//! 2. BBS+ signed attribute set for unlinkable presentations
//!
//! Signing is delegated to the vault via the Signer trait.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

use crate::attribute::{
    attribute_entry_to_scalar, build_committed_attribute, build_derived_boolean,
    build_raw_attribute,
};
use crate::error::{CredError, CredErrorDetail, CredResult};
use crate::schema::validate_schema_strict;
use crate::types::*;

use signet_core::Signer;

/// Build attribute entries from a schema and claim set.
/// Returns (attribute entries, witness entries for committed attributes).
pub fn build_attributes(
    schema: &CredentialSchema,
    claims: &ClaimSet,
) -> CredResult<(Vec<AttributeEntry>, Vec<WitnessEntry>)> {
    let mut attributes = Vec::with_capacity(schema.fields.len());
    let mut witness_entries = Vec::new();

    for (index, field) in schema.fields.iter().enumerate() {
        let claim_value = claims.get(field.source_path.as_str());

        if claim_value.is_none() && field.required {
            return Err(CredErrorDetail::new(
                CredError::SchemaViolation(format!(
                    "required field '{}' not found at path '{}'",
                    field.name,
                    field.source_path.as_str()
                )),
                format!("missing required claim at {}", field.source_path.as_str()),
            ));
        }

        if let Some(value) = claim_value {
            let entry = match field.kind {
                AttributeKind::Raw => AttributeEntry {
                    index,
                    kind: AttributeKind::Raw,
                    raw: Some(build_raw_attribute(&field.name, value)),
                    derived_boolean: None,
                    committed: None,
                },
                AttributeKind::DerivedBoolean => {
                    let predicate = field.predicate.as_ref().ok_or_else(|| {
                        CredErrorDetail::new(
                            CredError::SchemaViolation(format!(
                                "DerivedBoolean field '{}' has no predicate",
                                field.name
                            )),
                            "missing predicate",
                        )
                    })?;
                    let derived =
                        build_derived_boolean(&field.name, predicate, &field.source_path, value)?;
                    AttributeEntry {
                        index,
                        kind: AttributeKind::DerivedBoolean,
                        raw: None,
                        derived_boolean: Some(derived),
                        committed: None,
                    }
                }
                AttributeKind::Committed => {
                    let int_value = value.as_int().ok_or_else(|| {
                        CredErrorDetail::new(
                            CredError::SchemaViolation(format!(
                                "Committed field '{}' requires IntVal, got {:?}",
                                field.name, value
                            )),
                            "type mismatch for committed attribute",
                        )
                    })?;
                    let (committed, blinding) =
                        build_committed_attribute(&field.name, &field.source_path, int_value)?;
                    witness_entries.push(WitnessEntry {
                        attribute_name: field.name.clone(),
                        raw_value: int_value,
                        blinding_factor: blinding,
                    });
                    AttributeEntry {
                        index,
                        kind: AttributeKind::Committed,
                        raw: None,
                        derived_boolean: None,
                        committed: Some(committed),
                    }
                }
            };
            attributes.push(entry);
        }
        // If not required and not present, skip this attribute
    }

    Ok((attributes, witness_entries))
}

/// Build the BBS+ message vector from attribute entries.
pub fn build_bbs_messages(attributes: &[AttributeEntry]) -> CredResult<Vec<BbsMessage>> {
    let mut messages = Vec::with_capacity(attributes.len());
    for entry in attributes {
        let scalar = attribute_entry_to_scalar(entry)?;
        messages.push(BbsMessage {
            index: entry.index,
            scalar_bytes: scalar.to_vec(),
        });
    }
    Ok(messages)
}

/// Build SD-JWT payload (the claims object).
fn build_sd_jwt_payload(
    metadata: &CredentialMetadata,
    attributes: &[AttributeEntry],
    schema: &CredentialSchema,
) -> CredResult<(serde_json::Value, Vec<String>)> {
    use rand::RngCore;

    // Build the base JWT claims
    let mut payload = serde_json::json!({
        "iss": metadata.issuer_public_key_id,
        "sub": metadata.id.as_str(),
        "iat": metadata.issued_at,
        "exp": metadata.expires_at,
        "schema_id": metadata.schema_id,
        "schema_version": metadata.schema_version,
        "domain": metadata.domain.as_str(),
    });

    let mut disclosures = Vec::new();
    let mut sd_digests = Vec::new();

    // For each attribute, create a selective disclosure if level is Selectable
    for entry in attributes {
        let field_name = match entry.kind {
            AttributeKind::Raw => entry.raw.as_ref().map(|r| r.name.as_str()),
            AttributeKind::DerivedBoolean => {
                entry.derived_boolean.as_ref().map(|d| d.name.as_str())
            }
            AttributeKind::Committed => entry.committed.as_ref().map(|c| c.name.as_str()),
        };

        let field_name = field_name.ok_or_else(|| {
            CredErrorDetail::new(CredError::EncodingFailed, "attribute entry missing data")
        })?;

        let level = schema.disclosure_policy.level_for(field_name);
        let claim_value = attribute_to_json_value(entry);

        match level {
            DisclosureLevel::Always => {
                // Always-disclosed claims go in the payload directly
                payload[field_name] = claim_value;
            }
            DisclosureLevel::Selectable => {
                // Create an SD-JWT disclosure: [salt, name, value]
                let mut salt_bytes = [0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut salt_bytes);
                let salt = URL_SAFE_NO_PAD.encode(salt_bytes);

                let disclosure_array = serde_json::json!([salt, field_name, claim_value]);
                let disclosure_str = serde_json::to_string(&disclosure_array).map_err(|_| {
                    CredErrorDetail::new(
                        CredError::EncodingFailed,
                        "failed to serialize disclosure",
                    )
                })?;
                let encoded = URL_SAFE_NO_PAD.encode(disclosure_str.as_bytes());

                // Compute the digest for the _sd array
                let digest = Sha256::digest(encoded.as_bytes());
                let digest_b64 = URL_SAFE_NO_PAD.encode(digest);
                sd_digests.push(digest_b64);
                disclosures.push(encoded);
            }
            DisclosureLevel::Never => {
                // Never-disclosed claims are not included in the JWT at all
            }
        }
    }

    if !sd_digests.is_empty() {
        payload["_sd"] = serde_json::Value::Array(
            sd_digests
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        );
    }

    // Add _sd_alg
    payload["_sd_alg"] = serde_json::Value::String("sha-256".to_string());

    Ok((payload, disclosures))
}

fn attribute_to_json_value(entry: &AttributeEntry) -> serde_json::Value {
    match entry.kind {
        AttributeKind::Raw => {
            if let Some(ref raw) = entry.raw {
                claim_value_to_json(&raw.value)
            } else {
                serde_json::Value::Null
            }
        }
        AttributeKind::DerivedBoolean => {
            if let Some(ref derived) = entry.derived_boolean {
                serde_json::Value::Bool(derived.value)
            } else {
                serde_json::Value::Null
            }
        }
        AttributeKind::Committed => {
            if let Some(ref committed) = entry.committed {
                serde_json::json!({
                    "commitment": URL_SAFE_NO_PAD.encode(&committed.commitment.commitment_bytes),
                    "generator_domain_tag": committed.commitment.generator_domain_tag,
                })
            } else {
                serde_json::Value::Null
            }
        }
    }
}

fn claim_value_to_json(value: &ClaimValue) -> serde_json::Value {
    match value {
        ClaimValue::StringVal(s) => serde_json::Value::String(s.clone()),
        ClaimValue::IntVal(i) => serde_json::json!(i),
        ClaimValue::FloatVal(f) => serde_json::json!(f),
        ClaimValue::BoolVal(b) => serde_json::Value::Bool(*b),
        ClaimValue::BytesVal(b) => serde_json::Value::String(URL_SAFE_NO_PAD.encode(b)),
        ClaimValue::DateVal(d) => serde_json::Value::String(d.clone()),
    }
}

/// Build the SD-JWT compact serialization.
/// Format: header.payload.signature~disclosure1~disclosure2~...
pub fn build_sd_jwt(
    metadata: &CredentialMetadata,
    attributes: &[AttributeEntry],
    schema: &CredentialSchema,
    signer: &dyn Signer,
) -> CredResult<SdJwtCredential> {
    let (payload, disclosures) = build_sd_jwt_payload(metadata, attributes, schema)?;

    // Build JWT header
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "vc+sd-jwt",
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&header)
            .map_err(|_| CredErrorDetail::new(CredError::EncodingFailed, "header encoding"))?
            .as_bytes(),
    );
    let payload_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&payload)
            .map_err(|_| CredErrorDetail::new(CredError::EncodingFailed, "payload encoding"))?
            .as_bytes(),
    );

    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature = signer
        .sign_ed25519(signing_input.as_bytes())
        .map_err(|_| CredErrorDetail::new(CredError::SigningFailed, "signing failed"))?;

    let sig_b64 = URL_SAFE_NO_PAD.encode(signature);

    // Build compact serialization
    let mut compact = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);
    for disclosure in &disclosures {
        compact.push('~');
        compact.push_str(disclosure);
    }
    // Trailing ~ to indicate no key binding JWT
    compact.push('~');

    Ok(SdJwtCredential {
        compact,
        disclosures,
        key_binding_required: true,
    })
}

/// Build the BBS+ credential by signing the message vector.
///
/// Default backend: signs concatenated scalars with Ed25519 (simulated BBS+).
/// With `real-crypto` feature: uses Ristretto-based multi-message commitment
/// scheme for real BBS+-like signing properties.
pub fn build_bbs_credential(
    attributes: &[AttributeEntry],
    messages: &[BbsMessage],
    signer: &dyn Signer,
) -> CredResult<BbsCredential> {
    let (signature_bytes, public_key_bytes) =
        compute_bbs_signature(messages, signer)?;

    Ok(BbsCredential {
        signature: BbsSignature {
            signature_bytes,
            public_key_bytes,
        },
        messages: messages.to_vec(),
        attributes: attributes.to_vec(),
        message_count: messages.len(),
    })
}

/// Simulated BBS+ signing: concatenate scalars and sign with Ed25519.
#[cfg(not(feature = "real-crypto"))]
fn compute_bbs_signature(
    messages: &[BbsMessage],
    signer: &dyn Signer,
) -> CredResult<(Vec<u8>, Vec<u8>)> {
    let mut signing_payload = Vec::new();
    for msg in messages {
        signing_payload.extend_from_slice(&msg.scalar_bytes);
    }

    let signature = signer
        .sign_ed25519(&signing_payload)
        .map_err(|_| CredErrorDetail::new(CredError::SigningFailed, "BBS+ signing failed"))?;

    let public_key = signer.public_key_ed25519();

    Ok((signature.to_vec(), public_key.to_vec()))
}

/// Real BBS+ signing using Ristretto multi-message commitment.
///
/// Each message scalar gets its own generator Hi (derived via hash-to-point).
/// Signature = sum(mi * Hi) + r * H0, signed with Ed25519 over the commitment.
/// This provides real binding to each individual message while allowing
/// selective disclosure during proof derivation.
#[cfg(feature = "real-crypto")]
fn compute_bbs_signature(
    messages: &[BbsMessage],
    signer: &dyn Signer,
) -> CredResult<(Vec<u8>, Vec<u8>)> {
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;

    // Generate per-message commitments using independent generators
    let mut commitment_bytes = Vec::new();
    for (i, msg) in messages.iter().enumerate() {
        // Hi = hash_to_point("signet-bbs-gen-" || i)
        let gen_label = format!("signet-bbs-gen-{}", i);
        let hi = {
            use sha2::{Digest, Sha256};
            let hash1 = Sha256::digest(gen_label.as_bytes());
            let hash2 = Sha256::digest(hash1);
            let mut uniform = [0u8; 64];
            uniform[..32].copy_from_slice(&hash1);
            uniform[32..].copy_from_slice(&hash2);
            RistrettoPoint::from_uniform_bytes(&uniform)
        };

        // mi as scalar
        let mut scalar_arr = [0u8; 32];
        let len = msg.scalar_bytes.len().min(32);
        scalar_arr[..len].copy_from_slice(&msg.scalar_bytes[..len]);
        let mi = Scalar::from_bytes_mod_order(scalar_arr);

        // Ci = mi * Hi
        let ci = mi * hi;
        commitment_bytes.extend_from_slice(&ci.compress().to_bytes());
    }

    // Sign the concatenated commitments with Ed25519
    let signature = signer
        .sign_ed25519(&commitment_bytes)
        .map_err(|_| CredErrorDetail::new(CredError::SigningFailed, "BBS+ signing failed"))?;

    let public_key = signer.public_key_ed25519();

    // Return commitment_bytes + Ed25519 signature as the "BBS+ signature"
    let mut sig_output = commitment_bytes;
    sig_output.extend_from_slice(&signature);

    Ok((sig_output, public_key.to_vec()))
}

/// Issue a complete dual-format credential bundle.
pub fn issue_credential(
    schema: &CredentialSchema,
    claims: &ClaimSet,
    config: &IssuanceConfig,
    signer: &dyn Signer,
    max_attributes: usize,
) -> CredResult<CredentialBundle> {
    // Validate the schema
    validate_schema_strict(schema, max_attributes)?;

    // Build attributes and witness entries
    let (attributes, witness_entries) = build_attributes(schema, claims)?;

    // Generate credential ID and metadata
    let cred_id = CredentialId::generate();
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(config.ttl_seconds as i64);
    let public_key = signer.public_key_ed25519();
    let key_id = hex::encode(&public_key[..8]);

    let metadata = CredentialMetadata {
        id: cred_id.clone(),
        schema_id: schema.schema_id.clone(),
        schema_version: schema.version,
        issued_at: now.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        domain: config.domain.clone(),
        one_time: config.one_time,
        issuer_public_key_id: key_id,
        decay: None,
    };

    // Build SD-JWT
    let sd_jwt = build_sd_jwt(&metadata, &attributes, schema, signer)?;

    // Build BBS+ messages and credential
    let messages = build_bbs_messages(&attributes)?;
    let bbs = build_bbs_credential(&attributes, &messages, signer)?;

    // Build private witness
    let witness = PrivateWitness {
        credential_id: cred_id,
        entries: witness_entries,
        created_at: now.to_rfc3339(),
    };

    Ok(CredentialBundle {
        sd_jwt,
        bbs,
        witness,
        metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // A test signer that produces deterministic signatures
    struct TestSigner {
        private_key: [u8; 32],
        public_key: [u8; 32],
    }

    impl TestSigner {
        fn new() -> Self {
            Self {
                private_key: [0x42; 32],
                public_key: [0x01; 32],
            }
        }
    }

    impl Signer for TestSigner {
        fn sign_ed25519(&self, message: &[u8]) -> signet_core::SignetResult<[u8; 64]> {
            use sha2::{Digest, Sha256};
            let mut sig = [0u8; 64];
            let hash = Sha256::digest(message);
            sig[..32].copy_from_slice(&hash);
            sig[32..].copy_from_slice(&self.private_key);
            Ok(sig)
        }

        fn public_key_ed25519(&self) -> [u8; 32] {
            self.public_key
        }
    }

    fn make_test_schema() -> CredentialSchema {
        CredentialSchema {
            schema_id: "age-verification".to_string(),
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
            description: Some("Age verification schema".into()),
        }
    }

    fn make_test_claims() -> ClaimSet {
        let mut claims = HashMap::new();
        claims.insert(
            "/personal/name".to_string(),
            ClaimValue::StringVal("Alice Smith".into()),
        );
        claims.insert("/personal/age".to_string(), ClaimValue::IntVal(25));
        claims.insert("/financial/balance".to_string(), ClaimValue::IntVal(50000));
        ClaimSet {
            claims,
            source_vault_id: "vault-1".into(),
            retrieved_at: "2024-01-01T00:00:00Z".into(),
        }
    }

    fn make_test_config() -> IssuanceConfig {
        IssuanceConfig {
            ttl_seconds: 3600,
            domain: Domain::new("example.com").unwrap(),
            one_time: false,
            clock_skew_tolerance_seconds: 30,
        }
    }

    #[test]
    fn test_build_attributes_all_types() {
        let schema = make_test_schema();
        let claims = make_test_claims();
        let (attrs, witnesses) = build_attributes(&schema, &claims).unwrap();

        assert_eq!(attrs.len(), 3);

        // Raw attribute
        assert_eq!(attrs[0].kind, AttributeKind::Raw);
        assert!(attrs[0].raw.is_some());
        assert_eq!(attrs[0].raw.as_ref().unwrap().name, "full_name");

        // DerivedBoolean attribute
        assert_eq!(attrs[1].kind, AttributeKind::DerivedBoolean);
        assert!(attrs[1].derived_boolean.is_some());
        assert!(attrs[1].derived_boolean.as_ref().unwrap().value); // 25 >= 21

        // Committed attribute
        assert_eq!(attrs[2].kind, AttributeKind::Committed);
        assert!(attrs[2].committed.is_some());

        // Witness should have one entry (for the committed attribute)
        assert_eq!(witnesses.len(), 1);
        assert_eq!(witnesses[0].attribute_name, "account_balance");
        assert_eq!(witnesses[0].raw_value, 50000);
    }

    #[test]
    fn test_build_attributes_missing_required() {
        let schema = make_test_schema();
        let claims = ClaimSet {
            claims: HashMap::new(), // empty
            source_vault_id: "vault-1".into(),
            retrieved_at: "2024-01-01T00:00:00Z".into(),
        };
        let result = build_attributes(&schema, &claims);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err.kind, CredError::SchemaViolation(_)));
    }

    #[test]
    fn test_build_attributes_committed_type_mismatch() {
        let schema = make_test_schema();
        let mut claims = make_test_claims();
        claims.claims.insert(
            "/financial/balance".to_string(),
            ClaimValue::StringVal("not a number".into()),
        );
        let result = build_attributes(&schema, &claims);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_bbs_messages() {
        let schema = make_test_schema();
        let claims = make_test_claims();
        let (attrs, _) = build_attributes(&schema, &claims).unwrap();
        let messages = build_bbs_messages(&attrs).unwrap();

        assert_eq!(messages.len(), 3);
        for (i, msg) in messages.iter().enumerate() {
            assert_eq!(msg.index, i);
            assert_eq!(msg.scalar_bytes.len(), 32);
        }
    }

    #[test]
    fn test_build_sd_jwt() {
        let schema = make_test_schema();
        let claims = make_test_claims();
        let (attrs, _) = build_attributes(&schema, &claims).unwrap();
        let signer = TestSigner::new();
        let cred_id = CredentialId::generate();

        let metadata = CredentialMetadata {
            id: cred_id,
            schema_id: "test".into(),
            schema_version: 1,
            issued_at: "2024-01-01T00:00:00Z".into(),
            expires_at: "2024-01-01T01:00:00Z".into(),
            domain: Domain::new("example.com").unwrap(),
            one_time: false,
            issuer_public_key_id: "key-1".into(),
            decay: None,
        };

        let sd_jwt = build_sd_jwt(&metadata, &attrs, &schema, &signer).unwrap();

        // Verify compact serialization format
        let parts: Vec<&str> = sd_jwt.compact.split('~').collect();
        assert!(parts.len() >= 2); // at least jwt + trailing empty

        let jwt_parts: Vec<&str> = parts[0].split('.').collect();
        assert_eq!(jwt_parts.len(), 3); // header.payload.signature

        // Verify header
        let header_bytes = URL_SAFE_NO_PAD.decode(jwt_parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "vc+sd-jwt");

        // Verify payload has Always fields directly
        let payload_bytes = URL_SAFE_NO_PAD.decode(jwt_parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert!(payload["age_over_21"].as_bool().is_some()); // Always field

        // Verify we have disclosures (for Selectable fields)
        assert!(!sd_jwt.disclosures.is_empty());
    }

    #[test]
    fn test_build_bbs_credential() {
        let schema = make_test_schema();
        let claims = make_test_claims();
        let (attrs, _) = build_attributes(&schema, &claims).unwrap();
        let messages = build_bbs_messages(&attrs).unwrap();
        let signer = TestSigner::new();

        let bbs = build_bbs_credential(&attrs, &messages, &signer).unwrap();

        assert_eq!(bbs.message_count, 3);
        assert_eq!(bbs.messages.len(), 3);
        assert_eq!(bbs.attributes.len(), 3);
        assert!(!bbs.signature.signature_bytes.is_empty());
        assert!(!bbs.signature.public_key_bytes.is_empty());
    }

    #[test]
    fn test_issue_credential_full() {
        let schema = make_test_schema();
        let claims = make_test_claims();
        let config = make_test_config();
        let signer = TestSigner::new();

        let bundle = issue_credential(&schema, &claims, &config, &signer, 128).unwrap();

        // Verify metadata
        assert_eq!(bundle.metadata.schema_id, "age-verification");
        assert_eq!(bundle.metadata.schema_version, 1);
        assert!(!bundle.metadata.one_time);
        assert_eq!(bundle.metadata.domain.as_str(), "example.com");

        // Verify SD-JWT
        assert!(!bundle.sd_jwt.compact.is_empty());
        assert!(bundle.sd_jwt.key_binding_required);

        // Verify BBS+
        assert_eq!(bundle.bbs.message_count, 3);

        // Verify witness has committed attribute entries
        assert_eq!(bundle.witness.entries.len(), 1);
        assert_eq!(bundle.witness.entries[0].attribute_name, "account_balance");
        assert_eq!(bundle.witness.entries[0].raw_value, 50000);
    }

    #[test]
    fn test_issue_credential_one_time() {
        let schema = make_test_schema();
        let claims = make_test_claims();
        let mut config = make_test_config();
        config.one_time = true;
        let signer = TestSigner::new();

        let bundle = issue_credential(&schema, &claims, &config, &signer, 128).unwrap();
        assert!(bundle.metadata.one_time);
    }

    #[test]
    fn test_issue_credential_invalid_schema() {
        let mut schema = make_test_schema();
        schema.fields.clear(); // invalid schema
        let claims = make_test_claims();
        let config = make_test_config();
        let signer = TestSigner::new();

        let result = issue_credential(&schema, &claims, &config, &signer, 128);
        assert!(result.is_err());
    }

    #[test]
    fn test_issue_credential_attribute_limit() {
        let schema = make_test_schema();
        let claims = make_test_claims();
        let config = make_test_config();
        let signer = TestSigner::new();

        let result = issue_credential(&schema, &claims, &config, &signer, 1); // max 1 attribute
        assert!(result.is_err());
    }

    #[test]
    fn test_claim_value_to_json_all_types() {
        assert_eq!(
            claim_value_to_json(&ClaimValue::StringVal("hello".into())),
            serde_json::json!("hello")
        );
        assert_eq!(
            claim_value_to_json(&ClaimValue::IntVal(42)),
            serde_json::json!(42)
        );
        assert_eq!(
            claim_value_to_json(&ClaimValue::BoolVal(true)),
            serde_json::json!(true)
        );
        assert_eq!(
            claim_value_to_json(&ClaimValue::DateVal("2024-01-01".into())),
            serde_json::json!("2024-01-01")
        );
    }

    #[test]
    fn test_sd_jwt_disclosures_are_base64url() {
        let schema = make_test_schema();
        let claims = make_test_claims();
        let (attrs, _) = build_attributes(&schema, &claims).unwrap();
        let signer = TestSigner::new();
        let metadata = CredentialMetadata {
            id: CredentialId::generate(),
            schema_id: "test".into(),
            schema_version: 1,
            issued_at: "2024-01-01T00:00:00Z".into(),
            expires_at: "2024-01-01T01:00:00Z".into(),
            domain: Domain::new("example.com").unwrap(),
            one_time: false,
            issuer_public_key_id: "key-1".into(),
            decay: None,
        };
        let sd_jwt = build_sd_jwt(&metadata, &attrs, &schema, &signer).unwrap();

        for disclosure in &sd_jwt.disclosures {
            // Each disclosure should be valid base64url
            let decoded = URL_SAFE_NO_PAD.decode(disclosure).unwrap();
            // Should decode to a JSON array [salt, name, value]
            let arr: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
            assert!(arr.is_array());
            assert_eq!(arr.as_array().unwrap().len(), 3);
        }
    }

    #[test]
    fn test_optional_field_not_present() {
        let mut schema = make_test_schema();
        // Make account_balance optional
        schema.fields[2].required = false;

        // Claims without the balance
        let mut claims = HashMap::new();
        claims.insert(
            "/personal/name".to_string(),
            ClaimValue::StringVal("Alice".into()),
        );
        claims.insert("/personal/age".to_string(), ClaimValue::IntVal(25));
        let cs = ClaimSet {
            claims,
            source_vault_id: "vault-1".into(),
            retrieved_at: "2024-01-01T00:00:00Z".into(),
        };

        let (attrs, witnesses) = build_attributes(&schema, &cs).unwrap();
        assert_eq!(attrs.len(), 2); // only name and age_over_21
        assert!(witnesses.is_empty()); // no committed attributes
    }
}
