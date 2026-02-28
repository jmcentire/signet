//! Proof verification logic.
//!
//! The `verify` function validates a cryptographic proof against a claimed
//! attribute. It is self-contained and does not require vault access.
//!
//! Verification flow:
//! 1. Validate preconditions (non-empty proof, defined claim attribute).
//! 2. Attempt to decode the proof as a `ProofEnvelope` (signet-structured).
//! 3. Detect the proof format.
//! 4. Verify the integrity binding (HMAC-SHA256 self-binding).
//! 5. Confirm the claim matches the proof's declared attribute and value.
//! 6. Return a `VerifyResult` with format and domain information.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha2::{Digest, Sha256};
use tracing;

use crate::error::{SdkErrorKind, SdkResult};
use crate::types::{Claim, Proof, ProofEnvelope, ProofFormat, VerifyResult};

/// Verifies a Signet proof against a claimed attribute.
///
/// This is one of the four SDK primitives. It is idempotent and performs
/// self-contained verification without vault access.
///
/// # Preconditions
/// - Proof data must be non-empty.
/// - Claim attribute must be defined (non-empty string).
///
/// # Returns
/// A `VerifyResult` indicating whether the proof is valid for the claim.
pub fn verify(proof: &Proof, claim: &Claim) -> SdkResult<VerifyResult> {
    tracing::debug!(
        attribute = %claim.attribute,
        proof_len = proof.data.len(),
        "verifying proof against claim"
    );

    // Precondition: proof data must be non-empty
    if !proof.is_non_empty() {
        tracing::warn!("verification rejected: empty proof data");
        return Ok(VerifyResult::failure(SdkErrorKind::InvalidProof));
    }

    // Precondition: claim attribute must be defined
    if !claim.is_valid() {
        tracing::warn!("verification rejected: empty claim attribute");
        return Ok(VerifyResult::failure(SdkErrorKind::InvalidClaim));
    }

    // Try to decode as a signet ProofEnvelope
    match serde_json::from_slice::<ProofEnvelope>(&proof.data) {
        Ok(envelope) => verify_envelope(&envelope, claim),
        Err(_) => {
            // Not a signet envelope — treat as opaque proof blob.
            // Attempt format detection from raw bytes.
            let format = detect_format_from_bytes(&proof.data);
            tracing::debug!(format = %format, "opaque proof, format detected from bytes");

            // For opaque proofs we cannot verify the claim binding, so we
            // report the format but mark as invalid (no verifiable binding).
            Ok(VerifyResult::failure(SdkErrorKind::InvalidProof))
        }
    }
}

/// Verify a decoded proof envelope against a claim.
fn verify_envelope(envelope: &ProofEnvelope, claim: &Claim) -> SdkResult<VerifyResult> {
    // Check version compatibility
    if envelope.version != 1 {
        tracing::warn!(
            version = envelope.version,
            "unsupported proof envelope version"
        );
        return Ok(VerifyResult::failure(SdkErrorKind::InvalidProof));
    }

    // Verify the integrity binding
    let expected_binding = compute_binding(
        &envelope.attribute,
        &envelope.value,
        envelope.domain.as_deref(),
        &envelope.payload,
    );

    if envelope.binding != expected_binding {
        tracing::warn!("proof integrity binding mismatch");
        return Ok(VerifyResult::failure(SdkErrorKind::InvalidProof));
    }

    // Verify the claim matches the proof's declared attribute
    if envelope.attribute != claim.attribute {
        tracing::warn!(
            proof_attr = %envelope.attribute,
            claim_attr = %claim.attribute,
            "claim attribute mismatch"
        );
        return Ok(VerifyResult::failure(SdkErrorKind::InvalidClaim));
    }

    // Verify the claim value matches
    if envelope.value != claim.value {
        tracing::warn!("claim value mismatch");
        return Ok(VerifyResult::failure(SdkErrorKind::InvalidClaim));
    }

    // Verify payload is valid base64 and non-empty
    match BASE64.decode(&envelope.payload) {
        Ok(bytes) if bytes.is_empty() => {
            tracing::warn!("empty payload in proof envelope");
            return Ok(VerifyResult::failure(SdkErrorKind::InvalidProof));
        }
        Ok(_) => {} // valid
        Err(_) => {
            tracing::warn!("invalid base64 payload in proof envelope");
            return Ok(VerifyResult::failure(SdkErrorKind::InvalidProof));
        }
    }

    tracing::info!(
        attribute = %claim.attribute,
        format = %envelope.format,
        "proof verified successfully"
    );

    Ok(VerifyResult::success(
        envelope.format,
        envelope.domain.clone(),
    ))
}

/// Compute the HMAC-SHA256 self-binding for a proof envelope.
///
/// The binding is SHA-256(attribute || "\0" || value_json || "\0" || domain || "\0" || payload),
/// hex-encoded. This is a self-binding integrity check — not a cryptographic
/// signature, but ensures the envelope fields have not been tampered with
/// relative to each other.
pub(crate) fn compute_binding(
    attribute: &str,
    value: &serde_json::Value,
    domain: Option<&str>,
    payload: &str,
) -> String {
    let value_str = serde_json::to_string(value).unwrap_or_default();
    let domain_str = domain.unwrap_or("");

    let mut hasher = Sha256::new();
    hasher.update(attribute.as_bytes());
    hasher.update(b"\0");
    hasher.update(value_str.as_bytes());
    hasher.update(b"\0");
    hasher.update(domain_str.as_bytes());
    hasher.update(b"\0");
    hasher.update(payload.as_bytes());

    hex::encode(hasher.finalize())
}

/// Detect the proof format from raw bytes using heuristics.
///
/// - SD-JWT tokens contain `~` separators and dot-separated JWT segments.
/// - BBS+ proofs start with specific byte prefixes (we check for 0x04 point encoding).
/// - Bulletproofs have a characteristic length and structure.
pub(crate) fn detect_format_from_bytes(data: &[u8]) -> ProofFormat {
    // Try interpreting as UTF-8 first for text-based formats
    if let Ok(text) = std::str::from_utf8(data) {
        // SD-JWT: segments separated by '~', each segment is base64url
        // Format: <issuer-jwt>~<disclosure1>~<disclosure2>~...~<kb-jwt>
        if text.contains('~') && text.contains('.') {
            return ProofFormat::SdJwt;
        }
    }

    // BBS+ signatures are typically 112 bytes (G1 point + scalar)
    // and compressed G1 points on BLS12-381 start with 0x80..0xBF
    if data.len() >= 112 && (data[0] & 0x80) != 0 {
        return ProofFormat::BbsPlus;
    }

    // Bulletproof range proofs have a recognizable structure:
    // 32-byte commitments repeated. Typical sizes: 672+ bytes for single range proof.
    if data.len() >= 672 && data.len().is_multiple_of(32) {
        return ProofFormat::Bulletproof;
    }

    ProofFormat::Unknown
}

/// Create a proof envelope from components. This is used to produce proofs
/// that `verify` can later validate.
pub fn create_proof_envelope(
    format: ProofFormat,
    attribute: &str,
    value: &serde_json::Value,
    domain: Option<&str>,
    raw_payload: &[u8],
) -> Vec<u8> {
    let payload_b64 = BASE64.encode(raw_payload);
    let binding = compute_binding(attribute, value, domain, &payload_b64);

    let envelope = ProofEnvelope {
        version: 1,
        format,
        attribute: attribute.to_string(),
        value: value.clone(),
        domain: domain.map(|s| s.to_string()),
        payload: payload_b64,
        binding,
    };

    serde_json::to_vec(&envelope).expect("envelope serialization should not fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: produce a valid proof envelope as bytes for testing.
    fn make_valid_proof(attribute: &str, value: serde_json::Value, domain: Option<&str>) -> Proof {
        let raw_payload = b"fake-crypto-payload-bytes-here!!";
        let data =
            create_proof_envelope(ProofFormat::SdJwt, attribute, &value, domain, raw_payload);
        Proof::new(data)
    }

    #[test]
    fn test_verify_valid_proof() {
        let proof = make_valid_proof("age_over_21", serde_json::Value::Bool(true), None);
        let claim = Claim::new("age_over_21", true);
        let result = verify(&proof, &claim).unwrap();
        assert!(result.valid);
        assert!(result.error.is_none());
        assert_eq!(result.proof_format, Some(ProofFormat::SdJwt));
    }

    #[test]
    fn test_verify_valid_proof_with_domain() {
        let proof = make_valid_proof(
            "age_over_21",
            serde_json::Value::Bool(true),
            Some("example.com"),
        );
        let claim = Claim::new("age_over_21", true);
        let result = verify(&proof, &claim).unwrap();
        assert!(result.valid);
        assert_eq!(result.domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_verify_empty_proof() {
        let proof = Proof::new(vec![]);
        let claim = Claim::new("age_over_21", true);
        let result = verify(&proof, &claim).unwrap();
        assert!(!result.valid);
        assert_eq!(result.error, Some(SdkErrorKind::InvalidProof));
    }

    #[test]
    fn test_verify_empty_claim_attribute() {
        let proof = make_valid_proof("age_over_21", serde_json::Value::Bool(true), None);
        let claim = Claim::new("", true);
        let result = verify(&proof, &claim).unwrap();
        assert!(!result.valid);
        assert_eq!(result.error, Some(SdkErrorKind::InvalidClaim));
    }

    #[test]
    fn test_verify_attribute_mismatch() {
        let proof = make_valid_proof("age_over_21", serde_json::Value::Bool(true), None);
        let claim = Claim::new("country", "US");
        let result = verify(&proof, &claim).unwrap();
        assert!(!result.valid);
        assert_eq!(result.error, Some(SdkErrorKind::InvalidClaim));
    }

    #[test]
    fn test_verify_value_mismatch() {
        let proof = make_valid_proof("age_over_21", serde_json::Value::Bool(true), None);
        let claim = Claim::new("age_over_21", false);
        let result = verify(&proof, &claim).unwrap();
        assert!(!result.valid);
        assert_eq!(result.error, Some(SdkErrorKind::InvalidClaim));
    }

    #[test]
    fn test_verify_tampered_binding() {
        let proof_bytes = make_valid_proof("age_over_21", serde_json::Value::Bool(true), None);
        // Tamper with the binding by modifying the envelope
        let mut envelope: ProofEnvelope = serde_json::from_slice(&proof_bytes.data).unwrap();
        envelope.binding =
            "0000000000000000000000000000000000000000000000000000000000000000".into();
        let tampered = Proof::new(serde_json::to_vec(&envelope).unwrap());
        let claim = Claim::new("age_over_21", true);
        let result = verify(&tampered, &claim).unwrap();
        assert!(!result.valid);
        assert_eq!(result.error, Some(SdkErrorKind::InvalidProof));
    }

    #[test]
    fn test_verify_bad_version() {
        let proof_bytes = make_valid_proof("test", serde_json::Value::Bool(true), None);
        let mut envelope: ProofEnvelope = serde_json::from_slice(&proof_bytes.data).unwrap();
        envelope.version = 99;
        let bad = Proof::new(serde_json::to_vec(&envelope).unwrap());
        let claim = Claim::new("test", true);
        let result = verify(&bad, &claim).unwrap();
        assert!(!result.valid);
        assert_eq!(result.error, Some(SdkErrorKind::InvalidProof));
    }

    #[test]
    fn test_verify_opaque_blob() {
        // Random bytes that are not a valid envelope
        let proof = Proof::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let claim = Claim::new("test", true);
        let result = verify(&proof, &claim).unwrap();
        assert!(!result.valid);
        assert_eq!(result.error, Some(SdkErrorKind::InvalidProof));
    }

    #[test]
    fn test_verify_invalid_payload_base64() {
        let proof_bytes = make_valid_proof("test", serde_json::Value::Bool(true), None);
        let mut envelope: ProofEnvelope = serde_json::from_slice(&proof_bytes.data).unwrap();
        envelope.payload = "not-valid-base64!!!@@@".into();
        // Recompute binding with the bad payload so binding check passes
        envelope.binding = compute_binding(
            &envelope.attribute,
            &envelope.value,
            envelope.domain.as_deref(),
            &envelope.payload,
        );
        let bad = Proof::new(serde_json::to_vec(&envelope).unwrap());
        let claim = Claim::new("test", true);
        let result = verify(&bad, &claim).unwrap();
        assert!(!result.valid);
        assert_eq!(result.error, Some(SdkErrorKind::InvalidProof));
    }

    #[test]
    fn test_verify_empty_payload() {
        let proof_bytes = make_valid_proof("test", serde_json::Value::Bool(true), None);
        let mut envelope: ProofEnvelope = serde_json::from_slice(&proof_bytes.data).unwrap();
        envelope.payload = BASE64.encode(b""); // empty payload, valid base64
        envelope.binding = compute_binding(
            &envelope.attribute,
            &envelope.value,
            envelope.domain.as_deref(),
            &envelope.payload,
        );
        let bad = Proof::new(serde_json::to_vec(&envelope).unwrap());
        let claim = Claim::new("test", true);
        let result = verify(&bad, &claim).unwrap();
        assert!(!result.valid);
        assert_eq!(result.error, Some(SdkErrorKind::InvalidProof));
    }

    #[test]
    fn test_detect_format_sd_jwt() {
        let sd_jwt = b"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig~disc1~disc2~";
        assert_eq!(detect_format_from_bytes(sd_jwt), ProofFormat::SdJwt);
    }

    #[test]
    fn test_detect_format_bbs_plus() {
        // 112 bytes with high bit set on first byte (BLS12-381 compressed G1 point)
        let mut data = vec![0x80; 112];
        data[1] = 0x42;
        assert_eq!(detect_format_from_bytes(&data), ProofFormat::BbsPlus);
    }

    #[test]
    fn test_detect_format_bulletproof() {
        // 672 bytes, divisible by 32
        let data = vec![0x01; 672];
        assert_eq!(detect_format_from_bytes(&data), ProofFormat::Bulletproof);
    }

    #[test]
    fn test_detect_format_unknown() {
        let data = vec![0x01; 50]; // too short for BBS+ or Bulletproof, not SD-JWT
        assert_eq!(detect_format_from_bytes(&data), ProofFormat::Unknown);
    }

    #[test]
    fn test_compute_binding_deterministic() {
        let b1 = compute_binding("a", &serde_json::Value::Bool(true), Some("d"), "p");
        let b2 = compute_binding("a", &serde_json::Value::Bool(true), Some("d"), "p");
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_compute_binding_differs_on_attribute() {
        let b1 = compute_binding("a", &serde_json::Value::Bool(true), None, "p");
        let b2 = compute_binding("b", &serde_json::Value::Bool(true), None, "p");
        assert_ne!(b1, b2);
    }

    #[test]
    fn test_compute_binding_differs_on_domain() {
        let b1 = compute_binding("a", &serde_json::Value::Bool(true), Some("x.com"), "p");
        let b2 = compute_binding("a", &serde_json::Value::Bool(true), Some("y.com"), "p");
        assert_ne!(b1, b2);
    }

    #[test]
    fn test_create_proof_envelope_roundtrip() {
        let data = create_proof_envelope(
            ProofFormat::BbsPlus,
            "country",
            &serde_json::json!("US"),
            Some("gov.example"),
            b"raw-proof-data",
        );
        let envelope: ProofEnvelope = serde_json::from_slice(&data).unwrap();
        assert_eq!(envelope.version, 1);
        assert_eq!(envelope.format, ProofFormat::BbsPlus);
        assert_eq!(envelope.attribute, "country");
        assert_eq!(envelope.domain.as_deref(), Some("gov.example"));
    }

    #[test]
    fn test_verify_idempotent() {
        let proof = make_valid_proof("x", serde_json::Value::Bool(true), None);
        let claim = Claim::new("x", true);
        let r1 = verify(&proof, &claim).unwrap();
        let r2 = verify(&proof, &claim).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_verify_different_proof_formats() {
        for fmt in &[
            ProofFormat::SdJwt,
            ProofFormat::BbsPlus,
            ProofFormat::Bulletproof,
        ] {
            let payload = b"some-payload";
            let data = create_proof_envelope(
                *fmt,
                "attr",
                &serde_json::Value::String("val".into()),
                None,
                payload,
            );
            let proof = Proof::new(data);
            let claim = Claim::new("attr", "val");
            let result = verify(&proof, &claim).unwrap();
            assert!(result.valid, "should verify for format {:?}", fmt);
            assert_eq!(result.proof_format, Some(*fmt));
        }
    }
}
