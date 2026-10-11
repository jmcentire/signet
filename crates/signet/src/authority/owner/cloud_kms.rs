//! Credential-free Cloud KMS protocol adapter. The deployment supplies the authenticated
//! transport; this module never loads ADC, shells out, or accepts a caller-selected key.
//! EC_SIGN_ED25519 uses raw data (not a pre-hashed digest) and SOFTWARE protection.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Value};
use signet_core::{Signer, SignetError, SignetResult};

/// Transport must POST to Google's fixed Cloud KMS API with workload identity,
/// a bounded timeout and no redirects. Do not include upstream errors or tokens in logs.
pub trait KmsTransport: Send + Sync {
    fn asymmetric_sign(&self, key_version: &str, request: &Value) -> SignetResult<Value>;
}
pub struct KmsSigner<T> {
    transport: T,
    key_version: String,
    public_key: VerifyingKey,
}
fn invalid() -> SignetError {
    SignetError::Crypto("Cloud KMS signing or integrity validation failed".into())
}
/// Castagnoli CRC, as required by Cloud KMS's request/response integrity contract.
fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f63b78 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
impl<T: KmsTransport> KmsSigner<T> {
    /// Pin an operator-verified public key and numeric version; never use a rotating alias.
    pub fn new(transport: T, key_version: String, public_key: [u8; 32]) -> SignetResult<Self> {
        let parts: Vec<_> = key_version.split('/').collect();
        if parts.len() != 10
            || parts[0] != "projects"
            || parts[2] != "locations"
            || parts[4] != "keyRings"
            || parts[6] != "cryptoKeys"
            || parts[8] != "cryptoKeyVersions"
            || !parts.iter().all(|p| {
                !p.is_empty()
                    && p.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            })
            || parts[9].parse::<u32>().ok().is_none_or(|v| v == 0)
        {
            return Err(invalid());
        }
        let public_key = VerifyingKey::from_bytes(&public_key).map_err(|_| invalid())?;
        if public_key.is_weak() {
            return Err(invalid());
        }
        Ok(Self {
            transport,
            key_version,
            public_key,
        })
    }
}
impl<T: KmsTransport> Signer for KmsSigner<T> {
    fn public_key_ed25519(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }
    fn sign_ed25519(&self, bytes: &[u8]) -> SignetResult<[u8; 64]> {
        let response = self
            .transport
            .asymmetric_sign(
                &self.key_version,
                &json!({
                    "data": STANDARD.encode(bytes), "dataCrc32c": crc32c(bytes).to_string()
                }),
            )
            .map_err(|_| invalid())?;
        if response["name"] != self.key_version
            || response["verifiedDataCrc32c"] != true
            || response["protectionLevel"] != "SOFTWARE"
        {
            return Err(invalid());
        }
        let signature = STANDARD
            .decode(response["signature"].as_str().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        let checksum = response["signatureCrc32c"]
            .as_str()
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(invalid)?;
        if crc32c(&signature) != checksum {
            return Err(invalid());
        }
        let signature = Signature::from_slice(&signature).map_err(|_| invalid())?;
        self.public_key
            .verify_strict(bytes, &signature)
            .map_err(|_| invalid())?;
        Ok(signature.to_bytes())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use rand::rngs::OsRng;
    const VERSION: &str = "projects/synthetic-project/locations/us-central1/keyRings/test/cryptoKeys/owner/cryptoKeyVersions/1";
    struct Fake {
        key: SigningKey,
        corrupt: &'static str,
    }
    impl KmsTransport for Fake {
        fn asymmetric_sign(&self, name: &str, request: &Value) -> SignetResult<Value> {
            assert_eq!(name, VERSION);
            assert!(
                request.get("digest").is_none(),
                "Ed25519 must receive original raw bytes"
            );
            let data = STANDARD.decode(request["data"].as_str().unwrap()).unwrap();
            assert_eq!(request["dataCrc32c"], crc32c(&data).to_string());
            let signature = self.key.sign(&data).to_bytes();
            let mut result = json!({"name":name,"signature":STANDARD.encode(signature),"signatureCrc32c":crc32c(&signature).to_string(),"verifiedDataCrc32c":true,"protectionLevel":"SOFTWARE"});
            match self.corrupt {
                "name" => result["name"] = json!(format!("{name}2")),
                "checksum" => result["signatureCrc32c"] = json!("0"),
                "verified" => result["verifiedDataCrc32c"] = json!(false),
                "protection" => result["protectionLevel"] = json!("HSM"),
                "signature" => {
                    result["signature"] = json!(STANDARD.encode([0; 64]));
                    result["signatureCrc32c"] = json!(crc32c(&[0; 64]).to_string());
                }
                _ => {}
            }
            Ok(result)
        }
    }
    #[test]
    fn raw_ed25519_and_crc_contract_and_fail_closed_responses() {
        assert_eq!(crc32c(b"123456789"), 0xe3069283);
        for corrupt in [
            "",
            "name",
            "checksum",
            "verified",
            "protection",
            "signature",
        ] {
            let key = SigningKey::generate(&mut OsRng);
            let public = key.verifying_key().to_bytes();
            let signer = KmsSigner::new(Fake { key, corrupt }, VERSION.into(), public).unwrap();
            let message = crate::authority::signing_bytes(
                crate::authority::OWNER_DOMAIN,
                b"synthetic exact approval",
            );
            assert_eq!(signer.sign_ed25519(&message).is_ok(), corrupt.is_empty());
        }
    }
    #[test]
    fn pins_public_key_and_rejects_alias_or_url_resource() {
        let key = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let signer = KmsSigner::new(
            Fake {
                key: key.clone(),
                corrupt: "",
            },
            VERSION.into(),
            other.verifying_key().to_bytes(),
        )
        .unwrap();
        assert!(signer.sign_ed25519(b"test").is_err());
        for name in [
            format!("https://example.test/{VERSION}"),
            VERSION.replace("/1", "/primary"),
            VERSION.replace("/1", "/0"),
        ] {
            assert!(KmsSigner::new(
                Fake {
                    key: key.clone(),
                    corrupt: ""
                },
                name,
                key.verifying_key().to_bytes()
            )
            .is_err());
        }
    }
}

/// Operator-selected Node helper; uses Cloud Run metadata identity, never ADC files.
pub struct NodeKmsTransport {
    pub node: std::path::PathBuf,
    pub script: std::path::PathBuf,
}
impl KmsTransport for NodeKmsTransport {
    fn asymmetric_sign(&self, key_version: &str, request: &Value) -> SignetResult<Value> {
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        if !self.node.is_absolute() || !self.script.is_absolute() {
            return Err(invalid());
        }
        let wire = serde_json::to_vec(&json!({"key_version":key_version,"request":request}))
            .map_err(|_| invalid())?;
        if wire.len() > 100_000 {
            return Err(invalid());
        }
        let mut child = Command::new(&self.node)
            .arg(&self.script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| invalid())?;
        let mut stdin = child.stdin.take().ok_or_else(invalid)?;
        if stdin.write_all(&wire).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(invalid());
        }
        drop(stdin);
        let output = child.wait_with_output().map_err(|_| invalid())?;
        if !output.status.success() || output.stdout.len() > 65536 {
            return Err(invalid());
        }
        serde_json::from_slice(&output.stdout).map_err(|_| invalid())
    }
}
