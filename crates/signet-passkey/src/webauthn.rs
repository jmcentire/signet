//! WebAuthn byte encodings: client data, authenticator data, the COSE public
//! key and the attestation object. Only what ES256 passkeys with "none"
//! attestation need.
use crate::PasskeyError;
use sha2::{Digest, Sha256};

/// User present.
pub const FLAG_UP: u8 = 0x01;
/// User verified.
pub const FLAG_UV: u8 = 0x04;
/// Backup eligible: the key can exist on more than one device.
pub const FLAG_BE: u8 = 0x08;
/// Backup state: the key is currently backed up.
pub const FLAG_BS: u8 = 0x10;
/// Attested credential data is present.
pub const FLAG_AT: u8 = 0x40;

/// COSE algorithm identifier for ECDSA P-256 with SHA-256.
pub const ES256: i64 = -7;

/// The ceremony a piece of client data belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceremony {
    Create,
    Get,
}

/// String escaping from the WebAuthn client-data serialization algorithm.
fn ccd_to_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Build the client data a browser would produce for a same-origin ceremony.
/// `challenge` is the site's challenge, base64url.
pub fn client_data_json(ceremony: Ceremony, challenge: &str, origin: &str) -> Vec<u8> {
    let kind = match ceremony {
        Ceremony::Create => "webauthn.create",
        Ceremony::Get => "webauthn.get",
    };
    format!(
        "{{\"type\":{},\"challenge\":{},\"origin\":{},\"crossOrigin\":false}}",
        ccd_to_string(kind),
        ccd_to_string(challenge),
        ccd_to_string(origin)
    )
    .into_bytes()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// COSE_Key for a P-256 public key in SEC1 uncompressed form, in CTAP2
/// canonical CBOR.
pub fn cose_es256_key(public_sec1: &[u8]) -> Result<Vec<u8>, PasskeyError> {
    if public_sec1.len() != 65 || public_sec1[0] != 0x04 {
        return Err(PasskeyError::Malformed("public key"));
    }
    let mut out = Vec::with_capacity(77);
    out.extend_from_slice(&[
        0xa5, // map of five
        0x01, 0x02, // kty: EC2
        0x03, 0x26, // alg: ES256 (-7)
        0x20, 0x01, // crv: P-256
        0x21, 0x58, 0x20, // x: 32 bytes
    ]);
    out.extend_from_slice(&public_sec1[1..33]);
    out.extend_from_slice(&[0x22, 0x58, 0x20]); // y: 32 bytes
    out.extend_from_slice(&public_sec1[33..65]);
    Ok(out)
}

/// DER SubjectPublicKeyInfo for a P-256 public key in SEC1 uncompressed form:
/// what a page gets from `getPublicKey()`. `None` if the point is not 65 bytes
/// starting with `0x04`.
pub fn spki_p256(public_sec1: &[u8]) -> Option<Vec<u8>> {
    if public_sec1.len() != 65 || public_sec1[0] != 0x04 {
        return None;
    }
    // SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING { point } }
    let mut out = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    out.extend_from_slice(public_sec1);
    Some(out)
}

/// A new credential's identifier and public key, as carried in authenticator
/// data when a passkey is created.
pub struct AttestedCredential<'a> {
    pub aaguid: &'a [u8; 16],
    pub credential_id: &'a [u8],
    pub public_sec1: &'a [u8],
}

/// Authenticator data: site hash, flags, counter and, at creation, the new
/// credential.
pub fn authenticator_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    attested: Option<&AttestedCredential<'_>>,
) -> Result<Vec<u8>, PasskeyError> {
    let mut out = Vec::with_capacity(37);
    out.extend_from_slice(&sha256(rp_id.as_bytes()));
    out.push(if attested.is_some() {
        flags | FLAG_AT
    } else {
        flags & !FLAG_AT
    });
    out.extend_from_slice(&sign_count.to_be_bytes());
    if let Some(attested) = attested {
        let id_len = u16::try_from(attested.credential_id.len())
            .map_err(|_| PasskeyError::Malformed("credential id length"))?;
        out.extend_from_slice(attested.aaguid);
        out.extend_from_slice(&id_len.to_be_bytes());
        out.extend_from_slice(attested.credential_id);
        out.extend_from_slice(&cose_es256_key(attested.public_sec1)?);
    }
    Ok(out)
}

fn cbor_bytes_header(len: usize) -> Result<Vec<u8>, PasskeyError> {
    Ok(match len {
        0..=23 => vec![0x40 | len as u8],
        24..=0xff => vec![0x58, len as u8],
        0x100..=0xffff => {
            let len = len as u16;
            vec![0x59, (len >> 8) as u8, len as u8]
        }
        _ => return Err(PasskeyError::Malformed("authenticator data length")),
    })
}

/// Attestation object with format "none": the passkey makes no claim about the
/// device that created it.
pub fn attestation_object_none(authenticator_data: &[u8]) -> Result<Vec<u8>, PasskeyError> {
    let mut out = vec![0xa3]; // map of three, keys in canonical order
    out.extend_from_slice(&[0x63, b'f', b'm', b't']);
    out.extend_from_slice(&[0x64, b'n', b'o', b'n', b'e']);
    out.extend_from_slice(&[0x67, b'a', b't', b't', b'S', b't', b'm', b't', 0xa0]);
    out.extend_from_slice(&[0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a']);
    out.extend_from_slice(&cbor_bytes_header(authenticator_data.len())?);
    out.extend_from_slice(authenticator_data);
    Ok(out)
}

/// The parts of authenticator data a receiver can check without a CBOR parser.
pub struct ParsedAuthenticatorData<'a> {
    pub rp_id_hash: &'a [u8],
    pub flags: u8,
    pub sign_count: u32,
}

pub fn parse_authenticator_data(bytes: &[u8]) -> Result<ParsedAuthenticatorData<'_>, PasskeyError> {
    if bytes.len() < 37 {
        return Err(PasskeyError::Malformed("authenticator data"));
    }
    Ok(ParsedAuthenticatorData {
        rp_id_hash: &bytes[..32],
        flags: bytes[32],
        sign_count: u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_data_matches_the_browser_serialization() {
        let json = client_data_json(Ceremony::Get, "dGVzdA", "https://example.com");
        assert_eq!(
            String::from_utf8(json).unwrap(),
            r#"{"type":"webauthn.get","challenge":"dGVzdA","origin":"https://example.com","crossOrigin":false}"#
        );
    }

    #[test]
    fn client_data_escapes_quotes_backslashes_and_controls() {
        assert_eq!(ccd_to_string("a\"b\\c\n"), "\"a\\\"b\\\\c\\u000a\"");
    }

    #[test]
    fn authenticator_data_layout() {
        let data = authenticator_data("example.com", FLAG_UP | FLAG_UV | FLAG_AT, 0, None).unwrap();
        assert_eq!(data.len(), 37);
        let parsed = parse_authenticator_data(&data).unwrap();
        assert_eq!(parsed.rp_id_hash, sha256(b"example.com"));
        // The attested-data flag is set only when attested data is present.
        assert_eq!(parsed.flags, FLAG_UP | FLAG_UV);
        assert_eq!(parsed.sign_count, 0);
    }

    #[test]
    fn cose_key_rejects_other_encodings() {
        assert!(cose_es256_key(&[0x02; 33]).is_err());
        assert_eq!(cose_es256_key(&[0x04; 65]).unwrap().len(), 77);
    }
}
