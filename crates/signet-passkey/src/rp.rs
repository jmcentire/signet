//! Site binding: which relying party identifier a page may use.
//!
//! WebAuthn's protection against phishing is this check. A browser performs it
//! for its built-in passkey support. Software that answers passkey calls in the
//! browser's place, such as an extension, must perform it itself, using the
//! origin the browser reports and never one supplied by the page.
//!
//! Rules implemented (Web Authentication Level 3, relying party identifier
//! validation):
//!
//! - the origin is `https`, or `http` on `localhost` for development;
//! - the origin's host is a domain name, not an IP address;
//! - the identifier equals the host, or is a parent domain of it;
//! - the identifier is not a public suffix such as `com` or `co.uk`.
//!
//! Not implemented: related origins (`/.well-known/webauthn`). A page that
//! depends on them is refused.
use crate::PasskeyError;

/// A relying party identifier that is syntactically acceptable on its own:
/// lower-case ASCII domain labels, and not a bare public suffix.
pub fn validate_rp_id(rp_id: &str) -> Result<(), PasskeyError> {
    if rp_id.is_empty() || rp_id.len() > 253 {
        return Err(PasskeyError::SiteBinding("identifier length"));
    }
    let label_ok = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if !rp_id.split('.').all(label_ok) {
        return Err(PasskeyError::SiteBinding("identifier syntax"));
    }
    if rp_id == "localhost" {
        return Ok(());
    }
    // A registrable domain exists only at or below a public suffix plus one
    // label. `com`, `co.uk` and other bare suffixes have none.
    if psl::domain_str(rp_id).is_none() {
        return Err(PasskeyError::SiteBinding("identifier is a public suffix"));
    }
    Ok(())
}

/// The serialized origin and host of a page, if a passkey may be used there.
fn secure_origin(origin: &str) -> Result<(String, String), PasskeyError> {
    let url = url::Url::parse(origin).map_err(|_| PasskeyError::SiteBinding("origin syntax"))?;
    let host = match url.host() {
        Some(url::Host::Domain(domain)) => domain.to_ascii_lowercase(),
        Some(_) => return Err(PasskeyError::SiteBinding("origin host is an address")),
        None => return Err(PasskeyError::SiteBinding("origin has no host")),
    };
    match url.scheme() {
        "https" => {}
        "http" if host == "localhost" => {}
        _ => return Err(PasskeyError::SiteBinding("origin is not secure")),
    }
    let serialized = url.origin().ascii_serialization();
    // An origin has no path, query, fragment or credentials. Refuse input that
    // carries any, so a caller cannot pass a full page address by mistake.
    if serialized != origin {
        return Err(PasskeyError::SiteBinding("origin is not in canonical form"));
    }
    Ok((serialized, host))
}

/// Decide the relying party identifier for a page.
///
/// `requested` is what the site asked for; when absent the page's own host is
/// used. Returns the identifier to use, or an error when the page may not use it.
pub fn effective_rp_id(origin: &str, requested: Option<&str>) -> Result<String, PasskeyError> {
    let (_, host) = secure_origin(origin)?;
    let rp_id = requested.unwrap_or(&host);
    validate_rp_id(rp_id)?;
    let is_parent = host
        .strip_suffix(rp_id)
        .is_some_and(|rest| rest.ends_with('.'));
    if host != rp_id && !is_parent {
        return Err(PasskeyError::SiteBinding(
            "identifier does not belong to the origin",
        ));
    }
    Ok(rp_id.to_owned())
}

/// Check that `rp_id` may be used from `origin`. The phone runs this again when
/// a request carries its origin.
pub fn check_binding(origin: &str, rp_id: &str) -> Result<(), PasskeyError> {
    effective_rp_id(origin, Some(rp_id)).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_and_parent_domains_are_allowed() {
        assert_eq!(
            effective_rp_id("https://example.com", None).unwrap(),
            "example.com"
        );
        assert_eq!(
            effective_rp_id("https://login.example.com", Some("example.com")).unwrap(),
            "example.com"
        );
        assert_eq!(
            effective_rp_id("https://a.b.example.co.uk:8443", Some("example.co.uk")).unwrap(),
            "example.co.uk"
        );
        assert_eq!(
            effective_rp_id("http://localhost:4322", None).unwrap(),
            "localhost"
        );
    }

    #[test]
    fn other_sites_are_refused() {
        for (origin, rp_id) in [
            ("https://evil.com", "example.com"),
            ("https://example.com.evil.com", "example.com"),
            ("https://notexample.com", "example.com"),
            ("https://example.com", "login.example.com"),
            ("https://example.com", "com"),
            ("https://example.co.uk", "co.uk"),
            ("https://user.github.io", "github.io"),
            ("http://localhost:4322", "example.com"),
        ] {
            assert!(
                check_binding(origin, rp_id).is_err(),
                "{origin} must not use {rp_id}"
            );
        }
    }

    #[test]
    fn insecure_or_malformed_origins_are_refused() {
        for origin in [
            "http://example.com",
            "https://192.0.2.7",
            "https://[2001:db8::1]",
            "https://example.com/login",
            "https://example.com/",
            "https://user@example.com",
            "file:///tmp/page.html",
            "example.com",
            "",
        ] {
            assert!(
                effective_rp_id(origin, None).is_err(),
                "{origin:?} must be refused"
            );
        }
    }

    #[test]
    fn identifier_syntax_is_strict() {
        for rp_id in [
            "Example.com",
            "exa mple.com",
            "example..com",
            "-a.com",
            "",
            "exämple.com",
        ] {
            assert!(validate_rp_id(rp_id).is_err(), "{rp_id:?} must be refused");
        }
        assert!(validate_rp_id("xn--exmple-cua.com").is_ok());
    }
}
