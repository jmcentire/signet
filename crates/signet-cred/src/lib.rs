//! Signet Credential Engine
//!
//! Self-issuance credential engine for the Signet sovereign agent stack.
//! Produces credentials in two formats:
//! 1. SD-JWT VC per RFC 9901 for baseline interoperability
//! 2. BBS+ signed attribute sets for unlinkable presentations
//!
//! Pre-computes boolean attributes (age_over_21, etc.) to avoid ZK circuits.
//! Generates Pedersen commitments for numeric attributes for downstream
//! Bulletproof range proofs.
//!
//! All signing is delegated to the vault via the Signer trait. The credential
//! engine never touches raw key material.

pub mod attribute;
pub mod authority;
pub mod capability;
pub mod consumption;
pub mod decay;
pub mod disclosure;
pub mod error;
pub mod issuance;
pub mod schema;
pub mod spl_capability;
pub mod status;
pub mod types;

// Re-export primary types and functions for convenience
pub use attribute::{encode_claim_to_scalar, evaluate_predicate, verify_pedersen_commitment};
pub use capability::{
    generate_capability_token, parse_capability_token, CapabilityClaims, CapabilityConstraints,
    CapabilityToken, CapabilityTokenConfig,
};
pub use disclosure::{validate_disclosure, validate_disclosure_for_schema};
pub use error::{CredError, CredErrorDetail, CredResult};
pub use issuance::issue_credential;
pub use schema::{compute_field_index_map, validate_schema, validate_schema_strict};
pub use status::{can_present, can_revoke, is_valid_transition};
pub use types::*;
