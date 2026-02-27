# Signet Standards of Practice

## Language and Tooling

- **Rust** (latest stable, nightly only for bulletproofs crate)
- **Cargo workspace** monorepo under `crates/`
- `cargo fmt` and `cargo clippy` enforced
- Tests via `cargo test` — unit tests in-module, integration tests in `tests/`

## Cryptography

- **aws-lc-rs** for all FIPS-path primitives (Ed25519, X25519, AES-256-GCM, HKDF-SHA-256)
- **anoncreds-v2-rs** for BBS+ signatures
- **dalek bulletproofs** for range proofs (Pedersen commitments)
- **rusty_paseto** for PASETO v4 capability tokens
- **sd-jwt-rust** (OpenWallet Foundation) for SD-JWT VC
- No libsodium (not FIPS validated)
- No custom crypto — use established libraries for every primitive
- Zero secrets in memory after use
- Constant-time operations for all secret-dependent code paths
- Authenticated encryption exclusively (AES-GCM or XChaCha20-Poly1305)

## Security Invariants

These must hold at all times and are tested explicitly:

1. Vault server never has access to plaintext
2. Tier 3 compartment keys are never held by the agent
3. Agent sessions expire and are revocable
4. All proofs are domain-bound and time-limited
5. One-way data flow: vault -> agent -> service, never reverse
6. All disclosures are on the audit chain
7. ANOMALY decisions are never silently resolved
8. Pipeline timeout = deny (fail-secure)
9. No algorithm negotiation in any protocol

## Naming Conventions

- Crate names: `signet-{component}` (e.g., `signet-vault`, `signet-cred`)
- Types: PascalCase
- Functions: snake_case
- Constants: SCREAMING_SNAKE_CASE
- Error types: `{Component}Error` enum per crate
- Trait names: describe capability (e.g., `ProofGenerator`, `CredentialIssuer`)

## Error Handling

- `thiserror` for library errors
- No `unwrap()` or `expect()` in library code — Result everywhere
- Errors must not leak sensitive information (no raw key material in error messages)
- Crypto failures return generic error types (no oracle)

## Testing

- Unit tests for every public function
- Integration tests for cross-crate interactions
- Property-based tests for crypto operations (round-trip, known-answer)
- The BBS+ unlinkability invariant must be statistically tested
- Tier 3 structural isolation must be tested (agent session cannot derive Tier 3 keys)
- Policy engine anomaly detection must be tested against role/predicate matrix

## Dependencies

Minimize. Every dependency is an attack surface. Prefer:
- Standard library where sufficient
- Well-audited crates over popular crates
- No dependency for one-time operations

## Documentation

- `//!` module-level docs on every crate
- `///` on every public type and function
- Protocol wire formats documented in `docs/`
- Architecture decisions include threat model rationale

## Git

- Commits signed by: Jeremy McEntire <jmc@kindex.tools>
- Conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
- No force push to main
