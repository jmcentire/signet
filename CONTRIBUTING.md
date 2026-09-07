# Contributing to Signet

Thank you for your interest in contributing to Signet.

## Prerequisites

- Rust 1.85+ (stable)
- Git
- Gitleaks 8.30.1+ (`brew install gitleaks` on macOS)

## Building

```bash
git clone https://github.com/jmcentire/signet.git
cd signet
cargo build --workspace
```

## Testing

Production credentials and operational private keys are forbidden. Generate
test keys in fixtures or use documented test-only vectors; never load a real
vault or ambient production credentials. Run:

```bash
make check
```

The Gitleaks credential scan blocks test execution on findings or scanner
failure. It scans current tracked files and non-ignored untracked files, with
redacted output. Cryptographic operations are permitted. The historical
quarantine and its correction are recorded in
[docs/no-key-test-quarantine.md](docs/no-key-test-quarantine.md).

## Code Quality

All PRs must pass:

```bash
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

## Architecture

```
signet-core          Shared types and traits (Signer, StorageBackend, AuditChainWriter)
  |
signet-vault         Root of trust, BlindDB storage, key hierarchy, envelope encryption
  |
  +-- signet-cred    Credential issuance (SD-JWT VC + BBS+, Pedersen commitments)
  +-- signet-proof   Typestate proof pipeline (ProofRequest -> ProofPlan -> ProofBundle)
  +-- signet-policy  XACML-for-individuals policy engine
  +-- signet-notify  Webhook authorization channel with circuit breaker
  |
signet-mcp           MCP server, middleware pipeline, JSON-RPC 2.0
  |
signet               CLI binary and orchestrator

signet-sdk           Standalone verifier SDK (no vault dependency)
```

## Security Guidelines

Signet handles cryptographic material. Follow these rules in all contributions:

### Constant-time operations
Use `subtle::ConstantTimeEq` for all comparisons involving secrets or authentication data. Never use `==` for comparing MACs, hashes, or ciphertext in security-sensitive paths.

### Random number generation
Use `rand::rngs::OsRng` for all cryptographic operations (key generation, nonce generation, salt generation). Never use `thread_rng()` for security-critical randomness.

### Memory safety
Wrap all secret key material in `zeroize::Zeroizing<>`. This ensures secrets are zeroed from memory when dropped.

### No unwrap in library code
Library crates must not use `.unwrap()` or `.expect()` outside of test modules. Return `Result` types and propagate errors.

### BlindDB invariants
The storage backend must never receive plaintext labels, semantic meaning, or relationship information. All addressing and encryption happen client-side. If you're modifying storage code, verify that:

1. Record IDs visible to the backend are SHA-256 hashes (not semantic labels)
2. Data visible to the backend is AES-256-GCM ciphertext (not plaintext)
3. No metadata leaks user identity or record relationships

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Run `make check` (credential scan, build, lint, formatting, and tests)
5. Review scan findings; never waive an entire test directory to suppress one fixture
6. Submit a pull request with a clear description of the change

## License

By contributing, you agree that your contributions will be licensed under the same terms as the project: MIT OR Apache-2.0.
