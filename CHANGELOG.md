# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-27

### Added

- **signet-core**: Shared types (`Tier`, `Timestamp`, `SignetId`, `DomainId`) and traits (`Signer`, `StorageBackend`, `AuditChainWriter`)
- **signet-vault**: BlindDB storage model with client-side addressing and encryption, BIP39 mnemonic generation, SLIP-0010 Ed25519 key derivation, AES-256-GCM envelope encryption, three-tier key hierarchy, hash-chained audit log, SQLite and in-memory storage backends
- **signet-policy**: XACML-for-individuals policy engine with PERMIT/DENY/ANOMALY three-way decisions, deny-override combining, six-tier actor classification, MAC-protected pattern tracker
- **signet-notify**: Webhook authorization channel with HMAC-SHA256 signatures, challenge registry, circuit breaker, scope subset validation
- **signet-cred**: Credential issuance supporting SD-JWT VC and BBS+ formats, Pedersen commitments for numeric attributes, five-state credential status machine, one-time credential consumption via atomic CAS
- **signet-proof**: Typestate proof pipeline (ProofRequest -> ProofPlan -> ProofBundle -> BoundPresentation), SD-JWT selective disclosure, BBS+ unlinkable proofs, Bulletproof range proofs, domain binding
- **signet-sdk**: Developer verification SDK with four primitives: `verify`, `requestCapability`, `checkAuthority`, `parseCredential`
- **signet-mcp**: MCP server with sequential middleware pipeline, five MCP tools, OAuth 2.1 + PKCE session provisioning, JSON-RPC 2.0 dispatcher
- **signet**: CLI binary with `init`, `serve`, `vault-status`, and `audit` commands

### Security

- Constant-time comparisons (`subtle::ConstantTimeEq`) for all CAS and authentication operations
- OS-level entropy (`OsRng`) for all cryptographic randomness
- `Zeroizing<>` wrappers on all secret key material
- BlindDB relational opacity: server stores only opaque hashes and ciphertext

[0.1.0]: https://github.com/jmcentire/signet/releases/tag/v0.1.0
