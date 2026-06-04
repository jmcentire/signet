# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Signet, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please use [GitHub Security Advisories](https://github.com/jmcentire/signet/security/advisories/new) to report vulnerabilities privately.

## Scope

The following areas are in scope for security reports:

- Cryptographic implementations (key derivation, encryption, signatures)
- BlindDB storage model (metadata leaks, relationship inference)
- Key management (key hierarchy, zeroization, memory handling)
- Authentication and authorization (tier enforcement, session management)
- Storage backends (SQLite, in-memory)
- Policy engine bypass
- Audit chain integrity

## Security Design

Signet's security model is built on these principles:

1. **Relational opacity**: The server cannot determine relationships between records, which records belong to which user, or what any record contains.
2. **Constant-time operations**: All security-sensitive comparisons use `subtle::ConstantTimeEq` to prevent timing side-channels.
3. **OS-level entropy**: All cryptographic randomness uses `OsRng`, never userspace PRNGs.
4. **Memory zeroization**: All secret key material is wrapped in `Zeroizing<>` for automatic cleanup.
5. **Defense in depth**: Five layers (relational opacity, signatures, hash chains, encryption, seed data) rather than relying on any single mechanism.

## Active Test Quarantine

Project test, demo, and integration-test execution is currently blocked because
test paths contain signing and private-key operations. GitHub Actions and local
`make` entrypoints fail closed through `scripts/no_key_material_scan.py`.
Build-only checks do not constitute cryptographic validation. See
[docs/no-key-test-quarantine.md](docs/no-key-test-quarantine.md) for the
incident record and remediation inventory.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| 0.1.x   | Yes       |
