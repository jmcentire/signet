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

## Credentials in Tests and CI

Production credentials and operational private keys must not appear in source,
test fixtures, CI artifacts, or releases. Generated test keys and documented
test-only vectors are permitted. Tests must not load real vaults or ambient
production credentials.

CI and local `make` test entrypoints run Gitleaks with redacted output before
executing tests. Findings or scanner failures block execution. Detection cannot
prove the provenance of arbitrary bytes; code review must still establish that
fixture material is test-only. See [the quarantine history and correction](docs/no-key-test-quarantine.md).

The local gate scans current tracked files and non-ignored untracked files,
including unstaged edits. It does not scan Git history, ignored local vaults,
or build caches, and is not a sandbox for an attacker-controlled workspace.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | Yes       |
| 0.2.x   | Yes       |
| 0.1.x   | Yes       |
