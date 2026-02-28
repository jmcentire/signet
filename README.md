```
     _                  _
 ___(_) __ _ _ __   ___| |_
/ __| |/ _` | '_ \ / _ \ __|
\__ \ | (_| | | | |  __/ |_
|___/_|\__, |_| |_|\___|\__|
       |___/
```

[![CI](https://github.com/jmcentire/signet/actions/workflows/ci.yml/badge.svg)](https://github.com/jmcentire/signet/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](LICENSE-MIT)
[![MSRV: 1.75](https://img.shields.io/badge/MSRV-1.75-orange)]()

**Personal Sovereign Agent Stack**

Your vault is the crown, your agent is the steward, external agents are petitioners. The user never appears directly -- only their authorized proofs do.

Signet gives AI agents a cryptographic vault for managing user credentials, generating zero-knowledge proofs, and enforcing privacy policies. Data flows one way: vault to agent to service, never reverse. Every disclosure is auditable, scoped, and revocable.

---

## Trust Hierarchy

```
User (Root Authority -- Ed25519 keypair)
  +-- Signet Vault (encrypted local store, never externally reachable)
        +-- Personal Agent (trusted steward, credentialed by vault)
              +-- External Agents / Services (petitioners, minimally disclosed)
```

## Three Tiers of Data

| Tier | Name | Access | Survives Password Reset |
|------|------|--------|------------------------|
| **1** | Freely Provable | Agent answers without asking | Yes |
| **2** | Agent-Internal | Agent reasons with it, never exports raw | No |
| **3** | Capability-Gated | Requires explicit user authorization | N/A (client-generated key) |

## Crates

| Crate | Lines | Description |
|-------|-------|-------------|
| `signet-core` | 713 | Shared types, traits (`Signer`, `StorageBackend`, `AuditChainWriter`) |
| `signet-vault` | 2,890 | Root of trust, BlindDB storage, BIP39/SLIP-0010, envelope encryption, passkey/FIDO2 support |
| `signet-policy` | 4,265 | XACML-for-individuals, PERMIT/DENY/ANOMALY decisions, role hierarchy |
| `signet-notify` | 4,290 | Webhook authorization channel, HMAC-SHA256, circuit breaker |
| `signet-cred` | 6,778 | Credential issuance (SD-JWT VC + BBS+), authority protocol, composable decay model, revocation |
| `signet-proof` | 5,135 | Typestate proof pipeline, selective disclosure, range proofs |
| `signet-sdk` | 3,055 | Developer SDK: `verify`, `requestCapability`, `checkAuthority`, `parseCredential` |
| `signet-mcp` | 4,903 | MCP server, middleware pipeline, JSON-RPC 2.0 dispatcher |
| `signet` | 3,766 | CLI binary, HTTP server, authority credential endpoints |

**~38,000 lines of Rust. 1,050 tests. 9 crates.**

## Quickstart

### Install from source

```bash
cargo install --git https://github.com/jmcentire/signet.git signet
```

### Or clone and build

```bash
git clone https://github.com/jmcentire/signet.git
cd signet
cargo build --release
```

### Initialize and run

```bash
# Create vault and default config
signet init

# Check vault status
signet vault-status

# Start MCP server (stdio transport)
signet serve

# View audit log
signet audit
```

## Security Model: BlindDB

Signet's storage layer implements the BlindDB pattern from *The Ephemeral Internet* (McEntire, 2026). The server stores only opaque record IDs and encrypted blobs. It never sees plaintext, labels, or relationships between records.

**Five defense layers:**

1. **Relational opacity** -- Destroy relationships between records. The server cannot tell which records belong to the same user, which form a collection, or what any record contains.
2. **Signatures** -- Tamper evidence via hash-chained audit log.
3. **Hash chains** -- Provenance and ordering guarantees.
4. **Encryption** -- AES-256-GCM per-record envelope encryption for data with independent value.
5. **Seed data** -- Plausible deniability through indistinguishable fake records.

### What the server sees

After storing data for three users (emails, addresses, payment cards, medical records, watch histories):

```
record_id (SHA-256 hash)                                   data (AES-256-GCM ciphertext)
-----------------------------------------------------------------------------------------------
0a3f...7c21                                                [encrypted blob]
1b8e...9d44                                                [encrypted blob]
2c7a...4f88                                                [encrypted blob]
3d1f...8e22                                                [encrypted blob]
...13 more records...
```

**Questions the attacker cannot answer:**
- Which records belong to Alice? Bob? Carol?
- Which email goes with which address?
- Who has the credit card? The SSN? The medical record?
- How many users are there?
- Which records form a collection?
- Are any of these records fake (seed data)?

Run the demo yourself:
```bash
cargo test --package signet-vault --test show_db -- --nocapture
```

## Standards

| Layer | Standard | Purpose |
|-------|----------|---------|
| Identity | Ed25519 public key fingerprint | Self-certifying, no DID, no registry |
| Credentials (interop) | SD-JWT VC (RFC 9901) | IETF standard, EU wallet compatible |
| Credentials (privacy) | BBS+ Signatures | Unlinkable selective disclosure |
| Range proofs | Bulletproofs | No trusted setup, audited |
| Agent protocol | MCP | Native Claude/AI integration |
| Capability tokens | PASETO v4 | Misuse-resistant, no algorithm confusion |
| Crypto backend | aws-lc-rs compatible | FIPS 140-3 ready |
| Key derivation | BIP39 + SLIP-0010 | Deterministic Ed25519 from mnemonic |

## Architecture

```
                          +-------------------+
                          |   signet (CLI)    |
                          +---------+---------+
                                    |
                          +---------+---------+
                          |   signet-mcp      |
                          | (MCP server +     |
                          |  middleware)       |
                          +-+---+---+---+---+-+
                            |   |   |   |   |
              +-------------+   |   |   |   +-------------+
              |                 |   |   |                 |
     +--------+--+    +--------+--+  +--+--------+    +--+--------+
     | signet-   |    | signet-   |  | signet-   |    | signet-   |
     | cred      |    | proof     |  | policy    |    | notify    |
     +-----+-----+    +-----+----+  +-----+-----+    +-----+-----+
           |               |              |                 |
           +-------+-------+--------------+-----------------+
                   |
          +--------+--------+          +-----------+
          |  signet-vault   |          | signet-sdk |
          | (root of trust) |          | (verifier) |
          +--------+--------+          +-----------+
                   |
          +--------+--------+
          |  signet-core    |
          | (shared types)  |
          +-----------------+
```

## Development

```bash
# Full check (build + test + clippy + fmt)
make check

# Individual targets
make build
make test
make clippy
make fmt

# Run BlindDB demo
make demo

# Run E2E integration test
make e2e
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines.

## License

Licensed under either of

- [MIT license](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.

## Links

- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Architecture](docs/architecture.md)
