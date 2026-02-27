# Signet Architecture Overview

This document provides a high-level overview of the Signet architecture for contributors and integrators. For the full design specification, see [DESIGN.md](../DESIGN.md).

## Trust Hierarchy

```
User (Root Authority — Ed25519 keypair)
  └── Signet Vault (encrypted store, architecturally unreachable externally)
        └── Personal Agent (trusted steward, vault-credentialed)
              └── External Agents / Services (petitioners, minimally disclosed)
```

The user's vault keypair is the cryptographic root. Every proof traces back to it. External parties verify against the public key embedded in proofs — the vault stays dark.

## Three Data Tiers

| Tier | Agent Access | External Disclosure | Enforcement |
|------|-------------|--------------------|-|
| 1 - Freely Provable | Full | ZK proof, no user prompt | Policy rule |
| 2 - Agent-Internal | Full (reasoning) | Conclusions only, never raw data | Policy rule |
| 3 - Capability-Gated | Schema only | Scoped credential after auth pipeline | Structural (agent lacks encryption key) |

## Four Protocol Layers

| Protocol | Governs | Trust Model |
|----------|---------|-------------|
| Layer 0 — SCP | User <-> Agent | User is root, agent is steward |
| Layer 1 — VAP | Agent <-> Vault | Mutual auth, capability-gated |
| Layer 2 — SNP | Agent <-> Agent | ZK proofs, claim-based, MCP-native |
| Layer 3 — SVP | Agent <-> Service | SDK-consumed, one-way data flow |

## Proof System

Three layers, no ZK circuits:

1. **SD-JWT VC** (RFC 9901) — Baseline credential format. Selective disclosure. IETF standard interop.
2. **BBS+ Signatures** — Unlinkable presentations. Pre-computed boolean attributes for age gates, thresholds.
3. **Bulletproofs** — Dynamic range proofs. No trusted setup. ~11ms proof generation.

## Policy Engine

Evaluates requests as Actor + Predicate + Context = Legitimacy:

- **PERMIT**: Rule exists, proceed per tier
- **DENY**: Rule exists, reject
- **ANOMALY**: No rule exists — escalate to user with reasoning

The user teaches the system through real interactions, not configuration screens.

## Components

| Component | Purpose |
|-----------|---------|
| `signet-vault` | Encrypted store, key management, tier enforcement |
| `signet-cred` | SD-JWT + BBS+ credential issuance |
| `signet-proof` | Proof derivation (SD-JWT, BBS+, Bulletproofs) |
| `signet-policy` | Role/predicate evaluation, anomaly detection |
| `signet-mcp` | MCP server — trust bridge to AI agents |
| `signet-sdk` | Developer SDK — four primitives: verify, request, check, parse |
| `signet-notify` | Authorization channel (webhook, SMS, push) |

## AI Connector

Signet appears as a connector in Claude, ChatGPT, Gemini — the same way Google Drive or Slack does. The MCP server is the integration surface. OAuth 2.1 for setup. The AI calls `signet_get_proof()` like any other tool.

## Standards

| Layer | Standard |
|-------|----------|
| Identity | Ed25519 public key fingerprint |
| Credentials | SD-JWT VC (RFC 9901) + BBS+ (IRTF draft) |
| Range Proofs | Bulletproofs (Pedersen commitments) |
| Capability Tokens | PASETO v4 |
| Agent Protocol | MCP |
| Crypto Backend | aws-lc-rs (FIPS 140-3) |
