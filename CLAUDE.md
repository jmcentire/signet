# Signet

Personal Sovereign Agent Stack. Your vault is the crown, your agent is the steward, external agents are petitioners. The user never appears directly — only their authorized proofs do.

A signet was a seal carried by a trusted proxy to sign documents on behalf of a lord, in their absence, with their full authority. The vault is the matrix (the original, never leaves you). The agent is the proxy carrying the seal. The ZK proof is the impression — proves authority without revealing the ring. Revocation is destroying or recalling the seal. Scoped credentials are letters sealed for a specific purpose.

## Quick Reference

```bash
# Build with Pact (contract-first pipeline)
cd ~/Code/pact
pact init signet          # scaffold project
pact run signet           # execute pipeline
pact status signet        # check progress

# Signet CLI (once built)
signet init               # create vault, generate root keypair
signet vault status       # inspect vault contents by tier
signet agent start        # launch personal agent + MCP server
signet proof list         # show available proof circuits
signet audit              # review disclosure log
```

## Trust Hierarchy

```
User (Root Authority — cryptographic root, Ed25519 keypair)
  └── Signet Vault (encrypted local store, never externally reachable)
        └── Personal Agent (trusted steward, credentialed by vault)
              └── External Agents / Services (petitioners, minimally disclosed)
```

The user's vault keypair is the anchor for everything downstream. Any proof that reaches an external service traces its chain of trust back to the vault root. External parties verify against the embedded public key — the vault itself stays dark. No DID. Identity is a public key fingerprint.

## Three Tiers of Data

### Tier 1: Freely Provable
Agent answers without asking. "Is the user over 21?" -> ZKP: yes. No raw data, just proof. Root authority: vault.

### Tier 2: Agent-Internal
Agent knows preferences, history, context. Uses it to reason and act. Never exports raw data. External agents get conclusions, not data. "What shelves did they order last time?" -> agent knows, agent decides, agent orders.

### Tier 3: Capability-Gated
Payment credentials, identity documents, medical data. Encrypted such that the agent literally cannot read them without a user-issued decryption grant. Agent knows the schema exists, can request access, can explain why, cannot proceed without user authorization.

## Four Protocols

Each protocol answers: "What does this party actually need to know?"

### Protocol 0: Steward Conversation Protocol (User <-> Agent)
- Conversational, multi-surface (web, mobile, CLI, browser plugin)
- Authorization channel with reasoning, not just prompts
- Audit window — user sees what agent did, disclosed, and holds
- The only place the user engages directly; all other protocols are invisible

### Protocol 1: Vault Access Protocol (Agent <-> Vault)
- Mutual authentication (agent proves identity, vault proves genuineness)
- Capability negotiation per tier rules
- Data minimization at source — vault never hands over raw Tier 3 data
- Tamper-evident log — every access signed, queryable via Protocol 0
- Vault never needs to be reachable by external parties

### Protocol 2: Steward Negotiation Protocol (Agent <-> Agent)
- MCP-native with Signet handshake layer on top
- Claim-based, not data-based — external agents receive proofs, not facts
- Tier 1: ZK proof issued immediately
- Tier 2: agent reasons internally, returns conclusions only
- Tier 3: suspends, fires Protocol 0 notification, awaits user auth
- Context negotiation — agent negotiates on user's behalf, disclosing minimum necessary

### Protocol 3: Steward Verification Protocol (Agent <-> Service)
- SDK layer — what service developers implement
- verify(proof, claim) -> boolean + expiry + scope
- One-way data flow: vault -> agent -> external service, never reverse
- One-time-use credential invalidation propagates back to vault
- Compliance benefit: services don't hold data, can't be breached for it

## Policy Engine

XACML-for-individuals. The user is policy administrator, the agent is enforcement point, the audit log belongs to the user.

### Actor Classification
```
Public          trust 1   can prove: user_exists
Commerce        trust 3   can read: preferences, shipping_address
Financial       trust 4   inherits Commerce + income_range_proof, creditworthiness_proof
Medical         trust 5   separate branch, health_data (Tier 3, purpose-bound)
Identity        trust 5   age, citizenship, legal_name verification
Trusted Agent   trust 6   reads everything granted, cannot override Tier 3 gates
```

### Evaluation Chain
```
REQUEST -> Actor Classification -> Predicate Legitimacy Check -> Context Analysis -> Policy Decision
```

Role/predicate mismatch = anomaly. Not denied — escalated with reasoning. User gets: "Amazon is asking for your age. This doesn't match their Commerce role. Here's why that's unusual."

### Role Negotiation
On escalation, user can: deny once, deny always, grant exception (logged), propose role amendment (policy learning), or reclassify the actor. Every amendment is on the audit chain.

### Execution Pipeline
```yaml
policy:
  on_tier3_request:
    steps:
      - evaluate_role_match
      - check_context_legitimacy
      - if_anomaly: notify_user(channel: configurable, reasoning: true)
      - await_decision(timeout: 300s, default: deny)
      - if_approved: issue_scoped_credential + log_grant(audit_chain)
      - if_role_expansion: propose_role_amendment(user_review: true)
```

Confirmation mechanisms are user-configured plugins: SMS, hardware token, biometric, geofence, auto-approve on home network, etc.

## Capability Credential Model

Every credential issued by the vault is:
- **Amount-bounded**: $X max
- **Domain-scoped**: amazon.com only
- **Time-limited**: one-time use / expires in N minutes
- **Purpose-tagged**: purchase, not subscription enrollment
- **Auditable**: cryptographically signed, user has the receipt

Closer to a scoped OAuth token than a password, but derived from vault root and cryptographically tied to context.

## Components to Build

### 1. Signet Vault (`signet-vault`)
Encrypted local store. Schema: facts, credentials, preferences, history. User UI for managing tiers. Runs locally or on user-controlled infra (or hosted multi-tenant). Generates proofs on demand. Root keypair management. Same binary self-hosted or hosted.

### 2. Agent Trust Bridge (`signet-mcp`)
MCP server connecting personal agent to vault (authenticated) and exposing tool interfaces to external agents. Enforces tier logic. Routes Tier 3 requests through authorization flow. Implements Steward Negotiation Protocol.

### 3. Credential Issuer (`signet-cred`)
On user approval, issues signed, scoped capability credentials. PASETO v4 tokens for capability constraints. SD-JWT VCs for interop. BBS+ signed attribute sets for unlinkable proofs. One-time tokens for payments. Reusable tokens for low-sensitivity proofs.

### 4. Policy Engine (`signet-policy`)
RBAC with actor/predicate/context legitimacy checking. Role hierarchy (user-curated, sensible defaults). Anomaly detection for role/predicate mismatches. Policy learning through real interactions. Pluggable execution handlers for authorization flow.

### 5. ZK Circuit Library (`signet-circuits`)
Three-layer proof system: SD-JWT (baseline interop), BBS+ (unlinkable selective disclosure with pre-computed booleans), Bulletproofs (dynamic range proofs). No circuit compilation toolchain. No trusted setup.

### 6. Developer SDK (`signet-sdk`)
Minimal surface area — four primitives:
- `verify(proof, claim)` — validate a ZK proof
- `requestCapability(spec)` — ask for a scoped credential
- `checkAuthority(signet_id)` — confirm root authority is valid
- `parseCredential(token)` — decode credential claims (not underlying data)

### 7. Notification/Authorization Channel (`signet-notify`)
Low-friction, high-trust. Agent presents reasoning. User responds approve/deny/modify. Vault issues credential directly to requesting context. Multi-channel: SMS, push, webhook, in-app.

### 8. Browser Extension (`signet-extension`)
Intercepts checkout flows, injects agent credentials into standard form fields. Zero merchant adoption required. Immediate user value. The near-term adoption wedge.

## Standards Stack

| Layer | Standard | Why |
|-------|----------|-----|
| Identity | Ed25519 public key fingerprint | Self-certifying, no DID, no resolution protocol |
| Key discovery | `/.well-known/signet.json` | HTTP, simple, optional |
| Credentials (interop) | SD-JWT VC (RFC 9901) | IETF standard, EU wallet compatible |
| Credentials (privacy) | BBS+ Signatures (IRTF draft) | Unlinkability, selective disclosure |
| Range proofs | Bulletproofs | No trusted setup, audited, fast |
| Agent Protocol | MCP | Native integration surface — Signet is a Claude connector |
| Capability Tokens | PASETO v4 | Misuse-resistant, no algorithm confusion |
| Crypto backend | aws-lc-rs | FIPS 140-3 validated |

## Portability

- **Public key fingerprint as identity**: `Base58(SHA-256(Ed25519_pubkey)[0:20])`. Self-certifying. No registry.
- **Well-Known endpoint**: `/.well-known/signet.json` — auto-discovery of supported claims, proof formats, public key.
- **Key rotation**: New key signed by old key. Rotation proof published at well-known endpoint.
- **Proof format compatibility**: SD-JWT for interop, BBS+ for privacy, Bulletproofs for range proofs.

## SDK Integration Profiles

### Profile 1: Passive Verifier (one-liner)
```javascript
import { verify } from '@signet/sdk'
const result = await verify(proofToken, { claim: 'age_over_21', domain: 'shop.example.com' })
```

### Profile 2: Active Requester (structured request)
```javascript
const request = await signet.requestCapability({
  type: 'payment',
  constraints: { maxAmount: 150, currency: 'USD', domain: 'amazon.com', oneTime: true },
  reason: 'Bookshelf purchase in cart #8821'
})
```

### Profile 3: Agent-to-Agent (full protocol)
Full MCP compatibility with Signet protocol layer. Structured context negotiation. Every exchange provably scoped.

## Adoption Flywheel

Browser extension gets users -> users show up at merchants with valid proofs -> merchants notice clean credential flow (better conversion, less fraud) -> merchants integrate SDK -> SDK adoption increases proof trust -> more users want the vault -> repeat.

## AI Provider Integration

The ask of Claude/GPT/Gemini is small:
1. Support MCP (already happening)
2. Treat vault-issued credentials as trusted context
3. Pass credentials downstream in structured form
4. Surface authorization requests through their UI

The vault MCP server is the adapter between their world and yours.

## Building with Pact

This project uses [Pact](~/Code/pact) (contract-first multi-agent framework) for implementation. The architecture decomposes naturally into components with clear interfaces — ideal for Pact's contract-test-implement pipeline.

Each component above maps to a Pact decomposition node. Contracts define the inter-component interfaces (especially the four protocol boundaries). Tests enforce the security invariants before any implementation begins.

**Build order** (dependency-driven):
1. `signet-vault` — root of trust, everything depends on this
2. `signet-cred` — credential issuance, depends on vault keypair
3. `signet-circuits` — ZK proof generation, depends on vault data access
4. `signet-policy` — role/predicate evaluation, depends on vault schema
5. `signet-mcp` — trust bridge, depends on vault + cred + circuits + policy
6. `signet-sdk` — developer surface, depends on protocol definitions from mcp
7. `signet-notify` — authorization channel, depends on policy decisions
8. `signet-extension` — browser integration, depends on sdk + notify

## Architecture Invariants

These are non-negotiable and must hold across all components:

1. **Vault never externally reachable** — issues proofs, agent carries them, external parties verify against embedded public key
2. **Tier 3 requires live user auth** — no exceptions, no caching, no delegation
3. **One-way data flow** — vault -> agent -> service, never reverse
4. **Every disclosure is auditable** — signed, timestamped, on the provenance chain
5. **Protocols do not collapse** — four layers, four trust models, four enforcement points
6. **Roles are user-curated** — system ships defaults, user owns the classification
7. **SDK stays minimal** — four primitives, complexity lives in the vault
8. **Credentials are scoped** — amount, domain, time, purpose, always

## Edge Cases and Open Questions

### Vault Availability
- What happens when the vault is offline? Agent cannot issue new proofs.
- Cached Tier 1 proofs with TTL? Or hard fail requiring vault presence?
- Mobile vault vs. desktop vault — sync model or single-device?

### Credential Revocation
- One-time credentials self-invalidate on use. But what about revocation mid-flight?
- Revocation list or expiry-only model?
- How does the external service learn a credential was revoked?

### Agent Compromise
- If the personal agent is compromised, what's the blast radius?
- Agent has Tier 1 and Tier 2 access — can it exfiltrate via side channels?
- Key rotation and agent re-credentialing flow

### Multi-Device
- User has phone, laptop, desktop — each with a vault instance?
- Or one vault, multiple authenticated agent connections?
- Key derivation per device vs. shared root?

### Recovery
- User loses their device. Root keypair is gone. What now?
- Social recovery (Shamir's Secret Sharing)? Hardware backup? Escrow?
- Recovery without compromising the trust model

### Delegation
- Can a user delegate to another human (spouse, assistant)?
- Sub-signet with constrained authority?
- Time-bounded delegation with full audit trail?

### Protocol Versioning
- How do agents negotiate protocol version?
- Backward compatibility when proof formats evolve?
- Migration path for credential format changes

### Performance
- ZK proof generation latency — acceptable for real-time checkout?
- Proof caching for repeated claims (Tier 1 age proofs)?
- Circuit compilation time for novel proof types

## Detailed Design

See [DESIGN.md](./DESIGN.md) for the comprehensive design document including:
- Proof architecture (three layers, no circuits)
- Vault encryption model (envelope encryption, key hierarchy)
- Multi-tenant hosted architecture
- All edge cases resolved
- Threat model
- Pact shape and interview preparation
- Acceptance criteria for every component

## Key References

- SD-JWT: RFC 9901 — https://datatracker.ietf.org/doc/rfc9901/
- BBS+ Signatures: https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html
- Bulletproofs (dalek): https://github.com/dalek-cryptography/bulletproofs
- aws-lc-rs FIPS: https://aws.amazon.com/blogs/security/aws-lc-fips-3-0-first-cryptographic-library-to-include-ml-kem-in-fips-140-3-validation/
- PASETO v4: https://paseto.io/
- MCP: https://modelcontextprotocol.io/
- "The Ephemeral Internet" (McEntire, 2026) — BlindDB concepts

## Kindex

Signet captures discoveries, decisions, and architectural rationale in [Kindex](~/Code/kindex). Search before adding. Link related concepts. Use `learn` after complex design sessions.
