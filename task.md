# Signet: Personal Sovereign Agent Stack

Build a personal data sovereignty system where the user's encrypted vault is the cryptographic root of trust, a personal agent acts as steward carrying proofs and scoped credentials, and external services receive only the minimum necessary disclosure.

## Core Problem

AI agents operating on behalf of users broadcast personal data to every service they touch. There is no minimum-disclosure mechanism, no audit trail, and no way to detect when an external service requests data outside its legitimate role.

## What to Build

A Rust monorepo (`crates/` workspace) implementing seven components:

### signet-vault
Encrypted local data store with key management. Envelope encryption (Ed25519 + X25519 + AES-256-GCM). Three-tier data model where Tier 3 uses compartment keys the agent cannot access. Per-device keys (Ed25519), device provisioning via existing-device ceremony. Content-addressed blob storage. Encrypted client-side index. Append-only audit log. Same binary for self-hosted (SQLite + filesystem) and hosted multi-tenant (Postgres + S3). Recovery via BIP39 mnemonic. Optional Shamir's Secret Sharing for social recovery.

### signet-cred
Credential issuance in two formats: SD-JWT VC (RFC 9901) for baseline interoperability, and BBS+ signed attribute sets for unlinkable presentations. Pre-computed boolean attributes (age_over_21, balance_above_1000, etc.) in BBS+ credentials to avoid ZK circuits. Pedersen commitments for numeric attributes enabling Bulletproof range proofs. TTL management. One-time credential consumption tracking.

### signet-proof
Proof derivation from cached credentials. SD-JWT presentations (selective disclosure). BBS+ unlinkable proofs (fresh per presentation). Bulletproof range proofs from Pedersen commitments. Domain binding. Proof composition. All operations <20ms.

### signet-policy
Policy engine evaluating Actor + Predicate + Context = Legitimacy. Three-way decision: PERMIT, DENY, ANOMALY. Role hierarchy (Public, Commerce, Financial, Medical, Identity, Trusted Agent). Actor classification via explicit assignment, credential, domain inference, or declaration. Anomaly escalation with structured reasoning. Policy learning from user decisions. Stored in vault as structured JSON.

### signet-mcp
MCP server bridging personal agent to vault and external agents. Authenticates personal agent (Ed25519 session). Exposes tools: signet_get_proof, signet_query, signet_request_capability, signet_negotiate_context, signet_check_status. Routes requests through policy engine. Enforces tier logic. Tier 3 requests suspend and fire notification. Session management. This is the AI connector surface — listed in Claude/ChatGPT/Gemini connector registries. OAuth 2.1 for setup.

### signet-sdk
Developer SDK with four primitives: verify(proof, claim), requestCapability(spec), checkAuthority(signet_id), parseCredential(token). Zero transitive dependencies beyond crypto. Rust primary, TypeScript (WASM) and Python (PyO3) bindings. A developer integrates passive verification in under 10 lines.

### signet-notify
Authorization channel. Webhook (primary), SMS (optional), push (optional). Presents reasoning (who, what, why unusual, options). User responds approve/deny/modify. Timeout defaults to deny. Sub-second delivery and propagation.

## Done Looks Like

1. User creates a vault (local or hosted)
2. Stores personal data in three tiers
3. Connects their AI agent via MCP
4. Agent answers Tier 1 proof request without user involvement
5. Agent reasons about Tier 2 data, returns conclusions only
6. User receives notification on Tier 3 request, sees reasoning, approves/denies
7. Audit log shows everything disclosed
8. Developer integrates verification in <10 lines using SDK
