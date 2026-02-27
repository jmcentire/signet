# Signet Design Document

Version: 0.1.0 (Draft)
Status: Pre-implementation, pending Pact interview

---

## 1. What This Is

Signet is a Personal Sovereign Agent Stack. It puts the user's encrypted vault at the root of a cryptographic trust chain. A personal agent acts on the user's behalf, carrying proofs and scoped credentials to external services. External parties never see the user — they see the seal.

**The novel contribution**: integrating encrypted personal storage, a policy engine, credential issuance, and selective-disclosure proofs into a single system where the user is the cryptographic root of trust. Each piece exists separately in the wild. Nobody has assembled them with user sovereignty as the actual design center.

---

## 2. Lessons from the Graveyard

The research surveyed every significant project in this space. The failures have clear patterns:

| Pattern | Killed | Lesson for Signet |
|---------|--------|-------------------|
| Chicken-and-egg (verifiers won't accept, issuers won't issue) | Sovrin, most SSI | Browser extension as adoption wedge — zero verifier cooperation needed |
| Running your own blockchain | Dock, ION, Sovrin | No blockchain. No tokens. No consensus mechanism. |
| RDF/Linked Data developer experience | Solid | JSON. Always JSON. |
| Privacy maximalism over deployment pragmatism | BBS+ lost to SD-JWT in EU | Ship SD-JWT first, layer BBS+ for unlinkability |
| Token economics | Dock, Ceramic, Sovrin | No token. Revenue from hosted vault service. |
| UX friction | Universal | Hide everything behind the agent. User sees conversation, not cryptography. |
| Academic origin = slow shipping | Solid, HAT | Build with Pact. Contract-first. Ship components independently. |
| No business model for privacy | Sismo | Monetize the hosted vault (B2C) and verifier compliance savings (B2B) |

**What's actually working (early 2026)**: SD-JWT is an IETF RFC. EU Digital Identity Wallet mandate (Dec 2026) forces 450M users into credential infrastructure. zkTLS (zkPass, Reclaim) sidesteps the adoption problem by not requiring data source cooperation. The AI agent + personal data sovereignty intersection is a wide-open gap — components exist, nobody has assembled them.

---

## 3. Identity: No DID

DID (W3C Decentralized Identifiers) is rejected for Signet. It is overengineered, underdelivers, and introduces complexity without proportionate value. The specification has 47 extension points, multiple competing methods (did:key, did:web, did:ion — the last one dead), and a JSON-LD dependency that serves no user.

### What Signet Actually Needs

1. A stable identifier for the vault
2. A way to verify that a proof came from that vault
3. Key rotation without breaking existing credentials

### What Signet Uses Instead

**The vault's identity is its public key fingerprint.**

```
Signet ID = Base58(SHA-256(Ed25519_public_key)[0:20])
```

A 20-byte truncated hash of the vault's Ed25519 public key, Base58-encoded. ~27 characters. Human-readable enough to compare visually. Self-certifying — if you have the public key, you can verify the fingerprint. No resolution protocol, no registry, no DID document.

**Examples of systems that work this way**: Bitcoin addresses, SSH key fingerprints, Signal safety numbers, IPFS CIDs, Tor .onion addresses. All are hashes of public keys. All work without a W3C specification.

**Key rotation**: When the vault rotates its root key, it signs the new public key with the old private key, creating a rotation proof. The new key becomes the active key. The old key's signatures remain valid for credentials issued before rotation. The rotation proof is published at the vault's well-known endpoint.

**Key discovery** (for hosted vaults or vaults with a web presence):
```
GET /.well-known/signet.json

{
  "signet_id": "5Kd3NBUAdUnhyzenEwVLy9pBKxSwXvE9FMPy",
  "public_key": "<base64-encoded-ed25519-public-key>",
  "supported_claims": ["age_over_18", "age_over_21", "country_in_*", ...],
  "proof_formats": ["sd-jwt", "bbs-plus", "bulletproof-range"],
  "rotation_history": [
    { "previous_id": "...", "rotated_at": "2026-01-15T...", "rotation_proof": "..." }
  ]
}
```

For self-hosted vaults with no web presence: the public key is embedded in every proof. The verifier checks the signature against the embedded key. No discovery step needed.

---

## 4. Proof Architecture: Three Layers, No Circuits

Full ZK circuit systems (Noir, Circom, Halo2) are rejected for v1. They add compilation toolchains, trusted setup ceremonies (Groth16), and complexity disproportionate to the actual use cases. The research shows a simpler stack covers all requirements:

### Layer 1: SD-JWT VC (Baseline — All Credentials)

**Standard**: IETF RFC 9901 (November 2025)

Every credential Signet issues is an SD-JWT VC. This gives:
- Selective disclosure of individual fields
- Key binding (proof of vault control via challenge-response)
- Trivial verification (<1ms — standard JWT signature check + hash comparison)
- Works with any JWT library in any language
- IETF standard interoperability with EU Digital Identity Wallet ecosystem

**Covers**: Credential ownership, simple attribute disclosure, compatibility with existing services.

**Does not cover**: Unlinkability, predicate proofs.

### Layer 2: BBS+ Signatures (Privacy Layer — Unlinkable Presentations)

**Standard**: IRTF draft-irtf-cfrg-bbs-signatures (advanced standardization)

For credentials requiring unlinkable presentation (the holder doesn't want verifiers correlating activity), the vault wraps credential attributes in a BBS+ signature. The agent derives a fresh, unlinkable proof per presentation.

**Performance** (Intel i7, Dyne.org benchmarks):
- Proof generation: ~9ms
- Verification: ~15ms
- Acceptable for real-time checkout

**The pre-computed boolean pattern**: Instead of proving "birthdate implies age > 21" with a ZK circuit, the vault issues BBS+ signed credentials containing pre-computed boolean attributes:

```json
{
  "age_over_18": true,
  "age_over_21": true,
  "age_over_25": true,
  "balance_above_1000": true,
  "balance_above_10000": false,
  "country_in_EU": true,
  "country_in_FVEY": true,
  "has_valid_shipping_address_US": true
}
```

The agent selectively discloses only the relevant boolean. No ZK circuit needed. The vault re-issues credentials when underlying values change (birthday threshold, balance change). Short TTL (24h for balance-related booleans) handles staleness.

**Covers**: Age verification, balance thresholds, set membership, all with full unlinkability.

### Layer 3: Bulletproofs (Range Proofs — Dynamic Thresholds)

**Library**: dalek-cryptography/bulletproofs (Rust, Quarkslab-audited 2019)

For cases where the verifier requests a threshold the vault didn't pre-compute, or the range is dynamic:
- Vault commits to the value using a Pedersen commitment at credential issuance time
- Agent generates a Bulletproofs range proof on demand
- No trusted setup
- Proof generation: ~11ms
- Verification: ~1.5ms
- Proof size: ~700 bytes

**Covers**: Arbitrary range proofs, dynamic thresholds, "balance between X and Y".

### Coverage Matrix

| Use Case | SD-JWT | BBS+ | Bulletproofs |
|----------|--------|------|-------------|
| Credential ownership | Key binding | Schnorr in BBS+ | -- |
| Simple attribute disclosure | Yes | Yes (unlinkable) | -- |
| Age gate (over X) | If pre-computed | Pre-computed boolean, unlinkable | Dynamic threshold |
| Balance threshold | If pre-computed | Pre-computed boolean, unlinkable | Dynamic threshold |
| Country membership | Disclose directly | Pre-computed boolean, unlinkable | -- |
| Range proof (A to B) | -- | -- | Native |
| Unlinkability | No | Yes | Yes (commitments) |

### What Is Explicitly Out of Scope for v1

- **No Noir/Circom/snarkjs** — no circuit compilation toolchain
- **No trusted setup ceremonies** at any layer
- **No Halo2** — ongoing soundness concerns (query collision bug), unnecessary complexity
- **No compound predicate proofs** — "age > 21 AND country in EU" is handled by disclosing two pre-computed booleans from the same BBS+ credential

If compound predicates or arbitrary circuit logic become necessary in v2, Noir with UltraHonk (no trusted setup) is the upgrade path.

---

## 5. Vault Architecture

### Encryption Model

The vault uses envelope encryption with a per-user key hierarchy:

```
Device Key (Ed25519 + X25519, per device, never leaves device)
  |
  +-- User Root Key (URK, random 256-bit, wrapped by each device key)
       |
       +-- Vault Symmetric Key (VSK, wrapped by URK)
            |
            +-- Per-record Data Encryption Keys (DEK, wrapped by VSK)
            +-- Encrypted Index (encrypted with VSK)
            +-- Tier 3 Compartment Keys (wrapped by URK, NOT by VSK)
```

**Critical property**: Tier 3 data uses compartment keys wrapped directly by the URK, not by the VSK. The agent holds a session token granting access to the VSK (and thus Tier 1 and Tier 2 data). The agent **never** holds the URK. Tier 3 decryption requires the user to issue a time-limited, single-use decryption grant that temporarily unwraps the specific compartment key needed.

### Cryptographic Primitives

| Purpose | Algorithm | Library | Audit Status |
|---------|-----------|---------|-------------|
| Vault root signing | Ed25519 | aws-lc-rs | FIPS 140-3 validated |
| Key agreement | X25519 | aws-lc-rs | FIPS 140-3 validated |
| Symmetric encryption | AES-256-GCM | aws-lc-rs | FIPS 140-3 validated |
| Key derivation | HKDF-SHA-256 | aws-lc-rs | FIPS 140-3 validated |
| Password KDF (if needed) | Argon2id | -- | PHC winner, well-studied |
| Credential signing (SD-JWT) | Ed25519 | aws-lc-rs | FIPS 140-3 validated |
| Credential signing (BBS+) | BLS12-381 | anoncreds-v2-rs | Formal security proof (2025) |
| Range proofs | Ristretto/Bulletproofs | dalek bulletproofs | Quarkslab audited (2019) |
| Capability tokens | PASETO v4 (XChaCha20 + BLAKE2b / Ed25519) | rusty_paseto | Misuse-resistant by design |

**aws-lc-rs** is the primary crypto backend. It provides FIPS 140-3 validation through AWS-LC, has official Rust bindings, and includes post-quantum readiness (ML-KEM in FIPS 3.0). This is the strongest FIPS story available in Rust.

**No libsodium**: While well-audited, libsodium is not FIPS validated. For a system that may face compliance requirements (hosted vault, financial data), FIPS validation matters.

### Storage Model

The vault server is a dumb encrypted blob store. It handles:
- **Blob storage**: Content-addressed by `HMAC(tenant_key, logical_path)` — the server never sees logical paths
- **Encrypted index**: A special blob synced to the client, decrypted locally, maps logical names to blob addresses
- **Blind indexes**: For specific exact-match server-side queries, `HMAC(index_key, field_value)` on designated fields
- **Audit log**: Append-only, per-tenant, field-level encryption for sensitive fields

The server cannot:
- Read any vault contents
- Determine what a blob contains
- Link blobs to each other (addresses are derived from unrelated HMAC keys)
- Search vault contents
- Identify which blob corresponds to which data category

### Self-Hosted vs. Hosted

**Same Docker image, same binary, different config.**

```
signet-vault-server
  ├── Storage backend: filesystem (self-hosted) | S3/MinIO (hosted)
  ├── Database: SQLite (self-hosted) | Postgres (hosted)
  ├── Auth: Ed25519 keypair (both) + mTLS (hosted)
  └── Config: environment variables (12-factor)
```

**Self-hosted**: Single container, <50MB RAM idle, runs on Raspberry Pi. SQLite for metadata, filesystem for blobs. User controls everything.

**Hosted (multi-tenant)**: Postgres for metadata, S3-compatible storage for blobs. Per-tenant isolation via envelope encryption with per-tenant root keys. Tenants can bring their own KMS (BYOK) or use managed key wrapping.

**Migration**: Export encrypted blobs + EDEKs + encrypted index as a portable bundle. Import to new environment. No re-encryption needed — the server never had keys. Re-register devices against new server.

### Multi-Tenant Hosted Architecture

```
Client Device
  |
  | mTLS + Ed25519 auth
  |
Signet Hosted Service
  ├── API Gateway (rate limiting, tenant routing)
  ├── Auth Service (Ed25519 challenge-response, device registry)
  ├── Blob Store (S3, per-tenant prefixed, encrypted at rest)
  ├── Metadata DB (Postgres, per-tenant schemas or row-level isolation)
  ├── Audit Log (append-only, immutable, per-tenant)
  └── Key Wrapping Service
        ├── Managed KMS (for tenants without BYOK)
        └── BYOK bridge (tenant's KMS wraps their root key)
```

**Tenant isolation properties**:
- Cryptographic: per-tenant key hierarchy. Compromise of one tenant's keys reveals nothing about another's.
- Storage: per-tenant blob prefixes. No cross-tenant blob addressability.
- Compute: no server-side decryption. The server cannot accidentally mix tenant data because it cannot read any of it.
- Deletion: cryptographic erasure via tenant root key destruction. Destroys all data across all backups and replicas simultaneously. GDPR Article 17 compliant.

**Audit logging** (safe to log):
- Timestamps, operation type (read/write/delete/rotate), tenant ID (opaque), device ID (opaque), blob address (opaque), success/fail, request size, key version used.

**Not logged**: Plaintext, keys, search queries, decrypted metadata, file names.

### Authentication

No passwords. The user's identity is their key.

1. **Primary**: Ed25519 keypair per device. Private key never leaves device. Challenge-response authentication.
2. **Transport**: mTLS with a private CA for hosted service. Client certificates issued per device.
3. **Browser**: FIDO2/WebAuthn for user presence, combined with locally-stored encrypted key blob that requires the authenticator to unwrap.
4. **Device provisioning**: New device is authorized by an existing device (Keybase model). Existing device re-encrypts the wrapped URK for the new device's public key.
5. **Trusted IPs**: Optional IP allowlist per tenant. Requests from unknown IPs require additional verification (FIDO2 tap or second-device approval).

---

## 6. Edge Cases: Resolved

### Vault Availability

**Decision**: Cached proofs with TTL for Tier 1. Hard fail for Tier 2 and Tier 3.

- **Tier 1 proofs** (freely provable booleans): The agent may cache issued BBS+ credentials with a TTL set by the vault (default: 24 hours for volatile claims like balance, 30 days for stable claims like age_over_21). The agent can derive fresh unlinkable presentations from cached credentials without contacting the vault.
- **Tier 2** (agent-internal reasoning): The agent may cache Tier 2 data in its own encrypted local store for offline reasoning. It cannot issue new proofs about this data without the vault.
- **Tier 3** (capability-gated): Hard fail. No caching. No offline access. The user must be reachable and the vault must be online. This is the security invariant.

**Implication**: For hosted vaults, the service provides high availability. For self-hosted, the user accepts that agent capabilities degrade when their device is off. This is the correct tradeoff — availability should not override security for Tier 3 data.

### Credential Revocation

**Decision**: Short-lived credentials + optional revocation endpoint. No revocation lists.

- **One-time credentials** (Tier 3 capabilities): Self-invalidate on use. The vault marks them consumed. If the external service attempts to re-verify, the vault returns "consumed." If the vault is unreachable, the service decides whether to accept the credential based on its own risk tolerance and the credential's expiry.
- **Reusable credentials** (Tier 1 proofs): Short TTL. The vault re-issues on refresh. If the user wants to revoke a credential early (e.g., they changed a preference), the vault updates the credential and the agent's cache.
- **No CRL/OCSP**: Revocation lists leak information (which credentials were revoked, when). Short TTLs are simpler and privacy-preserving.

### Agent Compromise

**Decision**: Blast radius is Tier 1 + Tier 2 only. Tier 3 is protected by construction.

- A compromised agent has access to: cached Tier 1 credentials (can derive proofs until TTL expires), Tier 2 data (preferences, history — can exfiltrate). It does **not** have access to: Tier 3 compartment keys (requires user-issued decryption grant), the vault's root signing key (held by the vault, not the agent), or the ability to issue new credentials (requires vault co-signature).
- **Mitigation**: Agent sessions have a maximum lifetime (configurable, default 24h). The vault can revoke an agent session at any time. Key rotation: vault generates a new agent credential, invalidating the old one.
- **Detection**: The audit log captures all agent actions. Anomaly detection in the policy engine can flag unusual patterns (e.g., agent requesting many Tier 1 proofs rapidly, agent requesting claims it has never requested before).

### Multi-Device

**Decision**: One vault, multiple authenticated device connections. Per-device keys.

- Each device generates its own Ed25519 + X25519 keypair.
- The vault's User Root Key (URK) is wrapped separately for each device's public key.
- Adding a device requires an existing device to perform the wrapping ceremony.
- Revoking a device: re-wrap the URK for remaining devices, rotate the VSK, re-encrypt the vault index. Per-record DEKs do not need rotation (they are wrapped by the VSK, which was rotated).
- **No vault replication**: There is one vault (self-hosted or hosted). Devices connect to it. This avoids the entire class of sync/conflict/consistency problems.

### Recovery

**Decision**: Printed recovery key (primary) + optional social recovery (Shamir's Secret Sharing).

- **Recovery key**: At vault creation, the system generates a 256-bit recovery key, displays it as a BIP39 mnemonic (24 words), and encrypts the URK with it. The user prints or writes down the mnemonic. This is the recovery path.
- **Social recovery** (optional): The user splits the recovery key using Shamir's Secret Sharing (3-of-5 or user-configured threshold). Shares are distributed to trusted contacts. Each share is individually useless. Recovery requires the threshold number of contacts to provide their shares.
- **No escrow**: Signet never holds recovery keys. The hosted service cannot recover a user's vault. This is a feature, not a limitation.
- **Key rotation after recovery**: After recovering with the recovery key, the system forces a full key rotation (new URK, new VSK, re-wrap all DEKs, new device key). The old recovery key is invalidated and a new one is generated.

### Delegation

**Decision**: Sub-signets with constrained authority and full audit trail.

- A user can issue a **delegate credential** to another person (spouse, assistant). This credential is a PASETO v4 token with:
  - Delegate's public key
  - Permission set (which tiers, which data categories, which actions)
  - Time bound (expires at T)
  - Revocable (vault can invalidate at any time)
- The delegate authenticates with their own device key, presents the delegate credential, and operates within its constraints.
- All delegate actions are on the audit log, tagged with the delegate's identity.
- Delegates cannot issue further delegations (no transitive delegation).

### Protocol Versioning

**Decision**: Version in every message header. Strict: both sides must agree on version.

- Every protocol message includes `"signet_version": "0.1"`.
- Agents advertise supported versions during handshake.
- If versions don't overlap, the connection fails with a clear error.
- No backward-compatibility shims. When a new version is released, the old one is supported for a defined sunset period (minimum 12 months), then dropped.
- Credential formats are versioned independently of the protocol. A v1 credential can be verified by a v2 SDK.

### Performance

All proof operations are real-time compatible:

| Operation | Time | Acceptable for Checkout? |
|-----------|------|--------------------------|
| SD-JWT issuance | <1ms | Yes |
| SD-JWT verification | <1ms | Yes |
| BBS+ proof generation | ~9ms | Yes |
| BBS+ verification | ~15ms | Yes |
| Bulletproof range proof | ~11ms | Yes |
| Bulletproof verification | ~1.5ms | Yes |
| PASETO token issuance | <1ms | Yes |
| AES-256-GCM encrypt (1KB) | <0.1ms | Yes |

**Credential caching** eliminates vault round-trips for Tier 1 proofs. The agent holds BBS+ signed credentials locally and derives fresh presentations on demand. No network latency for the common case.

---

## 7. Policy Engine

### Design Principles

1. **Actor + Predicate + Context = Legitimacy**. No single factor determines access.
2. **Undefined is not denied — it is escalated**. The user learns about novel requests.
3. **Policy learning through interaction**. The system gets smarter as the user makes decisions.
4. **Sensible defaults, user overrides everything**.

### Role Hierarchy

```
Public          trust 1   Unauthenticated actors
Commerce        trust 3   Verified merchants
Financial       trust 4   Banks, payment processors (inherits Commerce)
Medical         trust 5   Healthcare providers (separate branch, does NOT inherit Financial)
Identity        trust 5   Government, KYC providers (separate branch)
Trusted Agent   trust 6   User's personal agent (cannot override Tier 3 gates)
```

Roles are user-curated. The system ships these defaults. Users can create custom roles, merge roles, split roles, and adjust trust levels.

### Actor Classification

Actors are classified by:
- **Explicit assignment**: User assigns Amazon to Commerce role
- **Domain inference**: Unknown *.amazon.com -> Commerce (based on domain category databases)
- **Credential presentation**: Actor presents a verifiable credential proving its role (e.g., a bank presents a financial license credential)
- **Agent negotiation**: During Protocol 2 handshake, the external agent declares its purpose. The personal agent's policy engine classifies based on the declaration + domain + history.

### Evaluation Chain

```
1. CLASSIFY actor (explicit > credential > domain inference > declaration)
2. CHECK role permissions for the requested predicate
3. IF permitted: check tier rules, issue proof/credential
4. IF denied: return denial with reason code
5. IF undefined (role/predicate mismatch):
   a. Flag as anomalous
   b. Compose reasoning: what was requested, by whom, why it's unusual
   c. Fire Protocol 0 notification to user
   d. Await decision (timeout: configurable, default 5 minutes, default on timeout: deny)
   e. Record decision on audit chain
   f. If user approves role amendment: update policy, persist
```

### Policy Storage

Policies are stored in the vault as structured JSON:

```json
{
  "roles": {
    "commerce": {
      "trust_level": 3,
      "permissions": {
        "read": ["preferences.finish", "preferences.size", "shipping_address"],
        "prove": ["age_over_*", "country_in_*", "has_valid_shipping_address_*"],
        "request": ["payment_capability"]
      },
      "deny": ["income", "medical", "identity_documents"]
    }
  },
  "actor_overrides": {
    "amazon.com": {
      "role": "commerce",
      "trust_level": 3,
      "exceptions": [
        { "predicate": "age_over_21", "granted": "2026-02-15", "reason": "alcohol purchase", "expires": null }
      ]
    }
  },
  "defaults": {
    "unknown_actor": "public",
    "timeout_action": "deny",
    "timeout_seconds": 300
  }
}
```

---

## 8. Component Architecture

### Component Dependency Graph

```
signet-vault (root of trust)
  ├── signet-cred (credential issuance)
  │     └── depends on: vault keypair, vault data access
  ├── signet-proof (proof generation — replaces signet-circuits)
  │     └── depends on: vault data access, signet-cred
  ├── signet-policy (access control)
  │     └── depends on: vault schema, audit log
  └── signet-mcp (trust bridge)
        ├── depends on: vault, cred, proof, policy
        ├── signet-sdk (developer surface)
        │     └── depends on: protocol definitions from mcp
        └── signet-notify (authorization channel)
              └── depends on: policy decisions from policy
```

Note: `signet-extension` (browser) is deferred to post-v1. The browser extension requires a stable SDK and protocol, which are the outputs of v1.

### Component Specifications

#### signet-vault

**Purpose**: Encrypted local data store with key management.

**Inputs**: Plaintext data from user, encrypted blobs from sync.
**Outputs**: Encrypted blobs, wrapped DEKs, proof material (signed attributes for BBS+, Pedersen commitments for Bulletproofs).

**Key behaviors**:
- Generate and manage root keypair (Ed25519 + X25519)
- Encrypt/decrypt records using envelope encryption
- Manage three-tier data classification
- Tier 3 compartment key isolation (agent cannot access without user grant)
- Device provisioning (wrap URK for new device)
- Key rotation (root key, VSK, per-record DEKs)
- Recovery key generation (BIP39 mnemonic)
- Shamir's Secret Sharing for social recovery
- Content-addressed blob storage interface
- Encrypted client-side index
- Blind indexes for designated fields
- Append-only audit log

**Acceptance criteria**:
- [ ] Agent session cannot decrypt Tier 3 data without user-issued grant
- [ ] Vault compromise (all blobs + EDEKs) reveals no plaintext without device key
- [ ] Key rotation completes without data re-encryption (only DEK re-wrapping)
- [ ] Recovery via BIP39 mnemonic restores full vault access
- [ ] Same binary runs self-hosted (SQLite + filesystem) and hosted (Postgres + S3)
- [ ] All crypto operations use aws-lc-rs (FIPS 140-3 path)

#### signet-cred

**Purpose**: Issue signed credentials in SD-JWT and BBS+ formats.

**Inputs**: Vault data, credential schema, issuance request.
**Outputs**: SD-JWT VCs, BBS+ signed attribute sets, Pedersen commitments.

**Key behaviors**:
- Issue SD-JWT VC with selective disclosure for any vault attribute
- Issue BBS+ signed credential sets with pre-computed boolean attributes
- Embed Pedersen commitments for numeric attributes (balance, age-in-days) for Bulletproof range proofs
- Key binding (embed vault public key for holder verification)
- TTL management (short TTL for volatile claims, long TTL for stable claims)
- Credential refresh on underlying data change
- Credential consumption tracking (one-time tokens)

**Acceptance criteria**:
- [ ] SD-JWT credentials pass verification by any RFC 9901-compliant library
- [ ] BBS+ credentials produce unlinkable proofs (two proofs from same credential cannot be correlated)
- [ ] Pedersen commitments support range proofs via Bulletproofs
- [ ] One-time credentials cannot be reused after consumption
- [ ] Credential TTL is enforced — expired credentials fail verification
- [ ] Pre-computed booleans are refreshed when underlying values change

#### signet-proof

**Purpose**: Generate privacy-preserving proofs from credentials.

**Inputs**: Cached credentials (SD-JWT, BBS+, Pedersen commitments), proof request specifying claim and domain.
**Outputs**: Proofs (SD-JWT presentations, BBS+ derived proofs, Bulletproof range proofs).

**Key behaviors**:
- Derive SD-JWT presentations (selective disclosure of requested fields)
- Derive BBS+ unlinkable proofs (fresh proof per presentation)
- Generate Bulletproof range proofs from Pedersen commitments
- Domain binding (proof is scoped to requesting domain)
- Proof composition (multiple claims in a single response)

**Acceptance criteria**:
- [ ] BBS+ proofs are unlinkable (statistical test: N proofs from same credential are indistinguishable from N proofs from N credentials)
- [ ] Bulletproof range proofs verify in <2ms
- [ ] All proof generation completes in <20ms
- [ ] Domain-bound proofs fail verification when presented to a different domain
- [ ] Proof composition does not leak correlation between composed claims

#### signet-policy

**Purpose**: Evaluate access requests against user-defined policy.

**Inputs**: Actor identity, requested predicate, context (purpose, domain).
**Outputs**: Permit, deny, or escalate (with reasoning).

**Key behaviors**:
- Actor classification (explicit, credential, domain inference, declaration)
- Role/predicate legitimacy check
- Context analysis
- Anomaly detection (role/predicate mismatch)
- Escalation with composed reasoning
- Policy learning (record user decisions, propose role amendments)
- Policy persistence in vault

**Acceptance criteria**:
- [ ] Classified actors can only access predicates permitted by their role
- [ ] Undefined role/predicate combinations escalate, never silently permit
- [ ] Escalation messages include who, what, why unusual, and user options
- [ ] User decisions are persisted and applied to future requests
- [ ] Role amendments are on the audit chain
- [ ] Default-deny on timeout

#### signet-mcp

**Purpose**: MCP server bridging personal agent to vault and external agents.

**Inputs**: MCP tool calls from personal agent and external agents.
**Outputs**: Proofs, credentials, denial messages, escalation notifications.

**Key behaviors**:
- Authenticate personal agent (Ed25519 session)
- Expose vault query tools to personal agent (Tier 1 + Tier 2 access)
- Expose proof/capability request tools to external agents
- Route requests through policy engine
- Enforce tier logic (Tier 3 -> Protocol 0 notification)
- Steward Negotiation Protocol handshake with external agents
- Context negotiation (agent negotiates on user's behalf)
- Session management (agent session lifetime, revocation)

**MCP tool interface** (what external agents see):

```
signet_get_proof(claim, domain) -> proof_token | denial
signet_request_capability(spec) -> capability_token | denial | pending_authorization
signet_check_authority(signet_id) -> { valid, public_key, supported_claims }
signet_negotiate_context(purpose, needed_claims) -> available_claims | counter_proposal
```

**Acceptance criteria**:
- [ ] External agents cannot access Tier 2 data (only proofs and conclusions)
- [ ] Tier 3 requests suspend and fire Protocol 0 notification
- [ ] Agent sessions expire after configured lifetime
- [ ] Vault can revoke agent sessions immediately
- [ ] All MCP tool calls are on the audit log
- [ ] Context negotiation never discloses more than the minimum required claims

#### signet-sdk

**Purpose**: Minimal developer SDK for external service integration.

**Four primitives only**:
```
verify(proof, claim) -> { valid, expires, scope, signet_id }
requestCapability(spec) -> capability_token | denial | pending
checkAuthority(signet_id) -> { valid, public_key, supported_claims }
parseCredential(token) -> { claims, scope, expires } (no underlying data)
```

**Acceptance criteria**:
- [ ] SDK has zero transitive dependencies beyond a crypto library
- [ ] verify() works with SD-JWT, BBS+, and Bulletproof proofs
- [ ] A developer can integrate passive verification in under 10 lines of code
- [ ] SDK never requires the developer to understand BBS+ or Bulletproofs
- [ ] Available in Rust (primary), TypeScript (npm), and Python (pip)

#### signet-notify

**Purpose**: Authorization channel between vault and user.

**Inputs**: Escalation requests from policy engine.
**Outputs**: User decisions (approve/deny/modify).

**Key behaviors**:
- Multi-channel: webhook (primary), SMS (optional), push notification (optional)
- Present reasoning (not just "authorize?")
- User response options: approve, deny, deny always, grant exception, propose role amendment
- Timeout handling (configurable, default deny)
- Low-friction: one-tap approve on mobile, keyboard shortcut on desktop

**Acceptance criteria**:
- [ ] Webhook delivery within 1 second of escalation
- [ ] User decision propagates to requesting context within 1 second of response
- [ ] Timeout defaults to deny
- [ ] Notification includes full reasoning (who, what, why unusual, user options)
- [ ] All notifications and decisions are on the audit log

---

## 9. Standards Stack (Revised)

| Layer | Standard | Why |
|-------|----------|-----|
| Identity | Ed25519 public key fingerprint | Self-certifying, no DID, no resolution protocol |
| Key discovery | `/.well-known/signet.json` | HTTP, simple, optional |
| Credentials (interop) | SD-JWT VC (RFC 9901) | IETF standard, EU wallet compatible |
| Credentials (privacy) | BBS+ Signatures (IRTF draft) | Unlinkability, selective disclosure |
| Range proofs | Bulletproofs (Pedersen commitments) | No trusted setup, audited, fast |
| Agent protocol | MCP | Native integration surface |
| Capability tokens | PASETO v4 | Misuse-resistant, no algorithm confusion |
| Symmetric encryption | AES-256-GCM | FIPS 140-3 via aws-lc-rs |
| Signing | Ed25519 | FIPS 140-3 via aws-lc-rs |
| Key agreement | X25519 | FIPS 140-3 via aws-lc-rs |
| Key derivation | HKDF-SHA-256 | FIPS 140-3 via aws-lc-rs |
| Recovery | BIP39 mnemonic (24 words) | Human-writable, well-understood |
| Secret sharing | Shamir's Secret Sharing | Social recovery, no single point of failure |

---

## 10. Signet as an AI Connector

Signet's primary integration surface is as a **connector** for AI agents — the same way Google Drive, Slack, or GitHub appear as data sources in Claude, ChatGPT, or other AI platforms.

### How It Works

The user connects their Signet vault to Claude (or any MCP-compatible agent) through the platform's connector/integration settings. From the AI's perspective, Signet is just another MCP tool server. From the vault's perspective, the AI is just another agent — trusted within the scope the user defined.

### Connector Setup Flow

```
1. User clicks "Add Signet" in Claude settings (or equivalent)
2. Claude redirects to vault's OAuth 2.1 authorization endpoint
   (MCP Nov 2025 spec uses OAuth 2.1 for auth)
3. User authenticates to their vault (Ed25519 device key / FIDO2)
4. Vault displays: "Claude wants to connect as your personal agent"
   with the requested permission scope
5. User approves → vault issues a Trusted Agent credential (PASETO v4)
   scoped to Claude's session, with the permissions the user granted
6. Claude receives the credential, stores it, and can now call Signet MCP tools
7. Vault policy engine classifies Claude as trust level 6 (Trusted Agent)
```

### What Claude Sees (MCP Tool Interface)

After connection, Claude's tool list includes:

```
signet_get_proof(claim, domain)
  → "Is the user over 21?" → returns proof token
signet_query(question)
  → "What size shelves does the user prefer?" → returns answer (not raw data)
signet_request_capability(spec)
  → "Need payment auth for $150 at amazon.com" → returns capability token or pending
signet_check_status(request_id)
  → Check if a pending Tier 3 authorization was approved
```

Claude doesn't need to understand BBS+ or Bulletproofs. It calls a tool, gets a result. The hard stuff happens in the vault.

### Hosted Vault: The Connector Endpoint

For hosted vaults, the Signet MCP server is the publicly reachable endpoint:

```
User's Vault (encrypted, dark)
  └── Signet MCP Server (public, authenticated)
        ├── OAuth 2.1 authorization endpoint
        ├── MCP tool endpoint (authenticated sessions)
        ├── /.well-known/signet.json (discovery)
        └── Webhook endpoint (for delivering proofs to external agents)
```

The MCP server is reachable. The vault behind it is not. All data flows through the policy engine.

For self-hosted vaults, the user runs the MCP server alongside the vault (same machine or same network). If the user wants Claude to access their self-hosted vault, they need the MCP server to be reachable — via tunneling (Cloudflare Tunnel, ngrok) or by hosting the MCP server component on a reachable endpoint that authenticates back to the local vault.

### Registry Listing

Signet should be listed in:
- Anthropic's MCP connector marketplace (when it exists)
- Any emerging MCP server registries
- As a standard MCP server configuration users can add manually (URL + auth)

### Multi-Agent Support

The same vault can be connected to multiple AI platforms simultaneously:
- Claude gets a Trusted Agent credential scoped to Claude's session
- ChatGPT gets a separate Trusted Agent credential scoped to ChatGPT's session
- Each session has independent permissions, audit trails, and revocation
- The user manages all connected agents through Protocol 0 (their UI)

---

## 11. What We're NOT Building

Explicit exclusions to prevent scope creep:

1. **No blockchain** — no tokens, no consensus, no gas fees
2. **No DID** — public key fingerprints are sufficient
3. **No JSON-LD** — JSON, always JSON
4. **No ZK circuit compiler** in v1 — BBS+ pre-computed booleans + Bulletproofs cover all use cases
5. **No browser extension** in v1 — requires stable SDK and protocol first
6. **No mobile app** in v1 — CLI and web interface first
7. **No federated identity** — the vault IS the identity provider
8. **No backward compatibility with legacy SSI** — clean break, not an adapter layer
9. **No W3C Verifiable Presentations** wrapper — SD-JWT and BBS+ proofs are self-contained
10. **No OIDC/OAuth bridge** in v1 — could be v2, but not core architecture

---

## 12. Threat Model

### What We Protect Against

| Threat | Mitigation |
|--------|-----------|
| Server compromise (hosted) | Zero-knowledge architecture — server has only ciphertext |
| Agent compromise | Blast radius limited to Tier 1 + 2. Tier 3 protected by construction. Session expiry + revocation. |
| Network MITM | mTLS, Ed25519 challenge-response auth, PASETO (no algorithm confusion) |
| Credential theft | Scoped (domain, time, amount, purpose). One-time credentials self-invalidate. |
| Correlation across verifiers | BBS+ unlinkable proofs. Fresh derivation per presentation. |
| Coerced key disclosure | Social recovery (Shamir) — no single key to surrender. Optional duress key (returns plausible but limited vault). |
| Side-channel on server | Server never decrypts. No timing oracle possible because no decryption path exists. |
| Metadata analysis on hosted service | Content-addressed storage (addresses are HMAC-derived, unlinkable). Opaque tenant IDs. No plaintext metadata. |
| Root key loss | BIP39 recovery key (printed) + optional Shamir social recovery |

### What We Do NOT Protect Against

| Threat | Why Not |
|--------|---------|
| Compromised user device | If the device is rooted/compromised, the device key is exposed. This is the trust boundary. |
| User coercion (legal, physical) | Technical measures can offer duress keys; they cannot prevent coercion. |
| Server-served web client code injection | Mitigate with native clients, reproducible builds, content-addressed code serving. Cannot eliminate for web. |
| Quantum computing | FIPS 140-3 v3.0 (AWS-LC) includes ML-KEM. Upgrade path exists but not in v1 scope. |
| Stale credential exploitation | Mitigate with short TTLs. Cannot eliminate the window between issuance and expiry. |

---

## 13. Language and Build

**Primary language**: Rust

**Why Rust**:
- aws-lc-rs (FIPS 140-3) is Rust-native
- anoncreds-v2-rs (BBS+) is Rust
- dalek bulletproofs is Rust
- Memory safety without GC — critical for crypto operations (zeroing secrets)
- Single binary deployment for vault server
- WASM compilation for SDK (browser, Node.js)
- Pact supports Rust projects

**SDK language targets**:
- Rust (primary, source of truth)
- TypeScript/JavaScript (via WASM compilation of Rust core)
- Python (via PyO3 bindings)

**Build system**: Cargo workspace (monorepo)

```
signet/
  Cargo.toml (workspace)
  crates/
    signet-vault/
    signet-cred/
    signet-proof/
    signet-policy/
    signet-mcp/
    signet-sdk/
    signet-notify/
  tests/           # integration tests
  docs/            # protocol specifications
```

---

## 14. Pact Shape

For Pact's Shape step, the pitch:

**Problem**: Users have no cryptographic control over their personal data. AI agents operate on user data with no audit trail, no scoping, and no proof-based disclosure. Every service builds its own profile of the user. The user cannot verify what was disclosed, to whom, or why.

**Appetite**: 6-week build cycle for core vault + credential + proof + policy + MCP server. SDK and notification channel in a second 6-week cycle. Browser extension deferred.

**Solution**: Encrypted vault as root of trust. Personal agent as steward carrying proofs. Policy engine that surfaces reasoning on unusual requests. Three-layer proof system (SD-JWT + BBS+ + Bulletproofs) covering all disclosure use cases without circuit compilation.

**Rabbit holes to avoid**:
- DID/JSON-LD integration
- Custom ZK circuit DSL
- Blockchain anchoring
- Mobile app in v1
- Federated identity bridges
- W3C Verifiable Presentation wrapper format

**No-gos**:
- The vault server must never have access to plaintext
- Tier 3 must never be accessible without live user authorization
- The SDK must stay at four primitives
- No algorithm negotiation in any protocol (prevents confusion attacks)

---

## 15. Pact Interview Preparation

Questions Pact will ask and our answers:

**Q: What are the external dependencies?**
A: aws-lc-rs (FIPS crypto), anoncreds-v2-rs (BBS+), dalek bulletproofs (range proofs), rusty_paseto (capability tokens), sd-jwt-rust (credential format). All Rust, all FOSS.

**Q: What is the primary risk?**
A: Adoption. The cryptography is well-understood. The risk is that the UX of the authorization flow creates too much friction, causing users to reflexively approve everything (defeating the purpose) or to abandon the system. The policy engine's reasoning-based escalation is the mitigation.

**Q: What is the most complex component?**
A: signet-vault. It handles key hierarchy, multi-device provisioning, tier isolation, encryption, storage abstraction, and recovery. It should be decomposed further during Pact's decomposition step.

**Q: What are the hard integration points?**
A: (1) signet-mcp must faithfully bridge four protocol layers without collapsing trust boundaries. (2) signet-proof must compose SD-JWT, BBS+, and Bulletproof proofs into a unified presentation format. (3) signet-notify must deliver authorization requests with sub-second latency across multiple channels.

**Q: What does "done" look like?**
A: A user can:
1. Create a vault (local or hosted)
2. Store personal data in three tiers
3. Connect their AI agent via MCP
4. Have the agent answer a Tier 1 proof request from an external service without user involvement
5. Have the agent reason about Tier 2 data and return conclusions without disclosing raw data
6. Receive a notification when a Tier 3 capability is requested, see the reasoning, and approve/deny
7. Review the audit log of everything disclosed
8. A developer can integrate verification in under 10 lines of code using the SDK

---

## Key References

- SD-JWT: RFC 9901 — https://datatracker.ietf.org/doc/rfc9901/
- BBS+ Signatures: IRTF draft — https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html
- BBS+ W3C: https://www.w3.org/TR/vc-di-bbs/
- Bulletproofs: dalek — https://github.com/dalek-cryptography/bulletproofs
- Quarkslab audit of dalek: https://blog.quarkslab.com/security-audit-of-dalek-libraries.html
- AnonCreds v2 formal analysis: https://eprint.iacr.org/2025/694.pdf
- aws-lc-rs FIPS: https://aws.amazon.com/blogs/security/aws-lc-fips-3-0-first-cryptographic-library-to-include-ml-kem-in-fips-140-3-validation/
- PASETO v4: https://paseto.io/
- BBS+ benchmarks (Dyne.org): https://news.dyne.org/benchmark-of-the-bbs-signature-scheme-v06/
- SpruceID DIDKit audit (Trail of Bits): https://blog.spruceid.com/spruce-completes-first-security-audit-from-trail-of-bits/
- Bitwarden security whitepaper: https://bitwarden.com/help/bitwarden-security-white-paper/
- Proton Key Transparency: https://proton.me/support/key-transparency
- Brave ZKP age verification limits: https://brave.com/blog/zkp-age-verification-limits/
- EFF on ZKP and digital ID: https://www.eff.org/deeplinks/2025/07/zero-knowledge-proofs-alone-are-not-digital-id-solution-protecting-user-privacy
- MCP specification: https://modelcontextprotocol.io/
- EU Digital Identity Wallet regulation: https://ec.europa.eu/digital-building-blocks/sites/spaces/EUDIGITALIDENTITYWALLET/
- Trinsic pivot post-mortem: https://rileyparkerhughes.medium.com/why-verifiable-credentials-arent-widely-adopted-why-trinsic-pivoted-aee946379e3b
- "The Ephemeral Internet" (McEntire, 2026) — BlindDB concepts

---

## Kindex

Signet captures discoveries, decisions, and architectural rationale in [Kindex](~/Code/kindex). Search before adding. Link related concepts. Use `learn` after complex design sessions.
