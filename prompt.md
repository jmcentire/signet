# Signet — System Context

## What It Is
Personal Sovereign Agent Stack. Cryptographic vault as root authority, personal agent as steward, ZK proofs as the only external interface.

## How It Works
Trust hierarchy: User -> Vault -> Agent -> External. Three data tiers: freely provable (Tier 1), agent-internal (Tier 2), capability-gated (Tier 3). Four protocols: SCP (user<->agent), VAP (agent<->vault), SNP (agent<->agent), SVP (agent<->service).

## Key Constraints
- Vault never externally reachable (C001)
- Tier 3 requires live user auth (C002)
- One-way data flow: vault -> agent -> service (C003)
- Every disclosure auditable (C004)
- Protocols must not collapse (C005)
- Credentials always scoped (C008)
- Secret keys zeroized on drop (C009)

## Architecture
9 Rust crates. Core: vault (root of trust), cred (SD-JWT/BBS+/PASETO), proof (Bulletproofs), policy (XACML-for-individuals), mcp (trust bridge), sdk (4 primitives), notify (auth channel).

## Standards
Ed25519 identity, SD-JWT VC (RFC 9901), BBS+ signatures, Bulletproofs, PASETO v4, aws-lc-rs (FIPS 140-3).

## Done Checklist
- [ ] Vault isolation verified (no external network access)
- [ ] Tier 3 gate tested (requires live auth, no bypass)
- [ ] Audit chain integrity verified (hash-linked, signed)
- [ ] Credential scoping enforced (amount, domain, time, purpose)
- [ ] Secret zeroization tested
