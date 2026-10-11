# Integrate personal authority

**Preserved research prototype; further build is paused.** For the complete settled
design, read [architecture](architecture.md). For current verification and gaps,
read [prototype status](prototype-status.md) and [open work](open-work.md).

Signet is the open-source authority layer for the agent a person chooses. Its
architecture separates intelligence from authority: the platform supplies the
conversation and service access; the person remains the intended source of
permission. Created by Jeremy McEntire, Signet offers inspectable Rust components
and an MCP surface to develop that boundary.

## Start with the everyday contract

The intended experience lets the user set standing, conditional and temporary permissions by conversation; conversational authoring is not integrated.
Action authority and one-time authority to add/edit/remove an exact identified
rule are separate. Read [the product contract](everyday-authority.md) before
choosing how to map these into an agent. The [read-only MCP preview](agent-preview.md)
grants no authority. The separate [authenticated authority core](authority-service.md)
persists signed rule mutations, grants and execution reservations. Its owner and
executor trust boundaries must be provisioned outside the agent; a local passkey owner UI exists, but no live merchant executor is bundled.

## Responsibility split

| Layer | Responsibility |
|---|---|
| Person | Chooses the agent, determines permitted context, approves sensitive access. |
| Personal-agent platform | Model, memory experience, conversation, service adapters, consent UI, and transport security. |
| Signet components | Vault/key boundaries, policy decisions, proof/credential processing, notification and audit primitives. |
| Service | Establishes issuer trust, verifies claims in exact context, and enforces its own action/consumption boundary. |

MCP is a transport and tool interface, not a trust guarantee. Installing a server
does not automatically connect proof generation, enforce every boundary, or make
a service accept a credential. Cross-service personal agents are the intended
integration audience; no named platform integration or endorsement is claimed.

## Implementation status

This is a source-grounded integration map, not a production certification.

| Surface | Current behavior and source |
|---|---|
| Authenticated authority | [`authority`](../crates/signet/src/authority/mod.rs) verifies provisioned owner/client/executor signatures, versions rules and atomically consumes exact grants into mutations or execution reservations. [Raw/MCP contract](authority-service.md); a [passkey owner app](owner-approval.md) and signed HTTP/MCP adapter are implemented locally; isolated deployment and merchant adapters remain. |
| Native rings/owner | [`native owner`](../crates/signet/src/authority/owner/native.rs) stores WebAuthn credential state and [`rings`](../crates/signet/src/authority/rings/mod.rs) in one native JSON CAS aggregate. CLI/HTTP/forms are wired; synthetic service-level tests pass, while native browser/HTTP/concurrency and readable-requirement review remain. No live R2/KMS call was made. |
| Read-only preview | [`preview-serve`](../crates/signet/src/preview.rs) offers deterministic hypothetical purchase/rule-change evaluation through standard MCP tools calls. No vault, grants or persistence. |
| Store/list | [MCP storage tools](../crates/signet-mcp/src/tools/store.rs) use `VaultAccess`; Tier 3 list values are masked. Evaluate only with synthetic data. |
| MCP proof tool | [`get_proof`](../crates/signet-mcp/src/tools/get_proof.rs) generates deterministic hash-based placeholder bytes. It does not call the real proof pipeline. Do not accept these bytes as a proof. |
| MCP queries | [`query`](../crates/signet-mcp/src/tools/query.rs) returns scaffolded Tier 1 answers and Tier 2 conclusions. It does not perform real personal reasoning. |
| Middleware | [Pipeline](../crates/signet-mcp/src/pipeline.rs) defines session, tier, policy, execution, and audit stages. [Direct dispatch](../crates/signet-mcp/src/dispatcher.rs) has separate store/list paths and constructs an anonymous session for some tools. Audit every transport's actual enforcement path. |
| Capability requests | [MCP executor](../crates/signet-mcp/src/tools/capability.rs) denies issuance. Direct Tier 3 dispatch can return a pending challenge first. Neither outcome is a signed grant. SDK and CLI issuance also fail closed. |
| Generic capability verification | [`verify_capability_for_context`](../crates/signet-cred/src/capability.rs) checks signed envelopes against expected issuer, domain, purpose, time and requested financial constraints. One-time issuance and acceptance fail closed without a consumption ledger. |
| Delegated providers | [Acceptance-only draft](delegated-provider-authorization-boundary-2026-06-04.md); not a working provider integration or a substitute for the generic envelope. |

Review the [capability boundary](capability-verification-boundary-2026-06-04.md)
and [security policy](../SECURITY.md). The design's three-tier model is not a
blanket guarantee that a connected model cannot leak its context.

Named platform routes and remaining access/transport requirements are tracked
in [platform readiness](platform-readiness.md). This includes Gemini Spark,
consumer Muse, Muse Code, dot/ChatGPT, Alexa+, Siri and Meta AI Connectors.

## Use the new authority boundary

For action/rule authority, start with [the service contract](authority-service.md)
and its executable synthetic walkthrough. Do not route these operations through
the legacy dispatcher or enable generic one-time tokens because this separate
ledger now exists. Its stateful grants are a different scoped interface.

## Legacy vault/proof integration path

1. **Evaluate storage and transport.** Follow [getting started](getting-started.md),
   pin the source revision you evaluate, and discover schemas with `tools/list`.
   Use explicit paths and synthetic data. Keep network listeners local.
2. **Map the person's authority.** Define each fact's tier, the actor requesting
   it, its purpose and permitted output. Separate internal reasoning context
   from externally disclosed material. Map each actual dispatch path to policy.
3. **Wire the real data and proof paths.** Replace MCP placeholders with vault and
   proof-engine integration. Define trusted credential provenance, proof format,
   nonce/domain binding, verification, and invalid/expired proof behavior.
4. **Implement consent as a lifecycle.** Present requester, scope, purpose and
   expiry to the person. Bind their decision to the request. A timeout, denial,
   or unresolved challenge must not become permission.
5. **Complete sensitive capability use.** Add trusted issuer and rotation policy,
   signing custody, exact-context verification, durable consumption and replay
   prevention, revocation behavior, and auditable outcomes. Do not enable
   one-time actions before those dependencies exist.
6. **Validate the combined system.** Test cross-domain/purpose rejection, stale
   grants, repeated use, denied consent, unavailable state, transport bypass,
   and data leaving the model. Local component tests alone do not prove the
   safety of a platform integration.

These steps include proposed work, not configuration switches that unlock a
finished service. No production payment custody or browser extension is provided
by this walkthrough.

## For agent implementers

Read the current source, not only tool descriptions. Preserve existing client
configuration. Never emit or store real credentials in examples, logs or tests.
Treat successful placeholder responses as scaffolding, pending status as pending,
and denied issuance as denied. Report remaining implementation work rather than
inventing tokens, proof results, platform support, or performance measurements.

## Related project

[Signet Eval](https://github.com/wandercom/signet-eval) is the separate tool-call
policy engine maintained by Wander. Its host integrations and install command
are independent of this vault and proof stack.
