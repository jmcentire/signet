# Preserved prototype status

Checkpoint: October 11, 2026. Development is paused. This inventory describes the
preserved source in this repository.
“Implemented” means code exists, not that deployment or operational safety is proven.

| Surface | Implemented and tested locally | Still missing |
|---|---|---|
| Website and owner preview | Responsive fictional scenarios; zero-ring initial state; separate rules/assets and task-assignment interactions. | No connected purchases or conversational policy authoring. |
| SQLite authority/owner | Signed exact action/rule approvals, one-shot grants, reservations, baselines, WebAuthn, backup passkeys and revocation; HTTP/MCP tests. | Real-device tests, operational custody and provider execution. |
| Native rings | Versioned bindings, per-worker/task scopes, expiry, bounded swaps, shared budgets, reservations, outcomes and recovered receipts. | Provider evidence verification and operational reconciliation. |
| Native owner integration | Passkeys, counters, revocations and rings commit through one native JSON CAS aggregate; shared HTTP interface, management forms and R2 bootstrap/serve CLI. Five new synthetic service-level lifecycle tests pass. | Dedicated native HTTP/browser and cross-instance revocation coverage. Scoped review found that passkey revocation leaves existing ring delegations active; separate revocation is required, a live-use blocker. Purchase requirements are currently shown as hashes: complete readable binding before owner-facing use. |
| R2 persistence | Canonical immutable snapshots, user-bound CAS, current-head lineage recovery; SDK transport with mocked conditional requests. | No live bucket/token test, protected anti-rollback checkpoint or deletion worker. |
| Cloud KMS | Pinned Ed25519 version/public key, integrity checks and fixed-destination workload-identity transport; mocked HTTP tests. | No live KMS key/signing call, deployment identity or runtime isolation validation. |
| Client asset cipher | AES-256-GCM with asset/epoch binding, current-key rotation and zeroized buffers; synthetic tests. | Enrollment, strong-auth wiring, client broker and reviewed custody protocol. |
| Browser/Jev | Agreed conceptual flow and documented threat model. | No controlled browser, Jev calls, classification evaluation or universal enforcement. |
| Escalation | Exact one-time approval exists in the SQLite path. | Structured “$5 more this month” proposals, bounded monthly grants and anti-stacking semantics. |
| Legacy proof/capability surfaces | Nine Rust crates; inspect individual contracts. | MCP proof bytes/query answers include placeholders; generic one-time capability issuance remains disabled. Native rings do not enable that separate path. |

## Verification boundary

The publication checkpoint passed **1,119 Rust tests, 7 Python tests**, workspace
build/lint/format checks, the credential scan and dependency audit. All **6 Node
R2/KMS mock tests** passed. Product CI now uses the declared Rust 1.88 minimum
alongside stable, and includes the bridge tests after its credential gate.

The website build and **177 local link checks** passed. Chrome checks covered
320, 390, 768 and 1440px; the new concept page was inspected at desktop/mobile
sizes. These visual checks do not establish native management-form correctness;
that newer owner UI still needs its own browser/real-device ceremony run.

OpenTofu validated the infrastructure draft with Google provider 6.50.0; no cloud
plan/apply ran. The authority Docker image build was not run. No live R2 or KMS
call was made. Tests use synthetic credentials and mocked provider responses.

Earlier independent review findings in the SQLite owner, object-store and ring
recovery paths were repaired and rechecked. A scoped independent review of the later native owner integration found the
passkey/delegation revocation gap above; it remains explicitly unresolved. Tests use synthetic credentials; no real
owner credential, asset key or provider account was enrolled.

## Deployment state

The pre-existing Fly website/vault deployment is separate from this local work.
A new personal GCP project was created and remains unbilled. No new service,
load balancer, signing key, secret, runtime IAM grant or DNS record was created.
The infrastructure draft is an unapplied proposal. Public publishing, deployment
and paid/security-sensitive setup each require explicit authorization.

The legacy `signet serve` startup persists a mnemonic in `vault.json`; it must
not be deployed as evidence of the proposed client-only asset custody. The
legacy mock passkey path is distinct from the new WebAuthn owner implementations.
