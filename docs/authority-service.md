# Authenticated authority core

This source revision implements durable personal-authority state, distinct from
the fictional website preview and the legacy vault/MCP dispatcher. It is a real
local component with signed caller authentication, owner approvals, SQLite
transactions, rule revisions, grants, execution reservations and receipt-backed
baselines. **It is not yet a deployed consumer approval app or merchant service.**

Code: [`authority`](../crates/signet/src/authority/mod.rs),
[wire types](../crates/signet/src/authority/types.rs),
[MCP relay](../crates/signet/src/authority/mcp.rs),
[adversarial/process tests](../crates/signet/tests/authority_contract.rs).

## Start with the executable contract

```sh
make check
cargo run --locked -p signet --example authority_walkthrough
```

The walkthrough creates random **synthetic** owner, agent and executor keys in
memory and a private temporary database. It adds a $50 rule, requests an exact
$75 exception, reserves that purchase once, rejects replay, and verifies the
standing limit stayed $50. It performs no network requests or purchases. Its
automatic test signatures are not a human-authentication mechanism; do not use
this signer pattern in a real agent deployment.

## Trust and roles

| Role | Authority | Must not be controlled by the model |
|---|---|---|
| Owner signer | Signs the exact approval envelope after authenticating the person and displaying its complete action | Private key, confirmation surface, account enrollment/recovery |
| Agent adapter | Signs requests using one provisioned agent identity; can propose purchases, submit owner signatures and commit approved mutations | It cannot enroll keys, manufacture owner signatures or record purchase completion |
| Executor | Attests the exact quote, consumes purchase grants and records authenticated provider outcomes | Private executor key, merchant credentials, quote verification, idempotent provider calls |
| Authority service | Pins these public keys and mediates all state changes in one database | Process, executable, configuration, database/WAL files, clock and backups |

An OAuth connection, host confirmation, `approved: true`, model-generated text or
access to the same macOS login is not owner authentication. The owner and executor
keys must differ from every agent key. The service rejects unknown/weak keys and
pins its complete trust configuration in the database. Agent/executor enrollment, signing-key rotation and recovery are operator work.
The separate owner app exposes passkey enrollment and revocation, with no generic signing operation.

The [passkey owner approval app](owner-approval.md) now authenticates the person
with `webauthn-rs`, displays the exact purchase or rule change, and invokes the
isolated owner signer only after a fresh verified assertion. It supports one-time
bootstrap, authenticated backup enrollment and revocation. WebAuthn does not itself
produce arbitrary Ed25519 signatures; the app bridges that verified assertion to
the pinned signer. The legacy passkey abstraction is not used for this boundary.

## Deployment decisions still required

The chosen implementation is a passkey-backed web approval app with an injected
signer. It is implemented and tested locally with synthetic authenticators. Select
an isolated service account/sandbox or trusted service host before live use.
Hardware custody, all-keys-lost recovery/key rotation, real-device validation and
merchant integrations remain gates. No real credentials, hosting, account grants,
remote access, merchant registration or transactions were provisioned.

## Operator bootstrap and adapters

After external provisioning, the operator supplies a JSON trust configuration:

```json
{
  "authority_id": "operator-assigned-unique-authority-id",
  "owner_key": "<64 lowercase hex characters: owner public key>",
  "agent_keys": ["<64 lowercase hex characters: agent public key>"],
  "executor_key": "<64 lowercase hex characters: executor public key>"
}
```

These placeholders deliberately are not usable credentials. Keep the private
keys with their separate trusted signers. In an isolated service environment:

```sh
signet authority-init --database /private/service/authority.sqlite --trust-config /private/service/trust.json
signet authority-serve --database /private/service/authority.sqlite --trust-config /private/service/trust.json
# Or wrap the same authenticated contract in standard stdio MCP:
signet authority-serve --mcp --database /private/service/authority.sqlite --trust-config /private/service/trust.json
```

The parent directory must already be private (Unix mode 0700). Bootstrap creates
a new mode-0600 file and refuses to overwrite it. Serving opens existing state
and refuses changed trust configuration. Do not give an unrestricted agent file
access to this directory or launch this as a same-user "security sandbox".
File modes protect other accounts; they do not isolate processes with the same UID.
This implementation fails closed on platforms without its Unix permission backend.

Raw mode accepts one `SignedMessage` JSON object per line and returns
`{"ok":true,"result":...}` or `{"ok":false,"error":...}`. Input is bounded to
64 KiB per line. Diagnostics use stderr. No legacy vault config or private key is
loaded. MCP mode supports initialize, ping, tools/list and tools/call with one
`authority_request` tool whose arguments are the same signed envelope. The tool
is explicitly marked write-capable; a host may impose additional confirmations.
Notifications cannot execute authority operations.

The owner service adds signed HTTP and stateless Streamable HTTP MCP adapters;
see [HTTP contract](owner-approval.md#http-and-mcp-adapters). HTTPS deployment,
vendor OAuth/session binding and host-specific review remain integration work. A relay must bind its provisioned agent
identity to the authenticated host session and prevent cross-session signing.
Never expose the owner or executor signer to an LLM as a general tool. Authenticate
the service channel and responses; raw stdio assumes a trusted local endpoint.

## Signed wire format

```json
{"payload":"<base64url, no padding, of original UTF-8 JSON>","signature":"<128 hex characters>"}
```

Ed25519 signing input is **UTF-8 domain + a single NUL byte + the original decoded
payload bytes**. Verification does not reserialize JSON. Use the exported
`signing_bytes` function or implement these bytes exactly. There is no ambiguous
cross-language JSON canonicalization step. Unknown fields, wrong types, malformed
signatures, missing identities, future timestamps and excessive lifetimes fail.

| Domain | Payload type | Signed by |
|---|---|---|
| `signet.authority-request.v1` | `Request` | Registered agent or executor |
| `signet.owner-approval.v1` | `OwnerApproval` | Pinned owner signer |
| `signet.executor-quote.v1` | `Quote` | Pinned executor |

Every payload binds `authority_id`, `client_key`, `issued_at` and `expires_at`.
Requests and approvals have a fresh 256-bit lowercase-hex `nonce`; quotes have a
stable 256-bit `quote_id`. Lifetimes are positive and at most 300 seconds.
Use service-clock seconds since Unix epoch. Owner approvals additionally bind
the current `policy_revision` and the exact action. Read the Rust wire types for
all required fields; do not infer fields from prose or natural-language requests.

An authenticated agent snapshot request, before signing, looks like:

```json
{
  "authority_id": "<provisioned authority>",
  "client_key": "<provisioned agent public key>",
  "nonce": "<fresh 256-bit hex nonce>",
  "issued_at": 0,
  "expires_at": 120,
  "command": {"method": "snapshot"}
}
```

The example timestamps are intentionally expired; supply current service time.
Successful request nonces are persisted. For a lost response, use a new signed
snapshot request to inspect committed state; never turn a timeout into a fresh
purchase intent. Failed transactions roll back their nonce and all effects.

## Exact grants and rule lifecycle

`prepare_purchase` accepts an executor-signed quote. It reads only stored rules,
never caller-supplied policy. It returns an opaque grant identifier when the
quote fits, or `requires_owner_approval`. The opaque grant is a stateful
capability, **not** a new `signet.cap.v1` token or a portable offline proof.

`submit_approval` verifies an owner-signed `OwnerApproval`, client/audience/time,
global policy revision, exact mutation or quote, and a never-used approval nonce.
It issues a grant with at most the remaining owner/quote lifetime. The owner nonce
is spent at issuance, so the same approval cannot manufacture replacement grants.

`commit_mutation` accepts only a rule-mutation grant belonging to that agent.
Add requires a never-used rule ID; edit/remove require the exact current version.
Removed IDs retain tombstones to prevent remove/re-add replay. Content cannot be
changed at commit. Mutation, grant consumption, revision increment and audit record
share one transaction. Every mutation invalidates all earlier unspent grants and
pending approvals by advancing the global policy revision. Revoke-grant is also
an exact, owner-approved mutation; it cannot undo an already reserved purchase.

There is no path from a purchase grant to rule mutation, from a rule grant to a
purchase, or from an agent request to key enrollment. Owner exceptions do not edit
standing limits. Rule management is not persistent blanket permission.

## Purchase boundary, replay and uncertain outcomes

Only the executor can `consume_purchase`, supplying both grant ID and the exact
purchase. It revalidates the signature, quote expiry, client, policy revision and
every purchase field. Consumption and durable execution reservation are one
SQLite `BEGIN IMMEDIATE` transaction, with WAL and synchronous FULL durability.
Concurrent consumers cannot both reserve a grant. Multiple grants for the same
quote cannot create multiple reservations.

The returned `execution_id` is the quote's stable purchase-intent ID and the
`provider_idempotency_key`. The executor must bind it to a **single user task**,
reuse it across uncertain retries, verify the exact current merchant quote,
then perform at most one provider action using provider-supported idempotency.
The agent cannot invent a new ID to bypass a consumed intent: the trusted executor
controls quote issuance and must keep a durable task-to-intent mapping. The core
cannot identify semantic duplicates hidden behind different executor-signed IDs.

The core returns `reserved`, never "purchased." It makes no merchant calls. A
provider adapter must use the exact merchant, item/pack, quantity, final total,
currency, terms and delivery conditions. The executor also owns verification of
the requirement/category claims; a model assertion that requirements are met is
not sufficient. Digests must resolve to the same reviewed, human-readable terms
in the trusted owner and executor surfaces. This core checks their exact binding,
not the truth of a merchant's description or fulfillment.

`complete_purchase` accepts only the authenticated executor and one terminal
outcome for a reserved execution: succeeded, failed or unknown. Only success
creates a receipt, derived from the stored purchase rather than caller-reported
amounts. Provider references are unique. Unknown/failed outcomes never restore
the grant or establish a baseline. Snapshot exposes the reserved purchase and
outcome for reconciliation. Terminal outcomes cannot be overwritten through this
adapter. Recovery/reconciliation after unknown outcomes needs a separate reviewed
operator/provider workflow; do not simply retry or forge a success receipt.

## Baselines and rule composition

- Matching spend rules use the strictest ceiling. No matching allowance means
  owner approval, not permission.
- A global or matching-category confirmation rule requires an exact owner
  approval even under the ceiling.
- A reorder rule references a completed executor-authenticated receipt and needs
  its own exact owner-approved addition or edit. Its baseline is that receipt's
  recorded total; there is no model-supplied "usual price".
- Every matching reorder rule must agree with the exact merchant, currency, item,
  description, quantity, requirements, terms and fulfillment. A cheaper or equal
  total qualifies. Higher totals or changed conditions require approval and cannot
  fall back to a looser general spending limit.
- An explicitly approved reorder is a separate scoped allowance; it may exceed a
  general limit, but never overrides confirmation rules. Show this precedence to
  the owner before signing the reorder rule.
- Buying at a higher or lower price does not mutate a baseline. A changed baseline
  needs another explicit edit, current rule version and completed receipt.

No aggregate budget, purchase-frequency limit, subscription lifecycle or
cross-merchant semantic deduplication is implemented. The $50 rule is a per-action
limit, not permission to claim a $50 daily budget.

## Remaining production gates

The locally implemented security boundary depends on an isolated trusted service
and separately authenticated owner/executor surfaces. Before live custody:

- Review the implemented passkey owner authentication, exact-action display and
  enrollment/revocation on real devices. Complete signing/client key rotation,
  deployment isolation and all-keys-lost account recovery. No real owner signer
  has been provisioned by this change.
- Protect the service account, configuration, executable and clock. This local
  SQLite store contains private rule/history/audit data in plaintext inside its
  private directory; it is not the encrypted vault or a substitute for at-rest
  encryption, operational access control and backup policy.
- Define rollback protection and disaster recovery. Restoring an old database can
  restore spent nonces; ordinary SQLite transactions do not defeat operator-level
  snapshot rollback. Never restore a live ledger without reconciling external
  execution history or introducing a new authority epoch/key boundary.
- Add provider adapters, durable task/intent identity, provider idempotency,
  receipt verification and uncertain-outcome reconciliation. No real provider
  credentials, accounts or merchant flows were exercised.
- Add remote authenticated transport, session binding, quotas/rate limiting,
  retention and monitoring, plus host-specific mandatory confirmation and review.
  Current audit entries preserve signed inputs but are not an externally anchored,
  tamper-proof log. Rejected transactions leave no committed audit entry.

The old generic `signet.cap.v1` issuance path remains fail-closed. This service's
ledger is scoped to its own grants; it must not silently enable legacy one-time
tokens or bypass Tier 3 live-auth requirements.

## Recovering a raw approval submission

If `SubmitApproval` loses its reply, an agent-signed `SubmittedApprovalStatus { owner_nonce }` retrieves the original client-bound grant ID and current status. It does not create a replacement grant. Another agent or executor cannot query it. The durable receipt survives reopening the database; consumed, revoked, stale and expired grants remain unusable. Owner-app proposals have their own status path.

The newer native JSON rings service and recovery semantics are documented in [R2 persistence](r2-persistence.md); it is not yet wired into this SQLite owner HTTP service.
